import { createHash } from 'node:crypto'
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises'
import { isAbsolute, relative, resolve } from 'node:path'

const MAX_FILE = 4 * 1024 * 1024
const HEX = /^[a-f0-9]{64}$/
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/
const DUTIES = new Set(['request', 'approve', 'execute', 'observe'])
const SECRET_VALUE = /(?:bearer\s+[a-z0-9._-]{12,}|(?:sk|ghp|github_pat)_[a-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i
const stable = value => JSON.stringify(value, (_, child) => child && typeof child === 'object' && !Array.isArray(child) ? Object.fromEntries(Object.entries(child).sort(([a], [b]) => a.localeCompare(b))) : child)
export const sha256 = value => createHash('sha256').update(value).digest('hex')
const fail = (code, message) => Object.assign(new Error(message), { code })
const hash = (value, label) => { if (typeof value !== 'string' || !HEX.test(value)) throw fail('INVALID_MANIFEST', `${label} must be lowercase SHA-256`) }
const boundedId = (value, label) => { if (typeof value !== 'string' || !ID.test(value)) throw fail('INVALID_MANIFEST', `${label} must be a bounded public id`) }
const timestamp = (value, label) => { const parsed = Date.parse(value); if (!Number.isFinite(parsed)) throw fail('INVALID_TIME', `${label} must be an ISO timestamp`); return parsed }
const integer = (value, label, min, max) => { if (!Number.isSafeInteger(value) || value < min || value > max) throw fail('INVALID_MANIFEST', `${label} invalid`) }

function rejectSecrets(value, path = '$') {
  if (typeof value === 'string' && SECRET_VALUE.test(value)) throw fail('SECRET_MATERIAL', `secret-shaped value rejected at ${path}`)
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    if (/(?:secret|password|credential|api[_-]?key|private[_-]?key|authorization|cookie|token|raw|body|content|log|prompt|chat|email|account|display[_-]?name)$/i.test(key) && (typeof child === 'string' || typeof child === 'number')) throw fail('SECRET_MATERIAL', `sensitive field rejected at ${path}.${key}`)
    rejectSecrets(child, `${path}.${key}`)
  }
}

function dutyList(value, label, min = 1) {
  if (!Array.isArray(value) || value.length < min || value.length > 32 || value.some(item => !DUTIES.has(item))) throw fail('INVALID_MANIFEST', `${label} invalid`)
  return value
}

function parseManifest(input) {
  let manifest
  try { manifest = typeof input === 'string' ? JSON.parse(input) : structuredClone(input) } catch { throw fail('INVALID_MANIFEST', 'manifest must be JSON') }
  if (!manifest || manifest.schemaVersion !== 1) throw fail('INVALID_MANIFEST', 'schemaVersion 1 required')
  rejectSecrets(manifest); boundedId(manifest.proofId, 'proofId')
  const evaluationMs = timestamp(manifest.evaluationTime, 'evaluationTime')
  const workflow = manifest.workflow || {}
  for (const key of ['workflowIdHash', 'objectHash', 'revisionHash', 'policySha256']) hash(workflow[key], `workflow.${key}`)
  const startsMs = timestamp(workflow.startsAt, 'workflow.startsAt'); const completedMs = timestamp(workflow.completedAt, 'workflow.completedAt')
  const policy = manifest.policy || {}
  integer(policy.maxEvidenceAgeMs, 'policy.maxEvidenceAgeMs', 1000, 365 * 86400000)
  integer(policy.minDistinctPrincipals, 'policy.minDistinctPrincipals', 2, 32)
  integer(policy.minDistinctObservers, 'policy.minDistinctObservers', 1, 100)
  integer(policy.minDistinctApprovers, 'policy.minDistinctApprovers', 1, 16)
  if (policy.forbidFullWorkflowControl !== true) throw fail('INVALID_MANIFEST', 'policy.forbidFullWorkflowControl must be true')
  const requiredSequence = dutyList(policy.requiredSequence, 'policy.requiredSequence', 4)
  if (requiredSequence[0] !== 'request' || requiredSequence.at(-1) !== 'observe' || !requiredSequence.includes('execute')) throw fail('INVALID_MANIFEST', 'requiredSequence must start request, include execute and end observe')
  if (requiredSequence.filter(duty => duty === 'approve').length < policy.minDistinctApprovers) throw fail('INVALID_MANIFEST', 'requiredSequence cannot satisfy approval quorum')
  if (!Array.isArray(policy.disjointDutySets) || !policy.disjointDutySets.length || policy.disjointDutySets.length > 16) throw fail('INVALID_MANIFEST', 'disjointDutySets invalid')
  const disjointDutySets = policy.disjointDutySets.map((set, index) => { const values = dutyList(set, `policy.disjointDutySets[${index}]`, 2); if (new Set(values).size !== values.length) throw fail('INVALID_MANIFEST', 'duplicate duty in conflict set'); return values })
  if (!Array.isArray(manifest.events) || manifest.events.length !== requiredSequence.length || manifest.events.length > 32) throw fail('INVALID_MANIFEST', 'events must match requiredSequence length')
  const sequenceNumbers = new Set(); const outputReceipts = new Set()
  const events = manifest.events.map((row, index) => {
    integer(row?.sequence, `events[${index}].sequence`, 1, 32)
    if (!DUTIES.has(row?.duty)) throw fail('INVALID_MANIFEST', `events[${index}].duty invalid`)
    for (const key of ['principalHash', 'observerHash', 'workflowIdHash', 'objectHash', 'inputReceiptSha256', 'outputReceiptSha256']) hash(row?.[key], `events[${index}].${key}`)
    if (sequenceNumbers.has(row.sequence)) throw fail('INVALID_MANIFEST', 'duplicate event sequence'); sequenceNumbers.add(row.sequence)
    const duplicateOutput = outputReceipts.has(row.outputReceiptSha256); outputReceipts.add(row.outputReceiptSha256)
    return { ...row, duplicateOutput, occurredMs: timestamp(row.occurredAt, `events[${index}].occurredAt`) }
  })
  events.sort((a, b) => a.sequence - b.sequence)
  return { manifest, evaluationMs, workflow, startsMs, completedMs, policy, requiredSequence, disjointDutySets, events }
}

export function inspectDutySeparationManifestJson(manifestJson) {
  const { manifest, workflow, policy, events } = parseManifest(manifestJson)
  return { schemaVersion: 1, proofIdHash: sha256(manifest.proofId), workflowIdHash: workflow.workflowIdHash, objectHash: workflow.objectHash, revisionHash: workflow.revisionHash, policySha256: workflow.policySha256, eventCount: events.length, requiredDutyCount: policy.requiredSequence.length, changesAuthority: false, executesActions: false }
}

export function evaluateDutySeparationManifest(manifestJson) {
  const { manifest, evaluationMs, workflow, startsMs, completedMs, policy, requiredSequence, disjointDutySets, events } = parseManifest(manifestJson)
  const workflowChronologyValid = startsMs < completedMs && completedMs <= evaluationMs
  const eventSequenceValid = events.every((row, index) => row.sequence === index + 1 && row.occurredMs >= startsMs && row.occurredMs <= completedMs && (index === 0 || row.occurredMs >= events[index - 1].occurredMs))
  const dutyOrderSatisfied = events.every((row, index) => row.duty === requiredSequence[index])
  const bindingsSatisfied = events.every(row => row.workflowIdHash === workflow.workflowIdHash && row.objectHash === workflow.objectHash)
  const receiptChainClosed = events.every((row, index) => index === 0 || row.inputReceiptSha256 === events[index - 1].outputReceiptSha256)
  const distinctEventReceipts = events.every(row => !row.duplicateOutput)
  const principalsByDuty = new Map([...DUTIES].map(duty => [duty, new Set(events.filter(row => row.duty === duty).map(row => row.principalHash))]))
  const conflictSetsSatisfied = disjointDutySets.every(set => set.every((duty, index) => set.slice(index + 1).every(other => [...principalsByDuty.get(duty)].every(principal => !principalsByDuty.get(other).has(principal)))))
  const approverQuorumSatisfied = principalsByDuty.get('approve').size >= policy.minDistinctApprovers
  const principalDuties = new Map()
  for (const event of events) { const duties = principalDuties.get(event.principalHash) || new Set(); duties.add(event.duty); principalDuties.set(event.principalHash, duties) }
  const fullWorkflowControlAbsent = [...principalDuties.values()].every(duties => ![...new Set(requiredSequence)].every(duty => duties.has(duty)))
  const distinctPrincipalCount = principalDuties.size
  const principalThresholdSatisfied = distinctPrincipalCount >= policy.minDistinctPrincipals
  const distinctObserverCount = new Set(events.map(row => row.observerHash)).size
  const observerThresholdSatisfied = distinctObserverCount >= policy.minDistinctObservers
  const evidenceFresh = evaluationMs - completedMs >= 0 && evaluationMs - completedMs <= policy.maxEvidenceAgeMs
  const checks = { workflowChronologyValid, eventSequenceValid, dutyOrderSatisfied, bindingsSatisfied, receiptChainClosed, distinctEventReceipts, conflictSetsSatisfied, approverQuorumSatisfied, fullWorkflowControlAbsent, principalThresholdSatisfied, observerThresholdSatisfied, evidenceFresh }
  const verified = Object.values(checks).every(Boolean)
  return { schemaVersion: 1, verdict: verified ? 'duty-separation-settled' : 'not-settled', proofIdHash: sha256(manifest.proofId), workflowIdHash: workflow.workflowIdHash, objectHash: workflow.objectHash, revisionHash: workflow.revisionHash, policySha256: workflow.policySha256, checks, disclosures: { eventCount: events.length, distinctPrincipalCount, distinctApproverCount: principalsByDuty.get('approve').size, distinctObserverCount, conflictSetCount: disjointDutySets.length }, changesAuthority: false, grantsAccess: false, approvesActions: false, executesActions: false, authenticatesReceipts: false, observesLiveSystems: false, provesLedgerExhaustive: false, provesAbsenceOfUndeclaredActions: false, destructiveActions: false }
}

async function safeManifest(root, manifestPath) {
  if (typeof manifestPath !== 'string' || !manifestPath || manifestPath.length > 512 || isAbsolute(manifestPath)) throw fail('PATH_ESCAPE', 'manifestPath must be workspace-relative')
  const absolute = resolve(root, manifestPath); const rel = relative(root, absolute); if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'manifestPath escapes workspaceRoot')
  let cursor = root; let stat; const parts = rel.split(/[\\/]/)
  for (const [index, part] of parts.entries()) { cursor = resolve(cursor, part); stat = await lstat(cursor).catch(() => { throw fail('MISSING_MANIFEST', 'manifest missing') }); if (stat.isSymbolicLink()) throw fail('UNSAFE_MANIFEST', 'manifest path contains symlink'); if (index < parts.length - 1 && !stat.isDirectory()) throw fail('UNSAFE_MANIFEST', 'manifest parent invalid') }
  if (!stat.isFile() || stat.size > MAX_FILE) throw fail('UNSAFE_MANIFEST', 'manifest must be a regular file no larger than 4 MiB')
  const realRel = relative(await realpath(root), await realpath(absolute)); if (realRel.startsWith('..') || isAbsolute(realRel)) throw fail('PATH_ESCAPE', 'real manifest escapes workspaceRoot')
  return readFile(absolute, 'utf8')
}

async function safeArtifactDir(root, artifactDir) {
  if (typeof artifactDir !== 'string' || !artifactDir || artifactDir.length > 512 || isAbsolute(artifactDir)) throw fail('PATH_ESCAPE', 'artifactDir must be workspace-relative')
  const dir = resolve(root, artifactDir); const rel = relative(root, dir); if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'artifactDir escapes workspaceRoot')
  let cursor = root
  for (const part of rel.split(/[\\/]/)) { cursor = resolve(cursor, part); try { const stat = await lstat(cursor); if (stat.isSymbolicLink() || !stat.isDirectory()) throw fail('UNSAFE_ARTIFACT_DIR', 'artifactDir components must be real directories') } catch (error) { if (error.code !== 'ENOENT') throw error; await mkdir(cursor) } }
  return dir
}

export async function verifyDutySeparationManifest({ workspaceRoot, manifestPath, artifactDir }) {
  const root = resolve(workspaceRoot); const report = evaluateDutySeparationManifest(await safeManifest(root, manifestPath)); const bytes = Buffer.from(`${stable(report)}\n`); const digest = sha256(bytes); const dir = await safeArtifactDir(root, artifactDir); const output = resolve(dir, `duty-separation-proof-${digest}.json`)
  try { await writeFile(output, bytes, { flag: 'wx' }) } catch (error) { if (error.code !== 'EEXIST') throw error; if (!(await readFile(output)).equals(bytes)) throw fail('ARTIFACT_DIVERGED', 'content-addressed artifact diverged') }
  const readBack = await readFile(output); if (sha256(readBack) !== digest) throw fail('READBACK_FAILED', 'artifact read-back failed')
  return { ...report, artifact: { path: relative(root, output).replaceAll('\\', '/'), sha256: digest, verifiedByReadBack: true } }
}
