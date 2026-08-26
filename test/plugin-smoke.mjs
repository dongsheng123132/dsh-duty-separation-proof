import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createDefinitions } from '../index.js'
const manifestJson = await readFile(new URL('../examples/settled.json', import.meta.url), 'utf8'); const tools = createDefinitions(); assert.deepEqual(tools.map(tool => tool.name), ['dsh_duty_separation_inspect', 'dsh_duty_separation_verify']); const result = await tools[0].execute({ manifestJson }); assert.equal(result.eventCount, 5); process.stdout.write(`${JSON.stringify({ ok: true, tools: tools.map(tool => tool.name), eventCount: result.eventCount })}\n`)
