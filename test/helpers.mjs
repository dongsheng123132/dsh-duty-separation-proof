import { readFile } from 'node:fs/promises'
export async function fixture() { return JSON.parse(await readFile(new URL('../examples/settled.json', import.meta.url), 'utf8')) }
