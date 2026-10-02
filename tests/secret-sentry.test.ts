import type { On } from 'claude-code'
import { expect, test } from 'claude-code/testing'

import { findSecrets, nameIsSecret, redact, scrubBlocks } from '../hooks/detect'

// Built at run time so this repository never holds a literal credential shape.
const GH = 'gh' + 'p_' + 'R7kQ2mX9vL4tB8nW1cZ5yH3jD6fA0sGeUoPi'
const GH_TAIL = 'W4nP8xK2qL6vB9mT3cY7hJ1dF5sA0gRzEuOi'
const AWS = 'AK' + 'IA' + 'Q3VN7XK2M4P9TB6W'
const STRIPE = 'sk' + '_live_' + '51Hx9Qm2Lp8Vt4Rk7Zc3Wn6Yb'
const ANT = 'sk-' + 'ant-' + 'api03-Zx8Qm2Lp9Vt4Rk7Zc3Wn6YbHj5DfQp1Wn8Xc3Vb6Nm2Lk9Jh4Gf7Ds0Aq'
const PEM = '-----BEGIN ' + 'RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7x\n-----END ' + 'RSA PRIVATE KEY-----'
const OPAQUE = 'Zq8Lm2Vt4Rk7Zc3Wn6YbHj5Df9Qp'

const person = (text: string) => ({ text, wait: false, origin: { kind: 'composer' as const } })
const hits = (s: string) => findSecrets(s).length

test('detectors find real shapes', () => {
  for (const s of [
    GH,
    AWS,
    STRIPE,
    ANT,
    PEM,
    `const dbPassword = "Tq8#vR2!mZ6pLx9w"`,
    'password = "Password1!"',
    'password = "correct horse battery 42"',
    'DB_PASSWORD=CorrectHorseBatteryStaple42!',
    'API_KEY=Tq8#vR2!mZ6pLx9w',
    `Authorization: Bearer ${OPAQUE}`,
    `headers["Authorization"] = "Bearer ${OPAQUE}"`,
    `os.environ["API_KEY"] = "Tq8#vR2!mZ6pLx9w"`,
    `curl -H "x-api-key: ${OPAQUE}XX" https://api.example.org`,
    `https://api.example.org/v1?api_key=${OPAQUE}`,
    'postgres://admin:Tq8vR2mZ6pLx@db.internal:5432/app',
    'mysql --password=Tq8vR2mZ6pLx9w -h db',
    'curl -u admin:Tq8vR2mZ6pLx9w https://x.internal',
    `docker run -e API_KEY=${OPAQUE} app`,
    `cd /app && export API_TOKEN=${OPAQUE}`,
    `env API_TOKEN=${OPAQUE} deploy`,
    `  - API_KEY=${OPAQUE}`,
    'API_TOKEN: supersecrettokenvalue123',
    'password: Tq8#vR2!mZ6pLx9w',
    `aws configure set aws_secret_access_key ${'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzq8Lm2Vt4R'}`,
    'https://hooks.slack.com/services/' + 'T0123ABCD/B0456EFGH/' + 'Zq8Lm2Vt4Rk7Zc3Wn6YbHj5D',
    `DB_PASSWORD="Tq8#vR2!m'Z6pLx9w"`,
    'password = "QvRmZaLpTxNcBwHsKdFyJuEg"',
    'API_KEY=kRqmXwLpNzBvYcHjTsDfGeUa',
    'DB_PASSWORD=CorrectHorseBatteryStaple',
    'password = "nonempty-K9#mQ2wL8r"',
    'DB_PASSWORD=changemeNOW-K9#mQ2wL8r',
    'API_KEY=Tq8vR2mZ6pxxxxLx9wAb',
    'postgres://admin:correct-horse-battery-staple@db.internal:5432/app',
    'curl -u admin:correct-horse-battery-staple https://x.internal',
    'Authorization: Bearer correct-horse-battery-staple-extra',
    '//registry.npmjs.org/:_authToken=npm_Tq8vR2mZ6pLx9wAbCdEf',
    'RAILS_MASTER_KEY=9f8e7d6c5b4a39281706f5e4d3c2b1a0',
    '-----BEGIN ' + 'PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ==',
    'password: Tq8#vR2!mZ6pLx9w # production',
    'mysql --password "correct horse battery 42"',
    `payload = '{"password":"Tq8#vR2!mZ6pLx9w"}'`,
    `AWS_SESSION_TOKEN="${'Zq8Lm2Vt4Rk7Zc3Wn6Yb'.repeat(20)}"`,
    'apiKey2 = "Tq8#vR2!mZ6pLx9w"',
    'xoxe-' + '1-My0xLTEyMzQ1Njc4OTAtYWJjZGVm',
    // A provider token is trusted even if a word happens to appear inside it.
    'gh' + 'p_' + 'fake' + 'QmX9vL4tB8nW1cZ5yH3jD6fA0sGeUoPi',
  ]) {
    expect([s, hits(s)]).toEqual([s, 1])
  }
})

test('detectors pass placeholders, identifiers and paths', () => {
  for (const s of [
    'API_KEY="your-api-key-here"',
    'token = "${GITHUB_TOKEN}"',
    'const key = process.env.STRIPE_KEY',
    'AKIAIOSFODNN7EXAMPLE',
    'password = "hunter2"',
    'authorUrl = "https://github.com/ccdwyer/x1"',
    'secretName = "prod-db-password-v2"',
    'sk-learn is a library',
    'sk-projection-matrix-uniform-binding-extra',
    'see sk-ant-api03-documentation-page',
    'sk-abcdefghijklmnopqrstuvwxyz',
    'token: "xxxxxxxxxxxxxxxx"',
    'DB_PASSWORD=changeme',
    'export API_TOKEN=$OTHER_VAR',
    'git clone https://github.com/a/b.git',
    'SECRETARY_EMAIL=jane.doe@company.com',
    'AUTHOR_ID=ab12cd34ef56',
    'MAX_COMPLETION_TOKENS=12345678',
    'OAUTH_AUDIENCE=api://12345678-abcd-ef',
    'secret = "config/secrets.yml"',
    'const tokenFile = "C:/Users/chris/AppData/token.txt"',
    'token = "i18next-parser"',
    'token = "k8s-prod-db-admin"',
    'docker run --secret src/db.password app',
    'secretFile = "config/production.json"',
    'please parse -----BEGIN PRIVATE KEY----- and explain',
    'docker build --secret id=npmrc,src=.npmrc .',
    'docker build --secret id=aws,src=/Users/chris/.aws/credentials .',
    'MAX_TOKEN=123456789',
    'tokenCount = "123456789"',
    'tokenId = "ab12cd34ef567890"',
    'passRate = "0.12345678"',
    'const tokenFile = "src/MyModule/TokenStore"',
    'password = "src/MyModule/TokenStore"',
    'sk-projection-matrix-uniform-binding-extra-01-extra',
    'tokenCount2 = "1234567890123456"',
    'curl https://cdn.example.com/a?key=user-profile-settings-page',
    '--token production-service-account-name',
    'docker run --secret my-app-database-password app',
  ]) {
    expect([s, hits(s)]).toEqual([s, 0])
  }
})

test('redaction is exact', () => {
  // The capture's own offset is redacted, not an earlier copy of the same text.
  const tricky = 'secretAbC123xyzDEF = "AbC123xyzDEF"'
  expect(findSecrets(tricky)[0]?.start).toBe(tricky.lastIndexOf('AbC123xyzDEF'))
  // `#` inside an unquoted value is part of it.
  expect(redact('API_KEY=Tq8vR2mZ6p#Lx9wAbCdEf').text).toBe('API_KEY=[REDACTED:generic-secret]')
  // A truncated key stops at its base64 lines; the rest of the text stays.
  const cut = '-----BEGIN ' + 'PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B\nand then the design notes stay visible'
  expect(redact(cut).text).toBe('[REDACTED:private-key]\nand then the design notes stay visible')
  const tail = '-----BEGIN ' + 'PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B\nAQAB\nand then notes'
  expect(redact(tail).text).toBe('[REDACTED:private-key]\nand then notes')
  expect(nameIsSecret('SECRETARY_EMAIL')).toBe(false)
  expect(nameIsSecret('clientSecret')).toBe(true)
})

test('a pasted secret is redacted before the model sees it, context too', async ($, on) => {
  let seen = ''
  let toast = ''
  let context: readonly string[] = []
  on('ui.toast', (_$, e) => {
    toast = e.text
    return { value: undefined }
  })
  on('ui.status', () => ({ value: undefined }))
  on('prompt.submit', (_$, e) => {
    seen = e.text
    context = e.context ?? []
    return { text: e.text }
  })
  await $.prompt.submit({ ...person(`use ${GH} to push`), context: [`key ${AWS}`] })
  expect(seen).toBe('use [REDACTED:github-token] to push')
  expect(context).toEqual(['key [REDACTED:aws-access-key]'])
  expect(toast).toMatch(/redacted 2 secret/)
  expect(toast).not.toContain(GH)
})

test('secrets in tool output are redacted, nested text blocks too', () => {
  const { content, findings } = scrubBlocks([
    { type: 'tool_result', tool_use_id: 't1', content: `AWS=${AWS}` },
    { type: 'tool_result', tool_use_id: 't2', content: [{ type: 'text', text: PEM }, { type: 'image', source: {} }] },
    { type: 'tool_use', id: 'x', input: { k: GH } },
  ])
  const text = JSON.stringify(content.slice(0, 2))
  expect(findings.length).toBe(2)
  expect(text).toContain('[REDACTED:aws-access-key]')
  expect(text).toContain('[REDACTED:private-key]')
  expect(text).not.toContain(AWS)
  expect(content[2]).toEqual({ type: 'tool_use', id: 'x', input: { k: GH } })
})

// A fake repository at /repo: which files git tracks or ignores, file contents,
// folders that exist, and how git misbehaves.
type Repo = {
  tracked: string[]
  ignored: string[]
  files?: Record<string, string>
  outside?: boolean
  broken?: 'rev-parse' | 'ls-files'
  huge?: string[]
}
function fakeRepo(on: On, repo: Repo) {
  const ran = (exitCode: number, stdout = '', stderr = '') => ({
    value: { exitCode, stdout, stderr, isStdoutTruncated: false, isStderrTruncated: false },
  })
  on('fs.stat', (_$, e) =>
    /^\/repo(\/src)?$/.test(e.path)
      ? { value: { kind: 'dir' as const, size: 0, mtimeMs: 0, isLink: false, realPath: e.path } }
      : { deny: 'ENOENT' },
  )
  on('fs.read', (_$, e) => {
    const text = repo.files?.[e.path]
    return text === undefined ? { deny: 'ENOENT' } : { value: text }
  })
  on('fs.exists', (_$, e) => ({ value: repo.files?.[e.path] !== undefined || (repo.huge ?? []).includes(e.path) }))
  on('process.run', (_$, e) => {
    const [, cmd] = e.argv
    const path = e.argv[e.argv.length - 1] ?? ''
    if (cmd === repo.broken) return ran(128, '', 'fatal: detected dubious ownership in repository')
    if (cmd === 'rev-parse') return repo.outside ? ran(128, '', 'fatal: not a git repository') : ran(0, 'true\n')
    if (cmd === 'ls-files') return ran(repo.tracked.includes(path) ? 0 : 1)
    if (cmd === 'check-ignore') return ran(repo.ignored.includes(path) ? 0 : 1)
    return ran(2)
  })
  on('ui.status', () => ({ value: undefined }))
}

test('writes: only git-ignored files may hold a secret inside a repo', async ($, on) => {
  let wrote = 0
  fakeRepo(on, { tracked: ['/repo/.env.production'], ignored: ['/repo/.env', '/repo/secrets.json', '/repo/.env.production'] })
  on('tool.call', () => {
    wrote += 1
    return { result: 'ok' }
  })
  const write = (file_path: string, content: string) => $.tool.call({ tool: 'Write', file_path, content })
  const committed = await write('/repo/src/config.ts', `export const k = '${STRIPE}'`)
  expect(committed.deny).toMatch(/would commit/)
  expect(committed.deny).not.toContain(STRIPE)
  expect(committed.deny).not.toContain('/repo')
  expect((await write('/repo/.env', `K=${STRIPE}`)).deny).toBeUndefined()
  expect((await write('/repo/.env.local', `K=${STRIPE}`)).deny).toMatch(/would commit/)
  expect((await write('/repo/.env.production', `K=${STRIPE}`)).deny).toMatch(/tracks/)
  expect((await write('/repo/.env.example', `K=${STRIPE}`)).deny).toMatch(/would commit/)
  expect((await write('/repo/secrets.json', `{"k":"${STRIPE}"}`)).deny).toBeUndefined()
  expect((await write('/repo/src/new/deep.ts', `k='${STRIPE}'`)).deny).toMatch(/would commit/)
  expect(wrote).toBe(2)
})

test('writes: outside a repo is allowed, any git failure is refused', async ($, on) => {
  const repo: Repo = { tracked: [], ignored: ['/repo/.env'], outside: true }
  fakeRepo(on, repo)
  on('tool.call', () => ({ result: 'ok' }))
  const write = () => $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: `k='${GH}'` })
  expect((await write()).deny).toBeUndefined()
  repo.outside = false
  repo.broken = 'rev-parse'
  expect((await write()).deny).toMatch(/would commit/)
  repo.broken = 'ls-files'
  expect((await write()).deny).toMatch(/would commit/)
})

test('edits: the whole file is checked, so a key assembled across the edit is caught', async ($, on) => {
  fakeRepo(on, {
    tracked: ['/repo/src/a.ts'],
    ignored: [],
    files: {
      '/repo/src/a.ts': `const k = 'ghp_PENDING'\nconst old = '${GH}' // old\n`,
      '/repo/src/doc.md': 'Markers look like [REDACTED:kind].\n',
    },
  })
  on('tool.call', () => ({ result: 'ok' }))
  const assembled = await $.tool.call({ tool: 'Edit', file_path: '/repo/src/a.ts', old_string: 'PENDING', new_string: GH_TAIL })
  expect(assembled.deny).toMatch(/credential/)
  const keep = await $.tool.call({
    tool: 'Edit',
    file_path: '/repo/src/a.ts',
    old_string: `const old = '${GH}' // old`,
    new_string: `const old = '${GH}' // new`,
  })
  expect(keep.deny).toBeUndefined()
  const marker = await $.tool.call({
    tool: 'Edit',
    file_path: '/repo/src/a.ts',
    old_string: "const k = '[REDACTED:github-token]'",
    new_string: 'const k = env()',
  })
  expect(marker.deny).toMatch(/hidden from you/)
  const write = await $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: 'K=[REDACTED:stripe-key]' })
  expect(write.deny).toMatch(/hidden from you/)
  // A file that already mentions one marker does not let a Write add more.
  const doc = await $.tool.call({
    tool: 'Write',
    file_path: '/repo/src/doc.md',
    content: 'Markers look like [REDACTED:kind].\nK=[REDACTED:stripe-key]',
  })
  expect(doc.deny).toMatch(/hidden from you/)
  // A second copy of a credential already in the file is a new occurrence.
  const copy = await $.tool.call({
    tool: 'Edit',
    file_path: '/repo/src/a.ts',
    old_string: "const k = 'ghp_PENDING'",
    new_string: `const k = '${GH}'`,
  })
  expect(copy.deny).toMatch(/credential/)
})

test('notebook cells are diffed against the cell they replace', async ($, on) => {
  const notebook = JSON.stringify({ cells: [{ id: 'c1', source: [`key = '${GH}'\n`, 'print(1)'] }] })
  fakeRepo(on, { tracked: ['/repo/n.ipynb'], ignored: [], files: { '/repo/n.ipynb': notebook } })
  on('tool.call', () => ({ result: 'ok' }))
  const keep = await $.tool.call({ tool: 'NotebookEdit', notebook_path: '/repo/n.ipynb', cell_id: 'c1', new_source: `key = '${GH}'\nprint(2)` })
  expect(keep.deny).toBeUndefined()
  const insert = await $.tool.call({
    tool: 'NotebookEdit',
    notebook_path: '/repo/n.ipynb',
    cell_id: 'c1',
    edit_mode: 'insert',
    cell_type: 'code',
    new_source: `key = '${GH}'`,
  })
  expect(insert.deny).toMatch(/credential/)
})

test('an existing file that cannot be read is refused, not checked against nothing', async ($, on) => {
  fakeRepo(on, { tracked: ['/repo/big.lock'], ignored: [], huge: ['/repo/big.lock'] })
  on('tool.call', () => ({ result: 'ok' }))
  const edit = await $.tool.call({ tool: 'Edit', file_path: '/repo/big.lock', old_string: 'PENDING', new_string: GH_TAIL })
  expect(edit.deny).toMatch(/could not be read/)
})

test('commands with a literal credential are refused; env references pass', async ($, on) => {
  on('ui.status', () => ({ value: undefined }))
  on('tool.call', () => ({ result: 'ok' }))
  const bad = await $.tool.call({ tool: 'Bash', command: `curl -H "x-api-key: ${ANT}" https://api.anthropic.com` })
  expect(bad.deny).toMatch(/environment variable/)
  expect(bad.deny).not.toContain(ANT)
  const inline = await $.tool.call({ tool: 'Bash', command: `cd app && API_TOKEN=${OPAQUE} ./deploy.sh` })
  expect(inline.deny).toMatch(/environment variable/)
  const good = await $.tool.call({ tool: 'Bash', command: 'curl -H "x-api-key: $ANTHROPIC_API_KEY" https://api.anthropic.com' })
  expect(good.deny).toBeUndefined()
})
