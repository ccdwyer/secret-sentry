// Secret detectors. Provider rules match a structural prefix and are trusted;
// labelled rules (`password = ...`) have no structure to lean on, so the name
// must really name a secret, and the value must have entropy and not look like
// a placeholder, a path or an identifier. A false positive hides text from the
// model or blocks a legitimate write; a false negative leaks.

export type Finding = { kind: string; start: number; end: number; value: string }

type Rule = {
  kind: string
  pattern: RegExp
  // Which capture group is the secret itself (the first that matched, when
  // several alternatives each have one); 0 for the whole match.
  group?: number | number[]
  // Which capture group is the label naming it, checked by nameIsSecret.
  name?: number
  // Minimum Shannon entropy (bits per char) of the secret.
  entropy?: number
  // The value has no structure of its own: apply the placeholder filter.
  labelled?: boolean
  // The value sits under a free-form name: also reject words, paths and identifiers.
  // (Structural positions such as URLs, headers and flags are evidence enough.)
  shaped?: boolean
  // Extra check on the value.
  test?: (value: string) => boolean
}

const hasDigit = (v: string) => /\d/.test(v)

// A label naming a secret, matched by segment so SECRETARY, AUTHOR, OAUTH_AUDIENCE
// and MAX_TOKENS do not count. Segments come from _ - . and camelCase.
const SECRET_WORDS = new Set(['password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'credential', 'credentials', 'passphrase'])
const SECRET_PAIRS = new Set([
  'api key', 'access key', 'private key', 'secret key', 'client secret', 'auth token', 'access token',
  'refresh token', 'session token', 'bearer token', 'master key', 'encryption key', 'signing key',
])
// `token` next to these names a count or a pointer, not a credential.
const NOT_AFTER = new Set(['count', 'counts', 'id', 'ids', 'index', 'file', 'path', 'limit', 'size', 'type', 'usage', 'budget', 'length', 'name'])
const NOT_BEFORE = new Set(['max', 'min', 'num', 'total', 'remaining'])
// A name ending in one of these describes a secret without holding it: a count,
// a time, a kind (`tokenExpiresAt`, `token_count`). Never a credential.
const METADATA_SUFFIX = new Set([
  'count', 'counts', 'length', 'len', 'size', 'limit', 'index', 'budget', 'usage', 'type', 'kind',
  'at', 'expires', 'expiry', 'expiration', 'ttl', 'age', 'created', 'updated', 'issued', 'scope', 'scopes',
])
// A name ending in one of these points at a secret (its file, path, env var,
// header or URL), but the value is only exempt when it also looks like a pointer:
// `PASSWORD_FILE=CorrectHorse99!` is still a password.
const POINTER_SUFFIX = new Set([
  'file', 'files', 'filename', 'path', 'paths', 'dir', 'directory', 'name', 'names', 'env', 'var', 'variable',
  'field', 'header', 'url', 'uri', 'endpoint', 'arn', 'ref', 'location',
])
// Words whose `_id` is itself a secret (Vault's `secret_id`), unlike `refresh_token_id`.
const ID_IS_SECRET = new Set(['secret', 'password', 'passwd', 'pwd', 'passphrase', 'credential', 'credentials'])

function nameParts(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .map(part => part.replace(/\d+$/, ''))
    .filter(Boolean)
}

// How a secret-looking name relates to its value: 'pointer' names are exempt only
// when the value is a pointer too; 'id' names are opaque identifiers.
export function nameRole(name: string): 'holds' | 'pointer' | 'id' | 'metadata' {
  const parts = nameParts(name)
  const last = parts[parts.length - 1] ?? ''
  if (parts.length < 2) return 'holds'
  if (METADATA_SUFFIX.has(last)) return 'metadata'
  if (last === 'id' || last === 'ids') return parts.slice(0, -1).some(p => ID_IS_SECRET.has(p)) ? 'holds' : 'id'
  if (POINTER_SUFFIX.has(last)) return 'pointer'
  return 'holds'
}

// A value that names where a secret lives instead of being one.
export function looksLikePointer(value: string): boolean {
  if (isPathLike(value)) return true
  if (/^arn:/i.test(value)) return true
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return true
  if (isEnvName(value)) return true
  // A bare file name with an extension (`token.txt`, `client-secret.json`).
  if (/^[\w.-]+\.(?:txt|json|ya?ml|pem|key|env|cfg|conf|ini|toml|p12|pfx|crt)$/i.test(value)) return true
  // A short header name (`X-Api-Key`, `Authorization`).
  if (/^[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*$/.test(value) && value.length <= 32 && /-|^[A-Z][a-z]+$/.test(value)) return true
  return false
}

// The name of an environment variable (`DB_PASSWORD_PROD`, `API_KEY_V2`), not a
// value: upper-case words, at least one short one, digits only in a trailing `V2`.
// A shouted passphrase (`CORRECT_HORSE_BATTERY_STAPLE`) or code (`AB12_CD34`) is not.
function isEnvName(value: string): boolean {
  const segs = value.split('_')
  if (segs.length < 2) return false
  const body = /^V\d{1,3}$/.test(segs[segs.length - 1] ?? '') ? segs.slice(0, -1) : segs
  if (body.length < 2 && segs.length === body.length) return false
  if (!body.every(s => /^[A-Z]+$/.test(s))) return false
  if (!body.some(s => s.length <= 3)) return false
  return !body.every(s => s.length >= 5)
}
export function nameIsSecret(name: string): boolean {
  const parts = nameParts(name)
  if (parts.length === 1 && parts[0] === 'pass') return true
  const role = nameRole(name)
  if (role === 'metadata' || role === 'id') return false
  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i] ?? ''
    if (part === 'token' && (NOT_AFTER.has(parts[i + 1] ?? '') || NOT_BEFORE.has(parts[i - 1] ?? ''))) continue
    if (SECRET_WORDS.has(part)) return true
    if (i + 1 < parts.length && SECRET_PAIRS.has(`${part} ${parts[i + 1]}`)) return true
  }
  return false
}

// Assignment value characters for unquoted values: no whitespace or quotes.
const BARE = `[^\\s'"\`]`
const NAME = `[A-Za-z_][\\w.-]*`

// Every pattern carries `d` so a capture's exact offset is known.
const RULES: Rule[] = [
  {
    kind: 'private-key',
    pattern: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/dg,
  },
  // A truncated key: the header and the base64 lines that follow it, nothing more.
  {
    kind: 'private-key',
    pattern:
      /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[ \t]*(?:\r?\n(?:Proc-Type|DEK-Info):[^\n]*)*(?:\r?\n(?=\r?\n))?(?:[A-Za-z0-9+/=]{16,}|(?:\r?\n[A-Za-z0-9+/=]{16,}){1,200}(?:\r?\n[A-Za-z0-9+/]{1,15}={0,2}(?=\r?\n|$))?)/dg,
  },
  { kind: 'aws-access-key', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/dg },
  {
    kind: 'aws-secret-key',
    pattern: /\baws_?secret_?access_?key\b["']?\s*(?:[:=]|\s)\s*["']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/dgi,
    group: 1,
    entropy: 4,
  },
  { kind: 'github-token', pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/dg },
  { kind: 'github-token', pattern: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/dg },
  { kind: 'slack-token', pattern: /\b(?:xox[abposrecd]|xapp)-[A-Za-z0-9.-]{10,}\b/dg, entropy: 3, test: hasDigit },
  { kind: 'slack-webhook', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/dg },
  { kind: 'discord-webhook', pattern: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{50,}/dg },
  { kind: 'stripe-key', pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/dg },
  { kind: 'anthropic-key', pattern: /\bsk-ant-[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])/dg, entropy: 3.5, test: hasDigit },
  {
    kind: 'openai-key',
    pattern: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])/dg,
    entropy: 3.5,
    // An unprefixed legacy key is random base62; kebab-case identifiers score well below 4.5.
    test: v => hasDigit(v) && (/^sk-(?:proj|svcacct|admin)-/.test(v) || entropy(v) >= 4.5),
  },
  { kind: 'google-api-key', pattern: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/dg },
  { kind: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,}/dg },
  // scheme://user:password@host
  {
    kind: 'url-credentials',
    pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@'"]*:([^\s@'"]{6,})@[^\s'"]+/dgi,
    group: 1,
    entropy: 2.5,
    labelled: true,
    // `host:8080/path@x` is a port and a path, not a password.
    test: v => !/^\d{1,5}(?:\/|$)/.test(v),
  },
  // ?api_key=... / &token=... in URLs.
  {
    kind: 'url-param',
    pattern: /[?&]((?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|secret|client[_-]?secret|password))=([^\s&#'"]{12,})/dgi,
    group: 2,
    entropy: 3.5,
    labelled: true,
    shaped: true,
  },
  // Authorization: Bearer <opaque> / Basic <base64>, and API-key headers.
  {
    kind: 'auth-header',
    pattern: /\bauthorization["']?\]?\s*[:=]\s*["']?(?:bearer|basic|token)\s+([A-Za-z0-9._~+/=-]{20,})/dgi,
    group: 1,
    entropy: 3.5,
    labelled: true,
  },
  {
    kind: 'auth-header',
    pattern: /\b(?:x-api-key|api-key|x-auth-token|private-token|x-access-token)["']?\s*:\s*["']?([A-Za-z0-9._~+/=-]{16,})/dgi,
    group: 1,
    entropy: 3.5,
    labelled: true,
  },
  // name = "value" / name: "value" / env["NAME"] = "value", quoted (spaces allowed).
  {
    kind: 'generic-secret',
    pattern: new RegExp(
      `(${NAME})["']?\\]?\\s*(?::|=|:=|=>)\\s*(?:"((?:[^"\\\\\\n]|\\\\.){8,8192})"|'((?:[^'\\\\\\n]|\\\\.){8,8192})'|\`([^\`\\n]{8,8192})\`)`,
      'dg',
    ),
    name: 1,
    group: [2, 3, 4],
    entropy: 3,
    labelled: true,
    shaped: true,
  },
  // NAME=value anywhere on a line (env files, `export`, `env`, `-e`, after `&&`), unquoted.
  {
    kind: 'generic-secret',
    pattern: new RegExp(`(?:^|[\\s;&|(:])(?:export\\s+|ENV\\s+|-e\\s+)?([A-Za-z_][A-Za-z0-9_]*)=(?!["'$])(${BARE}{8,})`, 'dgm'),
    name: 1,
    group: 2,
    entropy: 3,
    labelled: true,
    shaped: true,
  },
  // YAML and compose: `name: value` unquoted, optionally a list item.
  {
    kind: 'generic-secret',
    pattern: new RegExp(`^[ \\t]*(?:-[ \\t]+)?(${NAME})[ \\t]*:[ \\t]+(?!["'$|>&*{\\[])(${BARE}{8,})(?:[ \\t]+#.*)?[ \\t]*$`, 'dgm'),
    name: 1,
    group: 2,
    entropy: 3,
    labelled: true,
    shaped: true,
  },
  // YAML `password: correct horse battery staple`, unquoted with spaces.
  {
    kind: 'generic-secret',
    pattern: /^[ \t]*(?:-[ \t]+)?((?:[A-Za-z_][\w.-]*[_.-])?(?:password|passwd|passphrase|pwd))[ \t]*:[ \t]+(?!["'$|>&*{[])([^\s'"#][^'"#\n]*\s[^'"#\n]*?)[ \t]*(?:#.*)?$/dgim,
    name: 1,
    group: 2,
    entropy: 3,
    labelled: true,
    shaped: true,
  },
  // --password=value / --api-key value / curl -u user:password on a command line.
  {
    kind: 'cli-secret',
    pattern:
      /(?:^|\s)--?(?:password|passwd|token|api[-_]?key|secret|secret[-_]key|client[-_]secret|auth[-_]token|access[-_]token)(?:=|\s+)(?!["']?\$)(?:"([^"\n]{8,8192})"|'([^'\n]{8,8192})'|([^\s'"]{8,}))/dgi,
    group: [1, 2, 3],
    entropy: 3,
    labelled: true,
    shaped: true,
    // `--secret id=npmrc,src=.npmrc` (BuildKit) and file paths name a secret, they are not one.
    test: v => !/^(?:id|src|source|type|env|target)=/.test(v) && !isPathLike(v),
  },
  {
    kind: 'cli-secret',
    pattern: /(?:^|\s)(?:-u\s*|--user(?:=|\s+))["']?[^\s:'"]+:(?!\$)([^\s'"]{6,256})/dg,
    group: 1,
    entropy: 2.5,
    labelled: true,
  },
]

// Whole-value shapes that cannot be a live provider credential: runs of one
// character, the providers' documented example suffix, and templating. (Eight
// x's or zeros inside a random 36+ character token has odds near 1e-13.)
const STRICT_PLACEHOLDER = /^(.)\1+$|x{8,}|X{8,}|0{8,}|EXAMPLE(?:KEY)?$|<[^>]*>|\$\{|\{\{/
// For labelled values: templating anywhere, placeholder words at the edges.
// Placeholder words count only as the whole value or a separated leading/trailing word.
const PLACEHOLDER =
  /\*{3,}|\.{3}|<[^>]*>|\$\{|\{\{|%\(|^\$|process\.env|os\.environ|getenv|REDACTED|^(?:your|example|dummy|sample|fake|placeholder|changeme|change[-_]me|replace[-_]?me|insert|todo)(?:$|[-_ .])|^(?:none|null|undefined|true|false|secret|password|token)$|[-_ ](?:here|example|placeholder)$/i
const PADDING = /x{6,}|X{6,}/

function entropy(text: string): number {
  const counts = new Map<string, number>()
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let bits = 0
  for (const n of counts.values()) {
    const p = n / text.length
    bits -= p * Math.log2(p)
  }
  return bits
}

// Slash-separated names (`src/MyModule/TokenStore`, `config/secrets.yml`,
// `C:/Users/x/token.txt`): letters with at most a trailing number or an extension
// per segment. Base64 rarely fits: it mixes digits inside segments, `+` and `=`.
function isPathLike(value: string): boolean {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return true
  if (/^(?:\.{0,2}\/|~\/|[A-Za-z]:[\\/])/.test(value)) return true
  const segments = value.split(/[\\/]/)
  return segments.length >= 2 && segments.every(s => /^[A-Za-z_.][A-Za-z_.-]*\d{0,3}(?:\.\w{1,6})?$/.test(s))
}

// A value under a free-form name must look like a credential, not a word, a
// path or an identifier. Entropy decides the rest.
function shapedLooksReal(value: string, password = false): boolean {
  // A short all-letter value reads as a word; a long one is a passphrase.
  if (/^[A-Za-z]+$/.test(value) && value.length < 16) return false
  if (isPathLike(value)) return false
  // The name of an environment variable (`DB_PASSWORD_PROD`), not its value.
  if (isEnvName(value)) return false
  // kebab/snake identifiers: several lowercase segments, at least one a plain word.
  // kebab/snake identifiers: short lowercase segments, at least one a plain word,
  // none a long hex or base62 run (`prod-9f3a…`, `npm_…`). Under a password name a
  // word-shaped value is a passphrase, so the exemption does not apply there.
  const segments = value.split(/[-_.]/)
  if (
    !password &&
    segments.length >= 2 &&
    segments.every(s => /^[a-z0-9]{0,16}$/.test(s)) &&
    segments.some(s => /^[a-z]{3,}$/.test(s)) &&
    !segments.some(s => /^[0-9a-f]{12,}$/.test(s))
  ) {
    return false
  }
  return true
}

const PASSWORD_NAME = /pass(?:word|wd|phrase)?|pwd/i

export function findSecrets(text: string): Finding[] {
  const found: Finding[] = []
  for (const rule of RULES) {
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags)
    for (let m = pattern.exec(text); m !== null; m = pattern.exec(text)) {
      // A rejected candidate must not hide one nested inside it
      // (`payload = '{"password":"..."}'`): resume one character later.
      const reject = () => {
        pattern.lastIndex = m!.index + 1
      }
      const groups = Array.isArray(rule.group) ? rule.group : [rule.group ?? 0]
      const group = groups.find(g => m[g] !== undefined) ?? groups[0] ?? 0
      const value = m[group]
      const at = m.indices?.[group]
      if (value === undefined || at === undefined) {
        reject()
        continue
      }
      const name = rule.name !== undefined ? (m[rule.name] ?? '') : ''
      if (rule.name !== undefined && !nameIsSecret(name)) {
        reject()
        continue
      }
      if (rule.name !== undefined && nameRole(name) === 'pointer' && looksLikePointer(value)) {
        reject()
        continue
      }
      if (rule.kind !== 'private-key') {
        if (STRICT_PLACEHOLDER.test(value)) {
        reject()
        continue
      }
        if (rule.labelled === true && (PLACEHOLDER.test(value) || PADDING.test(value))) {
        reject()
        continue
      }
        const password = PASSWORD_NAME.test(rule.name !== undefined ? name : (m[0] ?? '').trim().split(/[=\s]/)[0] ?? '')
        if (rule.shaped === true && !shapedLooksReal(value, password)) {
        reject()
        continue
      }
      }
      if (rule.entropy !== undefined && entropy(value) < rule.entropy) {
        reject()
        continue
      }
      if (rule.test !== undefined && !rule.test(value)) {
        reject()
        continue
      }
      found.push({ kind: rule.kind, start: at[0], end: at[1], value })
    }
  }
  // Keep the earliest, longest match where rules overlap.
  found.sort((a, b) => a.start - b.start || b.end - a.end)
  const kept: Finding[] = []
  for (const f of found) {
    const last = kept[kept.length - 1]
    if (last !== undefined && f.start < last.end) continue
    kept.push(f)
  }
  return kept
}

export const MARK = '[REDACTED:'

export function redact(text: string): { text: string; findings: Finding[] } {
  const findings = findSecrets(text)
  if (findings.length === 0) return { text, findings }
  let out = ''
  let at = 0
  for (const f of findings) {
    out += text.slice(at, f.start) + `${MARK}${f.kind}]`
    at = f.end
  }
  return { text: out + text.slice(at), findings }
}

// Secrets in `after` beyond those already in `before`, counted by occurrence:
// keeping a credential where it was is fine, a new copy of it is not.
export function introduced(before: string, after: string): Finding[] {
  const had = new Map<string, number>()
  for (const f of findSecrets(before)) had.set(f.value, (had.get(f.value) ?? 0) + 1)
  return findSecrets(after).filter(f => {
    const left = had.get(f.value) ?? 0
    if (left === 0) return true
    had.set(f.value, left - 1)
    return false
  })
}

export const markers = (text: string) => text.split(MARK).length - 1

export function kinds(findings: Finding[]): string {
  const tally = new Map<string, number>()
  for (const f of findings) tally.set(f.kind, (tally.get(f.kind) ?? 0) + 1)
  return [...tally].map(([k, n]) => (n > 1 ? `${k} ×${n}` : k)).join(', ')
}

// The file as an Edit would leave it, or null when the edit would not apply.
export function applyEdit(file: string, from: string, to: string, all: boolean): string | null {
  if (from === '' || !file.includes(from)) return null
  if (all) return file.split(from).join(to)
  const at = file.indexOf(from)
  return file.slice(0, at) + to + file.slice(at + from.length)
}

type Block = { type: string; [field: string]: unknown }

// Redacts the text of a conversation row: text blocks and tool_result content,
// string or nested text blocks. Other blocks are passed through untouched.
export function scrubBlocks(content: readonly Block[]): { content: Block[]; findings: Finding[] } {
  const findings: Finding[] = []
  const scrub = (text: string) => {
    const r = redact(text)
    findings.push(...r.findings)
    return r.text
  }
  const out = content.map((block): Block => {
    if (block.type === 'text' && typeof block.text === 'string') return { ...block, text: scrub(block.text) }
    if (block.type !== 'tool_result') return block
    if (typeof block.content === 'string') return { ...block, content: scrub(block.content) }
    if (Array.isArray(block.content)) {
      return {
        ...block,
        content: block.content.map((inner: Block) =>
          inner.type === 'text' && typeof inner.text === 'string' ? { ...inner, text: scrub(inner.text) } : inner,
        ),
      }
    }
    return block
  })
  return { content: out, findings }
}
