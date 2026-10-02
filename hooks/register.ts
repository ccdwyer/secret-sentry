import { atom, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { Tally } from '../types'
import { MARK, applyEdit, introduced, kinds, markers, redact, scrubBlocks } from './detect'
import type { Finding } from './detect'

const tally = atom({ plugin: 'secret-sentry', key: 'tally' } as const, { redacted: 0, blocked: 0, kinds: {} })

// Env templates are meant to be committed, whatever .gitignore says.
const ENV_TEMPLATE = /(^|\/)\.env\.(example|sample|template|dist|defaults)$/

// Bookkeeping only: a failure here must never stop a redaction or a refusal.
async function count($: EngineInterface, found: Finding[], key: 'redacted' | 'blocked') {
  try {
    await tallyUp($, found, key)
  } catch {
    // The decision stands without the tally.
  }
}

async function tallyUp($: EngineInterface, found: Finding[], key: 'redacted' | 'blocked') {
  const next = await update($, tally, (t): Tally => {
    const k = { ...t.kinds }
    for (const f of found) k[f.kind] = (k[f.kind] ?? 0) + 1
    return { ...t, [key]: t[key] + found.length, kinds: k }
  })
  $.ui.status(`🔒 secret-sentry: ${next.redacted} redacted · ${next.blocked} blocked`)
}

// Where a path lands with links resolved, and the nearest folder that exists
// (git needs a real working directory; a Write may create new folders).
async function place($: EngineInterface, path: string): Promise<{ real: string; dir: string } | null> {
  const own = await $.fs.stat(path, { resolve: true }).catch(() => undefined)
  if (own?.realPath !== undefined) {
    return { real: own.realPath, dir: own.realPath.replace(/\/[^/]*$/, '') || '/' }
  }
  const parts = path.split('/')
  const rest: string[] = []
  while (parts.length > 1) {
    rest.unshift(parts.pop() ?? '')
    const folder = parts.join('/') || '/'
    const dir = await $.fs.stat(folder, { resolve: true }).catch(() => undefined)
    if (dir?.realPath !== undefined && dir.kind === 'dir') {
      const base = dir.realPath.replace(/\/$/, '')
      return { real: `${base}/${rest.join('/')}`, dir: dir.realPath }
    }
  }
  return null
}

const git = ($: EngineInterface, dir: string, args: string[]) =>
  $.process.run(['git', ...args], { cwd: dir, timeoutMs: 5000, env: { LC_ALL: 'C', LANG: 'C' } })

// May this file hold a secret? Only if git ignores it (a .env file included:
// its name alone does not keep it out of a commit) or it lives outside any
// repository. Never if git tracks it. Anything git cannot classify is refused.
async function mayHoldSecrets($: EngineInterface, path: string): Promise<boolean> {
  try {
    const where = await place($, path)
    if (where === null) return false
    const { real, dir } = where
    if (ENV_TEMPLATE.test(path) || ENV_TEMPLATE.test(real)) return false

    const inside = await git($, dir, ['rev-parse', '--is-inside-work-tree'])
    if (inside.exitCode !== 0) {
      // Only a clear "not a repository" counts as outside; any other failure is unknown.
      return /not a git repository/i.test(inside.stderr)
    }
    if (inside.stdout.trim() !== 'true') return false

    // ls-files: 0 tracked, 1 not tracked, anything else unknown.
    const tracked = await git($, dir, ['ls-files', '--error-unmatch', '--', real])
    if (tracked.exitCode !== 1) return false
    // check-ignore: 0 ignored, 1 not ignored, anything else unknown.
    const ignored = await git($, dir, ['check-ignore', '-q', '--no-index', '--', real])
    return ignored.exitCode === 0
  } catch {
    return false
  }
}

const hidden = (where: string) =>
  `secret-sentry: ${where} contains ${MARK}…] markers. Those stand for real secrets hidden from you; ` +
  `writing them would replace the real values with the marker text. Leave those lines out of your ` +
  `edit (edit around them), or ask the user to make that change.`

export const register: Register = on => {
  // IN: what the person pastes, and any context riding along with the prompt.
  on('prompt.submit', async ($, e, next) => {
    const { text, findings } = redact(e.text)
    const context = e.context?.map(block => {
      const r = redact(block)
      findings.push(...r.findings)
      return r.text
    })
    if (findings.length === 0) return next(e)
    await count($, findings, 'redacted')
    $.ui.toast(`secret-sentry: redacted ${findings.length} secret(s) from your prompt (${kinds(findings)})`)
    return next(context === undefined ? { ...e, text } : { ...e, text, context })
  })

  // IN: every row the model reads from outside itself: tool output (file reads,
  // command output, fetched pages), hook and plugin context, deliveries.
  on('session.append', async ($, e, next) => {
    if (e.message.role !== 'user') return next(e)
    const { content, findings } = scrubBlocks(e.message.content)
    if (findings.length === 0) return next(e)
    await count($, findings, 'redacted')
    return next({ ...e, message: { ...e.message, content } })
  })

  // OUT: file writes and shell commands.
  on('tool.call', async ($, e, next) => {
    let path: string
    // What the model wrote, for the marker check, and the file before and after,
    // for the introduced-secret check (so a key split across an edit boundary is seen).
    let wrote: string
    let before = ''
    let after: string
    if (e.tool === 'Write') {
      path = e.file_path
      wrote = e.content
      after = e.content
      const file = await readText($, path)
      if (file === null) return { deny: unreadable }
      before = file
    } else if (e.tool === 'Edit') {
      path = e.file_path
      wrote = e.new_string
      if (e.old_string.includes(MARK)) return { deny: hidden('old_string') }
      if (markers(e.new_string) > 0) return { deny: hidden('new_string') }
      const file = await readText($, path)
      if (file === null) return { deny: unreadable }
      const edited = applyEdit(file, e.old_string, e.new_string, e.replace_all === true)
      before = edited === null ? e.old_string : file
      after = edited ?? e.new_string
    } else if (e.tool === 'NotebookEdit') {
      path = e.notebook_path
      wrote = e.new_source ?? ''
      after = wrote
      const notebook = e.edit_mode === 'insert' ? '' : await readText($, path)
      if (notebook === null) return { deny: unreadable }
      before = e.edit_mode === 'insert' ? '' : cellSource(notebook, e.cell_id)
    } else if (e.tool === 'Bash' || (e.tool === 'Monitor' && e.command !== undefined)) {
      const found = introduced('', e.command ?? '')
      if (found.length === 0) return next(e)
      await count($, found, 'blocked')
      return {
        deny:
          `secret-sentry: this command contains a literal credential (${kinds(found)}). Do not put ` +
          `secrets in commands: they land in shell history, logs and the transcript. Reference an ` +
          `environment variable instead (for example "$API_KEY"), and ask the user to export it.`,
      }
    } else {
      return next(e)
    }

    // More markers than the file already had means real values would be overwritten.
    if (markers(wrote) > markers(before)) return { deny: hidden('this content') }
    const found = introduced(before, after)
    if (found.length === 0 || (await mayHoldSecrets($, path))) return next(e)
    await count($, found, 'blocked')
    return {
      deny:
        `secret-sentry: this would write a credential (${kinds(found)}) into a file git tracks or ` +
        `would commit. Read it from configuration instead (an environment variable or a ` +
        `git-ignored .env file) and leave a placeholder here.`,
    }
  })
}

// The file's text: '' when it does not exist yet, null when it exists but cannot
// be read (too large, unreadable), so a check that needs it cannot be done.
async function readText($: EngineInterface, path: string): Promise<string | null> {
  try {
    return await $.fs.read(path)
  } catch {
    const exists = await $.fs.exists(path).catch(() => true)
    return exists ? null : ''
  }
}

const unreadable =
  'secret-sentry: this file exists but could not be read (it may be too large), so the change ' +
  'cannot be checked for credentials. Make a smaller change with Bash tools, or ask the user.'

// One notebook cell's source, or '' when the notebook or cell cannot be read.
function cellSource(notebook: string, id: string | undefined): string {
  try {
    const cells = (JSON.parse(notebook) as { cells?: { id?: string; source?: string | string[] }[] }).cells ?? []
    const cell = id === undefined ? cells[0] : cells.find(c => c.id === id)
    const source = cell?.source ?? ''
    return Array.isArray(source) ? source.join('') : source
  } catch {
    return ''
  }
}
