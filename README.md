# Secret Sentry

![Secret Sentry demo](media/demo.gif)

A key read from a file reaches the model as `[REDACTED:stripe-key]`, and an attempt to hardcode a live key into a tracked file is refused (screenshots: [redacted read](media/01-redacted-read.png), [write refused](media/02-write-refused.png)).

A Claude Code mod that keeps credentials out of the model's context and out of your repo.

**In (redaction)**
- Secrets you paste into a prompt are replaced with `[REDACTED:<kind>]` before the model sees them, and a toast tells you how many.
- Secrets in tool output entering the conversation (file reads, command output, fetched pages) are redacted the same way, at the moment the row is stored (`session.append`).

**Out (blocking)**
- `Write` / `Edit` / `NotebookEdit` that would *introduce* a credential into a file git tracks or would commit is refused. Edits are checked against the whole file as it would be after the edit, so a key assembled across the edit boundary is caught; notebook edits are diffed against the cell they replace.
- `Bash` commands containing a literal credential are refused with advice to use an environment variable.
- Edits that would write a `[REDACTED:…]` marker back into a file are refused, so a redacted secret is never overwritten with marker text.

**Detectors:** AWS access/secret keys, GitHub (`ghp_`/`gho_`/`github_pat_`…), Slack `xox*`, Stripe live keys, Anthropic/OpenAI keys, Google API keys, PEM private keys, JWTs, Slack/Discord webhooks, credentials in URLs (`scheme://user:pass@host`, `?api_key=`), `Authorization:` / `x-api-key:` headers, `--password=` / `curl -u` flags, and labelled assignments (quoted, unquoted anywhere on a line, YAML, `env["KEY"] =`) with an entropy check. Labels are matched by word segment, so `SECRETARY_EMAIL` or `MAX_TOKENS` don't count; values that look like paths, URLs or kebab-case identifiers don't count either. Placeholders (`your-key-here`, `xxxx`, `${VAR}`, `process.env…`, AWS's documented example key) pass.

**Which files may hold a secret:** inside a repository, only files git ignores, and never a file git tracks. A `.env` file's name alone is not enough, since an un-ignored `.env` gets committed by `git add .`. `.env.example`-style templates never may. Files outside any repository may. Paths are resolved through symlinks, and any git result other than a clean answer (an error other than "not a git repository") refuses the write.

**Limits:** detection is pattern-based. Low-entropy passwords (`hunter2`), hyphenated lowercase passphrases under a free-form name (`DB_PASSWORD=correct-horse-battery-staple`, which can't be told apart from an identifier without a dictionary), short `-p`/`-a` flags (ambiguous with ports), space-separated forms (`ENV KEY value`, `.netrc`), YAML block scalars, and a secret split across two separate blocks are not flagged. On Windows, path placement only understands `/`, so every credential write fails closed (it is refused), including writes to ignored files. A file that exists but can't be read (over 4 MiB) refuses edits rather than skipping the check. A denied command still appears in the model's own tool-use block; the API doesn't allow rewriting that block. Bash is checked for *literal* credentials only, so indirect writes (`cp .env src/config.ts`, `printf "$KEY" > file`) are not caught.

The mod never stores or echoes a secret: state holds only counts per kind. The status line shows `🔒 N redacted · M blocked`.

## Install

```
/plugin marketplace add ccdwyer/claude-mods
/plugin install secret-sentry@ccdwyer-mods
/reload-plugins
```

## Develop

```
claude plugin validate .
claude plugin test .
```
