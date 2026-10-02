// Counts only: the mod never keeps a secret, a hash of one, or where it was.
export type Tally = { redacted: number; blocked: number; kinds: Record<string, number> }

declare module 'claude-code' {
  interface PluginState {
    'secret-sentry': { tally: Tally }
  }
}
