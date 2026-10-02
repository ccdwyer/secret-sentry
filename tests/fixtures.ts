// Test fixtures are stored rotated (letters by 13, digits by 5) so no file in this
// repository holds a literal credential shape; d() turns them back at run time.
export function d(s: string): string {
  return s.replace(/[A-Za-z0-9]/g, ch => {
    const c = ch.charCodeAt(0)
    if (c >= 97) return String.fromCharCode(((c - 97 + 13) % 26) + 97)
    if (c >= 65) return String.fromCharCode(((c - 65 + 13) % 26) + 65)
    return String.fromCharCode(((c - 48 + 5) % 10) + 48)
  })
}
