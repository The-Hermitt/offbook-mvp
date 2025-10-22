export function normalizeChar(name: string): string {
  return name
    .toUpperCase()
    .trim()
    .replace(/\s*\(O\.S\.\)/gi, '')
    .replace(/\s*\(V\.O\.\)/gi, '')
    .replace(/\s*\(CONT'D\)/gi, '')
    .replace(/\s*\(CONT\)/gi, '')
    .trim();
}
