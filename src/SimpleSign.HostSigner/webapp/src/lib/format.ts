export function extractCN(raw: string | null | undefined): string {
  if (!raw) return ''
  for (const p of raw.split(',')) {
    const t = p.trim()
    if (t.startsWith('CN=')) return t.substring(3)
  }
  return raw.length > 50 ? raw.substring(0, 47) + '…' : raw
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleDateString() } catch { return '—' }
}

export function fileName(path: string): string {
  return path.split(/[/\\]/).pop() || path
}

export function fmtSize(bytes: number | null | undefined): string {
  if (!bytes) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1048576).toFixed(1)} MB`
}

export function fmtByteRange(br: any): { text: string; valid: boolean } | null {
  if (!br) return null
  const total = br.offset2 + br.length2
  return { text: `[0 → ${total.toLocaleString()} bytes]`, valid: br.valid }
}

export function fmtDocMdp(doc: any): string {
  if (!doc?.docMdpLocked) return 'Not locked'
  const map: Record<number, string> = { 1: 'No changes allowed', 2: 'Form filling only', 3: 'Form filling + annotations' }
  return map[doc.docMdpLevel] || `Level ${doc.docMdpLevel}`
}
