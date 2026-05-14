import { useState, useEffect } from 'react'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from '@/components/ui/accordion'
import { KeyRound } from 'lucide-react'
import { fetchCertificates, type CertificateInfo } from '@/lib/api'
import { extractCN, formatDate } from '@/lib/format'

export default function CertificatesPage() {
  const [certs, setCerts] = useState<CertificateInfo[]>([])
  const [icpOnly, setIcpOnly] = useState(false)
  const [validOnly, setValidOnly] = useState(false)

  useEffect(() => {
    fetchCertificates().then(setCerts).catch(() => {})
  }, [])

  const filtered = certs.filter(c => {
    if (validOnly && c.expireDate && new Date(c.expireDate) < new Date()) return false
    if (icpOnly) {
      const issuer = (c.issuerName || '').toLowerCase()
      if (!issuer.includes('icp-brasil') && !issuer.includes('icp brasil') && !issuer.includes('ac ')) return false
    }
    return true
  })

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h2 className="text-xl font-semibold">Certificates</h2>
        <p className="text-sm text-muted-foreground mt-1">Signing certificates available in your personal store.</p>
      </div>

      <div className="flex items-center gap-4">
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <Switch checked={icpOnly} onCheckedChange={setIcpOnly} />
          ICP-Brasil only
        </label>
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <Switch checked={validOnly} onCheckedChange={setValidOnly} />
          Valid only
        </label>
        <span className="text-xs text-muted-foreground ml-auto">{filtered.length} certificate{filtered.length !== 1 ? 's' : ''}</span>
      </div>

      {filtered.length === 0 ? (
        <p className="text-sm text-muted-foreground py-4">No certificates match the current filters.</p>
      ) : (
        <Accordion type="single">
          {filtered.map((c, i) => {
            const expired = c.expireDate && new Date(c.expireDate) < new Date()
            const cn = extractCN(c.name)
            const issuerCn = extractCN(c.issuerName)
            return (
              <AccordionItem key={c.thumbprint} value={`cert-${i}`} className={expired ? 'opacity-60' : ''}>
                <AccordionTrigger>
                  <div className="flex items-center gap-3 text-left flex-1 min-w-0">
                    <span className={`h-2 w-2 rounded-full shrink-0 ${expired ? 'bg-destructive' : 'bg-success'}`} />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium truncate">{cn}</div>
                      <div className="text-xs text-muted-foreground truncate">{issuerCn}</div>
                    </div>
                    <div className="text-xs text-muted-foreground text-right shrink-0 mr-2">
                      <div>{formatDate(c.expireDate)}</div>
                      <div>{c.signatureAlgorithm || ''}</div>
                    </div>
                  </div>
                </AccordionTrigger>
                <AccordionContent>
                  <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs font-mono">
                    <dt className="text-muted-foreground">Subject</dt><dd>{c.name}</dd>
                    <dt className="text-muted-foreground">Issuer</dt><dd>{c.issuerName}</dd>
                    <dt className="text-muted-foreground">Thumbprint</dt><dd>{c.thumbprint}</dd>
                    <dt className="text-muted-foreground">Valid</dt><dd>{formatDate(c.notBefore)} → {formatDate(c.expireDate)}</dd>
                    <dt className="text-muted-foreground">Algorithm</dt><dd>{c.signatureAlgorithm} / {c.hashAlgorithm}</dd>
                  </dl>
                </AccordionContent>
              </AccordionItem>
            )
          })}
        </Accordion>
      )}
    </div>
  )
}
