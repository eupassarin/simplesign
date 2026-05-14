import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert } from '@/components/ui/alert'
import { FileSearch, Loader2 } from 'lucide-react'
import { validateFile, browseValidate } from '@/lib/api'
import { useWebViewMessage } from '@/lib/webview'

function PropGrid({ children }: { children: React.ReactNode }) {
  return <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5 text-sm">{children}</dl>
}

function Prop({ label, value }: { label: string; value: React.ReactNode }) {
  if (value === null || value === undefined || value === '') return null
  return (
    <>
      <dt className="text-muted-foreground whitespace-nowrap">{label}</dt>
      <dd>{value}</dd>
    </>
  )
}

function VCheck({ label, valid }: { label: string; valid: boolean }) {
  return (
    <span className={valid ? 'text-success' : 'text-destructive'}>
      {valid ? '✓' : '✗'} {label}
    </span>
  )
}

export default function ValidatePage() {
  const [data, setData] = useState<any[] | null>(null)
  const [status, setStatus] = useState<{ type: 'idle' | 'loading' | 'success' | 'error'; message?: string }>({ type: 'idle' })

  useWebViewMessage((data) => {
    if (data?.action === 'validateFile' && data.file) {
      doValidate(data.file)
    }
  })

  const doValidate = async (filePath: string) => {
    setStatus({ type: 'loading' })
    setData(null)
    try {
      const result = await validateFile(filePath)
      const valid = result.filter((r: any) => r.isValid).length
      const total = result.length
      setData(result)
      setStatus({
        type: 'success',
        message: total === valid ? `All ${total} signature(s) valid` : `${valid}/${total} signature(s) valid`
      })
    } catch (e: any) {
      setStatus({ type: 'error', message: e.message })
    }
  }

  const userSigs = data?.filter(r => !r.isDocumentTimestamp) || []
  const archiveTs = data?.filter(r => r.isDocumentTimestamp) || []

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h2 className="text-xl font-semibold">Validate Signatures</h2>
        <p className="text-sm text-muted-foreground mt-1">Verify the integrity and validity of digital signatures.</p>
      </div>

      <Button variant="outline" onClick={() => browseValidate()} className="gap-2">
        <FileSearch className="h-4 w-4" />
        Select PDF to Validate
      </Button>

      {status.type === 'loading' && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Validating...
        </div>
      )}
      {status.type === 'error' && (
        <p className="text-sm text-destructive">Error: {status.message}</p>
      )}
      {status.type === 'success' && (
        <p className="text-sm text-success">✓ {status.message}</p>
      )}

      {data && (
        <div className="space-y-4">
          {userSigs.map((r, i) => (
            <Card key={i} className={r.isValid ? 'border-success/30' : 'border-destructive/30'}>
              <CardContent className="p-4 space-y-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant={r.isValid ? 'success' : 'destructive'}>
                    {r.isValid ? '✓ VALID' : '✗ INVALID'}
                  </Badge>
                  <span className="font-medium">Signature {i + 1}/{userSigs.length}: {r.fieldName}</span>
                  {r.level && <Badge>{r.level}</Badge>}
                </div>

                <PropGrid>
                  <Prop label="Signer" value={r.signerName ? <strong>{r.signerName}</strong> : null} />
                  <Prop label="SubFilter" value={r.subFilter} />
                  <Prop label="Level" value={r.level} />
                  <Prop label="Algorithm" value={r.digestAlgorithm} />
                  <Prop label="Signed" value={r.signingTime ? new Date(r.signingTime).toLocaleString() : null} />
                </PropGrid>

                <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs pt-1">
                  <VCheck label="Integrity" valid={r.isIntegrityValid} />
                  <VCheck label="Signature" valid={r.isSignatureValid} />
                  <VCheck label="Chain" valid={r.isCertificateChainValid} />
                  <VCheck label="Revocation" valid={r.isNotRevoked} />
                  {r.hasValidTimestamp != null && <VCheck label="Timestamp" valid={r.hasValidTimestamp} />}
                </div>

                {r.errors?.length > 0 && (
                  <div className="space-y-1">
                    {r.errors.map((e: string, j: number) => (
                      <p key={j} className="text-xs text-destructive">⚠ {e}</p>
                    ))}
                  </div>
                )}
                {r.warnings?.length > 0 && (
                  <div className="space-y-1">
                    {r.warnings.map((w: string, j: number) => (
                      <p key={j} className="text-xs text-warning">⚠ {w}</p>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}

          {archiveTs.map((r, i) => (
            <Card key={`ts-${i}`} className={r.isValid ? 'border-success/30' : 'border-destructive/30'}>
              <CardContent className="p-4 space-y-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant={r.isValid ? 'success' : 'destructive'}>
                    {r.isValid ? '✓ VALID' : '✗ INVALID'}
                  </Badge>
                  <span className="font-medium">Archive TS {i + 1}/{archiveTs.length}: {r.fieldName}</span>
                  <Badge variant="secondary">ETSI.RFC3161</Badge>
                </div>

                <PropGrid>
                  <Prop label="TSA" value={r.signerName ? <strong>{r.signerName}</strong> : null} />
                  <Prop label="Algorithm" value={r.digestAlgorithm} />
                  <Prop label="Stamped" value={r.signingTime ? new Date(r.signingTime).toLocaleString() : null} />
                </PropGrid>

                <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs pt-1">
                  <VCheck label="Integrity" valid={r.isIntegrityValid} />
                  <VCheck label="Signature" valid={r.isSignatureValid} />
                  <VCheck label="Chain" valid={r.isCertificateChainValid} />
                  <VCheck label="Revocation" valid={r.isNotRevoked} />
                </div>

                {r.errors?.length > 0 && (
                  <div className="space-y-1">
                    {r.errors.map((e: string, j: number) => (
                      <p key={j} className="text-xs text-destructive">⚠ {e}</p>
                    ))}
                  </div>
                )}
                {r.warnings?.length > 0 && (
                  <div className="space-y-1">
                    {r.warnings.map((w: string, j: number) => (
                      <p key={j} className="text-xs text-warning">⚠ {w}</p>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
