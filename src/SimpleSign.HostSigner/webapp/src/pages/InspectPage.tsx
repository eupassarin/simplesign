import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from '@/components/ui/accordion'
import { FileSearch, Loader2 } from 'lucide-react'
import { inspectFile, browseInspect } from '@/lib/api'
import { extractCN, formatDate, fmtSize, fmtByteRange, fmtDocMdp } from '@/lib/format'
import { useWebViewMessage } from '@/lib/webview'

function PropGrid({ children }: { children: React.ReactNode }) {
  return <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5 text-sm">{children}</dl>
}

function Prop({ label, value, className }: { label: string; value: React.ReactNode; className?: string }) {
  if (value === null || value === undefined || value === '') return null
  return (
    <>
      <dt className="text-muted-foreground whitespace-nowrap">{label}</dt>
      <dd className={className}>{value}</dd>
    </>
  )
}

export default function InspectPage() {
  const [data, setData] = useState<any>(null)
  const [status, setStatus] = useState<{ type: 'idle' | 'loading' | 'success' | 'error'; message?: string }>({ type: 'idle' })

  useWebViewMessage((data) => {
    if (data?.action === 'inspectFile' && data.file) {
      doInspect(data.file)
    }
  })

  const doInspect = async (filePath: string) => {
    setStatus({ type: 'loading' })
    setData(null)
    try {
      const result = await inspectFile(filePath)
      setData(result)
      const sigCount = result.signatures?.length || 0
      setStatus({ type: 'success', message: `${sigCount} signature(s) found` })
    } catch (e: any) {
      setStatus({ type: 'error', message: e.message })
    }
  }

  const sigs = data?.signatures?.filter((s: any) => !s.isDocumentTimestamp) || []
  const tss = data?.signatures?.filter((s: any) => s.isDocumentTimestamp) || []
  const doc = data?.document

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h2 className="text-xl font-semibold">Inspect Document</h2>
        <p className="text-sm text-muted-foreground mt-1">Analyze digital signatures in a PDF document.</p>
      </div>

      <Button variant="outline" onClick={() => browseInspect()} className="gap-2">
        <FileSearch className="h-4 w-4" />
        Select PDF to Inspect
      </Button>

      {status.type === 'loading' && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Inspecting...
        </div>
      )}
      {status.type === 'error' && (
        <p className="text-sm text-destructive">Error: {status.message}</p>
      )}
      {status.type === 'success' && (
        <p className="text-sm text-success">{status.message}</p>
      )}

      {data && (
        <div className="space-y-4">
          {/* Document card */}
          <Card>
            <CardContent className="p-4 space-y-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-medium">📄 Document</span>
                <Badge>{sigs.length} sig{sigs.length !== 1 ? 's' : ''}</Badge>
                {tss.length > 0 && <Badge variant="secondary">{tss.length} TS</Badge>}
                {doc?.dss?.present
                  ? <Badge variant="success">✓ DSS</Badge>
                  : <Badge variant="warning">✗ No DSS</Badge>}
              </div>
              <PropGrid>
                <Prop label="Signatures" value={sigs.length} />
                {tss.length > 0 && <Prop label="Archive Timestamps" value={tss.length} />}
                <Prop label="Encrypted" value={doc?.encrypted ? 'Yes' : 'No'} />
                <Prop label="DocMDP" value={fmtDocMdp(doc)} />
                <Prop label="PDF/A" value={doc?.pdfA || 'Not detected'} />
              </PropGrid>
              {doc?.dss?.present ? (
                <div className="border-t pt-3 space-y-2">
                  <p className="text-xs font-medium text-success">✓ Document Security Store (DSS)</p>
                  <PropGrid>
                    <Prop label="Certificates" value={doc.dss.certificates} />
                    <Prop label="CRLs" value={doc.dss.crls} />
                    <Prop label="OCSPs" value={doc.dss.ocsps} />
                    <Prop label="VRI" value={doc.dss.hasVri ? '✓ Present' : '✗ Missing'} />
                  </PropGrid>
                </div>
              ) : (
                <p className="text-xs text-warning">⚠ DSS not embedded — required for PAdES B-LT / B-LTA</p>
              )}
            </CardContent>
          </Card>

          {/* Signatures */}
          {sigs.length > 0 && (
            <Accordion type="multiple" defaultValue={sigs.map((_: any, i: number) => `sig-${i}`)}>
              {sigs.map((sig: any, i: number) => (
                <AccordionItem key={i} value={`sig-${i}`}>
                  <AccordionTrigger>
                    <div className="flex items-center gap-2 flex-wrap text-left">
                      <span>✍️ Signature {i + 1}/{sigs.length}: {sig.fieldName}</span>
                      <Badge variant="default">{sig.level || 'Unknown'}</Badge>
                      {sig.timestamp
                        ? <Badge variant="success">✓ TS</Badge>
                        : <Badge variant="warning">✗ No TS</Badge>}
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <SignatureDetails sig={sig} />
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>
          )}

          {/* Archive Timestamps */}
          {tss.length > 0 && (
            <Accordion type="multiple" defaultValue={tss.map((_: any, i: number) => `ts-${i}`)}>
              {tss.map((sig: any, i: number) => (
                <AccordionItem key={i} value={`ts-${i}`}>
                  <AccordionTrigger>
                    <div className="flex items-center gap-2 flex-wrap text-left">
                      <span>🕐 Archive TS {i + 1}/{tss.length}: {sig.fieldName}</span>
                      <Badge variant="secondary">ETSI.RFC3161</Badge>
                      {sig.signer?.isExpired && <Badge variant="destructive">TSA Expired</Badge>}
                    </div>
                  </AccordionTrigger>
                  <AccordionContent>
                    <TimestampDetails sig={sig} />
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>
          )}
        </div>
      )}
    </div>
  )
}

function SignatureDetails({ sig }: { sig: any }) {
  const br = fmtByteRange(sig.byteRange)
  return (
    <div className="space-y-4">
      <PropGrid>
        <Prop label="SubFilter" value={sig.subFilter} />
        <Prop label="Level" value={sig.level} />
        <Prop label="Digest" value={sig.digestAlgorithm} />
        <Prop label="Algorithm" value={sig.signatureAlgorithm} />
        <Prop label="Signed" value={sig.signingTime ? new Date(sig.signingTime).toLocaleString() : null} />
        <Prop label="PDF Time" value={sig.pdfDeclaredTime ? new Date(sig.pdfDeclaredTime).toLocaleString() + ' (declared)' : null} />
        <Prop label="Reason" value={sig.reason} />
        <Prop label="Location" value={sig.location} />
        <Prop label="Contact" value={sig.contactInfo} />
        <Prop label="Name" value={sig.declaredSignerName} />
        <Prop label="ESS CertV2" value={sig.hasSigningCertificateV2 ? '✓ Present' : '✗ Missing'} className={sig.hasSigningCertificateV2 ? 'text-success' : 'text-destructive'} />
        <Prop label="Commitment" value={sig.commitmentTypeOid} />
        <Prop label="Policy" value={sig.signaturePolicyOid} />
        <Prop label="CMS Size" value={fmtSize(sig.cmsDataSize)} />
        {br && <Prop label="Byte Range" value={<>{br.text} {br.valid ? <span className="text-success">✓</span> : <span className="text-destructive">✗</span>}</>} />}
        <Prop label="Contents" value={fmtSize(sig.byteRange?.contentsLength)} />
      </PropGrid>

      {/* Manifest */}
      {sig.manifest && (
        <div className="border-t pt-3 space-y-2">
          <p className="text-xs font-medium">📋 Signature Manifest (Lei 14.063)</p>
          <PropGrid>
            <Prop label="Signer" value={sig.manifest.signerName} />
            <Prop label="CPF" value={sig.manifest.cpf} />
            <Prop label="Email" value={sig.manifest.email} />
            <Prop label="IP" value={sig.manifest.ip} />
            <Prop label="Auth Method" value={sig.manifest.authMethod} />
            <Prop label="Timestamp" value={sig.manifest.timestamp ? new Date(sig.manifest.timestamp).toLocaleString() : null} />
            <Prop label="Institution" value={sig.manifest.institution} />
            <Prop label="CNPJ" value={sig.manifest.cnpj} />
            <Prop label="Commitment" value={sig.manifest.commitment} />
          </PropGrid>
        </div>
      )}

      {/* Signer cert */}
      {sig.signer && (
        <div className="border-t pt-3 space-y-2">
          <p className="text-xs font-medium">👤 Signer Certificate</p>
          <CertDetails cert={sig.signer} />
        </div>
      )}

      {/* Timestamp */}
      {sig.timestamp && (
        <div className="border-t pt-3 space-y-2">
          <p className="text-xs font-medium text-success">🕐 RFC 3161 Timestamp</p>
          <PropGrid>
            <Prop label="Time" value={<strong>{new Date(sig.timestamp.time).toLocaleString()}</strong>} />
            <Prop label="TSA" value={sig.timestamp.tsaSubject} />
            <Prop label="TSA Issuer" value={sig.timestamp.tsaIssuer} />
            <Prop label="Hash" value={sig.timestamp.hashAlgorithm} />
            <Prop label="Policy" value={sig.timestamp.policyOid} />
            <Prop label="Serial" value={sig.timestamp.serialNumber} />
            <Prop label="Token Size" value={fmtSize(sig.timestamp.tokenSize)} />
          </PropGrid>
        </div>
      )}

      {/* Embedded certs */}
      <EmbeddedCerts certs={sig.embeddedCertificates} />
    </div>
  )
}

function TimestampDetails({ sig }: { sig: any }) {
  const br = fmtByteRange(sig.byteRange)
  return (
    <div className="space-y-4">
      <PropGrid>
        <Prop label="Purpose" value="Archive protection layer — protects all preceding signatures (LTA)" />
        <Prop label="SubFilter" value={sig.subFilter} />
        <Prop label="Hash" value={sig.digestAlgorithm} />
        <Prop label="Time" value={sig.signingTime ? new Date(sig.signingTime).toLocaleString() : null} />
        {br && <Prop label="Covers" value={<>{br.text} {br.valid ? <span className="text-success">✓</span> : <span className="text-destructive">✗</span>}</>} />}
        <Prop label="Token Size" value={fmtSize(sig.cmsDataSize)} />
      </PropGrid>

      {sig.signer && (
        <div className="border-t pt-3 space-y-2">
          <p className="text-xs font-medium">🏢 TSA Certificate</p>
          <PropGrid>
            <Prop label="Subject" value={<strong>{sig.signer.subject}</strong>} />
            <Prop label="Issuer" value={sig.signer.issuer} />
            <Prop label="Valid" value={`${formatDate(sig.signer.notBefore)} → ${formatDate(sig.signer.notAfter)}`} />
            <Prop label="Expired" value={sig.signer.isExpired ? '✗ Yes' : '✓ No'} className={sig.signer.isExpired ? 'text-destructive' : 'text-success'} />
            {sig.signer.extendedKeyUsages?.length > 0 && <Prop label="Extended KU" value={sig.signer.extendedKeyUsages.join(', ')} />}
          </PropGrid>
        </div>
      )}

      <EmbeddedCerts certs={sig.embeddedCertificates} />
    </div>
  )
}

function CertDetails({ cert }: { cert: any }) {
  return (
    <PropGrid>
      <Prop label="Subject" value={<strong>{cert.subject}</strong>} />
      <Prop label="Issuer" value={cert.issuer} />
      <Prop label="Serial" value={cert.serialNumber} />
      <Prop label="Thumbprint" value={<span className="font-mono text-xs">{cert.thumbprint}</span>} />
      <Prop label="Key" value={`${cert.keyAlgorithm || '?'} ${cert.keySizeBits ? cert.keySizeBits + '-bit' : ''}`} />
      <Prop label="Valid" value={`${formatDate(cert.notBefore)} → ${formatDate(cert.notAfter)}`} />
      <Prop label="Expired" value={cert.isExpired ? '✗ Yes' : '✓ No'} className={cert.isExpired ? 'text-destructive' : 'text-success'} />
      <Prop label="NonRepudiation" value={cert.hasNonRepudiation ? '✓ Legal signatures' : '✗ Not set'} className={cert.hasNonRepudiation ? 'text-success' : 'text-destructive'} />
      {cert.keyUsages?.length > 0 && <Prop label="Key Usage" value={cert.keyUsages.join(', ')} />}
      {cert.extendedKeyUsages?.length > 0 && <Prop label="Extended KU" value={cert.extendedKeyUsages.join(', ')} />}
      <Prop label="OCSP" value={cert.ocspUrl} />
      <Prop label="CRL" value={cert.crlUrl} />
      {cert.aiaUrls?.length > 0 && <Prop label="AIA" value={cert.aiaUrls.join(', ')} />}
    </PropGrid>
  )
}

function EmbeddedCerts({ certs }: { certs: any[] | null }) {
  if (!certs?.length) return null
  return (
    <div className="border-t pt-3 space-y-2">
      <p className="text-xs font-medium">🔗 Embedded Certificates ({certs.length})</p>
      <div className="space-y-1">
        {certs.map((c, i) => (
          <div key={i} className={`flex items-center gap-2 text-xs px-2 py-1.5 rounded bg-secondary ${c.isExpired ? 'opacity-50' : ''}`}>
            <span className="truncate flex-1">{extractCN(c.subject)}</span>
            <span className="text-muted-foreground shrink-0">
              {c.keyAlgorithm} {c.keySizeBits ? `${c.keySizeBits}-bit` : ''} · {formatDate(c.notBefore)} → {formatDate(c.notAfter)}
            </span>
            {c.isExpired && <Badge variant="destructive" className="text-[10px] px-1 py-0">EXPIRED</Badge>}
          </div>
        ))}
      </div>
    </div>
  )
}
