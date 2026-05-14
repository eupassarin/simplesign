import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Card, CardContent } from '@/components/ui/card'
import { Collapsible, CollapsibleTrigger, CollapsibleContent } from '@/components/ui/collapsible'
import { Alert } from '@/components/ui/alert'
import { PenLine, Upload, X } from 'lucide-react'
import { fetchCertificates, signFile, browseFiles, type CertificateInfo } from '@/lib/api'
import { extractCN, fileName } from '@/lib/format'
import { useWebViewMessage } from '@/lib/webview'

export default function SignPage() {
  const [certs, setCerts] = useState<CertificateInfo[]>([])
  const [selectedThumbprint, setSelectedThumbprint] = useState('')
  const [files, setFiles] = useState<string[]>([])
  const [icpOnly, setIcpOnly] = useState(false)
  const [validOnly, setValidOnly] = useState(false)
  const [signing, setSigning] = useState(false)
  const [results, setResults] = useState<{ file: string; success: boolean; message: string }[]>([])

  // Advanced options
  const [tsaUrl, setTsaUrl] = useState('')
  const [reason, setReason] = useState('')
  const [location, setLocation] = useState('')
  const [signerName, setSignerName] = useState('')
  const [contactInfo, setContactInfo] = useState('')
  const [fieldName, setFieldName] = useState('')
  const [hashAlgorithm, setHashAlgorithm] = useState('SHA-256')
  const [enableLtv, setEnableLtv] = useState(false)
  const [preservePdfA, setPreservePdfA] = useState(false)
  const [archivalTimestamp, setArchivalTimestamp] = useState(false)
  const [certificationLevel, setCertificationLevel] = useState('none')
  const [visibleStamp, setVisibleStamp] = useState(false)

  useEffect(() => {
    fetchCertificates().then(setCerts).catch(() => {})
  }, [])

  const filteredCerts = certs.filter(c => {
    if (validOnly && c.expireDate && new Date(c.expireDate) < new Date()) return false
    if (icpOnly) {
      const issuer = (c.issuerName || '').toLowerCase()
      if (!issuer.includes('icp-brasil') && !issuer.includes('icp brasil') && !issuer.includes('ac ')) return false
    }
    return true
  })

  useWebViewMessage((data) => {
    if (data?.action === 'filesSelected' && Array.isArray(data.files)) {
      setFiles(prev => {
        const next = [...prev]
        for (const f of data.files) { if (!next.includes(f)) next.push(f) }
        return next
      })
    }
  })

  const removeFile = (idx: number) => setFiles(prev => prev.filter((_, i) => i !== idx))

  const handleSign = async () => {
    if (!selectedThumbprint || !files.length) return
    setSigning(true)
    setResults([])
    const newResults: typeof results = []

    for (const file of files) {
      try {
        const data = await signFile({
          filePath: file,
          thumbprint: selectedThumbprint,
          tsaUrl: tsaUrl || null,
          reason: reason || null,
          location: location || null,
          signerName: signerName || null,
          contactInfo: contactInfo || null,
          fieldName: fieldName || null,
          hashAlgorithm,
          enableLtv,
          preservePdfA,
          archivalTimestamp,
          certificationLevel,
          visibleStamp,
        })
        newResults.push({ file, success: true, message: `→ ${fileName(data.outputPath)}` })
      } catch (e: any) {
        newResults.push({ file, success: false, message: e.message })
      }
    }
    setResults(newResults)
    setSigning(false)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    const items = Array.from(e.dataTransfer.files)
    const paths = items.map(f => (f as any).path || f.name).filter(Boolean)
    setFiles(prev => {
      const next = [...prev]
      for (const f of paths) { if (!next.includes(f)) next.push(f) }
      return next
    })
  }

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h2 className="text-xl font-semibold">Sign Documents</h2>
        <p className="text-sm text-muted-foreground mt-1">Select a certificate and PDF files to digitally sign.</p>
      </div>

      {/* Certificate */}
      <div className="space-y-3">
        <Label>Certificate</Label>
        <Select value={selectedThumbprint} onChange={e => setSelectedThumbprint(e.target.value)}>
          <option value="">Select a certificate...</option>
          {filteredCerts.map(c => {
            const expired = c.expireDate && new Date(c.expireDate) < new Date()
            return (
              <option key={c.thumbprint} value={c.thumbprint}>
                {extractCN(c.name)}{expired ? ' (expired)' : ''}
              </option>
            )
          })}
        </Select>
        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-sm text-muted-foreground">
            <Switch checked={icpOnly} onCheckedChange={setIcpOnly} />
            ICP-Brasil only
          </label>
          <label className="flex items-center gap-2 text-sm text-muted-foreground">
            <Switch checked={validOnly} onCheckedChange={setValidOnly} />
            Valid only
          </label>
        </div>
      </div>

      {/* Files */}
      <div className="space-y-3">
        <Label>Files</Label>
        <div
          onDrop={handleDrop}
          onDragOver={e => e.preventDefault()}
          onClick={() => browseFiles()}
          className="border-2 border-dashed border-border rounded-lg p-8 text-center cursor-pointer hover:border-primary/50 hover:bg-accent/30 transition-colors"
        >
          <Upload className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
          <p className="text-sm text-muted-foreground">Drop PDF files here or click to browse</p>
        </div>
        {files.length > 0 && (
          <div className="space-y-1">
            {files.map((f, i) => (
              <div key={i} className="flex items-center justify-between rounded-md bg-secondary px-3 py-2 text-sm">
                <span className="truncate">{fileName(f)}</span>
                <button onClick={() => removeFile(i)} className="text-muted-foreground hover:text-destructive ml-2">
                  <X className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Advanced Options */}
      <Collapsible>
        <CollapsibleTrigger>Advanced Options</CollapsibleTrigger>
        <CollapsibleContent>
          <Card className="mt-2">
            <CardContent className="p-4 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label className="text-xs">TSA URL</Label>
                  <Input placeholder="http://tsa.example.com" value={tsaUrl} onChange={e => setTsaUrl(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Hash Algorithm</Label>
                  <Select value={hashAlgorithm} onChange={e => setHashAlgorithm(e.target.value)}>
                    <option value="SHA-256">SHA-256</option>
                    <option value="SHA-384">SHA-384</option>
                    <option value="SHA-512">SHA-512</option>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Reason</Label>
                  <Input placeholder="Signing reason" value={reason} onChange={e => setReason(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Location</Label>
                  <Input placeholder="Signing location" value={location} onChange={e => setLocation(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Signer Name</Label>
                  <Input placeholder="Name" value={signerName} onChange={e => setSignerName(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Contact Info</Label>
                  <Input placeholder="Email or phone" value={contactInfo} onChange={e => setContactInfo(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Field Name</Label>
                  <Input placeholder="Auto" value={fieldName} onChange={e => setFieldName(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">DocMDP Level</Label>
                  <Select value={certificationLevel} onChange={e => setCertificationLevel(e.target.value)}>
                    <option value="none">None (approval)</option>
                    <option value="no-changes">No changes</option>
                    <option value="form-filling">Form filling</option>
                    <option value="annotations">Form + annotations</option>
                  </Select>
                </div>
              </div>

              <div className="flex flex-wrap gap-x-6 gap-y-3 pt-2">
                <label className="flex items-center gap-2 text-sm">
                  <Switch checked={enableLtv} onCheckedChange={setEnableLtv} /> LTV
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <Switch checked={archivalTimestamp} onCheckedChange={setArchivalTimestamp} /> Archival Timestamp
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <Switch checked={preservePdfA} onCheckedChange={setPreservePdfA} /> Preserve PDF/A
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <Switch checked={visibleStamp} onCheckedChange={setVisibleStamp} /> Visible Stamp
                </label>
              </div>
            </CardContent>
          </Card>
        </CollapsibleContent>
      </Collapsible>

      {/* Sign Button */}
      <Button onClick={handleSign} disabled={signing || !selectedThumbprint || !files.length} className="w-full">
        <PenLine className="h-4 w-4" />
        {signing ? 'Signing...' : 'Sign Documents'}
      </Button>

      {/* Results */}
      {results.length > 0 && (
        <div className="space-y-2">
          {results.map((r, i) => (
            <Alert key={i} variant={r.success ? 'success' : 'destructive'}>
              <span className="text-sm">{fileName(r.file)} {r.message}</span>
            </Alert>
          ))}
        </div>
      )}
    </div>
  )
}
