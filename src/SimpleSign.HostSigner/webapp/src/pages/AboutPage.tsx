import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { ExternalLink, RefreshCw, Loader2 } from 'lucide-react'
import { fetchVersion, openUrl } from '@/lib/api'

export default function AboutPage() {
  const [version, setVersion] = useState<any>(null)
  const [checking, setChecking] = useState(false)
  const [updateStatus, setUpdateStatus] = useState<string | null>(null)

  const checkUpdates = async () => {
    setChecking(true)
    setUpdateStatus(null)
    try {
      const data = await fetchVersion()
      setVersion(data)
      if (data.updateAvailable) {
        setUpdateStatus(`v${data.latest} available!`)
      } else {
        setUpdateStatus('You\'re up to date ✓')
      }
    } catch {
      setUpdateStatus('Failed to check for updates')
    }
    setChecking(false)
  }

  return (
    <div className="max-w-lg space-y-6">
      <div>
        <h2 className="text-xl font-semibold">About</h2>
        <p className="text-sm text-muted-foreground mt-1">SimpleSign HostSigner</p>
      </div>

      <Card>
        <CardContent className="p-6 space-y-4">
          <div className="space-y-1">
            <h3 className="text-lg font-bold">SimpleSign</h3>
            <p className="text-sm text-muted-foreground">Digital signature desktop application for PAdES signing, inspection, and validation.</p>
          </div>

          <Separator />

          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted-foreground">Version</dt>
            <dd><Badge variant="outline">0.1.0-alpha</Badge></dd>
            <dt className="text-muted-foreground">Runtime</dt>
            <dd>{window._hostInfo?.runtime || '.NET 8'}</dd>
            <dt className="text-muted-foreground">PID</dt>
            <dd className="font-mono text-xs">{window._hostInfo?.pid || '-'}</dd>
            <dt className="text-muted-foreground">Port</dt>
            <dd className="font-mono text-xs">21590</dd>
          </dl>

          <Separator />

          <div className="flex items-center gap-3">
            <Button variant="outline" size="sm" onClick={checkUpdates} disabled={checking}>
              {checking ? <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5 mr-1" />}
              Check for Updates
            </Button>
            {updateStatus && (
              <span className={`text-xs ${updateStatus.includes('available') ? 'text-success' : updateStatus.includes('Failed') ? 'text-destructive' : 'text-success'}`}>
                {updateStatus}
              </span>
            )}
            {version?.updateAvailable && version.downloadUrl && (
              <Button variant="link" size="sm" onClick={() => openUrl(version.downloadUrl)} className="text-xs">
                Download <ExternalLink className="h-3 w-3 ml-1" />
              </Button>
            )}
          </div>

          <Separator />

          <Button variant="ghost" size="sm" onClick={() => openUrl('https://github.com/eupassarin/SimpleSign')} className="gap-2">
            <ExternalLink className="h-3.5 w-3.5" />
            GitHub Repository
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
