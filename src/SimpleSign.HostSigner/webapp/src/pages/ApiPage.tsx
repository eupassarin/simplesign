import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

const endpoints = [
  {
    method: 'GET',
    path: '/api/health',
    desc: 'Returns service status and version.',
    response: '{ "status": "ok", "version": "0.1.0-alpha" }',
  },
  {
    method: 'GET',
    path: '/api/certificates',
    desc: 'Lists signing certificates from the personal store.',
    params: '?filterIcpBrasil=true',
    response: '[{ "name": "CN=...", "thumbprint": "...", "issuerName": "...", "expireDate": "..." }]',
  },
  {
    method: 'POST',
    path: '/api/sign',
    desc: 'Signs hash(es) using a certificate (deferred signing for remote use).',
    request: '{\n  "thumbprint": "...",\n  "hashAlgorithm": "SHA-256",\n  "signRequests": [\n    { "id": "1", "authenticatedAttributeBase64": "..." }\n  ]\n}',
    response: '[{ "id": "1", "signedHashBase64": "..." }]',
  },
  {
    method: 'GET',
    path: '/api/version',
    desc: 'Checks for updates from GitHub releases.',
    response: '{ "current": "0.1.0-alpha", "latest": "...", "updateAvailable": false }',
  },
]

export default function ApiPage() {
  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h2 className="text-xl font-semibold">API Endpoints</h2>
        <p className="text-sm text-muted-foreground mt-1">HTTP endpoints available for remote integration.</p>
      </div>

      <div className="space-y-3">
        {endpoints.map((ep, i) => (
          <Card key={i}>
            <CardContent className="p-0">
              <div className="flex items-center gap-2 px-4 py-3 border-b">
                <Badge variant={ep.method === 'GET' ? 'success' : 'default'} className="font-mono text-xs">
                  {ep.method}
                </Badge>
                <code className="text-sm">{ep.path}</code>
                {ep.params && <span className="text-xs text-muted-foreground">{ep.params}</span>}
              </div>
              <div className="p-4 space-y-3">
                <p className="text-sm text-muted-foreground">{ep.desc}</p>
                {ep.request && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Request</p>
                    <pre className="bg-secondary rounded-md p-3 text-xs font-mono overflow-x-auto">{ep.request}</pre>
                  </div>
                )}
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Response</p>
                  <pre className="bg-secondary rounded-md p-3 text-xs font-mono overflow-x-auto">{ep.response}</pre>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}
