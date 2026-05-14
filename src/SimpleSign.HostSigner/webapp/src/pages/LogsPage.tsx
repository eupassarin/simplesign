import { useState, useEffect, useRef } from 'react'
import { Button } from '@/components/ui/button'
import { Trash2, Copy } from 'lucide-react'
import { useWebViewMessage } from '@/lib/webview'

export default function LogsPage() {
  const [logs, setLogs] = useState<string[]>([])
  const containerRef = useRef<HTMLPreElement>(null)

  useWebViewMessage((data) => {
    if (data?.action === 'log') {
      const ts = new Date().toLocaleTimeString()
      setLogs(prev => [...prev, `[${ts}] ${data.message}`])
    }
  })

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight
    }
  }, [logs])

  const clearLogs = () => setLogs([])
  const copyLogs = () => navigator.clipboard.writeText(logs.join('\n'))

  return (
    <div className="max-w-3xl space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold">Logs</h2>
          <p className="text-sm text-muted-foreground mt-1">Application activity log.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={copyLogs} disabled={!logs.length}>
            <Copy className="h-3.5 w-3.5 mr-1" /> Copy
          </Button>
          <Button variant="outline" size="sm" onClick={clearLogs} disabled={!logs.length}>
            <Trash2 className="h-3.5 w-3.5 mr-1" /> Clear
          </Button>
        </div>
      </div>

      <pre
        ref={containerRef}
        className="bg-secondary rounded-lg p-4 text-xs font-mono h-[calc(100vh-200px)] overflow-y-auto whitespace-pre-wrap"
      >
        {logs.length > 0 ? logs.join('\n') : 'No log entries yet.'}
      </pre>
    </div>
  )
}
