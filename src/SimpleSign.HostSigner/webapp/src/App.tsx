import { useState, useEffect } from 'react'
import { cn } from '@/lib/utils'
import { PenLine, Search, ShieldCheck, KeyRound, Globe, ScrollText, Info } from 'lucide-react'
import SignPage from '@/pages/SignPage'
import InspectPage from '@/pages/InspectPage'
import ValidatePage from '@/pages/ValidatePage'
import CertificatesPage from '@/pages/CertificatesPage'
import ApiPage from '@/pages/ApiPage'
import LogsPage from '@/pages/LogsPage'
import AboutPage from '@/pages/AboutPage'

type Page = 'sign' | 'inspect' | 'validate' | 'certificates' | 'api' | 'logs' | 'about'

const navItems: { id: Page; label: string; icon: React.ElementType; section?: string }[] = [
  { id: 'sign', label: 'Sign', icon: PenLine },
  { id: 'inspect', label: 'Inspect', icon: Search },
  { id: 'validate', label: 'Validate', icon: ShieldCheck },
  { id: 'certificates', label: 'Certificates', icon: KeyRound, section: 'Tools' },
  { id: 'api', label: 'API', icon: Globe },
  { id: 'logs', label: 'Logs', icon: ScrollText },
  { id: 'about', label: 'About', icon: Info },
]

export default function App() {
  const [page, setPage] = useState<Page>('sign')

  // Listen for hostInfo from WebView2
  useEffect(() => {
    const webview = (window as any).chrome?.webview
    if (webview) {
      const handler = (event: any) => {
        const data = typeof event.data === 'string' ? JSON.parse(event.data) : event.data
        if (data?.action === 'hostInfo') {
          window._hostInfo = { pid: String(data.pid), runtime: data.runtime }
        }
      }
      webview.addEventListener('message', handler)
      return () => webview.removeEventListener('message', handler)
    }
  }, [])

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <nav className="w-52 shrink-0 border-r bg-card flex flex-col">
        <div className="p-4 pb-2">
          <h1 className="text-base font-bold tracking-tight">SimpleSign</h1>
          <p className="text-xs text-muted-foreground">HostSigner</p>
        </div>
        <div className="flex-1 px-2 py-2 space-y-0.5">
          {navItems.map((item, idx) => (
            <div key={item.id}>
              {item.section && (
                <div className={cn("px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground", idx > 0 && "mt-4")}>
                  {item.section}
                </div>
              )}
              <button
                onClick={() => setPage(item.id)}
                className={cn(
                  "flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                  page === item.id
                    ? "bg-accent text-accent-foreground font-medium"
                    : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
                )}
              >
                <item.icon className="h-4 w-4" />
                {item.label}
              </button>
            </div>
          ))}
        </div>
      </nav>

      {/* Content */}
      <main className="flex-1 overflow-y-auto p-6">
        {page === 'sign' && <SignPage />}
        {page === 'inspect' && <InspectPage />}
        {page === 'validate' && <ValidatePage />}
        {page === 'certificates' && <CertificatesPage />}
        {page === 'api' && <ApiPage />}
        {page === 'logs' && <LogsPage />}
        {page === 'about' && <AboutPage />}
      </main>
    </div>
  )
}
