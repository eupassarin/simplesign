import { useState } from "react"
import { Code2, FileCheck2, FileCode2, FileText, FlaskConical, Grid3x3, Moon, PenTool, Server, Sun, SunMoon } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Toaster } from "@/components/ui/sonner"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { MatrixPage } from "@/features/matrix/MatrixPage"
import { SigningPage } from "@/features/pdf-signing/SigningPage"
import { SigningProvider } from "@/features/pdf-signing/state"
import { SandboxPage } from "@/features/sandbox/SandboxPage"
import { useTheme } from "@/hooks/use-theme"
import type { EnvironmentMode } from "@/lib/types"
import { cn } from "@/lib/utils"

type Page = "sign" | "matrix" | "sandbox"

const nav: { id: Page; label: string; icon: typeof PenTool }[] = [
  { id: "sign", label: "PDF signing", icon: PenTool },
  { id: "matrix", label: "Run matrix", icon: Grid3x3 },
  { id: "sandbox", label: "Sandbox", icon: FlaskConical },
]

const comingNext = [
  { label: "Validation", icon: FileCheck2 },
  { label: "CAdES", icon: FileCode2 },
  { label: "XAdES", icon: Code2 },
  { label: "HTML → PDF", icon: FileText },
]

export default function App() {
  const [page, setPage] = useState<Page>("sign")
  const [environment, setEnvironment] = useState<EnvironmentMode>("Sandbox")
  const { theme, setTheme } = useTheme()
  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex h-screen overflow-hidden">
        <aside className="bg-sidebar text-sidebar-foreground flex w-56 shrink-0 flex-col border-r max-md:hidden">
          <div className="flex items-center gap-2 px-4 py-4">
            <div className="bg-primary text-primary-foreground flex size-8 items-center justify-center rounded-lg"><PenTool className="size-4" /></div>
            <div className="leading-tight">
              <p className="text-sm font-semibold">SimpleSign</p>
              <p className="text-muted-foreground text-xs">TestBench</p>
            </div>
          </div>
          <nav className="space-y-0.5 px-2">
            {nav.map((n) => (
              <button key={n.id} onClick={() => setPage(n.id)}
                className={cn("flex w-full items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors", page === n.id ? "bg-sidebar-accent font-medium" : "hover:bg-sidebar-accent/60 text-sidebar-foreground/80")}>
                <n.icon className="size-4" /> {n.label}
              </button>
            ))}
          </nav>
          <p className="text-muted-foreground mt-6 px-4 text-[11px] font-medium tracking-wide uppercase">Coming next</p>
          <nav className="space-y-0.5 px-2 pt-1">
            {comingNext.map((n) => (
              <div key={n.label} className="text-muted-foreground flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm">
                <n.icon className="size-4" /> {n.label} <Badge variant="outline" className="ml-auto px-1.5 text-[10px] font-normal">soon</Badge>
              </div>
            ))}
          </nav>
          <div className="text-muted-foreground mt-auto space-y-1 p-4 text-[11px] leading-relaxed">
            <p className="flex items-center gap-1.5"><Server className="size-3" /> 127.0.0.1 only</p>
            <p>Uploads, keys and token sessions live in memory and are gone when the TestBench stops.</p>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex h-14 shrink-0 items-center gap-3 border-b px-4">
            <h1 className="text-sm font-medium">{nav.find((n) => n.id === page)?.label}</h1>
            <div className="ml-auto flex items-center gap-2">
              <div className="bg-muted flex rounded-lg p-0.5" role="radiogroup" aria-label="Environment">
                {(["Sandbox", "Real"] as const).map((e) => (
                  <Tooltip key={e}>
                    <TooltipTrigger asChild>
                      <button role="radio" aria-checked={environment === e} onClick={() => setEnvironment(e)}
                        className={cn("rounded-md px-3 py-1 text-xs font-medium transition-all", environment === e ? "bg-background shadow-sm" : "text-muted-foreground hover:text-foreground")}>
                        {e === "Sandbox" && <FlaskConical className="mr-1 inline size-3" />}
                        {e}
                      </button>
                    </TooltipTrigger>
                    <TooltipContent className="max-w-64">
                      {e === "Sandbox" ? "Offline: test PKI, TSA, CRLs and simulated PSC/CSC. Nothing leaves this machine." : "Your certificates, real TSAs, real PSC/CSC providers and validation against real roots."}
                    </TooltipContent>
                  </Tooltip>
                ))}
              </div>
              <Button variant="ghost" size="icon" aria-label="Theme" onClick={() => setTheme(theme === "light" ? "dark" : theme === "dark" ? "system" : "light")}>
                {theme === "light" ? <Sun /> : theme === "dark" ? <Moon /> : <SunMoon />}
              </Button>
            </div>
          </header>
          <main className="flex min-h-0 flex-1 flex-col">
            <SigningProvider environment={environment}>
              {page === "sign" && <SigningPage />}
              {page === "matrix" && <MatrixPage />}
              {page === "sandbox" && <SandboxPage />}
            </SigningProvider>
          </main>
        </div>
      </div>
      <Toaster richColors position="bottom-right" />
    </TooltipProvider>
  )
}
