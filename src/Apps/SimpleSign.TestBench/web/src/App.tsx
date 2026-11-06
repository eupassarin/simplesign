import { useEffect, useState } from "react"
import { BookOpen, FlaskConical, Globe, Loader2, Moon, PenTool, ShieldCheck, Sun, SunMoon, TriangleAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet"
import { Toaster } from "@/components/ui/sonner"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { SandboxPage } from "@/features/sandbox/SandboxPage"
import { CatalogProvider } from "@/features/shared/catalog"
import { CoveragePage } from "@/features/standards/CoveragePage"
import { ValidatePage } from "@/features/validate/ValidatePage"
import type { RunKind, WorkbenchSchema } from "@/features/workbench/schema"
import { useWorkbench, WorkbenchProvider } from "@/features/workbench/state"
import { WorkbenchPage } from "@/features/workbench/WorkbenchPage"
import { useTheme } from "@/hooks/use-theme"
import { locales, useI18n, type Locale } from "@/i18n"
import { api } from "@/lib/api"
import type { EnvironmentMode } from "@/lib/types"
import { cn } from "@/lib/utils"

export default function App() {
  const [environment, setEnvironment] = useState<EnvironmentMode>("Sandbox")
  const [schema, setSchema] = useState<WorkbenchSchema | null>(null)
  const { locale } = useI18n()
  // The schema carries the explanations, so it is fetched again in the new language.
  useEffect(() => {
    api.workbench.schema().then(setSchema).catch(() => setSchema(null))
  }, [locale])
  return (
    <TooltipProvider delayDuration={200}>
      <CatalogProvider>
        {!schema ? <div className="text-muted-foreground flex h-screen items-center justify-center"><Loader2 className="size-5 animate-spin" /></div> : (
          <WorkbenchProvider schema={schema} environment={environment}>
            <Shell environment={environment} onEnvironment={setEnvironment} />
          </WorkbenchProvider>
        )}
      </CatalogProvider>
      <Toaster richColors position="bottom-right" />
    </TooltipProvider>
  )
}

const modes: { id: RunKind; icon: typeof PenTool }[] = [
  { id: "sign", icon: PenTool },
  { id: "validate", icon: ShieldCheck },
]

/**
 * One top bar and one task on screen. There are two tasks, Sign and Validate; Reference (what
 * the library covers of each standard) and Environment (the sandbox) open as panels over either.
 */
function Shell({ environment, onEnvironment }: { environment: EnvironmentMode; onEnvironment: (environment: EnvironmentMode) => void }) {
  const { mode, setMode, sandbox } = useWorkbench()
  const { theme, setTheme } = useTheme()
  const { t, locale, setLocale } = useI18n()
  return (
    <div className="flex h-screen flex-col overflow-hidden">
      <header className="flex h-14 shrink-0 items-center gap-3 border-b px-4">
        <div className="flex items-center gap-2">
          <div className="bg-primary text-primary-foreground flex size-8 items-center justify-center rounded-lg"><PenTool className="size-4" /></div>
          <div className="leading-tight max-md:hidden">
            <p className="text-sm font-semibold">SimpleSign</p>
            <p className="text-muted-foreground text-xs">TestBench</p>
          </div>
        </div>
        <div className="bg-muted ml-2 flex rounded-lg p-0.5" role="radiogroup" aria-label={t("app.task")}>
          {modes.map((m) => (
            <button key={m.id} role="radio" aria-checked={mode === m.id} onClick={() => setMode(m.id)}
              className={cn("flex items-center gap-1.5 rounded-md px-4 py-1.5 text-sm font-medium transition-all", mode === m.id ? "bg-background shadow-sm" : "text-muted-foreground hover:text-foreground")}>
              <m.icon className="size-4" /> {t(m.id === "sign" ? "app.mode.sign" : "app.mode.validate")}
            </button>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-2">
          <Panel icon={<BookOpen />} label={t("app.reference")} hint={t("app.referenceHint")}><CoveragePage /></Panel>
          <div className="bg-muted flex rounded-lg p-0.5" role="radiogroup" aria-label={t("app.environment")}>
            {(["Sandbox", "Real"] as const).map((e) => (
              <Tooltip key={e}>
                <TooltipTrigger asChild>
                  <button role="radio" aria-checked={environment === e} onClick={() => onEnvironment(e)}
                    className={cn("rounded-md px-3 py-1 text-xs font-medium transition-all", environment === e ? "bg-background shadow-sm" : "text-muted-foreground hover:text-foreground")}>
                    {t(e === "Sandbox" ? "app.env.sandbox" : "app.env.real")}
                  </button>
                </TooltipTrigger>
                <TooltipContent className="max-w-64">{t(e === "Sandbox" ? "app.env.sandboxHint" : "app.env.realHint")}</TooltipContent>
              </Tooltip>
            ))}
          </div>
          <Panel icon={<FlaskConical />} label={t("app.environmentPanel")} hint={t("app.environmentHint")}><SandboxPage /></Panel>
          {sandbox?.faultsActive && <span className="border-warning/60 bg-warning/15 flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium"><TriangleAlert className="size-3.5" /> {t("lab.active")}</span>}
          <Select value={locale} onValueChange={(v) => setLocale(v as Locale)}>
            <SelectTrigger size="sm" className="h-8 w-auto gap-1.5 border-none shadow-none" aria-label={t("app.language")}>
              <Globe className="size-4" />
              <span className="text-xs font-medium">{locales.find((l) => l.id === locale)?.short}</span>
            </SelectTrigger>
            <SelectContent position="popper" align="end">
              {locales.map((l) => <SelectItem key={l.id} value={l.id}>{l.label}</SelectItem>)}
            </SelectContent>
          </Select>
          <Button variant="ghost" size="icon" aria-label={t("app.theme")} onClick={() => setTheme(theme === "light" ? "dark" : theme === "dark" ? "system" : "light")}>
            {theme === "light" ? <Sun /> : theme === "dark" ? <Moon /> : <SunMoon />}
          </Button>
        </div>
      </header>
      <main className="flex min-h-0 flex-1 flex-col">
        {mode === "sign" ? <WorkbenchPage /> : <ValidatePage />}
      </main>
    </div>
  )
}

/** A reference or control panel that slides over the task without leaving it. */
function Panel({ icon, label, hint, children }: { icon: React.ReactNode; label: string; hint: string; children: React.ReactNode }) {
  return (
    <Sheet>
      <Tooltip>
        <TooltipTrigger asChild>
          <SheetTrigger asChild><Button variant="ghost" size="sm" className="h-8">{icon}<span className="max-lg:hidden">{label}</span></Button></SheetTrigger>
        </TooltipTrigger>
        <TooltipContent className="max-w-64">{hint}</TooltipContent>
      </Tooltip>
      <SheetContent className="flex w-[min(96vw,1200px)] flex-col p-0 sm:max-w-none">
        <SheetHeader className="sr-only"><SheetTitle>{label}</SheetTitle><SheetDescription>{hint}</SheetDescription></SheetHeader>
        {children}
      </SheetContent>
    </Sheet>
  )
}
