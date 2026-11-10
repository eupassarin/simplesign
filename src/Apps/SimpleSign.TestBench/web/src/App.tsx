import { useEffect, useState } from "react"
import { BookOpen, FileSliders, FlaskConical, Globe, Loader2, Moon, PenTool, ShieldCheck, Sun, SunMoon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet"
import { Toaster } from "@/components/ui/sonner"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { RealEnvironment } from "@/features/environment/RealEnvironment"
import { PoliciesPage } from "@/features/policies/PoliciesPage"
import { SandboxPage } from "@/features/sandbox/SandboxPage"
import { CatalogProvider } from "@/features/shared/catalog"
import { DssControl } from "@/features/shared/DssControl"
import { CoveragePage } from "@/features/standards/CoveragePage"
import { ValidatePage } from "@/features/validate/ValidatePage"
import type { RunKind, WorkbenchSchema } from "@/features/workbench/schema"
import { useWorkbench, WorkbenchProvider } from "@/features/workbench/state"
import { WorkbenchPage } from "@/features/workbench/WorkbenchPage"
import { useTheme } from "@/hooks/use-theme"
import { locales, useI18n, type Locale } from "@/i18n"
import { api } from "@/lib/api"
import type { EnvironmentInfo } from "@/lib/types"
import { cn } from "@/lib/utils"

export default function App() {
  const [schema, setSchema] = useState<WorkbenchSchema | null>(null)
  // The environment (the connected Sandbox) is read first: the defaults depend on it.
  const [env, setEnv] = useState<EnvironmentInfo | null | undefined>(undefined)
  useEffect(() => {
    api.env().then(setEnv).catch(() => setEnv(null))
  }, [])
  const { locale } = useI18n()
  // The schema carries the explanations, so it is fetched again in the new language.
  useEffect(() => {
    api.workbench.schema().then(setSchema).catch(() => setSchema(null))
  }, [locale])
  return (
    <TooltipProvider delayDuration={200}>
      <CatalogProvider>
        {!schema || env === undefined ? <div className="text-muted-foreground flex h-screen items-center justify-center"><Loader2 className="size-5 animate-spin" /></div> : (
          <WorkbenchProvider schema={schema} initialEnv={env}>
            <Shell />
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
 * the library covers of each standard), Sandbox (the connected SimpleSign Sandbox) and Environment
 * (what this machine has) open as panels over either; the DSS switch, which both tasks use, sits beside them.
 */
function Shell() {
  const { mode, setMode, env } = useWorkbench()
  const sandbox = env?.sandbox ?? null
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
          <Panel icon={<FileSliders />} label={t("policies.title")} hint={t("policies.hint")}><PoliciesPage /></Panel>
          <Panel icon={<BookOpen />} label={t("app.reference")} hint={t("app.referenceHint")}><CoveragePage /></Panel>
          <Panel icon={<FlaskConical />} label={sandbox ? t("app.sandboxConnected") : t("app.sandboxNone")} active={!!sandbox}
            hint={sandbox ? `${t("app.sandboxName", { name: sandbox.name })} ${t("app.sandboxHint")}` : t("app.sandboxHint")}>
            <SandboxPage />
          </Panel>
          <DssControl />
          <Panel icon={<Globe />} label={t("app.environmentPanel")} hint={t("app.environmentRealHint")}>
            <RealEnvironment />
          </Panel>
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

/** A reference or control panel that slides over the task without leaving it; `active` highlights a connected service. */
function Panel({ icon, label, hint, active, children }: { icon: React.ReactNode; label: string; hint: string; active?: boolean; children: React.ReactNode }) {
  return (
    <Sheet>
      <Tooltip>
        <TooltipTrigger asChild>
          <SheetTrigger asChild>
            <Button variant="ghost" size="sm" aria-label={label} className={cn("h-8", active && "border-info/60 bg-info/10 border")}>{icon}<span className="max-xl:hidden">{label}</span></Button>
          </SheetTrigger>
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
