import { useEffect, useState } from "react"
import { FileCheck2, FileText, FlaskConical, Globe, Grid3x3, ListChecks, Loader2, Moon, PenTool, Server, Sun, SunMoon } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger } from "@/components/ui/select"
import { Toaster } from "@/components/ui/sonner"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { CoveragePage } from "@/features/standards/CoveragePage"
import { MatrixPage } from "@/features/matrix/MatrixPage"
import { CatalogProvider } from "@/features/shared/catalog"
import { SandboxPage } from "@/features/sandbox/SandboxPage"
import { ValidationArea } from "@/features/validation/ValidationArea"
import type { WorkbenchSchema } from "@/features/workbench/schema"
import { WorkbenchProvider } from "@/features/workbench/state"
import { WorkbenchPage } from "@/features/workbench/WorkbenchPage"
import { useTheme } from "@/hooks/use-theme"
import { locales, useI18n, type Locale, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import { NavigationContext } from "@/lib/navigation"
import type { EnvironmentMode } from "@/lib/types"
import { cn } from "@/lib/utils"

type Page = "workbench" | "validation" | "matrix" | "coverage" | "sandbox"

const nav: { id: Page; label: MessageKey; icon: typeof PenTool }[] = [
  { id: "workbench", label: "app.nav.workbench", icon: PenTool },
  { id: "validation", label: "app.nav.validation", icon: FileCheck2 },
  { id: "matrix", label: "app.nav.matrix", icon: Grid3x3 },
  { id: "coverage", label: "app.nav.coverage", icon: ListChecks },
  { id: "sandbox", label: "app.nav.sandbox", icon: FlaskConical },
]

const comingNext: { label: MessageKey; icon: typeof PenTool }[] = [
  { label: "app.nav.htmlToPdf", icon: FileText },
]

export default function App() {
  const [page, setPage] = useState<Page>("workbench")
  const [schema, setSchema] = useState<WorkbenchSchema | null>(null)
  const [toValidate, setToValidate] = useState<{ id: string; name: string } | null>(null)
  const [environment, setEnvironment] = useState<EnvironmentMode>("Sandbox")
  const { theme, setTheme } = useTheme()
  const { t, locale, setLocale } = useI18n()
  // The schema carries the explanations, so it is fetched again in the new language.
  useEffect(() => {
    api.workbench.schema().then(setSchema).catch(() => setSchema(null))
  }, [locale])
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
                <n.icon className="size-4" /> {t(n.label)}
              </button>
            ))}
          </nav>
          <p className="text-muted-foreground mt-6 px-4 text-[11px] font-medium tracking-wide uppercase">{t("app.comingNext")}</p>
          <nav className="space-y-0.5 px-2 pt-1">
            {comingNext.map((n) => (
              <div key={n.label} className="text-muted-foreground flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm">
                <n.icon className="size-4" /> {t(n.label)} <Badge variant="outline" className="ml-auto px-1.5 text-[10px] font-normal">{t("app.soon")}</Badge>
              </div>
            ))}
          </nav>
          <div className="text-muted-foreground mt-auto space-y-1 p-4 text-[11px] leading-relaxed">
            <p className="flex items-center gap-1.5"><Server className="size-3" /> {t("app.loopbackOnly")}</p>
            <p>{t("app.memoryOnly")}</p>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex h-14 shrink-0 items-center gap-3 border-b px-4">
            <h1 className="text-sm font-medium">{t(nav.find((n) => n.id === page)!.label)}</h1>
            <div className="ml-auto flex items-center gap-2">
              <div className="bg-muted flex rounded-lg p-0.5" role="radiogroup" aria-label={t("app.environment")}>
                {(["Sandbox", "Real"] as const).map((e) => (
                  <Tooltip key={e}>
                    <TooltipTrigger asChild>
                      <button role="radio" aria-checked={environment === e} onClick={() => setEnvironment(e)}
                        className={cn("rounded-md px-3 py-1 text-xs font-medium transition-all", environment === e ? "bg-background shadow-sm" : "text-muted-foreground hover:text-foreground")}>
                        {e === "Sandbox" && <FlaskConical className="mr-1 inline size-3" />}
                        {t(e === "Sandbox" ? "app.env.sandbox" : "app.env.real")}
                      </button>
                    </TooltipTrigger>
                    <TooltipContent className="max-w-64">
                      {t(e === "Sandbox" ? "app.env.sandboxHint" : "app.env.realHint")}
                    </TooltipContent>
                  </Tooltip>
                ))}
              </div>
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
            <NavigationContext.Provider value={{ validate: (file) => { setToValidate(file); setPage("validation") } }}>
              <CatalogProvider>
                {!schema ? <div className="text-muted-foreground flex flex-1 items-center justify-center"><Loader2 className="size-5 animate-spin" /></div> : (
                  <WorkbenchProvider schema={schema} environment={environment}>
                    {page === "workbench" && <WorkbenchPage />}
                    {page === "validation" && <ValidationArea environment={environment} initialFile={toValidate} />}
                    {page === "matrix" && <MatrixPage />}
                    {page === "coverage" && <CoveragePage />}
                    {page === "sandbox" && <SandboxPage />}
                  </WorkbenchProvider>
                )}
              </CatalogProvider>
            </NavigationContext.Provider>
          </main>
        </div>
      </div>
      <Toaster richColors position="bottom-right" />
    </TooltipProvider>
  )
}
