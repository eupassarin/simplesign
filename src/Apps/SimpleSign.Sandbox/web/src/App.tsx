import { useCallback, useEffect, useState } from "react"
import { FlaskConical, Globe, Loader2, Moon, Sun, SunMoon, TriangleAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger } from "@/components/ui/select"
import { Toaster } from "@/components/ui/sonner"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { Pill } from "@/components/parts"
import { EnvironmentPage } from "@/features/EnvironmentPage"
import { FaultsPage } from "@/features/FaultsPage"
import { LogPage } from "@/features/LogPage"
import { PkiPage } from "@/features/PkiPage"
import { useTheme } from "@/hooks/use-theme"
import { locales, useI18n, type Locale } from "@/i18n"
import { api } from "@/lib/api"
import { load, save } from "@/lib/storage"
import type { PkiView, SandboxFaults, SandboxInfo } from "@/lib/types"

const tabs = ["environment", "pki", "faults", "log"] as const
type Tab = (typeof tabs)[number]
const savedTab = (): Tab => tabs.find((t) => t === load("tab")) ?? "environment"

export default function App() {
  const { t, locale, setLocale } = useI18n()
  const { theme, setTheme } = useTheme()
  const [info, setInfo] = useState<SandboxInfo | null>(null)
  const [pki, setPki] = useState<PkiView | null>(null)
  const [faults, setFaults] = useState<SandboxFaults | null>(null)
  const [tab, setTabState] = useState<Tab>(savedTab)
  const setTab = (next: string) => {
    const known = tabs.find((t) => t === next)
    if (!known) return
    setTabState(known)
    save("tab", known)
  }
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(() => {
    Promise.all([api.info(), api.pki(), api.faults()])
      .then(([i, p, f]) => { setInfo(i); setPki(p); setFaults(f); setError(null) })
      .catch((e: Error) => setError(e.message))
  }, [])
  useEffect(refresh, [refresh])

  const faultsOn = !!faults && (faults.tsa !== "None" || faults.crl !== "None" || faults.ocsp !== "None" || (faults.trustedList ?? "None") !== "None")
  const nextTheme = theme === "light" ? "dark" : theme === "dark" ? "system" : "light"
  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex min-h-screen flex-col">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b px-4">
          <FlaskConical className="size-5" />
          <span className="font-semibold whitespace-nowrap">{t("app.title")}</span>
          {info && <Pill tone="info">{t("app.environment", { name: info.name })}</Pill>}
          {info && <span className="text-muted-foreground hidden truncate font-mono text-xs md:inline">{t("app.certificatesPointTo", { url: info.baseUrl })}</span>}
          {faultsOn && (
            <button type="button" onClick={() => setTab("faults")}>
              <Pill tone="danger"><TriangleAlert className="size-3" /> {t("app.faultsOn")}</Pill>
            </button>
          )}
          <div className="ml-auto flex items-center gap-1">
            <Select value={locale} onValueChange={(v) => setLocale(v as Locale)}>
              <SelectTrigger size="sm" className="w-auto gap-1.5" aria-label={t("app.language")}><Globe className="size-4" />{locales.find((l) => l.id === locale)?.short}</SelectTrigger>
              <SelectContent position="popper" align="end">{locales.map((l) => <SelectItem key={l.id} value={l.id}>{l.label}</SelectItem>)}</SelectContent>
            </Select>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="icon" aria-label={t("app.theme")} onClick={() => setTheme(nextTheme)}>
                  {theme === "light" ? <Sun /> : theme === "dark" ? <Moon /> : <SunMoon />}
                </Button>
              </TooltipTrigger>
              <TooltipContent>{t("app.theme")}</TooltipContent>
            </Tooltip>
          </div>
        </header>
        <main className="mx-auto w-full max-w-7xl flex-1 p-4 sm:p-6">
          <p className="text-muted-foreground mb-4 max-w-3xl text-sm">{t("app.subtitle")}</p>
          {error && <p className="text-destructive text-sm">{t("common.error")}: {error}</p>}
          {!info || !pki ? <Loader2 className="text-muted-foreground size-5 animate-spin" /> : (
            <Tabs value={tab} onValueChange={setTab}>
              <TabsList>
                <TabsTrigger value="environment">{t("tabs.environment")}</TabsTrigger>
                <TabsTrigger value="pki">{t("tabs.pki")}</TabsTrigger>
                <TabsTrigger value="faults">{t("tabs.faults")}</TabsTrigger>
                <TabsTrigger value="log">{t("tabs.log")}</TabsTrigger>
              </TabsList>
              <div className="pt-4">
                <TabsContent value="environment"><EnvironmentPage info={info} /></TabsContent>
                <TabsContent value="pki"><PkiPage info={info} pki={pki} onChanged={refresh} /></TabsContent>
                <TabsContent value="faults"><FaultsPage initial={faults} onChanged={setFaults} /></TabsContent>
                <TabsContent value="log"><LogPage /></TabsContent>
              </div>
            </Tabs>
          )}
        </main>
      </div>
      <Toaster richColors position="bottom-right" />
    </TooltipProvider>
  )
}
