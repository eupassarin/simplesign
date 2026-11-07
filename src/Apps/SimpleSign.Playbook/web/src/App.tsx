import { useCallback, useEffect, useState } from "react"
import { BookCheck, FolderOpen, Globe, Loader2, Moon, Sun, SunMoon } from "lucide-react"
import { Pill } from "@/components/parts"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Toaster } from "@/components/ui/sonner"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { AssetsPage } from "@/features/AssetsPage"
import { HistoryPage } from "@/features/HistoryPage"
import { PlaybookPage } from "@/features/PlaybookPage"
import { RunPage } from "@/features/RunPage"
import { SettingsPage } from "@/features/SettingsPage"
import { WorkspacesPage } from "@/features/WorkspacesPage"
import { useTheme } from "@/hooks/use-theme"
import { locales, useI18n, type Locale } from "@/i18n"
import { api } from "@/lib/api"
import type { WorkspaceView } from "@/lib/types"

export default function App() {
  const { t, locale, setLocale } = useI18n()
  const { theme, setTheme } = useTheme()
  const [workspace, setWorkspace] = useState<WorkspaceView | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [chooser, setChooser] = useState(false)
  const [tab, setTab] = useState(() => localStorage.getItem("tab") ?? "playbook")

  const refresh = useCallback(() => {
    api.workspace().then(setWorkspace).catch(() => setWorkspace(null)).finally(() => setLoaded(true))
  }, [])
  useEffect(refresh, [refresh])

  const nextTheme = theme === "light" ? "dark" : theme === "dark" ? "system" : "light"
  const opened = (w: WorkspaceView) => {
    setWorkspace(w)
    setChooser(false)
  }
  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex min-h-screen flex-col">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b px-4">
          <BookCheck className="size-5" />
          <span className="font-semibold whitespace-nowrap">{t("app.title")}</span>
          {workspace ? (
            <>
              <Pill tone="info">{workspace.playbook?.name ?? workspace.path.split(/[\\/]/).pop()}</Pill>
              <span className="text-muted-foreground hidden truncate font-mono text-xs md:inline">{workspace.path}</span>
            </>
          ) : loaded && <Pill>{t("app.noWorkspace")}</Pill>}
          {workspace?.activeRunId && <Pill tone="warning"><Loader2 className="size-3 animate-spin" /> {t("app.running")}</Pill>}
          <div className="ml-auto flex items-center gap-1">
            <Button variant="ghost" size="sm" onClick={() => setChooser(true)}><FolderOpen /> <span className="max-md:hidden">{t("app.workspaces")}</span></Button>
            <Select value={locale} onValueChange={(v) => setLocale(v as Locale)}>
              <SelectTrigger size="sm" className="w-auto gap-1.5" aria-label={t("app.language")}><Globe className="size-4" />{locales.find((l) => l.id === locale)?.short}</SelectTrigger>
              <SelectContent>{locales.map((l) => <SelectItem key={l.id} value={l.id}>{l.label}</SelectItem>)}</SelectContent>
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
        <main className="flex-1 p-6 lg:p-8">
          {!loaded ? <Loader2 className="text-muted-foreground size-5 animate-spin" /> : !workspace ? (
            <>
              <p className="text-muted-foreground mb-6 max-w-3xl text-sm">{t("app.subtitle")}</p>
              <WorkspacesPage onOpened={opened} />
            </>
          ) : (
            <Tabs value={tab} onValueChange={(v) => { setTab(v); localStorage.setItem("tab", v) }}>
              <TabsList>
                <TabsTrigger value="playbook">{t("tabs.playbook")}</TabsTrigger>
                <TabsTrigger value="assets">{t("tabs.assets")}</TabsTrigger>
                <TabsTrigger value="run">{t("tabs.run")}</TabsTrigger>
                <TabsTrigger value="history">{t("tabs.history")}</TabsTrigger>
                <TabsTrigger value="settings">{t("tabs.settings")}</TabsTrigger>
              </TabsList>
              <div className="pt-6">
                <TabsContent value="playbook"><PlaybookPage workspace={workspace} onChanged={setWorkspace} /></TabsContent>
                <TabsContent value="assets"><AssetsPage workspace={workspace} onChanged={setWorkspace} /></TabsContent>
                <TabsContent value="run"><RunPage key={workspace.path} workspace={workspace} onFinished={refresh} /></TabsContent>
                <TabsContent value="history"><HistoryPage key={`${workspace.path}-${workspace.runs[0]?.id ?? ""}`} workspace={workspace} /></TabsContent>
                <TabsContent value="settings"><SettingsPage /></TabsContent>
              </div>
            </Tabs>
          )}
        </main>
      </div>
      <Sheet open={chooser} onOpenChange={setChooser}>
        <SheetContent className="w-[min(96vw,760px)] overflow-y-auto p-6 sm:max-w-none">
          <SheetHeader className="px-0"><SheetTitle>{t("workspaces.title")}</SheetTitle><SheetDescription className="sr-only">{t("workspaces.intro")}</SheetDescription></SheetHeader>
          <WorkspacesPage onOpened={opened} />
        </SheetContent>
      </Sheet>
      <Toaster richColors position="bottom-right" />
    </TooltipProvider>
  )
}
