import { useEffect, useState } from "react"
import { FolderOpen, FolderPlus, Loader2 } from "lucide-react"
import { toast } from "sonner"
import { Section } from "@/components/parts"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { WorkspaceView, WorkspacesView } from "@/lib/types"

/** Open a workspace folder, or create one (blank or from a sample). */
export function WorkspacesPage({ onOpened }: { onOpened: (workspace: WorkspaceView) => void }) {
  const { t } = useI18n()
  const [view, setView] = useState<WorkspacesView | null>(null)
  const [openPath, setOpenPath] = useState("")
  const [folder, setFolder] = useState("")
  const [name, setName] = useState("")
  const [sample, setSample] = useState("blank")
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.workspaces().then((v) => {
      setView(v)
      setFolder(`${v.defaultFolder}/my-playbook`)
    }).catch((e: Error) => toast.error(e.message))
  }, [])

  const run = async (action: () => Promise<WorkspaceView>) => {
    setBusy(true)
    try {
      onOpened(await action())
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (!view) return <Loader2 className="text-muted-foreground size-5 animate-spin" />
  return (
    <div className="max-w-3xl space-y-8">
      <p className="text-muted-foreground text-sm">{t("workspaces.intro")}</p>
      {view.current && <p className="text-sm">{t("workspaces.current")}: <span className="font-mono text-xs">{view.current}</span></p>}

      <Section title={t("workspaces.open")} description={t("workspaces.openHint")}>
        <div className="flex gap-2">
          <Input value={openPath} onChange={(e) => setOpenPath(e.target.value)} placeholder="~/playbooks/my-playbook" className="font-mono" />
          <Button disabled={busy || !openPath.trim()} onClick={() => run(() => api.open(openPath.trim()))}><FolderOpen /> {t("common.open")}</Button>
        </div>
        <div className="space-y-1">
          <h3 className="text-muted-foreground text-xs font-medium">{t("workspaces.recent")}</h3>
          {view.recent.length === 0 ? <p className="text-muted-foreground text-sm">{t("workspaces.noRecent")}</p> : (
            <ul className="divide-y rounded-md border">
              {view.recent.map((r) => (
                <li key={r}>
                  <button type="button" className="hover:bg-muted/50 w-full px-3 py-2 text-left font-mono text-xs" onClick={() => run(() => api.open(r))}>{r}</button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Section>

      <Section title={t("workspaces.create")} description={t("workspaces.createHint")}>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1 sm:col-span-2">
            <Label htmlFor="ws-folder">{t("workspaces.folder")}</Label>
            <Input id="ws-folder" value={folder} onChange={(e) => setFolder(e.target.value)} className="font-mono" />
          </div>
          <div className="space-y-1">
            <Label htmlFor="ws-name">{t("workspaces.name")}</Label>
            <Input id="ws-name" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label>{t("workspaces.start")}</Label>
            <Select value={sample} onValueChange={setSample}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="blank">{t("workspaces.blank")}</SelectItem>
                {view.samples.map((s) => <SelectItem key={s.id} value={s.id}>{s.name}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
        </div>
        {sample !== "blank" && <p className="text-muted-foreground text-sm">{view.samples.find((s) => s.id === sample)?.description}</p>}
        <Button disabled={busy || !folder.trim()} onClick={() => run(() => api.create(folder.trim(), name.trim() || null, sample === "blank" ? null : sample))}>
          <FolderPlus /> {t("common.create")}
        </Button>
      </Section>
    </div>
  )
}
