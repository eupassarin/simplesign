import { useEffect, useState } from "react"
import { CheckCircle2, Loader2, Save, XCircle } from "lucide-react"
import { toast } from "sonner"
import { KeyValue, Section } from "@/components/parts"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { CliCheck, SettingsView } from "@/lib/types"

/** How this machine starts the SimpleSign CLI. */
export function SettingsPage() {
  const { t } = useI18n()
  const [view, setView] = useState<SettingsView | null>(null)
  const [command, setCommand] = useState("")
  const [prefix, setPrefix] = useState("")
  const [check, setCheck] = useState<CliCheck | null>(null)
  const [busy, setBusy] = useState(false)
  const load = (v: SettingsView) => {
    setView(v)
    setCommand(v.cliCommand ?? "")
    setPrefix(v.cliPrefix.join("\n"))
  }
  useEffect(() => { api.settings().then(load).catch((e: Error) => toast.error(e.message)) }, [])

  if (!view) return <Loader2 className="text-muted-foreground size-5 animate-spin" />
  return (
    <div className="max-w-3xl space-y-6">
      <Section title={t("settings.cli")} description={t("settings.cliHint")}>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="cli-command">{t("settings.cliCommand")}</Label>
            <Input id="cli-command" value={command} onChange={(e) => setCommand(e.target.value)} placeholder="simplesign" className="font-mono" />
          </div>
          <div className="space-y-1">
            <Label htmlFor="cli-prefix">{t("settings.cliPrefix")}</Label>
            <Textarea id="cli-prefix" value={prefix} onChange={(e) => setPrefix(e.target.value)} rows={3} className="font-mono text-xs" placeholder={"run\n--project\nsrc/Apps/SimpleSign.Cli\n--"} />
          </div>
          <div className="flex flex-wrap gap-2">
            <Button disabled={busy} onClick={async () => {
              setBusy(true)
              try {
                load(await api.saveSettings(command.trim() || null, prefix.split("\n").map((l) => l.trim()).filter(Boolean)))
                toast.success(t("common.saved"))
              } catch (e) {
                toast.error((e as Error).message)
              } finally {
                setBusy(false)
              }
            }}><Save /> {t("common.save")}</Button>
            <Button variant="outline" disabled={busy} onClick={async () => {
              setBusy(true)
              try {
                setCheck(await api.checkCli())
              } catch (e) {
                toast.error((e as Error).message)
              } finally {
                setBusy(false)
              }
            }}>{busy ? <Loader2 className="animate-spin" /> : null} {t("settings.check")}</Button>
          </div>
        </div>
        <div className="rounded-md border px-3 py-1">
          <KeyValue stacked mono label={t("settings.resolved")}>{[view.resolvedProgram, ...view.resolvedPrefix].join(" ")}</KeyValue>
        </div>
        {check && (
          <div className="space-y-1 rounded-md border p-3 text-sm">
            <p className="flex items-center gap-2">
              {check.ok ? <CheckCircle2 className="text-success size-4" /> : <XCircle className="text-destructive size-4" />}
              {check.ok ? t("settings.checkOk") : t("settings.checkFail")}
            </p>
            <pre className="text-muted-foreground font-mono text-xs whitespace-pre-wrap">{check.commandLine}{"\n"}{check.output}</pre>
          </div>
        )}
      </Section>
    </div>
  )
}
