import { useEffect, useState } from "react"
import { Loader2 } from "lucide-react"
import { toast } from "sonner"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type { EnvironmentMode, ValidationSettings, XmlSample, XmlValidationView } from "@/lib/types"
import { cn } from "@/lib/utils"
import { CodeTabs, Indication } from "../shared/results"
import { ChoiceCard, Pill, Section } from "../shared/ui"
import { UploadButton } from "../shared/UploadButton"
import { SignatureList, XmlViews } from "../xml/XmlViews"
import { defaultValidationSettings, SettingsCard } from "./ValidationPage"

export function XmlValidateView({ environment }: { environment: EnvironmentMode }) {
  const { t } = useI18n()
  const [settings, setSettings] = useState<ValidationSettings>(() => defaultValidationSettings(environment))
  const [signature, setSignature] = useState<{ id: string; name: string } | null>(null)
  const [data, setData] = useState<{ id: string; name: string } | null>(null)
  const [view, setView] = useState<XmlValidationView | null>(null)
  const [busy, setBusy] = useState(false)
  const [samples, setSamples] = useState<XmlSample[]>([])
  useEffect(() => { api.xml.samples().then(setSamples).catch(() => setSamples([])) }, [])
  useEffect(() => setSettings(defaultValidationSettings(environment)), [environment])
  useEffect(() => {
    if (!signature) return
    let cancelled = false
    setBusy(true)
    api.xml.validate(signature.id, data?.id ?? null, settings)
      .then((v) => !cancelled && setView(v))
      .catch((e: Error) => toast.error(t("validation.failed"), { description: e.message }))
      .finally(() => !cancelled && setBusy(false))
    return () => { cancelled = true }
  }, [signature, data, settings, t])
  return (
    <div className="mx-auto grid max-w-7xl gap-6 p-6 lg:grid-cols-[300px_minmax(0,1fr)] lg:p-8">
      <aside className="space-y-4 lg:sticky lg:top-0 lg:self-start">
        <header className="space-y-1">
          <h2 className="text-2xl font-semibold tracking-tight">{t("xml.validate.title")}</h2>
          <p className="text-muted-foreground text-sm">{t("xml.validate.intro")}</p>
        </header>
        <SettingsCard settings={settings} onChange={setSettings} />
      </aside>
      <main className="min-w-0 space-y-6">
        <Section title={t("cades.validate.samples")} description={t("xml.validate.samplesHint")}>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {samples.filter((s) => s.kind === "validation").map((s) => (
              <ChoiceCard key={s.id} selected={signature?.id === s.fileId} title={s.title}
                onSelect={() => { setSignature({ id: s.fileId, name: s.fileName }); setData(s.dataId ? { id: s.dataId, name: "pedido.xml" } : null) }}
                description={<>{s.expectedIndication && <span className="mb-1.5 block"><Indication value={s.expectedIndication as "Valid"} /></span>}{s.description}</>} />
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <UploadButton label={t("xml.validate.upload")} accept=".xml,text/xml,application/xml" onUploaded={(f) => { setSignature({ id: f.id, name: f.fileName }); setData(null) }} />
            <UploadButton label={t("xml.validate.uploadData")} accept=".xml,text/xml,application/xml" onUploaded={(f) => setData({ id: f.id, name: f.fileName })} />
            {signature && <span className="text-muted-foreground text-sm">{t("cades.validate.current", { signature: signature.name, data: data?.name ?? "—" })}</span>}
          </div>
        </Section>
        {busy && !view && <Loader2 className="size-5 animate-spin" />}
        {view && (
          <>
            <div className={cn("flex flex-wrap items-center gap-3 rounded-lg border p-4", view.overall === "Valid" ? "border-success/40 bg-success/5" : view.overall === "Invalid" ? "border-destructive/40 bg-destructive/5" : "")}>
              <Indication value={view.overall} />
              <Pill>{t(`xml.mode.${view.mode}.title` as MessageKey)}</Pill>
              <span className="text-muted-foreground text-xs">{t("xml.validate.summary", { n: view.signatures.length, ms: view.ms })}</span>
              {busy && <Loader2 className="size-4 animate-spin" />}
            </div>
            <SignatureList view={view} />
            <XmlViews view={view} />
            <Section title={t("result.tabs.code")}><CodeTabs code={view.code} /></Section>
          </>
        )}
      </main>
    </div>
  )
}
