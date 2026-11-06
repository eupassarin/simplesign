import { useEffect, useState } from "react"
import { Loader2 } from "lucide-react"
import { toast } from "sonner"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { CadesSample, CadesValidationView, EnvironmentMode, ValidationSettings } from "@/lib/types"
import { cn } from "@/lib/utils"
import { CmsStructure, SignerTree } from "../cades/CmsViews"
import { CodeTabs, Indication } from "../shared/results"
import { ChoiceCard, Section } from "../shared/ui"
import { UploadButton } from "../shared/UploadButton"
import { defaultValidationSettings, SettingsCard } from "./ValidationPage"

export function CadesValidateView({ environment }: { environment: EnvironmentMode }) {
  const { t } = useI18n()
  const [settings, setSettings] = useState<ValidationSettings>(() => defaultValidationSettings(environment))
  const [signature, setSignature] = useState<{ id: string; name: string } | null>(null)
  const [data, setData] = useState<{ id: string; name: string } | null>(null)
  const [view, setView] = useState<CadesValidationView | null>(null)
  const [busy, setBusy] = useState(false)
  const [samples, setSamples] = useState<CadesSample[]>([])
  useEffect(() => { api.cades.samples().then(setSamples).catch(() => setSamples([])) }, [])
  useEffect(() => setSettings(defaultValidationSettings(environment)), [environment])
  const validationSamples = samples.filter((s) => s.kind !== "data")
  const dataName = (id: string | null | undefined) => samples.find((s) => s.fileId === id)?.fileName ?? data?.name ?? ""

  useEffect(() => {
    if (!signature) return
    let cancelled = false
    setBusy(true)
    api.cades.validate(signature.id, data?.id ?? null, settings)
      .then((v) => !cancelled && setView(v))
      .catch((e: Error) => toast.error(t("validation.failed"), { description: e.message }))
      .finally(() => !cancelled && setBusy(false))
    return () => { cancelled = true }
  }, [signature, data, settings, t])

  return (
    <div className="mx-auto grid max-w-7xl gap-6 p-6 lg:grid-cols-[300px_minmax(0,1fr)] lg:p-8">
      <aside className="space-y-4 lg:sticky lg:top-0 lg:self-start">
        <header className="space-y-1">
          <h2 className="text-2xl font-semibold tracking-tight">{t("cades.validate.title")}</h2>
          <p className="text-muted-foreground text-sm">{t("cades.validate.intro")}</p>
        </header>
        <SettingsCard settings={settings} onChange={setSettings} />
      </aside>
      <main className="min-w-0 space-y-6">
        <Section title={t("cades.validate.samples")} description={t("cades.validate.samplesHint")}>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {validationSamples.map((s) => (
              <ChoiceCard key={s.id} selected={signature?.id === s.fileId && (data?.id ?? null) === (s.dataId ?? null)} title={s.title}
                onSelect={() => { setSignature({ id: s.fileId, name: s.fileName }); setData(s.dataId ? { id: s.dataId, name: dataName(s.dataId) } : null) }}
                description={<>{s.expectedIndication && <span className="mb-1.5 block"><Indication value={s.expectedIndication as "Valid"} /></span>}{s.description}</>} />
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <UploadButton label={t("cades.data.uploadSignature")} accept=".p7s,.p7m,.p7b,.der" onUploaded={(f) => { setSignature({ id: f.id, name: f.fileName }); setData(null) }} />
            <UploadButton label={t("cades.validate.uploadData")} accept="*/*" onUploaded={(f) => setData({ id: f.id, name: f.fileName })} />
            {signature && <span className="text-muted-foreground text-sm">{t("cades.validate.current", { signature: signature.name, data: data?.name ?? "—" })}</span>}
          </div>
        </Section>
        {busy && !view && <Loader2 className="size-5 animate-spin" />}
        {view && (
          <>
            <div className={cn("flex flex-wrap items-center gap-3 rounded-lg border p-4", view.overall === "Valid" ? "border-success/40 bg-success/5" : view.overall === "Invalid" ? "border-destructive/40 bg-destructive/5" : "")}>
              <Indication value={view.overall} />
              <span className="text-muted-foreground text-xs">{t("cades.validate.summary", { n: view.signers.length, ms: view.ms })}</span>
              {busy && <Loader2 className="size-4 animate-spin" />}
            </div>
            <SignerTree view={view} />
            <Section title={t("cades.result.structure")} description={t("cades.result.structureHint")}><CmsStructure facts={view.structure} /></Section>
            <Section title={t("result.tabs.code")}><CodeTabs code={view.code} /></Section>
          </>
        )}
      </main>
    </div>
  )
}
