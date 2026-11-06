import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  ArrowLeft, ArrowRight, Check, CircleAlert, Download, FileCode2, FileText, Landmark, Layers, Loader2, PenTool, Receipt, RotateCcw, ScrollText, ShieldCheck,
} from "lucide-react"
import { toast } from "sonner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type {
  CredentialFacts, EnvironmentInfo, EnvironmentMode, OptionState, ValidationSettings, XadesExtendedChoice, XadesFormChoice, XadesIcpPolicy, XmlOptions, XmlOptionsResponse, XmlSample, XmlSignResult, XmlValidationView,
} from "@/lib/types"
import { cn } from "@/lib/utils"
import { UploadButton } from "../cades/CadesPage"
import { CredentialPicker } from "../credentials/CredentialPicker"
import { CodeTabs, Indication } from "../pdf-signing/steps/ResultStep"
import { hashes, paddings } from "../pdf-signing/steps/CryptoStep"
import { levels, TsaPicker } from "../pdf-signing/steps/TypeStep"
import { ChoiceCard, Field, IssueList, KeyValue, Pill, Section, ToggleRow } from "../pdf-signing/ui"
import { defaultValidationSettings, SettingsCard } from "../validation/ValidationPage"

const profiles = ["nfe", "evento", "inutilizacao", "cte", "mdfe", "nfse", "esocial", "reinf"]
const forms: XadesFormChoice[] = ["Enveloped", "Detached", "Enveloping"]
const icpPolicies: { id: XadesIcpPolicy; title: string; level: string }[] = [
  { id: "AdRb", title: "AD-RB", level: "B-B" },
  { id: "AdRt", title: "AD-RT", level: "B-T" },
  { id: "AdRv", title: "AD-RV", level: "XAdES-X" },
  { id: "AdRc", title: "AD-RC", level: "XAdES-X-L" },
  { id: "AdRa", title: "AD-RA", level: "XAdES-A" },
]
const extendedForms: { id: XadesExtendedChoice; title: string }[] = [
  { id: "None", title: "—" },
  { id: "CompleteReferences", title: "XAdES-X" },
  { id: "ExtendedLong", title: "XAdES-X-L" },
  { id: "Archive", title: "XAdES-A" },
]
const commitments = ["ProofOfOrigin", "ProofOfReceipt", "ProofOfDelivery", "ProofOfSender", "ProofOfApproval", "ProofOfCreation"]

function defaults(environment: EnvironmentMode): XmlOptions {
  return {
    environment,
    mode: "Xades",
    form: "Enveloped",
    dataUri: "document.xml",
    kind: "Baseline",
    level: "BB",
    icpPolicy: "AdRb",
    policyOid: "2.16.76.1.7.1.6.2.3",
    policyUri: "",
    extendedForm: "None",
    timestamp: { provider: environment === "Sandbox" ? "Sandbox" : "DigiCert", auth: "None" },
    hash: "Sha256",
    padding: "Pkcs1",
    signingCertificateV1: false,
    signerRoles: [],
    profile: "nfe",
    signAll: false,
    validate: true,
  }
}

type StepId = "data" | "signer" | "type" | "crypto" | "details"
const stepIds: StepId[] = ["data", "signer", "type", "crypto", "details"]

function useXmlState(environment: EnvironmentMode) {
  const [options, setOptions] = useState<XmlOptions>(() => defaults(environment))
  const [response, setResponse] = useState<XmlOptionsResponse | null>(null)
  const [samples, setSamples] = useState<XmlSample[]>([])
  const [env, setEnv] = useState<EnvironmentInfo | null>(null)
  const [evaluating, setEvaluating] = useState(false)
  const sequence = useRef(0)
  const { locale } = useI18n()
  useEffect(() => {
    api.xml.samples().then(setSamples).catch(() => {})
    api.env().then(setEnv).catch(() => {})
  }, [locale])
  useEffect(() => setOptions((o) => ({ ...defaults(environment), mode: o.mode, dataId: o.dataId, profile: o.profile })), [environment])
  useEffect(() => {
    const id = ++sequence.current
    setEvaluating(true)
    const timer = setTimeout(() => {
      api.xml.options(options)
        .then((r) => id === sequence.current && setResponse(r))
        .catch(() => {})
        .finally(() => id === sequence.current && setEvaluating(false))
    }, 120)
    return () => clearTimeout(timer)
  }, [options, locale])
  const update = useCallback((patch: Partial<XmlOptions>) => setOptions((o) => ({ ...o, ...patch })), [])
  const state = useCallback((key: string): OptionState => response?.report.options[key] ?? { visible: true }, [response])
  const reset = useCallback(() => setOptions(defaults(environment)), [environment])
  return { options, update, response, state, samples, env, environment, evaluating, reset }
}

type XmlState = ReturnType<typeof useXmlState>

export function XmlPage({ environment }: { environment: EnvironmentMode }) {
  const { t } = useI18n()
  const xml = useXmlState(environment)
  const [tab, setTab] = useState("sign")
  return (
    <Tabs value={tab} onValueChange={setTab} className="flex min-h-0 flex-1 flex-col gap-0">
      <div className="border-b px-4 py-2">
        <TabsList>
          <TabsTrigger value="sign"><PenTool /> {t("cades.tabs.sign")}</TabsTrigger>
          <TabsTrigger value="validate"><ShieldCheck /> {t("cades.tabs.validate")}</TabsTrigger>
        </TabsList>
      </div>
      <TabsContent value="sign" className="flex min-h-0 flex-1 flex-col"><SignWizard xml={xml} /></TabsContent>
      <TabsContent value="validate" className="min-h-0 flex-1 overflow-y-auto"><ValidateView samples={xml.samples} environment={environment} /></TabsContent>
    </Tabs>
  )
}

function SignWizard({ xml }: { xml: XmlState }) {
  const { t, number } = useI18n()
  const { options, update, response, evaluating, reset } = xml
  const [current, setCurrent] = useState(0)
  const [result, setResult] = useState<XmlSignResult | null>(null)
  const [signing, setSigning] = useState(false)
  const showingResult = current === stepIds.length
  const issues = response?.report.issues ?? []
  const errorsByStep = useMemo(() => {
    const map = new Map<string, number>()
    for (const i of issues) if (i.severity === "Error") map.set(i.step, (map.get(i.step) ?? 0) + 1)
    return map
  }, [issues])
  const canSign = response?.report.canSign ?? false

  async function sign() {
    setCurrent(stepIds.length)
    setSigning(true)
    setResult(null)
    try {
      const r = await api.xml.sign(options)
      setResult(r)
      if (!r.success) toast.error(t("sign.failed"), { description: r.error ?? undefined })
    } catch (e) {
      toast.error(t("sign.failed"), { description: (e as Error).message })
    } finally {
      setSigning(false)
    }
  }

  const stepId = stepIds[current]
  const stepIssues = stepId ? issues.filter((i) => i.step === stepId) : []
  const effective = response?.report.effective
  return (
    <div className="grid min-h-0 flex-1 lg:grid-cols-[230px_minmax(0,1fr)_300px]">
      <nav className="border-r p-3 max-lg:hidden">
        <ol className="space-y-0.5">
          {stepIds.map((s, i) => {
            const errors = errorsByStep.get(s) ?? 0
            return (
              <li key={s}>
                <button onClick={() => setCurrent(i)}
                  className={cn("flex w-full items-start gap-3 rounded-md px-2.5 py-2 text-left transition-colors", i === current ? "bg-accent" : "hover:bg-accent/50")}>
                  <span className={cn("mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border text-[11px] font-medium",
                    i === current && "border-primary bg-primary text-primary-foreground", errors > 0 && i !== current && "border-destructive text-destructive")}>
                    {errors > 0 ? "!" : i < current ? <Check className="size-3" /> : i + 1}
                  </span>
                  <span className="min-w-0">
                    <span className="block text-sm font-medium">{t(`xml.steps.${s}.title` as MessageKey)}</span>
                    <span className="text-muted-foreground block truncate text-xs">{t(`xml.steps.${s}.subtitle` as MessageKey)}</span>
                  </span>
                </button>
              </li>
            )
          })}
          <li>
            <button onClick={() => result && setCurrent(stepIds.length)} disabled={!result}
              className={cn("flex w-full items-start gap-3 rounded-md px-2.5 py-2 text-left", showingResult ? "bg-accent" : "hover:bg-accent/50", !result && "opacity-50")}>
              <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border text-[11px]">✓</span>
              <span><span className="block text-sm font-medium">{t("steps.result.title")}</span><span className="text-muted-foreground block text-xs">{t("cades.steps.result")}</span></span>
            </button>
          </li>
        </ol>
        <Separator className="my-3" />
        <Button variant="ghost" size="sm" className="w-full justify-start" onClick={() => { reset(); setCurrent(0); setResult(null) }}>
          <RotateCcw /> {t("sign.startOver")}
        </Button>
      </nav>

      <div className="min-h-0 min-w-0 overflow-y-auto">
        <div className="mx-auto max-w-5xl space-y-6 p-6 lg:p-8">
          <header className="space-y-1">
            <p className="text-muted-foreground text-xs font-medium tracking-wide uppercase">{showingResult ? t("steps.result.title") : t("sign.stepOf", { n: current + 1, total: stepIds.length })}</p>
            <h2 className="text-2xl font-semibold tracking-tight">{showingResult ? t("xml.result.title") : t(`xml.steps.${stepId}.title` as MessageKey)}</h2>
          </header>
          {!showingResult && stepIssues.length > 0 && <IssueList issues={stepIssues} />}
          {showingResult
            ? signing ? <Loader2 className="size-5 animate-spin" /> : result && <ResultView result={result} />
            : <>
              {stepId === "data" && <DataStep xml={xml} />}
              {stepId === "signer" && (
                <CredentialPicker environment={xml.environment} env={xml.env} credential={response?.credential ?? null}
                  onCredential={(facts: CredentialFacts) => update({ credentialId: facts.id })} />
              )}
              {stepId === "type" && <TypeStep xml={xml} />}
              {stepId === "crypto" && <CryptoStep xml={xml} />}
              {stepId === "details" && <DetailsStep xml={xml} />}
            </>}
          {!showingResult && (
            <div className="flex items-center justify-between border-t pt-6">
              <Button variant="outline" onClick={() => setCurrent((c) => Math.max(0, c - 1))} disabled={current === 0}><ArrowLeft /> {t("common.back")}</Button>
              {current < stepIds.length - 1 ? (
                <Button onClick={() => setCurrent((c) => c + 1)}>{t("common.next")} <ArrowRight /></Button>
              ) : (
                <Button onClick={sign} disabled={!canSign || signing}>{signing ? <Loader2 className="animate-spin" /> : <PenTool />} {t("sign.sign")}</Button>
              )}
            </div>
          )}
        </div>
      </div>

      <aside className="bg-muted/20 border-l max-lg:hidden">
        <div className="h-full overflow-y-auto">
          <div className="space-y-5 p-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold">{t("sign.summary.title")}</h3>
              {evaluating && <Loader2 className="text-muted-foreground size-3.5 animate-spin" />}
            </div>
            <div className="divide-y rounded-lg border bg-background px-3">
              <KeyValue label={t("xml.summary.mode")}>{t(`xml.mode.${options.mode}.title` as MessageKey)}</KeyValue>
              <KeyValue label={t("cades.summary.data")}>{response?.data?.fileName ?? "—"}</KeyValue>
              <KeyValue label={t("sign.summary.signer")}>{response?.credential?.holder ?? "—"}</KeyValue>
              {options.mode === "Xades"
                ? <KeyValue label={t("xml.summary.form")}>{t(`xml.form.${effective?.form ?? options.form}.title` as MessageKey)}</KeyValue>
                : <KeyValue label={t("xml.summary.profile")}>{t(`xml.profiles.${options.profile}.title` as MessageKey)}</KeyValue>}
              <KeyValue label={t("sign.summary.level")}>{response?.report.effectiveLevel ?? "—"}</KeyValue>
            </div>
            {issues.length === 0 ? (
              <p className="text-success flex items-center gap-1.5 text-xs"><Check className="size-3.5" /> {t("sign.summary.compatible")}</p>
            ) : (
              <div className="space-y-2">
                <p className="flex items-center gap-1.5 text-xs font-medium"><CircleAlert className="size-3.5" /> {t("sign.summary.notes")}</p>
                <IssueList issues={issues} />
              </div>
            )}
            <Button className="w-full" onClick={sign} disabled={!canSign || signing}>
              {signing ? <Loader2 className="animate-spin" /> : <PenTool />} {t("sign.signNow")}
            </Button>
            {result?.success && <p className="text-muted-foreground text-xs">{t("cades.result.size", { size: number(result.bytes / 1024, 1) })}</p>}
          </div>
        </div>
      </aside>
    </div>
  )
}

function Note({ state }: { state: OptionState }) {
  return state.note ? <p className="text-muted-foreground rounded-lg border border-dashed p-3 text-xs">{state.note}</p> : null
}

function DataStep({ xml }: { xml: XmlState }) {
  const { t } = useI18n()
  const { options, update, state, samples, response } = xml
  const dataSamples = samples.filter((s) => s.kind === "data" && s.mode === options.mode)
  const facts = response?.data
  const targets = facts?.fiscalTargets[options.profile] ?? []
  return (
    <div className="space-y-8">
      <Section title={t("xml.data.mode")} description={t("xml.data.modeHint")}>
        <div className="grid gap-3 md:grid-cols-2">
          {(["Xades", "Fiscal"] as const).map((m) => (
            <ChoiceCard key={m} selected={options.mode === m} state={state(`mode.${m}`)} icon={m === "Xades" ? <FileCode2 className="size-4" /> : <Receipt className="size-4" />}
              onSelect={() => {
                const first = samples.find((s) => s.kind === "data" && s.mode === m)
                update({ mode: m, dataId: first?.fileId ?? null, profile: first?.profile ?? options.profile, elementId: null, signAll: false })
              }}
              title={t(`xml.mode.${m}.title` as MessageKey)} description={t(`xml.mode.${m}.hint` as MessageKey)} />
          ))}
        </div>
      </Section>

      <Section title={t("xml.data.file")} description={t("xml.data.fileHint")}>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {dataSamples.map((s) => (
            <ChoiceCard key={s.id} selected={options.dataId === s.fileId} icon={<FileText className="size-4" />} title={s.title} description={s.description}
              onSelect={() => update({ dataId: s.fileId, ...(s.profile ? { profile: s.profile } : {}), elementId: null, signAll: false })} />
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <UploadButton label={t("xml.data.upload")} accept=".xml,text/xml,application/xml" onUploaded={(f) => update({ dataId: f.id, elementId: null })} />
          {facts && (
            <span className="text-muted-foreground text-sm">
              {facts.error ? facts.error : t("xml.data.facts", { name: facts.fileName, root: facts.root ?? "?", n: facts.signatures })}
            </span>
          )}
        </div>
      </Section>

      {options.mode === "Fiscal" ? (
        <Section title={t("xml.data.profile")} description={t("xml.data.profileHint")}>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {profiles.map((p) => (
              <ChoiceCard key={p} selected={options.profile === p} onSelect={() => update({ profile: p, elementId: null })} state={state(`profile.${p}`)}
                title={t(`xml.profiles.${p}.title` as MessageKey)} description={t(`xml.profiles.${p}.hint` as MessageKey)}
                badge={targets.length > 0 && options.profile === p ? <Pill tone="success">{targets[0] === "" ? "URI=\"\"" : targets.length}</Pill> : undefined} />
            ))}
          </div>
          <ToggleRow checked={options.signAll} onChange={(signAll) => update({ signAll })} state={state("signAll")} label={t("xml.data.signAll")} description={t("xml.data.signAllHint")} />
          {state("elementId").visible && (
            <Field label={t("xml.data.elementId")} description={t("xml.data.elementIdHint")}>
              <Select value={options.elementId ?? ""} onValueChange={(v) => update({ elementId: v })}>
                <SelectTrigger className="w-full max-w-xl font-mono text-xs"><SelectValue placeholder={t("xml.data.chooseId")} /></SelectTrigger>
                <SelectContent>{targets.map((id) => <SelectItem key={id} value={id} className="font-mono text-xs">{id}</SelectItem>)}</SelectContent>
              </Select>
            </Field>
          )}
        </Section>
      ) : (
        <Section title={t("xml.data.form")} description={t("xml.data.formHint")}>
          <div className="grid gap-3 md:grid-cols-3">
            {forms.map((f) => (
              <ChoiceCard key={f} selected={options.form === f} onSelect={() => update({ form: f })} state={state(`form.${f}`)}
                title={t(`xml.form.${f}.title` as MessageKey)} description={t(`xml.form.${f}.hint` as MessageKey)} />
            ))}
          </div>
          {state("dataUri").visible && (
            <Field label={t("xml.data.dataUri")} description={t("xml.data.dataUriHint")}>
              <Input value={options.dataUri} onChange={(e) => update({ dataUri: e.target.value })} className="max-w-md font-mono" />
            </Field>
          )}
        </Section>
      )}
    </div>
  )
}

function TypeStep({ xml }: { xml: XmlState }) {
  const { t } = useI18n()
  const { options, update, state, response, env } = xml
  if (options.mode === "Fiscal") return <Note state={state("kind")} />
  const extended = state("extendedForm")
  return (
    <div className="space-y-8">
      <Section title={t("type.kind")} description={t("xml.type.kindHint")}>
        <div className="grid gap-3 md:grid-cols-3">
          <ChoiceCard selected={options.kind === "Baseline"} onSelect={() => update({ kind: "Baseline" })} title={t("xml.type.baseline")} description={t("xml.type.baselineHint")} icon={<Layers className="size-4" />} state={state("kind.Baseline")} />
          <ChoiceCard selected={options.kind === "IcpBrasil"} onSelect={() => update({ kind: "IcpBrasil" })} title={t("type.icp")} description={t("xml.type.icpHint")} icon={<Landmark className="size-4" />} state={state("kind.IcpBrasil")} />
          <ChoiceCard selected={options.kind === "CustomPolicy"} onSelect={() => update({ kind: "CustomPolicy" })} title={t("type.custom")} description={t("cades.type.customHint")} icon={<ScrollText className="size-4" />} state={state("kind.CustomPolicy")} />
        </div>
      </Section>
      {options.kind === "IcpBrasil" ? (
        <Section title={t("xml.type.icpPolicy")} description={t("xml.type.icpPolicyHint")}>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {icpPolicies.map((p) => (
              <ChoiceCard key={p.id} selected={options.icpPolicy === p.id} onSelect={() => update({ icpPolicy: p.id })} title={`${p.title} · ${p.level}`} description={t(`cades.icp.${p.id}` as MessageKey)} />
            ))}
          </div>
        </Section>
      ) : (
        <Section title={t("type.level")} description={t("cades.type.levelHint")}>
          <div className="grid gap-3 sm:grid-cols-2">
            {levels.map((l) => (
              <ChoiceCard key={l.id} selected={options.level === l.id} onSelect={() => update({ level: l.id })} title={l.title} description={t(`xml.levels.${l.id}` as MessageKey)} state={state(`level.${l.id}`)} />
            ))}
          </div>
        </Section>
      )}
      {state("customPolicy").visible && (
        <Section title={t("type.policy")} description={t("cades.type.policyHint")}>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t("type.policyOid")}><Input value={options.policyOid} onChange={(e) => update({ policyOid: e.target.value })} className="font-mono" /></Field>
            <Field label={t("type.policyUri")}><Input value={options.policyUri ?? ""} onChange={(e) => update({ policyUri: e.target.value })} /></Field>
          </div>
        </Section>
      )}
      {extended.visible ? (
        <Section title={t("xml.type.extended")} description={t("xml.type.extendedHint")}>
          <div className="grid gap-3 sm:grid-cols-2">
            {extendedForms.map((f) => (
              <ChoiceCard key={f.id} selected={(response?.report.effective.extendedForm ?? options.extendedForm) === f.id} onSelect={() => update({ extendedForm: f.id })}
                title={f.id === "None" ? t("cades.extended.None") : f.title} description={t(`xml.extendedHints.${f.id}` as MessageKey)} state={state(`extendedForm.${f.id}`)} />
            ))}
          </div>
        </Section>
      ) : <Note state={extended} />}
      {state("timestamp").visible && (
        <Section title={t("type.timestamp")} description={t("type.timestampHint", { level: response?.report.effectiveLevel ?? "" })} infoId="timestamp">
          <TsaPicker value={options.timestamp} onChange={(timestamp) => update({ timestamp })} state={state} env={env} />
        </Section>
      )}
    </div>
  )
}

function CryptoStep({ xml }: { xml: XmlState }) {
  const { t } = useI18n()
  const { options, update, state, response } = xml
  if (options.mode === "Fiscal") return <Note state={state("hash")} />
  const padding = state("padding")
  const credential = response?.credential
  return (
    <div className="space-y-8">
      <Section title={t("crypto.hash")} infoId="hash" description={credential ? t("crypto.hashFiltered", { holder: credential.holder, source: credential.source }) : t("crypto.hashNoSigner")}>
        <div className="grid gap-3 sm:grid-cols-3">
          {hashes.map((h) => (
            <ChoiceCard key={h.id} selected={options.hash === h.id} onSelect={() => update({ hash: h.id })} title={h.title} description={t(`crypto.hashes.${h.id}` as MessageKey)} state={state(`hash.${h.id}`)} />
          ))}
        </div>
      </Section>
      {padding.visible ? (
        <Section title={t("crypto.padding")} infoId="padding">
          <div className="grid gap-3 sm:grid-cols-2">
            {paddings.map((p) => (
              <ChoiceCard key={p.id} selected={(response?.report.effective.padding ?? options.padding) === p.id} onSelect={() => update({ padding: p.id })} title={p.title}
                description={t(`crypto.paddings.${p.id}` as MessageKey)} state={state(`padding.${p.id}`)} />
            ))}
          </div>
        </Section>
      ) : <Note state={padding} />}
    </div>
  )
}

function DetailsStep({ xml }: { xml: XmlState }) {
  const { t } = useI18n()
  const { options, update, state } = xml
  const signingCertificate = state("signingCertificate")
  return (
    <div className="space-y-6">
      {options.mode === "Xades" && (
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("xml.details.roles")} description={t("xml.details.rolesHint")}>
            <Input value={options.signerRoles.join(", ")} onChange={(e) => update({ signerRoles: e.target.value.split(",").map((r) => r.trimStart()) })} placeholder={t("xml.details.rolesPlaceholder")} />
          </Field>
          <Field label={t("xml.details.mimeType")} description={t("xml.details.mimeTypeHint")}>
            <Input value={options.mimeType ?? ""} onChange={(e) => update({ mimeType: e.target.value || null })} placeholder="text/xml" className="font-mono" />
          </Field>
          <Field label={t("cades.details.commitment")} description={t("cades.details.commitmentHint")}>
            <Select value={options.commitment ?? "none"} onValueChange={(v) => update({ commitment: v === "none" ? null : v })}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="none">{t("cades.details.noCommitment")}</SelectItem>
                {commitments.map((c) => <SelectItem key={c} value={c}>{t(`details.commitments.${c}` as MessageKey)}</SelectItem>)}
              </SelectContent>
            </Select>
          </Field>
          <Field label={t("cades.details.signingTime")} description={t("cades.details.signingTimeHint")}>
            <Input type="datetime-local" value={options.signingTime ? options.signingTime.slice(0, 16) : ""}
              onChange={(e) => update({ signingTime: e.target.value ? new Date(e.target.value).toISOString() : null })} />
          </Field>
          <Field label={t("details.operationId")} description={t("details.operationIdHint")}>
            <Input value={options.operationId ?? ""} onChange={(e) => update({ operationId: e.target.value })} placeholder={t("details.operationIdPlaceholder")} />
          </Field>
        </div>
      )}
      {options.mode === "Xades" && (
        <ToggleRow checked={signingCertificate.disabled ? true : options.signingCertificateV1} onChange={(signingCertificateV1) => update({ signingCertificateV1 })} state={signingCertificate}
          label={t("xml.details.v1")} description={t("xml.details.v1Hint")} />
      )}
      <ToggleRow checked={options.validate} onChange={(validate) => update({ validate })} label={t("cades.details.validate")} description={t("xml.details.validateHint")} />
    </div>
  )
}

function SignatureList({ view }: { view: XmlValidationView }) {
  const { t } = useI18n()
  return (
    <div className="space-y-3">
      {view.errors.length > 0 && <ul className="text-destructive space-y-1 text-xs">{view.errors.map((e) => <li key={e}>✕ {e}</li>)}</ul>}
      {view.signatures.map((s) => (
        <div key={s.index} className="rounded-lg border">
          <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
            <span className="text-sm font-medium">{t("cades.result.signer", { n: s.index + 1 })}</span>
            <span className="text-muted-foreground truncate text-sm">{s.signer ?? "—"}</span>
            {s.cnpj && <Pill tone="info">CNPJ {s.cnpj}</Pill>}
            {s.level && <Pill>{s.level}</Pill>}
            {s.reference && <span className="text-muted-foreground font-mono text-xs">{s.reference}</span>}
            <span className="ml-auto"><Indication value={s.indication} /></span>
          </div>
          <div className="divide-y px-4">
            {s.checks.map((c) => (
              <div key={c.id} className="flex items-start gap-3 py-2 text-sm">
                <span className={cn("mt-0.5 size-2 shrink-0 rounded-full", c.status === "pass" ? "bg-success" : c.status === "fail" ? "bg-destructive" : c.status === "warn" ? "bg-warning" : "bg-muted-foreground/40")} />
                <span className="min-w-0 flex-1">{c.name}{c.detail && <span className="text-muted-foreground block text-xs break-words">{c.detail}</span>}</span>
                <span className="text-muted-foreground text-xs">{c.status}</span>
              </div>
            ))}
          </div>
          {(s.errors.length > 0 || s.warnings.length > 0) && (
            <ul className="space-y-1 border-t px-4 py-2 text-xs">
              {s.errors.map((e) => <li key={e} className="text-destructive">✕ {e}</li>)}
              {s.warnings.map((w) => <li key={w} className="text-muted-foreground">! {w}</li>)}
            </ul>
          )}
        </div>
      ))}
    </div>
  )
}

function XmlViews({ view }: { view: XmlValidationView }) {
  const { t } = useI18n()
  return (
    <>
      {view.signatureXml && (
        <Section title={t("xml.result.signature")} description={t("xml.result.signatureHint")}>
          <pre className="bg-muted max-h-96 overflow-auto rounded-lg p-4 font-mono text-xs leading-relaxed">{view.signatureXml}</pre>
        </Section>
      )}
      <Section title={t("xml.result.document")} description={t("xml.result.documentHint")}>
        <pre className="bg-muted max-h-72 overflow-auto rounded-lg p-4 font-mono text-xs leading-relaxed">{view.documentPreview}</pre>
      </Section>
    </>
  )
}

function ResultView({ result }: { result: XmlSignResult }) {
  const { t, number } = useI18n()
  if (!result.success) {
    return (
      <div className="space-y-4">
        <Alert variant="destructive">
          <AlertTitle>{t("result.failed", { type: result.errorType ?? "" })}</AlertTitle>
          <AlertDescription className="break-words">{result.error}</AlertDescription>
        </Alert>
        <IssueList issues={result.issues} />
        {result.code.cSharp && <CodeTabs code={result.code} />}
      </div>
    )
  }
  const view = result.validation
  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-center gap-3 rounded-lg border p-4">
        <FileCode2 className="text-success size-6" />
        <div className="min-w-0 flex-1">
          <p className="font-medium">{t("result.signed", { level: result.requestedLevel })}</p>
          <p className="text-muted-foreground text-xs">{t("cades.result.summary", { name: result.fileName ?? "", size: number(result.bytes / 1024, 1), ms: result.signMs, achieved: result.achievedLevel ?? "" })}</p>
        </div>
        {view && <Indication value={view.overall} />}
        <Button asChild><a href={api.fileUrl(result.outputId!, true)}><Download /> {t("common.download")}</a></Button>
      </div>
      {result.warnings.length > 0 && (
        <Alert><AlertTitle>{t("result.warnings")}</AlertTitle><AlertDescription><ul>{result.warnings.map((w) => <li key={w}>{w}</li>)}</ul></AlertDescription></Alert>
      )}
      {view && (
        <>
          <Section title={t("cades.result.validation")} description={t("xml.result.validationHint")}><SignatureList view={view} /></Section>
          <XmlViews view={view} />
        </>
      )}
      <Section title={t("result.tabs.code")}><CodeTabs code={result.code} /></Section>
    </div>
  )
}

function ValidateView({ samples, environment }: { samples: XmlSample[]; environment: EnvironmentMode }) {
  const { t } = useI18n()
  const [settings, setSettings] = useState<ValidationSettings>(() => defaultValidationSettings(environment))
  const [signature, setSignature] = useState<{ id: string; name: string } | null>(null)
  const [data, setData] = useState<{ id: string; name: string } | null>(null)
  const [view, setView] = useState<XmlValidationView | null>(null)
  const [busy, setBusy] = useState(false)
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
