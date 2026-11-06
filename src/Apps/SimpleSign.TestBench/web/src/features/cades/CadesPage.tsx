import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  ArrowLeft, ArrowRight, Check, CircleAlert, Download, FileLock2, FilePlus2, FileUp, GitBranch, Landmark, Layers, Loader2, PenTool, RotateCcw, ScrollText, ShieldCheck, Users,
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
  CadesExtendedChoice, CadesIcpPolicy, CadesOptions, CadesOptionsResponse, CadesSample, CadesSignResult, CadesValidationView, CredentialFacts, EnvironmentInfo, EnvironmentMode, OptionState, ValidationSettings,
} from "@/lib/types"
import { cn } from "@/lib/utils"
import { CredentialPicker } from "../credentials/CredentialPicker"
import { CodeTabs, Indication } from "../pdf-signing/steps/ResultStep"
import { hashes, paddings } from "../pdf-signing/steps/CryptoStep"
import { levels, TsaPicker } from "../pdf-signing/steps/TypeStep"
import { ChoiceCard, Field, IssueList, KeyValue, Section, ToggleRow } from "../pdf-signing/ui"
import { defaultValidationSettings, SettingsCard } from "../validation/ValidationPage"
import { CmsStructure, SignerTree } from "./CmsViews"

const icpPolicies: { id: CadesIcpPolicy; title: string; level: string }[] = [
  { id: "AdRb", title: "AD-RB", level: "B-B" },
  { id: "AdRt", title: "AD-RT", level: "B-T" },
  { id: "AdRv", title: "AD-RV", level: "CAdES-X" },
  { id: "AdRc", title: "AD-RC", level: "CAdES-X Long" },
  { id: "AdRa", title: "AD-RA", level: "CAdES-A" },
]

const extendedForms: { id: CadesExtendedChoice; title: string }[] = [
  { id: "None", title: "—" },
  { id: "CompleteReferences", title: "CAdES-X" },
  { id: "ExtendedLong", title: "CAdES-X Long" },
  { id: "Archive", title: "CAdES-A" },
]

const commitments = ["ProofOfOrigin", "ProofOfReceipt", "ProofOfDelivery", "ProofOfSender", "ProofOfApproval", "ProofOfCreation"]

function defaults(environment: EnvironmentMode): CadesOptions {
  return {
    environment,
    operation: "Sign",
    signerIndex: 0,
    contentType: "Detached",
    kind: "Baseline",
    level: "BB",
    icpPolicy: "AdRb",
    policyOid: "2.16.76.1.7.1.1.2.3",
    policyUri: "",
    extendedForm: "None",
    timestamp: { provider: environment === "Sandbox" ? "Sandbox" : "DigiCert", auth: "None" },
    hash: "Sha256",
    padding: "Pkcs1",
    validate: true,
  }
}

type StepId = "data" | "signer" | "type" | "crypto" | "details"
const stepIds: StepId[] = ["data", "signer", "type", "crypto", "details"]

interface CadesState {
  options: CadesOptions
  update: (patch: Partial<CadesOptions>) => void
  response: CadesOptionsResponse | null
  state: (key: string) => OptionState
  samples: CadesSample[]
  env: EnvironmentInfo | null
  environment: EnvironmentMode
}

function useCadesState(environment: EnvironmentMode) {
  const [options, setOptions] = useState<CadesOptions>(() => defaults(environment))
  const [response, setResponse] = useState<CadesOptionsResponse | null>(null)
  const [samples, setSamples] = useState<CadesSample[]>([])
  const [env, setEnv] = useState<EnvironmentInfo | null>(null)
  const [evaluating, setEvaluating] = useState(false)
  const sequence = useRef(0)
  const { locale } = useI18n()

  useEffect(() => {
    api.cades.samples().then(setSamples).catch(() => {})
    api.env().then(setEnv).catch(() => {})
  }, [locale])
  useEffect(() => setOptions((o) => ({ ...defaults(environment), dataId: o.dataId })), [environment])
  useEffect(() => {
    const id = ++sequence.current
    setEvaluating(true)
    const timer = setTimeout(() => {
      api.cades.options(options)
        .then((r) => id === sequence.current && setResponse(r))
        .catch(() => {})
        .finally(() => id === sequence.current && setEvaluating(false))
    }, 120)
    return () => clearTimeout(timer)
  }, [options, locale])

  const update = useCallback((patch: Partial<CadesOptions>) => setOptions((o) => ({ ...o, ...patch })), [])
  const state = useCallback((key: string): OptionState => response?.report.options[key] ?? { visible: true }, [response])
  const reset = useCallback(() => setOptions(defaults(environment)), [environment])
  return { options, update, response, state, samples, env, environment, evaluating, reset }
}

export function CadesPage({ environment }: { environment: EnvironmentMode }) {
  const { t } = useI18n()
  const cades = useCadesState(environment)
  const [tab, setTab] = useState("sign")
  return (
    <Tabs value={tab} onValueChange={setTab} className="flex min-h-0 flex-1 flex-col gap-0">
      <div className="border-b px-4 py-2">
        <TabsList>
          <TabsTrigger value="sign"><PenTool /> {t("cades.tabs.sign")}</TabsTrigger>
          <TabsTrigger value="validate"><ShieldCheck /> {t("cades.tabs.validate")}</TabsTrigger>
        </TabsList>
      </div>
      <TabsContent value="sign" className="flex min-h-0 flex-1 flex-col"><SignWizard cades={cades} /></TabsContent>
      <TabsContent value="validate" className="min-h-0 flex-1 overflow-y-auto"><ValidateView samples={cades.samples} environment={environment} /></TabsContent>
    </Tabs>
  )
}

function SignWizard({ cades }: { cades: ReturnType<typeof useCadesState> }) {
  const { t, number } = useI18n()
  const { options, update, response, evaluating, reset } = cades
  const [current, setCurrent] = useState(0)
  const [result, setResult] = useState<CadesSignResult | null>(null)
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
      const r = await api.cades.sign(options)
      setResult(r)
      if (!r.success) toast.error(t("sign.failed"), { description: r.error ?? undefined })
    } catch (e) {
      toast.error(t("sign.failed"), { description: (e as Error).message })
    } finally {
      setSigning(false)
    }
  }

  function continueWith(operation: "CoSign" | "CounterSign") {
    if (!result?.outputId) return
    update({ operation, existingSignatureId: result.outputId, signerIndex: 0, credentialId: null })
    setResult(null)
    setCurrent(1)
    toast.info(t(operation === "CoSign" ? "cades.result.coSignNext" : "cades.result.counterSignNext"))
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
                    <span className="block text-sm font-medium">{t(`cades.steps.${s}.title` as MessageKey)}</span>
                    <span className="text-muted-foreground block truncate text-xs">{t(`cades.steps.${s}.subtitle` as MessageKey)}</span>
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
            <h2 className="text-2xl font-semibold tracking-tight">{showingResult ? t("cades.result.title") : t(`cades.steps.${stepId}.title` as MessageKey)}</h2>
          </header>
          {!showingResult && stepIssues.length > 0 && <IssueList issues={stepIssues} />}
          {showingResult
            ? signing ? <Loader2 className="size-5 animate-spin" /> : result && <ResultView result={result} onContinue={continueWith} />
            : <>
              {stepId === "data" && <DataStep cades={cades} />}
              {stepId === "signer" && (
                <CredentialPicker environment={cades.environment} env={cades.env} credential={response?.credential ?? null}
                  onCredential={(facts: CredentialFacts) => update({ credentialId: facts.id })} />
              )}
              {stepId === "type" && <TypeStep cades={cades} />}
              {stepId === "crypto" && <CryptoStep cades={cades} />}
              {stepId === "details" && <DetailsStep cades={cades} />}
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
              <KeyValue label={t("cades.summary.operation")}>{t(`cades.operation.${options.operation}.title` as MessageKey)}</KeyValue>
              <KeyValue label={t("cades.summary.data")}>{response?.inputs.dataName ?? "—"}</KeyValue>
              {options.operation !== "Sign" && <KeyValue label={t("cades.summary.existing")}>{response?.inputs.existing?.fileName ?? "—"}</KeyValue>}
              <KeyValue label={t("sign.summary.signer")}>{response?.credential?.holder ?? "—"}</KeyValue>
              <KeyValue label={t("cades.summary.content")}>{effective?.contentType === "Enveloped" ? ".p7m" : ".p7s"}</KeyValue>
              <KeyValue label={t("sign.summary.level")}>{response?.report.effectiveLevel ?? "—"}</KeyValue>
              <KeyValue label={t("sign.summary.digest")}>{effective?.hash.replace("Sha3_", "SHA3-").replace("Sha", "SHA-")}</KeyValue>
              {response?.credential?.keyAlgorithm === "RSA" && <KeyValue label={t("sign.summary.scheme")}>{effective?.padding === "Pss" ? "RSASSA-PSS" : "PKCS#1 v1.5"}</KeyValue>}
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

export function UploadButton({ label, accept, onUploaded }: { label: string; accept: string; onUploaded: (file: { id: string; fileName: string }) => void }) {
  const input = useRef<HTMLInputElement>(null)
  return (
    <>
      <Button variant="outline" size="sm" onClick={() => input.current?.click()}><FileUp /> {label}</Button>
      <input ref={input} type="file" accept={accept} hidden onChange={async (e) => {
        const file = e.target.files?.[0]
        if (!file) return
        const uploaded = await api.uploadFile(file)
        onUploaded({ id: uploaded.id, fileName: uploaded.fileName })
        e.target.value = ""
      }} />
    </>
  )
}

function DataStep({ cades }: { cades: CadesState }) {
  const { t } = useI18n()
  const { options, update, state, samples, response } = cades
  const data = state("data")
  const existing = response?.inputs.existing
  const dataSamples = samples.filter((s) => s.kind === "data")
  const signatureSamples = samples.filter((s) => s.kind === "signature")
  const contentType = state("contentType")
  return (
    <div className="space-y-8">
      <Section title={t("cades.data.operation")} description={t("cades.data.operationHint")}>
        <div className="grid gap-3 md:grid-cols-3">
          {(["Sign", "CoSign", "CounterSign"] as const).map((op) => (
            <ChoiceCard key={op} selected={options.operation === op} onSelect={() => update({ operation: op })} state={state(`operation.${op}`)}
              icon={op === "Sign" ? <PenTool className="size-4" /> : op === "CoSign" ? <Users className="size-4" /> : <GitBranch className="size-4" />}
              title={t(`cades.operation.${op}.title` as MessageKey)} description={t(`cades.operation.${op}.hint` as MessageKey)} />
          ))}
        </div>
      </Section>

      {state("existing").visible && (
        <Section title={t("cades.data.existing")} description={t("cades.data.existingHint")}>
          <div className="grid gap-3 sm:grid-cols-2">
            {signatureSamples.map((s) => (
              <ChoiceCard key={s.id} selected={options.existingSignatureId === s.fileId} icon={<FileLock2 className="size-4" />} title={s.title} description={s.description}
                onSelect={() => update({ existingSignatureId: s.fileId, dataId: s.dataId ?? options.dataId, signerIndex: 0 })} />
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <UploadButton label={t("cades.data.uploadSignature")} accept=".p7s,.p7m,.p7b,.der,application/pkcs7-signature,application/pkcs7-mime"
              onUploaded={(f) => update({ existingSignatureId: f.id, signerIndex: 0 })} />
            {existing && <span className="text-muted-foreground text-sm">{t("cades.data.existingFacts", { name: existing.fileName, n: existing.signers.length })}</span>}
          </div>
          {state("signerIndex").visible && existing && existing.signers.length > 0 && (
            <Field label={t("cades.data.signerIndex")} description={t("cades.data.signerIndexHint")}>
              <Select value={String(options.signerIndex)} onValueChange={(v) => update({ signerIndex: Number(v) })}>
                <SelectTrigger className="w-full max-w-md"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {existing.signers.map((s) => <SelectItem key={s.index} value={String(s.index)}>#{s.index + 1} · {s.subject ?? "—"}</SelectItem>)}
                </SelectContent>
              </Select>
            </Field>
          )}
        </Section>
      )}

      {data.visible ? (
        <Section title={t("cades.data.data")} description={data.note ?? t("cades.data.dataHint")}>
          <div className="grid gap-3 sm:grid-cols-3">
            {dataSamples.map((s) => (
              <ChoiceCard key={s.id} selected={options.dataId === s.fileId} onSelect={() => update({ dataId: s.fileId })} icon={<FilePlus2 className="size-4" />} title={s.title} description={s.description} />
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <UploadButton label={t("cades.data.upload")} accept="*/*" onUploaded={(f) => update({ dataId: f.id })} />
            {response?.inputs.dataName && <span className="text-muted-foreground text-sm">{t("validation.current", { name: response.inputs.dataName })}</span>}
          </div>
        </Section>
      ) : data.note && <p className="text-muted-foreground rounded-lg border border-dashed p-3 text-xs">{data.note}</p>}

      {contentType.visible ? (
        <Section title={t("cades.data.contentType")} description={contentType.disabled ?? t("cades.data.contentTypeHint")}>
          <div className="grid gap-3 sm:grid-cols-2">
            {(["Detached", "Enveloped"] as const).map((c) => (
              <ChoiceCard key={c} selected={(response?.report.effective.contentType ?? options.contentType) === c} onSelect={() => update({ contentType: c })} state={state(`contentType.${c}`)}
                title={t(`cades.content.${c}.title` as MessageKey)} description={t(`cades.content.${c}.hint` as MessageKey)} />
            ))}
          </div>
        </Section>
      ) : contentType.note && <p className="text-muted-foreground rounded-lg border border-dashed p-3 text-xs">{contentType.note}</p>}
    </div>
  )
}

function TypeStep({ cades }: { cades: CadesState }) {
  const { t } = useI18n()
  const { options, update, state, response, env } = cades
  const extended = state("extendedForm")
  return (
    <div className="space-y-8">
      <Section title={t("type.kind")} description={t("cades.type.kindHint")}>
        <div className="grid gap-3 md:grid-cols-3">
          <ChoiceCard selected={options.kind === "Baseline"} onSelect={() => update({ kind: "Baseline" })} title={t("cades.type.baseline")} description={t("cades.type.baselineHint")} icon={<Layers className="size-4" />} state={state("kind.Baseline")} />
          <ChoiceCard selected={options.kind === "IcpBrasil"} onSelect={() => update({ kind: "IcpBrasil" })} title={t("type.icp")} description={t("cades.type.icpHint")} icon={<Landmark className="size-4" />} state={state("kind.IcpBrasil")} />
          <ChoiceCard selected={options.kind === "CustomPolicy"} onSelect={() => update({ kind: "CustomPolicy" })} title={t("type.custom")} description={t("cades.type.customHint")} icon={<ScrollText className="size-4" />} state={state("kind.CustomPolicy")} />
        </div>
      </Section>

      {options.kind === "IcpBrasil" ? (
        <Section title={t("cades.type.icpPolicy")} description={t("cades.type.icpPolicyHint")}>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {icpPolicies.map((p) => (
              <ChoiceCard key={p.id} selected={options.icpPolicy === p.id} onSelect={() => update({ icpPolicy: p.id })} title={`${p.title} · ${p.level}`}
                description={t(`cades.icp.${p.id}` as MessageKey)} />
            ))}
          </div>
        </Section>
      ) : (
        <Section title={t("type.level")} description={t("cades.type.levelHint")}>
          <div className="grid gap-3 sm:grid-cols-2">
            {levels.map((l) => (
              <ChoiceCard key={l.id} selected={options.level === l.id} onSelect={() => update({ level: l.id })} title={l.title} description={t(`cades.levels.${l.id}` as MessageKey)} state={state(`level.${l.id}`)} />
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
        <Section title={t("cades.type.extended")} description={t("cades.type.extendedHint")}>
          <div className="grid gap-3 sm:grid-cols-2">
            {extendedForms.map((f) => (
              <ChoiceCard key={f.id} selected={(response?.report.effective.extendedForm ?? options.extendedForm) === f.id} onSelect={() => update({ extendedForm: f.id })}
                title={f.id === "None" ? t("cades.extended.None") : f.title} description={t(`cades.extendedHints.${f.id}` as MessageKey)} state={state(`extendedForm.${f.id}`)} />
            ))}
          </div>
        </Section>
      ) : extended.note && <p className="text-muted-foreground rounded-lg border border-dashed p-3 text-xs">{extended.note}</p>}

      {state("timestamp").visible && (
        <Section title={t("type.timestamp")} description={t("type.timestampHint", { level: response?.report.effectiveLevel ?? "" })} infoId="timestamp">
          <TsaPicker value={options.timestamp} onChange={(timestamp) => update({ timestamp })} state={state} env={env} />
        </Section>
      )}
    </div>
  )
}

function CryptoStep({ cades }: { cades: CadesState }) {
  const { t } = useI18n()
  const { options, update, state, response } = cades
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
      ) : padding.note && <p className="text-muted-foreground rounded-lg border border-dashed p-3 text-xs">{padding.note}</p>}
    </div>
  )
}

function DetailsStep({ cades }: { cades: CadesState }) {
  const { t } = useI18n()
  const { options, update } = cades
  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2">
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
      <ToggleRow checked={options.validate} onChange={(validate) => update({ validate })} label={t("cades.details.validate")} description={t("cades.details.validateHint")} />
    </div>
  )
}

function ResultView({ result, onContinue }: { result: CadesSignResult; onContinue: (op: "CoSign" | "CounterSign") => void }) {
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
        <FileLock2 className="text-success size-6" />
        <div className="min-w-0 flex-1">
          <p className="font-medium">{t("result.signed", { level: result.requestedLevel })}</p>
          <p className="text-muted-foreground text-xs">{t("cades.result.summary", { name: result.fileName ?? "", size: number(result.bytes / 1024, 1), ms: result.signMs, achieved: result.achievedLevel ?? "" })}</p>
        </div>
        {view && <Indication value={view.overall} />}
        <Button variant="outline" onClick={() => onContinue("CoSign")}><Users /> {t("cades.result.coSign")}</Button>
        <Button variant="outline" onClick={() => onContinue("CounterSign")}><GitBranch /> {t("cades.result.counterSign")}</Button>
        <Button asChild><a href={api.fileUrl(result.outputId!, true)}><Download /> {t("common.download")}</a></Button>
      </div>
      {result.warnings.length > 0 && (
        <Alert><AlertTitle>{t("result.warnings")}</AlertTitle><AlertDescription><ul>{result.warnings.map((w) => <li key={w}>{w}</li>)}</ul></AlertDescription></Alert>
      )}
      {view && (
        <>
          <Section title={t("cades.result.validation")} description={t("cades.result.validationHint")}><SignerTree view={view} /></Section>
          <Section title={t("cades.result.structure")} description={t("cades.result.structureHint")}><CmsStructure facts={view.structure} /></Section>
        </>
      )}
      <Section title={t("result.tabs.code")}><CodeTabs code={result.code} /></Section>
    </div>
  )
}

function ValidateView({ samples, environment }: { samples: CadesSample[]; environment: EnvironmentMode }) {
  const { t } = useI18n()
  const [settings, setSettings] = useState<ValidationSettings>(() => defaultValidationSettings(environment))
  const [signature, setSignature] = useState<{ id: string; name: string } | null>(null)
  const [data, setData] = useState<{ id: string; name: string } | null>(null)
  const [view, setView] = useState<CadesValidationView | null>(null)
  const [busy, setBusy] = useState(false)
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
