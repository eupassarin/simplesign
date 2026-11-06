import { useEffect, useRef, useState } from "react"
import { Download, FileSearch, FileUp, Files, Loader2, Play, ShieldCheck, ShieldQuestion, ShieldX } from "lucide-react"
import { toast } from "sonner"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type { BulkReport, CertificateView, DetailedSignature, EnvironmentMode, InspectionReport, TrustChoice, ValidationReport, ValidationSample, ValidationSettings } from "@/lib/types"
import { cn } from "@/lib/utils"
import { CodeTabs, Indication, SignatureCard } from "../pdf-signing/steps/ResultStep"
import { ChoiceCard, Field, KeyValue, Pill, Section } from "../pdf-signing/ui"

const trustChoices: TrustChoice[] = ["Sandbox", "System", "IcpBrasil", "IcpHomologation"]

function defaults(environment: EnvironmentMode): ValidationSettings {
  return {
    environment,
    trust: environment === "Sandbox" ? ["Sandbox"] : ["System", "IcpBrasil"],
    customRootUploadIds: [],
    checkRevocation: true,
    timeoutSeconds: 10,
    useBrasil: true,
  }
}

interface FileRef {
  id: string
  name: string
}

export function ValidationPage({ environment, initialFile }: { environment: EnvironmentMode; initialFile?: FileRef | null }) {
  const { t } = useI18n()
  const [settings, setSettings] = useState<ValidationSettings>(() => defaults(environment))
  const [samples, setSamples] = useState<ValidationSample[]>([])
  const [file, setFile] = useState<FileRef | null>(initialFile ?? null)
  const [tab, setTab] = useState("validate")
  useEffect(() => setSettings(defaults(environment)), [environment])
  useEffect(() => {
    api.validation.samples().then(setSamples).catch(() => {})
  }, [t])
  useEffect(() => {
    if (initialFile) setFile(initialFile)
  }, [initialFile])

  return (
    <div className="min-h-0 min-w-0 flex-1 overflow-y-auto">
      <div className="mx-auto grid max-w-7xl gap-6 p-6 lg:grid-cols-[300px_minmax(0,1fr)] lg:p-8">
        <aside className="space-y-4 lg:sticky lg:top-0 lg:self-start">
          <header className="space-y-1">
            <h2 className="text-2xl font-semibold tracking-tight">{t("validation.title")}</h2>
            <p className="text-muted-foreground text-sm">{t("validation.intro")}</p>
          </header>
          <SettingsCard settings={settings} onChange={setSettings} />
        </aside>
        <main className="min-w-0 space-y-6">
          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="validate"><ShieldCheck /> {t("validation.tabs.validate")}</TabsTrigger>
              <TabsTrigger value="bulk"><Files /> {t("validation.tabs.bulk")}</TabsTrigger>
              <TabsTrigger value="inspect"><FileSearch /> {t("validation.tabs.inspect")}</TabsTrigger>
            </TabsList>
            <TabsContent value="validate" className="space-y-6 pt-4">
              <FilePicker samples={samples} file={file} onFile={setFile} />
              {file && <ValidateView file={file} settings={settings} />}
            </TabsContent>
            <TabsContent value="bulk" className="pt-4">
              <BulkView samples={samples} settings={settings} />
            </TabsContent>
            <TabsContent value="inspect" className="space-y-6 pt-4">
              <FilePicker samples={samples} file={file} onFile={setFile} />
              {file && <InspectView file={file} />}
            </TabsContent>
          </Tabs>
        </main>
      </div>
    </div>
  )
}

function SettingsCard({ settings, onChange }: { settings: ValidationSettings; onChange: (s: ValidationSettings) => void }) {
  const { t } = useI18n()
  const set = (patch: Partial<ValidationSettings>) => onChange({ ...settings, ...patch })
  const toggle = (choice: TrustChoice, on: boolean) => set({ trust: on ? [...settings.trust, choice] : settings.trust.filter((c) => c !== choice) })
  const [uploading, setUploading] = useState(false)
  return (
    <div className="space-y-4 rounded-lg border p-4">
      <p className="text-sm font-semibold">{t("validation.settings.title")}</p>
      <div className="space-y-2">
        <p className="text-muted-foreground text-xs font-medium">{t("validation.settings.trust")}</p>
        {trustChoices.map((choice) => (
          <label key={choice} className="flex items-start gap-2 text-sm">
            <Checkbox className="mt-0.5" checked={settings.trust.includes(choice)} onCheckedChange={(v) => toggle(choice, v === true)} />
            <span>
              {t(`validation.trust.${choice}.title` as MessageKey)}
              <span className="text-muted-foreground block text-xs">{t(`validation.trust.${choice}.hint` as MessageKey)}</span>
            </span>
          </label>
        ))}
      </div>
      <Field label={t("validation.settings.customRoots")} description={t("validation.settings.customRootsHint", { n: settings.customRootUploadIds.length })}>
        <Input type="file" accept=".cer,.crt,.pem,.der" multiple disabled={uploading}
          onChange={async (e) => {
            const files = [...(e.target.files ?? [])]
            if (files.length === 0) return
            setUploading(true)
            try {
              const ids = await Promise.all(files.map(async (f) => (await api.uploadFile(f)).id))
              set({ customRootUploadIds: [...settings.customRootUploadIds, ...ids] })
            } finally {
              setUploading(false)
            }
          }} />
      </Field>
      <label className="flex items-center justify-between gap-2 text-sm">{t("validation.settings.revocation")}<Switch checked={settings.checkRevocation} onCheckedChange={(checkRevocation) => set({ checkRevocation })} /></label>
      <label className="flex items-center justify-between gap-2 text-sm">{t("validation.settings.brasil")}<Switch checked={settings.useBrasil} onCheckedChange={(useBrasil) => set({ useBrasil })} /></label>
      <Field label={t("validation.settings.timeout")}>
        <Input type="number" min={1} max={120} value={settings.timeoutSeconds} onChange={(e) => set({ timeoutSeconds: Number(e.target.value) })} />
      </Field>
    </div>
  )
}

function FilePicker({ samples, file, onFile }: { samples: ValidationSample[]; file: FileRef | null; onFile: (f: FileRef) => void }) {
  const { t } = useI18n()
  const input = useRef<HTMLInputElement>(null)
  return (
    <Section title={t("validation.files")} description={t("validation.filesHint")}>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {samples.map((s) => (
          <ChoiceCard key={s.id} selected={file?.id === s.fileId} onSelect={() => onFile({ id: s.fileId, name: s.title })} title={s.title}
            description={<><span className="mb-1.5 block"><Indication value={s.expectedIndication as "Valid"} /></span>{s.description}</>} />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="outline" onClick={() => input.current?.click()}><FileUp /> {t("validation.upload")}</Button>
        {file && !samples.some((s) => s.fileId === file.id) && <span className="text-muted-foreground text-sm">{t("validation.current", { name: file.name })}</span>}
        <input ref={input} type="file" accept="application/pdf,.pdf" hidden onChange={async (e) => {
          const f = e.target.files?.[0]
          if (!f) return
          const uploaded = await api.uploadFile(f)
          onFile({ id: uploaded.id, name: uploaded.fileName })
        }} />
      </div>
    </Section>
  )
}

function ValidateView({ file, settings }: { file: FileRef; settings: ValidationSettings }) {
  const { t } = useI18n()
  const [report, setReport] = useState<ValidationReport | null>(null)
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    try {
      setReport(await api.validation.validate(file.id, settings))
    } catch (e) {
      toast.error(t("validation.failed"), { description: (e as Error).message })
    } finally {
      setBusy(false)
    }
  }
  useEffect(() => {
    run()
  }, [file.id, settings])
  if (busy && !report) return <Loader2 className="size-5 animate-spin" />
  if (!report) return null
  const Icon = report.overall === "Valid" ? ShieldCheck : report.overall === "Invalid" || report.overall === "Error" ? ShieldX : ShieldQuestion
  return (
    <div className="space-y-6">
      <div className={cn("flex flex-wrap items-center gap-3 rounded-lg border p-4",
        report.overall === "Valid" && "border-success/40 bg-success/5", (report.overall === "Invalid" || report.overall === "Error") && "border-destructive/40 bg-destructive/5")}>
        <Icon className={cn("size-6", report.overall === "Valid" ? "text-success" : report.overall === "Indeterminate" ? "text-warning" : "text-destructive")} />
        <div className="min-w-0 flex-1">
          <p className="font-medium">{t(`validation.overall.${report.overall}` as MessageKey)}</p>
          <p className="text-muted-foreground text-xs">{t("validation.summary", { name: file.name, n: report.signatures.length, ms: report.ms })}</p>
        </div>
        <Button variant="outline" size="sm" onClick={run} disabled={busy}>{busy ? <Loader2 className="animate-spin" /> : <Play />} {t("validation.revalidate")}</Button>
      </div>
      {report.error && <Alert variant="destructive"><AlertTitle>{t("validation.error")}</AlertTitle><AlertDescription>{report.error}</AlertDescription></Alert>}
      {report.signatures.map((s) => <DetailedCard key={s.report.fieldName} signature={s} />)}
      {report.dss && (
        <Section title={t("validation.dss.title")} description={t("validation.dss.hint")}>
          <div className="grid gap-x-8 rounded-lg border p-4 sm:grid-cols-3">
            <KeyValue label={t("validation.dss.certificates")}>{report.dss.certificates}</KeyValue>
            <KeyValue label="CRLs">{report.dss.crls}</KeyValue>
            <KeyValue label="OCSPs">{report.dss.ocsps}</KeyValue>
            <KeyValue label="VRI">{report.dss.hasVri ? report.dss.vriEntries : t("common.no")}</KeyValue>
          </div>
          {report.dss.warnings.length > 0 && <ul className="text-muted-foreground text-xs">{report.dss.warnings.map((w) => <li key={w}>! {w}</li>)}</ul>}
        </Section>
      )}
      <Section title={t("result.tabs.code")}><CodeTabs code={report.code} /></Section>
    </div>
  )
}

function DetailedCard({ signature: s }: { signature: DetailedSignature }) {
  const { t } = useI18n()
  return (
    <div className="space-y-3">
      <SignatureCard report={s.report} />
      <div className="flex flex-wrap gap-1.5">
        {s.padesLevel && <Pill tone="info">PAdES {s.padesLevel.replace("Baseline", "B-").replace("B-LTA", "B-LTA")}</Pill>}
        {s.lei14063Level && <Pill tone="success">{t("validation.lei", { level: s.lei14063Level })}</Pill>}
        {s.policyName && <Pill>{s.policyName}</Pill>}
        {s.deprecatedAlgorithm && <Pill tone="warning">{t("validation.deprecated")}</Pill>}
      </div>
      <Accordion type="multiple" className="rounded-lg border px-4">
        {s.signer && (
          <AccordionItem value="certificate">
            <AccordionTrigger>{t("validation.sections.certificate")}</AccordionTrigger>
            <AccordionContent className="space-y-3">
              <CertificateBlock cert={s.signer} />
              {s.embeddedCertificates.length > 0 && (
                <div className="space-y-1">
                  <p className="text-muted-foreground text-xs font-medium">{t("validation.embedded", { n: s.embeddedCertificates.length })}</p>
                  <ul className="space-y-1 text-xs">{s.embeddedCertificates.map((c) => <li key={c.thumbprint} className="truncate font-mono">• {c.subject}</li>)}</ul>
                </div>
              )}
            </AccordionContent>
          </AccordionItem>
        )}
        {s.timestamp && (
          <AccordionItem value="timestamp">
            <AccordionTrigger>{t("validation.sections.timestamp")}</AccordionTrigger>
            <AccordionContent className="grid gap-x-8 sm:grid-cols-2">
              <KeyValue label={t("validation.timestamp.time")}>{s.timestamp.time}</KeyValue>
              <KeyValue label="TSA">{s.timestamp.tsa ?? "—"}</KeyValue>
              <KeyValue label={t("validation.timestamp.policy")} mono>{s.timestamp.policyOid ?? "—"}</KeyValue>
              <KeyValue label={t("validation.timestamp.hash")}>{s.timestamp.hashAlgorithm ?? "—"}</KeyValue>
            </AccordionContent>
          </AccordionItem>
        )}
        {s.coverage && (
          <AccordionItem value="coverage">
            <AccordionTrigger>{t("validation.sections.coverage")}</AccordionTrigger>
            <AccordionContent className="space-y-2 text-sm">
              <KeyValue label={t("validation.coverage.signedUntil")}>{s.coverage.signedUntil} / {s.coverage.fileSize} bytes</KeyValue>
              <KeyValue label={t("validation.coverage.revision")}>{s.coverage.revision} / {s.coverage.revisions}</KeyValue>
              <p className="text-muted-foreground text-xs">{t(s.coverage.coversWholeFile ? "validation.coverage.whole" : "validation.coverage.later")}</p>
            </AccordionContent>
          </AccordionItem>
        )}
        <AccordionItem value="attributes">
          <AccordionTrigger>{t("validation.sections.attributes")}</AccordionTrigger>
          <AccordionContent className="grid gap-x-8 sm:grid-cols-2">
            <KeyValue label={t("validation.attributes.algorithm")}>{s.signatureAlgorithm ?? "—"}</KeyValue>
            <KeyValue label={t("validation.attributes.policy")} mono>{s.policyOid ?? "—"}</KeyValue>
            <KeyValue label={t("validation.attributes.commitment")} mono>{s.commitmentTypeOid ?? "—"}</KeyValue>
            <KeyValue label={t("details.reason")}>{s.reason ?? "—"}</KeyValue>
            <KeyValue label={t("details.location")}>{s.location ?? "—"}</KeyValue>
            <KeyValue label={t("details.contact")}>{s.contactInfo ?? "—"}</KeyValue>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </div>
  )
}

function CertificateBlock({ cert }: { cert: CertificateView }) {
  const { t } = useI18n()
  return (
    <div className="grid gap-x-8 sm:grid-cols-2">
      <KeyValue label={t("validation.cert.subject")}>{cert.subject}</KeyValue>
      <KeyValue label={t("signer.card.issuer")}>{cert.issuer}</KeyValue>
      <KeyValue label={t("signer.card.valid")}>{cert.notBefore} → {cert.notAfter}</KeyValue>
      <KeyValue label={t("signer.card.key")}>{cert.keyAlgorithm} {cert.keySize ?? ""}</KeyValue>
      <KeyValue label={t("validation.cert.serial")} mono>{cert.serialNumber}</KeyValue>
      <KeyValue label="nonRepudiation">{t(cert.hasNonRepudiation ? "common.yes" : "common.no")}</KeyValue>
    </div>
  )
}

function BulkView({ samples, settings }: { samples: ValidationSample[]; settings: ValidationSettings }) {
  const { t, number } = useI18n()
  const [files, setFiles] = useState<FileRef[]>([])
  const [concurrency, setConcurrency] = useState(4)
  const [report, setReport] = useState<BulkReport | null>(null)
  const [busy, setBusy] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  return (
    <div className="space-y-4">
      <p className="text-muted-foreground text-sm">{t("validation.bulk.intro")}</p>
      <div className="flex flex-wrap items-end gap-3">
        <Button variant="outline" onClick={() => setFiles(samples.map((s) => ({ id: s.fileId, name: s.title })))}><Files /> {t("validation.bulk.addSamples")}</Button>
        <Button variant="outline" onClick={() => input.current?.click()}><FileUp /> {t("validation.bulk.addFiles")}</Button>
        <input ref={input} type="file" accept="application/pdf,.pdf" multiple hidden onChange={async (e) => {
          const list = [...(e.target.files ?? [])]
          const uploaded = await Promise.all(list.map((f) => api.uploadFile(f)))
          setFiles((current) => [...current, ...uploaded.map((u) => ({ id: u.id, name: u.fileName }))])
        }} />
        <Field label={t("mode.concurrency")}><Input type="number" min={1} max={16} className="w-24" value={concurrency} onChange={(e) => setConcurrency(Number(e.target.value))} /></Field>
        <Button disabled={files.length === 0 || busy} onClick={async () => {
          setBusy(true)
          try {
            setReport(await api.validation.bulk(files.map((f) => f.id), settings, concurrency))
          } finally {
            setBusy(false)
          }
        }}>{busy ? <Loader2 className="animate-spin" /> : <Play />} {t("validation.bulk.run", { n: files.length })}</Button>
      </div>
      {report && (
        <>
          <p className="text-sm">{t("validation.bulk.summary", { processed: report.processed, failed: report.failed, avg: number(report.averageMs, 0), total: report.totalMs })}</p>
          <div className="rounded-lg border">
            <Table>
              <TableHeader><TableRow><TableHead>{t("document.facts.file")}</TableHead><TableHead>{t("validation.bulk.result")}</TableHead><TableHead>{t("validation.bulk.signatures")}</TableHead><TableHead className="text-right">ms</TableHead></TableRow></TableHeader>
              <TableBody>
                {report.items.map((i) => (
                  <TableRow key={i.fileId}>
                    <TableCell className="text-sm">{i.fileName}</TableCell>
                    <TableCell>{i.error ? <span className="text-destructive text-xs">{i.error}</span> : <OverallPill value={i.overall} />}</TableCell>
                    <TableCell className="text-xs">{t("validation.bulk.validOf", { valid: i.valid, total: i.total })}</TableCell>
                    <TableCell className="text-right text-xs">{i.ms}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </>
      )}
    </div>
  )
}

function OverallPill({ value }: { value: string }) {
  const { t } = useI18n()
  const tone = value === "Valid" ? "success" : value === "Indeterminate" ? "warning" : value === "NoSignatures" ? "default" : "danger"
  const key = value === "Valid" || value === "Invalid" || value === "Indeterminate" ? `result.indication.${value}` : `validation.overall.${value}`
  return <Pill tone={tone}>{t(key as MessageKey)}</Pill>
}

function InspectView({ file }: { file: FileRef }) {
  const { t } = useI18n()
  const [report, setReport] = useState<InspectionReport | null>(null)
  useEffect(() => {
    setReport(null)
    api.validation.inspect(file.id).then(setReport).catch((e: Error) => toast.error(e.message))
  }, [file.id])
  if (!report) return <Loader2 className="size-5 animate-spin" />
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Pill>{t("validation.inspect.revisions", { n: report.revisions })}</Pill>
        <Pill>{t("validation.inspect.objects", { n: report.objects.length })}</Pill>
        {report.signatureFields.map((f) => (
          <Button key={f} variant="outline" size="sm" asChild><a href={api.validation.cmsUrl(file.id, f)}><Download /> {t("validation.inspect.cms", { field: f })}</a></Button>
        ))}
      </div>
      <p className="text-muted-foreground text-xs">{t("validation.inspect.hint")}</p>
      {report.error && <Alert variant="destructive"><AlertDescription>{report.error}</AlertDescription></Alert>}
      <Accordion type="multiple" className="rounded-lg border px-4">
        {report.objects.map((o) => (
          <AccordionItem key={o.objectNumber} value={String(o.objectNumber)}>
            <AccordionTrigger>
              <span className="flex flex-wrap items-center gap-2 text-left">
                <span className="text-muted-foreground font-mono text-xs">#{o.objectNumber}</span>
                <span>{o.label}</span>
                {o.badges.map((b) => <Pill key={b}>{b}</Pill>)}
              </span>
            </AccordionTrigger>
            <AccordionContent className="space-y-2">
              {o.streamInfo && <p className="text-muted-foreground text-xs">{t("validation.inspect.stream", { info: o.streamInfo })}</p>}
              {o.cmsContentType && <p className="text-xs">CMS: {o.cmsContentType}{o.cmsSigner ? ` · ${o.cmsSigner}` : ""}</p>}
              <Table>
                <TableBody>
                  {o.entries.map((e, i) => (
                    <TableRow key={i}>
                      <TableCell className="w-40 align-top font-mono text-xs">{e.key}</TableCell>
                      <TableCell className="max-w-md align-top font-mono text-xs break-all whitespace-normal">{e.value}</TableCell>
                      <TableCell className="text-muted-foreground align-top text-xs whitespace-normal">{e.explanation}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </AccordionContent>
          </AccordionItem>
        ))}
      </Accordion>
    </div>
  )
}
