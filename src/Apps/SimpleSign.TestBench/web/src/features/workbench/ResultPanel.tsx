import { useEffect, useState, type ReactNode } from "react"
import { Check, CircleSlash, Download, FileCheck2, Loader2, RefreshCw, ShieldCheck, ShieldQuestion, TriangleAlert, XCircle } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useI18n, useT, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type { CadesSignResult, CadesValidationView, SigningResult, ValidationReport, XmlSignResult, XmlValidationView } from "@/lib/types"
import { cn } from "@/lib/utils"
import { CmsStructure } from "../cades/CmsViews"
import { PdfPreview } from "../shared/PdfPreview"
import { DetailedCard, InspectView } from "../validate/pdf"
import { CodeTabs, Indication } from "../shared/results"
import { IssueList, KeyValue, Pill } from "../shared/ui"
import { XmlViews } from "../xml/XmlViews"
import { LogView } from "./LogView"
import { StandardBadge } from "./parts"
import type { DssComparison, RunVerdict, RunView } from "./schema"
import { useWorkbench, type VariantRow } from "./state"

/** Everything a run produced: the result, what is inside the file, the verdicts (SimpleSign and DSS), the log and the code. */
export function ResultPanel({ extra }: { extra?: { id: string; label: ReactNode; content: ReactNode; open?: boolean } }) {
  const { run, logs, running, format, variants: allVariants, variantsRunning, mode } = useWorkbench()
  const variants = mode === "sign" ? allVariants : null
  const t = useT()
  const [tab, setTab] = useState("result")
  // While signing, the log is what there is to look at.
  useEffect(() => {
    if (running) setTab("logs")
  }, [running])
  useEffect(() => {
    if (run) setTab((current) => (current === "logs" && run.success ? "result" : !run.success ? "result" : current))
  }, [run?.id]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (variantsRunning) setTab("variants")
  }, [variantsRunning])

  useEffect(() => {
    if (extra?.open) setTab(extra.id)
  }, [extra?.open, extra?.id])

  if (!run && !running && !variants && !extra) {
    return (
      <div className="text-muted-foreground flex h-full flex-col items-center justify-center gap-2 p-10 text-center">
        <FileCheck2 className="size-8 opacity-40" />
        <p className="text-sm font-medium">{t(mode === "validate" ? "val.emptyTitle" : "wb.result.emptyTitle")}</p>
        <p className="max-w-sm text-xs leading-relaxed">{t(mode === "validate" ? "val.emptyHint" : "wb.result.emptyHint")}</p>
      </div>
    )
  }
  const dss = run?.crossValidation
  return (
    <Tabs value={tab} onValueChange={setTab} className="gap-0">
      <TabsList className="mb-4">
        <TabsTrigger value="result">{t("wb.tabs.result")}</TabsTrigger>
        <TabsTrigger value="inspection" disabled={!run?.success}>{t("wb.tabs.inspection")}</TabsTrigger>
        <TabsTrigger value="validation" disabled={!run?.success}>
          {t("wb.tabs.validation")}
          {dss?.available && <span className={cn("ml-1.5 size-1.5 rounded-full", dss.agree ? "bg-success" : "bg-warning")} />}
        </TabsTrigger>
        <TabsTrigger value="logs">{t("wb.tabs.logs")}<span className="text-muted-foreground ml-1.5 text-[10px] tabular-nums">{logs.length}</span></TabsTrigger>
        <TabsTrigger value="code" disabled={!run?.code?.cSharp}>{t("wb.tabs.code")}</TabsTrigger>
        {extra && <TabsTrigger value={extra.id}>{extra.label}</TabsTrigger>}
        {variants && <TabsTrigger value="variants">{t("wb.tabs.variants")}{variantsRunning && <Loader2 className="ml-1 size-3 animate-spin" />}</TabsTrigger>}
      </TabsList>
      <TabsContent value="result">{run ? <Summary run={run} /> : running ? <Signing /> : null}</TabsContent>
      {extra && <TabsContent value={extra.id}>{extra.content}</TabsContent>}
      <TabsContent value="variants">{variants && <VariantsTable onOpen={() => setTab("result")} />}</TabsContent>
      <TabsContent value="inspection">{run?.success && <Inspection run={run} />}</TabsContent>
      <TabsContent value="validation">{run?.success && <Validation run={run} />}</TabsContent>
      <TabsContent value="logs"><LogView logs={logs} format={run?.format ?? format} running={running} /></TabsContent>
      <TabsContent value="code">{run?.code && <CodeTabs code={run.code} />}</TabsContent>
    </Tabs>
  )
}

function Signing() {
  const t = useT()
  return <div className="text-muted-foreground flex items-center gap-2 py-10 text-sm"><Loader2 className="size-4 animate-spin" /> {t("result.signing")}</div>
}

function Summary({ run }: { run: RunView }) {
  const { t, number } = useI18n()
  const { reuse, schema, openInValidate } = useWorkbench()
  const validating = run.kind === "validate"
  const formatTitle = schema.formats.find((f) => f.id === run.format)?.title ?? run.format
  if (!run.success) {
    return (
      <div className="space-y-4">
        <Alert variant="destructive">
          <XCircle />
          <AlertTitle>{t("result.failed", { type: run.errorType ?? "" })}</AlertTitle>
          <AlertDescription className="break-words">{run.error}</AlertDescription>
        </Alert>
        <IssueList issues={run.issues} />
        <p className="text-muted-foreground text-xs">{t("wb.result.failedHint")}</p>
      </div>
    )
  }
  const downgraded = !!run.requestedLevel && !!run.achievedLevel && run.requestedLevel !== run.achievedLevel
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3 rounded-lg border p-4">
        <ShieldCheck className="text-success size-6" />
        <div className="min-w-0 flex-1">
          <p className="font-medium">{formatTitle} · {validating ? run.fileName : run.achievedLevel ?? run.requestedLevel}</p>
          <p className="text-muted-foreground text-xs">
            {validating
              ? t("val.summary", { size: number(run.bytes / 1024, 1), validate: run.validateMs, total: run.totalMs })
              : t("wb.result.summary", { name: run.fileName ?? "", size: number(run.bytes / 1024, 1), sign: run.signMs, validate: run.validateMs, total: run.totalMs })}
          </p>
        </div>
        {run.overall && <Indication value={run.overall} />}
        {run.crossValidation?.available && <Pill tone={run.crossValidation.agree ? "success" : "warning"}>{t(run.crossValidation.agree ? "wb.dss.agrees" : "wb.dss.differs")}</Pill>}
        {!validating && (
          <Button variant="outline" size="sm" onClick={() => openInValidate({
            fileId: run.outputId!, name: run.fileName ?? "", dataId: run.format === "pades" ? null : (run.options.dataId as string | null | undefined) ?? null,
          })}><FileCheck2 /> {t("wb.result.openInValidate")}</Button>
        )}
        <Button size="sm" asChild><a href={api.fileUrl(run.outputId!, true)}><Download /> {t("common.download")}</a></Button>
      </div>
      <div className="grid gap-x-8 rounded-lg border px-4 py-2 sm:grid-cols-2">
        {!validating && <KeyValue label={t("wb.result.requested")}>{run.requestedLevel ?? "—"}</KeyValue>}
        <KeyValue label={t(validating ? "val.detectedLevel" : "wb.result.achieved")}>{downgraded ? <Pill tone="warning">{run.achievedLevel}</Pill> : run.achievedLevel ?? "—"}</KeyValue>
        <KeyValue label={t("wb.result.signatures")}>{run.validation.length}</KeyValue>
        <KeyValue label={t("wb.result.logLines")}>{run.logs.length}</KeyValue>
      </div>
      {run.warnings.length > 0 && (
        <Alert>
          <TriangleAlert />
          <AlertTitle>{t("result.warnings")}</AlertTitle>
          <AlertDescription><ul className="list-disc pl-4">{run.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul></AlertDescription>
        </Alert>
      )}
      <IssueList issues={run.issues} />
      <div className="space-y-2">{run.validation.map((v, i) => <VerdictCard key={i} verdict={v} compact />)}</div>
      {!validating && <Button variant="ghost" size="sm" onClick={() => reuse(run)}><RefreshCw /> {t("wb.result.reuse")}</Button>}
    </div>
  )
}

/** One signature's verdict: the indication and each check behind it. */
function VerdictCard({ verdict, compact, depth = 0 }: { verdict: RunVerdict; compact?: boolean; depth?: number }) {
  const t = useT()
  return (
    <div className={cn("rounded-lg border", depth > 0 && "ml-6")}>
      <div className="flex flex-wrap items-center gap-2 px-4 py-2.5">
        <FileCheck2 className="size-4" />
        <span className="text-sm font-medium">{verdict.label}</span>
        <span className="text-muted-foreground truncate text-xs">{verdict.signer}</span>
        {verdict.level && <Pill>{verdict.level}</Pill>}
        {verdict.signingTime && <span className="text-muted-foreground text-xs">{verdict.signingTime}</span>}
        <span className="ml-auto"><Indication value={verdict.indication} /></span>
      </div>
      {!compact && (
        <ul className="divide-y border-t">
          {verdict.checks.map((c) => (
            <li key={c.id + c.name} className="flex items-start gap-2 px-4 py-1.5 text-sm">
              {c.status === "pass" ? <Check className="text-success mt-0.5 size-4" /> : c.status === "fail" ? <XCircle className="text-destructive mt-0.5 size-4" /> : c.status === "warn" ? <TriangleAlert className="text-warning mt-0.5 size-4" /> : <CircleSlash className="text-muted-foreground mt-0.5 size-4" />}
              <span className="flex-1">{c.name}</span>
              <span className="text-muted-foreground max-w-[50%] text-right text-xs break-words">{c.detail}</span>
            </li>
          ))}
        </ul>
      )}
      {(verdict.errors.length > 0 || verdict.warnings.length > 0) && (
        <ul className="space-y-1 border-t px-4 py-2 text-xs">
          {verdict.errors.map((e, i) => <li key={`e${i}`} className="text-destructive">✕ {e}</li>)}
          {verdict.warnings.map((w, i) => <li key={`w${i}`} className="text-muted-foreground">! {w}</li>)}
        </ul>
      )}
      {verdict.children.length > 0 && (
        <div className="space-y-2 border-t p-2">
          <p className="text-muted-foreground px-2 text-xs">{t("wb.validation.counterSignatures")}</p>
          {verdict.children.map((c, i) => <VerdictCard key={i} verdict={c} compact={compact} depth={depth + 1} />)}
        </div>
      )}
    </div>
  )
}

/** What is inside the produced file, in the terms of its format. */
function Inspection({ run }: { run: RunView }) {
  const { t, number } = useI18n()
  const yes = (b: boolean) => t(b ? "common.yes" : "common.no")
  if (run.kind === "validate") {
    // The validators' own reports: the same views, without the signing facts.
    if (run.format === "cades") return <CmsStructure facts={(run.detail as CadesValidationView).structure} />
    if (run.format === "xades") return <div className="space-y-6"><XmlViews view={run.detail as XmlValidationView} /></div>
    const report = run.detail as ValidationReport
    return (
      <div className="space-y-6">
        {report.signatures.map((s) => <DetailedCard key={s.report.fieldName} signature={s} />)}
        <InspectView file={{ id: run.outputId! }} />
      </div>
    )
  }
  if (run.format === "cades") {
    const detail = run.detail as CadesSignResult
    return detail.validation ? <CmsStructure facts={detail.validation.structure} /> : <p className="text-muted-foreground text-sm">{t("wb.inspection.needsValidation")}</p>
  }
  if (run.format === "xades") {
    const detail = run.detail as XmlSignResult
    return detail.validation ? <div className="space-y-6"><XmlViews view={detail.validation} /></div> : <p className="text-muted-foreground text-sm">{t("wb.inspection.needsValidation")}</p>
  }
  const detail = run.detail as SigningResult
  return (
    <div className="space-y-5">
      <div className="grid gap-x-8 rounded-lg border px-4 py-2 sm:grid-cols-2">
        <KeyValue label={t("result.output.signatures")}>{detail.output?.signatureCount}</KeyValue>
        <KeyValue label={t("result.output.level")}>{detail.output?.detectedLevel}</KeyValue>
        <KeyValue label={t("result.output.timestamp")}>{yes(detail.hasSignatureTimestamp)}</KeyValue>
        <KeyValue label={t("result.output.dss")}>{detail.output?.hasDss ? t("result.output.dssValue", { certs: detail.output.dssCertificates, crls: detail.output.dssCrls, ocsps: detail.output.dssOcsps }) : t("common.no")}</KeyValue>
        <KeyValue label={t("result.output.archive")}>{yes(detail.hasArchiveTimestamp)}</KeyValue>
        <KeyValue label="DocMDP">{detail.output?.docMdpLevel ? `P=${detail.output.docMdpLevel}` : t("common.none")}</KeyValue>
        <KeyValue label="PDF/A">{detail.output?.pdfALevel}</KeyValue>
      </div>
      {detail.deferred && (
        <div className="space-y-1 rounded-lg border px-4 py-2">
          <p className="py-1 text-sm font-medium">{t("result.tabs.deferred")}</p>
          <KeyValue label={t("result.deferred.hashToSign")} mono>{detail.deferred.hashToSignHex}</KeyValue>
          <KeyValue label={t("result.deferred.digest")}>{detail.deferred.digestAlgorithm}</KeyValue>
          <KeyValue label={t("result.deferred.algorithm")} mono>{detail.deferred.signatureAlgorithmOid}</KeyValue>
          <KeyValue label={t("result.deferred.session")}>{t("result.deferred.bytes", { n: detail.deferred.sessionBytes })}</KeyValue>
          <KeyValue label={t("result.deferred.raw")} mono>{detail.deferred.rawSignatureHex}</KeyValue>
        </div>
      )}
      {detail.batch.length > 0 && (
        <Table>
          <TableHeader><TableRow><TableHead>Id</TableHead><TableHead>{t("result.batch.result")}</TableHead><TableHead className="text-right">{t("result.batch.size")}</TableHead><TableHead /></TableRow></TableHeader>
          <TableBody>
            {detail.batch.map((b) => (
              <TableRow key={b.id}>
                <TableCell className="font-mono text-xs">{b.id}</TableCell>
                <TableCell>{b.ok ? <Pill tone="success">{t("result.batch.signed")}</Pill> : <span className="text-destructive text-xs">{b.error}</span>}</TableCell>
                <TableCell className="text-right text-xs">{number(b.bytes / 1024, 1)} KB</TableCell>
                <TableCell className="text-right">{b.outputId && <Button variant="ghost" size="sm" asChild><a href={api.fileUrl(b.outputId, true)}><Download /></a></Button>}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <PdfPreview url={api.fileUrl(run.outputId!)} page={1} onPageChange={() => {}} />
    </div>
  )
}

/** SimpleSign's verdict with every check, and the DSS verdict next to it when cross-validation is on. */
function Validation({ run }: { run: RunView }) {
  const t = useT()
  const { schema, dss } = useWorkbench()
  const stage = schema.stages.find((s) => s.id === "validation")
  return (
    <div className="space-y-6">
      <section className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-sm font-semibold">SimpleSign</h3>
          {stage && <StandardBadge explanation={{ title: stage.title, summary: stage.summary, standards: stage.standards[run.format], api: schema.formats.find((f) => f.id === run.format)?.validatorApi }} />}
          {run.overall && <span className="ml-auto"><Indication value={run.overall} /></span>}
        </div>
        {run.validation.length === 0 && <p className="text-muted-foreground text-sm">{t("result.validationOff")}</p>}
        {run.validation.map((v, i) => <VerdictCard key={i} verdict={v} />)}
      </section>
      <section className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-sm font-semibold">{t("wb.dss.title")}</h3>
          <StandardBadge explanation={{ title: t("wb.dss.title"), summary: t("wb.dss.about"), standards: schema.stages.find((s) => s.id === "cross-validation")?.standards[run.format] ?? [], api: "POST /services/rest/validation/validateSignature" }} />
        </div>
        {run.crossValidation ? <DssReport comparison={run.crossValidation} /> : <p className="text-muted-foreground text-sm">{t(dss.enabled ? "wb.dss.notRun" : "wb.dss.off")}</p>}
      </section>
    </div>
  )
}

function DssReport({ comparison }: { comparison: DssComparison }) {
  const t = useT()
  if (!comparison.available) {
    return (
      <Alert>
        <ShieldQuestion />
        <AlertTitle>{t("wb.dss.unavailable")}</AlertTitle>
        <AlertDescription className="break-words">{comparison.error}</AlertDescription>
      </Alert>
    )
  }
  return (
    <div className="space-y-3">
      <div className={cn("flex flex-wrap items-center gap-2 rounded-lg border px-4 py-2.5 text-sm", comparison.agree ? "border-success/40 bg-success/5" : "border-warning/50 bg-warning/5")}>
        <Pill tone={comparison.agree ? "success" : "warning"}>{t(comparison.agree ? "wb.dss.agrees" : "wb.dss.differs")}</Pill>
        <span className="text-muted-foreground text-xs">{t("wb.dss.answered", { url: comparison.url, ms: comparison.ms })}</span>
        {comparison.reportId && <Button variant="outline" size="sm" className="ml-auto" asChild><a href={api.fileUrl(comparison.reportId, true)}><Download /> {t("wb.dss.report")}</a></Button>}
      </div>
      <Table>
        <TableHeader><TableRow><TableHead>{t("wb.dss.signature")}</TableHead><TableHead /><TableHead>SimpleSign</TableHead><TableHead>DSS</TableHead><TableHead /></TableRow></TableHeader>
        <TableBody>
          {comparison.rows.map((row, i) => (
            <TableRow key={i}>
              <TableCell className="text-xs font-medium">{row.label}</TableCell>
              <TableCell className="text-muted-foreground text-xs">{t(row.topic === "indication" ? "wb.dss.indication" : "wb.dss.level")}</TableCell>
              <TableCell className="font-mono text-xs">{row.library ?? "—"}</TableCell>
              <TableCell className="font-mono text-xs">{row.dss ?? "—"}{row.note && <span className="text-muted-foreground block max-w-md font-sans whitespace-normal">{row.note}</span>}</TableCell>
              <TableCell>{row.agree ? <Check className="text-success size-4" /> : <TriangleAlert className="text-warning size-4" />}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {comparison.notes.length > 0 && <ul className="text-muted-foreground space-y-1 text-xs">{comparison.notes.map((n) => <li key={n}>• {n}</li>)}</ul>}
      {comparison.signatures.some((s) => s.errors.length + s.warnings.length > 0) && (
        <div className="space-y-2">
          {comparison.signatures.map((s, i) => (
            <div key={i} className="rounded-lg border px-4 py-2 text-xs">
              <p className="font-medium">{s.id ?? `#${i + 1}`} · {s.indication}{s.subIndication ? ` / ${s.subIndication}` : ""}{s.format ? ` · ${s.format}` : ""}</p>
              <ul className="mt-1 space-y-0.5">
                {s.errors.map((e) => <li key={e} className="text-destructive">✕ {e}</li>)}
                {s.warnings.map((w) => <li key={w} className="text-muted-foreground">! {w}</li>)}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

type RowFilter = "all" | "problems" | "dss" | "skipped"

/** Combinations of option values, each signed as a normal run: what works, at what level, and what the validators say. */
function VariantsTable({ onOpen }: { onOpen: () => void }) {
  const { variants, variantsRunning, stopVariants, openRun, schema } = useWorkbench()
  const t = useT()
  const [filter, setFilter] = useState<RowFilter>("all")
  if (!variants) return null
  const finished = variants.rows.filter((r) => r.status === "done" || r.status === "skipped")
  const good = (r: VariantRow) => r.status === "done" && !!r.run?.success && (!r.run.overall || r.run.overall === "Valid")
  const differs = (r: VariantRow) => !!r.run?.crossValidation?.available && !r.run.crossValidation.agree
  const counts: Record<RowFilter, number> = {
    all: variants.rows.length,
    problems: variants.rows.filter((r) => r.status === "done" && !good(r)).length,
    dss: variants.rows.filter(differs).length,
    skipped: variants.rows.filter((r) => r.status === "skipped").length,
  }
  const shown = variants.rows.filter((r) => filter === "all" || (filter === "problems" ? r.status === "done" && !good(r) : filter === "dss" ? differs(r) : r.status === "skipped"))
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-sm font-medium">{schema.formats.find((f) => f.id === variants.format)?.title} · {variants.options.map((o) => o.title).join(" × ")}</p>
        {variants.options.length > 1 && <Pill>{t(variants.strategy === "pairs" ? "wb.variants.pairs" : "wb.variants.all")}</Pill>}
        <span className="text-muted-foreground ml-auto text-xs tabular-nums">{finished.length} / {variants.rows.length}</span>
        {variantsRunning && <Button variant="outline" size="sm" onClick={stopVariants}>{t("wb.variants.stop")}</Button>}
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        {(["all", "problems", "dss", "skipped"] as const).filter((f) => f === "all" || counts[f] > 0).map((f) => (
          <button key={f} type="button" onClick={() => setFilter(f)}
            className={cn("rounded-full border px-2.5 py-0.5 text-xs", filter === f ? "bg-accent border-foreground/30 font-medium" : "text-muted-foreground hover:text-foreground")}>
            {t(`wb.variants.filter.${f}` as MessageKey)} {counts[f]}
          </button>
        ))}
        <span className="text-muted-foreground ml-2 text-xs">{t("wb.variants.hint")}</span>
      </div>
      {variants.options.length > 1 && finished.length > 0 && (
        <div className="grid gap-x-6 gap-y-1 rounded-lg border px-3 py-2 text-xs sm:grid-cols-2">
          {variants.options.map((option, i) => (
            <div key={option.id} className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
              <span className="text-muted-foreground shrink-0">{option.title}</span>
              {[...new Set(variants.rows.map((r) => r.values[i]))].map((value) => {
                const withValue = variants.rows.filter((r) => r.values[i] === value && r.status === "done")
                const ok = withValue.filter(good).length
                const title = variants.rows.find((r) => r.values[i] === value)!.titles[i]
                return withValue.length === 0 ? null : (
                  <span key={value} className={cn("tabular-nums", ok < withValue.length && "text-destructive font-medium")}>{title} {ok}/{withValue.length}</span>
                )
              })}
            </div>
          ))}
        </div>
      )}
      <Table>
        <TableHeader>
          <TableRow>
            {variants.options.map((o) => <TableHead key={o.id}>{o.title}</TableHead>)}
            <TableHead>{t("wb.result.achieved")}</TableHead>
            <TableHead>SimpleSign</TableHead>
            <TableHead>DSS</TableHead>
            <TableHead className="text-right">ms</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {shown.map((row) => (
            <TableRow key={row.key} className={cn(row.run && "hover:bg-accent/50 cursor-pointer", row.run && !good(row) && "bg-destructive/5")}
              onClick={() => { if (row.run) { void openRun(row.run.id); onOpen() } }}>
              {row.titles.map((title, i) => <TableCell key={i} className="text-sm">{title}</TableCell>)}
              {row.status === "pending" && <TableCell colSpan={4} className="text-muted-foreground text-xs">—</TableCell>}
              {row.status === "running" && <TableCell colSpan={4}><Loader2 className="size-4 animate-spin" /></TableCell>}
              {row.status === "skipped" && <TableCell colSpan={4} className="text-muted-foreground text-xs whitespace-normal">{t("wb.variants.incompatible")}: {row.reason}</TableCell>}
              {row.status === "done" && row.run && (row.run.success ? (
                <>
                  <TableCell className="font-mono text-xs">{row.run.achievedLevel ?? "—"}</TableCell>
                  <TableCell>{row.run.overall ? <Indication value={row.run.overall} /> : "—"}</TableCell>
                  <TableCell>{row.run.crossValidation?.available
                    ? <Pill tone={row.run.crossValidation.agree ? "success" : "warning"}>{row.run.crossValidation.signatures.map((s) => s.subIndication ?? s.indication).join(", ") || "—"}</Pill>
                    : <span className="text-muted-foreground text-xs">—</span>}</TableCell>
                  <TableCell className="text-right text-xs tabular-nums">{row.run.totalMs}</TableCell>
                </>
              ) : <TableCell colSpan={4} className="text-destructive text-xs whitespace-normal">{row.run.errorType}: {row.run.error}</TableCell>)}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
