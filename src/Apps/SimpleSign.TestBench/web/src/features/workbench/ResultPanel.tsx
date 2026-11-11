import { useEffect, useState, type ReactNode } from "react"
import { Check, ChevronRight, CircleSlash, Download, FileCheck2, Info, Loader2, RefreshCw, ShieldCheck, ShieldQuestion, TriangleAlert, XCircle } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useI18n, useT, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type { CadesSignResult, CadesValidationView, SigningResult, ValidationReport, XmlSignResult, XmlValidationView } from "@/lib/types"
import { cn } from "@/lib/utils"
import { CmsStructure } from "../cades/CmsViews"
import { DetailedCard, InspectView } from "../validate/pdf"
import { ReportButtons } from "../shared/ReportViewer"
import { CodeTabs, Indication } from "../shared/results"
import { IssueList, KeyValue, Pill } from "../shared/ui"
import { XmlViews } from "../xml/XmlViews"
import { LogView } from "./LogView"
import { StandardBadge } from "./parts"
import type { CliStep, DssComparison, DssComparisonRow, Finding, RunVerdict, RunView } from "./schema"
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

/** The commands a run through the CLI executed: each line, its exit code and time, and what it printed (open on click). */
function CliSteps({ steps }: { steps: CliStep[] }) {
  const t = useT()
  return (
    <div className="space-y-2 rounded-lg border p-4">
      <p className="text-sm font-medium">{t("wb.result.cliCommands")}</p>
      <p className="text-muted-foreground text-xs">{t("wb.result.cliHint")}</p>
      {steps.map((step, i) => (
        <Collapsible key={i}>
          <CollapsibleTrigger className="group flex w-full items-start gap-2 text-left">
            <ChevronRight className="mt-1 size-3.5 shrink-0 transition-transform group-data-[state=open]:rotate-90" />
            <code className="min-w-0 flex-1 font-mono text-[11px] break-all">{step.command}</code>
            <Pill tone={step.exitCode === 0 ? "success" : "danger"}>{t("wb.result.exitCode", { code: step.exitCode, ms: step.ms })}</Pill>
          </CollapsibleTrigger>
          <CollapsibleContent>
            <pre className="bg-muted mt-2 max-h-72 overflow-auto rounded-md p-2 font-mono text-[11px] whitespace-pre-wrap">{step.output || "—"}</pre>
          </CollapsibleContent>
        </Collapsible>
      ))}
    </div>
  )
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
        {run.cli && run.cli.length > 0 && <CliSteps steps={run.cli} />}
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
          <p className="font-medium">
            {formatTitle} · {validating ? run.fileName : run.achievedLevel ?? run.requestedLevel}
            {run.engine === "cli" && <span className="ml-2"><Pill tone="info">{t("wb.engine.cli")}</Pill></span>}
          </p>
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
      {run.cli && run.cli.length > 0 && <CliSteps steps={run.cli} />}
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
        <span className="ml-auto"><Indication value={verdict.indication} subIndication={verdict.subIndication} /></span>
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
      <Findings verdict={verdict} />
      {verdict.children.length > 0 && (
        <div className="space-y-2 border-t p-2">
          <p className="text-muted-foreground px-2 text-xs">{t("wb.validation.counterSignatures")}</p>
          {verdict.children.map((c, i) => <VerdictCard key={i} verdict={c} compact={compact} depth={depth + 1} />)}
        </div>
      )}
    </div>
  )
}

/**
 * What SimpleSign found beyond the checks: the policy constraints that failed, warned or informed, one line per
 * constraint (its messages, one per certificate or token, open on click), then the other errors and warnings once each.
 */
function Findings({ verdict }: { verdict: RunVerdict }) {
  const t = useT()
  const findings = verdict.findings ?? []
  const covered = new Set(findings.flatMap((f) => f.messages))
  const errors = [...new Set(verdict.errors)].filter((e) => !covered.has(e))
  const warnings = [...new Set(verdict.warnings)].filter((w) => !covered.has(w))
  if (findings.length === 0 && errors.length === 0 && warnings.length === 0) return null
  return (
    <div className="space-y-1 border-t px-4 py-2">
      {findings.map((f) => <FindingRow key={f.status + f.constraint} finding={f} />)}
      {(errors.length > 0 || warnings.length > 0) && (
        <ul className="space-y-1 pt-1 text-xs">
          {findings.length > 0 && <li className="text-muted-foreground text-[10px] font-semibold tracking-wide uppercase">{t("wb.validation.other")}</li>}
          {errors.map((e) => <li key={e} className="text-destructive">✕ {e}</li>)}
          {warnings.map((w) => <li key={w} className="text-muted-foreground">! {w}</li>)}
        </ul>
      )}
    </div>
  )
}

function FindingRow({ finding }: { finding: Finding }) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const icon = finding.status === "fail" ? <XCircle className="text-destructive size-4 shrink-0" />
    : finding.status === "warn" ? <TriangleAlert className="text-warning size-4 shrink-0" /> : <Info className="text-info size-4 shrink-0" />
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger className="hover:bg-accent/40 -mx-2 flex w-[calc(100%+1rem)] items-center gap-2 rounded-md px-2 py-1 text-left text-sm">
        <ChevronRight className={cn("text-muted-foreground size-3.5 shrink-0 transition-transform", open && "rotate-90")} />
        {icon}
        <span className="min-w-0 flex-1">
          <span className="text-muted-foreground mr-1 text-xs">{t(finding.status === "fail" ? "wb.validation.failed" : finding.status === "warn" ? "wb.validation.warning" : "wb.validation.info")}:</span>
          {finding.title}
        </span>
        {finding.standard && <span className="text-muted-foreground hidden font-mono text-[10px] sm:inline">{finding.standard}</span>}
        <Pill>{finding.messages.length}</Pill>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <ul className="text-muted-foreground space-y-0.5 py-1 pl-11 text-xs">
          {finding.messages.map((m) => <li key={m}>{m}</li>)}
          <li className="font-mono text-[10px] opacity-70">{finding.constraint}</li>
        </ul>
      </CollapsibleContent>
    </Collapsible>
  )
}

/** DSS's indication as SimpleSign's: TOTAL_PASSED/PASSED → Valid, TOTAL_FAILED/FAILED → Invalid, else Indeterminate. */
function dssIndication(value?: string | null): RunVerdict["indication"] | null {
  if (!value) return null
  const main = value.split("/")[0].trim()
  return main === "TOTAL_PASSED" || main === "PASSED" ? "Valid" : main === "TOTAL_FAILED" || main === "FAILED" ? "Invalid" : "Indeterminate"
}

/**
 * The top of the Validation tab: for each signature, SimpleSign's verdict and DSS's side by side, and for each
 * difference why (in plain words), whether it is DSS's setup or a real disagreement, and what to do.
 */
function ValidationSummary({ run }: { run: RunView }) {
  const t = useT()
  const dss = run.crossValidation
  if (!dss?.available || dss.rows.length === 0) return null
  const signatures = [...new Set(dss.rows.map((r) => r.label))]
  return (
    <section className={cn("space-y-3 rounded-lg border p-4", dss.agree ? "border-success/40 bg-success/5" : "border-warning/50 bg-warning/5")}>
      <p className="text-sm font-medium">{dss.summary ?? t(dss.agree ? "wb.dss.agrees" : "wb.dss.differs")}</p>
      {signatures.map((label) => {
        const rows = dss.rows.filter((r) => r.label === label)
        const indication = rows.find((r) => r.topic === "indication")
        const theirs = dssIndication(indication?.dss)
        return (
          <div key={label} className="space-y-2">
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
              <span className="font-medium">{label}</span>
              <span className="inline-flex items-center gap-1.5 text-xs"><span className="text-muted-foreground">SimpleSign</span>{indication?.library ? <Indication value={indication.library as RunVerdict["indication"]} /> : "—"}</span>
              <span className="inline-flex items-center gap-1.5 text-xs"><span className="text-muted-foreground">DSS</span>{theirs ? <Indication value={theirs} /> : "—"}</span>
            </div>
            {rows.filter((r) => !r.agree).map((r, i) => <Difference key={i} row={r} />)}
          </div>
        )
      })}
    </section>
  )
}

/** One difference: what differs, what DSS concluded in plain words, its likely cause and what to do. */
function Difference({ row }: { row: DssComparisonRow }) {
  const t = useT()
  return (
    <div className="bg-background space-y-1.5 rounded-md border px-3 py-2 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{t(row.topic === "indication" ? "wb.dss.diffIndication" : "wb.dss.diffLevel")}</span>
        <span className="font-mono text-xs">{row.library ?? "—"} × {row.dss ?? "—"}</span>
        {row.cause && <Pill tone={row.cause === "setup" ? "info" : row.cause === "disagreement" ? "danger" : "default"}>{t(`wb.dss.cause.${row.cause}` as MessageKey)}</Pill>}
      </div>
      {row.reason && <p>{row.reason}</p>}
      {row.action && <p className="text-muted-foreground text-xs">→ {row.action}</p>}
    </div>
  )
}

/** What is inside the produced file, in the terms of its format. */
function Inspection({ run }: { run: RunView }) {
  const { t, number } = useI18n()
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
  // A signed PDF: the same views as the Validation page (each signature in detail, then the file's objects).
  const detail = run.detail as SigningResult
  return (
    <div className="space-y-6">
      {detail.report?.signatures.map((s) => <DetailedCard key={s.report.fieldName} signature={s} />)}
      {detail.deferred && (
        <div className="space-y-1 rounded-lg border px-4 py-2">
          <p className="py-1 text-sm font-medium">{t("result.tabs.deferred")}</p>
          <KeyValue stacked label={t("result.deferred.hashToSign")} mono>{detail.deferred.hashToSignHex}</KeyValue>
          <KeyValue label={t("result.deferred.digest")}>{detail.deferred.digestAlgorithm}</KeyValue>
          <KeyValue stacked label={t("result.deferred.algorithm")} mono>{detail.deferred.signatureAlgorithmOid}</KeyValue>
          <KeyValue label={t("result.deferred.session")}>{t("result.deferred.bytes", { n: detail.deferred.sessionBytes })}</KeyValue>
          <KeyValue stacked label={t("result.deferred.raw")} mono>{detail.deferred.rawSignatureHex}</KeyValue>
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
      <InspectView file={{ id: run.outputId! }} />
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
      <ValidationSummary run={run} />
      <section className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-sm font-semibold">SimpleSign</h3>
          {stage && <StandardBadge explanation={{ title: stage.title, summary: stage.summary, standards: stage.standards[run.format], api: schema.formats.find((f) => f.id === run.format)?.validatorApi }} />}
          {run.overall && <span className="ml-auto"><Indication value={run.overall} /></span>}
          {run.reportId && (
            <span className={cn("flex items-center gap-2", !run.overall && "ml-auto")}>
              <ReportButtons source="simplesign" reportId={run.reportId} />
              <Button variant="outline" size="sm" asChild><a href={api.fileUrl(run.reportId, true)}><Download /> {t("report.simplesign")} (JSON)</a></Button>
              {run.etsiReportId && <Button variant="outline" size="sm" asChild><a href={api.fileUrl(run.etsiReportId, true)}><Download /> {t("report.etsiReport")} (XML)</a></Button>}
            </span>
          )}
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
        {comparison.reportId && (
          <span className="ml-auto flex items-center gap-2">
            <ReportButtons source="dss" reportId={comparison.reportId} />
            <Button variant="outline" size="sm" asChild><a href={api.fileUrl(comparison.reportId, true)}><Download /> {t("wb.dss.report")}</a></Button>
          </span>
        )}
      </div>
      {comparison.rows.filter((r) => r.agree).length > 0 && (
        <p className="text-muted-foreground flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
          <Check className="text-success size-3.5" />
          {t("wb.dss.agreeOn")}
          {comparison.rows.filter((r) => r.agree).map((r, i) => (
            <span key={i} className="font-mono">{r.label} · {t(r.topic === "indication" ? "wb.dss.indication" : "wb.dss.level")} {r.dss ?? r.library}</span>
          ))}
        </p>
      )}
      {comparison.rows.some((r) => !r.agree) && <p className="text-muted-foreground text-xs">{t("wb.dss.seeSummary")}</p>}
      {comparison.notes.length > 0 && <ul className="text-muted-foreground space-y-1 text-xs">{comparison.notes.map((n) => <li key={n}>• {n}</li>)}</ul>}
      <DssMessages comparison={comparison} />
    </div>
  )
}

/** DSS's own messages per signature, as it wrote them: closed by default. */
function DssMessages({ comparison }: { comparison: DssComparison }) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const count = comparison.signatures.reduce((n, s) => n + s.errors.length + s.warnings.length, 0)
  if (count === 0) return null
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="rounded-lg border">
      <CollapsibleTrigger className="hover:bg-accent/40 flex w-full items-center gap-2 rounded-lg px-4 py-2 text-left text-sm">
        <ChevronRight className={cn("text-muted-foreground size-4 transition-transform", open && "rotate-90")} />
        <span className="flex-1">{t("wb.dss.messages")}</span>
        <Pill>{count}</Pill>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="space-y-2 border-t p-3">
          {comparison.signatures.filter((s) => s.errors.length + s.warnings.length > 0).map((s, i) => (
            <div key={i} className="text-xs">
              <p className="font-medium break-all">{s.id ?? `#${i + 1}`} · {s.indication}{s.subIndication ? ` / ${s.subIndication}` : ""}{s.format ? ` · ${s.format}` : ""}</p>
              <ul className="mt-1 space-y-0.5">
                {s.errors.map((e) => <li key={e} className="text-destructive">✕ {e}</li>)}
                {s.warnings.map((w) => <li key={w} className="text-muted-foreground">! {w}</li>)}
              </ul>
            </div>
          ))}
        </div>
      </CollapsibleContent>
    </Collapsible>
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
