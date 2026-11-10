import { useEffect, useState, type ReactNode } from "react"
import { ArrowDown, Check, ChevronRight, CircleSlash, Clock, Download, FileJson, Info, KeyRound, Loader2, ShieldCheck, TriangleAlert, XCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { useT, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import { cn } from "@/lib/utils"
import type { ReportCertificate, ReportConstraint, ReportSignature, ReportView } from "../workbench/schema"
import { Indication } from "./results"
import { Pill } from "./ui"

export type ReportSource = "simplesign" | "dss"

/** An ISO time as "2026-11-10 10:51:25 UTC" (seconds kept, fractions dropped), or the text as it came. */
function time(value?: string | null) {
  if (!value) return null
  const utc = /^(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d)(\.\d+)?(Z|\+00:00)$/.exec(value)
  return utc ? `${utc[1]} ${utc[2]} UTC` : value.replace(/^(\d{4}-\d\d-\d\d)T/, "$1 ")
}

/** "NO_CERTIFICATE_CHAIN_FOUND" with a line-break opportunity after each underscore. */
function breakable(text: string) {
  return text.split("_").map((part, i, all) => <span key={i}>{part}{i < all.length - 1 && <>_<wbr /></>}</span>)
}

/**
 * The ETSI indication and sub-indication, as the reports write them: "INDETERMINATE · REVOKED_NO_POE". Compact (in a
 * table, under the badge that already says the indication): the sub-indication, or the indication when there is none.
 */
export function EtsiText({ indication, subIndication, className, compact }: { indication?: string | null; subIndication?: string | null; className?: string; compact?: boolean }) {
  if (!indication && !subIndication) return null
  const full = [indication, subIndication].filter(Boolean).join(" · ")
  return (
    <span className={cn("text-muted-foreground font-mono text-[11px] whitespace-normal", className)} title={`ETSI EN 319 102-1 §5.1.3: ${full}`}>
      {breakable(compact ? subIndication ?? indication ?? "" : full)}
    </span>
  )
}

/**
 * A report's buttons: open it in the viewer and download the JSON. In a clickable row, clicks stay here (the dialog
 * is a React child of this element, so its clicks would reach the row too).
 */
export function ReportButtons({ reportId, source, compact }: { reportId?: string | null; source: ReportSource; compact?: boolean }) {
  const t = useT()
  const [open, setOpen] = useState(false)
  if (!reportId) return null
  const label = source === "dss" ? "DSS" : "SimpleSign"
  return (
    <span className="inline-flex items-center gap-0.5" onClick={(e) => e.stopPropagation()}>
      <Button variant={compact ? "ghost" : "outline"} size="sm" className={cn(compact && "h-7 px-2 text-xs")} onClick={() => setOpen(true)}
        title={t(source === "dss" ? "report.viewDss" : "report.viewSimpleSign")}>
        <FileJson /> {compact ? label : t(source === "dss" ? "report.viewDss" : "report.viewSimpleSign")}
      </Button>
      {compact && (
        <Button variant="ghost" size="sm" className="h-7 px-1.5" asChild title={t("report.downloadJson")}>
          <a href={api.fileUrl(reportId, true)} aria-label={`${t("report.downloadJson")} (${label})`}><Download /></a>
        </Button>
      )}
      <ReportDialog reportId={reportId} source={source} open={open} onOpenChange={setOpen} />
    </span>
  )
}

export function ReportDialog({ reportId, source, open, onOpenChange }: { reportId: string; source: ReportSource; open: boolean; onOpenChange: (open: boolean) => void }) {
  const t = useT()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[90vh] flex-col gap-0 p-0 sm:max-w-4xl">
        <DialogHeader className="border-b px-6 py-4 pr-12">
          <DialogTitle className="flex items-center gap-2"><FileJson className="size-5" /> {t(source === "dss" ? "report.dss" : "report.simplesign")}</DialogTitle>
          <DialogDescription>{t(source === "dss" ? "report.introDss" : "report.introSimplesign")}</DialogDescription>
        </DialogHeader>
        <div className="min-h-0 flex-1 overflow-y-auto px-6 py-4">{open && <ReportViewer reportId={reportId} />}</div>
      </DialogContent>
    </Dialog>
  )
}

/** The report explained: a summary per signature, its chain, timestamps, revocation data and checks, and the raw JSON. */
export function ReportViewer({ reportId }: { reportId: string }) {
  const t = useT()
  const [report, setReport] = useState<ReportView | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let live = true
    setReport(null)
    setError(null)
    api.workbench.report(reportId).then((r) => { if (live) setReport(r) }).catch((e: Error) => { if (live) setError(e.message) })
    return () => { live = false }
  }, [reportId])
  return (
    <div className="space-y-5">
      {error && <p className="text-destructive text-sm">{t("report.error", { error })}</p>}
      {!report && !error && <p className="text-muted-foreground flex items-center gap-2 text-sm"><Loader2 className="size-4 animate-spin" /> {t("report.loading")}</p>}
      {report && (
        <>
          <div className="text-muted-foreground flex flex-wrap gap-x-6 gap-y-1 text-xs">
            {report.document && <span>{t("report.document")}: <span className="text-foreground">{report.document}</span></span>}
            {report.validationTime && <span>{t("report.validationTime")}: <span className="text-foreground">{time(report.validationTime)}</span></span>}
            {report.policy && <span>{t("report.policy")}: <span className="text-foreground">{report.policy}</span></span>}
            <span>{t("report.signatures")}: <span className="text-foreground">{report.signatures.length}</span></span>
          </div>
          {report.signatures.map((s) => <SignatureSection key={s.id} signature={s} />)}
        </>
      )}
      <RawJson reportId={reportId} />
    </div>
  )
}

function SignatureSection({ signature: s }: { signature: ReportSignature }) {
  const t = useT()
  const tone = s.indication === "Valid" ? "border-success/40 bg-success/5" : s.indication === "Invalid" ? "border-destructive/40 bg-destructive/5" : "border-warning/50 bg-warning/5"
  return (
    <section className={cn("space-y-3", s.kind === "counterSignature" && "border-l-2 pl-4")}>
      <div className={cn("space-y-2 rounded-lg border p-4", tone)}>
        <div className="flex flex-wrap items-center gap-2">
          <Pill>{t(`report.kind.${s.kind}` as MessageKey)}</Pill>
          <span className="font-medium">{s.signedBy ?? s.id}</span>
          {s.format && <span className="text-muted-foreground font-mono text-xs">{s.format}</span>}
          <span className="ml-auto flex flex-col items-end gap-0.5">
            <Indication value={s.indication} />
            <EtsiText indication={s.etsiIndication} subIndication={s.subIndication} />
          </span>
        </div>
        <p className="text-sm">{s.explanation}</p>
        <div className="text-muted-foreground flex flex-wrap gap-x-6 gap-y-1 text-xs">
          {s.signingTime && <span>{t("report.signingTime")}: <span className="text-foreground">{time(s.signingTime)}</span></span>}
          {s.bestSignatureTime && <span>{t("report.bestSignatureTime")}: <span className="text-foreground">{time(s.bestSignatureTime)}</span></span>}
          <span className="font-mono break-all opacity-70">{s.id}</span>
        </div>
      </div>
      <Messages signature={s} />
      <Part icon={<KeyRound className="size-4" />} title={t("report.chain")} hint={t("report.chainHint")} count={s.chain.length} defaultOpen>
        {s.chain.length === 0 ? <Empty>{t("report.noChain")}</Empty> : <Chain chain={s.chain} />}
      </Part>
      <Part icon={<Clock className="size-4" />} title={t("report.timestamps")} hint={t("report.timestampsHint")} count={s.timestamps.length}>
        {s.timestamps.length === 0 ? <Empty>{t("report.noTimestamps")}</Empty> : (
          <ul className="divide-y">
            {s.timestamps.map((ts, i) => (
              <li key={i} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1.5 text-sm">
                <span className="font-medium">{time(ts.time) ?? "—"}</span>
                {ts.type && <span className="text-muted-foreground font-mono text-xs">{ts.type}</span>}
                {ts.producedBy && <span className="text-muted-foreground text-xs">{t("report.producedBy", { name: ts.producedBy })}</span>}
                <EtsiText className="ml-auto" indication={ts.indication} subIndication={ts.subIndication} />
              </li>
            ))}
          </ul>
        )}
      </Part>
      <Part icon={<ShieldCheck className="size-4" />} title={t("report.revocation")} hint={t("report.revocationHint")} count={s.revocation.length}>
        {s.revocation.length === 0 ? <Empty>{t("report.noRevocation")}</Empty> : (
          <ul className="divide-y">
            {s.revocation.map((r, i) => (
              <li key={i} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1.5 text-sm">
                <Pill>{r.type}</Pill>
                {r.certificate && <span>{t("report.about", { name: r.certificate })}</span>}
                {r.status && <Pill tone={r.status === "GOOD" ? "success" : r.status === "REVOKED" ? "danger" : "warning"}>{r.status}</Pill>}
                {r.issuer && <span className="text-muted-foreground text-xs">{t("report.issuedBy", { issuer: r.issuer })}</span>}
                {(r.producedAt ?? r.thisUpdate) && <span className="text-muted-foreground text-xs">{t("report.produced", { time: time(r.producedAt ?? r.thisUpdate) ?? "" })}</span>}
                {r.nextUpdate && <span className="text-muted-foreground text-xs">{t("report.nextUpdate", { time: time(r.nextUpdate) ?? "" })}</span>}
                {r.origin && <span className="text-muted-foreground font-mono text-[11px]">{r.origin}</span>}
                {r.url && <span className="text-muted-foreground font-mono text-[11px] break-all">{r.url}</span>}
                <EtsiText className="ml-auto" indication={r.indication} subIndication={r.subIndication} />
              </li>
            ))}
          </ul>
        )}
      </Part>
      <Part icon={<Check className="size-4" />} title={t("report.checks")} hint={t("report.checksHint")} count={s.constraints.length} defaultOpen>
        {s.constraints.length === 0 ? <Empty>{t("report.noChecks")}</Empty> : <Checks constraints={s.constraints} />}
      </Part>
    </section>
  )
}

/** A folding part of a signature: title, one-line hint, count. */
function Part({ icon, title, hint, count, defaultOpen, children }: { icon: ReactNode; title: string; hint: string; count: number; defaultOpen?: boolean; children: ReactNode }) {
  const [open, setOpen] = useState(!!defaultOpen)
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="rounded-lg border">
      <CollapsibleTrigger className="hover:bg-accent/40 flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left">
        <ChevronRight className={cn("text-muted-foreground size-4 shrink-0 transition-transform", open && "rotate-90")} />
        {icon}
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-medium">{title}</span>
          <span className="text-muted-foreground block text-xs">{hint}</span>
        </span>
        <span className="text-muted-foreground text-xs tabular-nums">{count}</span>
      </CollapsibleTrigger>
      <CollapsibleContent><div className="border-t px-4 py-2">{children}</div></CollapsibleContent>
    </Collapsible>
  )
}

function Empty({ children }: { children: ReactNode }) {
  return <p className="text-muted-foreground py-1 text-sm">{children}</p>
}

/** The signer's certificate, then each issuer, with an arrow between them. */
function Chain({ chain }: { chain: ReportCertificate[] }) {
  const t = useT()
  return (
    <ol className="space-y-1 py-1">
      {chain.map((c, i) => (
        <li key={i}>
          {i > 0 && <ArrowDown className="text-muted-foreground mx-3 my-0.5 size-3.5" />}
          <div className="rounded-md border px-3 py-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium">{c.name}</span>
              {i === 0 && <Pill tone="info">{t("report.signer")}</Pill>}
              {c.selfSigned && <Pill>{t("report.selfSigned")}</Pill>}
              {c.trusted === true && <Pill tone="success">{t("report.trusted")}</Pill>}
              {c.trusted === false && c.selfSigned && <Pill tone="warning">{t("report.notTrusted")}</Pill>}
              {c.revocationStatus && <Pill tone={c.revocationStatus === "GOOD" ? "success" : c.revocationStatus === "REVOKED" ? "danger" : "warning"}>{t("report.certRevocation", { status: c.revocationStatus })}</Pill>}
            </div>
            <div className="text-muted-foreground mt-1 space-y-0.5 text-xs">
              {c.subject && <p className="font-mono break-all">{c.subject}</p>}
              <p className="flex flex-wrap gap-x-4">
                {c.notBefore && c.notAfter && <span>{t("report.validity", { from: time(c.notBefore) ?? "", to: time(c.notAfter) ?? "" })}</span>}
                {c.serialNumber && <span className="font-mono break-all">{t("report.serial", { serial: c.serialNumber })}</span>}
              </p>
              {c.issuer && !c.selfSigned && <p className="break-all">{t("report.issuedBy", { issuer: c.issuer })}</p>}
            </div>
          </div>
        </li>
      ))}
    </ol>
  )
}

const groups = ["fail", "warn", "info", "pass", "skip"] as const

/** The checks grouped by outcome: failures and warnings open, the rest closed. */
function Checks({ constraints }: { constraints: ReportConstraint[] }) {
  return (
    <div className="space-y-1 py-1">
      {groups.map((g) => {
        const list = constraints.filter((c) => c.status === g)
        return list.length === 0 ? null : <CheckGroup key={g} status={g} list={list} />
      })}
    </div>
  )
}

function StatusIcon({ status }: { status: ReportConstraint["status"] }) {
  return status === "pass" ? <Check className="text-success size-4 shrink-0" />
    : status === "fail" ? <XCircle className="text-destructive size-4 shrink-0" />
    : status === "warn" ? <TriangleAlert className="text-warning size-4 shrink-0" />
    : status === "info" ? <Info className="text-info size-4 shrink-0" />
    : <CircleSlash className="text-muted-foreground size-4 shrink-0" />
}

function CheckGroup({ status, list }: { status: ReportConstraint["status"]; list: ReportConstraint[] }) {
  const t = useT()
  const [open, setOpen] = useState(status === "fail" || status === "warn")
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger className="hover:bg-accent/40 -mx-2 flex w-[calc(100%+1rem)] items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm font-medium">
        <ChevronRight className={cn("text-muted-foreground size-3.5 shrink-0 transition-transform", open && "rotate-90")} />
        <StatusIcon status={status} />
        <span className="flex-1">{t(`report.group.${status}` as MessageKey)}</span>
        <Pill tone={status === "fail" ? "danger" : status === "warn" ? "warning" : status === "pass" ? "success" : "default"}>{list.length}</Pill>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <ul className="mb-1 ml-5 border-l pl-2">{list.map((c) => <CheckRow key={c.key + c.status} constraint={c} />)}</ul>
      </CollapsibleContent>
    </Collapsible>
  )
}

function CheckRow({ constraint: c }: { constraint: ReportConstraint }) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const details = c.messages.length > 0
  return (
    <li>
      <Collapsible open={open} onOpenChange={setOpen}>
        <CollapsibleTrigger disabled={!details} className={cn("flex w-full items-start gap-2 rounded-md px-2 py-1 text-left text-sm", details && "hover:bg-accent/40")}>
          <StatusIcon status={c.status} />
          <span className="min-w-0 flex-1">
            {c.title}
            <span className="text-muted-foreground ml-2 font-mono text-[10px]">{c.key}</span>
          </span>
          {c.standard && <span className="text-muted-foreground hidden font-mono text-[10px] sm:inline">{c.standard}</span>}
          {c.count > 1 && <span className="text-muted-foreground text-xs tabular-nums">{t("report.times", { n: c.count })}</span>}
          {details && <ChevronRight className={cn("text-muted-foreground mt-0.5 size-3.5 shrink-0 transition-transform", open && "rotate-90")} />}
        </CollapsibleTrigger>
        <CollapsibleContent>
          <ul className="text-muted-foreground space-y-0.5 py-1 pl-8 text-xs">{c.messages.map((m) => <li key={m}>{m}</li>)}</ul>
        </CollapsibleContent>
      </Collapsible>
    </li>
  )
}

/** The validator's own errors, warnings and information messages for the signature. */
function Messages({ signature: s }: { signature: ReportSignature }) {
  const t = useT()
  if (s.errors.length + s.warnings.length + s.infos.length === 0) return null
  return (
    <div className="space-y-1 rounded-lg border px-4 py-2 text-xs">
      {s.errors.length > 0 && <p className="text-[10px] font-semibold tracking-wide uppercase">{t("report.errors")}</p>}
      {s.errors.map((e) => <p key={e} className="text-destructive">✕ {e}</p>)}
      {s.warnings.length > 0 && <p className="pt-1 text-[10px] font-semibold tracking-wide uppercase">{t("report.warnings")}</p>}
      {s.warnings.map((w) => <p key={w} className="text-muted-foreground">! {w}</p>)}
      {s.infos.length > 0 && <p className="pt-1 text-[10px] font-semibold tracking-wide uppercase">{t("report.infos")}</p>}
      {s.infos.map((i) => <p key={i} className="text-muted-foreground">i {i}</p>)}
    </div>
  )
}

/** The file as written, folded; read only when opened. */
function RawJson({ reportId }: { reportId: string }) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const [text, setText] = useState<string | null>(null)
  useEffect(() => {
    if (!open || text !== null) return
    fetch(api.fileUrl(reportId)).then((r) => r.text()).then((raw) => {
      try { setText(JSON.stringify(JSON.parse(raw), null, 2)) } catch { setText(raw) }
    }).catch((e: Error) => setText(e.message))
  }, [open, reportId, text])
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="rounded-lg border">
      <div className="flex items-center gap-2 px-3 py-2">
        <CollapsibleTrigger className="hover:bg-accent/40 -mx-1 flex flex-1 items-center gap-2 rounded-md px-1 py-0.5 text-left">
          <ChevronRight className={cn("text-muted-foreground size-4 shrink-0 transition-transform", open && "rotate-90")} />
          <FileJson className="size-4" />
          <span className="min-w-0 flex-1">
            <span className="block text-sm font-medium">{t("report.raw")}</span>
            <span className="text-muted-foreground block text-xs">{t("report.rawHint")}</span>
          </span>
        </CollapsibleTrigger>
        <Button variant="outline" size="sm" asChild><a href={api.fileUrl(reportId, true)}><Download /> {t("report.downloadJson")}</a></Button>
      </div>
      <CollapsibleContent>
        {text === null
          ? <p className="text-muted-foreground flex items-center gap-2 border-t px-4 py-3 text-sm"><Loader2 className="size-4 animate-spin" /></p>
          : <pre className="bg-muted/50 max-h-[480px] overflow-auto border-t p-4 font-mono text-[11px] leading-relaxed">{text}</pre>}
      </CollapsibleContent>
    </Collapsible>
  )
}
