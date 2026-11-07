import type { ReactNode } from "react"
import { Check, Download, FileText, X } from "lucide-react"
import { Pill } from "@/components/parts"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type { Status, StepRecord } from "@/lib/types"

/** The state of a run or a step, in its color. */
export function StatusPill({ status }: { status: Status }) {
  const { t } = useI18n()
  const tone = status === "passed" ? "success" : status === "failed" || status === "error" ? "danger"
    : status === "waiting" ? "warning" : status === "running" ? "info" : "default"
  return <Pill tone={tone}>{t(`status.${status}` as MessageKey)}</Pill>
}

/** A titled block inside a step. */
function Block({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <h4 className="text-muted-foreground text-xs font-medium tracking-wide uppercase">{title}</h4>
      {children}
    </div>
  )
}

/** Lines of output, monospaced, newest at the bottom. */
export function Lines({ lines }: { lines: { stream: string; text: string }[] }) {
  if (lines.length === 0) return null
  return (
    <pre className="bg-muted/50 max-h-72 overflow-auto rounded-md border p-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap">
      {lines.map((l, i) => <span key={i} className={l.stream === "stderr" ? "text-destructive block" : "block"}>{l.text}</span>)}
    </pre>
  )
}

/** What a step did: its actions, command, checks, the Sandbox's requests, its files. */
export function StepDetails({ runId, step, lines, children }: { runId: string; step: StepRecord; lines?: { stream: string; text: string }[]; children?: ReactNode }) {
  const { t, time } = useI18n()
  return (
    <div className="space-y-4">
      {step.description && <p className="text-muted-foreground text-sm">{step.description}</p>}
      {step.error && <p className="text-destructive text-sm">{step.error}</p>}
      {step.actions.length > 0 && (
        <Block title={t("run.actions")}>
          <ul className="list-disc pl-5 font-mono text-xs">{step.actions.map((a, i) => <li key={i}>{a}</li>)}</ul>
        </Block>
      )}
      {step.command && (
        <Block title={t("run.command") + (step.timedOut ? ` · ${t("run.timedOut")}` : step.exitCode != null ? ` · ${t("run.exit", { code: step.exitCode })}` : "")}>
          <pre className="bg-muted/50 overflow-auto rounded-md border p-2 font-mono text-[11px] whitespace-pre-wrap break-all">{step.command}</pre>
        </Block>
      )}
      {lines && lines.length > 0 && <Block title={t("run.output")}><Lines lines={lines} /></Block>}
      {step.checks.length > 0 && (
        <Block title={t("run.checks")}>
          <Table>
            <TableHeader>
              <TableRow><TableHead className="w-8" /><TableHead>{t("run.check")}</TableHead><TableHead>{t("run.expected")}</TableHead><TableHead>{t("run.found")}</TableHead></TableRow>
            </TableHeader>
            <TableBody>
              {step.checks.map((c, i) => (
                <TableRow key={i}>
                  <TableCell>{c.passed ? <Check className="text-success size-4" /> : <X className="text-destructive size-4" />}</TableCell>
                  <TableCell className="font-mono text-xs">{c.name}</TableCell>
                  <TableCell className="font-mono text-xs break-all whitespace-pre-wrap">{c.expected}</TableCell>
                  <TableCell className="font-mono text-xs break-all whitespace-pre-wrap">{c.actual}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Block>
      )}
      {step.sandboxRequests.length > 0 && (
        <Block title={t("run.requests")}>
          <div className="rounded-md border font-mono text-[11px]">
            {step.sandboxRequests.map((r) => (
              <div key={r.id} className="flex gap-3 border-b px-2 py-1 last:border-0">
                <span className="text-muted-foreground">{time(r.time)}</span>
                <span className="w-10">{r.service}</span>
                <span className="min-w-0 flex-1 truncate">{r.method} {r.path}</span>
                <span className={r.status >= 400 ? "text-destructive" : ""}>{r.status}</span>
                {r.fault && <span className="text-warning">{r.fault}</span>}
              </div>
            ))}
          </div>
        </Block>
      )}
      {step.note && <Block title={t("run.note")}><p className="text-sm whitespace-pre-wrap">{step.note}</p></Block>}
      {step.files.length + step.attachments.length > 0 && (
        <Block title={t("run.files")}>
          <div className="flex flex-wrap gap-2">
            {[...step.files, ...step.attachments].map((f) => (
              <span key={f} className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs">
                <a className="inline-flex items-center gap-1 hover:underline" href={api.fileUrl(runId, f)} target="_blank" rel="noreferrer"><FileText className="size-3" />{f.split("/").pop()}</a>
                <a className="text-muted-foreground hover:text-foreground" href={api.fileUrl(runId, f, true)} aria-label={t("common.download")}><Download className="size-3" /></a>
              </span>
            ))}
          </div>
        </Block>
      )}
      {children}
    </div>
  )
}
