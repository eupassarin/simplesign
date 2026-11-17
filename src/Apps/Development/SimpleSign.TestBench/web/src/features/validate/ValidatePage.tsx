import { useEffect, useRef, useState } from "react"
import { Check, ListChecks, Loader2, ShieldCheck, TriangleAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useT } from "@/i18n"
import { api } from "@/lib/api"
import { cn } from "@/lib/utils"
import { EtsiText, ReportButtons } from "../shared/ReportViewer"
import { Indication } from "../shared/results"
import { Pill } from "../shared/ui"
import { OptionField, OptionScope } from "../workbench/fields"
import { ProfileMenu, ProfileStrip } from "../workbench/profile"
import { ResultPanel } from "../workbench/ResultPanel"
import type { DssSignature, RunVerdict, RunView, ValidationSampleView } from "../workbench/schema"
import { useWorkbench, type ValidateTarget } from "../workbench/state"
import { HistoryDrawer } from "../workbench/WorkbenchPage"
import { Block, SignedFilePicker, useOpenBlocks } from "./parts"

/** The settings of a validation, in the order a validator uses them: whom to trust, what to check, where to look. */
const settingBlocks = [
  { id: "trust", title: "val.trust", summary: "val.trustHint", ids: ["common.validation.trust"] },
  { id: "policy", title: "val.policy", summary: "val.policyHint", ids: ["common.validation.policy", "common.validation.level"] },
  { id: "revocation", title: "val.revocation", summary: "val.revocationHint", ids: ["common.validation.revocationStrategy"] },
] as const

const openByDefault: Record<string, boolean> = { file: true, "samples.pades": true, trust: true, policy: true, revocation: false }

interface ConformanceRow {
  sample: ValidationSampleView
  status: "pending" | "running" | "done"
  run?: RunView
}

/**
 * The Validate task: any signed file (PDF, CMS or XML, told apart by its content), the trust to
 * validate it with, and the same result as a signing run: verdicts of SimpleSign and DSS,
 * what is inside the file, the log and the code.
 */
export function ValidatePage() {
  const { schema, validateTarget, setValidateTarget, validateOptions, setValidateOption, updateValidate, validate, running, run, dss, engine, openRun } = useWorkbench()
  const t = useT()
  const [samples, setSamples] = useState<ValidationSampleView[]>([])
  const [rows, setRows] = useState<ConformanceRow[] | null>(null)
  const [checking, setChecking] = useState(false)
  const [showConformance, setShowConformance] = useState(false)
  const stop = useRef(false)
  useEffect(() => {
    api.workbench.samples().then(setSamples).catch(() => setSamples([]))
  }, [schema])

  const choose = (target: ValidateTarget) => {
    setShowConformance(false)
    setValidateTarget(target)
    void validate(target)
  }

  // Validates every sample and lines the verdicts up with what each sample should get.
  const checkAll = async () => {
    const list = samples
    stop.current = false
    setChecking(true)
    setShowConformance(true)
    setRows(list.map((sample) => ({ sample, status: "pending" })))
    try {
      for (const sample of list) {
        if (stop.current) break
        setRows((current) => current && current.map((r) => (r.sample === sample ? { ...r, status: "running" } : r)))
        const { id } = await api.workbench.start("", { fileId: sample.fileId, dataId: sample.dataId ?? null, settings: validateOptions.validation }, dss.enabled, "validate", engine)
        let result: RunView | undefined
        while (!result) {
          await new Promise((resolve) => setTimeout(resolve, 200))
          result = await api.workbench.run(id)
        }
        const done = result
        setRows((current) => current && current.map((r) => (r.sample === sample ? { ...r, status: "done", run: done } : r)))
      }
    } finally {
      setChecking(false)
    }
  }

  const { open, toggle } = useOpenBlocks("val.sections", openByDefault)
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="space-y-2 border-b px-4 py-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span className="text-sm">
          {validateTarget
            ? <><span className="font-medium">{validateTarget.name}</span>{validateTarget.dataName && <span className="text-muted-foreground"> + {validateTarget.dataName}</span>}</>
            : <span className="text-muted-foreground">{t("val.noFile")}</span>}
        </span>
        {run && validateTarget?.fileId === run.outputId && <Pill>{schema.formats.find((f) => f.id === run.format)?.title}</Pill>}
        <div className="ml-auto flex items-center gap-2">
          <ProfileMenu page="validate" options={validateOptions} update={updateValidate} />
          <Button variant="outline" size="sm" className="h-8" onClick={checking ? () => { stop.current = true } : checkAll} disabled={samples.length === 0}>
            {checking ? <Loader2 className="animate-spin" /> : <ListChecks />} {t(checking ? "wb.variants.stop" : "val.validateAll")}
          </Button>
          <HistoryDrawer />
          <Button className="min-w-36" disabled={!validateTarget || running} onClick={() => { setShowConformance(false); void validate() }}>
            {running ? <Loader2 className="animate-spin" /> : <ShieldCheck />} {t("val.validate")}
          </Button>
        </div>
      </div>
      <ProfileStrip page="validate" options={validateOptions} />
      </div>
      <div className="grid min-h-0 flex-1 lg:grid-cols-[minmax(400px,5fr)_7fr]">
        <div className="min-h-0 space-y-3 overflow-y-auto border-r p-4">
          <Block id="file" title={t("val.file")} summary={t("val.fileHint")} open={open} toggle={toggle}>
            <SignedFilePicker target={validateTarget} onChoose={choose} samples={samples} open={open} toggle={toggle} />
          </Block>

          <OptionScope.Provider value={{ options: validateOptions, set: setValidateOption }}>
            {settingBlocks.map((block) => {
              const options = block.ids.map((id) => schema.options.find((o) => o.id === id)).filter((o) => o !== undefined)
              return options.length === 0 ? null : (
                <Block key={block.id} id={block.id} title={t(block.title)} summary={t(block.summary)} count={options.length} open={open} toggle={toggle}>
                  {options.map((o) => <OptionField key={o.id} option={o} />)}
                </Block>
              )
            })}
          </OptionScope.Provider>
        </div>
        <div className="min-h-0 overflow-y-auto p-4">
          <ResultPanel extra={rows ? {
            id: "conformance",
            open: showConformance,
            label: <>{t("val.conformance")}{checking && <Loader2 className="ml-1 size-3 animate-spin" />}</>,
            content: <Conformance rows={rows} onOpen={(id) => { setShowConformance(false); void openRun(id) }} />,
          } : undefined} />
        </div>
      </div>
    </div>
  )
}

/** Each sample with the verdict it should get, the one SimpleSign gives and the one DSS gives. */
function Conformance({ rows, onOpen }: { rows: ConformanceRow[]; onOpen: (id: string) => void }) {
  const { schema } = useWorkbench()
  const t = useT()
  const done = rows.filter((r) => r.status === "done")
  const matching = done.filter((r) => !r.sample.expectedIndication || r.run?.overall === r.sample.expectedIndication).length
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Pill tone={done.length > 0 && matching === done.length ? "success" : done.length === 0 ? "default" : "warning"}>{t("val.conformanceSummary", { ok: matching, total: rows.length })}</Pill>
        <span className="text-muted-foreground text-xs">{t("val.reportsHint")}</span>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead /><TableHead>{t("val.sample")}</TableHead><TableHead>{t("val.expected")}</TableHead><TableHead>SimpleSign</TableHead><TableHead>DSS</TableHead><TableHead>{t("val.reports")}</TableHead><TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => {
            const ok = row.run && (!row.sample.expectedIndication || row.run.overall === row.sample.expectedIndication)
            const cross = row.run?.crossValidation
            return (
              <TableRow key={row.sample.format + row.sample.id} className={cn(row.run && "hover:bg-accent/50 cursor-pointer", row.run && !ok && "bg-warning/5")}
                onClick={() => row.run && onOpen(row.run.id)}>
                <TableCell className="text-muted-foreground text-xs font-semibold">{schema.formats.find((f) => f.id === row.sample.format)?.title}</TableCell>
                <TableCell className="text-sm whitespace-normal">{row.sample.title}</TableCell>
                <TableCell>{row.sample.expectedIndication ? <Indication value={row.sample.expectedIndication as "Valid"} /> : "—"}</TableCell>
                <TableCell className="align-top">{row.status === "running" ? <Loader2 className="size-4 animate-spin" /> : row.run?.overall ? <Verdicts verdicts={flatten(row.run.validation)} /> : row.run ? <span className="text-destructive text-xs whitespace-normal">{row.run.error ?? "—"}</span> : "—"}</TableCell>
                <TableCell className="align-top">{cross?.available ? <DssVerdicts signatures={cross.signatures.filter((s) => s.format || s.signedBy)} /> : cross ? <span className="text-muted-foreground text-xs" title={cross.error ?? undefined}>—</span> : "—"}</TableCell>
                <TableCell className="align-top">
                  <span className="flex flex-col items-start">
                    <ReportButtons compact source="simplesign" reportId={row.run?.reportId} />
                    <ReportButtons compact source="dss" reportId={cross?.reportId} />
                  </span>
                </TableCell>
                <TableCell>{row.run && (ok ? <Check className="text-success size-4" /> : <TriangleAlert className="text-warning size-4" />)}</TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}

function flatten(verdicts: RunVerdict[]): RunVerdict[] {
  return verdicts.flatMap((v) => [v, ...flatten(v.children)])
}

/** One entry per signature: the indication as a badge and, under it, the ETSI indication and sub-indication. */
function Verdicts({ verdicts }: { verdicts: RunVerdict[] }) {
  return (
    <ul className="space-y-1.5">
      {verdicts.map((v, i) => (
        <li key={i} className="flex flex-col items-start gap-0.5" title={[v.label, v.signer].filter(Boolean).join(" · ")}>
          <Indication value={v.indication} />
          <EtsiText compact indication={v.etsiIndication} subIndication={v.subIndication} />
        </li>
      ))}
    </ul>
  )
}

/** DSS's verdicts in the same shape: TOTAL_PASSED → Valid, TOTAL_FAILED → Invalid, INDETERMINATE → Indeterminate. */
function DssVerdicts({ signatures }: { signatures: DssSignature[] }) {
  if (signatures.length === 0) return <span className="text-muted-foreground text-xs">—</span>
  return (
    <ul className="space-y-1.5">
      {signatures.map((s, i) => (
        <li key={i} className="flex flex-col items-start gap-0.5" title={[s.signedBy, s.format].filter(Boolean).join(" · ")}>
          <Indication value={s.indication === "TOTAL_PASSED" || s.indication === "PASSED" ? "Valid" : s.indication === "TOTAL_FAILED" || s.indication === "FAILED" ? "Invalid" : "Indeterminate"} />
          <EtsiText compact indication={s.indication} subIndication={s.subIndication} />
        </li>
      ))}
    </ul>
  )
}
