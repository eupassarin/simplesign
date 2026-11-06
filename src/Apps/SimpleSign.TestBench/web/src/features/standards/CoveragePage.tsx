import { useMemo, useState } from "react"
import { Check, Minus } from "lucide-react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useT } from "@/i18n"
import { cn } from "@/lib/utils"
import { FrameworkTag } from "../workbench/parts"
import type { Format, SchemaOption, StandardRef } from "../workbench/schema"
import { useWorkbench } from "../workbench/state"

interface Row {
  key: string
  section: string
  title: string
  framework?: string | null
  standards: StandardRef[]
  api?: string | null
  supported: boolean
}

/** One row per option, and one per value of the choices that name their own clause. */
function rows(option: SchemaOption, section: string): Row[] {
  const own: Row = { key: option.id, section, title: option.title, framework: option.framework, standards: option.standards, api: option.api, supported: option.support === "supported" }
  const values = option.values.filter((v) => v.standards.length > 0 || v.api)
    .map((v) => ({ key: `${option.id}=${v.value}`, section, title: `${option.title}: ${v.title}`, framework: v.framework ?? option.framework, standards: v.standards, api: v.api, supported: v.support === "supported" }))
  return [own, ...values]
}

/**
 * What SimpleSign implements of each standard, read from the same schema the workbench is drawn
 * from: every option with its clause and library call, and the ones the library does not have.
 */
export function CoveragePage() {
  const { schema, frameworks } = useWorkbench()
  const t = useT()
  const [format, setFormat] = useState<Format>("pades")
  const [only, setOnly] = useState<"all" | "missing">("all")
  const all = useMemo(() => schema.options
    .filter((o) => o.formats.includes(format) && (!o.framework || frameworks.has(o.framework)))
    .flatMap((o) => rows(o, schema.sections.find((s) => s.id === o.section)?.title ?? o.section))
    .filter((r) => !r.framework || frameworks.has(r.framework)),
  [schema, format, frameworks])
  const shown = only === "missing" ? all.filter((r) => !r.supported) : all
  const supported = all.filter((r) => r.supported).length
  const current = schema.formats.find((f) => f.id === format)!
  return (
    <div className="min-h-0 flex-1 overflow-y-auto">
      <div className="space-y-5 p-6 lg:p-8">
        <header className="max-w-3xl space-y-1">
          <h2 className="text-2xl font-semibold tracking-tight">{t("coverage.title")}</h2>
          <p className="text-muted-foreground text-sm">{t("coverage.intro")}</p>
        </header>
        <div className="flex flex-wrap items-center gap-3">
          <div className="bg-muted flex rounded-lg p-0.5" role="radiogroup">
            {schema.formats.map((f) => (
              <button key={f.id} role="radio" aria-checked={format === f.id} onClick={() => setFormat(f.id)}
                className={cn("rounded-md px-4 py-1.5 text-sm font-semibold transition-all", format === f.id ? "bg-background shadow-sm" : "text-muted-foreground hover:text-foreground")}>{f.title}</button>
            ))}
          </div>
          <div className="bg-muted flex rounded-lg p-0.5 text-xs">
            {(["all", "missing"] as const).map((v) => (
              <button key={v} onClick={() => setOnly(v)} className={cn("rounded-md px-3 py-1.5 font-medium", only === v ? "bg-background shadow-sm" : "text-muted-foreground")}>
                {t(v === "all" ? "coverage.all" : "coverage.onlyMissing")}
              </button>
            ))}
          </div>
          <span className="text-sm">{t("coverage.summary", { supported, total: all.length, missing: all.length - supported })}</span>
        </div>
        <ul className="text-muted-foreground space-y-0.5 text-xs">
          {current.standards.map((s) => <li key={s.document}><span className="text-foreground font-medium">{s.document}</span> · {s.clause}</li>)}
        </ul>
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10" />
                <TableHead>{t("coverage.option")}</TableHead>
                <TableHead>{t("coverage.standard")}</TableHead>
                <TableHead>{t("coverage.api")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((r, i) => (
                <TableRow key={r.key} className={cn(!r.supported && "bg-muted/40")}>
                  <TableCell>{r.supported ? <Check className="text-success size-4" /> : <Minus className="text-muted-foreground size-4" />}</TableCell>
                  <TableCell className="whitespace-normal">
                    {(i === 0 || shown[i - 1].section !== r.section) && <span className="text-muted-foreground block text-[10px] font-semibold tracking-wide uppercase">{r.section}</span>}
                    <span className={cn("flex items-center gap-1.5 text-sm", !r.supported && "text-muted-foreground")}>{r.title}<FrameworkTag framework={r.framework} /></span>
                  </TableCell>
                  <TableCell className="text-xs whitespace-normal">
                    {r.standards.map((s) => <span key={s.document + s.clause} className="block"><span className="font-medium">{s.document}</span>{s.clause && <span className="text-muted-foreground"> · {s.clause}</span>}</span>)}
                  </TableCell>
                  <TableCell className="font-mono text-[11px] whitespace-normal break-all">{r.supported ? r.api : <span className="font-sans">{t("wb.notInLibrary")}</span>}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
    </div>
  )
}
