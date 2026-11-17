import { useMemo, useState } from "react"
import { Check, Minus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useT } from "@/i18n"
import { cn } from "@/lib/utils"
import type { Format, SchemaOption, StandardRef } from "../workbench/schema"
import { useWorkbench } from "../workbench/state"

interface Row {
  key: string
  section: string
  title: string
  standards: StandardRef[]
  api?: string | null
  supported: boolean
}

/** One row per option, and one per value of the choices that name their own clause. */
function rows(option: SchemaOption, section: string): Row[] {
  const own: Row = { key: option.id, section, title: option.title, standards: option.standards, api: option.api, supported: option.support === "supported" }
  const values = option.values.filter((v) => v.standards.length > 0 || v.api)
    .map((v) => ({ key: `${option.id}=${v.value}`, section, title: `${option.title}: ${v.title}`, standards: v.standards, api: v.api, supported: v.support === "supported" }))
  return [own, ...values]
}

/**
 * What SimpleSign implements of each standard, read from the same schema the workbench is drawn
 * from: every option with its clause and library call, and the ones the library does not have.
 */
export function CoveragePage() {
  const { schema } = useWorkbench()
  const t = useT()
  const [format, setFormat] = useState<Format>("pades")
  const [only, setOnly] = useState<"all" | "missing">("all")
  const [view, setView] = useState<"format" | "standard">("format")
  const all = useMemo(() => schema.options
    .filter((o) => o.formats.includes(format))
    .flatMap((o) => rows(o, schema.sections.find((s) => s.id === o.section)?.title ?? o.section)),
  [schema, format])
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
          <div className="bg-muted flex rounded-lg p-0.5 text-xs">
            {(["format", "standard"] as const).map((v) => (
              <button key={v} onClick={() => setView(v)} className={cn("rounded-md px-3 py-1.5 font-medium", view === v ? "bg-background shadow-sm" : "text-muted-foreground")}>
                {t(v === "format" ? "coverage.byFormat" : "coverage.byStandard")}
              </button>
            ))}
          </div>
          <div className={cn("bg-muted flex rounded-lg p-0.5", view === "standard" && "hidden")} role="radiogroup">
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
          {view === "format" && <span className="text-sm">{t("coverage.summary", { supported, total: all.length, missing: all.length - supported })}</span>}
          <Button variant="outline" size="sm" className="ml-auto" asChild>
            <a href="https://github.com/eupassarin/simplesign/blob/main/docs/articles/coverage.md" target="_blank" rel="noreferrer">{t("coverage.docs")}</a>
          </Button>
        </div>
        {view === "standard" && <ByStandard onlyMissing={only === "missing"} />}
        <div className={cn("space-y-5", view === "standard" && "hidden")}>
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
                    <span className={cn("flex items-center gap-1.5 text-sm", !r.supported && "text-muted-foreground")}>{r.title}</span>
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
    </div>
  )
}

/** The reverse index: each standard, its clauses, and the options (of any format) that implement each one. */
function ByStandard({ onlyMissing }: { onlyMissing: boolean }) {
  const { schema } = useWorkbench()
  const documents = useMemo(() => {
    const entries = new Map<string, Map<string, { clause: string; title: string; supported: boolean; formats: Set<Format> }>>()
    for (const option of schema.options) {
      for (const format of option.formats) {
        for (const row of rows(option, "")) {
          for (const standard of row.standards) {
            const clauses = entries.get(standard.document) ?? new Map()
            entries.set(standard.document, clauses)
            const key = `${standard.clause}\u0000${row.title}`
            const entry = clauses.get(key) ?? { clause: standard.clause, title: row.title, supported: row.supported, formats: new Set<Format>() }
            entry.formats.add(format)
            clauses.set(key, entry)
          }
        }
      }
    }
    return [...entries.entries()].sort(([a], [b]) => a.localeCompare(b))
      .map(([document, clauses]) => ({ document, clauses: [...clauses.values()].sort((a, b) => a.clause.localeCompare(b.clause, undefined, { numeric: true }) || a.title.localeCompare(b.title)) }))
  }, [schema])
  const t = useT()
  return (
    <div className="space-y-4">
      {documents.map(({ document, clauses }) => {
        const shown = onlyMissing ? clauses.filter((c) => !c.supported) : clauses
        return shown.length === 0 ? null : (
          <section key={document} className="rounded-lg border">
            <p className="bg-muted/40 flex items-center gap-2 border-b px-3 py-2 text-sm font-semibold">
              {document}
              <span className="text-muted-foreground text-xs font-normal">{t("coverage.summary", { supported: clauses.filter((c) => c.supported).length, total: clauses.length, missing: clauses.filter((c) => !c.supported).length })}</span>
            </p>
            <ul className="divide-y">
              {shown.map((c) => (
                <li key={c.clause + c.title} className={cn("flex flex-wrap items-center gap-x-3 gap-y-0.5 px-3 py-1.5 text-sm", !c.supported && "bg-muted/40 text-muted-foreground")}>
                  {c.supported ? <Check className="text-success size-4 shrink-0" /> : <Minus className="size-4 shrink-0" />}
                  <span className="w-72 shrink-0 text-xs">{c.clause || "—"}</span>
                  <span className="flex min-w-0 flex-1 items-center gap-1.5">{c.title}</span>
                  <span className="text-muted-foreground shrink-0 text-xs">{schema.formats.filter((f) => c.formats.has(f.id)).map((f) => f.title).join(" · ")}</span>
                </li>
              ))}
            </ul>
          </section>
        )
      })}
    </div>
  )
}
