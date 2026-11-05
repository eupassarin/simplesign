import { useEffect, useMemo, useState } from "react"
import { CheckCircle2, Loader2, Play, XCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { api } from "@/lib/api"
import type { MatrixCase, MatrixCaseResult, MatrixRunResult } from "@/lib/types"
import { cn } from "@/lib/utils"
import { Pill } from "../pdf-signing/ui"

export function MatrixPage() {
  const [cases, setCases] = useState<MatrixCase[] | null>(null)
  const [result, setResult] = useState<MatrixRunResult | null>(null)
  const [running, setRunning] = useState(false)
  const [filter, setFilter] = useState("all")
  useEffect(() => {
    api.matrix.cases().then(setCases)
  }, [])
  const dimensions = useMemo(() => (cases?.[0] ? Object.keys(cases[0].values) : []), [cases])
  const byId = useMemo(() => new Map(result?.cases.map((c) => [c.id, c]) ?? []), [result])
  const shown = (cases ?? []).filter((c) => {
    const r = byId.get(c.id)
    return filter === "all" || (filter === "failed" ? r?.status === "fail" : c.group === filter)
  })

  async function run() {
    setRunning(true)
    try {
      setResult(await api.matrix.run({ group: "all" }))
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="min-h-0 min-w-0 flex-1 overflow-y-auto">
      <div className="space-y-6 p-6 lg:p-8">
        <header className="flex flex-wrap items-end justify-between gap-4">
          <div className="max-w-3xl space-y-1">
            <h2 className="text-2xl font-semibold tracking-tight">Run matrix</h2>
            <p className="text-muted-foreground text-sm">
              Proves every option is testable. Cases are generated from the same Compatibility rules the signing page uses: every value of every dimension on its own,
              plus pairwise combinations (every pair of values appears in at least one valid case). Each case signs in the sandbox, validates, and checks the output has what was asked
              (level, sub-filter, timestamps, DSS, document timestamp, DocMDP, mode).
            </p>
          </div>
          <Button onClick={run} disabled={running || !cases}>{running ? <Loader2 className="animate-spin" /> : <Play />} Run {cases?.length ?? ""} cases</Button>
        </header>

        {running && <Progress value={undefined} className="h-1 animate-pulse" />}
        {result && (
          <div className="flex flex-wrap items-center gap-4 rounded-lg border p-4 text-sm">
            {result.failed === 0 ? <CheckCircle2 className="text-success size-5" /> : <XCircle className="text-destructive size-5" />}
            <span className="font-medium">{result.passed} / {result.total} passed</span>
            {result.failed > 0 && <span className="text-destructive">{result.failed} failed</span>}
            <span className="text-muted-foreground">{(result.ms / 1000).toFixed(1)} s</span>
            <span className="text-muted-foreground">{result.uncoverablePairs} value pairs are never compatible (and are not generated).</span>
          </div>
        )}

        <Tabs value={filter} onValueChange={setFilter}>
          <TabsList>
            <TabsTrigger value="all">All ({cases?.length ?? 0})</TabsTrigger>
            <TabsTrigger value="single">Single values ({cases?.filter((c) => c.group === "single").length ?? 0})</TabsTrigger>
            <TabsTrigger value="pairwise">Pairwise ({cases?.filter((c) => c.group === "pairwise").length ?? 0})</TabsTrigger>
            {result && result.failed > 0 && <TabsTrigger value="failed">Failed ({result.failed})</TabsTrigger>}
          </TabsList>
        </Tabs>

        {!cases ? (
          <Loader2 className="size-4 animate-spin" />
        ) : (
          <div className="overflow-x-auto rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-16">Case</TableHead>
                  <TableHead className="w-20">Result</TableHead>
                  {dimensions.map((d) => <TableHead key={d} className="text-xs whitespace-nowrap">{d}</TableHead>)}
                </TableRow>
              </TableHeader>
              <TableBody>
                {shown.map((c) => <Row key={c.id} c={c} r={byId.get(c.id)} dimensions={dimensions} />)}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </div>
  )
}

function Row({ c, r, dimensions }: { c: MatrixCase; r?: MatrixCaseResult; dimensions: string[] }) {
  return (
    <>
      <TableRow className={cn(r?.status === "fail" && "bg-destructive/5")}>
        <TableCell className="font-mono text-xs">{c.id}</TableCell>
        <TableCell>
          {!r ? <span className="text-muted-foreground text-xs">—</span> : r.status === "pass" ? <Pill tone="success">{r.ms} ms</Pill> : <Pill tone="danger">fail</Pill>}
        </TableCell>
        {dimensions.map((d) => <TableCell key={d} className="text-xs whitespace-nowrap">{c.values[d]}</TableCell>)}
      </TableRow>
      {r?.status === "fail" && (
        <TableRow className="bg-destructive/5">
          <TableCell />
          <TableCell colSpan={dimensions.length + 1} className="text-destructive text-xs whitespace-normal">{r.detail}</TableCell>
        </TableRow>
      )}
    </>
  )
}
