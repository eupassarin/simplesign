import { useCallback, useEffect, useMemo, useState } from "react"
import { toast } from "sonner"
import { ChevronDown, ChevronRight, CircleCheck, CircleDashed, Download, Play, RotateCcw, Search } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useT } from "@/i18n"
import { api } from "@/lib/api"
import type { PolicyKind, PolicyLevel, PolicyNodeView, PolicyView } from "@/lib/types"
import { cn } from "@/lib/utils"
import { Pill } from "../shared/ui"
import { UploadButton } from "../shared/UploadButton"
import { useWorkbench } from "../workbench/state"

const levels: PolicyLevel[] = ["FAIL", "WARN", "INFORM", "IGNORE"]

const levelStyle: Record<PolicyLevel, { on: string; dot: string }> = {
  FAIL: { on: "bg-destructive text-white", dot: "bg-destructive" },
  WARN: { on: "bg-warning text-black", dot: "bg-warning" },
  INFORM: { on: "bg-info text-white", dot: "bg-info" },
  IGNORE: { on: "bg-muted-foreground/70 text-white", dot: "bg-muted-foreground/50" },
}

const rootKey: Record<PolicyKind, string> = { signing: "SigningConstraints", validation: "ValidationConstraints" }
const fileName: Record<PolicyKind, string> = { signing: "signing-policy.json", validation: "validation-policy.json" }

/** Sets the Level of the element at a path of the policy file and returns the new text. */
function withLevel(json: string, kind: PolicyKind, path: string, level: PolicyLevel): string {
  const file = JSON.parse(json) as Record<string, unknown>
  let node = file[rootKey[kind]] as Record<string, unknown>
  for (const part of path.split("/").filter(Boolean)) node = node[part] as Record<string, unknown>
  node.Level = level
  return JSON.stringify(file, null, 2)
}

function matches(node: PolicyNodeView, query: string): boolean {
  const q = query.toLowerCase()
  return node.name.toLowerCase().includes(q) || node.explanation.toLowerCase().includes(q) || node.path.toLowerCase().includes(q)
}

/** Whether the node, or one of its descendants, passes the filters. */
/** Whether a node, or one of its descendants, is left out of what DSS receives. */
function hasNotSent(node: PolicyNodeView, notSent: ReadonlySet<string>): boolean {
  return notSent.has(node.name) || node.children.some((c) => hasNotSent(c, notSent))
}

function visible(node: PolicyNodeView, query: string, hideIgnored: boolean, onlyNotEvaluated: boolean): boolean {
  if (node.children.some((c) => visible(c, query, hideIgnored, onlyNotEvaluated))) return true
  if (node.kind === "section") return false
  if (hideIgnored && node.level === "IGNORE") return false
  if (onlyNotEvaluated && (node.evaluation === "evaluated" || node.evaluation === "none" || node.level === "IGNORE")) return false
  return query === "" || matches(node, query)
}

/** The policy a page opens with: the default of a kind, or an uploaded file. */
export interface PolicyRequest {
  kind: PolicyKind
  uploadId?: string | null
}

/**
 * What DSS receives (the DSS control): the constraints left out of its constraint.xml (DSS does not know them, so it
 * does not evaluate them), and that XML itself.
 */
export interface DssPolicy {
  notSent: string[]
  constraintXml: string
}

/**
 * The signing and validation policies, element by element: what each constraint checks, the clause
 * that defines it, its level (click to change) and whether SimpleSign evaluates it. The result can be
 * downloaded or used in the next runs.
 */
export function PoliciesPage({ initial, readOnly: readOnlyProp = false, dss }: { initial?: PolicyRequest | null; readOnly?: boolean; dss?: DssPolicy | null }) {
  const t = useT()
  // In the DSS control: the validation policy as DSS receives it, read-only, inside the drawer's own layout.
  const readOnly = readOnlyProp || !!dss
  const notSent = useMemo(() => new Set(dss?.notSent ?? []), [dss])
  const [onlyNotSent, setOnlyNotSent] = useState(false)
  const { set, setValidateOption } = useWorkbench()
  const [kind, setKind] = useState<PolicyKind>(dss ? "validation" : initial?.kind ?? "signing")
  const [view, setView] = useState<PolicyView | null>(null)
  const [modified, setModified] = useState(false)
  const [tab, setTab] = useState<"tree" | "json">("tree")
  const [text, setText] = useState("")
  const [query, setQuery] = useState("")
  const [hideIgnored, setHideIgnored] = useState(false)
  const [onlyNotEvaluated, setOnlyNotEvaluated] = useState(false)
  const [open, setOpen] = useState<Set<string>>(new Set(["", "SignatureConstraints", "SignatureConstraints/BasicSignatureConstraints", "SigningCertificate", "CACertificate", "Cryptographic"]))

  const load = useCallback(async (body: { kind: PolicyKind; json?: string | null; uploadId?: string | null }, changed: boolean) => {
    const result = await api.policies.view(body)
    if (result.error) {
      toast.error(result.error)
      if (!body.json) setView(result)
      return
    }
    setView(result)
    setKind(result.kind)
    setText(JSON.stringify(JSON.parse(result.json), null, 2))
    setModified(changed)
  }, [])

  useEffect(() => { void load({ kind, uploadId: initial?.uploadId ?? null }, false) }, [])

  const changeLevel = (path: string, level: PolicyLevel) => {
    if (!view) return
    void load({ kind: view.kind, json: withLevel(view.json, view.kind, path, level) }, true)
  }

  const download = () => {
    if (!view) return
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }))
    const a = document.createElement("a")
    a.href = url
    a.download = fileName[view.kind]
    a.click()
    URL.revokeObjectURL(url)
  }

  const use = async () => {
    if (!view) return
    const uploaded = await api.uploadFile(new File([text], fileName[view.kind], { type: "application/json" }))
    if (view.kind === "signing") {
      set("signingPolicyId", uploaded.id)
    } else {
      set("validation.policyId", uploaded.id)
      setValidateOption("validation.policyId", uploaded.id)
    }
    toast.success(t("policies.used"))
  }

  const toggle = (path: string) => setOpen((current) => {
    const next = new Set(current)
    if (next.has(path)) next.delete(path)
    else next.add(path)
    return next
  })
  const allSections = useMemo(() => {
    const paths: string[] = []
    const walk = (n: PolicyNodeView) => { if (n.children.length > 0) paths.push(n.path); n.children.forEach(walk) }
    if (view?.root) walk(view.root)
    return paths
  }, [view])
  const filtering = query !== "" || hideIgnored || onlyNotEvaluated || onlyNotSent
  const show = (n: PolicyNodeView) => visible(n, query, hideIgnored, onlyNotEvaluated) && (!onlyNotSent || hasNotSent(n, notSent))

  return (
    <div className={cn(!dss && "min-h-0 flex-1 overflow-y-auto")}>
      <div className={cn("space-y-5", !dss && "p-6 lg:p-8")}>
        {!dss && <header className="max-w-3xl space-y-1">
          <h2 className="text-2xl font-semibold tracking-tight">{t(readOnly ? (kind === "signing" ? "policies.signing" : "policies.validation") : "policies.title")}</h2>
          <p className="text-muted-foreground text-sm">{t(readOnly ? "policies.readOnlyIntro" : "policies.intro")}</p>
        </header>}

        {!readOnly && <div className="flex flex-wrap items-center gap-2">
          <div className="bg-muted flex rounded-lg p-0.5" role="radiogroup">
            {(["signing", "validation"] as const).map((k) => (
              <button key={k} role="radio" aria-checked={kind === k} onClick={() => { setKind(k); void load({ kind: k }, false) }}
                className={cn("rounded-md px-3 py-1.5 text-sm font-medium", kind === k ? "bg-background shadow-sm" : "text-muted-foreground")}>
                {t(k === "signing" ? "policies.signing" : "policies.validation")}
              </button>
            ))}
          </div>
          <Button variant="outline" size="sm" onClick={() => void load({ kind }, false)}><RotateCcw /> {t("policies.loadDefault")}</Button>
          <UploadButton label={t("policies.loadFile")} accept=".json,application/json" onUploaded={(f) => void load({ kind, uploadId: f.id }, false)} />
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <Button variant="outline" size="sm" onClick={download} disabled={!view?.root}><Download /> {t("policies.download")}</Button>
            <Button size="sm" onClick={() => void use()} disabled={!view?.root}><Play /> {t(kind === "signing" ? "policies.useSigning" : "policies.useValidation")}</Button>
          </div>
        </div>}

        {view?.root && (
          <section className="bg-card space-y-3 rounded-lg border p-4">
            <div className="flex flex-wrap items-baseline gap-2">
              <h3 className="text-lg font-semibold">{view.name ?? "—"}</h3>
              {modified && <Pill tone="warning">{t("policies.modified")}</Pill>}
            </div>
            {view.description && <p className="text-muted-foreground text-sm">{view.description}</p>}
            {view.counts && (
              <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs">
                <span>{t("policies.counts", { fail: view.counts.fail, warn: view.counts.warn, inform: view.counts.inform, ignore: view.counts.ignore })}</span>
                {view.kind === "validation" && <span className="text-muted-foreground">{t("policies.coverage", { evaluated: view.counts.evaluated, toConnect: view.counts.toConnect, toImplement: view.counts.toImplement })}</span>}
                <span className="text-muted-foreground font-mono">{t("policies.digest")} {view.digest?.slice(0, 16)}…</span>
                {dss && <span className="text-warning">{t("policies.notSentCount", { n: dss.notSent.length })}</span>}
              </div>
            )}
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              {levels.map((l) => (
                <div key={l} className="flex gap-2 text-xs">
                  <span className={cn("mt-0.5 h-4 shrink-0 rounded px-1.5 text-[10px] font-semibold leading-4", levelStyle[l].on)}>{l}</span>
                  <span className="text-muted-foreground">{view.levels[l]}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <div className="bg-muted flex rounded-lg p-0.5 text-xs">
            {(["tree", "json"] as const).map((v) => (
              <button key={v} onClick={() => setTab(v)} className={cn("rounded-md px-3 py-1.5 font-medium", tab === v ? "bg-background shadow-sm" : "text-muted-foreground")}>
                {v === "tree" ? t("policies.tree") : dss ? "constraint.xml" : t("policies.json")}
              </button>
            ))}
          </div>
          {tab === "tree" && (
            <>
              <div className="relative w-64">
                <Search className="text-muted-foreground absolute left-2 top-2 size-4" />
                <Input className="h-8 pl-8" value={query} placeholder={t("policies.search")} onChange={(e) => setQuery(e.target.value)} />
              </div>
              <label className="flex items-center gap-2 text-xs"><Switch checked={hideIgnored} onCheckedChange={setHideIgnored} /> {t("policies.hideIgnored")}</label>
              {kind === "validation" && <label className="flex items-center gap-2 text-xs"><Switch checked={onlyNotEvaluated} onCheckedChange={setOnlyNotEvaluated} /> {t("policies.onlyNotEvaluated")}</label>}
              {dss && <label className="flex items-center gap-2 text-xs"><Switch checked={onlyNotSent} onCheckedChange={setOnlyNotSent} /> {t("policies.onlyNotSent")}</label>}
              <div className="ml-auto flex gap-1">
                <Button variant="ghost" size="sm" onClick={() => setOpen(new Set(allSections))}>{t("policies.expandAll")}</Button>
                <Button variant="ghost" size="sm" onClick={() => setOpen(new Set([""]))}>{t("policies.collapseAll")}</Button>
              </div>
            </>
          )}
        </div>

        {view?.error && <p className="text-destructive text-sm">{view.error}</p>}

        {tab === "json" ? (
          <div className="space-y-2">
            <Textarea className="min-h-[60vh] font-mono text-xs" value={dss ? dss.constraintXml : text} readOnly={readOnly} onChange={(e) => setText(e.target.value)} spellCheck={false} />
            {!readOnly && <Button size="sm" onClick={() => void load({ kind, json: text }, true)}>{t("policies.apply")}</Button>}
          </div>
        ) : view?.root && (
          <div className="rounded-lg border">
            {view.root.children.filter(show).map((c) => (
              <Node key={c.path} node={c} depth={0} open={open} filtering={filtering} toggle={toggle} onLevel={readOnly ? undefined : changeLevel}
                show={show} notSent={notSent} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function Node({ node, depth, open, filtering, toggle, onLevel, show, notSent }: {
  node: PolicyNodeView
  depth: number
  open: Set<string>
  filtering: boolean
  toggle: (path: string) => void
  onLevel?: (path: string, level: PolicyLevel) => void
  show: (node: PolicyNodeView) => boolean
  notSent: ReadonlySet<string>
}) {
  const t = useT()
  const hasChildren = node.children.length > 0
  const leftOut = notSent.has(node.name)
  const expanded = filtering || open.has(node.path)
  const dimmed = node.level === "IGNORE"
  return (
    <div className={cn(depth === 0 && "border-b last:border-b-0")}>
      <div className={cn("flex gap-3 px-3 py-2 hover:bg-accent/30", dimmed && "opacity-60")} style={{ paddingLeft: 12 + depth * 20 }}>
        <button className={cn("mt-0.5 size-4 shrink-0 text-muted-foreground", !hasChildren && "invisible")} onClick={() => toggle(node.path)} aria-label={node.name}>
          {expanded ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
        </button>
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn("font-mono text-sm", node.kind === "section" && "font-semibold")}>{node.name}</span>
            {node.evaluation !== "none" && <Evaluation node={node} />}
            {node.standard && <span className="text-muted-foreground rounded border px-1.5 text-[10px]">{node.standard}</span>}
            {leftOut && (
              <Tooltip>
                <TooltipTrigger asChild><span><Pill tone="warning">{t("policies.notSent")}</Pill></span></TooltipTrigger>
                <TooltipContent className="max-w-64">{t("policies.notSentHint")}</TooltipContent>
              </Tooltip>
            )}
            {node.level && (onLevel
              ? <LevelPicker level={node.level} onChange={(l) => onLevel(node.path, l)} />
              : <span className={cn("ml-auto rounded px-1.5 py-0.5 text-[10px] font-semibold", levelStyle[node.level].on)}>{node.level}</span>)}
          </div>
          <p className="text-muted-foreground text-xs">{node.explanation}</p>
          {Object.keys(node.attributes).length > 0 && (
            <div className="flex flex-wrap gap-1">
              {Object.entries(node.attributes).map(([k, v]) => <span key={k} className="bg-muted rounded px-1.5 py-0.5 font-mono text-[11px]">{k} = {v}</span>)}
            </div>
          )}
          {node.ids.length > 0 && (
            <div className="flex flex-wrap items-center gap-1">
              <span className="text-muted-foreground text-[11px]">{t("policies.values")}:</span>
              {node.ids.map((id) => <span key={id} className="bg-muted rounded px-1.5 py-0.5 font-mono text-[11px]">{id}</span>)}
            </div>
          )}
          {node.algorithms.length > 0 && <Algorithms node={node} />}
          {node.kind === "crypto" && !hasChildren && <p className="text-muted-foreground text-[11px] italic">{t("policies.empty")}</p>}
        </div>
      </div>
      {hasChildren && expanded && node.children.filter(show).map((c) => (
        <Node key={c.path} node={c} depth={depth + 1} open={open} filtering={filtering} toggle={toggle} onLevel={onLevel} show={show} notSent={notSent} />
      ))}
    </div>
  )
}

function Evaluation({ node }: { node: PolicyNodeView }) {
  const t = useT()
  if (node.evaluation === "evaluated") {
    return <span className="text-success flex items-center gap-1 text-[11px]"><CircleCheck className="size-3" />{t("policies.evaluated")}</span>
  }
  const pending = node.evaluation === "toImplement"
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={cn("flex items-center gap-1 text-[11px]", pending ? "text-warning" : "text-muted-foreground")}>
          <CircleDashed className="size-3" />{t(pending ? "policies.toImplement" : "policies.toConnect")}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-64">{t(pending ? "policies.toImplementHint" : "policies.toConnectHint")}</TooltipContent>
    </Tooltip>
  )
}

function LevelPicker({ level, onChange }: { level: PolicyLevel; onChange: (level: PolicyLevel) => void }) {
  return (
    <div className="bg-muted ml-auto flex rounded-md p-0.5" role="radiogroup">
      {levels.map((l) => (
        <button key={l} role="radio" aria-checked={l === level} onClick={() => l !== level && onChange(l)}
          className={cn("rounded px-1.5 py-0.5 text-[10px] font-semibold", l === level ? levelStyle[l].on : "text-muted-foreground hover:text-foreground")}>
          {l}
        </button>
      ))}
    </div>
  )
}

function Algorithms({ node }: { node: PolicyNodeView }) {
  const t = useT()
  const sized = node.algorithms.some((a) => a.size != null)
  const dated = node.algorithms.some((a) => a.date != null)
  if (!sized && !dated) {
    return <div className="flex flex-wrap gap-1">{node.algorithms.map((a) => <span key={a.name} className="bg-muted rounded px-1.5 py-0.5 font-mono text-[11px]">{a.name}</span>)}</div>
  }
  const today = new Date().toISOString().slice(0, 10)
  return (
    <table className="text-[11px]">
      <thead className="text-muted-foreground">
        <tr><th className="pr-4 text-left font-normal">{t("policies.algorithm")}</th>{sized && <th className="pr-4 text-left font-normal">{t("policies.size")}</th>}{dated && <th className="text-left font-normal">{t("policies.until")}</th>}</tr>
      </thead>
      <tbody className="font-mono">
        {node.algorithms.map((a, i) => (
          <tr key={`${a.name}-${a.size ?? ""}-${i}`}>
            <td className="pr-4">{a.name}</td>
            {sized && <td className="pr-4">{a.size ?? "—"}</td>}
            {dated && <td className={cn(a.date && a.date < today && "text-destructive")}>{a.date ?? "—"}</td>}
          </tr>
        ))}
      </tbody>
    </table>
  )
}
