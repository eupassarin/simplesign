import { useEffect, useMemo, useState, type ReactNode } from "react"
import { ChevronRight, Download, ExternalLink, Landmark, ListChecks, Loader2, RefreshCw, Search, ShieldCheck, Wrench } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import { cn } from "@/lib/utils"
import { PoliciesPage } from "../policies/PoliciesPage"
import { Pill } from "../shared/ui"
import type { DssPolicyView, DssServerConfig } from "../workbench/schema"
import { useWorkbench } from "../workbench/state"

const tabs = ["overview", "trust", "policy"] as const
type Tab = (typeof tabs)[number]

function savedTab(): Tab {
  try {
    return tabs.find((x) => x === localStorage.getItem("dss.tab")) ?? "overview"
  } catch {
    return "overview"
  }
}

/**
 * DSS turned on. Above the tabs: whether it answers, its address and the switch. Three tabs on what the server of
 * tools/dss set up (its /simplesign/config.json): the overview (every setting, what it means and the variable that
 * changes it), trust (how it trusts the Sandbox and the lists, then every certificate it trusts) and the policy it is given.
 */
export function DssWorkspace({ onTurnOff }: { onTurnOff: () => void }) {
  const { dss, dssStatus, saveDss, checkDss } = useWorkbench()
  const { t, time } = useI18n()
  const [url, setUrl] = useState<string | null>(null)
  const [policy, setPolicy] = useState<DssPolicyView | null>(null)
  const [tab, setTabState] = useState<Tab>(savedTab)
  const setTab = (next: string) => {
    const known = tabs.find((x) => x === next)
    if (!known) return
    setTabState(known)
    try {
      localStorage.setItem("dss.tab", known)
    } catch {
      // Not kept: the tab lasts until the page is reloaded.
    }
  }
  // Fresh on every opening: the server may have been restarted with another setup.
  const [checked, setChecked] = useState(false)
  useEffect(() => {
    api.dss.policy().then(setPolicy).catch(() => setPolicy(null))
    void checkDss().finally(() => setChecked(true))
  }, [checkDss])
  const config = dssStatus?.reachable ? dssStatus.config ?? null : null
  const base = dss.url.replace(/\/+$/, "")
  const needsConfig = (content: ReactNode) => !checked ? <Loading /> : config ? content : <Unknown />
  return (
    <div className="min-h-0 min-w-0 flex-1 overflow-y-auto">
      <div className="space-y-5 p-6 lg:p-8">
        <header className="flex flex-wrap items-start justify-between gap-3">
          <div className="max-w-3xl space-y-1">
            <h2 className="flex flex-wrap items-center gap-2 text-2xl font-semibold tracking-tight">
              <ShieldCheck className="size-6" /> {t("wb.dss.setup.drawer")}
              {dssStatus && (dssStatus.reachable
                ? <Pill tone="success">{t("wb.dss.reachable", { ms: dssStatus.ms })}</Pill>
                : <Pill tone="danger">{t("wb.dss.setup.unreachable")}</Pill>)}
              {config?.dssVersion && <Pill>DSS {config.dssVersion}</Pill>}
            </h2>
            {config?.startedAt && <p className="text-muted-foreground text-xs">{t("wb.dss.setup.version", { version: config.dssVersion || "?", time: time(config.startedAt) })}</p>}
          </div>
          <Switch checked onCheckedChange={(on) => { if (!on) onTurnOff() }} aria-label={t("wb.dss.setup.turnOff")} className="mt-2" />
        </header>

        <div className="flex max-w-3xl flex-wrap items-center gap-2">
          <Input className="min-w-64 flex-1 font-mono text-xs" value={url ?? dss.url} onChange={(e) => setUrl(e.target.value)} />
          <Button variant="outline" size="sm" className="h-9" onClick={() => void saveDss({ ...dss, url: url ?? dss.url })}>{t("wb.dss.check")}</Button>
          <Button variant="ghost" size="sm" className="h-9" onClick={() => void checkDss()} aria-label={t("common.refresh")}><RefreshCw /></Button>
          <Button variant="ghost" size="sm" className="h-9" asChild><a href={base + "/"} target="_blank" rel="noreferrer"><ExternalLink /> {t("wb.dss.setup.openDemo")}</a></Button>
        </div>
        {dssStatus && !dssStatus.reachable && (
          <div className="space-y-2">
            <p className="text-destructive text-sm break-words">{dssStatus.error}</p>
            <pre className="bg-muted w-fit rounded-md p-2 font-mono text-[11px]">docker compose -f tools/dss/docker-compose.yml up -d</pre>
          </div>
        )}

        <Tabs value={tab} onValueChange={setTab}>
          <TabsList className="flex-wrap">
            {tabs.map((id) => <TabsTrigger key={id} value={id}>{t(`wb.dss.setup.tabs.${id}` as MessageKey)}</TabsTrigger>)}
          </TabsList>
          <div className="pt-4">
            <TabsContent value="overview"><Overview config={config} checked={checked} policy={policy} onOpen={setTab} /></TabsContent>
            <TabsContent value="trust">{needsConfig(config && <TrustTab config={config} />)}</TabsContent>
            <TabsContent value="policy"><PolicyTab policy={policy} /></TabsContent>
          </div>
        </Tabs>
      </div>
    </div>
  )
}

function Loading() {
  return <Loader2 className="text-muted-foreground size-5 animate-spin" />
}

/** A DSS not started by tools/dss (or by an older image) says nothing about its setup. */
function Unknown() {
  const { t } = useI18n()
  return (
    <div className="bg-muted/40 max-w-3xl space-y-2 rounded-lg border p-4 text-sm">
      <p>{t("wb.dss.setup.serverUnknown")}</p>
      <pre className="bg-muted w-fit rounded-md p-2 font-mono text-[11px]">docker compose -f tools/dss/docker-compose.yml up -d --build</pre>
    </div>
  )
}

function Card({ icon, title, aside, children, className }: { icon: ReactNode; title: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn("space-y-3 rounded-lg border p-4", className)}>
      <div className="flex items-center gap-2">
        <span className="text-muted-foreground [&_svg]:size-4">{icon}</span>
        <h3 className="flex-1 text-sm font-semibold">{title}</h3>
        {aside}
      </div>
      {children}
    </section>
  )
}

function Line({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[10rem_1fr] items-start gap-2 text-xs">
      <span className="text-muted-foreground pt-0.5">{label}</span>
      <span className="flex min-w-0 flex-wrap items-center gap-1.5">{children}</span>
    </div>
  )
}

const trustLabels: Record<string, MessageKey> = {
  list: "wb.dss.setup.sandboxList", anchor: "wb.dss.setup.sandboxAnchor", testbench: "wb.dss.setup.sandboxTestbench", none: "wb.dss.setup.sandboxNone",
}
const trustTone = (trust: string) => trust === "list" ? "success" : trust === "none" ? "danger" : "warning"

/** One row of the settings: what it is, its value, what it means for the verdicts, the variable that changes it. */
interface Setting {
  name: string
  value: ReactNode
  meaning?: ReactNode
  variable?: string
  open?: Tab
}

/**
 * Every setting of the DSS server on one table: the value, what it means next to SimpleSign's verdicts, and the
 * variable of tools/dss/docker-compose.yml that changes it (then a rebuild). Rows with more open their tab.
 */
function Overview({ config, checked, policy, onOpen }: { config: DssServerConfig | null; checked: boolean; policy: DssPolicyView | null; onOpen: (tab: Tab) => void }) {
  const { t } = useI18n()
  const unknown = <span className="text-muted-foreground">{checked ? t("wb.dss.setup.unknownValue") : "…"}</span>
  const trust = config?.sandbox?.trust ?? "none"
  const eu = config?.euTrustedLists ?? "false"
  const trusted = config?.trusted ?? []
  const counts = groupOrder.map((g) => [g, trusted.filter((c) => c.group === g).length] as const).filter(([, n]) => n > 0)
  const forwarding = config?.forwarding
  const rows: Setting[] = [
    {
      name: t("wb.dss.setup.sandboxTrust"), open: "trust", variable: "DSS_SANDBOX_TRUST · SANDBOX_URL",
      value: config ? <Pill tone={trustTone(trust)}>{t(trustLabels[trust] ?? trustLabels.none)}</Pill> : unknown,
      meaning: config && t(`wb.dss.setup.sandboxExplain.${trust in trustLabels ? trust : "none"}` as MessageKey),
    },
    {
      name: t("wb.dss.setup.euLists"), open: "trust", variable: "DSS_LOAD_EU_TRUSTED_LISTS",
      value: config ? <Pill tone={eu === "false" ? "default" : "success"}>{t(`wb.dss.setup.euListsValues.${eu}` as MessageKey)}</Pill> : unknown,
      meaning: t("wb.dss.setup.euMeaning"),
    },
    {
      name: t("wb.dss.setup.refresh"), variable: "DSS_TL_REFRESH_SECONDS",
      value: config ? (config.tlLoaderOnline ? t("wb.dss.setup.tlRefresh", { s: config.tlRefreshSeconds }) : <span className="text-muted-foreground">{t("wb.dss.setup.loaderOffline")}</span>) : unknown,
    },
    {
      name: t("wb.dss.setup.badSignature"), variable: "DSS_ACCEPT_INVALID_TRUSTED_LISTS",
      value: config ? (config.acceptInvalidTrustedLists ? <Pill tone="warning">{t("wb.dss.setup.kept")}</Pill> : <Pill tone="success">{t("wb.dss.setup.refused")}</Pill>) : unknown,
      meaning: config && (config.acceptInvalidTrustedLists ? t("wb.dss.setup.acceptInvalid") : t("wb.dss.setup.refuseInvalid")),
    },
    {
      name: t("wb.dss.setup.anchorsRow"), open: "trust", variable: "DSS_TRUST_ICP_BRASIL · _GOVBR · _PERU · _TSA_ROOTS",
      value: config ? <Pill>{t("wb.dss.setup.trusted", { n: trusted.length })}</Pill> : unknown,
      meaning: config && counts.map(([g, n]) => `${groupName(g, t)} ${n}`).join(" · "),
    },
    {
      name: t("wb.dss.setup.revocation"), variable: "DSS_REVOCATION_CACHE · SANDBOX_FORWARD_PORTS",
      value: config ? <Pill tone={config.revocationCache ? "warning" : "success"}>{config.revocationCache ? t("wb.dss.setup.revocationCacheOn") : t("wb.dss.setup.revocationCacheOff")}</Pill> : unknown,
      meaning: config && <>{t(config.revocationCache ? "wb.dss.setup.cacheOnExplain" : "wb.dss.setup.cacheOffExplain")}
        {forwarding?.ports && <span className="mt-1 block">{t("wb.dss.setup.forwarding", { host: forwarding.host || "?", ports: forwarding.ports })}</span>}</>,
    },
    {
      name: t("wb.dss.setup.policyTitle"), open: "policy",
      value: policy ? <span className="flex flex-wrap gap-1"><Pill>{policy.name}</Pill>{policy.notInDss.length > 0 && <Pill tone="warning">{t("policies.notSentCount", { n: policy.notInDss.length })}</Pill>}</span> : "…",
      meaning: t("wb.dss.setup.policyMeaning"),
    },
  ]
  return (
    <div className="space-y-4">
      <p className="text-muted-foreground max-w-3xl text-sm">{t("wb.dss.setup.drawerAbout")}</p>
      {checked && !config && <Unknown />}
      <div className="divide-y rounded-lg border">
        <div className="text-muted-foreground hidden grid-cols-[13rem_12rem_1fr_17rem_1.5rem] gap-4 px-4 py-2 text-xs font-medium xl:grid">
          <span>{t("wb.dss.setup.colSetting")}</span><span>{t("wb.dss.setup.colValue")}</span><span>{t("wb.dss.setup.colMeaning")}</span><span>{t("wb.dss.setup.colVariable")}</span><span />
        </div>
        {rows.map((row) => {
          const content = (
            <>
              <span className="text-sm font-medium">{row.name}</span>
              <span className="flex flex-wrap items-center gap-1 text-xs">{row.value}</span>
              <span className="text-muted-foreground text-xs leading-relaxed sm:col-span-2 xl:col-span-1">{row.meaning}</span>
              <span className="font-mono text-[11px] break-all sm:col-span-2 xl:col-span-1">{row.variable ?? <span className="text-muted-foreground font-sans">{t("wb.dss.setup.fromTestBench")}</span>}</span>
              <span className="text-muted-foreground hidden xl:block">{row.open && <ChevronRight className="size-4" />}</span>
            </>
          )
          // Five columns on wide screens; narrower, the name and value on one line, the meaning and the variable below.
          const layout = "grid gap-1.5 px-4 py-3 text-left sm:grid-cols-[13rem_1fr] sm:gap-x-4 xl:grid-cols-[13rem_12rem_1fr_17rem_1.5rem] xl:items-start xl:gap-4"
          return row.open
            ? <button key={row.name} type="button" onClick={() => onOpen(row.open!)} className={cn(layout, "hover:bg-muted/40 w-full transition-colors")}>{content}</button>
            : <div key={row.name} className={layout}>{content}</div>
        })}
      </div>
      <div className="space-y-1.5">
        <p className="text-muted-foreground flex items-center gap-1.5 text-xs"><Wrench className="size-3.5" /> {t("wb.dss.setup.changeFooter")}</p>
        <pre className="bg-muted w-fit rounded-md p-2 font-mono text-[11px]">docker compose -f tools/dss/docker-compose.yml up -d --build</pre>
      </div>
    </div>
  )
}

/** How DSS trusts (the Sandbox and the trusted lists), then every certificate it trusts. */
function TrustTab({ config }: { config: DssServerConfig }) {
  const { t } = useI18n()
  return (
    <div className="space-y-6">
      <div className="grid gap-4 lg:grid-cols-2">
        <SandboxTrustCard config={config} />
        <ListsCard config={config} />
      </div>
      <section className="space-y-3">
        <h3 className="flex items-center gap-2 text-sm font-semibold"><Landmark className="text-muted-foreground size-4" /> {t("wb.dss.setup.certificatesTitle")}</h3>
        <Certificates config={config} />
      </section>
    </div>
  )
}

function SandboxTrustCard({ config }: { config: DssServerConfig }) {
  const { t } = useI18n()
  const sandbox = config.sandbox
  const trust = sandbox?.trust ?? "none"
  return (
    <Card icon={<ShieldCheck />} title={t("wb.dss.setup.sandboxTrust")}
      aside={<Pill tone={trustTone(trust)}>{t(trustLabels[trust] ?? trustLabels.none)}</Pill>}>
      <p className="text-muted-foreground text-xs leading-relaxed">{t(`wb.dss.setup.sandboxExplain.${trust in trustLabels ? trust : "none"}` as MessageKey)}</p>
      {sandbox?.url && <Line label="SANDBOX_URL"><span className="font-mono break-all">{sandbox.url}</span></Line>}
      {sandbox?.lotlUrl && <Line label="LOTL"><span className="font-mono break-all">{sandbox.lotlUrl}</span></Line>}
      {sandbox?.tls && <Line label="TLS">{t("wb.dss.setup.sandboxTls")}</Line>}
      {trust === "none" && (
        <div className="space-y-1">
          <p className="text-muted-foreground text-xs">{t("wb.dss.setup.sandboxNoneHint")}</p>
          <code className="bg-muted block rounded p-1.5 font-mono text-[11px]">curl http://127.0.0.1:5300/root.pem &gt; tools/dss/trust/sandbox-root.pem</code>
        </div>
      )}
    </Card>
  )
}

function ListsCard({ config }: { config: DssServerConfig }) {
  const { t } = useI18n()
  const eu = config.euTrustedLists ?? "false"
  return (
    <Card icon={<ListChecks />} title={t("wb.dss.setup.lists")}>
      <Line label={t("wb.dss.setup.euLists")}><Pill tone={eu === "false" ? "default" : "success"}>{t(`wb.dss.setup.euListsValues.${eu}` as MessageKey)}</Pill></Line>
      <Line label="Sandbox">{config.sandbox?.lotlUrl ? <Pill tone="success">{t("wb.dss.setup.sandboxList")}</Pill> : <Pill>{t("wb.dss.offShort")}</Pill>}</Line>
      {config.peru?.enabled && (
        <Line label="Peru (INDECOPI)">
          <span>{config.peru.sequence ? t("wb.dss.setup.peruDetail", { seq: config.peru.sequence, next: config.peru.nextUpdate || "?" }) : config.peru.origin}</span>
          {config.peru.url && <span className="text-muted-foreground w-full font-mono break-all">{config.peru.url}</span>}
        </Line>
      )}
      <Line label={t("wb.dss.setup.loaderOnline")}>
        {config.tlLoaderOnline ? <span>{t("wb.dss.setup.tlRefresh", { s: config.tlRefreshSeconds })}</span> : <span className="text-muted-foreground">{t("wb.dss.setup.loaderOffline")}</span>}
      </Line>
      <Line label="TS 119 615">
        {config.acceptInvalidTrustedLists ? <Pill tone="warning">{t("wb.dss.setup.acceptInvalid")}</Pill> : <span>{t("wb.dss.setup.refuseInvalid")}</span>}
      </Line>
    </Card>
  )
}

const groupOrder = ["icp-brasil", "govbr", "peru", "tsa", "sandbox", "mounted"]

function groupName(id: string, t: (key: MessageKey) => string): string {
  const names: Record<string, string> = { "icp-brasil": "ICP-Brasil", govbr: "Gov.br", tsa: t("wb.dss.setup.groupTsa"), peru: "Peru (INDECOPI)", sandbox: "Sandbox", mounted: t("wb.dss.setup.mounted") }
  return names[id] ?? id
}

/** Splits an RFC 2253 name (CN=a\,b,O=c,C=BR) into its attributes; the first of each kind wins. */
function parseName(subject: string): Record<string, string> {
  const parts: Record<string, string> = {}
  for (const piece of subject.split(/(?<!\\),/)) {
    const at = piece.indexOf("=")
    if (at <= 0) continue
    const key = piece.slice(0, at).trim().toUpperCase()
    if (!(key in parts)) parts[key] = unescape(piece.slice(at + 1).trim())
  }
  return parts
}

/** An RFC 2253 value: UTF-8 written as hex escapes (Certic\C3\A1mara) back to text, then \, \+ and the like. */
function unescape(value: string): string {
  return value
    .replace(/(?:\\[0-9A-Fa-f]{2})+/g, (run) => {
      const bytes = new Uint8Array(run.split("\\").filter(Boolean).map((h) => parseInt(h, 16)))
      return new TextDecoder().decode(bytes)
    })
    .replace(/\\(.)/g, "$1")
}

/**
 * Every certificate DSS trusts, by group on the left (with how many each has, and those switched off), as a table on
 * the right: the name, the organization and the country read from the subject, and the alias it has in the store.
 */
function Certificates({ config }: { config: DssServerConfig }) {
  const { t } = useI18n()
  const trusted = useMemo(() => config.trusted ?? [], [config])
  const enabled: Record<string, boolean> = { "icp-brasil": config.icpBrasil, govbr: config.govBr, tsa: config.tsaRoots, peru: !!config.peru?.enabled }
  const groups = [...new Set([...groupOrder, ...trusted.map((c) => c.group)])]
  const [group, setGroup] = useState<string>("")
  const [query, setQuery] = useState("")
  const rows = useMemo(() => trusted
    .filter((c) => !group || c.group === group)
    .map((c) => ({ ...c, text: unescape(c.subject), parts: parseName(c.subject) }))
    .filter((c) => !query || `${c.text} ${c.name}`.toLowerCase().includes(query.toLowerCase()))
    .sort((a, b) => (a.parts.CN ?? a.name).localeCompare(b.parts.CN ?? b.name)), [trusted, group, query])
  const sandboxByList = config.sandbox?.trust === "list"
  const item = (id: string, label: string, count: number, off?: boolean, note?: string) => (
    <button key={id} type="button" onClick={() => setGroup(id)}
      className={cn("flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-left text-sm", group === id ? "bg-accent font-medium" : "hover:bg-muted/50 text-muted-foreground")}>
      <span className="flex-1 truncate">{label}</span>
      {note ? <span className="text-success text-[11px]">{note}</span> : off ? <span className="text-[11px]">{t("wb.dss.offShort")}</span> : <span className="text-xs tabular-nums">{count}</span>}
    </button>
  )
  const detail = group === "peru" && config.peru?.sequence
    ? t("wb.dss.setup.peruDetail", { seq: config.peru.sequence, next: config.peru.nextUpdate || "?" })
    : group === "sandbox" && sandboxByList ? t("wb.dss.setup.sandboxByList") : null
  return (
    <div className="grid gap-4 md:grid-cols-[14rem_1fr]">
      <nav className="space-y-0.5">
        {item("", t("wb.dss.setup.allGroups"), trusted.length)}
        {groups.map((id) => {
          const count = trusted.filter((c) => c.group === id).length
          return item(id, groupName(id, t), count, count === 0 && enabled[id] === false, id === "sandbox" && count === 0 && sandboxByList ? "LOTL" : undefined)
        })}
      </nav>
      <div className="min-w-0 space-y-3">
        <p className="text-muted-foreground text-xs leading-relaxed">{t("wb.dss.setup.anchorsHint")}</p>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-72">
            <Search className="text-muted-foreground absolute left-2 top-2 size-4" />
            <Input className="h-8 pl-8" value={query} placeholder={t("wb.dss.setup.searchCertificates")} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <span className="text-muted-foreground text-xs">{t("wb.dss.setup.trusted", { n: rows.length })}</span>
          {detail && <Pill>{detail}</Pill>}
        </div>
        {rows.length === 0 ? <p className="text-muted-foreground text-sm">{group === "sandbox" && sandboxByList ? t("wb.dss.setup.sandboxByList") : t("wb.dss.setup.noCertificates")}</p> : (
          <div className="max-h-[60vh] overflow-auto rounded-lg border">
            <Table>
              <TableHeader className="bg-background sticky top-0 z-10">
                <TableRow>
                  <TableHead>{t("wb.dss.setup.columnName")}</TableHead>
                  <TableHead>{t("wb.dss.setup.columnOrganization")}</TableHead>
                  <TableHead className="w-12">{t("wb.dss.setup.columnCountry")}</TableHead>
                  {!group && <TableHead>{t("wb.dss.setup.columnGroup")}</TableHead>}
                  <TableHead>{t("wb.dss.setup.columnAlias")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((c) => (
                  <TableRow key={`${c.group}/${c.name}`} title={c.text}>
                    <TableCell className="text-sm font-medium whitespace-normal">{c.parts.CN ?? c.text}</TableCell>
                    <TableCell className="text-muted-foreground text-xs whitespace-normal">{[c.parts.O, c.parts.OU].filter(Boolean).join(" · ")}</TableCell>
                    <TableCell className="text-xs">{c.parts.C}</TableCell>
                    {!group && <TableCell><Pill>{groupName(c.group, t)}</Pill></TableCell>}
                    <TableCell className="text-muted-foreground font-mono text-[11px]">{c.name}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </div>
  )
}

/** The policy DSS receives, in the same explained tree as the Policies panel, with what it does not get marked. */
function PolicyTab({ policy }: { policy: DssPolicyView | null }) {
  const { t } = useI18n()
  const dssPolicy = useMemo(() => policy ? { notSent: policy.notInDss, constraintXml: policy.constraintXml } : null, [policy])
  if (!policy || !dssPolicy) return <p className="text-muted-foreground text-sm">…</p>
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="text-muted-foreground max-w-3xl text-sm">{t("wb.dss.setup.policyExplain", { name: policy.name })}</p>
        <Button variant="outline" size="sm" asChild><a href={api.dss.constraintXmlUrl} download><Download /> {t("wb.dss.setup.downloadXml")}</a></Button>
      </div>
      <PoliciesPage dss={dssPolicy} />
    </div>
  )
}

