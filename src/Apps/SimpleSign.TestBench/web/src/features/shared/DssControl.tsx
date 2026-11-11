import { useState, type ReactNode } from "react"
import { ChevronRight, ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useI18n, useT, type MessageKey } from "@/i18n"
import { cn } from "@/lib/utils"
import type { DssServerConfig } from "../workbench/schema"
import { useWorkbench } from "../workbench/state"
import { Pill } from "./ui"

/**
 * Cross-validation with the EU DSS, for the whole app (signing and validating): on or off, where it
 * is, whether it answers and, for the DSS of tools/dss, how it is set up (what it trusts, which lists
 * it loads). It sits in the top bar next to the Sandbox, the other outside service.
 */
export function DssControl() {
  const { dss, dssStatus, saveDss, checkDss } = useWorkbench()
  const t = useT()
  const [url, setUrl] = useState<string | null>(null)
  const label = `DSS ${dss.enabled ? t("wb.dss.on") : t("wb.dss.offShort")}`
  return (
    <Popover onOpenChange={(open) => { if (open) { setUrl(null); void checkDss() } }}>
      <Tooltip>
        <TooltipTrigger asChild>
          <PopoverTrigger asChild>
            <Button variant="ghost" size="sm" aria-label={label} className={cn("h-8", dss.enabled && "border-info/60 bg-info/10 border")}>
              <ShieldCheck /><span className="max-xl:hidden">{label}</span>
            </Button>
          </PopoverTrigger>
        </TooltipTrigger>
        <TooltipContent className="max-w-64">{label} · {t("wb.dss.about")}</TooltipContent>
      </Tooltip>
      <PopoverContent align="start" className="max-h-[80vh] w-[28rem] space-y-3 overflow-y-auto text-sm">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="font-medium">{t("wb.dss.title")}</p>
            <p className="text-muted-foreground text-xs leading-relaxed">{t("wb.dss.about")}</p>
          </div>
          <Switch checked={dss.enabled} onCheckedChange={(enabled) => saveDss({ ...dss, enabled })} aria-label={t("wb.dss.title")} />
        </div>
        <div className="flex gap-2">
          <Input className="font-mono text-xs" value={url ?? dss.url} onChange={(e) => setUrl(e.target.value)} />
          <Button variant="outline" size="sm" className="h-9" onClick={() => saveDss({ ...dss, url: url ?? dss.url })}>{t("wb.dss.check")}</Button>
        </div>
        {dssStatus && (dssStatus.reachable
          ? <>
              <Pill tone="success">{t("wb.dss.reachable", { ms: dssStatus.ms })}</Pill>
              {dssStatus.config ? <ServerSetup config={dssStatus.config} /> : (
                <div className="space-y-1.5 border-t pt-3">
                  <p className="font-medium">{t("wb.dss.setup.server")}</p>
                  <p className="text-muted-foreground text-xs leading-relaxed">{t("wb.dss.setup.serverUnknown")}</p>
                  <pre className="bg-muted overflow-x-auto rounded-md p-2 font-mono text-[11px]">docker compose -f tools/dss/docker-compose.yml up -d --build</pre>
                </div>
              )}
            </>
          : <>
              <p className="text-muted-foreground text-xs leading-relaxed break-words">{dssStatus.error}</p>
              <pre className="bg-muted overflow-x-auto rounded-md p-2 font-mono text-[11px]">docker compose -f tools/dss/docker-compose.yml up</pre>
            </>)}
      </PopoverContent>
    </Popover>
  )
}

const groupLabels: Record<string, string> = { "icp-brasil": "ICP-Brasil", govbr: "Gov.br", tsa: "TSA", peru: "Peru", sandbox: "Sandbox", mounted: "tools/dss/trust" }

/** What tools/dss/entrypoint.sh set up: one line per source of trust, then every trusted certificate, folded. */
function ServerSetup({ config }: { config: DssServerConfig }) {
  const { t, time } = useI18n()
  const sandbox = config.sandbox
  const trust = sandbox?.trust ?? "none"
  const sandboxKey: Record<string, MessageKey> = {
    list: "wb.dss.setup.sandboxList", anchor: "wb.dss.setup.sandboxAnchor", testbench: "wb.dss.setup.sandboxTestbench", none: "wb.dss.setup.sandboxNone",
  }
  const eu = config.euTrustedLists ?? "false"
  const trusted = config.trusted ?? []
  const groups = [...new Set(trusted.map((c) => c.group))]
  const onOff = (on: boolean, extra?: string) => <Pill tone={on ? "success" : "default"}>{on ? (extra ?? t("wb.dss.on")) : t("wb.dss.offShort")}</Pill>
  return (
    <div className="space-y-2 border-t pt-3">
      <div>
        <p className="font-medium">{t("wb.dss.setup.server")}</p>
        <p className="text-muted-foreground text-xs leading-relaxed">
          {t("wb.dss.setup.serverAbout")}
          {config.startedAt && <> {t("wb.dss.setup.version", { version: config.dssVersion || "?", time: time(config.startedAt) })}</>}
        </p>
      </div>
      <div className="divide-y rounded-md border text-xs">
        <Row label={t("wb.dss.setup.sandbox")}>
          <Pill tone={trust === "list" ? "success" : trust === "none" ? "danger" : "warning"}>{t(sandboxKey[trust] ?? sandboxKey.none)}</Pill>
          {sandbox?.tls && <span className="text-muted-foreground">{t("wb.dss.setup.sandboxTls")}</span>}
          {sandbox?.lotlUrl && <span className="text-muted-foreground w-full font-mono text-[11px] break-all">{sandbox.lotlUrl}</span>}
          {trust === "none" && (
            <span className="w-full space-y-1">
              <span className="text-muted-foreground block">{t("wb.dss.setup.sandboxNoneHint")}</span>
              <code className="bg-muted block rounded p-1.5 font-mono text-[11px]">curl http://127.0.0.1:5300/root.pem &gt; tools/dss/trust/sandbox-root.pem</code>
            </span>
          )}
        </Row>
        <Row label={t("wb.dss.setup.euLists")}>
          <Pill tone={eu === "false" ? "default" : "success"}>{t(`wb.dss.setup.euListsValues.${eu}` as MessageKey)}</Pill>
          {config.tlLoaderOnline && <span className="text-muted-foreground">{t("wb.dss.setup.tlRefresh", { s: config.tlRefreshSeconds })}</span>}
          {config.acceptInvalidTrustedLists && <span className="w-full"><Pill tone="warning">{t("wb.dss.setup.acceptInvalid")}</Pill></span>}
        </Row>
        <Row label={t("wb.dss.setup.icpBrasil")}>{onOff(config.icpBrasil)}</Row>
        <Row label={t("wb.dss.setup.govBr")}>{onOff(config.govBr)}</Row>
        <Row label={t("wb.dss.setup.tsaRoots")}>{onOff(config.tsaRoots)}</Row>
        <Row label={t("wb.dss.setup.peru")}>
          {onOff(!!config.peru?.enabled && config.peru.trusted > 0, config.peru ? t("wb.dss.setup.peruCount", { n: config.peru.trusted, origin: config.peru.origin || "?" }) : undefined)}
        </Row>
        <Row label={t("wb.dss.setup.revocationCache")}>
          <span className="text-muted-foreground">{config.revocationCache ? t("wb.dss.setup.revocationCacheOn") : t("wb.dss.setup.revocationCacheOff")}</span>
        </Row>
      </div>
      <Collapsible className="rounded-md border">
        <CollapsibleTrigger className="group hover:text-foreground flex w-full items-center gap-1.5 px-3 py-2 text-left text-xs font-medium">
          <ChevronRight className="text-muted-foreground size-3.5 transition-transform group-data-[state=open]:rotate-90" />
          {t("wb.dss.setup.trusted", { n: trusted.length })}
        </CollapsibleTrigger>
        <CollapsibleContent className="space-y-2 border-t px-3 py-2">
          {groups.map((g) => (
            <div key={g} className="space-y-0.5">
              <p className="text-muted-foreground text-[11px] font-medium uppercase">{groupLabels[g] ?? g}</p>
              <ul className="space-y-0.5">
                {trusted.filter((c) => c.group === g).map((c) => (
                  <li key={c.name} className="font-mono text-[11px] break-all" title={c.name}>{c.subject || c.name}</li>
                ))}
              </ul>
            </div>
          ))}
        </CollapsibleContent>
      </Collapsible>
      <p className="text-muted-foreground text-xs">{t("wb.dss.setup.policy")}</p>
    </div>
  )
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[9rem_1fr] items-start gap-2 px-3 py-1.5">
      <span className="text-muted-foreground pt-0.5">{label}</span>
      <span className="flex flex-wrap items-center gap-1.5">{children}</span>
    </div>
  )
}
