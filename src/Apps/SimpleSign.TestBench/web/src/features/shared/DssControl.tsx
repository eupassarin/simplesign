import { useState } from "react"
import { ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useT } from "@/i18n"
import { cn } from "@/lib/utils"
import { useWorkbench } from "../workbench/state"
import { Pill } from "./ui"

/**
 * Cross-validation with the EU DSS, for the whole app (signing and validating): on or off, where it
 * is, and whether it answers. It sits in the top bar next to the Sandbox, the other outside service.
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
      <PopoverContent align="end" className="w-96 space-y-3 text-sm">
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
          ? <Pill tone="success">{t("wb.dss.reachable", { ms: dssStatus.ms })}</Pill>
          : <p className="text-muted-foreground text-xs leading-relaxed break-words">{dssStatus.error}</p>)}
        <pre className="bg-muted overflow-x-auto rounded-md p-2 font-mono text-[11px]">docker compose -f tools/dss/docker-compose.yml up</pre>
      </PopoverContent>
    </Popover>
  )
}
