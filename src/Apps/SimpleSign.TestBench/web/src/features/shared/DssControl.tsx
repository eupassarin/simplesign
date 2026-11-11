import { useState } from "react"
import { ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useT } from "@/i18n"
import { cn } from "@/lib/utils"
import { DssWorkspace } from "../dss/DssWorkspace"
import { useWorkbench } from "../workbench/state"
import { Pill } from "./ui"

/**
 * Cross-validation with the EU DSS, for the whole app (signing and validating), on or off like the Sandbox. Off, the
 * button opens a popup to turn it on (the address, whether it answers, how to start it). On, it opens a drawer with
 * how the DSS server is set up and what that means for the verdicts it gives next to SimpleSign's.
 */
export function DssControl() {
  const { dss, dssStatus, saveDss, checkDss } = useWorkbench()
  const t = useT()
  const [url, setUrl] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const label = `DSS ${dss.enabled ? t("wb.dss.on") : t("wb.dss.offShort")}`
  const failing = dss.enabled && dssStatus !== null && !dssStatus.reachable
  const trigger = (
    <Button variant="ghost" size="sm" aria-label={label} onClick={dss.enabled ? () => setOpen(true) : undefined}
      className={cn("h-8", dss.enabled && "border-info/60 bg-info/10 border", failing && "border-destructive/60 bg-destructive/10")}>
      <ShieldCheck className={cn(failing && "text-destructive")} /><span className="max-xl:hidden">{label}</span>
    </Button>
  )
  const tooltip = <TooltipContent className="max-w-64">{failing ? t("wb.dss.setup.unreachable") : `${label} · ${t("wb.dss.about")}`}</TooltipContent>
  if (dss.enabled) {
    return (
      <Sheet open={open} onOpenChange={(next) => { setOpen(next); if (next) void checkDss() }}>
        <Tooltip><TooltipTrigger asChild>{trigger}</TooltipTrigger>{tooltip}</Tooltip>
        <SheetContent className="flex w-[min(96vw,1200px)] flex-col p-0 sm:max-w-none" onOpenAutoFocus={(e) => e.preventDefault()}>
          <SheetHeader className="sr-only"><SheetTitle>{t("wb.dss.setup.drawer")}</SheetTitle><SheetDescription>{t("wb.dss.about")}</SheetDescription></SheetHeader>
          <DssWorkspace onTurnOff={() => { setOpen(false); void saveDss({ ...dss, enabled: false }) }} />
        </SheetContent>
      </Sheet>
    )
  }
  return (
    <Popover onOpenChange={(next) => { if (next) { setUrl(null); void checkDss() } }}>
      <Tooltip><TooltipTrigger asChild><PopoverTrigger asChild>{trigger}</PopoverTrigger></TooltipTrigger>{tooltip}</Tooltip>
      <PopoverContent align="end" className="w-96 space-y-3 text-sm">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="font-medium">{t("wb.dss.title")}</p>
            <p className="text-muted-foreground text-xs leading-relaxed">{t("wb.dss.about")}</p>
          </div>
          {/* Turning it on keeps the address typed here and opens the drawer. */}
          <Switch checked={false} aria-label={t("wb.dss.title")}
            onCheckedChange={(on) => { if (on) { void saveDss({ enabled: true, url: url ?? dss.url }).then(() => setOpen(true)) } }} />
        </div>
        <div className="flex gap-2">
          <Input className="font-mono text-xs" value={url ?? dss.url} onChange={(e) => setUrl(e.target.value)} />
          <Button variant="outline" size="sm" className="h-9" onClick={() => saveDss({ ...dss, url: url ?? dss.url })}>{t("wb.dss.check")}</Button>
        </div>
        {dssStatus && (dssStatus.reachable
          ? <Pill tone="success">{t("wb.dss.reachable", { ms: dssStatus.ms })}</Pill>
          : <p className="text-muted-foreground text-xs leading-relaxed break-words">{dssStatus.error}</p>)}
        <pre className="bg-muted overflow-x-auto rounded-md p-2 font-mono text-[11px]">docker compose -f tools/dss/docker-compose.yml up -d</pre>
      </PopoverContent>
    </Popover>
  )
}
