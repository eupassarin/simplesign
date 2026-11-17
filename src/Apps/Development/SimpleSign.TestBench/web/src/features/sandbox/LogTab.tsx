import { useEffect, useRef, useState } from "react"
import { Pause, Play, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Pill } from "./parts"
import { useI18n } from "./i18n"
import { api } from "./api"
import type { SandboxRequest } from "./types"
import { cn } from "@/lib/utils"

const services = ["", "AIA", "CRL", "CRL (LDAP)", "OCSP", "TSA", "CSC", "TL"]

/** How many requests the page keeps (the Sandbox keeps 500), and how many it shows at a time. */
const kept = 200
const page = 50

/** The requests the services answered, polled every second and a half: the newest first, in a box of fixed height. */
export function LogTab() {
  const { t, time } = useI18n()
  const [entries, setEntries] = useState<SandboxRequest[]>([])
  const [service, setService] = useState("")
  const [shownCount, setShownCount] = useState(page)
  const [paused, setPaused] = useState(false)
  const last = useRef(0)
  useEffect(() => {
    if (paused) return
    let stopped = false
    const poll = async () => {
      try {
        // Never more than the page keeps: the first poll after a busy run fetches only the newest.
        const next = await api.log(last.current, kept)
        if (next.length > 0 && !stopped) {
          last.current = next[next.length - 1].id
          setEntries((current) => [...current, ...next].slice(-kept))
        }
      } catch {
        // The Sandbox stopped: try again on the next tick.
      }
    }
    void poll()
    const timer = setInterval(poll, 1500)
    return () => { stopped = true; clearInterval(timer) }
  }, [paused])
  const clear = async () => {
    try {
      await api.clearLog()
      setEntries([])
      setShownCount(page)
      toast.success(t("log.cleared"))
    } catch (e) {
      toast.error(t("common.error"), { description: (e as Error).message })
    }
  }
  const matching = entries.filter((e) => !service || e.service === service).reverse()
  const shown = matching.slice(0, shownCount)
  const present = services.filter((name) => !name || entries.some((e) => e.service === name))
  return (
    <div className="space-y-3">
      <p className="text-muted-foreground text-sm">{t("log.intro")}</p>
      <div className="flex flex-wrap items-center gap-1.5">
        {present.map((name) => (
          <button key={name} type="button" onClick={() => { setService(name); setShownCount(page) }}
            className={cn("rounded-full border px-2.5 py-0.5 text-xs", service === name ? "bg-accent border-foreground/30 font-medium" : "text-muted-foreground hover:text-foreground")}>
            {name || t("log.all")} {entries.filter((e) => !name || e.service === name).length}
          </button>
        ))}
        <span className="ml-auto flex gap-1">
          <Button variant="ghost" size="sm" onClick={() => setPaused((p) => !p)}>
            {paused ? <><Play /> {t("log.resume")}</> : <><Pause /> {t("log.pause")}</>}
          </Button>
          <Button variant="ghost" size="sm" disabled={entries.length === 0} onClick={clear}><Trash2 /> {t("common.clear")}</Button>
        </span>
      </div>
      {shown.length === 0 ? <p className="text-muted-foreground text-sm">{t("log.empty")}</p> : (
        <>
          <div className="max-h-[60vh] overflow-auto rounded-lg border">
            <Table>
              <TableHeader className="bg-background sticky top-0 z-10">
                <TableRow>
                  <TableHead>{t("log.time")}</TableHead>
                  <TableHead>{t("log.service")}</TableHead>
                  <TableHead>{t("log.request")}</TableHead>
                  <TableHead>{t("log.status")}</TableHead>
                  <TableHead>{t("log.fault")}</TableHead>
                  <TableHead className="text-right">ms</TableHead>
                  <TableHead>{t("log.client")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {shown.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell className="text-xs tabular-nums">{time(e.time)}</TableCell>
                    <TableCell><Pill>{e.service}</Pill></TableCell>
                    <TableCell className="font-mono text-[11px] whitespace-normal break-all">{e.method} {e.path}</TableCell>
                    <TableCell><Pill tone={e.status < 400 ? "success" : "danger"}>{e.status}</Pill></TableCell>
                    <TableCell>{e.fault && <Pill tone="warning">{e.fault}</Pill>}</TableCell>
                    <TableCell className="text-right text-xs tabular-nums">{e.ms}</TableCell>
                    <TableCell className="font-mono text-[11px]">{e.client}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className="text-muted-foreground flex items-center gap-3 text-xs">
            {t("log.showing", { shown: shown.length, total: matching.length })}
            {matching.length > shown.length && (
              <Button variant="outline" size="sm" onClick={() => setShownCount((n) => n + page)}>
                {t("common.showMore", { n: Math.min(page, matching.length - shown.length) })}
              </Button>
            )}
          </div>
        </>
      )}
    </div>
  )
}
