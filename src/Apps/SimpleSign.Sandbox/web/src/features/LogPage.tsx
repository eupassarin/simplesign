import { useEffect, useRef, useState } from "react"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Pill } from "@/components/parts"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { SandboxRequest } from "@/lib/types"
import { cn } from "@/lib/utils"

const services = ["", "AIA", "CRL", "TSA", "CSC"]

/** The requests the services answered, polled every second and a half. */
export function LogPage() {
  const { t, time } = useI18n()
  const [entries, setEntries] = useState<SandboxRequest[]>([])
  const [service, setService] = useState("")
  const last = useRef(0)
  useEffect(() => {
    let stopped = false
    const poll = async () => {
      try {
        const next = await api.log(last.current)
        if (next.length > 0 && !stopped) {
          last.current = next[next.length - 1].id
          setEntries((current) => [...current, ...next].slice(-500))
        }
      } catch {
        // The Sandbox stopped: try again on the next tick.
      }
    }
    void poll()
    const timer = setInterval(poll, 1500)
    return () => { stopped = true; clearInterval(timer) }
  }, [])
  const shown = entries.filter((e) => !service || e.service === service).slice().reverse()
  return (
    <div className="space-y-4">
      <p className="text-muted-foreground text-sm">{t("log.intro")}</p>
      <div className="flex flex-wrap gap-1.5">
        {services.map((name) => (
          <button key={name} type="button" onClick={() => setService(name)}
            className={cn("rounded-full border px-2.5 py-0.5 text-xs", service === name ? "bg-accent border-foreground/30 font-medium" : "text-muted-foreground hover:text-foreground")}>
            {name || t("log.all")} {entries.filter((e) => !name || e.service === name).length}
          </button>
        ))}
      </div>
      {shown.length === 0 ? <p className="text-muted-foreground text-sm">{t("log.empty")}</p> : (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
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
      )}
    </div>
  )
}
