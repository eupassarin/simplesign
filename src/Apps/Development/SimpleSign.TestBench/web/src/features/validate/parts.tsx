import { useRef, useState, type ReactNode } from "react"
import { ChevronRight, FileUp } from "lucide-react"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { useT } from "@/i18n"
import { api } from "@/lib/api"
import { cn } from "@/lib/utils"
import { Indication } from "../shared/results"
import { UploadButton } from "../shared/UploadButton"
import type { ValidationSampleView } from "../workbench/schema"
import { useWorkbench, type ValidateTarget } from "../workbench/state"

/** Which blocks of a task are open, remembered in this browser under `key`. */
export function useOpenBlocks(key: string, defaults: Record<string, boolean>) {
  const [open, setOpen] = useState<Record<string, boolean>>(() => {
    try {
      return { ...defaults, ...(JSON.parse(localStorage.getItem(key) ?? "{}") as Record<string, boolean>) }
    } catch {
      return defaults
    }
  })
  const toggle = (id: string, value: boolean) => {
    const next = { ...open, [id]: value }
    try { localStorage.setItem(key, JSON.stringify(next)) } catch { /* the choice is only kept for this page */ }
    setOpen(next)
  }
  return { open, toggle }
}

/** A collapsible block, as in the Sign tab: title, one-line summary and how many options it holds. */
export function Block({ id, title, summary, count, open, toggle, children }: {
  id: string
  title: string
  summary: string
  count?: number
  open: Record<string, boolean>
  toggle: (id: string, value: boolean) => void
  children: ReactNode
}) {
  const isOpen = open[id] ?? false
  return (
    <Collapsible open={isOpen} onOpenChange={(v) => toggle(id, v)} className="bg-card rounded-lg border">
      <CollapsibleTrigger className="hover:bg-accent/40 flex w-full items-center gap-2 rounded-lg px-3 py-2.5 text-left transition-colors">
        <ChevronRight className={cn("text-muted-foreground size-4 shrink-0 transition-transform", isOpen && "rotate-90")} />
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-semibold">{title}</span>
          <span className="text-muted-foreground block truncate text-xs">{summary}</span>
        </span>
        {count !== undefined && <span className="text-muted-foreground shrink-0 text-xs tabular-nums">{count}</span>}
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="divide-y border-t px-3">{children}</div>
      </CollapsibleContent>
    </Collapsible>
  )
}

/**
 * A signed file to work on: dropped or chosen (PDF, CMS or XML, told apart by its content), the data of a detached
 * signature, and the samples made at startup grouped by format.
 */
export function SignedFilePicker({ target, onChoose, samples, open, toggle }: {
  target: ValidateTarget | null
  onChoose: (target: ValidateTarget) => void
  samples: ValidationSampleView[]
  open: Record<string, boolean>
  toggle: (id: string, value: boolean) => void
}) {
  const { schema } = useWorkbench()
  const t = useT()
  const input = useRef<HTMLInputElement>(null)
  const upload = async (file: File) => {
    const uploaded = await api.uploadFile(file)
    onChoose({ fileId: uploaded.id, name: uploaded.fileName })
  }
  const groups = schema.formats.map((f) => ({ format: f, samples: samples.filter((s) => s.format === f.id) })).filter((g) => g.samples.length > 0)
  return (
    <div className="space-y-3 py-3">
      <div className="hover:border-foreground/30 hover:bg-accent/30 flex cursor-pointer flex-col items-center gap-1.5 rounded-lg border border-dashed p-5 text-center transition-colors"
        onClick={() => input.current?.click()} onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => { e.preventDefault(); const file = e.dataTransfer.files[0]; if (file) void upload(file) }}>
        <FileUp className="text-muted-foreground size-5" />
        <p className="text-sm font-medium">{t("val.drop")}</p>
        <p className="text-muted-foreground text-xs">PDF · .p7s · .p7m · XML</p>
        <input ref={input} type="file" hidden onChange={(e) => { const file = e.target.files?.[0]; if (file) void upload(file); e.target.value = "" }} />
      </div>
      {target && (
        <div className="flex flex-wrap items-center gap-2">
          <UploadButton label={t("val.data")} accept="*/*" onUploaded={(f) => onChoose({ ...target, dataId: f.id, dataName: f.fileName })} />
          <span className="text-muted-foreground text-xs">{target.dataName ?? t("val.dataHint")}</span>
        </div>
      )}
      {groups.length > 0 && (
        <div className="space-y-2">
          <div>
            <p className="text-sm font-medium">{t("val.samples")}</p>
            <p className="text-muted-foreground text-xs">{t("val.samplesHint")}</p>
          </div>
          {groups.map((group) => {
            const id = "samples." + group.format.id
            const isOpen = open[id] ?? false
            return (
              <Collapsible key={group.format.id} open={isOpen} onOpenChange={(v) => toggle(id, v)} className="rounded-md border">
                <CollapsibleTrigger className="hover:bg-accent/40 flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left transition-colors">
                  <ChevronRight className={cn("text-muted-foreground size-4 shrink-0 transition-transform", isOpen && "rotate-90")} />
                  <span className="flex-1 text-sm font-semibold">{group.format.title}</span>
                  <span className="text-muted-foreground text-xs tabular-nums">{group.samples.length}</span>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <ul className="border-t py-1">
                    {group.samples.map((s) => (
                      <li key={s.format + s.id}>
                        <button type="button" onClick={() => onChoose({ fileId: s.fileId, name: s.fileName, dataId: s.dataId })}
                          className={cn("hover:bg-accent/50 flex w-full items-start gap-2 px-2.5 py-1.5 text-left", target?.fileId === s.fileId && (target.dataId ?? null) === (s.dataId ?? null) && "bg-accent/60")}>
                          <span className="min-w-0 flex-1">
                            <span className="block text-sm">{s.title}</span>
                            <span className="text-muted-foreground block text-xs leading-snug">{s.description}</span>
                          </span>
                          {s.expectedIndication && <Indication value={s.expectedIndication as "Valid"} />}
                        </button>
                      </li>
                    ))}
                  </ul>
                </CollapsibleContent>
              </Collapsible>
            )
          })}
        </div>
      )}
    </div>
  )
}
