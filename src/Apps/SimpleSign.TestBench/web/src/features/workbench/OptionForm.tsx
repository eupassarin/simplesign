import { useState } from "react"
import { ChevronRight, RefreshCw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { useT } from "@/i18n"
import { api } from "@/lib/api"
import type { AppearanceChoice, SigningOptions } from "@/lib/types"
import { cn } from "@/lib/utils"
import { PdfPreview } from "../shared/PdfPreview"
import { OptionField } from "./fields"
import type { SchemaSection } from "./schema"
import { useWorkbench } from "./state"

const openByDefault = ["input", "level", "timestamp", "crypto"]

function loadOpen(): Record<string, boolean> {
  try {
    return JSON.parse(localStorage.getItem("wb.sections") ?? "{}") as Record<string, boolean>
  } catch {
    return {}
  }
}

/** The form of the current format, drawn from the schema: one collapsible block per section. */
export function OptionForm() {
  const { schema } = useWorkbench()
  const [open, setOpen] = useState<Record<string, boolean>>(loadOpen)
  const toggle = (id: string, value: boolean) => {
    const next = { ...open, [id]: value }
    localStorage.setItem("wb.sections", JSON.stringify(next))
    setOpen(next)
  }
  return (
    <div className="space-y-3">
      {schema.sections.map((section) => (
        <SectionBlock key={section.id} section={section} open={open[section.id] ?? openByDefault.includes(section.id)} onOpenChange={(v) => toggle(section.id, v)} />
      ))}
    </div>
  )
}

function SectionBlock({ section, open, onOpenChange }: { section: SchemaSection; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { schema, isVisible } = useWorkbench()
  const t = useT()
  const [showMissing, setShowMissing] = useState(false)
  const options = schema.options.filter((o) => o.section === section.id && isVisible(o))
  const supported = options.filter((o) => o.support === "supported")
  const missing = options.filter((o) => o.support === "notInLibrary")
  if (options.length === 0) return null
  return (
    <Collapsible open={open} onOpenChange={onOpenChange} className="bg-card rounded-lg border">
      <CollapsibleTrigger className="hover:bg-accent/40 flex w-full items-center gap-2 rounded-lg px-3 py-2.5 text-left transition-colors">
        <ChevronRight className={cn("text-muted-foreground size-4 shrink-0 transition-transform", open && "rotate-90")} />
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-semibold">{section.title}</span>
          <span className="text-muted-foreground block truncate text-xs">{section.summary}</span>
        </span>
        <span className="text-muted-foreground shrink-0 text-xs tabular-nums">{supported.length}{missing.length > 0 && <span className="opacity-60"> +{missing.length}</span>}</span>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="divide-y border-t px-3">
          {supported.map((o) => <OptionField key={o.id} option={o} />)}
          {section.id === "appearance" && <StampPreview />}
          {missing.length > 0 && (
            <div className="py-2">
              <button type="button" className="text-muted-foreground hover:text-foreground flex items-center gap-1 text-xs" onClick={() => setShowMissing(!showMissing)}>
                <ChevronRight className={cn("size-3 transition-transform", showMissing && "rotate-90")} />
                {t("wb.missingInSection", { n: missing.length })}
              </button>
              {showMissing && <div className="divide-y">{missing.map((o) => <OptionField key={o.id} option={o} />)}</div>}
            </div>
          )}
        </div>
      </CollapsibleContent>
    </Collapsible>
  )
}

/** Shows where the stamp goes: click the page to place it, or render it exactly as it will be signed. */
function StampPreview() {
  const { format, options, patch } = useWorkbench()
  const t = useT()
  const appearance = options.appearance as AppearanceChoice | undefined
  const [fileId, setFileId] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [page, setPage] = useState(appearance?.page ?? 1)
  if (format !== "pades" || !appearance?.visible || !options.documentId) return null
  const existing = options.fieldMode === "Existing"
  const render = () => {
    setBusy(true)
    // The preview signs a throwaway copy (B-B, sandbox key) with exactly these appearance options.
    api.preview(options as unknown as SigningOptions)
      .then((r) => { setFileId(r.fileId); setError(null) })
      .catch((e: Error) => setError(e.message))
      .finally(() => setBusy(false))
  }
  return (
    <div className="space-y-2 py-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-muted-foreground text-xs">{t(existing ? "field.preview.existing" : appearance.autoPosition ? "field.preview.auto" : "field.preview.click")}</p>
        <Button variant="outline" size="sm" onClick={render} disabled={busy}><RefreshCw className={busy ? "animate-spin" : ""} /> {t("field.preview.rerender")}</Button>
      </div>
      <PdfPreview url={api.fileUrl(fileId ?? String(options.documentId))} page={page} onPageChange={setPage} rendering={busy}
        box={!existing && !appearance.autoPosition && page === appearance.page && !fileId ? { x: appearance.x, y: appearance.y, width: appearance.width ?? 200, height: appearance.height ?? 60 } : null}
        onPlace={existing || appearance.autoPosition ? undefined : (x, y) => { setFileId(null); patch({ "appearance.x": Math.round(x), "appearance.y": Math.round(y), "appearance.page": page }) }} />
      {error && <p className="text-destructive text-xs">{t("field.preview.error", { error })}</p>}
    </div>
  )
}
