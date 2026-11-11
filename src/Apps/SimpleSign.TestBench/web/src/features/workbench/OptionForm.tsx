import { useState } from "react"
import { ChevronRight, Stamp } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet"
import { StampPage } from "../stamp/StampPage"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { useT } from "@/i18n"
import { cn } from "@/lib/utils"
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
      {schema.sections.map((section) => section.id === "appearance" ? <StampLink key={section.id} /> : (
        <SectionBlock key={section.id} section={section} open={open[section.id] ?? openByDefault.includes(section.id)} onOpenChange={(v) => toggle(section.id, v)} />
      ))}
    </div>
  )
}

/** The visible stamp: whether it is on, and "Edit the stamp", which opens its page as a drawer over the form. */
function StampLink() {
  const { options, format } = useWorkbench()
  const t = useT()
  const [open, setOpen] = useState(false)
  if (format !== "pades") return null
  const visible = (options.appearance as { visible?: boolean } | undefined)?.visible === true
  return (
    <div className="bg-card flex items-center gap-3 rounded-lg border px-3 py-2.5">
      <Stamp className="text-muted-foreground size-4 shrink-0" />
      <span className="min-w-0 flex-1">
        <span className="block text-sm font-semibold">{t("stamp.title")}</span>
        <span className="text-muted-foreground block truncate text-xs">{t(visible ? "stamp.onSummary" : "stamp.offSummary")}</span>
      </span>
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetTrigger asChild><Button variant="outline" size="sm">{t("stamp.edit")}</Button></SheetTrigger>
        {/* No focus on open: the first focusable is an "i" button, and focusing it opens its hover card. */}
        <SheetContent className="flex w-[min(96vw,1400px)] flex-col p-0 sm:max-w-none" onOpenAutoFocus={(e) => e.preventDefault()}>
          <SheetHeader className="sr-only"><SheetTitle>{t("stamp.title")}</SheetTitle><SheetDescription>{t("stamp.about")}</SheetDescription></SheetHeader>
          <div className="min-h-0 flex-1">{open && <StampPage onClose={() => setOpen(false)} />}</div>
        </SheetContent>
      </Sheet>
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
