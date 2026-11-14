import { useState } from "react"
import { BookCheck, Check, ChevronDown, FolderOpen } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { useT } from "@/i18n"
import { cn } from "@/lib/utils"
import type { PlaybookSample } from "./types"

/**
 * The loaded playbook's title as a menu: pick one of the samples, or open a playbook file. Takes the place of the
 * title (the description stays in the menu, where there is room for it).
 */
export function PlaybookPicker({ current, samples, disabled, onSample, onOpenFile }: {
  current: { id: string; title: string } | null
  samples: PlaybookSample[]
  disabled: boolean
  onSample: (id: string) => void
  onOpenFile: () => void
}) {
  const t = useT()
  const [open, setOpen] = useState(false)
  const pick = (action: () => void) => {
    setOpen(false)
    action()
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="sm" disabled={disabled} className="h-9 max-w-full min-w-0 justify-start gap-2 px-2 text-left">
          <BookCheck className="text-primary size-5 shrink-0" />
          <span className="truncate text-sm font-semibold">{current?.title ?? t("playbook.choose")}</span>
          <ChevronDown className="shrink-0 opacity-60" />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-[28rem] max-w-[calc(100vw-2rem)] p-1">
        {samples.length > 0 && (
          <>
            <p className="text-muted-foreground px-2 pt-1.5 pb-1 text-xs font-medium uppercase">{t("playbook.samples")}</p>
            {samples.map((s) => (
              <button key={s.id} type="button" onClick={() => pick(() => onSample(s.id))}
                className={cn("hover:bg-accent hover:text-accent-foreground flex w-full items-start gap-2 rounded-sm px-2 py-1.5 text-left",
                  current?.id === s.id && "bg-accent/50")}>
                <Check className={cn("mt-0.5 size-4 shrink-0", current?.id === s.id ? "opacity-100" : "opacity-0")} />
                <span className="min-w-0">
                  <span className="block text-sm font-medium">{s.title}</span>
                  {s.description && <span className="text-muted-foreground line-clamp-2 text-xs">{s.description}</span>}
                </span>
              </button>
            ))}
            <div className="bg-border -mx-1 my-1 h-px" />
          </>
        )}
        <button type="button" onClick={() => pick(onOpenFile)}
          className="hover:bg-accent hover:text-accent-foreground flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm">
          <FolderOpen className="size-4" /> {t("playbook.openFile")}
        </button>
      </PopoverContent>
    </Popover>
  )
}
