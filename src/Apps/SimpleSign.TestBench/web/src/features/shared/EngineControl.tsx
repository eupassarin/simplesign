import { Library, Terminal } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useT } from "@/i18n"
import { useWorkbench } from "../workbench/state"

/**
 * How the whole app signs and validates: through the SimpleSign library in the TestBench's process, or by running the
 * commands the Code tab shows through the simplesign CLI. It sits in the top bar: it applies to both tasks.
 */
export function EngineControl() {
  const { engine, setEngine } = useWorkbench()
  const t = useT()
  return (
    <div className="flex items-center rounded-md border p-0.5" role="radiogroup" aria-label={t("wb.engine.title")}>
      {(["library", "cli"] as const).map((id) => {
        const label = t(id === "cli" ? "wb.engine.cli" : "wb.engine.library")
        return (
          <Tooltip key={id}>
            <TooltipTrigger asChild>
              <Button role="radio" aria-checked={engine === id} aria-label={label} variant={engine === id ? "secondary" : "ghost"} size="sm" className="h-7 px-2 text-xs"
                onClick={() => setEngine(id)}>
                {id === "cli" ? <Terminal /> : <Library />}<span className="max-xl:hidden">{label}</span>
              </Button>
            </TooltipTrigger>
            <TooltipContent className="max-w-72">{t(id === "cli" ? "wb.engine.cliAbout" : "wb.engine.libraryAbout")}</TooltipContent>
          </Tooltip>
        )
      })}
    </div>
  )
}
