import { useState } from "react"
import { ChevronDown, Download, Eye, FileJson, Loader2 } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { useT } from "@/i18n"
import { HighlightedCode } from "../shared/CodeHighlight"
import { playbookApi } from "./api"

/** The loaded playbook's file: a menu to view it (as loaded, in a dialog) or download it. */
export function PlaybookFileMenu({ id, title }: { id: string; title: string }) {
  const t = useT()
  const [menu, setMenu] = useState(false)
  const [viewing, setViewing] = useState(false)
  const [json, setJson] = useState<string | null>(null)
  const fileName = `${id || "playbook"}.json`

  const view = async () => {
    setMenu(false)
    setViewing(true)
    setJson(null)
    try {
      const text = await playbookApi.loadedJson()
      setJson(text ?? "")
    } catch (e) {
      toast.error((e as Error).message)
      setViewing(false)
    }
  }

  return (
    <>
      <Popover open={menu} onOpenChange={setMenu}>
        <PopoverTrigger asChild>
          <Button variant="ghost" size="sm" aria-description={t("playbook.downloadHint")}><FileJson /> {t("playbook.file")} <ChevronDown className="opacity-60" /></Button>
        </PopoverTrigger>
        <PopoverContent align="end" className="w-56 p-1">
          <button className="hover:bg-accent hover:text-accent-foreground flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm" onClick={() => void view()}>
            <Eye className="size-4" /> {t("playbook.view")}
          </button>
          <a href={playbookApi.loadedJsonUrl} download={fileName} onClick={() => setMenu(false)}
            className="hover:bg-accent hover:text-accent-foreground flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm">
            <Download className="size-4" /> {t("playbook.download")}
          </a>
        </PopoverContent>
      </Popover>

      <Dialog open={viewing} onOpenChange={setViewing}>
        <DialogContent className="flex h-[90vh] flex-col gap-0 p-0 sm:max-w-4xl">
          <DialogHeader className="space-y-1 border-b px-6 pt-5 pb-3">
            <DialogTitle className="flex items-center gap-2"><FileJson className="size-4" /> {title}</DialogTitle>
            <DialogDescription className="font-mono text-xs">{fileName} · {t("playbook.viewHint")}</DialogDescription>
          </DialogHeader>
          <div className="min-h-0 flex-1 overflow-auto px-6 py-4">
            {json === null
              ? <p className="text-muted-foreground flex items-center gap-2 text-sm"><Loader2 className="size-4 animate-spin" /> {t("playbook.preparing")}</p>
              : <HighlightedCode code={json} language="json" />}
          </div>
          <div className="flex justify-end border-t px-6 py-3">
            <Button variant="outline" size="sm" asChild><a href={playbookApi.loadedJsonUrl} download={fileName}><Download /> {t("playbook.download")}</a></Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}
