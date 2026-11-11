import { useEffect, useMemo, useRef, useState } from "react"
import { AlertCircle, PenTool } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { useT } from "@/i18n"
import { api } from "@/lib/api"
import type { AppearanceChoice, SigningOptions, StampPreview } from "@/lib/types"
import { PdfPreview, type StampBox } from "../shared/PdfPreview"
import { Pill } from "../shared/ui"
import { OptionField } from "../workbench/fields"
import { asText } from "../workbench/schema"
import { useWorkbench } from "../workbench/state"

/**
 * The visible signature of a PAdES signature: its options on the left, the PDF signed with it on the right, drawn by the
 * library itself (a throwaway B-B signature) a moment after each change. The rectangle can be dragged and resized on the
 * page. The stamp is part of the PAdES options: what is set here is what the Sign page signs with.
 */
export function StampPage() {
  const { schema, format, setFormat, options, patch, isVisible, setMode } = useWorkbench()
  const t = useT()

  // The stamp is PAdES only.
  useEffect(() => {
    if (format !== "pades") setFormat("pades")
  }, [format, setFormat])

  const o = options as unknown as SigningOptions
  const a = o.appearance
  const documentOption = schema.options.find((x) => x.id === "pades.document")
  const fields = schema.options.filter((x) => x.section === "appearance" && x.support === "supported" && isVisible(x))
  const existing = o.fieldMode === "Existing"
  const preview = usePreview(format === "pades" && a?.visible ? o : null)

  const [viewPage, setViewPage] = useState(1)
  const fixed = !!a && !existing && !a.autoPosition && !!a.width && !!a.height
  const page = fixed ? a.page : preview.result?.page ?? viewPage
  const box: StampBox | null = fixed
    ? { x: a.x, y: a.y, width: a.width!, height: a.height! }
    : preview.result?.rect ? { x: preview.result.rect[0], y: preview.result.rect[1], width: preview.result.rect[2], height: preview.result.rect[3] } : null

  const place = (b: StampBox) => patch({
    "appearance.autoPosition": false, "appearance.page": page,
    "appearance.x": b.x, "appearance.y": b.y, "appearance.width": b.width, "appearance.height": b.height,
  })
  const url = a?.visible ? (preview.result ? api.fileUrl(preview.result.fileId) : null) : o.documentId ? api.fileUrl(asText(o.documentId)) : null

  return (
    <div className="grid h-full min-h-0 lg:grid-cols-[minmax(400px,5fr)_7fr]">
      <div className="min-h-0 space-y-3 overflow-y-auto border-r p-4">
        <div className="space-y-1">
          <h2 className="text-sm font-semibold">{t("stamp.title")}</h2>
          <p className="text-muted-foreground text-xs leading-relaxed">{t("stamp.about")}</p>
        </div>
        <div className="bg-card divide-y rounded-lg border px-3">
          {documentOption && <OptionField option={documentOption} />}
          {fields.map((f) => <OptionField key={f.id} option={f} />)}
        </div>
        <Button variant="outline" size="sm" onClick={() => setMode("sign")}><PenTool /> {t("stamp.toSign")}</Button>
      </div>
      <div className="min-h-0 space-y-3 overflow-y-auto p-4">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {a?.visible
            ? <Pill tone="info">{t(existing ? "stamp.existing" : fixed ? "stamp.drag" : "stamp.auto")}</Pill>
            : <Pill>{t("stamp.off")}</Pill>}
          {preview.result && a?.visible && <span className="text-muted-foreground ml-auto tabular-nums">{t("stamp.rendered", { ms: preview.result.ms })}</span>}
        </div>
        {preview.error && a?.visible && (
          <Alert variant="destructive"><AlertCircle /><AlertDescription className="break-words">{preview.error}</AlertDescription></Alert>
        )}
        {url
          ? (
            <PdfPreview url={url} page={a?.visible ? page : viewPage} rendering={preview.loading} maxWidth={720}
              box={a?.visible ? box : null}
              onBoxChange={a?.visible && !existing ? place : undefined}
              onPageChange={(p) => (a?.visible && !existing ? patch({ "appearance.page": p }) : setViewPage(p))} />
          )
          : <p className="text-muted-foreground text-sm">{t(o.documentId ? "stamp.rendering" : "stamp.noDocument")}</p>}
      </div>
    </div>
  )
}

/**
 * The stamp drawn by the library for <paramref name="options"/>, again 400 ms after the last change that shows on it
 * (an older request is cancelled); null options: none.
 */
function usePreview(options: SigningOptions | null) {
  const [result, setResult] = useState<StampPreview | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const pending = useRef<AbortController | null>(null)
  // Only what shows on the stamp: the document, the field, the details it prints, the signer, the appearance.
  const key = useMemo(() => options && JSON.stringify([
    options.documentId, options.credentialId, options.fieldMode, options.fieldName, options.existingFieldName,
    options.reason, options.location, options.signerName, options.signingTime, options.appearance as AppearanceChoice,
  ]), [options])

  useEffect(() => {
    if (!options || !key || !options.documentId) return
    const timer = setTimeout(() => {
      pending.current?.abort()
      const controller = new AbortController()
      pending.current = controller
      setLoading(true)
      api.stampPreview(options, controller.signal)
        .then((r) => { setResult(r); setError(null) })
        .catch((e: Error) => { if (!controller.signal.aborted) setError(e.message) })
        .finally(() => { if (pending.current === controller) setLoading(false) })
    }, 400)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])

  useEffect(() => () => pending.current?.abort(), [])
  return { result, error, loading }
}
