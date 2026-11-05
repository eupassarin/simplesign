import { useEffect, useRef, useState } from "react"
import { ChevronLeft, ChevronRight, Loader2 } from "lucide-react"
import * as pdfjs from "pdfjs-dist"
import workerUrl from "pdfjs-dist/build/pdf.worker.min.mjs?url"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

pdfjs.GlobalWorkerOptions.workerSrc = workerUrl

export interface StampBox {
  x: number
  y: number
  width: number
  height: number
}

/**
 * Renders one page of a PDF with pdf.js. Optionally overlays the planned stamp rectangle (PDF
 * coordinates, origin bottom-left) and reports clicks in PDF coordinates so the stamp can be placed.
 */
export function PdfPreview({
  url,
  page,
  onPageCount,
  onPageChange,
  box,
  onPlace,
  rendering,
}: {
  url: string
  page: number
  onPageCount?: (count: number) => void
  onPageChange?: (page: number) => void
  box?: StampBox | null
  onPlace?: (x: number, y: number) => void
  rendering?: boolean
}) {
  const canvas = useRef<HTMLCanvasElement>(null)
  const [doc, setDoc] = useState<pdfjs.PDFDocumentProxy | null>(null)
  const [size, setSize] = useState<{ width: number; height: number; scale: number } | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setError(null)
    const task = pdfjs.getDocument({ url })
    task.promise
      .then((d) => {
        if (cancelled) return
        setDoc(d)
        onPageCount?.(d.numPages)
      })
      .catch((e: Error) => !cancelled && setError(e.message))
    return () => {
      cancelled = true
      task.destroy()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url])

  useEffect(() => {
    if (!doc || !canvas.current) return
    let cancelled = false
    let renderTask: pdfjs.RenderTask | null = null
    doc.getPage(Math.min(Math.max(page, 1), doc.numPages)).then((p) => {
      if (cancelled || !canvas.current) return
      const base = p.getViewport({ scale: 1 })
      const scale = Math.min(1.4, 560 / base.width)
      const viewport = p.getViewport({ scale: scale * window.devicePixelRatio })
      const c = canvas.current
      c.width = viewport.width
      c.height = viewport.height
      c.style.width = `${base.width * scale}px`
      c.style.height = `${base.height * scale}px`
      setSize({ width: base.width, height: base.height, scale })
      renderTask = p.render({ canvas: c, viewport })
      renderTask.promise.catch(() => {})
    })
    return () => {
      cancelled = true
      renderTask?.cancel()
    }
  }, [doc, page])

  const pageCount = doc?.numPages ?? 1
  return (
    <div className="space-y-2">
      <div className="bg-muted/40 relative mx-auto w-fit overflow-hidden rounded-md border shadow-sm">
        {error && <p className="text-destructive p-6 text-sm">Could not render the PDF: {error}</p>}
        <canvas
          ref={canvas}
          className={cn("block bg-white", onPlace && "cursor-crosshair")}
          onClick={(e) => {
            if (!onPlace || !size) return
            const rect = e.currentTarget.getBoundingClientRect()
            const x = (e.clientX - rect.left) / size.scale
            const yTop = (e.clientY - rect.top) / size.scale
            onPlace(Math.round(x), Math.round(size.height - yTop))
          }}
        />
        {box && size && (
          <div
            className="border-info bg-info/10 pointer-events-none absolute border-2 border-dashed"
            style={{
              left: box.x * size.scale,
              top: (size.height - box.y - box.height) * size.scale,
              width: box.width * size.scale,
              height: box.height * size.scale,
            }}
          />
        )}
        {(rendering || (!doc && !error)) && (
          <div className="bg-background/40 absolute inset-0 flex items-center justify-center">
            <Loader2 className="text-muted-foreground size-5 animate-spin" />
          </div>
        )}
      </div>
      {pageCount > 1 && onPageChange && (
        <div className="flex items-center justify-center gap-2 text-xs">
          <Button variant="ghost" size="icon" className="size-7" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>
            <ChevronLeft />
          </Button>
          Page {page} of {pageCount}
          <Button variant="ghost" size="icon" className="size-7" disabled={page >= pageCount} onClick={() => onPageChange(page + 1)}>
            <ChevronRight />
          </Button>
        </div>
      )}
    </div>
  )
}
