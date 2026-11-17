import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react"
import { ChevronLeft, ChevronRight, Loader2 } from "lucide-react"
import * as pdfjs from "pdfjs-dist"
import workerUrl from "pdfjs-dist/build/pdf.worker.min.mjs?url"
import { Button } from "@/components/ui/button"
import { useT } from "@/i18n"
import { cn } from "@/lib/utils"

pdfjs.GlobalWorkerOptions.workerSrc = workerUrl

/** A rectangle in PDF points, origin at the bottom left of the page. */
export interface StampBox {
  x: number
  y: number
  width: number
  height: number
}

const minSize = 20

/**
 * Renders one page of a PDF with pdf.js. Optionally overlays the stamp rectangle (PDF coordinates, origin bottom-left).
 * With `onBoxChange` the rectangle can be dragged, resized from its bottom-right corner, or moved by clicking the page
 * (its top-left corner goes where the click is); the new rectangle is reported when the pointer is released.
 */
export function PdfPreview({
  url,
  page,
  onPageCount,
  onPageChange,
  box,
  onBoxChange,
  rendering,
  maxWidth = 560,
}: {
  url: string
  page: number
  onPageCount?: (count: number) => void
  onPageChange?: (page: number) => void
  box?: StampBox | null
  onBoxChange?: (box: StampBox) => void
  rendering?: boolean
  maxWidth?: number
}) {
  const canvas = useRef<HTMLCanvasElement>(null)
  const [doc, setDoc] = useState<pdfjs.PDFDocumentProxy | null>(null)
  const [size, setSize] = useState<{ width: number; height: number; scale: number } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [drag, setDrag] = useState<StampBox | null>(null)
  const start = useRef<{ mode: "move" | "resize"; x: number; y: number; box: StampBox } | null>(null)
  const t = useT()

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
      const scale = Math.min(1.4, maxWidth / base.width)
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
  }, [doc, page, maxWidth])

  const clamp = (b: StampBox): StampBox => {
    if (!size) return b
    const width = Math.max(minSize, Math.min(b.width, size.width))
    const height = Math.max(minSize, Math.min(b.height, size.height))
    return {
      x: Math.round(Math.max(0, Math.min(b.x, size.width - width))),
      y: Math.round(Math.max(0, Math.min(b.y, size.height - height))),
      width: Math.round(width),
      height: Math.round(height),
    }
  }

  const begin = (mode: "move" | "resize") => (e: ReactPointerEvent<HTMLDivElement>) => {
    if (!onBoxChange || !box) return
    e.preventDefault()
    e.stopPropagation()
    e.currentTarget.setPointerCapture(e.pointerId)
    start.current = { mode, x: e.clientX, y: e.clientY, box }
    setDrag(box)
  }

  const move = (e: ReactPointerEvent<HTMLDivElement>) => {
    const s = start.current
    if (!s || !size) return
    const dx = (e.clientX - s.x) / size.scale
    const dy = (e.clientY - s.y) / size.scale
    setDrag(clamp(s.mode === "move"
      ? { ...s.box, x: s.box.x + dx, y: s.box.y - dy }
      // The corner moves down-right: the width grows, the height grows downwards (the bottom edge moves down).
      : { x: s.box.x, y: s.box.y - dy, width: s.box.width + dx, height: s.box.height + dy }))
  }

  const end = () => {
    if (start.current && drag) onBoxChange?.(drag)
    start.current = null
    setDrag(null)
  }

  const shown = drag ?? box
  const pageCount = doc?.numPages ?? 1
  return (
    <div className="space-y-2">
      <div className="bg-muted/40 relative mx-auto w-fit overflow-hidden rounded-md border shadow-sm">
        {error && <p className="text-destructive p-6 text-sm">{t("preview.error", { error })}</p>}
        <canvas
          ref={canvas}
          className={cn("block bg-white", onBoxChange && box && "cursor-crosshair")}
          onClick={(e) => {
            if (!onBoxChange || !box || !size) return
            const rect = e.currentTarget.getBoundingClientRect()
            const x = (e.clientX - rect.left) / size.scale
            const yTop = (e.clientY - rect.top) / size.scale
            onBoxChange(clamp({ ...box, x, y: size.height - yTop - box.height }))
          }}
        />
        {shown && size && (
          <div
            className={cn("border-info bg-info/10 absolute border-2 border-dashed", onBoxChange ? "cursor-move touch-none" : "pointer-events-none")}
            style={{
              left: shown.x * size.scale,
              top: (size.height - shown.y - shown.height) * size.scale,
              width: shown.width * size.scale,
              height: shown.height * size.scale,
            }}
            onPointerDown={begin("move")}
            onPointerMove={move}
            onPointerUp={end}
            onPointerCancel={end}
          >
            {onBoxChange && (
              <div
                aria-hidden
                className="bg-info absolute -right-1.5 -bottom-1.5 size-3 cursor-nwse-resize rounded-sm"
                onPointerDown={begin("resize")}
                onPointerMove={move}
                onPointerUp={end}
                onPointerCancel={end}
              />
            )}
          </div>
        )}
        {(rendering || (!doc && !error)) && (
          <div className="pointer-events-none absolute top-2 right-2">
            <Loader2 className="text-muted-foreground size-4 animate-spin" />
          </div>
        )}
      </div>
      {pageCount > 1 && onPageChange && (
        <div className="flex items-center justify-center gap-2 text-xs">
          <Button variant="ghost" size="icon" className="size-7" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>
            <ChevronLeft />
          </Button>
          {t("preview.page", { page, total: pageCount })}
          <Button variant="ghost" size="icon" className="size-7" disabled={page >= pageCount} onClick={() => onPageChange(page + 1)}>
            <ChevronRight />
          </Button>
        </div>
      )}
    </div>
  )
}
