import { useState } from "react"
import type { EnvironmentMode } from "@/lib/types"
import { cn } from "@/lib/utils"
import { CadesValidateView } from "./CadesValidateView"
import { ValidationPage } from "./ValidationPage"
import { XmlValidateView } from "./XmlValidateView"

const formats = [
  { id: "pdf", title: "PDF (PAdES)" },
  { id: "cades", title: "CAdES (.p7s / .p7m)" },
  { id: "xml", title: "XML (XAdES / XML-DSig)" },
] as const

/** Validation of files that already exist, in the three formats (including samples that are broken on purpose). */
export function ValidationArea({ environment, initialFile }: { environment: EnvironmentMode; initialFile?: { id: string; name: string } | null }) {
  const [format, setFormat] = useState<(typeof formats)[number]["id"]>("pdf")
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="border-b px-4 py-2">
        <div className="bg-muted inline-flex rounded-lg p-0.5" role="radiogroup">
          {formats.map((f) => (
            <button key={f.id} role="radio" aria-checked={format === f.id} onClick={() => setFormat(f.id)}
              className={cn("rounded-md px-3 py-1 text-xs font-medium transition-all", format === f.id ? "bg-background shadow-sm" : "text-muted-foreground hover:text-foreground")}>
              {f.title}
            </button>
          ))}
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {format === "pdf" && <ValidationPage environment={environment} initialFile={initialFile} />}
        {format === "cades" && <CadesValidateView environment={environment} />}
        {format === "xml" && <XmlValidateView environment={environment} />}
      </div>
    </div>
  )
}
