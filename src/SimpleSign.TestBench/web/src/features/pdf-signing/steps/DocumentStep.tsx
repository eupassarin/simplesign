import { useEffect, useRef, useState } from "react"
import { FileText, FileUp, Loader2, PenLine, ShieldCheck } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { api } from "@/lib/api"
import type { DocumentFacts, SampleDocument } from "@/lib/types"
import { ChoiceCard, KeyValue, Pill, Section } from "../ui"
import { useSigning } from "../state"

export function DocumentStep() {
  const { options, update, document } = useSigning()
  const [samples, setSamples] = useState<SampleDocument[]>([])
  const [uploading, setUploading] = useState(false)
  const input = useRef<HTMLInputElement>(null)

  useEffect(() => {
    api.samples().then((list) => {
      setSamples(list)
      if (!options.documentId && list.length > 0) update({ documentId: list[0].facts.id })
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function onFile(file: File) {
    setUploading(true)
    try {
      const facts = await api.uploadDocument(file)
      update({ documentId: facts.id, existingFieldName: null, fieldMode: "New" })
      toast.success(`${facts.fileName} uploaded`, { description: "Kept in memory only; nothing is written to disk." })
    } catch (e) {
      toast.error("Upload failed", { description: (e as Error).message })
    } finally {
      setUploading(false)
    }
  }

  const uploaded = document && !document.id.startsWith("sample:") ? document : null
  return (
    <div className="space-y-8">
      <Section title="Sample documents" description="Each sample shows a case the later steps react to. Pick one, or upload your own PDF." infoId="document">
        <div className="grid gap-3 sm:grid-cols-2">
          {samples.map((s) => (
            <ChoiceCard
              key={s.id}
              selected={options.documentId === s.facts.id}
              onSelect={() => update({ documentId: s.facts.id, existingFieldName: s.facts.emptyFields[0] ?? null, fieldMode: "New", certification: "None" })}
              title={s.title}
              description={s.description}
              icon={s.facts.signatures.length > 0 ? <ShieldCheck className="size-4" /> : s.facts.emptyFields.length > 0 ? <PenLine className="size-4" /> : <FileText className="size-4" />}
              badge={<FactBadges facts={s.facts} />}
            />
          ))}
          {uploaded && (
            <ChoiceCard selected title={uploaded.fileName} description="Your upload" icon={<FileUp className="size-4" />} onSelect={() => {}} badge={<FactBadges facts={uploaded} />} />
          )}
        </div>
        <div
          className="hover:border-foreground/30 hover:bg-accent/30 flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed p-6 text-center transition-colors"
          onClick={() => input.current?.click()}
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault()
            const file = e.dataTransfer.files[0]
            if (file) onFile(file)
          }}
        >
          {uploading ? <Loader2 className="text-muted-foreground size-5 animate-spin" /> : <FileUp className="text-muted-foreground size-5" />}
          <p className="text-sm font-medium">Drop a PDF here or click to upload</p>
          <p className="text-muted-foreground text-xs">Up to 50 MB. Uploads stay in this process's memory.</p>
          <input ref={input} type="file" accept="application/pdf,.pdf" hidden onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])} />
        </div>
      </Section>

      {document && <DocumentFactsCard facts={document} />}
    </div>
  )
}

function FactBadges({ facts }: { facts: DocumentFacts }) {
  return (
    <span className="ml-auto flex flex-wrap gap-1">
      {facts.isPdfA && <Pill tone="info">PDF/{facts.pdfALevel.replace("A", "A-")}</Pill>}
      {facts.docMdpLevel > 0 && <Pill tone={facts.docMdpLevel === 1 ? "danger" : "warning"}>P={facts.docMdpLevel}</Pill>}
      {facts.signatures.length > 0 && <Pill>{facts.signatures.length} sig.</Pill>}
    </span>
  )
}

function DocumentFactsCard({ facts }: { facts: DocumentFacts }) {
  return (
    <Section title="What the TestBench found" description="Read with PdfSignatureInspector and PdfStructureReader. These facts decide what the next steps offer.">
      <div className="grid gap-x-8 rounded-lg border p-4 sm:grid-cols-2">
        <KeyValue label="File">{facts.fileName}</KeyValue>
        <KeyValue label="Size">{(facts.size / 1024).toFixed(1)} KB</KeyValue>
        <KeyValue label="PDF version">{facts.pdfVersion}</KeyValue>
        <KeyValue label="PDF/A">{facts.isPdfA ? facts.pdfALevel : "no"}</KeyValue>
        <KeyValue label="Encrypted">{facts.isEncrypted ? "yes" : "no"}</KeyValue>
        <KeyValue label="DocMDP (certification)">{facts.docMdpLevel === 0 ? "not certified" : `P=${facts.docMdpLevel}`}</KeyValue>
        <KeyValue label="Signatures">{facts.signatures.length === 0 ? "none" : facts.signatures.map((s) => s.fieldName).join(", ")}</KeyValue>
        <KeyValue label="Empty signature fields">{facts.emptyFields.length === 0 ? "none" : facts.emptyFields.join(", ")}</KeyValue>
      </div>
      <ul className="text-muted-foreground space-y-1 text-xs">
        {facts.emptyFields.length > 0 && <li>• “Sign an existing field” will be offered in Field &amp; appearance.</li>}
        {facts.signatures.length > 0 && <li>• Already signed: certification is not possible; the new signature goes in a new revision.</li>}
        {facts.isPdfA && <li>• PDF/A: “Preserve PDF/A” will be offered in Cryptography{facts.isPdfA1 ? " (PDF/A-1 only allows adbe.pkcs7.detached)" : ""}.</li>}
        {facts.docMdpLevel === 1 && <li className="text-destructive">• DocMDP P=1: this document cannot be signed again.</li>}
      </ul>
      <Button variant="outline" size="sm" asChild>
        <a href={api.fileUrl(facts.id)} target="_blank" rel="noreferrer">
          Open the PDF
        </a>
      </Button>
    </Section>
  )
}
