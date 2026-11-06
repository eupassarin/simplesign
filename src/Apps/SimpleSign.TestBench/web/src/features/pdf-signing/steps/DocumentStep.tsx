import { useEffect, useRef, useState } from "react"
import { FileText, FileUp, Loader2, PenLine, ShieldCheck } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { DocumentFacts, SampleDocument } from "@/lib/types"
import { ChoiceCard, KeyValue, Pill, Section } from "../ui"
import { useSigning } from "../state"

export function DocumentStep() {
  const { options, update, document } = useSigning()
  const [samples, setSamples] = useState<SampleDocument[]>([])
  const [uploading, setUploading] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  const { t } = useI18n()

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
      toast.success(t("document.uploaded", { name: facts.fileName }), { description: t("document.uploadedHint") })
    } catch (e) {
      toast.error(t("document.uploadFailed"), { description: (e as Error).message })
    } finally {
      setUploading(false)
    }
  }

  const uploaded = document && !document.id.startsWith("sample:") ? document : null
  return (
    <div className="space-y-8">
      <Section title={t("document.samples")} description={t("document.samplesHint")} infoId="document">
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
            <ChoiceCard selected title={uploaded.fileName} description={t("document.yourUpload")} icon={<FileUp className="size-4" />} onSelect={() => {}} badge={<FactBadges facts={uploaded} />} />
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
          <p className="text-sm font-medium">{t("document.drop")}</p>
          <p className="text-muted-foreground text-xs">{t("document.dropHint")}</p>
          <input ref={input} type="file" accept="application/pdf,.pdf" hidden onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])} />
        </div>
      </Section>

      {document && <DocumentFactsCard facts={document} />}
    </div>
  )
}

function FactBadges({ facts }: { facts: DocumentFacts }) {
  const { t } = useI18n()
  return (
    <span className="ml-auto flex flex-wrap gap-1">
      {facts.isPdfA && <Pill tone="info">PDF/{facts.pdfALevel.replace("A", "A-")}</Pill>}
      {facts.docMdpLevel > 0 && <Pill tone={facts.docMdpLevel === 1 ? "danger" : "warning"}>P={facts.docMdpLevel}</Pill>}
      {facts.signatures.length > 0 && <Pill>{t("document.sigCount", { n: facts.signatures.length })}</Pill>}
    </span>
  )
}

function DocumentFactsCard({ facts }: { facts: DocumentFacts }) {
  const { t, number } = useI18n()
  return (
    <Section title={t("document.found")} description={t("document.foundHint")}>
      <div className="grid gap-x-8 rounded-lg border p-4 sm:grid-cols-2">
        <KeyValue label={t("document.facts.file")}>{facts.fileName}</KeyValue>
        <KeyValue label={t("document.facts.size")}>{number(facts.size / 1024, 1)} KB</KeyValue>
        <KeyValue label={t("document.facts.version")}>{facts.pdfVersion}</KeyValue>
        <KeyValue label="PDF/A">{facts.isPdfA ? facts.pdfALevel : t("common.no")}</KeyValue>
        <KeyValue label={t("document.facts.encrypted")}>{facts.isEncrypted ? t("common.yes") : t("common.no")}</KeyValue>
        <KeyValue label={t("document.facts.docMdp")}>{facts.docMdpLevel === 0 ? t("document.facts.notCertified") : `P=${facts.docMdpLevel}`}</KeyValue>
        <KeyValue label={t("document.facts.signatures")}>{facts.signatures.length === 0 ? t("common.none") : facts.signatures.map((s) => s.fieldName).join(", ")}</KeyValue>
        <KeyValue label={t("document.facts.emptyFields")}>{facts.emptyFields.length === 0 ? t("common.none") : facts.emptyFields.join(", ")}</KeyValue>
      </div>
      <ul className="text-muted-foreground space-y-1 text-xs">
        {facts.emptyFields.length > 0 && <li>• {t("document.hints.emptyField")}</li>}
        {facts.signatures.length > 0 && <li>• {t("document.hints.signed")}</li>}
        {facts.isPdfA && <li>• {t(facts.isPdfA1 ? "document.hints.pdfA1" : "document.hints.pdfA")}</li>}
        {facts.docMdpLevel === 1 && <li className="text-destructive">• {t("document.hints.p1")}</li>}
      </ul>
      <Button variant="outline" size="sm" asChild>
        <a href={api.fileUrl(facts.id)} target="_blank" rel="noreferrer">
          {t("document.open")}
        </a>
      </Button>
    </Section>
  )
}
