import { CornerDownRight, FileLock2, Timer } from "lucide-react"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { useI18n } from "@/i18n"
import type { CadesSignerReport, CadesValidationView, CmsFacts, CmsSignerView } from "@/lib/types"
import { cn } from "@/lib/utils"
import { Indication } from "../pdf-signing/steps/ResultStep"
import { KeyValue, Pill } from "../pdf-signing/ui"

/** The verdict of each signer, with countersignatures nested under their signer. */
export function SignerTree({ view }: { view: CadesValidationView }) {
  const { t } = useI18n()
  return (
    <div className="space-y-3">
      {view.errors.length > 0 && (
        <ul className="text-destructive space-y-1 text-xs">{view.errors.map((e) => <li key={e}>✕ {e}</li>)}</ul>
      )}
      {view.signers.map((s) => <SignerNode key={s.index} signer={s} depth={0} />)}
      {view.signers.length === 0 && view.errors.length === 0 && <p className="text-muted-foreground text-sm">{t("cades.result.noSigners")}</p>}
    </div>
  )
}

function SignerNode({ signer, depth }: { signer: CadesSignerReport; depth: number }) {
  const { t } = useI18n()
  return (
    <div className={cn("space-y-2", depth > 0 && "border-l-2 pl-4")}>
      <div className="rounded-lg border">
        <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
          {depth > 0 ? <CornerDownRight className="text-muted-foreground size-4" /> : <FileLock2 className="text-muted-foreground size-4" />}
          <span className="text-sm font-medium">
            {depth > 0 ? t("cades.result.counterSigner", { n: signer.index + 1 }) : t("cades.result.signer", { n: signer.index + 1 })}
          </span>
          <span className="text-muted-foreground truncate text-sm">{signer.signer ?? "—"}</span>
          <span className="ml-auto"><Indication value={signer.indication} /></span>
        </div>
        <div className="divide-y px-4">
          {signer.checks.map((c) => (
            <div key={c.id} className="flex items-start gap-3 py-2 text-sm">
              <span className={cn("mt-0.5 size-2 shrink-0 rounded-full", c.status === "pass" ? "bg-success" : c.status === "fail" ? "bg-destructive" : "bg-muted-foreground/40")} />
              <span className="min-w-0 flex-1">
                {c.name}
                {c.detail && <span className="text-muted-foreground block text-xs">{c.detail}</span>}
              </span>
              <span className="text-muted-foreground text-xs">{c.status}</span>
            </div>
          ))}
        </div>
        {(signer.errors.length > 0 || signer.warnings.length > 0) && (
          <ul className="space-y-1 border-t px-4 py-2 text-xs">
            {signer.errors.map((e) => <li key={e} className="text-destructive">✕ {e}</li>)}
            {signer.warnings.map((w) => <li key={w} className="text-muted-foreground">! {w}</li>)}
          </ul>
        )}
      </div>
      {signer.counterSignatures.map((c) => <SignerNode key={c.index} signer={c} depth={depth + 1} />)}
    </div>
  )
}

/** What is inside the CMS: content, signers, their signed and unsigned attributes. */
export function CmsStructure({ facts }: { facts: CmsFacts }) {
  const { t, number } = useI18n()
  if (facts.error) {
    return <p className="text-destructive text-sm">{facts.error}</p>
  }
  return (
    <div className="space-y-3">
      <div className="grid gap-x-8 rounded-lg border p-4 sm:grid-cols-3">
        <KeyValue label={t("cades.structure.content")}>
          {facts.isDetached ? t("cades.structure.detached") : t("cades.structure.enveloped", { size: number((facts.contentSize ?? 0) / 1024, 1) })}
        </KeyValue>
        <KeyValue label={t("cades.structure.size")}>{number(facts.size / 1024, 1)} KB</KeyValue>
        <KeyValue label={t("cades.structure.certificates")}>{facts.certificates}</KeyValue>
      </div>
      <Accordion type="multiple" className="rounded-lg border px-4">
        {facts.signers.map((s) => <SignerStructure key={s.index} signer={s} prefix="" />)}
      </Accordion>
    </div>
  )
}

function SignerStructure({ signer, prefix }: { signer: CmsSignerView; prefix: string }) {
  const { t } = useI18n()
  const id = `${prefix}${signer.index}`
  return (
    <>
      <AccordionItem value={id}>
        <AccordionTrigger>
          <span className="flex flex-wrap items-center gap-2 text-left">
            {prefix && <CornerDownRight className="text-muted-foreground size-3.5" />}
            <span className="text-muted-foreground font-mono text-xs">SignerInfo {prefix ? `${prefix}→` : ""}#{signer.index + 1}</span>
            <span className="truncate text-sm">{signer.subject ?? "—"}</span>
            <Pill>{signer.digestAlgorithm}</Pill>
            <Pill>{signer.signatureAlgorithm}</Pill>
            {signer.hasSignatureTimestamp && <Pill tone="info"><Timer className="mr-1 inline size-3" />{t("cades.structure.timestamp")}</Pill>}
            {signer.policyOid && <Pill tone="success">{t("cades.structure.policy")}</Pill>}
          </span>
        </AccordionTrigger>
        <AccordionContent className="space-y-3">
          <div className="grid gap-x-8 sm:grid-cols-2">
            <KeyValue label={t("cades.structure.issuer")}>{signer.issuer ?? "—"}</KeyValue>
            <KeyValue label={t("validation.cert.serial")} mono>{signer.serialNumber ?? "—"}</KeyValue>
            <KeyValue label={t("cades.structure.signingTime")}>{signer.signingTime ?? "—"}</KeyValue>
            <KeyValue label={t("validation.attributes.policy")} mono>{signer.policyOid ?? "—"}</KeyValue>
            <KeyValue label={t("validation.attributes.commitment")} mono>{signer.commitmentTypeOid ?? "—"}</KeyValue>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <AttributeList title={t("cades.structure.signed")} attributes={signer.signedAttributes} />
            <AttributeList title={t("cades.structure.unsigned")} attributes={signer.unsignedAttributes} />
          </div>
        </AccordionContent>
      </AccordionItem>
      {signer.counterSignatures.map((c) => <SignerStructure key={c.index} signer={c} prefix={`${id}.`} />)}
    </>
  )
}

function AttributeList({ title, attributes }: { title: string; attributes: CmsSignerView["signedAttributes"] }) {
  return (
    <div className="space-y-1">
      <p className="text-muted-foreground text-xs font-medium">{title}</p>
      {attributes.length === 0 ? <p className="text-muted-foreground text-xs">—</p> : (
        <ul className="space-y-0.5 text-xs">
          {attributes.map((a) => (
            <li key={a.oid} className="flex gap-2"><span>{a.name}</span><span className="text-muted-foreground font-mono">{a.oid}</span></li>
          ))}
        </ul>
      )}
    </div>
  )
}
