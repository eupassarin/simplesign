import { BadgeCheck, FileSignature, Plus, Stethoscope, UserRound, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useT, type MessageKey } from "@/i18n"
import type { CertificationChoice, ProfessionalChoice } from "@/lib/types"
import { ChoiceCard, Field, Section, ToggleRow } from "../ui"
import { useSigning } from "../state"

const commitments = ["ProofOfOrigin", "ProofOfReceipt", "ProofOfDelivery", "ProofOfSender", "ProofOfApproval", "ProofOfCreation"]
const authMethods = ["InstitutionalLogin", "DigitalCertificate", "GovBr", "FacialBiometrics", "TokenOtp", "UsernamePassword"]
const councils = ["Oab", "Cfm", "Cff", "Cfbio", "Cfbm", "Confef", "Cofen", "Coffito", "Cffa", "Cfmv", "Cfn", "Cfo", "Cfp", "Cfess", "Conter", "Cfq"]

const certifications: CertificationChoice[] = ["None", "NoChanges", "FormFilling", "FormFillingAndAnnotations"]

export function DetailsStep() {
  const { options, update, state } = useSigning()
  const signer = state("details.signer")
  const t = useT()
  return (
    <div className="space-y-8">
      <Section title={t("details.dictionary")} infoId="details.basic" description={t("details.dictionaryHint")}>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t("details.reason")}><Input value={options.reason ?? ""} onChange={(e) => update({ reason: e.target.value })} placeholder={t("details.reasonPlaceholder")} /></Field>
          <Field label={t("details.location")}><Input value={options.location ?? ""} onChange={(e) => update({ location: e.target.value })} placeholder="São Paulo, BR" /></Field>
          <Field label={t("details.contact")}><Input value={options.contactInfo ?? ""} onChange={(e) => update({ contactInfo: e.target.value })} placeholder={t("details.contactPlaceholder")} /></Field>
          <Field label={t("details.signerName")} description={t("details.signerNameHint")}><Input value={options.signerName ?? ""} onChange={(e) => update({ signerName: e.target.value })} /></Field>
        </div>
        <Field label={t("details.signingTime")} infoId="details.signingTime" description={state("details.signingTime").disabled ?? t("details.signingTimeHint")}>
          <Input type="datetime-local" className="max-w-64" disabled={!!state("details.signingTime").disabled}
            value={options.signingTime ? options.signingTime.slice(0, 16) : ""}
            onChange={(e) => update({ signingTime: e.target.value ? new Date(e.target.value).toISOString() : null })} />
        </Field>
      </Section>

      <Section title={t("details.signer")} description={signer.disabled ?? t("details.signerHint")}>
        <div className="grid gap-3 sm:grid-cols-3">
          <ChoiceCard selected={!options.useSignerDetails} onSelect={() => update({ useSignerDetails: false })} title={t("details.none")} description={t("details.noneHint")} state={signer.disabled ? { visible: true } : undefined} />
          <ChoiceCard selected={options.useSignerDetails && options.signerDetails === "Metadata"} onSelect={() => update({ useSignerDetails: true, signerDetails: "Metadata" })}
            title={t("details.metadata")} infoId="details.Metadata" icon={<UserRound className="size-4" />} state={signer.disabled ? signer : state("details.Metadata")} />
          <ChoiceCard selected={options.useSignerDetails && options.signerDetails === "Aea"} onSelect={() => update({ useSignerDetails: true, signerDetails: "Aea" })}
            title="AEA (Lei 14.063)" infoId="details.Aea" icon={<BadgeCheck className="size-4" />} state={signer.disabled ? signer : state("details.Aea")} />
        </div>
        {options.useSignerDetails && !signer.disabled && options.signerDetails === "Metadata" && <MetadataForm />}
        {options.useSignerDetails && !signer.disabled && options.signerDetails === "Aea" && state("details.Aea").disabled == null && <AeaForm />}
      </Section>

      <Section title={t("details.certification")} infoId="certification" description={t("details.certificationHint")}>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {certifications.map((c) => (
            <ChoiceCard key={c} selected={options.certification === c} onSelect={() => update({ certification: c })} title={t(`details.certifications.${c}.title` as MessageKey)} description={t(`details.certifications.${c}.hint` as MessageKey)}
              icon={<FileSignature className="size-4" />} state={c === "None" ? undefined : state(`certification.${c}`)} />
          ))}
        </div>
      </Section>

      <HealthSection />

      <Section title={t("details.documentInfo")} infoId="documentInfo" description={state("documentInfo").disabled ?? t("details.documentInfoHint")}>
        {!state("documentInfo").disabled && (
          <div className="space-y-2">
            {options.documentInfo.map((entry, i) => (
              <div key={i} className="flex gap-2">
                <Input className="max-w-48 font-mono text-xs" value={entry.key} placeholder={t("details.key")} onChange={(e) => update((o) => ({ documentInfo: o.documentInfo.map((d, j) => (j === i ? { ...d, key: e.target.value } : d)) }))} />
                <Input value={entry.value} placeholder={t("details.value")} onChange={(e) => update((o) => ({ documentInfo: o.documentInfo.map((d, j) => (j === i ? { ...d, value: e.target.value } : d)) }))} />
                <Button variant="ghost" size="icon" onClick={() => update((o) => ({ documentInfo: o.documentInfo.filter((_, j) => j !== i) }))}><X /></Button>
              </div>
            ))}
            <Button variant="outline" size="sm" onClick={() => update((o) => ({ documentInfo: [...o.documentInfo, { key: o.documentInfo.length === 0 ? "Title" : "", value: "" }] }))}><Plus /> {t("details.addEntry")}</Button>
          </div>
        )}
      </Section>

      <Field label={t("details.operationId")} infoId="operationId" description={t("details.operationIdHint")}>
        <Input className="max-w-80 font-mono text-xs" value={options.operationId ?? ""} onChange={(e) => update({ operationId: e.target.value })} placeholder={t("details.operationIdPlaceholder")} />
      </Field>
    </div>
  )
}

function MetadataForm() {
  const { options, update, state } = useSigning()
  const m = options.metadata
  const set = (patch: Partial<typeof m>) => update((o) => ({ metadata: { ...o.metadata, ...patch } }))
  const policy = state("metadata.policy")
  const t = useT()
  return (
    <div className="grid gap-4 rounded-lg border p-4 sm:grid-cols-2">
      <Field label={t("details.form.signerName")}><Input value={m.signerName ?? ""} onChange={(e) => set({ signerName: e.target.value })} /></Field>
      <Field label={t("details.form.commitment")}>
        <Select value={m.commitmentType} onValueChange={(commitmentType) => set({ commitmentType })}>
          <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent>{commitments.map((c) => <SelectItem key={c} value={c}>{t(`details.commitments.${c}` as MessageKey)}</SelectItem>)}</SelectContent>
        </Select>
      </Field>
      <Field label={t("details.form.signerId")}><Input value={m.signerId ?? ""} onChange={(e) => set({ signerId: e.target.value })} /></Field>
      <Field label={t("details.form.signerIdType")}><Input value={m.signerIdType ?? ""} onChange={(e) => set({ signerIdType: e.target.value })} placeholder={t("details.form.signerIdTypePlaceholder")} /></Field>
      <Field label="Email"><Input value={m.email ?? ""} onChange={(e) => set({ email: e.target.value })} /></Field>
      <Field label={t("details.form.ip")}><Input value={m.ipAddress ?? ""} onChange={(e) => set({ ipAddress: e.target.value })} /></Field>
      <Field label={t("details.form.authMethod")}><Input value={m.authenticationMethod ?? ""} onChange={(e) => set({ authenticationMethod: e.target.value })} /></Field>
      <Field label={t("details.form.legalBasis")}><Input value={m.legalBasis ?? ""} onChange={(e) => set({ legalBasis: e.target.value })} /></Field>
      <Field label={t("details.form.institution")}><Input value={m.institutionName ?? ""} onChange={(e) => set({ institutionName: e.target.value })} /></Field>
      <div className="grid grid-cols-2 gap-2">
        <Field label={t("details.form.institutionId")}><Input value={m.institutionId ?? ""} onChange={(e) => set({ institutionId: e.target.value })} /></Field>
        <Field label={t("details.form.idType")}><Input value={m.institutionIdType ?? ""} onChange={(e) => set({ institutionIdType: e.target.value })} placeholder="CNPJ" /></Field>
      </div>
      {policy.visible ? (
        <>
          <Field label={t("details.form.policyOid")}><Input value={m.policyOid ?? ""} onChange={(e) => set({ policyOid: e.target.value })} className="font-mono text-xs" /></Field>
          <Field label={t("details.form.policyUri")}><Input value={m.policyUri ?? ""} onChange={(e) => set({ policyUri: e.target.value })} /></Field>
        </>
      ) : (
        <p className="text-muted-foreground text-xs sm:col-span-2">{policy.note}</p>
      )}
      <p className="text-muted-foreground text-xs sm:col-span-2">{t("details.form.metadataNote")}</p>
    </div>
  )
}

function AeaForm() {
  const { options, update } = useSigning()
  const a = options.aea
  const set = (patch: Partial<typeof a>) => update((o) => ({ aea: { ...o.aea, ...patch } }))
  const t = useT()
  return (
    <div className="grid gap-4 rounded-lg border p-4 sm:grid-cols-2">
      <Field label={t("details.form.signerName")}><Input value={a.signerName} onChange={(e) => set({ signerName: e.target.value })} /></Field>
      <Field label="CPF *" description={t("details.form.cpfHint")}><Input value={a.cpf} onChange={(e) => set({ cpf: e.target.value })} placeholder="111.444.777-35" /></Field>
      <Field label={t("details.form.authMethod")}>
        <Select value={a.authMethod} onValueChange={(authMethod) => set({ authMethod })}>
          <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent>{authMethods.map((c) => <SelectItem key={c} value={c}>{t(`details.authMethods.${c}` as MessageKey)}</SelectItem>)}</SelectContent>
        </Select>
      </Field>
      <Field label={t("details.form.commitment")}>
        <Select value={a.commitmentType} onValueChange={(commitmentType) => set({ commitmentType })}>
          <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent>{commitments.map((c) => <SelectItem key={c} value={c}>{t(`details.commitments.${c}` as MessageKey)}</SelectItem>)}</SelectContent>
        </Select>
      </Field>
      <Field label="Email"><Input value={a.email ?? ""} onChange={(e) => set({ email: e.target.value })} /></Field>
      <Field label={t("details.form.ip")}><Input value={a.ipAddress ?? ""} onChange={(e) => set({ ipAddress: e.target.value })} /></Field>
      <Field label={t("details.form.institution")}><Input value={a.institutionName ?? ""} onChange={(e) => set({ institutionName: e.target.value })} /></Field>
      <Field label={t("details.form.institutionCnpj")}><Input value={a.institutionCnpj ?? ""} onChange={(e) => set({ institutionCnpj: e.target.value })} /></Field>
      <Field label={t("details.form.policyOid")}><Input value={a.policyOid ?? ""} onChange={(e) => set({ policyOid: e.target.value })} className="font-mono text-xs" /></Field>
      <Field label={t("details.form.policyUri")}><Input value={a.policyUri ?? ""} onChange={(e) => set({ policyUri: e.target.value })} /></Field>
      <p className="text-muted-foreground text-xs sm:col-span-2">{t("details.form.aeaNote")}</p>
    </div>
  )
}

function HealthSection() {
  const { options, update, state } = useSigning()
  const h = options.health
  const set = (patch: Partial<typeof h>) => update((o) => ({ health: { ...o.health, ...patch } }))
  const setPro = (i: number, patch: Partial<ProfessionalChoice>) => set({ professionals: h.professionals.map((p, j) => (j === i ? { ...p, ...patch } : p)) })
  const t = useT()
  return (
    <div className="space-y-3">
      <ToggleRow checked={h.enabled} onChange={(enabled) => set({ enabled, professionals: enabled && h.professionals.length === 0 ? [{ council: "Cfm", registrationNumber: "", stateCode: "SP" }] : h.professionals })}
        state={state("health")} infoId="health" label={<span className="flex items-center gap-1.5"><Stethoscope className="size-4" /> {t("details.health.title")}</span>}
        description={t("details.health.hint")} />
      {h.enabled && !state("health").disabled && (
        <div className="space-y-3 rounded-lg border p-4">
          <Field label={t("details.health.type")}>
            <Select value={h.type} onValueChange={(type) => set({ type })}>
              <SelectTrigger className="w-64"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="Prescricao">{t("details.health.types.Prescricao")}</SelectItem>
                <SelectItem value="Atestado">{t("details.health.types.Atestado")}</SelectItem>
                <SelectItem value="SolicitacaoExame">{t("details.health.types.SolicitacaoExame")}</SelectItem>
                <SelectItem value="Relatorio">{t("details.health.types.Relatorio")}</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          {h.professionals.map((p, i) => (
            <div key={i} className="grid grid-cols-[110px_1fr_70px_1fr_auto] items-end gap-2">
              <Field label={t("details.health.council")}>
                <Select value={p.council} onValueChange={(council) => setPro(i, { council })}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>{councils.map((c) => <SelectItem key={c} value={c}>{c.toUpperCase()}</SelectItem>)}</SelectContent>
                </Select>
              </Field>
              <Field label={t("details.health.registration")}><Input value={p.registrationNumber} onChange={(e) => setPro(i, { registrationNumber: e.target.value })} /></Field>
              <Field label="UF"><Input value={p.stateCode ?? ""} maxLength={2} onChange={(e) => setPro(i, { stateCode: e.target.value.toUpperCase() })} /></Field>
              <Field label={t("details.health.specialty")}><Input value={p.specialty ?? ""} onChange={(e) => setPro(i, { specialty: e.target.value })} /></Field>
              <Button variant="ghost" size="icon" onClick={() => set({ professionals: h.professionals.filter((_, j) => j !== i) })}><X /></Button>
            </div>
          ))}
          <Button variant="outline" size="sm" onClick={() => set({ professionals: [...h.professionals, { council: "Cff", registrationNumber: "", stateCode: "SP" }] })}><Plus /> {t("details.health.add")}</Button>
        </div>
      )}
    </div>
  )
}
