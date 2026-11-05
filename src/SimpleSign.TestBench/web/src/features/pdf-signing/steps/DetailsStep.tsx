import { BadgeCheck, FileSignature, Plus, Stethoscope, UserRound, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import type { CertificationChoice, ProfessionalChoice } from "@/lib/types"
import { ChoiceCard, Field, Section, ToggleRow } from "../ui"
import { useSigning } from "../state"

const commitments = ["ProofOfOrigin", "ProofOfReceipt", "ProofOfDelivery", "ProofOfSender", "ProofOfApproval", "ProofOfCreation"]
const authMethods = ["InstitutionalLogin", "DigitalCertificate", "GovBr", "FacialBiometrics", "TokenOtp", "UsernamePassword"]
const councils = ["Oab", "Cfm", "Cff", "Cfbio", "Cfbm", "Confef", "Cofen", "Coffito", "Cffa", "Cfmv", "Cfn", "Cfo", "Cfp", "Cfess", "Conter", "Cfq"]

const certifications: { id: CertificationChoice; title: string; text: string }[] = [
  { id: "None", title: "Approval signature", text: "A regular signature: no restriction on later changes." },
  { id: "NoChanges", title: "Certify, P=1", text: "No changes allowed, not even more signatures." },
  { id: "FormFilling", title: "Certify, P=2", text: "Form filling and further signatures allowed." },
  { id: "FormFillingAndAnnotations", title: "Certify, P=3", text: "Also annotations (comments)." },
]

export function DetailsStep() {
  const { options, update, state } = useSigning()
  const signer = state("details.signer")
  return (
    <div className="space-y-8">
      <Section title="Signature dictionary" infoId="details.basic" description="Shown by PDF viewers in the signature panel.">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Reason"><Input value={options.reason ?? ""} onChange={(e) => update({ reason: e.target.value })} placeholder="I approve this document" /></Field>
          <Field label="Location"><Input value={options.location ?? ""} onChange={(e) => update({ location: e.target.value })} placeholder="São Paulo, BR" /></Field>
          <Field label="Contact info"><Input value={options.contactInfo ?? ""} onChange={(e) => update({ contactInfo: e.target.value })} placeholder="email or phone" /></Field>
          <Field label="Signer name (/Name)" description="Default: from the certificate."><Input value={options.signerName ?? ""} onChange={(e) => update({ signerName: e.target.value })} /></Field>
        </div>
        <Field label="Claimed signing time" infoId="details.signingTime" description={state("details.signingTime").disabled ?? "Empty = now. A timestamp (B-T+) is the trusted time."}>
          <Input type="datetime-local" className="max-w-64" disabled={!!state("details.signingTime").disabled}
            value={options.signingTime ? options.signingTime.slice(0, 16) : ""}
            onChange={(e) => update({ signingTime: e.target.value ? new Date(e.target.value).toISOString() : null })} />
        </Field>
      </Section>

      <Section title="Signer details" description={signer.disabled ?? "Structured data in the CMS (signed attributes). Generic metadata, or the Brazilian AEA route."}>
        <div className="grid gap-3 sm:grid-cols-3">
          <ChoiceCard selected={!options.useSignerDetails} onSelect={() => update({ useSignerDetails: false })} title="None" description="Only the dictionary entries above." state={signer.disabled ? { visible: true } : undefined} />
          <ChoiceCard selected={options.useSignerDetails && options.signerDetails === "Metadata"} onSelect={() => update({ useSignerDetails: true, signerDetails: "Metadata" })}
            title="Signer metadata" infoId="details.Metadata" icon={<UserRound className="size-4" />} state={signer.disabled ? signer : state("details.Metadata")} />
          <ChoiceCard selected={options.useSignerDetails && options.signerDetails === "Aea"} onSelect={() => update({ useSignerDetails: true, signerDetails: "Aea" })}
            title="AEA (Lei 14.063)" infoId="details.Aea" icon={<BadgeCheck className="size-4" />} state={signer.disabled ? signer : state("details.Aea")} />
        </div>
        {options.useSignerDetails && !signer.disabled && options.signerDetails === "Metadata" && <MetadataForm />}
        {options.useSignerDetails && !signer.disabled && options.signerDetails === "Aea" && state("details.Aea").disabled == null && <AeaForm />}
      </Section>

      <Section title="Certification (DocMDP)" infoId="certification" description="Whether this signature restricts what can change afterwards.">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {certifications.map((c) => (
            <ChoiceCard key={c.id} selected={options.certification === c.id} onSelect={() => update({ certification: c.id })} title={c.title} description={c.text}
              icon={<FileSignature className="size-4" />} state={c.id === "None" ? undefined : state(`certification.${c.id}`)} />
          ))}
        </div>
      </Section>

      <HealthSection />

      <Section title="Document information" infoId="documentInfo" description={state("documentInfo").disabled ?? "Entries of the PDF Info dictionary, in the signed revision."}>
        {!state("documentInfo").disabled && (
          <div className="space-y-2">
            {options.documentInfo.map((entry, i) => (
              <div key={i} className="flex gap-2">
                <Input className="max-w-48 font-mono text-xs" value={entry.key} placeholder="Key" onChange={(e) => update((o) => ({ documentInfo: o.documentInfo.map((d, j) => (j === i ? { ...d, key: e.target.value } : d)) }))} />
                <Input value={entry.value} placeholder="Value" onChange={(e) => update((o) => ({ documentInfo: o.documentInfo.map((d, j) => (j === i ? { ...d, value: e.target.value } : d)) }))} />
                <Button variant="ghost" size="icon" onClick={() => update((o) => ({ documentInfo: o.documentInfo.filter((_, j) => j !== i) }))}><X /></Button>
              </div>
            ))}
            <Button variant="outline" size="sm" onClick={() => update((o) => ({ documentInfo: [...o.documentInfo, { key: o.documentInfo.length === 0 ? "Title" : "", value: "" }] }))}><Plus /> Add entry</Button>
          </div>
        )}
      </Section>

      <Field label="Operation id" infoId="operationId" description="Correlates logs and warnings of this signature.">
        <Input className="max-w-80 font-mono text-xs" value={options.operationId ?? ""} onChange={(e) => update({ operationId: e.target.value })} placeholder="e.g. order-1234" />
      </Field>
    </div>
  )
}

function MetadataForm() {
  const { options, update, state } = useSigning()
  const m = options.metadata
  const set = (patch: Partial<typeof m>) => update((o) => ({ metadata: { ...o.metadata, ...patch } }))
  const policy = state("metadata.policy")
  return (
    <div className="grid gap-4 rounded-lg border p-4 sm:grid-cols-2">
      <Field label="Signer name *"><Input value={m.signerName ?? ""} onChange={(e) => set({ signerName: e.target.value })} /></Field>
      <Field label="Commitment type">
        <Select value={m.commitmentType} onValueChange={(commitmentType) => set({ commitmentType })}>
          <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent>{commitments.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}</SelectContent>
        </Select>
      </Field>
      <Field label="Signer id"><Input value={m.signerId ?? ""} onChange={(e) => set({ signerId: e.target.value })} /></Field>
      <Field label="Signer id type"><Input value={m.signerIdType ?? ""} onChange={(e) => set({ signerIdType: e.target.value })} placeholder="CPF, passport…" /></Field>
      <Field label="Email"><Input value={m.email ?? ""} onChange={(e) => set({ email: e.target.value })} /></Field>
      <Field label="IP address"><Input value={m.ipAddress ?? ""} onChange={(e) => set({ ipAddress: e.target.value })} /></Field>
      <Field label="Authentication method"><Input value={m.authenticationMethod ?? ""} onChange={(e) => set({ authenticationMethod: e.target.value })} /></Field>
      <Field label="Legal basis"><Input value={m.legalBasis ?? ""} onChange={(e) => set({ legalBasis: e.target.value })} /></Field>
      <Field label="Institution"><Input value={m.institutionName ?? ""} onChange={(e) => set({ institutionName: e.target.value })} /></Field>
      <div className="grid grid-cols-2 gap-2">
        <Field label="Institution id"><Input value={m.institutionId ?? ""} onChange={(e) => set({ institutionId: e.target.value })} /></Field>
        <Field label="Id type"><Input value={m.institutionIdType ?? ""} onChange={(e) => set({ institutionIdType: e.target.value })} placeholder="CNPJ" /></Field>
      </div>
      {policy.visible ? (
        <>
          <Field label="Policy OID"><Input value={m.policyOid ?? ""} onChange={(e) => set({ policyOid: e.target.value })} className="font-mono text-xs" /></Field>
          <Field label="Policy URI"><Input value={m.policyUri ?? ""} onChange={(e) => set({ policyUri: e.target.value })} /></Field>
        </>
      ) : (
        <p className="text-muted-foreground text-xs sm:col-span-2">{policy.note}</p>
      )}
      <p className="text-muted-foreground text-xs sm:col-span-2">Reason, location and contact come from the fields above. Empty contact info is built from the id, email, IP and institution.</p>
    </div>
  )
}

function AeaForm() {
  const { options, update } = useSigning()
  const a = options.aea
  const set = (patch: Partial<typeof a>) => update((o) => ({ aea: { ...o.aea, ...patch } }))
  return (
    <div className="grid gap-4 rounded-lg border p-4 sm:grid-cols-2">
      <Field label="Signer name *"><Input value={a.signerName} onChange={(e) => set({ signerName: e.target.value })} /></Field>
      <Field label="CPF *" description="Masked in the manifest (***.444.777-**)."><Input value={a.cpf} onChange={(e) => set({ cpf: e.target.value })} placeholder="111.444.777-35" /></Field>
      <Field label="Authentication method">
        <Select value={a.authMethod} onValueChange={(authMethod) => set({ authMethod })}>
          <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent>{authMethods.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}</SelectContent>
        </Select>
      </Field>
      <Field label="Commitment type">
        <Select value={a.commitmentType} onValueChange={(commitmentType) => set({ commitmentType })}>
          <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent>{commitments.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}</SelectContent>
        </Select>
      </Field>
      <Field label="Email"><Input value={a.email ?? ""} onChange={(e) => set({ email: e.target.value })} /></Field>
      <Field label="IP address"><Input value={a.ipAddress ?? ""} onChange={(e) => set({ ipAddress: e.target.value })} /></Field>
      <Field label="Institution"><Input value={a.institutionName ?? ""} onChange={(e) => set({ institutionName: e.target.value })} /></Field>
      <Field label="Institution CNPJ"><Input value={a.institutionCnpj ?? ""} onChange={(e) => set({ institutionCnpj: e.target.value })} /></Field>
      <Field label="Policy OID"><Input value={a.policyOid ?? ""} onChange={(e) => set({ policyOid: e.target.value })} className="font-mono text-xs" /></Field>
      <Field label="Policy URI"><Input value={a.policyUri ?? ""} onChange={(e) => set({ policyUri: e.target.value })} /></Field>
      <p className="text-muted-foreground text-xs sm:col-span-2">AEA sets the reason (“ADVANCED ELECTRONIC SIGNATURE (Lei 14.063/2020)”) and the location (institution) itself.</p>
    </div>
  )
}

function HealthSection() {
  const { options, update, state } = useSigning()
  const h = options.health
  const set = (patch: Partial<typeof h>) => update((o) => ({ health: { ...o.health, ...patch } }))
  const setPro = (i: number, patch: Partial<ProfessionalChoice>) => set({ professionals: h.professionals.map((p, j) => (j === i ? { ...p, ...patch } : p)) })
  return (
    <div className="space-y-3">
      <ToggleRow checked={h.enabled} onChange={(enabled) => set({ enabled, professionals: enabled && h.professionals.length === 0 ? [{ council: "Cfm", registrationNumber: "", stateCode: "SP" }] : h.professionals })}
        state={state("health")} infoId="health" label={<span className="flex items-center gap-1.5"><Stethoscope className="size-4" /> Health document</span>}
        description="Prescription, medical certificate, exam request or report, with the professionals' registrations." />
      {h.enabled && !state("health").disabled && (
        <div className="space-y-3 rounded-lg border p-4">
          <Field label="Document type">
            <Select value={h.type} onValueChange={(type) => set({ type })}>
              <SelectTrigger className="w-64"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="Prescricao">Prescrição</SelectItem>
                <SelectItem value="Atestado">Atestado</SelectItem>
                <SelectItem value="SolicitacaoExame">Solicitação de exame</SelectItem>
                <SelectItem value="Relatorio">Relatório</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          {h.professionals.map((p, i) => (
            <div key={i} className="grid grid-cols-[110px_1fr_70px_1fr_auto] items-end gap-2">
              <Field label="Council">
                <Select value={p.council} onValueChange={(council) => setPro(i, { council })}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>{councils.map((c) => <SelectItem key={c} value={c}>{c.toUpperCase()}</SelectItem>)}</SelectContent>
                </Select>
              </Field>
              <Field label="Registration"><Input value={p.registrationNumber} onChange={(e) => setPro(i, { registrationNumber: e.target.value })} /></Field>
              <Field label="UF"><Input value={p.stateCode ?? ""} maxLength={2} onChange={(e) => setPro(i, { stateCode: e.target.value.toUpperCase() })} /></Field>
              <Field label="Specialty"><Input value={p.specialty ?? ""} onChange={(e) => setPro(i, { specialty: e.target.value })} /></Field>
              <Button variant="ghost" size="icon" onClick={() => set({ professionals: h.professionals.filter((_, j) => j !== i) })}><X /></Button>
            </div>
          ))}
          <Button variant="outline" size="sm" onClick={() => set({ professionals: [...h.professionals, { council: "Cff", registrationNumber: "", stateCode: "SP" }] })}><Plus /> Add professional</Button>
        </div>
      )}
    </div>
  )
}
