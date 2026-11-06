import { Input } from "@/components/ui/input"
import type { HashChoice, RsaPadding, SubFilterChoice } from "@/lib/types"
import { ChoiceCard, Field, Section, ToggleRow } from "../ui"
import { useSigning } from "../state"

const hashes: { id: HashChoice; title: string; text: string }[] = [
  { id: "Sha256", title: "SHA-256", text: "Default; what ICP-Brasil policies list." },
  { id: "Sha384", title: "SHA-384", text: "Common with P-384 keys." },
  { id: "Sha512", title: "SHA-512", text: "Longest SHA-2 digest." },
  { id: "Sha3_256", title: "SHA3-256", text: "SHA-3 family (FIPS 202)." },
  { id: "Sha3_384", title: "SHA3-384", text: "" },
  { id: "Sha3_512", title: "SHA3-512", text: "" },
]

const paddings: { id: RsaPadding; title: string; text: string }[] = [
  { id: "Pkcs1", title: "PKCS#1 v1.5", text: "sha256WithRSAEncryption & co. Supported everywhere." },
  { id: "Pss", title: "RSASSA-PSS", text: "Probabilistic; MGF1 with the same hash, salt = hash length." },
]

const subFilters: { id: SubFilterChoice; title: string; text: string }[] = [
  { id: "EtsiCadesDetached", title: "ETSI.CAdES.detached", text: "PAdES (ETSI EN 319 142). The default." },
  { id: "AdbePkcs7Detached", title: "adbe.pkcs7.detached", text: "Legacy PKCS#7, for PDF/A-1. B-B only." },
  { id: "PbadPades", title: "PBAD.PAdES", text: "/Filter /PBAD_PAdES — required by ICP-Brasil policies." },
]

export function CryptoStep() {
  const { options, update, state, report, credential } = useSigning()
  const effective = report?.effective
  const padding = state("padding")
  const subFilter = state("subFilter")
  return (
    <div className="space-y-8">
      <Section title="Digest algorithm" infoId="hash" description={credential ? `Filtered by what ${credential.holder} (${credential.source}) can produce.` : "Choose a signer to see what it supports."}>
        <div className="grid gap-3 sm:grid-cols-3">
          {hashes.map((h) => (
            <ChoiceCard key={h.id} selected={options.hash === h.id} onSelect={() => update({ hash: h.id })} title={h.title} description={h.text} state={state(`hash.${h.id}`)} />
          ))}
        </div>
      </Section>

      {padding.visible ? (
        <Section title="RSA signature scheme" infoId="padding">
          <div className="grid gap-3 sm:grid-cols-2">
            {paddings.map((p) => (
              <ChoiceCard key={p.id} selected={(effective?.padding ?? options.padding) === p.id} onSelect={() => update({ padding: p.id })} title={p.title} description={p.text} state={state(`padding.${p.id}`)} />
            ))}
          </div>
        </Section>
      ) : (
        padding.note && <p className="text-muted-foreground rounded-lg border border-dashed p-3 text-xs">{padding.note}</p>
      )}

      <Section title="Sub-filter" infoId="subFilter" description={subFilter.disabled ?? "How the PDF identifies the CMS format."}>
        <div className="grid gap-3 sm:grid-cols-3">
          {subFilters.map((s) => (
            <ChoiceCard key={s.id} selected={(effective?.subFilter ?? options.subFilter) === s.id} onSelect={() => update({ subFilter: s.id })} title={<span className="font-mono text-xs">{s.title}</span>} description={s.text} state={state(`subFilter.${s.id}`)} />
          ))}
        </div>
      </Section>

      <ToggleRow checked={options.preservePdfA} onChange={(preservePdfA) => update({ preservePdfA })} state={state("pdfa")} infoId="pdfa"
        label="Preserve PDF/A conformance" description="WithPdfAPreservation(): the library refuses options that would break the document's PDF/A level." />

      <Section title="Advanced">
        <Field label="Reserved /Contents size (bytes)" infoId="contents" description="Empty = 16384. Larger chains or long timestamps may need more.">
          <Input type="number" min={4096} max={200000} step={1024} className="max-w-48" value={options.contentsReservedBytes ?? ""}
            onChange={(e) => update({ contentsReservedBytes: e.target.value ? Number(e.target.value) : null })} placeholder="16384" />
        </Field>
      </Section>
    </div>
  )
}
