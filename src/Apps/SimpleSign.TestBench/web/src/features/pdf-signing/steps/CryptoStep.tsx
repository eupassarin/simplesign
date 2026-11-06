import { Input } from "@/components/ui/input"
import { useT, type MessageKey } from "@/i18n"
import type { HashChoice, RsaPadding, SubFilterChoice } from "@/lib/types"
import { ChoiceCard, Field, Section, ToggleRow } from "../ui"
import { useSigning } from "../state"

export const hashes: { id: HashChoice; title: string }[] = [
  { id: "Sha256", title: "SHA-256" },
  { id: "Sha384", title: "SHA-384" },
  { id: "Sha512", title: "SHA-512" },
  { id: "Sha3_256", title: "SHA3-256" },
  { id: "Sha3_384", title: "SHA3-384" },
  { id: "Sha3_512", title: "SHA3-512" },
]

export const paddings: { id: RsaPadding; title: string }[] = [
  { id: "Pkcs1", title: "PKCS#1 v1.5" },
  { id: "Pss", title: "RSASSA-PSS" },
]

const subFilters: { id: SubFilterChoice; title: string }[] = [
  { id: "EtsiCadesDetached", title: "ETSI.CAdES.detached" },
  { id: "AdbePkcs7Detached", title: "adbe.pkcs7.detached" },
  { id: "PbadPades", title: "PBAD.PAdES" },
]

export function CryptoStep() {
  const { options, update, state, report, credential } = useSigning()
  const effective = report?.effective
  const padding = state("padding")
  const subFilter = state("subFilter")
  const t = useT()
  return (
    <div className="space-y-8">
      <Section title={t("crypto.hash")} infoId="hash" description={credential ? t("crypto.hashFiltered", { holder: credential.holder, source: credential.source }) : t("crypto.hashNoSigner")}>
        <div className="grid gap-3 sm:grid-cols-3">
          {hashes.map((h) => (
            <ChoiceCard key={h.id} selected={options.hash === h.id} onSelect={() => update({ hash: h.id })} title={h.title} description={t(`crypto.hashes.${h.id}` as MessageKey)} state={state(`hash.${h.id}`)} />
          ))}
        </div>
      </Section>

      {padding.visible ? (
        <Section title={t("crypto.padding")} infoId="padding">
          <div className="grid gap-3 sm:grid-cols-2">
            {paddings.map((p) => (
              <ChoiceCard key={p.id} selected={(effective?.padding ?? options.padding) === p.id} onSelect={() => update({ padding: p.id })} title={p.title} description={t(`crypto.paddings.${p.id}` as MessageKey)} state={state(`padding.${p.id}`)} />
            ))}
          </div>
        </Section>
      ) : (
        padding.note && <p className="text-muted-foreground rounded-lg border border-dashed p-3 text-xs">{padding.note}</p>
      )}

      <Section title="Sub-filter" infoId="subFilter" description={subFilter.disabled ?? t("crypto.subFilterHint")}>
        <div className="grid gap-3 sm:grid-cols-3">
          {subFilters.map((s) => (
            <ChoiceCard key={s.id} selected={(effective?.subFilter ?? options.subFilter) === s.id} onSelect={() => update({ subFilter: s.id })} title={<span className="font-mono text-xs">{s.title}</span>} description={t(`crypto.subFilters.${s.id}` as MessageKey)} state={state(`subFilter.${s.id}`)} />
          ))}
        </div>
      </Section>

      <ToggleRow checked={options.preservePdfA} onChange={(preservePdfA) => update({ preservePdfA })} state={state("pdfa")} infoId="pdfa"
        label={t("crypto.pdfa")} description={t("crypto.pdfaHint")} />

      <Section title={t("crypto.advanced")}>
        <Field label={t("crypto.contents")} infoId="contents" description={t("crypto.contentsHint")}>
          <Input type="number" min={4096} max={200000} step={1024} className="max-w-48" value={options.contentsReservedBytes ?? ""}
            onChange={(e) => update({ contentsReservedBytes: e.target.value ? Number(e.target.value) : null })} placeholder="16384" />
        </Field>
      </Section>
    </div>
  )
}
