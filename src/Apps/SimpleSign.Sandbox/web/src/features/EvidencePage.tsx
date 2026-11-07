import { Download } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Pill, Section } from "@/components/parts"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type { CrlFault, OcspFault, SandboxFaults, TsaFault } from "@/lib/types"

/** One scenario: the certificate (or TSA) to use, the failure to switch on, and what a correct client does. */
interface Scenario {
  key: string
  requirement: string
  certificate?: string
  faults?: { crl?: CrlFault; ocsp?: OcspFault; tsa?: TsaFault }
}

const scenarios: Scenario[] = [
  { key: "crlHttp", requirement: "11", certificate: "revoked" },
  { key: "crlHttps", requirement: "11", certificate: "revoked-crl-https" },
  { key: "crlLdap", requirement: "11", certificate: "revoked-crl-ldap" },
  { key: "ocsp", requirement: "11", certificate: "revoked-ocsp" },
  { key: "chain", requirement: "11", certificate: "under-revoked-ca" },
  { key: "crlSignature", requirement: "11", certificate: "good-crl-https", faults: { crl: "WrongKey" } },
  { key: "crlExpired", requirement: "11", certificate: "good-crl-https", faults: { crl: "Expired" } },
  { key: "crlNotUpdated", requirement: "11", certificate: "good-crl-https" },
  { key: "ocspUnauthorized", requirement: "11", certificate: "revoked-ocsp", faults: { ocsp: "Unauthorized" } },
  { key: "revocationDown", requirement: "11", certificate: "good-crl-https", faults: { crl: "Down" } },
  { key: "control", requirement: "11", certificate: "good-ocsp" },
  { key: "expired", requirement: "12", certificate: "expired" },
  { key: "notYetValid", requirement: "12", certificate: "not-yet-valid" },
  { key: "expiredCa", requirement: "12", certificate: "under-expired-ca" },
  { key: "weakKey", requirement: "13", certificate: "rsa-1024" },
  { key: "keyUsage", requirement: "16", certificate: "no-signing-key-usage" },
  { key: "tsaRevoked", requirement: "30" },
  { key: "tsaWrongName", requirement: "30" },
  { key: "tsaUntrusted", requirement: "30" },
]

/** The certification scenarios the Sandbox can show, ready to run against the application under evaluation. */
export function EvidencePage({ faults, onFaults }: { faults: SandboxFaults | null; onFaults: (faults: SandboxFaults) => void }) {
  const { t } = useI18n()
  const apply = async (scenario: Scenario) => {
    if (!faults) return
    try {
      const saved = await api.setFaults({ ...faults, crl: "None", ocsp: "None", tsa: "None", ...scenario.faults })
      onFaults(saved)
      toast.success(t("evidence.applied"))
    } catch (e) {
      toast.error(t("common.error"), { description: (e as Error).message })
    }
  }
  const groups = [...new Set(scenarios.map((s) => s.requirement))]
  return (
    <div className="space-y-8">
      <p className="text-muted-foreground max-w-3xl text-sm">{t("evidence.intro")}</p>
      {groups.map((requirement) => (
        <Section key={requirement} title={t(`evidence.requirements.r${requirement}` as MessageKey)}>
          <div className="grid gap-3 lg:grid-cols-2">
            {scenarios.filter((s) => s.requirement === requirement).map((s) => (
              <div key={s.key} className="space-y-2 rounded-lg border p-4">
                <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
                  <Pill tone="info">{t("pki.evidence", { req: s.requirement })}</Pill>
                  {t(`evidence.items.${s.key}.title` as MessageKey)}
                </p>
                <p className="text-sm"><span className="text-muted-foreground text-xs">{t("evidence.setup")} </span>{t(`evidence.items.${s.key}.setup` as MessageKey)}</p>
                <p className="text-sm"><span className="text-muted-foreground text-xs">{t("evidence.expected")} </span>{t(`evidence.items.${s.key}.expected` as MessageKey)}</p>
                <div className="flex flex-wrap gap-2 pt-1">
                  {s.certificate && (
                    <Button variant="outline" size="sm" asChild><a href={api.pfxUrl(s.certificate)}><Download /> {s.certificate}.pfx</a></Button>
                  )}
                  {s.faults && <Button size="sm" onClick={() => void apply(s)}>{t("evidence.apply")}</Button>}
                </div>
              </div>
            ))}
          </div>
        </Section>
      ))}
    </div>
  )
}
