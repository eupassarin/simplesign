import { useI18n } from "@/i18n"
import type { SandboxInfo } from "@/lib/types"
import { KeyValue, Section } from "@/components/parts"

/** What a client needs: the root to trust, the CRL, TSA and CSC addresses and their test credentials. */
export function EnvironmentPage({ info }: { info: SandboxInfo }) {
  const { t, date } = useI18n()
  return (
    <div className="space-y-8">
      <div className="grid gap-6 lg:grid-cols-2">
        <Section title={t("environment.trust")} description={t("environment.trustHint")}>
          <div className="rounded-lg border px-4 py-2">
            <KeyValue stacked label={t("environment.rootSubject")}>{info.rootSubject}</KeyValue>
            <KeyValue stacked mono label={t("environment.thumbprint")} copy={info.rootThumbprint}>{info.rootThumbprint}</KeyValue>
            <KeyValue stacked mono label={t("environment.rootPem")} copy={info.urls.rootPem}><a className="underline underline-offset-2" href={info.urls.rootPem}>{info.urls.rootPem}</a></KeyValue>
            <KeyValue stacked mono label={t("environment.chainPem")} copy={info.urls.chainPem}><a className="underline underline-offset-2" href={info.urls.chainPem}>{info.urls.chainPem}</a></KeyValue>
            <KeyValue label={t("environment.pfxPassword")} mono>{info.pfxPassword}</KeyValue>
            <p className="text-muted-foreground py-1 text-xs">{t("environment.created", { date: date(info.createdAt) })}</p>
          </div>
        </Section>
        <Section title={t("environment.access")} description={t("environment.accessHint")}>
          <div className="rounded-lg border px-4 py-2">
            <KeyValue stacked mono label="HTTP">{info.baseUrl}</KeyValue>
            <KeyValue stacked mono label="HTTPS">{info.httpsBaseUrl}</KeyValue>
            <KeyValue stacked mono label="LDAP">{info.ldapBaseUrl}</KeyValue>
            <KeyValue stacked mono label={t("environment.loopbackOrigins")} copy={info.loopbackOrigins.join("\n")}>{info.loopbackOrigins.join(", ")}</KeyValue>
            <pre className="bg-muted/40 overflow-auto rounded-md p-2 text-[11px] leading-relaxed">{`new OutboundHttpPolicy
{
    AllowLdap = true,
    LoopbackOrigins = [${info.loopbackOrigins.map((o) => `new Uri("${o}")`).join(", ")}],
}`}</pre>
          </div>
        </Section>
        <Section title={t("environment.tsa")} description={t("environment.tsaHint")}>
          <div className="rounded-lg border px-4 py-2">
            <KeyValue stacked mono label={t("environment.tsaUrl")} copy={info.tsa.url}>{info.tsa.url}</KeyValue>
            <KeyValue stacked mono label={t("environment.tsaAuthenticated")} copy={info.tsa.authenticatedUrl}>{info.tsa.authenticatedUrl}</KeyValue>
            <KeyValue label={t("environment.userPassword")} mono>{info.tsa.user} / {info.tsa.password}</KeyValue>
            <KeyValue stacked mono label={t("environment.tsaUntrusted")} copy={info.tsa.untrustedUrl}>{info.tsa.untrustedUrl}</KeyValue>
            <KeyValue stacked mono label={t("environment.tsaRevoked")} copy={info.tsa.revokedUrl}>{info.tsa.revokedUrl}</KeyValue>
            <KeyValue stacked mono label={t("environment.tsaWrongName", { name: info.tsa.wrongName })} copy={info.tsa.wrongNameUrl}>{info.tsa.wrongNameUrl}</KeyValue>
          </div>
        </Section>
        <Section title={t("environment.csc")} description={t("environment.cscHint")}>
          <div className="rounded-lg border px-4 py-2">
            <KeyValue stacked mono label={t("environment.cscBase")} copy={info.csc.baseUrl}>{info.csc.baseUrl}</KeyValue>
            <KeyValue label={t("environment.client")} mono>{info.csc.clientId} / {info.csc.clientSecret}</KeyValue>
            <KeyValue label={t("environment.serviceToken")} mono>{info.csc.serviceToken}</KeyValue>
            <KeyValue label={t("environment.pinOtp")} mono>{info.csc.pin} / {info.csc.otp}</KeyValue>
            <KeyValue stacked label={t("environment.credentials")}>
              <ul className="space-y-0.5">
                {info.csc.credentials.map((c) => <li key={c.id}><span className="font-mono text-xs">{c.id}</span> — {c.description}</li>)}
              </ul>
            </KeyValue>
          </div>
        </Section>
      </div>
      <Section title={t("environment.revocation")} description={t("environment.revocationHint")}>
        <div className="grid gap-3 lg:grid-cols-2">
          {info.authorities.map((a) => (
            <div key={a.id} className="rounded-lg border px-4 py-2">
              <p className="py-1 font-mono text-xs font-medium">{a.id}</p>
              <KeyValue stacked mono label="CRL (HTTP)" copy={a.crl}>{a.crl}</KeyValue>
              <KeyValue stacked mono label="CRL (HTTPS)" copy={a.httpsCrl}>{a.httpsCrl}</KeyValue>
              <KeyValue stacked mono label="CRL (LDAP)" copy={a.ldapCrl}>{a.ldapCrl}</KeyValue>
              <KeyValue stacked mono label="OCSP" copy={a.ocsp}>{a.ocsp}</KeyValue>
            </div>
          ))}
        </div>
      </Section>
      <Section title={t("environment.clients")} description={t("environment.clientsHint")}>
        <KeyValue stacked mono label="GET /api/info" copy={JSON.stringify(info, null, 2)}>
          <pre className="bg-muted/40 max-h-72 overflow-auto rounded-md p-3 text-[11px] leading-relaxed">{JSON.stringify(info, null, 2)}</pre>
        </KeyValue>
      </Section>
    </div>
  )
}
