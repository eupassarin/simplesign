import { Download } from "lucide-react"
import { Button } from "@/components/ui/button"
import { useI18n } from "@/i18n"
import type { SandboxInfo } from "@/lib/types"
import { CopyButton, Fold, KeyValue, Section } from "@/components/parts"

/** What a client needs: the essentials first (root, base URL, TSA, CSC), every other address and credential folded. */
export function EnvironmentPage({ info }: { info: SandboxInfo }) {
  const { t, date } = useI18n()
  const link = (url: string) => <a className="underline underline-offset-2" href={url}>{url}</a>
  return (
    <div className="space-y-6">
      <Section title={t("environment.quickStart")} description={t("environment.quickStartHint")}
        aside={
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" asChild><a href={info.urls.rootPem}><Download /> {t("environment.rootPem")}</a></Button>
            <Button variant="outline" size="sm" asChild><a href={info.urls.chainPem}><Download /> {t("environment.chainPem")}</a></Button>
          </div>
        }>
        <div className="grid gap-x-8 rounded-lg border px-4 py-2 md:grid-cols-2">
          <KeyValue stacked mono label={t("environment.baseUrl")} copy={info.baseUrl}>{info.baseUrl}</KeyValue>
          <KeyValue stacked mono label={t("environment.tsaUrl")} copy={info.tsa.url}>{info.tsa.url}</KeyValue>
          <KeyValue stacked mono label={`CSC — ${t("environment.cscBase")}`} copy={info.csc.baseUrl}>{info.csc.baseUrl}</KeyValue>
          <KeyValue stacked mono label={t("environment.pfxPassword")} copy={info.pfxPassword}>{info.pfxPassword}</KeyValue>
        </div>
      </Section>

      <Section title={t("environment.details")}>
        <div className="space-y-2">
          <Fold id="env.trust" title={t("environment.trust")} summary={t("environment.rootDetails")}>
            <p className="text-muted-foreground py-1 text-xs">{t("environment.trustHint")}</p>
            <KeyValue stacked label={t("environment.rootSubject")}>{info.rootSubject}</KeyValue>
            <KeyValue stacked mono label={t("environment.thumbprint")} copy={info.rootThumbprint}>{info.rootThumbprint}</KeyValue>
            <KeyValue stacked mono label={t("environment.rootPem")} copy={info.urls.rootPem}>{link(info.urls.rootPem)}</KeyValue>
            <KeyValue stacked mono label={t("environment.chainPem")} copy={info.urls.chainPem}>{link(info.urls.chainPem)}</KeyValue>
            <p className="text-muted-foreground py-1 text-xs">{t("environment.created", { date: date(info.createdAt) })}</p>
          </Fold>

          <Fold id="env.access" title={t("environment.access")} summary={t("environment.accessSummary")}>
            <p className="text-muted-foreground py-1 text-xs">{t("environment.accessHint")}</p>
            <KeyValue stacked mono label="HTTP" copy={info.baseUrl}>{info.baseUrl}</KeyValue>
            <KeyValue stacked mono label="HTTPS" copy={info.httpsBaseUrl}>{info.httpsBaseUrl}</KeyValue>
            <KeyValue stacked mono label="LDAP" copy={info.ldapBaseUrl}>{info.ldapBaseUrl}</KeyValue>
            <KeyValue stacked mono label={t("environment.loopbackOrigins")} copy={info.loopbackOrigins.join("\n")}>{info.loopbackOrigins.join(", ")}</KeyValue>
            <pre className="bg-muted/40 my-1.5 overflow-auto rounded-md p-2 text-[11px] leading-relaxed">{`new OutboundHttpPolicy
{
    AllowLdap = true,
    LoopbackOrigins = [${info.loopbackOrigins.map((o) => `new Uri("${o}")`).join(", ")}],
}`}</pre>
          </Fold>

          <Fold id="env.tsa" title={t("environment.tsa")} summary={t("environment.tsaSummary")}>
            <p className="text-muted-foreground py-1 text-xs">{t("environment.tsaHint")}</p>
            <KeyValue stacked mono label={t("environment.tsaUrl")} copy={info.tsa.url}>{info.tsa.url}</KeyValue>
            <KeyValue stacked mono label={t("environment.tsaAuthenticated")} copy={info.tsa.authenticatedUrl}>{info.tsa.authenticatedUrl}</KeyValue>
            <KeyValue label={t("environment.userPassword")} mono>{info.tsa.user} / {info.tsa.password}</KeyValue>
            <KeyValue stacked mono label={t("environment.tsaUntrusted")} copy={info.tsa.untrustedUrl}>{info.tsa.untrustedUrl}</KeyValue>
            <KeyValue stacked mono label={t("environment.tsaRevoked")} copy={info.tsa.revokedUrl}>{info.tsa.revokedUrl}</KeyValue>
            <KeyValue stacked mono label={t("environment.tsaWrongName", { name: info.tsa.wrongName })} copy={info.tsa.wrongNameUrl}>{info.tsa.wrongNameUrl}</KeyValue>
          </Fold>

          <Fold id="env.csc" title={t("environment.csc")} summary={t("environment.cscSummary", { n: info.csc.credentials.length })}>
            <p className="text-muted-foreground py-1 text-xs">{t("environment.cscHint")}</p>
            <KeyValue stacked mono label={t("environment.cscBase")} copy={info.csc.baseUrl}>{info.csc.baseUrl}</KeyValue>
            <KeyValue label={t("environment.client")} mono>{info.csc.clientId} / {info.csc.clientSecret}</KeyValue>
            <KeyValue label={t("environment.serviceToken")} mono copy={info.csc.serviceToken}>{info.csc.serviceToken}</KeyValue>
            <KeyValue label={t("environment.pinOtp")} mono>{info.csc.pin} / {info.csc.otp}</KeyValue>
            <KeyValue stacked label={t("environment.credentials")}>
              <ul className="space-y-0.5">
                {info.csc.credentials.map((c) => <li key={c.id}><span className="font-mono text-xs">{c.id}</span> — {c.description}</li>)}
              </ul>
            </KeyValue>
          </Fold>

          <Fold id="env.revocation" title={t("environment.revocation")} summary={t("environment.revocationSummary", { n: info.authorities.length })}>
            <p className="text-muted-foreground py-1 text-xs">{t("environment.revocationHint")}</p>
            <div className="grid gap-3 py-1.5 lg:grid-cols-2">
              {info.authorities.map((a) => (
                <div key={a.id} className="rounded-md border px-3 py-1.5">
                  <p className="py-1 font-mono text-xs font-medium">{a.id}</p>
                  <KeyValue stacked mono label="CRL (HTTP)" copy={a.crl}>{a.crl}</KeyValue>
                  <KeyValue stacked mono label="CRL (HTTPS)" copy={a.httpsCrl}>{a.httpsCrl}</KeyValue>
                  <KeyValue stacked mono label="CRL (LDAP)" copy={a.ldapCrl}>{a.ldapCrl}</KeyValue>
                  <KeyValue stacked mono label="OCSP" copy={a.ocsp}>{a.ocsp}</KeyValue>
                </div>
              ))}
            </div>
          </Fold>

          {info.trustedLists && (
            <Fold id="env.tl" title={t("environment.trustedLists")} summary={t("environment.trustedListsSummary", { territory: info.trustedLists.territory })}>
              <KeyValue stacked mono label={t("environment.lotl")} copy={info.trustedLists.lotlUrl}>{link(info.trustedLists.lotlUrl)}</KeyValue>
              <KeyValue stacked mono label={t("environment.tl")} copy={info.trustedLists.tlUrl}>{link(info.trustedLists.tlUrl)}</KeyValue>
              <KeyValue stacked mono label={t("environment.lotlSigner")} copy={info.trustedLists.lotlSignerUrl}>{link(info.trustedLists.lotlSignerUrl)}</KeyValue>
              <KeyValue stacked mono label={t("environment.tlSigner")} copy={info.trustedLists.tlSignerUrl}>{link(info.trustedLists.tlSignerUrl)}</KeyValue>
            </Fold>
          )}

          <Fold id="env.json" title={t("environment.clients")} summary={t("environment.clientsSummary")}
            aside={<CopyButton value={JSON.stringify(info, null, 2)} label="GET /api/info" />}>
            <p className="text-muted-foreground py-1 text-xs">{t("environment.clientsHint")}</p>
            <pre className="bg-muted/40 my-1.5 max-h-72 overflow-auto rounded-md p-3 text-[11px] leading-relaxed">{JSON.stringify(info, null, 2)}</pre>
          </Fold>
        </div>
      </Section>
    </div>
  )
}
