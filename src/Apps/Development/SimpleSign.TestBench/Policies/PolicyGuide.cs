using System.Globalization;
using SimpleSign.TestBench.Localization;

namespace SimpleSign.TestBench.Policies;

/// <summary>What one element of a policy file means, in English and Portuguese, and the clause that defines it.</summary>
internal sealed record PolicyGuideEntry(string English, string Portuguese, string? Standard = null)
{
    /// <summary>The text in the language of the current UI culture.</summary>
    public string Text => L.Language(CultureInfo.CurrentUICulture) == "pt-BR" ? Portuguese : English;
}

/// <summary>
/// Explanations of the elements of the policy files (of SimpleSign's validation and signing policies), shown by the policy viewer. An element missing here gets the generic text of its kind.
/// </summary>
internal static class PolicyGuide
{
    private const string Bv = "EN 319 102-1 §5.2";
    private const string Xcv = "EN 319 102-1 §5.2.6";
    private const string Crypto = "EN 319 102-1 §5.2.7 · TS 119 312";
    private const string Ltv = "EN 319 102-1 §5.5";
    private const string Tl = "TS 119 612";
    private const string Pdf = "EN 319 142-1 · ISO 32000-2 §12.8";
    private const string Qc = "EN 319 412-5";

    private static readonly Dictionary<string, PolicyGuideEntry> s_entries = new(StringComparer.Ordinal)
    {
        // ── Roots and sections ─────────────────────────────────────────────
        ["ValidationConstraints"] = new("The validation policy: which checks the validator makes and how much each one weighs.", "A política de validação: quais verificações o validador faz e quanto pesa cada uma.", "EN 319 102-1 §5.1.3 · TS 119 172-1"),
        ["SigningConstraints"] = new("The signing policy: the checks SimpleSign makes on the certificate, key and algorithms before signing.", "A política de assinatura: as verificações que o SimpleSign faz no certificado, na chave e nos algoritmos antes de assinar.", "TS 119 172-1"),
        ["SignatureConstraints"] = new("Constraints on each signature.", "Restrições sobre cada assinatura.", Bv),
        ["CounterSignatureConstraints"] = new("Constraints on countersignatures (a signature over another signature).", "Restrições sobre contra-assinaturas (uma assinatura sobre outra assinatura).", Bv),
        ["Timestamp"] = new("Constraints on timestamps (signature, archive and document timestamps).", "Restrições sobre carimbos do tempo (de assinatura, de arquivo e de documento).", "EN 319 102-1 §5.4"),
        ["Revocation"] = new("Constraints on the revocation data (CRLs and OCSP responses).", "Restrições sobre os dados de revogação (LCRs e respostas OCSP).", Xcv),
        ["BasicSignatureConstraints"] = new("The basic checks of a signature or token: integrity, signature value, certificate chain, certificates and cryptography.", "As verificações básicas de uma assinatura ou token: integridade, valor da assinatura, cadeia, certificados e criptografia.", Bv),
        ["SignedAttributes"] = new("Constraints on the signed attributes (signed properties) of the signature.", "Restrições sobre os atributos assinados (propriedades assinadas) da assinatura.", "EN 319 122-1 §5.2 · EN 319 132-1 §5.2"),
        ["UnsignedAttributes"] = new("Constraints on the unsigned attributes: timestamps and validation data added after signing.", "Restrições sobre os atributos não assinados: carimbos e dados de validação acrescentados depois da assinatura.", "EN 319 122-1 §5.3"),
        ["SigningCertificate"] = new("Constraints on the certificate of the signer (or of the TSA, or of the revocation issuer, depending on where it is).", "Restrições sobre o certificado do signatário (ou da ACT, ou do emissor da revogação, conforme onde está).", Xcv),
        ["CACertificate"] = new("Constraints on the certificates of the certification authorities of the chain.", "Restrições sobre os certificados das autoridades certificadoras da cadeia.", Xcv),
        ["TrustedLists"] = new("Constraints on the trusted lists (ETSI TS 119 612) the trust anchors come from.", "Restrições sobre as listas de confiança (ETSI TS 119 612) de onde vêm as âncoras.", Tl),
        ["Model"] = new("The validation model of the chain: SHELL (every certificate valid at the validation time), CHAIN (each certificate valid when it issued the next one) or HYBRID (the CA certificates at the issuance of the signing certificate).", "O modelo de validação da cadeia: SHELL (todo certificado válido no momento da validação), CHAIN (cada certificado válido quando emitiu o seguinte) ou HYBRID (os certificados de AC na emissão do certificado do signatário).", Xcv),

        // ── Cryptography ───────────────────────────────────────────────────
        ["Cryptographic"] = new("The accepted algorithms, key sizes and expiration dates. Empty in a context, it takes the one of the enclosing context (in the end, the global one).", "Os algoritmos, tamanhos de chave e datas de expiração aceitos. Vazio num contexto, vale o do contexto acima (no fim, o global).", Crypto),
        ["AcceptableEncryptionAlgo"] = new("The signature (public key) algorithms accepted: RSA, RSASSA-PSS, ECDSA, DSA, EdDSA…", "Os algoritmos de assinatura (chave pública) aceitos: RSA, RSASSA-PSS, ECDSA, DSA, EdDSA…", Crypto),
        ["MiniPublicKeySize"] = new("The minimum key size of each algorithm, in bits.", "O tamanho mínimo de chave de cada algoritmo, em bits.", Crypto),
        ["AcceptableDigestAlgo"] = new("The hash algorithms accepted.", "Os algoritmos de hash aceitos.", Crypto),
        ["AlgoExpirationDate"] = new("Until when each algorithm (and key size) is considered secure. After the date the check fails, unless a proof of existence before the date exists. Past UpdateDate, LevelAfterUpdate applies.", "Até quando cada algoritmo (e tamanho de chave) é considerado seguro. Depois da data a verificação falha, a não ser que haja prova de existência anterior. Passada a UpdateDate, vale o LevelAfterUpdate.", Crypto),

        // ── Basic signature constraints ────────────────────────────────────
        ["ReferenceDataExistence"] = new("The signed data (each reference) can be found.", "Os dados assinados (cada referência) foram encontrados.", "EN 319 102-1 §5.2.7"),
        ["ReferenceDataIntact"] = new("The signed data was not changed: its digest matches the one in the signature.", "Os dados assinados não foram alterados: o hash confere com o da assinatura.", "EN 319 102-1 §5.2.7"),
        ["SignatureIntact"] = new("The signature value is correct for the signed data and the signer's public key.", "O valor da assinatura está correto para os dados assinados e a chave pública do signatário.", "EN 319 102-1 §5.2.7"),
        ["SignatureValid"] = new("The signature is valid as a whole (used for timestamps and revocation tokens).", "A assinatura é válida como um todo (usado para carimbos e tokens de revogação)."),
        ["SignatureDuplicated"] = new("The signature identifier is not used by another signature.", "O identificador da assinatura não é usado por outra assinatura."),
        ["ProspectiveCertificateChain"] = new("A chain can be built from the signing certificate to a trust anchor.", "É possível montar uma cadeia do certificado do signatário até uma âncora de confiança.", Xcv),
        ["SignerInformationStore"] = new("The CMS SignerInfo can be found and is unique.", "O SignerInfo do CMS foi encontrado e é único.", "RFC 5652"),
        ["ByteRange"] = new("The PDF ByteRange is well formed and covers the signature dictionary correctly.", "O ByteRange do PDF está bem formado e cobre corretamente o dicionário de assinatura.", Pdf),
        ["ByteRangeCollision"] = new("The ByteRanges of different signatures do not overlap in a suspicious way.", "Os ByteRanges de assinaturas diferentes não se sobrepõem de forma suspeita.", Pdf),
        ["ByteRangeAllDocument"] = new("The ByteRange of the last signature covers the whole file.", "O ByteRange da última assinatura cobre o arquivo inteiro.", Pdf),
        ["PdfSignatureDictionary"] = new("The PDF signature dictionary is consistent with the CMS it carries.", "O dicionário de assinatura do PDF é coerente com o CMS que carrega.", Pdf),
        ["PdfPageDifference"] = new("No page was added or removed after signing.", "Nenhuma página foi acrescentada ou removida depois da assinatura.", Pdf),
        ["PdfAnnotationOverlap"] = new("No annotation added after signing covers the visible content.", "Nenhuma anotação acrescentada depois da assinatura cobre o conteúdo visível.", Pdf),
        ["DocMDP"] = new("The changes after a certification signature respect its DocMDP permissions.", "As alterações depois de uma assinatura de certificação respeitam as permissões DocMDP.", Pdf),
        ["FieldMDP"] = new("The changes respect the FieldMDP locks of the signature fields.", "As alterações respeitam os bloqueios FieldMDP dos campos de assinatura.", Pdf),
        ["SigFieldLock"] = new("The changes respect the /Lock dictionary of the signature field.", "As alterações respeitam o dicionário /Lock do campo de assinatura.", Pdf),
        ["FormFillChanges"] = new("Form fields were filled after signing.", "Campos de formulário foram preenchidos depois da assinatura.", Pdf),
        ["AnnotationChanges"] = new("Annotations were added, changed or removed after signing.", "Anotações foram acrescentadas, alteradas ou removidas depois da assinatura.", Pdf),
        ["UndefinedChanges"] = new("Other changes after signing that cannot be classified.", "Outras alterações depois da assinatura que não podem ser classificadas.", Pdf),
        ["TrustServiceTypeIdentifier"] = new("The service type of the trusted list entry of the issuer (for example CA/QC).", "O tipo de serviço da entrada da lista de confiança do emissor (por exemplo CA/QC).", Tl),
        ["TrustServiceStatus"] = new("The status of the trusted list entry of the issuer (granted, withdrawn…).", "O status da entrada da lista de confiança do emissor (concedido, retirado…).", Tl),

        // ── Certificate constraints ────────────────────────────────────────
        ["Recognition"] = new("The certificate can be identified (it is present in the signature or in the validation data).", "O certificado pode ser identificado (está na assinatura ou nos dados de validação).", Xcv),
        ["Signature"] = new("The certificate's own signature is correct (checked with its issuer's key).", "A assinatura do próprio certificado está correta (verificada com a chave do emissor).", Xcv),
        ["NotExpired"] = new("The certificate is within its validity period (notBefore–notAfter) at the reference time.", "O certificado está dentro da validade (notBefore–notAfter) no momento de referência.", Xcv),
        ["AuthorityInfoAccessPresent"] = new("The certificate has the Authority Information Access extension.", "O certificado tem a extensão Authority Information Access.", "RFC 5280 §4.2.2.1"),
        ["RevocationDataSkip"] = new("Certificates (by extension or policy) for which no revocation data is needed, such as OCSP responder certificates with id-pkix-ocsp-nocheck.", "Certificados (por extensão ou política) para os quais dados de revogação não são necessários, como os do respondedor OCSP com id-pkix-ocsp-nocheck.", "RFC 6960 §4.2.2.2.1"),
        ["CertificateExtensions"] = new("The extension OIDs that make a certificate skip the revocation check.", "Os OIDs de extensão que dispensam um certificado da verificação de revogação."),
        ["CertificatePolicies"] = new("The certificate policy OIDs that make a certificate skip the revocation check.", "Os OIDs de política que dispensam um certificado da verificação de revogação."),
        ["RevocationInfoAccessPresent"] = new("The certificate says where its revocation data is (CRL distribution points or OCSP).", "O certificado informa onde estão os dados de revogação (pontos de distribuição de LCR ou OCSP).", "RFC 5280 §4.2.1.13"),
        ["RevocationDataAvailable"] = new("Revocation data (CRL or OCSP) for the certificate was found.", "Foram encontrados dados de revogação (LCR ou OCSP) do certificado.", Xcv),
        ["AcceptableRevocationDataFound"] = new("Among the revocation data found, at least one is acceptable (valid and trusted).", "Entre os dados de revogação encontrados, ao menos um é aceitável (válido e confiável).", Xcv),
        ["CRLNextUpdatePresent"] = new("The CRL has a nextUpdate field.", "A LCR tem o campo nextUpdate.", "RFC 5280 §5.1.2.5"),
        ["OCSPNextUpdatePresent"] = new("The OCSP response has a nextUpdate field.", "A resposta OCSP tem o campo nextUpdate.", "RFC 6960 §4.2.2.1"),
        ["RevocationFreshness"] = new("The revocation data is recent enough: issued at most Value Unit before the reference time (0 means after the best signature time).", "Os dados de revogação são recentes o bastante: emitidos no máximo Value Unit antes do momento de referência (0 significa depois do melhor momento da assinatura).", "EN 319 102-1 §5.2.5"),
        ["RevocationFreshnessNextUpdate"] = new("The revocation data is fresh by its own nextUpdate.", "Os dados de revogação estão atualizados segundo o próprio nextUpdate.", "EN 319 102-1 §5.2.5"),
        ["CA"] = new("The issuer certificates are CA certificates (basicConstraints cA=true).", "Os certificados emissores são certificados de AC (basicConstraints cA=true).", "RFC 5280 §4.2.1.9"),
        ["MaxPathLength"] = new("The chain respects the pathLenConstraint of each CA.", "A cadeia respeita o pathLenConstraint de cada AC.", "RFC 5280 §4.2.1.9"),
        ["KeyUsage"] = new("The key usage of the certificate includes one of the listed values (for signatures: nonRepudiation or digitalSignature).", "O key usage do certificado inclui um dos valores listados (para assinaturas: nonRepudiation ou digitalSignature).", "RFC 5280 §4.2.1.3"),
        ["ExtendedKeyUsage"] = new("The extended key usage of the certificate includes one of the listed values (for a TSA: timeStamping).", "O extended key usage do certificado inclui um dos valores listados (para uma ACT: timeStamping).", "RFC 5280 §4.2.1.12"),
        ["PolicyTree"] = new("The certificate policies of the chain form a valid policy tree.", "As políticas de certificado da cadeia formam uma árvore de políticas válida.", "RFC 5280 §6.1"),
        ["NameConstraints"] = new("The chain respects the name constraints of the CAs.", "A cadeia respeita as restrições de nome das ACs.", "RFC 5280 §4.2.1.10"),
        ["AuthorityKeyIdentifierPresent"] = new("The certificate has the Authority Key Identifier extension.", "O certificado tem a extensão Authority Key Identifier.", "RFC 5280 §4.2.1.1"),
        ["SubjectKeyIdentifierPresent"] = new("The certificate has the Subject Key Identifier extension.", "O certificado tem a extensão Subject Key Identifier.", "RFC 5280 §4.2.1.2"),
        ["NoRevAvail"] = new("The certificate declares that no revocation information is available (noRevAvail), which is accepted.", "O certificado declara que não há informação de revogação (noRevAvail), o que é aceito.", "RFC 9608"),
        ["SupportedCriticalExtensions"] = new("Every critical extension of the certificate is one the validator supports.", "Toda extensão crítica do certificado é uma que o validador suporta.", "RFC 5280 §4.2"),
        ["ForbiddenExtensions"] = new("The certificate has none of the listed extensions (for example ocsp-nocheck on a signer).", "O certificado não tem nenhuma das extensões listadas (por exemplo ocsp-nocheck num signatário).", "RFC 5280 §4.2"),
        ["IssuerName"] = new("The issuer name of the certificate matches the subject name of its issuer.", "O nome do emissor do certificado confere com o nome do titular do emissor.", "RFC 5280 §4.1.2.4"),
        ["SerialNumberPresent"] = new("The subject name has a serialNumber attribute.", "O nome do titular tem o atributo serialNumber.", "EN 319 412-1"),
        ["NotRevoked"] = new("The certificate is not revoked at the reference time.", "O certificado não está revogado no momento de referência.", Xcv),
        ["NotOnHold"] = new("The certificate is not suspended (certificateHold).", "O certificado não está suspenso (certificateHold).", "RFC 5280 §5.3.1"),
        ["RevocationIssuerNotExpired"] = new("The issuer of the revocation data was valid when it issued it.", "O emissor dos dados de revogação estava válido quando os emitiu.", Xcv),
        ["SelfSigned"] = new("The certificate is self-signed.", "O certificado é autoassinado.", "RFC 5280"),
        ["NotSelfSigned"] = new("The signing certificate is not self-signed.", "O certificado do signatário não é autoassinado.", "RFC 5280"),
        ["PolicyIds"] = new("The certificate has one of the listed certificate policy OIDs.", "O certificado tem um dos OIDs de política de certificado listados.", "RFC 5280 §4.2.1.4"),
        ["QcCompliance"] = new("The certificate has the QcCompliance statement (EU qualified certificate).", "O certificado tem a declaração QcCompliance (certificado qualificado da UE).", Qc),
        ["QcSSCD"] = new("The certificate has the QcSSCD statement (the key is in a qualified device).", "O certificado tem a declaração QcSSCD (a chave está num dispositivo qualificado).", Qc),
        ["UsePseudonym"] = new("The certificate uses a pseudonym.", "O certificado usa um pseudônimo.", "EN 319 412-2"),
        ["Surname"] = new("The surname of the subject is one of the listed values.", "O sobrenome do titular é um dos valores listados."),
        ["GivenName"] = new("The given name of the subject is one of the listed values.", "O prenome do titular é um dos valores listados."),
        ["CommonName"] = new("The common name of the subject is one of the listed values.", "O nome comum do titular é um dos valores listados."),
        ["Pseudonym"] = new("The pseudonym of the subject is one of the listed values.", "O pseudônimo do titular é um dos valores listados."),
        ["Title"] = new("The title of the subject is one of the listed values.", "O título do titular é um dos valores listados."),
        ["Email"] = new("The e-mail of the subject is one of the listed values.", "O e-mail do titular é um dos valores listados."),
        ["OrganizationIdentifier"] = new("The organization identifier of the subject is one of the listed values.", "O identificador da organização do titular é um dos valores listados."),
        ["OrganizationUnit"] = new("The organization unit of the subject is one of the listed values.", "A unidade organizacional do titular é um dos valores listados."),
        ["OrganizationName"] = new("The organization of the subject is one of the listed values.", "A organização do titular é um dos valores listados."),
        ["Country"] = new("The country of the subject is one of the listed values.", "O país do titular é um dos valores listados."),
        ["Locality"] = new("The locality of the subject is one of the listed values.", "A localidade do titular é um dos valores listados."),
        ["State"] = new("The state of the subject is one of the listed values.", "O estado do titular é um dos valores listados."),

        // ── Signature constraints ──────────────────────────────────────────
        ["StructuralValidation"] = new("The signature conforms to its XML or ASN.1 schema.", "A assinatura está conforme o esquema XML ou ASN.1.", "EN 319 132-1 · EN 319 122-1"),
        ["AcceptablePolicies"] = new("The signature policy of the signature is one of the listed ones (ANY_POLICY: any; NO_POLICY: an implicit policy is accepted).", "A política de assinatura da assinatura é uma das listadas (ANY_POLICY: qualquer; NO_POLICY: política implícita é aceita).", "EN 319 102-1 §5.2.3 · TS 119 172-1"),
        ["PolicyAvailable"] = new("The signature policy document can be obtained.", "O documento da política de assinatura pode ser obtido.", "EN 319 102-1 §5.2.3"),
        ["SignaturePolicyStorePresent"] = new("The signature carries the policy document (signature policy store).", "A assinatura carrega o documento da política (signature policy store).", "EN 319 122-1 §5.2.10"),
        ["PolicyHashMatch"] = new("The hash of the policy document matches the one in the signature.", "O hash do documento da política confere com o da assinatura.", "EN 319 102-1 §5.2.3"),
        ["AcceptableFormats"] = new("The signature format (for example PAdES-BASELINE-B) is one of the listed ones.", "O formato da assinatura (por exemplo PAdES-BASELINE-B) é um dos listados."),
        ["FullScope"] = new("The signature covers the whole document.", "A assinatura cobre o documento inteiro."),

        // ── Signed attributes ──────────────────────────────────────────────
        ["SigningCertificatePresent"] = new("The signature references the signing certificate (signing-certificate-v2 / SigningCertificateV2).", "A assinatura referencia o certificado do signatário (signing-certificate-v2 / SigningCertificateV2).", "EN 319 122-1 §5.2.2"),
        ["UnicitySigningCertificate"] = new("Only one signing certificate reference is present.", "Só existe uma referência ao certificado do signatário.", "EN 319 122-1 §5.2.2"),
        ["SigningCertificateRefersCertificateChain"] = new("The signing certificate references point to certificates of the chain.", "As referências ao certificado do signatário apontam para certificados da cadeia."),
        ["ReferencesToAllCertificateChainPresent"] = new("Every certificate of the chain is referenced.", "Todo certificado da cadeia é referenciado."),
        ["SigningCertificateDigestAlgorithm"] = new("The digest of the signing certificate reference uses an accepted algorithm.", "O hash da referência ao certificado do signatário usa um algoritmo aceito."),
        ["CertDigestPresent"] = new("The signing certificate reference carries the certificate's digest.", "A referência ao certificado do signatário traz o hash do certificado.", "EN 319 122-1 §5.2.2"),
        ["CertDigestMatch"] = new("That digest matches the signing certificate.", "Esse hash confere com o certificado do signatário.", "EN 319 122-1 §5.2.2"),
        ["IssuerSerialMatch"] = new("The issuer and serial number of the reference match the signing certificate.", "O emissor e o número de série da referência conferem com o certificado do signatário."),
        ["SigningTime"] = new("The signature has a claimed signing time.", "A assinatura tem um horário de assinatura declarado.", "EN 319 122-1 §5.2.1"),
        ["SigningTimeInCertRange"] = new("The claimed signing time is within the validity of the signing certificate.", "O horário de assinatura declarado está dentro da validade do certificado do signatário."),
        ["ContentType"] = new("The content type of the signed data is one of the listed values.", "O content type dos dados assinados é um dos valores listados.", "RFC 5652 §11.1"),
        ["ContentHints"] = new("The content hints are one of the listed values.", "Os content hints são um dos valores listados.", "RFC 2634"),
        ["ContentIdentifier"] = new("The content identifier is one of the listed values.", "O content identifier é um dos valores listados.", "RFC 2634"),
        ["MessageDigestOrSignedPropertiesPresent"] = new("The message-digest attribute (CAdES) or the SignedProperties (XAdES) is present.", "O atributo message-digest (CAdES) ou as SignedProperties (XAdES) estão presentes."),
        ["CommitmentTypeIndication"] = new("The commitment type (proof of origin, of approval…) is one of the listed values.", "O tipo de compromisso (prova de origem, de aprovação…) é um dos valores listados.", "EN 319 122-1 §5.2.3"),
        ["SignerLocation"] = new("The signature has a signer location.", "A assinatura tem o local do signatário.", "EN 319 122-1 §5.2.5"),
        ["ClaimedRoles"] = new("The roles the signer claims are among the listed ones.", "Os papéis que o signatário declara estão entre os listados.", "EN 319 122-1 §5.2.6"),
        ["CertifiedRoles"] = new("The roles certified by attribute certificates are among the listed ones.", "Os papéis certificados por certificados de atributo estão entre os listados.", "EN 319 122-1 §5.2.6"),
        ["ContentTimeStamp"] = new("The signature has a content timestamp (taken before signing).", "A assinatura tem um carimbo do conteúdo (feito antes de assinar).", "EN 319 122-1 §5.2.8"),
        ["ContentTimeStampMessageImprint"] = new("The content timestamp covers the signed data.", "O carimbo do conteúdo cobre os dados assinados."),

        // ── Unsigned attributes ────────────────────────────────────────────
        ["CounterSignature"] = new("The signature has a countersignature.", "A assinatura tem uma contra-assinatura."),
        ["SignatureTimeStamp"] = new("The signature has a signature timestamp (level B-T).", "A assinatura tem um carimbo de assinatura (nível B-T).", "EN 319 122-1 §5.3"),
        ["ValidationDataTimeStamp"] = new("The signature has a timestamp over its validation data.", "A assinatura tem um carimbo sobre os dados de validação."),
        ["ValidationDataRefsOnlyTimeStamp"] = new("The signature has a timestamp over the references to its validation data.", "A assinatura tem um carimbo sobre as referências aos dados de validação."),
        ["ArchiveTimeStamp"] = new("The signature has an archive timestamp (level B-LTA).", "A assinatura tem um carimbo de arquivo (nível B-LTA).", Ltv),
        ["DocumentTimeStamp"] = new("The PDF has a document timestamp.", "O PDF tem um carimbo de documento.", "EN 319 142-1 §5.4"),
        ["TLevelTimeStamp"] = new("The signature has a timestamp of level T.", "A assinatura tem um carimbo de nível T."),
        ["LTALevelTimeStamp"] = new("The signature has a timestamp of level LTA.", "A assinatura tem um carimbo de nível LTA."),

        // ── Timestamp constraints ──────────────────────────────────────────
        ["TimestampDelay"] = new("The signature timestamp was taken at most Value Unit after the claimed signing time.", "O carimbo de assinatura foi feito no máximo Value Unit depois do horário de assinatura declarado.", "EN 319 102-1 §5.3"),
        ["RevocationTimeAgainstBestSignatureTime"] = new("The revocation time of a revoked certificate is after the best signature time (the signature was made before the revocation).", "O momento da revogação de um certificado revogado é posterior ao melhor momento da assinatura (ela foi feita antes da revogação).", Ltv),
        ["BestSignatureTimeBeforeExpirationDateOfSigningCertificate"] = new("The best signature time is before the expiration of the signing certificate.", "O melhor momento da assinatura é anterior à expiração do certificado do signatário.", Ltv),
        ["Coherence"] = new("The timestamps are in a coherent order (signature timestamp before archive timestamps…).", "Os carimbos estão numa ordem coerente (carimbo de assinatura antes dos de arquivo…).", Ltv),
        ["TimestampValid"] = new("The timestamp itself is valid.", "O próprio carimbo é válido.", "EN 319 102-1 §5.4"),
        ["TSAGeneralNamePresent"] = new("The timestamp names its TSA (tsa field).", "O carimbo nomeia a ACT (campo tsa).", "RFC 3161 §2.4.2"),
        ["TSAGeneralNameContentMatch"] = new("The TSA name matches the TSA certificate.", "O nome da ACT confere com o certificado da ACT.", "RFC 3161 §2.4.2"),
        ["TSAGeneralNameOrderMatch"] = new("The TSA name matches the TSA certificate, in the same order.", "O nome da ACT confere com o certificado da ACT, na mesma ordem.", "RFC 3161 §2.4.2"),
        ["AtsHashIndex"] = new("The ats-hash-index of the CAdES archive timestamp is correct.", "O ats-hash-index do carimbo de arquivo CAdES está correto.", "EN 319 122-1 §5.5.3"),

        // ── Revocation constraints ─────────────────────────────────────────
        ["UnknownStatus"] = new("The revocation status is not unknown (an OCSP 'unknown' answer).", "O status de revogação não é desconhecido (resposta OCSP 'unknown').", "RFC 6960"),
        ["ThisUpdatePresent"] = new("The revocation data has a thisUpdate time.", "Os dados de revogação têm o horário thisUpdate.", "RFC 5280 §5.1.2.4"),
        ["RevocationIssuerKnown"] = new("The issuer of the revocation data is known (its certificate was found).", "O emissor dos dados de revogação é conhecido (o certificado dele foi encontrado)."),
        ["RevocationIssuerValidAtProductionTime"] = new("The issuer of the revocation data was valid when it produced it.", "O emissor dos dados de revogação estava válido quando os produziu."),
        ["RevocationAfterCertificateIssuance"] = new("The revocation data was issued after the certificate it is about.", "Os dados de revogação foram emitidos depois do certificado a que se referem."),
        ["RevocationHasInformationAboutCertificate"] = new("The revocation data covers the certificate (still in the CRL scope, not expired before).", "Os dados de revogação cobrem o certificado (dentro do escopo da LCR, não expirado antes)."),
        ["OCSPResponderIdMatch"] = new("The responder id of the OCSP response matches its signing certificate.", "O responder id da resposta OCSP confere com o certificado que a assinou.", "RFC 6960 §4.2.2.3"),
        ["SelfIssuedOCSP"] = new("The OCSP response is not signed by the certificate it is about.", "A resposta OCSP não é assinada pelo próprio certificado a que se refere."),

        // ── Trusted lists ──────────────────────────────────────────────────
        ["TLFreshness"] = new("The trusted list was issued at most Value Unit ago.", "A lista de confiança foi emitida há no máximo Value Unit.", Tl),
        ["TLNotExpired"] = new("The trusted list is before its NextUpdate.", "A lista de confiança está antes do NextUpdate.", Tl),
        ["TLWellSigned"] = new("The signature of the trusted list is valid.", "A assinatura da lista de confiança é válida.", Tl),
        ["TLVersion"] = new("The trusted list version is one of the listed ones (5 or 6).", "A versão da lista de confiança é uma das listadas (5 ou 6).", Tl),
        ["TLStructure"] = new("The trusted list conforms to its XML schema.", "A lista de confiança está conforme o esquema XML.", Tl),
    };

    /// <summary>What each level does.</summary>
    public static IReadOnlyDictionary<string, PolicyGuideEntry> Levels { get; } = new Dictionary<string, PolicyGuideEntry>(StringComparer.Ordinal)
    {
        ["FAIL"] = new("The check must pass: when it does not, the signature is not valid (or, before signing, the signature is refused).", "A verificação tem de passar: quando não passa, a assinatura não é válida (ou, antes de assinar, a assinatura é recusada)."),
        ["WARN"] = new("The check is made; when it does not pass, a warning is reported and the result does not change.", "A verificação é feita; quando não passa, um aviso é reportado e o resultado não muda."),
        ["INFORM"] = new("The check is made and its outcome reported as information only.", "A verificação é feita e o resultado é reportado só como informação."),
        ["IGNORE"] = new("The check is not made.", "A verificação não é feita."),
    };

    /// <summary>The generic text of a section the guide does not know.</summary>
    public static PolicyGuideEntry Section { get; } = new("A group of constraints.", "Um grupo de restrições.");

    /// <summary>The generic text of a constraint the guide does not know.</summary>
    public static PolicyGuideEntry Constraint { get; } = new("A constraint of the validation policy.", "Uma restrição da política de validação.");

    /// <summary>The names the guide explains.</summary>
    public static IEnumerable<string> Names => s_entries.Keys;

    /// <summary>The explanation of an element, or null when there is none.</summary>
    public static PolicyGuideEntry? Of(string name) => s_entries.GetValueOrDefault(name);
}
