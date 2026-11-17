using SimpleSign.Core.Validation;

namespace SimpleSign.Peru.Iofe.Accredited.Internal;

/// <summary>
/// Why a signature was not accepted, in Spanish: the notice to the sender, the reasons of a verification and its audit
/// record are read by people, and the validator's own messages are in English. One sentence per sub-indication of
/// ETSI EN 319 102-1; the detail of each check is in the validation report.
/// </summary>
internal static class IofeReasons
{
    /// <summary>The sentence for <paramref name="subIndication"/>, followed by its name; "sin detalle" when there is none.</summary>
    internal static string Describe(SignatureSubIndication? subIndication) =>
        subIndication is { } value ? $"{Sentence(value)} ({value})" : "sin detalle";

    private static string Sentence(SignatureSubIndication subIndication) => subIndication switch
    {
        SignatureSubIndication.FormatFailure => "la firma no tiene un formato válido",
        SignatureSubIndication.HashFailure => "el documento fue modificado después de la firma",
        SignatureSubIndication.SigCryptoFailure => "la firma no verifica con la clave pública del certificado",
        SignatureSubIndication.Revoked => "el certificado del firmante estaba revocado al momento de la firma",
        SignatureSubIndication.NotYetValid => "la firma es anterior al inicio de la vigencia del certificado",
        SignatureSubIndication.SigConstraintsFailure => "la firma no cumple la política de validación",
        SignatureSubIndication.ChainConstraintsFailure =>
            "el certificado o su cadena no cumplen la política de validación (por ejemplo, el uso de clave)",
        SignatureSubIndication.CryptoConstraintsFailure or SignatureSubIndication.CryptoConstraintsFailureNoPoe =>
            "un algoritmo o un tamaño de clave no es aceptable",
        SignatureSubIndication.NoSigningCertificateFound => "no se encontró el certificado del firmante",
        SignatureSubIndication.NoCertificateChainFound => "el certificado no encadena a una entidad de certificación de confianza",
        SignatureSubIndication.OutOfBoundsNoPoe =>
            "el certificado del firmante no está vigente y no hay prueba de que la firma sea anterior a su expiración",
        SignatureSubIndication.RevokedNoPoe =>
            "el certificado del firmante está revocado y no hay prueba de que la firma sea anterior a la revocación",
        SignatureSubIndication.TryLater => "no se pudo obtener el estado de revocación en este momento",
        SignatureSubIndication.TimestampOrderFailure => "los sellos de tiempo no guardan el orden debido",
        SignatureSubIndication.SignedDataNotFound => "no se encontró el contenido firmado",
        SignatureSubIndication.SignaturePolicyNotAvailable => "la política de firma no está disponible",
        SignatureSubIndication.CertificateChainGeneralFailure =>
            "no se pudo validar la cadena de certificados o su estado de revocación",
        SignatureSubIndication.RevokedCaNoPoe =>
            "un certificado de la cadena está revocado y no hay prueba de que la firma sea anterior a la revocación",
        _ => "la firma no pudo validarse",
    };
}
