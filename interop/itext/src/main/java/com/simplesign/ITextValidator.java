package com.simplesign;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.SignatureUtil;

import java.io.FileInputStream;
import java.security.Security;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Minimal CLI wrapper around iText 9 for PAdES interop testing.
 * Validates PDF signatures using iText's signature verification engine.
 */
public class ITextValidator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            printHelp();
            System.exit(0);
            return;
        }

        String command = args[0];
        String filePath = args[1];

        switch (command) {
            case "validate-pdf":
                validatePdf(filePath);
                break;
            case "inspect-pdf":
                inspectPdf(filePath);
                break;
            case "check-structure":
                checkStructure(filePath);
                break;
            case "help":
            default:
                printHelp();
                break;
        }
    }

    private static void validatePdf(String filePath) {
        System.out.println("=== PDF Signature Validation (iText 9) ===");
        System.out.println("File: " + filePath);

        try (PdfDocument pdfDoc = new PdfDocument(new PdfReader(filePath))) {
            SignatureUtil signUtil = new SignatureUtil(pdfDoc);
            List<String> names = signUtil.getSignatureNames();

            System.out.println("Signature fields: " + names.size());

            if (names.isEmpty()) {
                System.out.println("RESULT: NO_SIGNATURES");
                System.exit(1);
                return;
            }

            boolean allIntact = true;
            for (String name : names) {
                PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);
                boolean intact = pkcs7.verifySignatureIntegrityAndAuthenticity();

                String signerName = pkcs7.getSigningCertificate() != null
                        ? pkcs7.getSigningCertificate().getSubjectX500Principal().getName()
                        : "UNKNOWN";
                String digestAlg = pkcs7.getDigestAlgorithmName();
                String encAlg = pkcs7.getSignatureAlgorithmName();

                System.out.println("Signature '" + name + "':");
                System.out.println("  Signer: " + signerName);
                System.out.println("  Digest: " + digestAlg);
                System.out.println("  Algorithm: " + encAlg);
                System.out.println("  Intact: " + intact);
                System.out.println("  Covers whole document: " + signUtil.signatureCoversWholeDocument(name));

                if (!intact) {
                    allIntact = false;
                }
            }

            if (allIntact) {
                System.out.println("RESULT: VALID (all signatures intact)");
                System.exit(0);
            } else {
                System.out.println("RESULT: INVALID (integrity check failed)");
                System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.out.println("RESULT: ERROR");
            System.exit(2);
        }
    }

    private static void inspectPdf(String filePath) {
        System.out.println("=== PDF Signature Inspection (iText 9) ===");

        try (PdfDocument pdfDoc = new PdfDocument(new PdfReader(filePath))) {
            SignatureUtil signUtil = new SignatureUtil(pdfDoc);
            List<String> names = signUtil.getSignatureNames();

            System.out.println("Total signatures: " + names.size());

            for (String name : names) {
                PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);

                System.out.println("Field: " + name);
                System.out.println("  Revision: " + signUtil.getRevision(name) + " of " + signUtil.getTotalRevisions());
                System.out.println("  Covers whole: " + signUtil.signatureCoversWholeDocument(name));
                System.out.println("  Digest: " + pkcs7.getDigestAlgorithmName());
                System.out.println("  Algorithm: " + pkcs7.getSignatureAlgorithmName());

                if (pkcs7.getSigningCertificate() != null) {
                    System.out.println("  Subject: " + pkcs7.getSigningCertificate().getSubjectX500Principal().getName());
                    System.out.println("  Issuer: " + pkcs7.getSigningCertificate().getIssuerX500Principal().getName());
                    System.out.println("  NotAfter: " + pkcs7.getSigningCertificate().getNotAfter());
                }

                if (pkcs7.getTimeStampDate() != null) {
                    System.out.println("  Timestamp: " + pkcs7.getTimeStampDate().getTime());
                }

                System.out.println("  Reason: " + pkcs7.getReason());
                System.out.println("  Location: " + pkcs7.getLocation());
            }

            System.out.println("RESULT: INSPECTED");
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(2);
        }
    }

    private static void checkStructure(String filePath) {
        System.out.println("=== PDF Structure Check (iText 9) ===");

        try (PdfDocument pdfDoc = new PdfDocument(new PdfReader(filePath))) {
            System.out.println("Pages: " + pdfDoc.getNumberOfPages());
            System.out.println("PDF version: " + pdfDoc.getPdfVersion());

            SignatureUtil signUtil = new SignatureUtil(pdfDoc);
            System.out.println("Signature fields: " + signUtil.getSignatureNames().size());
            System.out.println("Blank signature fields: " + signUtil.getBlankSignatureNames().size());

            System.out.println("RESULT: VALID (structure parsed)");
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.out.println("RESULT: ERROR (parse failed)");
            System.exit(2);
        }
    }

    private static void printHelp() {
        System.out.println("SimpleSign iText Interop Validator");
        System.out.println("");
        System.out.println("Commands:");
        System.out.println("  validate-pdf <file.pdf>     Validate all PDF signatures");
        System.out.println("  inspect-pdf <file.pdf>      Inspect signature details");
        System.out.println("  check-structure <file.pdf>  Check PDF structure");
        System.out.println("  help                        Show this help");
    }
}
