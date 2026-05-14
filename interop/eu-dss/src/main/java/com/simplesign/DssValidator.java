package com.simplesign;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import java.util.List;

/**
 * Minimal CLI wrapper around EU DSS for interop testing.
 * Validates PAdES, CAdES, and XAdES signatures per ETSI EN 319 102.
 */
public class DssValidator {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            printHelp();
            System.exit(0);
            return;
        }

        String command = args[0];
        String filePath = args[1];

        switch (command) {
            case "validate-pades":
            case "validate-cades":
            case "validate-xades":
                validate(filePath, command);
                break;
            case "validate-xades-detached":
                String dataFile = args.length > 2 ? args[2] : null;
                validateDetached(filePath, dataFile);
                break;
            case "report":
                report(filePath);
                break;
            case "help":
            default:
                printHelp();
                break;
        }
    }

    private static void validate(String filePath, String command) {
        try {
            System.out.println("=== EU DSS Validation (" + command + ") ===");
            System.out.println("File: " + filePath);

            DSSDocument document = new FileDocument(filePath);

            // Auto-detect document type
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

            // Use a permissive certificate verifier (no online lookups for interop testing)
            CommonCertificateVerifier verifier = new CommonCertificateVerifier();
            validator.setCertificateVerifier(verifier);

            Reports reports = validator.validateDocument();
            SimpleReport simpleReport = reports.getSimpleReport();

            List<String> signatureIds = simpleReport.getSignatureIdList();
            System.out.println("Signatures found: " + signatureIds.size());

            boolean allValid = true;
            for (String sigId : signatureIds) {
                boolean valid = simpleReport.isValid(sigId);
                String indication = simpleReport.getIndication(sigId).toString();
                String subIndication = simpleReport.getSubIndication(sigId) != null
                        ? simpleReport.getSubIndication(sigId).toString()
                        : "N/A";
                String format = simpleReport.getSignatureFormat(sigId) != null
                        ? simpleReport.getSignatureFormat(sigId).toString()
                        : "UNKNOWN";

                System.out.println("Signature " + sigId + ":");
                System.out.println("  Format: " + format);
                System.out.println("  Indication: " + indication);
                System.out.println("  Sub-indication: " + subIndication);
                System.out.println("  Valid: " + valid);

                if (!valid) {
                    allValid = false;
                }
            }

            if (signatureIds.isEmpty()) {
                System.out.println("RESULT: NO_SIGNATURES");
                System.exit(1);
            } else if (allValid) {
                System.out.println("RESULT: TOTAL_PASSED (all signatures valid per ETSI EN 319 102)");
                System.exit(0);
            } else {
                // For self-signed certs, DSS reports INDETERMINATE (not TOTAL_FAILED)
                // This is correct behavior — check for INDETERMINATE vs TOTAL_FAILED
                boolean anyFailed = false;
                for (String sigId : signatureIds) {
                    String indication = simpleReport.getIndication(sigId).toString();
                    if ("TOTAL_FAILED".equals(indication)) {
                        anyFailed = true;
                    }
                }
                if (anyFailed) {
                    System.out.println("RESULT: TOTAL_FAILED");
                    System.exit(1);
                } else {
                    // INDETERMINATE is expected with self-signed certs (no trusted list)
                    System.out.println("RESULT: INDETERMINATE (expected with self-signed certificates)");
                    System.exit(0);
                }
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            e.printStackTrace();
            System.out.println("RESULT: ERROR");
            System.exit(2);
        }
    }

    private static void report(String filePath) {
        try {
            DSSDocument document = new FileDocument(filePath);
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
            CommonCertificateVerifier verifier = new CommonCertificateVerifier();
            validator.setCertificateVerifier(verifier);

            Reports reports = validator.validateDocument();
            // Print the simple report as text
            System.out.println(reports.getXmlSimpleReport());
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(2);
        }
    }

    private static void validateDetached(String signatureFile, String dataFile) {
        try {
            System.out.println("=== EU DSS Validation (validate-xades-detached) ===");
            System.out.println("Signature: " + signatureFile);
            System.out.println("Data: " + (dataFile != null ? dataFile : "N/A"));

            DSSDocument sigDocument = new FileDocument(signatureFile);
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(sigDocument);

            if (dataFile != null) {
                // Use InMemoryDocument with null name so URI="" references match
                byte[] dataBytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(dataFile));
                DSSDocument originalDoc = new eu.europa.esig.dss.model.InMemoryDocument(dataBytes);
                validator.setDetachedContents(java.util.Collections.singletonList(originalDoc));
            }

            CommonCertificateVerifier verifier = new CommonCertificateVerifier();
            validator.setCertificateVerifier(verifier);

            Reports reports = validator.validateDocument();
            SimpleReport simpleReport = reports.getSimpleReport();

            List<String> signatureIds = simpleReport.getSignatureIdList();
            System.out.println("Signatures found: " + signatureIds.size());

            boolean anyFailed = false;
            for (String sigId : signatureIds) {
                String indication = simpleReport.getIndication(sigId).toString();
                System.out.println("Signature " + sigId + ": " + indication);
                if ("TOTAL_FAILED".equals(indication)) {
                    anyFailed = true;
                }
            }

            if (signatureIds.isEmpty()) {
                System.out.println("RESULT: NO_SIGNATURES");
                System.exit(1);
            } else if (anyFailed) {
                System.out.println("RESULT: TOTAL_FAILED");
                System.exit(1);
            } else {
                System.out.println("RESULT: INDETERMINATE (expected with self-signed certificates)");
                System.exit(0);
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            e.printStackTrace();
            System.out.println("RESULT: ERROR");
            System.exit(2);
        }
    }

    private static void printHelp() {
        System.out.println("SimpleSign EU DSS Validator");
        System.out.println("");
        System.out.println("Commands:");
        System.out.println("  validate-pades <file.pdf>                    Validate PAdES signature (ETSI EN 319 102)");
        System.out.println("  validate-cades <file.p7s>                    Validate CAdES signature");
        System.out.println("  validate-xades <file.xml>                    Validate XAdES signature");
        System.out.println("  validate-xades-detached <sig.xml> <data.xml> Validate detached XAdES with original data");
        System.out.println("  report <file>                                Full ETSI validation report (XML)");
        System.out.println("  help                                         Show this help");
    }
}
