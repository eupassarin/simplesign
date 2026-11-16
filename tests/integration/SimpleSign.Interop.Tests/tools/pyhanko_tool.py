"""pyHanko for the SimpleSign interop tests.

  validate <pdf> <root.pem>...
      Validates every signature and document timestamp of <pdf>, trusting only the given roots, without fetching
      anything. Prints one JSON object: {"signatures": [{field, kind, intact, valid, trusted, coverage,
      modification_level, docmdp_ok, timestamp_trusted, summary}, ...]}. Exit 0 when it could read the file.

  sign <in.pdf> <out.pdf> <key.pem> <cert.pem> <chain.pem>
      Appends a signature (field "PyHanko") in an incremental update.

Pinned by requirements.txt beside this file.
"""

import json
import sys

from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers
from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp
from pyhanko_certvalidator import ValidationContext


def _context(roots):
    # Offline: what the document carries, the given roots, and nothing fetched.
    return ValidationContext(trust_roots=roots, allow_fetching=False, revocation_mode="soft-fail")


def validate(pdf_path, root_paths):
    roots = [load_cert_from_pemder(path) for path in root_paths]
    results = []
    with open(pdf_path, "rb") as stream:
        reader = PdfFileReader(stream, strict=True)
        for sig in reader.embedded_signatures:
            entry = {"field": sig.field_name}
            try:
                if sig.sig_object.get("/Type") == "/DocTimeStamp":
                    status = validate_pdf_timestamp(sig, validation_context=_context(roots))
                    entry["kind"] = "timestamp"
                else:
                    status = validate_pdf_signature(
                        sig,
                        signer_validation_context=_context(roots),
                        ts_validation_context=_context(roots),
                    )
                    entry["kind"] = "signature"
                    timestamp = status.timestamp_validity
                    entry["timestamp_trusted"] = None if timestamp is None else bool(timestamp.trusted)
                    entry["docmdp_ok"] = status.docmdp_ok
                entry.update(
                    intact=bool(status.intact),
                    valid=bool(status.valid),
                    trusted=bool(status.trusted),
                    coverage=status.coverage.name if status.coverage is not None else None,
                    modification_level=status.modification_level.name if status.modification_level is not None else None,
                    summary=status.summary(),
                )
            except Exception as error:  # noqa: BLE001 - the test reports whatever pyHanko refused
                entry.update(intact=False, valid=False, trusted=False, error=f"{type(error).__name__}: {error}")
            results.append(entry)
    print(json.dumps({"signatures": results}))


def sign(in_path, out_path, key_path, cert_path, chain_path):
    signer = signers.SimpleSigner.load(key_path, cert_path, ca_chain_files=(chain_path,))
    with open(in_path, "rb") as source, open(out_path, "wb") as target:
        writer = IncrementalPdfFileWriter(source)
        signers.sign_pdf(writer, signers.PdfSignatureMetadata(field_name="PyHanko"), signer=signer, output=target)
    print(json.dumps({"signed": out_path}))


def main(argv):
    if len(argv) >= 3 and argv[0] == "validate":
        validate(argv[1], argv[2:])
    elif len(argv) == 6 and argv[0] == "sign":
        sign(*argv[1:])
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
