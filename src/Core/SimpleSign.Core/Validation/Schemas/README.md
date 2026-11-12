# XML schemas

Embedded, unmodified, to check the ETSI validation report (`ValidationReports.ValidateEtsiXml`). They are loaded from
the assembly only; the `schemaLocation` of their imports is never fetched. The imported XML Signature, XAdES and
trusted-list schemas are the files of `src/Formats/SimpleSign.XAdES/Schemas` (linked from the project file).

| File | Source | Terms |
|---|---|---|
| `TS119102-2-v122.xsd` | ETSI TS 119 102-2 v1.2.1 validation report schema, as distributed by EU DSS: https://github.com/esig/dss/blob/master/specs-validation-report/src/main/resources/xsd/TS119102-2-v122.xsd | ETSI TS 119 102-2 schema, as published by ETSI |
