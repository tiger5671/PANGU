# Evaluation firmware

The inventory contains 42 analyzed firmware images from 13 vendors and 78 distinct known BAC CVE references. These are the known-vulnerability benchmark records. The 34 newly discovered vulnerabilities are reported separately in the paper.

| File | Use |
| --- | --- |
| [firmware_manifest.md](firmware_manifest.md) | Readable inventory with the same image IDs as the response-letter inventory. |
| [firmware_manifest.json](firmware_manifest.json) | Structured records for scripts. Each record includes the source and displayed firmware-version strings. |
| [PANGU_Firmware_Dataset_42_Images.xlsx](PANGU_Firmware_Dataset_42_Images.xlsx) | Original workbook, preserved without editing. |
| [vendor_sources.md](vendor_sources.md) | Official vendor support/download portals. |
| [vendor_sources.json](vendor_sources.json) | The same portal references in a machine-readable form. |

## Fields

| Field | Meaning |
| --- | --- |
| `image_id` | Stable inventory ID from 1 to 42. |
| `vendor` | Reported vendor name. |
| `device_model` | Device-model entry recorded in the workbook. Composite labels are preserved. |
| `firmware_version` | Displayed version or release identifier used in the response-letter inventory. |
| `firmware_version_source` | Unmodified firmware-version string from the workbook. |
| `known_bac_cves` | Array of known benchmark CVE IDs associated with the analyzed image. An empty array corresponds to a dash in the Markdown inventory. |

An empty CVE list means that the benchmark lists no known BAC CVE for that image. It does not assert that the image has no vulnerabilities. A firmware identifier describes the analyzed image; it is not a complete CVE affected-version statement.

## Display changes and source records

Three version strings have presentation-only changes: image 40 uses `20220721 (release build)`, and images 41 and 42 omit the annotation `[decoded]`. Their source strings remain in JSON and in the original workbook. Version/build identifiers are unchanged.

The workbook sometimes includes another model in a firmware-version string. For example, image 9 is listed as `DNS-320` with a `DNS-320L` version annotation, and image 34 is listed as `Tapo C200` with a `C100 v2` annotation. Both fields are preserved as recorded; the supplied metadata does not resolve these model annotations. Users selecting a binary should also check its hardware and regional revision.

## Obtaining images

Use the vendor portals to search for the recorded model and version. The supplied records do not contain exact archive URLs, binary filenames, image hashes, or acquisition dates. The portal list is therefore a starting point for locating firmware, not a verified download manifest for the 42 exact binaries. The SHA-256 recorded in the JSON inventory identifies the **Excel workbook**, not a firmware binary.

Firmware binaries are not included. Availability of historical releases and redistribution permissions are vendor-specific. For benchmark matching and validation, see the [evaluation protocol](../docs/evaluation_protocol.md).
