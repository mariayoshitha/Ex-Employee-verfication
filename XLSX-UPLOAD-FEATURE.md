# XLSX Upload + Dropdown Template — Progress & Behavior Notes

## What changed

Three connected things:

1. **CSV BOM bug fixed.** Excel "CSV UTF-8 (Comma delimited)" prepends a UTF-8 byte-order mark (`\xEF\xBB\xBF`). The first header read by `fgetcsv` came back as `\xef\xbb\xbfemployeeid`, never matched the alias list, so `reference` column lookup returned `false` → every row stored an empty `reference` → every row dropped → `"No valid records found. Check your CSV column names match the template."` Now the parser strips the BOM off `$rawHeaders[0]` before lowercasing.

2. **XLSX upload + template.** Upload accepts `.xlsx` alongside `.csv`. A hand-rolled xlsx generator emits a template with **data-validation dropdowns** on Location, Enterprise, and Separation Type columns (backed by a hidden `Lists` sheet). A hand-rolled xlsx parser reads it back. **No composer / PhpSpreadsheet dependency** — pure PHP via `ZipArchive` + `SimpleXMLElement`, ~150 LOC.

3. **Date inputs.** Admin Add and Edit modals now use native `<input type="date">` instead of `<input type="text" placeholder="DD-MM-YYYY">` for DOB, Start Date, End Date. Pre-fill uses the raw `YYYY-MM-DD` value from `data.json`. `normalizeDate()` also now accepts Excel date serials (the integer Excel stores when a user types a date into an xlsx cell).

## Why

User reported uploads silently failing with "no valid records" after they exported the template from admin and re-uploaded it edited. Root cause was the BOM. While in there: users were also asking for in-cell dropdowns to stop typos in Location / Enterprise / Separation Type — CSV cannot do that (no metadata), so xlsx support landed alongside.

## Files touched

| File | Change |
| --- | --- |
| `admin.php` | BOM strip on CSV header. New xlsx helpers (`xlsxColLetter`, `xlsxEsc`, `xlsxColIndex`, `xlsxBuildSheet`, `buildXlsxTemplate`, `parseXlsx`). New `?download=template_xlsx` endpoint. Upload handler refactored to accept both `.csv` and `.xlsx` through a shared row-processing path. `normalizeDate` extended for Excel date serials. Add/Edit modals: text date inputs → `type="date"`. Upload form: `accept=".csv,.xlsx"`, two template buttons, hint text. |

No other files touched. No schema change. No data migration.

## CSV behavior (unchanged + one fix)

- Delimiter: comma. Locale-induced semicolons still fail (Excel "CSV UTF-8" in some locales). Documented in upload form hint.
- BOM on first header: now stripped.
- Header aliases unchanged. Date formats accepted: `YYYY-MM-DD`, `DD-MM-YYYY`, `DD/MM/YYYY`, `YYYY/MM/DD`, and now numeric Excel serials.

## XLSX template (`?download=template_xlsx`)

- Two sheets: `Data` (visible) + `Lists` (hidden, holds dropdown source values).
- Rows 1–2 = header + note. Rows 3–5 = three example rows the user replaces.
- Data validations (`<dataValidations>`) cover rows 3 through ~505:
  - Admin template: column D (Location), E (Enterprise), I (Separation Type).
  - Location-user template: no Location column; Enterprise + Separation Type still validated.
- Dropdowns reference ranges in `Lists` sheet (`Lists!$A$1:$A$N`, etc.).
- Strings are shared-string-indexed. No styles, no formatting — Excel and LibreOffice both open it without complaining about repair.
- Filename: `upload-template-admin.xlsx` or `upload-template-<location-slug>.xlsx`.

## XLSX parser (`parseXlsx`)

Reads `xl/sharedStrings.xml` + `xl/worksheets/sheet1.xml` from the uploaded zip and returns a 2D string array. Then the existing CSV row-processing logic runs identically — same `cleanRow`, `sanitizeText`, `matchLocation`, `matchEnterprise`, scope enforcement.

Handles:
- Shared strings (`t="s"`) and inline strings (`t="inlineStr"`).
- Cells in non-sequential columns (uses cell `r=` attribute, not position).
- Empty cells, blank rows (filtered downstream).
- Numeric cells (no `t` attribute) — passed through as strings; `normalizeDate` converts if column maps to a date field.

Rejects:
- Zips missing `[Content_Types].xml` or `xl/workbook.xml` (defends against any zip renamed to `.xlsx`).
- Total uncompressed size > 25 MB (zip-bomb guard).
- Malformed XML (silent return of empty array).

## Date handling

| Input | Stored |
| --- | --- |
| `2024-12-31` (ISO, from `type="date"` or template) | `2024-12-31` |
| `31-12-2024` (DD-MM-YYYY) | `2024-12-31` |
| `31/12/2024` | `2024-12-31` |
| `45657` (Excel serial integer for 2024-12-31) | `2024-12-31` |
| Anything else | `''` (silently dropped) |

Serial conversion: `gmdate('Y-m-d', (int)(($n - 25569) * 86400))`. Accepted range: `25569 ≤ n ≤ 60000` (≈ 1970 to 2064). Below 25569 = pre-1970, rejected. Above 60000 = far future, rejected.

## Security posture

| Threat | Mitigation |
| --- | --- |
| XXE / billion-laughs in xlsx XML | `LIBXML_NONET` flag on every `simplexml_load_string` call |
| Zip bomb (small zip, huge uncompressed) | Reject if `sum(stat['size']) > 25 MB` before parsing |
| Arbitrary zip renamed `.xlsx` | Require markers `[Content_Types].xml` AND `xl/workbook.xml` |
| MIME spoofing | Ext + MIME whitelist (xlsx: `…spreadsheetml.sheet`, `application/zip`, `application/x-zip`) |
| Path traversal via zip-slip | Not exposed — `parseXlsx` only calls `getFromName()`, never extracts to disk |
| Formula injection in stored data | Existing `sanitizeText` already prefixes `'` to `=+-@\t\r` |
| Privilege escalation (location user uploads with `location` column) | Existing handler still forces `$loc = $myLocation` for non-admin |
| CSRF on upload | Existing CSRF check on POST handler unchanged |

Reviewer (cavecrew-reviewer + Claude security pass) found no exploitable issues in session changes.

## Smoke-test results

End-to-end POST upload tests via PowerShell + multipart/form-data, hitting `http://localhost:1000/admin`:

| Test | Input | Result |
| --- | --- | --- |
| CSV + BOM | header with `\xEF\xBB\xBF`, 1 row | Row inserted, all 10 fields correct |
| XLSX inlineStr | hand-built xlsx, no sharedStrings, 1 row | Row inserted, all 10 fields correct |
| Excel date serials | CSV with DOB=`32888`, Start=`43831`, End=`45657` | Stored as `1990-01-15`, `2020-01-01`, `2024-12-31` |

`data.json` restored to pre-test state after verification.

## UI changes

- **Upload section.** Two template-download buttons (Excel + CSV), file input accepts both extensions, hint reads "Excel template includes dropdowns for Location, Enterprise, and Separation Type."
- **Add Record modal.** DOB / Start Date / End Date are `<input type="date">` (native picker). No more typed `DD-MM-YYYY`.
- **Edit Record modal.** Same. Pre-fill uses raw ISO string from DB.

Public verification page (`index.html`) already used `type="date"` for DOB — no change.

## Known caveats

- `tt-config.json` may contain leftover test entries (e.g. `aus` location, `test1` enterprise). They appear in the xlsx dropdowns. Clean via Settings → Locations / Enterprises when convenient.
- Excel "Lists" sheet is hidden via `state="hidden"`. To inspect, right-click any sheet tab → Unhide.
- Locale-specific CSV (semicolon-delimited) still fails. Users in those locales must pick "CSV (Comma delimited)" when saving, or use the xlsx flow.

## Deploy

`admin.php` is the only changed file. Upload it. No config changes, no migration. Tested locally via `php -S localhost:1000 router.php`.
