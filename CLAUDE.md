# CLAUDE.md — context for AI agents

You are working on the **TechTiera Employment Verification Portal**. Read this first.

## What this is

PHP flat-file admin tool that lets TechTiera HR / location offices store ex-employee separation records and lets ex-employees (or background-check firms) verify employment by Employee ID + DOB on a public page. Hosted on cPanel shared hosting, no MySQL, no frameworks, single `admin.php` file holds all admin logic + UI.

## Read these first

| Doc | What's in it |
| --- | --- |
| `PROJECT-DOCS.md` | Goal, tech stack, file map, feature checklist, schemas, deploy. **Start here.** |
| `ENTERPRISE-FEATURE.md` | Enterprise/legal-entity field, Settings UI, scoped users, `tt-config.json`. |
| `XLSX-UPLOAD-FEATURE.md` | XLSX upload + dropdown template, CSV BOM fix, native date inputs, Excel date serial handling. |
| `manual.html` | Customer-facing user manual. UI mockups + walkthroughs. |

## Hard constraints

- **Single-file admin.** `admin.php` is intentionally one large file (~2200 lines). Do not split it into includes / classes / a framework unless the user explicitly asks. The deploy story is "upload one PHP file to cPanel."
- **No composer.** Hosting is cPanel shared. No CLI access for `composer install`. Hand-roll what you need (see `buildXlsxTemplate` / `parseXlsx` in admin.php for the pattern). `ZipArchive` and `SimpleXMLElement` are available in stock PHP.
- **No build step.** Vanilla HTML/CSS/JS. No bundler, no transpiler. Inline `<style>` and `<script>` are fine.
- **Flat file storage.** `data.json` + `audit.json` + `tt-config.json`. Writes use `file_put_contents(..., LOCK_EX)`. Up to ~500 records this is fine; the docs flag MySQL migration as low-priority future work.
- **Two CLAUDE.md exclusions still apply:** never commit `data.json`, `audit.json`, `tt-config.json`, `tt-credentials.php`, or `audit-YYYY-MM.json` archives. `.gitignore` enforces this — keep it.

## How to run locally

```powershell
php -S localhost:1000 router.php
```

`router.php` mirrors production `.htaccess` (clean URLs `/admin`, `/api`, `/manual`; blocks direct access to sensitive files). Visit http://localhost:1000/admin to log in.

Plaintext passwords for the seeded users are NOT in the repo. They survive only in the historical `tt verification live.zip` outside the repo (in `E:\e drive\Tech Teira\`). Default admin password is the value from that zip's `tt-credentials.php`. To rotate: `php -r "echo password_hash('newpass', PASSWORD_BCRYPT);"` → paste hash into `tt-config.json`.

## How to test changes

1. Run the local server (above).
2. Log in as `admin`.
3. For upload / template / data work, generate a CSV or XLSX with one or two real-looking rows, upload via the admin Upload section, then check `data.json` directly for the new rows.
4. Restore `data.json` to its pre-test state after verifying (back it up first).

The codebase has no automated tests. PRs land after manual verification + a `cavecrew-reviewer` security pass on diff hunks that touch upload / parsing / auth.

## Conventions

- **Dates.** Stored as `YYYY-MM-DD` in JSON. `normalizeDate()` accepts ISO, DD-MM-YYYY, DD/MM/YYYY, YYYY/MM/DD, and Excel date serials (integer 25569–60000 ≈ 1970–2064). When adding date inputs to admin forms, use `<input type="date">`.
- **Locations / Enterprises.** Source of truth is `tt-config.json`. Code references via `LOCATIONS` and `ENTERPRISES` constants populated in `loadConfig()`. Fuzzy match incoming user-supplied location strings via `matchLocation()`.
- **CSV column aliases.** See the `$colMap = [...]` block in `admin.php` around line 700. Accept multiple aliases per logical column (`employeeid|reference|empid|id`, etc.). When adding a new column, add aliases not just one name.
- **Auth.** Every admin POST checks `$_SESSION['admin_auth']` AND a CSRF token. Every download endpoint checks `$_SESSION['admin_auth']`. Don't bypass.
- **Scope enforcement.** Non-admin users have `$_SESSION['user_location']` (and sometimes `user_enterprise`) set. Server-side code MUST force the row's location/enterprise to the session value for non-admin writes, regardless of what the user submitted. See `if ($isAdminAction ? '' : $myLocation)` patterns.
- **Sanitization.** All cell values from CSV/XLSX go through `sanitizeText()` which prefixes `'` to formula triggers (`= + - @ \t \r`) to defend against CSV-injection when the data is re-exported.

## Security must-haves on parsers

When touching `parseXlsx` or adding a new file-upload parser:

- `LIBXML_NONET` flag on every `simplexml_load_string()` call (XXE defense).
- Bounded uncompressed size for any zip-backed format (current cap: 25 MB).
- Marker check before parsing (xlsx requires `[Content_Types].xml` AND `xl/workbook.xml`).
- MIME-type + extension whitelist on upload. xlsx accepts `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`, `application/zip`, `application/x-zip`.
- Never extract zip contents to disk — always read via `ZipArchive::getFromName()`.

## Things known to be ugly / on the to-do list

- `tt-config.json` may still contain leftover test entries (`aus` location, `test1` enterprise from earlier development). Clean via Settings → Locations / Enterprises when noticed.
- `preview-result.html` is a dev scratch file showing card-variant mockups. Untracked. Either delete, gitignore it, or commit if it becomes a reference doc.
- No automated tests. Adding `phpunit` would need the codebase to grow includes / autoload — currently a one-file deploy.
- Locale-specific CSV (semicolon delimiter) still fails. Users must pick "CSV (Comma delimited)" or use the xlsx flow.

## Don'ts

- Don't introduce frameworks, package managers, or build steps.
- Don't move `admin.php` content into multiple files without explicit ask.
- Don't change date storage format from `YYYY-MM-DD`.
- Don't commit `data.json`, `tt-config.json`, `tt-credentials.php`, or `audit*.json`.
- Don't strip the BOM strip in CSV upload — Excel really does emit it.
- Don't replace `LIBXML_NONET` / 25 MB cap / marker check in `parseXlsx`. They're load-bearing.
