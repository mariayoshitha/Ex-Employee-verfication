# TechTiera Employment Verification Portal
## Project Documentation

**URL:** https://verify.techteira.com  
**Admin Panel:** https://verify.techteira.com/admin  
**Last Updated:** 2026-05-22

> **Recent feature docs (read these in addition to this file):**
> - [ENTERPRISE-FEATURE.md](ENTERPRISE-FEATURE.md) — enterprise / legal-entity field, Settings UI, scoped users, `tt-config.json`.
> - [XLSX-UPLOAD-FEATURE.md](XLSX-UPLOAD-FEATURE.md) — xlsx upload + dropdown template, CSV BOM fix, native date pickers, Excel date serial handling.

---

## Goal

Internal tool for TechTiera HR and recruiters to:
1. **Store** ex-employee separation records across all global offices
2. **Verify** employment history via a public-facing portal (employee ID + DOB)
3. **Manage** records by location — each office manages its own data

---

## Tech Stack

| Layer | Technology |
|---|---|
| Hosting | cPanel shared hosting |
| Subdomain | verify.techteira.com |
| Backend | PHP (flat-file, no MySQL) |
| Database | data.json + audit.json (file-based) |
| Auth | Session-based + IP lockout |
| Web server | Apache + mod_rewrite |
| Frontend | Vanilla HTML/CSS/JS (no frameworks) |
| Security | CSRF tokens, bcrypt passwords, HTTPS enforced |

---

## Files

| File | Purpose |
|---|---|
| `index.html` | Public employee verification portal |
| `admin.php` | Full admin panel (all logic + UI) |
| `api.php` | Public search API (rate-limited, 20/min per IP) |
| `router.php` | Dev-only router for `php -S` (maps `/admin` → `admin.php`, mirrors `.htaccess` clean URLs + blocks). Not used in production. |
| `data.json` | Employee records database (gitignored) |
| `audit.json` | Audit log database (gitignored) |
| `tt-config.json` | Locations + enterprises + users (lives outside public_html; gitignored). See ENTERPRISE-FEATURE.md. |
| `verify-techtiera-credentials.php` | Seed-source for first-bootstrap user credentials (bcrypt) — move above public_html, gitignored |
| `manual.html` | User manual (Admin + Location User guide) |
| `.htaccess` | Routing, security headers, file access blocking |
| `logo.svg` | TechTiera logo (base64-embedded in HTML/PHP) |
| `PROJECT-DOCS.md` | This file. |
| `ENTERPRISE-FEATURE.md` | Enterprise field rollout notes. |
| `XLSX-UPLOAD-FEATURE.md` | XLSX upload + template + BOM fix + date input notes. |

---

## Locations (9 offices)

- Chicago, USA
- Hyderabad, India
- Manila, Philippines
- Singapore
- Kuala Lumpur, Malaysia
- Sydney, Australia
- Dubai, UAE
- Bangkok, Thailand
- Jakarta, Indonesia

---

## User Accounts

| Username | Role | Scope |
|---|---|---|
| `admin` | Admin | All locations |
| `chicago` | Location | Chicago, USA only |
| `hyderabad` | Location | Hyderabad, India only |
| `manila` | Location | Manila, Philippines only |
| `singapore` | Location | Singapore only |
| `kualalumpur` | Location | Kuala Lumpur, Malaysia only |
| `sydney` | Location | Sydney, Australia only |
| `dubai` | Location | Dubai, UAE only |
| `bangkok` | Location | Bangkok, Thailand only |
| `jakarta` | Location | Jakarta, Indonesia only |

> Passwords stored as bcrypt hashes (cost 12) in `verify-techtiera-credentials.php`.  
> To change a password: `php -r "echo password_hash('newpass', PASSWORD_BCRYPT);"`

---

## Features — Completed

### Public Portal
- [x] Employee lookup by Employee ID + Date of Birth
- [x] Returns: name, role, location, start date, end date, separation type
- [x] Never exposes DOB or salary
- [x] Rate limited: 20 requests/minute per IP
- [x] Error message if not found or wrong DOB

### Admin Panel — Auth
- [x] Username/password login
- [x] bcrypt password hashing (PASSWORD_BCRYPT, cost 12)
- [x] IP-based login lockout (5 attempts → 15 min lock, survives cookie clear)
- [x] 30-minute session timeout on inactivity
- [x] Session regeneration on login
- [x] CSRF protection on all POST forms
- [x] Logout with CSRF check

### Admin Panel — Records
- [x] Add record (modal form, native date pickers for DOB/Start/End)
- [x] Edit record (inline modal, pre-filled, native date pickers)
- [x] Delete record (confirmation prompt)
- [x] CSV bulk upload (merge/upsert by Employee ID, UTF-8 BOM tolerated)
- [x] CSV template download (admin gets all-location template, location user gets scoped template)
- [x] **XLSX bulk upload** (same row-processing as CSV; accepts shared-string and inline-string cells; Excel date serials auto-converted)
- [x] **XLSX template download** with in-cell dropdowns for Location, Enterprise, Separation Type (hidden Lists sheet backs the validations)
- [x] Export filtered CSV (respects current search/filter/location scope)
- [x] Duplicate Employee ID on upload upserts by reference (case-insensitive) — see ENTERPRISE-FEATURE.md

### Admin Panel — Filters & Search
- [x] Search box (matches Employee ID, name, role, location)
- [x] Separation type filter (Voluntary / Involuntary / Project End)
- [x] Location filter (admin only — location users auto-scoped)
- [x] Clear filters button
- [x] All filters preserve state across pagination

### Admin Panel — Pagination
- [x] Per-page selector: 25 / 50 / 100
- [x] Smart page number controls (prev/next + numbered + ellipsis)
- [x] Record range display ("1–50 of 342 records")

### Admin Panel — Dashboard
- [x] Stats cards: Total, Voluntary, Involuntary, Project End
- [x] DB Status panel (per-location record count + last updated) — admin only
- [x] Audit Log viewer (last 50 actions) — admin only
- [x] Audit Log header link — admin only

### Admin Panel — Access Control
- [x] Role-based: admin (all locations) vs location user (own office only)
- [x] Location users cannot see, add, edit, or delete other offices' records
- [x] Location filter dropdown hidden for location users
- [x] Audit Log link hidden for location users
- [x] Server-side enforcement on all write operations

### Data & Audit
- [x] Audit log: every add, edit, delete, CSV upload recorded
- [x] Audit entries: timestamp, username, action, Employee ID, location, detail
- [x] Audit log capped at 500 entries (rolling)
- [x] file_put_contents with LOCK_EX for safe concurrent writes
- [x] Date normalization (accepts DD-MM-YYYY, YYYY-MM-DD, DD/MM/YYYY, YYYY/MM/DD, AND Excel date serials on input)
- [x] Location fuzzy matching on CSV/XLSX upload
- [x] CSV injection prevention (sanitizeText prefix on `=+-@\t\r`)
- [x] XLSX upload hardening: LIBXML_NONET on simplexml, 25 MB uncompressed cap (zip-bomb guard), `[Content_Types].xml` + `xl/workbook.xml` marker check (rejects arbitrary zips)

### Security & Infrastructure
- [x] HTTPS enforced via .htaccess (301 redirect)
- [x] Direct PHP file access blocked (.htaccess THE_REQUEST rules)
- [x] Clean URLs: /admin → admin.php, /api → api.php, /manual → manual.html
- [x] Security headers: X-Frame-Options DENY, CSP, HSTS, X-Content-Type-Options
- [x] data.json, audit.json, .htaccess, verify-techtiera-credentials.php all blocked from direct access
- [x] Logo base64-embedded (no external requests)
- [x] verify-techtiera-credentials.php loads from above public_html first (fallback to same dir for dev)

### Documentation
- [x] User manual (manual.html) — step-by-step with HTML UI mockups
- [x] Covers: login, roles, add/edit/delete, CSV upload, filters, audit log, public portal
- [x] Field reference table (exact location strings, date format, separation types)
- [x] Troubleshooting section
- [x] Help → link in admin header (opens manual in new tab)

---

## Features — Pending / Future

### High Priority
- [ ] **Move verify-techtiera-credentials.php above public_html** — file sits in web root currently; move to `/home/CPANEL_USERNAME/verify-techtiera-credentials.php` via cPanel File Manager

### Medium Priority
- [ ] **Automated backup** — cPanel cron job to copy data.json daily to a backup folder. Protects against bad CSV upload wiping the database.

### Low Priority / Future
- [ ] **MySQL migration** — flat-file JSON fine up to ~500 records; concurrent writes at scale need a real DB. cPanel gives free MySQL.
- [ ] **Password change UI** — currently requires editing verify-techtiera-credentials.php manually + running PHP hash command
- [ ] **Email notification** — alert admin when a record is added/deleted (cPanel supports PHP mail)

---

## Separation Types

| Value (stored) | Display |
|---|---|
| `voluntary` | Voluntary |
| `involuntary` | Involuntary |
| `project end` | Project End |

---

## Data Schema (data.json)

```json
{
  "id":             "rec_unique_internal_id",
  "reference":      "TT-1042",
  "legalName":      "Aisha Patel",
  "role":           "Senior Analyst",
  "location":       "Hyderabad, India",
  "enterprise":     "TechTiera Corporation India Pvt. Ltd.",
  "dob":            "1990-06-15",
  "startDate":      "2021-03-01",
  "endDate":        "2023-12-31",
  "separationType": "voluntary",
  "lastUpdated":    "2025-05-16 14:30"
}
```

## Audit Schema (audit.json)

```json
{
  "ts":       "2025-05-16 14:30",
  "user":     "admin",
  "action":   "add",
  "ref":      "TT-1042",
  "location": "Hyderabad, India",
  "detail":   ""
}
```

---

## Local Development

```powershell
# From the project folder:
php -S localhost:1000 router.php
```

- Visit http://localhost:1000/ for the public verification page, http://localhost:1000/admin for the admin panel.
- `router.php` reproduces the production `.htaccess` clean-URL routing + sensitive-file blocks for the built-in PHP server.
- First admin load auto-bootstraps `tt-config.json` from `verify-techtiera-credentials.php`. After that, `tt-config.json` is authoritative.
- Plaintext credentials are stored as bcrypt in `verify-techtiera-credentials.php` — the original plaintext lives only in the historical `tt verification live.zip` (kept outside the repo). To set a new password: `php -r "echo password_hash('newpass', PASSWORD_BCRYPT);"` and paste the hash into `tt-config.json`.

## Deployment Checklist

- [ ] Upload `employee verification.zip` to cPanel File Manager
- [ ] Extract into `verify.techteira.com` root folder
- [ ] Confirm these files present at root: `.htaccess`, `admin.php`, `api.php`, `index.html`, `data.json`, `audit.json`, `manual.html`, `verify-techtiera-credentials.php`, `logo.svg`
- [ ] Set `data.json` and `audit.json` permissions to **644** (or 666 if writes fail)
- [ ] Move `verify-techtiera-credentials.php` to `/home/CPANEL_USERNAME/verify-techtiera-credentials.php`
- [ ] Test login at https://verify.techteira.com/admin
- [ ] Test public lookup at https://verify.techteira.com
- [ ] Test CSV upload with template
- [ ] Confirm audit log records actions
- [ ] Distribute passwords to location users (see credentials table above)
