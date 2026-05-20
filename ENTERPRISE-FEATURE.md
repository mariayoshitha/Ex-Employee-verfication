# Enterprise Support — Progress & Behavior Notes

## What changed

Added **Enterprise (legal entity)** as a first-class field across the system, plus a full **Admin Settings UI** to manage locations, enterprises, and user accounts. Stored in `tt-config.json` outside the web root (next to `tt-credentials.php`).

## Data model

Each employee record now carries `enterprise` alongside `location`. Enterprises are tied to a single location (1:N: one location can hold many enterprises; an enterprise belongs to one location).

```
location  ──┬── enterprise 1
            ├── enterprise 2
            └── enterprise 3
```

## Seeded locations (9)

Chicago USA, Hyderabad India, Manila Philippines, Singapore, Kuala Lumpur Malaysia, Sydney Australia, Dubai UAE, Bangkok Thailand, Jakarta Indonesia.

## Seeded enterprises (6) — admin can add the rest from Settings

| Location | Enterprise |
| --- | --- |
| Chicago, USA | TechTiera Corporation |
| Hyderabad, India | TechTiera Corporation India Pvt. Ltd. |
| Singapore | TechTiera Pte. Ltd. |
| Kuala Lumpur, Malaysia | TechTiera Sdn. Bhd |
| Manila, Philippines | TechTiera Services Inc. |
| Jakarta, Indonesia | PT TechTiera Services |

Sydney, Dubai, Bangkok start empty — add via **Settings → Enterprises**.

## Migration (one-time, automatic)

On first admin page load after this change:

1. `tt-config.json` auto-created (locations + enterprises + users seeded; users migrated from `tt-credentials.php` with bcrypt hashes preserved).
2. All existing employee records get `enterprise = "TechTiera Corporation India Pvt. Ltd."` (since current dataset is India-only).

Idempotent — re-running causes no changes.

## User scopes (admin chooses per user)

| Role | Location | Enterprise | What they see |
| --- | --- | --- | --- |
| `admin` | — | — | Everything across all locations and enterprises |
| `location` | set | empty | All enterprises within that location |
| `location` | set | set | Only their enterprise at their location (locked in UI + CSV) |

Admin-only safeguards: cannot delete last admin, cannot delete own account, cannot delete a location/enterprise still referenced by records or users.

## CSV behavior

### Upload
- New optional column **Enterprise** (also accepts `entity`, `company`, `legalentity`, `organization`, `organisation`).
- If a row's Enterprise cell is blank → defaults to the user's primary enterprise (if set).
- Constrained location users have Enterprise force-set; CSV column is ignored.
- **Duplicate handling: upsert by Employee ID (case-insensitive).** A row with an existing ID updates the matching record in place, keeping the original internal `id` and refreshing all other fields including `lastUpdated`. No duplicate row is created. Other records are untouched.

### Template
- Admin template has Location + Enterprise columns with one example per seeded entity.
- Location-user template hides Location, shows Enterprise pre-filled with the user's default (or blank if unscoped).

### Export
- Adds **Enterprise** column. Round-trips cleanly back into upload.

### Excel edits
- Date formats are tolerant: `DD-MM-YYYY`, `YYYY-MM-DD`, and `YYYY/MM/DD` all accepted on import. Excel locale changes don't break re-upload.
- CSV-injection prevention: cells starting with `=`, `+`, `-`, `@`, tab, or CR get a leading apostrophe on import (Excel treats as literal).
- File-type whitelist on upload (MIME + extension must be `.csv`).

### Manual Add (admin panel form)
- Duplicate Employee ID → blocks insert with error: `Employee ID "X" already exists. Use Edit to update it.`
- Edit form keeps original `id`, refreshes all other fields.

## Public verification page (`index.html`)

- API now returns `enterprise` field.
- Result card shows enterprise name in bold dark blue, directly below the legal name. Renders only if the record has an enterprise set.

## Admin UI additions

- **Settings** link in header (admin only).
- `/admin?page=settings` page with three managed sections:
  - **Locations** — add (free-form name), delete (blocked if in use).
  - **Enterprises** — add (name + parent location), edit (renames cascade through all records and user scopes), delete (blocked if in use).
  - **Users** — add (username 3–32 chars, password ≥8 chars, role, location, optional enterprise scope), edit (role/location/enterprise + optional password reset), delete.
- Records table gains an Enterprise column + a filter dropdown (admin sees all enterprises; location user sees only ones at their location; enterprise-scoped user has the filter locked).
- Add/Edit record modals get cascading dropdowns: choose Location → Enterprise list filters to that location's entities.

## Files touched

| File | Change |
| --- | --- |
| `admin.php` | Config loader, bootstrap + backfill, enterprise wired through add/edit/upload/export/filter, Settings page + handlers, scope enforcement, table column, modal cascades. |
| `api.php` | `enterprise` in response; reads card variant from `tt-config.json`. |
| `index.html` | Enterprise rendered under name on verification result. |
| `.htaccess` | Blocks `tt-config.json`, `tt-config.json.lock`, and `audit-YYYY-MM.json` archives from direct access. |
| `tt-config.json` (new, outside webroot) | Auto-created on first admin load. Holds locations, enterprises, users. |

## Storage

- `tt-config.json` — preferred path: `/home/<cpanel-user>/tt-config.json` (sibling of `tt-credentials.php`). Falls back to web root if parent dir isn't writable (still blocked by `.htaccess`).
- `tt-credentials.php` — retained as the seed source on first bootstrap. Optional thereafter; the app reads `tt-config.json` for all auth.

## Security posture

- Passwords: bcrypt cost 12.
- Login: 5-attempt IP lockout (15 min); session regenerated on success.
- CSRF token on every POST.
- Sessions: `httponly`, `samesite=Strict`, `secure=1`, 30-minute idle timeout.
- HTTPS forced; HSTS + CSP + X-Frame DENY + nosniff headers.
- All sensitive files blocked by `.htaccess`.
- Admin actions audit-logged (add, edit, delete, upload, settings).

## Smoke-test results

Bootstrap on a copy of the live `data.json`:
- 9 locations seeded, 6 enterprises seeded, 10 users migrated.
- 37 records, 37 missing enterprise → 0 after backfill.
- `tt-config.json` written (~3.4 KB).

Duplicate upload test:
- 2 starting records (`TT001`, `TT002`).
- CSV with `TT001` updated name + end date → record at index 0 updated in place, original `id` preserved, `TT002` untouched, count stays at 2.

## Deploy checklist

1. Upload `admin.php`, `api.php`, `index.html`, `.htaccess` to `public_html`.
2. Ensure the parent directory of `public_html` is writable by the web user (so PHP can create `tt-config.json` there). If not, file falls back to web root and stays blocked by `.htaccess`.
3. Log into `/admin` as `admin` — bootstrap and backfill run automatically.
4. Go to **Settings → Enterprises** and add the missing entities (Sydney, Dubai, Bangkok) if needed.
5. Create per-user accounts with the right scope.
6. Verify a record on `/` to confirm the enterprise renders below the name.
