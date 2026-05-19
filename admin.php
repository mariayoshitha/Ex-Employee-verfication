<?php
/**
 * Employment Verification — Admin Panel
 * Multi-user, location-scoped access control.
 */

// ── Secure session settings ──────────────────────────────────────────────────
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.cookie_secure', 1); // enforced — HTTPS required by .htaccess
session_start();

// Clean URL for this panel (avoids redirecting to blocked admin.php)
define('ADMIN_URL', rtrim(str_replace('admin.php', 'admin', $_SERVER['SCRIPT_NAME']), '/'));

// ── Session timeout: 30 minutes ──────────────────────────────────────────────
if (isset($_SESSION['admin_auth'])) {
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > 1800) {
        session_unset(); session_destroy();
        header('Location: ' . ADMIN_URL . '?msg=timeout'); exit;
    }
    $_SESSION['last_activity'] = time();
}

// ── CSRF token ───────────────────────────────────────────────────────────────
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ── CONFIG ───────────────────────────────────────────────────────────────────
define('DATA_FILE',  __DIR__ . '/data.json');
define('AUDIT_FILE', __DIR__ . '/audit.json');

define('LOCATIONS', [
    'Chicago, USA',
    'Hyderabad, India',
    'Manila, Philippines',
    'Singapore',
    'Kuala Lumpur, Malaysia',
    'Sydney, Australia',
    'Dubai, UAE',
    'Bangkok, Thailand',
    'Jakarta, Indonesia',
]);

// ── Credentials: loaded from OUTSIDE public_html ────────────────────────────
// File: /home/YOUR_CPANEL_USERNAME/tt-credentials.php
// This keeps passwords out of the web root entirely.
// After uploading, move tt-credentials.php one level above public_html and
// update the path below to match your cPanel username.
$_credFile = dirname(__DIR__) . '/tt-credentials.php';
if (!file_exists($_credFile)) {
    // Fallback for local dev: look in same directory
    $_credFile = __DIR__ . '/tt-credentials.php';
}
if (!file_exists($_credFile)) {
    http_response_code(500);
    die('Server configuration error: credentials file not found.');
}
require $_credFile;
// TT_USERS constant is now defined by tt-credentials.php
define('USERS', TT_USERS);

// ── Data helpers ─────────────────────────────────────────────────────────────
function loadData(): array {
    if (!file_exists(DATA_FILE)) return [];
    $data = json_decode(file_get_contents(DATA_FILE), true);
    return is_array($data) ? array_values($data) : [];
}

function saveData(array $data): bool {
    $json = json_encode(array_values($data), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($json === false) return false;
    return file_put_contents(DATA_FILE, $json, LOCK_EX) !== false;
}


function generateId(): string { return uniqid('rec_', true); }
function nowStamp(): string   { return date('Y-m-d H:i'); }

// ── Audit log ─────────────────────────────────────────────────────────────────
function loadAudit(): array {
    if (!file_exists(AUDIT_FILE)) return [];
    $d = json_decode(file_get_contents(AUDIT_FILE), true);
    return is_array($d) ? $d : [];
}
function logAudit(string $user, string $action, string $ref, string $location, string $detail = ''): void {
    $log = loadAudit();
    array_unshift($log, [
        'ts'       => nowStamp(),
        'user'     => $user,
        'action'   => $action,
        'ref'      => $ref,
        'location' => $location,
        'detail'   => $detail,
    ]);
    if (count($log) > 500) $log = array_slice($log, 0, 500);
    file_put_contents(AUDIT_FILE, json_encode($log, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
}

// Display YYYY-MM-DD as DD-MM-YYYY in tables
function displayDate(string $d): string {
    if (!$d) return '—';
    $parts = explode('-', $d);
    if (count($parts) === 3 && strlen($parts[0]) === 4) {
        return $parts[2] . '-' . $parts[1] . '-' . $parts[0];
    }
    return $d;
}

// Strip spreadsheet formula triggers to prevent CSV injection
function sanitizeText(string $v, int $maxLen = 200): string {
    $v = substr(trim($v), 0, $maxLen);
    if ($v !== '' && in_array($v[0], ['=', '+', '-', '@', "\t", "\r"], true)) {
        $v = "'" . $v; // prefix apostrophe — Excel treats as literal
    }
    return $v;
}

// Validate date format YYYY-MM-DD, return '' if invalid
function validateDate(string $d): string {
    $d = normalizeDate($d);
    return preg_match('/^\d{4}-\d{2}-\d{2}$/', $d) ? $d : '';
}

// Convert DD-MM-YYYY, DD/MM/YYYY, YYYY/MM/DD → YYYY-MM-DD
function normalizeDate(string $d): string {
    $d = trim($d);
    if (!$d) return '';
    if (preg_match('/^(\d{4})[-\/\.](\d{1,2})[-\/\.](\d{1,2})$/', $d, $m))
        return sprintf('%04d-%02d-%02d', $m[1], $m[2], $m[3]);
    if (preg_match('/^(\d{1,2})[-\/\.](\d{1,2})[-\/\.](\d{4})$/', $d, $m))
        return sprintf('%04d-%02d-%02d', $m[3], $m[2], $m[1]);
    return $d;
}

// Fuzzy-match a raw location string to the canonical LOCATIONS list
function matchLocation(string $raw): string {
    $raw = trim($raw);
    if (!$raw) return '';
    $v = strtolower(preg_replace('/[^a-z\s]/i', '', $raw));
    foreach (LOCATIONS as $loc) {
        if (strtolower($loc) === strtolower($raw)) return $loc;  // exact
    }
    foreach (LOCATIONS as $loc) {
        $lv = strtolower(preg_replace('/[^a-z\s]/i', '', $loc));
        if (str_contains($lv, $v) || str_contains($v, $lv)) return $loc;  // partial
    }
    return $raw;
}

function cleanRow(array $colMap, array $row, string $location = ''): array {
    $get = fn($key) => isset($colMap[$key]) && $colMap[$key] !== false
        ? trim($row[$colMap[$key]] ?? '') : '';
    $rawLoc = $location ?: $get('location');
    $allowedSep = ['voluntary', 'involuntary', 'project end'];
    $sep = strtolower(trim($get('separationType')));
    if (!in_array($sep, $allowedSep, true)) $sep = 'voluntary';
    return [
        'id'             => generateId(),
        'reference'      => sanitizeText($get('reference'), 50),
        'legalName'      => sanitizeText($get('legalName'), 150),
        'role'           => sanitizeText($get('role'), 150),
        'location'       => matchLocation($rawLoc),
        'dob'            => validateDate($get('dob')),
        'startDate'      => validateDate($get('startDate')),
        'endDate'        => validateDate($get('endDate')),
        'separationType' => $sep,
        'lastUpdated'    => nowStamp(),
    ];
}

// ── CSV Template Download ─────────────────────────────────────────────────────
if (isset($_GET['download']) && $_GET['download'] === 'template' && isset($_SESSION['admin_auth'])) {
    $isAdm = ($_SESSION['user_role'] ?? '') === 'admin';
    $myLoc = $_SESSION['user_location'] ?? '';

    $headers = $isAdm
        ? ['Employee ID','Name','Role','Location','DOB','Start Date','End Date','Separation Type']
        : ['Employee ID','Name','Role','DOB','Start Date','End Date','Separation Type'];

    $note = 'NOTE: Replace example rows below with real data. Rows starting with EXAMPLE- or NOTE: are skipped automatically.';

    $rows = $isAdm ? [
        ['EXAMPLE-001','Full Legal Name','Software Engineer',  'Chicago, USA',          '1990-01-15','2022-03-01','2025-12-31','voluntary'],
        ['EXAMPLE-002','Full Legal Name','Project Manager',    'Hyderabad, India',      '1988-06-20','2021-07-15','2025-11-30','involuntary'],
        ['EXAMPLE-003','Full Legal Name','Business Analyst',   'Manila, Philippines',   '1992-11-05','2023-01-10','2025-10-15','project end'],
        ['EXAMPLE-004','Full Legal Name','Operations Lead',    'Singapore',             '1991-03-22','2020-09-01','2025-08-31','voluntary'],
        ['EXAMPLE-005','Full Legal Name','HR Coordinator',     'Kuala Lumpur, Malaysia','1994-07-14','2022-06-15','2025-07-20','involuntary'],
        ['EXAMPLE-006','Full Legal Name','Finance Analyst',    'Sydney, Australia',     '1989-12-01','2019-04-01','2025-06-30','voluntary'],
        ['EXAMPLE-007','Full Legal Name','Recruitment Lead',   'Dubai, UAE',            '1993-09-18','2021-11-01','2025-05-15','project end'],
        ['EXAMPLE-008','Full Legal Name','Training Specialist','Bangkok, Thailand',     '1995-05-30','2023-02-01','2025-09-30','involuntary'],
        ['EXAMPLE-009','Full Legal Name','Admin Executive',    'Jakarta, Indonesia',    '1996-08-10','2022-08-15','2025-11-01','voluntary'],
    ] : [
        ['EXAMPLE-001','Full Legal Name','Software Engineer','1990-01-15','2022-03-01','2025-12-31','voluntary'],
        ['EXAMPLE-002','Full Legal Name','Project Manager',  '1988-06-20','2021-07-15','2025-11-30','involuntary'],
        ['EXAMPLE-003','Full Legal Name','Business Analyst', '1992-11-05','2023-01-10','2025-10-15','project end'],
        ['EXAMPLE-004','Full Legal Name','Operations Lead',  '1991-03-22','2020-09-01','2025-08-31','voluntary'],
        ['EXAMPLE-005','Full Legal Name','HR Coordinator',   '1994-07-14','2022-06-15','2025-07-20','involuntary'],
        ['EXAMPLE-006','Full Legal Name','Finance Analyst',  '1989-12-01','2019-04-01','2025-06-30','voluntary'],
        ['EXAMPLE-007','Full Legal Name','Recruitment Lead', '1993-09-18','2021-11-01','2025-05-15','project end'],
    ];

    $filename = $isAdm ? 'upload-template-admin.csv' : 'upload-template-' . preg_replace('/[^a-z0-9]/i','-', strtolower($myLoc)) . '.csv';
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Cache-Control: no-cache');
    $out = fopen('php://output', 'w');
    fputcsv($out, $headers);
    fputcsv($out, [$note]);
    foreach ($rows as $row) fputcsv($out, $row);
    fclose($out);
    exit;
}

// ── Handle POST ───────────────────────────────────────────────────────────────
$error = ''; $success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // ── Login (IP-based lockout — session-clearing cannot bypass) ────────────────
    if ($action === 'login') {
        $loginIp  = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $rlFile   = sys_get_temp_dir() . '/tt_adm_' . md5($loginIp) . '.json';
        $rl       = @json_decode(@file_get_contents($rlFile), true) ?: ['attempts' => 0, 'lockout_until' => 0];
        if (time() < (int)$rl['lockout_until']) {
            $mins  = (int)ceil(($rl['lockout_until'] - time()) / 60);
            $error = "Too many failed attempts. Try again in {$mins} minute(s).";
        } else {
            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';
            $user     = USERS[$username] ?? null;
            if ($user && password_verify($password, $user['password'])) {
                @file_put_contents($rlFile, json_encode(['attempts' => 0, 'lockout_until' => 0]), LOCK_EX);
                session_regenerate_id(true);
                $_SESSION['admin_auth']    = true;
                $_SESSION['user_role']     = $user['role'];
                $_SESSION['user_location'] = $user['location'];
                $_SESSION['username']      = $username;
                $_SESSION['last_activity'] = time();
                header('Location: ' . ADMIN_URL); exit;
            } else {
                $rl['attempts']++;
                if ($rl['attempts'] >= 5) {
                    $rl['lockout_until'] = time() + 900;
                    $rl['attempts']      = 0;
                    $error = 'Too many failed attempts. Locked for 15 minutes.';
                } else {
                    $left  = 5 - $rl['attempts'];
                    $error = "Invalid username or password. {$left} attempt(s) remaining.";
                }
                @file_put_contents($rlFile, json_encode($rl), LOCK_EX);
            }
        }
    }

    // ── Logout ────────────────────────────────────────────────────────────────
    if ($action === 'logout') {
        // CSRF check for logout
        if (isset($_POST['csrf']) && isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf'])) {
            session_unset(); session_destroy();
        }
        header('Location: ' . ADMIN_URL); exit;
    }

    // ── Auth wall ─────────────────────────────────────────────────────────────
    if (!isset($_SESSION['admin_auth'])) {
        header('Location: ' . ADMIN_URL); exit;
    }

    // ── CSRF check ────────────────────────────────────────────────────────────
    if (!isset($_POST['csrf']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf'])) {
        http_response_code(403); die('Invalid security token. Please go back and try again.');
    }

    $isAdminAction = ($_SESSION['user_role'] ?? '') === 'admin';
    $myLocation    = $_SESSION['user_location'] ?? '';
    $allowedSep    = ['voluntary', 'involuntary', 'project end'];

    // ── Upload CSV ────────────────────────────────────────────────────────────
    if ($action === 'upload_csv') {
        if (isset($_FILES['csv_file']) && $_FILES['csv_file']['error'] === UPLOAD_ERR_OK) {
            // Validate file type
            $finfo   = new finfo(FILEINFO_MIME_TYPE);
            $mime    = $finfo->file($_FILES['csv_file']['tmp_name']);
            $ext     = strtolower(pathinfo($_FILES['csv_file']['name'], PATHINFO_EXTENSION));
            $okMimes = ['text/csv','text/plain','application/csv','application/vnd.ms-excel'];
            if (!in_array($mime, $okMimes, true) || $ext !== 'csv') {
                $error = 'Invalid file. Please upload a .csv file only.';
                goto done;
            }
            $parsed = [];
            if (($handle = fopen($_FILES['csv_file']['tmp_name'], 'r')) !== false) {
                $rawHeaders = fgetcsv($handle);
                if ($rawHeaders) {
                    $headers = array_map(fn($h) => strtolower(trim(preg_replace('/\s+/', '', $h))), $rawHeaders);
                    $find    = fn($opts) => array_reduce($opts, fn($c, $o) => $c !== false ? $c : array_search($o, $headers), false);
                    $colMap  = [
                        'reference'      => $find(['employeeid','reference','empid','id']),
                        'legalName'      => $find(['name','legalname','fullname','employeename']),
                        'role'           => $find(['role','jobtitle','designation','title','position']),
                        'location'       => $find(['location','office','city','branch']),
                        'dob'            => $find(['dob','dateofbirth','birthdate']),
                        'startDate'      => $find(['startdate','start','joiningdate','dateofjoining']),
                        'endDate'        => $find(['enddate','end','lastworkingdate','relievingdate']),
                        'separationType' => $find(['separationtype','separation','terminationtype','termination','exittype']),
                    ];
                    while (($row = fgetcsv($handle)) !== false) {
                        if (count(array_filter($row)) === 0) continue;
                        // Skip example/note rows
                        $refVal = trim($row[$colMap['reference'] ?? 0] ?? '');
                        if (preg_match('/^(e\.g\.|example[-\s]|example$|sample|notes?$|note:|format)/i', $refVal)) continue;
                        // Non-admin: force location to their own
                        $loc    = $isAdminAction ? '' : $myLocation;
                        $record = cleanRow($colMap, $row, $loc);
                        if ($record['reference']) $parsed[] = $record;
                    }
                }
                fclose($handle);
            }
            if ($parsed) {
                // Always merge — upsert by reference (case-insensitive)
                $existing     = loadData();
                $existingRefs = array_column($existing, 'reference');
                $added = 0; $updated = 0;
                foreach ($parsed as $new) {
                    $idx = array_search(strtolower($new['reference']), array_map('strtolower', $existingRefs));
                    if ($idx !== false) {
                        $existing[$idx] = array_merge($existing[$idx], $new, ['id' => $existing[$idx]['id']]);
                        $updated++;
                    } else {
                        $existing[] = $new;
                        $added++;
                    }
                }
                if (!saveData($existing)) {
                    $error = 'Failed to write data.json — check file permissions (chmod 666).';
                    goto done;
                }
                logAudit(
                    $_SESSION['username'] ?? '',
                    'upload',
                    '',
                    $isAdminAction ? 'all' : $myLocation,
                    '+' . $added . ' upd:' . $updated
                );
                header('Location: ' . ADMIN_URL . '?msg=uploaded'); exit;
            } else {
                $error = 'No valid records found. Check your CSV column names match the template.';
            }
        } else {
            $error = 'File upload failed. Please try again.';
        }
    }

    // ── Add record ────────────────────────────────────────────────────────────
    if ($action === 'add_record') {
        $sep    = strtolower(trim($_POST['separationType'] ?? ''));
        $newRef = sanitizeText(trim($_POST['reference'] ?? ''), 50);
        if (!$newRef) { $error = 'Employee ID is required.'; goto done; }
        if (!in_array($sep, $allowedSep, true)) { $error = 'Invalid separation type.'; goto done; }
        $loc  = $isAdminAction ? trim($_POST['location'] ?? '') : $myLocation;
        $data = loadData();
        // Duplicate Employee ID check
        $existing = array_map('strtolower', array_column($data, 'reference'));
        if (in_array(strtolower($newRef), $existing, true)) {
            $error = 'Employee ID "' . htmlspecialchars($newRef) . '" already exists. Use Edit to update it.';
            goto done;
        }
        $data[] = [
            'id'             => generateId(),
            'reference'      => $newRef,
            'legalName'      => sanitizeText(trim($_POST['legalName'] ?? ''), 150),
            'role'           => sanitizeText(trim($_POST['role'] ?? ''), 150),
            'location'       => $loc,
            'dob'            => normalizeDate(trim($_POST['dob'] ?? '')),
            'startDate'      => normalizeDate(trim($_POST['startDate'] ?? '')),
            'endDate'        => normalizeDate(trim($_POST['endDate'] ?? '')),
            'separationType' => $sep,
            'lastUpdated'    => nowStamp(),
        ];
        if (!saveData($data)) { $error = 'Failed to write data.json — check file permissions.'; goto done; }
        logAudit($_SESSION['username'] ?? '', 'add', $newRef, $loc);
        header('Location: ' . ADMIN_URL . '?msg=added'); exit;
    }

    // ── Edit record ───────────────────────────────────────────────────────────
    if ($action === 'edit_record') {
        $sep = strtolower(trim($_POST['separationType'] ?? ''));
        if (!in_array($sep, $allowedSep, true)) { $error = 'Invalid separation type.'; goto done; }
        $data = loadData();
        $id   = $_POST['id'] ?? '';
        foreach ($data as &$record) {
            if ($record['id'] !== $id) continue;
            // Location users can only edit their own location's records
            if (!$isAdminAction && ($record['location'] ?? '') !== $myLocation) {
                $error = 'Access denied.'; goto done;
            }
            $record['reference']      = trim($_POST['reference']);
            $record['legalName']      = trim($_POST['legalName']);
            $record['role']           = trim($_POST['role'] ?? '');
            $record['location']       = $isAdminAction ? trim($_POST['location'] ?? '') : $myLocation;
            $record['dob']            = normalizeDate(trim($_POST['dob']));
            $record['startDate']      = normalizeDate(trim($_POST['startDate']));
            $record['endDate']        = normalizeDate(trim($_POST['endDate']));
            $record['separationType'] = $sep;
            $record['lastUpdated']    = nowStamp();
            break;
        }
        if (!saveData($data)) { $error = 'Failed to write data.json — check file permissions.'; goto done; }
        $editRef = trim($_POST['reference'] ?? '');
        $editLoc = $isAdminAction ? trim($_POST['location'] ?? '') : $myLocation;
        logAudit($_SESSION['username'] ?? '', 'edit', $editRef, $editLoc);
        header('Location: ' . ADMIN_URL . '?msg=edited'); exit;
    }

    // ── Delete record ─────────────────────────────────────────────────────────
    if ($action === 'delete_record') {
        $id   = $_POST['id'] ?? '';
        $data = loadData();
        // Find the record first to authorise
        $target = null;
        foreach ($data as $r) { if ($r['id'] === $id) { $target = $r; break; } }
        if ($target && !$isAdminAction && ($target['location'] ?? '') !== $myLocation) {
            $error = 'Access denied.'; goto done;
        }
        if (!saveData(array_values(array_filter($data, fn($r) => $r['id'] !== $id)))) {
            $error = 'Failed to write data.json — check file permissions.'; goto done;
        }
        logAudit(
            $_SESSION['username'] ?? '',
            'delete',
            $target['reference'] ?? '',
            $target['location']  ?? ''
        );
        header('Location: ' . ADMIN_URL . '?msg=deleted'); exit;
    }

    done:
}

// ── View variables ────────────────────────────────────────────────────────────
$isLoggedIn  = isset($_SESSION['admin_auth']);
$isAdmin     = $isLoggedIn && ($_SESSION['user_role']     ?? '') === 'admin';
$myLocation  = $_SESSION['user_location'] ?? '';
$username    = $_SESSION['username']      ?? '';

$records = $isLoggedIn ? loadData() : [];
if (!$isAdmin && $myLocation !== '') {
    $records = array_values(array_filter($records, fn($r) => ($r['location'] ?? '') === $myLocation));
}
$total    = count($records);
$search   = trim($_GET['q'] ?? '');
$filtered = $records;
if ($search) {
    $q        = strtolower($search);
    $filtered = array_values(array_filter($records, fn($r) =>
        str_contains(strtolower($r['reference'] ?? ''), $q) ||
        str_contains(strtolower($r['legalName'] ?? ''), $q) ||
        str_contains(strtolower($r['role']      ?? ''), $q) ||
        str_contains(strtolower($r['location']  ?? ''), $q)
    ));
}
$filterType     = trim($_GET['type'] ?? '');
$filterLocation = $isAdmin ? trim($_GET['loc'] ?? '') : '';
if ($filterType !== '') {
    $filtered = array_values(array_filter($filtered, fn($r) => strcasecmp($r['separationType'] ?? '', $filterType) === 0));
}
if ($filterLocation !== '') {
    $filtered = array_values(array_filter($filtered, fn($r) => ($r['location'] ?? '') === $filterLocation));
}

// ── CSV Export (uses same filters/scope as the table view) ────────────────────
if (isset($_GET['download']) && $_GET['download'] === 'export' && $isLoggedIn) {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="employees-export-' . date('Y-m-d') . '.csv"');
    header('Cache-Control: no-cache');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['Employee ID','Name','Role','Location','DOB','Start Date','End Date','Separation Type','Last Updated']);
    foreach ($filtered as $r) {
        fputcsv($out, [
            $r['reference']      ?? '',
            $r['legalName']      ?? '',
            $r['role']           ?? '',
            $r['location']       ?? '',
            $r['dob']            ?? '',
            $r['startDate']      ?? '',
            $r['endDate']        ?? '',
            $r['separationType'] ?? '',
            $r['lastUpdated']    ?? '',
        ]);
    }
    fclose($out);
    exit;
}

// ── Pagination ────────────────────────────────────────────────────────────────
$perPage       = (int)($_GET['pp'] ?? 50);
if (!in_array($perPage, [25, 50, 100], true)) $perPage = 50;
$totalFiltered = count($filtered);
$totalPages    = max(1, (int)ceil($totalFiltered / $perPage));
$page          = max(1, min($totalPages, (int)($_GET['p'] ?? 1)));
$paginated     = array_slice($filtered, ($page - 1) * $perPage, $perPage);

// Build URL helper for pagination links (preserves existing filters)
function pageUrl(array $extra = []): string {
    $params = array_merge(
        array_filter([
            'q'    => trim($_GET['q']   ?? ''),
            'type' => trim($_GET['type'] ?? ''),
            'loc'  => trim($_GET['loc']  ?? ''),
            'pp'   => ($_GET['pp'] ?? '') !== '50' ? ($_GET['pp'] ?? '') : '',
        ]),
        $extra
    );
    $qs = http_build_query(array_filter($params, fn($v) => $v !== ''));
    return ADMIN_URL . ($qs ? '?' . $qs : '');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>TechTiera — Admin Panel</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; color: #111827; min-height: 100vh; }

    header { background: #0d1e3c; color: white; padding: 16px 32px; display: flex; align-items: center; justify-content: space-between; box-shadow: 0 2px 8px rgba(0,0,0,0.2); }
    .header-left { display: flex; align-items: center; gap: 14px; }
    .logo img { height: 36px; display: block; }
    header h1 { font-size: 17px; font-weight: 600; }
    header p  { font-size: 11.5px; color: #94a3b8; margin-top: 2px; }
    .user-badge { background: rgba(255,255,255,0.12); border: 1px solid rgba(255,255,255,0.2); border-radius: 20px; padding: 4px 12px; font-size: 12px; color: #e2e8f0; }
    .btn-logout { background: rgba(255,255,255,0.1); color: white; border: 1px solid rgba(255,255,255,0.2); padding: 7px 16px; border-radius: 8px; font-size: 13px; font-weight: 500; cursor: pointer; transition: background 0.15s; }
    .btn-logout:hover { background: rgba(255,255,255,0.2); }

    .login-wrap { display: flex; align-items: center; justify-content: center; min-height: calc(100vh - 66px); padding: 20px; }
    .login-card { background: white; border-radius: 16px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); width: 100%; max-width: 400px; overflow: hidden; }
    .login-head { background: linear-gradient(135deg,#0d1e3c,#1a3a64); padding: 28px 32px; color: white; }
    .login-head h2 { font-size: 17px; margin-bottom: 5px; }
    .login-head p  { font-size: 12.5px; color: #94a3b8; }
    .login-body { padding: 28px 32px; }

    .wrap { max-width: 1400px; margin: 0 auto; padding: 28px 24px; }

    .flash { padding: 12px 16px; border-radius: 8px; font-size: 13.5px; font-weight: 500; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }
    .flash.success { background: #f0fdf4; border: 1.5px solid #bbf7d0; color: #166534; }
    .flash.error   { background: #fff5f5; border: 1.5px solid #fecaca; color: #b91c1c; }

    .stats { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
    .stat-card { background: white; border-radius: 10px; padding: 16px 20px; flex: 1; min-width: 140px; box-shadow: 0 1px 4px rgba(0,0,0,0.06); }
    .stat-card .val { font-size: 28px; font-weight: 700; color: #1a2e4a; }
    .stat-card .lbl { font-size: 12px; color: #6b7280; margin-top: 2px; }

    .toolbar { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; flex-wrap: nowrap; }
    .search-box { flex: 0 0 25%; min-width: 0; }
    .search-box input { width: 100%; padding: 8px 10px 8px 32px; border: 1.5px solid #e5e7eb; border-radius: 8px; font-size: 13px; outline: none; background: white url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%239ca3af' stroke-width='2.5' stroke-linecap='round'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cpath d='m21 21-4.35-4.35'/%3E%3C/svg%3E") no-repeat 10px center; box-sizing: border-box; }
    .search-box input:focus { border-color: #0066cc; box-shadow: 0 0 0 3px rgba(0,102,204,0.1); }

    .btn { padding: 10px 18px; border: none; border-radius: 8px; font-size: 13.5px; font-weight: 600; cursor: pointer; transition: background 0.15s; }
    .btn-primary   { background: #0d1e3c; color: white; } .btn-primary:hover   { background: #1a3a64; }
    .btn-success   { background: #16a34a; color: white; } .btn-success:hover   { background: #15803d; }
    .btn-danger    { background: #dc2626; color: white; } .btn-danger:hover    { background: #b91c1c; }
    .btn-outline   { background: white; color: #374151; border: 1.5px solid #d1d5db; } .btn-outline:hover { background: #f9fafb; }
    .btn-sm { padding: 6px 12px; font-size: 12.5px; }
    a.portal-link { color: #3b82f6; text-decoration: none; font-size: 13px; font-weight: 500; }
    a.portal-link:hover { text-decoration: underline; }

    .table-wrap { background: white; border-radius: 12px; box-shadow: 0 1px 4px rgba(0,0,0,0.06); overflow: hidden; }
    .table-header { padding: 16px 20px; border-bottom: 1px solid #f3f4f6; display: flex; align-items: center; justify-content: space-between; }
    .table-header h3 { font-size: 14px; font-weight: 600; color: #374151; }
    .table-header span { font-size: 12px; color: #9ca3af; }
    table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
    thead th { background: #f9fafb; padding: 11px 14px; text-align: left; font-size: 11.5px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.4px; border-bottom: 1px solid #f3f4f6; white-space: nowrap; }
    tbody tr { border-bottom: 1px solid #f9fafb; transition: background 0.1s; }
    tbody tr:hover { background: #fafafa; }
    tbody td { padding: 11px 14px; color: #374151; vertical-align: middle; }
    .ref-code { font-family: 'Courier New', monospace; font-size: 12.5px; background: #f3f4f6; padding: 3px 8px; border-radius: 4px; }
    .badge { display: inline-flex; align-items: center; padding: 3px 9px; border-radius: 20px; font-size: 11.5px; font-weight: 600; }
    .badge.voluntary   { background: #dcfce7; color: #16a34a; }
    .badge.involuntary { background: #fee2e2; color: #dc2626; }
    .badge.project-end { background: #dbeafe; color: #1d4ed8; }
    .loc-pill { display: inline-flex; align-items: center; gap: 4px; background: #f3f4f6; color: #374151; border-radius: 12px; padding: 2px 8px; font-size: 11.5px; white-space: nowrap; }
    .actions { display: flex; gap: 6px; }
    .empty-state { text-align: center; padding: 48px 20px; color: #9ca3af; font-size: 14px; }

    .upload-section { background: white; border-radius: 12px; padding: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.06); margin-bottom: 24px; }
    .upload-section h3 { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
    .upload-section p  { font-size: 12.5px; color: #6b7280; margin-bottom: 16px; }
    .csv-template { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 14px; font-family: 'Courier New', monospace; font-size: 11.5px; color: #475569; margin-bottom: 16px; overflow-x: auto; white-space: nowrap; }
    .upload-row { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
    .upload-row .form-group { flex: 1; min-width: 200px; margin-bottom: 0; }

    .form-group { margin-bottom: 16px; }
    label { display: block; font-size: 12.5px; font-weight: 600; color: #374151; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.4px; }
    input[type=text], input[type=date], input[type=password], select {
      width: 100%; padding: 10px 14px; border: 1.5px solid #e5e7eb; border-radius: 8px;
      font-size: 14px; outline: none; background: #f9fafb; color: #111827;
      transition: border-color 0.2s, box-shadow 0.2s, background 0.2s;
    }
    input:focus, select:focus { border-color: #0066cc; background: white; box-shadow: 0 0 0 3px rgba(0,102,204,0.1); }
    input[type=file] { width: 100%; padding: 10px; border: 1.5px dashed #d1d5db; border-radius: 8px; font-size: 13.5px; background: #fafafa; cursor: pointer; }
    .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .location-fixed { background: #f3f4f6; border: 1.5px solid #e5e7eb; border-radius: 8px; padding: 10px 14px; font-size: 14px; color: #374151; font-weight: 500; }

    .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 100; align-items: center; justify-content: center; padding: 20px; }
    .modal-overlay.open { display: flex; }
    .modal { background: white; border-radius: 16px; width: 100%; max-width: 560px; max-height: 90vh; overflow-y: auto; box-shadow: 0 20px 60px rgba(0,0,0,0.2); }
    .modal-head { padding: 20px 24px; border-bottom: 1px solid #f3f4f6; display: flex; align-items: center; justify-content: space-between; }
    .modal-head h3 { font-size: 16px; font-weight: 600; }
    .modal-close { background: none; border: none; font-size: 20px; color: #6b7280; cursor: pointer; line-height: 1; padding: 2px 6px; border-radius: 4px; }
    .modal-close:hover { background: #f3f4f6; }
    .modal-body { padding: 24px; }
    .modal-footer { padding: 16px 24px; border-top: 1px solid #f3f4f6; display: flex; justify-content: flex-end; gap: 10px; }

    /* DB Status */
    .db-status { background: white; border-radius: 12px; padding: 20px 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.06); margin-bottom: 24px; }
    .db-status h3 { font-size: 14px; font-weight: 600; margin-bottom: 14px; color: #374151; }
    .loc-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; }
    .loc-card { background: #f8fafc; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px 14px; }
    .loc-card .loc-name { font-size: 12.5px; font-weight: 600; color: #374151; margin-bottom: 4px; }
    .loc-card .loc-count { font-size: 22px; font-weight: 700; color: #0d1e3c; }
    .loc-card .loc-updated { font-size: 11px; color: #9ca3af; margin-top: 2px; }

    /* Audit Log */
    .audit-section { background: white; border-radius: 12px; padding: 20px 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.06); margin-bottom: 24px; }
    .audit-section h3 { font-size: 14px; font-weight: 600; margin-bottom: 14px; color: #374151; }
    .audit-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
    .audit-table th { background: #f9fafb; padding: 9px 12px; text-align: left; font-size: 11px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 0.4px; border-bottom: 1px solid #f3f4f6; }
    .audit-table td { padding: 9px 12px; border-bottom: 1px solid #f9fafb; color: #374151; vertical-align: middle; }
    .audit-table tr:last-child td { border-bottom: none; }
    .audit-badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
    .audit-add    { background: #dcfce7; color: #16a34a; }
    .audit-edit   { background: #dbeafe; color: #1d4ed8; }
    .audit-delete { background: #fee2e2; color: #dc2626; }
    .audit-upload { background: #fef3c7; color: #92400e; }
    .audit-login  { background: #f3f4f6; color: #374151; }
    .audit-empty  { text-align: center; padding: 24px; color: #9ca3af; font-size: 13px; }

    @media (max-width: 640px) {
      .form-row { grid-template-columns: 1fr; }
      .upload-row { flex-direction: column; }
      .stats { flex-direction: column; }
    }
  </style>
</head>
<body>

<header>
  <div class="header-left">
    <div class="logo"><img src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgd2lkdGg9IjQ5NiIgaGVpZ2h0PSIxMDciPgo8cGF0aCBkPSJNMCAwIEMwLjc3OTIzMzI1IC0wLjAwNjU3MTIgMS41NTg0NjY0OSAtMC4wMTMxNDI0IDIuMzYxMzEyODcgLTAuMDE5OTEyNzIgQzQuOTQxMDcxNTYgLTAuMDM5NjI4NjQgNy41MjA3NzIwNiAtMC4wNTEzMDUwNiAxMC4xMDA1ODU5NCAtMC4wNjEyNzkzIEMxMS40MjM4MDk4NSAtMC4wNjczOTI1OSAxMS40MjM4MDk4NSAtMC4wNjczOTI1OSAxMi43NzM3NjU1NiAtMC4wNzM2MjkzOCBDMTcuNDQzNzM4NDYgLTAuMDk0NDgzNzUgMjIuMTEzNjgyMDMgLTAuMTA4Nzg3NjkgMjYuNzgzNjkxNDEgLTAuMTE4MTY0MDYgQzMxLjYwMDA3MzczIC0wLjEyOTIyMTc1IDM2LjQxNTk5MzIxIC0wLjE2MzYxNTk1IDQxLjIzMjIxMjA3IC0wLjIwMzMzNTc2IEM0NC45NDE3ODEwMiAtMC4yMjk1MTkxIDQ4LjY1MTI0MDAyIC0wLjIzNzg1NzQ2IDUyLjM2MDg5MzI1IC0wLjI0MTQ0NTU0IEM1NC4xMzU4NTI3OSAtMC4yNDYzMDc3NyA1NS45MTA4MDc1NCAtMC4yNTc5MTE0MSA1Ny42ODU2NzY1NyAtMC4yNzY0ODM1NCBDNjAuMTc0OTM1MzkgLTAuMzAwOTEwMDUgNjIuNjYzMDAxMDMgLTAuMjk5OTAzODMgNjUuMTUyMzQzNzUgLTAuMjkyOTY4NzUgQzY1Ljg3OTg3MzUgLTAuMzA1Nzc4ODEgNjYuNjA3NDAzMjYgLTAuMzE4NTg4ODcgNjcuMzU2OTc5MzcgLTAuMzMxNzg3MTEgQzczLjQ1NDc5MjI4IC0wLjI3MDEzODg1IDc3LjU5Mjk1NTMxIDEuNjYyNDcyMTMgODIuMDc3MTQ4NDQgNS43NzQ2NTgyIEM4Ni4wMjc5NjYzNyAxMC44ODM0NzQ1IDg2LjQ4NjU4MzIzIDE0LjU4NTk4MDQzIDg2LjQ5NjA5Mzc1IDIwLjg1NzkxMDE2IEM4Ni41MDM1NDExMSAyMi4wMjkxNjk0NiA4Ni41MDM1NDExMSAyMi4wMjkxNjk0NiA4Ni41MTExMzg5MiAyMy4yMjQwOTA1OCBDODYuNTI1NzQ5ODkgMjUuODA4NjYzNzQgODYuNTMyNTYxMDEgMjguMzkzMTc1NTEgODYuNTM4MDg1OTQgMzAuOTc3NzgzMiBDODYuNTQzODM4NTggMzIuNzc1MTYxNzYgODYuNTQ5NTk2MyAzNC41NzI1NDAzIDg2LjU1NTM1ODg5IDM2LjM2OTkxODgyIEM4Ni41NjU4NjYwNiA0MC4xNDAxNzAxNCA4Ni41NzE3MTA0OCA0My45MTA0MDAxNiA4Ni41NzUxOTUzMSA0Ny42ODA2NjQwNiBDODYuNTgwNjc3MyA1Mi41MDYwMjc5MSA4Ni42MDQ3MDAxNiA1Ny4zMzExMDkxOCA4Ni42MzMxNjcyNyA2Mi4xNTYzODQ0NyBDODYuNjUxODE0MjcgNjUuODcwMjAxNzggODYuNjU3MDAwMzYgNjkuNTgzOTUxMzQgODYuNjU4NTMxMTkgNzMuMjk3ODExNTEgQzg2LjY2MTU1Mzk0IDc1LjA3NjM3MjU5IDg2LjY2OTU2OTc1IDc2Ljg1NDkzMjU5IDg2LjY4MjcxNjM3IDc4LjYzMzQ0NzY1IEM4Ni42OTk4MTg5OCA4MS4xMjUxNTIxNiA4Ni42OTc4ODY0MyA4My42MTYxNzAzNiA4Ni42OTE0MDYyNSA4Ni4xMDc5MTAxNiBDODYuNzAwNjIxMDMgODYuODM5MDM1MTkgODYuNzA5ODM1ODIgODcuNTcwMTYwMjIgODYuNzE5MzI5ODMgODguMzIzNDQwNTUgQzg2LjY3NDI5MDExIDkzLjg2Njk5MTEyIDg1LjQxMTI3OTc4IDk3Ljk3MTIwMjIgODEuNTgxMDU0NjkgMTAyLjA0MDI4MzIgQzgwLjY4NTgwMDc4IDEwMi43NTc2NDY0OCA4MC42ODU4MDA3OCAxMDIuNzU3NjQ2NDggNzkuNzcyNDYwOTQgMTAzLjQ4OTUwMTk1IEM3OC44NzMzMzk4NCAxMDQuMjI2MjAxMTcgNzguODczMzM5ODQgMTA0LjIyNjIwMTE3IDc3Ljk1NjA1NDY5IDEwNC45Nzc3ODMyIEM3NC4zMzk1NjQ0NiAxMDcuNjUzMTE0NTMgNzAuOTQ5MDg1MzcgMTA3LjM0NTQ2NjU2IDY2LjYxNTcyMjY2IDEwNy4zNjk4NzMwNSBDNjUuODE4NzM0NTkgMTA3LjM3ODA1MDU0IDY1LjAyMTc0NjUyIDEwNy4zODYyMjgwMyA2NC4yMDA2MDczIDEwNy4zOTQ2NTMzMiBDNjEuNTU1Mjk1MzMgMTA3LjQxOTUyMjY1IDU4LjkxMDAzNzIzIDEwNy40MzYwMzA2OCA1Ni4yNjQ2NDg0NCAxMDcuNDUwNDM5NDUgQzU1LjM2MDc2NTExIDEwNy40NTU3NjMxMyA1NC40NTY4ODE3OSAxMDcuNDYxMDg2ODEgNTMuNTI1NjA4MDYgMTA3LjQ2NjU3MTgxIEM0OC43Mzc3ODM3OSAxMDcuNDkzMzE1MDIgNDMuOTQ5OTg1NjUgMTA3LjUxMjY4Mjc5IDM5LjE2MjEwOTM4IDEwNy41MjcwOTk2MSBDMzQuMjI1NzQ5OTQgMTA3LjU0MzcxNTIzIDI5LjI5MDA2MjMzIDEwNy41ODg0NjM0OSAyNC4zNTM5NTYyMiAxMDcuNjM5NDcxMDUgQzIwLjU1MTY5OTU1IDEwNy42NzMyMDIwNiAxNi43NDk2MDA4MyAxMDcuNjg0NjgzNjUgMTIuOTQ3MjA4NCAxMDcuNjkwMzI2NjkgQzExLjEyODM5Nzc3IDEwNy42OTcwMjcxNiA5LjMwOTU5NzA5IDEwNy43MTIyMTc4NCA3LjQ5MDkzMjQ2IDEwNy43MzYyMTc1IEM0LjkzNjkyOTIxIDEwNy43Njc5ODcyMiAyLjM4NDcxNjk3IDEwNy43Njc4ODgyMiAtMC4xNjk0MzM1OSAxMDcuNzYwNDk4MDUgQy0wLjkxMzY0MDU5IDEwNy43NzY5MDMzOCAtMS42NTc4NDc2IDEwNy43OTMzMDg3MiAtMi40MjQ2MDYzMiAxMDcuODEwMjExMTggQy04LjIwNzg0MDM2IDEwNy43NDIxMTY0IC0xMi4yOTg2MDM1NyAxMDUuOTkwNjU1OSAtMTYuNjY1MDM5MDYgMTAyLjE3NzAwMTk1IEMtMjAuNjMyMjU2NjYgOTcuNTU3MzA1MDQgLTIxLjI0Nzk0NjQgOTIuODQxMjYyMzkgLTIxLjE4MjYxNzE5IDg2Ljg1ODM5ODQ0IEMtMjEuMTg5NjI2NDYgODYuMDU3NDY3NjUgLTIxLjE5NjYzNTc0IDg1LjI1NjUzNjg3IC0yMS4yMDM4NTc0MiA4NC40MzEzMzU0NSBDLTIxLjIyMTM1NzQ3IDgxLjgwMzIyODUzIC0yMS4yMDk4NDQ3OSA3OS4xNzYyMTIxNiAtMjEuMTk2Mjg5MDYgNzYuNTQ4MDk1NyBDLTIxLjE5ODk4NjAyIDc0LjcxMTU5MTU0IC0yMS4yMDI4NzAxNCA3Mi44NzUwODg3NyAtMjEuMjA3ODg1NzQgNzEuMDM4NTg5NDggQy0yMS4yMTM3Njk3MiA2Ny4xOTc5NTA3IC0yMS4yMDUyNTI0NSA2My4zNTc2ODUxIC0yMS4xODY1MjM0NCA1OS41MTcwODk4NCBDLTIxLjE2MzcxODM1IDU0LjYwMTk4MjggLTIxLjE3Njg3MzY3IDQ5LjY4Nzc0ODc2IC0yMS4yMDA4MTMyOSA0NC43NzI2NzM2MSBDLTIxLjIxNTI4NzM1IDQwLjk4MzMxNjYgLTIxLjIxMDY1ODIgMzcuMTk0MTY1NjMgLTIxLjIwMDMwMjEyIDMzLjQwNDgwMjMyIEMtMjEuMTk3NjQwMTIgMzEuNTkyNzYyODQgLTIxLjIwMDg4NjA2IDI5Ljc4MDcwNDQ1IC0yMS4yMTAyMjAzNCAyNy45Njg2ODcwNiBDLTIxLjIyMDQxNDQzIDI1LjQzNDAyNjIgLTIxLjIwNDg0Njc4IDIyLjkwMDc2NzcxIC0yMS4xODI2MTcxOSAyMC4zNjYyMTA5NCBDLTIxLjE5NDc2MjU3IDE5LjI1MDg5NzQ1IC0yMS4xOTQ3NjI1NyAxOS4yNTA4OTc0NSAtMjEuMjA3MTUzMzIgMTguMTEzMDUyMzcgQy0yMS4xMTE2NTExNCAxMi4yMTU3MDc2NSAtMTkuMTE1OTE4MTUgOC42OTk3ODk0NyAtMTUuMDY3MzgyODEgNC41MzI0NzA3IEMtOS45ODE2OTIgMC40Nzc0Nzk4OSAtNi4zMDkxMjQzNyAwLjAyMzA2MTQ2IDAgMCBaICIgZmlsbD0iIzAyNjFBRiIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMjAuNjY1MDM5MDYyNSwtMC4xNzcwMDE5NTMxMjUpIi8+CjxwYXRoIGQ9Ik0wIDAgQzUuNTYyNjc1NTIgMy45OTY2NzE4OCA4LjcyOTgxNjIyIDguMjk1MjQzNjYgMTEuMjYxNzE4NzUgMTQuNjI1IEMxMS4yNjE3MTg3NSAxOC41ODUgMTEuMjYxNzE4NzUgMjIuNTQ1IDExLjI2MTcxODc1IDI2LjYyNSBDLTIuNTk4MjgxMjUgMjYuNjI1IC0xNi40NTgyODEyNSAyNi42MjUgLTMwLjczODI4MTI1IDI2LjYyNSBDLTI1LjczMDIyMjU1IDM0LjkxNDQ3NzI1IC0yNS43MzAyMjI1NSAzNC45MTQ0NzcyNSAtMTcuNzM4MjgxMjUgMzguNjI1IEMtMTIuNjk1MTY1NTUgMzkuNTQ4OTI5NTkgLTguNjEyOTI3MDcgMzguNjU3MzYzOCAtNC4zMTI1IDM1Ljk4MDQ2ODc1IEMtMi41Mjc3MTY0IDM0LjQ0MzY5NDc4IC0xLjU2Mjg4NDUyIDMyLjg5MzQ0NTA5IC0wLjM2MzI4MTI1IDMwLjg3NSBDMC43OTY4NzUgMjkuMDQyOTY4NzUgMC43OTY4NzUgMjkuMDQyOTY4NzUgMi4yNjE3MTg3NSAyNy42MjUgQzUuMzQ0MTQxNDggMjcuMDI1MjA1MzkgOC4xNjMzNjgzNSAyNy4xOTk3MzYyMiAxMS4yNjE3MTg3NSAyNy42MjUgQzkuMjgzNzM0NDMgMzYuNTI1OTI5NDUgNC43NTI5MDU4NiA0MS43NTA2NDAyNSAtMi44NjMyODEyNSA0Ni42MjUgQy05Ljg0MjIxNTYyIDQ5LjA3NDAyOTcyIC0xOC44MjE5NjY3NiA0OC43NzAxMjU2NiAtMjUuNjc1NzgxMjUgNDYuMTI1IEMtMzIuMTY3NDcwODEgNDIuNjkxNzc4NyAtMzcuMDg3OTYyMDkgMzYuODMyMzc1NDcgLTM5LjMwNDY4NzUgMjkuODI0MjE4NzUgQy00MC43NDY3NTQ0NyAyMi41MDk5NTExNiAtNDAuNDQxMDE1MzcgMTUuMTk1MjY1MDUgLTM2LjczODI4MTI1IDguNjI1IEMtMjguMzc1NDYyMTEgLTMuNzQxODM1NTcgLTEzLjEzMzk1NTQ0IC03LjQ0NDY4OTcyIDAgMCBaIE0tMjguNTc0MjE4NzUgMTIuMDI3MzQzNzUgQy0zMC4wNjMwNDI0NCAxMy44NjA3NzYzOCAtMzAuMDYzMDQyNDQgMTMuODYwNzc2MzggLTMwLjczODI4MTI1IDE3LjYyNSBDLTE5Ljg0ODI4MTI1IDE3LjYyNSAtOC45NTgyODEyNSAxNy42MjUgMi4yNjE3MTg3NSAxNy42MjUgQzAuMDMyODAwNjMgMTAuOTM4MjQ1NjQgLTEuNzAwODM1NTYgOC44MDkxMzIzMiAtNy43MzgyODEyNSA1LjYyNSBDLTE2LjIxMDcyNDcgMy4wMTM2MzA0NCAtMjIuNTIwNDcxNDMgNS45NTc0MDk5NCAtMjguNTc0MjE4NzUgMTIuMDI3MzQzNzUgWiAiIGZpbGw9IiMwMEFFRUYiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDQwMi43MzgyODEyNSwzOS4zNzUpIi8+CjxwYXRoIGQ9Ik0wIDAgQzUuNzg5NDUyIDQuNTU5MzM0NTIgOS4zMDY5Nzg1NiA5LjQwMDg1NzY5IDEwLjQyOTY4NzUgMTYuODUxNTYyNSBDMTAuNzE4NzE2NzkgMTkuNTc5NzE2OTggMTAuOTgxMDEyOTIgMjIuMjU2MzY2NjkgMTEgMjUgQzguODQ1NDMwMzEgMjcuMTU0NTY5NjkgMy45Mjg4MzczIDI2LjI2MDI2NjI2IDAuOTMzNTkzNzUgMjYuMzE2NDA2MjUgQzAuMDI0OTcwODYgMjYuMzM3MTg3MzUgLTAuODgzNjUyMDQgMjYuMzU3OTY4NDQgLTEuODE5ODA4OTYgMjYuMzc5Mzc5MjcgQy00LjczMzk1OTQ2IDI2LjQ0NDk3NjcyIC03LjY0ODIwMzA0IDI2LjUwMzgwNjggLTEwLjU2MjUgMjYuNTYyNSBDLTEyLjUzMzIxMjkxIDI2LjYwNTY3NTU0IC0xNC41MDM5MTYyNiAyNi42NDkyODk1MSAtMTYuNDc0NjA5MzggMjYuNjkzMzU5MzggQy0yMS4zMTYzMDk4OCAyNi44MDA2Njg0MyAtMjYuMTU4MTA0MzcgMjYuOTAxOTA2NzUgLTMxIDI3IEMtMjcuNjk2OTU3MTkgMzIuMTI2Mzc4NTUgLTI0Ljk1MTU0NjQyIDM2LjAxNjE1MTE5IC0xOSAzOCBDLTEzLjM4NDAwMDg0IDM4LjM2ODI2MjI0IC05LjgyMzM0MDExIDM4LjIxNTU2MDA3IC01IDM1IEMtMi42MDk0OTUwNyAzMi41NzcxOTA5NSAtMC41MzEwNDQzMyAzMC4wNjIwODg2NyAxIDI3IEMzLjk3IDI3IDYuOTQgMjcgMTAgMjcgQzkuMDMwNjIwNiAzMy4zMjg4MjE4MyA1Ljk2MDE1ODQ4IDM4LjYzMTg3MzIxIDAuOTI5Njg3NSA0Mi42NTYyNSBDLTYuNDk3NzUyNjEgNDcuMzcwMzQ0ODMgLTEzLjI4MDQzMDM5IDQ3LjgxMTMzOTYzIC0yMiA0NyBDLTI4Ljg0NTY3NDcxIDQ0Ljk2NzI2MzA0IC0zNC4yNzg3NjYxNyA0MS4xMjgzNjg1OCAtMzggMzUgQy00MS40NDQ1NzA4NCAyNy43MzEwMzg3MiAtNDIuMDg2MDAwMzQgMjEuMDUwNDI5NyAtMzkuNzUgMTMuMzc1IEMtMzYuNjg4ODU4MTMgNS4xMjY5MjMzMSAtMzIuMDkwNzg3OSAwLjQ4NjE5ODc0IC0yNC4zMTI1IC0zLjMxMjUgQy0xNS42ODI1NzM1NSAtNS4xMDM2MTY4MSAtNy41MTkxMDYyNCAtNC45MDY5MDIzNCAwIDAgWiBNLTI4LjkzNzUgMTEuMDYyNSBDLTMxLjExMzY4NjAzIDEzLjg2MzgyOTE1IC0zMS4xMTM2ODYwMyAxMy44NjM4MjkxNSAtMzIgMTcgQy0yMS4xMSAxNyAtMTAuMjIgMTcgMSAxNyBDLTAuMjEzMTEzODQgMTAuOTM0NDMwNzggLTIuMDc2MDkzOTQgOS4zNDY2Mzg0MSAtNyA2IEMtMTUuMzg1ODMzNjQgMi4zMTAyMzMyIC0yMi45MjIwODc3OCA0LjA3MDY3MzA1IC0yOC45Mzc1IDExLjA2MjUgWiAiIGZpbGw9IiMwMDYwQUYiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDE5NCw0MCkiLz4KPHBhdGggZD0iTTAgMCBDNS44ODMwOTU4IDUuMTA3NTQ2NDQgOS42NjA1Mzk2IDExLjA5NzA1NzEyIDEwLjM0MDU3NjE3IDE4LjkxNTc3MTQ4IEMxMC4zNDAxMDkxNiAyMC4zMTc2MzUzMiAxMC4zMjM2MzgxOSAyMS43MTk1NjUzNyAxMC4yOTI5Njg3NSAyMy4xMjEwOTM3NSBDMTAuMjg4NzIzOTEgMjMuODY1ODU0NjQgMTAuMjg0NDc5MDYgMjQuNjEwNjE1NTQgMTAuMjgwMTA1NTkgMjUuMzc3OTQ0OTUgQzEwLjI2MzQ1NzI0IDI3LjczMTUxNDczIDEwLjIyNTgzMzc1IDMwLjA4NDE5Mzc5IDEwLjE4NzUgMzIuNDM3NSBDMTAuMTcyNDM1MTUgMzQuMDQzNjA3MzMgMTAuMTU4NzQ5OTEgMzUuNjQ5NzI4MjMgMTAuMTQ2NDg0MzggMzcuMjU1ODU5MzggQzEwLjExMzU5OTUyIDQxLjE3MDkxMDQ3IDEwLjA2MTkxNjI2IDQ1LjA4NTMwNDc5IDEwIDQ5IEM5LjUyOTQ5MjE5IDQ4LjU2Njg3NSA5LjA1ODk4NDM4IDQ4LjEzMzc1IDguNTc0MjE4NzUgNDcuNjg3NSBDNy45NTE2MDE1NiA0Ny4xMzA2MjUgNy4zMjg5ODQzOCA0Ni41NzM3NSA2LjY4NzUgNDYgQzYuMDcyNjE3MTkgNDUuNDQzMTI1IDUuNDU3NzM0MzcgNDQuODg2MjUgNC44MjQyMTg3NSA0NC4zMTI1IEMyLjk2ODY4NjY1IDQyLjcwNzk4NTAyIDIuOTY4Njg2NjUgNDIuNzA3OTg1MDIgMCA0MyBDLTEuMDkzMTI1IDQzLjY2IC0yLjE4NjI1IDQ0LjMyIC0zLjMxMjUgNDUgQy05Ljg3MDc0MzQzIDQ4LjM4ODAyMjQzIC0xNy42MDAwNjI2MyA0OC4wMzUyNzkzOCAtMjQuNjU2MjUgNDYuMzc1IEMtMzEuODU2Mzk2NiA0My42MTMyOTk5MyAtMzYuMDgxOTg1MzEgMzguMjE3MzE0OTcgLTM5LjkzNzUgMzEuNzUgQy00MS45NzU2MTU5NCAyNC41NTY2NDk2NCAtNDIuMTIxMTUzNTUgMTYuNzM2MDk3NDYgLTM5LjAzOTA2MjUgOS44MDg1OTM3NSBDLTM1LjMzMTY1MjYgMy4zNTU0NzA1IC0zMC4zMzkyNDg1OSAtMS4zNTYzMDU3IC0yMy4xMDkzNzUgLTMuNTgyMDMxMjUgQy0xNC45ODkyNzU0NyAtNS4xOTEwMTM5MyAtNy4xMTQ3ODkwNyAtNC4zMjcwNTIzIDAgMCBaIE0tMjcuNzUgOS4yNSBDLTMxLjM3MjY0NDA0IDEzLjY3NzY3NjA1IC0zMy4zMzA0MTg0MiAxNy42NzIyOTI1MiAtMzMuMDYyNSAyMy40Mzc1IEMtMzIuMjMxODM1MTkgMjguNjYyNjQ5NjEgLTI5Ljc4OTk0NDI4IDMyLjM3MTg3MzU3IC0yNiAzNiBDLTIxLjI1NzIxNDIgMzguNzU5NDM5MDEgLTE3LjQ1MDAwMjI3IDM5LjY2OTI5ODUyIC0xMiAzOSBDLTUuNjU1MTcxMiAzNi43ODE2OTUyIC0xLjkwNjczOTU0IDMzLjYyMjgwNTE0IDEuMjUgMjcuNjI1IEMyLjkzMzk4ODcyIDIxLjczMTAzOTUgMi4yNDU2MjIyNSAxNy4xMzA4ODQ0NyAtMC42Nzk2ODc1IDExLjg2MzI4MTI1IEMtMy40MzAwODI0MyA3Ljk4MTgwNjc0IC02LjYyNzgzMTg4IDUuNjc1OTYyOTUgLTExLjIwNzAzMTI1IDQuMzcxMDkzNzUgQy0xNy44ODYxMTE5NiAzLjI5MDE1MjI0IC0yMi40ODcwNDg3MiA0Ljk0Mzk0ODk1IC0yNy43NSA5LjI1IFogIiBmaWxsPSIjMDBBRUVGIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSg0ODYsNDApIi8+CjxwYXRoIGQ9Ik0wIDAgQzcuOTgyNTU4MDIgNi44NDIxOTI1OSA3Ljk4MjU1ODAyIDYuODQyMTkyNTkgOC4yMDUzMjIyNyA4Ljg1NzY2NjAyIEM4LjI0MTk3OTk4IDkuNjQ4NDI1MjkgOC4yNzg2Mzc3IDEwLjQzOTE4NDU3IDguMzE2NDA2MjUgMTEuMjUzOTA2MjUgQzguMzc5MjQ4MDUgMTIuNTM0OTEyMTEgOC4zNzkyNDgwNSAxMi41MzQ5MTIxMSA4LjQ0MzM1OTM4IDEzLjg0MTc5Njg4IEM4LjQ4MjY3NTc4IDE0LjczOTYyODkxIDguNTIxOTkyMTkgMTUuNjM3NDYwOTQgOC41NjI1IDE2LjU2MjUgQzguNjA1NjgzNTkgMTcuNDY0MTk5MjIgOC42NDg4NjcxOSAxOC4zNjU4OTg0NCA4LjY5MzM1OTM4IDE5LjI5NDkyMTg4IEM4Ljc5OTc4MTQyIDIxLjUyOTc4NDg1IDguOTAxNzk5ODggMjMuNzY0NzYzMDggOSAyNiBDOS41ODI2NTYyNSAyNS42MzkwNjI1IDEwLjE2NTMxMjUgMjUuMjc4MTI1IDEwLjc2NTYyNSAyNC45MDYyNSBDMTguMjYwMjg0MDcgMjAuNjYzOTkwMTUgMjQuODcxNTQ3NDMgMTkuNjUyOTc0MzUgMzMuMzI4MTI1IDIxLjUxMTcxODc1IEM0MC40MjU3NTM5MiAyMy44NTUwMTk5IDQ1LjM2NzkxNjM2IDI4LjUxNDEzNjM2IDQ5IDM1IEM1MC42NTQ5NzgwMyAzOS44OTA5MTMwNiA1MS4yMzk1MzQyNiA0NC4wOTQyNTgyMSA1MS4xOTUzMTI1IDQ5LjI0NjA5Mzc1IEM1MS4xOTI0ODI2IDQ5LjkwMjA3MDQ3IDUxLjE4OTY1MjcxIDUwLjU1ODA0NzE4IDUxLjE4NjczNzA2IDUxLjIzMzkwMTk4IEM1MS4xNzU2NTk4NCA1My4zMDE5NjQwOSA1MS4xNTA1ODA2MyA1NS4zNjk1NzE3MyA1MS4xMjUgNTcuNDM3NSBDNTEuMTE0OTU0MDIgNTguODUwOTA1MTUgNTEuMTA1ODMxMDIgNjAuMjY0MzE3MTcgNTEuMDk3NjU2MjUgNjEuNjc3NzM0MzggQzUxLjA3NTc2MTg0IDY1LjExODYzMzk0IDUxLjA0MTMyMDUxIDY4LjU1OTI3MjUyIDUxIDcyIEM0OC4zNiA3MiA0NS43MiA3MiA0MyA3MiBDNDIuOTg1NDE3NDggNzEuMjIzOTg0MzggNDIuOTcwODM0OTYgNzAuNDQ3OTY4NzUgNDIuOTU1ODEwNTUgNjkuNjQ4NDM3NSBDNDIuODgwODgyMzQgNjYuMDk4NDgyMjcgNDIuNzg0MzY4ODcgNjIuNTQ5NDIxNTcgNDIuNjg3NSA1OSBDNDIuNjUzNjYyMTEgNTcuMTY4ODg2NzIgNDIuNjUzNjYyMTEgNTcuMTY4ODg2NzIgNDIuNjE5MTQwNjIgNTUuMzAwNzgxMjUgQzQyLjQ3NzMyNjcyIDQ0LjY3NTE3MzE5IDQyLjQ3NzMyNjcyIDQ0LjY3NTE3MzE5IDM3LjY1NTUxNzU4IDM1LjQ4ODc2OTUzIEMzNC4xMTA2NTUwNyAzMi4zMzAxMTU1MyAzMC43MTMzMjQxMSAzMC4wNDAzNDY4MyAyNS44OTg0Mzc1IDI5Ljk2ODc1IEMyMC42MTkyMjY1OSAzMC4zMjE4NzQ0OCAxNy4wNTk0MDM2NiAzMS40MTI2MjAwMiAxMyAzNSBDNy43MTA4NDE1NyA0MS42OTE4MDgxNyA4LjMzMTgyNDY3IDQ5LjI4NDUyODMxIDguMjUgNTcuNDM3NSBDOC4yMjE4MDU1OSA1OC44NTA5NDc1MiA4LjE5MTg3MzM1IDYwLjI2NDM2MTUxIDguMTYwMTU2MjUgNjEuNjc3NzM0MzggQzguMDg2NzAwNSA2NS4xMTgzMzI1NyA4LjAzNjg3NTc1IDY4LjU1ODc5Mjc3IDggNzIgQzUuMzYgNzIgMi43MiA3MiAwIDcyIEMwIDQ4LjI0IDAgMjQuNDggMCAwIFogIiBmaWxsPSIjMDA2MEFGIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgyNjEsMTUpIi8+CjxwYXRoIGQ9Ik0wIDAgQzYuNTkwMTgzOTEgMy43NzE5MTk1MiA5LjgyNzM3MTM0IDguMTE4NzIwMjYgMTIuODA4NTkzNzUgMTUuMDM1MTU2MjUgQzkuMzY3ODk3NTEgMTcuMzI4OTUzNzQgOC4wODU2OTA3NCAxOC4wMzUxNTYyNSAzLjgwODU5Mzc1IDE4LjAzNTE1NjI1IEMyLjMwODU5Mzc1IDE1Ljc4NTE1NjI1IDIuMzA4NTkzNzUgMTUuNzg1MTU2MjUgMC44MDg1OTM3NSAxMy4wMzUxNTYyNSBDLTIuMTU1MTMzOTIgOS40NTgyNDM1NCAtNC42MjkzODYxNCA3Ljk4MTk5MDYxIC05LjE5MTQwNjI1IDcuMDM1MTU2MjUgQy0xNC44NzUxODA1MSA2Ljg0ODQ2MjkzIC0xOS4yOTU3MjgwNSA3LjkxNjYxNDA0IC0yMy43NSAxMS41MjM0Mzc1IEMtMjcuMTQ3OTE1OTUgMTUuMDg3MTA1NDUgLTI4LjMzMTkwMDA1IDE5LjIzNjY0OTg3IC0yOC42Mjg5MDYyNSAyNC4wMzUxNTYyNSBDLTI4LjQyMDE4ODgzIDI4LjM1MTQzMjQgLTI3LjAxMzY2NTgyIDMxLjc2ODk0NTczIC0yNC4xOTE0MDYyNSAzNS4wMzUxNTYyNSBDLTIwLjYwOTExODY1IDM4LjE3MzYyMDYgLTE3LjAxMzYwNzk4IDQwLjMxMjg4MDU2IC0xMi4xOTE0MDYyNSA0MC41OTc2NTYyNSBDLTYuODU2OTk2MjIgNDAuMTk5NDA5NTMgLTIuMTQ4ODg0NTggMzguMjQ4NTc2MDUgMS40MjE4NzUgMzQuMjEwOTM3NSBDMi42MjY2NzQ0OCAzMi41Mzc3OTM0NCAzLjcyODAxODEyIDMwLjc5MTA5MTY1IDQuODA4NTkzNzUgMjkuMDM1MTU2MjUgQzEwLjU1ODU5Mzc1IDMwLjc4NTE1NjI1IDEwLjU1ODU5Mzc1IDMwLjc4NTE1NjI1IDEyLjgwODU5Mzc1IDMzLjAzNTE1NjI1IEM4LjkyNDQyMTgyIDM5Ljk2MTM1NjY0IDQuNzcxMjY5NDMgNDUuNTM2OTUzNDIgLTIuOTQ1MzEyNSA0OC41MjczNDM3NSBDLTEwLjMxOTAxODE0IDUwLjE5NDQ0MjQyIC0xOC44NDQ2MTU3NSA1MC4zODg0MDQxMSAtMjUuNDQ5MjE4NzUgNDYuMzYzMjgxMjUgQy0zMC43MzUwMDc5IDQyLjMzMzc1NTg5IC0zNS44ODY2MzYzMSAzNy44MjY5NDk3NSAtMzcuMTkxNDA2MjUgMzEuMDM1MTU2MjUgQy0zNy45MTc0MTg3NiAyMi45MTI4OTEyNSAtMzguNTk3ODg0MjUgMTQuNjUzMTY5OTQgLTMzLjE5MTQwNjI1IDguMDM1MTU2MjUgQy0yNC4zNDk1NjIwOSAtMS40MjA0Mzg0OCAtMTIuMzU2NzMyMDIgLTUuNTIzMjc5MzkgMCAwIFogIiBmaWxsPSIjMDA2MEFGIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgyNDUuMTkxNDA2MjUsMzcuOTY0ODQzNzUpIi8+CjxwYXRoIGQ9Ik0wIDAgQzE1LjUxIDAgMzEuMDIgMCA0NyAwIEM0NyAyLjY0IDQ3IDUuMjggNDcgOCBDNDAuNzMgOCAzNC40NiA4IDI4IDggQzI4IDI5LjEyIDI4IDUwLjI0IDI4IDcyIEMyMy43NjIyODczNCA2OS44ODExNDM2NyAyMS43NDk1NzU1OSA2OC44Mzk4Njg3MSAxOSA2NSBDMTguMjk3MjE5OTggNjAuNjc5MTQzNTYgMTguNDE5NDE1MDkgNTYuNDEwMjAxNzYgMTguNTExNzE4NzUgNTIuMDQyOTY4NzUgQzE4LjUxODc5MzQ5IDUwLjc4NDg2ODkzIDE4LjUyNTg2ODIzIDQ5LjUyNjc2OTEgMTguNTMzMTU3MzUgNDguMjMwNTQ1MDQgQzE4LjU1NjM3NjMgNDQuODk3NTA2NzMgMTguNjAxMjM0NTIgNDEuNTY2MjAwMjUgMTguNjU2Njc3MjUgMzguMjMzNjQyNTggQzE4LjcwNzk3MjY2IDM0LjgyODQzOTQ1IDE4LjczMDY5MzA5IDMxLjQyMzA1Njg2IDE4Ljc1NTg1OTM4IDI4LjAxNzU3ODEyIEMxOC44MTA5NjI4MSAyMS4zNDQ1MTM4NSAxOC44OTcyNTg3IDE0LjY3MjQ5NCAxOSA4IEMxMi43MyA4IDYuNDYgOCAwIDggQzAgNS4zNiAwIDIuNzIgMCAwIFogIiBmaWxsPSIjMDBBRUVGIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgzMDEsMTcpIi8+CjxwYXRoIGQ9Ik0wIDAgQzE1LjUxIDAgMzEuMDIgMCA0NyAwIEM0NyAyLjY0IDQ3IDUuMjggNDcgOCBDNDAuNCA4IDMzLjggOCAyNyA4IEMyNyAyOS4xMiAyNyA1MC4yNCAyNyA3MiBDMjAgNjYgMjAgNjYgMTkgNjUgQzE4LjkwNjI5Mzc2IDYzLjIyMDA4MDc2IDE4Ljg4MjU1NzI5IDYxLjQzNjQzMjYxIDE4Ljg4NjQ3NDYxIDU5LjY1NDA1MjczIEMxOC44ODY1NTAxNCA1OC41MTI5NDU0IDE4Ljg4NjYyNTY3IDU3LjM3MTgzODA3IDE4Ljg4NjcwMzQ5IDU2LjE5NjE1MTczIEMxOC44OTE4NjQ3OCA1NC45NTQ1MDc2IDE4Ljg5NzAyNjA2IDUzLjcxMjg2MzQ2IDE4LjkwMjM0Mzc1IDUyLjQzMzU5Mzc1IEMxOC45MDM3NTg3IDUxLjE2OTgzNDE0IDE4LjkwNTE3MzY1IDQ5LjkwNjA3NDUyIDE4LjkwNjYzMTQ3IDQ4LjYwNDAxOTE3IEMxOC45MTEyOTQxOCA0NS4yMzg3NTExMSAxOC45MjAyODUyIDQxLjg3MzU1MDEgMTguOTMxMzM1NDUgMzguNTA4MzAwNzggQzE4Ljk0MTU1MTU0IDM1LjA3NjUwMzMgMTguOTQ2MTI5NTEgMzEuNjQ0Njk4OTEgMTguOTUxMTcxODggMjguMjEyODkwNjIgQzE4Ljk2MjIyNjIgMjEuNDc1MjM5MzYgMTguOTc5NTAzNjMgMTQuNzM3NjI4ODkgMTkgOCBDMTIuNzMgOCA2LjQ2IDggMCA4IEMwIDUuMzYgMCAyLjcyIDAgMCBaICIgZmlsbD0iIzAwNjBBRiIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMTIwLDE3KSIvPgo8cGF0aCBkPSJNMCAwIEMxOS45NTM4Njc3IC0xLjgyMjY1NTE0IDE5Ljk1Mzg2NzcgLTEuODIyNjU1MTQgMjYuNzY4NTU0NjkgMy41Mjc4MzIwMyBDMjkuMDA1NTI5NzUgNS41NzAyNTY3NiAzMS4wNzEyNTI0OCA3LjY2MzkzOTM0IDMzIDEwIEMzMyAxMC4zMyAzMyAxMC42NiAzMyAxMSBDMjMuMSAxMSAxMy4yIDExIDMgMTEgQzMgMjcuNSAzIDQ0IDMgNjEgQzEuMDIgNTkuNjggLTAuOTYgNTguMzYgLTMgNTcgQy0zLjk3OTQ0NTggNTYuNDQyNTYxMDQgLTQuOTU4ODkxNiA1NS44ODUxMjIwNyAtNS45NjgwMTc1OCA1NS4zMTA3OTEwMiBDLTEzLjI2NjYxNzY5IDUwLjU0Njg4NTA0IC0xMy4yNjY2MTc2OSA1MC41NDY4ODUwNCAtMTQuNTczMTgxMTUgNDYuMDA5NDYwNDUgQy0xNS4zNzQ2NDE4NyA0MC4zMjgxNjIxNiAtMTUuMDAyOTA2NDcgMzQuNjQ0NTcxNzQgLTE0LjY4NzUgMjguOTM3NSBDLTE0LjYzMjI0NjM0IDI3LjE5NjExODU2IC0xNC41ODIwNjk2MSAyNS40NTQ1NjgyMiAtMTQuNTM3MTA5MzggMjMuNzEyODkwNjIgQy0xNC40MTY2MzEwNiAxOS40NzEwNDg4IC0xNC4yMjczMzg3NSAxNS4yMzc0MDM0NSAtMTQgMTEgQy0xNC44MzE0NDUzMSAxMS4wNDY0MDYyNSAtMTUuNjYyODkwNjMgMTEuMDkyODEyNSAtMTYuNTE5NTMxMjUgMTEuMTQwNjI1IEMtMTcuNjA2MjEwOTQgMTEuMTc2NzE4NzUgLTE4LjY5Mjg5MDYzIDExLjIxMjgxMjUgLTE5LjgxMjUgMTEuMjUgQy0yMS40MzA5MTc5NyAxMS4zMTk2MDkzNyAtMjEuNDMwOTE3OTcgMTEuMzE5NjA5MzcgLTIzLjA4MjAzMTI1IDExLjM5MDYyNSBDLTI0LjUyNjQyNTc4IDExLjE5NzI2NTYyIC0yNC41MjY0MjU3OCAxMS4xOTcyNjU2MiAtMjYgMTEgQy0yNi45OSA5LjY4IC0yNy45OCA4LjM2IC0yOSA3IEMtMjMuMDYgNyAtMTcuMTIgNyAtMTEgNyBDLTExIDE5Ljg3IC0xMSAzMi43NCAtMTEgNDYgQy05LjY4IDQ2LjY2IC04LjM2IDQ3LjMyIC03IDQ4IEMtNS4wMiA0OS42NSAtMy4wNCA1MS4zIC0xIDUzIEMtMC42NyAzNy44MiAtMC4zNCAyMi42NCAwIDcgQzEwLjM5NSA2LjUwNSAxMC4zOTUgNi41MDUgMjEgNiBDMTkuNDE1OTY0NzYgNC40MTU5NjQ3NiAxNy43MjI4MzYyIDQuNzgwMjUwNjUgMTUuNTI3MzQzNzUgNC42ODM1OTM3NSBDMTQuNjI4MjIyNjYgNC42NDE2OTkyMiAxMy43MjkxMDE1NiA0LjU5OTgwNDY5IDEyLjgwMjczNDM4IDQuNTU2NjQwNjIgQzExLjg1NzIwNzAzIDQuNTE3MzI0MjIgMTAuOTExNjc5NjkgNC40NzgwMDc4MSA5LjkzNzUgNC40Mzc1IEM4Ljk4ODEwNTQ3IDQuMzk0MzE2NDEgOC4wMzg3MTA5NCA0LjM1MTEzMjgxIDcuMDYwNTQ2ODggNC4zMDY2NDA2MiBDNC43MDcxODY0NyA0LjIwMDIwNzI0IDIuMzUzNzE2NDYgNC4wOTgxODk5MiAwIDQgQzAgMi42OCAwIDEuMzYgMCAwIFogIiBmaWxsPSIjRjBGNUZBIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSg2MCwzMCkiLz4KPHBhdGggZD0iTTAgMCBDMS4zMTE5NDMzNiAwLjAyMDMwMjczIDEuMzExOTQzMzYgMC4wMjAzMDI3MyAyLjY1MDM5MDYyIDAuMDQxMDE1NjIgQzQuNzg4MDMwODYgMC4wNzYwNTg5MSA2LjkyNTM0OTg0IDAuMTI5ODU0NTkgOS4wNjI1IDAuMTg3NSBDNy40NTg4MzIwNyAzLjUzNzAzMzAxIDYuMDA3NjA0NzIgNS44Mzk1MTI3MyAzLjA2MjUgOC4xODc1IEMwLjAzOTA2MjUgOC44NzUgMC4wMzkwNjI1IDguODc1IC0zLjMxMjUgOS4xODc1IEMtMTAuMDQ5ODYzOTEgMTAuMDcwMjIyOTMgLTEzLjc1NzE5OTggMTEuNDEyNTcyNDcgLTE4LjA0Mjk2ODc1IDE2Ljg2NzE4NzUgQy0yMS4zMzkzMTY0NSAyMi44MDQ5NDM1NCAtMjAuNjIxMTI2MzIgMzAuMDExNTU3MDkgLTIwLjY4NzUgMzYuNjI1IEMtMjAuNzE1Njk0NDEgMzguMDM4NDQ3NTIgLTIwLjc0NTYyNjY1IDM5LjQ1MTg2MTUxIC0yMC43NzczNDM3NSA0MC44NjUyMzQzOCBDLTIwLjg1MDc5OTUgNDQuMzA1ODMyNTcgLTIwLjkwMDYyNDI1IDQ3Ljc0NjI5Mjc3IC0yMC45Mzc1IDUxLjE4NzUgQy0yMy41Nzc1IDUxLjE4NzUgLTI2LjIxNzUgNTEuMTg3NSAtMjguOTM3NSA1MS4xODc1IEMtMjkuMDM3MDgxMjEgNDYuNjM0MzQwNzggLTI5LjEwOTI5OTg1IDQyLjA4MTgyODQ4IC0yOS4xNTcyMjY1NiAzNy41Mjc4MzIwMyBDLTI5LjE3NzIyNTAzIDM1Ljk4MTgyMTEzIC0yOS4yMDQ0MzMzMSAzNC40MzU4ODQ3MyAtMjkuMjM5MjU3ODEgMzIuODkwMTM2NzIgQy0yOS42MTc4OTM5OSAxNS42Mzk5MTc3NSAtMjkuNjE3ODkzOTkgMTUuNjM5OTE3NzUgLTIzLjA0Mjk2ODc1IDcuOTgwNDY4NzUgQy0yMi40MTAwMzkwNiA3LjQ1MDY2NDA2IC0yMS43NzcxMDkzOCA2LjkyMDg1OTM3IC0yMS4xMjUgNi4zNzUgQy0yMC40OTk4MDQ2OSA1LjgzMjMwNDY5IC0xOS44NzQ2MDkzNyA1LjI4OTYwOTM3IC0xOS4yMzA0Njg3NSA0LjczMDQ2ODc1IEMtMTIuNzUxMzA1MDUgMC4zNzA1NTQ1MSAtNy42NDAwNDI5MSAtMC4yMjY1ODY4MiAwIDAgWiAiIGZpbGw9IiMwMEFFRUYiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDQ0Ni45Mzc1LDM1LjgxMjUpIi8+CjxwYXRoIGQ9Ik0wIDAgQzcuNjQwNzA3NDIgLTAuMDkyNjUzNDcgMTUuMjgxMzU2NjUgLTAuMTYzNzQxMDkgMjIuOTIyNDk3NzUgLTAuMjA3MjQ4NjkgQzI2LjQ3MDU4NzYyIC0wLjIyODEyOTc3IDMwLjAxODI5MzM1IC0wLjI1NjQ1NTQ1IDMzLjU2NjE2MjExIC0wLjMwMTc1NzgxIEMzNy42NDQ0MDYxMyAtMC4zNTM1MDY5NyA0MS43MjIyNDYyNiAtMC4zNzI5NDA3NCA0NS44MDA3ODEyNSAtMC4zOTA2MjUgQzQ3LjA3NTg1MDM3IC0wLjQxMTI3MDE0IDQ4LjM1MDkxOTQ5IC0wLjQzMTkxNTI4IDQ5LjY2NDYyNzA4IC0wLjQ1MzE4NjA0IEM1MC44NDU2MjQ4NSAtMC40NTM0ODgxNiA1Mi4wMjY2MjI2MiAtMC40NTM3OTAyOCA1My4yNDM0MDgyIC0wLjQ1NDEwMTU2IEM1NC4yODQ4NzUwMyAtMC40NjI5ODQwMSA1NS4zMjYzNDE4NiAtMC40NzE4NjY0NiA1Ni4zOTkzNjgyOSAtMC40ODEwMTgwNyBDNTkgMCA1OSAwIDYyIDQgQzM2Ljc1NSA0LjQ5NSAzNi43NTUgNC40OTUgMTEgNSBDMTMuODQ1MzU3MjUgNi40MjI2Nzg2MiAxNi4zNjIxODU1MiA2LjIxOTcxODY5IDE5LjUzOTA2MjUgNi4zMTY0MDYyNSBDMjAuNzExNjI1OTggNi4zNTQ1MTQxNiAyMS44ODQxODk0NSA2LjM5MjYyMjA3IDIzLjA5MjI4NTE2IDYuNDMxODg0NzcgQzI0LjU4ODA4MTA1IDYuNDc0OTg3NzkgMjYuMDgzODc2OTUgNi41MTgwOTA4MiAyNy42MjUgNi41NjI1IEMzNC43NDA2MjUgNi43NzkwNjI1IDM0Ljc0MDYyNSA2Ljc3OTA2MjUgNDIgNyBDNDIgMjIuMTggNDIgMzcuMzYgNDIgNTMgQzQxLjAxIDUyLjM0IDQwLjAyIDUxLjY4IDM5IDUxIEMzOC43MzM1MTMgNDcuOTQ5MjQ5MTYgMzguNjUyNDI4NTQgNDUuMTAzNzM4MjEgMzguNzA3MDMxMjUgNDIuMDU0Njg3NSBDMzguNzExMjc2MDkgNDEuMTY5Njc1NiAzOC43MTU1MjA5NCA0MC4yODQ2NjM3IDM4LjcxOTg5NDQxIDM5LjM3MjgzMzI1IEMzOC43MzY3MTc0MSAzNi41Mzk5MTU1NSAzOC43NzQzNzU3NSAzMy43MDc3MDM0OCAzOC44MTI1IDMwLjg3NSBDMzguODI3NTQyMTggMjguOTU3MDQxNTEgMzguODQxMjMxMzkgMjcuMDM5MDcxODkgMzguODUzNTE1NjIgMjUuMTIxMDkzNzUgQzM4Ljg4NjYzMjczIDIwLjQxMzc4OTY5IDM4LjkzODQzOTQ1IDE1LjcwNzAxNDU2IDM5IDExIEMzOC4yNDQ5MzE2NCAxMS4wNTIzNjgxNiAzNy40ODk4NjMyOCAxMS4xMDQ3MzYzMyAzNi43MTE5MTQwNiAxMS4xNTg2OTE0MSBDMTIuNDU5MjA0MDYgMTIuNjIyMTUzMTMgMTIuNDU5MjA0MDYgMTIuNjIyMTUzMTMgNS44MDk1NzAzMSA3LjQ3MjE2Nzk3IEMzLjY2MDExNDk2IDUuNDQ4MjAyNjcgMS43NDYxNTM2NSAzLjM4MTExODYxIDAgMSBDMCAwLjY3IDAgMC4zNCAwIDAgWiAiIGZpbGw9IiNFOUYxRjgiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDE0LDIzKSIvPgo8cGF0aCBkPSJNMCAwIEMyLjY0IDAgNS4yOCAwIDggMCBDOCAxNi44MyA4IDMzLjY2IDggNTEgQzUuMzYgNTEgMi43MiA1MSAwIDUxIEMwIDM0LjE3IDAgMTcuMzQgMCAwIFogIiBmaWxsPSIjMDBBRUVGIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgzNTIsMzYpIi8+CjxwYXRoIGQ9Ik0wIDAgQzIuNjQgMCA1LjI4IDAgOCAwIEM4IDIuOTcgOCA1Ljk0IDggOSBDNS4zNiA5IDIuNzIgOSAwIDkgQzAgNi4wMyAwIDMuMDYgMCAwIFogIiBmaWxsPSIjMDBBRUVGIiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgzNTIsMjEpIi8+Cjwvc3ZnPgo=" alt="TechTiera"/></div>
    <div>
      <h1 style="font-size:14px;font-weight:500;color:#94a3b8;margin-top:2px;">Admin Panel</h1>
    </div>
  </div>
  <?php if ($isLoggedIn): ?>
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
      <span class="user-badge">
        <?= htmlspecialchars($username) ?>
        <?php if ($myLocation): ?> · <?= htmlspecialchars($myLocation) ?><?php endif; ?>
      </span>
      <a href="/" class="portal-link" style="color:#94a3b8;">View Public Portal →</a>
      <a href="/manual" class="portal-link" style="color:#94a3b8;" target="_blank">Help →</a>
      <?php if ($isAdmin): ?>
      <a href="<?= ADMIN_URL ?>?page=audit" class="portal-link" style="color:#94a3b8;">Audit Log →</a>
      <?php endif; ?>
      <form method="POST" style="display:inline;">
        <input type="hidden" name="action" value="logout"/>
        <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>"/>
        <button type="submit" class="btn-logout">Logout</button>
      </form>
    </div>
  <?php endif; ?>
</header>

<?php if (!$isLoggedIn): ?>
<!-- ── LOGIN ───────────────────────────────────────────────────────────────── -->
<div class="login-wrap">
  <div class="login-card">
    <div class="login-head">
      <h2>Admin Login</h2>
      <p>Enter your username and password to access the panel.</p>
    </div>
    <div class="login-body">
      <?php if (isset($_GET['msg']) && $_GET['msg'] === 'timeout'): ?>
        <div class="flash error">⚠ Session expired. Please log in again.</div>
      <?php endif; ?>
      <?php if ($error): ?>
        <div class="flash error">⚠ <?= htmlspecialchars($error) ?></div>
      <?php endif; ?>
      <form method="POST">
        <input type="hidden" name="action" value="login"/>
        <div class="form-group">
          <label for="un">Username</label>
          <input type="text" id="un" name="username" placeholder="e.g. admin, chicago" autocomplete="username" autofocus required/>
        </div>
        <div class="form-group">
          <label for="pw">Password</label>
          <input type="password" id="pw" name="password" placeholder="Enter password" autocomplete="current-password" required/>
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;padding:12px;font-size:15px;margin-top:4px;">Login</button>
      </form>
    </div>
  </div>
</div>

<?php else: ?>
<!-- ── ADMIN PANEL ─────────────────────────────────────────────────────────── -->
<div class="wrap">

  <?php
  $msgMap = ['added'=>'Record added successfully.','edited'=>'Record updated successfully.','deleted'=>'Record deleted.','uploaded'=>'Records uploaded successfully.'];
  $msgGet = $_GET['msg'] ?? '';
  if (isset($msgMap[$msgGet])): ?><div class="flash success">✓ <?= htmlspecialchars($msgMap[$msgGet]) ?></div><?php endif; ?>
  <?php if ($success): ?><div class="flash success">✓ <?= htmlspecialchars($success) ?></div><?php endif; ?>
  <?php if ($error):   ?><div class="flash error">⚠ <?= htmlspecialchars($error) ?></div><?php endif; ?>

  <!-- Stats -->
  <div class="stats">
    <?php
      $vol   = count(array_filter($records, fn($r) => ($r['separationType']??'') === 'voluntary'));
      $invol = count(array_filter($records, fn($r) => ($r['separationType']??'') === 'involuntary'));
      $proj  = count(array_filter($records, fn($r) => ($r['separationType']??'') === 'project end'));
    ?>
    <div class="stat-card"><div class="val"><?= $total ?></div><div class="lbl">Total Records</div></div>
    <div class="stat-card"><div class="val"><?= $vol ?></div><div class="lbl">Voluntary</div></div>
    <div class="stat-card"><div class="val"><?= $invol ?></div><div class="lbl">Involuntary</div></div>
    <div class="stat-card"><div class="val"><?= $proj ?></div><div class="lbl">Project End</div></div>
  </div>

  <?php if ($isAdmin): ?>
  <!-- DB Status — admin only -->
  <?php
    // Build per-location stats from all records (unfiltered)
    $allRecs = loadData();
    $locStats = [];
    foreach ($allRecs as $r) {
        $l = $r['location'] ?? 'Unknown';
        if (!isset($locStats[$l])) $locStats[$l] = ['count' => 0, 'lastUpdated' => ''];
        $locStats[$l]['count']++;
        if (($r['lastUpdated'] ?? '') > $locStats[$l]['lastUpdated'])
            $locStats[$l]['lastUpdated'] = $r['lastUpdated'];
    }
    ksort($locStats);
  ?>
  <div class="db-status">
    <h3>📊 Database Status — By Location</h3>
    <?php if (empty($locStats)): ?>
      <p style="color:#9ca3af;font-size:13px;">No records in database yet.</p>
    <?php else: ?>
      <div class="loc-grid">
        <?php foreach ($locStats as $locName => $stat): ?>
          <div class="loc-card">
            <div class="loc-name"><?= htmlspecialchars($locName) ?></div>
            <div class="loc-count"><?= $stat['count'] ?></div>
            <div class="loc-updated">Last updated: <?= htmlspecialchars($stat['lastUpdated'] ?: '—') ?></div>
          </div>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
  </div>

  <!-- Audit Log — admin only -->
  <?php
    $auditLog = loadAudit();
    $auditShow = array_slice($auditLog, 0, 50);
  ?>
  <div class="audit-section">
    <h3>🔍 Audit Log <span style="font-size:11.5px;font-weight:400;color:#9ca3af;margin-left:8px;">Last 50 actions</span></h3>
    <?php if (empty($auditShow)): ?>
      <div class="audit-empty">No audit entries yet. Actions (add, edit, delete, upload) will appear here.</div>
    <?php else: ?>
      <div style="overflow-x:auto;">
        <table class="audit-table">
          <thead>
            <tr>
              <th>Date / Time</th>
              <th>User</th>
              <th>Action</th>
              <th>Reference</th>
              <th>Location</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($auditShow as $entry): ?>
              <?php
                $act   = $entry['action'] ?? '';
                $badge = match($act) {
                  'add'    => 'audit-add',
                  'edit'   => 'audit-edit',
                  'delete' => 'audit-delete',
                  'upload' => 'audit-upload',
                  default  => 'audit-login',
                };
              ?>
              <tr>
                <td style="white-space:nowrap;color:#6b7280;"><?= htmlspecialchars($entry['ts'] ?? '—') ?></td>
                <td><strong><?= htmlspecialchars($entry['user'] ?? '—') ?></strong></td>
                <td><span class="audit-badge <?= $badge ?>"><?= htmlspecialchars(ucfirst($act)) ?></span></td>
                <td><span style="font-family:'Courier New',monospace;font-size:12px;"><?= htmlspecialchars($entry['ref'] ?? '—') ?></span></td>
                <td><?= htmlspecialchars($entry['location'] ?? '—') ?></td>
                <td style="color:#6b7280;"><?= htmlspecialchars($entry['detail'] ?? '') ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    <?php endif; ?>
  </div>
  <?php endif; ?>

  <!-- Upload Section -->
  <div class="upload-section">
    <h3>Upload / Sync Data</h3>
    <form method="POST" enctype="multipart/form-data" style="margin-top:12px;">
      <input type="hidden" name="action" value="upload_csv"/>
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>"/>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
        <a href="<?= ADMIN_URL ?>?download=template" class="btn btn-outline btn-sm" style="text-decoration:none;white-space:nowrap;">⬇ Template</a>
        <input type="file" name="csv_file" accept=".csv" required style="flex:1;min-width:160px;font-size:13px;"/>
        <button type="submit" class="btn btn-success btn-sm" style="white-space:nowrap;">Upload CSV</button>
      </div>
    </form>
  </div>

  <!-- Toolbar -->
  <form method="GET" id="filterForm">
  <div class="toolbar">
    <div class="search-box" style="flex:1;">
      <input type="text" name="q" placeholder="Search by name, ID, location..." value="<?= htmlspecialchars($search) ?>" onchange="this.form.submit()"/>
    </div>
    <select name="type" onchange="this.form.submit()" style="width:148px;padding:8px 10px;border:1.5px solid #e5e7eb;border-radius:8px;font-size:13px;background:white;cursor:pointer;">
      <option value="">All Types</option>
      <option value="voluntary"   <?= $filterType==='voluntary'  ?'selected':'' ?>>Voluntary</option>
      <option value="involuntary" <?= $filterType==='involuntary'?'selected':'' ?>>Involuntary</option>
      <option value="project end" <?= $filterType==='project end'?'selected':'' ?>>Project End</option>
    </select>
    <?php if ($isAdmin): ?>
    <select name="loc" onchange="this.form.submit()" style="width:148px;padding:8px 10px;border:1.5px solid #e5e7eb;border-radius:8px;font-size:13px;background:white;cursor:pointer;">
      <option value="">All Locations</option>
      <?php foreach (LOCATIONS as $loc): ?>
      <option value="<?= htmlspecialchars($loc) ?>" <?= $filterLocation===$loc?'selected':'' ?>><?= htmlspecialchars($loc) ?></option>
      <?php endforeach; ?>
    </select>
    <?php else: ?>
    <input type="hidden" name="loc" value=""/>
    <?php endif; ?>
    <select name="pp" onchange="this.form.submit()" style="width:100px;padding:8px 10px;border:1.5px solid #e5e7eb;border-radius:8px;font-size:13px;background:white;cursor:pointer;">
      <option value="25"  <?= $perPage===25 ?'selected':'' ?>>25 / page</option>
      <option value="50"  <?= $perPage===50 ?'selected':'' ?>>50 / page</option>
      <option value="100" <?= $perPage===100?'selected':'' ?>>100 / page</option>
    </select>
    <?php if ($search || $filterType || $filterLocation): ?>
      <a href="<?= ADMIN_URL ?>" class="btn btn-outline btn-sm">✕ Clear</a>
    <?php endif; ?>
    <a href="<?= htmlspecialchars(pageUrl(['download' => 'export'])) ?>" class="btn btn-outline btn-sm" style="white-space:nowrap;">⬇ Export CSV</a>
    <button type="button" class="btn btn-primary btn-sm" onclick="document.getElementById('addModal').style.display='flex'" style="white-space:nowrap;">+ Add Record</button>
  </div>
  </form>

  <!-- Table -->
  <div class="table-wrap">
    <div class="table-header">
      <h3>Employee Records</h3>
      <span>
        <?php if ($totalPages > 1): ?>
          <?= (($page-1)*$perPage)+1 ?>–<?= min($page*$perPage, $totalFiltered) ?> of <?= $totalFiltered ?> record<?= $totalFiltered !== 1 ? 's' : '' ?>
        <?php else: ?>
          <?= $totalFiltered ?> record<?= $totalFiltered !== 1 ? 's' : '' ?>
        <?php endif; ?>
      </span>
    </div>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th>Employee ID</th>
            <th>Name</th>
            <th>Role</th>
            <th>Location</th>
            <th>DOB</th>
            <th>Start Date</th>
            <th>End Date</th>
            <th>Type</th>
            <th>Updated</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
        <?php if (empty($paginated)): ?>
          <tr><td colspan="10" class="empty-state"><?= $total === 0 ? 'No records yet. Upload a CSV or add manually.' : 'No records match your search.' ?></td></tr>
        <?php else: ?>
          <?php foreach ($paginated as $r): ?>
            <?php
              $sep   = $r['separationType'] ?? '';
              $sc    = str_replace(' ', '-', $sep);
              $sl    = ucwords($sep);
            ?>
            <tr>
              <td><span class="ref-code"><?= htmlspecialchars($r['reference'] ?? '') ?></span></td>
              <td><?= htmlspecialchars($r['legalName'] ?? '') ?></td>
              <td style="color:#6b7280;"><?= htmlspecialchars($r['role'] ?? '') ?: '—' ?></td>
              <td><?= $r['location'] ? '<span class="loc-pill">' . htmlspecialchars($r['location']) . '</span>' : '<span style="color:#9ca3af;">—</span>' ?></td>
              <td><?= htmlspecialchars(displayDate($r['dob'] ?? '')) ?></td>
              <td><?= htmlspecialchars(displayDate($r['startDate'] ?? '')) ?></td>
              <td><?= htmlspecialchars(displayDate($r['endDate'] ?? '')) ?></td>
              <td><span class="badge <?= htmlspecialchars($sc) ?>"><?= htmlspecialchars($sl) ?></span></td>
              <td style="font-size:12px;color:#6b7280;"><?= htmlspecialchars($r['lastUpdated'] ?? '—') ?></td>
              <td>
                <div class="actions">
                  <a href="#" class="btn btn-outline btn-sm" onclick="openEdit(<?= htmlspecialchars(json_encode($r)) ?>);return false;">Edit</a>
                  <form method="POST" style="display:inline;" onsubmit="return confirm('Delete this record?');">
                    <input type="hidden" name="action" value="delete_record"/>
                    <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>"/>
                    <input type="hidden" name="id" value="<?= htmlspecialchars($r['id']) ?>"/>
                    <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                  </form>
                </div>
              </td>
            </tr>
          <?php endforeach; ?>
        <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>

  <?php if ($totalPages > 1): ?>
  <div style="display:flex;align-items:center;justify-content:center;gap:6px;margin-top:16px;flex-wrap:wrap;">
    <?php if ($page > 1): ?>
      <a href="<?= htmlspecialchars(pageUrl(['p' => $page - 1])) ?>" class="btn btn-outline btn-sm">← Prev</a>
    <?php else: ?>
      <span class="btn btn-outline btn-sm" style="opacity:.4;cursor:default;">← Prev</span>
    <?php endif; ?>

    <?php
      $start = max(1, $page - 2);
      $end   = min($totalPages, $page + 2);
      if ($start > 1): ?>
        <a href="<?= htmlspecialchars(pageUrl(['p' => 1])) ?>" class="btn btn-outline btn-sm">1</a>
        <?php if ($start > 2): ?><span style="padding:0 4px;color:#9ca3af;">…</span><?php endif; ?>
    <?php endif; ?>

    <?php for ($i = $start; $i <= $end; $i++): ?>
      <?php if ($i === $page): ?>
        <span class="btn btn-primary btn-sm" style="cursor:default;"><?= $i ?></span>
      <?php else: ?>
        <a href="<?= htmlspecialchars(pageUrl(['p' => $i])) ?>" class="btn btn-outline btn-sm"><?= $i ?></a>
      <?php endif; ?>
    <?php endfor; ?>

    <?php if ($end < $totalPages): ?>
      <?php if ($end < $totalPages - 1): ?><span style="padding:0 4px;color:#9ca3af;">…</span><?php endif; ?>
      <a href="<?= htmlspecialchars(pageUrl(['p' => $totalPages])) ?>" class="btn btn-outline btn-sm"><?= $totalPages ?></a>
    <?php endif; ?>

    <?php if ($page < $totalPages): ?>
      <a href="<?= htmlspecialchars(pageUrl(['p' => $page + 1])) ?>" class="btn btn-outline btn-sm">Next →</a>
    <?php else: ?>
      <span class="btn btn-outline btn-sm" style="opacity:.4;cursor:default;">Next →</span>
    <?php endif; ?>
  </div>
  <?php endif; ?>

</div><!-- /.wrap -->

<!-- ADD MODAL -->
<div class="modal-overlay" id="addModal" style="display:none;">
  <div class="modal">
    <div class="modal-head"><h3>Add New Record</h3><button class="modal-close" onclick="document.getElementById('addModal').style.display='none'">×</button></div>
    <form method="POST">
      <input type="hidden" name="action" value="add_record"/>
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>"/>
      <div class="modal-body">
        <div class="form-group"><label>Employee ID</label><input type="text" name="reference" placeholder="e.g. TTBT00112" required/></div>
        <div class="form-row">
          <div class="form-group"><label>Legal Name</label><input type="text" name="legalName" placeholder="Full legal name" required/></div>
          <div class="form-group"><label>Role / Designation</label><input type="text" name="role" placeholder="e.g. Software Engineer"/></div>
        </div>
        <div class="form-group">
          <label>Location</label>
          <?php if ($isAdmin): ?>
            <select name="location">
              <option value="">Select location...</option>
              <?php foreach (LOCATIONS as $loc): ?>
                <option value="<?= htmlspecialchars($loc) ?>"><?= htmlspecialchars($loc) ?></option>
              <?php endforeach; ?>
            </select>
          <?php else: ?>
            <input type="hidden" name="location" value="<?= htmlspecialchars($myLocation) ?>"/>
            <div class="location-display"><?= htmlspecialchars($myLocation) ?></div>
          <?php endif; ?>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Date of Birth (DD-MM-YYYY)</label><input type="text" name="dob" placeholder="DD-MM-YYYY" maxlength="10"/></div>
          <div class="form-group"><label>Separation Type</label>
            <select name="separationType">
              <option value="voluntary">Voluntary</option>
              <option value="involuntary">Involuntary</option>
              <option value="project end">Project End</option>
            </select>
          </div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Start Date (DD-MM-YYYY)</label><input type="text" name="startDate" placeholder="DD-MM-YYYY" maxlength="10"/></div>
          <div class="form-group"><label>End Date (DD-MM-YYYY)</label><input type="text" name="endDate" placeholder="DD-MM-YYYY" maxlength="10"/></div>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" onclick="document.getElementById('addModal').style.display='none'">Cancel</button>
        <button type="submit" class="btn btn-success">Add Record</button>
      </div>
    </form>
  </div>
</div>

<!-- EDIT MODAL -->
<div class="modal-overlay" id="editModal" style="display:none;">
  <div class="modal">
    <div class="modal-head"><h3>Edit Record</h3><button class="modal-close" onclick="document.getElementById('editModal').style.display='none'">×</button></div>
    <form method="POST">
      <input type="hidden" name="action" value="edit_record"/>
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>"/>
      <input type="hidden" name="id" id="editId"/>
      <div class="modal-body">
        <div class="form-group"><label>Employee ID</label><input type="text" name="reference" id="editRef" required/></div>
        <div class="form-row">
          <div class="form-group"><label>Legal Name</label><input type="text" name="legalName" id="editName" required/></div>
          <div class="form-group"><label>Role / Designation</label><input type="text" name="role" id="editRole"/></div>
        </div>
        <div class="form-group">
          <label>Location</label>
          <?php if ($isAdmin): ?>
            <select name="location" id="editLocation">
              <option value="">Select location...</option>
              <?php foreach (LOCATIONS as $loc): ?>
                <option value="<?= htmlspecialchars($loc) ?>"><?= htmlspecialchars($loc) ?></option>
              <?php endforeach; ?>
            </select>
          <?php else: ?>
            <input type="hidden" name="location" value="<?= htmlspecialchars($myLocation) ?>"/>
            <div class="location-display"><?= htmlspecialchars($myLocation) ?></div>
          <?php endif; ?>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Date of Birth (DD-MM-YYYY)</label><input type="text" name="dob" id="editDob" placeholder="DD-MM-YYYY" maxlength="10"/></div>
          <div class="form-group"><label>Separation Type</label>
            <select name="separationType" id="editSep">
              <option value="voluntary">Voluntary</option>
              <option value="involuntary">Involuntary</option>
              <option value="project end">Project End</option>
            </select>
          </div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Start Date (DD-MM-YYYY)</label><input type="text" name="startDate" id="editStart" placeholder="DD-MM-YYYY" maxlength="10"/></div>
          <div class="form-group"><label>End Date (DD-MM-YYYY)</label><input type="text" name="endDate" id="editEnd" placeholder="DD-MM-YYYY" maxlength="10"/></div>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline" onclick="document.getElementById('editModal').style.display='none'">Cancel</button>
        <button type="submit" class="btn btn-primary">Save Changes</button>
      </div>
    </form>
  </div>
</div>

<script>
  // Close modals on overlay click
  ['addModal','editModal'].forEach(id => {
    document.getElementById(id).addEventListener('click', function(e) {
      if (e.target === this) this.style.display = 'none';
    });
  });

  // Populate edit modal — dates displayed as DD-MM-YYYY (stored YYYY-MM-DD)
  function toDisplay(d) {
    if (!d) return '';
    const m = String(d).match(/^(\d{4})-(\d{2})-(\d{2})$/);
    return m ? `${m[3]}-${m[2]}-${m[1]}` : d;
  }

  function openEdit(r) {
    document.getElementById('editId').value    = r.id        || '';
    document.getElementById('editRef').value   = r.reference || '';
    document.getElementById('editName').value  = r.legalName || '';
    document.getElementById('editRole').value  = r.role      || '';
    document.getElementById('editDob').value   = toDisplay(r.dob);
    document.getElementById('editStart').value = toDisplay(r.startDate);
    document.getElementById('editEnd').value   = toDisplay(r.endDate);
    const sep = document.getElementById('editSep');
    if (sep) sep.value = r.separationType || 'voluntary';
    const loc = document.getElementById('editLocation');
    if (loc) loc.value = r.location || '';
    document.getElementById('editModal').style.display = 'flex';
  }
</script>

<?php endif; ?>
</body>
</html>
