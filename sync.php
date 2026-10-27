<?php
/**
 * HRMS -> Verification Portal record sync (server-to-server, write path).
 *
 * Kept out of api.php on purpose: the public lookup endpoint stays read-only.
 * Disabled until tt-config.json has  "sync": { "token_hash": "<sha256 hex>", "allowed_ips": ["x.x.x.x"] }.
 * Only ever touches records that carry an hrmsUserId, plus adopts a legacy record
 * when reference + DOB match exactly (HRMS is the newer source).
 *
 * POST /api/sync   Authorization: Bearer <token>   Content-Type: application/json
 *   { "action": "upsert", "hrmsUserId": "<uuid>", "record": { reference, legalName, role,
 *       location, enterprise, dob, startDate, endDate, separationType, employmentType } }
 *   { "action": "delete", "hrmsUserId": "<uuid>" }
 */
header('Content-Type: application/json');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

define('DATA_FILE', __DIR__ . '/data.json');
define('SYNC_LOG',  __DIR__ . '/sync.log');
const MAX_BODY      = 16384;
const SEP_TYPES     = ['voluntary', 'involuntary', 'project end'];
const EMP_TYPES     = ['inhouse', 'contract'];
const RATE_PER_MIN  = 60;
const MAX_FAILS     = 10;     // failed auths per IP before lockout
const LOCKOUT_SECS  = 900;

function out(int $code, array $body): void {
    http_response_code($code);
    echo json_encode($body);
    exit;
}

function syncLog(string $ip, string $action, string $ref, int $code): void {
    $line = date('Y-m-d H:i:s') . "\t$ip\t$action\t" . preg_replace('/[^\w.\/-]/', '_', $ref) . "\t$code\n";
    @file_put_contents(SYNC_LOG, $line, FILE_APPEND | LOCK_EX);
}

$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

// ── Transport: HTTPS only (direct signals only, never proxy-forwarded headers) ─
$isHttps = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') === '443');
$isLocal = in_array($ip, ['127.0.0.1', '::1'], true);
if (!$isHttps && !$isLocal) out(403, ['ok' => false, 'error' => 'https required']);

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    out(405, ['ok' => false, 'error' => 'method not allowed']);
}

// ── Config (same lookup as admin.php) ─────────────────────────────────────────
$cfgFile = dirname(__DIR__) . '/tt-config.json';
if (!file_exists($cfgFile)) $cfgFile = __DIR__ . '/tt-config.json';
$cfg   = json_decode(@file_get_contents($cfgFile), true);
$cfg   = is_array($cfg) ? $cfg : [];
$sync  = is_array($cfg['sync'] ?? null) ? $cfg['sync'] : [];
$hash  = (string)($sync['token_hash'] ?? '');
if (!preg_match('/^[0-9a-f]{64}$/', $hash)) out(503, ['ok' => false, 'error' => 'sync not configured']);

// ── Per-IP rate limit + failed-auth lockout ───────────────────────────────────
$rlFile = sys_get_temp_dir() . '/tt_sync_rl_' . md5($ip) . '.json';
$now    = time();
$rl     = @json_decode(@file_get_contents($rlFile), true);
if (!is_array($rl)) $rl = [];
$rl += ['count' => 0, 'reset' => $now + 60, 'fails' => 0, 'lock_until' => 0];
if ($now > $rl['reset']) { $rl['count'] = 0; $rl['reset'] = $now + 60; }
$saveRl = function () use (&$rl, $rlFile) { @file_put_contents($rlFile, json_encode($rl), LOCK_EX); };
if ($now < $rl['lock_until'] || ++$rl['count'] > RATE_PER_MIN) {
    $saveRl();
    out(429, ['ok' => false, 'error' => 'too many requests']);
}

// ── Auth: optional IP allowlist, then bearer token (constant-time on its hash) ─
$allowed = $sync['allowed_ips'] ?? [];
$authHdr = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
$token   = preg_match('/^Bearer\s+(\S{16,256})$/', $authHdr, $m) ? $m[1] : '';
$ipOk    = !is_array($allowed) || !$allowed || in_array($ip, $allowed, true);
if (!$ipOk || $token === '' || !hash_equals($hash, hash('sha256', $token))) {
    if (++$rl['fails'] >= MAX_FAILS) { $rl['lock_until'] = $now + LOCKOUT_SECS; $rl['fails'] = 0; }
    $saveRl();
    syncLog($ip, 'auth', '', 401);
    out(401, ['ok' => false, 'error' => 'unauthorized']);
}
$rl['fails'] = 0;
$saveRl();

// ── Body ──────────────────────────────────────────────────────────────────────
if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) out(415, ['ok' => false, 'error' => 'json only']);
$raw = file_get_contents('php://input', false, null, 0, MAX_BODY + 1);
if ($raw === false || strlen($raw) > MAX_BODY) out(413, ['ok' => false, 'error' => 'body too large']);
$req = json_decode($raw, true);
if (!is_array($req)) out(400, ['ok' => false, 'error' => 'invalid json']);

$action = $req['action'] ?? '';
$uid    = $req['hrmsUserId'] ?? '';
if (!in_array($action, ['upsert', 'delete'], true)) out(400, ['ok' => false, 'error' => 'invalid action']);
if (!is_string($uid) || !preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $uid)) {
    out(400, ['ok' => false, 'error' => 'invalid hrmsUserId']);
}
$uid = strtolower($uid);

// ── Validation helpers ────────────────────────────────────────────────────────
function cleanStr($v, int $max, bool $required): ?string {
    if (!is_string($v)) return $required ? null : '';
    $v = trim($v);
    if ($v === '' ) return $required ? null : '';
    if (strlen($v) > $max || preg_match('/[\x00-\x1F\x7F]/', $v)) return null;
    // Same CSV-injection defence as admin.php sanitizeText().
    if (in_array($v[0], ['=', '+', '-', '@'], true)) $v = "'" . $v;
    return $v;
}
function cleanDate($v): ?string {
    if (!is_string($v) || !preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $v, $p)) return null;
    return checkdate((int)$p[2], (int)$p[3], (int)$p[1]) ? $v : null;
}
function fail(string $why): void { out(422, ['ok' => false, 'error' => $why]); }

$rec = null;
if ($action === 'upsert') {
    $in = $req['record'] ?? null;
    if (!is_array($in)) fail('record required');

    $ref = cleanStr($in['reference'] ?? null, 50, true);
    if ($ref === null || !preg_match('/^[A-Za-z0-9][A-Za-z0-9._\/-]*$/', $ref)) fail('invalid reference');

    $name = cleanStr($in['legalName'] ?? null, 200, true);   if ($name === null) fail('invalid legalName');
    $role = cleanStr($in['role'] ?? '', 200, false);          if ($role === null) fail('invalid role');

    $loc = null;
    foreach ((array)($cfg['locations'] ?? []) as $l) {
        if (is_string($in['location'] ?? null) && strcasecmp($l, trim($in['location'])) === 0) { $loc = $l; break; }
    }
    if ($loc === null) fail('unknown location');

    $ent = null;
    foreach ((array)($cfg['enterprises'] ?? []) as $e) {
        if (is_string($in['enterprise'] ?? null) && strcasecmp($e['name'] ?? '', trim($in['enterprise'])) === 0) { $ent = $e['name']; break; }
    }
    if ($ent === null) fail('unknown enterprise');

    $dob   = cleanDate($in['dob'] ?? null);        if ($dob === null || $dob > date('Y-m-d')) fail('invalid dob');
    $start = cleanDate($in['startDate'] ?? null);  if ($start === null) fail('invalid startDate');
    $end   = cleanDate($in['endDate'] ?? null);    if ($end === null || $end < $start) fail('invalid endDate');

    $sep = is_string($in['separationType'] ?? null) ? strtolower(trim($in['separationType'])) : '';
    if (!in_array($sep, SEP_TYPES, true)) fail('invalid separationType');
    $emp = is_string($in['employmentType'] ?? null) ? strtolower(trim($in['employmentType'])) : '';
    if (!in_array($emp, EMP_TYPES, true)) fail('invalid employmentType');

    $rec = [
        'reference' => $ref, 'legalName' => $name, 'role' => $role, 'location' => $loc,
        'dob' => $dob, 'startDate' => $start, 'endDate' => $end, 'separationType' => $sep,
        'employmentType' => $emp, 'enterprise' => $ent,
    ];
}

// ── Read-modify-write under an exclusive lock (admin.php writes take LOCK_EX on the same file) ─
$fh = @fopen(DATA_FILE, 'c+');
if (!$fh || !flock($fh, LOCK_EX)) out(503, ['ok' => false, 'error' => 'busy']);
$cur  = stream_get_contents($fh);
$data = $cur === '' ? [] : json_decode($cur, true);
if (!is_array($data)) { flock($fh, LOCK_UN); fclose($fh); out(500, ['ok' => false, 'error' => 'data unreadable']); } // never clobber
$data = array_values($data);

$byUid = null; $legacy = null; $clash = false;
foreach ($data as $i => $r) {
    if (($r['hrmsUserId'] ?? '') === $uid) { $byUid = $i; continue; }
    if ($rec && strcasecmp($r['reference'] ?? '', $rec['reference']) === 0 && ($r['dob'] ?? '') === $rec['dob']) {
        if (empty($r['hrmsUserId'])) $legacy = $i; else $clash = true;
    }
}

$status = 200; $result = '';
if ($action === 'delete') {
    if ($byUid !== null) { array_splice($data, $byUid, 1); $result = 'deleted'; } else { $result = 'absent'; }
} elseif ($clash && $byUid === null) {
    flock($fh, LOCK_UN); fclose($fh);
    syncLog($ip, $action, $rec['reference'], 409);
    out(409, ['ok' => false, 'error' => 'another HRMS record already uses this reference + dob']);
} else {
    $idx = $byUid ?? $legacy;
    $new = $rec + ['hrmsUserId' => $uid, 'source' => 'hrms', 'lastUpdated' => date('Y-m-d H:i')];
    if ($idx !== null) {
        $new['id'] = $data[$idx]['id'] ?? uniqid('rec_', true);
        $data[$idx] = $new;
        $result = $byUid !== null ? 'updated' : 'adopted-legacy';
    } else {
        $new['id'] = uniqid('rec_', true);
        $data[] = $new;
        $result = 'created';
    }
}

$json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
if ($json === false) { flock($fh, LOCK_UN); fclose($fh); out(500, ['ok' => false, 'error' => 'encode failed']); }
rewind($fh); ftruncate($fh, 0); fwrite($fh, $json); fflush($fh);
flock($fh, LOCK_UN); fclose($fh);

syncLog($ip, $action . ':' . $result, $rec['reference'] ?? '-', $status);
out($status, ['ok' => true, 'result' => $result]);
