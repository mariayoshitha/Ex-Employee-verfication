<?php
ini_set('display_errors', '0');
header('Content-Type: application/json');
header('Cache-Control: no-store');

// ── CORS: restrict to same origin only ───────────────────────────────────────
$origin  = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowed = (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? '');
if ($origin && $origin === $allowed) {
    header("Access-Control-Allow-Origin: $origin");
    header('Vary: Origin');
}

// ── Rate limiting: max 20 lookups per minute per IP ──────────────────────────
$ip     = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$rlFile = sys_get_temp_dir() . '/tt_rl_' . md5($ip) . '.json';
$now    = time();
$window = 60;   // seconds
$limit  = 20;   // max requests per window

// Read-modify-write under one exclusive lock so parallel requests cannot undercount.
function bumpCounter(string $file, int $window): int {
    $fh = @fopen($file, 'c+');
    if (!$fh) return 0;
    flock($fh, LOCK_EX);
    $c = json_decode((string)stream_get_contents($fh), true);
    $now = time();
    if (!is_array($c) || $now > ($c['reset'] ?? 0)) $c = ['count' => 0, 'reset' => $now + $window];
    $c['count']++;
    ftruncate($fh, 0); rewind($fh); fwrite($fh, json_encode($c));
    flock($fh, LOCK_UN); fclose($fh);
    return $c['count'];
}
$rl = ['count' => bumpCounter($rlFile, $window)];

if ($rl['count'] > $limit) {
    http_response_code(429);
    echo json_encode(['found' => false, 'error' => 'Too many requests. Please try again later.']);
    exit;
}

// ── Load data ─────────────────────────────────────────────────────────────────
define('DATA_FILE', __DIR__ . '/data.json');
function loadData(): array {
    // Shared lock: never read while the admin panel or sync.php is mid-rewrite.
    $fh = @fopen(DATA_FILE, 'rb');
    if (!$fh) return [];
    flock($fh, LOCK_SH);
    $raw = stream_get_contents($fh);
    flock($fh, LOCK_UN); fclose($fh);
    $data = json_decode((string)$raw, true);
    return is_array($data) ? $data : [];
}

$ref = trim($_GET['ref'] ?? '');
$dob = trim($_GET['dob'] ?? '');

if (!$ref || !$dob) {
    echo json_encode(['found' => false, 'error' => 'Missing employee ID or date of birth.']);
    exit;
}

// Basic format validation on DOB (must be YYYY-MM-DD)
if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $dob)) {
    echo json_encode(['found' => false]);
    exit;
}

// Per-employee-ID guess cap. Employee IDs are sequential and a DOB has only ~17k plausible values,
// so a per-IP limit alone can be walked around with many IPs. Over the cap the answer is the same
// generic "not found" for everyone, for 24h.
define('MAX_GUESSES_PER_ID', 30);
$refFile = sys_get_temp_dir() . '/tt_ref_' . md5(strtolower($ref)) . '.json';
$refInfo = @json_decode((string)@file_get_contents($refFile), true);
if (is_array($refInfo) && time() <= ($refInfo['reset'] ?? 0) && ($refInfo['count'] ?? 0) >= MAX_GUESSES_PER_ID) {
    echo json_encode(['found' => false]);
    exit;
}

foreach (loadData() as $record) {
    if (
        strtolower(trim($record['reference'] ?? '')) === strtolower($ref) &&
        trim($record['dob'] ?? '') === $dob
    ) {
        echo json_encode([
            'found'          => true,
            'legalName'      => $record['legalName'],
            'role'           => $record['role'] ?? '',
            'dob'            => $record['dob'] ?? '',
            'startDate'      => $record['startDate'],
            'endDate'        => $record['endDate'],
            'separationType' => $record['separationType'],
            'employmentType' => $record['employmentType'] ?? 'inhouse',
            'location'       => $record['location']   ?? '',
            'enterprise'     => $record['enterprise'] ?? '',
            'cardVariant'    => 'v1',
        ]);
        exit;
    }
}

bumpCounter($refFile, 86400); // a miss counts against this ID
echo json_encode(['found' => false]);
