<?php
header('Content-Type: application/json');

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

$rl = @json_decode(@file_get_contents($rlFile), true) ?: ['count' => 0, 'reset' => $now + $window];
if ($now > $rl['reset']) { $rl = ['count' => 0, 'reset' => $now + $window]; }
$rl['count']++;
@file_put_contents($rlFile, json_encode($rl), LOCK_EX);

if ($rl['count'] > $limit) {
    http_response_code(429);
    echo json_encode(['found' => false, 'error' => 'Too many requests. Please try again later.']);
    exit;
}

// ── Load data ─────────────────────────────────────────────────────────────────
define('DATA_FILE', __DIR__ . '/data.json');
function loadData(): array {
    if (!file_exists(DATA_FILE)) return [];
    $data = json_decode(file_get_contents(DATA_FILE), true);
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
            'location'       => $record['location']   ?? '',
            'enterprise'     => $record['enterprise'] ?? '',
            'cardVariant'    => 'v1',
        ]);
        exit;
    }
}

echo json_encode(['found' => false]);
