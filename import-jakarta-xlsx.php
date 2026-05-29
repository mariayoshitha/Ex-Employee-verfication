<?php
// One-shot converter: section-headered "TTID Exit Employee Details" xlsx → clean upload CSV.
// Writes upload-ready CSV next to the source xlsx; does NOT touch data.json.
// After running: upload the CSV via admin → Upload form (which upserts by Employee ID).

declare(strict_types=1);

$src = $argv[1] ?? __DIR__ . '/TTID Exit Employee Details 2018-26(Updated-05-31-2026).xlsx';
$out = $argv[2] ?? __DIR__ . '/TTID-Exit-cleaned-for-upload.csv';

if (!file_exists($src)) { fwrite(STDERR, "missing xlsx: $src\n"); exit(1); }

// Borrow parser + date normalizer from admin.php without booting the request stack.
$adminSrc = file_get_contents(__DIR__ . '/admin.php');
foreach (['xlsxColIndex', 'parseXlsx', 'normalizeDate'] as $fn) {
    if (!preg_match('/function\s+' . $fn . '\b[\s\S]+?\n\}\n/', $adminSrc, $m)) {
        fwrite(STDERR, "could not extract $fn\n"); exit(1);
    }
    eval($m[0]);
}

$rows = parseXlsx($src);
if (!$rows) { fwrite(STDERR, "empty xlsx\n"); exit(1); }

$sepMap = [
    'voluntary'        => 'voluntary',
    'involuntary'      => 'involuntary',
    'end of contract'  => 'project end',
    'project end'      => 'project end',
    'terminated'       => 'involuntary',
];

$entMap = [
    // Canonicalise xlsx entity strings to tt-config.json names.
    'pt techtiera services indonesia' => 'PT TechTiera Services',
    'techtiera india'                  => 'TechTiera Corporation India Pvt. Ltd.',
];

$locMap = [
    'jakarta - indonesia' => 'Jakarta, Indonesia',
];

$section = '';
$out_rows = [];
$skipped = [];

foreach ($rows as $idx => $r) {
    $first = trim((string)($r[0] ?? ''));
    if ($first === '') continue;
    if (preg_match('/^\s*CONTRACT\s+EMPLOYEE\s*$/i', $first)) { $section = 'contract'; continue; }
    if (preg_match('/^\s*INHOUSE\s+EMPLOYEE\s*$/i',  $first)) { $section = 'inhouse';  continue; }
    if (strcasecmp($first, 'Employee ID') === 0) continue;

    [$ref, $name, $role, $ent, $loc, $dob, $sd, $ed, $sep] = array_pad($r, 9, '');

    $sepLower = strtolower(trim((string)$sep));
    if (!isset($sepMap[$sepLower])) { $skipped[] = "row $idx: unmapped sep '$sep'"; continue; }
    $sepClean = $sepMap[$sepLower];

    $locKey = strtolower(trim((string)$loc));
    $locClean = $locMap[$locKey] ?? $loc;

    $entKey = strtolower(trim((string)$ent));
    $entClean = $entMap[$entKey] ?? $ent;

    $employmentType = $section ?: 'inhouse';

    $out_rows[] = [
        $ref,
        $name,
        $role,
        $locClean,
        $entClean,
        normalizeDate((string)$dob),
        normalizeDate((string)$sd),
        normalizeDate((string)$ed),
        $sepClean,
        $employmentType,
    ];
}

$fh = fopen($out, 'w');
// No BOM: admin.php strips BOM only AFTER fgetcsv has parsed row 1, by which
// point a BOM-prefixed quoted first cell ('"Employee ID"' preceded by BOM)
// has already lost its opening quote semantics and gets stored with literal
// quotes in the header. Skipping the BOM keeps the headers cleanly parseable.
fputcsv($fh, ['Employee ID','Name','Role','Location','Enterprise','DOB','Start Date','End Date','Separation Type','Employment Type'], ',', '"', '');
foreach ($out_rows as $row) fputcsv($fh, $row, ',', '"', '');
fclose($fh);

echo "wrote " . count($out_rows) . " rows → $out\n";
if ($skipped) {
    echo "\nskipped:\n";
    foreach ($skipped as $s) echo "  $s\n";
}

$contractCount = 0; $inhouseCount = 0;
foreach ($out_rows as $row) {
    if ($row[9] === 'contract') $contractCount++;
    else $inhouseCount++;
}
echo "\nsummary: contract=$contractCount inhouse=$inhouseCount\n";
