<?php
// Dev-only router for `php -S`. Maps the clean URLs that .htaccess handles
// in production (/admin -> admin.php, /api -> api.php, /manual -> manual.html)
// so the built-in PHP server matches Apache behavior.
$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($uri === false || $uri === null) {
    http_response_code(400);
    echo 'Bad Request';
    return true;
}

// Block sensitive files + direct .php/.html that .htaccess hides in production.
$blocked = [
    '/data.json', '/audit.json', '/tt-credentials.php', '/tt-config.json', '/tt-config.json.lock', '/.htaccess',
    '/admin.php', '/api.php', '/router.php', '/manual.html',
];
foreach ($blocked as $b) {
    if (strcasecmp($uri, $b) === 0) {
        http_response_code(403);
        echo 'Forbidden';
        return true;
    }
}
// Block audit-YYYY-MM.json archives too.
if (preg_match('#^/audit-\d{4}-\d{2}\.json$#i', $uri)) {
    http_response_code(403);
    echo 'Forbidden';
    return true;
}

// Clean URL routes.
if (preg_match('#^/admin/?$#', $uri))  { require __DIR__ . '/admin.php';  return true; }
if (preg_match('#^/api/?$#',   $uri))  { require __DIR__ . '/api.php';    return true; }
if (preg_match('#^/manual/?$#',$uri))  { readfile(__DIR__ . '/manual.html'); return true; }

// Let the built-in server serve static files (index.html, logo.svg, etc).
return false;
