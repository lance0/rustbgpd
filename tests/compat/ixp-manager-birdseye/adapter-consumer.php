<?php

declare(strict_types=1);

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use IXP\Models\Router;
use IXP\Services\LookingGlass\BirdsEye;
use IXP\Utils\Foil\Extensions\Bird;

require getenv('IXP_MANAGER_ROOT') . '/vendor/autoload.php';

$manifest = json_decode(
    file_get_contents(__DIR__ . '/contract.json'),
    true,
    512,
    JSON_THROW_ON_ERROR,
);
$protocol = getenv('EXPECTED_PROTOCOL');
if (!is_string($protocol) || $protocol === '') {
    throw new RuntimeException('EXPECTED_PROTOCOL is required');
}
$knownProtocols = array_values($manifest['protocol_aliases'] ?? []);
$table = $manifest['routing_tables'][0] ?? null;
$versionPrefix = $manifest['adapter_api_version']['prefix'] ?? null;
$filtered = $manifest['filtered_prefix_query'] ?? [];
$expectedReasons = [
    1 => 'PREFIX LENGTH TOO LONG', 2 => 'PREFIX LENGTH TOO SHORT',
    3 => 'BOGON', 4 => 'BOGON ASN', 5 => 'AS PATH TOO LONG',
    6 => 'AS PATH TOO SHORT', 7 => 'FIRST AS NOT PEER AS',
    8 => 'NEXT HOP NOT PEER IP', 9 => 'IRRDB PREFIX FILTERED',
    10 => 'IRRDB ORIGIN AS FILTERED', 11 => 'PREFIX NOT IN ORIGIN AS',
    12 => 'RPKI UNKNOWN', 13 => 'RPKI INVALID', 14 => 'TRANSIT FREE ASN',
    15 => 'TOO MANY COMMUNITIES',
];
$reasonContract = $manifest['reject_reasons'] ?? [];
if (
    !in_array($protocol, $knownProtocols, true)
    || $table !== 'master4'
    || $versionPrefix !== 'rustbgpd '
    || $filtered !== ['global_admin' => 65001, 'function' => 1101]
    || ($reasonContract['display'] ?? null) !== $expectedReasons
    || ($reasonContract['active_ids'] ?? null) !== [1, 3, 5, 6, 7, 8, 9, 10, 13, 14]
    || ($reasonContract['defined_only_ids'] ?? null) !== [2, 4, 11, 12, 15]
    || ($reasonContract['fallback_id'] ?? null) !== 0
) {
    throw new RuntimeException('adapter consumer contract drifted');
}
$bird = new Bird();
foreach ($expectedReasons as $id => $meaning) {
    if ($bird->translateBgpFilteringLargeCommunity(":1101:$id") !== [$meaning, 'danger']) {
        throw new RuntimeException("IXP Manager reject reason $id drifted");
    }
}
if ($bird->translateBgpFilteringLargeCommunity(':1101:0') !== null) {
    throw new RuntimeException('fallback reason 0 must remain untranslated');
}
$expectedActive = [1, 3, 5, 6, 7, 8, 9, 10, 13, 14];
$expectedDefinedOnly = [2, 4, 11, 12, 15];
foreach (['bird2', 'bird2-2025'] as $template) {
    $directory = getenv('IXP_MANAGER_ROOT') . "/resources/views/api/v4/router/server/$template";
    $definitions = file_get_contents("$directory/community-filtering-definitions.foil.php");
    if (!is_string($definitions)) {
        throw new RuntimeException("$template reject-reason definitions are required");
    }
    preg_match_all(
        '/define\s+(IXP_LC_FILTERED_[A-Z0-9_]+)\s*=\s*\([^,]+,\s*1101,\s*(\d+)\s*\)/',
        $definitions,
        $definedMatches,
        PREG_SET_ORDER,
    );
    $symbolIds = [];
    foreach ($definedMatches as $match) {
        $symbolIds[$match[1]] = (int) $match[2];
    }
    if (array_values($symbolIds) !== range(1, 15)) {
        throw new RuntimeException("$template reject-reason definitions drifted");
    }
    $symbols = [];
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory)) as $file) {
        if (!$file->isFile() || $file->getFilename() === 'community-filtering-definitions.foil.php') {
            continue;
        }
        $contents = file_get_contents($file->getPathname());
        if (!is_string($contents)) {
            throw new RuntimeException("$template source is unreadable");
        }
        preg_match_all(
            '/^[ \t]*bgp_large_community\.add\s*\(\s*(IXP_LC_FILTERED_[A-Z0-9_]+)\s*\)\s*;/m',
            $contents,
            $matches,
        );
        foreach ($matches[1] as $symbol) {
            $symbols[$symbol] = true;
        }
    }
    $active = [];
    foreach (array_keys($symbols) as $symbol) {
        if (!isset($symbolIds[$symbol])) {
            throw new RuntimeException("$template references an unknown reject-reason symbol");
        }
        $active[] = $symbolIds[$symbol];
    }
    sort($active);
    $active = array_values(array_unique($active));
    if ($active !== $expectedActive || array_values(array_diff(range(1, 15), $active)) !== $expectedDefinedOnly) {
        throw new RuntimeException("$template active reject-reason partition drifted");
    }
}

$container = new Container();
Container::setInstance($container);
$container->instance('config', new Repository([
    'ixp_fe' => ['frontend' => ['disabled' => ['logs' => true]]],
]));
$router = new Router();
$router->api = getenv('BIRDSEYE_API');
$consumer = new BirdsEye($router);
$view = @file_get_contents(
    getenv('IXP_MANAGER_ROOT') . '/resources/views/services/lg/bgp-summary.foil.php'
);
$diagnostic = @file_get_contents(
    getenv('IXP_MANAGER_ROOT') . '/app/Services/Diagnostics/Suites/RouterBgpSessionsDiagnosticSuite.php'
);
if (!is_string($view) || !is_string($diagnostic)) {
    throw new RuntimeException('pinned session-detail consumers are required');
}
foreach (['p.connection', 'p.bgp_session', 'p.source_address', 'p.keepalive'] as $use) {
    if (!str_contains($view, $use)) {
        throw new RuntimeException("pinned session-detail view use drifted: $use");
    }
}
foreach (['{$bgpsum->connection}', 'isset( $bgpsum->keepalive )'] as $use) {
    if (!str_contains($diagnostic, $use)) {
        throw new RuntimeException("pinned session diagnostic use drifted: $use");
    }
}
$symbols = $consumer->symbols();
if (!is_string($symbols)) {
    throw new RuntimeException('symbols did not return adapter JSON');
}
$decodedSymbols = json_decode($symbols, true, 512, JSON_THROW_ON_ERROR);
if (($decodedSymbols['symbols']['routing table'] ?? null) !== [$table]) {
    throw new RuntimeException('symbols did not expose the configured live routing table');
}
$responses = [
    'exact-protocol-route' => $consumer->protocolRoute($protocol, '192.0.2.0', 24),
    'exact-export-route' => $consumer->exportRoute($protocol, '192.0.2.0', 24),
    'lpm-table-search' => $consumer->protocolTable($table, '192.0.2.128', 25),
    'atomic-full-table' => $consumer->routesForTable($table),
    'filtered-prefix-wildcard' => $consumer->routesProtocolLargeCommunityWildXYRoutes(
        $protocol,
        $filtered['global_admin'],
        $filtered['function'],
    ),
];
$session = $consumer->bgpNeighbourSummary($protocol);
if (!is_string($session)) {
    throw new RuntimeException('session detail did not return adapter JSON');
}
$decodedSession = json_decode($session, true, 512, JSON_THROW_ON_ERROR);
$detail = $decodedSession['protocol'] ?? [];
if (($detail['connection'] ?? null) !== '') {
    throw new RuntimeException('down session connection must be present and empty');
}
foreach (['source_address', 'keepalive', 'bgp_session', 'hold_timer_now', 'keepalive_now'] as $field) {
    if (array_key_exists($field, $detail)) {
        throw new RuntimeException("down session fabricated $field");
    }
}
$responses['session-detail'] = $session;

foreach ($responses as $journey => $response) {
    if ($journey === 'session-detail') {
        continue;
    }
    if (!is_string($response)) {
        throw new RuntimeException("$journey did not return adapter JSON");
    }
    $decoded = json_decode($response, true, 512, JSON_THROW_ON_ERROR);
    if (($decoded['routes'] ?? null) !== []) {
        throw new RuntimeException("$journey expected the configured down peer to be empty");
    }
    $version = $decoded['api']['version'] ?? '';
    if (!is_string($version) || !str_starts_with($version, $versionPrefix)) {
        throw new RuntimeException("$journey api.version is not rustbgpd product identity");
    }
}
$responses['symbols'] = $symbols;

echo json_encode($responses, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
