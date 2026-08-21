<?php

declare(strict_types=1);

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use IXP\Models\Router;
use IXP\Services\LookingGlass\BirdsEye;

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
if (
    !in_array($protocol, $knownProtocols, true)
    || $table !== 'master4'
    || $versionPrefix !== 'rustbgpd '
    || $filtered !== ['global_admin' => 65001, 'function' => 1101]
) {
    throw new RuntimeException('adapter consumer contract drifted');
}

$container = new Container();
Container::setInstance($container);
$container->instance('config', new Repository([
    'ixp_fe' => ['frontend' => ['disabled' => ['logs' => true]]],
]));
$router = new Router();
$router->api = getenv('BIRDSEYE_API');
$consumer = new BirdsEye($router);
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
    'filtered-prefix-wildcard' => $consumer->routesProtocolLargeCommunityWildXYRoutes(
        $protocol,
        $filtered['global_admin'],
        $filtered['function'],
    ),
];

foreach ($responses as $journey => $response) {
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
