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
$protocol = $manifest['protocol_aliases']['member-v4'] ?? null;
if ($protocol !== 'pb_as64496') {
    throw new RuntimeException('explicit member-v4 protocol alias drifted');
}

$container = new Container();
Container::setInstance($container);
$container->instance('config', new Repository([
    'ixp_fe' => ['frontend' => ['disabled' => ['logs' => true]]],
]));
$router = new Router();
$router->api = getenv('BIRDSEYE_API');
$consumer = new BirdsEye($router);
$responses = [
    'status' => $consumer->status(),
    'protocols' => $consumer->bgpSummary(),
    'protocol' => $consumer->bgpNeighbourSummary($protocol),
    'symbols' => $consumer->symbols(),
    'protocol_routes' => $consumer->routesForProtocol($protocol),
    'table_routes' => $consumer->routesForTable('master4'),
    'export_routes' => $consumer->routesForExport($protocol),
    'lookup_protocol' => $consumer->protocolRoute($protocol, '192.0.2.0', 24),
    'lookup_table' => $consumer->protocolTable('master4', '192.0.2.0', 24),
    'lookup_export' => $consumer->exportRoute($protocol, '192.0.2.0', 24),
    'wildcard' => $consumer->routesProtocolLargeCommunityWildXYRoutes($protocol, 64496, 1101),
    'non_2xx_400_bad_lookup_is_empty' => $consumer->protocolTable('master4', 'not-an-ip', 24),
    'non_2xx_403_over_limit_is_empty' => $consumer->routesForProtocol('pb_large_as64498'),
    'non_2xx_404_missing_is_empty' => $consumer->bgpNeighbourSummary('missing'),
    'non_2xx_503_bird_failure_is_empty' => $consumer->routesForProtocol('pb_fail_as64497'),
];

echo json_encode(
    [
        'ixp_manager_commit' => $manifest['ixp_manager_commit'],
        'responses' => $responses,
    ],
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
) . "\n";
