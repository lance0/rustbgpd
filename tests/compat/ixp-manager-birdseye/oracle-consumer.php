<?php

declare(strict_types=1);

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use IXP\Models\Router;
use IXP\Services\LookingGlass\BirdsEye;

require getenv('IXP_MANAGER_ROOT') . '/vendor/autoload.php';

// Drives every Bird's Eye endpoint IXP Manager v7.4.0's BirdsEye consumer
// calls, through that consumer, against one populated route server: the
// pinned BIRD 2.0.12 + Bird's Eye oracle or the rustbgpd + adapter live leg.
// Both legs receive the same announcements, so the two outputs are an
// oracle/live fixture pair that verify_capture.py --populated diffs.
$manifest = json_decode(
    file_get_contents(__DIR__ . '/contract.json'),
    true,
    512,
    JSON_THROW_ON_ERROR,
);
$topology = $manifest['populated_topology'] ?? [];
$v4 = $topology['protocols']['member-v4'] ?? null;
$v6 = $topology['protocols']['member-v6'] ?? null;
$filtered = $manifest['filtered_prefix_query'] ?? [];
if ($v4 !== 'pb_as64496' || $v6 !== 'pb6_as64496'
    || $filtered !== ['global_admin' => 65001, 'function' => 1101]) {
    throw new RuntimeException('populated oracle topology drifted');
}

$container = new Container();
Container::setInstance($container);
$container->instance('config', new Repository([
    'ixp_fe' => ['frontend' => ['disabled' => ['logs' => true]]],
]));
$router = new Router();
$router->api = getenv('BIRDSEYE_API');
$consumer = new BirdsEye($router);

$journey = static fn (string $endpoint, string $response): array => [
    'endpoint' => $endpoint,
    'response' => $response,
];
$journeys = [
    'status' => $journey('api/status', $consumer->status()),
    'protocols' => $journey('api/protocols/bgp', $consumer->bgpSummary()),
    'protocol_v4' => $journey('api/protocol/{protocol}', $consumer->bgpNeighbourSummary($v4)),
    'protocol_v6' => $journey('api/protocol/{protocol}', $consumer->bgpNeighbourSummary($v6)),
    'symbols' => $journey('api/symbols', $consumer->symbols()),
    'routes_protocol_v4' => $journey('api/routes/protocol/{protocol}', $consumer->routesForProtocol($v4)),
    'routes_protocol_v6' => $journey('api/routes/protocol/{protocol}', $consumer->routesForProtocol($v6)),
    'routes_table_v4' => $journey('api/routes/table/{table}', $consumer->routesForTable('master4')),
    'routes_table_v6' => $journey('api/routes/table/{table}', $consumer->routesForTable('master6')),
    'routes_export_v4' => $journey('api/routes/export/{protocol}', $consumer->routesForExport($v4)),
    'routes_export_v6' => $journey('api/routes/export/{protocol}', $consumer->routesForExport($v6)),
    'lookup_protocol_exact' => $journey('api/route/{net}/protocol/{protocol}', $consumer->protocolRoute($v4, '203.0.113.0', 24)),
    'lookup_protocol_covering' => $journey('api/route/{net}/protocol/{protocol}', $consumer->protocolRoute($v4, '203.0.113.0', 25)),
    'lookup_protocol_host' => $journey('api/route/{net}/protocol/{protocol}', $consumer->protocolRoute($v4, '203.0.113.1', 32)),
    'lookup_protocol_v6' => $journey('api/route/{net}/protocol/{protocol}', $consumer->protocolRoute($v6, '2001:db8:a::', 48)),
    'lookup_table_exact' => $journey('api/route/{net}/table/{table}', $consumer->protocolTable('master4', '203.0.113.128', 25)),
    'lookup_table_less_specific' => $journey('api/route/{net}/table/{table}', $consumer->protocolTable('master4', '203.0.113.192', 26)),
    'lookup_table_unaligned' => $journey('api/route/{net}/table/{table}', $consumer->protocolTable('master4', '203.0.113.1', 24)),
    'lookup_table_v6' => $journey('api/route/{net}/table/{table}', $consumer->protocolTable('master6', '2001:db8:c::', 48)),
    'lookup_export_exact' => $journey('api/route/{net}/export/{protocol}', $consumer->exportRoute($v4, '192.0.2.0', 24)),
    'lookup_export_covering' => $journey('api/route/{net}/export/{protocol}', $consumer->exportRoute($v4, '192.0.2.0', 25)),
    'lookup_export_v6' => $journey('api/route/{net}/export/{protocol}', $consumer->exportRoute($v6, '2001:db8:c::', 48)),
    'wildcard_daemon' => $journey(
        'api/routes/lc-zwild/protocol/{protocol}/{x}/{y}',
        $consumer->routesProtocolLargeCommunityWildXYRoutes($v4, $filtered['global_admin'], $filtered['function']),
    ),
    'wildcard_foreign' => $journey(
        'api/routes/lc-zwild/protocol/{protocol}/{x}/{y}',
        $consumer->routesProtocolLargeCommunityWildXYRoutes($v4, 64496, 1),
    ),
];

echo json_encode(
    ['ixp_manager_commit' => $manifest['ixp_manager_commit'], 'journeys' => $journeys],
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
) . "\n";
