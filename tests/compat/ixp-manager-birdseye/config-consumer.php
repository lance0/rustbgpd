<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;
use IXP\Models\Router;
use IXP\Tasks\Router\ConfigurationGenerator;

$ixp = getenv('IXP_MANAGER_ROOT');
require $ixp . '/vendor/autoload.php';
$app = require $ixp . '/bootstrap/app.php';
require_once $ixp . '/version.php';
$app->make(Kernel::class)->bootstrap();

$output = rtrim((string)getenv('CAPTURE_OUTPUT'), '/');
$router = Router::whereHandle('b2-rs1-lan1-ipv4')->firstOrFail();
$router->template = 'api/v4/router/server/rustbgpd/json';
$fail = static function (string $message): never {
    fwrite(STDERR, $message . "\n");
    exit(1);
};

$render = static function (string $name) use ($router, $output): string {
    $json = (new ConfigurationGenerator($router))->render()->render();
    json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    $path = $output . '/' . $name;
    file_put_contents($path, $json, LOCK_EX);
    chmod($path, 0600);
    return $json;
};

config(['ixp.no_transit_asns.override' => false]);
$render('config-implicit.json');
config(['ixp.no_transit_asns.override' => []]);
DB::table('route_server_filters_prod')->where('id', 32)->update([
    'peer_id' => null, 'vlan_id' => 1, 'received_prefix' => null,
    'advertised_prefix' => null, 'protocol' => 4, 'action_advertise' => 'AS_IS',
    'action_receive' => 'PREPEND_ONCE', 'order_by' => 3,
]);
DB::table('route_server_filters_prod')->update(['enabled' => 0]);
$router->template = 'api/v4/router/server/bird2/standard';
$birdBaseline = (new ConfigurationGenerator($router))->render()->render();
DB::table('route_server_filters_prod')->whereIn('id', [32, 33])->update(['enabled' => 1]);
$birdCandidate = (new ConfigurationGenerator($router))->render()->render();
$prepend = 'bgp_path.prepend( bgp_path.first );';
$peerGuard = 'if ( bgp_path.first =';
$global = "    # PREPEND_ONCE\n    bgp_path.prepend( bgp_path.first );\n";
$specific = "    if ( bgp_path.first = 112 ) then {\n"
    . "        if ( net = 192.175.48.0/24 ) then {\n"
    . "            # PREPEND_TWICE\n"
    . "            bgp_path.prepend( bgp_path.first );\n"
    . "            bgp_path.prepend( bgp_path.first );\n"
    . "        }\n    }\n";
$globalPosition = strpos($birdCandidate, $global);
$specificPosition = strpos($birdCandidate, $specific);
if (substr_count($birdCandidate, $prepend) - substr_count($birdBaseline, $prepend) !== 3
    || substr_count($birdCandidate, $peerGuard) - substr_count($birdBaseline, $peerGuard) !== 1
    || str_contains($birdBaseline, $global) || str_contains($birdBaseline, $specific)
    || $globalPosition === false || $specificPosition === false
    || $globalPosition >= $specificPosition) {
    $fail('pinned BIRD overlapping PREPEND order drifted');
}
unset(
    $birdBaseline,
    $birdCandidate,
    $global,
    $specific,
    $globalPosition,
    $specificPosition,
    $prepend,
    $peerGuard,
);
$router->template = 'api/v4/router/server/rustbgpd/json';
DB::table('vlaninterface')->whereNotIn('id', [1, 4])->update(['rsclient' => 0]);
DB::table('irrdb_asn')->where('customer_id', 2)->where('protocol', 4)
    ->where('asn', '<>', 1213)->delete();
DB::table('irrdb_prefix')->where('customer_id', 2)->where('protocol', 4)
    ->where('prefix', '<>', '77.72.72.0/21')->delete();
DB::table('route_server_filters_prod')->whereNotIn('id', [31, 33, 35])
    ->update(['enabled' => 0]);
DB::table('route_server_filters_prod')->whereIn('id', [31, 33, 35])
    ->update(['enabled' => 1]);
$ui = json_decode($render('config-ui-filter.json'), true, 512, JSON_THROW_ON_ERROR);
$filters = $ui['ui_filters'];
if (array_column($filters, 'id') !== [31, 33, 35]
    || array_column($filters, 'order_by') !== [2, 4, 6]
    || $filters[1]['peer'] !== ['customer_id' => 4, 'asn' => 112]
    || $filters[1]['received_prefix'] !== '192.175.48.0/24'
    || $filters[1]['advertised_prefix'] !== '77.72.72.0/21') {
    $fail('seeded ordered UI-filter rows were not exported exactly');
}

DB::table('route_server_filters_prod')->where('id', 31)->update(['enabled' => 0]);
DB::table('route_server_filters_prod')->where('id', 32)->update(['enabled' => 1]);
$supportedRaw = $render('ixp-manager-v7.4-rustbgpd.json');
$supported = json_decode($supportedRaw, true, 512, JSON_THROW_ON_ERROR);
if (array_column($supported['ui_filters'], 'id') !== [32, 33, 35]
    || array_column($supported['ui_filters'], 'action_receive')
        !== ['PREPEND_ONCE', 'PREPEND_TWICE', 'AS_IS']
    || $supported['ui_filters'][0]['peer'] !== null
    || $supported['ui_filters'][0]['received_prefix'] !== null) {
    $fail('row-31-disabled ordered UI-filter export drifted');
}
$second = (new ConfigurationGenerator($router))->render()->render();
if ($supportedRaw !== $second) {
    $fail('supported exporter output is nondeterministic');
}

DB::table('route_server_filters_prod')->update(['enabled' => 0]);
$skin = $ixp . '/resources/skins/' . getenv('VIEW_SKIN')
    . '/api/v4/router/server/bird2/contract.foil.php';
if (!is_dir(dirname($skin))) {
    mkdir(dirname($skin), 0700, true);
}
file_put_contents($skin, "<?php // contract-only override\n");
$skinned = json_decode($render('config-skin.json'), true, 512, JSON_THROW_ON_ERROR);
unlink($skin);
if ($skinned['unsupported']['route_server_skin_files'] !== [
    'api/v4/router/server/bird2/contract.foil.php',
]) {
    $fail('active BIRD skin file was not surfaced');
}
