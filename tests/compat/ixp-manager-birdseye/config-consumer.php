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
$ui = json_decode($render('config-ui-filter.json'), true, 512, JSON_THROW_ON_ERROR);
$filters = $ui['unsupported']['active_ui_filters'];
if ($filters !== [['customer_id' => 2, 'filter_ids' => [31, 33, 35]]]) {
    $fail('seeded applicable UI filters were not surfaced exactly');
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

DB::table('vlaninterface')->where('id', '<>', 3)->update(['rsclient' => 0]);
DB::table('irrdb_asn')->where('customer_id', 3)->where('protocol', 4)
    ->where('asn', '<>', 42)->delete();
DB::table('irrdb_prefix')->where('customer_id', 3)->where('protocol', 4)
    ->where('prefix', '<>', '31.135.128.0/19')->delete();
$first = $render('ixp-manager-v7.4-rustbgpd.json');
$second = (new ConfigurationGenerator($router))->render()->render();
if ($first !== $second) {
    $fail('supported exporter output is nondeterministic');
}
