<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Http\Request;
use IXP\Http\Controllers\Api\V4\NagiosController;
use IXP\Models\Router;
use IXP\Models\Vlan;

$ixp = getenv('IXP_MANAGER_ROOT');
require $ixp . '/vendor/autoload.php';
$app = require $ixp . '/bootstrap/app.php';
require_once $ixp . '/version.php';
$app->make(Kernel::class)->bootstrap();
// The console bootstrap renders uncaught exceptions to stdout and exits 0;
// the gate must go red instead.
set_exception_handler(static function (Throwable $exception): never {
    fwrite(STDERR, $exception . "\n");
    exit(1);
});

$manifest = json_decode(
    file_get_contents(__DIR__ . '/contract.json'),
    true,
    512,
    JSON_THROW_ON_ERROR,
);
$handle = $manifest['manual_config_export']['router_handle'] ?? null;
if ($handle !== 'b2-rs1-lan1-ipv4' || ($manifest['nagios_monitoring'] ?? null) !== [
    'router_filter' => 'api_type = Birdseye',
    'generators' => ['birdseye-daemons', 'birdseye-bgp-sessions'],
    'daemon_check' => 'nagios-check-birdseye.php',
    'session_protocol' => 'pb_{vlan_interface_id:04}_as{asn}',
]) {
    throw new RuntimeException('Nagios monitoring contract drifted');
}
$api = getenv('BIRDSEYE_API');
$plugin = getenv('BIRDSEYE_ROOT') . '/bin/nagios-check-birdseye.php';
if (!is_string($api) || $api === '' || !is_file($plugin)) {
    throw new RuntimeException('BIRDSEYE_API and the pinned Bird\'s Eye checkout are required');
}
$fail = static function (string $message, string ...$raw): never {
    fwrite(STDERR, $message . "\n");
    foreach ($raw as $dump) {
        fwrite(STDERR, "--- raw output ---\n" . $dump . "\n");
    }
    exit(1);
};

// The pinned CI fixture ships this router as api_type None with no API URL,
// exactly the row shape both generators silently exclude.
$router = Router::whereHandle($handle)->firstOrFail();
$router->api_type = Router::API_TYPE_BIRDSEYE;
$router->api = $api;
$router->save();
$vlan = Vlan::findOrFail($router->vlan_id);
$controller = new NagiosController();

$daemons = $controller->birdseyeDaemons(Request::create('/'), 'default', $vlan);
$daemonConfig = $daemons->getContent();
if ($daemons->getStatusCode() !== 200
    || !str_starts_with((string) $daemons->headers->get('Content-Type'), 'text/plain')) {
    $fail('birdseye-daemons generator did not return text/plain 200', $daemonConfig);
}
if (!preg_match(
    "/^define host\s+\{\n\s+use\s+ixp-manager-host-birdseye-daemon\n\s+host_name\s+bird-$handle\n"
    . "\s+alias\s+(?<alias>.+)\n\s+address\s+(?<address>\S+)\n\s+_apiurl\s+(?<apiurl>\S+)\n\}$/m",
    $daemonConfig,
    $host,
)) {
    $fail("birdseye-daemons generator omitted router $handle", $daemonConfig);
}
if ($host['apiurl'] !== $api || $host['alias'] !== $router->name || $host['address'] !== $router->mgmt_host) {
    $fail("birdseye-daemons host bird-$handle does not describe the live router", $daemonConfig);
}
if (!preg_match(
    "/^define service\s+\{\n\s+use\s+ixp-manager-service-birdseye-daemon\n\s+host_name\s+bird-$handle\n\}$/m",
    $daemonConfig,
)) {
    $fail("birdseye-daemons generator emitted no service for bird-$handle", $daemonConfig);
}
if (!preg_match('/^define hostgroup \{\n\s+hostgroup_name\s+bird-daemons-vlanid-' . $vlan->id . "\n.*?members\s+(?<members>.*?)\n\}/ms", $daemonConfig, $group)
    || !in_array("bird-$handle", preg_split('/,\s*\\\\?\s*/', $group['members']), true)) {
    $fail("birdseye-daemons hostgroup omitted bird-$handle", $daemonConfig);
}

$sessions = $controller->birdseyeBgpSessions(Request::create('/'), $vlan, (int) $router->protocol, (int) $router->type);
$sessionConfig = $sessions->getContent();
if ($sessions->getStatusCode() !== 200
    || !str_starts_with((string) $sessions->headers->get('Content-Type'), 'text/plain')) {
    $fail('birdseye-bgp-sessions generator did not return text/plain 200', $sessionConfig);
}
preg_match_all(
    "/^define service\s+\{\n\s+use\s+ixp-manager-member-bgp-session-service\n\s+host_name\s+(?<host>\S+)\n"
    . "\s+service_description\s+BGP session to $handle\n\s+_api_url\s+(?<apiurl>\S+)\n\s+_protocol\s+(?<protocol>\S+)\n\}$/m",
    $sessionConfig,
    $services,
    PREG_SET_ORDER,
);
$protocols = array_column($services, 'protocol');
sort($protocols);
if ($protocols !== ['pb_0001_as1213', 'pb_0004_as112']) {
    $fail("birdseye-bgp-sessions generator did not emit both route-server client sessions for $handle", $sessionConfig);
}
foreach ($services as $service) {
    if ($service['apiurl'] !== $api) {
        $fail("birdseye-bgp-sessions service {$service['host']} does not point at the live adapter", $sessionConfig);
    }
}
if (!str_contains($sessionConfig, "hostgroup_name  birdseye-rs-bgp-sessions-vlanid-{$vlan->id}-ipv{$router->protocol}-$handle\n")) {
    $fail("birdseye-bgp-sessions generator emitted no per-router hostgroup for $handle", $sessionConfig);
}

// Drive the pinned Bird's Eye daemon plugin exactly as Nagios would: with the
// _apiurl the generator emitted, not the URL this script configured.
exec(
    'php ' . escapeshellarg($plugin) . ' -a ' . escapeshellarg($host['apiurl']) . ' 2>&1',
    $pluginLines,
    $pluginStatus,
);
$pluginOutput = implode("\n", $pluginLines);
if ($pluginStatus !== 0 || !preg_match(
    "/^OK: Bird (?<daemon>rustbgpd \S+)\. Bird's Eye (?<api>rustbgpd \S+)\. Router ID (?<router_id>\S+)\. "
    . "Uptime: \d+ days\. Last Reconfigure: (?<last_reconfig>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\."
    . "(?<up>\d+) BGP sessions up of (?<total>\d+)\.$/",
    $pluginOutput,
    $check,
)) {
    $fail("pinned nagios-check-birdseye.php did not report OK (exit $pluginStatus)", $pluginOutput, $daemonConfig);
}
if ($check['up'] !== '0' || $check['total'] !== '1') {
    $fail('daemon check did not count the one configured, down session', $pluginOutput);
}

echo json_encode([
    'daemon_host' => $host[0],
    'session_protocols' => $protocols,
    'daemon_check' => $pluginOutput,
    'last_reconfig' => $check['last_reconfig'],
], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT) . "\n";
