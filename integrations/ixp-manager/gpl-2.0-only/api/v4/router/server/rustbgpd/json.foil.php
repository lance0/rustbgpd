<?php
// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Lance McKee
// Original rustbgpd integration code. No upstream router template is copied.

use IXP\Models\Aggregators\IrrdbAggregator;
use IXP\Models\RouteServerFilterProd;
use IXP\Models\Router;

$router = $t->router;
$protocol = (int)$router->protocol;
$ipSort = static function( array &$values ): void {
    usort( $values, static function( $left, $right ): int {
        [ $leftIp, $leftMask ] = array_pad( explode( '/', (string)$left, 2 ), 2, '0' );
        [ $rightIp, $rightMask ] = array_pad( explode( '/', (string)$right, 2 ), 2, '0' );
        return strcmp( (string)inet_pton( $leftIp ), (string)inet_pton( $rightIp ) )
            ?: ( (int)$leftMask <=> (int)$rightMask );
    } );
};

$skinFiles = [];
$skin = (string)env( 'VIEW_SKIN', '' );
if( $skin !== '' ) {
    $skinRoot = base_path( 'resources/skins/' . $skin );
    foreach( [ 'bird', 'bird2', 'bird2-2025' ] as $tree ) {
        $root = $skinRoot . '/api/v4/router/server/' . $tree;
        if( !is_dir( $root ) ) {
            continue;
        }
        $walk = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS )
        );
        foreach( $walk as $file ) {
            if( $file->isFile() ) {
                $skinFiles[] = substr( $file->getPathname(), strlen( $skinRoot ) + 1 );
            }
        }
    }
}
sort( $skinFiles, SORT_STRING );

$caches = [];
if( (bool)$router->rpki ) {
    foreach( [ 1, 2 ] as $number ) {
        $host = config( "ixp.rpki.rtr{$number}.host" );
        $port = config( "ixp.rpki.rtr{$number}.port" );
        if( $host ) {
            $host = filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 )
                ? '[' . $host . ']' : $host;
            $caches[] = $host . ':' . (int)$port;
        }
    }
}
sort( $caches, SORT_STRING );

$override = config( 'ixp.no_transit_asns.override' );
$noTransitSource = $override === false
    ? 'IXP_MANAGER_IMPLICIT_DEFAULT' : 'IXP_NO_TRANSIT_ASNS_OVERRIDE';
$noTransit = $override === false ? [] : array_map( 'intval', $override );
sort( $noTransit, SORT_NUMERIC );

$clients = [];
$activeFilters = [];
foreach( $t->ints as $int ) {
    if( (int)$int['autsys'] === (int)$router->asn ) {
        continue;
    }
    $customer = (int)$int['cid'];
    $filters = RouteServerFilterProd::whereCustomerId( $customer )
        ->where( 'enabled', 1 )
        ->where( static function( $query ) use ( $int ): void {
            $query->whereNull( 'vlan_id' )->orWhere( 'vlan_id', $int['vlanid'] );
        } )
        ->where( static function( $query ) use ( $router ): void {
            $query->whereNull( 'protocol' )->orWhere( 'protocol', $router->protocol );
        } )
        ->orderBy( 'order_by' )->get();
    if( $filters->isNotEmpty() ) {
        $ids = array_map( 'intval', $filters->pluck( 'id' )->all() );
        sort( $ids, SORT_NUMERIC );
        $activeFilters[] = [ 'customer_id' => $customer, 'filter_ids' => $ids ];
    }

    $origins = array_map( 'intval', IrrdbAggregator::asnsForRouterConfiguration(
        $customer, $protocol, true
    ) );
    sort( $origins, SORT_NUMERIC );
    $prefixes = array_values( IrrdbAggregator::prefixesForRouterConfiguration(
        $customer, $protocol, true
    ) );
    $ipSort( $prefixes );
    $peeringIps = array_values( $int['allpeeringips'] );
    $ipSort( $peeringIps );

    $secret = $int['bgpmd5secret'];
    $auth = (bool)$router->skip_md5 || !$secret
        ? [ 'type' => 'none' ]
        : [ 'type' => 'md5', 'value' => (string)$secret ];
    $clients[] = [
        'customer_id' => $customer,
        'vlan_interface_id' => (int)$int['vliid'],
        'name' => (string)$int['cname'],
        'asn' => (int)$int['autsys'],
        'address' => (string)$int['address'],
        'peering_ips' => $peeringIps,
        'max_prefix' => (int)$int['maxprefixes'],
        'auth' => $auth,
        'irr_filter' => (bool)$int['irrdbfilter'],
        'more_specifics' => (bool)$int['rsmorespecifics'],
        'origins' => $origins,
        'prefixes' => $prefixes,
    ];
}
usort( $clients, static fn( $a, $b ) => $a['vlan_interface_id'] <=> $b['vlan_interface_id'] );
usort( $activeFilters, static fn( $a, $b ) => $a['customer_id'] <=> $b['customer_id'] );

$types = [
    Router::TYPE_ROUTE_SERVER => 'route-server',
    Router::TYPE_ROUTE_COLLECTOR => 'collector',
    Router::TYPE_AS112 => 'as112',
];
$document = [
    'schema' => 'rustbgpd.ixp-manager.router-config/v1',
    'ixp_manager' => [ 'version' => APPLICATION_VERSION ],
    'router' => [
        'handle' => (string)$router->handle,
        'type' => $types[$router->type] ?? 'other',
        'protocol' => $protocol,
        'asn' => (int)$router->asn,
        'router_id' => (string)$router->router_id,
        'peering_ip' => (string)$router->peering_ip,
        'vlan_id' => (int)$router->vlan_id,
        'quarantine' => (bool)$router->quarantine,
        'bgp_lc' => (bool)$router->bgp_lc,
        'rfc1997_passthru' => (bool)$router->rfc1997_passthru,
        'rpki' => (bool)$router->rpki,
        'skip_md5' => (bool)$router->skip_md5,
    ],
    'policy' => [
        'minimum_prefix_length' => (int)config(
            'ixp.irrdb.min_v' . $protocol . '_subnet_size'
        ),
        'rtr_caches' => $caches,
        'no_transit' => [ 'source' => $noTransitSource, 'asns' => $noTransit ],
    ],
    'clients' => $clients,
    'unsupported' => [
        'active_ui_filters' => $activeFilters,
        'route_server_skin_files' => $skinFiles,
    ],
    'complete' => [
        'handle' => (string)$router->handle,
        'client_count' => count( $clients ),
        'marker' => 'END_OF_RUSTBGPD_IXP_MANAGER_CONFIG_' . $router->handle,
    ],
];
echo json_encode( $document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR );
echo "\n";
