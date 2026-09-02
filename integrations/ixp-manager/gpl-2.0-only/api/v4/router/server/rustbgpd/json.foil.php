<?php
// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Lance Tuller
// Original rustbgpd integration code. No upstream router template is copied.

use IXP\Models\Aggregators\IrrdbAggregator;
use IXP\Models\Customer;
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

$defaultNoTransit = [
    174, 701, 1299, 2914, 3257, 3320, 3356, 3491, 4134, 5511, 6453, 6461,
    6762, 6830, 7018,
];
$override = config( 'ixp.no_transit_asns.override' );
if( $override === false ) {
    $excluded = array_fill_keys( array_map(
        'intval', (array)config( 'ixp.no_transit_asns.exclude' )
    ), true );
    $noTransit = array_values( array_filter(
        $defaultNoTransit, static fn( $asn ) => !isset( $excluded[$asn] )
    ) );
    $noTransitSource = 'IXP_MANAGER_EFFECTIVE_DEFAULT';
} else {
    $noTransit = array_map( 'intval', $override );
    $noTransitSource = 'IXP_NO_TRANSIT_ASNS_OVERRIDE';
}
$noTransit = array_values( array_unique( $noTransit, SORT_NUMERIC ) );
sort( $noTransit, SORT_NUMERIC );

$clients = [];
$filterRows = [];
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
    foreach( $filters as $filter ) {
        $filterRows[] = $filter;
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
$peerIds = array_values( array_unique( array_map(
    'intval',
    array_filter( array_map( static fn( $filter ) => $filter->peer_id, $filterRows ) )
) ) );
$peers = Customer::whereIn( 'id', $peerIds )->get()->keyBy( 'id' );
$uiFilters = array_map( static function( $filter ) use ( $peers ): array {
    $peerId = $filter->peer_id === null ? null : (int)$filter->peer_id;
    $peer = $peerId === null ? null : $peers->get( $peerId );
    return [
        'id' => (int)$filter->id,
        'customer_id' => (int)$filter->customer_id,
        'peer' => $peerId === null ? null : [
            'customer_id' => $peerId,
            'asn' => $peer === null ? null : (int)$peer->autsys,
        ],
        'received_prefix' => $filter->received_prefix === null
            ? null : (string)$filter->received_prefix,
        'advertised_prefix' => $filter->advertised_prefix === null
            ? null : (string)$filter->advertised_prefix,
        'protocol' => $filter->protocol === null ? null : (int)$filter->protocol,
        'action_advertise' => (string)$filter->action_advertise,
        'action_receive' => (string)$filter->action_receive,
        'order_by' => (int)$filter->order_by,
    ];
}, $filterRows );
usort( $clients, static fn( $a, $b ) => $a['vlan_interface_id'] <=> $b['vlan_interface_id'] );
usort( $uiFilters, static fn( $a, $b ) =>
    [ $a['customer_id'], $a['order_by'], $a['id'] ]
        <=> [ $b['customer_id'], $b['order_by'], $b['id'] ]
);

$types = [
    Router::TYPE_ROUTE_SERVER => 'route-server',
    Router::TYPE_ROUTE_COLLECTOR => 'collector',
    Router::TYPE_AS112 => 'as112',
];
$document = [
    'schema' => 'rustbgpd.ixp-manager.router-config/v2',
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
    'ui_filters' => $uiFilters,
    'unsupported' => [
        'active_ui_filters' => [],
        'route_server_skin_files' => $skinFiles,
    ],
    'complete' => [
        'handle' => (string)$router->handle,
        'client_count' => count( $clients ),
        'ui_filter_count' => count( $uiFilters ),
        'marker' => 'END_OF_RUSTBGPD_IXP_MANAGER_CONFIG_' . $router->handle,
    ],
];
echo json_encode( $document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR );
echo "\n";
