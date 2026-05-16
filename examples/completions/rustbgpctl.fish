# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_rustbgpctl_global_optspecs
	string join \n s/addr= token-file= j/json no-color h/help V/version
end

function __fish_rustbgpctl_needs_command
	# Figure out if the current invocation already has a command.
	set -l cmd (commandline -opc)
	set -e cmd[1]
	argparse -s (__fish_rustbgpctl_global_optspecs) -- $cmd 2>/dev/null
	or return
	if set -q argv[1]
		# Also print the command, so this can be used to figure out what it is.
		echo $argv[1]
		return 1
	end
	return 0
end

function __fish_rustbgpctl_using_subcommand
	set -l cmd (__fish_rustbgpctl_needs_command)
	test -z "$cmd"
	and return 1
	contains -- $cmd[1] $argv
end

complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -s V -l version -d 'Print version'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "global" -d 'Show daemon global configuration'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "neighbor" -d 'Manage BGP neighbors'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "rib" -d 'Query and manage the RIB'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "flowspec" -d 'Manage FlowSpec routes'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "evpn" -d 'Manage EVPN routes (list, add, delete — RFC 7432)'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "watch" -d 'Watch route updates (streaming)'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "events" -d 'Show recent route update events'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "health" -d 'Check daemon health'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "metrics" -d 'Show Prometheus metrics'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "shutdown" -d 'Request daemon shutdown'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "mrt-dump" -d 'Trigger an on-demand MRT dump'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "gshut" -d 'Toggle the RFC 8326 GRACEFUL_SHUTDOWN community on outbound updates for one peer (`--peer X`) or every currently-managed peer (omit `--peer`). Receivers that honor RFC 8326 will set local_pref = 0 on tagged paths, draining traffic ahead of planned maintenance'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "top" -d 'Live TUI dashboard'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "policy" -d 'Manage named `[[policy_definitions]]` entries and the global / per-neighbor import/export chains. Backed by PolicyService'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "neighbor-set" -d 'Manage named `[[neighbor_sets]]` entries used by policy `match_neighbor_set`. Backed by PolicyService'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "peer-group" -d 'Manage named `[[peer_groups]]` entries and bind/unbind neighbors to them. Backed by PeerGroupService'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "completions" -d 'Generate shell completions'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand global" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand global" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand global" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand global" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand global" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "add" -d 'Add a new neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "delete" -d 'Delete this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "enable" -d 'Enable this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "disable" -d 'Disable this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "softreset" -d 'Trigger soft reset (inbound)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l asn -d 'Remote AS number' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l description -d 'Description' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l hold-time -d 'Hold time in seconds' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l max-prefixes -d 'Max prefix limit' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l families -d 'Address families (comma-separated)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l add-path-send-max -d 'Max paths per prefix for Add-Path send' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l route-server-client -d 'Enable transparent route-server client mode (eBGP only)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l add-path-receive -d 'Enable Add-Path receive'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l add-path-send -d 'Enable Add-Path send'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -l reason -d 'Disable reason' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -s a -l family -d 'Address family to refresh' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "add" -d 'Add a new neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "enable" -d 'Enable this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "disable" -d 'Disable this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "softreset" -d 'Trigger soft reset (inbound)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -s a -l family -d 'Address family filter (ipv4_unicast, ipv6_unicast)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -s p -l prefix -d 'Prefix filter (e.g., 10.0.0.0/24)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -l explain-peer -d 'Scope --explain to a specific peer\'s Add-Path send view. When set, candidates are filtered by the peer\'s export policy + sendable families and the top `add_path_send_max` are tagged with their advertised rank. Omit for the global Loc-RIB view' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -l origin-asn -d 'Filter by origin ASN (last ASN in AS_PATH)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -s c -l community -d 'Filter by community (e.g., 65001:100 or BLACKHOLE); may be repeated' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -l large-community -d 'Filter by large community (e.g., 65001:100:200); may be repeated' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -s l -l longer -d 'Show longer (more specific) prefixes matching --prefix'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -l explain -d 'Show why the best route was selected (requires --prefix)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -f -a "received" -d 'Show received routes from a neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -f -a "advertised" -d 'Show advertised routes to a neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -f -a "blackholes" -d 'Show RFC 7999 BLACKHOLE discard install status'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -f -a "fib" -d 'Show ADR-0061 general FIB route install status'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -f -a "add" -d 'Inject a route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -f -a "delete" -d 'Withdraw a route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised blackholes fib add delete help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from received" -s a -l family -d 'Address family filter' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from received" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from received" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from received" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from received" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from received" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from advertised" -s a -l family -d 'Address family filter' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from advertised" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from advertised" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from advertised" -l explain -d 'Explain whether this exact prefix would be advertised to the peer'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from advertised" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from advertised" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from advertised" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from blackholes" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from blackholes" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from blackholes" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from blackholes" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from blackholes" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from fib" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from fib" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from fib" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from fib" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from fib" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l nexthop -d 'Next hop address' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l origin -d 'Origin (0=igp, 1=egp, 2=incomplete)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l local-pref -d 'Local preference' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l med -d 'MED' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l as-path -d 'AS path (space-separated)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l communities -d 'Communities (e.g., 65001:100 or BLACKHOLE)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l large-communities -d 'Large communities (e.g., 65001:100:200)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l path-id -d 'Path ID for Add-Path' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from delete" -l path-id -d 'Path ID for Add-Path' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "received" -d 'Show received routes from a neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "advertised" -d 'Show advertised routes to a neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "blackholes" -d 'Show RFC 7999 BLACKHOLE discard install status'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "fib" -d 'Show ADR-0061 general FIB route install status'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "add" -d 'Inject a route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Withdraw a route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -s a -l family -d 'Address family (ipv4_flowspec, ipv6_flowspec)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -f -a "add" -d 'Add a FlowSpec rule'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -f -a "delete" -d 'Delete a FlowSpec rule'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -s a -l family -d 'Address family (required: ipv4_flowspec or ipv6_flowspec)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -l match -d 'Match components (e.g., dest=10.0.0.0/24 port==80)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -l action -d 'Actions (e.g., drop, rate=1000, redirect=65001:100)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -s a -l family -d 'Address family (required: ipv4_flowspec or ipv6_flowspec)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -l match -d 'Match components identifying the rule' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from help" -f -a "add" -d 'Add a FlowSpec rule'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a FlowSpec rule'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -l route-type -d 'Route type filter (1..=5) — applies when no subcommand is given' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -l peer -d 'Peer IP address filter (list mode only)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -l rd -d 'Route Distinguisher filter (list mode only), e.g. "65000:100"' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -f -a "list" -d 'List EVPN routes (default action — same as omitting the subcommand)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -f -a "add-mac-ip" -d 'Inject a Type 2 MAC/IP route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -f -a "add-imet" -d 'Inject a Type 3 IMET route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -f -a "delete-mac-ip" -d 'Withdraw a Type 2 MAC/IP route by its key fields'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -f -a "delete-imet" -d 'Withdraw a Type 3 IMET route by its key fields'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -f -a "instances" -d 'List local EVPN instances configured on this VTEP. Empty when the daemon is acting purely as an EVPN route reflector'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -f -a "nexthops" -d 'List rustbgpd-owned FDB nexthop groups (ADR-0059 aliasing ECMP)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -f -a "vrfs" -d 'List configured IP-VRFs (Gate 9, ADR-0058) and their readiness verdict from the most recent reconcile pass'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -f -a "diagnose" -d 'Summarize EVPN VTEP alpha state and key metrics'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from list" -l route-type -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from list" -l peer -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from list" -l rd -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from list" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from list" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from list" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from list" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l rd -d 'Route Distinguisher, "asn:value" / "ip:value"' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l ethernet-tag -d 'Ethernet-tag identifying the EVI (default 0)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l mac -d 'MAC address "aa:bb:cc:dd:ee:ff"' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l ip -d 'Host IP (optional — MAC-only route if omitted)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l label -d 'VNI for this EVI (required)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l label2 -d 'Optional second label for RFC 9135 symmetric IRB' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l next-hop -d 'VTEP loopback IP (next-hop)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l rt -d 'Optional route targets, each "asn:value"' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l no-vxlan-encap -d 'Disable the RFC 8365 VXLAN encapsulation ext community'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l rd -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l ethernet-tag -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l ip -d 'Originator IP (required for Type 3)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l next-hop -d 'VTEP loopback IP (next-hop)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l rt -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l no-vxlan-encap
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -l rd -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -l ethernet-tag -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -l mac -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -l ip -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -l rd -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -l ethernet-tag -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -l ip -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from instances" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from instances" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from instances" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from instances" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from instances" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from nexthops" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from nexthops" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from nexthops" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from nexthops" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from nexthops" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from vrfs" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from vrfs" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from vrfs" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from vrfs" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from vrfs" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from diagnose" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from diagnose" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from diagnose" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from diagnose" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from diagnose" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "list" -d 'List EVPN routes (default action — same as omitting the subcommand)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "add-mac-ip" -d 'Inject a Type 2 MAC/IP route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "add-imet" -d 'Inject a Type 3 IMET route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "delete-mac-ip" -d 'Withdraw a Type 2 MAC/IP route by its key fields'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "delete-imet" -d 'Withdraw a Type 3 IMET route by its key fields'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "instances" -d 'List local EVPN instances configured on this VTEP. Empty when the daemon is acting purely as an EVPN route reflector'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "nexthops" -d 'List rustbgpd-owned FDB nexthop groups (ADR-0059 aliasing ECMP)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "vrfs" -d 'List configured IP-VRFs (Gate 9, ADR-0058) and their readiness verdict from the most recent reconcile pass'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "diagnose" -d 'Summarize EVPN VTEP alpha state and key metrics'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand watch" -s a -l family -d 'Address family filter' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand watch" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand watch" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand watch" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand watch" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand watch" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and not __fish_seen_subcommand_from watch help" -l address -d 'Neighbor address filter' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and not __fish_seen_subcommand_from watch help" -s a -l family -d 'Address family filter' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and not __fish_seen_subcommand_from watch help" -l prefix -d 'Exact prefix filter, e.g. 203.0.113.0/24' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and not __fish_seen_subcommand_from watch help" -s l -l limit -d 'Maximum recent events to return' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and not __fish_seen_subcommand_from watch help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and not __fish_seen_subcommand_from watch help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and not __fish_seen_subcommand_from watch help" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and not __fish_seen_subcommand_from watch help" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and not __fish_seen_subcommand_from watch help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and not __fish_seen_subcommand_from watch help" -f -a "watch" -d 'Watch the unified live event stream'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and not __fish_seen_subcommand_from watch help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and __fish_seen_subcommand_from watch" -l address -d 'Neighbor address filter' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and __fish_seen_subcommand_from watch" -s a -l family -d 'Address family filter' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and __fish_seen_subcommand_from watch" -l prefix -d 'Exact prefix filter, e.g. 203.0.113.0/24' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and __fish_seen_subcommand_from watch" -l type -d 'Event type filter: added, withdrawn, best_changed' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and __fish_seen_subcommand_from watch" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and __fish_seen_subcommand_from watch" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and __fish_seen_subcommand_from watch" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and __fish_seen_subcommand_from watch" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and __fish_seen_subcommand_from watch" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and __fish_seen_subcommand_from help" -f -a "watch" -d 'Watch the unified live event stream'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand events; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand health" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand health" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand health" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand health" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand health" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand metrics" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand metrics" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand metrics" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand metrics" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand metrics" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand shutdown" -l reason -d 'Shutdown reason' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand shutdown" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand shutdown" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand shutdown" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand shutdown" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand shutdown" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand mrt-dump" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand mrt-dump" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand mrt-dump" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand mrt-dump" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand mrt-dump" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand gshut" -l peer -d 'Peer address; omit to toggle for all peers' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand gshut" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand gshut" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand gshut" -l clear -d 'Clear instead of enabling'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand gshut" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand gshut" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand gshut" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand top" -s i -l interval -d 'Poll interval in seconds (1-60)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand top" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand top" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand top" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand top" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand top" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and not __fish_seen_subcommand_from list get set delete chain help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and not __fish_seen_subcommand_from list get set delete chain help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and not __fish_seen_subcommand_from list get set delete chain help" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and not __fish_seen_subcommand_from list get set delete chain help" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and not __fish_seen_subcommand_from list get set delete chain help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and not __fish_seen_subcommand_from list get set delete chain help" -f -a "list" -d 'List configured policies (names + statement counts)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and not __fish_seen_subcommand_from list get set delete chain help" -f -a "get" -d 'Show one policy by name'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and not __fish_seen_subcommand_from list get set delete chain help" -f -a "set" -d 'Set (create or replace) a policy from a JSON file'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and not __fish_seen_subcommand_from list get set delete chain help" -f -a "delete" -d 'Delete a policy by name'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and not __fish_seen_subcommand_from list get set delete chain help" -f -a "chain" -d 'Manage global / per-neighbor import/export chains'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and not __fish_seen_subcommand_from list get set delete chain help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from list" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from list" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from list" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from list" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from get" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from get" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from get" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from get" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from get" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from set" -l from-file -d 'JSON file containing the PolicyDefinition shape' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from set" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from set" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from set" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from set" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from set" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from chain" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from chain" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from chain" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from chain" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from chain" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from chain" -f -a "show" -d 'Show the global chains, or the per-neighbor chains when `--neighbor` is given'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from chain" -f -a "set-import" -d 'Replace the import chain. Empty list is rejected — use `clear-import` instead. Apply globally by omitting `--neighbor`'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from chain" -f -a "set-export" -d 'Replace the export chain'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from chain" -f -a "clear-import" -d 'Clear the import chain entirely'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from chain" -f -a "clear-export" -d 'Clear the export chain entirely'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from chain" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "list" -d 'List configured policies (names + statement counts)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "get" -d 'Show one policy by name'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "set" -d 'Set (create or replace) a policy from a JSON file'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a policy by name'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "chain" -d 'Manage global / per-neighbor import/export chains'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -f -a "list" -d 'List configured neighbor sets'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -f -a "get" -d 'Show one neighbor set by name'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -f -a "set" -d 'Set (create or replace) a neighbor set from a JSON file'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -f -a "delete" -d 'Delete a neighbor set'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from list" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from list" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from list" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from list" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from get" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from get" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from get" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from get" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from get" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from set" -l from-file -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from set" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from set" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from set" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from set" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from set" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from help" -f -a "list" -d 'List configured neighbor sets'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from help" -f -a "get" -d 'Show one neighbor set by name'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from help" -f -a "set" -d 'Set (create or replace) a neighbor set from a JSON file'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a neighbor set'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor-set; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "list" -d 'List configured peer groups'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "get" -d 'Show one peer group by name'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "set" -d 'Set (create or replace) a peer group from a JSON file'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "delete" -d 'Delete a peer group'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "attach" -d 'Bind a neighbor to a peer group'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "detach" -d 'Unbind a neighbor from its peer group'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from list" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from list" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from list" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from list" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from get" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from get" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from get" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from get" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from get" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from set" -l from-file -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from set" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from set" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from set" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from set" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from set" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from attach" -l group -d 'Peer-group name' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from attach" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from attach" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from attach" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from attach" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from attach" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from detach" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from detach" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from detach" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from detach" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from detach" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "list" -d 'List configured peer groups'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "get" -d 'Show one peer group by name'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "set" -d 'Set (create or replace) a peer group from a JSON file'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a peer group'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "attach" -d 'Bind a neighbor to a peer group'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "detach" -d 'Unbind a neighbor from its peer group'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand completions" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand completions" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand completions" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand completions" -l no-color -d 'Disable colored output'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand completions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "global" -d 'Show daemon global configuration'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "neighbor" -d 'Manage BGP neighbors'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "rib" -d 'Query and manage the RIB'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "flowspec" -d 'Manage FlowSpec routes'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "evpn" -d 'Manage EVPN routes (list, add, delete — RFC 7432)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "watch" -d 'Watch route updates (streaming)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "events" -d 'Show recent route update events'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "health" -d 'Check daemon health'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "metrics" -d 'Show Prometheus metrics'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "shutdown" -d 'Request daemon shutdown'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "mrt-dump" -d 'Trigger an on-demand MRT dump'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "gshut" -d 'Toggle the RFC 8326 GRACEFUL_SHUTDOWN community on outbound updates for one peer (`--peer X`) or every currently-managed peer (omit `--peer`). Receivers that honor RFC 8326 will set local_pref = 0 on tagged paths, draining traffic ahead of planned maintenance'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "top" -d 'Live TUI dashboard'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "policy" -d 'Manage named `[[policy_definitions]]` entries and the global / per-neighbor import/export chains. Backed by PolicyService'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "neighbor-set" -d 'Manage named `[[neighbor_sets]]` entries used by policy `match_neighbor_set`. Backed by PolicyService'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "peer-group" -d 'Manage named `[[peer_groups]]` entries and bind/unbind neighbors to them. Backed by PeerGroupService'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "completions" -d 'Generate shell completions'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec evpn watch events health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "add" -d 'Add a new neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "delete" -d 'Delete this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "enable" -d 'Enable this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "disable" -d 'Disable this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "softreset" -d 'Trigger soft reset (inbound)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "received" -d 'Show received routes from a neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "advertised" -d 'Show advertised routes to a neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "blackholes" -d 'Show RFC 7999 BLACKHOLE discard install status'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "fib" -d 'Show ADR-0061 general FIB route install status'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "add" -d 'Inject a route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "delete" -d 'Withdraw a route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from flowspec" -f -a "add" -d 'Add a FlowSpec rule'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from flowspec" -f -a "delete" -d 'Delete a FlowSpec rule'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "list" -d 'List EVPN routes (default action — same as omitting the subcommand)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "add-mac-ip" -d 'Inject a Type 2 MAC/IP route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "add-imet" -d 'Inject a Type 3 IMET route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "delete-mac-ip" -d 'Withdraw a Type 2 MAC/IP route by its key fields'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "delete-imet" -d 'Withdraw a Type 3 IMET route by its key fields'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "instances" -d 'List local EVPN instances configured on this VTEP. Empty when the daemon is acting purely as an EVPN route reflector'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "nexthops" -d 'List rustbgpd-owned FDB nexthop groups (ADR-0059 aliasing ECMP)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "vrfs" -d 'List configured IP-VRFs (Gate 9, ADR-0058) and their readiness verdict from the most recent reconcile pass'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "diagnose" -d 'Summarize EVPN VTEP alpha state and key metrics'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from events" -f -a "watch" -d 'Watch the unified live event stream'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "list" -d 'List configured policies (names + statement counts)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "get" -d 'Show one policy by name'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "set" -d 'Set (create or replace) a policy from a JSON file'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "delete" -d 'Delete a policy by name'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "chain" -d 'Manage global / per-neighbor import/export chains'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor-set" -f -a "list" -d 'List configured neighbor sets'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor-set" -f -a "get" -d 'Show one neighbor set by name'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor-set" -f -a "set" -d 'Set (create or replace) a neighbor set from a JSON file'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor-set" -f -a "delete" -d 'Delete a neighbor set'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from peer-group" -f -a "list" -d 'List configured peer groups'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from peer-group" -f -a "get" -d 'Show one peer group by name'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from peer-group" -f -a "set" -d 'Set (create or replace) a peer group from a JSON file'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from peer-group" -f -a "delete" -d 'Delete a peer group'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from peer-group" -f -a "attach" -d 'Bind a neighbor to a peer group'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from peer-group" -f -a "detach" -d 'Unbind a neighbor from its peer group'
