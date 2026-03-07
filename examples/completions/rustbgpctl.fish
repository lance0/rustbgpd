# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_rustbgpctl_global_optspecs
	string join \n s/addr= token-file= j/json h/help V/version
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
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -s V -l version -d 'Print version'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "global" -d 'Show daemon global configuration'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "neighbor" -d 'Manage BGP neighbors'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "rib" -d 'Query and manage the RIB'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "flowspec" -d 'Manage FlowSpec routes'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "watch" -d 'Watch route updates (streaming)'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "health" -d 'Check daemon health'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "metrics" -d 'Show Prometheus metrics'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "shutdown" -d 'Request daemon shutdown'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "mrt-dump" -d 'Trigger an on-demand MRT dump'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "completions" -d 'Generate shell completions'
complete -c rustbgpctl -n "__fish_rustbgpctl_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand global" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand global" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand global" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand global" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -s h -l help -d 'Print help'
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
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -l reason -d 'Disable reason' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -s a -l family -d 'Address family to refresh' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "add" -d 'Add a new neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "enable" -d 'Enable this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "disable" -d 'Disable this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "softreset" -d 'Trigger soft reset (inbound)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised add delete help" -s a -l family -d 'Address family filter (ipv4_unicast, ipv6_unicast)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised add delete help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised add delete help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised add delete help" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised add delete help" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised add delete help" -f -a "received" -d 'Show received routes from a neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised add delete help" -f -a "advertised" -d 'Show advertised routes to a neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised add delete help" -f -a "add" -d 'Inject a route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised add delete help" -f -a "delete" -d 'Withdraw a route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and not __fish_seen_subcommand_from received advertised add delete help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from received" -s a -l family -d 'Address family filter' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from received" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from received" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from received" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from received" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from advertised" -s a -l family -d 'Address family filter' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from advertised" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from advertised" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from advertised" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from advertised" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l nexthop -d 'Next hop address' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l origin -d 'Origin (0=igp, 1=egp, 2=incomplete)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l local-pref -d 'Local preference' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l med -d 'MED' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l as-path -d 'AS path (space-separated)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l communities -d 'Communities (e.g., 65001:100)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l large-communities -d 'Large communities (e.g., 65001:100:200)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l path-id -d 'Path ID for Add-Path' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from delete" -l path-id -d 'Path ID for Add-Path' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "received" -d 'Show received routes from a neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "advertised" -d 'Show advertised routes to a neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "add" -d 'Inject a route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Withdraw a route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -s a -l family -d 'Address family (ipv4_flowspec, ipv6_flowspec)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -f -a "add" -d 'Add a FlowSpec rule'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -f -a "delete" -d 'Delete a FlowSpec rule'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -s a -l family -d 'Address family (required: ipv4_flowspec or ipv6_flowspec)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -l match -d 'Match components (e.g., dest=10.0.0.0/24 port==80)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -l action -d 'Actions (e.g., drop, rate=1000, redirect=65001:100)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -s a -l family -d 'Address family (required: ipv4_flowspec or ipv6_flowspec)' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -l match -d 'Match components identifying the rule' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from help" -f -a "add" -d 'Add a FlowSpec rule'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a FlowSpec rule'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand flowspec; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand watch" -s a -l family -d 'Address family filter' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand watch" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand watch" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand watch" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand watch" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand health" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand health" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand health" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand health" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand metrics" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand metrics" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand metrics" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand metrics" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand shutdown" -l reason -d 'Shutdown reason' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand shutdown" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand shutdown" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand shutdown" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand shutdown" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand mrt-dump" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand mrt-dump" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand mrt-dump" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand mrt-dump" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand completions" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand completions" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand completions" -s j -l json -d 'Output in JSON format'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand completions" -s h -l help -d 'Print help'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec watch health metrics shutdown mrt-dump completions help" -f -a "global" -d 'Show daemon global configuration'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec watch health metrics shutdown mrt-dump completions help" -f -a "neighbor" -d 'Manage BGP neighbors'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec watch health metrics shutdown mrt-dump completions help" -f -a "rib" -d 'Query and manage the RIB'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec watch health metrics shutdown mrt-dump completions help" -f -a "flowspec" -d 'Manage FlowSpec routes'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec watch health metrics shutdown mrt-dump completions help" -f -a "watch" -d 'Watch route updates (streaming)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec watch health metrics shutdown mrt-dump completions help" -f -a "health" -d 'Check daemon health'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec watch health metrics shutdown mrt-dump completions help" -f -a "metrics" -d 'Show Prometheus metrics'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec watch health metrics shutdown mrt-dump completions help" -f -a "shutdown" -d 'Request daemon shutdown'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec watch health metrics shutdown mrt-dump completions help" -f -a "mrt-dump" -d 'Trigger an on-demand MRT dump'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec watch health metrics shutdown mrt-dump completions help" -f -a "completions" -d 'Generate shell completions'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and not __fish_seen_subcommand_from global neighbor rib flowspec watch health metrics shutdown mrt-dump completions help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "add" -d 'Add a new neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "delete" -d 'Delete this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "enable" -d 'Enable this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "disable" -d 'Disable this neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "softreset" -d 'Trigger soft reset (inbound)'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "received" -d 'Show received routes from a neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "advertised" -d 'Show advertised routes to a neighbor'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "add" -d 'Inject a route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "delete" -d 'Withdraw a route'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from flowspec" -f -a "add" -d 'Add a FlowSpec rule'
complete -c rustbgpctl -n "__fish_rustbgpctl_using_subcommand help; and __fish_seen_subcommand_from flowspec" -f -a "delete" -d 'Delete a FlowSpec rule'
