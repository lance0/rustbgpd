# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_rbgp_global_optspecs
    string join \n s/addr= token-file= j/json no-color h/help V/version
end

function __fish_rbgp_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_rbgp_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_rbgp_using_subcommand
    set -l cmd (__fish_rbgp_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c rbgp -n "__fish_rbgp_needs_command" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_needs_command" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_needs_command" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_needs_command" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_needs_command" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_needs_command" -s V -l version -d 'Print version'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "global" -d 'Show daemon global configuration'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "config" -d 'Runtime config diagnostics'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "neighbor" -d 'Manage BGP neighbors'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "summary" -d 'Manage BGP neighbors'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "bfd" -d 'Inspect single-hop BFD sessions (ADR-0067)'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "rib" -d 'Query and manage the RIB'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "topology" -d 'Show the RFC 9107 ORR topology graph derived from BGP-LS'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "orr" -d 'Show RFC 9107 ORR per-vantage status (resolution, SPF reach, peers)'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "diff" -d 'Compare live RIB views against an external snapshot (read-only)'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "flowspec" -d 'Manage FlowSpec routes'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "evpn" -d 'Manage EVPN routes (list, add, delete — RFC 7432)'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "watch" -d 'Watch route updates (streaming)'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "events" -d 'Show recent route update events'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "health" -d 'Check daemon health'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "doctor" -d 'Run red/green triage checks and write a redacted support bundle'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "metrics" -d 'Show Prometheus metrics'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "shutdown" -d 'Request daemon shutdown'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "mrt-dump" -d 'Trigger an on-demand MRT dump'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "gshut" -d 'Toggle the RFC 8326 GRACEFUL_SHUTDOWN community on outbound updates'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "top" -d 'Live TUI dashboard'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "policy" -d 'Manage policy definitions and import/export chains'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "neighbor-set" -d 'Manage named neighbor sets used by policy'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "peer-group" -d 'Manage peer groups and neighbor membership'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "dynamic-neighbor" -d 'Manage dynamic-neighbor prefix ranges'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "fib-table" -d 'Manage general unicast FIB export tables at runtime'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "completions" -d 'Generate shell completions'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "man" -d 'Print the rbgp man page (roff) to stdout'
complete -c rbgp -n "__fish_rbgp_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand global" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand global" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand global" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand global" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand global" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and not __fish_seen_subcommand_from diff plan apply confirm abort status effective help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and not __fish_seen_subcommand_from diff plan apply confirm abort status effective help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and not __fish_seen_subcommand_from diff plan apply confirm abort status effective help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and not __fish_seen_subcommand_from diff plan apply confirm abort status effective help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and not __fish_seen_subcommand_from diff plan apply confirm abort status effective help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and not __fish_seen_subcommand_from diff plan apply confirm abort status effective help" -f -a "diff" -d 'Diff a candidate TOML file against the daemon\'s live runtime snapshot'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and not __fish_seen_subcommand_from diff plan apply confirm abort status effective help" -f -a "plan" -d 'Validate and classify a candidate transaction without mutation'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and not __fish_seen_subcommand_from diff plan apply confirm abort status effective help" -f -a "apply" -d 'Commit a previously planned candidate transaction'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and not __fish_seen_subcommand_from diff plan apply confirm abort status effective help" -f -a "confirm" -d 'Confirm a pending confirmed config transaction'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and not __fish_seen_subcommand_from diff plan apply confirm abort status effective help" -f -a "abort" -d 'Abort a pending confirmed config transaction and roll back immediately'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and not __fish_seen_subcommand_from diff plan apply confirm abort status effective help" -f -a "status" -d 'Show pending or last confirmed-transaction lifecycle state'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and not __fish_seen_subcommand_from diff plan apply confirm abort status effective help" -f -a "effective" -d 'Dump the daemon\'s effective running config (defaults materialized)'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and not __fish_seen_subcommand_from diff plan apply confirm abort status effective help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from diff" -l from-file -d 'Hidden compatibility alias for the positional `CANDIDATE`' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from diff" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from diff" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from diff" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from diff" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from diff" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from plan" -l from-file -d 'Hidden compatibility alias for the positional `CANDIDATE`' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from plan" -l expected-runtime-snapshot-token -d 'Optional runtime snapshot token to check while planning' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from plan" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from plan" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from plan" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from plan" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from plan" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from apply" -l from-file -d 'Hidden compatibility alias for the positional `CANDIDATE`' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from apply" -l expected-runtime-snapshot-token -d 'Runtime snapshot token returned by config plan' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from apply" -l client-request-id -d 'Optional audit/correlation identifier' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from apply" -l comment -d 'Optional human change note; not logged verbatim by the daemon' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from apply" -l confirm-id -d 'Optional confirmed-commit handle; requires explicit confirm/abort' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from apply" -l confirm-timeout -d 'Confirmed-commit timeout in seconds; daemon default is 600, max is 86400' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from apply" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from apply" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from apply" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from apply" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from apply" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from confirm" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from confirm" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from confirm" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from confirm" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from confirm" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from abort" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from abort" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from abort" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from abort" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from abort" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from status" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from status" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from status" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from status" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from effective" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from effective" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from effective" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from effective" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from effective" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "diff" -d 'Diff a candidate TOML file against the daemon\'s live runtime snapshot'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "plan" -d 'Validate and classify a candidate transaction without mutation'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "apply" -d 'Commit a previously planned candidate transaction'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "confirm" -d 'Confirm a pending confirmed config transaction'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "abort" -d 'Abort a pending confirmed config transaction and roll back immediately'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "status" -d 'Show pending or last confirmed-transaction lifecycle state'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "effective" -d 'Dump the daemon\'s effective running config (defaults materialized)'
complete -c rbgp -n "__fish_rbgp_using_subcommand config; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -l wide -d 'Append the classic summary columns to the list: MsgRcvd, MsgSent, Flaps, RRC (route-reflector client), and State/PfxRcd (prefix count when Established). Display-only; -j already carries every field'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "add" -d 'Add a new neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "delete" -d 'Delete this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "enable" -d 'Enable this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "disable" -d 'Disable this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "softreset" -d 'Trigger soft reset (inbound)'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l remote-asn -l asn -d 'Remote AS number of the peer (the local AS is `rbgp global`)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l description -d 'Description' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l hold-time -d 'Hold time in seconds' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l send-hold-time -d 'RFC 9687 send hold time in seconds (0 disables; must exceed the hold time; default: max(480, 2 x hold time))' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l max-prefixes -d 'Max prefix limit' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l families -d 'Address families (comma-separated)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l role -d 'Local BGP Role for RFC 9234 route-leak protection' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l add-path-send-max -d 'Max paths per prefix for Add-Path send' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l paths-limit-receive-max -d 'Experimental Paths-Limit preference for Add-Path receive families' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l route-server-client -d 'Enable transparent route-server client mode (eBGP only)'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l per-client-best -d 'RFC 7947 per-client best-path (path-hiding mitigation); requires --route-server-client'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l strict-role -d 'Require the peer to advertise a compatible BGP Role capability'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l add-path-receive -d 'Enable Add-Path receive'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l add-path-send -d 'Enable Add-Path send'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from enable" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -l reason -d 'Disable reason' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from disable" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -s a -l family -d 'Address family to refresh' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from softreset" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "add" -d 'Add a new neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "enable" -d 'Enable this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "disable" -d 'Disable this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "softreset" -d 'Trigger soft reset (inbound)'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and not __fish_seen_subcommand_from add delete enable disable softreset help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and not __fish_seen_subcommand_from add delete enable disable softreset help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and not __fish_seen_subcommand_from add delete enable disable softreset help" -l wide -d 'Append the classic summary columns to the list: MsgRcvd, MsgSent, Flaps, RRC (route-reflector client), and State/PfxRcd (prefix count when Established). Display-only; -j already carries every field'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and not __fish_seen_subcommand_from add delete enable disable softreset help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and not __fish_seen_subcommand_from add delete enable disable softreset help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and not __fish_seen_subcommand_from add delete enable disable softreset help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "add" -d 'Add a new neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "delete" -d 'Delete this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "enable" -d 'Enable this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "disable" -d 'Disable this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "softreset" -d 'Trigger soft reset (inbound)'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and not __fish_seen_subcommand_from add delete enable disable softreset help" -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l remote-asn -l asn -d 'Remote AS number of the peer (the local AS is `rbgp global`)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l description -d 'Description' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l hold-time -d 'Hold time in seconds' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l send-hold-time -d 'RFC 9687 send hold time in seconds (0 disables; must exceed the hold time; default: max(480, 2 x hold time))' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l max-prefixes -d 'Max prefix limit' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l families -d 'Address families (comma-separated)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l role -d 'Local BGP Role for RFC 9234 route-leak protection' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l add-path-send-max -d 'Max paths per prefix for Add-Path send' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l paths-limit-receive-max -d 'Experimental Paths-Limit preference for Add-Path receive families' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l route-server-client -d 'Enable transparent route-server client mode (eBGP only)'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l per-client-best -d 'RFC 7947 per-client best-path (path-hiding mitigation); requires --route-server-client'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l strict-role -d 'Require the peer to advertise a compatible BGP Role capability'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l add-path-receive -d 'Enable Add-Path receive'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l add-path-send -d 'Enable Add-Path send'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from enable" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from enable" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from enable" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from enable" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from enable" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from disable" -l reason -d 'Disable reason' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from disable" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from disable" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from disable" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from disable" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from disable" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from softreset" -s a -l family -d 'Address family to refresh' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from softreset" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from softreset" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from softreset" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from softreset" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from softreset" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from help" -f -a "add" -d 'Add a new neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from help" -f -a "enable" -d 'Enable this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from help" -f -a "disable" -d 'Disable this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from help" -f -a "softreset" -d 'Trigger soft reset (inbound)'
complete -c rbgp -n "__fish_rbgp_using_subcommand summary; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and not __fish_seen_subcommand_from list show help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and not __fish_seen_subcommand_from list show help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and not __fish_seen_subcommand_from list show help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and not __fish_seen_subcommand_from list show help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and not __fish_seen_subcommand_from list show help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and not __fish_seen_subcommand_from list show help" -f -a "list" -d 'List all BFD sessions (default)'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and not __fish_seen_subcommand_from list show help" -f -a "show" -d 'Show a single BFD session by peer address'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and not __fish_seen_subcommand_from list show help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and __fish_seen_subcommand_from list" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and __fish_seen_subcommand_from list" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and __fish_seen_subcommand_from list" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and __fish_seen_subcommand_from list" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and __fish_seen_subcommand_from show" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and __fish_seen_subcommand_from show" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and __fish_seen_subcommand_from show" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and __fish_seen_subcommand_from show" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and __fish_seen_subcommand_from help" -f -a "list" -d 'List all BFD sessions (default)'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and __fish_seen_subcommand_from help" -f -a "show" -d 'Show a single BFD session by peer address'
complete -c rbgp -n "__fish_rbgp_using_subcommand bfd; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -s a -l family -d 'Address family filter (ipv4_unicast, ipv6_unicast)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -s p -l prefix -d 'Prefix filter (e.g., 10.0.0.0/24)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -l explain-peer -d 'Scope --explain to a specific peer\'s Add-Path send view. When set, candidates are filtered by the peer\'s export policy + sendable families and the top `add_path_send_max` are tagged with their advertised rank. Omit for the global Loc-RIB view' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -l origin-asn -d 'Filter by origin ASN (last ASN in AS_PATH)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -s c -l community -d 'Filter by community (e.g., 65001:100 or BLACKHOLE); may be repeated' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -l large-community -d 'Filter by large community (e.g., 65001:100:200); may be repeated' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -s l -l longer -d 'Show longer (more specific) prefixes matching --prefix'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -l explain -d 'Show why the best route was selected (requires --prefix)'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "received" -d 'Show received routes from a neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "recv" -d 'Show received routes from a neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "advertised" -d 'Show advertised routes to a neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "sent" -d 'Show advertised routes to a neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "blackholes" -d 'Show RFC 7999 BLACKHOLE discard install status'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "fib" -d 'Show ADR-0061 general FIB route install status'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "bgpls" -d 'Show BGP-LS routes learned from peers (RFC 9552)'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "bgp-ls" -d 'Show BGP-LS routes learned from peers (RFC 9552)'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "vpn" -d 'Show VPNv4/VPNv6 routes learned from peers (RFC 4364/4659)'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "labeled" -d 'Show IPv4/IPv6 labeled-unicast routes learned from peers (RFC 8277)'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "rtc" -d 'Show RT-Constrain routes (RFC 4684, single IPv4 family)'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "add" -d 'Inject a route'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "delete" -d 'Withdraw a route'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and not __fish_seen_subcommand_from received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from received" -s a -l family -d 'Address family filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from received" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from received" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from received" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from received" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from received" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from recv" -s a -l family -d 'Address family filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from recv" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from recv" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from recv" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from recv" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from recv" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from advertised" -s a -l family -d 'Address family filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from advertised" -l rd -d 'Route Distinguisher ("asn:nn" or "ip:nn") - explain the VPNv4/VPNv6 export ladder for the (RD, prefix) identity, including the RFC 4684 RT-Constrain membership gate' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from advertised" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from advertised" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from advertised" -l explain -d 'Explain whether this exact prefix would be advertised to the peer'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from advertised" -l labeled -d 'Explain the labeled-unicast (SAFI 4, RFC 8277) export ladder for the prefix instead of the plain unicast ladder'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from advertised" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from advertised" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from advertised" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from sent" -s a -l family -d 'Address family filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from sent" -l rd -d 'Route Distinguisher ("asn:nn" or "ip:nn") - explain the VPNv4/VPNv6 export ladder for the (RD, prefix) identity, including the RFC 4684 RT-Constrain membership gate' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from sent" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from sent" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from sent" -l explain -d 'Explain whether this exact prefix would be advertised to the peer'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from sent" -l labeled -d 'Explain the labeled-unicast (SAFI 4, RFC 8277) export ladder for the prefix instead of the plain unicast ladder'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from sent" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from sent" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from sent" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from blackholes" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from blackholes" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from blackholes" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from blackholes" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from blackholes" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from fib" -l table -d 'FIB table-name filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from fib" -l state -d 'FIB route state filter: installed, rejected, failed' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from fib" -l reason -d 'Exact reason-code filter, e.g. owned or route_limit_exceeded' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from fib" -l prefix -d 'Exact prefix filter, e.g. 203.0.113.0/24' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from fib" -l neighbor -l peer -d 'Source neighbor-address filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from fib" -l page-size -d 'Maximum FIB status rows to return; omitted returns the full snapshot' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from fib" -l page-token -d 'Page token returned by a previous paginated FIB status query' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from fib" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from fib" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from fib" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from fib" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from fib" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgpls" -s a -l family -d 'BGP-LS family filter: linkstate (aliases bgpls, bgp-ls) or linkstate_vpn (aliases bgpls-vpn, bgp-ls-vpn)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgpls" -l neighbor -l peer -d 'Neighbor IP address filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgpls" -l nlri-type -d 'NLRI type filter (1=node, 2=link, 3=IPv4 prefix, 4=IPv6 prefix)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgpls" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgpls" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgpls" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgpls" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgpls" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgp-ls" -s a -l family -d 'BGP-LS family filter: linkstate (aliases bgpls, bgp-ls) or linkstate_vpn (aliases bgpls-vpn, bgp-ls-vpn)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgp-ls" -l neighbor -l peer -d 'Neighbor IP address filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgp-ls" -l nlri-type -d 'NLRI type filter (1=node, 2=link, 3=IPv4 prefix, 4=IPv6 prefix)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgp-ls" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgp-ls" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgp-ls" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgp-ls" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from bgp-ls" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from vpn" -s a -l family -d 'VPN family filter: l3vpn_ipv4_unicast (alias vpnv4) or l3vpn_ipv6_unicast (alias vpnv6)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from vpn" -l neighbor -l peer -d 'Neighbor IP address filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from vpn" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from vpn" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from vpn" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from vpn" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from vpn" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from labeled" -s a -l family -d 'Labeled family filter: ipv4_labeled_unicast (alias labeled-v4) or ipv6_labeled_unicast (alias labeled-v6)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from labeled" -l neighbor -l peer -d 'Neighbor IP address filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from labeled" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from labeled" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from labeled" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from labeled" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from labeled" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from rtc" -l neighbor -l peer -d 'Neighbor IP address filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from rtc" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from rtc" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from rtc" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from rtc" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from rtc" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from add" -l nexthop -d 'Next hop address' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from add" -l origin -d 'Origin (0=igp, 1=egp, 2=incomplete)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from add" -l local-pref -d 'Local preference' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from add" -l med -d 'MED' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from add" -l as-path -d 'AS path (space-separated)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from add" -l communities -d 'Communities (e.g., 65001:100 or BLACKHOLE)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from add" -l large-communities -d 'Large communities (e.g., 65001:100:200)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from add" -l path-id -d 'Path ID for Add-Path' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from add" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from add" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from add" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from add" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from delete" -l path-id -d 'Path ID for Add-Path' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "received" -d 'Show received routes from a neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "advertised" -d 'Show advertised routes to a neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "blackholes" -d 'Show RFC 7999 BLACKHOLE discard install status'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "fib" -d 'Show ADR-0061 general FIB route install status'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "bgpls" -d 'Show BGP-LS routes learned from peers (RFC 9552)'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "vpn" -d 'Show VPNv4/VPNv6 routes learned from peers (RFC 4364/4659)'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "labeled" -d 'Show IPv4/IPv6 labeled-unicast routes learned from peers (RFC 8277)'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "rtc" -d 'Show RT-Constrain routes (RFC 4684, single IPv4 family)'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "add" -d 'Inject a route'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Withdraw a route'
complete -c rbgp -n "__fish_rbgp_using_subcommand rib; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and not __fish_seen_subcommand_from nodes links help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and not __fish_seen_subcommand_from nodes links help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and not __fish_seen_subcommand_from nodes links help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and not __fish_seen_subcommand_from nodes links help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and not __fish_seen_subcommand_from nodes links help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and not __fish_seen_subcommand_from nodes links help" -f -a "nodes" -d 'List topology nodes (BGP-LS node identities across all peers)'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and not __fish_seen_subcommand_from nodes links help" -f -a "links" -d 'List usable directed topology links (with IGP metrics)'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and not __fish_seen_subcommand_from nodes links help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and __fish_seen_subcommand_from nodes" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and __fish_seen_subcommand_from nodes" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and __fish_seen_subcommand_from nodes" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and __fish_seen_subcommand_from nodes" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and __fish_seen_subcommand_from nodes" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and __fish_seen_subcommand_from links" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and __fish_seen_subcommand_from links" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and __fish_seen_subcommand_from links" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and __fish_seen_subcommand_from links" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and __fish_seen_subcommand_from links" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and __fish_seen_subcommand_from help" -f -a "nodes" -d 'List topology nodes (BGP-LS node identities across all peers)'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and __fish_seen_subcommand_from help" -f -a "links" -d 'List usable directed topology links (with IGP metrics)'
complete -c rbgp -n "__fish_rbgp_using_subcommand topology; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand orr" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand orr" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand orr" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand orr" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand orr" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and not __fish_seen_subcommand_from advertised snapshot help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and not __fish_seen_subcommand_from advertised snapshot help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and not __fish_seen_subcommand_from advertised snapshot help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and not __fish_seen_subcommand_from advertised snapshot help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and not __fish_seen_subcommand_from advertised snapshot help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and not __fish_seen_subcommand_from advertised snapshot help" -f -a "advertised" -d 'Compare the live Adj-RIB-Out against an incumbent NDJSON snapshot'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and not __fish_seen_subcommand_from advertised snapshot help" -f -a "snapshot" -d 'Produce an `rbgp-ribsnap/1` snapshot from an incumbent\'s own output (offline; no daemon connection)'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and not __fish_seen_subcommand_from advertised snapshot help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from advertised" -l neighbor -l peer -d 'Neighbor address to compare; may be repeated. Omit to compare every peer present in the snapshot' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from advertised" -l against -d 'Path to the incumbent `rbgp-ribsnap/1` NDJSON snapshot' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from advertised" -s a -l family -d 'Address family filter (ipv4_unicast, ipv6_unicast); may be repeated' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from advertised" -l max-routes -d 'Maximum retained routes per side; exceeding it refuses the comparison (exit 2)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from advertised" -l max-input-bytes -d 'Maximum snapshot bytes read; exceeding it refuses the comparison (exit 2)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from advertised" -l ignore-attribute -d 'Attribute to exclude from comparison on both sides (origin, as_path, next_hop, med, local_pref, communities, extended_communities, large_communities, unknown); may be repeated' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from advertised" -l detail -d 'Maximum detailed difference rows in human output (--json is always complete)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from advertised" -l deadline -d 'Overall wall-clock budget in seconds; expiry refuses the comparison (exit 2)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from advertised" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from advertised" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from advertised" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from advertised" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from advertised" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from snapshot" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from snapshot" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from snapshot" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from snapshot" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from snapshot" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from snapshot" -f -a "from-mrt" -d 'Convert an RFC 6396 TABLE_DUMP_V2 MRT dump into a snapshot'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from snapshot" -f -a "from-bmp" -d 'Convert a captured RFC 7854/8671 BMP byte stream into a snapshot'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from snapshot" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from help" -f -a "advertised" -d 'Compare the live Adj-RIB-Out against an incumbent NDJSON snapshot'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from help" -f -a "snapshot" -d 'Produce an `rbgp-ribsnap/1` snapshot from an incumbent\'s own output (offline; no daemon connection)'
complete -c rbgp -n "__fish_rbgp_using_subcommand diff; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -s a -l family -d 'Address family (ipv4_flowspec, ipv6_flowspec)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -f -a "add" -d 'Add a FlowSpec rule'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -f -a "delete" -d 'Delete a FlowSpec rule'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and not __fish_seen_subcommand_from add delete help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from add" -s a -l family -d 'Address family (required: ipv4_flowspec or ipv6_flowspec)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from add" -l match -d 'Match components (e.g., dest=10.0.0.0/24 port==80)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from add" -l action -d 'Actions (e.g., drop, rate=1000, redirect=65001:100)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from add" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from add" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from add" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from add" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -s a -l family -d 'Address family (required: ipv4_flowspec or ipv6_flowspec)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -l match -d 'Match components identifying the rule' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from help" -f -a "add" -d 'Add a FlowSpec rule'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a FlowSpec rule'
complete -c rbgp -n "__fish_rbgp_using_subcommand flowspec; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -l route-type -d 'Route type filter (1..=5) — applies when no subcommand is given' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -l neighbor -l peer -d 'Neighbor IP address filter (list mode only)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -l rd -d 'Route Distinguisher filter (list mode only), e.g. "65000:100"' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "list" -d 'List EVPN routes (default action — same as omitting the subcommand)'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "add-mac-ip" -d 'Inject a Type 2 MAC/IP route'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "add-imet" -d 'Inject a Type 3 IMET route'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "add-ip-prefix" -d 'Inject a Type 5 IP Prefix route'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "delete-mac-ip" -d 'Withdraw a Type 2 MAC/IP route by its key fields'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "delete-imet" -d 'Withdraw a Type 3 IMET route by its key fields'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "delete-ip-prefix" -d 'Withdraw a Type 5 IP Prefix route by its key fields'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "clear-duplicate-mac" -d 'Clear one duplicate-MAC local-origin quarantine'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "es" -d 'Ethernet Segment runtime controls and diagnose state'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "runtime" -d 'Show the committed ADR-0063 EVPN runtime generation'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "instances" -d 'List local EVPN instances configured on this VTEP'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "nexthops" -d 'List rustbgpd-owned FDB nexthop groups (ADR-0059 aliasing ECMP)'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "managed-netdevs" -d 'List managed EVPN netdev ownership/status rows (ADR-0091)'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "vrfs" -d 'List configured IP-VRFs and their readiness verdict'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "diagnose" -d 'Summarize EVPN VTEP alpha state and key metrics'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and not __fish_seen_subcommand_from list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from list" -l route-type -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from list" -l neighbor -l peer -d 'Neighbor IP address filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from list" -l rd -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from list" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from list" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from list" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from list" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l rd -d 'Route Distinguisher, "asn:value" / "ip:value"' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l ethernet-tag -d 'Ethernet-tag identifying the EVI (default 0)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l mac -d 'MAC address "aa:bb:cc:dd:ee:ff"' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l ip -d 'Host IP (optional — MAC-only route if omitted)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l label -d 'VNI for this EVI (required)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l label2 -d 'Optional second label for RFC 9135 symmetric IRB' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l next-hop -d 'VTEP loopback IP (next-hop)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l rt -d 'Optional route targets, each "asn:value"' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l no-vxlan-encap -d 'Disable the RFC 8365 VXLAN encapsulation ext community'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-mac-ip" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l rd -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l ethernet-tag -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l ip -d 'Originator IP (required for Type 3)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l next-hop -d 'VTEP loopback IP (next-hop)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l rt -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l no-vxlan-encap
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-imet" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -l rd -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -l ethernet-tag -d 'Ethernet Tag ID. Must be 0 for supported Type 5 injection' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -l prefix -d 'IP prefix, e.g. "10.0.0.0/24" or "2001:db8::/48"' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -l label -d 'L3VNI for this IP-VRF' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -l next-hop -d 'VTEP loopback IP (next-hop)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -l gateway -d 'Optional Type 5 Gateway IP for overlay-index injection. Omit for interface-less Type 5' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -l router-mac -d 'Router MAC extended community value. Required unless --no-vxlan-encap is set' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -l rt -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -l no-vxlan-encap
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from add-ip-prefix" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -l rd -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -l ethernet-tag -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -l mac -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -l ip -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-mac-ip" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -l rd -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -l ethernet-tag -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -l ip -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-imet" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-ip-prefix" -l rd -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-ip-prefix" -l ethernet-tag -d 'Ethernet Tag ID. Must be 0 for Type 5 withdrawal' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-ip-prefix" -l prefix -d 'IP prefix, e.g. "10.0.0.0/24" or "2001:db8::/48"' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-ip-prefix" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-ip-prefix" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-ip-prefix" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-ip-prefix" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from delete-ip-prefix" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from clear-duplicate-mac" -l vni -d 'L2VNI containing the quarantined MAC' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from clear-duplicate-mac" -l mac -d 'MAC address "aa:bb:cc:dd:ee:ff"' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from clear-duplicate-mac" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from clear-duplicate-mac" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from clear-duplicate-mac" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from clear-duplicate-mac" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from clear-duplicate-mac" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from es" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from es" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from es" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from es" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from es" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from es" -f -a "list" -d 'List configured Ethernet Segments'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from es" -f -a "drain" -d 'Drain an Ethernet Segment before access-circuit maintenance'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from es" -f -a "undrain" -d 'Undrain an Ethernet Segment'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from es" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from runtime" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from runtime" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from runtime" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from runtime" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from runtime" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from instances" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from instances" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from instances" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from instances" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from instances" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from nexthops" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from nexthops" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from nexthops" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from nexthops" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from nexthops" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from managed-netdevs" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from managed-netdevs" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from managed-netdevs" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from managed-netdevs" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from managed-netdevs" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from vrfs" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from vrfs" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from vrfs" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from vrfs" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from vrfs" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from diagnose" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from diagnose" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from diagnose" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from diagnose" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from diagnose" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "list" -d 'List EVPN routes (default action — same as omitting the subcommand)'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "add-mac-ip" -d 'Inject a Type 2 MAC/IP route'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "add-imet" -d 'Inject a Type 3 IMET route'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "add-ip-prefix" -d 'Inject a Type 5 IP Prefix route'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "delete-mac-ip" -d 'Withdraw a Type 2 MAC/IP route by its key fields'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "delete-imet" -d 'Withdraw a Type 3 IMET route by its key fields'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "delete-ip-prefix" -d 'Withdraw a Type 5 IP Prefix route by its key fields'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "clear-duplicate-mac" -d 'Clear one duplicate-MAC local-origin quarantine'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "es" -d 'Ethernet Segment runtime controls and diagnose state'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "runtime" -d 'Show the committed ADR-0063 EVPN runtime generation'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "instances" -d 'List local EVPN instances configured on this VTEP'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "nexthops" -d 'List rustbgpd-owned FDB nexthop groups (ADR-0059 aliasing ECMP)'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "managed-netdevs" -d 'List managed EVPN netdev ownership/status rows (ADR-0091)'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "vrfs" -d 'List configured IP-VRFs and their readiness verdict'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "diagnose" -d 'Summarize EVPN VTEP alpha state and key metrics'
complete -c rbgp -n "__fish_rbgp_using_subcommand evpn; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand watch" -s a -l family -d 'Address family filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand watch" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand watch" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand watch" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand watch" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand watch" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -l address -d 'Neighbor address filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -s a -l family -d 'Address family filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -l prefix -d 'Exact prefix filter, e.g. 203.0.113.0/24' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -s l -l limit -d 'Maximum recent route events to return (default 100; route history only)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -f -a "watch" -d 'Watch the unified live event stream'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -f -a "sessions" -d 'Show recent session lifecycle events'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -f -a "policy" -d 'Show recent policy / neighbor-set / peer-group / chain mutation events'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -f -a "evpn" -d 'Show recent EVPN route events'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and not __fish_seen_subcommand_from watch sessions policy evpn help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from watch" -l category -d 'Event category filter: route, session, policy, dataplane, evpn, bfd' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from watch" -l address -d 'Neighbor address filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from watch" -s a -l family -d 'Address family filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from watch" -l prefix -d 'Exact prefix filter, e.g. 203.0.113.0/24' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from watch" -l type -d 'Event type filter: added, withdrawn, best_changed, state_changed, established, lost, peer_enabled, peer_disabled, notification_sent, notification_received, policy_changed, dataplane_status_changed, dataplane_route_installed, dataplane_route_withdrawn, dataplane_route_failed, evpn_added, evpn_withdrawn, evpn_best_changed, bfd_up, bfd_down, bfd_state_changed' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from watch" -l backfill -d 'Print recent route history before tailing the live stream. Applies only to route-capable event streams. Mutually exclusive with `--from-event-id`; `--backfill` replays the daemon\'s process-local route ring (resets on restart), while `--from-event-id` replays the durable event outbox (survives restart)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from watch" -l from-event-id -d 'ADR-0072 durable cursor: replay committed events with `event_id > N` from the daemon\'s local event outbox, then tail the live stream. `0` replays everything retained. Survives daemon restart. Returns `FAILED_PRECONDITION` when the daemon was started with `[event_history].enabled = false` or EHM is unavailable' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from watch" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from watch" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from watch" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from watch" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from watch" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from sessions" -l address -d 'Neighbor address filter' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from sessions" -l type -d 'Session event type filter: state_changed, established, lost, peer_enabled, peer_disabled' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from sessions" -s l -l limit -d 'Maximum recent session events to return (default 100; explicit 0 requests the daemon\'s full bounded window)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from sessions" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from sessions" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from sessions" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from sessions" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from sessions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from policy" -l address -d 'Neighbor address filter. Only peer-scoped policy events match' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from policy" -l type -d 'Policy event type filter: policy_changed' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from policy" -s l -l limit -d 'Maximum recent policy events to return (default 100; explicit 0 requests the daemon\'s full bounded window)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from policy" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from policy" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from policy" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from policy" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from policy" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from evpn" -l address -d 'Neighbor address filter. Matches current and previous best-path peer' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from evpn" -l route-type -d 'EVPN route type filter (1..=5)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from evpn" -l rd -d 'Route Distinguisher filter, e.g. "65000:100"' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from evpn" -l type -d 'EVPN event type filter: evpn_added, evpn_withdrawn, evpn_best_changed' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from evpn" -s l -l limit -d 'Maximum recent EVPN events to return (default 100; explicit 0 requests the daemon\'s full bounded window)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from evpn" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from evpn" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from evpn" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from evpn" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from evpn" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from help" -f -a "watch" -d 'Watch the unified live event stream'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from help" -f -a "sessions" -d 'Show recent session lifecycle events'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from help" -f -a "policy" -d 'Show recent policy / neighbor-set / peer-group / chain mutation events'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from help" -f -a "evpn" -d 'Show recent EVPN route events'
complete -c rbgp -n "__fish_rbgp_using_subcommand events; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand health" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand health" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand health" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand health" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand health" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand doctor" -l output -d 'Output tarball path. Defaults to `rustbgpd-doctor-<unix-seconds>.tar.gz`' -r -F
complete -c rbgp -n "__fish_rbgp_using_subcommand doctor" -l log-file -d 'Daemon log file to tail (last 1000 lines) into the bundle. Without it the manifest records that the daemon logs to stdout/journald' -r -F
complete -c rbgp -n "__fish_rbgp_using_subcommand doctor" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand doctor" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand doctor" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand doctor" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand doctor" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand metrics" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand metrics" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand metrics" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand metrics" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand metrics" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand shutdown" -l reason -d 'Shutdown reason' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand shutdown" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand shutdown" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand shutdown" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand shutdown" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand shutdown" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand mrt-dump" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand mrt-dump" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand mrt-dump" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand mrt-dump" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand mrt-dump" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand gshut" -l neighbor -l peer -d 'Neighbor address; omit to toggle for all peers' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand gshut" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand gshut" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand gshut" -l clear -d 'Clear instead of enabling'
complete -c rbgp -n "__fish_rbgp_using_subcommand gshut" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand gshut" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand gshut" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand top" -s i -l interval -d 'Poll interval in seconds (1-60)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand top" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand top" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand top" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand top" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand top" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -f -a "list" -d 'List configured policies (names + statement counts)'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -f -a "check" -d 'Check an `.rpol` policy file locally (parse, typecheck, tests)'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -f -a "fmt" -d 'Format `.rpol` files in the one canonical style'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -f -a "test" -d 'Dry-run a candidate `.rpol` policy against the live RIB'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -f -a "get" -d 'Show one policy by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -f -a "set" -d 'Set (create or replace) a policy from a JSON file'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -f -a "delete" -d 'Delete a policy by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -f -a "chain" -d 'Manage global / per-neighbor import/export chains'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -f -a "stats" -d 'Show live per-term policy hit counters'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -f -a "counters" -d 'Show live per-term policy hit counters'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -f -a "explain" -d 'Explain the import-policy decision for a prefix on a neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and not __fish_seen_subcommand_from list check fmt test get set delete chain stats counters explain help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from list" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from list" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from list" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from list" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from check" -l root -d 'Additional policy root for `import` resolution (repeatable; the main file\'s directory is always a root) — mirror of the daemon\'s `[policy] rpol_roots`' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from check" -l coverage-min -d 'Minimum acceptable exercised-term percentage (implies --coverage): exit 3 when coverage falls below PCT (CI gate). Diagnostics (1) and test failures (2) take precedence' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from check" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from check" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from check" -l list-deps -d 'Print the resolved import graph — each module\'s path, SHA-256 content hash, and imports — instead of running tests (audit/packaging aid)'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from check" -l coverage -d 'Report which policy terms the in-language tests exercised (evaluated vs. matched, per term) plus static lints (unused sets/datasets/fns, unreachable terms, unreferenced policies). A report only — it never changes the exit code by itself'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from check" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from check" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from check" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from fmt" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from fmt" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from fmt" -l check -d 'Rewrite nothing; print a diff and exit 1 when any file is not canonically formatted (CI mode)'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from fmt" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from fmt" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from fmt" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from test" -l policy -d 'Policy to evaluate: a name, or a call-form with u32 arguments for parameterized policies, e.g. "customer-in(200)"' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from test" -l direction -d 'Evaluation direction: import (Adj-RIB-In) or export (Loc-RIB best routes)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from test" -l neighbor -l peer -d 'Neighbor address: restricts the import snapshot to one peer\'s Adj-RIB-In, or sets the export evaluation target' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from test" -s a -l family -d 'Address family filter (ipv4_unicast, ipv6_unicast)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from test" -l limit -d 'Maximum routes to evaluate (0 = all)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from test" -l show-changes -d 'Maximum before/after attribute diffs to show' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from test" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from test" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from test" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from test" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from test" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from get" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from get" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from get" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from get" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from get" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from set" -l from-file -d 'JSON file containing the PolicyDefinition shape' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from set" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from set" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from set" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from set" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from set" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from chain" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from chain" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from chain" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from chain" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from chain" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from chain" -f -a "show" -d 'Show the global or per-neighbor chains'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from chain" -f -a "set-import" -d 'Replace the import chain'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from chain" -f -a "set-export" -d 'Replace the export chain'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from chain" -f -a "clear-import" -d 'Clear the import chain entirely'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from chain" -f -a "clear-export" -d 'Clear the export chain entirely'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from chain" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from stats" -l neighbor -l peer -d 'Restrict to one neighbor\'s installed chain' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from stats" -l direction -d 'Direction: export (default), import, or both' -r -f -a "import\t''
export\t''
both\t''"
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from stats" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from stats" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from stats" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from stats" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from stats" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from counters" -l neighbor -l peer -d 'Restrict to one neighbor\'s installed chain' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from counters" -l direction -d 'Direction: export (default), import, or both' -r -f -a "import\t''
export\t''
both\t''"
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from counters" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from counters" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from counters" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from counters" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from counters" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from explain" -l neighbor -l peer -d 'Neighbor (peer) address whose import-decision cache to read' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from explain" -l prefix -d 'Prefix in CIDR form, e.g. `192.0.2.0/24` or `2001:db8::/32`' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from explain" -l path-id -d 'Add-Path identifier; omit to show every matching path' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from explain" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from explain" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from explain" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from explain" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from explain" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "list" -d 'List configured policies (names + statement counts)'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "check" -d 'Check an `.rpol` policy file locally (parse, typecheck, tests)'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "fmt" -d 'Format `.rpol` files in the one canonical style'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "test" -d 'Dry-run a candidate `.rpol` policy against the live RIB'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "get" -d 'Show one policy by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "set" -d 'Set (create or replace) a policy from a JSON file'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a policy by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "chain" -d 'Manage global / per-neighbor import/export chains'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "stats" -d 'Show live per-term policy hit counters'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "explain" -d 'Explain the import-policy decision for a prefix on a neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand policy; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -f -a "list" -d 'List configured neighbor sets'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -f -a "get" -d 'Show one neighbor set by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -f -a "set" -d 'Set (create or replace) a neighbor set from a JSON file'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -f -a "delete" -d 'Delete a neighbor set'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and not __fish_seen_subcommand_from list get set delete help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from list" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from list" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from list" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from list" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from get" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from get" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from get" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from get" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from get" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from set" -l from-file -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from set" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from set" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from set" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from set" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from set" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from help" -f -a "list" -d 'List configured neighbor sets'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from help" -f -a "get" -d 'Show one neighbor set by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from help" -f -a "set" -d 'Set (create or replace) a neighbor set from a JSON file'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a neighbor set'
complete -c rbgp -n "__fish_rbgp_using_subcommand neighbor-set; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "list" -d 'List configured peer groups'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "get" -d 'Show one peer group by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "set" -d 'Set (create or replace) a peer group from a JSON file'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "delete" -d 'Delete a peer group'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "attach" -d 'Bind a neighbor to a peer group'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "detach" -d 'Unbind a neighbor from its peer group'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and not __fish_seen_subcommand_from list get set delete attach detach help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from list" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from list" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from list" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from list" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from get" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from get" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from get" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from get" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from get" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from set" -l from-file -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from set" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from set" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from set" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from set" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from set" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from attach" -l group -d 'Peer-group name' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from attach" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from attach" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from attach" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from attach" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from attach" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from detach" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from detach" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from detach" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from detach" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from detach" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "list" -d 'List configured peer groups'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "get" -d 'Show one peer group by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "set" -d 'Set (create or replace) a peer group from a JSON file'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a peer group'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "attach" -d 'Bind a neighbor to a peer group'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "detach" -d 'Unbind a neighbor from its peer group'
complete -c rbgp -n "__fish_rbgp_using_subcommand peer-group; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and not __fish_seen_subcommand_from list add delete help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and not __fish_seen_subcommand_from list add delete help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and not __fish_seen_subcommand_from list add delete help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and not __fish_seen_subcommand_from list add delete help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and not __fish_seen_subcommand_from list add delete help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and not __fish_seen_subcommand_from list add delete help" -f -a "list" -d 'List configured dynamic neighbor ranges'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and not __fish_seen_subcommand_from list add delete help" -f -a "add" -d 'Add a dynamic neighbor range'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and not __fish_seen_subcommand_from list add delete help" -f -a "delete" -d 'Delete a dynamic neighbor range by prefix'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and not __fish_seen_subcommand_from list add delete help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from list" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from list" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from list" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from list" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from add" -l peer-group -d 'Peer group the dynamic peers inherit' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from add" -l remote-asn -l asn -d 'Expected remote ASN (0 = accept any ASN from OPEN)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from add" -l description -d 'Optional description' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from add" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from add" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from add" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from add" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from help" -f -a "list" -d 'List configured dynamic neighbor ranges'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from help" -f -a "add" -d 'Add a dynamic neighbor range'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a dynamic neighbor range by prefix'
complete -c rbgp -n "__fish_rbgp_using_subcommand dynamic-neighbor; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and not __fish_seen_subcommand_from list set delete help" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and not __fish_seen_subcommand_from list set delete help" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and not __fish_seen_subcommand_from list set delete help" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and not __fish_seen_subcommand_from list set delete help" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and not __fish_seen_subcommand_from list set delete help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and not __fish_seen_subcommand_from list set delete help" -f -a "list" -d 'List the configured FIB tables and runtime availability'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and not __fish_seen_subcommand_from list set delete help" -f -a "set" -d 'Create or replace a FIB table by name (full definition, not a patch)'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and not __fish_seen_subcommand_from list set delete help" -f -a "delete" -d 'Delete a FIB table by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and not __fish_seen_subcommand_from list set delete help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from list" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from list" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from list" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from list" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -l table-id -d 'Linux route table id' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -l metric -d 'Kernel route metric / priority for daemon-owned rows' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -l families -d 'Address families (comma-separated, e.g. ipv4_unicast,ipv6_unicast). Empty defaults to both unicast families' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -l allowed-peer-group -d 'Peer-group allow-list (repeatable / comma-separated). Empty = all' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -l allowed-neighbor -d 'Neighbor-address allow-list (repeatable / comma-separated). Empty = all' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -l max-routes -d 'Hard cap on eligible routes (rows). Unset = no cap' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -l maximum-paths -d 'Global ECMP cap (1..=256). Unset/1 = single next-hop' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -l maximum-paths-ebgp -d 'Per-class eBGP ECMP cap (overrides maximum_paths for eBGP)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -l maximum-paths-ibgp -d 'Per-class iBGP ECMP cap (overrides maximum_paths for iBGP)' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from set" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from delete" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from delete" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from delete" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from delete" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from delete" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from help" -f -a "list" -d 'List the configured FIB tables and runtime availability'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from help" -f -a "set" -d 'Create or replace a FIB table by name (full definition, not a patch)'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from help" -f -a "delete" -d 'Delete a FIB table by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand fib-table; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand completions" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand completions" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand completions" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand completions" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand completions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand man" -s s -l addr -d 'gRPC server address or unix:///path/to/socket' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand man" -l token-file -d 'Bearer token file for authenticated gRPC endpoints' -r
complete -c rbgp -n "__fish_rbgp_using_subcommand man" -s j -l json -d 'Output in JSON format'
complete -c rbgp -n "__fish_rbgp_using_subcommand man" -l no-color -d 'Disable colored output'
complete -c rbgp -n "__fish_rbgp_using_subcommand man" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "global" -d 'Show daemon global configuration'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "config" -d 'Runtime config diagnostics'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "neighbor" -d 'Manage BGP neighbors'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "bfd" -d 'Inspect single-hop BFD sessions (ADR-0067)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "rib" -d 'Query and manage the RIB'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "topology" -d 'Show the RFC 9107 ORR topology graph derived from BGP-LS'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "orr" -d 'Show RFC 9107 ORR per-vantage status (resolution, SPF reach, peers)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "diff" -d 'Compare live RIB views against an external snapshot (read-only)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "flowspec" -d 'Manage FlowSpec routes'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "evpn" -d 'Manage EVPN routes (list, add, delete — RFC 7432)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "watch" -d 'Watch route updates (streaming)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "events" -d 'Show recent route update events'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "health" -d 'Check daemon health'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "doctor" -d 'Run red/green triage checks and write a redacted support bundle'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "metrics" -d 'Show Prometheus metrics'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "shutdown" -d 'Request daemon shutdown'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "mrt-dump" -d 'Trigger an on-demand MRT dump'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "gshut" -d 'Toggle the RFC 8326 GRACEFUL_SHUTDOWN community on outbound updates'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "top" -d 'Live TUI dashboard'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "policy" -d 'Manage policy definitions and import/export chains'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "neighbor-set" -d 'Manage named neighbor sets used by policy'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "peer-group" -d 'Manage peer groups and neighbor membership'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "dynamic-neighbor" -d 'Manage dynamic-neighbor prefix ranges'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "fib-table" -d 'Manage general unicast FIB export tables at runtime'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "completions" -d 'Generate shell completions'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "man" -d 'Print the rbgp man page (roff) to stdout'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and not __fish_seen_subcommand_from global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "diff" -d 'Diff a candidate TOML file against the daemon\'s live runtime snapshot'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "plan" -d 'Validate and classify a candidate transaction without mutation'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "apply" -d 'Commit a previously planned candidate transaction'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "confirm" -d 'Confirm a pending confirmed config transaction'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "abort" -d 'Abort a pending confirmed config transaction and roll back immediately'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "status" -d 'Show pending or last confirmed-transaction lifecycle state'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from config" -f -a "effective" -d 'Dump the daemon\'s effective running config (defaults materialized)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "add" -d 'Add a new neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "delete" -d 'Delete this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "enable" -d 'Enable this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "disable" -d 'Disable this neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from neighbor" -f -a "softreset" -d 'Trigger soft reset (inbound)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from bfd" -f -a "list" -d 'List all BFD sessions (default)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from bfd" -f -a "show" -d 'Show a single BFD session by peer address'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "received" -d 'Show received routes from a neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "advertised" -d 'Show advertised routes to a neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "blackholes" -d 'Show RFC 7999 BLACKHOLE discard install status'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "fib" -d 'Show ADR-0061 general FIB route install status'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "bgpls" -d 'Show BGP-LS routes learned from peers (RFC 9552)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "vpn" -d 'Show VPNv4/VPNv6 routes learned from peers (RFC 4364/4659)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "labeled" -d 'Show IPv4/IPv6 labeled-unicast routes learned from peers (RFC 8277)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "rtc" -d 'Show RT-Constrain routes (RFC 4684, single IPv4 family)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "add" -d 'Inject a route'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from rib" -f -a "delete" -d 'Withdraw a route'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from topology" -f -a "nodes" -d 'List topology nodes (BGP-LS node identities across all peers)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from topology" -f -a "links" -d 'List usable directed topology links (with IGP metrics)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from diff" -f -a "advertised" -d 'Compare the live Adj-RIB-Out against an incumbent NDJSON snapshot'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from diff" -f -a "snapshot" -d 'Produce an `rbgp-ribsnap/1` snapshot from an incumbent\'s own output (offline; no daemon connection)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from flowspec" -f -a "add" -d 'Add a FlowSpec rule'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from flowspec" -f -a "delete" -d 'Delete a FlowSpec rule'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "list" -d 'List EVPN routes (default action — same as omitting the subcommand)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "add-mac-ip" -d 'Inject a Type 2 MAC/IP route'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "add-imet" -d 'Inject a Type 3 IMET route'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "add-ip-prefix" -d 'Inject a Type 5 IP Prefix route'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "delete-mac-ip" -d 'Withdraw a Type 2 MAC/IP route by its key fields'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "delete-imet" -d 'Withdraw a Type 3 IMET route by its key fields'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "delete-ip-prefix" -d 'Withdraw a Type 5 IP Prefix route by its key fields'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "clear-duplicate-mac" -d 'Clear one duplicate-MAC local-origin quarantine'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "es" -d 'Ethernet Segment runtime controls and diagnose state'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "runtime" -d 'Show the committed ADR-0063 EVPN runtime generation'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "instances" -d 'List local EVPN instances configured on this VTEP'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "nexthops" -d 'List rustbgpd-owned FDB nexthop groups (ADR-0059 aliasing ECMP)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "managed-netdevs" -d 'List managed EVPN netdev ownership/status rows (ADR-0091)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "vrfs" -d 'List configured IP-VRFs and their readiness verdict'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from evpn" -f -a "diagnose" -d 'Summarize EVPN VTEP alpha state and key metrics'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from events" -f -a "watch" -d 'Watch the unified live event stream'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from events" -f -a "sessions" -d 'Show recent session lifecycle events'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from events" -f -a "policy" -d 'Show recent policy / neighbor-set / peer-group / chain mutation events'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from events" -f -a "evpn" -d 'Show recent EVPN route events'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "list" -d 'List configured policies (names + statement counts)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "check" -d 'Check an `.rpol` policy file locally (parse, typecheck, tests)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "fmt" -d 'Format `.rpol` files in the one canonical style'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "test" -d 'Dry-run a candidate `.rpol` policy against the live RIB'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "get" -d 'Show one policy by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "set" -d 'Set (create or replace) a policy from a JSON file'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "delete" -d 'Delete a policy by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "chain" -d 'Manage global / per-neighbor import/export chains'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "stats" -d 'Show live per-term policy hit counters'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from policy" -f -a "explain" -d 'Explain the import-policy decision for a prefix on a neighbor'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from neighbor-set" -f -a "list" -d 'List configured neighbor sets'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from neighbor-set" -f -a "get" -d 'Show one neighbor set by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from neighbor-set" -f -a "set" -d 'Set (create or replace) a neighbor set from a JSON file'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from neighbor-set" -f -a "delete" -d 'Delete a neighbor set'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from peer-group" -f -a "list" -d 'List configured peer groups'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from peer-group" -f -a "get" -d 'Show one peer group by name'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from peer-group" -f -a "set" -d 'Set (create or replace) a peer group from a JSON file'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from peer-group" -f -a "delete" -d 'Delete a peer group'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from peer-group" -f -a "attach" -d 'Bind a neighbor to a peer group'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from peer-group" -f -a "detach" -d 'Unbind a neighbor from its peer group'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from dynamic-neighbor" -f -a "list" -d 'List configured dynamic neighbor ranges'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from dynamic-neighbor" -f -a "add" -d 'Add a dynamic neighbor range'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from dynamic-neighbor" -f -a "delete" -d 'Delete a dynamic neighbor range by prefix'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from fib-table" -f -a "list" -d 'List the configured FIB tables and runtime availability'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from fib-table" -f -a "set" -d 'Create or replace a FIB table by name (full definition, not a patch)'
complete -c rbgp -n "__fish_rbgp_using_subcommand help; and __fish_seen_subcommand_from fib-table" -f -a "delete" -d 'Delete a FIB table by name'
