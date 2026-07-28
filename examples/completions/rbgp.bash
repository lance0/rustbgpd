_rbgp() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="rbgp"
                ;;
            rbgp,bfd)
                cmd="rbgp__subcmd__bfd"
                ;;
            rbgp,completions)
                cmd="rbgp__subcmd__completions"
                ;;
            rbgp,config)
                cmd="rbgp__subcmd__config"
                ;;
            rbgp,diff)
                cmd="rbgp__subcmd__diff"
                ;;
            rbgp,doctor)
                cmd="rbgp__subcmd__doctor"
                ;;
            rbgp,dynamic-neighbor)
                cmd="rbgp__subcmd__dynamic__subcmd__neighbor"
                ;;
            rbgp,events)
                cmd="rbgp__subcmd__events"
                ;;
            rbgp,evpn)
                cmd="rbgp__subcmd__evpn"
                ;;
            rbgp,fib-table)
                cmd="rbgp__subcmd__fib__subcmd__table"
                ;;
            rbgp,flowspec)
                cmd="rbgp__subcmd__flowspec"
                ;;
            rbgp,global)
                cmd="rbgp__subcmd__global"
                ;;
            rbgp,gshut)
                cmd="rbgp__subcmd__gshut"
                ;;
            rbgp,health)
                cmd="rbgp__subcmd__health"
                ;;
            rbgp,help)
                cmd="rbgp__subcmd__help"
                ;;
            rbgp,man)
                cmd="rbgp__subcmd__man"
                ;;
            rbgp,metrics)
                cmd="rbgp__subcmd__metrics"
                ;;
            rbgp,mrt-dump)
                cmd="rbgp__subcmd__mrt__subcmd__dump"
                ;;
            rbgp,neighbor)
                cmd="rbgp__subcmd__neighbor"
                ;;
            rbgp,neighbor-set)
                cmd="rbgp__subcmd__neighbor__subcmd__set"
                ;;
            rbgp,orr)
                cmd="rbgp__subcmd__orr"
                ;;
            rbgp,peer-group)
                cmd="rbgp__subcmd__peer__subcmd__group"
                ;;
            rbgp,policy)
                cmd="rbgp__subcmd__policy"
                ;;
            rbgp,rib)
                cmd="rbgp__subcmd__rib"
                ;;
            rbgp,shutdown)
                cmd="rbgp__subcmd__shutdown"
                ;;
            rbgp,summary)
                cmd="rbgp__subcmd__neighbor"
                ;;
            rbgp,top)
                cmd="rbgp__subcmd__top"
                ;;
            rbgp,topology)
                cmd="rbgp__subcmd__topology"
                ;;
            rbgp,watch)
                cmd="rbgp__subcmd__watch"
                ;;
            rbgp__subcmd__bfd,help)
                cmd="rbgp__subcmd__bfd__subcmd__help"
                ;;
            rbgp__subcmd__bfd,list)
                cmd="rbgp__subcmd__bfd__subcmd__list"
                ;;
            rbgp__subcmd__bfd,show)
                cmd="rbgp__subcmd__bfd__subcmd__show"
                ;;
            rbgp__subcmd__bfd__subcmd__help,help)
                cmd="rbgp__subcmd__bfd__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__bfd__subcmd__help,list)
                cmd="rbgp__subcmd__bfd__subcmd__help__subcmd__list"
                ;;
            rbgp__subcmd__bfd__subcmd__help,show)
                cmd="rbgp__subcmd__bfd__subcmd__help__subcmd__show"
                ;;
            rbgp__subcmd__config,abort)
                cmd="rbgp__subcmd__config__subcmd__abort"
                ;;
            rbgp__subcmd__config,apply)
                cmd="rbgp__subcmd__config__subcmd__apply"
                ;;
            rbgp__subcmd__config,confirm)
                cmd="rbgp__subcmd__config__subcmd__confirm"
                ;;
            rbgp__subcmd__config,diff)
                cmd="rbgp__subcmd__config__subcmd__diff"
                ;;
            rbgp__subcmd__config,effective)
                cmd="rbgp__subcmd__config__subcmd__effective"
                ;;
            rbgp__subcmd__config,help)
                cmd="rbgp__subcmd__config__subcmd__help"
                ;;
            rbgp__subcmd__config,history)
                cmd="rbgp__subcmd__config__subcmd__history"
                ;;
            rbgp__subcmd__config,import)
                cmd="rbgp__subcmd__config__subcmd__import"
                ;;
            rbgp__subcmd__config,plan)
                cmd="rbgp__subcmd__config__subcmd__plan"
                ;;
            rbgp__subcmd__config,rollback)
                cmd="rbgp__subcmd__config__subcmd__rollback"
                ;;
            rbgp__subcmd__config,status)
                cmd="rbgp__subcmd__config__subcmd__status"
                ;;
            rbgp__subcmd__config__subcmd__help,abort)
                cmd="rbgp__subcmd__config__subcmd__help__subcmd__abort"
                ;;
            rbgp__subcmd__config__subcmd__help,apply)
                cmd="rbgp__subcmd__config__subcmd__help__subcmd__apply"
                ;;
            rbgp__subcmd__config__subcmd__help,confirm)
                cmd="rbgp__subcmd__config__subcmd__help__subcmd__confirm"
                ;;
            rbgp__subcmd__config__subcmd__help,diff)
                cmd="rbgp__subcmd__config__subcmd__help__subcmd__diff"
                ;;
            rbgp__subcmd__config__subcmd__help,effective)
                cmd="rbgp__subcmd__config__subcmd__help__subcmd__effective"
                ;;
            rbgp__subcmd__config__subcmd__help,help)
                cmd="rbgp__subcmd__config__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__config__subcmd__help,history)
                cmd="rbgp__subcmd__config__subcmd__help__subcmd__history"
                ;;
            rbgp__subcmd__config__subcmd__help,import)
                cmd="rbgp__subcmd__config__subcmd__help__subcmd__import"
                ;;
            rbgp__subcmd__config__subcmd__help,plan)
                cmd="rbgp__subcmd__config__subcmd__help__subcmd__plan"
                ;;
            rbgp__subcmd__config__subcmd__help,rollback)
                cmd="rbgp__subcmd__config__subcmd__help__subcmd__rollback"
                ;;
            rbgp__subcmd__config__subcmd__help,status)
                cmd="rbgp__subcmd__config__subcmd__help__subcmd__status"
                ;;
            rbgp__subcmd__diff,advertised)
                cmd="rbgp__subcmd__diff__subcmd__advertised"
                ;;
            rbgp__subcmd__diff,help)
                cmd="rbgp__subcmd__diff__subcmd__help"
                ;;
            rbgp__subcmd__diff,snapshot)
                cmd="rbgp__subcmd__diff__subcmd__snapshot"
                ;;
            rbgp__subcmd__diff__subcmd__help,advertised)
                cmd="rbgp__subcmd__diff__subcmd__help__subcmd__advertised"
                ;;
            rbgp__subcmd__diff__subcmd__help,help)
                cmd="rbgp__subcmd__diff__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__diff__subcmd__help,snapshot)
                cmd="rbgp__subcmd__diff__subcmd__help__subcmd__snapshot"
                ;;
            rbgp__subcmd__diff__subcmd__help__subcmd__snapshot,from-bmp)
                cmd="rbgp__subcmd__diff__subcmd__help__subcmd__snapshot__subcmd__from__subcmd__bmp"
                ;;
            rbgp__subcmd__diff__subcmd__help__subcmd__snapshot,from-mrt)
                cmd="rbgp__subcmd__diff__subcmd__help__subcmd__snapshot__subcmd__from__subcmd__mrt"
                ;;
            rbgp__subcmd__diff__subcmd__snapshot,from-bmp)
                cmd="rbgp__subcmd__diff__subcmd__snapshot__subcmd__from__subcmd__bmp"
                ;;
            rbgp__subcmd__diff__subcmd__snapshot,from-mrt)
                cmd="rbgp__subcmd__diff__subcmd__snapshot__subcmd__from__subcmd__mrt"
                ;;
            rbgp__subcmd__diff__subcmd__snapshot,help)
                cmd="rbgp__subcmd__diff__subcmd__snapshot__subcmd__help"
                ;;
            rbgp__subcmd__diff__subcmd__snapshot__subcmd__help,from-bmp)
                cmd="rbgp__subcmd__diff__subcmd__snapshot__subcmd__help__subcmd__from__subcmd__bmp"
                ;;
            rbgp__subcmd__diff__subcmd__snapshot__subcmd__help,from-mrt)
                cmd="rbgp__subcmd__diff__subcmd__snapshot__subcmd__help__subcmd__from__subcmd__mrt"
                ;;
            rbgp__subcmd__diff__subcmd__snapshot__subcmd__help,help)
                cmd="rbgp__subcmd__diff__subcmd__snapshot__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__dynamic__subcmd__neighbor,add)
                cmd="rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__add"
                ;;
            rbgp__subcmd__dynamic__subcmd__neighbor,delete)
                cmd="rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__delete"
                ;;
            rbgp__subcmd__dynamic__subcmd__neighbor,help)
                cmd="rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help"
                ;;
            rbgp__subcmd__dynamic__subcmd__neighbor,list)
                cmd="rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__list"
                ;;
            rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help,add)
                cmd="rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help__subcmd__add"
                ;;
            rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help,delete)
                cmd="rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help__subcmd__delete"
                ;;
            rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help,help)
                cmd="rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help,list)
                cmd="rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help__subcmd__list"
                ;;
            rbgp__subcmd__events,evpn)
                cmd="rbgp__subcmd__events__subcmd__evpn"
                ;;
            rbgp__subcmd__events,help)
                cmd="rbgp__subcmd__events__subcmd__help"
                ;;
            rbgp__subcmd__events,policy)
                cmd="rbgp__subcmd__events__subcmd__policy"
                ;;
            rbgp__subcmd__events,sessions)
                cmd="rbgp__subcmd__events__subcmd__sessions"
                ;;
            rbgp__subcmd__events,watch)
                cmd="rbgp__subcmd__events__subcmd__watch"
                ;;
            rbgp__subcmd__events__subcmd__help,evpn)
                cmd="rbgp__subcmd__events__subcmd__help__subcmd__evpn"
                ;;
            rbgp__subcmd__events__subcmd__help,help)
                cmd="rbgp__subcmd__events__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__events__subcmd__help,policy)
                cmd="rbgp__subcmd__events__subcmd__help__subcmd__policy"
                ;;
            rbgp__subcmd__events__subcmd__help,sessions)
                cmd="rbgp__subcmd__events__subcmd__help__subcmd__sessions"
                ;;
            rbgp__subcmd__events__subcmd__help,watch)
                cmd="rbgp__subcmd__events__subcmd__help__subcmd__watch"
                ;;
            rbgp__subcmd__evpn,add-imet)
                cmd="rbgp__subcmd__evpn__subcmd__add__subcmd__imet"
                ;;
            rbgp__subcmd__evpn,add-ip-prefix)
                cmd="rbgp__subcmd__evpn__subcmd__add__subcmd__ip__subcmd__prefix"
                ;;
            rbgp__subcmd__evpn,add-mac-ip)
                cmd="rbgp__subcmd__evpn__subcmd__add__subcmd__mac__subcmd__ip"
                ;;
            rbgp__subcmd__evpn,clear-duplicate-mac)
                cmd="rbgp__subcmd__evpn__subcmd__clear__subcmd__duplicate__subcmd__mac"
                ;;
            rbgp__subcmd__evpn,delete-imet)
                cmd="rbgp__subcmd__evpn__subcmd__delete__subcmd__imet"
                ;;
            rbgp__subcmd__evpn,delete-ip-prefix)
                cmd="rbgp__subcmd__evpn__subcmd__delete__subcmd__ip__subcmd__prefix"
                ;;
            rbgp__subcmd__evpn,delete-mac-ip)
                cmd="rbgp__subcmd__evpn__subcmd__delete__subcmd__mac__subcmd__ip"
                ;;
            rbgp__subcmd__evpn,diagnose)
                cmd="rbgp__subcmd__evpn__subcmd__diagnose"
                ;;
            rbgp__subcmd__evpn,es)
                cmd="rbgp__subcmd__evpn__subcmd__es"
                ;;
            rbgp__subcmd__evpn,help)
                cmd="rbgp__subcmd__evpn__subcmd__help"
                ;;
            rbgp__subcmd__evpn,instances)
                cmd="rbgp__subcmd__evpn__subcmd__instances"
                ;;
            rbgp__subcmd__evpn,list)
                cmd="rbgp__subcmd__evpn__subcmd__list"
                ;;
            rbgp__subcmd__evpn,managed-netdevs)
                cmd="rbgp__subcmd__evpn__subcmd__managed__subcmd__netdevs"
                ;;
            rbgp__subcmd__evpn,nexthops)
                cmd="rbgp__subcmd__evpn__subcmd__nexthops"
                ;;
            rbgp__subcmd__evpn,runtime)
                cmd="rbgp__subcmd__evpn__subcmd__runtime"
                ;;
            rbgp__subcmd__evpn,vrfs)
                cmd="rbgp__subcmd__evpn__subcmd__vrfs"
                ;;
            rbgp__subcmd__evpn__subcmd__es,drain)
                cmd="rbgp__subcmd__evpn__subcmd__es__subcmd__drain"
                ;;
            rbgp__subcmd__evpn__subcmd__es,help)
                cmd="rbgp__subcmd__evpn__subcmd__es__subcmd__help"
                ;;
            rbgp__subcmd__evpn__subcmd__es,list)
                cmd="rbgp__subcmd__evpn__subcmd__es__subcmd__list"
                ;;
            rbgp__subcmd__evpn__subcmd__es,undrain)
                cmd="rbgp__subcmd__evpn__subcmd__es__subcmd__undrain"
                ;;
            rbgp__subcmd__evpn__subcmd__es__subcmd__help,drain)
                cmd="rbgp__subcmd__evpn__subcmd__es__subcmd__help__subcmd__drain"
                ;;
            rbgp__subcmd__evpn__subcmd__es__subcmd__help,help)
                cmd="rbgp__subcmd__evpn__subcmd__es__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__evpn__subcmd__es__subcmd__help,list)
                cmd="rbgp__subcmd__evpn__subcmd__es__subcmd__help__subcmd__list"
                ;;
            rbgp__subcmd__evpn__subcmd__es__subcmd__help,undrain)
                cmd="rbgp__subcmd__evpn__subcmd__es__subcmd__help__subcmd__undrain"
                ;;
            rbgp__subcmd__evpn__subcmd__help,add-imet)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__add__subcmd__imet"
                ;;
            rbgp__subcmd__evpn__subcmd__help,add-ip-prefix)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__add__subcmd__ip__subcmd__prefix"
                ;;
            rbgp__subcmd__evpn__subcmd__help,add-mac-ip)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__add__subcmd__mac__subcmd__ip"
                ;;
            rbgp__subcmd__evpn__subcmd__help,clear-duplicate-mac)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__clear__subcmd__duplicate__subcmd__mac"
                ;;
            rbgp__subcmd__evpn__subcmd__help,delete-imet)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__delete__subcmd__imet"
                ;;
            rbgp__subcmd__evpn__subcmd__help,delete-ip-prefix)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__delete__subcmd__ip__subcmd__prefix"
                ;;
            rbgp__subcmd__evpn__subcmd__help,delete-mac-ip)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__delete__subcmd__mac__subcmd__ip"
                ;;
            rbgp__subcmd__evpn__subcmd__help,diagnose)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__diagnose"
                ;;
            rbgp__subcmd__evpn__subcmd__help,es)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__es"
                ;;
            rbgp__subcmd__evpn__subcmd__help,help)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__evpn__subcmd__help,instances)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__instances"
                ;;
            rbgp__subcmd__evpn__subcmd__help,list)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__list"
                ;;
            rbgp__subcmd__evpn__subcmd__help,managed-netdevs)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__managed__subcmd__netdevs"
                ;;
            rbgp__subcmd__evpn__subcmd__help,nexthops)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__nexthops"
                ;;
            rbgp__subcmd__evpn__subcmd__help,runtime)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__runtime"
                ;;
            rbgp__subcmd__evpn__subcmd__help,vrfs)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__vrfs"
                ;;
            rbgp__subcmd__evpn__subcmd__help__subcmd__es,drain)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__es__subcmd__drain"
                ;;
            rbgp__subcmd__evpn__subcmd__help__subcmd__es,list)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__es__subcmd__list"
                ;;
            rbgp__subcmd__evpn__subcmd__help__subcmd__es,undrain)
                cmd="rbgp__subcmd__evpn__subcmd__help__subcmd__es__subcmd__undrain"
                ;;
            rbgp__subcmd__fib__subcmd__table,delete)
                cmd="rbgp__subcmd__fib__subcmd__table__subcmd__delete"
                ;;
            rbgp__subcmd__fib__subcmd__table,help)
                cmd="rbgp__subcmd__fib__subcmd__table__subcmd__help"
                ;;
            rbgp__subcmd__fib__subcmd__table,list)
                cmd="rbgp__subcmd__fib__subcmd__table__subcmd__list"
                ;;
            rbgp__subcmd__fib__subcmd__table,set)
                cmd="rbgp__subcmd__fib__subcmd__table__subcmd__set"
                ;;
            rbgp__subcmd__fib__subcmd__table__subcmd__help,delete)
                cmd="rbgp__subcmd__fib__subcmd__table__subcmd__help__subcmd__delete"
                ;;
            rbgp__subcmd__fib__subcmd__table__subcmd__help,help)
                cmd="rbgp__subcmd__fib__subcmd__table__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__fib__subcmd__table__subcmd__help,list)
                cmd="rbgp__subcmd__fib__subcmd__table__subcmd__help__subcmd__list"
                ;;
            rbgp__subcmd__fib__subcmd__table__subcmd__help,set)
                cmd="rbgp__subcmd__fib__subcmd__table__subcmd__help__subcmd__set"
                ;;
            rbgp__subcmd__flowspec,add)
                cmd="rbgp__subcmd__flowspec__subcmd__add"
                ;;
            rbgp__subcmd__flowspec,delete)
                cmd="rbgp__subcmd__flowspec__subcmd__delete"
                ;;
            rbgp__subcmd__flowspec,help)
                cmd="rbgp__subcmd__flowspec__subcmd__help"
                ;;
            rbgp__subcmd__flowspec__subcmd__help,add)
                cmd="rbgp__subcmd__flowspec__subcmd__help__subcmd__add"
                ;;
            rbgp__subcmd__flowspec__subcmd__help,delete)
                cmd="rbgp__subcmd__flowspec__subcmd__help__subcmd__delete"
                ;;
            rbgp__subcmd__flowspec__subcmd__help,help)
                cmd="rbgp__subcmd__flowspec__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__help,bfd)
                cmd="rbgp__subcmd__help__subcmd__bfd"
                ;;
            rbgp__subcmd__help,completions)
                cmd="rbgp__subcmd__help__subcmd__completions"
                ;;
            rbgp__subcmd__help,config)
                cmd="rbgp__subcmd__help__subcmd__config"
                ;;
            rbgp__subcmd__help,diff)
                cmd="rbgp__subcmd__help__subcmd__diff"
                ;;
            rbgp__subcmd__help,doctor)
                cmd="rbgp__subcmd__help__subcmd__doctor"
                ;;
            rbgp__subcmd__help,dynamic-neighbor)
                cmd="rbgp__subcmd__help__subcmd__dynamic__subcmd__neighbor"
                ;;
            rbgp__subcmd__help,events)
                cmd="rbgp__subcmd__help__subcmd__events"
                ;;
            rbgp__subcmd__help,evpn)
                cmd="rbgp__subcmd__help__subcmd__evpn"
                ;;
            rbgp__subcmd__help,fib-table)
                cmd="rbgp__subcmd__help__subcmd__fib__subcmd__table"
                ;;
            rbgp__subcmd__help,flowspec)
                cmd="rbgp__subcmd__help__subcmd__flowspec"
                ;;
            rbgp__subcmd__help,global)
                cmd="rbgp__subcmd__help__subcmd__global"
                ;;
            rbgp__subcmd__help,gshut)
                cmd="rbgp__subcmd__help__subcmd__gshut"
                ;;
            rbgp__subcmd__help,health)
                cmd="rbgp__subcmd__help__subcmd__health"
                ;;
            rbgp__subcmd__help,help)
                cmd="rbgp__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__help,man)
                cmd="rbgp__subcmd__help__subcmd__man"
                ;;
            rbgp__subcmd__help,metrics)
                cmd="rbgp__subcmd__help__subcmd__metrics"
                ;;
            rbgp__subcmd__help,mrt-dump)
                cmd="rbgp__subcmd__help__subcmd__mrt__subcmd__dump"
                ;;
            rbgp__subcmd__help,neighbor)
                cmd="rbgp__subcmd__help__subcmd__neighbor"
                ;;
            rbgp__subcmd__help,neighbor-set)
                cmd="rbgp__subcmd__help__subcmd__neighbor__subcmd__set"
                ;;
            rbgp__subcmd__help,orr)
                cmd="rbgp__subcmd__help__subcmd__orr"
                ;;
            rbgp__subcmd__help,peer-group)
                cmd="rbgp__subcmd__help__subcmd__peer__subcmd__group"
                ;;
            rbgp__subcmd__help,policy)
                cmd="rbgp__subcmd__help__subcmd__policy"
                ;;
            rbgp__subcmd__help,rib)
                cmd="rbgp__subcmd__help__subcmd__rib"
                ;;
            rbgp__subcmd__help,shutdown)
                cmd="rbgp__subcmd__help__subcmd__shutdown"
                ;;
            rbgp__subcmd__help,top)
                cmd="rbgp__subcmd__help__subcmd__top"
                ;;
            rbgp__subcmd__help,topology)
                cmd="rbgp__subcmd__help__subcmd__topology"
                ;;
            rbgp__subcmd__help,watch)
                cmd="rbgp__subcmd__help__subcmd__watch"
                ;;
            rbgp__subcmd__help__subcmd__bfd,list)
                cmd="rbgp__subcmd__help__subcmd__bfd__subcmd__list"
                ;;
            rbgp__subcmd__help__subcmd__bfd,show)
                cmd="rbgp__subcmd__help__subcmd__bfd__subcmd__show"
                ;;
            rbgp__subcmd__help__subcmd__config,abort)
                cmd="rbgp__subcmd__help__subcmd__config__subcmd__abort"
                ;;
            rbgp__subcmd__help__subcmd__config,apply)
                cmd="rbgp__subcmd__help__subcmd__config__subcmd__apply"
                ;;
            rbgp__subcmd__help__subcmd__config,confirm)
                cmd="rbgp__subcmd__help__subcmd__config__subcmd__confirm"
                ;;
            rbgp__subcmd__help__subcmd__config,diff)
                cmd="rbgp__subcmd__help__subcmd__config__subcmd__diff"
                ;;
            rbgp__subcmd__help__subcmd__config,effective)
                cmd="rbgp__subcmd__help__subcmd__config__subcmd__effective"
                ;;
            rbgp__subcmd__help__subcmd__config,history)
                cmd="rbgp__subcmd__help__subcmd__config__subcmd__history"
                ;;
            rbgp__subcmd__help__subcmd__config,import)
                cmd="rbgp__subcmd__help__subcmd__config__subcmd__import"
                ;;
            rbgp__subcmd__help__subcmd__config,plan)
                cmd="rbgp__subcmd__help__subcmd__config__subcmd__plan"
                ;;
            rbgp__subcmd__help__subcmd__config,rollback)
                cmd="rbgp__subcmd__help__subcmd__config__subcmd__rollback"
                ;;
            rbgp__subcmd__help__subcmd__config,status)
                cmd="rbgp__subcmd__help__subcmd__config__subcmd__status"
                ;;
            rbgp__subcmd__help__subcmd__diff,advertised)
                cmd="rbgp__subcmd__help__subcmd__diff__subcmd__advertised"
                ;;
            rbgp__subcmd__help__subcmd__diff,snapshot)
                cmd="rbgp__subcmd__help__subcmd__diff__subcmd__snapshot"
                ;;
            rbgp__subcmd__help__subcmd__diff__subcmd__snapshot,from-bmp)
                cmd="rbgp__subcmd__help__subcmd__diff__subcmd__snapshot__subcmd__from__subcmd__bmp"
                ;;
            rbgp__subcmd__help__subcmd__diff__subcmd__snapshot,from-mrt)
                cmd="rbgp__subcmd__help__subcmd__diff__subcmd__snapshot__subcmd__from__subcmd__mrt"
                ;;
            rbgp__subcmd__help__subcmd__dynamic__subcmd__neighbor,add)
                cmd="rbgp__subcmd__help__subcmd__dynamic__subcmd__neighbor__subcmd__add"
                ;;
            rbgp__subcmd__help__subcmd__dynamic__subcmd__neighbor,delete)
                cmd="rbgp__subcmd__help__subcmd__dynamic__subcmd__neighbor__subcmd__delete"
                ;;
            rbgp__subcmd__help__subcmd__dynamic__subcmd__neighbor,list)
                cmd="rbgp__subcmd__help__subcmd__dynamic__subcmd__neighbor__subcmd__list"
                ;;
            rbgp__subcmd__help__subcmd__events,evpn)
                cmd="rbgp__subcmd__help__subcmd__events__subcmd__evpn"
                ;;
            rbgp__subcmd__help__subcmd__events,policy)
                cmd="rbgp__subcmd__help__subcmd__events__subcmd__policy"
                ;;
            rbgp__subcmd__help__subcmd__events,sessions)
                cmd="rbgp__subcmd__help__subcmd__events__subcmd__sessions"
                ;;
            rbgp__subcmd__help__subcmd__events,watch)
                cmd="rbgp__subcmd__help__subcmd__events__subcmd__watch"
                ;;
            rbgp__subcmd__help__subcmd__evpn,add-imet)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__add__subcmd__imet"
                ;;
            rbgp__subcmd__help__subcmd__evpn,add-ip-prefix)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__add__subcmd__ip__subcmd__prefix"
                ;;
            rbgp__subcmd__help__subcmd__evpn,add-mac-ip)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__add__subcmd__mac__subcmd__ip"
                ;;
            rbgp__subcmd__help__subcmd__evpn,clear-duplicate-mac)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__clear__subcmd__duplicate__subcmd__mac"
                ;;
            rbgp__subcmd__help__subcmd__evpn,delete-imet)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__delete__subcmd__imet"
                ;;
            rbgp__subcmd__help__subcmd__evpn,delete-ip-prefix)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__delete__subcmd__ip__subcmd__prefix"
                ;;
            rbgp__subcmd__help__subcmd__evpn,delete-mac-ip)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__delete__subcmd__mac__subcmd__ip"
                ;;
            rbgp__subcmd__help__subcmd__evpn,diagnose)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__diagnose"
                ;;
            rbgp__subcmd__help__subcmd__evpn,es)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__es"
                ;;
            rbgp__subcmd__help__subcmd__evpn,instances)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__instances"
                ;;
            rbgp__subcmd__help__subcmd__evpn,list)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__list"
                ;;
            rbgp__subcmd__help__subcmd__evpn,managed-netdevs)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__managed__subcmd__netdevs"
                ;;
            rbgp__subcmd__help__subcmd__evpn,nexthops)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__nexthops"
                ;;
            rbgp__subcmd__help__subcmd__evpn,runtime)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__runtime"
                ;;
            rbgp__subcmd__help__subcmd__evpn,vrfs)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__vrfs"
                ;;
            rbgp__subcmd__help__subcmd__evpn__subcmd__es,drain)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__es__subcmd__drain"
                ;;
            rbgp__subcmd__help__subcmd__evpn__subcmd__es,list)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__es__subcmd__list"
                ;;
            rbgp__subcmd__help__subcmd__evpn__subcmd__es,undrain)
                cmd="rbgp__subcmd__help__subcmd__evpn__subcmd__es__subcmd__undrain"
                ;;
            rbgp__subcmd__help__subcmd__fib__subcmd__table,delete)
                cmd="rbgp__subcmd__help__subcmd__fib__subcmd__table__subcmd__delete"
                ;;
            rbgp__subcmd__help__subcmd__fib__subcmd__table,list)
                cmd="rbgp__subcmd__help__subcmd__fib__subcmd__table__subcmd__list"
                ;;
            rbgp__subcmd__help__subcmd__fib__subcmd__table,set)
                cmd="rbgp__subcmd__help__subcmd__fib__subcmd__table__subcmd__set"
                ;;
            rbgp__subcmd__help__subcmd__flowspec,add)
                cmd="rbgp__subcmd__help__subcmd__flowspec__subcmd__add"
                ;;
            rbgp__subcmd__help__subcmd__flowspec,delete)
                cmd="rbgp__subcmd__help__subcmd__flowspec__subcmd__delete"
                ;;
            rbgp__subcmd__help__subcmd__neighbor,add)
                cmd="rbgp__subcmd__help__subcmd__neighbor__subcmd__add"
                ;;
            rbgp__subcmd__help__subcmd__neighbor,delete)
                cmd="rbgp__subcmd__help__subcmd__neighbor__subcmd__delete"
                ;;
            rbgp__subcmd__help__subcmd__neighbor,disable)
                cmd="rbgp__subcmd__help__subcmd__neighbor__subcmd__disable"
                ;;
            rbgp__subcmd__help__subcmd__neighbor,enable)
                cmd="rbgp__subcmd__help__subcmd__neighbor__subcmd__enable"
                ;;
            rbgp__subcmd__help__subcmd__neighbor,refresh-out)
                cmd="rbgp__subcmd__help__subcmd__neighbor__subcmd__refresh__subcmd__out"
                ;;
            rbgp__subcmd__help__subcmd__neighbor,softreset)
                cmd="rbgp__subcmd__help__subcmd__neighbor__subcmd__softreset"
                ;;
            rbgp__subcmd__help__subcmd__neighbor__subcmd__set,delete)
                cmd="rbgp__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__delete"
                ;;
            rbgp__subcmd__help__subcmd__neighbor__subcmd__set,get)
                cmd="rbgp__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__get"
                ;;
            rbgp__subcmd__help__subcmd__neighbor__subcmd__set,list)
                cmd="rbgp__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__list"
                ;;
            rbgp__subcmd__help__subcmd__neighbor__subcmd__set,set)
                cmd="rbgp__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__set"
                ;;
            rbgp__subcmd__help__subcmd__peer__subcmd__group,attach)
                cmd="rbgp__subcmd__help__subcmd__peer__subcmd__group__subcmd__attach"
                ;;
            rbgp__subcmd__help__subcmd__peer__subcmd__group,delete)
                cmd="rbgp__subcmd__help__subcmd__peer__subcmd__group__subcmd__delete"
                ;;
            rbgp__subcmd__help__subcmd__peer__subcmd__group,detach)
                cmd="rbgp__subcmd__help__subcmd__peer__subcmd__group__subcmd__detach"
                ;;
            rbgp__subcmd__help__subcmd__peer__subcmd__group,get)
                cmd="rbgp__subcmd__help__subcmd__peer__subcmd__group__subcmd__get"
                ;;
            rbgp__subcmd__help__subcmd__peer__subcmd__group,list)
                cmd="rbgp__subcmd__help__subcmd__peer__subcmd__group__subcmd__list"
                ;;
            rbgp__subcmd__help__subcmd__peer__subcmd__group,set)
                cmd="rbgp__subcmd__help__subcmd__peer__subcmd__group__subcmd__set"
                ;;
            rbgp__subcmd__help__subcmd__policy,chain)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__chain"
                ;;
            rbgp__subcmd__help__subcmd__policy,check)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__check"
                ;;
            rbgp__subcmd__help__subcmd__policy,delete)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__delete"
                ;;
            rbgp__subcmd__help__subcmd__policy,explain)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__explain"
                ;;
            rbgp__subcmd__help__subcmd__policy,fmt)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__fmt"
                ;;
            rbgp__subcmd__help__subcmd__policy,get)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__get"
                ;;
            rbgp__subcmd__help__subcmd__policy,list)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__list"
                ;;
            rbgp__subcmd__help__subcmd__policy,set)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__set"
                ;;
            rbgp__subcmd__help__subcmd__policy,stats)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__stats"
                ;;
            rbgp__subcmd__help__subcmd__policy,test)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__test"
                ;;
            rbgp__subcmd__help__subcmd__policy__subcmd__chain,clear-export)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__export"
                ;;
            rbgp__subcmd__help__subcmd__policy__subcmd__chain,clear-import)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__import"
                ;;
            rbgp__subcmd__help__subcmd__policy__subcmd__chain,set-export)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__chain__subcmd__set__subcmd__export"
                ;;
            rbgp__subcmd__help__subcmd__policy__subcmd__chain,set-import)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__chain__subcmd__set__subcmd__import"
                ;;
            rbgp__subcmd__help__subcmd__policy__subcmd__chain,show)
                cmd="rbgp__subcmd__help__subcmd__policy__subcmd__chain__subcmd__show"
                ;;
            rbgp__subcmd__help__subcmd__rib,add)
                cmd="rbgp__subcmd__help__subcmd__rib__subcmd__add"
                ;;
            rbgp__subcmd__help__subcmd__rib,advertised)
                cmd="rbgp__subcmd__help__subcmd__rib__subcmd__advertised"
                ;;
            rbgp__subcmd__help__subcmd__rib,bgpls)
                cmd="rbgp__subcmd__help__subcmd__rib__subcmd__bgpls"
                ;;
            rbgp__subcmd__help__subcmd__rib,blackholes)
                cmd="rbgp__subcmd__help__subcmd__rib__subcmd__blackholes"
                ;;
            rbgp__subcmd__help__subcmd__rib,delete)
                cmd="rbgp__subcmd__help__subcmd__rib__subcmd__delete"
                ;;
            rbgp__subcmd__help__subcmd__rib,fib)
                cmd="rbgp__subcmd__help__subcmd__rib__subcmd__fib"
                ;;
            rbgp__subcmd__help__subcmd__rib,labeled)
                cmd="rbgp__subcmd__help__subcmd__rib__subcmd__labeled"
                ;;
            rbgp__subcmd__help__subcmd__rib,received)
                cmd="rbgp__subcmd__help__subcmd__rib__subcmd__received"
                ;;
            rbgp__subcmd__help__subcmd__rib,rtc)
                cmd="rbgp__subcmd__help__subcmd__rib__subcmd__rtc"
                ;;
            rbgp__subcmd__help__subcmd__rib,vpn)
                cmd="rbgp__subcmd__help__subcmd__rib__subcmd__vpn"
                ;;
            rbgp__subcmd__help__subcmd__topology,links)
                cmd="rbgp__subcmd__help__subcmd__topology__subcmd__links"
                ;;
            rbgp__subcmd__help__subcmd__topology,nodes)
                cmd="rbgp__subcmd__help__subcmd__topology__subcmd__nodes"
                ;;
            rbgp__subcmd__neighbor,add)
                cmd="rbgp__subcmd__neighbor__subcmd__add"
                ;;
            rbgp__subcmd__neighbor,delete)
                cmd="rbgp__subcmd__neighbor__subcmd__delete"
                ;;
            rbgp__subcmd__neighbor,disable)
                cmd="rbgp__subcmd__neighbor__subcmd__disable"
                ;;
            rbgp__subcmd__neighbor,enable)
                cmd="rbgp__subcmd__neighbor__subcmd__enable"
                ;;
            rbgp__subcmd__neighbor,help)
                cmd="rbgp__subcmd__neighbor__subcmd__help"
                ;;
            rbgp__subcmd__neighbor,refresh-out)
                cmd="rbgp__subcmd__neighbor__subcmd__refresh__subcmd__out"
                ;;
            rbgp__subcmd__neighbor,softreset)
                cmd="rbgp__subcmd__neighbor__subcmd__softreset"
                ;;
            rbgp__subcmd__neighbor__subcmd__help,add)
                cmd="rbgp__subcmd__neighbor__subcmd__help__subcmd__add"
                ;;
            rbgp__subcmd__neighbor__subcmd__help,delete)
                cmd="rbgp__subcmd__neighbor__subcmd__help__subcmd__delete"
                ;;
            rbgp__subcmd__neighbor__subcmd__help,disable)
                cmd="rbgp__subcmd__neighbor__subcmd__help__subcmd__disable"
                ;;
            rbgp__subcmd__neighbor__subcmd__help,enable)
                cmd="rbgp__subcmd__neighbor__subcmd__help__subcmd__enable"
                ;;
            rbgp__subcmd__neighbor__subcmd__help,help)
                cmd="rbgp__subcmd__neighbor__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__neighbor__subcmd__help,refresh-out)
                cmd="rbgp__subcmd__neighbor__subcmd__help__subcmd__refresh__subcmd__out"
                ;;
            rbgp__subcmd__neighbor__subcmd__help,softreset)
                cmd="rbgp__subcmd__neighbor__subcmd__help__subcmd__softreset"
                ;;
            rbgp__subcmd__neighbor__subcmd__set,delete)
                cmd="rbgp__subcmd__neighbor__subcmd__set__subcmd__delete"
                ;;
            rbgp__subcmd__neighbor__subcmd__set,get)
                cmd="rbgp__subcmd__neighbor__subcmd__set__subcmd__get"
                ;;
            rbgp__subcmd__neighbor__subcmd__set,help)
                cmd="rbgp__subcmd__neighbor__subcmd__set__subcmd__help"
                ;;
            rbgp__subcmd__neighbor__subcmd__set,list)
                cmd="rbgp__subcmd__neighbor__subcmd__set__subcmd__list"
                ;;
            rbgp__subcmd__neighbor__subcmd__set,set)
                cmd="rbgp__subcmd__neighbor__subcmd__set__subcmd__set"
                ;;
            rbgp__subcmd__neighbor__subcmd__set__subcmd__help,delete)
                cmd="rbgp__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__delete"
                ;;
            rbgp__subcmd__neighbor__subcmd__set__subcmd__help,get)
                cmd="rbgp__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__get"
                ;;
            rbgp__subcmd__neighbor__subcmd__set__subcmd__help,help)
                cmd="rbgp__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__neighbor__subcmd__set__subcmd__help,list)
                cmd="rbgp__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__list"
                ;;
            rbgp__subcmd__neighbor__subcmd__set__subcmd__help,set)
                cmd="rbgp__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__set"
                ;;
            rbgp__subcmd__peer__subcmd__group,attach)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__attach"
                ;;
            rbgp__subcmd__peer__subcmd__group,delete)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__delete"
                ;;
            rbgp__subcmd__peer__subcmd__group,detach)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__detach"
                ;;
            rbgp__subcmd__peer__subcmd__group,get)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__get"
                ;;
            rbgp__subcmd__peer__subcmd__group,help)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__help"
                ;;
            rbgp__subcmd__peer__subcmd__group,list)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__list"
                ;;
            rbgp__subcmd__peer__subcmd__group,set)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__set"
                ;;
            rbgp__subcmd__peer__subcmd__group__subcmd__help,attach)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__attach"
                ;;
            rbgp__subcmd__peer__subcmd__group__subcmd__help,delete)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__delete"
                ;;
            rbgp__subcmd__peer__subcmd__group__subcmd__help,detach)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__detach"
                ;;
            rbgp__subcmd__peer__subcmd__group__subcmd__help,get)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__get"
                ;;
            rbgp__subcmd__peer__subcmd__group__subcmd__help,help)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__peer__subcmd__group__subcmd__help,list)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__list"
                ;;
            rbgp__subcmd__peer__subcmd__group__subcmd__help,set)
                cmd="rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__set"
                ;;
            rbgp__subcmd__policy,chain)
                cmd="rbgp__subcmd__policy__subcmd__chain"
                ;;
            rbgp__subcmd__policy,check)
                cmd="rbgp__subcmd__policy__subcmd__check"
                ;;
            rbgp__subcmd__policy,counters)
                cmd="rbgp__subcmd__policy__subcmd__stats"
                ;;
            rbgp__subcmd__policy,delete)
                cmd="rbgp__subcmd__policy__subcmd__delete"
                ;;
            rbgp__subcmd__policy,explain)
                cmd="rbgp__subcmd__policy__subcmd__explain"
                ;;
            rbgp__subcmd__policy,fmt)
                cmd="rbgp__subcmd__policy__subcmd__fmt"
                ;;
            rbgp__subcmd__policy,get)
                cmd="rbgp__subcmd__policy__subcmd__get"
                ;;
            rbgp__subcmd__policy,help)
                cmd="rbgp__subcmd__policy__subcmd__help"
                ;;
            rbgp__subcmd__policy,list)
                cmd="rbgp__subcmd__policy__subcmd__list"
                ;;
            rbgp__subcmd__policy,set)
                cmd="rbgp__subcmd__policy__subcmd__set"
                ;;
            rbgp__subcmd__policy,stats)
                cmd="rbgp__subcmd__policy__subcmd__stats"
                ;;
            rbgp__subcmd__policy,test)
                cmd="rbgp__subcmd__policy__subcmd__test"
                ;;
            rbgp__subcmd__policy__subcmd__chain,clear-export)
                cmd="rbgp__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__export"
                ;;
            rbgp__subcmd__policy__subcmd__chain,clear-import)
                cmd="rbgp__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__import"
                ;;
            rbgp__subcmd__policy__subcmd__chain,help)
                cmd="rbgp__subcmd__policy__subcmd__chain__subcmd__help"
                ;;
            rbgp__subcmd__policy__subcmd__chain,set-export)
                cmd="rbgp__subcmd__policy__subcmd__chain__subcmd__set__subcmd__export"
                ;;
            rbgp__subcmd__policy__subcmd__chain,set-import)
                cmd="rbgp__subcmd__policy__subcmd__chain__subcmd__set__subcmd__import"
                ;;
            rbgp__subcmd__policy__subcmd__chain,show)
                cmd="rbgp__subcmd__policy__subcmd__chain__subcmd__show"
                ;;
            rbgp__subcmd__policy__subcmd__chain__subcmd__help,clear-export)
                cmd="rbgp__subcmd__policy__subcmd__chain__subcmd__help__subcmd__clear__subcmd__export"
                ;;
            rbgp__subcmd__policy__subcmd__chain__subcmd__help,clear-import)
                cmd="rbgp__subcmd__policy__subcmd__chain__subcmd__help__subcmd__clear__subcmd__import"
                ;;
            rbgp__subcmd__policy__subcmd__chain__subcmd__help,help)
                cmd="rbgp__subcmd__policy__subcmd__chain__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__policy__subcmd__chain__subcmd__help,set-export)
                cmd="rbgp__subcmd__policy__subcmd__chain__subcmd__help__subcmd__set__subcmd__export"
                ;;
            rbgp__subcmd__policy__subcmd__chain__subcmd__help,set-import)
                cmd="rbgp__subcmd__policy__subcmd__chain__subcmd__help__subcmd__set__subcmd__import"
                ;;
            rbgp__subcmd__policy__subcmd__chain__subcmd__help,show)
                cmd="rbgp__subcmd__policy__subcmd__chain__subcmd__help__subcmd__show"
                ;;
            rbgp__subcmd__policy__subcmd__help,chain)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__chain"
                ;;
            rbgp__subcmd__policy__subcmd__help,check)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__check"
                ;;
            rbgp__subcmd__policy__subcmd__help,delete)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__delete"
                ;;
            rbgp__subcmd__policy__subcmd__help,explain)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__explain"
                ;;
            rbgp__subcmd__policy__subcmd__help,fmt)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__fmt"
                ;;
            rbgp__subcmd__policy__subcmd__help,get)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__get"
                ;;
            rbgp__subcmd__policy__subcmd__help,help)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__policy__subcmd__help,list)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__list"
                ;;
            rbgp__subcmd__policy__subcmd__help,set)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__set"
                ;;
            rbgp__subcmd__policy__subcmd__help,stats)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__stats"
                ;;
            rbgp__subcmd__policy__subcmd__help,test)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__test"
                ;;
            rbgp__subcmd__policy__subcmd__help__subcmd__chain,clear-export)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__chain__subcmd__clear__subcmd__export"
                ;;
            rbgp__subcmd__policy__subcmd__help__subcmd__chain,clear-import)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__chain__subcmd__clear__subcmd__import"
                ;;
            rbgp__subcmd__policy__subcmd__help__subcmd__chain,set-export)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__chain__subcmd__set__subcmd__export"
                ;;
            rbgp__subcmd__policy__subcmd__help__subcmd__chain,set-import)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__chain__subcmd__set__subcmd__import"
                ;;
            rbgp__subcmd__policy__subcmd__help__subcmd__chain,show)
                cmd="rbgp__subcmd__policy__subcmd__help__subcmd__chain__subcmd__show"
                ;;
            rbgp__subcmd__rib,add)
                cmd="rbgp__subcmd__rib__subcmd__add"
                ;;
            rbgp__subcmd__rib,advertised)
                cmd="rbgp__subcmd__rib__subcmd__advertised"
                ;;
            rbgp__subcmd__rib,bgp-ls)
                cmd="rbgp__subcmd__rib__subcmd__bgpls"
                ;;
            rbgp__subcmd__rib,bgpls)
                cmd="rbgp__subcmd__rib__subcmd__bgpls"
                ;;
            rbgp__subcmd__rib,blackholes)
                cmd="rbgp__subcmd__rib__subcmd__blackholes"
                ;;
            rbgp__subcmd__rib,delete)
                cmd="rbgp__subcmd__rib__subcmd__delete"
                ;;
            rbgp__subcmd__rib,fib)
                cmd="rbgp__subcmd__rib__subcmd__fib"
                ;;
            rbgp__subcmd__rib,help)
                cmd="rbgp__subcmd__rib__subcmd__help"
                ;;
            rbgp__subcmd__rib,labeled)
                cmd="rbgp__subcmd__rib__subcmd__labeled"
                ;;
            rbgp__subcmd__rib,received)
                cmd="rbgp__subcmd__rib__subcmd__received"
                ;;
            rbgp__subcmd__rib,recv)
                cmd="rbgp__subcmd__rib__subcmd__received"
                ;;
            rbgp__subcmd__rib,rtc)
                cmd="rbgp__subcmd__rib__subcmd__rtc"
                ;;
            rbgp__subcmd__rib,sent)
                cmd="rbgp__subcmd__rib__subcmd__advertised"
                ;;
            rbgp__subcmd__rib,vpn)
                cmd="rbgp__subcmd__rib__subcmd__vpn"
                ;;
            rbgp__subcmd__rib__subcmd__help,add)
                cmd="rbgp__subcmd__rib__subcmd__help__subcmd__add"
                ;;
            rbgp__subcmd__rib__subcmd__help,advertised)
                cmd="rbgp__subcmd__rib__subcmd__help__subcmd__advertised"
                ;;
            rbgp__subcmd__rib__subcmd__help,bgpls)
                cmd="rbgp__subcmd__rib__subcmd__help__subcmd__bgpls"
                ;;
            rbgp__subcmd__rib__subcmd__help,blackholes)
                cmd="rbgp__subcmd__rib__subcmd__help__subcmd__blackholes"
                ;;
            rbgp__subcmd__rib__subcmd__help,delete)
                cmd="rbgp__subcmd__rib__subcmd__help__subcmd__delete"
                ;;
            rbgp__subcmd__rib__subcmd__help,fib)
                cmd="rbgp__subcmd__rib__subcmd__help__subcmd__fib"
                ;;
            rbgp__subcmd__rib__subcmd__help,help)
                cmd="rbgp__subcmd__rib__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__rib__subcmd__help,labeled)
                cmd="rbgp__subcmd__rib__subcmd__help__subcmd__labeled"
                ;;
            rbgp__subcmd__rib__subcmd__help,received)
                cmd="rbgp__subcmd__rib__subcmd__help__subcmd__received"
                ;;
            rbgp__subcmd__rib__subcmd__help,rtc)
                cmd="rbgp__subcmd__rib__subcmd__help__subcmd__rtc"
                ;;
            rbgp__subcmd__rib__subcmd__help,vpn)
                cmd="rbgp__subcmd__rib__subcmd__help__subcmd__vpn"
                ;;
            rbgp__subcmd__topology,help)
                cmd="rbgp__subcmd__topology__subcmd__help"
                ;;
            rbgp__subcmd__topology,links)
                cmd="rbgp__subcmd__topology__subcmd__links"
                ;;
            rbgp__subcmd__topology,nodes)
                cmd="rbgp__subcmd__topology__subcmd__nodes"
                ;;
            rbgp__subcmd__topology__subcmd__help,help)
                cmd="rbgp__subcmd__topology__subcmd__help__subcmd__help"
                ;;
            rbgp__subcmd__topology__subcmd__help,links)
                cmd="rbgp__subcmd__topology__subcmd__help__subcmd__links"
                ;;
            rbgp__subcmd__topology__subcmd__help,nodes)
                cmd="rbgp__subcmd__topology__subcmd__help__subcmd__nodes"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        rbgp)
            opts="-s -j -h -V --addr --token-file --json --no-color --help --version global config neighbor summary bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__bfd)
            opts="-s -j -h --addr --token-file --json --no-color --help list show help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__bfd__subcmd__help)
            opts="list show help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__bfd__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__bfd__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__bfd__subcmd__help__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__bfd__subcmd__list)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__bfd__subcmd__show)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__completions)
            opts="-s -j -h --addr --token-file --json --no-color --help bash elvish fish powershell zsh"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config)
            opts="-s -j -h --addr --token-file --json --no-color --help diff plan apply confirm abort status history rollback effective import help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__abort)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__apply)
            opts="-s -j -h --from-file --expected-runtime-snapshot-token --client-request-id --comment --confirm-id --confirm-timeout --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --from-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --expected-runtime-snapshot-token)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --client-request-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --comment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --confirm-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --confirm-timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__confirm)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__diff)
            opts="-s -j -h --from-file --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --from-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__effective)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__help)
            opts="diff plan apply confirm abort status history rollback effective import help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__help__subcmd__abort)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__help__subcmd__apply)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__help__subcmd__confirm)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__help__subcmd__diff)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__help__subcmd__effective)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__help__subcmd__history)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__help__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__help__subcmd__plan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__help__subcmd__rollback)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__help__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__history)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__import)
            opts="-s -j -h --format --out --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --format)
                    COMPREPLY=($(compgen -W "bird frr gobgp" -- "${cur}"))
                    return 0
                    ;;
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__plan)
            opts="-s -j -h --from-file --expected-runtime-snapshot-token --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --from-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --expected-runtime-snapshot-token)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__rollback)
            opts="-s -j -h --expected-runtime-snapshot-token --client-request-id --comment --confirm-id --confirm-timeout --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --expected-runtime-snapshot-token)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --client-request-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --comment)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --confirm-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --confirm-timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__config__subcmd__status)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff)
            opts="-s -j -h --addr --token-file --json --no-color --help advertised snapshot help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__advertised)
            opts="-a -s -j -h --peer --neighbor --against --family --max-routes --max-input-bytes --ignore-attribute --detail --deadline --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --against)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-routes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-input-bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ignore-attribute)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --detail)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --deadline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__help)
            opts="advertised snapshot help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__help__subcmd__advertised)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__help__subcmd__snapshot)
            opts="from-mrt from-bmp"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__help__subcmd__snapshot__subcmd__from__subcmd__bmp)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__help__subcmd__snapshot__subcmd__from__subcmd__mrt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__snapshot)
            opts="-s -j -h --addr --token-file --json --no-color --help from-mrt from-bmp help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__snapshot__subcmd__from__subcmd__bmp)
            opts="-s -j -h --peer --source --generation --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --source)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --generation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__snapshot__subcmd__from__subcmd__mrt)
            opts="-s -j -h --view --peer --peer-asn --source --generation --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --view)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer-asn)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --source)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --generation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__snapshot__subcmd__help)
            opts="from-mrt from-bmp help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__snapshot__subcmd__help__subcmd__from__subcmd__bmp)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__snapshot__subcmd__help__subcmd__from__subcmd__mrt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__diff__subcmd__snapshot__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__doctor)
            opts="-s -j -h --output --log-file --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --log-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__dynamic__subcmd__neighbor)
            opts="-s -j -h --addr --token-file --json --no-color --help list add delete help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__add)
            opts="-s -j -h --peer-group --asn --remote-asn --description --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --peer-group)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --remote-asn)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --asn)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --description)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__delete)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help)
            opts="list add delete help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__dynamic__subcmd__neighbor__subcmd__list)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__events)
            opts="-a -l -s -j -h --address --family --prefix --limit --addr --token-file --json --no-color --help watch sessions policy evpn help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --address)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prefix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -l)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__events__subcmd__evpn)
            opts="-l -s -j -h --address --route-type --rd --type --limit --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --address)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --route-type)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --type)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -l)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__events__subcmd__help)
            opts="watch sessions policy evpn help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__events__subcmd__help__subcmd__evpn)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__events__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__events__subcmd__help__subcmd__policy)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__events__subcmd__help__subcmd__sessions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__events__subcmd__help__subcmd__watch)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__events__subcmd__policy)
            opts="-l -s -j -h --address --type --limit --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --address)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --type)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -l)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__events__subcmd__sessions)
            opts="-l -s -j -h --address --type --limit --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --address)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --type)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -l)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__events__subcmd__watch)
            opts="-a -s -j -h --category --address --family --prefix --type --backfill --from-event-id --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --category)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --address)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prefix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --type)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --backfill)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --from-event-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn)
            opts="-s -j -h --route-type --peer --neighbor --rd --addr --token-file --json --no-color --help list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --route-type)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__add__subcmd__imet)
            opts="-s -j -h --rd --ethernet-tag --ip --next-hop --rt --no-vxlan-encap --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --rd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ethernet-tag)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ip)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --next-hop)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rt)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__add__subcmd__ip__subcmd__prefix)
            opts="-s -j -h --rd --ethernet-tag --prefix --label --next-hop --gateway --router-mac --rt --no-vxlan-encap --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --rd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ethernet-tag)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prefix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --label)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --next-hop)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --gateway)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --router-mac)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rt)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__add__subcmd__mac__subcmd__ip)
            opts="-s -j -h --rd --ethernet-tag --mac --ip --label --label2 --next-hop --rt --no-vxlan-encap --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --rd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ethernet-tag)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mac)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ip)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --label)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --label2)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --next-hop)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rt)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__clear__subcmd__duplicate__subcmd__mac)
            opts="-s -j -h --vni --mac --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --vni)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mac)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__delete__subcmd__imet)
            opts="-s -j -h --rd --ethernet-tag --ip --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --rd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ethernet-tag)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ip)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__delete__subcmd__ip__subcmd__prefix)
            opts="-s -j -h --rd --ethernet-tag --prefix --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --rd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ethernet-tag)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prefix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__delete__subcmd__mac__subcmd__ip)
            opts="-s -j -h --rd --ethernet-tag --mac --ip --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --rd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ethernet-tag)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mac)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ip)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__diagnose)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__es)
            opts="-s -j -h --addr --token-file --json --no-color --help list drain undrain help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__es__subcmd__drain)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__es__subcmd__help)
            opts="list drain undrain help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__es__subcmd__help__subcmd__drain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__es__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__es__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__es__subcmd__help__subcmd__undrain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__es__subcmd__list)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__es__subcmd__undrain)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help)
            opts="list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__add__subcmd__imet)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__add__subcmd__ip__subcmd__prefix)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__add__subcmd__mac__subcmd__ip)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__clear__subcmd__duplicate__subcmd__mac)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__delete__subcmd__imet)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__delete__subcmd__ip__subcmd__prefix)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__delete__subcmd__mac__subcmd__ip)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__diagnose)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__es)
            opts="list drain undrain"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__es__subcmd__drain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__es__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__es__subcmd__undrain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__instances)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__managed__subcmd__netdevs)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__nexthops)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__runtime)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__help__subcmd__vrfs)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__instances)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__list)
            opts="-s -j -h --route-type --peer --neighbor --rd --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --route-type)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__managed__subcmd__netdevs)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__nexthops)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__runtime)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__evpn__subcmd__vrfs)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__fib__subcmd__table)
            opts="-s -j -h --addr --token-file --json --no-color --help list set delete help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__fib__subcmd__table__subcmd__delete)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__fib__subcmd__table__subcmd__help)
            opts="list set delete help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__fib__subcmd__table__subcmd__help__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__fib__subcmd__table__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__fib__subcmd__table__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__fib__subcmd__table__subcmd__help__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__fib__subcmd__table__subcmd__list)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__fib__subcmd__table__subcmd__set)
            opts="-s -j -h --table-id --metric --families --allowed-peer-group --allowed-neighbor --max-routes --maximum-paths --maximum-paths-ebgp --maximum-paths-ibgp --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --table-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --metric)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --families)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --allowed-peer-group)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --allowed-neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-routes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --maximum-paths)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --maximum-paths-ebgp)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --maximum-paths-ibgp)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__flowspec)
            opts="-a -s -j -h --family --addr --token-file --json --no-color --help add delete help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__flowspec__subcmd__add)
            opts="-a -s -j -h --family --match --action --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --match)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --action)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__flowspec__subcmd__delete)
            opts="-a -s -j -h --family --match --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --match)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__flowspec__subcmd__help)
            opts="add delete help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__flowspec__subcmd__help__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__flowspec__subcmd__help__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__flowspec__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__global)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__gshut)
            opts="-s -j -h --peer --neighbor --clear --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__health)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help)
            opts="global config neighbor bfd rib topology orr diff flowspec evpn watch events health doctor metrics shutdown mrt-dump gshut top policy neighbor-set peer-group dynamic-neighbor fib-table completions man help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__bfd)
            opts="list show"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__bfd__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__bfd__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__completions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__config)
            opts="diff plan apply confirm abort status history rollback effective import"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__config__subcmd__abort)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__config__subcmd__apply)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__config__subcmd__confirm)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__config__subcmd__diff)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__config__subcmd__effective)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__config__subcmd__history)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__config__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__config__subcmd__plan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__config__subcmd__rollback)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__config__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__diff)
            opts="advertised snapshot"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__diff__subcmd__advertised)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__diff__subcmd__snapshot)
            opts="from-mrt from-bmp"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__diff__subcmd__snapshot__subcmd__from__subcmd__bmp)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__diff__subcmd__snapshot__subcmd__from__subcmd__mrt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__doctor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__dynamic__subcmd__neighbor)
            opts="list add delete"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__dynamic__subcmd__neighbor__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__dynamic__subcmd__neighbor__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__dynamic__subcmd__neighbor__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__events)
            opts="watch sessions policy evpn"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__events__subcmd__evpn)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__events__subcmd__policy)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__events__subcmd__sessions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__events__subcmd__watch)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn)
            opts="list add-mac-ip add-imet add-ip-prefix delete-mac-ip delete-imet delete-ip-prefix clear-duplicate-mac es runtime instances nexthops managed-netdevs vrfs diagnose"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__add__subcmd__imet)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__add__subcmd__ip__subcmd__prefix)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__add__subcmd__mac__subcmd__ip)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__clear__subcmd__duplicate__subcmd__mac)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__delete__subcmd__imet)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__delete__subcmd__ip__subcmd__prefix)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__delete__subcmd__mac__subcmd__ip)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__diagnose)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__es)
            opts="list drain undrain"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__es__subcmd__drain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__es__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__es__subcmd__undrain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__instances)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__managed__subcmd__netdevs)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__nexthops)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__runtime)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__evpn__subcmd__vrfs)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__fib__subcmd__table)
            opts="list set delete"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__fib__subcmd__table__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__fib__subcmd__table__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__fib__subcmd__table__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__flowspec)
            opts="add delete"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__flowspec__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__flowspec__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__global)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__gshut)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__health)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__man)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__metrics)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__mrt__subcmd__dump)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__neighbor)
            opts="add delete enable disable softreset refresh-out"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__neighbor__subcmd__set)
            opts="list get set delete"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__get)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__neighbor__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__neighbor__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__neighbor__subcmd__disable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__neighbor__subcmd__enable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__neighbor__subcmd__refresh__subcmd__out)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__neighbor__subcmd__softreset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__orr)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__peer__subcmd__group)
            opts="list get set delete attach detach"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__peer__subcmd__group__subcmd__attach)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__peer__subcmd__group__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__peer__subcmd__group__subcmd__detach)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__peer__subcmd__group__subcmd__get)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__peer__subcmd__group__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__peer__subcmd__group__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy)
            opts="list check fmt test get set delete chain stats explain"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__chain)
            opts="show set-import set-export clear-import clear-export"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__chain__subcmd__set__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__chain__subcmd__set__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__chain__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__check)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__fmt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__get)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__stats)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__policy__subcmd__test)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__rib)
            opts="received advertised blackholes fib bgpls vpn labeled rtc add delete"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__rib__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__rib__subcmd__advertised)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__rib__subcmd__bgpls)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__rib__subcmd__blackholes)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__rib__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__rib__subcmd__fib)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__rib__subcmd__labeled)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__rib__subcmd__received)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__rib__subcmd__rtc)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__rib__subcmd__vpn)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__shutdown)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__top)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__topology)
            opts="nodes links"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__topology__subcmd__links)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__topology__subcmd__nodes)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__help__subcmd__watch)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__man)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__metrics)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__mrt__subcmd__dump)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor)
            opts="-s -j -h --wide --compare --addr --token-file --json --no-color --help add delete enable disable softreset refresh-out help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --compare)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__set)
            opts="-s -j -h --addr --token-file --json --no-color --help list get set delete help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__set__subcmd__delete)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__set__subcmd__get)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__set__subcmd__help)
            opts="list get set delete help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__get)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__set__subcmd__list)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__set__subcmd__set)
            opts="-s -j -h --from-file --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --from-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__add)
            opts="-s -j -h --asn --remote-asn --description --hold-time --min-hold-time --send-hold-time --max-prefixes --peer-group --max-prefix-restart-seconds --families --required-families --route-server-client --per-client-best --role --strict-role --add-path-receive --add-path-send --add-path-send-max --paths-limit-receive-max --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --remote-asn)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --asn)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --description)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --hold-time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-hold-time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --send-hold-time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-prefixes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer-group)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-prefix-restart-seconds)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --families)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --required-families)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --role)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --add-path-send-max)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --paths-limit-receive-max)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__delete)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__disable)
            opts="-s -j -h --reason --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reason)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__enable)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__help)
            opts="add delete enable disable softreset refresh-out help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__help__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__help__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__help__subcmd__disable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__help__subcmd__enable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__help__subcmd__refresh__subcmd__out)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__help__subcmd__softreset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__refresh__subcmd__out)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__neighbor__subcmd__softreset)
            opts="-a -s -j -h --family --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__orr)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group)
            opts="-s -j -h --addr --token-file --json --no-color --help list get set delete attach detach help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__attach)
            opts="-s -j -h --group --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --group)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__delete)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__detach)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__get)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__help)
            opts="list get set delete attach detach help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__attach)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__detach)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__get)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__help__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__list)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__peer__subcmd__group__subcmd__set)
            opts="-s -j -h --from-file --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --from-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy)
            opts="-s -j -h --addr --token-file --json --no-color --help list check fmt test get set delete chain stats counters explain help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__chain)
            opts="-s -j -h --addr --token-file --json --no-color --help show set-import set-export clear-import clear-export help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__export)
            opts="-s -j -h --peer --neighbor --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__import)
            opts="-s -j -h --peer --neighbor --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__chain__subcmd__help)
            opts="show set-import set-export clear-import clear-export help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__chain__subcmd__help__subcmd__clear__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__chain__subcmd__help__subcmd__clear__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__chain__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__chain__subcmd__help__subcmd__set__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__chain__subcmd__help__subcmd__set__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__chain__subcmd__help__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__chain__subcmd__set__subcmd__export)
            opts="-s -j -h --peer --neighbor --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__chain__subcmd__set__subcmd__import)
            opts="-s -j -h --peer --neighbor --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__chain__subcmd__show)
            opts="-s -j -h --peer --neighbor --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__check)
            opts="-s -j -h --root --list-deps --coverage --coverage-min --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --coverage-min)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__delete)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__explain)
            opts="-s -j -h --peer --neighbor --prefix --path-id --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prefix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --path-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__fmt)
            opts="-s -j -h --check --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__get)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help)
            opts="list check fmt test get set delete chain stats explain help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__chain)
            opts="show set-import set-export clear-import clear-export"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__chain__subcmd__clear__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__chain__subcmd__clear__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__chain__subcmd__set__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__chain__subcmd__set__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__chain__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__check)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__fmt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__get)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__set)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__stats)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__help__subcmd__test)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__list)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__set)
            opts="-s -j -h --from-file --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --from-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__stats)
            opts="-s -j -h --peer --neighbor --direction --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --direction)
                    COMPREPLY=($(compgen -W "import export both" -- "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__policy__subcmd__test)
            opts="-a -s -j -h --policy --direction --peer --neighbor --family --limit --show-changes --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --policy)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --direction)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --show-changes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib)
            opts="-a -p -l -c -s -j -h --family --prefix --longer --explain --count --age --explain-peer --origin-asn --community --large-community --addr --token-file --json --no-color --help received recv advertised sent blackholes fib bgpls bgp-ls vpn labeled rtc add delete help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prefix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -p)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --explain-peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --origin-asn)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --community)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --large-community)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__add)
            opts="-s -j -h --nexthop --origin --local-pref --med --as-path --communities --large-communities --path-id --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --nexthop)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --origin)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --local-pref)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --med)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --as-path)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --communities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --large-communities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --path-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__advertised)
            opts="-a -s -j -h --family --count --age --explain --rd --labeled --source-peer --source-path-id --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --source-peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --source-path-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__bgpls)
            opts="-a -s -j -h --family --peer --neighbor --nlri-type --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --nlri-type)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__blackholes)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__delete)
            opts="-s -j -h --path-id --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --path-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__fib)
            opts="-s -j -h --table --state --reason --prefix --peer --neighbor --page-size --page-token --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --table)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --state)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reason)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prefix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --page-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --page-token)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__help)
            opts="received advertised blackholes fib bgpls vpn labeled rtc add delete help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__help__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__help__subcmd__advertised)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__help__subcmd__bgpls)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__help__subcmd__blackholes)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__help__subcmd__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__help__subcmd__fib)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__help__subcmd__labeled)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__help__subcmd__received)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__help__subcmd__rtc)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__help__subcmd__vpn)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__labeled)
            opts="-a -s -j -h --family --peer --neighbor --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__received)
            opts="-a -s -j -h --family --count --age --rejected --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__rtc)
            opts="-s -j -h --peer --neighbor --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__rib__subcmd__vpn)
            opts="-a -s -j -h --family --peer --neighbor --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --neighbor)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__shutdown)
            opts="-s -j -h --reason --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reason)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__top)
            opts="-i -s -j -h --interval --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --interval)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -i)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__topology)
            opts="-s -j -h --addr --token-file --json --no-color --help nodes links help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__topology__subcmd__help)
            opts="nodes links help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__topology__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__topology__subcmd__help__subcmd__links)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__topology__subcmd__help__subcmd__nodes)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__topology__subcmd__links)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__topology__subcmd__nodes)
            opts="-s -j -h --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        rbgp__subcmd__watch)
            opts="-a -s -j -h --family --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --family)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --addr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _rbgp -o nosort -o bashdefault -o default rbgp
else
    complete -F _rbgp -o bashdefault -o default rbgp
fi
