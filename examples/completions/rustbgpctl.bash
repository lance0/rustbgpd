_rustbgpctl() {
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
                cmd="rustbgpctl"
                ;;
            rustbgpctl,completions)
                cmd="rustbgpctl__subcmd__completions"
                ;;
            rustbgpctl,evpn)
                cmd="rustbgpctl__subcmd__evpn"
                ;;
            rustbgpctl,flowspec)
                cmd="rustbgpctl__subcmd__flowspec"
                ;;
            rustbgpctl,global)
                cmd="rustbgpctl__subcmd__global"
                ;;
            rustbgpctl,gshut)
                cmd="rustbgpctl__subcmd__gshut"
                ;;
            rustbgpctl,health)
                cmd="rustbgpctl__subcmd__health"
                ;;
            rustbgpctl,help)
                cmd="rustbgpctl__subcmd__help"
                ;;
            rustbgpctl,metrics)
                cmd="rustbgpctl__subcmd__metrics"
                ;;
            rustbgpctl,mrt-dump)
                cmd="rustbgpctl__subcmd__mrt__subcmd__dump"
                ;;
            rustbgpctl,neighbor)
                cmd="rustbgpctl__subcmd__neighbor"
                ;;
            rustbgpctl,neighbor-set)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__set"
                ;;
            rustbgpctl,peer-group)
                cmd="rustbgpctl__subcmd__peer__subcmd__group"
                ;;
            rustbgpctl,policy)
                cmd="rustbgpctl__subcmd__policy"
                ;;
            rustbgpctl,rib)
                cmd="rustbgpctl__subcmd__rib"
                ;;
            rustbgpctl,shutdown)
                cmd="rustbgpctl__subcmd__shutdown"
                ;;
            rustbgpctl,top)
                cmd="rustbgpctl__subcmd__top"
                ;;
            rustbgpctl,watch)
                cmd="rustbgpctl__subcmd__watch"
                ;;
            rustbgpctl__subcmd__evpn,add-imet)
                cmd="rustbgpctl__subcmd__evpn__subcmd__add__subcmd__imet"
                ;;
            rustbgpctl__subcmd__evpn,add-mac-ip)
                cmd="rustbgpctl__subcmd__evpn__subcmd__add__subcmd__mac__subcmd__ip"
                ;;
            rustbgpctl__subcmd__evpn,delete-imet)
                cmd="rustbgpctl__subcmd__evpn__subcmd__delete__subcmd__imet"
                ;;
            rustbgpctl__subcmd__evpn,delete-mac-ip)
                cmd="rustbgpctl__subcmd__evpn__subcmd__delete__subcmd__mac__subcmd__ip"
                ;;
            rustbgpctl__subcmd__evpn,diagnose)
                cmd="rustbgpctl__subcmd__evpn__subcmd__diagnose"
                ;;
            rustbgpctl__subcmd__evpn,help)
                cmd="rustbgpctl__subcmd__evpn__subcmd__help"
                ;;
            rustbgpctl__subcmd__evpn,instances)
                cmd="rustbgpctl__subcmd__evpn__subcmd__instances"
                ;;
            rustbgpctl__subcmd__evpn,list)
                cmd="rustbgpctl__subcmd__evpn__subcmd__list"
                ;;
            rustbgpctl__subcmd__evpn,nexthops)
                cmd="rustbgpctl__subcmd__evpn__subcmd__nexthops"
                ;;
            rustbgpctl__subcmd__evpn,vrfs)
                cmd="rustbgpctl__subcmd__evpn__subcmd__vrfs"
                ;;
            rustbgpctl__subcmd__evpn__subcmd__help,add-imet)
                cmd="rustbgpctl__subcmd__evpn__subcmd__help__subcmd__add__subcmd__imet"
                ;;
            rustbgpctl__subcmd__evpn__subcmd__help,add-mac-ip)
                cmd="rustbgpctl__subcmd__evpn__subcmd__help__subcmd__add__subcmd__mac__subcmd__ip"
                ;;
            rustbgpctl__subcmd__evpn__subcmd__help,delete-imet)
                cmd="rustbgpctl__subcmd__evpn__subcmd__help__subcmd__delete__subcmd__imet"
                ;;
            rustbgpctl__subcmd__evpn__subcmd__help,delete-mac-ip)
                cmd="rustbgpctl__subcmd__evpn__subcmd__help__subcmd__delete__subcmd__mac__subcmd__ip"
                ;;
            rustbgpctl__subcmd__evpn__subcmd__help,diagnose)
                cmd="rustbgpctl__subcmd__evpn__subcmd__help__subcmd__diagnose"
                ;;
            rustbgpctl__subcmd__evpn__subcmd__help,help)
                cmd="rustbgpctl__subcmd__evpn__subcmd__help__subcmd__help"
                ;;
            rustbgpctl__subcmd__evpn__subcmd__help,instances)
                cmd="rustbgpctl__subcmd__evpn__subcmd__help__subcmd__instances"
                ;;
            rustbgpctl__subcmd__evpn__subcmd__help,list)
                cmd="rustbgpctl__subcmd__evpn__subcmd__help__subcmd__list"
                ;;
            rustbgpctl__subcmd__evpn__subcmd__help,nexthops)
                cmd="rustbgpctl__subcmd__evpn__subcmd__help__subcmd__nexthops"
                ;;
            rustbgpctl__subcmd__evpn__subcmd__help,vrfs)
                cmd="rustbgpctl__subcmd__evpn__subcmd__help__subcmd__vrfs"
                ;;
            rustbgpctl__subcmd__flowspec,add)
                cmd="rustbgpctl__subcmd__flowspec__subcmd__add"
                ;;
            rustbgpctl__subcmd__flowspec,delete)
                cmd="rustbgpctl__subcmd__flowspec__subcmd__delete"
                ;;
            rustbgpctl__subcmd__flowspec,help)
                cmd="rustbgpctl__subcmd__flowspec__subcmd__help"
                ;;
            rustbgpctl__subcmd__flowspec__subcmd__help,add)
                cmd="rustbgpctl__subcmd__flowspec__subcmd__help__subcmd__add"
                ;;
            rustbgpctl__subcmd__flowspec__subcmd__help,delete)
                cmd="rustbgpctl__subcmd__flowspec__subcmd__help__subcmd__delete"
                ;;
            rustbgpctl__subcmd__flowspec__subcmd__help,help)
                cmd="rustbgpctl__subcmd__flowspec__subcmd__help__subcmd__help"
                ;;
            rustbgpctl__subcmd__help,completions)
                cmd="rustbgpctl__subcmd__help__subcmd__completions"
                ;;
            rustbgpctl__subcmd__help,evpn)
                cmd="rustbgpctl__subcmd__help__subcmd__evpn"
                ;;
            rustbgpctl__subcmd__help,flowspec)
                cmd="rustbgpctl__subcmd__help__subcmd__flowspec"
                ;;
            rustbgpctl__subcmd__help,global)
                cmd="rustbgpctl__subcmd__help__subcmd__global"
                ;;
            rustbgpctl__subcmd__help,gshut)
                cmd="rustbgpctl__subcmd__help__subcmd__gshut"
                ;;
            rustbgpctl__subcmd__help,health)
                cmd="rustbgpctl__subcmd__help__subcmd__health"
                ;;
            rustbgpctl__subcmd__help,help)
                cmd="rustbgpctl__subcmd__help__subcmd__help"
                ;;
            rustbgpctl__subcmd__help,metrics)
                cmd="rustbgpctl__subcmd__help__subcmd__metrics"
                ;;
            rustbgpctl__subcmd__help,mrt-dump)
                cmd="rustbgpctl__subcmd__help__subcmd__mrt__subcmd__dump"
                ;;
            rustbgpctl__subcmd__help,neighbor)
                cmd="rustbgpctl__subcmd__help__subcmd__neighbor"
                ;;
            rustbgpctl__subcmd__help,neighbor-set)
                cmd="rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set"
                ;;
            rustbgpctl__subcmd__help,peer-group)
                cmd="rustbgpctl__subcmd__help__subcmd__peer__subcmd__group"
                ;;
            rustbgpctl__subcmd__help,policy)
                cmd="rustbgpctl__subcmd__help__subcmd__policy"
                ;;
            rustbgpctl__subcmd__help,rib)
                cmd="rustbgpctl__subcmd__help__subcmd__rib"
                ;;
            rustbgpctl__subcmd__help,shutdown)
                cmd="rustbgpctl__subcmd__help__subcmd__shutdown"
                ;;
            rustbgpctl__subcmd__help,top)
                cmd="rustbgpctl__subcmd__help__subcmd__top"
                ;;
            rustbgpctl__subcmd__help,watch)
                cmd="rustbgpctl__subcmd__help__subcmd__watch"
                ;;
            rustbgpctl__subcmd__help__subcmd__evpn,add-imet)
                cmd="rustbgpctl__subcmd__help__subcmd__evpn__subcmd__add__subcmd__imet"
                ;;
            rustbgpctl__subcmd__help__subcmd__evpn,add-mac-ip)
                cmd="rustbgpctl__subcmd__help__subcmd__evpn__subcmd__add__subcmd__mac__subcmd__ip"
                ;;
            rustbgpctl__subcmd__help__subcmd__evpn,delete-imet)
                cmd="rustbgpctl__subcmd__help__subcmd__evpn__subcmd__delete__subcmd__imet"
                ;;
            rustbgpctl__subcmd__help__subcmd__evpn,delete-mac-ip)
                cmd="rustbgpctl__subcmd__help__subcmd__evpn__subcmd__delete__subcmd__mac__subcmd__ip"
                ;;
            rustbgpctl__subcmd__help__subcmd__evpn,diagnose)
                cmd="rustbgpctl__subcmd__help__subcmd__evpn__subcmd__diagnose"
                ;;
            rustbgpctl__subcmd__help__subcmd__evpn,instances)
                cmd="rustbgpctl__subcmd__help__subcmd__evpn__subcmd__instances"
                ;;
            rustbgpctl__subcmd__help__subcmd__evpn,list)
                cmd="rustbgpctl__subcmd__help__subcmd__evpn__subcmd__list"
                ;;
            rustbgpctl__subcmd__help__subcmd__evpn,nexthops)
                cmd="rustbgpctl__subcmd__help__subcmd__evpn__subcmd__nexthops"
                ;;
            rustbgpctl__subcmd__help__subcmd__evpn,vrfs)
                cmd="rustbgpctl__subcmd__help__subcmd__evpn__subcmd__vrfs"
                ;;
            rustbgpctl__subcmd__help__subcmd__flowspec,add)
                cmd="rustbgpctl__subcmd__help__subcmd__flowspec__subcmd__add"
                ;;
            rustbgpctl__subcmd__help__subcmd__flowspec,delete)
                cmd="rustbgpctl__subcmd__help__subcmd__flowspec__subcmd__delete"
                ;;
            rustbgpctl__subcmd__help__subcmd__neighbor,add)
                cmd="rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__add"
                ;;
            rustbgpctl__subcmd__help__subcmd__neighbor,delete)
                cmd="rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__delete"
                ;;
            rustbgpctl__subcmd__help__subcmd__neighbor,disable)
                cmd="rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__disable"
                ;;
            rustbgpctl__subcmd__help__subcmd__neighbor,enable)
                cmd="rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__enable"
                ;;
            rustbgpctl__subcmd__help__subcmd__neighbor,softreset)
                cmd="rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__softreset"
                ;;
            rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set,delete)
                cmd="rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__delete"
                ;;
            rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set,get)
                cmd="rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__get"
                ;;
            rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set,list)
                cmd="rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__list"
                ;;
            rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set,set)
                cmd="rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__set"
                ;;
            rustbgpctl__subcmd__help__subcmd__peer__subcmd__group,attach)
                cmd="rustbgpctl__subcmd__help__subcmd__peer__subcmd__group__subcmd__attach"
                ;;
            rustbgpctl__subcmd__help__subcmd__peer__subcmd__group,delete)
                cmd="rustbgpctl__subcmd__help__subcmd__peer__subcmd__group__subcmd__delete"
                ;;
            rustbgpctl__subcmd__help__subcmd__peer__subcmd__group,detach)
                cmd="rustbgpctl__subcmd__help__subcmd__peer__subcmd__group__subcmd__detach"
                ;;
            rustbgpctl__subcmd__help__subcmd__peer__subcmd__group,get)
                cmd="rustbgpctl__subcmd__help__subcmd__peer__subcmd__group__subcmd__get"
                ;;
            rustbgpctl__subcmd__help__subcmd__peer__subcmd__group,list)
                cmd="rustbgpctl__subcmd__help__subcmd__peer__subcmd__group__subcmd__list"
                ;;
            rustbgpctl__subcmd__help__subcmd__peer__subcmd__group,set)
                cmd="rustbgpctl__subcmd__help__subcmd__peer__subcmd__group__subcmd__set"
                ;;
            rustbgpctl__subcmd__help__subcmd__policy,chain)
                cmd="rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain"
                ;;
            rustbgpctl__subcmd__help__subcmd__policy,delete)
                cmd="rustbgpctl__subcmd__help__subcmd__policy__subcmd__delete"
                ;;
            rustbgpctl__subcmd__help__subcmd__policy,get)
                cmd="rustbgpctl__subcmd__help__subcmd__policy__subcmd__get"
                ;;
            rustbgpctl__subcmd__help__subcmd__policy,list)
                cmd="rustbgpctl__subcmd__help__subcmd__policy__subcmd__list"
                ;;
            rustbgpctl__subcmd__help__subcmd__policy,set)
                cmd="rustbgpctl__subcmd__help__subcmd__policy__subcmd__set"
                ;;
            rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain,clear-export)
                cmd="rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__export"
                ;;
            rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain,clear-import)
                cmd="rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__import"
                ;;
            rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain,set-export)
                cmd="rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain__subcmd__set__subcmd__export"
                ;;
            rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain,set-import)
                cmd="rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain__subcmd__set__subcmd__import"
                ;;
            rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain,show)
                cmd="rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain__subcmd__show"
                ;;
            rustbgpctl__subcmd__help__subcmd__rib,add)
                cmd="rustbgpctl__subcmd__help__subcmd__rib__subcmd__add"
                ;;
            rustbgpctl__subcmd__help__subcmd__rib,advertised)
                cmd="rustbgpctl__subcmd__help__subcmd__rib__subcmd__advertised"
                ;;
            rustbgpctl__subcmd__help__subcmd__rib,blackholes)
                cmd="rustbgpctl__subcmd__help__subcmd__rib__subcmd__blackholes"
                ;;
            rustbgpctl__subcmd__help__subcmd__rib,delete)
                cmd="rustbgpctl__subcmd__help__subcmd__rib__subcmd__delete"
                ;;
            rustbgpctl__subcmd__help__subcmd__rib,fib)
                cmd="rustbgpctl__subcmd__help__subcmd__rib__subcmd__fib"
                ;;
            rustbgpctl__subcmd__help__subcmd__rib,received)
                cmd="rustbgpctl__subcmd__help__subcmd__rib__subcmd__received"
                ;;
            rustbgpctl__subcmd__neighbor,add)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__add"
                ;;
            rustbgpctl__subcmd__neighbor,delete)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__delete"
                ;;
            rustbgpctl__subcmd__neighbor,disable)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__disable"
                ;;
            rustbgpctl__subcmd__neighbor,enable)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__enable"
                ;;
            rustbgpctl__subcmd__neighbor,help)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__help"
                ;;
            rustbgpctl__subcmd__neighbor,softreset)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__softreset"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__help,add)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__help__subcmd__add"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__help,delete)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__help__subcmd__delete"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__help,disable)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__help__subcmd__disable"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__help,enable)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__help__subcmd__enable"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__help,help)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__help__subcmd__help"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__help,softreset)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__help__subcmd__softreset"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__set,delete)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__delete"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__set,get)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__get"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__set,help)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__set,list)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__list"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__set,set)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__set"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help,delete)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__delete"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help,get)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__get"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help,help)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__help"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help,list)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__list"
                ;;
            rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help,set)
                cmd="rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__set"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group,attach)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__attach"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group,delete)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__delete"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group,detach)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__detach"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group,get)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__get"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group,help)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__help"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group,list)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__list"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group,set)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__set"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group__subcmd__help,attach)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__attach"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group__subcmd__help,delete)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__delete"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group__subcmd__help,detach)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__detach"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group__subcmd__help,get)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__get"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group__subcmd__help,help)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__help"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group__subcmd__help,list)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__list"
                ;;
            rustbgpctl__subcmd__peer__subcmd__group__subcmd__help,set)
                cmd="rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__set"
                ;;
            rustbgpctl__subcmd__policy,chain)
                cmd="rustbgpctl__subcmd__policy__subcmd__chain"
                ;;
            rustbgpctl__subcmd__policy,delete)
                cmd="rustbgpctl__subcmd__policy__subcmd__delete"
                ;;
            rustbgpctl__subcmd__policy,get)
                cmd="rustbgpctl__subcmd__policy__subcmd__get"
                ;;
            rustbgpctl__subcmd__policy,help)
                cmd="rustbgpctl__subcmd__policy__subcmd__help"
                ;;
            rustbgpctl__subcmd__policy,list)
                cmd="rustbgpctl__subcmd__policy__subcmd__list"
                ;;
            rustbgpctl__subcmd__policy,set)
                cmd="rustbgpctl__subcmd__policy__subcmd__set"
                ;;
            rustbgpctl__subcmd__policy__subcmd__chain,clear-export)
                cmd="rustbgpctl__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__export"
                ;;
            rustbgpctl__subcmd__policy__subcmd__chain,clear-import)
                cmd="rustbgpctl__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__import"
                ;;
            rustbgpctl__subcmd__policy__subcmd__chain,help)
                cmd="rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help"
                ;;
            rustbgpctl__subcmd__policy__subcmd__chain,set-export)
                cmd="rustbgpctl__subcmd__policy__subcmd__chain__subcmd__set__subcmd__export"
                ;;
            rustbgpctl__subcmd__policy__subcmd__chain,set-import)
                cmd="rustbgpctl__subcmd__policy__subcmd__chain__subcmd__set__subcmd__import"
                ;;
            rustbgpctl__subcmd__policy__subcmd__chain,show)
                cmd="rustbgpctl__subcmd__policy__subcmd__chain__subcmd__show"
                ;;
            rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help,clear-export)
                cmd="rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help__subcmd__clear__subcmd__export"
                ;;
            rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help,clear-import)
                cmd="rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help__subcmd__clear__subcmd__import"
                ;;
            rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help,help)
                cmd="rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help__subcmd__help"
                ;;
            rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help,set-export)
                cmd="rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help__subcmd__set__subcmd__export"
                ;;
            rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help,set-import)
                cmd="rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help__subcmd__set__subcmd__import"
                ;;
            rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help,show)
                cmd="rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help__subcmd__show"
                ;;
            rustbgpctl__subcmd__policy__subcmd__help,chain)
                cmd="rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain"
                ;;
            rustbgpctl__subcmd__policy__subcmd__help,delete)
                cmd="rustbgpctl__subcmd__policy__subcmd__help__subcmd__delete"
                ;;
            rustbgpctl__subcmd__policy__subcmd__help,get)
                cmd="rustbgpctl__subcmd__policy__subcmd__help__subcmd__get"
                ;;
            rustbgpctl__subcmd__policy__subcmd__help,help)
                cmd="rustbgpctl__subcmd__policy__subcmd__help__subcmd__help"
                ;;
            rustbgpctl__subcmd__policy__subcmd__help,list)
                cmd="rustbgpctl__subcmd__policy__subcmd__help__subcmd__list"
                ;;
            rustbgpctl__subcmd__policy__subcmd__help,set)
                cmd="rustbgpctl__subcmd__policy__subcmd__help__subcmd__set"
                ;;
            rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain,clear-export)
                cmd="rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain__subcmd__clear__subcmd__export"
                ;;
            rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain,clear-import)
                cmd="rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain__subcmd__clear__subcmd__import"
                ;;
            rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain,set-export)
                cmd="rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain__subcmd__set__subcmd__export"
                ;;
            rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain,set-import)
                cmd="rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain__subcmd__set__subcmd__import"
                ;;
            rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain,show)
                cmd="rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain__subcmd__show"
                ;;
            rustbgpctl__subcmd__rib,add)
                cmd="rustbgpctl__subcmd__rib__subcmd__add"
                ;;
            rustbgpctl__subcmd__rib,advertised)
                cmd="rustbgpctl__subcmd__rib__subcmd__advertised"
                ;;
            rustbgpctl__subcmd__rib,blackholes)
                cmd="rustbgpctl__subcmd__rib__subcmd__blackholes"
                ;;
            rustbgpctl__subcmd__rib,delete)
                cmd="rustbgpctl__subcmd__rib__subcmd__delete"
                ;;
            rustbgpctl__subcmd__rib,fib)
                cmd="rustbgpctl__subcmd__rib__subcmd__fib"
                ;;
            rustbgpctl__subcmd__rib,help)
                cmd="rustbgpctl__subcmd__rib__subcmd__help"
                ;;
            rustbgpctl__subcmd__rib,received)
                cmd="rustbgpctl__subcmd__rib__subcmd__received"
                ;;
            rustbgpctl__subcmd__rib__subcmd__help,add)
                cmd="rustbgpctl__subcmd__rib__subcmd__help__subcmd__add"
                ;;
            rustbgpctl__subcmd__rib__subcmd__help,advertised)
                cmd="rustbgpctl__subcmd__rib__subcmd__help__subcmd__advertised"
                ;;
            rustbgpctl__subcmd__rib__subcmd__help,blackholes)
                cmd="rustbgpctl__subcmd__rib__subcmd__help__subcmd__blackholes"
                ;;
            rustbgpctl__subcmd__rib__subcmd__help,delete)
                cmd="rustbgpctl__subcmd__rib__subcmd__help__subcmd__delete"
                ;;
            rustbgpctl__subcmd__rib__subcmd__help,fib)
                cmd="rustbgpctl__subcmd__rib__subcmd__help__subcmd__fib"
                ;;
            rustbgpctl__subcmd__rib__subcmd__help,help)
                cmd="rustbgpctl__subcmd__rib__subcmd__help__subcmd__help"
                ;;
            rustbgpctl__subcmd__rib__subcmd__help,received)
                cmd="rustbgpctl__subcmd__rib__subcmd__help__subcmd__received"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        rustbgpctl)
            opts="-s -j -h -V --addr --token-file --json --no-color --help --version global neighbor rib flowspec evpn watch health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help"
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
        rustbgpctl__subcmd__completions)
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
        rustbgpctl__subcmd__evpn)
            opts="-s -j -h --route-type --peer --rd --addr --token-file --json --no-color --help list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --route-type)
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
        rustbgpctl__subcmd__evpn__subcmd__add__subcmd__imet)
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
        rustbgpctl__subcmd__evpn__subcmd__add__subcmd__mac__subcmd__ip)
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
        rustbgpctl__subcmd__evpn__subcmd__delete__subcmd__imet)
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
        rustbgpctl__subcmd__evpn__subcmd__delete__subcmd__mac__subcmd__ip)
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
        rustbgpctl__subcmd__evpn__subcmd__diagnose)
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
        rustbgpctl__subcmd__evpn__subcmd__help)
            opts="list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose help"
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
        rustbgpctl__subcmd__evpn__subcmd__help__subcmd__add__subcmd__imet)
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
        rustbgpctl__subcmd__evpn__subcmd__help__subcmd__add__subcmd__mac__subcmd__ip)
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
        rustbgpctl__subcmd__evpn__subcmd__help__subcmd__delete__subcmd__imet)
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
        rustbgpctl__subcmd__evpn__subcmd__help__subcmd__delete__subcmd__mac__subcmd__ip)
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
        rustbgpctl__subcmd__evpn__subcmd__help__subcmd__diagnose)
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
        rustbgpctl__subcmd__evpn__subcmd__help__subcmd__help)
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
        rustbgpctl__subcmd__evpn__subcmd__help__subcmd__instances)
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
        rustbgpctl__subcmd__evpn__subcmd__help__subcmd__list)
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
        rustbgpctl__subcmd__evpn__subcmd__help__subcmd__nexthops)
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
        rustbgpctl__subcmd__evpn__subcmd__help__subcmd__vrfs)
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
        rustbgpctl__subcmd__evpn__subcmd__instances)
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
        rustbgpctl__subcmd__evpn__subcmd__list)
            opts="-s -j -h --route-type --peer --rd --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --route-type)
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
        rustbgpctl__subcmd__evpn__subcmd__nexthops)
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
        rustbgpctl__subcmd__evpn__subcmd__vrfs)
            opts="-s -j -h --addr --token-file --json --no-color --help [NAME]"
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
        rustbgpctl__subcmd__flowspec)
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
        rustbgpctl__subcmd__flowspec__subcmd__add)
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
        rustbgpctl__subcmd__flowspec__subcmd__delete)
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
        rustbgpctl__subcmd__flowspec__subcmd__help)
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
        rustbgpctl__subcmd__flowspec__subcmd__help__subcmd__add)
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
        rustbgpctl__subcmd__flowspec__subcmd__help__subcmd__delete)
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
        rustbgpctl__subcmd__flowspec__subcmd__help__subcmd__help)
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
        rustbgpctl__subcmd__global)
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
        rustbgpctl__subcmd__gshut)
            opts="-s -j -h --peer --clear --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
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
        rustbgpctl__subcmd__health)
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
        rustbgpctl__subcmd__help)
            opts="global neighbor rib flowspec evpn watch health metrics shutdown mrt-dump gshut top policy neighbor-set peer-group completions help"
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
        rustbgpctl__subcmd__help__subcmd__completions)
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
        rustbgpctl__subcmd__help__subcmd__evpn)
            opts="list add-mac-ip add-imet delete-mac-ip delete-imet instances nexthops vrfs diagnose"
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
        rustbgpctl__subcmd__help__subcmd__evpn__subcmd__add__subcmd__imet)
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
        rustbgpctl__subcmd__help__subcmd__evpn__subcmd__add__subcmd__mac__subcmd__ip)
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
        rustbgpctl__subcmd__help__subcmd__evpn__subcmd__delete__subcmd__imet)
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
        rustbgpctl__subcmd__help__subcmd__evpn__subcmd__delete__subcmd__mac__subcmd__ip)
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
        rustbgpctl__subcmd__help__subcmd__evpn__subcmd__diagnose)
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
        rustbgpctl__subcmd__help__subcmd__evpn__subcmd__instances)
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
        rustbgpctl__subcmd__help__subcmd__evpn__subcmd__list)
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
        rustbgpctl__subcmd__help__subcmd__evpn__subcmd__nexthops)
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
        rustbgpctl__subcmd__help__subcmd__evpn__subcmd__vrfs)
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
        rustbgpctl__subcmd__help__subcmd__flowspec)
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
        rustbgpctl__subcmd__help__subcmd__flowspec__subcmd__add)
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
        rustbgpctl__subcmd__help__subcmd__flowspec__subcmd__delete)
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
        rustbgpctl__subcmd__help__subcmd__global)
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
        rustbgpctl__subcmd__help__subcmd__gshut)
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
        rustbgpctl__subcmd__help__subcmd__health)
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
        rustbgpctl__subcmd__help__subcmd__help)
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
        rustbgpctl__subcmd__help__subcmd__metrics)
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
        rustbgpctl__subcmd__help__subcmd__mrt__subcmd__dump)
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
        rustbgpctl__subcmd__help__subcmd__neighbor)
            opts="add delete enable disable softreset"
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
        rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set)
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
        rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__delete)
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
        rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__get)
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
        rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__list)
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
        rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__set__subcmd__set)
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
        rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__add)
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
        rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__delete)
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
        rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__disable)
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
        rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__enable)
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
        rustbgpctl__subcmd__help__subcmd__neighbor__subcmd__softreset)
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
        rustbgpctl__subcmd__help__subcmd__peer__subcmd__group)
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
        rustbgpctl__subcmd__help__subcmd__peer__subcmd__group__subcmd__attach)
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
        rustbgpctl__subcmd__help__subcmd__peer__subcmd__group__subcmd__delete)
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
        rustbgpctl__subcmd__help__subcmd__peer__subcmd__group__subcmd__detach)
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
        rustbgpctl__subcmd__help__subcmd__peer__subcmd__group__subcmd__get)
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
        rustbgpctl__subcmd__help__subcmd__peer__subcmd__group__subcmd__list)
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
        rustbgpctl__subcmd__help__subcmd__peer__subcmd__group__subcmd__set)
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
        rustbgpctl__subcmd__help__subcmd__policy)
            opts="list get set delete chain"
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
        rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain)
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
        rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__export)
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
        rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__import)
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
        rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain__subcmd__set__subcmd__export)
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
        rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain__subcmd__set__subcmd__import)
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
        rustbgpctl__subcmd__help__subcmd__policy__subcmd__chain__subcmd__show)
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
        rustbgpctl__subcmd__help__subcmd__policy__subcmd__delete)
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
        rustbgpctl__subcmd__help__subcmd__policy__subcmd__get)
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
        rustbgpctl__subcmd__help__subcmd__policy__subcmd__list)
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
        rustbgpctl__subcmd__help__subcmd__policy__subcmd__set)
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
        rustbgpctl__subcmd__help__subcmd__rib)
            opts="received advertised blackholes fib add delete"
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
        rustbgpctl__subcmd__help__subcmd__rib__subcmd__add)
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
        rustbgpctl__subcmd__help__subcmd__rib__subcmd__advertised)
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
        rustbgpctl__subcmd__help__subcmd__rib__subcmd__blackholes)
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
        rustbgpctl__subcmd__help__subcmd__rib__subcmd__delete)
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
        rustbgpctl__subcmd__help__subcmd__rib__subcmd__fib)
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
        rustbgpctl__subcmd__help__subcmd__rib__subcmd__received)
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
        rustbgpctl__subcmd__help__subcmd__shutdown)
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
        rustbgpctl__subcmd__help__subcmd__top)
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
        rustbgpctl__subcmd__help__subcmd__watch)
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
        rustbgpctl__subcmd__metrics)
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
        rustbgpctl__subcmd__mrt__subcmd__dump)
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
        rustbgpctl__subcmd__neighbor)
            opts="-s -j -h --addr --token-file --json --no-color --help [ADDRESS] add delete enable disable softreset help"
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
        rustbgpctl__subcmd__neighbor__subcmd__set)
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
        rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__delete)
            opts="-s -j -h --addr --token-file --json --no-color --help <NAME>"
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
        rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__get)
            opts="-s -j -h --addr --token-file --json --no-color --help <NAME>"
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
        rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help)
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
        rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__delete)
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
        rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__get)
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
        rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__help)
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
        rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__list)
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
        rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__help__subcmd__set)
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
        rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__list)
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
        rustbgpctl__subcmd__neighbor__subcmd__set__subcmd__set)
            opts="-s -j -h --from-file --addr --token-file --json --no-color --help <NAME>"
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
        rustbgpctl__subcmd__neighbor__subcmd__add)
            opts="-s -j -h --asn --description --hold-time --max-prefixes --families --route-server-client --add-path-receive --add-path-send --add-path-send-max --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
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
                --max-prefixes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --families)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --add-path-send-max)
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
        rustbgpctl__subcmd__neighbor__subcmd__delete)
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
        rustbgpctl__subcmd__neighbor__subcmd__disable)
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
        rustbgpctl__subcmd__neighbor__subcmd__enable)
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
        rustbgpctl__subcmd__neighbor__subcmd__help)
            opts="add delete enable disable softreset help"
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
        rustbgpctl__subcmd__neighbor__subcmd__help__subcmd__add)
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
        rustbgpctl__subcmd__neighbor__subcmd__help__subcmd__delete)
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
        rustbgpctl__subcmd__neighbor__subcmd__help__subcmd__disable)
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
        rustbgpctl__subcmd__neighbor__subcmd__help__subcmd__enable)
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
        rustbgpctl__subcmd__neighbor__subcmd__help__subcmd__help)
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
        rustbgpctl__subcmd__neighbor__subcmd__help__subcmd__softreset)
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
        rustbgpctl__subcmd__neighbor__subcmd__softreset)
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
        rustbgpctl__subcmd__peer__subcmd__group)
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__attach)
            opts="-s -j -h --group --addr --token-file --json --no-color --help <ADDRESS>"
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__delete)
            opts="-s -j -h --addr --token-file --json --no-color --help <NAME>"
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__detach)
            opts="-s -j -h --addr --token-file --json --no-color --help <ADDRESS>"
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__get)
            opts="-s -j -h --addr --token-file --json --no-color --help <NAME>"
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__help)
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__attach)
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__delete)
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__detach)
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__get)
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__help)
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__list)
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__help__subcmd__set)
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__list)
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
        rustbgpctl__subcmd__peer__subcmd__group__subcmd__set)
            opts="-s -j -h --from-file --addr --token-file --json --no-color --help <NAME>"
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
        rustbgpctl__subcmd__policy)
            opts="-s -j -h --addr --token-file --json --no-color --help list get set delete chain help"
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
        rustbgpctl__subcmd__policy__subcmd__chain)
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
        rustbgpctl__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__export)
            opts="-s -j -h --neighbor --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
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
        rustbgpctl__subcmd__policy__subcmd__chain__subcmd__clear__subcmd__import)
            opts="-s -j -h --neighbor --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
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
        rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help)
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
        rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help__subcmd__clear__subcmd__export)
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
        rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help__subcmd__clear__subcmd__import)
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
        rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help__subcmd__help)
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
        rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help__subcmd__set__subcmd__export)
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
        rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help__subcmd__set__subcmd__import)
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
        rustbgpctl__subcmd__policy__subcmd__chain__subcmd__help__subcmd__show)
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
        rustbgpctl__subcmd__policy__subcmd__chain__subcmd__set__subcmd__export)
            opts="-s -j -h --neighbor --addr --token-file --json --no-color --help [POLICIES]..."
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
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
        rustbgpctl__subcmd__policy__subcmd__chain__subcmd__set__subcmd__import)
            opts="-s -j -h --neighbor --addr --token-file --json --no-color --help [POLICIES]..."
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
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
        rustbgpctl__subcmd__policy__subcmd__chain__subcmd__show)
            opts="-s -j -h --neighbor --addr --token-file --json --no-color --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --neighbor)
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
        rustbgpctl__subcmd__policy__subcmd__delete)
            opts="-s -j -h --addr --token-file --json --no-color --help <NAME>"
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
        rustbgpctl__subcmd__policy__subcmd__get)
            opts="-s -j -h --addr --token-file --json --no-color --help <NAME>"
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
        rustbgpctl__subcmd__policy__subcmd__help)
            opts="list get set delete chain help"
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
        rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain)
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
        rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain__subcmd__clear__subcmd__export)
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
        rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain__subcmd__clear__subcmd__import)
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
        rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain__subcmd__set__subcmd__export)
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
        rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain__subcmd__set__subcmd__import)
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
        rustbgpctl__subcmd__policy__subcmd__help__subcmd__chain__subcmd__show)
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
        rustbgpctl__subcmd__policy__subcmd__help__subcmd__delete)
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
        rustbgpctl__subcmd__policy__subcmd__help__subcmd__get)
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
        rustbgpctl__subcmd__policy__subcmd__help__subcmd__help)
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
        rustbgpctl__subcmd__policy__subcmd__help__subcmd__list)
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
        rustbgpctl__subcmd__policy__subcmd__help__subcmd__set)
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
        rustbgpctl__subcmd__policy__subcmd__list)
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
        rustbgpctl__subcmd__policy__subcmd__set)
            opts="-s -j -h --from-file --addr --token-file --json --no-color --help <NAME>"
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
        rustbgpctl__subcmd__rib)
            opts="-a -p -l -c -s -j -h --family --prefix --longer --explain --explain-peer --origin-asn --community --large-community --addr --token-file --json --no-color --help received advertised blackholes fib add delete help"
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
        rustbgpctl__subcmd__rib__subcmd__add)
            opts="-s -j -h --nexthop --origin --local-pref --med --as-path --communities --large-communities --path-id --addr --token-file --json --no-color --help <PREFIX>"
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
        rustbgpctl__subcmd__rib__subcmd__advertised)
            opts="-a -s -j -h --family --explain --addr --token-file --json --no-color --help <ADDRESS>"
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
        rustbgpctl__subcmd__rib__subcmd__blackholes)
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
        rustbgpctl__subcmd__rib__subcmd__delete)
            opts="-s -j -h --path-id --addr --token-file --json --no-color --help <PREFIX>"
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
        rustbgpctl__subcmd__rib__subcmd__fib)
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
        rustbgpctl__subcmd__rib__subcmd__help)
            opts="received advertised blackholes fib add delete help"
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
        rustbgpctl__subcmd__rib__subcmd__help__subcmd__add)
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
        rustbgpctl__subcmd__rib__subcmd__help__subcmd__advertised)
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
        rustbgpctl__subcmd__rib__subcmd__help__subcmd__blackholes)
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
        rustbgpctl__subcmd__rib__subcmd__help__subcmd__delete)
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
        rustbgpctl__subcmd__rib__subcmd__help__subcmd__fib)
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
        rustbgpctl__subcmd__rib__subcmd__help__subcmd__help)
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
        rustbgpctl__subcmd__rib__subcmd__help__subcmd__received)
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
        rustbgpctl__subcmd__rib__subcmd__received)
            opts="-a -s -j -h --family --addr --token-file --json --no-color --help <ADDRESS>"
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
        rustbgpctl__subcmd__shutdown)
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
        rustbgpctl__subcmd__top)
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
        rustbgpctl__subcmd__watch)
            opts="-a -s -j -h --family --addr --token-file --json --no-color --help [ADDRESS]"
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
    complete -F _rustbgpctl -o nosort -o bashdefault -o default rustbgpctl
else
    complete -F _rustbgpctl -o bashdefault -o default rustbgpctl
fi
