#compdef styxwire hping3 hping2 hping
# styxwire(8) completion for zsh.                             -*- shell-script -*-
#
# The option list mirrors the binary's own table (parseoptions.c:hping_optlist);
# tests/completion.sh checks that it matches, so it cannot drift silently.
# Install as a file named _styxwire on $fpath (see INSTALL).

_styxwire() {
    local -a longopts shortopts
    longopts=( --count --interval --numeric --quiet --interface --help --version --destport --baseport --ttl --id --win --spoof --fin --syn --rst --push --ack --urg --xmas --ymas --frag --morefrag --dontfrag --fragoff --tcpoff --rel --data --rawip --icmp --udp --scan --bind --unbind --debug --verbose --winid --keep --file --dump --print --sign --listen --safe --traceroute --tos --mtu --seqnum --badcksum --setseq --setack --icmptype --icmpcode --end --rroute --ipproto --icmp-help --icmp-ipver --icmp-iphlen --icmp-iplen --icmp-ipid --icmp-ipproto --icmp-cksum --icmp-ts --icmp-addr --tcpexitcode --fast --faster --tr-keep-ttl --tcp-timestamp --tr-stop --tr-no-rtt --rand-dest --rand-source --lsrr --ssrr --route-help --apd-send --icmp-ipsrc --icmp-ipdst --icmp-gw --icmp-srcport --icmp-dstport --force-icmp --beep --flood --dry-run --json --read --clock-skew --clock-skew-win --clock-skew-win-shift --clock-skew-packets-per-sample  )
    shortopts=( -c -i -n -q -I -h -v -p -s -t -N -w -a -F -S -R -P -A -U -X -Y -f -x -y -g -O -r -d -0 -1 -2 -8 -z -Z -D -V -W -k -E -j -J -e -9 -B -T -o -m -Q -b -M -L -C -K -u -G -H  )

    case $words[CURRENT] in
    --*) compadd -- $longopts ;;
    -*)  compadd -- $shortopts $longopts ;;
    *)
        case $words[CURRENT-1] in
        --file|-E|--read|--apd-send|--data|-d|--sign|-e) _files ;;
        --interface|-I) _net_interfaces 2>/dev/null || _files -W /sys/class/net ;;
        *) _alternative 'commands:scripting command:(exec)' 'files:target or file:_files' ;;
        esac ;;
    esac
}

_styxwire "$@"
