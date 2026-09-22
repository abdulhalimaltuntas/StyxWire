# styxwire(8) programmable completion for bash.               -*- shell-script -*-
#
# The long-option list below is the binary's own option table
# (parseoptions.c:hping_optlist); tests/completion.sh checks that it matches,
# so it cannot drift silently. Install to the bash-completion directory (see
# INSTALL) or source it from ~/.bashrc.

_styxwire()
{
    local cur prev longopts shortopts
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    longopts="--count --interval --numeric --quiet --interface --help --version --destport --baseport --ttl --id --win --spoof --fin --syn --rst --push --ack --urg --xmas --ymas --frag --morefrag --dontfrag --fragoff --tcpoff --rel --data --rawip --icmp --udp --scan --bind --unbind --debug --verbose --winid --keep --file --dump --print --sign --listen --safe --traceroute --tos --mtu --seqnum --badcksum --setseq --setack --icmptype --icmpcode --end --rroute --ipproto --icmp-help --icmp-ipver --icmp-iphlen --icmp-iplen --icmp-ipid --icmp-ipproto --icmp-cksum --icmp-ts --icmp-addr --tcpexitcode --fast --faster --tr-keep-ttl --tcp-timestamp --tr-stop --tr-no-rtt --rand-dest --rand-source --lsrr --ssrr --route-help --apd-send --icmp-ipsrc --icmp-ipdst --icmp-gw --icmp-srcport --icmp-dstport --force-icmp --beep --flood --dry-run --json --read --clock-skew --clock-skew-win --clock-skew-win-shift --clock-skew-packets-per-sample "
    shortopts="-c -i -n -q -I -h -v -p -s -t -N -w -a -F -S -R -P -A -U -X -Y -f -x -y -g -O -r -d -0 -1 -2 -8 -z -Z -D -V -W -k -E -j -J -e -9 -B -T -o -m -Q -b -M -L -C -K -u -G -H "

    # options whose argument is a file
    case "$prev" in
        --file|-E|--read|--apd-send|--data|-d|--sign|-e)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0 ;;
        --interface|-I)
            local nics
            nics=$(command ls /sys/class/net 2>/dev/null)
            COMPREPLY=( $(compgen -W "$nics" -- "$cur") )
            return 0 ;;
    esac

    if [[ "$cur" == --* ]]; then
        COMPREPLY=( $(compgen -W "$longopts" -- "$cur") )
    elif [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$shortopts $longopts" -- "$cur") )
    else
        # first argument: the "exec" scripting subcommand, a script/pcap
        # file, or a target host
        COMPREPLY=( $(compgen -W "exec" -f -- "$cur") )
    fi
    return 0
}
complete -F _styxwire styxwire hping3 hping2 hping
