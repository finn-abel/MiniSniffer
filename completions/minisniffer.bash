# Bash completion for MiniSniffer.
#
# Install manually:
#   source completions/minisniffer.bash
# Or copy into your bash-completion directory, e.g.:
#   cp completions/minisniffer.bash /etc/bash_completion.d/minisniffer
#
# `make install` installs this automatically under
# $(PREFIX)/share/bash-completion/completions/minisniffer.

_minisniffer() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD - 1]}"

    opts="--help --version --list-interfaces --interface --count --quiet --verbose
          --no-color --protocol --port --host --payload --payload-bytes
          --payload-decode-bytes --domain-match --payload-contains --payload-hex
          --log --read --write --no-bpf --json --flush-log --decode-app
          --reassemble --max-flows --stream-buffer-bytes --flow-timeout --app
          --http-host --http-method --dns-query --dns-type --tls-sni --tls-alpn
          --dhcp-type --quic-version --stats"

    case "$prev" in
        --protocol)
            COMPREPLY=($(compgen -W "tcp udp icmp arp other" -- "$cur"))
            return 0
            ;;
        --app)
            COMPREPLY=($(compgen -W "http dns tls dhcp mdns quic" -- "$cur"))
            return 0
            ;;
        --domain-match)
            COMPREPLY=($(compgen -W "normalized exact idna" -- "$cur"))
            return 0
            ;;
        --flush-log)
            COMPREPLY=($(compgen -W "always line exit" -- "$cur"))
            return 0
            ;;
        --http-method)
            COMPREPLY=($(compgen -W "GET POST PUT DELETE HEAD OPTIONS PATCH TRACE CONNECT" -- "$cur"))
            return 0
            ;;
        --dns-type)
            COMPREPLY=($(compgen -W "A NS CNAME AAAA" -- "$cur"))
            return 0
            ;;
        --dhcp-type)
            COMPREPLY=($(compgen -W "discover offer request decline ack nak release inform" -- "$cur"))
            return 0
            ;;
        --interface)
            COMPREPLY=($(compgen -W "$(command ifconfig -l 2>/dev/null || command ls /sys/class/net 2>/dev/null)" -- "$cur"))
            return 0
            ;;
        --log|--read|--write)
            COMPREPLY=($(compgen -f -- "$cur"))
            return 0
            ;;
        --count|--port|--payload-bytes|--payload-decode-bytes|--max-flows| \
        --stream-buffer-bytes|--flow-timeout|--host|--payload-contains| \
        --payload-hex|--http-host|--dns-query|--tls-sni|--tls-alpn|--quic-version)
            return 0
            ;;
    esac

    COMPREPLY=($(compgen -W "$opts" -- "$cur"))
    return 0
}

complete -F _minisniffer MiniSniffer
