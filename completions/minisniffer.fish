# Fish completion for MiniSniffer.
#
# Install manually:
#   cp completions/minisniffer.fish ~/.config/fish/completions/minisniffer.fish
#
# `make install` installs this automatically under
# $(PREFIX)/share/fish/vendor_completions.d/minisniffer.fish.

function __minisniffer_interfaces
    ifconfig -l 2>/dev/null | string split ' '
    or command ls /sys/class/net 2>/dev/null
end

complete -c MiniSniffer -f

complete -c MiniSniffer -l help -d 'Print usage and exit'
complete -c MiniSniffer -l version -d 'Print the MiniSniffer version and exit'
complete -c MiniSniffer -l list-interfaces -d 'List libpcap capture devices'
complete -c MiniSniffer -l interface -x -a '(__minisniffer_interfaces)' -d 'Capture from a specific interface'
complete -c MiniSniffer -l count -x -d 'Stop after this many displayed packets'
complete -c MiniSniffer -l quiet -d 'Suppress startup and stop summaries'
complete -c MiniSniffer -l verbose -d 'Print the full startup configuration summary'
complete -c MiniSniffer -l no-color -d 'Disable terminal color output'
complete -c MiniSniffer -l protocol -x -a 'tcp udp icmp arp other' -d 'Display only packets matching the protocol'
complete -c MiniSniffer -l port -x -d 'Display only packets matching this port'
complete -c MiniSniffer -l host -x -d 'Display only packets matching this IPv4 or IPv6 host'
complete -c MiniSniffer -l payload -d 'Print a bounded payload preview'
complete -c MiniSniffer -l payload-bytes -x -d 'Set the payload preview length'
complete -c MiniSniffer -l payload-decode-bytes -x -d 'Set the payload decode window'
complete -c MiniSniffer -l domain-match -x -a 'normalized exact idna' -d 'Set domain matching mode'
complete -c MiniSniffer -l payload-contains -x -d 'Filter on literal payload text'
complete -c MiniSniffer -l payload-hex -x -d 'Filter on hex payload pattern'
complete -c MiniSniffer -l log -r -d 'Write displayed packets to a CSV file'
complete -c MiniSniffer -l read -r -d 'Read packets from an offline pcap file'
complete -c MiniSniffer -l write -r -d 'Write displayed packets to a new pcap file'
complete -c MiniSniffer -l no-bpf -d 'Disable kernel-level BPF pre-filtering'
complete -c MiniSniffer -l json -d 'Print displayed packets as JSON Lines'
complete -c MiniSniffer -l flush-log -x -a 'always line exit' -d 'Control CSV flush timing'
complete -c MiniSniffer -l decode-app -d 'Decode packet-local HTTP, DNS, and TLS ClientHello metadata'
complete -c MiniSniffer -l reassemble -d 'Enable bounded TCP stream reassembly'
complete -c MiniSniffer -l max-flows -x -d 'Set the maximum number of tracked TCP flows'
complete -c MiniSniffer -l stream-buffer-bytes -x -d 'Set the per-direction TCP stream buffer cap'
complete -c MiniSniffer -l flow-timeout -x -d 'Evict flows idle for at least this many seconds'
complete -c MiniSniffer -l app -x -a 'http dns tls dhcp mdns quic' -d 'Display only packets with decoded app metadata'
complete -c MiniSniffer -l http-host -x -d 'Filter on decoded HTTP Host header'
complete -c MiniSniffer -l http-method -x -a 'GET POST PUT DELETE HEAD OPTIONS PATCH TRACE CONNECT' -d 'Filter on decoded HTTP method'
complete -c MiniSniffer -l dns-query -x -d 'Filter on decoded DNS/mDNS query name'
complete -c MiniSniffer -l dns-type -x -a 'A NS CNAME AAAA' -d 'Filter on decoded DNS/mDNS query type'
complete -c MiniSniffer -l tls-sni -x -d 'Filter on decoded TLS SNI hostname'
complete -c MiniSniffer -l tls-alpn -x -d 'Filter on decoded TLS ALPN protocol'
complete -c MiniSniffer -l dhcp-type -x -a 'discover offer request decline ack nak release inform' -d 'Filter on decoded DHCP message type'
complete -c MiniSniffer -l quic-version -x -d 'Filter on decoded QUIC Initial version'
complete -c MiniSniffer -l stats -d 'Print summary statistics after capture completes'
