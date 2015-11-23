if [ "$(id -u)" != "0" ]; then
    exit 0
fi

pcat() {
  for i in "$@"
  do
    python -mjson.tool "$i"
  done
}

ovs-ports() {
  ovs-ofctl show br-int | awk '/addr:/ {print $2, $1}'
}

opflex-db() {
  gbp_inspect -fprq DmtreeRoot
}

opflex-eps() {
  for i in /var/lib/opflex-agent-ovs/endpoints/*.ep ; do
    [ -f "$i" ] || continue
    echo '#----------------------------------------'
    echo '# EP: ' `basename $i .ep`
    pcat $i
    echo ""
  done
}

opflex-flows() {
  ovs-ofctl -OOpenFlow13 dump-flows br-int "$@"
}

opflex-svc() {
  supervisorctl -c /var/lib/neutron/opflex_agent/metadata.conf "$@"
}

vxlan-pkts() {
  opflex_iface=bond0.4093
  if [ -n "$1" ] ; then
    opflex_iface="$1"
    shift
  fi
  tcpdump -lane -i "$opflex_iface" "$@" port 8472 | grep --line-buffered -v OTV ;
}
