pcat() {
  for i in "$@"
  do
    python -mjson.tool "$i"
  done
}

opflex-eps() {
  for i in /var/lib/opflex-agent-ovs/endpoints/*.ep ; do
    [ -f "$i" ] || continue
    echo '#----------------------------------------'
    echo '# EP: ' `basename $i .ep`
    pcat $i;
    echo ""
  done
}

opflex-db() {
  gbp_inspect -fprq DmtreeRoot
}

opflex-flows() {
  ovs-ofctl -OOpenFlow13 dump-flows br-int "$@" ;
}

ovs-ports() {
  ovs-ofctl show br-int | awk '/addr:/ {print $2, $1}'
}

vxlan-pkts() {
  tcpdump -lane -i bond0.4093 "$@" port 8472 | grep --line-buffered -v OTV ;
}
