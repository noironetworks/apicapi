#!/usr/bin/env python

import os
import sys
import subprocess
import tempfile


def runscript(script):
    retval = -1
    fname = None
    try:
        fname = tempfile.mkstemp()[1]
        with open(fname, 'w') as f:
            f.write(script + '\n')
        process = subprocess.Popen(
            '/bin/bash %s' % fname, shell=True,
            stdout=sys.stdout, stderr=sys.stderr)
        process.wait()
        retval = process.returncode
    except Exception as e:
        sys.stderr.write('Error: {}'.format(e))
    finally:
        if fname is not None:
            os.unlink(fname)
    return retval


host_report_script = r"""
#!/bin/bash

ID=`id -u`
if [ "$ID" -ne 0 ]
then
  echo "You must be root to run this command"
  exit 1
fi

host=`hostname -s`
time_stamp=`date +'%y%m%d-%H%M%S'`
report_name="report-${host}-${time_stamp}"
report_dir="/tmp/${report_name}"
report_file="${report_dir}.tar.gz"

exec 3>&1
prn() { echo "$@" 1>&3 ; }

prn "Creating host report: $report_file"
prn "  Collecting host info ..."
mkdir $report_dir
cd $report_dir
  exec 1>stdout 2>stderr

  date > date-start
  hostname --fqdn > hostname
  uname -a > uname
  uptime > uptime
  dmesg > dmesg
  dmidecode > dmidecode
  lspci > lspci

  ulimit -a > ulimit
  cat /proc/meminfo > meminfo
  cat /proc/cpuinfo > cpuinfo
  free > free
  ps auxww > ps
  top -b -n3 > top
  cat /proc/mounts > mount
  fdisk -l > fdisk
  df > df
  lsmod > lsmod
  sysctl -a > sysctl
  systemctl -l --no-pager list-unit-files > systemctl-units
  systemctl -l --no-pager status > systemctl-status
  chkconfig --list > chkconfig 2>&1
  service --status-all > service-status-all 2>&1

cd $report_dir
mkdir etc
  prn "  Collecting config files"
  cd etc
  cp /etc/*release .
  cp /etc/sysctl.conf .
  for i in sysconfig default neutron \
      group-based-policy servicechain \
      opflex-agent-ovs openvswitch lldpd.d
  do
    cp -r /etc/$i $i
  done

  prn "  Collecting package info (this can take some time) ..."
  rpm -qa > rpm-qa
  rpm -Va > rpm-Va || true

prn "  Collecting network info ..."
cd $report_dir
mkdir network
  cd network
  ip link > ip-link
  ip address > ip-address
  ip route > ip-route
  ip netns > ip-netns
  cat /proc/net/igmp > igmp
  ifconfig > ifconfig
  netstat -tlpn > netstat-tlpn
  netstat -s > netstat-s
  lldpctl > lldpctl
  lldpctl -f keyvalue > lldpctl-kv

prn "  Collecting opflex info ..."
cd $report_dir
mkdir opflex
  cd opflex
  ping -c 3 -w 5 10.0.0.30 1>ping-10.0.0.30 2>&1
  cp -r /var/lib/opflex-agent-ovs opflex-agent-ovs
  cp -r /var/lib/neutron neutron
  gbp_inspect -fpr -t dump -q DmtreeRoot > dmtree-root
  ovs-vsctl show > ovs-show
  ovs-ofctl dump-ports-desc br-int > ovs-ports
  ovs-ofctl dump-ports br-int > ovs-ports-stats
  ovs-ofctl -OOpenFlow13 dump-flows br-int > ovs-flows
  ovs-dpctl show > ovs-ports-dp
  ovs-appctl dpif/tnl/igmp-dump br-int 8472 > ovs-igmp

prn "  Collecting log data (this can take some time) ..."
cd $report_dir
mkdir -p var/log
  date > date-reports
  cd var/log
  journalctl --no-pager -n 10000 -l > journalctl-all
  journalctl --no-pager -n 10000 -l -u agent-ovs.service > journalctl-agent-ovs
  ( find /var/log -type f -not -name \*\[0123456789z\] -print |
    while read name
    do
      filename=`echo $name | cut -c10- | tr '/' '-'`
      tail -n 30000 "$name" > "$filename"
    done
  )

prn "  Creating tar file ..."
cd $report_dir
  date > date-end
  cd ..
  tar -czf $report_file `basename $report_dir`

cd /tmp
exec 2>&1
rm -rf "$report_dir"
prn "Created report: $report_file"
"""


def main():
    return runscript(host_report_script)


if __name__ == "__main__":
    main()
