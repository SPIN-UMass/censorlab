#!/bin/sh
set -eu

# Firewall rules for nftables
## Which firewall table
FW_TABLE=PREROUTING
## Which queue to use
QUEUE_NUM=0
## Common args
COMMON_ARGS="-j NFQUEUE --queue-num ${QUEUE_NUM}"

case $1 in
  start)
    modprobe xt_NFQUEUE
    iptables -t raw -A $FW_TABLE $COMMON_ARGS
    ;;
  stop)
    modprobe xt_NFQUEUE
    iptables -t raw -D $FW_TABLE $COMMON_ARGS
    ;;
  *)
    ;;
esac
