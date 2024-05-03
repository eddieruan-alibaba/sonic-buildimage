#!/bin/bash

for ((i=1; i<=128; i++))
do
    /sbin/tc qdisc add dev eth$i ingress
    /sbin/tc filter add dev eth$i parent ffff: \
                        protocol all u32 match u8 0 0 \
                        action mirred egress redirect dev swveth$i

    /sbin/tc qdisc add dev swveth$i ingress
    /sbin/tc filter add dev swveth$i parent ffff: \
                        protocol all u32 match u8 0 0 \
                        action mirred egress redirect dev eth$i
done

