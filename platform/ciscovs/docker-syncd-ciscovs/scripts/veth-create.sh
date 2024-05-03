#! /bin/bash

for num in {1..128}; do
    ip link add veth"$num" type veth peer name swveth"$num"
    ip link set swveth"$num" up
    ip link set veth"$num" up
    ip link set eth"$num" up
done

