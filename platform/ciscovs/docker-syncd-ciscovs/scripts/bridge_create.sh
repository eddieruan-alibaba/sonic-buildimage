#!/bin/bash

eth=0
cnt=1
br=1
while [ $br -le $1 ]
do
    echo "STEP$br: Checking if bridge br$br already exists..."
    if  ! ifconfig br$br; then
        echo "br$br not found, creating bridge network"
        sudo ip link add br$br type bridge
    fi
    sudo ip link set sw1eth$cnt master br$br
    sudo ip link set br$br up
    sudo ip link set Ethernet$eth master br$br
    ((cnt++))
    eth=$(($eth+4))
    ((br++))
done
echo Configuration done!
