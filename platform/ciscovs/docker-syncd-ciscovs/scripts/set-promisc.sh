#!/bin/bash

for ((i=1; i<=128; i++))
do
	ip link set eth$i promisc on
done
