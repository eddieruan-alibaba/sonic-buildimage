#!/bin/bash

cmd="/usr/lib/frr/zebra -A 127.0.0.1 -s 90000000 -M dplane_fpm_nl -M snmp"

if [ -f /etc/sonic/enable_sonic_fpm ]; then
    cmd="/usr/lib/frr/zebra -A 127.0.0.1 -s 90000000 -M dplane_fpm_sonic -M snmp"
fi

$cmd
