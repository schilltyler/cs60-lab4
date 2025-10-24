#!/bin/bash

if [[ -z $1 ]];
then

    echo "Usage: ./monitor-mode.sh {interface name} {channel}"

else
    if [[ -z $2 ]];
    then

        echo "Usage: ./monitor-mode.sh {interface name} {channel}"

    else

        interface_name=$1
        channel=$2

        sudo ip link set $interface_name down
        sudo iw $interface_name set monitor none
        sudo ip link set $interface_name up

        sudo iw $interface_name set channel $channel

        sudo iw dev

    fi
fi

