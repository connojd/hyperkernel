#!/bin/bash

ip link set eth0 up
dhcpcd --waitip
./hello
