#!/bin/bash

echo "Hello world" > /dev/ttyprintk
ip link set eth0 up > /dev/ttyprintk
dhcpcd --waitip --nobackground > /dev/ttyprintk
./hello > /dev/ttyprintk
