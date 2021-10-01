#!/usr/bin/env bash

if [ $(whoami) = "root" ]; then
    sudo apt update && sudo apt install -y libssl-dev libcurl4-gnutls-dev
fi

sed -i 's/gcc_z_support=yes/gcc_z_support=no/' configure
sed -i 's/-z,noexecstack//' configure
./configure LIBS=-lcurl --with-libcurl-dir=/usr/lib/x86_64-linux-gnu/
