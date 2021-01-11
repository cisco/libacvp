#!/usr/bin/env bash

if [ $(whoami) = "root" ]; then
    apt update && apt install -y libssl-dev libcurl4-gnutls-dev
fi

cd $1
sed -i 's/gcc_z_support=yes/gcc_z_support=no/' configure
sed -i 's/-z,noexecstack//' configure
./configure LIBS=-lcurl --with-libcurl-dir=/usr/lib/x86_64-linux-gnu/
