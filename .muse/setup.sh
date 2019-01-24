if [ $(whoami) = "root" ]; then
    apt install -y libssl1.0-dev libcurl4-gnutls-dev
fi

cd $1
sed -i 's/gcc_z_support=yes/gcc_z_support=no/' configure
sed -i 's/-z,noexecstack//' configure
./configure LIBS=-lcurl
