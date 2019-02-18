export OPENSSL_DIR=<path to ssl install>
export CURL_DIR=<path to libcurl install>
export ACVP_DIR=<path to libacvp install>
export CRITERION_DIR=<path to criterion install>
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$OPENSSL_DIR/lib:$CURL_DIR/lib:$ACVP_DIR/lib:$CRITERION_DIR/lib
