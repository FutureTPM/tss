#!/usr/bin/env bash

./startup
./getrandom -by 32 -of cred.bin
./createekcert -alg rsa -cakey cakey.pem -capwd rrrr -noflush
./createprimary -kyber k=4 -hi o -kt p -kt f -st
./create -dilithium mode=2 -kt p -kt f -hp 80000001 -opr akpriv.bin -opu akpub.bin -sir -pol policies/policyccactivate.bin
./load -hp 80000001 -ipr akpriv.bin -ipu akpub.bin
./makecredential -ha 80000001 -icred cred.bin -in h80000002.bin -ocred credblob.bin -os secret.bin
./startauthsession -se p
./policycommandcode -ha 03000000 -cc 00000147
./activatecredential -ha 80000002 -hk 80000001 -icred credblob.bin -is secret.bin -se0 03000000 1
