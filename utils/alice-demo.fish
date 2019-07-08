#!/usr/bin/env fish
set -x TPM_COMMAND_PORT 2325
set -x TPM_PLATFORM_PORT 2326

echo "./startup -c"
./startup -c

echo "./createprimary -kyber k=3 -hi p -pwdk sto -tk alice-pritk.bin -ch alice-prich.bin"
./createprimary -kyber k=3 -hi p -pwdk sto -tk alice-pritk.bin -ch alice-prich.bin

echo "./create -hp 80000000 -si -dilithium mode=2 -kt f -kt p -opr dil_priv.bin -opu dil_pub.bin -pwdp sto -pwdk dilithium"
./create -hp 80000000 -si -dilithium mode=2 -kt f -kt p -opr dil_priv.bin -opu dil_pub.bin -pwdp sto -pwdk dilithium

read -P "Create Bob's key-pair before running next command"

echo "./loadexternal -hi p -den -ipu kyber_pub.bin"
./loadexternal -hi p -den -ipu kyber_pub.bin

echo "./kyberencrypt -hk 80000001 -id test.txt -oe enc.bin"
./kyberencrypt -hk 80000001 -id test.txt -oe enc.bin

echo "./flushcontext -ha 80000001"
./flushcontext -ha 80000001

echo "./load -hp 80000000 -ipr dil_priv.bin -ipu dil_pub.bin -pwdp sto"
./load -hp 80000000 -ipr dil_priv.bin -ipu dil_pub.bin -pwdp sto

echo "./sign -hk 80000001 -dilithium -if enc.bin -os sig.bin -pwdk dilithium"
./sign -hk 80000001 -dilithium -if enc.bin -os sig.bin -pwdk dilithium
