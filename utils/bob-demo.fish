#!/usr/bin/env fish

echo "./create -hp 80000000 -kyber k=4 -den -kt f -kt p -opr kyber_priv.bin -opu kyber_pub.bin -pwdp sto -pwdk kyber"
./create -hp 80000000 -kyber k=4 -den -kt f -kt p -opr kyber_priv.bin -opu kyber_pub.bin -pwdp sto -pwdk kyber

read -P "Run Alice's command before running next command"

echo "./load -hp 80000000 -ipr kyber_priv.bin -ipu kyber_pub.bin -pwdp sto"
./load -hp 80000000 -ipr kyber_priv.bin -ipu kyber_pub.bin -pwdp sto

echo "./loadexternal -hi p -ipu dil_pub.bin"
./loadexternal -hi p -ipu dil_pub.bin

echo "./verifysignature -hk 80000002 -dilithium -if enc.bin -is sig.bin"
./verifysignature -hk 80000002 -dilithium -if enc.bin -is sig.bin

echo "./kyberdecrypt -hk 80000001 -ie enc.bin -od dec.bin -pwdk kyber"
./kyberdecrypt -hk 80000001 -ie enc.bin -od dec.bin -pwdk kyber

echo "./flushcontext -ha 80000001"
echo "./flushcontext -ha 80000002"
./flushcontext -ha 80000001
./flushcontext -ha 80000002
