#!/bin/bash

echo ""
echo "Kyber decryption key"
echo ""

echo "Load the decryption key under the primary key"
${PREFIX}load -hp 80000000 -ipr derkyberpriv.bin -ipu derkyberpub.bin -pwdp sto > run.out
checkSuccess $?

#echo "Kyber encrypt with the encryption key"
#${PREFIX}kyberencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
#checkSuccess $?
#
#echo "Kyber decrypt with the decryption key"
#${PREFIX}kyberdecrypt -hk 80000001 -ie enc.bin -od dec.bin -pwdk dec > run.out
#checkSuccess $?
#
#echo "Verify the decrypt result"
#tail -c 3 dec.bin > tmp.bin
#diff policies/aaa tmp.bin > run.out
#checkSuccess $?

echo "Flush the decryption key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?
