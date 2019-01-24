#!/bin/bash

echo ""
echo "Kyber Tests"
echo ""

echo "Load the kyber key under the primary key"
${PREFIX}load -hp 80000000 -ipr derkyberpriv.bin -ipu derkyberpub.bin -pwdp sto > run.out
checkSuccess $?

echo "Kyber encapsulate with the public key"
${PREFIX}kyber_enc -hk 80000001 -c cipher_text.bin -ss shared_key_1.bin > run.out
checkSuccess $?

echo "Kyber decapsulate with the secret key"
${PREFIX}kyber_dec -hk 80000001 -c cipher_text.bin -ss shared_key_2.bin -pwdk dec > run.out
checkSuccess $?

echo "Verify the shared key result"
diff shared_key_1.bin shared_key_2.bin > run.out
checkSuccess $?

echo "Flush the kyber key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

rm cipher_text.bin
rm shared_key_1.bin shared_key_2.bin
