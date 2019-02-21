#!/bin/bash
#
# MIT License
#
# Copyright (c) 2019 Luís Fiolhais, Paulo Martins, Leonel Sousa (INESC-ID)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

echo ""
echo "Kyber Tests"
echo ""

echo ""
echo "Kyber Encapsulation and Decapsulation"
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

echo ""
echo "Kyber Mutually Authenticated Key Exchange"
echo ""

echo "Create static keys for Alice and Bob"
${PREFIX}create -hp 80000000 -kyber k=2 -den -kt f -kt p -opr static_alice_priv.bin -opu static_alice_pub.bin -pwdp sto -pwdk alice_dec > run.out
checkSuccess $?

${PREFIX}create -hp 80000000 -kyber k=2 -den -kt f -kt p -opr static_bob_priv.bin -opu static_bob_pub.bin -pwdp sto -pwdk bob_dec > run.out
checkSuccess $?

echo ""
echo "1st Phase"
echo ""

echo "Alice starts the first phase of the KEX"
echo "Create ephemeral key"
${PREFIX}create -hp 80000000 -kyber k=2 -den -kt f -kt p -opr ephemeral_priv.bin -opu ephemeral_pub.bin -pwdp sto -pwdk eph  > run.out

echo "Load Bob's public key"
# Returns key handle 80000001
${PREFIX}loadexternal -kyber -den -ipu static_bob_pub.bin > run.out
checkSuccess $?

echo "Encapsulate shared key to Bob"
${PREFIX}kyber_enc -hk 80000001 -c alice_cipher_text_3.bin -ss shared_key_3.bin > run.out
checkSuccess $?

echo "Alice completed the first phase of the KEX!"
echo "Flushing her context"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "2nd Phase"
echo ""

echo "Bob starts the second phase of the KEX"
echo "Load Bob's static key"
# Returns key handle 80000001
${PREFIX}load -hp 80000000 -ipr static_bob_priv.bin -ipu static_bob_pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Load Alice's ephemeral public key"
# Returns key handle 80000002
${PREFIX}loadexternal -kyber -den -ipu ephemeral_pub.bin > run.out
checkSuccess $?

echo "Load Alice's static public key"
# Returns key handle 80000003
${PREFIX}loadexternal -kyber -den -ipu static_alice_pub.bin > run.out
checkSuccess $?

echo "Perform 2nd phase KEX"
${PREFIX}kyber_2phase_kex -hk 80000001 -hke 80000002 -hka 80000003 -pwdk bob_dec -cs alice_cipher_text_3.bin -ss bob_final_shared_key.bin -c1 bob_cipher_text_1.bin -c2 bob_cipher_text_2.bin > run.out
checkSuccess $?

echo "Bob completed the second phase of the KEX!"
echo "Flushing Alice's static public key context"
${PREFIX}flushcontext -ha 80000003 > run.out
checkSuccess $?

echo "Flushing his ephemeral context"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flushing his static context"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "3rd Phase"
echo ""

echo "Alice starts the third and final phase of the KEX"
echo "Load Alice's static key"
# Returns key handle 80000001
${PREFIX}load -hp 80000000 -ipr static_alice_priv.bin -ipu static_alice_pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Load Alice's ephemeral key"
# Returns key handle 80000002
${PREFIX}load -hp 80000000 -ipu ephemeral_pub.bin -ipr ephemeral_priv.bin -pwdp sto > run.out
checkSuccess $?

echo "Perform 3rd phase KEX"
${PREFIX}kyber_3phase_kex -hk 80000001 -hke 80000002 -pwdks alice_dec -pwdke eph -c1 bob_cipher_text_1.bin -c2 bob_cipher_text_2.bin -ssi shared_key_3.bin -sso alice_final_shared_key.bin > run.out
checkSuccess $?

echo "Alice completed the third and final phase of the KEX!"
echo "Flushing her ephemeral context"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flushing her static context"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Verify the final shared key result"
diff alice_final_shared_key.bin bob_final_shared_key.bin > run.out
checkSuccess $?

# Clean
rm cipher_text.bin
rm shared_key_1.bin shared_key_2.bin
rm static_alice_priv.bin static_alice_pub.bin
rm static_bob_priv.bin static_bob_pub.bin
rm bob_cipher_text_1.bin bob_cipher_text_2.bin
rm ephemeral_pub.bin ephemeral_priv.bin
rm shared_key_3.bin alice_cipher_text_3.bin
rm alice_final_shared_key.bin bob_final_shared_key.bin
