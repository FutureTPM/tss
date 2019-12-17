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
echo "NTTRU Tests"
echo ""

echo ""
echo "NTTRU Encapsulation and Decapsulation"
echo ""

echo "Load the nttru key under the primary key"
${PREFIX}load -hp 80000000 -ipr dernttrupriv.bin -ipu dernttrupub.bin -pwdp sto > run.out
checkSuccess $?

echo "NTTRU encapsulate with the public key"
${PREFIX}nttru_enc -hk 80000001 -c cipher_text.bin -ss shared_key_1.bin > run.out
checkSuccess $?

echo "NTTRU decapsulate with the secret key"
${PREFIX}nttru_dec -hk 80000001 -c cipher_text.bin -ss shared_key_2.bin -pwdk dec > run.out
checkSuccess $?

echo "Verify the shared key result"
diff shared_key_1.bin shared_key_2.bin > run.out
checkSuccess $?

# Clean
rm cipher_text.bin
rm shared_key_1.bin shared_key_2.bin
