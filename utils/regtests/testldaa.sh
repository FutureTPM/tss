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
echo "LDAA Tests"
echo ""
# These tests fake an LDAA session, all of the data used has been pre-processed
# to guarantee that the results returned are correct

echo "LDAA Create Key"
${PREFIX}create -hp 80000000 -dau -ldaa test_keys/issuer_at.bin -kt f -kt p -opr ldaa_priv.bin -opu ldaa_pub.bin -pwdp sto -pwdk ldaa > run.out
checkSuccess $?

echo ""
echo "Starting LDAA Session"
echo ""

echo "Loading LDAA key"
${PREFIX}load -hp 80000000 -ipr ldaa_priv.bin -ipu ldaa_pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Performing Join Command"
${PREFIX}ldaa_join -hk 80000001 -sid 0 -jsid 1 -bsn issuer -onym ldaa_join_token.bin -pwdk ldaa > run.out
checkSuccess $?

#echo "Try to proceed to commit token link processing without approval by the host (should fail)"
#${PREFIX}ldaa_committokenlink -hk 80000001 -sid 0 -bsn BASENAME -onym ldaa_commit_token.bin -ope ldaa_pe.bin -opbsn ldaa_pbsn.bin -pwdk ldaa > run.out
#checkFailure $?

echo "Host gives TPM permission to proceed"
${PREFIX}ldaa_signproceed -hk 80000001 -sid 0 -pwdk ldaa > run.out
checkSuccess $?

echo "Process Commit Token Link"
${PREFIX}ldaa_committokenlink -hk 80000001 -sid 0 -bsn basename -onym ldaa_commit_token.bin -ope ldaa_pe.bin -opbsn ldaa_pbsn.bin -pwdk ldaa > run.out
checkSuccess $?

echo ""
echo "Start processing commits"
echo ""

for SIGN in $(seq 0 7)
do
    for COMM in "1" "2" "3"
    do
        echo "Processing commit ${COMM} for sign state ${SIGN}"
        ${PREFIX}ldaa_signcommit -v -hk 80000001 -sid 0 -bsn basename -comm "${COMM}" -sign "${SIGN}" -iatntt test_keys/issuer_at_ntt_v2.bin -ibntt "test_keys/host_b_ntt${COMM}_v2.bin" -ipe ldaa_pe.bin -ipbsn ldaa_pbsn.bin -ocomm "ldaa_commit_sign_${SIGN}_commit_${COMM}.bin" -pwdk ldaa > run.out
        checkSuccess $?
    done
done

echo ""
echo "Start sign proof"
echo ""

signT_array=(0 0 1 0 1 0 2 1)

for SIGN in $(seq 0 7)
do
    echo "Processing sign proof for sign state ${SIGN}"
    ${PREFIX}ldaa_signproof -v -pwdk ldaa -hk 80000001 -sid 0 -sign "${SIGN}" -signT "${signT_array[${SIGN}]}" -isign1 "test_keys/ldaa_sign_state_RES${signT_array[${SIGN}]}_1_commit_${SIGN}.bin" -isign2 "test_keys/ldaa_sign_state_RES${signT_array[${SIGN}]}_2_commit_${SIGN}.bin" -osign1 "sign_result_1_${SIGN}.bin" -osign2 "sign_result_2_${SIGN}.bin" -ogroup "sign_group_${SIGN}.bin" > run.out
    checkSuccess $?
done

#echo "Processing sign proof for sign state 1"
#${PREFIX}ldaa_signproof -v -pwdk ldaa -hk 80000001 -sid 0 -sign 0 -signT 0 -isign1 test_keys/ldaa_sign_state_RES0_R2_commit_1.bin -isign2 test_keys/ldaa_sign_state_RES0_R3_commit_1.bin -osign1 sign_result_1_1.bin -osign2 sign_result_2_1.bin -ogroup sign_group_1.bin > run.out
#checkSuccess $?
#
#echo "Processing sign proof for sign state 2"
#${PREFIX}ldaa_signproof -v -pwdk ldaa -hk 80000001 -sid 0 -sign 0 -signT 0 -isign1 test_keys/ldaa_sign_state_RES1_R1_commit_2.bin -isign2 test_keys/ldaa_sign_state_RES1_R3_commit_2.bin -osign1 sign_result_1_2.bin -osign2 sign_result_2_2.bin -ogroup sign_group_2.bin > run.out
#checkSuccess $?

echo "Flushing LDAA key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

# Cleanup
rm ldaa_pub.bin ldaa_priv.bin
rm ldaa_join_token.bin
rm ldaa_commit_token.bin
rm ldaa_pe.bin ldaa_pbsn.bin
rm ldaa_commit_sign_*_commit_*.bin
