#!/usr/bin/env fish
echo "./startup -c"
./startup -c

echo "./createprimary -kyber k=3 -hi p -pwdk sto -tk pritk.bin -ch prich.bin"
./createprimary -kyber k=3 -hi p -pwdk sto -tk pritk.bin -ch prich.bin

echo "./create -hp 80000000 -dau -ldaa ~/Downloads/athens-ldaa/issuer_at.bin mode=weak -kt f -kt p -opr ldaa_priv.bin -opu ldaa_pub.bin -pwdp sto -pwdk ldaa"
./create -hp 80000000 -dau -ldaa ~/Downloads/athens-ldaa/issuer_at.bin mode=weak -kt f -kt p -opr ldaa_priv.bin -opu ldaa_pub.bin -pwdp sto -pwdk ldaa

echo "./load -hp 80000000 -ipr ldaa_priv.bin -ipu ldaa_pub.bin -pwdp sto"
./load -hp 80000000 -ipr ldaa_priv.bin -ipu ldaa_pub.bin -pwdp sto

read -P "Run TPM Join"

echo "./ldaa_join -hk 80000001 -sid 0 -jsid 1 -bsn issuer -onym ldaa_join_token.bin -out ldaa_ut.bin -pwdk ldaa"
./ldaa_join -hk 80000001 -sid 0 -jsid 1 -bsn issuer -onym ldaa_join_token.bin -out ldaa_ut.bin -pwdk ldaa
echo "cp ldaa_join_token.bin ~/Downloads/athens-ldaa/tpm_link_token.bin"
cp ldaa_join_token.bin ~/Downloads/athens-ldaa/tpm_link_token.bin
echo "cp ldaa_ut.bin ~/Downloads/athens-ldaa/tpm_public_key.bin"
cp ldaa_ut.bin ~/Downloads/athens-ldaa/tpm_public_key.bin

echo "./ldaa_signproceed -hk 80000001 -sid 0 -pwdk ldaa"
./ldaa_signproceed -hk 80000001 -sid 0 -pwdk ldaa

read -P "Run TPM Sign Proceed"

echo "./ldaa_committokenlink -hk 80000001 -sid 0 -bsn basename -onym ldaa_nym.bin -ope ldaa_pe.bin -opbsn ldaa_pbsn.bin -pwdk ldaa"
./ldaa_committokenlink -hk 80000001 -sid 0 -bsn basename -onym ldaa_nym.bin -ope ldaa_pe.bin -opbsn ldaa_pbsn.bin -pwdk ldaa
echo "cp ldaa_nym.bin ~/Downloads/athens-ldaa/tpm_sign_link_token.bin"
cp ldaa_nym.bin ~/Downloads/athens-ldaa/tpm_sign_link_token.bin
echo "cp ldaa_pbsn.bin ~/Downloads/athens-ldaa/tpm_pbsn.bin"
cp ldaa_pbsn.bin ~/Downloads/athens-ldaa/tpm_pbsn.bin

for SIGN in (seq 0 3)
    set -l commit1 ldaa_commit_sign_"$SIGN"_commit_1.bin
    set -l commit2 ldaa_commit_sign_"$SIGN"_commit_2.bin
    set -l commit3 ldaa_commit_sign_"$SIGN"_commit_3.bin
    echo "./ldaa_signcommit1 -hk 80000001 -sid 0 -bsn basename -seed deadbee1 -sign $SIGN -iatntt ~/Downloads/athens-ldaa/issuer_at_ntt.bin -ipe ldaa_pe.bin -ipbsn ldaa_pbsn.bin -ocomm $commit1 -pwdk ldaa"
    ./ldaa_signcommit1 -hk 80000001 -sid 0 -bsn basename -seed deadbee1 -sign "$SIGN" -iatntt ~/Downloads/athens-ldaa/issuer_at_ntt.bin -ipe ldaa_pe.bin -ipbsn ldaa_pbsn.bin -ocomm "$commit1" -pwdk ldaa
    echo "./ldaa_signcommit2 -hk 80000001 -sid 0 -bsn basename -seed deadbee2 -sign $SIGN -ipe ldaa_pe.bin -ipbsn ldaa_pbsn.bin -ocomm $commit2 -pwdk ldaa"
    ./ldaa_signcommit2 -hk 80000001 -sid 0 -bsn basename -seed deadbee2 -sign "$SIGN" -ipe ldaa_pe.bin -ipbsn ldaa_pbsn.bin -ocomm "$commit2" -pwdk ldaa
    echo "./ldaa_signcommit3 -hk 80000001 -sid 0 -bsn basename -seed deadbee3 -sign $SIGN -ipe ldaa_pe.bin -ipbsn ldaa_pbsn.bin -ocomm $commit3 -pwdk ldaa"
    ./ldaa_signcommit3 -hk 80000001 -sid 0 -bsn basename -seed deadbee3 -sign "$SIGN" -ipe ldaa_pe.bin -ipbsn ldaa_pbsn.bin -ocomm "$commit3" -pwdk ldaa
    echo "cp $commit1 ~/Downloads/athens-ldaa/tpm_comm1_$SIGN.bin"
    cp $commit1 ~/Downloads/athens-ldaa/tpm_comm1_"$SIGN".bin
    echo "cp $commit2 ~/Downloads/athens-ldaa/tpm_comm2_$SIGN.bin"
    cp $commit2 ~/Downloads/athens-ldaa/tpm_comm2_"$SIGN".bin
    echo "cp $commit3 ~/Downloads/athens-ldaa/tpm_comm3_$SIGN.bin"
    cp $commit3 ~/Downloads/athens-ldaa/tpm_comm3_"$SIGN".bin
end

read -P "Run TPM Sign Proof"
read -aP "Challenges: " signT_array

echo "signT_array = $signT_array"

for SIGN in (seq 0 3)
    set -l index (math $SIGN + 1)
    set -l host_r1 ~/Downloads/athens-ldaa/host_RES"$signT_array[$index]"_1_commit_"$SIGN".bin
    set -l host_r2 ~/Downloads/athens-ldaa/host_RES"$signT_array[$index]"_2_commit_"$SIGN".bin
    echo "./ldaa_signproof -pwdk ldaa -hk 80000001 -sid 0 -sign $SIGN -signT $signT_array[$index] -isign1 $host_r1 -isign2 $host_r2 -osign1 res_1_$SIGN.bin -osign2 res_2_$SIGN.bin -ogroup sign_group_$SIGN.bin"
    ./ldaa_signproof -pwdk ldaa -hk 80000001 -sid 0 -sign "$SIGN" -signT "$signT_array[$index]" -isign1 "$host_r1" -isign2 "$host_r2" -osign1 "res_1_$SIGN.bin" -osign2 "res_2_$SIGN.bin" -ogroup "sign_group_$SIGN.bin"
    echo "cp res_1_$SIGN.bin ~/Downloads/athens-ldaa/res_1_$SIGN.bin"
    echo "cp res_2_$SIGN.bin ~/Downloads/athens-ldaa/res_2_$SIGN.bin"
    echo "cp sign_group_$SIGN.bin ~/Downloads/athens-ldaa/sign_group_$SIGN.bin"
    cp res_1_"$SIGN".bin ~/Downloads/athens-ldaa/res_1_"$SIGN".bin
    cp res_2_"$SIGN".bin ~/Downloads/athens-ldaa/res_2_"$SIGN".bin
    cp sign_group_"$SIGN".bin ~/Downloads/athens-ldaa/sign_group_"$SIGN".bin
end

echo "./flushcontext -ha 80000001"
./flushcontext -ha 80000001

# Cleanup
rm ldaa_pub.bin ldaa_priv.bin
rm ldaa_join_token.bin
rm ldaa_nym.bin
rm ldaa_pe.bin ldaa_pbsn.bin
rm ldaa_commit_sign_*_commit_*.bin
rm sign_group_*.bin
rm res_?_?.bin
