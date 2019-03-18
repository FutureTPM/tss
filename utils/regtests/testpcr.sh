#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#		$Id: testpcr.sh 1301 2018-08-15 21:46:19Z kgoldman $		#
#										#
# (c) Copyright IBM Corporation 2015 - 2018					#
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################

#
# for pcrextend
#

# extend of aaa + 0 pad to digest length using pcrextend, use resettable PCR 16

# sha1extaaa0.bin
# 1d 47 f6 8a ce d5 15 f7 79 73 71 b5 54 e3 2d 47
# 98 1a a0 a0

# sha256extaaa0.bin
# c2 11 97 64 d1 16 13 bf 07 b7 e2 04 c3 5f 93 73
# 2b 4a e3 36 b4 35 4e bc 16 e8 d0 c3 96 3e be bb

# sha384extaaa0.bin
# 29 29 63 e3 1c 34 c2 72 bd ea 27 15 40 94 af 92
# 50 ad 97 d9 e7 44 6b 83 6d 3a 73 7c 90 ca 47 df
# 2c 39 90 21 ce dd 00 85 3e f0 84 97 c5 a4 23 84

# sha512extaaa0.bin
# 7f e1 e4 cf 01 52 93 13 6b f1 30 18 30 39 b6 a6
# 46 ea 00 8b 75 af d0 f8 46 6a 9b fe 53 1a f8 ad
# a8 67 a6 58 28 cf ce 48 60 77 52 9e 54 f1 83 0a
# a4 9a b7 80 56 2b ae a4 9c 67 a8 73 34 ff e7 78

# sha3-256extaaa0.bin
# 7b ad 50 33 30 70 a0 4d 83 cc be 61 ec fa 13 27
# d6 1e 2f 4a 0e 29 37 37 ca e9 f8 f2 25 7e 56 a7

# sha3-384extaaa0.bin
# a7 5f 49 05 20 ba f3 5d 9d bd 31 8d 2a e6 6c 78
# 88 19 61 15 14 62 d5 b1 fb a3 9a c9 1c 3f 29 c3
# 51 75 b6 d2 ad 53 fd 56 83 1b 48 b4 69 b5 95 53

# sha3-512extaaa0.bin
# e6 4d 24 94 9c a0 d9 34 0c 6d 1e 71 c1 9a 91 e1
# 60 ee 58 2c 13 39 b9 24 68 ec 38 ab 7a 45 6e 27
# 97 9c a7 ea d7 70 2e 8f 6e eb 54 36 c9 81 93 fa
# cd 8e cc 3e ab 34 d1 a0 88 eb e4 6b d2 70 a9 d2

#
# for pcrevent
#

# first hash using hash -ic aaa -ns
# then extend using policymaker

# sha1 of aaa
# 7e240de74fb1ed08fa08d38063f6a6a91462a815
# extend
# ab 53 c7 ec 3f fe fe 21 9e 9d 89 da f1 8e 16 55
# 3e 23 8e a6

# sha256 of aaa
# 9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0
# extend
# df 81 1e 9d 19 a0 d3 3d e6 7b b1 c7 26 a6 20 5c
# d0 a2 eb 0f 61 b7 c9 ee 91 66 eb cf dc 17 db ab

# sha384 of aaa
# 8e07e5bdd64aa37536c1f257a6b44963cc327b7d7dcb2cb47a22073d33414462bfa184487cf372ce0a19dfc83f8336d8
# extend of that
# 61 bc 70 39 e2 94 87 c2 17 b0 b1 46 10 5d 64 e6
# ad 32 a6 d5 c2 5b 45 01 a7 4b bc a7 7f cc 24 25
# 36 ca 1a 40 f9 36 44 f0 d8 b0 98 ea a6 50 97 4d

# sha512 of aaa
# d6f644b19812e97b5d871658d6d3400ecd4787faeb9b8990c1e7608288664be77257104a58d033bcf1a0e0945ff06468ebe53e2dff36e248424c7273117dac09
# extend of that (using policymaker)
# cb 7f be b3 1c 29 61 24 4c 9c 47 80 84 0d b4 3a
# 76 3f ba 96 ef c1 d9 52 f4 e3 e0 2c 06 8a 31 8a
# e5 3f a0 a7 a1 74 e8 23 e3 07 1a cd c6 52 6f b6
# 77 6d 07 0f 36 47 27 4d a6 29 db c9 10 a7 6c 2a

# sha3-256 of aaa
# 80fb34a2c6bc537d2d044c013042b3b36239aaf3cfd381d62a9ab8e8753876d0
# extend of that (using policymaker)
# de 6a 4c cd 15 d9 28 e8 3f f0 c2 a5 b5 ba 08 d4
# 40 6c 39 78 85 5c f8 4d c0 b0 4b 9a 33 08 02 f7

# sha3-384 of aaa
# e4a9e91e5c0dce64649fff8efab71939d2b9e5a7678edffd19e48112a744e2fbd31884b37de34a7fc41739c338ee25b1
# extend of that (using policymaker)
# 1a 57 b3 bb a2 bb a5 bd 6b b9 70 e8 a3 11 64 86
# ba c1 9f 8a ba ac 64 dd 82 bd ed c7 47 65 e2 e5
# a6 5b 08 c9 fc e8 b4 9e 2f d7 ad d2 e7 70 af c0

# sha3-512 of aaa
# f6518719cabaf6268c008ecca3f39c166720d252b9b5053a8b37a7f40465222fd8485e122e27eb387894f52b913d7aa0a3b615fbd62fff573dbdf3ba381c7ef2
# extend of that (using policymaker)
# 1b 96 6a 1b df 30 97 34 65 7f 4e 34 39 d0 b5 13
# 3b e8 29 54 10 f0 c5 25 97 2c c4 df 9c 5e 12 9c
# 9c 17 73 3a d7 bf d2 cc 79 22 5b fa 1f b2 b0 38
# 61 f8 28 3f e9 76 e6 c2 f2 8b b6 20 a7 eb 91 9c

# all these variables are related

# bank algorithm test pattern is

BANKS=( \
"sha1 " \
"sha256 " \
"sha1 sha256 " \
"sha384 " \
"sha1 sha384 " \
"sha256 sha384 " \
"sha1 sha256 sha384 " \
"sha512 " \
"sha1 sha512 " \
"sha256 sha512 " \
"sha1 sha256 sha512 " \
"sha384 sha512 " \
"sha1 sha384 sha512 " \
"sha256 sha384 sha512 " \
"sha1 sha256 sha384 sha512 " \
"sha3-256 " \
"sha1 sha3-256 " \
"sha256 sha3-256 " \
"sha1 sha256 sha3-256 " \
"sha384 sha3-256 " \
"sha1 sha384 sha3-256 " \
"sha256 sha384 sha3-256 " \
"sha1 sha256 sha384 sha3-256 " \
"sha512 sha3-256 " \
"sha1 sha512 sha3-256 " \
"sha256 sha512 sha3-256 " \
"sha1 sha256 sha512 sha3-256 " \
"sha384 sha512 sha3-256 " \
"sha1 sha384 sha512 sha3-256 " \
"sha256 sha384 sha512 sha3-256 " \
"sha1 sha256 sha384 sha512 sha3-256 " \
"sha3-384 " \
"sha1 sha3-384 " \
"sha256 sha3-384 " \
"sha1 sha256 sha3-384 " \
"sha384 sha3-384 " \
"sha1 sha384 sha3-384 " \
"sha256 sha384 sha3-384 " \
"sha1 sha256 sha384 sha3-384 " \
"sha512 sha3-384 " \
"sha1 sha512 sha3-384 " \
"sha256 sha512 sha3-384 " \
"sha1 sha256 sha512 sha3-384 " \
"sha384 sha512 sha3-384 " \
"sha1 sha384 sha512 sha3-384 " \
"sha256 sha384 sha512 sha3-384 " \
"sha1 sha256 sha384 sha512 sha3-384 " \
"sha3-256 sha3-384 " \
"sha1 sha3-256 sha3-384 " \
"sha256 sha3-256 sha3-384 " \
"sha1 sha256 sha3-256 sha3-384 " \
"sha384 sha3-256 sha3-384 " \
"sha1 sha384 sha3-256 sha3-384 " \
"sha256 sha384 sha3-256 sha3-384 " \
"sha1 sha256 sha384 sha3-256 sha3-384 " \
"sha512 sha3-256 sha3-384 " \
"sha1 sha512 sha3-256 sha3-384 " \
"sha256 sha512 sha3-256 sha3-384 " \
"sha1 sha256 sha512 sha3-256 sha3-384 " \
"sha384 sha512 sha3-256 sha3-384 " \
"sha1 sha384 sha512 sha3-256 sha3-384 " \
"sha256 sha384 sha512 sha3-256 sha3-384 " \
"sha1 sha256 sha384 sha512 sha3-256 sha3-384 " \
"sha3-512 " \
"sha1 sha3-512 " \
"sha256 sha3-512 " \
"sha1 sha256 sha3-512 " \
"sha384 sha3-512 " \
"sha1 sha384 sha3-512 " \
"sha256 sha384 sha3-512 " \
"sha1 sha256 sha384 sha3-512 " \
"sha512 sha3-512 " \
"sha1 sha512 sha3-512 " \
"sha256 sha512 sha3-512 " \
"sha1 sha256 sha512 sha3-512 " \
"sha384 sha512 sha3-512 " \
"sha1 sha384 sha512 sha3-512 " \
"sha256 sha384 sha512 sha3-512 " \
"sha1 sha256 sha384 sha512 sha3-512 " \
"sha3-256 sha3-512 " \
"sha1 sha3-256 sha3-512 " \
"sha256 sha3-256 sha3-512 " \
"sha1 sha256 sha3-256 sha3-512 " \
"sha384 sha3-256 sha3-512 " \
"sha1 sha384 sha3-256 sha3-512 " \
"sha256 sha384 sha3-256 sha3-512 " \
"sha1 sha256 sha384 sha3-256 sha3-512 " \
"sha512 sha3-256 sha3-512 " \
"sha1 sha512 sha3-256 sha3-512 " \
"sha256 sha512 sha3-256 sha3-512 " \
"sha1 sha256 sha512 sha3-256 sha3-512 " \
"sha384 sha512 sha3-256 sha3-512 " \
"sha1 sha384 sha512 sha3-256 sha3-512 " \
"sha256 sha384 sha512 sha3-256 sha3-512 " \
"sha1 sha256 sha384 sha512 sha3-256 sha3-512 " \
"sha3-384 sha3-512 " \
"sha1 sha3-384 sha3-512 " \
"sha256 sha3-384 sha3-512 " \
"sha1 sha256 sha3-384 sha3-512 " \
"sha384 sha3-384 sha3-512 " \
"sha1 sha384 sha3-384 sha3-512 " \
"sha256 sha384 sha3-384 sha3-512 " \
"sha1 sha256 sha384 sha3-384 sha3-512 " \
"sha512 sha3-384 sha3-512 " \
"sha1 sha512 sha3-384 sha3-512 " \
"sha256 sha512 sha3-384 sha3-512 " \
"sha1 sha256 sha512 sha3-384 sha3-512 " \
"sha384 sha512 sha3-384 sha3-512 " \
"sha1 sha384 sha512 sha3-384 sha3-512 " \
"sha256 sha384 sha512 sha3-384 sha3-512 " \
"sha1 sha256 sha384 sha512 sha3-384 sha3-512 " \
"sha3-256 sha3-384 sha3-512 " \
"sha1 sha3-256 sha3-384 sha3-512 " \
"sha256 sha3-256 sha3-384 sha3-512 " \
"sha1 sha256 sha3-256 sha3-384 sha3-512 " \
"sha384 sha3-256 sha3-384 sha3-512 " \
"sha1 sha384 sha3-256 sha3-384 sha3-512 " \
"sha256 sha384 sha3-256 sha3-384 sha3-512 " \
"sha1 sha256 sha384 sha3-256 sha3-384 sha3-512 " \
"sha512 sha3-256 sha3-384 sha3-512 " \
"sha1 sha512 sha3-256 sha3-384 sha3-512 " \
"sha256 sha512 sha3-256 sha3-384 sha3-512 " \
"sha1 sha256 sha512 sha3-256 sha3-384 sha3-512 " \
"sha384 sha512 sha3-256 sha3-384 sha3-512 " \
"sha1 sha384 sha512 sha3-256 sha3-384 sha3-512 " \
"sha256 sha384 sha512 sha3-256 sha3-384 sha3-512 " \
"sha1 sha256 sha384 sha512 sha3-256 sha3-384 sha3-512 " \
)

# bank extend algorithm test pattern is

EXTEND=( \
"-halg sha1 " \
"-halg sha256 " \
"-halg sha1 -halg sha256 " \
"-halg sha384 " \
"-halg sha1 -halg sha384 " \
"-halg sha256 -halg sha384 " \
"-halg sha1 -halg sha256 -halg sha384 " \
"-halg sha512 " \
"-halg sha1 -halg sha512 " \
"-halg sha256 -halg sha512 " \
"-halg sha1 -halg sha256 -halg sha512 " \
"-halg sha384 -halg sha512 " \
"-halg sha1 -halg sha384 -halg sha512 " \
"-halg sha256 -halg sha384 -halg sha512 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha512 " \
"-halg sha3-256 " \
"-halg sha1 -halg sha3-256 " \
"-halg sha256 -halg sha3-256 " \
"-halg sha1 -halg sha256 -halg sha3-256 " \
"-halg sha384 -halg sha3-256 " \
"-halg sha1 -halg sha384 -halg sha3-256 " \
"-halg sha256 -halg sha384 -halg sha3-256 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha3-256 " \
"-halg sha512 -halg sha3-256 " \
"-halg sha1 -halg sha512 -halg sha3-256 " \
"-halg sha256 -halg sha512 -halg sha3-256 " \
"-halg sha1 -halg sha256 -halg sha512 -halg sha3-256 " \
"-halg sha384 -halg sha512 -halg sha3-256 " \
"-halg sha1 -halg sha384 -halg sha512 -halg sha3-256 " \
"-halg sha256 -halg sha384 -halg sha512 -halg sha3-256 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha512 -halg sha3-256 " \
"-halg sha3-384 " \
"-halg sha1 -halg sha3-384 " \
"-halg sha256 -halg sha3-384 " \
"-halg sha1 -halg sha256 -halg sha3-384 " \
"-halg sha384 -halg sha3-384 " \
"-halg sha1 -halg sha384 -halg sha3-384 " \
"-halg sha256 -halg sha384 -halg sha3-384 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha3-384 " \
"-halg sha512 -halg sha3-384 " \
"-halg sha1 -halg sha512 -halg sha3-384 " \
"-halg sha256 -halg sha512 -halg sha3-384 " \
"-halg sha1 -halg sha256 -halg sha512 -halg sha3-384 " \
"-halg sha384 -halg sha512 -halg sha3-384 " \
"-halg sha1 -halg sha384 -halg sha512 -halg sha3-384 " \
"-halg sha256 -halg sha384 -halg sha512 -halg sha3-384 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha512 -halg sha3-384 " \
"-halg sha3-256 -halg sha3-384 " \
"-halg sha1 -halg sha3-256 -halg sha3-384 " \
"-halg sha256 -halg sha3-256 -halg sha3-384 " \
"-halg sha1 -halg sha256 -halg sha3-256 -halg sha3-384 " \
"-halg sha384 -halg sha3-256 -halg sha3-384 " \
"-halg sha1 -halg sha384 -halg sha3-256 -halg sha3-384 " \
"-halg sha256 -halg sha384 -halg sha3-256 -halg sha3-384 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha3-256 -halg sha3-384 " \
"-halg sha512 -halg sha3-256 -halg sha3-384 " \
"-halg sha1 -halg sha512 -halg sha3-256 -halg sha3-384 " \
"-halg sha256 -halg sha512 -halg sha3-256 -halg sha3-384 " \
"-halg sha1 -halg sha256 -halg sha512 -halg sha3-256 -halg sha3-384 " \
"-halg sha384 -halg sha512 -halg sha3-256 -halg sha3-384 " \
"-halg sha1 -halg sha384 -halg sha512 -halg sha3-256 -halg sha3-384 " \
"-halg sha256 -halg sha384 -halg sha512 -halg sha3-256 -halg sha3-384 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha512 -halg sha3-256 -halg sha3-384 " \
"-halg sha3-512 " \
"-halg sha1 -halg sha3-512 " \
"-halg sha256 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha3-512 " \
"-halg sha384 -halg sha3-512 " \
"-halg sha1 -halg sha384 -halg sha3-512 " \
"-halg sha256 -halg sha384 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha3-512 " \
"-halg sha512 -halg sha3-512 " \
"-halg sha1 -halg sha512 -halg sha3-512 " \
"-halg sha256 -halg sha512 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha512 -halg sha3-512 " \
"-halg sha384 -halg sha512 -halg sha3-512 " \
"-halg sha1 -halg sha384 -halg sha512 -halg sha3-512 " \
"-halg sha256 -halg sha384 -halg sha512 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha512 -halg sha3-512 " \
"-halg sha3-256 -halg sha3-512 " \
"-halg sha1 -halg sha3-256 -halg sha3-512 " \
"-halg sha256 -halg sha3-256 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha3-256 -halg sha3-512 " \
"-halg sha384 -halg sha3-256 -halg sha3-512 " \
"-halg sha1 -halg sha384 -halg sha3-256 -halg sha3-512 " \
"-halg sha256 -halg sha384 -halg sha3-256 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha3-256 -halg sha3-512 " \
"-halg sha512 -halg sha3-256 -halg sha3-512 " \
"-halg sha1 -halg sha512 -halg sha3-256 -halg sha3-512 " \
"-halg sha256 -halg sha512 -halg sha3-256 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha512 -halg sha3-256 -halg sha3-512 " \
"-halg sha384 -halg sha512 -halg sha3-256 -halg sha3-512 " \
"-halg sha1 -halg sha384 -halg sha512 -halg sha3-256 -halg sha3-512 " \
"-halg sha256 -halg sha384 -halg sha512 -halg sha3-256 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha512 -halg sha3-256 -halg sha3-512 " \
"-halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha3-384 -halg sha3-512 " \
"-halg sha256 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha3-384 -halg sha3-512 " \
"-halg sha384 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha384 -halg sha3-384 -halg sha3-512 " \
"-halg sha256 -halg sha384 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha3-384 -halg sha3-512 " \
"-halg sha512 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha512 -halg sha3-384 -halg sha3-512 " \
"-halg sha256 -halg sha512 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha512 -halg sha3-384 -halg sha3-512 " \
"-halg sha384 -halg sha512 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha384 -halg sha512 -halg sha3-384 -halg sha3-512 " \
"-halg sha256 -halg sha384 -halg sha512 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha512 -halg sha3-384 -halg sha3-512 " \
"-halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha256 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha384 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha384 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha256 -halg sha384 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha512 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha512 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha256 -halg sha512 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha512 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha384 -halg sha512 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha384 -halg sha512 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha256 -halg sha384 -halg sha512 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
"-halg sha1 -halg sha256 -halg sha384 -halg sha512 -halg sha3-256 -halg sha3-384 -halg sha3-512 " \
)

# bank event file test pattern is

EVENT=( \
"-of1 tmpsha1.bin " \
"-of2 tmpsha256.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin " \
"-of3 tmpsha384.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin " \
"-of5 tmpsha512.bin " \
"-of1 tmpsha1.bin -of5 tmpsha512.bin " \
"-of2 tmpsha256.bin -of5 tmpsha512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of5 tmpsha512.bin " \
"-of3 tmpsha384.bin -of5 tmpsha512.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of5 tmpsha512.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin " \
"-of32 tmpsha3-256.bin " \
"-of1 tmpsha1.bin -of32 tmpsha3-256.bin " \
"-of2 tmpsha256.bin -of32 tmpsha3-256.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of32 tmpsha3-256.bin " \
"-of3 tmpsha384.bin -of32 tmpsha3-256.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of32 tmpsha3-256.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of32 tmpsha3-256.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of32 tmpsha3-256.bin " \
"-of5 tmpsha512.bin -of32 tmpsha3-256.bin " \
"-of1 tmpsha1.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin " \
"-of2 tmpsha256.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin " \
"-of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin " \
"-of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of33 tmpsha3-384.bin " \
"-of2 tmpsha256.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of33 tmpsha3-384.bin " \
"-of3 tmpsha384.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of33 tmpsha3-384.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of33 tmpsha3-384.bin " \
"-of5 tmpsha512.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin " \
"-of2 tmpsha256.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin " \
"-of3 tmpsha384.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin " \
"-of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of2 tmpsha256.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of3 tmpsha384.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of2 tmpsha256.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin " \
"-of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of35 tmpsha3-512.bin " \
"-of3 tmpsha384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of35 tmpsha3-512.bin " \
"-of5 tmpsha512.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of5 tmpsha512.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of5 tmpsha512.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of5 tmpsha512.bin -of35 tmpsha3-512.bin " \
"-of3 tmpsha384.bin -of5 tmpsha512.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of35 tmpsha3-512.bin " \
"-of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of3 tmpsha384.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of5 tmpsha512.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of35 tmpsha3-512.bin " \
"-of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of3 tmpsha384.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of5 tmpsha512.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of3 tmpsha384.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of3 tmpsha384.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
"-of1 tmpsha1.bin -of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin -of32 tmpsha3-256.bin -of33 tmpsha3-384.bin -of35 tmpsha3-512.bin " \
)

# assuming starts with sha1 sha256 sha384 sha512 sha3-256 sha3-384 sha3-512

ALLOC=( \
"-sha256 -sha384 -sha512 -sha3-256 -sha3-384 -sha3-512 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 +sha512 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 -sha512 +sha3-256 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 +sha512 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 -sha512 -sha3-256 +sha3-384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 +sha512 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 -sha512 +sha3-256 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 +sha512 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 -sha512 -sha3-256 -sha3-384 +sha3-512 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 +sha512 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 -sha512 +sha3-256 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 +sha512 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 -sha512 -sha3-256 +sha3-384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 +sha512 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 -sha512 +sha3-256 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 -sha384 +sha512 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
"-sha1 -sha256 +sha384 " \
"+sha1 " \
"-sha1 +sha256 " \
"+sha1 " \
)

# i is iterator over PCR bank allocation patterns
for ((i = 0 ; i < 127 ; i++))
do
    echo ""
    echo "pcrallocate ${BANKS[i]}"
    echo ""
    ${PREFIX}pcrallocate ${ALLOC[i]} > run.out
    checkSuccess $?

    echo "powerup"
    ${PREFIX}powerup > run.out
    checkSuccess $?

    echo "startup"
    ${PREFIX}startup > run.out
    checkSuccess $?

    echo "display PCR banks"
    ${PREFIX}getcapability -cap 5 > run.out
    checkSuccess $?

    echo ""
    echo "PCR Extend"
    echo ""

    echo "PCR Reset banks ${BANKS[i]}"
    ${PREFIX}pcrreset -ha 16 > run.out
    checkSuccess $?

    echo "PCR Extend ${EXTEND[i]}"
    ${PREFIX}pcrextend -ha 16 ${EXTEND[i]} -if policies/aaa > run.out
    checkSuccess $?

    for HALG in ${BANKS[i]}
    do

	echo "PCR Read ${HALG}"
	${PREFIX}pcrread -ha 16 -halg ${HALG} -of tmp.bin > run.out
	checkSuccess $?

	echo "Verify the read data ${HALG}"
	diff policies/${HALG}extaaa0.bin tmp.bin > run.out
	checkSuccess $?

    done

    echo ""
    echo "PCR Event"
    echo ""

    echo "PCR Reset"
    ${PREFIX}pcrreset -ha 16 > run.out
    checkSuccess $?

    echo "PCR Event ${EVENT[i]}"
    ${PREFIX}pcrevent -ha 16 -if policies/aaa ${EVENT[i]} > run.out
    checkSuccess $?

    for HALG in ${BANKS[i]}
    do

    	echo "Verify Digest ${HALG}"
    	diff policies/${HALG}aaa.bin tmp${HALG}.bin > run.out
    	checkSuccess $?

    	echo "PCR Read ${HALG}"
    	${PREFIX}pcrread -ha 16 -halg ${HALG} -of tmp${HALG}.bin > run.out
    	checkSuccess $?

    	echo "Verify Digest ${HALG}"
    	diff policies/${HALG}exthaaa.bin tmp${HALG}.bin > run.out
    	checkSuccess $?

    done

    echo ""
    echo "Event Sequence Complete"
    echo ""

    echo "PCR Reset"
    ${PREFIX}pcrreset -ha 16 > run.out
    checkSuccess $?

    echo "Event sequence start, alg null"
    ${PREFIX}hashsequencestart -halg null -pwda aaa > run.out
    checkSuccess $?

    echo "Event Sequence Complete"
    ${PREFIX}eventsequencecomplete -hs 80000000 -pwds aaa -ha 16 -if policies/aaa ${EVENT[i]} > run.out
    checkSuccess $?

    for HALG in ${BANKS[i]}
    do

	echo "Verify Digest ${HALG}"
	diff policies/${HALG}aaa.bin tmp${HALG}.bin > run.out
	checkSuccess $?

	echo "PCR Read ${HALG}"
	${PREFIX}pcrread -ha 16 -halg ${HALG} -of tmp${HALG}.bin > run.out
	checkSuccess $?

	echo "Verify Digest ${HALG}"
	diff policies/${HALG}exthaaa.bin tmp${HALG}.bin > run.out
	checkSuccess $?

    done

done

echo "PCR Reset"
${PREFIX}pcrreset -ha 16 > run.out
checkSuccess $?

# recreate the primaty key that was fluched on the powerup

initprimary
