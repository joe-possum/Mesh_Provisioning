all : ecdh k1 k2 k3 s1 confirmation provisioning-data

test : test-ecdh test-k1 test-k2 test-confirmation test-provisioning-data

test-ecdh : ecdh
	./ecdh e38bb34946b0ddc6443e7eefe58549757d0e61de262d23ae88931199a2a37dcc32c1809ab2aaeaeb5b25e0aa52f78827286565bd5d3a0fc8adf35ea1181f0286 2dcf462904b478d868a7ff3f2bf1fcd97a96092ca5577464c4af1528a4e957db 47d32ba008f8fda910f64cffb250ffb231a87f6a667a064b84c1ad3632041893 9d64cc0328a01c6401b820d3ddba433a

test-k1 : k1
	./k1 3216d1509884b533248541792b877f98 2ba14ffa0df84a2831938d57d276cab4 5a09d60797eeb4478aada59db3352a0d
	./k1 ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69 5faabe187337c71cc6c973369dcaa79a 7072636b

test-k2 : k2
	./k2 f7a2a44f8e8a8029064f173ddc1e2b00 00
	./k2 f7a2a44f8e8a8029064f173ddc1e2b00 010203040506070809

test-k3 : k3
	@echo "-------------------==< 8.1.5 k3 function >==--+"
	@echo "Expect salt: 0036443503f195cc8a716e136291c302 |"
	@echo "          T: 6da9698c95f500e4edce3bb47f92754f |"
	@echo "         T1: 3527c5985f0c05ccff046958233db014 |"
	@echo "     result: ff046958233db014                 |"
	@echo "----------------------------------------------+"
	./k3 f7a2a44f8e8a8029064f173ddc1e2b00

test-confirmation : confirmation
	@echo "--==< Mesh Profile: 8.7.8 PB-ADV Provisioning Confirmation (Provisioner) >==--"
	@echo "Expect salt: 5faabe187337c71cc6c973369dcaa79a"
	@echo "        key: e31fe046c68ec339c425fc6629f0336f"
	@echo "     result: b38a114dfdca1fe153bd2c1e0dc46ac2"
	./confirmation 00 0100010000000000000000 0000000000 2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd919512183898dfbecd52e2408e43871fd021109117bd3ed4eaf8437743715d4f f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279 ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69 8b19ac31d58b124c946209b5db1021b9 00000000000000000000000000000000
	@echo "--==< Mesh Profile: 8.7.9 PB-ADV Provisioning Confirmation (Device) >==--"
	@echo "Expect salt: 5faabe187337c71cc6c973369dcaa79a"
	@echo "        key: e31fe046c68ec339c425fc6629f0336f"
	@echo "     result: eeba521c196b52cc2e37aa40329f554e"
	./confirmation 00 0100010000000000000000 0000000000 2c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd919512183898dfbecd52e2408e43871fd021109117bd3ed4eaf8437743715d4f f465e43ff23d3f1b9dc7dfc04da8758184dbc966204796eccf0d6cf5e16500cc0201d048bcbbd899eeefc424164e33c201c2b010ca6b4d43a8a155cad8ecb279 ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69  55a2a2bca04cd32ff6f346bd0a0c1a3a 00000000000000000000000000000000

test-provisioning-data : provisioning-data
	@echo "------------------------------------==< 8.7.12 PB-ADV Provisioning Data >==--+"
	@echo "Expect provisioning_salt: a21c7d45f201cf9489a2fb57145015b4                   |"
	@echo "             session_key: c80253af86b33dfa450bbdb2a191fea3                   |"
	@echo "                    data: d0bd7f4a89a2ff6222af59a90a60ad58acfe3123356f5cec29 |"
	@echo "                     mac: 73e0ec50783b10c7                                   |"
	@echo "-----------------------------------------------------------------------------+"
	./provisioning-data 5faabe187337c71cc6c973369dcaa79a 8b19ac31d58b124c946209b5db1021b9 55a2a2bca04cd32ff6f346bd0a0c1a3a ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69 efb2255e6422d330088e09bb015ed707056700010203040b0c
	@echo "------------------------------------==< 8.7.12 PB-ADV Provisioning Data >==--+"
	@echo "Expect provisioning_salt: a21c7d45f201cf9489a2fb57145015b4                   |"
	@echo "             session_key: c80253af86b33dfa450bbdb2a191fea3                   |"
	@echo "                    data: efb2255e6422d330088e09bb015ed707056700010203040b0c |"
	@echo "-----------------------------------------------------------------------------+"
	./provisioning-data 5faabe187337c71cc6c973369dcaa79a 8b19ac31d58b124c946209b5db1021b9 55a2a2bca04cd32ff6f346bd0a0c1a3a ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69 d0bd7f4a89a2ff6222af59a90a60ad58acfe3123356f5cec29 73e0ec50783b10c7

old-test : ecdh
	./ecdh e3393dc64a9a16135c04964ffa59ee6f641c51e38d4bc185b930508520b8a9614aad03b28a239bc495c2da5b3bb791e1b555bba641f7dd07fad98a17d259154d

ecdh : ecdh.c
	gcc -Wall -L/usr/local/lib ecdh.c -lmbedcrypto -o $@

k1 : k1.c
	gcc -DTEST_K1 -Wall -L/usr/local/lib k1.c -lmbedcrypto -o $@

k2 : k2.c k1.c s1.c
	gcc -DTEST_K2 -Wall -L/usr/local/lib k2.c k1.c s1.c -lmbedcrypto -o $@

k3 : k3.c s1.c
	gcc -DTEST_K3 -Wall -L/usr/local/lib k3.c s1.c -lmbedcrypto -o $@

s1 : s1.c
	gcc -DTEST_S1 -Wall -L/usr/local/lib s1.c -lmbedcrypto -o $@

confirmation : confirmation.c k1.c s1.c
	gcc -DTEST_CONFIRMATION -Wall -L/usr/local/lib $^ -lmbedcrypto -o $@

provisioning-data : provisioning-data.c k1.c s1.c
	gcc -DTEST_PROVISIONING_DATA -Wall -L/usr/local/lib $^ -lmbedcrypto -o $@

