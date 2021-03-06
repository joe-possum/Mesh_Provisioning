CC = gcc
CFLAGS = -g -Wall

all : ecdh k1 k2 k3 k4 s1 confirmation provisioning-data protocol advertising aes-ccm segmented-messages extract-mesh
	make -C fake-node

test : test-ecdh test-k1 test-k2 test-k3 test-k4 test-confirmation test-provisioning-data

test-ecdh : ecdh
	./ecdh e38bb34946b0ddc6443e7eefe58549757d0e61de262d23ae88931199a2a37dcc32c1809ab2aaeaeb5b25e0aa52f78827286565bd5d3a0fc8adf35ea1181f0286 2dcf462904b478d868a7ff3f2bf1fcd97a96092ca5577464c4af1528a4e957db 47d32ba008f8fda910f64cffb250ffb231a87f6a667a064b84c1ad3632041893 9d64cc0328a01c6401b820d3ddba433a

test-k1 : k1
	./k1 3216d1509884b533248541792b877f98 2ba14ffa0df84a2831938d57d276cab4 5a09d60797eeb4478aada59db3352a0d
	./k1 ab85843a2f6d883f62e5684b38e307335fe6e1945ecd19604105c6f23221eb69 5faabe187337c71cc6c973369dcaa79a 7072636b
	@echo "----------------==< 8.2.5 IdentityKey >==--+"
	@echo "Expect T: 55efb6c898c2a38bc9bd0a6097bff966 |"
	@echo "  return: 84396c435ac48560b5965385253e210c |"
	@echo "-------------------------------------------+"
	./k1 7dd7364cd842ad18c17c2b820c84c3d6 f8795a1aabf182e4f163d86e245e19f4 696431323801
	@echo "------------------==< 8.2.6 BeaconKey >==--+"
	@echo "Expect T: 829816cd429fde7d238b56d8bf771efb |"
	@echo "  return: 5423d967da639a99cb02231a83f7d254 |"
	@echo "-------------------------------------------+"
	./k1 7dd7364cd842ad18c17c2b820c84c3d6 2c24619ab793c1233f6e226738393dec 696431323801

test-k2 : k2
	./k2 f7a2a44f8e8a8029064f173ddc1e2b00 00
	./k2 f7a2a44f8e8a8029064f173ddc1e2b00 010203040506070809
	@echo "--==< 8.2.2 Encryption and privacy keys (Master) >==--+"
	@echo "Expect         salt: 4f90480c1871bfbffd16971f4d8d10b1 |"
	@echo "                  t: 39885e0463bafd54ca6e495b1001515a |"
	@echo "                 t1: 88dad4892e81fecbe061ebd3fb093268 |"
	@echo "                nid: 68                               |"
	@echo "                 ek: 0953fa93e7caac9638f58820220a398e |"
	@echo "                 pk: 8b84eedec100067d670971dd2aa700cf |"
	@echo "------------------------------------------------------+"
	./k2 7dd7364cd842ad18c17c2b820c84c3d6 00
	@echo "--==< 8.2.3 Encryption and privacy keys (Friendship) >==--+"
	@echo "Expect   salt: 4f90480c1871bfbffd16971f4d8d10b1 |"
	@echo "            t: 39885e0463bafd54ca6e495b1001515a |"
	@echo "           t1: d91a3b3c63b5c50a98c838e52a4bc0de |"
	@echo "          nid: 5e                               |"
	@echo "           ek: be635105434859f484fc798e043ce40e |"
	@echo "           pk: 5d396d4b54d3cbafe943e051fe9a4eb8 |"
	./k2 7dd7364cd842ad18c17c2b820c84c3d6 01120123450000072f

test-k3 : k3
	@echo "-------------------==< 8.1.5 k3 function >==--+"
	@echo "Expect salt: 0036443503f195cc8a716e136291c302 |"
	@echo "          T: 6da9698c95f500e4edce3bb47f92754f |"
	@echo "         T1: 3527c5985f0c05ccff046958233db014 |"
	@echo "     result: ff046958233db014                 |"
	@echo "----------------------------------------------+"
	./k3 f7a2a44f8e8a8029064f173ddc1e2b00
	@echo "--------------------==< 8.2.4 Network ID >==--+"
	@echo "Expect salt: 0036443503f195cc8a716e136291c302 |"
	@echo "          T: 36b82fd0fc400e797977bd12d08a4782 |"
	@echo "         T1: ca296bcee3ccc2d33ecaff672f673370 |"
	@echo "     result: 3ecaff672f673370                 |"
	@echo "----------------------------------------------+
	./k3 7dd7364cd842ad18c17c2b820c84c3d6

test-k4 : k4
	@echo "--==< 8.1.6 k4 function >==--+"
	./k4 3216d1509884b533248541792b877f98
	./k4 63964771734fbd76e3b40519d1d94a48

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
	${CC} ${CFLAGS} -L/usr/local/lib ecdh.c -lmbedcrypto -o $@

extract-mesh : extract-mesh.c
	${CC} ${CFLAGS} -L/usr/local/lib $^ -o $@

k1 : k1.c utility.c
	${CC} ${CFLAGS} -DTEST_K1 -L/usr/local/lib $^ -lmbedcrypto -o $@

k2 : k2.c k1.c s1.c utility.c
	${CC} ${CFLAGS} -DTEST_K2 -L/usr/local/lib $^ -lmbedcrypto -o $@

k3 : k3.c s1.c utility.c
	${CC} ${CFLAGS} -DTEST_K3 -L/usr/local/lib $^ -lmbedcrypto -o $@

k4 : k4.c s1.c utility.c
	${CC} ${CFLAGS} -DTEST_K4 -L/usr/local/lib $^ -lmbedcrypto -o $@

s1 : s1.c utility.c
	${CC} ${CFLAGS} -DTEST_S1 -L/usr/local/lib $^ -lmbedcrypto -o $@

aes-ccm : aes-ccm.c utility.c
	${CC} ${CFLAGS} -DTEST_AES_CCM -L/usr/local/lib $^ -lmbedcrypto -o $@

segmented-messages : segmented-messages.c utility.c
	${CC} ${CFLAGS} -DTEST_SEGMENTED_MESSAGES -L/usr/local/lib $^ -lmbedcrypto -o $@

confirmation : confirmation.c k1.c s1.c utility.c
	${CC} ${CFLAGS} -DTEST_CONFIRMATION -L/usr/local/lib $^ -lmbedcrypto -o $@

provisioning-data : provisioning-data.c k1.c s1.c utility.c
	${CC} ${CFLAGS} -DTEST_PROVISIONING_DATA -L/usr/local/lib $^ -lmbedcrypto -o $@

encryption : encryption.c k1.c k2.c k3.c k4.c s1.c utility.c
	${CC} ${CFLAGS} -DTEST_ENCRYPTION -L/usr/local/lib $^ -lmbedcrypto -o $@

protocol : protocol.c encryption.c provisioning-data.c confirmation.c k1.c k2.c k3.c k4.c s1.c utility.c mesh-access-lookup.c mesh-model-lookup.c segmented-messages.c
	${CC} ${CFLAGS} -DTEST_PROTOCOL -L/usr/local/lib $^ -lmbedcrypto -o $@

advertising : advertising.c utility.c cic.c mesh-fault-values.c mesh-model-lookup.c provision_transaction.c protocol.c confirmation.c encryption.c k1.c k2.c k4.c s1.c provisioning-data.c mesh-access-lookup.c segmented-messages.c
	${CC} ${CFLAGS} -DTEST_ADVERTISING -L/usr/local/lib $^ -lmbedcrypto -o $@
