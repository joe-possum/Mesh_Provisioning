test : ecdh
	./ecdh e38bb34946b0ddc6443e7eefe58549757d0e61de262d23ae88931199a2a37dcc32c1809ab2aaeaeb5b25e0aa52f78827286565bd5d3a0fc8adf35ea1181f0286 2dcf462904b478d868a7ff3f2bf1fcd97a96092ca5577464c4af1528a4e957db 47d32ba008f8fda910f64cffb250ffb231a87f6a667a064b84c1ad3632041893 9d64cc0328a01c6401b820d3ddba433a

old-test : ecdh
	./ecdh e3393dc64a9a16135c04964ffa59ee6f641c51e38d4bc185b930508520b8a9614aad03b28a239bc495c2da5b3bb791e1b555bba641f7dd07fad98a17d259154d

ecdh : ecdh.c
	gcc -Wall -L/usr/local/lib ecdh.c -lmbedcrypto -o $@
