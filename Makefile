test : ecdh
	./ecdh e3393dc64a9a16135c04964ffa59ee6f641c51e38d4bc185b930508520b8a9614aad03b28a239bc495c2da5b3bb791e1b555bba641f7dd07fad98a17d259154d

ecdh : ecdh.c
	gcc -Wall ecdh.c -lmbedcrypto -o $@
