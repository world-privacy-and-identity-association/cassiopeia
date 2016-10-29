LIB_SSL=openssl
LIB_SSL_FILES= $(shell find ${LIB_SSL} -name "*.c")

LIB_COLL_FILES= $(shell find collisiondetect -name "*.c")

openssl: openssl/libcrypto.a

collisiondetect: collisiondetect/libdetectcoll.la

collisiondetect/libdetectcoll.la: ${LIB_COLL_FILES}
#	make -C collisiondetect
#	echo $^

openssl/libcrypto.a: ${LIB_SSL_FILES}
	cd ${LIB_SSL} && ( [ -f Makefile ] || ./config -DPURIFY )
	${MAKE} -C ${LIB_SSL} depend
	${MAKE} -C ${LIB_SSL}
ifeq (,$(filter nocheck,$(DEB_BUILD_OPTIONS)))
	${MAKE} -C ${LIB_SSL} test
endif
