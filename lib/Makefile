LIB_SSL=openssl
LIB_SSL_FILES= $(shell find ${LIB_SSL} -name "*.c")

openssl: openssl/libcrypto.a

openssl/libcrypto.a: ${LIB_SSL_FILES}
	cd ${LIB_SSL} && ( [ -f Makefile ] || ./config -DPURIFY )
	${MAKE} -C ${LIB_SSL} depend
	${MAKE} -C ${LIB_SSL}
ifeq (,$(filter nocheck,$(DEB_BUILD_OPTIONS)))
	${MAKE} -C ${LIB_SSL} test
endif
