INSTALL = ${shell which install}
INSTALL_FILE    = $(INSTALL) -p -D -o root -g root  -m  644
INSTALL_PROGRAM = $(INSTALL) -p -D -o root -g root  -m  700
INSTALL_SCRIPT  = $(INSTALL) -p -D -o root -g root  -m  700
INSTALL_DIR     = $(INSTALL) -p -d -o root -g root  -m  755

MKDIR = mkdir -p

ifeq (,$(filter nostrip,$(DEB_BUILD_OPTIONS)))
    INSTALL_PROGRAM += -s
endif
ifneq (,$(filter parallel=%,$(DEB_BUILD_OPTIONS)))
    NUMJOBS = $(patsubst parallel=%,%,$(filter parallel=%,$(DEB_BUILD_OPTIONS)))
    MAKEFLAGS += -j$(NUMJOBS)
endif

BIN="bin/cassiopeia"
LIBS=openssl collissiondetect

CC=libtool --mode=compile gcc
CC_DEP=g++
CXX=libtool --mode=compile g++
CXX_DEP=g++
LD=libtool --mode=link g++

ifneq (,$(filter debug,$(DEB_BUILD_OPTIONS)))
CFLAGS+=-DNO_DAEMON -g
endif
ifneq (,$(filter noopt,$(DEB_BUILD_OPTIONS)))
    CFLAGS += -O0
else
    CFLAGS += -O2
endif

CFLAGS+=${ADDFLAGS} -Wall -Werror -Wextra -pedantic -std=c++11 -Ilib/openssl/include -Isrc
CXXFLAGS=$(CFLAGS)
LDFLAGS+=${ADDFLAGS} -L/usr/lib/i386-linux-gnu/ -lssl -lcrypto -ldl -Llib/openssl

ifneq (,$(filter coverage,$(DEB_BUILD_OPTIONS)))
    LDFLAGS += -lgcov
    CFLAGS += -fprofile-arcs -ftest-coverage
endif


SRC_DIR=src
OBJ_DIR=obj
DEP_DIR=dep

FS_SRC=$(wildcard ${SRC_DIR}/*.cpp) $(wildcard ${SRC_DIR}/io/*.cpp) $(wildcard ${SRC_DIR}/crypto/*.cpp) $(wildcard ${SRC_DIR}/db/*.cpp)

FS_BIN=$(wildcard ${SRC_DIR}/app/*.cpp)
FS_LIBS=$(wildcard lib/*/)
FS_OBJ=$(FS_SRC:${SRC_DIR}/%.cpp=${OBJ_DIR}/%.lo)
FS_DEP=$(FS_SRC:${SRC_DIR}/%.cpp=${DEP_DIR}/%.d)

.SUFFIXES: .c .cpp .d

.PHONY: all
all: build

.PHONY: clean
clean::
	-rm -rf .libs
	-rm -rf *.gcov
	-rm -rf gcov.log
	-rm -rf *.a
	-rm -rf *.d
	-rm -rf *.o
	-rm -rf *.la
	-rm -rf *.lo
	-rm -rf *.so
	-rm -rf ${OBJ_DIR}
	-rm -rf ${DEP_DIR}
ifeq (,$(filter nocheck,$(DEB_BUILD_OPTIONS)))
	# Code to run the package test suite.
	ADDFLAGS="$(ADDFLAGS)" DEB_BUILD_OPTIONS="$(DEB_BUILD_OPTIONS)" ${MAKE} -C test clean
endif

.PHONY: dist-clean
dist-clean: clean
	${MAKE} -C lib/openssl clean
	${MAKE} -C lib/collissiondetect clean


build: cassiopeia
ifeq (,$(filter nocheck,$(DEB_BUILD_OPTIONS)))
	ADDFLAGS="$(ADDFLAGS)" DEB_BUILD_OPTIONS="$(DEB_BUILD_OPTIONS)" ${MAKE} -C test
endif

.PHONY: install
install: build
	${INSTALL_PROGRAM} bin/cassiopeia ${DESTDIR}/usr/bin/cassiopeia
	${INSTALL_PROGRAM} bin/cassiopeia-signer ${DESTDIR}/usr/bin/cassiopeia-signer
	${INSTALL_DIR} ${DESTDIR}/etc/cacert/cassiopeia

.PHONY: libs
libs: ${LIBS}

.PHONY: openssl
openssl:
	${MAKE} -C lib openssl

.PHONY: collissiondetect
collissiondetect:
	${MAKE} -C lib/collissiondetect

.PHONY: coverage
coverage:
	find . -name "*.gcda" -exec rm {} + &&\
	rm -rf coverage &&\
	rm -rf coverage.info coverage_stripped.info &&\
	${MAKE} "DEB_BUILD_OPTIONS=coverage noopt" &&\
	lcov -c --directory obj --directory test/obj --output-file coverage.info &&\
	lcov -r coverage.info "/usr/**" -o coverage_stripped.info &&\
	genhtml -p $(shell pwd) coverage_stripped.info --output-directory coverage

# --------

cassiopeia: bin/cassiopeia bin/cassiopeia-signer

bin/cassiopeia: libs ${FS_OBJ} ${OBJ_DIR}/apps/client.lo
	${MKDIR} $(shell dirname $@) &&  ${LD} ${LDFLAGS} -lmysqlclient -o $@ ${FS_OBJ} ${OBJ_DIR}/apps/client.lo

bin/cassiopeia-signer: libs ${FS_OBJ} ${OBJ_DIR}/apps/signer.lo
	${MKDIR} $(shell dirname $@) &&  ${LD} ${LDFLAGS} -o $@ $(filter-out ${OBJ_DIR}/db/mysql.lo,${FS_OBJ}) ${OBJ_DIR}/apps/signer.lo

${DEP_DIR}/%.d: ${SRC_DIR}/%.cpp
	${MKDIR} $(shell dirname $@) && $(CXX_DEP) $(CXXFLAGS) -M -MF $@ $<
${DEP_DIR}/%.d: ${SRC_DIR}/%.c
	${MKDIR} $(shell dirname $@) && $(CC) $(CXXFLAGS) -M -MF $@ $<

${OBJ_DIR}/%.lo ${OBJ_DIR}/%.o: ${SRC_DIR}/%.c ${DEP_DIR}/%.d
	${MKDIR} $(shell dirname $@) && $(CC) $(CFLAGS) -o $@ -c $<
${OBJ_DIR}/%.lo ${OBJ_DIR}/%.o: ${SRC_DIR}/%.cpp ${DEP_DIR}/%.d
	${MKDIR} $(shell dirname $@) && $(CXX) $(CXXFLAGS) -o $@ -c $<

-include $(FS_DEP)
