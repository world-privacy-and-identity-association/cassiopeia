MKDIR = mkdir -p

ifneq (,$(filter noopt,$(DEB_BUILD_OPTIONS)))
    CFLAGS += -O0
else
    CFLAGS += -O2
endif

BIN="bin/cassiopeia-test"
LIBS=openssl collissiondetect

LT_CC=libtool --mode=compile gcc
LT_CC_DEP=g++
LT_CXX=libtool --mode=compile g++
LT_CXX_DEP=g++
LT_LD=libtool --mode=link g++

CC=${LT_CC}
CC_DEP=${LT_CC_DEP}
CXX=${LT_CXX}
CXX_DEP=${LT_CXX_DEP}
LD=${LT_LD}

ifneq (,$(filter debug,$(DEB_BUILD_OPTIONS)))
ADDFLAGS=-DNO_DAEMON
endif

CFLAGS=-O3 -g -flto -Wall -Werror -Wextra -pedantic -std=c++11 -I../src ${ADDFLAGS}
CXXFLAGS=$(CFLAGS)
LDFLAGS=-O3 -g -flto -lmysqlclient -lssl -lcrypto -ldl -lboost_unit_test_framework

SRC_DIR=src
OBJ_DIR=obj
DEP_DIR=dep
TESTDATA_DIR=testdata

FS_SRC=$(wildcard ${SRC_DIR}/*.cpp)
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
	-rm -rf *.a
	-rm -rf *.d
	-rm -rf *.o
	-rm -rf *.la
	-rm -rf *.lo
	-rm -rf *.so
	-rm -rf ${OBJ_DIR}
	-rm -rf ${DEP_DIR}
	-rm -rf ${TESTDATA_DIR}

.PHONY: testdata
testdata:
	./genTestData.sh

build: cassiopeia-test testdata
	${BIN}

.PHONY: install
install: build

.PHONY: libs
libs: ${LIBS}

.PHONY: openssl
openssl:
	${MAKE} -C ../lib/openssl

.PHONY: collissiondetect
collissiondetect:
	${MAKE} -C ../lib/collissiondetect

# --------

cassiopeia-test: bin/cassiopeia-test

bin/cassiopeia-test: libs ${FS_OBJ}
	${MKDIR} $(shell dirname $@) && ${LT_LD} ${LDFLAGS} -o $@ ${FS_OBJ} $(filter-out %/main.o,$(wildcard ../obj/*.o))

${DEP_DIR}/%.d: ${SRC_DIR}/%.cpp
	${MKDIR} $(shell dirname $@) && $(CXX_DEP) $(CXXFLAGS) -M -MF $@ $<
${DEP_DIR}/%.d: ${SRC_DIR}/%.c
	${MKDIR} $(shell dirname $@) && $(CC) $(CXXFLAGS) -M -MF $@ $<

${OBJ_DIR}/%.lo ${OBJ_DIR}/%.o: ${SRC_DIR}/%.c ${DEP_DIR}/%.d
	${MKDIR} $(shell dirname $@) && $(CC) $(CFLAGS) -o $@ -c $<
${OBJ_DIR}/%.lo ${OBJ_DIR}/%.o: ${SRC_DIR}/%.cpp ${DEP_DIR}/%.d
	${MKDIR} $(shell dirname $@) && $(CXX) $(CXXFLAGS) -o $@ -c $<

-include $(FS_DEP)
