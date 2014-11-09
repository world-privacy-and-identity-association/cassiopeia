LT_CC=libtool --mode=compile gcc
LT_CC_DEP=gcc
LT_LD=libtool --mode=link gcc

MKDIR=mkdir -p

CC=${LT_CC}
CC_DEP=${LT_CC_DEP}
LD=${LT_LD}

CFLAGS=-O3 -g -flto -Wall -Werror -Wextra -pedantic -std=c11 -Ilib
LDFLAGS=-O3 -g -flto

LIB_DIR=lib
SRC_DIR=src
OBJ_DIR=obj
DEP_DIR=dep

FS_LIB=$(wildcard ${LIB_DIR}/*.c)
FS_SRC=$(wildcard ${SRC_DIR}/*.c)
FS_OBJ_LIB=$(FS_LIB:${LIB_DIR}/%.c=${OBJ_DIR}/%.lo)
FS_OBJ_SRC=$(FS_SRC:${SRC_DIR}/%.c=${OBJ_DIR}/%.lo)
FS_OBJ=$(FS_OBJ_SRC) $(FS_OBJ_LIB)
FS_DEP_LIB=$(FS_LIB:${LIB_DIR}/%.c=${DEP_DIR}/%.d)
FS_DEP_SRC=$(FS_SRC:${SRC_DIR}/%.c=${DEP_DIR}/%.d)
FS_DEP=$(FS_DEP_SRC) $(FS_DEP_LIB)

.SUFFIXES: .c .d

.PHONY: all
all: library tools test

.PHONY: clean
clean::
	-find . -type f -name '*.a' -print -delete
	-find . -type f -name '*.d' -print -delete
	-find . -type f -name '*.o' -print -delete
	-find . -type f -name '*.la' -print -delete
	-find . -type f -name '*.lo' -print -delete
	-find . -type f -name '*.so' -print -delete
	-find . -type d -name '.libs' -print | xargs rm -rv
	-rm -rf bin/*

.PHONY: test
test: tools
	bin/detectcoll_verbose tests/*

.PHONY: tools
tools: detectcoll detectcoll_verbose detectcoll_reducedsha

.PHONY: detectcoll_verbose
detectcoll_verbose: bin/detectcoll_verbose

.PHONY: detectcoll
detectcoll: bin/detectcoll

.PHONY: detectcoll_reducedsha
detectcoll_reducedsha: bin/detectcoll_reducedsha

.PHONY: library
library: bin/libdetectcoll.la

bin/libdetectcoll.la: $(FS_OBJ_LIB)
	${LD} ${CFLAGS} $(FS_OBJ_LIB) -o bin/libdetectcoll.la

bin/detectcoll: $(FS_SRC) $(FS_LIB)
	${LD} ${CFLAGS} $(FS_SRC) $(FS_LIB) -o bin/detectcoll

bin/detectcoll_verbose: $(FS_SRC) $(FS_LIB)
	${LD} ${CFLAGS} -DVERBOSE_COLLDETECT $(FS_SRC) $(FS_LIB) -o bin/detectcoll_verbose

bin/detectcoll_reducedsha: $(FS_SRC) $(FS_LIB)
	${LD} ${CFLAGS} -DVERBOSE_COLLDETECT -DDETECT_REDUCED_SHA_COLLISION $(FS_SRC) $(FS_LIB) -o bin/detectcoll_reducedsha

${DEP_DIR}/%.d: ${LIB_DIR}/%.c
	${MKDIR} $(shell dirname $@) && $(CC_DEP) $(CFLAGS) -M -MF $@ $<

${OBJ_DIR}/%.lo ${OBJ_DIR}/%.o: ${LIB_DIR}/%.c ${DEP_DIR}/%.d
	${MKDIR} $(shell dirname $@) && $(CC) $(CFLAGS) -o $@ -c $<

-include $(FS_DEP)
