detectcollv: *.c *.h
	gcc -O3 -march=native -DVERBOSE_COLLDETECT main.c libdetectcoll.c -o detectcollv

detectcoll: *.c *.h
	gcc -O3 -march=native main.c libdetectcoll.c -o detectcoll

detectcoll_reducedsha: *.c *.h
	gcc -O3 -march=native -DVERBOSE_COLLDETECT -DDETECT_REDUCED_SHA_COLLISION main.c libdetectcoll.c -o detectcoll_reducedsha

test: detectcollv
	./detectcollv tests/*
	
all: detectcollv detectcoll detectcoll_reducedsha
