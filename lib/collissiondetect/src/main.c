/**************************************************************************\
|
|    Copyright (C) 2012 CWI
|    
|    Contact:
|    Marc Stevens
|    Cryptology Group
|    Centrum Wiskunde & Informatica
|    P.O. Box 94079, 1090 GB Amsterdam, Netherlands
|    marc@marc-stevens.nl
|
|  Permission is hereby granted, free of charge, to any person obtaining a copy
|  of this software and associated documentation files (the "Software"), to deal
|  in the Software without restriction, including without limitation the rights
|  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
|  copies of the Software, and to permit persons to whom the Software is
|  furnished to do so, subject to the following conditions:
| 
|  The above copyright notice and this permission notice shall be included in
|  all copies or substantial portions of the Software.
| 
|  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
|  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
|  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
|  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
|  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
|  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
|  THE SOFTWARE.
|
\**************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libdetectcoll.h"

int main(int argc, char** argv) {
	FILE* fd;
	unsigned char hash[16];
	unsigned char hash2[20];
	char buffer[65536];
	unsigned size;
	MD5_CTX ctx;
	SHA1_CTX ctx2;
	int i,j;

	gen_sha1_dv_xm_tables();
	if (argc < 2) {
		printf("Usage: md5sum <file>\n");
		return 1;
	}
	for (i=1; i < argc; ++i) {
		fd = fopen(argv[i], "rb");
		if (fd == NULL) {
			printf("cannot open file: %s\n", argv[i]);
			return 1;
		}

		MD5Init_unsafe(&ctx);
		SHA1Init_unsafe(&ctx2);

		while (1) {
			size=fread(buffer,1,65536,fd);
			MD5Update(&ctx, buffer, size);
			SHA1Update(&ctx2, buffer, size);
			if (size != 65536)
				break;
		}
		if (ferror(fd)) {
			printf("error while reading file: %s\n", argv[i]);
			return 1;
		}
		if (!feof(fd)) {
			printf("not end of file?: %s\n",argv[i]);
			return 1;
		}

		MD5Final(hash,&ctx);
		for (j = 0; j < 16; ++j) 
			sprintf(buffer+(j*2), "%02x", hash[j]);
		buffer[32] = 0;
		if (ctx.found_collision) {
			printf("md5 *coll* %s %s\n", buffer, argv[i]);
		} else {
			printf("md5 %s %s\n", buffer, argv[i]);
		}

		SHA1Final(hash2,&ctx2);
		for (j = 0; j < 20; ++j) 
			sprintf(buffer+(j*2), "%02x", hash2[j]);
		buffer[20*2] = 0;
		if (ctx2.found_collision) {
			printf("sha1 *coll* %s %s\n", buffer, argv[i]);
		} else {
			printf("sha1 %s %s\n", buffer, argv[i]);
		}
		printf("\n");

		fclose(fd);
	}
}
