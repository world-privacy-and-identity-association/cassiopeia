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

#include <stdint.h>

// lib interface below

typedef struct {
	uint64_t total;
	uint32_t ihv[4];
	unsigned char buffer[64];
	int bigendian;
	int found_collision;
	int safe_hash;

	uint32_t ihv1[4];
	uint32_t ihv2[4];
	uint32_t m2[16];
	uint32_t states[260];
	uint32_t statesmsb[260];
	uint32_t tmpihv[4];
	uint32_t tmpblock[16];
	uint32_t previhv[4];
	uint32_t prevblock[16];
} MD5_CTX;


void md5compress_states(uint32_t ihv[4], const uint32_t block[16], uint32_t states[260]);
int md5recompress_fast(unsigned t, uint32_t ihv[4], const uint32_t block[16], const uint32_t state[4], const uint32_t rihv[4]);
int detect_coll(const uint32_t block1[16], const uint32_t states[260], const uint32_t statesmsb[260], const uint32_t tihv[4], uint32_t ihv2[4], uint32_t block2[16]);

typedef struct {
	uint32_t msgdiff[16];
	unsigned t;
	int negate;
	int zero;
	int msb;
} msgdiff_tuples_t;
extern msgdiff_tuples_t msgdiff_tuples[];

typedef struct {
	uint64_t total;
	uint32_t ihv[5];
	unsigned char buffer[64];
	int bigendian;
	int found_collision;
	int safe_hash;

	uint32_t ihv1[5];
	uint32_t ihv2[5];
	uint32_t m1[80];
	uint32_t m2[80];
	uint32_t states[81*5];
} SHA1_CTX;	

void sha1compress_me(const uint32_t block[16], uint32_t me[80]);
void sha1compress_states(uint32_t ihv[5], const uint32_t me[80], uint32_t states[81*5]);
int sha1recompress_fast(unsigned t, uint32_t ihv[5], const uint32_t me[80], const uint32_t state[5], const uint32_t rihv[5]);



/* LIB INTERFACE */

void MD5Init(MD5_CTX*); // outputs MD5 hash if no collision was found and a modified-MD5 hash otherwise
void MD5Init_unsafe(MD5_CTX*); // always outputs MD5 hash
void MD5Update(MD5_CTX*, const char* buf, unsigned len);
int  MD5Final(unsigned char hash[16], MD5_CTX*); // returns: 0 = no collision, otherwise = collision found => warn user for active attack

void SHA1Init(SHA1_CTX*); // outputs SHA-1 hash if no collision was found and a modified-SHA-1 hash otherwise
void SHA1Init_unsafe(SHA1_CTX*); // always outputs SHA-1 hash
void SHA1Update(SHA1_CTX*, const char* buf, unsigned len);
int  SHA1Final(unsigned char hash[20], SHA1_CTX*); // returns: 0 = no collision, otherwise = collision found => warn user for active attack
