/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>

#include "ske.h"
#include "rsa.h"
#include "prf.h"

#include <errno.h>

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255

enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */
// #define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"

int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */

	// RSA-KEM(X) := RSA(X)|H(X) = RSA(X)|SHA256(X)
	/* Select x in random */
	setSeed(0, 0);
	unsigned char x[KLEN_SKE];	// x should be as much entropy as the key
	randBytes(x, KLEN_SKE);

	/* Apply RSA on x */
	size_t rsaNB = rsa_numBytesN(K);
	unsigned char rsaCt[rsaNB];
	rsa_encrypt(rsaCt, x, rsaNB, K);

	/* Compute H := SHA256 */
	unsigned char H[HASHLEN];
	// HMAC(EVP_sha256(), KDF_KEY, HASHLEN, x, KLEN_SKE, hmac, NULL);
	SHA256(x, rsaNB, H);
	
	/* write RSA-KEM(X) to file */
	FILE *fp = fopen(fnOut, "wb");
	if (fp == NULL) {
		perror("[ENC] Error: ");
		exit(1);
	}
	fwrite(rsaCt, 1, rsaNB, fp);
	fwrite(H, 1, HASHLEN, fp);
	fclose(fp);

	/* Compute key for SKE 
	   NOTE: HMAC-SHA512 will compute inside ske_keyGen() */
	SKE_KEY SK;
	ske_keyGen(&SK, x, KLEN_SKE);

	/* Encrypt fnIn */
	ske_encrypt_file(fnOut, fnIn, &SK, NULL, rsaNB + HASHLEN);

	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	FILE *fp = fopen(fnIn, "rb");
	if (fp == NULL) {
		perror("[KEM-DEC] Error: ");
		exit(1);
	}
	
	size_t rsaCtLen = rsa_numBytesN(K);
	unsigned char* rsaCt = malloc(rsaCtLen);
	unsigned char* rsaPt = malloc(rsaCtLen);
	fread(rsaCt, 1, rsaCtLen, fp);
	rsa_decrypt(rsaPt, rsaCt, rsaCtLen, K);

	/* step 2: check decapsulation */
	unsigned char* mac = malloc(HASHLEN);
	unsigned char* inMac = malloc(HASHLEN);
	fread(inMac, 1, HASHLEN, fp);
	SHA256(rsaPt, rsaCtLen, mac);
	if (memcmp(mac, inMac, HASHLEN) != 0) {
		fprintf(stderr, "INCORRECT MAC\n");
		exit(1);
	}
	fclose(fp);

	/* step 3: derive key from ephemKey and decrypt data. */
	// size_t inLen = strlen(fnIn);
	// size_t SKECtLen = inLen - rsaCtLen - HASHLEN;
	SKE_KEY SK;
	ske_keyGen(&SK, rsaPt, rsaCtLen);
	ske_decrypt_file(fnOut, fnIn, &SK, rsaCtLen + HASHLEN);
	// ske_decrypt((unsigned char *) fnOut, 
	// 			(unsigned char *) fnIn + rsaCtLen + HASHLEN,
	// 			SKECtLen, &SK);
	return 0;
}

int main(int argc, char *argv[]) {
	/* define long options */
	static struct option long_opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	// size_t nBits = 2048;
	size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				printf(usage,argv[0],nBits);
				return 0;
			case 'i':
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o':
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}

	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */
	RSA_KEY K;
	FILE *rsaPub;
	FILE *rsaPvt;
	switch (mode) {
		case ENC:
		{
			printf("[ENC] fnIn: %s\n", fnIn);
			printf("[ENC] fnOut: %s\n", fnOut);
			printf("[ENC] fnKey: %s\n", fnKey);
			// strcat(fnKey, ".pub");
			rsaPub = fopen(fnKey, "rb");
			if (rsaPub == NULL) {
				perror("[ENC] Error: ");
				exit(1);
			} else {
				rsa_readPublic(rsaPub, &K);
				fclose(rsaPub);
				kem_encrypt(fnOut, fnIn, &K);
			}

			
			rsa_shredKey(&K);
			break;
		}
		case DEC:
			printf("[DEC] fnIn: %s\n", fnIn);
			printf("[DEC] fnOut: %s\n", fnOut);
			printf("[DEC] fnKey: %s\n", fnKey);
			rsaPvt = fopen(fnKey, "rb");
			if (rsaPvt == NULL) {
				perror("[DEC] Error: ");
				exit(1);
			} else {
				rsa_readPrivate(rsaPvt, &K);
				kem_decrypt(fnOut, fnIn, &K);
			}

			fclose(rsaPvt);
			rsa_shredKey(&K);
			break;
		case GEN:
			printf("[GEN] fnIn: %s\n", fnIn);
			printf("[GEN] fnOut: %s\n", fnOut);
			printf("[GEN] optarg: %s\n", optarg);
			// nBits corresponds to the length of new RSA key
			rsa_keyGen(nBits, &K);
			/* Write RSA private key*/
			rsaPvt = fopen(fnOut, "wb");
			if (rsaPvt == NULL) {
				perror("[GEN RSA PVT] Error: ");
				exit(1);
			} else {
				rsa_writePrivate(rsaPvt, &K);
				fclose(rsaPvt);
			}

			strcat(fnOut, ".pub");
			rsaPub = fopen(fnOut, "wb");
			if (rsaPub == NULL) {
				perror("[GEN RSA PUB] Error: ");
				exit(1);
			} else {
				rsa_writePublic(rsaPub, &K);
				fclose(rsaPub);
			}

			rsa_shredKey(&K);
			break;
		default:
			return 1;
	}

	return 0;
}
