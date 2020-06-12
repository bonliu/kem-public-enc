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

  /* Generate X */
	setSeed(0, 0);
	size_t xLen = rsa_numBytesN(K);
	unsigned char *X = malloc(xLen); X[xLen - 1] = 0;
	randBytes(X, xLen - 1);	// Avoid reduction mod n

	/* Open output file */
	FILE *fp = fopen(fnOut, "wb");
	if (fp == NULL) {
		perror("[KEM-ENC] Output file");
		exit(EXIT_FAILURE);
	}

	/* (RSA) Encrypt X */
	unsigned char *xEnc = malloc(xLen);
	rsa_encrypt(xEnc, X, xLen, K);
	fwrite(xEnc, 1, xLen, fp);

	/* H := SHA256 */
	unsigned char H[HASHLEN];
	SHA256(X, xLen, H);
	fwrite(H, 1, HASHLEN, fp);

	fclose(fp);
	/* (SKE) Encrypt fnIn */
	size_t offset = rsa_numBytesN(K) + HASHLEN;
	SKE_KEY SK;
	ske_keyGen(&SK, X, xLen);
	ske_encrypt_file(fnOut, fnIn, &SK, NULL, offset);

	free(X);
	free(xEnc);
  
	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	size_t xLen = rsa_numBytesN(K);
	unsigned char *X    = malloc(xLen);
	unsigned char *xEnc = malloc(xLen);
	FILE *fp = fopen(fnIn, "rb");
	if (fp == NULL) {
		perror("[KEM-DEC] Input file");
		exit(EXIT_FAILURE);
	}
	fread(xEnc, 1, xLen, fp);
	rsa_decrypt(X, xEnc, xLen, K);
	
	/* step 2: check decapsulation */
	unsigned char   H[HASHLEN];
	unsigned char mac[HASHLEN];
	SHA256(X, xLen, H);
	fread(mac, 1, HASHLEN, fp);
	if (memcmp(H, mac, HASHLEN) != 0) {
		fprintf(stderr, "WRONG MAC\n");
		exit(EXIT_FAILURE);
	}

	fclose(fp);
	/* step 3: derive key from ephemKey and decrypt data. */
	size_t offset = xLen + HASHLEN;
	SKE_KEY SK;
	ske_keyGen(&SK, X, xLen);
	ske_decrypt_file(fnOut, fnIn, &SK, offset);

	free(X);
	free(xEnc);
  
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
	FILE *rsaPub, *rsaPvt;
	switch (mode) {
		case ENC:
			/* Read Public key from file */
			rsaPub = fopen(fnKey, "rb");
			if (rsaPub == NULL) {
				perror("[ENC] Public key");
				exit(EXIT_FAILURE);
			}
			rsa_readPublic(rsaPub, &K);
			fclose(rsaPub);
			
			/* Encrypt */
			kem_encrypt(fnOut, fnIn, &K);

			rsa_shredKey(&K);
			break;
		case DEC:
			/* Read Private key from file */
			rsaPvt = fopen(fnKey, "rb");
			if (rsaPvt == NULL) {
				perror("[DEC] Private key");
				exit(EXIT_FAILURE);
			}
			rsa_readPrivate(rsaPvt, &K);
			fclose(rsaPvt);

			/* Decrypt */
			kem_decrypt(fnOut, fnIn, &K);

			rsa_shredKey(&K);
			break;
		case GEN:
			/* ./kem-enc -b 2048 -g /tmp/testkey */
			/* Generate RSA key */
			rsa_keyGen(nBits, &K);

			/* Private key */
			rsaPvt = fopen(fnOut, "wb");
			if (rsaPvt == NULL) {
				perror("[GEN] Private key");
				exit(EXIT_FAILURE);
			}
			rsa_writePrivate(rsaPvt, &K);
			fclose(rsaPvt);
			
			/* Public key */
			strcat(fnOut, ".pub");
			rsaPub = fopen(fnOut, "wb");
			if (rsaPub == NULL) {
				perror("[GEN] Public key");
				exit(EXIT_FAILURE);
			}
			rsa_writePublic(rsaPub, &K);
			fclose(rsaPub);

			rsa_shredKey(&K);
			break;
		default:
			return 1;
	}

	return 0;
}
