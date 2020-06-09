#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+----------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(IV|C) (32 bytes for SHA256) |
 * +------------+--------------------+----------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */
	if (entropy) {
		setSeed(entropy, entLen);
		randBytes(K->hmacKey, KLEN_SKE);
		HMAC(EVP_sha512(), KDF_KEY, HM_LEN, entropy, entLen, K->aesKey, NULL);
	} else {
		setSeed(0,0);
		randBytes(K->hmacKey, KLEN_SKE);
		randBytes(K->aesKey, KLEN_SKE);
	}
	
	return 0;
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}
size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */
	
	// Setup IV
	size_t ivLen = AES_BLOCK_SIZE;
	unsigned char iv[ivLen];
	if (IV) {
		memcpy(iv,IV,ivLen);
	} else {
		setSeed(0,0);
		randBytes(iv, ivLen);
	}

	// Encrypt message (AES)
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,K->aesKey,iv)) {
		ERR_print_errors_fp(stderr);
	}

	unsigned char aesCt[len]; memset(aesCt,0,len);
	int msgLen = len -1;	// -1 to exclude null char
	int ctLen;
	if (1!=EVP_EncryptUpdate(ctx,aesCt,&ctLen,inBuf,msgLen)) {
		ERR_print_errors_fp(stderr);
	}
	EVP_CIPHER_CTX_free(ctx);

	// Compute HMAC(IV|C) (32 bytes for SHA256) 
	unsigned int macLen = HM_LEN;
	unsigned char *mac = malloc(macLen); memset(mac,0,macLen);
	
	unsigned char *ivc = malloc(ivLen+ctLen); memset(ivc,0,ivLen+ctLen+1);
	memcpy(ivc,iv,ivLen);
	memcpy(ivc+ivLen, aesCt, ctLen);
	size_t ivcLen = ivLen + ctLen;

	// HMAC(EVP_sha256(),K->hmacKey,KLEN_SKE,ivc,ivcLen,mac,&macLen);
	HMAC(EVP_sha256(),K->hmacKey,KLEN_SKE,ivc,ivcLen,mac, NULL);

	// Construct output
	memset(outBuf,0,ivcLen+1+macLen);

	memcpy(outBuf, ivc, ivcLen);
	memcpy(outBuf+ivcLen, "\0", 1);
	memcpy(outBuf+ivcLen+1, mac, macLen);
	memcpy(outBuf+ivcLen+1+macLen, "\0", 1);
	
	return ivcLen+1+macLen; /* TODO: should return number of bytes written, which
	             hopefully matches ske_getOutputLen(...). */
}
size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */
	// Map input into memory
	int fdin = open(fnin, O_RDONLY);
	struct stat sb;
	if (fstat(fdin,&sb) == -1) {
		fprintf(stderr, "[SKE-ENC] Can't get input file size.\n");
		exit(1);
	}
	size_t ptLen = sb.st_size + 1;	// + 1 to include null char
	char *pt = mmap(NULL, ptLen, PROT_READ, MAP_PRIVATE, fdin, 0);
	if (pt == MAP_FAILED) {
		fprintf(stderr, "[SKE-ENC] INPUT MAP_FAILED.\n");
		exit(1);
	}

	// Map output into memory
	int fdout = open(fnout, O_RDWR | O_CREAT | O_APPEND, S_IRWXU);
	if (fstat(fdout,&sb) == -1) {
		fprintf(stderr, "[SKE-ENC] Can't get output file size.\n");
		exit(1);	
	}
	// Write some character to file to get desired file size
	size_t ctLen = ske_getOutputLen(ptLen);
	char *tmp = malloc(ctLen);
	write(fdout, tmp, ctLen);

	ctLen += offset_out;
	unsigned char* ct = malloc(ctLen);
	ct = mmap(NULL, ctLen, PROT_READ | PROT_WRITE, MAP_SHARED, fdout, 0);
	if (ct == MAP_FAILED) {
		fprintf(stderr, "[SKE-ENC] OUTPUT MAP_FAILED.\n");
		exit(1);
	}
	
	// Encrypt
	ske_encrypt((unsigned char *) ct + offset_out,
				(unsigned char *) pt,
				ptLen, K, IV);
	
	// Clean up
	munmap(pt, ptLen - 1);
	munmap(ct, ctLen);
	close(fdin);
	close(fdout);
	
	return 0;
}
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */

	// Compute MAC
	size_t macLen = HM_LEN;
	size_t ivcLen = len - macLen - 1;	// -1 to exclude null char
	printf("ivcLen = %ld\n", ivcLen);
	unsigned char *mac = malloc(macLen);
	HMAC(EVP_sha256(),K->hmacKey,KLEN_SKE,inBuf,ivcLen,mac,NULL);
	
	// Autheticate
	if (memcmp(mac, inBuf+ivcLen+1, HM_LEN) != 0) return -1;

	// Decrypt
	// Extract iv
	size_t ivLen = AES_BLOCK_SIZE;
	unsigned char iv[ivLen];
	memcpy(iv,inBuf,ivLen);

	int nWritten;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,K->aesKey,iv)) {
		ERR_print_errors_fp(stderr);
	}
	
	int ctLen = ivcLen - ivLen;
	unsigned char ct[ctLen];
	memcpy(ct, inBuf+ivLen, ctLen);
	if (1!=EVP_DecryptUpdate(ctx,outBuf,&nWritten,ct,ctLen)) {
		ERR_print_errors_fp(stderr);
	}
	EVP_CIPHER_CTX_free(ctx);

	memset(outBuf+ctLen, 0, 1);

	return nWritten;
}
size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */
	// Map input into memory
	int fdin = open(fnin, O_RDONLY);
	struct stat sb;
	if (fstat(fdin,&sb) == -1) {
		fprintf(stderr, "[SKE-DEC] Can't get input file size.\n");
		exit(1);
	}
	size_t ctLen = sb.st_size;
	printf("ctLen = %ld\n", ctLen);
	char *ct = mmap(NULL, ctLen, PROT_READ, MAP_PRIVATE, fdin, 0);
	if (ct == MAP_FAILED) {
		fprintf(stderr, "[SKE-DEC] INPUT MAP_FAILED");
	}

	// Map output into memory
	int fdout = open(fnout, O_RDWR | O_CREAT | O_APPEND, S_IRWXU);
	if (fstat(fdin,&sb) == -1) {
		fprintf(stderr, "[SKE-DEC] Can't get output file size.\n");
		exit(1);
	}
	// Write some character to file to get desired file size
	// -1 to exclude null char
	size_t ptLen = ctLen - offset_in - AES_BLOCK_SIZE - HM_LEN - 1;
	char *tmp = malloc(ptLen);
	write(fdout, tmp, ptLen);	// Write will append null char. -1 later

	// ptLen += offset_in;
	unsigned char *pt = malloc(ptLen);
	pt = mmap(NULL, ptLen - 1, PROT_READ | PROT_WRITE, MAP_SHARED, fdout, 0);
	if (pt == MAP_FAILED) {
		fprintf(stderr, "[SKE-DEC] OUTPUT MAP FAILED.\n");
		exit(1);
	}
	
	// Decrypt
	ske_decrypt(pt, (unsigned char*)ct + offset_in, ctLen - offset_in, K);
	// ske_decrypt(pt, ct + offset_in, ctLen - offset_in, K);
	

	// // Write to file (fnout)
	// FILE * fp = fopen(fnout, "wb");
	// // fseek(fp, offset_in, SEEK_SET);
	// fwrite(pt, 1, ptLen-1, fp);	// -1 to exclude the null char (from mmap?)

	// Clean up
	munmap(ct, ctLen);
	munmap(pt, ptLen);
	close(fdin);
	close(fdout);
	
	return 0;
}
