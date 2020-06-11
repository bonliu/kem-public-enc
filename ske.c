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
		randBytes(K->aesKey,  KLEN_SKE);
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
	
	/* Setup IV */
	size_t ivLen = AES_BLOCK_SIZE;
	unsigned char iv[ivLen];
	if (IV) {
		memcpy(iv,IV,ivLen);
	} else {
		setSeed(0, 0);
		randBytes(iv, ivLen);
	}
	
	unsigned char *aesCt = malloc(len);	// len = strlen(message) + 1
	memset(aesCt, 0, len);

	/* Encrypt message (AES) */
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, iv)) {
		ERR_print_errors_fp(stderr);
	}
	int ctLen; // when strlen(message) == 14 --> ctLen = 15
	if (1 != EVP_EncryptUpdate(ctx, aesCt, &ctLen, inBuf, len)) {
		ERR_print_errors_fp(stderr);
	}
	EVP_CIPHER_CTX_free(ctx);

	unsigned int macLen = HM_LEN;
	unsigned char mac[macLen];
	memset(mac, 0, macLen);
	
	// Concat IV and C
	size_t ivcLen = ivLen + ctLen;	// ctLen includes null char
	unsigned char *ivc = malloc(ivcLen);
	memset(ivc, 0, ivcLen);
	memcpy(ivc, iv, ivLen);
	memcpy(ivc + ivLen, aesCt, ctLen);

	/* Compute HMAC(IV|C) (32 bytes for SHA256) */
	HMAC(EVP_sha256(), K->hmacKey, KLEN_SKE, ivc, ivcLen, mac, NULL);

	/* Construct output */
	memset(outBuf, 0, ivcLen + macLen);
	memcpy(outBuf, ivc, ivcLen);
	memcpy(outBuf + ivcLen, mac, macLen);

	/* Clean up */
	free(aesCt);
	free(ivc);

	/* TODO: should return number of bytes written, 
			 which hopefully matches ske_getOutputLen(...). */
	return ivcLen + macLen;
}
size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* NOTE: offset determines where to begin writing to the output file.
 * set to 0 to erase the file and write it from scratch. */

	/* TODO: write this.  Hint: mmap. */

	/* Open input file */
	int fdin = open(fnin, O_RDONLY);
	struct stat sb;
	if (fstat(fdin, &sb) == -1) {
		perror("[SKE-ENC] Open input file");
		exit(EXIT_FAILURE);
	}
	size_t msgLen = sb.st_size;

	/* Map input file to memory */
	unsigned char *inmap = mmap(NULL, msgLen, PROT_READ, MAP_PRIVATE, fdin, 0);
	if (inmap == MAP_FAILED) {
		perror("[SKE-ENC] Map input file");
		exit(EXIT_FAILURE);
	}
	close(fdin);
	
	/* Open output file */
	int fdout = open(fnout, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
	if (fstat(fdout, &sb) == -1) {
		perror("[SKE-ENC] Open output file");
		exit(EXIT_FAILURE);
	}
	msgLen += 1; // include null char
	size_t ctLen = ske_getOutputLen(msgLen);// + offset_out;
	write(fdout, "a", ctLen);
	
	/* Map output file to memory */
	unsigned char *outmap = mmap(NULL, ctLen + offset_out, 
								 PROT_WRITE, MAP_SHARED, fdout, 0);
	if (outmap == MAP_FAILED) {
		perror("[SKE-ENC] Map output file");
		exit(EXIT_FAILURE);
	}
	close(fdout);

	/* Encrypt */
	size_t bytesWritten = ske_encrypt(outmap + offset_out,
									  inmap, msgLen, K, IV);

	/* Clean up */
	munmap(inmap, msgLen - 1);
	munmap(outmap, ctLen + offset_out);	

	return bytesWritten;
}
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */

	/* Compute MAC */
	size_t macLen = HM_LEN;
	size_t ivcLen = len - macLen;	// len includes null char
	unsigned char mac[macLen];
	// from ske_encrypt: 
	// HMAC(EVP_sha256(), K->hmacKey, KLEN_SKE, ivc, ivcLen, mac, NULL);
	HMAC(EVP_sha256(), K->hmacKey, KLEN_SKE, inBuf, ivcLen, mac, NULL);
	
	/* Autheticate */
	if (memcmp(mac, inBuf + ivcLen, HM_LEN) != 0) {
		fprintf(stderr, "WRONG MAC\n");
		return -1;
	}
	
	// Extract iv
	size_t ivLen = AES_BLOCK_SIZE;
	unsigned char iv[ivLen];
	memcpy(iv, inBuf, ivLen);

	// Extract ciphertext
	int ctLen = ivcLen - ivLen;
	unsigned char ct[ctLen];
	memcpy(ct, inBuf + ivLen, ctLen);

	/* Decrypt */
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, iv)) {
		ERR_print_errors_fp(stderr);
	}
	int msgLen;
	if (1 != EVP_DecryptUpdate(ctx, outBuf, &msgLen, ct, ctLen)) {
		ERR_print_errors_fp(stderr);
	}
	EVP_CIPHER_CTX_free(ctx);

	return msgLen;
}
size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	/* NOTE: offset determines where to begin reading the input file. */
	/* TODO: write this. */

	/* Open input file */
	int fdin = open(fnin, O_RDONLY);
	struct stat sb;
	if (fstat(fdin, &sb) == -1) {
		perror("[SKE-DEC] Open input file");
		exit(EXIT_FAILURE);
	}
	size_t ctLen = sb.st_size;

	/* Map input file to memory */
	unsigned char *inmap = mmap(NULL, ctLen, PROT_READ, MAP_PRIVATE, fdin, 0);
	if (inmap == MAP_FAILED) {
		perror("[SKE-DEC] Map input file");
		exit(EXIT_FAILURE);
	}
	close(fdin);
	
	/* Open output file */
	int fdout = open(fnout, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
	if (fstat(fdout, &sb) == -1) {
		perror("[DKE-DEC] Open output file");
		exit(EXIT_FAILURE);
	}
	/* Exclude null char */
	size_t msgLen = ctLen - offset_in - AES_BLOCK_SIZE - HM_LEN - 1;
	write(fdout, "a", msgLen);

	/* Map output file to memory */
	unsigned char *outmap = mmap(NULL, msgLen, PROT_WRITE, MAP_SHARED, fdout, 0);
	if (outmap == MAP_FAILED) {
		perror("[SKE-DEC] Map output file");
		exit(EXIT_FAILURE);
	}
	close(fdout);

	/* Decrypt */
	// ske_decrypt((unsigned char*)pt,ct,ctLen,K);
	ske_decrypt(outmap, inmap + offset_in, ctLen - offset_in, K);

	/* Clean up */
	munmap(inmap, ctLen);
	munmap(outmap, msgLen);
	
	return 0;
}
