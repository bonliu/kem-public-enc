#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "rsa.h"
#include "prf.h"

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x,10)	// return 2 if x is definitely prime
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,&len,-1,1,0,0,x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE* f, mpz_t x)
{
	size_t i,len = mpz_size(x)*sizeof(mp_limb_t);
	unsigned char* buf = malloc(len);
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b = (len >> 8*i) % 256;
		fwrite(&b,1,1,f);
	}
	Z2BYTES(buf,len,x);
	fwrite(buf,1,len,f);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}
int zFromFile(FILE* f, mpz_t x)
{
	size_t i,len=0;
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b;
		/* XXX error check this; return meaningful value. */
		fread(&b,1,1,f);
		len += (b << 8*i);
	}
	unsigned char* buf = malloc(len);
	fread(buf,1,len,f);
	BYTES2Z(x,buf,len);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

int rsa_keyGen(size_t keyBits, RSA_KEY* K)
{
	rsa_initKey(K);
	/* TODO: write this.  Use the prf to get random byte strings of
	 * the right length, and then test for primality (see the ISPRIME
	 * macro above).  Once you've found the primes, set up the other
	 * pieces of the key ({en,de}crypting exponents, and n=pq). */

	// Choose 2 different large random prime numbers p and q
	size_t len = keyBits/16;

	int isPrime = 0;
	unsigned char* p = malloc(len);
	while (!isPrime) {
		assert(randBytes(p, len) == 0);
		BYTES2Z(K->p, (const void*)p, len);
		isPrime = ISPRIME(K->p);
	}
	
	isPrime = 0;
	unsigned char* q = malloc(len);
	while (!isPrime) {
		assert(randBytes(q, len) == 0);
		BYTES2Z(K->q, (const void*)q, len);
		isPrime = ISPRIME(K->q);
	}

	// Calculate n = p*q
	mpz_mul(K->n, K->p, K->q);

	// Calculate totient: phi(n) = (p-1)*(q-1)
	NEWZ(p_minus_1); mpz_sub_ui(p_minus_1, K->p, (unsigned long int)1);
	NEWZ(q_minus_1); mpz_sub_ui(q_minus_1, K->q, (unsigned long int)1);
	NEWZ(phi); mpz_mul(phi, p_minus_1, q_minus_1);
	
	// Choose e such that 1 < e < phi(n), and e is co-prime to phi(n)
	gmp_randstate_t state; gmp_randinit_default(state);
	while (1) {
		mpz_urandomm(K->e, state, phi);	// Generate a uniform random integer in [0, phi)
		NEWZ(one); mpz_set_ui(one, 1);
		NEWZ(gcd); mpz_gcd(gcd, K->e, phi);	// Check if e is coprime to phi

		if ((mpz_cmp(gcd, one) == 0) && (mpz_cmp(K->e, one) > 0)) break;
	}

	// Choose d such that e*d congurent 1 (mod phi(n))
	while (1) { 
		/* 
			int mpz_invert (mpz_t rop, const mpz_t op1, const mpz_t op2)
				- Compute the inverse of op1 modulo op2 and put the result in rop. 
		*/
		if (mpz_invert(K->d, K->e, phi) > 0) break;
	}

	// gmp_printf("p = %Zd\n", K->p);
	// gmp_printf("q = %Zd\n", K->q);
	// gmp_printf("n = %Zd\n", K->n);
	// gmp_printf("e = %Zd\n", K->e);
	// gmp_printf("d = %Zd\n", K->d);
	return 0;
}

size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	/* TODO: write this.  Use BYTES2Z to get integers, and then
	 * Z2BYTES to write the output buffer. */
	return 0; /* TODO: return should be # bytes written */
}
size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	/* TODO: write this.  See remarks above. */
	return 0;
}

size_t rsa_numBytesN(RSA_KEY* K)
{
	return mpz_size(K->n) * sizeof(mp_limb_t);
}

int rsa_initKey(RSA_KEY* K)
{
	mpz_init(K->d); mpz_set_ui(K->d,0);
	mpz_init(K->e); mpz_set_ui(K->e,0);
	mpz_init(K->p); mpz_set_ui(K->p,0);
	mpz_init(K->q); mpz_set_ui(K->q,0);
	mpz_init(K->n); mpz_set_ui(K->n,0);
	return 0;
}

int rsa_writePublic(FILE* f, RSA_KEY* K)
{
	/* only write n,e */
	zToFile(f,K->n);
	zToFile(f,K->e);
	return 0;
}
int rsa_writePrivate(FILE* f, RSA_KEY* K)
{
	zToFile(f,K->n);
	zToFile(f,K->e);
	zToFile(f,K->p);
	zToFile(f,K->q);
	zToFile(f,K->d);
	return 0;
}
int rsa_readPublic(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K); /* will set all unused members to 0 */
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	return 0;
}
int rsa_readPrivate(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K);
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	zFromFile(f,K->p);
	zFromFile(f,K->q);
	zFromFile(f,K->d);
	return 0;
}
int rsa_shredKey(RSA_KEY* K)
{
	/* clear memory for key. */
	mpz_t* L[5] = {&K->d,&K->e,&K->n,&K->p,&K->q};
	size_t i;
	for (i = 0; i < 5; i++) {
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs) {
			memset(mpz_limbs_write(*L[i],nLimbs),0,nLimbs*sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}
