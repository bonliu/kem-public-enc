int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
                        const EVP_CIPHER *type,
                        ENGINE *impl,
                        const unsigned char *key,
                        const unsigned char *iv);
/*
1) EVP_EncryptInit_ex() sets up cipher context ctx for encryption 
    with cipher type from ENGINE impl. 
2) ctx must be initialized before calling this function.
3) type is normally supplied by a function such as EVP_aes_256_cbc(). 
4) If impl is NULL then the default implementation is used.
5) key is the symmetric key to use and iv is the IV to use (if necessary), 
6) the actual number of bytes used for the key and IV depends on the cipher. 
7) It is possible to set all parameters to NULL except type in an initial call 
    and supply the remaining parameters in subsequent calls, all
*/
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx,
                        unsigned char *out,
                        int *outl,
                        const unsigned char *in,
                        int inl);
/*
1) EVP_EncryptUpdate() encrypts inl bytes from the buffer in 
2) and writes the encrypted version to out. 
3) the amount of data written may be anything from zero bytes to (inl + cipher_block_size - 1)
4) The actual number of bytes written is placed in outl.
*/

int EVP_DecryptInit(EVP_CIPHER_CTX *ctx,
                    const EVP_CIPHER *type,
                    const unsigned char *key,
                    const unsigned char *iv);

int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx,
                        unsigned char *out,
                        int *outl,
                        const unsigned char *in,
                        int inl);


unsigned char *HMAC(const EVP_MD *evp_md, 
                    const void *key,
                    int key_len,
                    const unsigned char *d,
                    int n,
                    unsigned char *md,
                    unsigned int *md_len);
/*
1) HMAC() computes the MAC of the n bytes at d
2) using the hash function evp_md and the key key which is key_len bytes long.
3) It places the result in md (which must have space for the output of the hash function,
    which is no more than EVP_MAX_MD_SIZE bytes). 
4) If md is NULL, the digest is placed in a static array. 
    !!!Note: passing a NULL value for md to use the static array is not thread safe!!!
5) The size of the output is placed in md_len, unless it is NULL.
*/