#include <err.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/param_build.h>

#include "crypto.h"
#include "utils/xalloc.h"

/* Globals updated to modern structs */
static X509 *g_x509 = NULL;
static EVP_PKEY *g_privkey = NULL; // Replaces EC_KEY
static EVP_PKEY *g_pubkey = NULL;  // Replaces EC_KEY
static uint8_t g_aes_key[32] = { 0 };
static uint8_t g_aes_iv[16] = { 0 };

// ---------------------------------------------------------
// 1. Modern Hashing (EVP_MD)
// ---------------------------------------------------------
size_t crypto_hash(const void *data, size_t data_len, unsigned char **hash)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        warnx("Failed to create MD context");
        return 0;
    }

    *hash = xmalloc(EVP_MD_get_size(EVP_sha256()));
    unsigned int hash_len = 0;

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, data, data_len) != 1 ||
        EVP_DigestFinal_ex(mdctx, *hash, &hash_len) != 1) 
    {
        warnx("Hashing failed");
        free(*hash);
        *hash = NULL;
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);
    return hash_len;
}

// ---------------------------------------------------------
// 2. Modern Key Generation (EVP_PKEY)
// ---------------------------------------------------------
EVP_PKEY *crypto_ec_generate_key(void)
{
    /* OpenSSL 3.0 provides a quick way to generate standard keys */
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "prime256v1");
    if (key == NULL) {
        warnx("Failed to generate EC Key");
    }
    return key;
}

// ---------------------------------------------------------
// 3. Modern Signing (EVP_PKEY_sign)
// ---------------------------------------------------------
/* Note: Because you are passing a pre-computed digest, we use EVP_PKEY_sign. 
   If passing raw data, you would use EVP_DigestSign. */
size_t crypto_ec_sign_with_key(EVP_PKEY *key, const unsigned char *digest, 
                               size_t digest_len, unsigned char **signature)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx || EVP_PKEY_sign_init(ctx) <= 0) {
        warnx("Failed to init signing context");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Determine buffer size */
    size_t sig_len = 0;
    if (EVP_PKEY_sign(ctx, NULL, &sig_len, digest, digest_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    *signature = OPENSSL_malloc(sig_len);
    if (!*signature) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Perform the actual signature */
    if (EVP_PKEY_sign(ctx, *signature, &sig_len, digest, digest_len) <= 0) {
        warnx("Signing failed");
        OPENSSL_free(*signature);
        *signature = NULL;
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return sig_len;
}

// ---------------------------------------------------------
// 4. Reading/Writing Keys (PEM/DER)
// ---------------------------------------------------------
char *crypto_ec_privkey_to_pem(EVP_PKEY *privkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return NULL;

    /* Replaces PEM_write_bio_ECPrivateKey */
    if (PEM_write_bio_PrivateKey(bio, privkey, NULL, NULL, 0, NULL, NULL) != 1) {
        BIO_free(bio);
        return NULL;
    }

    int len = BIO_pending(bio);
    char *buffer = xmalloc(len + 1);
    BIO_read(bio, buffer, len);
    buffer[len] = '\0';

    BIO_free(bio);
    return buffer;
}

static EVP_PKEY *crypto_ec_privkey_from_path(const char *pathname)
{
    FILE *fp = fopen(pathname, "re"); // "e" flag replaces O_CLOEXEC
    if (fp == NULL) {
        warn("Privkey: Failed to open %s", pathname);
        return NULL;
    }

    /* Replaces PEM_read_ECPrivateKey */
    EVP_PKEY *privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return privkey;
}



// ---------------------------------------------------------
// 5. Global Sign (Uses Attestation Key)
// ---------------------------------------------------------
size_t crypto_ec_sign(const uint8_t *digest, size_t digest_len, uint8_t **signature)
{
    if (g_privkey == NULL) {
        warnx("Global attestation key is not loaded!");
        return 0;
    }
    return crypto_ec_sign_with_key(g_privkey, digest, digest_len, signature);
}

// ---------------------------------------------------------
// 6. X509 Certificate Export
// ---------------------------------------------------------
size_t crypto_x509_get_bytes(uint8_t **out)
{
    if (g_x509 == NULL) {
        warnx("Global X509 certificate is not loaded!");
        return 0;
    }

    /* Get required buffer length */
    int len = i2d_X509(g_x509, NULL);
    if (len < 0) return 0;

    /* Allocate and write (using temp pointer as i2d advances it) */
    *out = xmalloc(len);
    uint8_t *p = *out;
    i2d_X509(g_x509, &p);

    return len;
}

// ---------------------------------------------------------
// 7. Key to Bytes (U2F Registration)
// ---------------------------------------------------------
size_t crypto_ec_pubkey_to_bytes(const EVP_PKEY *key, uint8_t **bytes)
{
    /* In OpenSSL 3.0, the "pub-key" param returns the uncompressed point (04 || X || Y) */
    size_t len = 0;
    if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &len)) {
        return 0;
    }

    *bytes = xmalloc(len);
    EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, *bytes, len, &len);
    return len;
}

size_t crypto_ec_key_to_bytes(const EVP_PKEY *key, uint8_t **bytes)
{
    /* Extract the 32-byte private key scalar */
    BIGNUM *priv = NULL;
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &priv)) {
        return 0;
    }

    *bytes = xmalloc(32);
    BN_bn2binpad(priv, *bytes, 32); /* Pad to ensure exactly 32 bytes */
    BN_free(priv);

    return 32;
}

EVP_PKEY *crypto_ec_bytes_to_key(const uint8_t *bytes, size_t len)
{
    /* Reconstruct an OpenSSL 3.0 EVP_PKEY from raw bytes using OSSL_PARAM_BLD */
    BIGNUM *priv = BN_bin2bn(bytes, len, NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv);

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY_fromdata_init(ctx);

    EVP_PKEY *key = NULL;
    EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params);

    /* Cleanup */
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(priv);
    EVP_PKEY_CTX_free(ctx);

    return key;
}

// ---------------------------------------------------------
// 8. AES Encrypt / Decrypt (Key Handles)
// ---------------------------------------------------------
size_t crypto_aes_encrypt(const uint8_t *in, size_t in_len, uint8_t **out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    /* AES-256-CBC padding block can add up to 1 block size (16 bytes) */
    *out = xmalloc(in_len + EVP_CIPHER_get_block_size(EVP_aes_256_cbc()));
    int len1 = 0, len2 = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_aes_key, g_aes_iv);
    EVP_EncryptUpdate(ctx, *out, &len1, in, in_len);
    EVP_EncryptFinal_ex(ctx, *out + len1, &len2);

    EVP_CIPHER_CTX_free(ctx);
    return len1 + len2;
}

size_t crypto_aes_decrypt(const uint8_t *in, size_t in_len, uint8_t **out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    *out = xmalloc(in_len);
    int len1 = 0, len2 = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, g_aes_key, g_aes_iv);
    EVP_DecryptUpdate(ctx, *out, &len1, in, in_len);

    if (EVP_DecryptFinal_ex(ctx, *out + len1, &len2) <= 0) {
        warnx("AES Decryption failed (invalid key or corrupted handle)");
        free(*out);
        *out = NULL;
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return len1 + len2;
}

// ---------------------------------------------------------
// 9. Global Setup and Release
// ---------------------------------------------------------
void crypto_setup(void)
{
    /* Initialize AES keys (In production, load this securely, do not hardcode zeros) */
    for (int i = 0; i < 32; i++) g_aes_key[i] = i;
    for (int i = 0; i < 16; i++) g_aes_iv[i] = i;

    /* Load Global Attestation Key */
    g_privkey = crypto_ec_privkey_from_path("keys/attestation_key.pem");
    if (!g_privkey) {
        errx(1, "Failed to load attestation private key.");
    }

    /* Load Global Attestation Certificate */
    FILE *fp = fopen("keys/attestation_cert.der", "re");
    if (fp) {
        g_x509 = d2i_X509_fp(fp, NULL);
        fclose(fp);
    }

    if (!g_x509) {
        errx(1, "Failed to load attestation certificate.");
    }
}

void crypto_release(void)
{
    /* Wipe AES keys from memory */
    OPENSSL_cleanse(g_aes_key, sizeof(g_aes_key));
    OPENSSL_cleanse(g_aes_iv, sizeof(g_aes_iv));

    /* Free OpenSSL structures */
    if (g_privkey) EVP_PKEY_free(g_privkey);
    if (g_pubkey) EVP_PKEY_free(g_pubkey);
    if (g_x509) X509_free(g_x509);
}
