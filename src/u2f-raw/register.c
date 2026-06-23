#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h> // Modern OpenSSL structures

#include "authenticate.h"
#include "frame.h"
#include "raw_message.h"
#include "register.h"

#include "../crypto.h"
#include "../utils/xalloc.h"
#include "../u2f-hid/commands.h"
#include "../u2f-hid/packet.h"
#include "../u2f-hid/message.h"


/** \brief Add reserved byte to the register response
**
** \param response The response
*/
static void register_response_reserved(struct message *response)
{
    /* Reserved buffer */
    const uint8_t reserved[] = { '\x05' };

    /* Add to response */
    message_add_data(response, reserved, sizeof(reserved));

    /* Log */
    dump_bytes("Reserved", (uint8_t *)"\x05", sizeof(reserved));
}

/** \brief Add pubkey bytes to the register response
**
** \param response The response
** \param key The key pair (Upgraded to EVP_PKEY)
*/
static void register_response_pubkey(struct message *response,
                                     const EVP_PKEY *key)
{
    /* Get pubkey bytes */
    uint8_t *pubkey_buffer = NULL;
    size_t pubkey_size = crypto_ec_pubkey_to_bytes(key, &pubkey_buffer);

    if (pubkey_size > 0) {
        /* Add to response */
        message_add_data(response, pubkey_buffer, pubkey_size);
        /* Log */
        dump_bytes("Pubkey", pubkey_buffer, pubkey_size);
    }

    /* Free */
    free(pubkey_buffer);
}

/** \brief Add ciphered key handle to the register response
**
** \param response The response
** \param key_handle_cipher The ciphered key handle
** \param key_handle_cipher_size The ciphered key handle size
*/
static void register_response_key_handle(struct message *response,
                                         const uint8_t *key_handle_cipher,
                                         size_t key_handle_cipher_size)
{
    /* Check size */
    if (key_handle_cipher_size > UINT8_MAX) {
        warnx("Key handle size: %zu > %d", key_handle_cipher_size, UINT8_MAX);
        return;
    }
    
    /* Get size */
    uint8_t key_handle_cipher_size_byte = (uint8_t)key_handle_cipher_size;

    /* Add to response */
    message_add_data(response, &key_handle_cipher_size_byte, sizeof(key_handle_cipher_size_byte));
    message_add_data(response, key_handle_cipher, key_handle_cipher_size);
}

/** \brief Add x509 bytes to the register response
**
** \param response The response
** \param x509_buffer The x509 buffer
** \param x509_buffer_size The x509 buffer size
*/
static void register_response_x509(struct message *response,
                                   const uint8_t *x509_buffer, 
                                   size_t x509_buffer_size)
{
    /* Add to response */
    message_add_data(response, x509_buffer, x509_buffer_size);

    /* Log */
    dump_bytes("X509", x509_buffer, x509_buffer_size);
}

/** \brief Add signature to the register response
**
** \param response The response
** \param key_handle_cipher The ciphered key handle
** \param key_handle_cipher_size The ciphered key handle size
** \param key The key pair (Upgraded to EVP_PKEY)
** \param params The register params
*/
static void register_response_signature(struct message *response,
                                        const uint8_t *key_handle_cipher,
                                        size_t key_handle_cipher_size,
                                        const EVP_PKEY *key,
                                        const struct registration_params *params)
{
    /* RFU */
    uint8_t rfu = 0x00;

    /* Get pubkey bytes */
    uint8_t *pubkey_buffer = NULL;
    size_t pubkey_size = crypto_ec_pubkey_to_bytes(key, &pubkey_buffer);

    /* Max expected size: 1 (RFU) + 32 (App) + 32 (Challenge) + ~150 (KeyHandle) + 65 (PubKey) = ~280 bytes */
    uint8_t buffer_to_sign[512]; 
    size_t index = 0;

    /* RFU */
    buffer_to_sign[index] = rfu;
    index += sizeof(rfu);

    /* App Param */
    memcpy(buffer_to_sign + index, &params->application_param, U2F_APP_PARAM_SIZE);
    index += U2F_APP_PARAM_SIZE;

    /* Challenge Param */
    memcpy(buffer_to_sign + index, &params->challenge_param, U2F_CHA_PARAM_SIZE);
    index += U2F_CHA_PARAM_SIZE;

    /* Key Handle */
    if (key_handle_cipher_size > 0 && (index + key_handle_cipher_size) < sizeof(buffer_to_sign)) {
        memcpy(buffer_to_sign + index, key_handle_cipher, key_handle_cipher_size);
        index += key_handle_cipher_size;
    }

    /* Pubkey */
    if (pubkey_size > 0 && (index + pubkey_size) < sizeof(buffer_to_sign)) {
        memcpy(buffer_to_sign + index, pubkey_buffer, pubkey_size);
        index += pubkey_size;
    }

    /* Digest */
    uint8_t *digest = NULL;
    size_t digest_len = crypto_hash(buffer_to_sign, index, &digest);

    if (digest_len > 0) {
        /* Sign (Uses the global attestation key inside crypto.c) */
        uint8_t *signature_buffer = NULL;
        size_t signature_len = crypto_ec_sign(digest, digest_len, &signature_buffer);

        if (signature_len > 0) {
            /* Add to response */
            message_add_data(response, signature_buffer, signature_len);
            /* Log */
            dump_bytes("Signature", signature_buffer, signature_len);
        }
        free(signature_buffer);
    }

    /* Free heap allocations */
    free(pubkey_buffer);
    free(digest);
}

/**
** \brief Add status code to the authentication response
**
** \param response The response
** \param status The status code
*/
static void register_response_sw(struct message *response,
                                 uint32_t status)
{
    /* SW (Big-Endian) */
    uint8_t sw[2] = { (status >> 8) & 0xFF, status & 0xFF };

    /* Add to response */
    message_add_data(response, sw, 2);

    /* Log */
    dump_bytes("SW", sw, 2);
}

/**
** \brief Build the plain key handle
**
** \param key The key pair (Upgraded to EVP_PKEY)
** \param params The register params
** \param size The ref size of the plain key handle
** \return The plain key handle
*/
static uint8_t *register_build_plain_key_handle(EVP_PKEY *key, 
                                                const struct registration_params *params,
                                                size_t *size)
{
    /* Get privkey bytes */
    uint8_t *key_buffer = NULL;
    size_t key_size = crypto_ec_key_to_bytes(key, &key_buffer);

    /* Size */
    size_t key_handle_size = key_size + U2F_APP_PARAM_SIZE;
    *size = key_handle_size;

    /* Allocate key_handle */
    uint8_t *key_handle = xmalloc(key_handle_size);

    /* Init key_handle */
    memcpy(key_handle, key_buffer, key_size);
    memcpy(key_handle + key_size, params->application_param, U2F_APP_PARAM_SIZE);

    /* Log */
    dump_bytes("Privkey", key_buffer, key_size);
    dump_bytes("Registration params", params->application_param, U2F_APP_PARAM_SIZE);
    dump_bytes("Key handle", key_handle, key_handle_size);

    /* Free */
    free(key_buffer);

    return key_handle;
}

/**
** \brief Encrypt the key handle
**
** \param key_handle The key handle
** \param key_handle_size The key handle size
** \param size The ref size of the ciphered key handle
** \return The ciphered key handle
*/
static uint8_t *register_encrypt_key_handle(const uint8_t *key_handle, 
                                            size_t key_handle_size, 
                                            size_t *size)
{
    /* Cipher Key handle */
    uint8_t *key_handle_cipher = NULL;
    size_t key_handle_cipher_size = crypto_aes_encrypt(key_handle,
                                                       key_handle_size,
                                                       &key_handle_cipher);

    /* Size */
    *size = key_handle_cipher_size;

    /* Log */
    dump_bytes("Key handle Ciphered size", (uint8_t *)size, sizeof(size));
    dump_bytes("Key handle Ciphered", key_handle_cipher, key_handle_cipher_size);

    return key_handle_cipher;
}

struct message *raw_register_handler(const struct message *request)
{
    /* Log */
    fprintf(stderr, "        Register\n");

    /* Request */
    struct registration_params params;
    message_read(request, (uint8_t *)&params,
                 U2F_APDU_HEADER_SIZE, sizeof(struct registration_params));

    /* New key (EVP_PKEY handles both public and private components) */
    EVP_PKEY *key = crypto_ec_generate_key();

    /* Start Response */
    struct message *response = message_new_blank(request->init_packet->cid, CMD_MSG);

    /* Reserved */
    register_response_reserved(response);

    /* Pubkey (passing EVP_PKEY directly) */
    register_response_pubkey(response, key);

    /* Key handle */
    size_t key_handle_size = 0;
    uint8_t *key_handle = register_build_plain_key_handle(key, &params, &key_handle_size);

    /* Cipher Key handle */
    size_t key_handle_cipher_size = 0;
    uint8_t *key_handle_cipher = register_encrypt_key_handle(key_handle, key_handle_size, &key_handle_cipher_size);

    /* Key handle */
    register_response_key_handle(response, key_handle_cipher, key_handle_cipher_size);

    /* X509 */
    uint8_t *x509_buffer = NULL;
    size_t x509_buffer_size = crypto_x509_get_bytes(&x509_buffer);
    register_response_x509(response, x509_buffer, x509_buffer_size);

    /* Signature */
    register_response_signature(response, key_handle_cipher, key_handle_cipher_size, key, &params);

    /* SW */
    register_response_sw(response, SW_NO_ERROR);

    /* Dump request */
    size_t request_buffer_size = packet_init_get_bcnt(request->init_packet);
    uint8_t *request_buffer = xmalloc(request_buffer_size);
    message_read(request, request_buffer, 0, request_buffer_size);
    dump_bytes("Message", request_buffer, request_buffer_size);

    /* Dump response */
    size_t response_buffer_size = packet_init_get_bcnt(response->init_packet);
    uint8_t *response_buffer = xmalloc(response_buffer_size);
    message_read(response, response_buffer, 0, response_buffer_size);
    dump_bytes("Message", response_buffer, response_buffer_size);

    /* Free */
    EVP_PKEY_free(key); // Replaces EC_KEY_free for both privkey and pubkey
    free(key_handle);
    free(key_handle_cipher);
    free(x509_buffer);
    free(request_buffer);
    free(response_buffer);

    return response;
}