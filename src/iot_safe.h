/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file   iot_safe.h
 * @brief  Define IoT SAFE interface as specified in
 *         https://www.gsma.com/iot/wp-content/uploads/2019/12/IoT.05-v1-IoT-Security-Applet-Interface-Description.pdf
 */

#ifndef __iot_safe_H_
#define __iot_safe_H_

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

static const uint8_t IOT_SAFE_AID[] = {
  0xA0, 0x00, 0x00, 0x05, 0x59, 0x00, 0x10
};

typedef uint16_t iot_safe_error_t;

#define IOT_SAFE_ERROR_MORE_DATA                        0x6300  /**< More data available. */
#define IOT_SAFE_ERROR_REMOTE_ADMIN                     0x63CF  /**< The command execution is successful but a remote administration session has completed. */
#define IOT_SAFE_ERROR_INTEGRITY                        0x6400  /**< Integrity Issue (applet store integrity issue detected). */
#define IOT_SAFE_ERROR_WRONG_LENGTH                     0x6700  /**< Wrong length. */
#define IOT_SAFE_ERROR_INCOMPATIBLE_FILE                0x6981  /**< Command incompatible with file structure. */
#define IOT_SAFE_ERROR_DATA_INVALIDATED                 0x6984  /**< Referenced data invalidated (remote administration session on-going, including update on targeted applet store object). */
#define IOT_SAFE_ERROR_CONDITIONS_NOT_SATISFIED         0x6985  /**< Conditions of use not satisfied. */
#define IOT_SAFE_ERROR_EXECUTION_OR_CAPACITY            0x6989  /**< Remote administration session including update on targeted applet store object has completed, and the command execution has failed or Maximum capacity reached. */
#define IOT_SAFE_ERROR_INCORRECT_DATA                   0x6A80  /**< Incorrect data. */
#define IOT_SAFE_ERROR_FILE_NOT_FOUND                   0x6A82  /**< File reference not found. */
#define IOT_SAFE_ERROR_MEMORY                           0x6A84  /**< Insufficient memory. */
#define IOT_SAFE_ERROR_INCORRECT_P1_P2                  0x6A86  /**< Incorrect P1, P2. */
#define IOT_SAFE_ERROR_INVALID_INSTRUCTION              0x6D00  /**< Invalid instruction. */
#define IOT_SAFE_ERROR_SIGNATURE_MISMATCH               0x6D01  /**< Provided signature does not match. */
#define IOT_SAFE_ERROR_INVALID_CLASS                    0x6E00  /**< Invalid class. */
#define IOT_SAFE_ERROR_UNKNOWN                          0x6F00  /**< Unknown error (other error). */
#define IOT_SAFE_SUCCESS                                0x9000  /**< Successful execution. */

typedef uint8_t iot_safe_object_state_t;

#define IOT_SAFE_OBJECT_STATE_ACTIVATED                 0x01  /**< Activated (filled). */
#define IOT_SAFE_OBJECT_STATE_DEACTIVATED               0x00  /**< Deactivated (container empty or partially filled). */

typedef uint8_t iot_safe_object_access_t;

#define IOT_SAFE_OBJECT_ACCESS_READ                     0x01  /**< Read. */
#define IOT_SAFE_OBJECT_ACCESS_UPDATE                   0x02  /**< Update. */

typedef uint8_t iot_safe_key_type_t;

#define IOT_SAFE_KEY_TYPE_RSA_2K                        0x03  /**< RSA 2K -optional. */
#define IOT_SAFE_KEY_TYPE_NIST_SECP256R1_PERSISTENT     0x13  /**< NIST secp256r1 (persistent). */
#define IOT_SAFE_KEY_TYPE_NIST_SECP256R1_VOLATILE       0x14  /**< NIST secp256r1 (volatile). */
#define IOT_SAFE_KEY_TYPE_BRAINPOOL_P256R1_PERSISTENT   0x23  /**< BrainpoolP256r1 (persistent). */
#define IOT_SAFE_KEY_TYPE_BRAINPOOL_P256R1_VOLATILE     0x24  /**< BrainpoolP256r1 (volatile). */
#define IOT_SAFE_KEY_TYPE_HMAC                          0xA0  /**< HMAC capable key -optional. */

typedef uint8_t iot_safe_key_usage_t;

#define IOT_SAFE_KEY_USAGE_GENERAL                      0x01  /**< General purpose key. */
#define IOT_SAFE_KEY_USAGE_CERTIFICATE_VERIFY_TLS12     0x02  /**< Key for Certificate Verify TLS1.2 handshake message. */
#define IOT_SAFE_KEY_USAGE_CERTIFICATE_VERIFY_TLS13     0x03  /**< Key for Certificate Verify TLS1.3 handshake message. */

typedef uint8_t iot_safe_hash_t;

#define IOT_SAFE_HASH_SHA_256                           0x01  /**< SHA-256. */
#define IOT_SAFE_HASH_SHA_384                           0x02  /**< SHA-384 -optional. */
#define IOT_SAFE_HASH_SHA_512                           0x04  /**< SHA-512 -optional. */

typedef uint8_t iot_safe_signature_t;

#define IOT_SAFE_SIGNATURE_RSA_PKCS                     0x01  /**< RSA with padding according to RSASSA PKCS#1 v1.5 -optional. */
#define IOT_SAFE_SIGNATURE_RSA_PSS                      0x02  /**< RSA with padding according to RSASSA PSS -optional. */
#define IOT_SAFE_SIGNATURE_ECDSA                        0x04  /**< ECDSA. */

typedef uint8_t iot_safe_key_agreement_t;

#define IOT_SAFE_KEY_AGREEMENT_ECKA                     0x01  /**< ECKA(DL/ECKAS-DH1, IEEE 1363). */

typedef uint8_t iot_safe_key_derivation_t;

#define IOT_SAFE_KEY_DERIVATION_PRF_SHA256              0x01  /**< PRF SHA-256 (rfc5246) -optional. */
#define IOT_SAFE_KEY_DERIVATION_HKDF                    0x02  /**< HKDF (rfc5869). */

typedef uint8_t iot_safe_crypto_function_t;

#define IOT_SAFE_CRYPTO_FUNCTION_SIGNATURE              0x01  /**< Signature (generation or verification). */
#define IOT_SAFE_CRYPTO_FUNCTION_KEY_GENERATION         0x02  /**< Key generation. */
#define IOT_SAFE_CRYPTO_FUNCTION_KEY_AGREEMENT          0x04  /**< Key agreement. */
#define IOT_SAFE_CRYPTO_FUNCTION_KEY_DERIVATION         0x08  /**< Key derivation -optional. */

typedef uint8_t iot_safe_file_usage_t;

#define IOT_SAFE_FILE_USAGE_GENERAL                     0x01  /**< General purpose file. */
#define IOT_SAFE_FILE_USAGE_X509V3                      0x02  /**< X509v3 certificate storage. */

typedef struct iot_safe_application
{
  uint8_t version;                                      /**< SIM Alliance version. */
  uint8_t id[0x20];                                     /**< applet proprietary identifier. */
  uint8_t max_files;                                    /**< Max number of files. */
  uint8_t max_private_keys;                             /**< Max number of private keys. */
  uint8_t max_public_keys;                              /**< Max number public keys. */
  uint8_t max_secrets;                                  /**< Max number secret keys. */
  iot_safe_crypto_function_t crypto_functions;          /**< Cryptographic functions. */
  iot_safe_hash_t algos_for_hash;                       /**< Supported algorithms for hash. */
  iot_safe_signature_t algos_for_sign;                  /**< Supported algorithms for signature. */
  iot_safe_key_agreement_t algos_for_key_agreement;     /**< Supported algorithms for key agreement. */
  iot_safe_key_derivation_t algos_for_key_derivation;   /**< Supported algorithms for key derivation. */
  uint8_t max_sessions;                                 /**< Maximum number of sessions. */
} iot_safe_application_t;

#define IOT_SAFE_LABEL_MAX_LENGTH  0x3C
#define IOT_SAFE_ID_MAX_LENGTH     0x14

typedef struct iot_safe_key
{
  uint8_t label_length;                                 /**< Length of private or public key label. */
  uint8_t label[IOT_SAFE_LABEL_MAX_LENGTH];             /**< Private or public key label. */
  uint8_t id_length;                                    /**< Length of private or public key ID. */
  uint8_t id[IOT_SAFE_ID_MAX_LENGTH];                   /**< Private or public key id. */
  iot_safe_object_access_t access_conditions;           /**< Object access conditions (for the private or public key). */
  iot_safe_object_state_t state;                        /**< Object state (for the private or public key). */
  iot_safe_key_type_t type;                             /**< Key type. */
  iot_safe_key_usage_t usage;                           /**< Key specific usage. */
  iot_safe_crypto_function_t crypto_functions;          /**< Cryptographic functions. */
  iot_safe_signature_t algos_for_sign;                  /**< Supported algorithms for signature (generation for private or verification for public). */
  iot_safe_hash_t algos_for_hash;                       /**< Supported algorithms for hash. */
  iot_safe_key_agreement_t algos_for_key_agreement;     /**< Supported algorithms for key agreement. */
} iot_safe_key_t;

typedef struct iot_safe_file
{
  uint8_t label_length;                                 /**< Length of secret label. */
  uint8_t label[IOT_SAFE_LABEL_MAX_LENGTH];             /**< File label. */
  uint8_t id_length;                                    /**< Length of file ID. */
  uint8_t id[IOT_SAFE_ID_MAX_LENGTH];                   /**< File ID. */
  iot_safe_object_access_t access_conditions;           /**< Object access conditions (for the file). */
  iot_safe_object_state_t state;                        /**< Object state (for the file). */
  iot_safe_file_usage_t usage;                          /**< File specific usage. */
  uint16_t size;                                        /**< File size. */
} iot_safe_file_t;

typedef struct iot_safe_secret
{
  uint8_t label_length;                                 /**< Length of secret key label. */
  uint8_t label[IOT_SAFE_LABEL_MAX_LENGTH];             /**< Secret key label. */
  uint8_t id_length;                                    /**< Length of secret key ID. */
  uint8_t id[IOT_SAFE_ID_MAX_LENGTH];                   /**< Secret key id. */
  iot_safe_object_access_t access_conditions;           /**< Object access conditions (for the secret key). */
  iot_safe_object_state_t state;                        /**< Object state (for the secret  key). */
  iot_safe_key_type_t type;                             /**< Key type. */
  iot_safe_crypto_function_t crypto_functions;          /**< Cryptographic functions. */
  iot_safe_key_derivation_t algos_for_key_derivation;   /**< Supported algorithms for key derivation. */
} iot_safe_secret_t;

/**
 * \brief The signature's operation mode.
 *
 * Three modes of operation are supported;
 * - Full text processing, meaning the full text is hashed by the applet before
 *   padding and signature computation.
 * - Last block processing,meaning the last block of the test is hashed by the
 *   applet before padding and signature computation.
 * - Pad and sign processing, meaning the hash on the full text is computed
 *   externally then transferred to the applet for padding and comparison with
 *   the value in the reference signature
 */
typedef uint8_t iot_safe_signature_operation_mode_t;

#define IOT_SAFE_SIGNATURE_OPERATION_MODE_FULL_TEXT     0x01  /**< Full text processing (the full text is hashed by the applet). */
#define IOT_SAFE_SIGNATURE_OPERATION_MODE_LAST_BLOCK    0x02  /**< Last block processing (the full text but the last block is hashed externally). */
#define IOT_SAFE_SIGNATURE_OPERATION_MODE_PAD_AND_SIGN  0x03  /**< Pad and sign processing (the full text is hashed externally). */

/**
 * \brief                          Initialize the IoT SAFE library: modem
 *                                 connection, applet selection ...
 *                                 This function must be called before any
 *                                 other functions.
 *
 * \param aid                      Applet ID (IOT_SAFE_AID or a custom AID).
 * \param aid_length               Length of the Applet ID.
 * \param channel                  Channel opened to communicate with the
 *                                 applet.
 * \return                         \c IOT_SAFE_SUCCESS on success.
 * \return                         An error code on failure.
 */
iot_safe_error_t iot_safe_init(const uint8_t* aid, uint8_t aid_length,
  uint8_t *channel);

/**
 * \brief                          Clean up the IoT SAFE library: modem
 *                                 disconnection, applet deselection ...
 *                                 This function must be called to exit
 *                                 "cleanly".
 *
 * \param channel                  Communication channel with the applet to be
 *                                 closed.
 * \return                         \c IOT_SAFE_SUCCESS on success.
 * \return                         An error code on failure.
 */
iot_safe_error_t iot_safe_finish(uint8_t channel);

/**
 * \brief                          Generates a shared secret from a public key
 *                                 and a private key present in the applet
 *                                 store.
 *
 *                                 Note: untested
 *
 * \param channel                  Channel to communicate with the applet.
 * \param private_key_id           Private key ID (NULL if key is searched by
 *                                 label).
 * \param private_key_id_length    Length of the private key ID (0 if key is
 *                                 searched by label).
 * \param public_key_id            Public key label (NULL if key is searched by
 *                                 ID).
 * \param public_key_id_length     Length of the public key label (0 if key is
 *                                 searched by ID).
 * \param private_key_label        Private key label (NULL if key is searched by
 *                                 label).
 * \param private_key_label_length Length of the private key ID (0 if key is
 *                                 searched by label).
 * \param public_key_label         Public key label (NULL if key is searched by
 *                                 ID).
 * \param public_key_label_length  Public key label (NULL if key is searched by
 *                                 ID).
 * \param secret                   Value used to save the shared secret, it
 *                                 must be allocated by the user.
 * \param secret_size              Size of the shared secret buffer allocated
 *                                 by the user.
 * \param secret_length            Length of the retrieved secret.
 * \return                         \c IOT_SAFE_SUCCESS on success.
 * \return                         An error code on failure.
 */
iot_safe_error_t iot_safe_compute_dh(uint8_t channel,
  const uint8_t *private_key_id, const uint8_t private_key_id_length,
  const uint8_t *public_key_id, const uint8_t public_key_id_length,
  const uint8_t *private_key_label, const uint8_t private_key_label_length,
  const uint8_t *public_key_label, const uint8_t public_key_label_length,
  uint8_t *secret, const uint16_t secret_size, uint16_t *secret_length);

/**
 * \brief                          Returns information about the applet and its
 *                                 capacity.
 *
 * \param channel                  Channel to communicate with the applet.
 * \param application              Buffer used to save the data application.
 * \return                         \c IOT_SAFE_SUCCESS on success.
 * \return                         An error code on failure.
 */
iot_safe_error_t iot_safe_get_application(uint8_t channel,
  iot_safe_application_t *application);

/**
 * \brief                          List all objects (files, key pairs, secret
 *                                 keys) and their attributes present in the
 *                                 applet store.
 *
 * \param channel                  Channel to communicate with the applet.
 * \param private_keys             Array used to save the private keys.
 * \param private_keys_length      Length of the private keys's array.
 * \param private_keys_number      Number of private keys retrieved from the
 *                                 applet.
 * \param public_keys              Array used to save the public keys.
 * \param public_keys_length       Length of the public keys's array.
 * \param public_keys_number       Number of public keys retrieved from the
 *                                 applet.
 * \param files                    Array used to save the files.
 * \param files_length             Length of the files's array.
 * \param files_number             Number of files retrieved from the applet.
 * \param secrets                  Array used to save the secrets.
 * \param secrets_length           Length of the secrets's array.
 * \param secrets_number           Number of secrets retrieved from the applet.
 * \return                         \c IOT_SAFE_SUCCESS on success.
 * \return                         An error code on failure.
 */
iot_safe_error_t iot_safe_get_object_list(uint8_t channel,
  iot_safe_key_t *private_keys, uint8_t private_keys_length,
  uint8_t *private_keys_number, iot_safe_key_t *public_keys,
  uint8_t public_keys_length, uint8_t *public_keys_number,
  iot_safe_file_t *files, uint8_t files_length, uint8_t *files_number,
  iot_safe_secret_t *secrets, uint8_t secrets_length, uint8_t *secrets_number);

/**
 * \brief                          Retrieves all information associated to a
 *                                 private key.
 *
 * \param channel                  Channel to communicate with the applet.
 * \param label                    Private key label (when the key is searched
 *                                 by label).
 * \param label_length             Private key label length (when the key is
 *                                 searched by label).
 * \param id                       Private key ID (when the key is searched by
 *                                 ID).
 * \param id_length                Private key ID length (when the key is
 *                                 searched by ID).
 * \param key                      Structure used to save the private key.
 * \return                         \c IOT_SAFE_SUCCESS on success.
 * \return                         An error code on failure.
 */
iot_safe_error_t iot_safe_get_private_key_information(uint8_t channel,
  const uint8_t *label, const uint8_t label_length, const uint8_t *id,
  const uint8_t id_length, iot_safe_key_t *key);

/**
 * \brief                          Compute a signature.
 *
 * \param channel                  Channel to communicate with the applet.
 * \param operation_mode           Operation mode.
 * \param hash_algorithm           Hash algorithm.
 * \param signature_type           Type of signature.
 * \param key_id                   ID of the private key to use (NULL if key is
 *                                 searched by label).
 * \param key_id_length            Length of the private key ID (0 if key is
 *                                 searched by label).
 * \param key_label                ID of the private key to use (NULL if key is
 *                                 searched by ID).
 * \param key_label_length         Length of the private key label (0 if key is
 *                                 searched by ID).
 * \param data                     Data to sign.
 * \param data_length              Length of the data.
 * \param signature                Buffer used to save the signature.
 * \param signature_size           Size of the signature buffer.
 * \param signature_length         Length of the retrieved signature.
 * \return                         \c IOT_SAFE_SUCCESS on success.
 * \return                         An error code on failure.
 */
iot_safe_error_t iot_safe_sign(uint8_t channel,
  iot_safe_signature_operation_mode_t operation_mode,
  iot_safe_hash_t hash_algorithm, iot_safe_signature_t signature_type,
  const uint8_t *key_id, const uint8_t key_id_length,
  const uint8_t *key_label, const uint8_t key_label_length,
  const uint8_t *data, uint32_t data_length, uint8_t *signature,
  uint16_t signature_size, uint16_t *signature_length);

/**
 * \brief                          Verify a signature.
 *
 * \param channel                  Channel to communicate with the applet.
 * \param operation_mode           Operation mode.
 * \param hash_algorithm           Hash algorithm.
 * \param signature_type           Type of signature.
 * \param key_id                   ID of the private key to use (NULL if key is
 *                                 searched by label).
 * \param key_id_length            Length of the private key ID (0 if key is
 *                                 searched by label).
 * \param key_label                Label of the private key to use (NULL if key
 *                                 is searched by ID).
 * \param key_label_length         Length of the private key label (0 if key is
 *                                 searched by ID).
 * \param data                     Data to verify.
 * \param data_length              Length of the data.
 * \param signature                Signature to verify.
 * \param signature_length         Length of the signature.
 * \return                         \c IOT_SAFE_SUCCESS on success.
 * \return                         An error code on failure.
 */
iot_safe_error_t iot_safe_verify(uint8_t channel,
  iot_safe_signature_operation_mode_t operation_mode,
  iot_safe_hash_t hash_algorithm, iot_safe_signature_t signature_type,
  const uint8_t *key_id, const uint8_t key_id_length,
  const uint8_t *key_label, const uint8_t key_label_length,
  const uint8_t *data, uint32_t data_length, uint8_t *signature,
  uint16_t signature_length);

/**
 * \brief                          Returns a random value that can extend from
 *                                 1 byte up to 256 bytes.
 *
 * \param channel                  Channel to communicate with the applet.
 * \param random                   Buffer used to save the random value (must
 *                                 be allocated by the user).
 * \param random_size              Size of the random buffer.
 * \param random_length            Length of the retrieved random value.
 * \return                         \c IOT_SAFE_SUCCESS on success.
 * \return                         An error code on failure.
 */
iot_safe_error_t iot_safe_get_random(uint8_t channel, uint8_t *random,
  uint16_t random_size, uint16_t *random_length);

/**
 * \brief                          Read file from the applet.
 *
 * \param channel                  Channel to communicate with the applet.
 * \param file_id                  ID of the file to read (NULL if file is
 *                                 searched by label).
 * \param file_id_length           Length of the file ID (0 if file is
 *                                 searched by label).
 * \param file_label               Label of the file to read  (NULL if file is
 *                                 searched by ID).
 * \param file_label_length        Length of the file label  (0 if key is
 *                                 searched by ID).
 * \param data                     Buffer used to save the file's data (must be
 *                                 allocated by the user).
 * \param data_length              Length of the file's data.
 * \return                         \c IOT_SAFE_SUCCESS on success.
 * \return                         An error code on failure.
 */
iot_safe_error_t iot_safe_read_file(uint8_t channel, const uint8_t *file_id,
  const uint8_t file_id_length, const uint8_t *file_label,
  const uint8_t file_label_length, uint8_t *data, uint16_t data_length);

/**
 * \brief                          Print in a readable format an
 *                                 iot_safe_application_t structure.
 *
 * \param application              Application to be displayed (must be set by
 *                                 the caller).
 */
void iot_safe_print_application(iot_safe_application_t *application);

/**
 * \brief                          Print in a readable format an iot_safe_key_t
 *                                 structure containing a private key.
 *
 * \param key                      Private key to be displayed (must be set by
 *                                 the caller).
 */
void iot_safe_print_private_key(iot_safe_key_t *key);

/**
 * \brief                          Print in a readable format an iot_safe_key_t
 *                                 structure containing a public key.
 *
 * \param key                      Public key to be displayed (must be set by
 *                                 the caller).
 */
void iot_safe_print_public_key(iot_safe_key_t *key);

/**
 * \brief                          Print in a readable format an
 *                                 iot_safe_file_t structure.
 *
 * \param file                     File to be displayed (must be set by the
 *                                 caller).
 */
void iot_safe_print_file(iot_safe_file_t *file);

/**
 * \brief                          Print in a readable format an
 *                                 iot_safe_secret_t structure.
 *
 * \param secret                   Secret key to be displayed (must be set by
 *                                 the caller).
 */
void iot_safe_print_secret(iot_safe_secret_t *secret);

/**
 * \brief                          Print in a readable format an
 *                                 iot_safe_error_t structure.
 *
 * \param error                    Error code to be displayed (must be set by
 *                                 the caller).
 */
void iot_safe_print_error(iot_safe_error_t error);

#if defined(__cplusplus)
}
#endif

#endif /* __iot_safe_H_ */
