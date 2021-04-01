/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file   iot_safe_internal.h
 * @brief  IoT SAFE internal functions
 */

#ifndef __iot_safe_internal_H_
#define __iot_safe_internal_H_

#include <stdint.h>
#include <stdlib.h>

#include "iot_safe.h"

#if defined(ARDUINO)
#include "iot_safe_arduino_internal.h"
#else
#include "iot_safe_pcsc_internal.h"
#include <stdio.h>
#include <string.h>
#endif

//#define IOT_SAFE_ENABLE_DEBUG
#if defined(IOT_SAFE_ENABLE_DEBUG)
#if defined(ARDUINO)
#define IOT_SAFE_DEBUG iot_safe_arduino_printf
#else
#define IOT_SAFE_DEBUG printf
#endif
#else
#define IOT_SAFE_DEBUG
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#define IOT_SAFE_CLA                          0x80

#define IOT_SAFE_AT_TIMER                     180000 // in microseconds
#define IOT_SAFE_APDU_BUFFER_LEN              256
#define IOT_SAFE_COMMAND_BUFFER_LEN           200
#define IOT_SAFE_FILE_CHUNK_SIZE              50

// Instructions
#define IOT_SAFE_INS_PUT_PUBLIC_KEY_INIT      0x24
#define IOT_SAFE_INS_COMPUTE_SIGNATURE_INIT   0x2A
#define IOT_SAFE_INS_COMPUTE_SIGNATURE_UPDATE 0x2B
#define IOT_SAFE_INS_VERIFY_SIGNATURE_INIT    0x2C
#define IOT_SAFE_INS_VERIFY_SIGNATURE_UPDATE  0x2D
#define IOT_SAFE_INS_COMPUTE_DH               0x46
#define IOT_SAFE_INS_COMPUTE_PRF              0x48
#define IOT_SAFE_INS_COMPUTE_HKDF             0x4A
#define IOT_SAFE_INS_GET_RANDOM               0x84
#define IOT_SAFE_INS_READ_FILE                0xB0
#define IOT_SAFE_INS_GENERATE_KEY_PAIR        0xB9
#define IOT_SAFE_INS_GET_DATA                 0xCB
#define IOT_SAFE_INS_READ_PUBLIC_KEY          0xCD
#define IOT_SAFE_INS_PUT_PUBLIC_KEY_UPDATE    0xD8

// Not specific to IoT SAFE
#define IOT_SAFE_INS_GET_RESPONSE             0xC0

// Tags
#define IOT_SAFE_TAG_SIM_ALLIANCE_VERSION     0x10
#define IOT_SAFE_TAG_APPLET_ID                0x11

#define IOT_SAFE_TAG_FILE_SIZE                0x20
#define IOT_SAFE_TAG_FILE_USAGE               0x21

#define IOT_SAFE_TAG_COMPUTED_SIGNATURE       0x33
#define IOT_SAFE_TAG_PUBLIC_KEY_DATA          0x34

#define IOT_SAFE_TAG_OBJECT_STATE             0x4A
#define IOT_SAFE_TAG_KEY_TYPE                 0x4B
#define IOT_SAFE_TAG_KEY_USAGE                0x4E

#define IOT_SAFE_TAG_OBJECT_ACCESS            0x60
#define IOT_SAFE_TAG_CRYPTO_FUNCTIONS         0x61
#define IOT_SAFE_TAG_KEY_AGREEMENT            0x6F

#define IOT_SAFE_TAG_FILE_LABEL               0x73
#define IOT_SAFE_TAG_PRIVATE_KEY_LABEL        0x74
#define IOT_SAFE_TAG_PUBLIC_KEY_LABEL         0x75
#define IOT_SAFE_TAG_SECRET_KEY_LABEL         0x76

#define IOT_SAFE_TAG_FILE_ID                  0x83
#define IOT_SAFE_TAG_PRIVATE_KEY_ID           0x84
#define IOT_SAFE_TAG_PUBLIC_KEY_ID            0x85
#define IOT_SAFE_TAG_SECRET_KEY_ID            0x86

#define IOT_SAFE_TAG_CRYPTO_FUNCTIONS2        0x90
#define IOT_SAFE_TAG_HASH                     0x91
#define IOT_SAFE_TAG_SIGNATURE                0x92
#define IOT_SAFE_TAG_KEY_AGREEMENT2           0x93
#define IOT_SAFE_TAG_KEY_DERIVATION           0x94

#define IOT_SAFE_TAG_LAST_BLOCK_TO_HASH       0x9A
#define IOT_SAFE_TAG_DATA_TO_BE_SIGNED        0x9B
#define IOT_SAFE_TAG_INTERMEDIATE_HASH        0x9C
#define IOT_SAFE_TAG_NUMBER_OF_BYTES_HASHED   0x9D
#define IOT_SAFE_TAG_FINAL_HASH               0x9E

#define IOT_SAFE_TAG_OPERATION_MODE           0xA1

#define IOT_SAFE_TAG_MAX_NUMBER_FILES         0xB1
#define IOT_SAFE_TAG_MAX_NUMBER_PRIVATE_KEYS  0xB2
#define IOT_SAFE_TAG_MAX_NUMBER_PUBLIC_KEYS   0xB3
#define IOT_SAFE_TAG_MAX_NUMBER_SECRET_KEYS   0xB4
#define IOT_SAFE_TAG_MAX_NUMBER_SESSIONS      0xB7

#define IOT_SAFE_TAG_PRIVATE_KEY_INFO         0xC1
#define IOT_SAFE_TAG_PUBLIC_KEY_INFO          0xC2
#define IOT_SAFE_TAG_FILE_INFO                0xC3
#define IOT_SAFE_TAG_SECRET_KEY_INFO          0xC4

#define IOT_SAFE_TAG_SECRET                   0xD1
#define IOT_SAFE_TAG_LABEL_AND_SEED           0xD2
#define IOT_SAFE_TAG_PSEUDO_RANDOM_LENGTH     0xD3
#define IOT_SAFE_TAG_SALT                     0xD5

#define IOT_SAFE_SESSION_OPEN                 0x00
#define IOT_SAFE_SESSION_CLOSE                0x01

#define IOT_SAFE_SESSION_NUMBER               0x01

void iot_safe_print_tag(uint8_t tag);

/**
 * \brief                 Sends an APDU to the applet through a modem using
 *                        AT CSIM command or through PCSC reader functions.
 *
 * \param cla             Class.
 * \param ins             Instruction.
 * \param p1              P1.
 * \param p2              P2.
 * \param lc              Lc.
 * \param command         Byte array to send after Lc.
 * \param le              Le.
 * \param with_le         1 to send Le byte or 0 otherwise.
 * \param response        A buffer provided by the caller to save the response.
 * \param response_size   Size of the buffer.
 * \param response_length Length of the response.
 * \return                \c IOT_SAFE_SUCCESS on success.
 * \return                An error code on failure.
 */
iot_safe_error_t iot_safe_sendAPDU(uint8_t cla, uint8_t ins,
  uint8_t p1, uint8_t p2, uint8_t lc, const uint8_t *command, uint8_t le,
  uint8_t with_le, uint8_t *response, uint16_t response_size,
  uint16_t* response_length);

/**
 * \brief               Converts a single byte to TLV format and add it to an
 *                      APDU command buffer.
 *
 * \param command       Buffer used to save the command. It must be allocated by
 *                      the user and must be have enough space to save the TLV.
 * \param position      Position inside command buffer where the TLV will be
 *                      added.
 * \param tag           Tag to add.
 * \param value         Value to add.
 * \return              \c the new position inside the command buffer.
 */
uint8_t iot_safe_add_tlv_byte(uint8_t *command, uint8_t position,
  uint8_t tag, uint8_t value);

/**
 * \brief               Converts a byte array to TLV format and add it to an
 *                      APDU command buffer.
 *
 * \param command       Buffer used to save the command. It must be allocated by
 *                      the user and must be have enough space to save the TLV.
 * \param position      Position inside command buffer where the TLV will be
 *                      added.
 * \param tag           Tag to add.
 * \param length        Length of the byte arrary to add
 * \param value         Byte array to add.
 * \return              \c the new position inside the command buffer.
 */
uint8_t iot_safe_add_tlv_byte_array(uint8_t *command,
  uint8_t position, uint8_t tag, uint8_t length, const uint8_t *value);

/**
 * \brief               Extracts a byte array in the TLV format from the
 *                      response buffer.
 *
 * \param response      Buffer containing the TLV to extract.
 * \param position      Position inside response buffer where the TLV will be
 *                      extracted.
 * \param tag           Tag to extract.
 * \param mandatory     Set to 1 if tag is mndatory, 0 otherwise.
 * \param length        Expected length of the byte arrary to extract (0 if
 *                      unknown)
 * \param value         Byte array to save the value. It must be allocated by
 *                      the user and must be have enough space to save the value.
 * \param value_size    Size of the value buffer.
 * \param value_length  Length of the value buffer (i.e. received length).
 * \param new_position  New position inside the response buffer (after the
 *                      extracted TLV). It must be used by the user for
 *                      subsequent calls.
 * \return              \c IOT_SAFE_SUCCESS on success.
 * \return              An error code on failure.
 */
iot_safe_error_t iot_safe_extract_tlv(uint8_t *response,
  uint8_t position, uint8_t tag, uint8_t mandatory, uint8_t length,
  uint8_t *value, size_t value_size, uint8_t* value_length,
  uint8_t *new_position);

/**
 * \brief               Extracts a key from the response buffer.
 *
 * \param response      Buffer containing the key to extract.
 * \param position      Position inside response buffer where the key will be
 *                      extracted.
 * \param tag           Tag to extract.
 * \param key           Key to save the value. It must be allocated by the
 *                      user.
 * \param new_position  New position inside the response buffer (after the
 *                      extracted key). It must be used by the user for
 *                      subsequent calls.
 * \return              \c IOT_SAFE_SUCCESS on success.
 * \return              An error code on failure.
 */
iot_safe_error_t iot_safe_extract_key(uint8_t *response,
  uint8_t position, uint8_t tag, iot_safe_key_t *key, uint8_t *new_position);

/**
 * \brief               Extracts a secret key from the response buffer.
 *
 * \param response      Buffer containing the secret to extract.
 * \param position      Position inside response buffer where the secret will
 *                      be extracted.
 * \param secret_key    Secret key to save the value. It must be allocated by
 *                      the user.
 * \param new_position  New position inside the response buffer (after the
 *                      extracted secret). It must be used by the user for
 *                      subsequent calls.
 * \return              \c IOT_SAFE_SUCCESS on success.
 * \return              An error code on failure.
 */
iot_safe_error_t iot_safe_extract_secret_key(uint8_t *response,
  uint8_t position, iot_safe_secret_t *secret_key, uint8_t *new_position);

/**
 * \brief               Extracts a file from the response buffer.
 *
 * \param response      Buffer containing the file to extract.
 * \param position      Position inside response buffer where the file will be
 *                      extracted.
 * \param file         File to save the value. It must be allocated by the user.
 * \param new_position  New position inside the response buffer (after the
 *                      extracted key). It must be used by the user for
 *                      subsequent calls.
 * \return              \c IOT_SAFE_SUCCESS on success.
 * \return              An error code on failure.
 */
iot_safe_error_t iot_safe_extract_file(uint8_t *response,
  uint8_t position, iot_safe_file_t *file, uint8_t *new_position);

/**
 * \brief                       Opens a session to compute a signature.
 *
 * \param channel               Channel to communicate with the applet.
 * \param session_number        Session number.
 * \param key_id                Private key ID (NULL is the key is searched by
 *                              label).
 * \param key_id_length         Length of private key ID (0 if the key is
 *                              searched by label).
 * \param label_id              Private key label (NULL is the key is searched
 *                              by ID).
 * \param label_id_length       Length of the private key label (0 if the key is
 *                              searched by label).
 * \param operation_mode        Mode of operation for the signature.
 * \param hash_algorithm        Hash algorithm.
 * \param signature_algorithm   Signature agorithm
 * \return                      \c IOT_SAFE_SUCCESS on success.
 * \return                      An error code on failure.
 */
iot_safe_error_t iot_safe_compute_signature_init(uint8_t channel,
  uint8_t session_number, const uint8_t *key_id, uint8_t key_id_length,
  const uint8_t *key_label, uint8_t key_label_length,
  iot_safe_signature_operation_mode_t operation_mode,
  iot_safe_hash_t hash_algorithm, iot_safe_signature_t signature_algorithm);

/**
 * \brief                       Opens a session to verify a signature.
 *
 * \param channel               Channel to communicate with the applet.
 * \param session_number        Session number.
 * \param key_id                Public key ID (NULL is the key is searched by
 *                              label).
 * \param key_id_length         Length of public key ID (0 if the key is
 *                              searched by label).
 * \param label_id              Public key label (NULL is the key is searched
 *                              by ID).
 * \param label_id_length       Length of the public key label (0 if the key is
 *                              searched by label).
 * \param operation_mode        Mode of operation for the signature.
 * \param hash_algorithm        Hash algorithm.
 * \param signature_algorithm   Signature agorithm
 * \return                      \c IOT_SAFE_SUCCESS on success.
 * \return                      An error code on failure.
 */
iot_safe_error_t iot_safe_verify_signature_init(uint8_t channel,
  uint8_t session_number, const uint8_t *key_id, uint8_t key_id_length,
  const uint8_t *key_label, uint8_t key_label_length,
  iot_safe_signature_operation_mode_t operation_mode,
  iot_safe_hash_t hash_algorithm, iot_safe_signature_t signature_algorithm);

/**
 * \brief                       Converts a ASN.1 DER signature to raw format.
 *
 * \param signature_asn1        ASN.1 DER signature to convert.
 * \param signature_asn1_length Length of the ASN.1 DER signature.
 * \param signature             Buffer to save the raw signature.
 * \param signature_size        Size of the raw signature buffer.
 * \param signature_length      Length of the converted raw signature.
 * \return                      \c IOT_SAFE_SUCCESS on success.
 * \return                      An error code on failure.
 */
iot_safe_error_t iot_safe_convert_asn1_to_raw(uint8_t *signature_asn1,
  uint8_t signature_asn1_length, uint8_t *signature, size_t signature_size,
  uint16_t *signature_length);

/**
 * \brief                       Provides the applet with reference data to
 *                              compute and return a signature to the caller.
 *
 *                              Note: For now, only the "Final Hash" mode (i.e.
 *                              IOT_SAFE_SIGNATURE_OPERATION_MODE_PAD_AND_SIGN)
 *                              is supported.
 *
 * \param channel               Channel to communicate with the applet.
 * \param session_number        Session number.
 * \param operation_mode        Operation mode.
 * \param data                  Data to be signed.
 * \param data_length           Length of data to be signed.
 * \param signature             Buffer used to save the signature. It must be
 *                              allocated by the user.
 * \param signature_size        Size of the signature buffer.
 * \param signature_length      Length of the received signature.
 * \return                      \c IOT_SAFE_SUCCESS on success.
 * \return                      An error code on failure.
 */
iot_safe_error_t iot_safe_compute_signature_update(uint8_t channel,
  uint8_t session_number, iot_safe_signature_operation_mode_t operation_mode,
  const uint8_t *data, size_t data_length, uint8_t *signature,
  size_t signature_size, uint16_t* signature_length);
  
/**
 * \brief                       Provides the applet with reference data to
 *                              verify a signature to the caller.
 *
 *                              Note: For now, only the "Final Hash" mode (i.e.
 *                              IOT_SAFE_SIGNATURE_OPERATION_MODE_PAD_AND_SIGN)
 *                              is supported.
 *
 * \param channel               Channel to communicate with the applet.
 * \param session_number        Session number.
 * \param operation_mode        Operation mode.
 * \param data                  Data to be verified.
 * \param data_length           Length of data to be verified.
 * \param signature             Signature to verify.
 * \param signature_length      Length of the signature.
 * \return                      \c IOT_SAFE_SUCCESS on success.
 * \return                      An error code on failure.
 */
iot_safe_error_t iot_safe_verify_signature_update(uint8_t channel,
  uint8_t session_number, iot_safe_signature_operation_mode_t operation_mode,
  const uint8_t *data, size_t data_length, uint8_t *signature,
  size_t signature_length);

#if defined(__cplusplus)
}
#endif

#endif /* __iot_safe_internal_H_ */
  
