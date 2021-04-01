/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file iot_safe.c
 * @brief IoT SAFE APDU interface.
 */

#include <string.h>

#include "iot_safe.h"
#include "iot_safe_internal.h"

iot_safe_error_t iot_safe_init(const uint8_t *aid, uint8_t aid_length,
  uint8_t *channel)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t response[IOT_SAFE_APDU_BUFFER_LEN];
  uint16_t response_length = 0;

  IOT_SAFE_DEBUG("Enter iot_safe_init\r\n");

  if (!aid_length && aid == NULL)
  {
    IOT_SAFE_DEBUG("AID must be set\r\n");
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  memset(&response, 0, sizeof(response));

  IOT_SAFE_DEBUG("Open channel\r\n");
  ret = iot_safe_sendAPDU(0x00, 0x70, 0x00, 0x00, 0, NULL, 0x01, 1, response,
    sizeof(response), &response_length);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  *channel = response[0];

  IOT_SAFE_DEBUG("Select IoT SAFE applet\r\n");
  return iot_safe_sendAPDU(*channel, 0xA4, 0x04, 0x00, aid_length, aid, 0x00,
    0, NULL, 0, &response_length);
}

iot_safe_error_t iot_safe_finish(uint8_t channel)
{
  uint16_t response_length = 0;
  IOT_SAFE_DEBUG("Enter iot_safe_finish\r\n");

  IOT_SAFE_DEBUG("Close channel\r\n");
  return iot_safe_sendAPDU(0x00, 0x70, 0x80, channel, 0, NULL, 0x00, 0, NULL,
    0, &response_length);
}

iot_safe_error_t iot_safe_compute_dh(uint8_t channel,
  const uint8_t *private_key_id, const uint8_t private_key_id_length,
  const uint8_t *public_key_id, const uint8_t public_key_id_length,
  const uint8_t *private_key_label, const uint8_t private_key_label_length,
  const uint8_t *public_key_label, const uint8_t public_key_label_length,
  uint8_t *secret, const uint16_t secret_size, uint16_t *secret_length)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t command_size = 4 + private_key_id_length + public_key_id_length +
    private_key_label_length + public_key_label_length;
  uint8_t command[command_size];
  uint8_t response[IOT_SAFE_APDU_BUFFER_LEN];
  uint8_t position = 0;

  memset(&command, 0, sizeof(command));
  memset(&response, 0, sizeof(response));

  IOT_SAFE_DEBUG("Enter iot_safe_compute_dh\r\n");

  if (!private_key_id_length && !private_key_label_length)
  {
    IOT_SAFE_DEBUG("Private ID or label must be set\r\n");
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  if (!public_key_id_length && !public_key_label_length)
  {
    IOT_SAFE_DEBUG("Public ID or label must be set\r\n");
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  if (private_key_id_length && private_key_label_length)
  {
    IOT_SAFE_DEBUG("Private ID and label can't be set at the same time\r\n");
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  if (public_key_id_length && public_key_label_length)
  {
    IOT_SAFE_DEBUG("Public ID and label can't be set at the same time\r\n");
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  if (private_key_id_length)
    position = iot_safe_add_tlv_byte_array(command, position,
      IOT_SAFE_TAG_PRIVATE_KEY_ID, private_key_id_length, private_key_id);

  if (public_key_id_length)
    position = iot_safe_add_tlv_byte_array(command, position,
      IOT_SAFE_TAG_PUBLIC_KEY_ID, public_key_id_length, public_key_id);

  if (private_key_label_length)
    position = iot_safe_add_tlv_byte_array(command, position,
      IOT_SAFE_TAG_PRIVATE_KEY_LABEL, private_key_label_length,
      private_key_label);

  if (public_key_label_length)
    position = iot_safe_add_tlv_byte_array(command, position,
      IOT_SAFE_TAG_PUBLIC_KEY_LABEL, public_key_label_length, public_key_label);

  return iot_safe_sendAPDU(channel, IOT_SAFE_INS_COMPUTE_DH, 0x00, 0x00,
      0x00, command, 0x00, 1, secret, secret_size, secret_length);
}

iot_safe_error_t iot_safe_get_application(uint8_t channel,
  iot_safe_application_t *application)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t response_size = 0x44;
  uint8_t response[response_size];
  uint16_t response_length = 0;
  uint8_t position = 0;
  uint8_t received_length = 0;

  IOT_SAFE_DEBUG("Enter iot_safe_get_application\r\n");

  memset(&response, 0, sizeof(response));

  ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_GET_DATA, 0x00, 0x00, 0x00,
    NULL, 0x44, 1, response, sizeof(response), &response_length);

  // Workaround for some applets which don't return a structure of 0x44
  if ((uint8_t) (ret >> 8) == 0x6C)
    ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_GET_DATA, 0x00, 0x00, 0x00,
      NULL, (uint8_t) ret, 1, response, (uint8_t) ret, &response_length);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, position,
    IOT_SAFE_TAG_SIM_ALLIANCE_VERSION, 1, sizeof(application->version),
    &application->version, sizeof(application->version), &received_length,
    &position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  // Some applets don't return an Applet ID on 0x20
  ret = iot_safe_extract_tlv(response, position, IOT_SAFE_TAG_APPLET_ID, 1,
    0/*sizeof(application->id)*/, application->id, sizeof(application->id),
    &received_length, &position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, position,
    IOT_SAFE_TAG_MAX_NUMBER_FILES, 1, sizeof(application->max_files),
    &application->max_files, sizeof(application->max_files), &received_length,
    &position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, position,
    IOT_SAFE_TAG_MAX_NUMBER_PRIVATE_KEYS, 1,
    sizeof(application->max_private_keys), &application->max_private_keys,
    sizeof(application->max_private_keys), &received_length, &position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, position,
    IOT_SAFE_TAG_MAX_NUMBER_PUBLIC_KEYS, 1, sizeof(application->max_public_keys),
    &application->max_public_keys, sizeof(application->max_public_keys),
    &received_length, &position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, position,
    IOT_SAFE_TAG_MAX_NUMBER_SECRET_KEYS, 1, sizeof(application->max_secrets),
    &application->max_secrets, sizeof(application->max_secrets),
    &received_length, &position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, position,
    IOT_SAFE_TAG_CRYPTO_FUNCTIONS2, 1, sizeof(application->crypto_functions),
    &application->crypto_functions, sizeof(application->crypto_functions),
    &received_length, &position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  // TODO: hash should be on 0x02 (applet bug)
  ret = iot_safe_extract_tlv(response, position, IOT_SAFE_TAG_HASH, 1,
    sizeof(application->algos_for_hash), &application->algos_for_hash,
    sizeof(application->algos_for_hash), &received_length, &position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, position, IOT_SAFE_TAG_SIGNATURE, 1,
    sizeof(application->algos_for_sign), &application->algos_for_sign,
    sizeof(application->algos_for_sign), &received_length, &position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, position, IOT_SAFE_TAG_KEY_AGREEMENT2, 1,
    sizeof(application->algos_for_key_agreement),
    &application->algos_for_key_agreement,
    sizeof(application->algos_for_key_agreement), &received_length, &position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, position,
    IOT_SAFE_TAG_KEY_DERIVATION, 1,
    sizeof(application->algos_for_key_derivation),
    &application->algos_for_key_derivation,
    sizeof(application->algos_for_key_derivation), &received_length, &position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  return iot_safe_extract_tlv(response, position,
    IOT_SAFE_TAG_MAX_NUMBER_SESSIONS, 1, sizeof(application->max_sessions),
    &application->max_sessions, sizeof(application->max_sessions),
    &received_length, &position);
}

iot_safe_error_t iot_safe_get_object_list(uint8_t channel,
  iot_safe_key_t *private_keys, uint8_t private_keys_length,
  uint8_t *private_keys_number, iot_safe_key_t *public_keys,
  uint8_t public_keys_length, uint8_t *public_keys_number,
  iot_safe_file_t *files, uint8_t files_length, uint8_t *files_number,
  iot_safe_secret_t *secrets, uint8_t secrets_length, uint8_t *secrets_number)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t response[IOT_SAFE_APDU_BUFFER_LEN];
  uint16_t response_length = 0;
  uint8_t number = 0;
  uint8_t position = 0;
  IOT_SAFE_DEBUG("Enter iot_safe_get_object_list\r\n");

  memset(&response, 0, sizeof(response));

  ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_GET_DATA, 0x01, 0x00, 0x00,
    NULL, 0x00, 1, response, sizeof(response), &response_length);

  // TODO: should be moved in iot_safe_sendAPDU and should be updated to manage
  // response over 255
  if ((uint8_t) (ret >> 8) == 0x6C)
      ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_GET_DATA, 0x01, 0x00, 0x00,
        NULL, (uint8_t) ret, 1, response, (uint8_t) ret, &response_length);

  while (number < private_keys_length &&
    response[position] == IOT_SAFE_TAG_PRIVATE_KEY_INFO)
  {
    ret = iot_safe_extract_key(response, position,
      IOT_SAFE_TAG_PRIVATE_KEY_INFO, &private_keys[number], &position);

    if (ret != IOT_SAFE_SUCCESS)
      return ret;

    number++;
  }
  *private_keys_number = number;

  // Search public keys
  while (position <= response_length &&
    response[position] != IOT_SAFE_TAG_PUBLIC_KEY_INFO)
    position++;

  number = 0;
  while (number < public_keys_length &&
    response[position] == IOT_SAFE_TAG_PUBLIC_KEY_INFO)
  {
    ret = iot_safe_extract_key(response, position,
      IOT_SAFE_TAG_PUBLIC_KEY_INFO, &public_keys[number], &position);

    if (ret != IOT_SAFE_SUCCESS)
      return ret;

    number++;
  }
  *public_keys_number = number;

  // Search secrets
  while (position <= response_length &&
    response[position] != IOT_SAFE_TAG_SECRET_KEY_INFO)
    position++;

  number = 0;
  while (number < secrets_length &&
    response[position] == IOT_SAFE_TAG_SECRET_KEY_INFO)
  {
    ret = iot_safe_extract_secret_key(response, position, &secrets[number], &position);

    if (ret != IOT_SAFE_SUCCESS)
      return ret;

    number++;
  }
  *secrets_number = number;

  // Search files
  while (position <= response_length &&
    response[position] != IOT_SAFE_TAG_FILE_INFO)
    position++;

  number = 0;
  while (number < files_length && response[position] == IOT_SAFE_TAG_FILE_INFO)
  {
    ret = iot_safe_extract_file(response, position, &files[number], &position);

    if (ret != IOT_SAFE_SUCCESS)
      return ret;

    number++;
  }
  *files_number = number;

  return ret;
}

iot_safe_error_t iot_safe_get_private_key_information(uint8_t channel,
  const uint8_t *label, const uint8_t label_length, const uint8_t *id,
  const uint8_t id_length, iot_safe_key_t *key)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t command_size = 2 + label_length + id_length;
  uint8_t command[command_size];
  uint8_t response[IOT_SAFE_APDU_BUFFER_LEN];
  uint16_t response_length = 0;
  uint8_t position = 0;

  memset(&command, 0, sizeof(command));
  memset(&response, 0, sizeof(response));

  IOT_SAFE_DEBUG("Enter iot_safe_get_private_key_information\r\n");

  if (!id_length && !label_length)
  {
    IOT_SAFE_DEBUG("ID or label must be set\r\n");
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  if (id_length && label_length)
  {
    IOT_SAFE_DEBUG("ID and label can't be set at the same time\r\n");
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  if (label_length)
    position = iot_safe_add_tlv_byte_array(command, position,
      IOT_SAFE_TAG_PRIVATE_KEY_LABEL, label_length, label);

  if (id_length)
    position = iot_safe_add_tlv_byte_array(command, position,
      IOT_SAFE_TAG_PRIVATE_KEY_ID, id_length, id);

  ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_GET_DATA, 0xC1, 0x00,
    sizeof(command), command, 0x00, 1, response, sizeof(response),
    &response_length);

  if ((uint8_t) (ret >> 8) == 0x6C)
      ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_GET_DATA, 0xC1, 0x00,
        sizeof(command), command, (uint8_t) ret, 1, response, (uint8_t) ret,
        &response_length);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  return iot_safe_extract_key(response, position, IOT_SAFE_TAG_PRIVATE_KEY_INFO,
    key, &position);
}

iot_safe_error_t iot_safe_sign(uint8_t channel,
  iot_safe_signature_operation_mode_t operation_mode,
  iot_safe_hash_t hash_algorithm, iot_safe_signature_t signature_type,
  const uint8_t *key_id, const uint8_t key_id_length,
  const uint8_t *key_label, const uint8_t key_label_length,
  const uint8_t *data, uint32_t data_length, uint8_t *signature,
  uint16_t signature_size, uint16_t *signature_length)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  IOT_SAFE_DEBUG("Enter iot_safe_sign\r\n");

  ret = iot_safe_compute_signature_init(channel, IOT_SAFE_SESSION_NUMBER,
    key_id, key_id_length, key_label, key_label_length, operation_mode,
    hash_algorithm, signature_type);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  return iot_safe_compute_signature_update(channel, IOT_SAFE_SESSION_NUMBER,
    operation_mode, data, data_length, signature, signature_size,
    signature_length);
}

iot_safe_error_t iot_safe_verify(uint8_t channel,
  iot_safe_signature_operation_mode_t operation_mode,
  iot_safe_hash_t hash_algorithm, iot_safe_signature_t signature_type,
  const uint8_t *key_id, const uint8_t key_id_length,
  const uint8_t *key_label, const uint8_t key_label_length,
  const uint8_t *data, uint32_t data_length, uint8_t *signature,
  uint16_t signature_length)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  IOT_SAFE_DEBUG("Enter iot_safe_verify\r\n");

  ret = iot_safe_verify_signature_init(channel, IOT_SAFE_SESSION_NUMBER, key_id,
    key_id_length, key_label, key_label_length, operation_mode, hash_algorithm,
    signature_type);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  return iot_safe_verify_signature_update(channel, IOT_SAFE_SESSION_NUMBER,
    operation_mode, data, data_length, signature, signature_length);
}

iot_safe_error_t iot_safe_get_random(uint8_t channel, uint8_t *random,
  uint16_t random_size, uint16_t *random_length)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  IOT_SAFE_DEBUG("Enter iot_safe_get_random random_size=%d\r\n", random_size);

  ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_GET_RANDOM, 0x00, 0x00,
    0x00, NULL, random_size, 1, random, random_size, random_length);

  return ret;
}

iot_safe_error_t iot_safe_read_file(uint8_t channel, const uint8_t *file_id,
  const uint8_t file_id_length, const uint8_t *file_label,
  const uint8_t file_label_length, uint8_t *data, uint16_t data_length)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t command_size = 2 + file_id_length + file_label_length;
  uint8_t command[command_size];
  uint8_t response[IOT_SAFE_APDU_BUFFER_LEN];
  uint8_t position = 0;
  uint16_t data_position = 0;
  uint8_t data_chunk_size = 0;
  uint16_t response_length = 0;

  memset(&command, 0, sizeof(command));
  memset(&response, 0, sizeof(response));

  IOT_SAFE_DEBUG("Enter iot_safe_read_file\r\n");

  if (!file_id_length && !file_label_length)
  {
    IOT_SAFE_DEBUG("File ID or label must be set\r\n");
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  if (file_id_length && file_label_length)
  {
    IOT_SAFE_DEBUG("File ID and label can't be set at the same time\r\n");
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  if (file_id_length)
    position = iot_safe_add_tlv_byte_array(command, position,
      IOT_SAFE_TAG_FILE_ID, file_id_length, file_id);

  if (file_label_length)
    position = iot_safe_add_tlv_byte_array(command, position,
      IOT_SAFE_TAG_FILE_LABEL, file_label_length, file_label);

  while (data_position < data_length)
  {
    // Read data in chunks
    if (data_length - data_position >= IOT_SAFE_FILE_CHUNK_SIZE)
      data_chunk_size = IOT_SAFE_FILE_CHUNK_SIZE;
    else
      data_chunk_size = data_length - data_position;

    // IoT SAFE standard specifies that Le should be equal to 00h but this
    // raises issue with modem such as Sequans Monarch GMS01Q which returns
    // incomplete answer when the answer is greater than its internal buffer
    // (e.g. 256). So set Le to data_chunk_size to avoid any issue.
    ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_READ_FILE,
      (uint8_t)(data_position >> 8), (uint8_t)data_position, sizeof(command),
      command, data_chunk_size, 1, response, data_chunk_size,
      &response_length);

    if ((uint8_t) (ret >> 8) == 0x61)
      ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_GET_RESPONSE, 0x00, 0x00,
        0, NULL, data_chunk_size, 1, response, data_chunk_size,
        &response_length);
    else if (ret != IOT_SAFE_SUCCESS)
      return ret;

    memcpy(&data[data_position], &response, data_chunk_size);
    data_position += data_chunk_size;
  }

  IOT_SAFE_DEBUG("Exit iot_safe_read_file: ");
  for (int i=0; i<data_length; i++)
    IOT_SAFE_DEBUG("%02X ", data[i]);
  IOT_SAFE_DEBUG("\r\n");

  return ret;
}

void iot_safe_print_crypto_functions(
  iot_safe_crypto_function_t crypto_functions)
{
  if (!crypto_functions)
    return;

  IOT_SAFE_DEBUG("  Cryptographic functions:                  %02X\r\n",
    crypto_functions);
  if (crypto_functions & IOT_SAFE_CRYPTO_FUNCTION_SIGNATURE)
    IOT_SAFE_DEBUG("                                              Signature (generation or verification) (%02X)\r\n",
      IOT_SAFE_CRYPTO_FUNCTION_SIGNATURE);
  if (crypto_functions & IOT_SAFE_CRYPTO_FUNCTION_KEY_GENERATION)
    IOT_SAFE_DEBUG("                                              Key generation (%02X)\r\n",
      IOT_SAFE_CRYPTO_FUNCTION_KEY_GENERATION);
  if (crypto_functions & IOT_SAFE_CRYPTO_FUNCTION_KEY_AGREEMENT)
    IOT_SAFE_DEBUG("                                              Key agreement (%02X)\r\n",
      IOT_SAFE_CRYPTO_FUNCTION_KEY_AGREEMENT);
  if (crypto_functions & IOT_SAFE_CRYPTO_FUNCTION_KEY_DERIVATION)
    IOT_SAFE_DEBUG("                                              Key derivation (%02X)\r\n",
      IOT_SAFE_CRYPTO_FUNCTION_KEY_DERIVATION);
}

void iot_safe_print_algos_for_hash(iot_safe_hash_t algos_for_hash)
{
  if (!algos_for_hash)
    return;

  IOT_SAFE_DEBUG("  Supported algorithms for hash:            %02X\r\n",
    algos_for_hash);
  if (algos_for_hash & IOT_SAFE_HASH_SHA_256)
    IOT_SAFE_DEBUG("                                              SHA-256 (%02X)\r\n",
      IOT_SAFE_HASH_SHA_256);
  if (algos_for_hash & IOT_SAFE_HASH_SHA_384)
    IOT_SAFE_DEBUG("                                              SHA-384 (%02X)\r\n",
      IOT_SAFE_HASH_SHA_384);
  if (algos_for_hash & IOT_SAFE_HASH_SHA_512)
    IOT_SAFE_DEBUG("                                              SHA-512 (%02X)\r\n",
      IOT_SAFE_HASH_SHA_512);
}

void iot_safe_print_algos_for_sign(
  iot_safe_signature_t algos_for_sign)
{
  if (!algos_for_sign)
    return;

  IOT_SAFE_DEBUG("  Supported algorithms for signature:       %02X\r\n",
    algos_for_sign);
  if (algos_for_sign & IOT_SAFE_SIGNATURE_RSA_PKCS)
    IOT_SAFE_DEBUG("                                              RSA with padding according to RSAPSSA PKCS#1 v1.5 (%02X)\r\n",
      IOT_SAFE_SIGNATURE_RSA_PKCS);
  if (algos_for_sign & IOT_SAFE_SIGNATURE_RSA_PSS)
    IOT_SAFE_DEBUG("                                              RSA with padding according to RSASSA PSS (%02X)\r\n",
      IOT_SAFE_SIGNATURE_RSA_PSS);
  if (algos_for_sign & IOT_SAFE_SIGNATURE_ECDSA)
    IOT_SAFE_DEBUG("                                              ECDSA (%02X)\r\n",
      IOT_SAFE_SIGNATURE_ECDSA);
}

void iot_safe_print_algos_for_key_agreement(
  iot_safe_key_agreement_t algos_for_key_agreement)
{
  if (!algos_for_key_agreement)
    return;

  IOT_SAFE_DEBUG("  Supported algorithms for key agreement:   %02X\r\n",
    algos_for_key_agreement);
  if (algos_for_key_agreement & IOT_SAFE_KEY_AGREEMENT_ECKA)
    IOT_SAFE_DEBUG("                                              ECKA (DL/ECKAS-DH1, IEEE 1363) (%02X)\r\n",
      IOT_SAFE_KEY_AGREEMENT_ECKA);
}

void iot_safe_print_algos_for_key_derivation(
  iot_safe_key_derivation_t algos_for_key_derivation)
{
  if (!algos_for_key_derivation)
    return;

  IOT_SAFE_DEBUG("  Supported algorithms for key derivation:  %02X\r\n",
    algos_for_key_derivation);
  if (algos_for_key_derivation & IOT_SAFE_KEY_DERIVATION_PRF_SHA256)
    IOT_SAFE_DEBUG("                                              PRF SHA-256 (rfc5246) (%02X)\r\n",
      IOT_SAFE_KEY_DERIVATION_PRF_SHA256);
  if (algos_for_key_derivation & IOT_SAFE_KEY_DERIVATION_HKDF)
    IOT_SAFE_DEBUG("                                              HKDF (rfc5869) (%02X)\r\n",
      IOT_SAFE_KEY_DERIVATION_HKDF);
}

void iot_safe_print_bytes(uint8_t *value, uint8_t size)
{
  uint8_t i = 0;
  if (value == NULL)
    return;

  for (i=0; i<size; i++)
    IOT_SAFE_DEBUG("%02X ", value[i]);
  IOT_SAFE_DEBUG("\r\n");
}

void iot_safe_print_access_conditions(
  iot_safe_object_access_t access_conditions)
  {
  if (!access_conditions)
    return;

  IOT_SAFE_DEBUG("  Object Access conditions:                 %02X\r\n", access_conditions);
  if (access_conditions & IOT_SAFE_OBJECT_ACCESS_READ)
    IOT_SAFE_DEBUG("                                              Read (%02X)\r\n",
      IOT_SAFE_OBJECT_ACCESS_READ);
  if (access_conditions & IOT_SAFE_OBJECT_ACCESS_UPDATE)
    IOT_SAFE_DEBUG("                                              Update (%02X)\r\n",
      IOT_SAFE_OBJECT_ACCESS_UPDATE);
}

void iot_safe_print_state(iot_safe_object_state_t state)
{
  if (!state)
    return;

  IOT_SAFE_DEBUG("  Object state:                             %02X ", state);
  switch (state)
  {
    case IOT_SAFE_OBJECT_STATE_ACTIVATED:
      IOT_SAFE_DEBUG("Activated (filled)");
      break;
    case IOT_SAFE_OBJECT_STATE_DEACTIVATED:
      IOT_SAFE_DEBUG("Deactivated (container empty or partially filled)");
      break;
    default:
      IOT_SAFE_DEBUG("RFU");
    }
    IOT_SAFE_DEBUG("\r\n");
}

void iot_safe_print_usage(iot_safe_key_usage_t usage)
{
  if (!usage)
    return;

  IOT_SAFE_DEBUG("  Key specific usage:                       %02X ", usage);
  switch (usage)
  {
    case IOT_SAFE_KEY_USAGE_GENERAL:
      IOT_SAFE_DEBUG("General purpose key");
      break;
    case IOT_SAFE_KEY_USAGE_CERTIFICATE_VERIFY_TLS12:
      IOT_SAFE_DEBUG("Key for certificate Verifiy TLS 1.2 handshake message");
      break;
    case IOT_SAFE_KEY_USAGE_CERTIFICATE_VERIFY_TLS13:
      IOT_SAFE_DEBUG("Key for certificate Verifiy TLS 1.3 handshake message");
      break;
    default:
      IOT_SAFE_DEBUG("RFU");
  }
  IOT_SAFE_DEBUG("\r\n");
}

void iot_safe_print_type(iot_safe_object_state_t type) {
  if (!type)
    return;

  IOT_SAFE_DEBUG("  Key type:                                 %02X ", type);
  switch (type)
  {
    case IOT_SAFE_KEY_TYPE_RSA_2K:
      IOT_SAFE_DEBUG("RSA 2K");
      break;
    case IOT_SAFE_KEY_TYPE_NIST_SECP256R1_PERSISTENT:
      IOT_SAFE_DEBUG("NIST secp256r1 (persistent)");
      break;
    case IOT_SAFE_KEY_TYPE_NIST_SECP256R1_VOLATILE:
      IOT_SAFE_DEBUG("NIST secp256r1 (volatile)");
      break;
    case IOT_SAFE_KEY_TYPE_BRAINPOOL_P256R1_PERSISTENT:
      IOT_SAFE_DEBUG("BrainPoolP256r1 (persistent)");
      break;
    case IOT_SAFE_KEY_TYPE_BRAINPOOL_P256R1_VOLATILE:
      IOT_SAFE_DEBUG("BrainPoolP256r1 (volatile)");
      break;
    case IOT_SAFE_KEY_TYPE_HMAC:
      IOT_SAFE_DEBUG("HMAC capable key");
      break;
    default:
      IOT_SAFE_DEBUG("RFU");
    }
    IOT_SAFE_DEBUG("\r\n");
}

void iot_safe_print_application(iot_safe_application_t *application)
{
  IOT_SAFE_DEBUG("Enter iot_safe_print_application\r\n");

  if (application == NULL)
    return;

  IOT_SAFE_DEBUG("  SIM Alliance version:                     %d\r\n",
    application->version);
  IOT_SAFE_DEBUG("  Applet proprietary identifier:            ");
  iot_safe_print_bytes(application->id, sizeof(application->id));
  IOT_SAFE_DEBUG("  Max number of files:                      %d\r\n",
    application->max_files);
  IOT_SAFE_DEBUG("  Max number of private keys:               %d\r\n",
    application->max_private_keys);
  IOT_SAFE_DEBUG("  Max number public keys:                   %d\r\n",
    application->max_public_keys);
  IOT_SAFE_DEBUG("  Max number secret keys:                   %d\r\n",
    application->max_secrets);
  iot_safe_print_crypto_functions(application->crypto_functions);
  iot_safe_print_algos_for_hash(application->algos_for_hash);
  iot_safe_print_algos_for_sign(application->algos_for_sign);
  iot_safe_print_algos_for_key_agreement(application->algos_for_key_agreement);
  iot_safe_print_algos_for_key_derivation(application->algos_for_key_derivation);
  IOT_SAFE_DEBUG("  Maximum number of sessions:               %d\r\n",
    application->max_sessions);
}

void iot_safe_print_key(iot_safe_key_t *key, uint8_t key_id_tag)
{
  IOT_SAFE_DEBUG("Enter iot_safe_print_key\r\n");

  if (key == NULL)
    return;

  if (key->label_length)
  {
    IOT_SAFE_DEBUG("  %s key label:                      ",
      key_id_tag==IOT_SAFE_TAG_PRIVATE_KEY_ID?"Private":"Public");
    iot_safe_print_bytes(key->label, key->label_length);
  }
  if (key->id_length)
  {
    IOT_SAFE_DEBUG("  %s key identifier:                   ",
      key_id_tag==IOT_SAFE_TAG_PRIVATE_KEY_ID?"Private":"Public");
    iot_safe_print_bytes(key->id, key->id_length);
  }
  iot_safe_print_access_conditions(key->access_conditions);
  iot_safe_print_state(key->state);
  iot_safe_print_type(key->type);
  iot_safe_print_usage(key->usage);
  iot_safe_print_crypto_functions(key->crypto_functions);
  iot_safe_print_algos_for_sign(key->algos_for_sign);
  iot_safe_print_algos_for_hash(key->algos_for_hash);
  iot_safe_print_algos_for_key_agreement(key->algos_for_key_agreement);
}

void iot_safe_print_private_key(iot_safe_key_t *key)
{
  return iot_safe_print_key(key, IOT_SAFE_TAG_PRIVATE_KEY_ID);
}

void iot_safe_print_public_key(iot_safe_key_t *key)
{
  return iot_safe_print_key(key, IOT_SAFE_TAG_PUBLIC_KEY_ID);
}

void iot_safe_print_secret(iot_safe_secret_t *secret)
{
  IOT_SAFE_DEBUG("Enter iot_safe_print_secret\r\n");

  if (secret == NULL)
    return;

  if (secret->label_length)
  {
    IOT_SAFE_DEBUG("  Secret key label:                      ");
    iot_safe_print_bytes(secret->label, secret->label_length);
  }
  if (secret->id_length)
  {
    IOT_SAFE_DEBUG("  Secret key identifier:                   ");
    iot_safe_print_bytes(secret->id, secret->id_length);
  }
  iot_safe_print_access_conditions(secret->access_conditions);
  iot_safe_print_state(secret->state);
  iot_safe_print_type(secret->type);
  iot_safe_print_crypto_functions(secret->crypto_functions);
  iot_safe_print_algos_for_key_derivation(secret->algos_for_key_derivation);
}

void iot_safe_print_file(iot_safe_file_t *file)
{
  IOT_SAFE_DEBUG("Enter iot_safe_print_file\r\n");

  if (file == NULL)
    return;

  if (file->label_length)
  {
    IOT_SAFE_DEBUG("  File label:                      ");
    iot_safe_print_bytes(file->label, file->label_length);
  }
  if (file->id_length)
  {
    IOT_SAFE_DEBUG("  File key identifier:                   ");
    iot_safe_print_bytes(file->id, file->id_length);
  }
  iot_safe_print_access_conditions(file->access_conditions);
  iot_safe_print_state(file->state);
  iot_safe_print_usage(file->usage);
  IOT_SAFE_DEBUG("  Size:                               %d\r\n", file->size);
}

void iot_safe_print_error(iot_safe_error_t error)
{
  IOT_SAFE_DEBUG("%04X: ", error);
  switch (error)
  {
    case IOT_SAFE_ERROR_MORE_DATA:
      IOT_SAFE_DEBUG("More data available");
      break;
    case IOT_SAFE_ERROR_REMOTE_ADMIN:
      IOT_SAFE_DEBUG("The command execution is successful but a remote administration session has completed");
      break;
    case IOT_SAFE_ERROR_INTEGRITY:
      IOT_SAFE_DEBUG("Integrity Issue (applet store integrity issue detected)");
      break;
    case IOT_SAFE_ERROR_WRONG_LENGTH:
      IOT_SAFE_DEBUG("Wrong length");
      break;
    case IOT_SAFE_ERROR_INCOMPATIBLE_FILE:
      IOT_SAFE_DEBUG("Command incompatible with file structure");
      break;
    case IOT_SAFE_ERROR_DATA_INVALIDATED:
      IOT_SAFE_DEBUG("Referenced data invalidated (remote administration session on-going, including update on targeted applet store object)");
      break;
    case IOT_SAFE_ERROR_CONDITIONS_NOT_SATISFIED:
      IOT_SAFE_DEBUG("Conditions of use not satisfied");
      break;
    case IOT_SAFE_ERROR_EXECUTION_OR_CAPACITY:
      IOT_SAFE_DEBUG("Remote administration session including update on targeted applet store object has completed, and the command execution has failed or Maximum capacity reached");
      break;
    case IOT_SAFE_ERROR_INCORRECT_DATA:
      IOT_SAFE_DEBUG("Incorrect data");
      break;
    case IOT_SAFE_ERROR_FILE_NOT_FOUND:
      IOT_SAFE_DEBUG("File reference not found");
      break;
    case IOT_SAFE_ERROR_MEMORY:
      IOT_SAFE_DEBUG("Insufficient memory");
      break;
    case IOT_SAFE_ERROR_INCORRECT_P1_P2:
      IOT_SAFE_DEBUG("Incorrect P1, P2");
      break;
    case IOT_SAFE_ERROR_INVALID_INSTRUCTION:
      IOT_SAFE_DEBUG("Invalid instruction");
      break;
    case IOT_SAFE_ERROR_SIGNATURE_MISMATCH:
      IOT_SAFE_DEBUG("Provided signature does not match");
      break;
    case IOT_SAFE_ERROR_INVALID_CLASS:
      IOT_SAFE_DEBUG("Invalid class");
      break;
    case IOT_SAFE_ERROR_UNKNOWN:
      IOT_SAFE_DEBUG("Unknown error (other error)");
      break;
    case IOT_SAFE_SUCCESS:
      IOT_SAFE_DEBUG("Successful execution");
      break;
    default:
      IOT_SAFE_DEBUG("RFU");
  }
  IOT_SAFE_DEBUG("\r\n");
}

void iot_safe_print_tag(uint8_t tag)
{
  IOT_SAFE_DEBUG("%02X: ", tag);
  switch(tag)
  {
    case IOT_SAFE_TAG_SIM_ALLIANCE_VERSION:
      IOT_SAFE_DEBUG("SIM Alliance version");
      break;
    case IOT_SAFE_TAG_APPLET_ID:
      IOT_SAFE_DEBUG("Applet proprietary identifier");
      break;
    case IOT_SAFE_TAG_FILE_SIZE:
      IOT_SAFE_DEBUG("File size");
      break;
    case IOT_SAFE_TAG_FILE_USAGE:
      IOT_SAFE_DEBUG("File specific usage");
      break;
    case IOT_SAFE_TAG_COMPUTED_SIGNATURE:
      IOT_SAFE_DEBUG("Computed signature");
      break;
    case IOT_SAFE_TAG_PUBLIC_KEY_DATA:
      IOT_SAFE_DEBUG("Public key data");
      break;
    case IOT_SAFE_TAG_OBJECT_STATE:
      IOT_SAFE_DEBUG("Object state");
      break;
    case IOT_SAFE_TAG_KEY_TYPE:
      IOT_SAFE_DEBUG("Key type");
      break;
    case IOT_SAFE_TAG_KEY_USAGE:
      IOT_SAFE_DEBUG("Key specific usage");
      break;
    case IOT_SAFE_TAG_OBJECT_ACCESS:
      IOT_SAFE_DEBUG("Object access conditions");
      break;
    case IOT_SAFE_TAG_CRYPTO_FUNCTIONS:
      IOT_SAFE_DEBUG("Cryptographic functions");
      break;
    case IOT_SAFE_TAG_KEY_AGREEMENT:
      IOT_SAFE_DEBUG("Supported algorithms for key agreement");
      break;
    case IOT_SAFE_TAG_FILE_LABEL:
      IOT_SAFE_DEBUG("File label");
      break;
    case IOT_SAFE_TAG_PRIVATE_KEY_LABEL:
      IOT_SAFE_DEBUG("Private key label");
      break;
    case IOT_SAFE_TAG_PUBLIC_KEY_LABEL:
      IOT_SAFE_DEBUG("Public key label");
      break;
    case IOT_SAFE_TAG_SECRET_KEY_LABEL:
      IOT_SAFE_DEBUG("Secret key label");
      break;
    case IOT_SAFE_TAG_FILE_ID:
      IOT_SAFE_DEBUG("File ID");
      break;
    case IOT_SAFE_TAG_PRIVATE_KEY_ID:
      IOT_SAFE_DEBUG("Private key ID");
      break;
    case IOT_SAFE_TAG_PUBLIC_KEY_ID:
      IOT_SAFE_DEBUG("Public key ID");
      break;
    case IOT_SAFE_TAG_SECRET_KEY_ID:
      IOT_SAFE_DEBUG("Secret key ID");
      break;
    case IOT_SAFE_TAG_CRYPTO_FUNCTIONS2:
      IOT_SAFE_DEBUG("Cryptographic functions");
      break;
    case IOT_SAFE_TAG_HASH:
      IOT_SAFE_DEBUG("Supported algorithms for hash or Hash algorithm");
      break;
    case IOT_SAFE_TAG_SIGNATURE:
      IOT_SAFE_DEBUG("Supported algorithms for signature or Signature algorithm");
      break;
    case IOT_SAFE_TAG_KEY_AGREEMENT2:
      IOT_SAFE_DEBUG("Supported algorithms for key agreement");
      break;
    case IOT_SAFE_TAG_KEY_DERIVATION:
      IOT_SAFE_DEBUG("Supported algorithms for key derivation");
      break;
    case IOT_SAFE_TAG_LAST_BLOCK_TO_HASH:
      IOT_SAFE_DEBUG("Last block to hash");
      break;
    case IOT_SAFE_TAG_DATA_TO_BE_SIGNED:
      IOT_SAFE_DEBUG("Data for which signature generation is requested");
      break;
    case IOT_SAFE_TAG_INTERMEDIATE_HASH:
      IOT_SAFE_DEBUG("Intermediate hash");
      break;
    case IOT_SAFE_TAG_NUMBER_OF_BYTES_HASHED:
      IOT_SAFE_DEBUG("Number of bytes already hashed");
      break;
    case IOT_SAFE_TAG_FINAL_HASH:
      IOT_SAFE_DEBUG("Final hash");
      break;
    case IOT_SAFE_TAG_OPERATION_MODE:
      IOT_SAFE_DEBUG("Mode of operation for the signature command");
      break;
    case IOT_SAFE_TAG_MAX_NUMBER_FILES:
      IOT_SAFE_DEBUG("Max number of files");
      break;
    case IOT_SAFE_TAG_MAX_NUMBER_PRIVATE_KEYS:
      IOT_SAFE_DEBUG("Max number of private keys");
      break;
    case IOT_SAFE_TAG_MAX_NUMBER_PUBLIC_KEYS:
      IOT_SAFE_DEBUG("Max number public keys");
      break;
    case IOT_SAFE_TAG_MAX_NUMBER_SECRET_KEYS:
      IOT_SAFE_DEBUG("Max number secret keys");
      break;
    case IOT_SAFE_TAG_MAX_NUMBER_SESSIONS:
      IOT_SAFE_DEBUG("Max number number of sessions");
      break;
    case IOT_SAFE_TAG_PRIVATE_KEY_INFO:
      IOT_SAFE_DEBUG("Private key information structure");
      break;
    case IOT_SAFE_TAG_PUBLIC_KEY_INFO:
      IOT_SAFE_DEBUG("Public key information structure");
      break;
    case IOT_SAFE_TAG_FILE_INFO:
      IOT_SAFE_DEBUG("File information structure");
      break;
    case IOT_SAFE_TAG_SECRET_KEY_INFO:
      IOT_SAFE_DEBUG("Secret key information structure");
      break;
    case IOT_SAFE_TAG_SECRET:
      IOT_SAFE_DEBUG("Secret");
      break;
    case IOT_SAFE_TAG_LABEL_AND_SEED:
      IOT_SAFE_DEBUG("Label and Seed");
      break;
    case IOT_SAFE_TAG_PSEUDO_RANDOM_LENGTH:
      IOT_SAFE_DEBUG("Pseudo-random length");
      break;
    case IOT_SAFE_TAG_SALT:
      IOT_SAFE_DEBUG("Salt");
      break;
    default:
      IOT_SAFE_DEBUG("RFU");
  }
  IOT_SAFE_DEBUG("\r\n");
}
