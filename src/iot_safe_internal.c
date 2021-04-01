/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file iot_safe_internal.c
 * @brief IoT SAFE internal functions.
 */

#include <stdio.h>
#include <string.h>
 
#include "iot_safe_internal.h"

iot_safe_error_t iot_safe_sendAPDU(uint8_t cla, uint8_t ins, uint8_t p1,
  uint8_t p2, uint8_t lc, const uint8_t *command, uint8_t le,
  uint8_t with_le, uint8_t *response, uint16_t response_size,
  uint16_t* response_length)
{
  char at[IOT_SAFE_APDU_BUFFER_LEN * 2];
  char char_command[IOT_SAFE_COMMAND_BUFFER_LEN * 2];

  memset(&at, 0, sizeof(at));
  memset(&char_command, 0, sizeof(char_command));

  // We translate bytes into char to be able to send them through MODEM.sendf
  for (int i=0; i<lc; i++)
    sprintf(&char_command[2*i], "%02X", command[i]);

  // Le is optional (compute signature init does not have one, compute update
  // sets Le to 0 (which means 256 ...)
  if (with_le == 1 && lc > 0)
    snprintf(at, sizeof(at), "%02X%02X%02X%02X%02X%s%02X", cla, ins, p1, p2,
      lc, char_command, le );
  else if (with_le == 1 && lc == 0)
    snprintf(at, sizeof(at), "%02X%02X%02X%02X%02X", cla, ins, p1, p2, le);
  else if (with_le == 0 && lc > 0)
    snprintf(at, sizeof(at), "%02X%02X%02X%02X%02X%s", cla, ins, p1, p2, lc,
      char_command);
  else if (with_le == 0 && lc == 0)
    snprintf(at, sizeof(at), "%02X%02X%02X%02X%02X", cla, ins, p1, p2, lc);

  IOT_SAFE_DEBUG("iot_safe_sendAPDU: %s\r\n", at);
#if defined(ARDUINO)
  return iot_safe_arduino_sendAT(at, response, response_size, response_length);
#else
  return iot_safe_pcsc_sendAPDU(cla, ins, p1, p2, lc, command, le, with_le,
    response, response_size, response_length);
#endif
}

uint8_t iot_safe_add_tlv_byte(uint8_t *command, uint8_t position, uint8_t tag,
  uint8_t value)
{
  uint8_t length = sizeof(value);
  uint8_t i = position;
  command[i] = tag;

  // Special case for hash as specification wants it to be on two bytes ...
  if (tag == IOT_SAFE_TAG_HASH)
    length++;

  command[++i] = length;

  if (tag == IOT_SAFE_TAG_HASH)
    command[++i] = 0x00;

  command[++i] = value;
  return i + 1;
}

uint8_t iot_safe_add_tlv_byte_array(uint8_t *command, uint8_t position,
  uint8_t tag, uint8_t length, const uint8_t *value)
{
  command[position] = tag;
  command[++position] = length;
  memcpy(&command[++position], value, length);
  return position + length;
}

iot_safe_error_t iot_safe_extract_tlv(uint8_t *response, uint8_t position,
  uint8_t tag, uint8_t mandatory, uint8_t length, uint8_t *value,
  size_t value_size, uint8_t* value_length, uint8_t *new_position)
{
  uint8_t expected_length = length;
  *value_length = 0;

  IOT_SAFE_DEBUG("iot_safe_extract_tlv for tag: ");
  iot_safe_print_tag(tag);
  // Special case for hash as specification wants it to be on two bytes ...
  // TODO: Will have to wait until applet is fixed for get data - application
  /*if (tag == IOT_SAFE_TAG_HASH)
    expected_length++;*/

  if (response[position] != tag)
  {
    if (mandatory)
    {
      IOT_SAFE_DEBUG("Wrong tag: %02X (received) != %02X (expected)\r\n",
        response[position], tag);
        return IOT_SAFE_ERROR_UNKNOWN;
    }
    else
      return IOT_SAFE_SUCCESS;
  }

  uint8_t received_length = response[position + 1];

  if (expected_length && received_length != expected_length)
  {
    IOT_SAFE_DEBUG("Wrong length: %02X (received) != %02X (expected)\r\n",
      received_length, expected_length);
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  if (value_size > 0)
  {

    // Special case for hash as specification wants it to be on two bytes ...
    if (tag == IOT_SAFE_TAG_HASH)
        memcpy(value, &response[position + 3], received_length - 1);
    else
    {
      if (received_length > value_size)
      {
        IOT_SAFE_DEBUG("Length is greater than value size: %02X (received) > %02X (value size)\r\n",
          received_length, value_size);
          return IOT_SAFE_ERROR_UNKNOWN;
      }

      // TODO: applet is bugged and returns 0x0E (14) for a 13-byte long applet ID ...
      if (tag == IOT_SAFE_TAG_APPLET_ID)
        received_length--;

      // Special case for hash as specification wants it to be on two bytes ...
      // TODO: Will have to wait until applet is fixed for get data - application
      /*if (tag == IOT_SAFE_TAG_HASH)
        memcpy(value, &response[position + 3], received_length - 1);
      else*/
        memcpy(value, &response[position + 2], received_length);
      }

      *new_position = position + 2 + received_length;
  } else
    *new_position = position + 2;
  *value_length = received_length;
  return IOT_SAFE_SUCCESS;
}

iot_safe_error_t iot_safe_extract_key(uint8_t *response, uint8_t position,
  uint8_t tag, iot_safe_key_t *key, uint8_t *new_position)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t key_position = 0;
  uint8_t received_length = 0;
  uint8_t key_tag_label = IOT_SAFE_TAG_PRIVATE_KEY_LABEL;
  uint8_t key_tag_id = IOT_SAFE_TAG_PRIVATE_KEY_ID;

  if (tag != IOT_SAFE_TAG_PRIVATE_KEY_INFO &&
    tag != IOT_SAFE_TAG_PUBLIC_KEY_INFO)
    return ret;

  if (tag == IOT_SAFE_TAG_PUBLIC_KEY_INFO)
  {
    key_tag_label = IOT_SAFE_TAG_PUBLIC_KEY_LABEL;
    key_tag_id = IOT_SAFE_TAG_PUBLIC_KEY_ID;
  }

  ret = iot_safe_extract_tlv(response, position, tag, 1, 0, NULL, 0,
    &received_length, &key_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, key_position, key_tag_label, 0, 0,
    key->label, sizeof(key->label), &received_length, &key_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  key->label_length = received_length;

  ret = iot_safe_extract_tlv(response, key_position, key_tag_id, 1, 0, key->id,
    sizeof(key->id), &received_length, &key_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  key->id_length = received_length;

  ret = iot_safe_extract_tlv(response, key_position,
    IOT_SAFE_TAG_OBJECT_ACCESS, 1, sizeof(key->access_conditions),
    &key->access_conditions, sizeof(key->access_conditions), &received_length,
    &key_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, key_position,
    IOT_SAFE_TAG_OBJECT_STATE, 1, sizeof(key->state), &key->state,
    sizeof(key->state), &received_length, &key_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, key_position, IOT_SAFE_TAG_KEY_TYPE, 1,
    sizeof(key->type), &key->type, sizeof(key->type), &received_length,
    &key_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, key_position, IOT_SAFE_TAG_KEY_USAGE, 1,
    sizeof(key->usage), &key->usage, sizeof(key->usage), &received_length,
    &key_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, key_position,
    IOT_SAFE_TAG_CRYPTO_FUNCTIONS, 1, sizeof(key->crypto_functions),
    &key->crypto_functions, sizeof(key->crypto_functions), &received_length,
    &key_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  // signature is optional
  ret = iot_safe_extract_tlv(response, key_position, IOT_SAFE_TAG_SIGNATURE, 0,
    sizeof(key->algos_for_sign), &key->algos_for_sign,
    sizeof(key->algos_for_sign), &received_length, &key_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  // Special case for hash as specification wants it to be on 2 bytes ...
  ret = iot_safe_extract_tlv(response, key_position, IOT_SAFE_TAG_HASH, 0,
    2, &key->algos_for_hash, sizeof(key->algos_for_hash), &received_length,
    &key_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, key_position,
    IOT_SAFE_TAG_KEY_AGREEMENT, 0, sizeof(key->algos_for_key_agreement),
    &key->algos_for_key_agreement, sizeof(key->algos_for_key_agreement),
    &received_length, &key_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  *new_position = key_position;

  return ret;
}

iot_safe_error_t iot_safe_extract_secret_key(uint8_t *response,
  uint8_t position, iot_safe_secret_t *secret_key, uint8_t *new_position)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t secret_position = 0;
  uint8_t received_length = 0;

  ret = iot_safe_extract_tlv(response, position, IOT_SAFE_TAG_SECRET_KEY_INFO,
    1, 0, NULL, 0, &received_length, &secret_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, secret_position,
   IOT_SAFE_TAG_SECRET_KEY_LABEL, 0, 0, secret_key->label,
   sizeof(secret_key->label), &received_length, &secret_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  secret_key->label_length = received_length;

  ret = iot_safe_extract_tlv(response, secret_position,
    IOT_SAFE_TAG_SECRET_KEY_ID, 1, 0, secret_key->id, sizeof(secret_key->id),
    &received_length, &secret_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  secret_key->id_length = received_length;

  ret = iot_safe_extract_tlv(response, secret_position,
    IOT_SAFE_TAG_OBJECT_ACCESS, 1, sizeof(secret_key->access_conditions),
    &secret_key->access_conditions, sizeof(secret_key->access_conditions),
    &received_length, &secret_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, secret_position,
    IOT_SAFE_TAG_OBJECT_STATE, 1, sizeof(secret_key->state),
    &secret_key->state, sizeof(secret_key->state), &received_length,
    &secret_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, secret_position, IOT_SAFE_TAG_KEY_TYPE,
    1, sizeof(secret_key->type), &secret_key->type, sizeof(secret_key->type),
    &received_length, &secret_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, secret_position,
    IOT_SAFE_TAG_CRYPTO_FUNCTIONS, 1, sizeof(secret_key->crypto_functions),
    &secret_key->crypto_functions, sizeof(secret_key->crypto_functions),
    &received_length, &secret_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  // key derivation is optional
  ret = iot_safe_extract_tlv(response, secret_position,
    IOT_SAFE_TAG_KEY_DERIVATION, 0,
    sizeof(secret_key->algos_for_key_derivation),
    &secret_key->algos_for_key_derivation,
    sizeof(secret_key->algos_for_key_derivation), &received_length,
    &secret_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  *new_position = secret_position;

  return ret;
}

iot_safe_error_t iot_safe_extract_file(uint8_t *response, uint8_t position,
  iot_safe_file_t *file, uint8_t *new_position)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t file_position = 0;
  uint8_t received_length = 0;
  uint8_t file_size_array[2];

  memset(file_size_array, 0, sizeof(file_size_array));

  ret = iot_safe_extract_tlv(response, position, IOT_SAFE_TAG_FILE_INFO, 1, 0,
    NULL, 0, &received_length, &file_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, file_position, IOT_SAFE_TAG_FILE_LABEL,
    0, 0, file->label, sizeof(file->label), &received_length, &file_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  file->label_length = received_length;

  ret = iot_safe_extract_tlv(response, file_position, IOT_SAFE_TAG_FILE_ID, 1,
    0, file->id, sizeof(file->id), &received_length, &file_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  file->id_length = received_length;

  ret = iot_safe_extract_tlv(response, file_position,
    IOT_SAFE_TAG_OBJECT_ACCESS, 1, sizeof(file->access_conditions),
    &file->access_conditions, sizeof(file->access_conditions),
    &received_length, &file_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, file_position,
    IOT_SAFE_TAG_OBJECT_STATE, 1, sizeof(file->state), &file->state,
    sizeof(file->state), &received_length, &file_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  // File size must be converted from byte array to uint16_t
  ret = iot_safe_extract_tlv(response, file_position, IOT_SAFE_TAG_FILE_SIZE,
    1, sizeof(file_size_array), file_size_array, sizeof(file_size_array),
    &received_length, &file_position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  file->size = file_size_array[1] << 8 | file_size_array[0];

  *new_position = file_position;

  return ret;
}

iot_safe_error_t iot_safe_compute_signature_init(uint8_t channel,
  uint8_t session_number, const uint8_t *key_id, uint8_t key_id_length,
  const uint8_t *key_label, uint8_t key_label_length,
  iot_safe_signature_operation_mode_t operation_mode,
  iot_safe_hash_t hash_algorithm, iot_safe_signature_t signature_algorithm)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t position = 0;
  uint8_t command_size = 12 + key_id_length + key_label_length;
  uint8_t command[command_size];
  uint16_t response_length = 0;

  IOT_SAFE_DEBUG("Enter iot_safe_compute_signature_init\r\n");

  memset(&command, 0, sizeof(command));

  if (key_id_length && key_label_length)
  {
    IOT_SAFE_DEBUG("ID and label can't be set at the same time\r\n");
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  if (key_id_length)
    position = iot_safe_add_tlv_byte_array(command, position,
      IOT_SAFE_TAG_PRIVATE_KEY_ID, key_id_length, key_id);

  if (key_label_length)
    position = iot_safe_add_tlv_byte_array(command, position,
      IOT_SAFE_TAG_PRIVATE_KEY_LABEL, key_label_length, key_label);

  position = iot_safe_add_tlv_byte(command, position,
    IOT_SAFE_TAG_OPERATION_MODE, operation_mode);

  position = iot_safe_add_tlv_byte(command, position, IOT_SAFE_TAG_HASH,
    hash_algorithm);

  position = iot_safe_add_tlv_byte(command, position, IOT_SAFE_TAG_SIGNATURE,
    signature_algorithm);

  IOT_SAFE_DEBUG("Try to close the session (in case previous one is open)\r\n");
  iot_safe_sendAPDU(channel, IOT_SAFE_INS_COMPUTE_SIGNATURE_INIT,
    IOT_SAFE_SESSION_CLOSE, session_number, 0, NULL, 0x00, 0, NULL, 0,
    &response_length);

  IOT_SAFE_DEBUG("Send iot_safe_compute_signature_init\r\n");
  ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_COMPUTE_SIGNATURE_INIT,
    IOT_SAFE_SESSION_OPEN, session_number, sizeof(command), command, 0x00, 0,
    NULL, 0, &response_length);

  return ret;
}

iot_safe_error_t iot_safe_verify_signature_init(uint8_t channel,
  uint8_t session_number, const uint8_t *key_id, uint8_t key_id_length,
  const uint8_t *key_label, uint8_t key_label_length,
  iot_safe_signature_operation_mode_t operation_mode,
  iot_safe_hash_t hash_algorithm, iot_safe_signature_t signature_algorithm)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t position = 0;
  uint8_t command_size = 12 + key_id_length + key_label_length;
  uint8_t command[command_size];
  uint16_t response_length = 0;

  IOT_SAFE_DEBUG("Enter iot_safe_verify_signature_init\r\n");

  memset(&command, 0, sizeof(command));

  if (key_id_length && key_label_length)
  {
    IOT_SAFE_DEBUG("ID and label can't be set at the same time\r\n");
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  if (key_id_length)
    position = iot_safe_add_tlv_byte_array(command, position,
      IOT_SAFE_TAG_PUBLIC_KEY_ID, key_id_length, key_id);

  if (key_label_length)
    position = iot_safe_add_tlv_byte_array(command, position,
      IOT_SAFE_TAG_PUBLIC_KEY_LABEL, key_label_length, key_label);

  position = iot_safe_add_tlv_byte(command, position,
    IOT_SAFE_TAG_OPERATION_MODE, operation_mode);

  position = iot_safe_add_tlv_byte(command, position, IOT_SAFE_TAG_HASH,
    hash_algorithm);

  position = iot_safe_add_tlv_byte(command, position, IOT_SAFE_TAG_SIGNATURE,
    signature_algorithm);

  IOT_SAFE_DEBUG("Try to close the session (in case previous one is open)\r\n");
  iot_safe_sendAPDU(channel, IOT_SAFE_INS_VERIFY_SIGNATURE_INIT,
    IOT_SAFE_SESSION_CLOSE, session_number, 0, NULL, 0x00, 0, NULL, 0,
    &response_length);

  IOT_SAFE_DEBUG("Send iot_safe_verify_signature_init\r\n");
  ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_VERIFY_SIGNATURE_INIT,
    IOT_SAFE_SESSION_OPEN, session_number, sizeof(command), command, 0x00, 0,
    NULL, 0, &response_length);

  return ret;
}

iot_safe_error_t iot_safe_convert_asn1_to_raw(uint8_t *signature_asn1,
  uint8_t signature_asn1_length, uint8_t *signature, size_t signature_size,
  uint16_t *signature_length)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t position = 0;
  uint8_t r_length = 0;
  uint8_t s_length = 0;

  if (signature_asn1[position] != 0x30) {
    IOT_SAFE_DEBUG("Unknown ASN.1 DER format (received: %02X, expected: 0x30)\r\n",
      signature_asn1[position]);
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  // Skip total length
  position = position + 2;

  if (signature_asn1[position] != 0x02) {
    IOT_SAFE_DEBUG("Unknown ASN.1 DER format (received: %02X, expected: 0x02)\r\n",
      signature_asn1[position]);
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  r_length = signature_asn1[++position];
  if (r_length > signature_size) {
    IOT_SAFE_DEBUG("r is bigger than buffer: %d > %d\r\n", r_length,
      signature_size);
    return IOT_SAFE_ERROR_UNKNOWN;
  }
  position++;

  // Remove padding byte if any
  if (r_length == 0x21) {
    position++;
    r_length--;
  }

  memcpy(&signature[0], &signature_asn1[position], r_length);

  position = position + r_length;

  if (signature_asn1[position] != 0x02) {
    IOT_SAFE_DEBUG("Unknown ASN.1 DER format (received: %02X, expected: 0x02)\r\n",
      signature_asn1[position]);
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  s_length = signature_asn1[++position];
  if (s_length > signature_size - r_length) {
    IOT_SAFE_DEBUG("s is bigger than remaining buffer size: %d > (%d - %d)\r\n",
      s_length, signature_size, r_length);
    return IOT_SAFE_ERROR_UNKNOWN;
  }
  position++;

  // Remove padding byte if any
  if (s_length == 0x21) {
    position++;
    s_length--;
  }

  memcpy(&signature[r_length], &signature_asn1[position], s_length);

  *signature_length = r_length + s_length;

  return IOT_SAFE_SUCCESS;
}

iot_safe_error_t iot_safe_compute_signature_update(uint8_t channel,
  uint8_t session_number, iot_safe_signature_operation_mode_t operation_mode,
  const uint8_t *data, size_t data_length, uint8_t *signature,
  size_t signature_size, uint16_t* signature_length)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t position = 0;
  uint8_t command_size = 2 + data_length;
  uint8_t command[command_size];
  uint8_t data_tag = IOT_SAFE_TAG_FINAL_HASH;
  uint8_t response[IOT_SAFE_APDU_BUFFER_LEN];
  uint16_t response_length = 0;
  uint8_t signature_asn1[IOT_SAFE_APDU_BUFFER_LEN];
  uint8_t signature_asn1_length = 0;

  IOT_SAFE_DEBUG("Enter iot_safe_compute_signature_update\r\n");

  memset(&command, 0, sizeof(command));
  memset(&response, 0, sizeof(response));
  memset(&signature_asn1, 0, sizeof(signature_asn1));

  switch(operation_mode) {
    case IOT_SAFE_SIGNATURE_OPERATION_MODE_FULL_TEXT:
      data_tag = IOT_SAFE_TAG_DATA_TO_BE_SIGNED;
      break;
    case IOT_SAFE_SIGNATURE_OPERATION_MODE_LAST_BLOCK:
      IOT_SAFE_DEBUG("Last block mode is unsupported\r\n");
      return IOT_SAFE_ERROR_UNKNOWN;
    case IOT_SAFE_SIGNATURE_OPERATION_MODE_PAD_AND_SIGN:
      data_tag = IOT_SAFE_TAG_FINAL_HASH;
      break;
    default:
      IOT_SAFE_DEBUG("Unsupported operation_mode: %d\r\n", operation_mode);
      return IOT_SAFE_ERROR_UNKNOWN;
  }

  iot_safe_add_tlv_byte_array(command, position, data_tag, data_length, data);

  ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_COMPUTE_SIGNATURE_UPDATE,
    0x80, session_number, sizeof(command), command, 0x00, 1, response,
    sizeof(response), &response_length);

  if ((uint8_t) (ret >> 8) == 0x61)
    ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_GET_RESPONSE, 0x00, 0x00, 0,
      NULL, (uint8_t) ret, 1, response, (uint8_t) ret, &response_length);
  else if (ret != IOT_SAFE_SUCCESS)
    return ret;

  ret = iot_safe_extract_tlv(response, position,
    IOT_SAFE_TAG_COMPUTED_SIGNATURE, 1, 0, signature_asn1,
    sizeof(signature_asn1), &signature_asn1_length, &position);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;

  // IoT SAFE specifies raw but some applets return ASN1
  // BearSSL can manage ASN1 or raw but mbedTLS expects raw
  /*ret = iot_safe_convert_asn1_to_raw(signature_asn1, signature_asn1_length,
    signature, signature_size, signature_length);

  if (ret != IOT_SAFE_SUCCESS)
    return ret;*/
  memcpy(signature, signature_asn1, signature_asn1_length);
  *signature_length = signature_asn1_length;

  IOT_SAFE_DEBUG("Close the session\r\n");
  iot_safe_sendAPDU(channel, IOT_SAFE_INS_COMPUTE_SIGNATURE_INIT,
    IOT_SAFE_SESSION_CLOSE, session_number, 0, NULL, 0x00, 0, NULL, 0,
    &response_length);

  return ret;
}

iot_safe_error_t iot_safe_verify_signature_update(uint8_t channel,
  uint8_t session_number, iot_safe_signature_operation_mode_t operation_mode,
  const uint8_t *data, size_t data_length, uint8_t *signature,
  size_t signature_length)
{
  iot_safe_error_t ret = IOT_SAFE_ERROR_UNKNOWN;
  uint8_t position = 0;
  uint8_t command_size = 4 + data_length + signature_length;
  uint8_t command[command_size];
  uint8_t data_tag = IOT_SAFE_TAG_FINAL_HASH;
  uint16_t response_length = 0;

  IOT_SAFE_DEBUG("Enter iot_safe_verify_signature_update\r\n");

  memset(&command, 0, sizeof(command));

  switch(operation_mode) {
    case IOT_SAFE_SIGNATURE_OPERATION_MODE_FULL_TEXT:
      data_tag = IOT_SAFE_TAG_DATA_TO_BE_SIGNED;
      break;
    case IOT_SAFE_SIGNATURE_OPERATION_MODE_LAST_BLOCK:
      IOT_SAFE_DEBUG("Last block mode is unsupported\r\n");
      return IOT_SAFE_ERROR_UNKNOWN;
    case IOT_SAFE_SIGNATURE_OPERATION_MODE_PAD_AND_SIGN:
      data_tag = IOT_SAFE_TAG_FINAL_HASH;
      break;
    default:
      IOT_SAFE_DEBUG("Unsupported operation_mode: %d\r\n", operation_mode);
      return IOT_SAFE_ERROR_UNKNOWN;
  }

  position = iot_safe_add_tlv_byte_array(command, position, data_tag,
    data_length, data);

  position = iot_safe_add_tlv_byte_array(command, position,
    IOT_SAFE_TAG_COMPUTED_SIGNATURE, signature_length, signature);

  ret = iot_safe_sendAPDU(channel, IOT_SAFE_INS_VERIFY_SIGNATURE_UPDATE,
    0x80, session_number, sizeof(command), command, 0x00, 0, NULL, 0,
    &response_length);

  IOT_SAFE_DEBUG("Close the session\r\n");
  iot_safe_sendAPDU(channel, IOT_SAFE_INS_VERIFY_SIGNATURE_INIT,
    IOT_SAFE_SESSION_CLOSE, session_number, 0, NULL, 0x00, 0, NULL, 0,
    &response_length);

  return ret;
}
