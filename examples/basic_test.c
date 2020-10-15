/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file   test.c
 * @brief  Basic PCSC test sample
 */

#include <stdio.h>
#include <string.h>

#include "iot_safe.h"

static const uint8_t IOT_SAFE_PRIVATE_KEY_ID[] = { 0x01 };

static const uint8_t IOT_SAFE_PUBLIC_KEY_ID[] = { 0x01 };

static const uint8_t IOT_SAFE_FILE_ID[] = { 0x02 };

static const uint8_t HASH_VALUE[] = {0xAB, 0xCD, 0xEF };

void iot_safe_test_verify()
{
  uint8_t channel = 0;
  uint8_t signature[256];
  uint16_t signature_length = 0;
  iot_safe_error_t ret;

  printf("Enter iot_safe_test_verify\n");

  memset(signature, 0, sizeof(signature));

  // Init communication channel
  iot_safe_init(IOT_SAFE_AID, sizeof(IOT_SAFE_AID), &channel);
  
  uint8_t random[32];
  memset(&random, 0, sizeof(random));
  uint16_t length;
  iot_safe_get_random(channel, random, sizeof(random), &length);

  // Applet crash ...
  iot_safe_application_t application;
  memset(&application, 0, sizeof(application));

  iot_safe_get_application(channel, &application);
  iot_safe_print_application(&application);

  // Call iot_safe_get_object_list and display keys
  iot_safe_key_t private_keys[2];
  iot_safe_key_t public_keys[2];
  uint8_t private_key_number = 0;
  uint8_t public_key_number = 0;
  uint8_t number = 0;
  memset(&private_keys, 0, sizeof(private_keys));
  memset(&public_keys, 0, sizeof(public_keys));

  iot_safe_get_object_list(channel, private_keys, sizeof(private_keys), &private_key_number,
                           public_keys, sizeof(public_keys), &public_key_number, NULL, 0,
                           &number, NULL, 0, &number);

  iot_safe_print_private_key(&private_keys[0]);
  iot_safe_print_public_key(&public_keys[0]);

  // Sign
  iot_safe_sign(channel, IOT_SAFE_SIGNATURE_OPERATION_MODE_FULL_TEXT,
                IOT_SAFE_HASH_SHA_256, IOT_SAFE_SIGNATURE_ECDSA, IOT_SAFE_PRIVATE_KEY_ID,
                sizeof(IOT_SAFE_PRIVATE_KEY_ID), NULL, 0, HASH_VALUE, sizeof(HASH_VALUE),
                signature, sizeof(signature), &signature_length);

  // Verify
  ret = iot_safe_verify(channel, IOT_SAFE_SIGNATURE_OPERATION_MODE_FULL_TEXT,
                  IOT_SAFE_HASH_SHA_256, IOT_SAFE_SIGNATURE_ECDSA, IOT_SAFE_PUBLIC_KEY_ID,
                  sizeof(IOT_SAFE_PUBLIC_KEY_ID), NULL, 0, HASH_VALUE, sizeof(HASH_VALUE),
                  signature, signature_length);

  if (ret != IOT_SAFE_SUCCESS)
     printf("Verify failure\n");
  else
     printf("Verify success\n");
     
  iot_safe_finish(channel);
}

void iot_safe_test_file()
{
  uint8_t channel = 0;
  
  // Init communication channel
  iot_safe_init(IOT_SAFE_AID, sizeof(IOT_SAFE_AID), &channel);

  // Read file
  uint8_t read_data[1024];
  memset(read_data, 0, sizeof(read_data));
  iot_safe_read_file(channel, IOT_SAFE_FILE_ID, sizeof(IOT_SAFE_FILE_ID), NULL, 0,
                     read_data, sizeof(read_data));

  iot_safe_finish(channel);
}

// ----------------------------------------------------------
/// Entry point to the program
int main() {
  iot_safe_test_verify();
  iot_safe_test_file();
}

