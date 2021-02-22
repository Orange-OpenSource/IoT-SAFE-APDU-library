/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file iot_safe_arduino_internal.cpp
 * @brief IoT SAFE arduino internal functions.
 */

#if defined(ARDUINO_ARCH_SAMD)

#include <Arduino.h>
#include <MKRNB.h>

#include <stdarg.h>
#include <stdio.h>

#include "iot_safe_arduino_internal.h"
#include "iot_safe_internal.h"

#define IOT_SAFE_MSG_TAG  0x5A

#define IOT_SAFE_MAX_MSG_SIZE     256 * 2
#define IOT_SAFE_TAIL_MSG_SIZE    5

static char _trace_str[IOT_SAFE_MAX_MSG_SIZE + IOT_SAFE_TAIL_MSG_SIZE];

void iot_safe_arduino_printf(char const *format, ...)
{
  va_list ap;
  va_start(ap, format);

  char *pt_str = _trace_str;
  char *end_str = _trace_str + IOT_SAFE_MAX_MSG_SIZE;

  *end_str = IOT_SAFE_MSG_TAG;

  // add user data
  pt_str += vsnprintf(pt_str, end_str - pt_str, format, ap);

  if (pt_str >= end_str) {
    // Truncated message
    pt_str = end_str - 1;
    *pt_str = 0;
  }

  if (*end_str != IOT_SAFE_MSG_TAG) {
    return;
  }

  SERIAL_PORT_MONITOR.print(_trace_str);
}

iot_safe_error_t iot_safe_arduino_sendAT(const char *at, uint8_t *response,
  uint16_t response_size, uint16_t *response_length)
{
  iot_safe_error_t error_code = IOT_SAFE_ERROR_UNKNOWN;
  String string_response;
  uint16_t string_response_length = 0;
  char byte[3];
  int posData = 0;

  MODEM.sendf("AT+CSIM=%d,\"%s\"", strlen(at), at);
  delay(100);
  if (MODEM.waitForResponse(IOT_SAFE_AT_TIMER, &string_response) == 1)
  {
    if (!string_response.startsWith("+CSIM: "))
    {
      IOT_SAFE_DEBUG("Response does not start with +CSIM: (try again)\n");
      // Try again (Arduino MKR NB 1500 modem seems to have a bug)
      MODEM.waitForResponse(IOT_SAFE_AT_TIMER, &string_response);
      /*if ((MODEM.waitForResponse(IOT_SAFE_AT_TIMER, &string_response) != 1) ||
        !string_response.startsWith("+CSIM: "))*/
        //return IOT_SAFE_ERROR_UNKNOWN;
    }

    posData = string_response.indexOf(",");
    string_response_length = string_response.substring(7, posData).toInt();

    string_response.substring(string_response.length()-5,
      string_response.length()-3).toCharArray(byte, sizeof(byte));
    error_code = strtoul(byte, 0, 16) << 8;

    string_response.substring(string_response.length()-3,
      string_response.length()-1).toCharArray(byte, sizeof(byte));
    error_code |= strtoul(byte, 0, 16);

    posData = posData + 2;
    // Extract data if requested
    if (response_size > 0)
    {
      *response_length = 0;
      for (size_t count = 0; count < response_size; count++) {

        // Error code has already been parsed
        if (posData >= string_response.length()-5)
          break;

        string_response.substring(posData, posData+2).toCharArray(byte,
          sizeof(byte));
        response[count] = strtoul(byte, 0, 16);
        IOT_SAFE_DEBUG("%02X ", response[count]);
        posData += 2;
        *response_length++;
      }
      IOT_SAFE_DEBUG("\n");
    }
  } else
  {
    IOT_SAFE_DEBUG("No response\n");
  }
  return error_code;
}

#endif
