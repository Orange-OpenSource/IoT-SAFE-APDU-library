/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file   iot_safe_arduino.h
 * @brief  IoT SAFE arduino internal functions
 */

#ifndef __iot_safe_arduino_internal_H_
#define __iot_safe_arduino_internal_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include "iot_safe.h"

#if defined(ARDUINO_ARCH_SAMD)

/**
 * \brief                    Printf implementation for Arduino.
 *
 */
void iot_safe_arduino_printf(char const *format, ...);

/**
 * \brief                     Send an AT command.
 *
 * \param at                  AT command to be sent to the applet.
 * \param response            Buffer used to save the response, it must be
 *                            allocated by the user.
 * \param response_size       Size of the response buffer allocated by the user
 * \param response_length     Length of the response.
 * \return                    \c IOT_SAFE_SUCCESS on success.
 * \return                    An error code on failure.
 *
 */
iot_safe_error_t iot_safe_arduino_sendAT(const char *at, uint8_t *response,
  uint16_t response_size, uint16_t* response_length);

#endif

#if defined(__cplusplus)
}
#endif

#endif /* __iot_safe_arduino_internal_H_ */
