/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file   iot_safe_pcsc_internal.h
 * @brief  IoT SAFE PCSC internal functions
 */

#ifndef __iot_safe_pcsc_internal_H_
#define __iot_safe_pcsc_internal_H_

#if defined(__cplusplus)
extern "C" {
#endif

#if !defined(ARDUINO)

// From libpcsclite-dev
#include <winscard.h>

#include "iot_safe.h"

/**
 * \brief                     Send an APDU command.
 *
 * \param cla                 Class of the APDU to be sent to the applet.
 * \param ins                 Instruction of the APDU to be sent to the applet.
 * \param p1                  P1 parameter of the APDU to be sent to the
 *                            applet.
 * \param p2                  P2 parameter of the APDU to be sent to the
 *                            applet.
 * \param lc                  Lc parameter of the APDU to be sent to the
 *                            applet.
 * \param command             Command buffer of the APDU to be sent to the
 *                            applet.
 * \param le                  Le parameter of the APDU to be sent to the
 *                            applet.
 * \param with_le             Set to 1 if the APDU must contain Le parameter, 0
 *                            otherwise.
 * \param response            Buffer used to save the response, it must be
 *                            allocated by the user.
 * \param response_size       Size of the response buffer allocated by the user
 * \param response_length     Length of the response.
 * \return                    \c IOT_SAFE_SUCCESS on success.
 * \return                    An error code on failure.
 *
 */
iot_safe_error_t iot_safe_pcsc_sendAPDU(uint8_t cla, uint8_t ins,
  uint8_t p1, uint8_t p2, uint8_t lc, const uint8_t *command, uint8_t le,
  uint8_t with_le, uint8_t *response, uint16_t response_size,
  uint16_t* response_length);
  
#if defined(__cplusplus)
}
#endif

#endif

#endif /* __iot_safe_pcsc_internal_H_ */
