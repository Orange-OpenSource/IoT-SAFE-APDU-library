# IoT SAFE APDU library

## Library

This library is compliant with the
[GSMA IoT SAFE interface](https://www.gsma.com/iot/wp-content/uploads/2019/12/IoT.05-v1-IoT-Security-Applet-Interface-Description.pdf).
It allows the user to use the (e)SIM as a keystore.

For now, the library implements a subset of this specification, namely:
 * Compute signature – Init
 * Compute signature – Update
 * Get data – application (to retrieve metadata about the applet)
 * Get data – object list (to retrieve metadata about the public and private
   key)
 * Get random (to retrieve a better random number than the one provided by the
   Rich OS)
 * Read file (to retrieve the client certificate associated to the private key)

By plugging this library to a (D)TLS library such as mbedTLS, it allows the user
to implement the first scenario of the standard: safely open a secure (D)TLS
channel with a private key strongly protected by the (e)SIM hardware.

Debug information can be enabled through the IOT_SAFE_ENABLE_DEBUG compilation
flag.

## Examples

This library has been tested with applets from two different manufacturers on:
 * Arduino MKR NB 1500
 * Linux (RPi)

### Arduino MKR NB 1500

On Arduino, this library forwards the IoT SAFE commands from the Rich OS to the
applet thanks to AT CSIM commands (which must be supported by the modem).

The Arduino LiveObjects sample uses
[ArduinoBearSSL](https://github.com/Orange-OpenSource/ArduinoBearSSL/tree/fix-_ecSign).
Until PR#36 is merged and version 1.6.0 is released, the user must use this
branch.

The Arduino MKR NB 1500 sample has been only tested over Ethernet (using an
Ethernet shield and the SIM card for IoT SAFE only). Using the SIM card for
IoT SAFE as well as the cellular connectivity has not, yet, been tested.

### Linux and PCSC lite

If there is no modem, this library can forward the IoT SAFE commands from a
Linux-base system to the applet if the (e)SIM is inserted in a smart card
reader. In this case, the library depends on
[PCSC lite](https://pcsclite.apdu.fr/) which is mainly licensed under
BSD-3-Clause: https://github.com/LudovicRousseau/PCSC/blob/master/COPYING.
