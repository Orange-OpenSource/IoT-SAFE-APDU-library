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
 * STM32 Nucleo-WB55 with Orange Live Booster (Sequans Monarch GMS01Q)
 * Orange LoRa Explorer with Orange Live Booster (Sequans Monarch GMS01Q)
 * Linux (RPi)

### Arduino

On Arduino, this library forwards the IoT SAFE commands from the Rich OS to the
applet thanks to AT CSIM commands (which must be supported by the modem).

The Arduino samples use
[ArduinoBearSSL](https://github.com/arduino-libraries/ArduinoBearSSL) in version
1.7.0.

#### Arduino MKR NB 1500

Four examples are available:
 * a basic example (without any network connection)
 * an example establishing a mutual MQTTS connection with Orange Live Objects
 * an example establishing a mutual MQTTS connection with Azure IoT Hub
 * an example establishing a mutual MQTTS connection with AWS IoT Core
   (through just-in-time registration)

The LiveObjects Arduino MKR NB 1500 sample has been tested over Ethernet (using
an Ethernet shield and the SIM card for IoT SAFE only) as well as over
cellular connectivity.

The Azure IoT Hub and AWS IoT Core samples have been tested over cellular
connectivity.

#### Arduino with [Orange Live Booster (Sequans Monarch GMS01Q)](https://blog.liveobjects.orange-business.com/gms01q-stmod)

To manage the Sequans Monarch GMS01Q modem, this library uses
[TinyGSM](https://github.com/vshymanskyy/TinyGSM) which is licensed under
LGPL-3.0.

The Arduino with Orange Live Booster sample has been tested over cellular
connectivity. This sample also depends on
[Time](https://github.com/PaulStoffregen/Time) which is licensed under
LGPL-2.1.

This sample has been tested with two different Arduinos:
 * STM32 Nucleo-WB55 running
[Arduino_Core_STM32](https://github.com/stm32duino/Arduino_Core_STM32)
 * [Orange LoRa Explorer](https://market.datavenue.orange-business.com/sodaq-orange-lorar-explorer-8719324913065-868-mhz.html)

### Linux and PCSC lite

If there is no modem, this library can forward the IoT SAFE commands from a
Linux-base system to the applet if the (e)SIM is inserted in a smart card
reader. In this case, the library depends on
[PCSC lite](https://pcsclite.apdu.fr/) which is mainly licensed under
BSD-3-Clause: https://github.com/LudovicRousseau/PCSC/blob/master/COPYING.
