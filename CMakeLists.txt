# This Makefile is not used by Arduino
# It is only used to build the IoT SAFE library on a PC
# Commands will be sent to the SIM card using a card reader and PCSC

project("iot-safe-apdu-library" C)
cmake_minimum_required(VERSION 3.0)

# Create bin directory in the build folder
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Lib inclusion

# Thread
find_package(Threads)

# IoT SAFE
file(GLOB IOT_SAFE_SOURCE src/*.c)

# PCSC
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I/usr/include/PCSC")

# Uncomment to enable debug
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DIOT_SAFE_ENABLE_DEBUG")

set(COMMON_LIB_LIST ${CMAKE_THREAD_LIBS_INIT} m pcsclite)

add_subdirectory(examples)
