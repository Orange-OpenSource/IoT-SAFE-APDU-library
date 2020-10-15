# Define various var name
set(EXECUTABLE_NAME basic_test)
set(IOT_SAFE_LIB iot_safe_for_${EXECUTABLE_NAME})
set(SOURCE_PATH ${CMAKE_SOURCE_DIR})

# Bring the headers
include_directories(../src)

# Make a List of all source files
file(GLOB_RECURSE ALL_SOURCE ${SOURCE_PATH}/*.c)

# Generate the library from the sources
add_library(${IOT_SAFE_LIB} ${ALL_SOURCE})

# You can change the name of the c file but don't forget to report the modification here
# Set the executable name and create it
add_executable(${EXECUTABLE_NAME} ${EXECUTABLE_NAME}.c)

# Link edition configuration
target_link_libraries(${EXECUTABLE_NAME}
 ${IOT_SAFE_LIB}
 ${COMMON_LIB_LIST}
)
