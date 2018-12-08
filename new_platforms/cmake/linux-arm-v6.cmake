set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(OE_TOOLCHAINS ${CMAKE_SOURCE_DIR}/toolchains)

set(CMAKE_C_COMPILER ${OE_TOOLCHAINS}/arm/bin/arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER ${OE_TOOLCHAINS}/arm/bin/arm-linux-gnueabihf-g++)

set(OE_C_CROSS_COMPILER_ARM ${CMAKE_C_COMPILER})
set(OE_CXX_CROSS_COMPILER_ARM ${CMAKE_CXX_COMPILER})

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
