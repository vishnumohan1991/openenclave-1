# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave)


oeedl_file(../props.edl enclave gen)

add_enclave(TARGET props_enc CONFIG sign.conf SOURCES enc.c props.c ${gen})
add_enclave(TARGET props_enc_unsigned SOURCES enc.c props.c ${gen})

target_include_directories(props_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(props_enc_unsigned PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(props_enc oeenclave)
target_link_libraries(props_enc_unsigned oeenclave)
