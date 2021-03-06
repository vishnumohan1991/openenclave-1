// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include "thread_local_u.h"

#define SKIP_RETURN_CODE 2

void run_enclave_thread(
    oe_enclave_t* enclave,
    int thread_num,
    int iters,
    int step)
{
    OE_TEST(enclave_thread(enclave, thread_num, iters, step) == OE_OK);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (((argc == 3) && strcmp(argv[2], "--exported-thread-locals")) ||
        argc < 2)
    {
        fprintf(
            stderr,
            "Usage: %s ENCLAVE_PATH [--exported-thread-locals]\n",
            argv[0]);
        return 1;
    }

    if (argc == 3)
    {
        // Ensure that the enclave has thread-local relocations.
        elf64_t elf = {0};
        OE_TEST(elf64_load(argv[1], &elf) == 0);

        elf64_rela_t* relocs = NULL;
        size_t relocs_size = 0;
        OE_TEST(
            elf64_load_relocations(&elf, (void**)&relocs, &relocs_size) ==
            OE_OK);

        size_t num_relocs = relocs_size / sizeof(elf64_rela_t);
        size_t num_thread_local_relocs = 0;
        for (size_t i = 0; i < num_relocs; ++i)
        {
            if (ELF64_R_TYPE(relocs[i].r_info) == R_X86_64_TPOFF64)
                ++num_thread_local_relocs;
        }

        // There are 7 exported thread-local variables.
        // 1 reloc for each exported variable.
        OE_TEST(num_thread_local_relocs == 7);
        free(relocs);
    }

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode "
            "(thread-local)\n");
        return SKIP_RETURN_CODE;
    }

    if ((result = oe_create_thread_local_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    // Run it twice to make sure the enclave thread is correctly reinitialized.
    for (int i = 0; i < 2; ++i)
    {
        // Clear test data in the enclave.
        OE_TEST(clear_test_data(enclave) == OE_OK);

        const int num_threads = 16;
        std::thread threads[num_threads];
        for (int t = 0; t < num_threads; ++t)
        {
            threads[t] =
                std::thread(run_enclave_thread, enclave, t, 1000, 2 * t + 1);
        }

        // Wait for the threads to complete.
        for (int t = 0; t < num_threads; ++t)
        {
            threads[t].join();
        }
    }

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (thread-local)\n");

    return 0;
}
