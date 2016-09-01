/*
 * TCG plugin for QEMU: for each executed block, print its address and
 *                      the name of the function if available.
 *
 * Copyright (C) 2011 STMicroelectronics
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * trace - Execution trace plugin
 *
 * Usage:
 *   $ env TPI_OUTPUT=trace.txt qemu-arch -tcg-plugin trace cmd...
 *
 * Generates a full execution trace, actually a trace of executed
 * Target blocks.
 * Note that the trace interleaves execution from different CPUs
 * and threads.
 *
 * Scope:
 * - linux-user: ok
 * - linux-user threaded: ok
 * - bsd-user: not compiled, not tested
 * - bsd-user threaded: not compiled, not tested
 * - system: not compiled, not tested
 * - generic: yes
 * - archs: all
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include "tcg-plugin.h"
#include "disas/disas.h"

static void pre_tb_helper_code(const TCGPluginInterface *tpi,
                               TPIHelperInfo info, uint64_t address,
                               uint64_t data1, uint64_t data2)
{
    const char *symbol = (const char *)(uintptr_t)data1;
    const char *filename = (const char *)(uintptr_t)data2;

    tpi_exec_lock(tpi);
    fprintf(tpi_output(tpi), "%s %"PRIu32" %"PRIu32": CPU #%" PRIu32 " - 0x%016" PRIx64 " [%" PRIu32 "]: %" PRIu32 " instruction(s) in '%s:%s'\n",
            tcg_plugin_get_filename(),
            tpi_thread_pid(tpi), tpi_thread_tid(tpi),
            tpi_current_cpu_index(tpi), address,
            tpi_current_tb_size(tpi),
            tpi_current_tb_icount(tpi),
            filename != NULL && filename[0] != '\0' ? filename : "<unknown>",
            symbol != NULL && symbol[0] != '\0' ? symbol : "<unknown>");
    tpi_exec_unlock(tpi);
}

static void pre_tb_helper_data(const TCGPluginInterface *tpi,
                               TPIHelperInfo info, uint64_t address,
                               uint64_t *data1, uint64_t *data2)
{
    const char *symbol = NULL;
    const char *filename = NULL;

    lookup_symbol2(address, &symbol, &filename);

    *data1 = (uintptr_t)symbol;
    *data2 = (uintptr_t)filename;
}

void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(tpi);
    tpi->pre_tb_helper_code = pre_tb_helper_code;
    tpi->pre_tb_helper_data = pre_tb_helper_data;
}
