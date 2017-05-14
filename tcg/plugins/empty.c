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

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include "tcg-plugin.h"
#include "disas/disas.h"

static FILE *output;

static void pre_tb_helper_code(const TCGPluginInterface *tpi,
                               TPIHelperInfo info, uint64_t address,
                               uint64_t data1, uint64_t data2,
                               const TranslationBlock* tb)
{
    // pre_tb_helper_code is called each time a translated block is executed
}

static void pre_tb_helper_data(const TCGPluginInterface *tpi,
                               TPIHelperInfo info, uint64_t address,
                               uint64_t *data1, uint64_t *data2,
                               const TranslationBlock* tb)
{
    // pre_tb_helper_data is called each time a basic block was translated
    // it can be used for preparing data for pre_tb_helper_code
}

static void after_exec_opc(uint64_t pc)
{
    fprintf(output, "0x%" PRIx64 "\n", pc);
}

static void after_gen_opc(
    const TCGPluginInterface *tpi, const TPIOpCode *tpi_opcode)
{
    // after_gen_opc is called after a TCG opcode is emitted
    if (tpi_opcode->operator != INDEX_op_insn_start)
        return;

    // insert call to after_exec_opc
    TCGArg args[] = {
        GET_TCGV_I64(tcg_const_i64((uint64_t)tpi_opcode->pc)) };
    tcg_gen_callN(tpi->tcg_ctx, after_exec_opc, TCG_CALL_DUMMY_ARG, 1, args);
}


static void cpus_stopped(const TCGPluginInterface *tpi)
{
}

void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(tpi);
    TPI_DECL_FUNC_1(tpi, after_exec_opc, void, i64);

    tpi->pre_tb_helper_code = pre_tb_helper_code;
    tpi->pre_tb_helper_data = pre_tb_helper_data;
    tpi->after_gen_opc  = after_gen_opc;
    tpi->cpus_stopped = cpus_stopped;

    output = tpi->output;
}
