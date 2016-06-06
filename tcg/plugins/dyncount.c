/*
 * TCG plugin for QEMU: count the number of executed instructions per
 *                      CPU.
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
#include <unistd.h>

#include "tcg-op.h"
#include "exec/def-helper.h"
#include "tcg-plugin.h"

#ifndef CONFIG_CAPSTONE
void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(*tpi);
    fprintf(tpi->output,
            "# WARNING: dyncount plugin disabled.\n"
            "#          capstone was not found or forced no at qemu configure time.\n");
}
#else

#include <capstone.h>

/* Check compatibility with capstone 3.x. */
#if CS_API_MAJOR < 3
#error "dyncount plugin required capstone library >= 3.x. Please install from http://www.capstone-engine.org/."
#endif

/* Undef this for DEBUGGING plugin. */
/*#define DEBUG_PLUGIN 1*/

#define MAX_GROUPS_COUNT 512
#define MAX_OPS_COUNT 16384

static csh cs_handle;
static uint64_t *group_count;
static uint64_t *op_count;
static uint64_t *icount_total;

static void pre_tb_helper_code(const TCGPluginInterface *tpi,
                               TPIHelperInfo info, uint64_t address,
                               uint64_t data1, uint64_t data2)
{
    icount_total[info.cpu_index] += info.icount;
}

static void cpus_stopped(const TCGPluginInterface *tpi)
{
    uint64_t total = 0;
    unsigned int i;

    fprintf(tpi->output, "\nInstructions per mnemonic:\n");
    for (i = 0; i < MAX_OPS_COUNT; i++) {
        if (op_count[i] > 0) {
            const char *op_name;
            op_name = cs_insn_name(cs_handle, i);
            fprintf(tpi->output,
                    "  %s: %"PRIu64"\n",
                    op_name,
                    op_count[i]);
        }
    }
    fprintf(tpi->output, "\nInstructions per group:\n");
    for (i = 0; i < MAX_GROUPS_COUNT; i++) {
        if (group_count[i] > 0) {
            const char *group_name;
            group_name = i == 0 ? "unclassified":
                cs_group_name(cs_handle, i);
            fprintf(tpi->output,
                    "  %s: %"PRIu64"\n",
                    group_name,
                    group_count[i]);
        }
    }
    for (i = 0; i < tpi->nb_cpus; i++) {
        total += icount_total[i];
    }
    fprintf(tpi->output, "\nInstructions count: %"PRIu64"\n", total);
}

static void update_group_count(uint32_t group, uint32_t count)
{
    group_count[group] += count;
}

static void update_op_count(uint32_t op, uint32_t count)
{
    op_count[op] += count;
}

static void gen_update_group_helper(const TCGPluginInterface *tpi, uint32_t group, uint32_t count)
{
    int sizemask = 0;
    TCGArg args[2];

    TCGv_i32 tcgv_group;
    TCGv_i32 tcgv_count;

    if (group >= MAX_GROUPS_COUNT)
        return;

    tcgv_group = tcg_const_i32(group);
    tcgv_count = tcg_const_i32(1);

    args[0] = GET_TCGV_I32(tcgv_group);
    args[1] = GET_TCGV_I32(tcgv_count);

    dh_sizemask(void, 0);
    dh_sizemask(i32, 1);
    dh_sizemask(i32, 2);

    tcg_gen_helperN(update_group_count, 0, sizemask, TCG_CALL_DUMMY_ARG, 2, args);

    tcg_temp_free_i32(tcgv_group);
    tcg_temp_free_i32(tcgv_count);
}

static void gen_update_op_helper(const TCGPluginInterface *tpi, uint32_t op, uint32_t count)
{
    int sizemask = 0;
    TCGArg args[2];

    TCGv_i32 tcgv_op;
    TCGv_i32 tcgv_count;

    if (op >= MAX_OPS_COUNT)
        return;

    tcgv_op = tcg_const_i32(op);
    tcgv_count = tcg_const_i32(1);

    args[0] = GET_TCGV_I32(tcgv_op);
    args[1] = GET_TCGV_I32(tcgv_count);

    dh_sizemask(void, 0);
    dh_sizemask(i32, 1);
    dh_sizemask(i32, 2);

    tcg_gen_helperN(update_op_count, 0, sizemask, TCG_CALL_DUMMY_ARG, 2, args);

    tcg_temp_free_i32(tcgv_op);
    tcg_temp_free_i32(tcgv_count);
}

static void decode_instr(const TCGPluginInterface *tpi, uint64_t pc)
{
    size_t count;
    cs_insn *insns;

    count = cs_disasm(cs_handle, (void *)(intptr_t)pc, 16,
                      pc, 1, &insns);
    if (count > 0) {
        cs_insn *insn = &insns[0];
        cs_detail *detail = insn->detail;
#ifdef DEBUG_PLUGIN
        fprintf(tpi->output, "0x%"PRIx64":\t%s\t\t%s",
                insn->address,
                insn->mnemonic,
                insn->op_str);
#endif
        gen_update_op_helper(tpi, insn->id, 1);
        if (detail->groups_count > 0) {
            int n;
            int group;
#ifdef DEBUG_PLUGIN
            fprintf(tpi->output, "\tgroups:");
#endif
            for (n = 0; n < detail->groups_count; n++) {
                group = detail->groups[n];
#ifdef DEBUG_PLUGIN
                fprintf(tpi->output, " %s", cs_group_name(cs_handle, group));
#endif
                gen_update_group_helper(tpi, group, 1);
            }

        } else {
            gen_update_group_helper(tpi, 0, 1);
        }
#ifdef DEBUG_PLUGIN
        fprintf(tpi->output, "\n");
#endif
        cs_free(insn, count);
    } else {
        fprintf(tpi->output, "tcg/plugins/dyncount: unable to disassnble instruction at PC 0x%"PRIx64"\n", pc);
    }
}

void tpi_init(TCGPluginInterface *tpi)
{
    TPI_INIT_VERSION_GENERIC(*tpi);

#if defined(TARGET_X86_64)
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK)
        abort();
#elif defined(TARGET_I386)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) != CS_ERR_OK)
        abort();
#else
#error "dyncount plugin currently works only for: TARGET_x86_64/TARGET_i386"
#endif

    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    tpi->pre_tb_helper_code = pre_tb_helper_code;
    tpi->cpus_stopped = cpus_stopped;
    tpi->decode_instr  = decode_instr;

    icount_total = g_malloc0(tpi->nb_cpus * sizeof(uint64_t));
    group_count = g_malloc0(MAX_GROUPS_COUNT * sizeof(uint64_t));
    op_count = g_malloc0(MAX_OPS_COUNT * sizeof(uint64_t));
}

#endif /* CONFIG_CAPSTONE */
