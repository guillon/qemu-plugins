/*
 * TCG plugin for QEMU: wrapper for Dinero IV (a cache simulator)
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

#include "tcg-op.h"
#include "exec/def-helper.h"
#include "tcg-plugin.h"

#define MAX_MEM_LEVEL 3
int mem_level_latencies[MAX_MEM_LEVEL];

#define D4ADDR uint64_t
#include "d4-7/d4.h"
#include "d4-7/cmdd4.h"
#include "d4-7/cmdargs.h"

static FILE *output;
static d4cache *instr_cache, *data_cache;

static TCGArg *icount_total_args;
static uint64_t icount_total;

#define TYPE_IFETCH 0
#define TYPE_DREAD 1
#define TYPE_DWRITE 2
#define TYPE_NUM 3

static inline size_t type2index(char type) {
    switch (type) {
    case 'i': return TYPE_IFETCH;
    case 'r': return TYPE_DREAD;
    case 'w': return TYPE_DWRITE;
    }
    assert(0);
}

static inline const char *index2type(size_t index) {
    switch (index) {
    case TYPE_IFETCH: return "instruction fetch";
    case TYPE_DREAD: return "data read";
    case TYPE_DWRITE: return "data write";
    }
    assert(0);
}

static struct {
    uint64_t *counts;
    size_t size;
} cost_summary[TYPE_NUM];

static void after_exec_opc(uint64_t info_, uint64_t address, uint64_t value, uint64_t pc)
{
    TPIHelperInfo info = *(TPIHelperInfo *)&info_;
    d4memref memref;
    int cost = -1;
    size_t index;
    int i;

    switch (info.type) {
    case 'i':
        address = pc;
        value = 0;

	memref.address    = pc;
	memref.accesstype = D4XINSTRN;
	memref.size       = (unsigned short) info.size;
        cost = d4ref(instr_cache, memref);
        break;

    case 'r':
	memref.address    = address;
	memref.accesstype = D4XREAD;
	memref.size       = (unsigned short) info.size;
	if ((address % info.size) != 0)
	  cost = 0; /* Ignore misaligned accesses for now. */
	else
	  cost = d4ref(data_cache, memref);
        break;

    case 'w':
	memref.address    = address;
	memref.accesstype = D4XWRITE;
	memref.size       = (unsigned short) info.size;
	if ((address % info.size) != 0)
	  cost = 0; /* Ignore misaligned accesses for now. */
	else
	  cost = d4ref(data_cache, memref);
        break;

    default:
        assert(0);
    }
    assert(cost >= 0);

    if (cost >= MAX_MEM_LEVEL) cost = MAX_MEM_LEVEL-1;

    /* Allocate cost slots on demand.  */
    index = type2index(info.type);
    if (cost >= cost_summary[index].size) {
        size_t old_size = cost_summary[index].size;
        size_t new_size = cost + 1;

        cost_summary[index].counts = g_realloc(cost_summary[index].counts,
                                               new_size * sizeof(uint64_t));

        /* Initialize new slots.  */
        for (i = old_size; i < new_size; i++)
            cost_summary[index].counts[i] = 0;

        cost_summary[index].size = new_size;
    }

    cost_summary[index].counts[cost]++;

#if 0
    fprintf(output, "%c 0x%016" PRIx64 " 0x%08" PRIx32 " (0x%016" PRIx64 ") CPU #%" PRIu32 " 0x%016" PRIx64 "\n",
            info.type, address, info.size, value, info.cpu_index, pc);
#endif
}

static void gen_helper(const TCGPluginInterface *tpi, TCGArg *opargs, uint64_t pc, TPIHelperInfo info);

static void after_gen_opc(const TCGPluginInterface *tpi, const TPIOpCode *tpi_opcode)
{
    TPIHelperInfo info;

#define MEMACCESS(type_, size_) do {                            \
        info.type = type_;                                      \
        info.size = size_;                                      \
        info.cpu_index = 0; /* tpi_opcode->cpu_index NYI */     \
    } while (0);

    switch (*tpi_opcode->opcode) {
    case INDEX_op_qemu_ld8s:
    case INDEX_op_qemu_ld8u:
        MEMACCESS('r', 1);
        break;

    case INDEX_op_qemu_ld16s:
    case INDEX_op_qemu_ld16u:
        MEMACCESS('r', 2);
        break;

    case INDEX_op_qemu_ld_i32:
    case INDEX_op_qemu_ld32:
#if TCG_TARGET_REG_BITS == 64
    case INDEX_op_qemu_ld32s:
    case INDEX_op_qemu_ld32u:
#endif
        MEMACCESS('r', 4);
        break;

    case INDEX_op_qemu_ld_i64:
    case INDEX_op_qemu_ld64:
        MEMACCESS('r', 8);
        break;

    case INDEX_op_qemu_st8:
        MEMACCESS('w', 1);
        break;

    case INDEX_op_qemu_st16:
        MEMACCESS('w', 2);
        break;

    case INDEX_op_qemu_st_i32:
    case INDEX_op_qemu_st32:
        MEMACCESS('w', 4);
        break;

    case INDEX_op_qemu_st_i64:
    case INDEX_op_qemu_st64:
        MEMACCESS('w', 8);
        break;

    default:
        return;
    }

    gen_helper(tpi, tpi_opcode->opargs, tpi_opcode->pc, info);
}

static void gen_helper(const TCGPluginInterface *tpi, TCGArg *opargs, uint64_t pc, TPIHelperInfo info)
{
    int sizemask = 0;
    TCGArg args[4];

    TCGv_i64 tcgv_info = tcg_const_i64(*(uint64_t *)&info);
    TCGv_i64 tcgv_pc   = tcg_const_i64(pc);

    args[0] = GET_TCGV_I64(tcgv_info);
    args[1] = opargs ? opargs[1] : 0;
    args[2] = opargs ? opargs[0] : 0;
    args[3] = GET_TCGV_I64(tcgv_pc);

    dh_sizemask(void, 0);
    dh_sizemask(i64, 1);
    dh_sizemask(i64, 2);
    dh_sizemask(i64, 3);
    dh_sizemask(i64, 4);

    tcg_gen_helperN(after_exec_opc, 0, sizemask, TCG_CALL_DUMMY_ARG, 4, args);

    tcg_temp_free_i64(tcgv_pc);
    tcg_temp_free_i64(tcgv_info);
}

static void decode_instr(const TCGPluginInterface *tpi, uint64_t pc)
{
    TPIHelperInfo info;

#if defined(TARGET_SH4)
    MEMACCESS('i', 2);
#elif defined(TARGET_ARM)
    MEMACCESS('i', ARM_TBFLAG_THUMB(tpi->tb->flags) ? 2 : 4);
#else
    MEMACCESS('i', 0);
#endif

    gen_helper(tpi, NULL, pc, info);
}

extern void dostats (void);
extern void doargs (int, char **);

static void cpus_stopped(const TCGPluginInterface *tpi)
{
    d4memref memref;
    int i, j;
    uint64_t cycles_total = icount_total;

    /* Flush the data cache.  */
    memref.accesstype = D4XCOPYB;
    memref.address = 0;
    memref.size = 0;
    d4ref(data_cache, memref);

    fprintf(output, "\n%s (%d): cache summary:\n",
            tcg_plugin_get_filename(), getpid());
    for (i = 0; i < TYPE_NUM; i++) {
        for (j = 0; j < cost_summary[i].size; j++) {
            fprintf(output, "\t%s: %"PRIu64" access in ", index2type(i),
                    cost_summary[i].counts[j]);
            if (j != cost_summary[i].size - 1)
                fprintf(output, "cache level %d\n", j + 1);
            else
                fprintf(output, "RAM\n");
            /* Treat only data reads for cycles estimate for now. */
            if (i == TYPE_DREAD)
                cycles_total +=
                    cost_summary[i].counts[j] * mem_level_latencies[j];
        }
    }
    fprintf(output,
            "\tfetched instructions: %"PRIu64 "\n",
            icount_total);

    fprintf(tpi->output,
            "%s (%d): number of estimated cycles = %" PRIu64 "\n",
            tcg_plugin_get_filename(), getpid(), cycles_total);

}

/* This function generates code which is *not* thread-safe!  */
static void before_gen_tb(const TCGPluginInterface *tpi)
{
    TCGv_ptr icount_ptr;
    TCGv_i64 icount_tmp;
    TCGv_i32 tb_icount32;
    TCGv_i64 tb_icount64;

    /* icount_ptr = &icount */
    icount_ptr = tcg_const_ptr((tcg_target_long)&icount_total);

    /* icount_tmp = *icount_ptr */
    icount_tmp = tcg_temp_new_i64();
    tcg_gen_ld_i64(icount_tmp, icount_ptr, 0);

    /* icount_args = &tb_icount32 */
    /* tb_icount32 = fixup(tb->icount) */
    icount_total_args = gen_opparam_ptr + 1;
    tb_icount32 = tcg_const_i32(0);

    /* tb_icount64 = (int64_t)tb_icount32 */
    tb_icount64 = tcg_temp_new_i64();
    tcg_gen_extu_i32_i64(tb_icount64, tb_icount32);

    /* icount_tmp += tb_icount64 */
    tcg_gen_add_i64(icount_tmp, icount_tmp, tb_icount64);

    /* *icount_ptr = icount_tmp */
    tcg_gen_st_i64(icount_tmp, icount_ptr, 0);

    tcg_temp_free_i64(tb_icount64);
    tcg_temp_free_i32(tb_icount32);
    tcg_temp_free_i64(icount_tmp);
    tcg_temp_free_ptr(icount_ptr);
}

static void after_gen_tb(const TCGPluginInterface *tpi)
{
    /* Patch parameter value.  */
    *icount_total_args = tpi->tb->icount;
}

static void parse_latencies(const char *latencies)
{
    int level = 0;
    const char *ptr = latencies;

    while (*ptr != '\0' && level < MAX_MEM_LEVEL) {
        mem_level_latencies[level] = atoi(ptr);
        if (mem_level_latencies[level] <= 0)
            fprintf(output, "# WARNING: %d latency for memory level %d, "
                    "while parsing DINERO_LATENCIES: %s\n",
                    mem_level_latencies[level], level, latencies);
        while(*ptr != '\0' && *ptr != ',')
            ptr++;
        if (*ptr == ',')
            ptr++;
        level += 1;
    }
}

void tpi_init(TCGPluginInterface *tpi)
{
    int i, argc;
    char **argv;
    char *cmdline;
    char *latencies;

    TPI_INIT_VERSION(*tpi);
    output = tpi->output;

    tpi->after_gen_opc = after_gen_opc;
    tpi->decode_instr  = decode_instr;
    tpi->cpus_stopped  = cpus_stopped;
    tpi->before_gen_tb = before_gen_tb;
    tpi->after_gen_tb  = after_gen_tb;

#if !defined(TARGET_SH4) && !defined(TARGET_ARM)
    fprintf(output, "# WARNING: instruction cache simulation NYI\n");
#endif

    latencies = getenv("DINEROIV_LATENCIES");
    if (latencies == NULL) {
        latencies = g_strdup("2,40");
        fprintf(output, "# WARNING: using default latencies "
                "for memory hierarchy: %s\n", latencies);
        fprintf(output, "# INFO: use the DINEROIV_LATENCIES envvar "
                "to specify memory hierarchy latencies\n");
    }

    cmdline = getenv("DINEROIV_CMDLINE");
    if (cmdline == NULL) {
        cmdline = g_strdup("-l1-isize 16k -l1-dsize 8192 -l1-ibsize 32 -l1-dbsize 16");
        fprintf(output, "# WARNING: using default DineroIV command-line: %s\n", cmdline);
        fprintf(output, "# INFO: use the DINEROIV_CMDLINE environment variable to specify a command-line\n");
    }

    /* Parse mem hierarchy latencies values. */
    parse_latencies(latencies);

    /* Create a valid argv[] for Dineroiv.  */
    argv = g_malloc0(2 * sizeof(char *));
    argv[0] = g_strdup("tcg-plugin-dineroIV");
    argv[1] = cmdline;
    argc = 2;

    for (i = 0; cmdline[i] != '\0'; i++) {
        if (cmdline[i] == ' ') {
            cmdline[i] = '\0';
            argv = g_realloc(argv, (argc + 1) * sizeof(char *));
            argv[argc++] = cmdline + i + 1;
        }
    }

    doargs(argc, argv);
    verify_options();
    initialize_caches(&instr_cache, &data_cache);

    if (data_cache == NULL)
        data_cache = instr_cache;

    /* fprintf(output, "---Dinero IV cache simulator, version %s\n", D4VERSION); */
    /* fprintf(output, "---Written by Jan Edler and Mark D. Hill\n"); */
    /* fprintf(output, "---Copyright (C) 1997 NEC Research Institute, Inc. and Mark D. Hill.\n"); */
    /* fprintf(output, "---All rights reserved.\n"); */
    /* fprintf(output, "---Copyright (C) 1985, 1989 Mark D. Hill.  All rights reserved.\n"); */
    /* fprintf(output, "---See -copyright option for details\n"); */
}
