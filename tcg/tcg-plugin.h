/*
 * QEMU TCG plugin support.
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

#ifndef TCG_PLUGIN_H
#define TCG_PLUGIN_H

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qom/cpu.h"

#include "tcg.h"
#include "tcg-op.h"

#if TARGET_LONG_BITS == 32
#define MAKE_TCGV MAKE_TCGV_I32
#else
#define MAKE_TCGV MAKE_TCGV_I64
#endif

/***********************************************************************
 * Hooks inserted into QEMU here and there.
 */

#ifdef CONFIG_TCG_PLUGIN
    bool tcg_plugin_enabled(void);
    void tcg_plugin_load(const char *name);
    void tcg_plugin_cpus_stopped(void);
    void tcg_plugin_before_gen_tb(CPUState *env, TranslationBlock *tb);
    void tcg_plugin_after_gen_tb(CPUState *env, TranslationBlock *tb);
    void tcg_plugin_after_gen_opc(TCGOp *opcode, TCGArg *opargs, uint8_t nb_args);
    const char *tcg_plugin_get_filename(void);
#else
#   define tcg_plugin_enabled() false
#   define tcg_plugin_load(dso)
#   define tcg_plugin_cpus_stopped()
#   define tcg_plugin_before_gen_tb(env, tb)
#   define tcg_plugin_after_gen_tb(env, tb)
#   define tcg_plugin_after_gen_opc(tcg_opcode, tcg_opargs_, nb_args)
#   define tcg_plugin_get_filename() "<unknown>"
#endif /* !CONFIG_TCG_PLUGIN */

/***********************************************************************
 * TCG plugin interface.
 */

/* This structure shall be 64 bits, see call_tb_helper_code() for
 * details.  */
typedef struct
{
    uint16_t cpu_index;
    uint16_t size;
    union {
        char type;
        uint32_t icount;
    };
} __attribute__((__packed__, __may_alias__)) TPIHelperInfo;

#define TPI_MAX_OP_ARGS 6
typedef struct
{
    uint64_t pc;
    uint8_t nb_args;
    uint8_t operator;
    uint16_t cpu_index;

    TCGOp *opcode;
    TCGArg *opargs;

    /* Should be used by the plugin only.  */
    void *data;
} TPIOpCode;

struct TCGPluginInterface;
typedef struct TCGPluginInterface TCGPluginInterface;

typedef void (* tpi_cpus_stopped_t)(const TCGPluginInterface *tpi);

typedef void (* tpi_before_gen_tb_t)(const TCGPluginInterface *tpi);
typedef void (* tpi_after_gen_tb_t)(const TCGPluginInterface *tpi);

typedef void (* tpi_after_gen_opc_t)(const TCGPluginInterface *tpi, const TPIOpCode *opcode);

typedef void (* tpi_decode_instr_t)(const TCGPluginInterface *tpi, uint64_t pc);

typedef void (* tpi_pre_tb_helper_code_t)(const TCGPluginInterface *tpi,
                                          TPIHelperInfo info, uint64_t address,
                                          uint64_t data1, uint64_t data2);

typedef void (* tpi_pre_tb_helper_data_t)(const TCGPluginInterface *tpi,
                                          TPIHelperInfo info, uint64_t address,
                                          uint64_t *data1, uint64_t *data2);

#define TPI_VERSION 6
struct TCGPluginInterface
{
    /* Compatibility information.  */
    int32_t version;
    const char *name;
    const char *path_name;
    const char *instance_path_name;
    void *instance_handle;
    const char *guest;
    const char *mode;
    size_t sizeof_CPUState;
    size_t sizeof_TranslationBlock;
    size_t sizeof_TCGContext;

    /* Common parameters.  */
    TCGContext *tcg_ctx;
    int nb_cpus;
    FILE *output;
    uint64_t low_pc;
    uint64_t high_pc;
    bool verbose;

    /* Parameters for non-generic plugins.  */
    bool is_generic;
    const CPUState *env;
    const TranslationBlock *tb;

    /* Some private state. */
    bool _in_gen_tpi_helper;
    uint64_t _current_pc;
    const CPUState *_current_env;
    const TranslationBlock *_current_tb;
    TCGArg *_tb_info;
    TCGArg *_tb_data1;
    TCGArg *_tb_data2;

    /* Plugin's callbacks.  */
    void *data;
    tpi_cpus_stopped_t cpus_stopped;
    tpi_before_gen_tb_t before_gen_tb;
    tpi_after_gen_tb_t  after_gen_tb;
    tpi_pre_tb_helper_code_t pre_tb_helper_code;
    tpi_pre_tb_helper_data_t pre_tb_helper_data;
    tpi_after_gen_opc_t after_gen_opc;
    tpi_decode_instr_t decode_instr;
};

#define TPI_INIT_VERSION(tpi) do {                                     \
        (tpi)->version = TPI_VERSION;                                   \
        (tpi)->guest   = TARGET_NAME;                                   \
        (tpi)->mode    = EMULATION_MODE;                                \
        (tpi)->sizeof_CPUState = sizeof(CPUState);                      \
        (tpi)->sizeof_TranslationBlock = sizeof(TranslationBlock);      \
        (tpi)->sizeof_TCGContext = sizeof(TCGContext);                  \
    } while (0);

#define TPI_INIT_VERSION_GENERIC(tpi) do {                             \
        (tpi)->version = TPI_VERSION;                                   \
        (tpi)->guest   = "any";                                         \
        (tpi)->mode    = "any";                                         \
        (tpi)->sizeof_CPUState = 0;                                     \
        (tpi)->sizeof_TranslationBlock = 0;                             \
        (tpi)->sizeof_TCGContext = sizeof(TCGContext);                  \
    } while (0);

/* Macros for declaration of plugin functions callable from target buffer.
   The declared function can then be called with tcg_gen_callN().
   For instance:
   void tpi_init(TCGPluginInterface *tpi) {
     TPI_INIT_VERSION_GENERIC(tpi);
     TPI_DECL_FUNC_2(tpi, myfunction, i64, i64, i32);
     ...
   }
   void after_gen_opc(TCGPluginInterface *tpi,...) {
     ...
     tcg_gen_callN(tpi->tcg_ctx, myfunction, GET_TCGV_I64(tcgv_ret), 2, args); 
     ...
   }
   Implementation note: the structure defined in _TPI_TCGHelperInfo_struct
   must match TCGHelperInfo in tcg.c.
 */
#define _TPI_TCGHelperInfo_struct { \
    void *func;                     \
    const char *name;               \
    unsigned flags;                 \
    unsigned sizemask;              \
    }

#define TPI_DECL_FUNC_0(tpi, NAME, ret) \
    TPI_DECL_FUNC_FLAGS_0(tpi, NAME, 0, ret)
#define TPI_DECL_FUNC_FLAGS_0(tpi, NAME, FLAGS, ret) do {               \
        static const struct _TPI_TCGHelperInfo_struct _info =           \
            { .func = NAME, .name = #NAME, .flags = FLAGS,              \
              .sizemask = dh_sizemask(ret, 0) };                        \
        g_hash_table_insert(tpi->tcg_ctx->helpers, (gpointer)_info.func, \
                            (gpointer)&_info);                          \
    } while(0)

#define TPI_DECL_FUNC_1(tpi, NAME, ret, t1)             \
    TPI_DECL_FUNC_FLAGS_1(tpi, NAME, 0, ret, t1)
#define TPI_DECL_FUNC_FLAGS_1(tpi, NAME, FLAGS, ret, t1) do {           \
        static const struct _TPI_TCGHelperInfo_struct _info =           \
            { .func = NAME, .name = #NAME, .flags = FLAGS,              \
              .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) };   \
        g_hash_table_insert(tpi->tcg_ctx->helpers, (gpointer)_info.func, \
                            (gpointer)&_info);                          \
    } while(0)

#define TPI_DECL_FUNC_2(tpi, NAME, ret, t1, t2)         \
    TPI_DECL_FUNC_FLAGS_2(tpi, NAME, 0, ret, t1, t2)
#define TPI_DECL_FUNC_FLAGS_2(tpi, NAME, FLAGS, ret, t1, t2) do {       \
        static const struct _TPI_TCGHelperInfo_struct _info =           \
            { .func = NAME, .name = #NAME, .flags = FLAGS,              \
              .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1)      \
              | dh_sizemask(t2, 2) };                                   \
        g_hash_table_insert(tpi->tcg_ctx->helpers, (gpointer)_info.func, \
                            (gpointer)&_info);                          \
    } while(0)

#define TPI_DECL_FUNC_3(tpi, NAME, ret, t1, t2, t3) \
    TPI_DECL_FUNC_FLAGS_3(tpi, NAME, 0, ret, t1, t2, t3)
#define TPI_DECL_FUNC_FLAGS_3(tpi, NAME, FLAGS, ret, t1, t2, t3) do {   \
        static const struct _TPI_TCGHelperInfo_struct _info =           \
            { .func = NAME, .name = #NAME, .flags = FLAGS,              \
              .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1)      \
              | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) };              \
        g_hash_table_insert(tpi->tcg_ctx->helpers, (gpointer)_info.func, \
                            (gpointer)&_info);                          \
    } while(0)

#define TPI_DECL_FUNC_4(tpi, NAME, ret, t1, t2, t3, t4)                 \
    TPI_DECL_FUNC_FLAGS_4(tpi, NAME, 0, ret, t1, t2, t3, t4)
#define TPI_DECL_FUNC_FLAGS_4(tpi, NAME, FLAGS, ret, t1, t2, t3, t4) do { \
        static const struct _TPI_TCGHelperInfo_struct _info =           \
            { .func = NAME, .name = #NAME, .flags = FLAGS,              \
              .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1)      \
              | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) }; \
        g_hash_table_insert(tpi->tcg_ctx->helpers, (gpointer)_info.func, \
                            (gpointer)&_info);                          \
    } while(0)

#define TPI_DECL_FUNC_5(tpi, NAME, ret, t1, t2, t3, t4, t5)             \
    TPI_DECL_FUNC_FLAGS_5(tpi, NAME, 0, ret, t1, t2, t3, t4, t5)
#define TPI_DECL_FUNC_FLAGS_5(tpi, NAME, FLAGS, ret, t1, t2, t3, t4, t5) do { \
        static const struct _TPI_TCGHelperInfo_struct _info =           \
            { .func = NAME, .name = #NAME, .flags = FLAGS,              \
              .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1)      \
              | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) \
              | dh_sizemask(t5, 5) };                                   \
        g_hash_table_insert(tpi->tcg_ctx->helpers, (gpointer)_info.func, \
                            (gpointer)&_info);                          \
    } while(0)


typedef void (* tpi_init_t)(TCGPluginInterface *tpi);
void tpi_init(TCGPluginInterface *tpi);

/*
 * Utility functions provided in addition to
 * QEMU interfaces callable from plugin execution time
 * or translation time helpers.
 */

/*
 * Thread local storage specification.
 * Use for instance as in:
 *   static TPI_THREAD int thread_local;
 */
#ifdef __GNUC__
#define TPI_THREAD __thread
#else
#error "Thread local storage not supported"
#endif

/*
 * Global plugin interface accessors.
 */
static inline FILE *tpi_output(const TCGPluginInterface *tpi);

/*
 * Translation blocks accessors.
 * Available at translation time and execution time.
 */
static inline TranslationBlock *tpi_current_tb(const TCGPluginInterface *tpi);
static inline uint64_t tpi_current_tb_address(const TCGPluginInterface *tpi);
static inline uint32_t tpi_current_tb_size(const TCGPluginInterface *tpi);
static inline uint32_t tpi_current_tb_icount(const TCGPluginInterface *tpi);

/*
 * Thread related identifiers.
 * Note that at translation time, these return the
 * translation thread ids which may be different from the
 * actual execution threads.
 */
static inline uint32_t tpi_thread_pid(const TCGPluginInterface *tpi);
static inline uint32_t tpi_thread_tid(const TCGPluginInterface *tpi);
static inline pthread_t tpi_thread_self(const TCGPluginInterface *tpi);

/*
 * QEMU CPUState and CPUArchState accessors.
 * Note that at translation time, these return the
 * translation CPU state which may be different from the
 * actual execution CPU state.
 */
static inline CPUState *tpi_current_cpu(const TCGPluginInterface *tpi);
static inline CPUArchState *tpi_current_cpu_arch(const TCGPluginInterface *tpi);
static inline uint32_t tpi_current_cpu_index(const TCGPluginInterface *tpi);
static inline uint32_t tpi_nb_cpus(const TCGPluginInterface *tpi);

/*
 * Execution lock functions.
 * Should be used for atomic regions executed from plugin
 * helpers such as printfs to tpi_output().
 * This lock is non recursive and will generate an
 * abort on relock condition.
 */
extern void tpi_exec_lock(const TCGPluginInterface *tpi);
extern void tpi_exec_unlock(const TCGPluginInterface *tpi);

/*
 * Guest to host address and loads.
 */
static inline uint64_t tpi_guest_ptr(const TCGPluginInterface *tpi, uint64_t guest_address);
static inline uint64_t tpi_guest_load64(const TCGPluginInterface *tpi, uint64_t guest_address);
static inline uint32_t tpi_guest_load32(const TCGPluginInterface *tpi, uint64_t guest_address);

#include "tcg-plugin.inc.c"

#endif /* TCG_PLUGIN_H */
