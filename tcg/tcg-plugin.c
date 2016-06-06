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

#include <stdbool.h> /* bool, true, false, */
#include <assert.h>  /* assert(3), */
#include <dlfcn.h>   /* dlopen(3), dlsym(3), */
#include <unistd.h>  /* access(2), STDERR_FILENO, getpid(2), */
#include <fcntl.h>   /* open(2), */
#include <stdlib.h>  /* getenv(3), mkstemp(3), */
#include <string.h>  /* strlen(3), strerror(3), */
#include <stdio.h>   /* *printf(3), memset(3), */
#include <pthread.h> /* pthread_*, */
#include <stdint.h>  /* int*_t types, */
#include <glib.h>    /* glib2 objects/functions,*/
#include <sys/sendfile.h> /* sendfile(2), */

#include "tcg.h"
#include "tcg-op.h"
#include "tcg-plugin.h"
#include "exec/exec-all.h"   /* TranslationBlock */
#include "qom/cpu.h"         /* CPUState */
#include "sysemu/sysemu.h"   /* max_cpus */

/* Singleton plugins global state. */
static struct {

    /* Global configuration. */
    FILE *output;
    uint64_t low_pc;
    uint64_t high_pc;
    bool verbose;

    /* Ensure resources used by *_helper_code are protected from
       concurrent access when mutex_protected is true.  */
    bool mutex_protected;
    pthread_mutex_t helper_mutex;

    /* Actual list of plugins. */
    GList *tpi_list;
} g_plugins_state;


void tcg_plugin_load(const char *name)
{
    TCGPluginInterface *tpi;

    assert(name != NULL);

    tpi = (TCGPluginInterface *)g_malloc0(sizeof(TCGPluginInterface));
    tpi->name = (char *)g_strdup(name);
    g_plugins_state.tpi_list = g_list_append(g_plugins_state.tpi_list, tpi);
}

/* Initialize global plugins state, unless already done. */
static void tcg_plugin_state_init(void)
{
    if (g_plugins_state.output != NULL) return;

    /* Plugins output is, in order of priority:
     *
     * 1. the file $TPI_OUTPUT.$PID if the environment variable
     *    TPI_OUTPUT is defined.
     *
     * 2. a duplicate of the error stream.
     *
     * 3. the error stream itself.
     */
    if (getenv("TPI_OUTPUT")) {
        int no_pid = getenv("TPI_OUTPUT_NO_PID") != NULL;
        char path[PATH_MAX];
        if (no_pid) {
            snprintf(path, PATH_MAX, "%s", getenv("TPI_OUTPUT"));
        }
        else {
            snprintf(path, PATH_MAX, "%s.%d", getenv("TPI_OUTPUT"), getpid());
        }
        g_plugins_state.output = fopen(path, "w");
        if (!g_plugins_state.output) {
            fprintf(stderr, "plugin: warning: can't open TPI_OUTPUT "
                    "(falling back to stderr) at %s: %s\n",
                    path, strerror(errno));
        } else {
            if (!no_pid) {
                /* Create a convenient link to last opened output. */
                int status;
                unlink(getenv("TPI_OUTPUT"));
                status = symlink(path, getenv("TPI_OUTPUT"));
                if (status != 0)
                    fprintf(stderr, "plugin: warning: can't create symlink TPI_OUTPUT "
                            "at %s: %s\n",
                            getenv("TPI_OUTPUT"), strerror(errno));
            }
        }
    }
    if (!g_plugins_state.output)
        g_plugins_state.output = fdopen(dup(fileno(stderr)), "a");
    if (!g_plugins_state.output)
        g_plugins_state.output = stderr;
    assert(g_plugins_state.output != NULL);

    /* This is a compromise between buffered output and truncated
     * output when exiting through _exit(2) in user-mode.  */
    setlinebuf(g_plugins_state.output);

    g_plugins_state.low_pc = 0;
    g_plugins_state.high_pc = UINT64_MAX;

    if (getenv("TPI_SYMBOL_PC")) {
#if 0
        struct syminfo *syminfo =
            reverse_lookup_symbol(getenv("TPI_SYMBOL_PC"));
        if (!syminfo)  {
            fprintf(stderr,
                    "plugin: warning: symbol '%s' not found\n",
                    getenv("TPI_SYMBOL_PC"));
        } else {
            g_plugins_state.low_pc  = syminfo.disas_symtab.elfXX.st_value;
            g_plugins_state.high_pc = g_plugins_state.low_pc +
                syminfo.disas_symtab.elfXX.st_size;
        }
#else
        fprintf(stderr,
                "plugin: warning: TPI_SYMBOL_PC parameter not supported yet\n");
#endif
    }

    if (getenv("TPI_LOW_PC")) {
        g_plugins_state.low_pc = (uint64_t) strtoull(getenv("TPI_LOW_PC"), NULL, 0);
        if (!g_plugins_state.low_pc) {
            fprintf(stderr,
                    "plugin: warning: can't parse TPI_LOW_PC (fall back to 0)\n");
        }
    }

    if (getenv("TPI_HIGH_PC")) {
        g_plugins_state.high_pc = (uint64_t) strtoull(getenv("TPI_HIGH_PC"), NULL, 0);
        if (!g_plugins_state.high_pc) {
            fprintf(stderr,
                    "plugin: warning: can't parse TPI_HIGH_PC (fall back to UINT64_MAX)\n");
            g_plugins_state.high_pc = UINT64_MAX;
        }
    }

    g_plugins_state.verbose = getenv("TPI_VERBOSE") != NULL;

    g_plugins_state.mutex_protected = (getenv("TPI_MUTEX_PROTECTED") != NULL);
    pthread_mutex_init(&g_plugins_state.helper_mutex, NULL);
}

/* Load the dynamic shared object "name" and call its function
 * "tpi_init()" to initialize itself.  Then, some sanity checks are
 * performed to ensure the dynamic shared object is compatible with
 * this instance of QEMU (guest CPU, emulation mode, ...).  */
static void tcg_plugin_tpi_init(TCGPluginInterface *tpi)
{
#if !defined(CONFIG_SOFTMMU)
    unsigned int max_cpus = 1;
#endif
    tpi_init_t tpi_init;
    char *path = NULL;
    void *handle = NULL;
    struct stat plugin_info = {0};
    int plugin_fd = -1;
    int plugin_instance_fd = -1;
    char *plugin_instance_path = NULL;
    int status;
    ssize_t count;
    size_t size;

    assert(tpi != NULL);
    assert(tpi->name != NULL);

    tcg_plugin_state_init();

    /* Check if "name" refers to an installed plugin (short form).  */
    if (tpi->name[0] != '.' && tpi->name[0] != '/') {
        const char *format = CONFIG_QEMU_LIBEXECDIR "/" TARGET_NAME
            "/" EMULATION_MODE "/tcg-plugin-%s.so";
        size_t size = strlen(format) + strlen(tpi->name) - strlen("%s") + 1;

        path = g_malloc0(size * sizeof(char));
        snprintf(path, size, format, tpi->name);

    } else {
        path = g_strdup(tpi->name);
    }
    tpi->path_name = path;

    plugin_fd = open(path, O_RDONLY);
    if (plugin_fd < 0) {
        fprintf(stderr, "plugin: error: can't open plugin at %s: %s\n", path, strerror(errno));
        goto error;
    }

    /*
     * Make a copy of the plugin file in order to allow multiple loads
     * of the same plugin.
     */
    plugin_instance_path = g_strdup("/tmp/qemu-plugin-XXXXXX");
    tpi->instance_path_name = plugin_instance_path;

    plugin_instance_fd = mkstemp(plugin_instance_path);
    if (plugin_instance_fd < 0) {
        fprintf(stderr, "plugin: error: can't create temporary file: %s\n", strerror(errno));
        goto error;
    }

    status = fstat(plugin_fd, &plugin_info);
    if (status != 0) {
        fprintf(stderr, "plugin: error: can't stat file at %s: %s\n", path, strerror(errno));
        goto error;
    }

    size = plugin_info.st_size;
    count = 0;
    while (count < size) {
        size -= count;
        count = sendfile(plugin_instance_fd, plugin_fd, NULL, size);
        if (count < 0) {
            fprintf(stderr, "plugin: error: can't copy plugin file at %s: %s\n", path, strerror(errno));
            goto error;
        }
    }

    /*
     * Load the dynamic shared object and retreive its symbol
     * "tpi_init".
     */
    handle = dlopen(plugin_instance_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "plugin: error: can't load plugin at %s  %s\n", plugin_instance_path,
                dlerror());
        goto error;
    }
    tpi->instance_handle = handle;

    tpi_init = dlsym(handle, "tpi_init");
    if (!tpi_init) {
        fprintf(stderr, "plugin: error: can't resolve 'tpi_init' function in plugin at %s: %s\n", path, dlerror());
        goto error;
    }

    /*
     * Fill the interface with information that may be useful to the
     * plugin initialization.
     */

    TPI_INIT_VERSION(tpi);

    tpi->nb_cpus = max_cpus;
    assert(tpi->nb_cpus >= 0);

    tpi->tcg_ctx = &tcg_ctx;
    assert(tpi->tcg_ctx != NULL);
    assert(tpi->tcg_ctx->helpers != NULL);

    tpi->output = fdopen(dup(fileno(g_plugins_state.output)), "a");
    setlinebuf(tpi->output);

    tpi->low_pc = g_plugins_state.low_pc;
    tpi->high_pc = g_plugins_state.high_pc;

    /*
     * Tell the plugin to initialize itself.
     */

    tpi_init(tpi);

    /*
     * Perform some sanity checks to ensure this TCG plugin is
     * compatible with this instance of QEMU (guest CPU, emulation
     * mode, ...)
     */

    if (!tpi->version) {
        fprintf(stderr, "plugin: error: initialization has failed\n");
        goto error;
    }

    if (tpi->version != TPI_VERSION) {
        fprintf(stderr, "plugin: error: incompatible plugin interface (%d != %d)\n",
                tpi->version, TPI_VERSION);
        goto error;
    }

    if (tpi->sizeof_CPUState != 0
        && tpi->sizeof_CPUState != sizeof(CPUState)) {
        fprintf(stderr, "plugin: error: incompatible CPUState size "
                "(%zu != %zu)\n", tpi->sizeof_CPUState, sizeof(CPUState));
        goto error;
    }

    if (tpi->sizeof_TranslationBlock != 0
        && tpi->sizeof_TranslationBlock != sizeof(TranslationBlock)) {
        fprintf(stderr, "plugin: error: incompatible TranslationBlock size "
                "(%zu != %zu)\n", tpi->sizeof_TranslationBlock,
                sizeof(TranslationBlock));
        goto error;
    }

    if (tpi->sizeof_TCGContext != sizeof(TCGContext)) {
        fprintf(stderr, "plugin: error: incompatible TCGContext size "
                "(%zu != %zu)\n", tpi->sizeof_TCGContext, sizeof(TCGContext));
        goto error;
    }

    if (strcmp(tpi->guest, TARGET_NAME) != 0
        && strcmp(tpi->guest, "any") != 0) {
        fprintf(stderr, "plugin: warning: incompatible guest CPU "
                "(%s != %s)\n", tpi->guest, TARGET_NAME);
    }

    if (strcmp(tpi->mode, EMULATION_MODE) != 0
        && strcmp(tpi->mode, "any") != 0) {
        fprintf(stderr, "plugin: warning: incompatible emulation mode "
                "(%s != %s)\n", tpi->mode, EMULATION_MODE);
    }

    tpi->is_generic = strcmp(tpi->guest, "any") == 0 && strcmp(tpi->mode, "any") == 0;

    if (g_plugins_state.verbose) {
        tpi->verbose = true;
        fprintf(tpi->output, "plugin: info: name = %s\n", tpi->name);
        fprintf(tpi->output, "plugin: info: version = %d\n", tpi->version);
        fprintf(tpi->output, "plugin: info: guest = %s\n", tpi->guest);
        fprintf(tpi->output, "plugin: info: mode = %s\n", tpi->mode);
        fprintf(tpi->output, "plugin: info: sizeof(CPUState) = %zu\n", tpi->sizeof_CPUState);
        fprintf(tpi->output, "plugin: info: sizeof(TranslationBlock) = %zu\n", tpi->sizeof_TranslationBlock);
        fprintf(tpi->output, "plugin: info: output fd = %d\n", fileno(tpi->output));
        fprintf(tpi->output, "plugin: info: low pc = 0x%016" PRIx64 "\n", tpi->low_pc);
        fprintf(tpi->output, "plugin: info: high pc = 0x%016" PRIx64 "\n", tpi->high_pc);
        fprintf(tpi->output, "plugin: info: cpus_stopped callback = %p\n", tpi->cpus_stopped);
        fprintf(tpi->output, "plugin: info: before_gen_tb callback = %p\n", tpi->before_gen_tb);
        fprintf(tpi->output, "plugin: info: after_gen_tb callback = %p\n", tpi->after_gen_tb);
        fprintf(tpi->output, "plugin: info: after_gen_opc callback = %p\n", tpi->after_gen_opc);
        fprintf(tpi->output, "plugin: info: pre_tb_helper_code callback = %p\n", tpi->pre_tb_helper_code);
        fprintf(tpi->output, "plugin: info: pre_tb_helper_data callback = %p\n", tpi->pre_tb_helper_data);
        fprintf(tpi->output, "plugin: info: is%s generic\n", tpi->is_generic ? "" : " not");
    }

    close(plugin_fd);
    close(plugin_instance_fd);
    unlink(plugin_instance_path);

    return;

error:
    if (path)
        g_free(path);

    if (plugin_instance_path)
        g_free(plugin_instance_path);

    if (plugin_fd >= 0)
        close(plugin_fd);

    if (plugin_instance_fd >= 0) {
        close(plugin_instance_fd);
        unlink(plugin_instance_path);
    }

    if (handle != NULL)
        dlclose(handle);

    memset(tpi, 0, sizeof(*tpi));

    return;
}

/* Initialize once the plugin interface an returns true on success.
   Must be called before any attempt to use the tpi interface as
   actual loading is defered until the plugin hooks are called.
 */
static bool tcg_plugin_initialize(TCGPluginInterface *tpi)
{
    assert(tpi != NULL);
    if (tpi->version > 0) return 1;
    if (tpi->version == -1) return 0;

    /* This is the first initialization, if failed, set version to -1. */
    tcg_plugin_tpi_init(tpi);
    if (tpi->version == 0) tpi->version = -1;

    return tpi->version > 0;
}

/* Wrapper to ensure only non-generic plugins can access non-generic data.  */
#define TPI_CALLBACK_NOT_GENERIC(tpi, callback, ...)       \
    do {                                                   \
        if (!tpi->is_generic) {                            \
            tpi->env = tpi->_current_env;                  \
            tpi->tb = tpi->_current_tb;                    \
        }                                                  \
        tpi->callback(tpi, ##__VA_ARGS__);                 \
        tpi->env = NULL;                                   \
        tpi->tb = NULL;                                    \
    } while (0);

static void tcg_plugin_tpi_before_gen_tb(TCGPluginInterface *tpi,
                                         CPUState *env, TranslationBlock *tb)
{
    if (tb->pc < tpi->low_pc || tb->pc >= tpi->high_pc) {
        return;
    }

    assert(!tpi->_in_gen_tpi_helper);
    tpi->_in_gen_tpi_helper = true;

    if (tpi->before_gen_tb) {
        TPI_CALLBACK_NOT_GENERIC(tpi, before_gen_tb);
    }

    /* Generate TCG opcodes to call helper_tcg_plugin_tb*().  */
    if (tpi->pre_tb_helper_code) {
        TCGv_i64 data1;
        TCGv_i64 data2;
        TCGv_i64 info;
        TCGv_i64 address;
        TCGv_i64 tpi_ptr;
        static int iii;

        tpi_ptr = tcg_const_i64((uint64_t)tpi);

        address = tcg_const_i64((uint64_t)tb->pc);

        /* Patched in tcg_plugin_after_gen_tb().  */
        tpi->_tb_info = &tpi->tcg_ctx->gen_opparam_buf[tpi->tcg_ctx->gen_next_parm_idx + 1];
        info = tcg_const_i64(iii++);

        /* Patched in tcg_plugin_after_gen_tb().  */
        tpi->_tb_data1 = &tpi->tcg_ctx->gen_opparam_buf[tpi->tcg_ctx->gen_next_parm_idx + 1];
        data1 = tcg_const_i64(0);

        /* Patched in tcg_plugin_after_gen_tb().  */
        tpi->_tb_data2 = &tpi->tcg_ctx->gen_opparam_buf[tpi->tcg_ctx->gen_next_parm_idx + 1];
        data2 = tcg_const_i64(0);

        gen_helper_tcg_plugin_pre_tb(tpi_ptr, address, info, data1, data2);

        tcg_temp_free_i64(data2);
        tcg_temp_free_i64(data1);
        tcg_temp_free_i64(info);
        tcg_temp_free_i64(address);
    }

    tpi->_in_gen_tpi_helper = false;
}

static void tcg_plugin_tpi_after_gen_tb(TCGPluginInterface *tpi,
                                        CPUState *env, TranslationBlock *tb)
{
    if (tb->pc < tpi->low_pc || tb->pc >= tpi->high_pc) {
        return;
    }

    assert(!tpi->_in_gen_tpi_helper);
    tpi->_in_gen_tpi_helper = true;

    if (tpi->pre_tb_helper_code) {
        /* Patch helper_tcg_plugin_tb*() parameters.  */
        ((TPIHelperInfo *)tpi->_tb_info)->cpu_index = env->cpu_index;
        ((TPIHelperInfo *)tpi->_tb_info)->size = tb->size;
#if TCG_TARGET_REG_BITS == 64
        ((TPIHelperInfo *)tpi->_tb_info)->icount = tb->icount;
#else
        /* i64 variables use 2 arguments on 32-bit host.  */
        *(tpi->_tb_info + 2) = tb->icount;
#endif

        /* Callback variables have to be initialized [when not used]
         * to ensure deterministic code generation, e.g. on some host
         * the opcode "movi_i64 tmp,$value" isn't encoded the same
         * whether $value fits into a given host instruction or
         * not.  */
        uint64_t data1 = 0;
        uint64_t data2 = 0;

        if (tpi->pre_tb_helper_data) {
            TPI_CALLBACK_NOT_GENERIC(tpi, pre_tb_helper_data, *(TPIHelperInfo *)tpi->_tb_info, tb->pc, &data1, &data2);
        }

#if TCG_TARGET_REG_BITS == 64
        *(uint64_t *)tpi->_tb_data1 = data1;
        *(uint64_t *)tpi->_tb_data2 = data2;
#else
        /* i64 variables use 2 arguments on 32-bit host.  */
        *tpi->_tb_data1 = data1 & 0xFFFFFFFF;
        *(tpi->_tb_data1 + 2) = data1 >> 32;

        *tpi->_tb_data2 = data2 & 0xFFFFFFFF;
        *(tpi->_tb_data2 + 2) = data2 >> 32;
#endif
    }

    if (tpi->after_gen_tb) {
        TPI_CALLBACK_NOT_GENERIC(tpi, after_gen_tb);
    }

    tpi->_in_gen_tpi_helper = false;

}

static void tcg_plugin_tpi_after_gen_opc(TCGPluginInterface *tpi,
                                         TCGOp *opcode, TCGArg *opargs, uint8_t nb_args)
{
    TPIOpCode tpi_opcode;

    /* Catch insn_start opcodes to get the current pc. */
    if (opcode->opc == INDEX_op_insn_start) {
#if TARGET_LONG_BITS <= TCG_TARGET_REG_BITS
        tpi->_current_pc = opargs[0];
#else
        tpi->_current_pc = (uint64_t)opargs[0] | (uint64_t)opargs[1] << 32;
#endif
    }

    if (tpi->_current_pc < tpi->low_pc || tpi->_current_pc >= tpi->high_pc) {
        return;
    }

    if (tpi->_in_gen_tpi_helper)
        return;

    tpi->_in_gen_tpi_helper = true;

    nb_args = MIN(nb_args, TPI_MAX_OP_ARGS);

    tpi_opcode.pc   = tpi->_current_pc;
    tpi_opcode.cpu_index = tpi->_current_env->cpu_index;
    tpi_opcode.nb_args = nb_args;

    tpi_opcode.operator = opcode->opc;
    tpi_opcode.opcode = opcode;
    tpi_opcode.opargs = opargs;

    if (tpi->after_gen_opc) {
        TPI_CALLBACK_NOT_GENERIC(tpi, after_gen_opc, &tpi_opcode);
    }

    tpi->_in_gen_tpi_helper = false;
}


/* TCG helper used to call pre_tb_helper_code() in a thread-safe
 * way.  */
void helper_tcg_plugin_pre_tb(uint64_t tpi_ptr,
                              uint64_t address, uint64_t info,
                              uint64_t data1, uint64_t data2)
{
    int error;

    if (g_plugins_state.mutex_protected) {
        error = pthread_mutex_lock(&g_plugins_state.helper_mutex);
        if (error) {
            fprintf(stderr, "plugin: in call_pre_tb_helper_code(), "
                    "pthread_mutex_lock() has failed: %s\n",
                    strerror(error));
            goto end;
        }
    }

    TCGPluginInterface *tpi = (TCGPluginInterface *)(intptr_t)tpi_ptr;
    if (tcg_plugin_initialize(tpi))
        TPI_CALLBACK_NOT_GENERIC(tpi, pre_tb_helper_code,
                                 *(TPIHelperInfo *)&info,
                                 address, data1, data2);
end:
    if (g_plugins_state.mutex_protected) {
        pthread_mutex_unlock(&g_plugins_state.helper_mutex);
    }
}

#if !defined(CONFIG_USER_ONLY)
const char *tcg_plugin_get_filename(void)
{
    return "<system>";
}
#else
extern const char *exec_path;
const char *tcg_plugin_get_filename(void)
{
    return exec_path;
}
#endif

/* Return true if at least one plugin was requested.  */
bool tcg_plugin_enabled(void)
{
    return g_plugins_state.tpi_list != NULL;
}

/* Hook called before the Intermediate Code Generation (ICG).  */
void tcg_plugin_cpus_stopped(void)
{
    GList *l;
    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next)
    {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (tcg_plugin_initialize(tpi))
            if (tpi->cpus_stopped)
                TPI_CALLBACK_NOT_GENERIC(tpi, cpus_stopped);
    }
}

/* Hook called before the Intermediate Code Generation (ICG).  */
void tcg_plugin_before_gen_tb(CPUState *env, TranslationBlock *tb)
{
    GList *l;
    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next)
    {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (tcg_plugin_initialize(tpi)) {
            tpi->_current_pc = tb->pc;
            tpi->_current_env = env;
            tpi->_current_tb = tb;
        }
    }
    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next)
    {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (tcg_plugin_initialize(tpi)) {
            tcg_plugin_tpi_before_gen_tb(tpi, env, tb);
        }
    }
}

/* Hook called after the Intermediate Code Generation (ICG).  */
void tcg_plugin_after_gen_tb(CPUState *env, TranslationBlock *tb)
{
    GList *l;
    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next)
    {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (tcg_plugin_initialize(tpi)) {
            tcg_plugin_tpi_after_gen_tb(tpi, env, tb);
        }
    }
    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next)
    {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (tcg_plugin_initialize(tpi)) {
            tpi->_current_pc = 0;
            tpi->_current_env = NULL;
            tpi->_current_tb = NULL;
        }
    }
}

/* Hook called each time a TCG opcode is generated.  */
void tcg_plugin_after_gen_opc(TCGOp *opcode, TCGArg *opargs, uint8_t nb_args)
{
    GList *l;
    for (l = g_plugins_state.tpi_list; l != NULL; l = l->next)
    {
        TCGPluginInterface *tpi = (TCGPluginInterface *)l->data;
        if (tcg_plugin_initialize(tpi))
            tcg_plugin_tpi_after_gen_opc(tpi, opcode, opargs, nb_args);
    }
}
