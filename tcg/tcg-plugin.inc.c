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

/*
 * Inline implementation of some of the plugin interfaces.
 * This file should be included at the end of tcg-plugin.h and
 * are considered private implementation from plugin interface
 * user perspective.
 */
#include <unistd.h>      /* syscall(2), getpid(3p)*/
#include <sys/syscall.h> /* SYS_gettid, */
#include <pthread.h>     /* pthread_*(3p), */

#ifdef CONFIG_USER_ONLY
#ifndef QEMU_H
/* Defined by linux_user/qemu.h. */
extern __thread CPUState *thread_cpu;
#endif
#endif

extern __thread uint32_t _tpi_thread_tid;

static inline FILE *tpi_output(const TCGPluginInterface *tpi)
{
    return tpi->output;
}

static inline uint32_t tpi_thread_pid(const TCGPluginInterface *tpi)
{
    (void)tpi;
    return (uint32_t)getpid();
}

static inline uint32_t tpi_thread_tid(const TCGPluginInterface *tpi)
{
    (void)tpi;
    if (_tpi_thread_tid == 0) _tpi_thread_tid = (uint32_t)syscall(SYS_gettid);
    return _tpi_thread_tid;
}

static inline uint64_t tpi_thread_self(const TCGPluginInterface *tpi)
{
    (void)tpi;
    return (uint64_t)pthread_self();
}

static inline TranslationBlock *tpi_current_tb(const TCGPluginInterface *tpi)
{
    (void)tpi;
    return (TranslationBlock *)tpi_current_cpu(tpi)->current_tb;
}

static inline uint64_t tpi_current_tb_address(const TCGPluginInterface *tpi)
{
    (void)tpi;
    return (uint64_t)tpi_current_cpu(tpi)->current_tb->pc;
}

static inline uint32_t tpi_current_tb_size(const TCGPluginInterface *tpi)
{
    (void)tpi;
    return (uint32_t)tpi_current_cpu(tpi)->current_tb->size;

}

static inline uint32_t tpi_current_tb_icount(const TCGPluginInterface *tpi)
{
    (void)tpi;
    return (uint32_t)tpi_current_cpu(tpi)->current_tb->icount;

}

static inline CPUState *tpi_current_cpu(const TCGPluginInterface *tpi)
{
    (void)tpi;
#ifdef CONFIG_USER_ONLY
    return thread_cpu;
#else
    return current_cpu;
#endif
}

static inline CPUArchState *tpi_current_cpu_arch(const TCGPluginInterface *tpi)
{
    (void)tpi;
    return tpi_current_cpu(tpi)->env_ptr;
}

static inline uint32_t tpi_current_cpu_index(const TCGPluginInterface *tpi)
{
    (void)tpi;
    return (uint32_t)tpi_current_cpu(tpi)->cpu_index;
}

static inline uint32_t tpi_nb_cpus(const TCGPluginInterface *tpi)
{
    return (uint32_t)tpi->nb_cpus;
}

static inline uint64_t tpi_guest_ptr(const TCGPluginInterface *tpi, uint64_t guest_address)
{
#ifdef CONFIG_USER_ONLY
    (void)tpi;
    return guest_address + guest_base;
#else
    (void)tpi;
    fprintf(stderr, "qemu: tpi_guest_ptr: fatal error: not implemented in system mode\n");
    abort();
#endif
}

static inline uint64_t tpi_guest_load64(const TCGPluginInterface *tpi, uint64_t guest_address)
{
#ifdef CONFIG_USER_ONLY
    union { uint64_t v; struct { char bytes[8]; } b; } val;
    (void)tpi;
    /* TODO: manage incompatible endianess. */
    val.b = *(__typeof(val.b) *)(guest_address + guest_base);
    return val.v;
#else
    (void)tpi;
    fprintf(stderr, "qemu: tpi_guest_load64: fatal error: not implemented in system mode\n");
    abort();
#endif
}

static inline uint32_t tpi_guest_load32(const TCGPluginInterface *tpi, uint64_t guest_address)
{
#ifdef CONFIG_USER_ONLY
    union { uint32_t v; struct { char bytes[4]; } b; } val;
    (void)tpi;
    /* TODO: manage incompatible endianess. */
    val.b = *(__typeof(val.b) *)(guest_address + guest_base);
    return val.v;
#else
    (void)tpi;
    fprintf(stderr, "qemu: tpi_guest_load32: fatal error: not implemented in system mode\n");
    abort();
#endif
}
