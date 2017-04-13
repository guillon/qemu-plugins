#ifndef QEMU_DISAS_H
#define QEMU_DISAS_H

#include "qemu-common.h"

#ifdef NEED_CPU_H
#include "cpu.h"

/* Disassemble this for me please... (debugging). */
void disas(FILE *out, void *code, unsigned long size);
void target_disas(FILE *out, CPUState *cpu, target_ulong code,
                  target_ulong size, int flags);

void monitor_disas(Monitor *mon, CPUState *cpu,
                   target_ulong pc, int nb_insn, int is_physical, int flags);

/* Look up symbol for debugging purpose.  Returns "" if unknown. */
const char *lookup_symbol(target_ulong orig_addr);
bool lookup_symbol2(target_ulong orig_addr, const char **symbol, const char **filename);
bool lookup_symbol3(target_ulong orig_addr, const char **symbol, const char **filename, uint64_t *address);
#endif

struct syminfo;
struct elf32_sym;
struct elf64_sym;

#if defined(CONFIG_USER_ONLY)
typedef const char *(*lookup_symbol_t)(struct syminfo *s, target_ulong orig_addr, target_ulong *symbol_addr);
#else
typedef const char *(*lookup_symbol_t)(struct syminfo *s, hwaddr orig_addr, hwaddr *symbol_addr);
#endif

struct syminfo {
    lookup_symbol_t lookup_symbol;
    unsigned int disas_num_syms;
    union {
      struct elf32_sym *elf32;
      struct elf64_sym *elf64;
    } disas_symtab;
    const char *disas_strtab;
    const char *filename;
    struct syminfo *next;
};

/* Filled in by elfload.c.  Simplistic, but will do for now. */
extern struct syminfo *syminfos;
extern uint64_t find_symbol(const char *name, int is_elf_class64);
extern uint64_t exit_code;
extern uint64_t exit_addr;

#endif /* QEMU_DISAS_H */
