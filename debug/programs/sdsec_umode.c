#include <stdint.h>
#include "init.h"
#include "encoding.h"

volatile int umode_counter = 0;
volatile int in_umode = 0;
volatile int m_trap_entered = 0;
volatile int s_trap_entered = 0;
volatile int after_ecall = 0;
volatile int after_ebreak = 0;

/*
 * M-mode trap handler: handles ebreak (exception 3) from U-mode.
 * Advances mepc past the faulting instruction and returns.
 */
__asm__(
    ".section .text\n"
    ".global m_trap_handler\n"
    ".align 2\n"
    "m_trap_handler:\n"
    "  addi sp, sp, -16\n"
    "  sd t0, 0(sp)\n"
    "  sd t1, 8(sp)\n"
    "  la t0, m_trap_entered\n"
    "  li t1, 1\n"
    "  sw t1, 0(t0)\n"
    "  csrr t0, mepc\n"
    "  addi t0, t0, 4\n"
    "  csrw mepc, t0\n"
    "  ld t0, 0(sp)\n"
    "  ld t1, 8(sp)\n"
    "  addi sp, sp, 16\n"
    "  mret\n"
);

/*
 * S-mode trap handler: handles ecall-from-U (exception 8).
 * Advances sepc past the ecall and returns to U-mode.
 */
__asm__(
    ".section .text\n"
    ".global s_trap_handler\n"
    ".align 2\n"
    "s_trap_handler:\n"
    "  addi sp, sp, -16\n"
    "  sd t0, 0(sp)\n"
    "  sd t1, 8(sp)\n"
    "  la t0, s_trap_entered\n"
    "  li t1, 1\n"
    "  sw t1, 0(t0)\n"
    "  csrr t0, sepc\n"
    "  addi t0, t0, 4\n"
    "  csrw sepc, t0\n"
    "  ld t0, 0(sp)\n"
    "  ld t1, 8(sp)\n"
    "  addi sp, sp, 16\n"
    "  sret\n"
);

void __attribute__((noreturn)) umode_entry(void);
void __attribute__((noreturn)) smode_setup(void);

void umode_entry(void) {
    in_umode = 1;
    asm volatile(
        ".global do_ecall\n"
        "do_ecall:\n"
        "ecall\n"
        ::: "memory"
    );
    after_ecall = 1;
    asm volatile(
        ".global do_ebreak\n"
        "do_ebreak:\n"
        "ebreak\n"
        ::: "memory"
    );
    after_ebreak = 1;
    while (1) {
        umode_counter++;
    }
}

void smode_setup(void) {
    extern void s_trap_handler(void);
    write_csr(stvec, (unsigned long)s_trap_handler & ~3UL);

    write_csr(sepc, (unsigned long)umode_entry);
    unsigned long ss = read_csr(sstatus);
    ss &= ~SSTATUS_SPP;
    write_csr(sstatus, ss);

    asm volatile("sret");
    __builtin_unreachable();
}

int main(void) {
    extern void m_trap_handler(void);
    write_csr(mtvec, (unsigned long)m_trap_handler & ~3UL);

    /* Delegate ecall-from-U (bit 8) to S-mode; ebreak (bit 3) stays in M. */
    write_csr(medeleg, 1UL << 8);

    write_csr(pmpaddr0, -1UL);
    write_csr(pmpcfg0, 0x1f);

    write_csr(mepc, (unsigned long)smode_setup);

    unsigned long ms = read_csr(mstatus);
    ms &= ~MSTATUS_MPP;
    ms |= (1UL << 11);
    write_csr(mstatus, ms);

    asm volatile("mret");
    __builtin_unreachable();
}
