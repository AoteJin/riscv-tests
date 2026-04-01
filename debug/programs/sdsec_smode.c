#include <stdint.h>
#include "init.h"
#include "encoding.h"

volatile int smode_counter = 0;
volatile int in_smode = 0;
volatile int trap_handler_entered = 0;
volatile int after_ecall = 0;

__asm__(
    ".section .text\n"
    ".global m_trap_handler\n"
    ".align 2\n"
    "m_trap_handler:\n"
    "  addi sp, sp, -16\n"
    "  sd t0, 0(sp)\n"
    "  sd t1, 8(sp)\n"
    "  la t0, trap_handler_entered\n"
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

void __attribute__((noreturn)) smode_entry(void);
void smode_entry(void) {
    in_smode = 1;
    asm volatile(
        ".global do_ecall\n"
        "do_ecall:\n"
        "ecall\n"
        ::: "memory"
    );
    after_ecall = 1;
    while (1) {
        smode_counter++;
    }
}

int main(void) {
    extern void m_trap_handler(void);
    write_csr(mtvec, (unsigned long)m_trap_handler & ~3UL);

    write_csr(pmpaddr0, -1UL);
    write_csr(pmpcfg0, 0x1f);

    write_csr(mepc, (unsigned long)smode_entry);

    unsigned long ms = read_csr(mstatus);
    ms &= ~MSTATUS_MPP;
    ms |= (1UL << 11);
    write_csr(mstatus, ms);

    asm volatile("mret");
    __builtin_unreachable();
}
