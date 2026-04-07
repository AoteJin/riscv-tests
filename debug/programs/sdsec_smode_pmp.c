#include <stdint.h>
#include "init.h"
#include "encoding.h"

/*
 * S-mode bootstrap with a PMP "deny hole".
 *
 * PMP layout (checked in entry order):
 *   Entry 0 — NAPOT 4 KB at PMP_DENIED_BASE, Locked, no perms  → deny region
 *   Entry 1 — NAPOT full address space, RWX                     → allow everything else
 *
 * After configuring PMP, drops to S-mode at smode_entry.
 */

#define PMP_DENIED_BASE  0x1212344000UL   /* hart.ram + 0x4000 */
#define PMP_DENIED_SIZE  4096UL           /* 4 KB */

volatile int smode_counter = 0;
volatile int in_smode = 0;
volatile int trap_handler_entered = 0;
volatile int after_ecall = 0;

/* Address exported for the test harness to read. */
volatile unsigned long pmp_denied_addr = PMP_DENIED_BASE;

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

/*
 * NAPOT pmpaddr encoding for a region of size 2^k at aligned base:
 *   pmpaddr = (base >> 2) | ((size/2 - 1) >> 2)
 * which equals  (base >> 2) | (2^(k-1) - 1) >> 2  ... but the simpler
 * form used in the priv spec:
 *   pmpaddr[y-1:0] = all 1s, where 2^(y+3) = size  →  y = k - 3
 *   pmpaddr[63:y]  = base[63:y+2]  (i.e. base >> 2 with low y bits set)
 *
 * For 4 KB (k=12): y = 9, so low 9 bits of pmpaddr = 0x1FF.
 */
static inline unsigned long napot_pmpaddr(unsigned long base, unsigned long size)
{
    /* y = __builtin_ctzl(size) - 3 ; mask = (1 << y) - 1 */
    unsigned long y = __builtin_ctzl(size) - 3;
    unsigned long mask = (1UL << y) - 1;
    return (base >> 2) | mask;
}

int main(void) {
    extern void m_trap_handler(void);
    write_csr(mtvec, (unsigned long)m_trap_handler & ~3UL);

    /*
     * PMP entry 0: deny 4 KB at PMP_DENIED_BASE (Locked, NAPOT, no perms).
     * pmpcfg byte: L=1 (bit 7) | A=NAPOT (bits 4:3 = 11) | R=0 W=0 X=0 = 0x98
     */
    write_csr(pmpaddr0, napot_pmpaddr(PMP_DENIED_BASE, PMP_DENIED_SIZE));

    /*
     * PMP entry 1: allow-all (NAPOT full range, RWX).
     * pmpcfg byte: L=0 | A=NAPOT (0x18) | R|W|X (0x07) = 0x1F
     */
    write_csr(pmpaddr1, -1UL);

    /*
     * pmpcfg0 on RV64 packs entries 0-7 in bytes 0-7.
     * Entry 0 = byte 0 = 0x98,  Entry 1 = byte 1 = 0x1F.
     */
    write_csr(pmpcfg0, (0x1FUL << 8) | 0x98UL);

    /* Drop to S-mode. */
    write_csr(mepc, (unsigned long)smode_entry);

    unsigned long ms = read_csr(mstatus);
    ms &= ~MSTATUS_MPP;
    ms |= (1UL << 11);   /* MPP = 01 (S-mode) */
    write_csr(mstatus, ms);

    asm volatile("mret");
    __builtin_unreachable();
}
