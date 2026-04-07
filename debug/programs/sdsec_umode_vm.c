/*
 * sdsec_umode_vm.c -- U-mode bootstrap with Sv48 identity-mapped page tables.
 *
 * Flow:
 *   M-mode: set up PMP, build Sv48 page tables (VA == PA, without PTE_U),
 *           activate satp (Sv48), mret into S-mode.
 *   S-mode: runs on non-PTE_U pages (S-mode can execute normally),
 *           does ecall to trap back to M-mode.
 *   M-mode trap handler: adds PTE_U to the page table entry, sfence.vma,
 *           sets mepc=umode_entry, MPP=U-mode, mrets directly to U-mode.
 *   U-mode: spin in a loop with satp (Sv48) active and PTE_U pages.
 *
 * Why the ecall-to-M trick:
 *   U-mode needs PTE_U=1 to access pages.  But S-mode cannot execute from
 *   PTE_U=1 pages (RISC-V spec forbids S-mode instruction fetch from U-pages).
 *   So the page table starts without PTE_U (S-mode can execute), then S-mode
 *   ecalls to M-mode which adds PTE_U and mrets directly to U-mode -- never
 *   executing another S-mode instruction on the now-PTE_U pages.
 *
 * The debugger halts the hart while it is in U-mode with address translation
 * enabled (satp=Sv48, PTE_U set). This lets us probe whether OpenOCD can
 * perform VA-based memory access through the sdsec debug path at U-mode
 * privilege.
 *
 * Based on sdsec_umode.c (M->S->U privilege drop) and sdsec_smode_vm.c
 * (Sv48 identity-mapped page tables).
 *
 * Why Sv48 instead of Sv39:
 *   hart.ram = 0x1212340000 is a 41-bit physical address. Sv39 only supports
 *   39-bit virtual addresses, so an identity map (VA == PA) is impossible.
 *   Sv48 supports 48-bit VAs, which is sufficient for identity-mapping.
 */

#include <stdint.h>
#include "init.h"
#include "encoding.h"

/* ---- Constants --------------------------------------------------------- */

#define PAGE_SIZE       4096

/* S-mode page flags (no PTE_U): used during M->S transition. */
#define PTE_FLAGS_S     (PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D)

/*
 * Sv48: 4-level page table.
 *   VPN[3] = bits 47:39   (level-3 root, each entry covers 512 GiB)
 *
 * We use a single level-3 superpage entry for the identity map.
 * Entry 0 maps PA 0..0x7FFFFFFFFF (512 GiB), covering hart.ram.
 *
 * hart.ram = 0x1212340000 (~72 GiB).  VPN[3] = 0x1212340000 >> 39 = 0.
 * So root_page_table[0] covers the entire hart.ram region.
 *
 * Higher VPN[3] entries are left unmapped so tests can verify that
 * accesses to unmapped VAs fail properly.
 */

/* 4 KiB-aligned root page table (must be page-aligned).
 * Not static: the M-mode assembly trap handler references it by name. */
uint64_t root_page_table[512]
    __attribute__((aligned(PAGE_SIZE)));

volatile int in_umode = 0;
volatile int vm_active = 0;
volatile int umode_counter = 0;
volatile int smode_ecall_done = 0;

/* Expose hart.ram VA for the test to probe. Identity-mapped, so VA == PA. */
volatile unsigned long probe_va = 0x1212340000UL;

/* ---- U-mode entry point ------------------------------------------------ */

void __attribute__((noreturn)) umode_entry(void);
void umode_entry(void) {
    in_umode = 1;
    while (1) {
        umode_counter++;
    }
}

/* ---- S-mode trap handler (for U-mode ecalls) --------------------------- */

__asm__(
    ".section .text\n"
    ".global s_trap_handler\n"
    ".align 2\n"
    "s_trap_handler:\n"
    "  csrr t0, sepc\n"
    "  addi t0, t0, 4\n"
    "  csrw sepc, t0\n"
    "  sret\n"
);

/* ---- M-mode trap handler ----------------------------------------------- */
/*
 * Handles two cases:
 *   1. ecall from S-mode (cause 9): S-mode has finished setup and is ready
 *      to drop to U-mode.  Add PTE_U to the page table, sfence.vma,
 *      set mepc=umode_entry, MPP=U-mode, and mret to U-mode.
 *   2. Other traps: advance mepc by 4 and return.
 */
__asm__(
    ".section .text\n"
    ".global m_trap_handler\n"
    ".align 2\n"
    "m_trap_handler:\n"
    "  csrr t0, mcause\n"
    /* Check for ecall-from-S (cause 9) */
    "  li t1, 9\n"
    "  bne t0, t1, .Ldefault_trap\n"
    "\n"
    "  /* ecall from S-mode: time to add PTE_U and drop to U-mode */\n"
    "  la t0, root_page_table\n"
    "  ld t1, 0(t0)\n"
    "  ori t1, t1, 0x10\n"       /* PTE_U = 0x010 */
    "  sd t1, 0(t0)\n"
    "  sfence.vma\n"
    "\n"
    "  /* Set vm_active flag */\n"
    "  la t0, vm_active\n"
    "  li t1, 1\n"
    "  sw t1, 0(t0)\n"
    "\n"
    "  /* Set mepc = umode_entry */\n"
    "  la t0, umode_entry\n"
    "  csrw mepc, t0\n"
    "\n"
    "  /* Set MPP = U-mode (0): clear bits 12:11 of mstatus */\n"
    "  li t0, 0x1800\n"
    "  csrc mstatus, t0\n"
    "\n"
    "  /* Set up stvec for U-mode traps (delegated ecalls) */\n"
    "  la t0, s_trap_handler\n"
    "  csrw stvec, t0\n"
    "\n"
    "  mret\n"
    "\n"
    ".Ldefault_trap:\n"
    "  csrr t0, mepc\n"
    "  addi t0, t0, 4\n"
    "  csrw mepc, t0\n"
    "  mret\n"
);

/* ---- S-mode setup: run with satp active, then ecall to M for U drop ---- */

void __attribute__((noreturn)) smode_setup(void);
void smode_setup(void) {
    /* S-mode is running with Sv48 active but WITHOUT PTE_U.
     * We've done all the setup we need. Now ecall to M-mode so it can
     * add PTE_U and mret directly to U-mode. */
    smode_ecall_done = 1;
    __asm__ __volatile__("ecall" ::: "memory");
    /* Should never reach here -- M-mode handler mrets to U-mode. */
    __builtin_unreachable();
}

/* ---- Page table setup & drop to S-mode --------------------------------- */

int main(void) {
    extern void m_trap_handler(void);
    write_csr(mtvec, (unsigned long)m_trap_handler & ~3UL);

    /* Do NOT delegate ecall-from-S -- we need it in M-mode to handle
     * the PTE_U addition and U-mode drop. */

    /* Open PMP wide: NAPOT covering the entire address space, RWX. */
    write_csr(pmpaddr0, -1UL);
    write_csr(pmpcfg0, 0x1f);   /* NAPOT | R | W | X */

    /*
     * Build Sv48 root page table with a 512-GiB identity-mapped superpage.
     *
     * A level-3 leaf PTE maps 2^39 bytes (512 GiB).
     * Identity map: entry 0 maps PA 0..0x7FFFFFFFFF.
     *   PTE field = (0 << 37) | flags = just flags.
     *
     * Initially WITHOUT PTE_U so S-mode can execute from these pages.
     * M-mode trap handler adds PTE_U before mret to U-mode.
     */
    root_page_table[0] = ((uint64_t)0 << 37) | PTE_FLAGS_S;

    /* sfence before switching address translation. */
    __asm__ __volatile__("sfence.vma" ::: "memory");

    /* Program satp: mode=Sv48 (9), PPN = root_page_table >> 12. */
    unsigned long satp_val = ((unsigned long)SATP_MODE_SV48 << 60) |
                             (((unsigned long)root_page_table) >> 12);
    write_csr(satp, satp_val);

    /* Verify satp took effect. */
    unsigned long satp_rb = read_csr(satp);
    if ((satp_rb >> 60) != SATP_MODE_SV48) {
        /* satp mode didn't stick -- spin (error). */
        while (1)
            ;
    }

    /* Drop to S-mode via mret. Translation active, no PTE_U, so S-mode
     * instruction fetch works. S-mode will ecall back to M-mode when ready. */
    write_csr(mepc, (unsigned long)smode_setup);

    unsigned long ms = read_csr(mstatus);
    ms &= ~MSTATUS_MPP;
    ms |= (1UL << 11);   /* MPP = S-mode (1) */
    write_csr(mstatus, ms);

    __asm__ __volatile__("mret");
    __builtin_unreachable();
}
