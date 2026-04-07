/*
 * sdsec_smode_vm.c -- S-mode bootstrap with Sv48 identity-mapped page tables.
 *
 * Flow:
 *   M-mode: set up PMP, build Sv48 page tables (VA == PA for hart.ram region),
 *           write satp, then mret into S-mode.
 *   S-mode: spin in a loop with satp (Sv48) active.
 *
 * The debugger halts the hart while it is in S-mode with address translation
 * enabled. This lets us probe whether OpenOCD can perform VA-based memory
 * access through the sdsec debug path.
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
/* S-mode pages: do NOT set PTE_U.  With PTE_U=1 the pages belong to U-mode
 * and S-mode instruction fetch would fault immediately, creating an infinite
 * M-mode trap loop that blocks halting under S-mode-only debug policy. */
#define PTE_FLAGS       (PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D)

/*
 * Sv48: 4-level page table.
 *   VPN[3] = bits 47:39   (level-3 root, each entry covers 512 GiB)
 *   VPN[2] = bits 38:30   (level-2, each entry covers 1 GiB)
 *   VPN[1] = bits 29:21   (level-1, each entry covers 2 MiB)
 *   VPN[0] = bits 20:12   (level-0, each entry covers 4 KiB)
 *
 * We use level-3 superpage entries (512 GiB each) for the identity map.
 * Each level-3 leaf PTE maps 2^39 bytes.  For the identity map we need
 * PTE.ppn to encode PA = (index << 39).
 *
 * hart.ram = 0x1212340000 (~72 GiB).  VPN[3] = 0x1212340000 >> 39 = 0.
 * So root_page_table[0] is a 512-GiB superpage covering PA 0..0x7FFFFFFFFF,
 * which includes the entire hart.ram region.
 *
 * We map only entry 0 (VPN[3]=0) which covers PA 0..0x7FFFFFFFFF.
 * Higher VPN[3] entries are left unmapped so tests can verify that
 * accesses to unmapped VAs fail properly.
 */

/* 4 KiB-aligned root page table (must be page-aligned). */
static uint64_t root_page_table[512]
    __attribute__((aligned(PAGE_SIZE)));

volatile int in_smode = 0;
volatile int vm_active = 0;
volatile int smode_counter = 0;

/* Expose hart.ram VA for the test to probe. Identity-mapped, so VA == PA. */
volatile unsigned long probe_va = 0x1212340000UL;

/* ---- M-mode trap handler ----------------------------------------------- */

__asm__(
    ".section .text\n"
    ".global m_trap_handler\n"
    ".align 2\n"
    "m_trap_handler:\n"
    "  csrr t0, mepc\n"
    "  addi t0, t0, 4\n"
    "  csrw mepc, t0\n"
    "  mret\n"
);

/* ---- S-mode entry point ------------------------------------------------ */

void __attribute__((noreturn)) smode_entry(void);
void smode_entry(void) {
    in_smode = 1;
    while (1) {
        smode_counter++;
    }
}

/* ---- Page table setup & drop to S-mode --------------------------------- */

int main(void) {
    extern void m_trap_handler(void);
    write_csr(mtvec, (unsigned long)m_trap_handler & ~3UL);

    /* Open PMP wide: NAPOT covering the entire address space, RWX. */
    write_csr(pmpaddr0, -1UL);
    write_csr(pmpcfg0, 0x1f);   /* NAPOT | R | W | X */

    /*
     * Build Sv48 root page table with 512-GiB identity-mapped superpages.
     *
     * A level-3 leaf PTE maps 2^39 bytes (512 GiB).
     * For a superpage at level L, ppn[L-1:0] must be zero.
     * For level-3: ppn[2:0] must all be zero; only ppn[3] matters.
     *
     * Identity map: PA = (index << 39).
     *   PTE.ppn   = PA >> 12 = index << 27
     *   PTE field = (PTE.ppn << PTE_PPN_SHIFT) | flags
     *             = (index << 27) << 10 | flags
     *             = (index << 37) | flags
     *
     * PTE bit layout for Sv48 level-3 superpage:
     *   [63:54] = reserved (0)
     *   [53:37] = ppn[3] (17 bits)  <-- encodes index
     *   [36:28] = ppn[2] (9 bits)   <-- must be 0 for superpage
     *   [27:19] = ppn[1] (9 bits)   <-- must be 0 for superpage
     *   [18:10] = ppn[0] (9 bits)   <-- must be 0 for superpage
     *   [ 9: 0] = flags
     */
    /* Map only entry 0: covers PA 0..0x7FFFFFFFFF (512 GiB).
     * hart.ram = 0x1212340000 falls within this range.
     * Leave all other entries unmapped (zero = invalid). */
    root_page_table[0] = ((uint64_t)0 << 37) | PTE_FLAGS;

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

    /* Mark VM as active before entering S-mode so the debugger always
     * sees it after halting, regardless of halt timing. */
    vm_active = 1;

    /* Drop to S-mode via mret. */
    write_csr(mepc, (unsigned long)smode_entry);

    unsigned long ms = read_csr(mstatus);
    ms &= ~MSTATUS_MPP;
    ms |= (1UL << 11);   /* MPP = S-mode (1) */
    write_csr(mstatus, ms);

    __asm__ __volatile__("mret");
    __builtin_unreachable();
}
