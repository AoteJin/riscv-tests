/*
 * sdsec_umode_vm.c -- U-mode bootstrap with Sv48 translation constraints.
 *
 * Flow:
 *   M-mode: set up PMP, build Sv48 page tables, activate satp (Sv48), then
 *           mret directly into U-mode.
 *   U-mode: spin in a loop with satp active.
 *
 * The page tables provide three distinct VA outcomes for the debugger:
 *   1. A U-accessible mapped VA, backed by the program RAM region.
 *   2. A mapped supervisor-only VA, backed by a real page but with PTE_U=0.
 *   3. An unmapped VA.
 *
 * The debugger halts the hart while it is in U-mode with address translation
 * enabled. This lets us probe whether OpenOCD performs VA-based memory access
 * through the sdsec debug path at U-mode privilege, including PTE_U checks.
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

#define PTE_FLAGS_SUPER (PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D)
#define PTE_FLAGS_USER  (PTE_FLAGS_SUPER | PTE_U)
#define VPN_MASK        0x1ffUL

/*
 * Chosen in VPN[3]=0 but outside the program's 1-GiB identity region.
 * It is mapped to supervisor_only_page with PTE_U=0.
 */
#define SUPERVISOR_ONLY_TEST_VA 0x1240000000UL
#define UNMAPPED_TEST_VA        0x0000008000000000UL

/*
 * Sv48: 4-level page table.
 *   VPN[3] = bits 47:39   (level-3 root, each entry covers 512 GiB)
 *
 * root[0] points to an L2 table.  That L2 table contains:
 *   - one 1-GiB U-accessible identity leaf for the program RAM region
 *   - one pointer to a 4-KiB supervisor-only leaf at SUPERVISOR_ONLY_TEST_VA
 *
 * root[1] and the rest of the tree are invalid, so UNMAPPED_TEST_VA fails at
 * translation time.
 */

static uint64_t root_page_table[512]
    __attribute__((aligned(PAGE_SIZE)));
static uint64_t l2_page_table[512]
    __attribute__((aligned(PAGE_SIZE)));
static uint64_t supervisor_l1_page_table[512]
    __attribute__((aligned(PAGE_SIZE)));
static uint64_t supervisor_l0_page_table[512]
    __attribute__((aligned(PAGE_SIZE)));

static uint8_t user_probe_page[PAGE_SIZE]
    __attribute__((aligned(PAGE_SIZE)));
static uint8_t supervisor_only_page[PAGE_SIZE]
    __attribute__((aligned(PAGE_SIZE)));

volatile int in_umode = 0;
volatile int vm_active = 0;
volatile int umode_counter = 0;

volatile unsigned long probe_va = 0;
volatile unsigned long supervisor_only_va = SUPERVISOR_ONLY_TEST_VA;
volatile unsigned long unmapped_va = UNMAPPED_TEST_VA;
volatile unsigned long user_region_pte_snapshot = 0;
volatile unsigned long supervisor_only_pte_snapshot = 0;

/* ---- U-mode entry point ------------------------------------------------ */

void __attribute__((noreturn)) umode_entry(void);
void umode_entry(void) {
    in_umode = 1;
    while (1) {
        umode_counter++;
    }
}

/* ---- M-mode trap handler ----------------------------------------------- */
__asm__(
    ".section .text\n"
    ".global m_trap_handler\n"
    ".align 2\n"
    "m_trap_handler:\n"
    "  j m_trap_handler\n"
);

/* ---- Page-table helpers ------------------------------------------------- */

static uint64_t pte_from_pa(uint64_t pa, uint64_t flags) {
    return ((pa >> 12) << PTE_PPN_SHIFT) | flags;
}

static unsigned long vpn2(unsigned long va) {
    return (va >> 30) & VPN_MASK;
}

static unsigned long vpn1(unsigned long va) {
    return (va >> 21) & VPN_MASK;
}

static unsigned long vpn0(unsigned long va) {
    return (va >> 12) & VPN_MASK;
}

/* ---- Page table setup & drop to U-mode --------------------------------- */

int main(void) {
    extern void m_trap_handler(void);
    write_csr(mtvec, (unsigned long)m_trap_handler & ~3UL);

    /* Open PMP wide: NAPOT covering the entire address space, RWX. */
    write_csr(pmpaddr0, -1UL);
    write_csr(pmpcfg0, 0x1f);   /* NAPOT | R | W | X */

    probe_va = (unsigned long)user_probe_page;

    unsigned long user_vpn2 = vpn2(probe_va);
    unsigned long user_1g_base = user_vpn2 << 30;

    root_page_table[0] = pte_from_pa((uint64_t)l2_page_table, PTE_V);

    /* U-accessible 1-GiB identity mapping covering code, data, and stack. */
    l2_page_table[user_vpn2] =
        pte_from_pa(user_1g_base, PTE_FLAGS_USER);

    /* Supervisor-only 4-KiB alias backed by a real page. */
    unsigned long sup_va = SUPERVISOR_ONLY_TEST_VA;
    l2_page_table[vpn2(sup_va)] =
        pte_from_pa((uint64_t)supervisor_l1_page_table, PTE_V);
    supervisor_l1_page_table[vpn1(sup_va)] =
        pte_from_pa((uint64_t)supervisor_l0_page_table, PTE_V);
    supervisor_l0_page_table[vpn0(sup_va)] =
        pte_from_pa((uint64_t)supervisor_only_page, PTE_FLAGS_SUPER);

    user_region_pte_snapshot = l2_page_table[user_vpn2];
    supervisor_only_pte_snapshot = supervisor_l0_page_table[vpn0(sup_va)];

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

    __asm__ __volatile__("sfence.vma" ::: "memory");
    vm_active = 1;

    /* Drop directly to U-mode via mret. */
    write_csr(mepc, (unsigned long)umode_entry);

    unsigned long ms = read_csr(mstatus);
    ms &= ~MSTATUS_MPP;  /* MPP = U-mode (0) */
    write_csr(mstatus, ms);

    __asm__ __volatile__("mret");
    __builtin_unreachable();
}
