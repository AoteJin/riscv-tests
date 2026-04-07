/*
 * sdsec_vsmode_vm.c -- VS-mode bootstrap with two-stage address translation.
 *
 * Flow:
 *   M-mode:  configure PMP, mret to HS-mode.
 *   HS-mode: build Sv48 guest page tables (for vsatp, stage 1),
 *            build Sv48x4 host page tables (for hgatp, stage 2),
 *            program vsatp and hgatp, then sret to VS-mode.
 *   VS-mode: spin in a loop with two-stage translation active.
 *
 * Two-stage address translation:
 *   Stage 1 (vsatp):  guest VA  -> guest PA   (Sv48, 512 entries at root)
 *   Stage 2 (hgatp):  guest PA  -> host PA    (Sv48x4, 2048 entries at root)
 *
 * Both stages use identity mapping (VA == GPA == HPA == actual PA).
 * Only entry 0 of each root table is populated, covering PA 0..512 GiB.
 * hart.ram = 0x1212340000 (~72 GiB) falls within this range.
 *
 * Why Sv48 / Sv48x4:
 *   hart.ram = 0x1212340000 is a 41-bit physical address.  Sv39 only supports
 *   39-bit virtual addresses, so an identity map is impossible.  Sv48 supports
 *   48-bit VAs and Sv48x4 supports 50-bit GPAs, both sufficient.
 */

#include <stdint.h>
#include "init.h"
#include "encoding.h"

/* ---- Constants --------------------------------------------------------- */

#define PAGE_SIZE       4096
/* VS-mode pages: do NOT set PTE_U.  With PTE_U=1 the pages belong to VU-mode
 * and VS-mode instruction fetch would fault. */
#define PTE_FLAGS       (PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D)

/* vsatp CSR number (not in all encoding.h versions as a macro usable with
 * write_csr, so we use inline asm with the numeric address). */
#define CSR_VSATP_NUM   0x280
#define CSR_HGATP_NUM   0x680

/* Sv48x4 root page table: 2048 entries (16 KiB, aligned to 16 KiB).
 * Regular Sv48 root: 512 entries (4 KiB, aligned to 4 KiB). */
#define HGATP_ROOT_ENTRIES  2048
#define VSATP_ROOT_ENTRIES  512

/* ---- Page tables ------------------------------------------------------- */

/* Place page tables at fixed offsets within hart.ram to avoid large BSS
 * arrays.  init.c's BSS-zeroing loop is byte-by-byte and takes minutes
 * through the debug interface for 20 KiB arrays.  Instead we place tables
 * at high offsets in RAM (far from code/stack) and zero only what we use.
 *
 * hart.ram = 0x1212340000, ram_size = 0x10000000 (256 MiB).
 * vsatp root (4 KiB):  ram + 0x0E00_0000  (at 0x1220340000)
 * hgatp root (16 KiB): ram + 0x0E00_4000  (at 0x1220344000, 16 KiB aligned)
 * ram_size = 0x10000000 (256 MiB), so max valid = ram + 0x0FFF_FFFF.
 */
#define HART_RAM        0x1212340000UL
#define VSATP_ROOT_PA   (HART_RAM + 0x0E000000UL)
#define HGATP_ROOT_PA   (HART_RAM + 0x0E004000UL)

/* ---- Program state flags ----------------------------------------------- */

volatile int in_hsmode = 0;
volatile int in_vsmode = 0;
volatile int vm_active = 0;
volatile int vsmode_counter = 0;

/* Expose hart.ram VA for the test to probe.  Identity-mapped: VA == PA. */
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

/* ---- VS-mode entry point (reached via sret from HS-mode) --------------- */

static void __attribute__((noreturn, section(".text"))) vsmode_entry(void);
static void vsmode_entry(void) {
    in_vsmode = 1;
    while (1) {
        vsmode_counter++;
    }
}

/* ---- HS-mode: build page tables and enter VS-mode ---------------------- */

static void __attribute__((noreturn, section(".text"))) hsmode_setup(void);
static void hsmode_setup(void) {
    in_hsmode = 1;

    /*
     * Build stage-1 page table (vsatp / Sv48).
     *
     * Level-3 leaf PTE: maps 2^39 bytes (512 GiB).
     * Identity map: entry i maps VA [i*512GiB .. (i+1)*512GiB) to PA = VA.
     *   PTE.ppn = PA >> 12 = (i << 39) >> 12 = i << 27
     *   PTE field = (PTE.ppn << PTE_PPN_SHIFT) | flags = (i << 37) | flags
     *
     * Map only entry 0: covers PA 0..0x7FFFFFFFFF (512 GiB).
     * hart.ram = 0x1212340000 falls within this range.
     */
    /* Zero the page table regions (only entry 0 is used, but clear
     * a few entries to ensure PTE_V=0 for invalid slots). */
    volatile uint64_t *vsatp_pt = (volatile uint64_t *)VSATP_ROOT_PA;
    volatile uint64_t *hgatp_pt = (volatile uint64_t *)HGATP_ROOT_PA;
    for (int i = 0; i < 4; i++) {
        vsatp_pt[i] = 0;
        hgatp_pt[i] = 0;
    }

    vsatp_pt[0] = ((uint64_t)0 << 37) | PTE_FLAGS;

    /*
     * Build stage-2 page table (hgatp / Sv48x4).
     *
     * Same PTE format as Sv48; root table just has 2048 entries instead of 512.
     * Level-3 leaf PTE maps 2^39 bytes (512 GiB) of guest physical space to
     * the same host physical address (identity map).
     *
     * Map only entry 0: covers GPA 0..0x7FFFFFFFFF -> HPA 0..0x7FFFFFFFFF.
     */
    hgatp_pt[0] = ((uint64_t)0 << 37) | PTE_FLAGS;

    /* Fence before programming address-translation CSRs. */
    __asm__ __volatile__("sfence.vma" ::: "memory");

    /* Program vsatp: mode=Sv48 (9), PPN = vsatp_root >> 12.
     * vsatp (CSR 0x280) is only writable from HS-mode (or M-mode). */
    {
        unsigned long val = ((unsigned long)SATP_MODE_SV48 << 60) |
                            (VSATP_ROOT_PA >> 12);
        __asm__ __volatile__("csrw 0x280, %0" :: "r"(val));
    }

    /* Program hgatp: mode=Sv48x4 (9), PPN = HGATP_ROOT_PA >> 12.
     * hgatp (CSR 0x680) is only writable from HS-mode (or M-mode). */
    {
        unsigned long val = ((unsigned long)9UL << 60) |
                            (HGATP_ROOT_PA >> 12);
        __asm__ __volatile__("csrw 0x680, %0" :: "r"(val));
    }

    /* Synchronize stage-2 translation changes.
     * hfence.gvma is the targeted fence, but it requires the H extension in
     * -march which the test harness compile() does not add.  sfence.vma with
     * no arguments flushes all address-translation caches (including G-stage)
     * and is always available from HS-mode. */
    __asm__ __volatile__("sfence.vma" ::: "memory");

    /* Mark VM as active before entering VS-mode so the debugger always
     * sees it after halting, regardless of halt timing. */
    vm_active = 1;

    /* Configure sret to enter VS-mode:
     *   hstatus.SPV  = 1  (bit 7) -> return to virtualized mode
     *   hstatus.SPVP = 1  (bit 8) -> return to VS-mode (not VU-mode)
     *   sstatus.SPP  = 1  (bit 8) -> return to S-level within virtual mode */
    {
        unsigned long hstatus_bits = HSTATUS_SPV | HSTATUS_SPVP;
        __asm__ __volatile__("csrs 0x600, %0" :: "r"(hstatus_bits));
    }
    {
        unsigned long spp_bit = SSTATUS_SPP;
        __asm__ __volatile__(
            "csrs sstatus, %0" :: "r"(spp_bit));
    }

    /* sepc = vsmode_entry */
    __asm__ __volatile__(
        "csrw sepc, %0" :: "r"((unsigned long)vsmode_entry));

    /* Enter VS-mode. */
    __asm__ __volatile__("sret");
    __builtin_unreachable();
}

/* ---- M-mode entry: configure PMP, drop to HS-mode ---------------------- */

int main(void) {
    extern void m_trap_handler(void);
    write_csr(mtvec, (unsigned long)m_trap_handler & ~3UL);

    /* Open PMP wide: NAPOT covering the entire address space, RWX. */
    write_csr(pmpaddr0, -1UL);
    write_csr(pmpcfg0, 0x1f);   /* NAPOT | R | W | X */

    /* Drop to HS-mode via mret.
     * MPP = 1 (S-mode level), MPV = 0 -> HS-mode (not VS-mode). */
    unsigned long ms = read_csr(mstatus);
    ms &= ~MSTATUS_MPP;           /* clear MPP */
    ms &= ~MSTATUS_MPV;           /* clear MPV -> HS-mode */
    ms |= (1UL << 11);            /* MPP = S-mode (1) */
    write_csr(mstatus, ms);

    write_csr(mepc, (unsigned long)hsmode_setup);

    __asm__ __volatile__("mret");
    __builtin_unreachable();
}
