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
 *
 * Stage 1 (vsatp): a single level-3 leaf PTE at entry 0 maps 512 GiB.
 *   This works because Sv48 supports level-3 superpages.
 *
 * Stage 2 (hgatp): a multi-level page table hierarchy:
 *   Level-3 root (2048 entries, 16 KiB): entry 0 is a non-leaf PTE
 *     pointing to a level-2 table.
 *   Level-2 table (512 entries, 4 KiB): leaf PTEs at entries 0 and 72
 *     create 1 GiB identity-mapped superpages.
 *     - Entry 0:  covers HPA [0, 1 GiB) — low memory.
 *     - Entry 72: covers HPA [72 GiB, 73 GiB) — contains hart.ram
 *       (0x1212340000) and the page tables themselves (0x1220340000).
 *
 * A single level-3 leaf superpage in hgatp (Sv48x4 G-stage) is NOT used
 * because Spike's Sv48x4 walker does not support level-3 leaf PTEs.
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
/* Stage-1 (vsatp) PTEs: do NOT set PTE_U — with PTE_U=1 the pages belong
 * to VU-mode and VS-mode instruction fetch would fault. */
#define PTE_FLAGS       (PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D)
/* Stage-2 (hgatp) PTEs: MUST set PTE_U.  Spike's s2xlate() G-stage walker
 * unconditionally rejects leaf PTEs with U=0 (mmu.cc line 593).  Per RISC-V
 * spec, G-stage PTE_U controls VS/VU access granularity; for our test both
 * modes need access, so PTE_U=1 is correct. */
#define PTE_FLAGS_G     (PTE_FLAGS | PTE_U)

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
 * hgatp L2   (4 KiB):  ram + 0x0E00_8000  (at 0x1220348000)
 * ram_size = 0x10000000 (256 MiB), so max valid = ram + 0x0FFF_FFFF.
 */
#define HART_RAM        0x1212340000UL
#define VSATP_ROOT_PA   (HART_RAM + 0x0E000000UL)
#define HGATP_ROOT_PA   (HART_RAM + 0x0E004000UL)
#define HGATP_L2_PA     (HART_RAM + 0x0E008000UL)

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
    /* Zero the page table regions.  Only a few entries per table are used;
     * clear a small neighbourhood to ensure PTE_V=0 for invalid slots. */
    volatile uint64_t *vsatp_pt = (volatile uint64_t *)VSATP_ROOT_PA;
    volatile uint64_t *hgatp_pt = (volatile uint64_t *)HGATP_ROOT_PA;
    volatile uint64_t *hgatp_l2 = (volatile uint64_t *)HGATP_L2_PA;
    for (int i = 0; i < 4; i++) {
        vsatp_pt[i] = 0;
        hgatp_pt[i] = 0;
    }

    vsatp_pt[0] = ((uint64_t)0 << 37) | PTE_FLAGS;

    /*
     * Build stage-2 page table (hgatp / Sv48x4).
     *
     * Level-3 root (2048 entries): entry 0 is a non-leaf PTE pointing to
     * the level-2 table.  A non-leaf PTE has PTE_V set but NO R/W/X bits.
     *   PTE = (PPN_of_L2_table << PTE_PPN_SHIFT) | PTE_V
     *
     * Level-2 table (512 entries): leaf PTEs with 1 GiB superpage mappings.
     *   Entry  0: identity map for PA [0, 1 GiB).
     *   Entry 72: identity map for PA [72 GiB, 73 GiB).
     *             hart.ram (0x1212340000) and page tables (0x1220340000)
     *             both fall within this 1 GiB range.
     *   PTE.ppn = PA >> 12 = (entry * 1GiB) >> 12 = entry << 18
     *   PTE     = (PPN << PTE_PPN_SHIFT) | PTE_FLAGS
     *           = (entry << 28) | PTE_FLAGS
     */

    /* Zero level-2 entries around the ones we populate. */
    for (int i = 0; i < 4; i++)
        hgatp_l2[i] = 0;
    for (int i = 70; i < 76; i++)
        hgatp_l2[i] = 0;

    /* Level-2 leaf PTE at entry 0: identity map PA [0, 1 GiB). */
    hgatp_l2[0] = ((uint64_t)0 << 28) | PTE_FLAGS_G;

    /* Level-2 leaf PTE at entry 72: identity map PA [72 GiB, 73 GiB). */
    hgatp_l2[72] = ((uint64_t)72 << 28) | PTE_FLAGS_G;

    /* Level-3 root entry 0: non-leaf PTE pointing to the level-2 table.
     * PPN = HGATP_L2_PA >> 12.  Only PTE_V is set (no R/W/X). */
    hgatp_pt[0] = ((HGATP_L2_PA >> 12) << PTE_PPN_SHIFT) | PTE_V;

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
