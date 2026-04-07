#include "encoding.h"

        .global main

        .section .text
main:
        # Configure PMP to allow all access from S/HS/VS-mode
        li      t0, 0x1f            # TOR, RWX
        csrw    CSR_PMPCFG0, t0
        li      t0, -1
        csrw    CSR_PMPADDR0, t0

        # Clear mstatus.MPP and MPV, then set MPP=01 (S-mode level)
        # With MPV=0, mret goes to HS-mode (not VS-mode)
        li      t0, MSTATUS_MPP
        csrc    CSR_MSTATUS, t0
        # Clear MPV (bit 39)
        li      t0, 1
        slli    t0, t0, 39
        csrc    CSR_MSTATUS, t0
        # Set MPP = S-mode (01)
        li      t0, (1 << 11)
        csrs    CSR_MSTATUS, t0

        # mepc = hsmode_entry
        la      t0, hsmode_entry
        csrw    CSR_MEPC, t0

        # Drop to HS-mode
        mret

        .balign 4
        .global hsmode_entry
hsmode_entry:
        # Now in HS-mode.
        # Configure sret to enter VS-mode:
        #   hstatus.SPV  = 1  (bit 7)  → return to virtualized mode
        #   hstatus.SPVP = 1  (bit 8)  → return to VS-mode (not VU-mode)
        li      t0, (HSTATUS_SPV | HSTATUS_SPVP)       # 0x180
        csrs    hstatus, t0

        # Set sstatus.SPP = 1 (S-level) — some implementations use SPP
        # alongside SPVP for sret target privilege in virtual mode
        li      t0, SSTATUS_SPP                        # 0x100
        csrs    CSR_SSTATUS, t0

        # sepc = vsmode_entry
        la      t0, vsmode_entry
        csrw    CSR_SEPC, t0

        sret

        .balign 4
        .global vsmode_entry
vsmode_entry:
        .global vsmode_loop
vsmode_loop:
        j       vsmode_loop
