#include "encoding.h"

        .global main

        .section .text
main:
        # Configure PMP to allow all access
        li      t0, 0x1f            # TOR, RWX
        csrw    CSR_PMPCFG0, t0
        li      t0, -1
        csrw    CSR_PMPADDR0, t0

        # Clear mstatus.MPP and MPV, then set MPP=01 (S-mode level)
        # With MPV=0, mret goes to HS-mode (not VS-mode)
        li      t0, MSTATUS_MPP
        csrc    CSR_MSTATUS, t0
        li      t0, 1
        slli    t0, t0, 39          # MPV bit 39
        csrc    CSR_MSTATUS, t0
        li      t0, (1 << 11)       # MPP = S-mode
        csrs    CSR_MSTATUS, t0

        la      t0, hsmode_entry
        csrw    CSR_MEPC, t0

        # Drop to HS-mode
        mret

        .balign 4
        .global hsmode_entry
hsmode_entry:
        # Now in HS-mode.
        # Configure sret to enter VU-mode (not VS-mode):
        #   hstatus.SPV  = 1  (bit 7)  -> return to virtualized mode
        #   hstatus.SPVP = 0  (bit 8)  -> return to VU-mode (U-level in V)
        li      t0, HSTATUS_SPV                        # 0x80
        csrs    hstatus, t0
        li      t0, HSTATUS_SPVP                       # 0x100
        csrc    hstatus, t0

        # Set sstatus.SPP = 0 (U-level)
        li      t0, SSTATUS_SPP                        # 0x100
        csrc    CSR_SSTATUS, t0

        # sepc = vumode_entry
        la      t0, vumode_entry
        csrw    CSR_SEPC, t0

        sret

        .balign 4
        .global vumode_entry
vumode_entry:
        .global vumode_loop
vumode_loop:
        j       vumode_loop
