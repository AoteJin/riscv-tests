#include "encoding.h"

        .global main

        .section .text
main:
        # Configure PMP to allow all access from S/HS-mode
        li      t0, 0x1f            # TOR, RWX
        csrw    CSR_PMPCFG0, t0
        li      t0, -1
        csrw    CSR_PMPADDR0, t0

        # Clear mstatus.MPP and MPV, then set MPP=01 (S-mode level)
        # With MPV=0, mret goes to HS-mode (not VS-mode)
        li      t0, MSTATUS_MPP
        csrc    CSR_MSTATUS, t0
        li      t0, 1
        slli    t0, t0, 39
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
        # Stay in HS-mode forever — never transition to VS-mode.
        # T53 uses this to prove that haltreq is denied in HS-mode
        # when only VSEDBGALW=1 is set.
        .global hsmode_loop
hsmode_loop:
        j       hsmode_loop
