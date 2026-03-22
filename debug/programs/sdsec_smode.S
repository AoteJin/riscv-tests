#include "encoding.h"

        .global main

        .section .text
main:
        # Configure PMP to allow all access from S-mode
        li      t0, 0x1f            # TOR, RWX
        csrw    CSR_PMPCFG0, t0
        li      t0, -1
        csrw    CSR_PMPADDR0, t0

        # Set mstatus.MPP = S-mode (01)
        li      t0, MSTATUS_MPP
        csrc    CSR_MSTATUS, t0
        li      t0, (1 << 11)       # MPP = 01 (S-mode)
        csrs    CSR_MSTATUS, t0

        # Set mepc to smode_entry
        la      t0, smode_entry
        csrw    CSR_MEPC, t0

        # Drop to S-mode
        mret

        .balign 4
smode_entry:
        .global smode_entry
smode_loop:
        .global smode_loop
        j       smode_loop
