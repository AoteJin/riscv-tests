#include "encoding.h"

        .global main

        .section .text
main:
        # Stay in M-mode forever — never transition to S-mode.
        # T19 uses this to prove that haltreq is denied in M-mode
        # when mdbgen=0 and SEDBGALW=1.
        .global mmode_loop
mmode_loop:
        j       mmode_loop
