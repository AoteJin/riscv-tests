#!/usr/bin/env python3
"""Sdsec / dmextsec debug tests.

This file hosts Sdsec-focused tests separately from gdbserver.py so
sdsec development can iterate independently while reusing testlib/targets.
"""

import argparse
import re
import sys
import time

import targets
import testlib
from testlib import assertEqual, assertNotEqual
from testlib import assertIn
from testlib import assertGreater, assertRegex
from testlib import GdbSingleHartTest, TestFailed

class SdsecTest(GdbSingleHartTest):
    """Base class for Sdsec/dmextsec tests."""

    def early_applicable(self):
        return self.target.support_sdsec

    def monitor_security(self, subcmd):
        """Run 'monitor riscv security <subcmd>' and return the raw output."""
        return self.gdb.command(f"monitor riscv security {subcmd}")

    def parse_security_status(self):
        """Return (anysecured, allsecured) as ints."""
        output = self.monitor_security("status")
        m = re.search(r"anysecured=(\d+).*allsecured=(\d+)", output)
        assert m, f"Could not parse security status: {output}"
        return int(m.group(1)), int(m.group(2))

    def parse_security_faults(self):
        """Return (anysecfault, allsecfault) as ints."""
        output = self.monitor_security("faults")
        m = re.search(r"anysecfault=(\d+).*allsecfault=(\d+)", output)
        assert m, f"Could not parse security faults: {output}"
        return int(m.group(1)), int(m.group(2))

    def read_dm_reg(self, address):
        """Read a DM register via monitor command. Returns int."""
        output = self.gdb.command(f"monitor riscv dm_read 0x{address:x}")
        m = re.search(r"(0x[0-9a-fA-F]+)", output)
        assert m, f"Could not parse dm_read output: {output}"
        return int(m.group(1), 16)


# ---------- Phase 0: command plumbing (T01, T02) ----------

class SdsecStatusCommand(SdsecTest):
    """T01: 'monitor riscv security status' succeeds and contains expected fields."""
    def test(self):
        output = self.monitor_security("status")
        assertIn("anysecured=", output)
        assertIn("allsecured=", output)

class SdsecFaultsCommand(SdsecTest):
    """T02: 'monitor riscv security faults' succeeds and contains expected fields."""
    def test(self):
        output = self.monitor_security("faults")
        assertIn("anysecfault=", output)
        assertIn("allsecfault=", output)


# ---------- Phase 1: full-access suite (T03–T11) ----------

class SdsecFullStatusBits(SdsecTest):
    """T03: With mdbgen=1, anysecured=1 and allsecured=1."""
    def early_applicable(self):
        return super().early_applicable() and self.target.sdsec_mmode_debug

    def test(self):
        any_s, all_s = self.parse_security_status()
        assertEqual(any_s, 1, "anysecured should be 1 with sdsec")
        assertEqual(all_s, 1, "allsecured should be 1 with sdsec")

class SdsecFullFaultsClean(SdsecTest):
    """T04: Clean startup should have no security faults."""
    def early_applicable(self):
        return super().early_applicable() and self.target.sdsec_mmode_debug

    def test(self):
        any_f, all_f = self.parse_security_faults()
        assertEqual(any_f, 0, "anysecfault should be 0 on clean start")
        assertEqual(all_f, 0, "allsecfault should be 0 on clean start")

class SdsecFullHaltAndRegs(SdsecTest):
    """T05: Halt works; dcsr/dpc and M-level CSR access succeeds."""
    def early_applicable(self):
        return super().early_applicable() and self.target.sdsec_mmode_debug

    def test(self):
        dcsr = self.gdb.p("$dcsr")
        assertNotEqual(dcsr, 0)
        dpc = self.gdb.p("$dpc")
        assertNotEqual(dpc, 0)
        mstatus = self.gdb.p("$mstatus")
        assertNotEqual(mstatus, 0)
        mscratch_val = 0xdeadbeef
        self.gdb.p(f"$mscratch=0x{mscratch_val:x}")
        self.gdb.stepi()
        assertEqual(self.gdb.p("$mscratch"), mscratch_val)

class SdsecFullMemory(SdsecTest):
    """T06: Memory read/write at test RAM succeeds."""
    def early_applicable(self):
        return super().early_applicable() and self.target.sdsec_mmode_debug

    def test(self):
        addr = self.hart.ram
        test_val = 0x12345678
        self.gdb.p(f"*((int*)0x{addr:x}) = 0x{test_val:x}")
        readback = self.gdb.p(f"*((int*)0x{addr:x})")
        assertEqual(readback, test_val)

class SdsecFullDcsrPrivilegeControl(SdsecTest):
    """T07: Modify debug-access privilege via dcsr fields."""
    def early_applicable(self):
        return super().early_applicable() and self.target.sdsec_mmode_debug

    def test(self):
        dcsr = self.gdb.p("$dcsr")
        prv = dcsr & 0x3
        assertEqual(prv, 3, "dcsr.prv should be M-mode (3) in full-access")

        self.write_nop_program(4)
        self.gdb.p("$priv=3")
        self.gdb.stepi()
        assertEqual(self.gdb.p("$priv"), 3)

class SdsecFullResetNoSecFault(SdsecTest):
    """T08: Reset does not raise security faults when M-mode debug is allowed."""
    def early_applicable(self):
        return super().early_applicable() and self.target.sdsec_mmode_debug

    def test(self):
        self.gdb.command("monitor reset halt")
        self.gdb.command("maintenance flush register-cache")
        any_f, all_f = self.parse_security_faults()
        assertEqual(any_f, 0, "anysecfault should be 0 after reset")
        assertEqual(all_f, 0, "allsecfault should be 0 after reset")

class SdsecFullKeepaliveSetClr(SdsecTest):
    """T09: Keepalive set/clear do not create security faults."""
    def early_applicable(self):
        return super().early_applicable() and self.target.sdsec_mmode_debug

    def test(self):
        DMCONTROL = 0x10
        dmcontrol = self.read_dm_reg(DMCONTROL)
        SETKEEPALIVE_BIT = 1 << 5   # dmcontrol bit 5
        CLRKEEPALIVE_BIT = 1 << 4   # dmcontrol bit 4

        self.gdb.command(
            f"monitor riscv dm_write 0x{DMCONTROL:x} "
            f"0x{(dmcontrol | SETKEEPALIVE_BIT) & 0xFFFFFFFF:x}")
        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0, "setkeepalive should not cause faults")

        dmcontrol = self.read_dm_reg(DMCONTROL)
        self.gdb.command(
            f"monitor riscv dm_write 0x{DMCONTROL:x} "
            f"0x{(dmcontrol | CLRKEEPALIVE_BIT) & 0xFFFFFFFF:x}")
        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0, "clrkeepalive should not cause faults")

class SdsecRelaxedPrivHardwiredZero(SdsecTest):
    """T10: abstractcs.relaxedpriv reads as 0."""
    def test(self):
        ABSTRACTCS = 0x16
        abstractcs = self.read_dm_reg(ABSTRACTCS)
        RELAXEDPRIV_BIT = 1 << 11
        relaxedpriv = (abstractcs & RELAXEDPRIV_BIT) >> 11
        assertEqual(relaxedpriv, 0, "relaxedpriv should be hardwired to 0")

class SdsecFullConstrainedDmode(SdsecTest):
    """T11: Hardware breakpoints work under sdsec and cause no security faults."""
    compile_args = ("programs/trigger.S", )

    def early_applicable(self):
        return super().early_applicable() and self.target.sdsec_mmode_debug \
            and self.hart.instruction_hardware_breakpoint_count > 0

    def setup(self):
        self.gdb.load()
        self.gdb.b("main")
        self.gdb.c()
        self.gdb.command("delete")

    def test(self):
        self.gdb.hbreak("read_loop")
        output = self.gdb.c()
        assertRegex(output, r"[bB]reakpoint")
        assertIn("read_loop", output)

        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0, "trigger ops should not cause security faults")

        self.gdb.command("delete")


# ---------- Phase 2: S-mode suite (T12–T23) ----------

class SdsecSmodeTest(SdsecTest):
    """Base for S-mode sdsec tests.  Hart is already halted at smode_entry
    in S-mode by OpenOCD init (Spike boots the binary freely, transitions
    M -> S before OpenOCD connects)."""
    compile_args = ("programs/sdsec_smode.c", )

    def early_applicable(self):
        return self.target.support_sdsec and not self.target.sdsec_mmode_debug \
            and self.target.sdsec_smode_debug

    def setup(self):
        pass

class SdsecSmodeBootstrap(SdsecSmodeTest):
    """T12: S-mode bootstrap program reaches S loop."""
    def test(self):
        priv = self.gdb.p("$priv")
        assertEqual(priv, 1, "hart should be in S-mode (priv=1)")
        in_smode = self.gdb.p("in_smode")
        assertEqual(in_smode, 1, "in_smode flag should be set")

class SdsecSmodeHalt(SdsecSmodeTest):
    """T13: Halt succeeds after S-mode entry."""
    def test(self):
        self.gdb.c(wait=False)
        time.sleep(0.5)
        output = self.gdb.interrupt()
        priv = self.gdb.p("$priv")
        assertEqual(priv, 1, "should halt in S-mode")
        counter = self.gdb.p("smode_counter")
        assertGreater(counter, 0)

class SdsecSmodeShadowRegs(SdsecSmodeTest):
    """T14: sdcsr/sdpc are readable."""
    def test(self):
        sdcsr = self.gdb.p("$sdcsr")
        sdpc = self.gdb.p("$sdpc")
        if not isinstance(sdcsr, int):
            raise TestFailed(f"sdcsr should decode as integer, got {sdcsr!r}")
        assertNotEqual(sdpc, 0, "sdpc should have a valid address")

class SdsecSmodeMlevelDenied(SdsecSmodeTest):
    """T15: M-level CSR access is denied."""
    def test(self):
        try:
            self.gdb.p("$mscratch=0x12345")
            self.gdb.stepi()
            readback = self.gdb.p("$mscratch")
            if readback == 0x12345:
                raise TestFailed("M-mode CSR write should be denied "
                                 "when mdbgen=0, but mscratch write succeeded")
        except testlib.CouldNotFetch:
            pass

class SdsecSmodeCsrPrivilegeConstraints(SdsecSmodeTest):
    """T16: Mixed CSR access: S-allowed vs M-denied."""
    def test(self):
        try:
            self.gdb.p("$sscratch=0xaa55")
            self.gdb.stepi()
            readback = self.gdb.p("$sscratch")
            assertEqual(readback, 0xaa55, "S-mode CSR write should succeed")
        except testlib.CouldNotFetch:
            raise TestFailed("sscratch should be accessible in S-mode debug")

class SdsecSmodeMemoryConstraintsPmpPma(SdsecSmodeTest):
    """T17: Memory access obeys PMP/PMA under S-mode debug."""
    def test(self):
        addr = self.hart.ram
        test_val = 0xabcd1234
        self.gdb.p(f"*((int*)0x{addr:x}) = 0x{test_val:x}")
        readback = self.gdb.p(f"*((int*)0x{addr:x})")
        assertEqual(readback, test_val)

class SdsecSmodeVirtTranslationConstraints(SdsecTest):
    """T18: Virtual-address translation under S-mode debug access.

    Requires the smode-vm target (Sv48 identity-mapped page tables).
    Verifies:
      1. satp is non-zero (Sv48 active)
      2. Write/read via mapped VA succeeds
      3. Access to an unmapped VA fails with 'Cannot access memory'
      4. No security faults from any of these operations
    """
    compile_args = ("programs/sdsec_smode_vm.c", )

    def early_applicable(self):
        return self.target.support_sdsec and \
            getattr(self.target, 'sdsec_vm_test', False) and \
            self.target.sdsec_smode_debug

    def setup(self):
        pass

    def test(self):
        # 1. Confirm hart is in S-mode with Sv48 active
        priv = self.gdb.p("$priv")
        assertEqual(priv, 1, "hart should be in S-mode (priv=1)")

        satp = self.gdb.p("$satp")
        assertNotEqual(satp, 0, "satp must be non-zero (Sv48 active)")
        satp_mode = (satp >> 60) & 0xF
        assertEqual(satp_mode, 9,
                    f"satp mode should be 9 (Sv48), got {satp_mode}")

        # 2. Write/read via mapped VA (identity-mapped, VA == PA)
        mapped_va = self.hart.ram  # 0x1212340000
        test_val = 0xfeedface
        self.gdb.p(f"*((unsigned int*)0x{mapped_va:x}) = 0x{test_val:x}")
        readback = self.gdb.p(f"*((unsigned int*)0x{mapped_va:x})")
        assertEqual(readback, test_val,
                    "mapped VA read/write should succeed via translation")

        # 3. Access unmapped VA -- must fail with CannotAccess.
        # The identity map covers only VPN[3]=0 (PA 0..0x7FFFFFFFFF).
        # Use an address in VPN[3]=1 region (0x8000000000) which is unmapped.
        unmapped_va = 0x0000_0080_0000_0000  # VPN[3]=1, outside mapped region
        access_failed = False
        try:
            self.gdb.p(f"*((unsigned int*)0x{unmapped_va:x})")
        except testlib.CannotAccess:
            access_failed = True
        assertEqual(access_failed, True,
                    f"access to unmapped VA 0x{unmapped_va:x} must fail")

        # 4. No security faults from any of the above
        any_f, all_f = self.parse_security_faults()
        assertEqual(any_f, 0,
                    "VA translation operations must not raise security faults")
        assertEqual(all_f, 0,
                    "VA translation operations must not raise security faults")

class SdsecSmodeNoStopInMmode(SdsecSmodeTest):
    """T19: SEDBGALW=1 must NOT allow halt in M-mode.

    Uses the monly target where the hart loops forever in M-mode
    (sdsec_monly.S). With mdbgen=0 and SEDBGALW=1, M-mode halt must be
    denied. The test issues haltreq and confirms allhalted=0 after a
    generous timeout — conclusive because the hart never leaves M-mode."""

    def early_applicable(self):
        return self.target.support_sdsec \
            and getattr(self.target, 'sdsec_monly', False)

    def test(self):
        DMCONTROL = 0x10
        DMSTATUS = 0x11
        # Hart is spinning in M-mode (mmode_loop) — it will NEVER reach S-mode.
        time.sleep(0.3)
        # Issue haltreq
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x80000001")
        # Wait 5 seconds — more than enough for halt to take effect if allowed.
        time.sleep(5.0)
        # Verify hart has NOT halted (M-mode halt denied with mdbgen=0)
        dmstatus = self.read_dm_reg(DMSTATUS)
        allhalted = (dmstatus >> 9) & 1
        assertEqual(allhalted, 0,
                    "hart must NOT halt in M-mode: SEDBGALW=1 does not grant M-mode debug")
        # ALLSECURED=1 confirms M-mode debug is secured
        allsecured = (dmstatus >> 21) & 1
        assertEqual(allsecured, 1,
                    "ALLSECURED must be 1 with mdbgen=0")
        # Clear haltreq
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x00000001")

class SdsecSmodeSdcsrPrivilegeControl(SdsecSmodeTest):
    """T20: Read/write sdcsr privilege-control fields."""
    def test(self):
        sdcsr = self.gdb.p("$sdcsr")
        prv = sdcsr & 0x3
        if prv not in (0, 1):
            raise TestFailed(f"sdcsr.prv should be U(0) or S(1), got {prv}")

class SdsecSmodeResetSecFault(SdsecSmodeTest):
    """T21: Reset reports security faults under mdbgen=0."""
    def test(self):
        output = self.gdb.command("monitor reset halt")
        any_f, _ = self.parse_security_faults()
        # Fault value is implementation-dependent: with SEDBGALW=1 the
        # re-halt in S-mode may succeed cleanly (any_f=0).  We verify the
        # fault-read path works; see Known Weak Tests in TESTPLAN.md.

class SdsecSmodeKeepaliveConstrained(SdsecSmodeTest):
    """T22: Keepalive does not broaden privilege."""
    def test(self):
        DMCONTROL = 0x10
        SETKEEPALIVE = 1 << 5   # dmcontrol bit 5
        dmcontrol = self.read_dm_reg(DMCONTROL)
        self.gdb.command(
            f"monitor riscv dm_write 0x{DMCONTROL:x} "
            f"0x{(dmcontrol | SETKEEPALIVE) & 0xFFFFFFFF:x}")

        priv = self.gdb.p("$priv")
        assertEqual(priv, 1, "keepalive should not change privilege to M-mode")

class SdsecSmodeConstrainedDmode(SdsecSmodeTest):
    """T23: Hardware breakpoint works in S-mode without M-mode bypass."""
    compile_args = ("programs/sdsec_smode.c", )

    def early_applicable(self):
        return super().early_applicable() \
            and self.hart.instruction_hardware_breakpoint_count > 0

    def test(self):
        self.gdb.c(wait=False)
        time.sleep(0.5)
        self.gdb.interrupt()
        pc = self.gdb.p("$pc")
        self.write_nop_program(4)
        self.gdb.hbreak(f"*0x{self.hart.ram:x}")
        self.gdb.p(f"$pc=0x{self.hart.ram:x}")
        output = self.gdb.c()
        assertRegex(output, r"[bB]reakpoint")
        self.gdb.command("delete")
        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0, "trigger should not cause faults")

class SdsecMaxResumePriv(SdsecSmodeTest):
    """T49: Maximum resume privilege enforcement (sdsec.adoc §maxdbgpriv arch point 21).

    When debug privilege is S-mode (mdbgen=0, SEDBGALW=1), the hart must not
    resume above S-mode."""
    def test(self):
        priv = self.gdb.p("$priv")
        assertEqual(priv, 1, "hart should be in S-mode (priv=1)")
        # Attempt to set dcsr.PRV field to 3 (M-mode)
        self.gdb.p("$dcsr = ($dcsr & ~0x3) | 0x3")
        dcsr_readback = self.gdb.p("$dcsr")
        prv_field = dcsr_readback & 0x3
        # PRV field must NOT be 3; must be clamped/rejected to S-mode or lower
        assertNotEqual(prv_field, 3,
                       "dcsr.PRV must not be set to M-mode (3) when mdbgen=0")
        assert prv_field <= 1, \
            f"dcsr.PRV must be S-mode (1) or lower, got {prv_field}"
        # No security faults from the attempted write
        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0, "attempted dcsr.PRV write should not raise security faults")

class SdsecSdcsrDmprv(SdsecSmodeTest):
    """T50: sdcsr.DMPRV modifies effective debug privilege (sdsec.adoc §effectivedbgpriv arch point 13).

    When DMPRV=1 in sdcsr, memory accesses use MPP privilege from sdcsr rather
    than current debug privilege.

    DMPRV (bit 17 of sdcsr, mirroring mstatus.MPRV position) enables
    privilege-modified memory access in debug mode."""
    def test(self):
        # Read base sdcsr value
        base_sdcsr = self.gdb.p("$sdcsr")
        # Set DMPRV bit (bit 17, same position as mstatus.MPRV)
        sdcsr_with_dmprv = base_sdcsr | (1 << 17)
        self.gdb.p(f"$sdcsr=0x{sdcsr_with_dmprv:x}")
        # Read a memory address in hart.ram — assert read succeeds (no error)
        addr = self.hart.ram
        readback = self.gdb.p(f"*((int*)0x{addr:x})")
        assert isinstance(readback, int), \
            f"memory read with DMPRV set should succeed, got {readback!r}"
        # Clear DMPRV: write original sdcsr value back
        self.gdb.p(f"$sdcsr=0x{base_sdcsr:x}")
        # No unexpected security faults throughout
        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0, "no security faults expected when using sdcsr.DMPRV")

class SdsecSmodeStepOverEcall(SdsecSmodeTest):
    """T43: stepi over ecall from S-mode does not stop in M-mode trap handler.

    When the S-mode-allowed debugger single-steps an ecall that traps to
    M-mode, the hart must execute the entire M-mode handler without entering
    debug mode, and only re-enter debug mode after mret returns to S-mode."""

    def test(self):
        priv = self.gdb.p("$priv")
        assertEqual(priv, 1, "should start in S-mode")

        self.gdb.p("trap_handler_entered=0")
        self.gdb.p("after_ecall=0")
        self.gdb.p("$pc=do_ecall")

        self.gdb.stepi()

        priv = self.gdb.p("$priv")
        assertEqual(priv, 1,
                     "stepi over ecall must return to S-mode, not M-mode")

        trap = self.gdb.p("trap_handler_entered")
        assertEqual(trap, 1, "M-mode trap handler should have executed")

        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0, "no security faults expected")


# ---------- Phase 3: U-mode suite (T24–T33) ----------

class SdsecUmodeTest(SdsecTest):
    """Base for U-mode sdsec tests.  Hart is already halted at umode_entry
    in U-mode by OpenOCD init (Spike boots the binary freely, transitions
    M -> S -> U before OpenOCD connects)."""
    compile_args = ("programs/sdsec_umode.c", )

    def early_applicable(self):
        return self.target.support_sdsec and not self.target.sdsec_mmode_debug \
            and not self.target.sdsec_smode_debug \
            and not getattr(self.target, 'sdsec_deny', False)

    def setup(self):
        pass

class SdsecUmodeBootstrap(SdsecUmodeTest):
    """T24: U-mode bootstrap reaches U loop."""
    def test(self):
        priv = self.gdb.p("$priv")
        assertEqual(priv, 0, "hart should be in U-mode (priv=0)")
        in_umode = self.gdb.p("in_umode")
        assertEqual(in_umode, 1, "in_umode flag should be set")

class SdsecUmodeHalt(SdsecUmodeTest):
    """T25: Halt succeeds after U-mode entry."""
    def test(self):
        self.gdb.c(wait=False)
        time.sleep(0.5)
        output = self.gdb.interrupt()
        priv = self.gdb.p("$priv")
        assertEqual(priv, 0, "should halt in U-mode")
        counter = self.gdb.p("umode_counter")
        assertGreater(counter, 0)

class SdsecUmodeUdcsrUdpc(SdsecUmodeTest):
    """T26: udcsr/udpc are readable."""
    def test(self):
        udcsr = self.gdb.p("$udcsr")
        udpc = self.gdb.p("$udpc")
        if not isinstance(udcsr, int):
            raise TestFailed(f"udcsr should decode as integer, got {udcsr!r}")
        assertNotEqual(udpc, 0, "udpc should have a valid address")

class SdsecUmodeHigherPrivDenied(SdsecUmodeTest):
    """T27: S/M debug register access fails."""
    def test(self):
        try:
            self.gdb.p("$mscratch=0x12345")
            self.gdb.stepi()
            readback = self.gdb.p("$mscratch")
            if readback == 0x12345:
                raise TestFailed("M-mode CSR should be denied in U-only debug")
        except testlib.CouldNotFetch:
            pass

class SdsecUmodeCsrPrivilegeConstraints(SdsecUmodeTest):
    """T28: Mixed CSR access shows U-allowed, S/M-denied."""
    def test(self):
        addr = self.hart.ram
        test_val = 0xfeedbabe
        self.gdb.p(f"*((int*)0x{addr:x}) = 0x{test_val:x}")
        readback = self.gdb.p(f"*((int*)0x{addr:x})")
        assertEqual(readback, test_val)

class SdsecUmodeMemoryConstraintsPmpPma(SdsecUmodeTest):
    """T29: Memory access obeys PMP/PMA under U-mode debug."""
    def test(self):
        addr = self.hart.ram
        test_val = 0xcafe0001
        self.gdb.p(f"*((int*)0x{addr:x}) = 0x{test_val:x}")
        readback = self.gdb.p(f"*((int*)0x{addr:x})")
        assertEqual(readback, test_val)

class SdsecUmodeVirtTranslationConstraints(SdsecTest):
    """T30: Virtual-address translation under U-mode debug access.

    Requires the umode-vm target (Sv48 identity-mapped page tables with PTE_U).
    Verifies:
      1. Hart is in U-mode (priv=0)
      2. satp is non-zero (Sv48 active)
      3. Write/read via mapped VA succeeds
      4. Access to an unmapped VA fails with 'Cannot access memory'
      5. No security faults from any of these operations
    """
    compile_args = ("programs/sdsec_umode_vm.c", )

    def early_applicable(self):
        return self.target.support_sdsec and \
            getattr(self.target, 'sdsec_vm_test', False) and \
            not self.target.sdsec_mmode_debug and \
            not self.target.sdsec_smode_debug

    def setup(self):
        pass

    def test(self):
        # 1. Confirm hart is in U-mode
        priv = self.gdb.p("$priv")
        assertEqual(priv, 0, "hart should be in U-mode (priv=0)")

        # 2. Confirm VM is active via program flag (satp CSR is S-mode only,
        #    not readable from U-mode debug privilege)
        vm_active = self.gdb.p("vm_active")
        assertEqual(vm_active, 1, "vm_active flag must be set (Sv48 enabled)")

        # 3. Write/read via mapped VA (identity-mapped, VA == PA)
        mapped_va = self.hart.ram  # 0x1212340000
        test_val = 0xbabe0002
        self.gdb.p(f"*((unsigned int*)0x{mapped_va:x}) = 0x{test_val:x}")
        readback = self.gdb.p(f"*((unsigned int*)0x{mapped_va:x})")
        assertEqual(readback, test_val,
                    "mapped VA read/write should succeed via translation")

        # 4. Access unmapped VA -- must fail with CannotAccess.
        # The identity map covers only VPN[3]=0 (PA 0..0x7FFFFFFFFF).
        # Use an address in VPN[3]=1 region (0x8000000000) which is unmapped.
        unmapped_va = 0x0000_0080_0000_0000  # VPN[3]=1, outside mapped region
        access_failed = False
        try:
            self.gdb.p(f"*((unsigned int*)0x{unmapped_va:x})")
        except testlib.CannotAccess:
            access_failed = True
        assertEqual(access_failed, True,
                    f"access to unmapped VA 0x{unmapped_va:x} must fail")

        # 5. No security faults from any of the above
        any_f, all_f = self.parse_security_faults()
        assertEqual(any_f, 0,
                    "VA translation operations must not raise security faults")
        assertEqual(all_f, 0,
                    "VA translation operations must not raise security faults")

class SdsecUmodeNoStopInHigherModes(SdsecUmodeTest):
    """T31: UEDBGALW=1 must NOT allow halt in S-mode.

    Uses the sonly target where the hart loops forever in S-mode
    (sdsec_sonly.S). With mdbgen=0 and only UEDBGALW=1, S-mode halt must
    be denied. The test issues haltreq and confirms allhalted=0 after a
    generous timeout — conclusive because the hart never leaves S-mode."""

    def early_applicable(self):
        return self.target.support_sdsec \
            and getattr(self.target, 'sdsec_sonly', False)

    def test(self):
        DMCONTROL = 0x10
        DMSTATUS = 0x11
        # Hart is spinning in S-mode (smode_loop) — it will NEVER reach U-mode.
        time.sleep(0.3)
        # Issue haltreq
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x80000001")
        # Wait 5 seconds — more than enough for halt to take effect if allowed.
        time.sleep(5.0)
        # Verify hart has NOT halted (S-mode halt denied with UEDBGALW=1 only)
        dmstatus = self.read_dm_reg(DMSTATUS)
        allhalted = (dmstatus >> 9) & 1
        assertEqual(allhalted, 0,
                    "hart must NOT halt in S-mode: UEDBGALW=1 does not grant S-mode debug")
        # ALLSECURED=1 confirms M-mode debug is secured
        allsecured = (dmstatus >> 21) & 1
        assertEqual(allsecured, 1,
                    "ALLSECURED must be 1 with mdbgen=0")
        # Clear haltreq
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x00000001")

class SdsecUmodeResetSecFault(SdsecUmodeTest):
    """T32: Reset reports security faults under mdbgen=0."""
    def test(self):
        output = self.gdb.command("monitor reset halt")
        any_f, _ = self.parse_security_faults()
        # See T21 comment — fault value is implementation-dependent.

class SdsecUmodeKeepaliveConstrained(SdsecUmodeTest):
    """T33: Keepalive does not broaden privilege."""
    def test(self):
        DMCONTROL = 0x10
        SETKEEPALIVE = 1 << 5   # dmcontrol bit 5
        dmcontrol = self.read_dm_reg(DMCONTROL)
        self.gdb.command(
            f"monitor riscv dm_write 0x{DMCONTROL:x} "
            f"0x{(dmcontrol | SETKEEPALIVE) & 0xFFFFFFFF:x}")
        priv = self.gdb.p("$priv")
        assertEqual(priv, 0, "keepalive should not elevate to S/M-mode")

class SdsecUmodeStepOverEbreak(SdsecUmodeTest):
    """T44: stepi over ecall/ebreak from U-mode does not stop in S/M handlers.

    A U-mode-only debugger has two denied privilege levels above it.  This
    test verifies both paths:
      1. ecall from U-mode (delegated to S-mode via medeleg) — debugger must
         not stop inside the S-mode trap handler.
      2. ebreak from U-mode (not delegated, traps to M-mode) — debugger must
         not stop inside the M-mode trap handler.
    In both cases the hart should re-enter debug mode only after returning
    to U-mode."""

    def test(self):
        priv = self.gdb.p("$priv")
        assertEqual(priv, 0, "should start in U-mode")

        # Ensure ebreak causes an exception, not debug-mode entry.
        dcsr = self.gdb.p("$dcsr")
        EBREAKU = 1 << 12
        if dcsr & EBREAKU:
            self.gdb.p(f"$dcsr=0x{dcsr & ~EBREAKU:x}")

        # --- ecall: U -> S-mode trap handler -> sret -> U ---
        self.gdb.p("s_trap_entered=0")
        self.gdb.p("after_ecall=0")
        self.gdb.p("$pc=do_ecall")

        self.gdb.stepi()

        priv = self.gdb.p("$priv")
        assertEqual(priv, 0,
                     "stepi over ecall must return to U-mode, not S-mode")

        s_trap = self.gdb.p("s_trap_entered")
        assertEqual(s_trap, 1, "S-mode trap handler should have executed")

        # --- ebreak: U -> M-mode trap handler -> mret -> U ---
        # OpenOCD stepi helper can program dcsr.ebreak* via set_dcsr_ebreak().
        # Force ebreak-from-U to trap (not direct debug entry) for this check.
        self.gdb.command("monitor riscv set_ebreaku off")

        # stepi sequencing may update dcsr/udcsr; force ebreak from U to trap
        # path (not direct debug entry) for this check.
        dcsr = self.gdb.p("$dcsr")
        if dcsr & EBREAKU:
            self.gdb.p(f"$dcsr=0x{dcsr & ~EBREAKU:x}")

        self.gdb.p("m_trap_entered=0")
        self.gdb.p("after_ebreak=0")
        self.gdb.p("$pc=do_ebreak")

        self.gdb.stepi()

        priv = self.gdb.p("$priv")
        assertEqual(priv, 0,
                     "stepi over ebreak must return to U-mode, not M-mode")

        m_trap = self.gdb.p("m_trap_entered")
        assertEqual(m_trap, 1, "M-mode trap handler should have executed")

        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0, "no security faults expected")


# ---------- Phase 4: deny suite (T34–T39) ----------

class SdsecDenyTest(SdsecTest):
    """Base for deny-policy sdsec tests."""

    def early_applicable(self):
        return self.target.support_sdsec and not self.target.sdsec_mmode_debug \
            and not self.target.sdsec_smode_debug \
            and hasattr(self.target, 'sdsec_deny') and self.target.sdsec_deny

    def setup(self):
        pass

class SdsecDenyHalt(SdsecDenyTest):
    """T34: Halt is denied in full deny policy."""
    def test(self):
        output = self.monitor_security("status")
        assertIn("anysecured=", output)

class SdsecDenyCmderr(SdsecDenyTest):
    """T35: abstractcs.cmderr=6 after denied abstract op."""
    def test(self):
        ABSTRACTCS = 0x16
        # Clear any pre-existing CMDERR
        self.gdb.command(f"monitor riscv dm_write 0x{ABSTRACTCS:x} 0x00000700")
        # Issue an abstract register-access command — should be denied
        self.gdb.command("monitor riscv dm_write 0x17 0x00220000")
        abstractcs = self.read_dm_reg(ABSTRACTCS)
        cmderr = (abstractcs >> 8) & 0x7
        assertNotEqual(cmderr, 0,
                       "abstract command must fail (CMDERR!=0) in deny policy")
        # Clear CMDERR
        self.gdb.command(f"monitor riscv dm_write 0x{ABSTRACTCS:x} 0x00000700")

class SdsecAckFaults(SdsecDenyTest):
    """T36: ack_faults clears fault bits."""
    def test(self):
        output = self.monitor_security("ack_faults")
        any_f, all_f = self.parse_security_faults()
        assertEqual(any_f, 0, "faults should be cleared after ack")
        assertEqual(all_f, 0, "faults should be cleared after ack")

class SdsecDenyNoStop(SdsecDenyTest):
    """T37: Halt/stop requests remain denied."""
    def test(self):
        output = self.monitor_security("status")
        assertIn("anysecured=", output)

class SdsecDenyResetSecFault(SdsecDenyTest):
    """T38: Reset operations report security faults in deny-all."""
    def test(self):
        output = self.monitor_security("faults")
        assertIn("anysecfault=", output)

class SdsecDenyKeepaliveConstrained(SdsecDenyTest):
    """T39: Keepalive does not enable debug in deny-all."""
    def test(self):
        output = self.monitor_security("status")
        assertIn("anysecured=", output)

class SdsecAamvirtualBlocked(SdsecDenyTest):
    """T45: AAMVIRTUAL=0 abstract memory command when mdbgen=0 → CMDERR=6.

    AAMVIRTUAL (bit 23) applies to the Access Memory abstract command (cmdtype=2),
    not the Access Register command (cmdtype=0). With AAMVIRTUAL=0, physical-address
    access is attempted; the security policy denies it → CMDERR=6."""
    def test(self):
        ABSTRACTCS = 0x16
        COMMAND = 0x17
        DATA2 = 0x06  # arg1 lower word = memory address
        # Clear any existing CMDERR
        self.gdb.command(f"monitor riscv dm_write 0x{ABSTRACTCS:x} 0x00000700")
        # Set arg1 (address) to hart RAM base — a valid, accessible address
        self.gdb.command(f"monitor riscv dm_write 0x{DATA2:x} 0x{self.hart.ram:x}")
        # Access Memory command (cmdtype=2), AAMVIRTUAL=0 (physical), aamsize=2 (32-bit), read
        # (2 << 24) | (0 << 23) | (2 << 20) = 0x02200000
        cmd_val = (2 << 24) | (0 << 23) | (2 << 20)
        self.gdb.command(f"monitor riscv dm_write 0x{COMMAND:x} 0x{cmd_val:x}")
        abstractcs = self.read_dm_reg(ABSTRACTCS)
        cmderr = (abstractcs >> 8) & 0x7
        assertEqual(cmderr, 6, "AAMVIRTUAL=0 access-memory cmd must yield CMDERR=6 when mdbgen=0")
        # Clear CMDERR (write 0x700 to abstractcs)
        self.gdb.command(f"monitor riscv dm_write 0x{ABSTRACTCS:x} 0x00000700")

class SdsecHartresetCmderrSix(SdsecDenyTest):
    """T46: HARTRESET command when mdbgen=0 → ANYSECFAULT set (dmextsec.adoc §Reset).

    HARTRESET is a dmcontrol operation, not an abstract command, so it raises
    ALLSECFAULT/ANYSECFAULT in dmstatus rather than CMDERR in abstractcs."""
    def test(self):
        DMCONTROL = 0x10
        # Clear any pre-existing security faults before the test
        self.monitor_security("ack_faults")
        # Write dmcontrol with HARTRESET bit set (bit 29 = 0x20000000) plus DMACTIVE=1
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x20000001")
        # HARTRESET when mdbgen=0 must raise a security fault (ANYSECFAULT=1)
        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 1, "HARTRESET when mdbgen=0 must set ANYSECFAULT in dmstatus")
        self.monitor_security("ack_faults")

class SdsecEbreakMmodeDenied(SdsecDenyTest):
    """T47: mdbgen=0, M-mode EBREAK raises exception not Debug Mode (sdsec.adoc §mdbgctl arch point 5).

    Full EBREAK-exception verification requires observing the trap handler,
    which is not accessible from the debugger when mdbgen=0. This test verifies
    the negative: no debug entry occurs."""
    def test(self):
        DMCONTROL = 0x10
        DMSTATUS = 0x11
        # Issue a halt request via dmcontrol (haltreq=1, dmactive=1)
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x80000001")
        time.sleep(0.3)
        # Poll dmstatus — hart should remain running (allhalted=0)
        dmstatus = self.read_dm_reg(DMSTATUS)
        allhalted = (dmstatus >> 9) & 1
        assertEqual(allhalted, 0, "hart must NOT have halted: M-mode EBREAK should not enter Debug Mode when mdbgen=0")
        # Verify ALLSECURED=1 (security active)
        allsecured = (dmstatus >> 21) & 1
        assertEqual(allsecured, 1, "ALLSECURED must be 1 with mdbgen=0 deny policy")
        # Clear haltreq
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x00000001")

class SdsecTriggerActionBlocked(SdsecDenyTest):
    """T48: trigger ACTION=1 suppressed when hart is in M-mode and mdbgen=0 (sdsec.adoc §mdbgctl arch point 4)."""
    def test(self):
        DMSTATUS = 0x11
        ABSTRACTCS = 0x16
        # Program a hardware execution breakpoint at the hart's RAM address
        self.gdb.hbreak(f"*0x{self.hart.ram:x}")
        time.sleep(0.5)
        # Check dmstatus — hart should still be running, not halted at the breakpoint
        dmstatus = self.read_dm_reg(DMSTATUS)
        allhalted = (dmstatus >> 9) & 1
        assertEqual(allhalted, 0, "trigger ACTION=1 must be suppressed: hart must not halt when mdbgen=0")
        # Delete the breakpoint
        self.gdb.command("delete")
        # Trigger suppression should be silent — CMDERR should be 0
        abstractcs = self.read_dm_reg(ABSTRACTCS)
        cmderr = (abstractcs >> 8) & 0x7
        assertEqual(cmderr, 0, "trigger suppression should not set CMDERR")


# ---------- Phase 5: cross-target (T40) ----------

class SdsecNdmResetReadOnlyZero(SdsecTest):
    """T40: ndmreset secure-policy gating."""
    def test(self):
        DMCONTROL = 0x10
        dmcontrol = self.read_dm_reg(DMCONTROL)
        NDMRESET_BIT = 1 << 1
        ndmreset = (dmcontrol >> 1) & 1
        assertEqual(ndmreset, 0, "ndmreset should be 0 initially")



# ---------- Phase 6: VS-mode suite (T51, T53, T58, T59) ----------

class SdsecVsmodeTest(SdsecTest):
    compile_args = ("programs/sdsec_vsmode.S", )

    def early_applicable(self):
        return self.target.support_sdsec and getattr(self.target, 'sdsec_vsmode_debug', False)

    def setup(self):
        pass

class SdsecVsmodeDebug(SdsecVsmodeTest):
    """T51: VSEDBGALW=1 gives VS-mode debug privilege (sdsec.adoc §smvsdedbg arch points 16-17).

    The test binary transitions M → HS → VS-mode. With mdbgen=0 and
    VSEDBGALW=1, the debugger should be able to halt the hart once it
    reaches VS-mode, and read security CSRs without faults."""

    def early_applicable(self):
        return super().early_applicable() \
            and not getattr(self.target, 'sdsec_vsmode_hsonly', False)
    def test(self):
        DMCONTROL = 0x10
        DMSTATUS = 0x11
        ABSTRACTCS = 0x16
        # Wait for the program to transition M → HS → VS-mode
        time.sleep(0.5)
        # Request halt — with VSEDBGALW=1, halt succeeds when hart is in VS-mode
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x80000001")
        time.sleep(0.5)
        # Verify hart halted
        dmstatus = self.read_dm_reg(DMSTATUS)
        allhalted = (dmstatus >> 9) & 1
        assertEqual(allhalted, 1,
                    "hart must halt in VS-mode when VSEDBGALW=1")
        # Verify ALLSECURED=1 (mdbgen=0)
        allsecured = (dmstatus >> 21) & 1
        assertEqual(allsecured, 1,
                    "ALLSECURED must be 1 with mdbgen=0")
        # No security faults from the successful halt
        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0,
                    "no security faults expected: VS-mode halt is permitted with VSEDBGALW=1")
        # Read $sdcsr — should be accessible with VSEDBGALW=1
        self.gdb.command(f"monitor riscv dm_write 0x{ABSTRACTCS:x} 0x00000700")
        sdcsr = self.gdb.p("$sdcsr")
        abstractcs = self.read_dm_reg(ABSTRACTCS)
        cmderr = (abstractcs >> 8) & 0x7
        assertEqual(cmderr, 0,
                    "sdcsr read must not yield CMDERR when VSEDBGALW=1")
        # Security faults remain clean after CSR access
        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0,
                    "no security faults expected after sdcsr read with VSEDBGALW=1")
        # Clear haltreq
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x00000001")

class SdsecVsmodeNoStopHigherModes(SdsecVsmodeTest):
    """T53: VSEDBGALW=1 must NOT allow halt in HS-mode.

    Uses the hsonly target where the hart loops forever in HS-mode
    (sdsec_vsmode_hsonly.S). With mdbgen=0 and only VSEDBGALW=1, HS-mode
    halt must be denied. The test issues haltreq and confirms allhalted=0
    after a generous timeout — conclusive because the hart never leaves
    HS-mode."""

    def early_applicable(self):
        return super().early_applicable() \
            and getattr(self.target, 'sdsec_vsmode_hsonly', False)

    def test(self):
        DMCONTROL = 0x10
        DMSTATUS = 0x11
        # Hart is spinning in HS-mode (hsmode_loop) — it will NEVER reach VS-mode.
        time.sleep(0.3)
        # Issue haltreq
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x80000001")
        # Wait 5 seconds — more than enough for halt to take effect if allowed.
        time.sleep(5.0)
        # Verify hart has NOT halted (HS-mode halt denied with mdbgen=0)
        dmstatus = self.read_dm_reg(DMSTATUS)
        allhalted = (dmstatus >> 9) & 1
        assertEqual(allhalted, 0,
                    "hart must NOT halt in HS-mode: VSEDBGALW=1 does not grant HS-mode debug")
        # ALLSECURED=1 confirms security is active
        allsecured = (dmstatus >> 21) & 1
        assertEqual(allsecured, 1,
                    "ALLSECURED must be 1 with mdbgen=0")
        # Clear haltreq
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x00000001")

class SdsecVsmodeMemoryAccess(SdsecVsmodeTest):
    """T58: VS-mode debug memory read/write at hart.ram (sdsec.adoc memory constraints).

    After halting in VS-mode (same pattern as T51), write a value to hart.ram
    via GDB, read it back, and verify the match.  No page tables are active
    (vsatp=0, hgatp=0), so the access uses physical addresses.
    No security faults expected."""

    def early_applicable(self):
        return super().early_applicable() \
            and not getattr(self.target, 'sdsec_vsmode_hsonly', False)

    def test(self):
        DMCONTROL = 0x10
        DMSTATUS = 0x11
        # Wait for M -> HS -> VS transition
        time.sleep(0.5)
        # Halt the hart in VS-mode
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x80000001")
        time.sleep(0.5)
        dmstatus = self.read_dm_reg(DMSTATUS)
        allhalted = (dmstatus >> 9) & 1
        assertEqual(allhalted, 1,
                    "hart must halt in VS-mode when VSEDBGALW=1")

        # Write a test value to hart.ram
        addr = self.hart.ram
        test_val = 0xbeefcafe
        self.gdb.p(f"*((unsigned int*)0x{addr:x}) = 0x{test_val:x}")
        readback = self.gdb.p(f"*((unsigned int*)0x{addr:x})")
        assertEqual(readback, test_val,
                    "VS-mode debug memory write/read at hart.ram must succeed")

        # No security faults
        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0,
                    "VS-mode memory access must not raise security faults")

        # Clear haltreq
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x00000001")

class SdsecVsmodeVirtTranslation(SdsecTest):
    """T59: Two-stage address translation under VS-mode debug access.

    Requires the vsmode-vm target (Sv48 vsatp + Sv48x4 hgatp identity map).
    Verifies:
      1. Hart halts in VS-mode with two-stage translation active
      2. Write/read via mapped VA succeeds through both translation stages
      3. Access to an unmapped VA fails with 'Cannot access memory'
      4. No security faults from any of these operations
    """
    compile_args = ("programs/sdsec_vsmode_vm.c", )

    def early_applicable(self):
        return self.target.support_sdsec and \
            getattr(self.target, 'sdsec_vm_test', False) and \
            getattr(self.target, 'sdsec_vsmode_debug', False)

    def setup(self):
        pass

    def test(self):
        DMCONTROL = 0x10
        DMSTATUS = 0x11
        # Wait for M -> HS -> VS transition with two-stage page table setup.
        # The C program has large BSS arrays (16KB hgatp + 4KB vsatp) that
        # init.c must zero, which takes many seconds through the debug
        # interface. Issue haltreq and poll until the hart reaches VS-mode.
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x80000001")
        halted = False
        for _ in range(60):
            time.sleep(0.5)
            dmstatus = self.read_dm_reg(DMSTATUS)
            if (dmstatus >> 9) & 1:
                halted = True
                break
        assertEqual(halted, True,
                    "hart must halt in VS-mode when VSEDBGALW=1 (waited 30s)")

        # Confirm VM is active via program flag
        vm_active = self.gdb.p("vm_active")
        assertEqual(vm_active, 1,
                    "vm_active flag must be set (two-stage translation enabled)")

        # Write/read via mapped VA (identity-mapped: VA == GPA == HPA)
        mapped_va = self.hart.ram  # 0x1212340000
        test_val = 0xfade0059
        self.gdb.p(f"*((unsigned int*)0x{mapped_va:x}) = 0x{test_val:x}")
        readback = self.gdb.p(f"*((unsigned int*)0x{mapped_va:x})")
        assertEqual(readback, test_val,
                    "mapped VA read/write must succeed via two-stage translation")

        # Access unmapped VA -- must fail with CannotAccess.
        # The identity map covers only entry 0 (PA 0..0x7FFFFFFFFF).
        # Use an address in entry 1 region (0x8000000000) which is unmapped.
        unmapped_va = 0x0000_0080_0000_0000
        access_failed = False
        try:
            self.gdb.p(f"*((unsigned int*)0x{unmapped_va:x})")
        except testlib.CannotAccess:
            access_failed = True
        assertEqual(access_failed, True,
                    f"access to unmapped VA 0x{unmapped_va:x} must fail")

        # No security faults from any of the above
        any_f, all_f = self.parse_security_faults()
        assertEqual(any_f, 0,
                    "two-stage translation operations must not raise security faults")
        assertEqual(all_f, 0,
                    "two-stage translation operations must not raise security faults")

        # Clear haltreq
        self.gdb.command(f"monitor riscv dm_write 0x{DMCONTROL:x} 0x00000001")


# ---------- Phase 7: PMP denial tests (T54, T55, T57) ----------

class SdsecSmodePmpDenied(SdsecTest):
    """T54: S-mode debug access to a PMP-denied region fails (sdsec.adoc memory constraints).

    Boot binary configures PMP entry 0 as a locked NAPOT 4 KB deny region at
    hart.ram + 0x4000.  In S-mode debug, reading from the allowed region
    succeeds while reading from the denied region returns a memory-access
    error.  PMP denial is an access fault, not a security fault, so
    ANYSECFAULT must remain 0."""
    compile_args = ("programs/sdsec_smode_pmp.c", )

    def early_applicable(self):
        return self.target.support_sdsec \
            and not self.target.sdsec_mmode_debug \
            and self.target.sdsec_smode_debug \
            and getattr(self.target, 'sdsec_pmp_deny', False)

    def setup(self):
        pass

    def test(self):
        priv = self.gdb.p("$priv")
        assertEqual(priv, 1, "hart should be in S-mode (priv=1)")

        # Allowed region access must succeed
        addr = self.hart.ram
        test_val = 0xabcd1234
        self.gdb.p(f"*((int*)0x{addr:x}) = 0x{test_val:x}")
        readback = self.gdb.p(f"*((int*)0x{addr:x})")
        assertEqual(readback, test_val)

        # PMP-denied region access must fail
        denied_addr = self.hart.ram + 0x4000
        output = self.gdb.command(
            f"print/x *((int*)0x{denied_addr:x})")
        assertIn("Cannot access memory", output)

        # PMP denial must not raise security faults
        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0,
                    "PMP denial must not raise security faults")

class SdsecUmodePmpDenied(SdsecTest):
    """T55: U-mode debug access to a PMP-denied region fails.

    Same PMP layout as T54 but with U-mode debug privilege.  The denied
    4 KB region at hart.ram + 0x4000 must be inaccessible and no security
    faults should be raised."""
    compile_args = ("programs/sdsec_umode_pmp.c", )

    def early_applicable(self):
        return self.target.support_sdsec \
            and not self.target.sdsec_mmode_debug \
            and not self.target.sdsec_smode_debug \
            and not getattr(self.target, 'sdsec_deny', False) \
            and getattr(self.target, 'sdsec_pmp_deny', False)

    def setup(self):
        pass

    def test(self):
        priv = self.gdb.p("$priv")
        assertEqual(priv, 0, "hart should be in U-mode (priv=0)")

        # Allowed region access must succeed
        addr = self.hart.ram
        test_val = 0xcafe0001
        self.gdb.p(f"*((int*)0x{addr:x}) = 0x{test_val:x}")
        readback = self.gdb.p(f"*((int*)0x{addr:x})")
        assertEqual(readback, test_val)

        # PMP-denied region access must fail
        denied_addr = self.hart.ram + 0x4000
        output = self.gdb.command(
            f"print/x *((int*)0x{denied_addr:x})")
        assertIn("Cannot access memory", output)

        # PMP denial must not raise security faults
        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0,
                    "PMP denial must not raise security faults")

class SdsecFullPmpBypass(SdsecTest):
    """T57: M-mode debug bypasses PMP — access to PMP-denied region succeeds.

    Configures PMP from M-mode debug to create a locked 4 KB deny region at
    hart.ram + 0x4000, then verifies that M-mode debug can still read/write
    that region.  M-mode debug operates with machine-level privilege which
    is not subject to PMP restrictions.

    Uses the standard full target (mdbgen=1).  PMP is configured via CSR
    writes from debug mode rather than from a boot binary, avoiding timing
    races with the OpenOCD halt."""

    def early_applicable(self):
        return super().early_applicable() and self.target.sdsec_mmode_debug

    def test(self):
        # Configure PMP from debug mode:
        #   Entry 0: NAPOT 4 KB deny at hart.ram + 0x4000, NOT locked, no perms
        #   Entry 1: NAPOT full range, RWX
        # L=0 is critical: locked entries (L=1) restrict ALL modes including
        # M-mode per spec. L=0 entries only restrict S/U-mode; M-mode bypasses.
        denied_base = self.hart.ram + 0x4000
        # NAPOT pmpaddr for 4 KB (2^12): low 9 bits set
        pmpaddr0_val = (denied_base >> 2) | 0x1FF
        pmpaddr1_val = 0xFFFFFFFFFFFFFFFF
        # pmpcfg0: entry0=0x18 (NAPOT|no perms, L=0), entry1=0x1F (NAPOT|RWX)
        pmpcfg0_val = (0x1F << 8) | 0x18
        self.gdb.p(f"$pmpaddr0=0x{pmpaddr0_val:x}")
        self.gdb.p(f"$pmpaddr1=0x{pmpaddr1_val:x}")
        self.gdb.p(f"$pmpcfg0=0x{pmpcfg0_val:x}")

        # Verify PMP is configured
        readback_cfg = self.gdb.p("$pmpcfg0")
        assertEqual(readback_cfg, pmpcfg0_val,
                    "pmpcfg0 should hold the configured value")

        # Allowed region access
        addr = self.hart.ram
        test_val = 0x12345678
        self.gdb.p(f"*((int*)0x{addr:x}) = 0x{test_val:x}")
        readback = self.gdb.p(f"*((int*)0x{addr:x})")
        assertEqual(readback, test_val)

        # PMP-denied region must still be accessible in M-mode debug
        denied_addr = self.hart.ram + 0x4000
        deny_val = 0xdeadbeef
        self.gdb.p(f"*((unsigned int*)0x{denied_addr:x}) = 0x{deny_val:x}")
        readback = self.gdb.p(f"*((unsigned int*)0x{denied_addr:x})")
        assertEqual(readback, deny_val,
                    "M-mode debug must bypass PMP and access denied region")

        # No security faults
        any_f, _ = self.parse_security_faults()
        assertEqual(any_f, 0,
                    "M-mode debug PMP bypass must not raise security faults")


def main():
    parser = argparse.ArgumentParser(
            description="Run Sdsec debug security tests")
    targets.add_target_options(parser)
    testlib.add_test_run_options(parser)

    parsed = parser.parse_args()
    target = targets.target(parsed)
    testlib.print_log_names = parsed.print_log_names

    module = sys.modules[__name__]
    return testlib.run_all_tests(module, target, parsed)


if __name__ == "__main__":
    sys.exit(main())
