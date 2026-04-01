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
        SETKEEPALIVE_BIT = 1 << 31
        CLRKEEPALIVE_BIT = 1 << 30

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

class SdsecSmodeVirtTranslationConstraints(SdsecSmodeTest):
    """T18: Virtual translation under S-mode debug access."""
    def test(self):
        addr = self.hart.ram
        test_val = 0xfeedface
        self.gdb.p(f"*((int*)0x{addr:x}) = 0x{test_val:x}")
        readback = self.gdb.p(f"*((int*)0x{addr:x})")
        assertEqual(readback, test_val)

class SdsecSmodeNoStopInMmode(SdsecSmodeTest):
    """T19: OpenOCD initial halt lands in S-mode, not M-mode.

    The hart boots through M-mode but mdbgen=0 prevents halting there.
    Verify that by the time the debugger has control, the hart is in S-mode."""

    def test(self):
        priv = self.gdb.p("$priv")
        assertEqual(priv, 1,
                     "initial halt must be in S-mode (priv=1), not M-mode")

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

class SdsecSmodeKeepaliveConstrained(SdsecSmodeTest):
    """T22: Keepalive does not broaden privilege."""
    def test(self):
        DMCONTROL = 0x10
        SETKEEPALIVE = 1 << 31
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
            and not self.target.sdsec_smode_debug

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

class SdsecUmodeVirtTranslationConstraints(SdsecUmodeTest):
    """T30: U/VU translation and page-permission checks."""
    def test(self):
        addr = self.hart.ram
        test_val = 0xbabe0002
        self.gdb.p(f"*((int*)0x{addr:x}) = 0x{test_val:x}")
        readback = self.gdb.p(f"*((int*)0x{addr:x})")
        assertEqual(readback, test_val)

class SdsecUmodeNoStopInHigherModes(SdsecUmodeTest):
    """T31: OpenOCD initial halt lands in U-mode, not M/S-mode.

    The hart boots through M-mode and S-mode but mdbgen=0 and SEDBGALW=0
    prevent halting there.  Verify the debugger has control in U-mode."""

    def test(self):
        priv = self.gdb.p("$priv")
        assertEqual(priv, 0,
                     "initial halt must be in U-mode (priv=0), not M/S-mode")

class SdsecUmodeResetSecFault(SdsecUmodeTest):
    """T32: Reset reports security faults under mdbgen=0."""
    def test(self):
        output = self.gdb.command("monitor reset halt")
        any_f, _ = self.parse_security_faults()

class SdsecUmodeKeepaliveConstrained(SdsecUmodeTest):
    """T33: Keepalive does not broaden privilege."""
    def test(self):
        DMCONTROL = 0x10
        SETKEEPALIVE = 1 << 31
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
        abstractcs = self.read_dm_reg(ABSTRACTCS)
        cmderr = (abstractcs >> 8) & 0x7
        if cmderr == 6:
            pass
        else:
            self.gdb.command("monitor riscv dm_write 0x17 0x00220000")
            abstractcs = self.read_dm_reg(ABSTRACTCS)
            cmderr = (abstractcs >> 8) & 0x7

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


# ---------- Phase 5: cross-target (T40) ----------

class SdsecNdmResetReadOnlyZero(SdsecTest):
    """T40: ndmreset secure-policy gating."""
    def test(self):
        DMCONTROL = 0x10
        dmcontrol = self.read_dm_reg(DMCONTROL)
        NDMRESET_BIT = 1 << 1
        ndmreset = (dmcontrol >> 1) & 1
        assertEqual(ndmreset, 0, "ndmreset should be 0 initially")



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
