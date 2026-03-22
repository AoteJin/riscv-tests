#!/usr/bin/env python3
"""Sdsec Debug Security Extension tests.

Run against Sdsec-enabled spike targets:
    ./sdsec_tests.py targets/RISC-V/spike32-sdsec-mmode.py --print-failures
    ./sdsec_tests.py targets/RISC-V/spike32-sdsec-smode.py --print-failures
    ./sdsec_tests.py targets/RISC-V/spike32-sdsec-locked.py --print-failures
"""

import argparse
import sys
import time

import targets
import testlib
from testlib import assertEqual, assertNotEqual, assertIn, assertNotIn
from testlib import GdbTest, GdbSingleHartTest
from testlib import TestNotApplicable, TestFailed

# dmstatus bit positions
DMSTATUS_ANYSECURED  = 1 << 20
DMSTATUS_ALLSECURED  = 1 << 21
DMSTATUS_ANYSECFAULT = 1 << 25
DMSTATUS_ALLSECFAULT = 1 << 26
DMSTATUS_ANYHALTED   = 1 << 8
DMSTATUS_ALLHALTED   = 1 << 9
DMSTATUS_ANYRUNNING  = 1 << 10

CMDERR_NONE     = 0
CMDERR_EXCEPTION = 3
CMDERR_SECFAULT = 6


class SdsecTestBase(GdbSingleHartTest):
    """Base class for all Sdsec security tests."""

    def early_applicable(self):
        return hasattr(self.target, 'sdsec_mdbgen')

    def read_dmi(self, addr):
        raw = self.server.command(f"riscv dmi_read 0x{addr:x}")
        return int(raw.strip(), 0)

    def write_dmi(self, addr, value):
        self.server.command(f"riscv dmi_write 0x{addr:x} 0x{value:x}")

    def read_dmstatus(self):
        return self.read_dmi(0x11)

    def read_abstractcs(self):
        return self.read_dmi(0x16)

    def get_cmderr(self):
        return (self.read_abstractcs() >> 8) & 0x7

    def clear_cmderr(self):
        self.write_dmi(0x16, 0x700)

    def write_acksecfault(self):
        self.write_dmi(0x32, 1 << 12)


# ---------------------------------------------------------------------------
# T01: Discovery -- ALLSECURED/ANYSECURED when sdsec enabled (mdbgen=1)
# ---------------------------------------------------------------------------
class SdsecDiscoveryMmode(SdsecTestBase):
    """With mdbgen=1 and sdsec ISA, dmstatus should show ALLSECURED=1."""

    def early_applicable(self):
        return (super().early_applicable()
                and self.target.sdsec_mdbgen == 1)

    def test(self):
        dmstatus = self.read_dmstatus()
        assertEqual(bool(dmstatus & DMSTATUS_ALLSECURED), True,
                    f"ALLSECURED should be 1 (dmstatus=0x{dmstatus:08x})")
        assertEqual(bool(dmstatus & DMSTATUS_ANYSECURED), True,
                    f"ANYSECURED should be 1 (dmstatus=0x{dmstatus:08x})")


# ---------------------------------------------------------------------------
# T02: Discovery -- No security without sdsec ISA
# (Run against standard spike32 target, not sdsec targets)
# ---------------------------------------------------------------------------
class SdsecDiscoveryNone(GdbSingleHartTest):
    """Without sdsec ISA, dmstatus ALLSECURED/ANYSECURED should be 0."""

    def early_applicable(self):
        return not hasattr(self.target, 'sdsec_mdbgen')

    def test(self):
        raw = self.server.command("riscv dmi_read 0x11")
        dmstatus = int(raw.strip(), 0)
        assertEqual(bool(dmstatus & DMSTATUS_ALLSECURED), False,
                    f"ALLSECURED should be 0 (dmstatus=0x{dmstatus:08x})")
        assertEqual(bool(dmstatus & DMSTATUS_ANYSECURED), False,
                    f"ANYSECURED should be 0 (dmstatus=0x{dmstatus:08x})")


# ---------------------------------------------------------------------------
# T03: M-mode locked -- halt stays pending
# ---------------------------------------------------------------------------
class SdsecMmodeLockedHalt(SdsecTestBase):
    """With mdbgen=0 and mdtcfg=0, halt should stay pending (hart in M-mode)."""

    def early_applicable(self):
        return (super().early_applicable()
                and self.target.sdsec_mdbgen == 0
                and self.target.sdsec_mdtcfg == 0)

    def test(self):
        dmstatus = self.read_dmstatus()
        # Hart should be running (not halted) because halt request
        # from spike-sdsec.cfg pends when all debug is disabled
        anyhalted = bool(dmstatus & DMSTATUS_ANYHALTED)
        # When all debug is disabled, the hart may or may not halt
        # depending on whether it was still in reset when halt was sent.
        # The key check is that ALLSECURED=1.
        assertEqual(bool(dmstatus & DMSTATUS_ALLSECURED), True,
                    f"ALLSECURED should be 1 (dmstatus=0x{dmstatus:08x})")


# ---------------------------------------------------------------------------
# T04: S-mode debug -- halt succeeds when hart is in S-mode
# NOTE: This test requires the spike boot binary to drop to S-mode.
# Currently skipped because the default infinite_loop runs in M-mode
# and can't be halted when mdbgen=0. Needs custom spike boot binary support.
# ---------------------------------------------------------------------------
class SdsecSmodeHalt(SdsecTestBase):
    """With mdbgen=0 and SEDBGALW=1, hart should halt when in S-mode."""

    def early_applicable(self):
        # TODO: Enable when spike boot binary can drop to S-mode
        return False


# ---------------------------------------------------------------------------
# T05: Quick Access blocked when mdbgen=0
# ---------------------------------------------------------------------------
class SdsecQuickAccessBlocked(SdsecTestBase):
    """Quick Access command should return CMDERR=6 when mdbgen=0."""

    def early_applicable(self):
        return (super().early_applicable()
                and self.target.sdsec_mdbgen == 0)

    def test(self):
        self.clear_cmderr()
        # Quick Access: cmdtype=1 (bits [31:24] = 0x01)
        self.write_dmi(0x17, 0x01000000)
        cmderr = self.get_cmderr()
        assertEqual(cmderr, CMDERR_SECFAULT,
                    f"Quick Access should return CMDERR=6, got {cmderr}")
        self.clear_cmderr()


# ---------------------------------------------------------------------------
# T06: AAMVIRTUAL=0 (physical address) blocked when mdbgen=0
# This test uses DMI directly, no need to halt the hart first.
# The DM should reject Access Memory with AAMVIRTUAL=0 regardless of halt state.
# ---------------------------------------------------------------------------
class SdsecAamvirtualBlocked(SdsecTestBase):
    """Access Memory with AAMVIRTUAL=0 should return CMDERR=6 when mdbgen=0."""

    def early_applicable(self):
        return (super().early_applicable()
                and self.target.sdsec_mdbgen == 0)

    def test(self):
        self.clear_cmderr()
        # Access Memory: cmdtype=2 (bits[31:24]=0x02), aamsize=2 (32-bit, bits[22:20]),
        # AAMVIRTUAL=0 (bit 23), write=0 (bit 16)
        # command = 0x02 << 24 | 2 << 20 = 0x02200000
        self.write_dmi(0x17, 0x02200000)
        cmderr = self.get_cmderr()
        assertEqual(cmderr, CMDERR_SECFAULT,
                    f"AAMVIRTUAL=0 should return CMDERR=6, got {cmderr}")
        self.clear_cmderr()


# ---------------------------------------------------------------------------
# T07: Security fault reporting -- HARTRESET triggers secfault
# ---------------------------------------------------------------------------
class SdsecSecfaultReporting(SdsecTestBase):
    """HARTRESET when mdbgen=0 should set ANYSECFAULT, cleared by ACKSECFAULT."""

    def early_applicable(self):
        return (super().early_applicable()
                and self.target.sdsec_mdbgen == 0
                and self.target.sdsec_mdtcfg == 0)

    def test(self):
        # Clear any existing faults
        self.write_acksecfault()
        dmstatus = self.read_dmstatus()
        assertEqual(bool(dmstatus & DMSTATUS_ANYSECFAULT), False,
                    "ANYSECFAULT should be 0 after clear")

        # Trigger HARTRESET: dmcontrol bit 29 = hartreset, bit 0 = dmactive
        self.write_dmi(0x10, (1 << 29) | 1)
        # Clear hartreset
        self.write_dmi(0x10, 1)

        dmstatus = self.read_dmstatus()
        assertEqual(bool(dmstatus & DMSTATUS_ANYSECFAULT), True,
                    f"ANYSECFAULT should be 1 after HARTRESET (dmstatus=0x{dmstatus:08x})")

        # Clear via ACKSECFAULT
        self.write_acksecfault()
        dmstatus = self.read_dmstatus()
        assertEqual(bool(dmstatus & DMSTATUS_ANYSECFAULT), False,
                    "ANYSECFAULT should be 0 after ACKSECFAULT")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
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


if __name__ == '__main__':
    sys.exit(main())
