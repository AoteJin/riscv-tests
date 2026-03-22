import os
import targets
import testlib

class spike32_sdsec_locked_hart(targets.Hart):
    xlen = 32
    ram = 0x10100000
    ram_size = 0x10000000
    bad_address = ram - 8
    instruction_hardware_breakpoint_count = 4
    reset_vectors = [0x1000]
    link_script_path = "spike32.lds"

class spike32_sdsec_locked(targets.Target):
    harts = [spike32_sdsec_locked_hart(misa=0x4034112d)]
    openocd_config_path = "spike-sdsec-nohalt.cfg"
    timeout_sec = 180
    implements_custom_test = True
    support_memory_sampling = False
    support_unavailable_control = True

    sdsec_mdbgen = 0
    sdsec_mdtcfg = 0  # all debug disabled

    def create(self):
        os.environ['RISCV_MDBGEN_INIT'] = str(self.sdsec_mdbgen)
        os.environ['RISCV_MDTCFG_INIT'] = str(self.sdsec_mdtcfg)
        return testlib.Spike(self, isa="RV32IMAFDCV_sdsec", dmi_rti=4,
                support_abstract_csr=True, support_haltgroups=False,
                elen=64)
