import os
import targets
import testlib

class spike64_sdsec_vumode_hart(targets.Hart):
    xlen = 64
    ram = 0x1212340000
    ram_size = 0x10000000
    bad_address = ram - 8
    instruction_hardware_breakpoint_count = 4
    reset_vectors = [0x1000]
    link_script_path = "spike64.lds"
    misa = 0x80000000001411a5  # H extension (bit 7)

class spike64_sdsec_vumode(targets.Target):
    harts = [spike64_sdsec_vumode_hart()]
    openocd_config_path = "spike-sdsec-vsmode.cfg"
    timeout_sec = 180
    support_sdsec = True
    support_memory_sampling = False

    sdsec_mdbgen = 0
    sdsec_mdtcfg = 4  # bit 2 = UEDBGALW (shared U/VU)

    sdsec_mmode_debug = False
    sdsec_smode_debug = False
    sdsec_vsmode_debug = False
    sdsec_vumode_debug = True

    def create(self):
        os.environ['RISCV_MDBGEN_INIT'] = str(self.sdsec_mdbgen)
        os.environ['RISCV_MDTCFG_INIT'] = str(self.sdsec_mdtcfg)
        return testlib.Spike(self, isa="RV64IMAFCH_sdsec",
                abstract_rti=30, support_abstract_csr=True,
                support_abstract_fpr=True,
                init_compile_args=("programs/sdsec_vumode.S",))
