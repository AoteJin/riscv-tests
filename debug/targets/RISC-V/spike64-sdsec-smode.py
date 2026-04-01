import os
import targets
import testlib

class spike64_sdsec_smode_hart(targets.Hart):
    xlen = 64
    ram = 0x1212340000
    ram_size = 0x10000000
    bad_address = ram - 8
    instruction_hardware_breakpoint_count = 4
    reset_vectors = [0x1000]
    link_script_path = "spike64.lds"
    misa = 0x8000000000141125

class spike64_sdsec_smode(targets.Target):
    harts = [spike64_sdsec_smode_hart()]
    openocd_config_path = "spike-sdsec-smode.cfg"
    timeout_sec = 180
    support_sdsec = True
    sdsec_mmode_debug = False
    sdsec_smode_debug = True
    support_memory_sampling = False

    def create(self):
        os.environ['RISCV_MDBGEN_INIT'] = '0'
        os.environ['RISCV_MDTCFG_INIT'] = '0x1'
        return testlib.Spike(self, isa="RV64IMAFC_sdsec",
                abstract_rti=30, support_abstract_csr=True,
                support_abstract_fpr=True,
                init_compile_args=("programs/sdsec_smode.c",))
