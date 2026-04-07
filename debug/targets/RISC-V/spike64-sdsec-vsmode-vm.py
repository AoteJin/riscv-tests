import os
import targets
import testlib

class spike64_sdsec_vsmode_vm_hart(targets.Hart):
    xlen = 64
    ram = 0x1212340000
    ram_size = 0x10000000
    bad_address = ram - 8
    instruction_hardware_breakpoint_count = 4
    reset_vectors = [0x1000]
    link_script_path = "spike64.lds"
    misa = 0x80000000001411a5  # H extension (bit 7) added for VS-mode

class spike64_sdsec_vsmode_vm(targets.Target):
    harts = [spike64_sdsec_vsmode_vm_hart()]
    openocd_config_path = "spike-sdsec-vsmode.cfg"
    timeout_sec = 180
    support_sdsec = True
    support_memory_sampling = False

    sdsec_mdbgen = 0
    sdsec_mdtcfg = 2  # bit 1 = VSEDBGALW

    sdsec_mmode_debug = False
    sdsec_smode_debug = False
    sdsec_vsmode_debug = True
    sdsec_vm_test = True

    def create(self):
        os.environ['RISCV_MDBGEN_INIT'] = str(self.sdsec_mdbgen)
        os.environ['RISCV_MDTCFG_INIT'] = str(self.sdsec_mdtcfg)
        return testlib.Spike(self, isa="RV64IMAFCH_sdsec",
                abstract_rti=30, support_abstract_csr=True,
                support_abstract_fpr=True,
                init_compile_args=("programs/sdsec_vsmode_vm.c",))
