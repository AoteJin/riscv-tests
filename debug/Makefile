XLEN ?= 64

src_dir ?= .
GDBSERVER_PY = $(src_dir)/gdbserver.py
SDSEC_PY = $(src_dir)/sdsec_tests.py
TESTS = $(shell $(GDBSERVER_PY) --list-tests $(src_dir)/targets/RISC-V/spike32.py)
MULTI_TESTS = $(shell $(GDBSERVER_PY) --list-tests $(src_dir)/targets/RISC-V/spike32.py | \
	      grep -i multi)
SDSEC_TESTS = $(shell $(SDSEC_PY) --list-tests $(src_dir)/targets/RISC-V/spike64-sdsec-full.py)

default: spike$(XLEN) spike$(XLEN)-2

all-tests: spike32 spike-multi-limited spike32-2 spike32-2-hwthread \
	spike64 spike64-2 spike64-2-hwthread

slow-tests:	spike-multi all-tests

all:	pylint all-tests

run.%:
	$(GDBSERVER_PY) \
		$(src_dir)/targets/RISC-V/$(word 2, $(subst ., ,$@)).py \
		$(word 3, $(subst ., ,$@)) \
		--isolate \
		--print-failures \
		$(if $(EXCLUDE_TESTS),--exclude-tests $(EXCLUDE_TESTS))

# Sdsec test runner (uses sdsec_tests.py instead of gdbserver.py)
sdsec-run.%:
	$(SDSEC_PY) \
		$(src_dir)/targets/RISC-V/$(word 2, $(subst ., ,$@)).py \
		$(word 3, $(subst ., ,$@)) \
		--isolate \
		--print-failures \
		$(if $(EXCLUDE_TESTS),--exclude-tests $(EXCLUDE_TESTS))

# Target to check all the multicore options.
multi-tests: spike32-2 spike32-2-hwthread

pylint:
	pylint --rcfile=pylint.rc `git ls-files '*.py'`

spike-multi-limited:	$(foreach test, $(MULTI_TESTS), run.spike-multi.$(test))
	echo Finished $@

spike%:	$(foreach test, $(TESTS), run.spike%.$(test))
	echo Finished $@

# ---- Sdsec targets ----

SDSEC_TARGETS_QUICK = spike64-sdsec-full spike64-sdsec-smode spike64-sdsec-deny
SDSEC_TARGETS_ALL = $(SDSEC_TARGETS_QUICK) \
	spike64-sdsec-umode spike64-sdsec-vsmode \
	spike64-sdsec-smode-vm spike64-sdsec-umode-vm spike64-sdsec-vsmode-vm \
	spike64-sdsec-smode-monly spike64-sdsec-umode-sonly spike64-sdsec-vsmode-hsonly \
	spike64-sdsec-smode-pmp spike64-sdsec-umode-pmp \
	spike64-sdsec-vumode spike64-sdsec-vumode-vsonly

sdsec-quick: $(foreach target, $(SDSEC_TARGETS_QUICK), sdsec-$(target))
	echo Finished $@

sdsec-tests: $(foreach target, $(SDSEC_TARGETS_ALL), sdsec-$(target))
	echo Finished $@

sdsec-%:	$(foreach test, $(SDSEC_TESTS), sdsec-run.%.$(test))
	echo Finished $@

clean:
	rm -f *.pyc
