.PHONY: default
default: all

VERSION = 00bet4
XMLDIR = v8.3

A64 = ${XMLDIR}/ISA_v83A_A64_xml_$(VERSION)
A32 = ${XMLDIR}/ISA_v83A_AArch32_xml_$(VERSION)
SYSREG = ${XMLDIR}/SysReg_v83A_xml-$(VERSION)


regs.asl: ${SYSREG}
	bin/reg2asl.py $< -o $@

arch.asl arch.tag: ${A32} ${A64}
	bin/instrs2asl.py $^

all :: regs.asl
all :: arch.asl

clean ::
	$(RM) regs.asl arch.asl arch.tag


clean ::
	$(MAKE) -C src clean


# End
