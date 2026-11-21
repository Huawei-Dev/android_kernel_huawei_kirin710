# SPDX-License-Identifier: GPL-2.0
# arch/arm64/boot/dts/hisilicon/Makefile

# Kirin 710: only ONE family is built per kernel build.
# Preferred selector: the device's kernel .config, with exactly one of:
#   CONFIG_KIRIN710_DTB_SNE=y  (sydneym)
#   CONFIG_KIRIN710_DTB_POT=y
#   CONFIG_KIRIN710_DTB_MAR=y
# Alternatively, pass KIRIN710_DTB_FAMILY=sne|pot|mar to kernel make.
# Simply running "brunch sydneym" does NOT set a Kbuild variable unless
# its kernel configuration or build invocation supplies that selection.

kirin710_from_config := $(strip \
	$(if $(filter y,$(CONFIG_KIRIN710_DTB_SNE)),sne) \
	$(if $(filter y,$(CONFIG_KIRIN710_DTB_POT)),pot) \
	$(if $(filter y,$(CONFIG_KIRIN710_DTB_MAR)),mar))

ifneq ($(word 2,$(kirin710_from_config)),)
$(error Kirin710: multiple DTB families enabled in kernel configuration: $(kirin710_from_config))
endif

kirin710_family := $(strip $(KIRIN710_DTB_FAMILY))
ifeq ($(kirin710_family),)
kirin710_family := $(kirin710_from_config)
else
ifneq ($(kirin710_from_config),)
ifneq ($(kirin710_family),$(kirin710_from_config))
$(error Kirin710: KIRIN710_DTB_FAMILY=$(kirin710_family) conflicts with $(kirin710_from_config) from .config)
endif
endif
endif

ifeq ($(kirin710_family),)
# Existing HiSilicon reference boards: only if no Kirin710 family is selected.
dtb-$(CONFIG_ARCH_HISI) += hi3660-hikey960.dtb
dtb-$(CONFIG_ARCH_HISI) += hi3798cv200-poplar.dtb
dtb-$(CONFIG_ARCH_HISI) += hi6220-hikey.dtb
dtb-$(CONFIG_ARCH_HISI) += hip05-d02.dtb
dtb-$(CONFIG_ARCH_HISI) += hip06-d03.dtb
dtb-$(CONFIG_ARCH_HISI) += hip07-d05.dtb

endif

ifneq ($(kirin710_family),)
ifeq ($(filter $(kirin710_family),sne pot mar),)
$(error Kirin710: invalid KIRIN710_DTB_FAMILY=$(kirin710_family); use sne, pot or mar)
endif

ifneq ($(CONFIG_ARCH_HISI),y)
$(error Kirin710: selected $(kirin710_family) but CONFIG_ARCH_HISI is not y)
endif

# These DTS source directories live next to this Makefile.
# The wildcard discovers every variant without maintaining 16/40/57 names
# by hand. Only the selected family's DTBs enter dtb-y.
sne_dtb_members := $(patsubst $(srctree)/$(src)/%.dts,%.dtb,$(wildcard $(srctree)/$(src)/sne/*.dts))
pot_dtb_members := $(patsubst $(srctree)/$(src)/%.dts,%.dtb,$(wildcard $(srctree)/$(src)/pot/*.dts))
mar_dtb_members := $(patsubst $(srctree)/$(src)/%.dts,%.dtb,$(wildcard $(srctree)/$(src)/mar/*.dts))

kirin710_dtb_members := $($(kirin710_family)_dtb_members)
kirin710_catalog := $(kirin710_family)_catalog.dtb
kirin710_generator := $(srctree)/$(src)/make_$(kirin710_family)_catalog.py

ifeq ($(strip $(kirin710_dtb_members)),)
$(error Kirin710: no DTS members found under $(src)/$(kirin710_family)/)
endif

# Compile member DTS -> member DTB, then assemble only the matching catalog.
dtb-$(CONFIG_ARCH_HISI) += $(kirin710_dtb_members)
dtb-$(CONFIG_ARCH_HISI) += $(kirin710_catalog)

quiet_cmd_kirin710_catalog = K710CAT $@
      cmd_kirin710_catalog = python3 $(kirin710_generator) \
	--output $@ --dtc $(DTC) \
	$(foreach m,$(kirin710_dtb_members),--dtb $(obj)/$(m))

$(obj)/$(kirin710_catalog): $(addprefix $(obj)/,$(kirin710_dtb_members)) \
	$(kirin710_generator) FORCE
	$(call if_changed,kirin710_catalog)

targets += $(kirin710_catalog)
clean-files += $(kirin710_dtb_members) $(kirin710_family)_catalog.dts
endif

always := $(dtb-y)
subdir-y := $(dts-dirs)
clean-files += *.dtb
