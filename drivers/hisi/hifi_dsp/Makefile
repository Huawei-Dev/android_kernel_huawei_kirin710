subdir-ccflags-y += -Wall -Werror

ifeq ($(CLT_IV),true)
EXTRA_CFLAGS += -DCLT_VOICE
endif

ifeq ($(CFG_CONFIG_HISI_FAMA),true)
LOCAL_CFLAGS += -DCONFIG_HISI_FAMA
endif

ifeq ($(CONFIG_HISI_FB_970),y)
EXTRA_CFLAGS += -DCONFIG_DP_MULTI_CHANNELS
endif

ifeq ($(CONFIG_HISI_FB_V501),y)
EXTRA_CFLAGS += -DCONFIG_DP_MULTI_CHANNELS
endif

ifeq ($(CONFIG_HIFI_IPC_3660),y)
EXTRA_CFLAGS += -Iinclude/modem/include/config/hi365x
EXTRA_CFLAGS += -Iinclude/modem/include/drv/hi365x
endif

ifeq ($(CONFIG_SND_SOC_HI6402),y)
EXTRA_CFLAGS += -DMULTI_MIC
endif

EXTRA_CFLAGS += -Idrivers/hisi/hifi_mailbox/mailbox
EXTRA_CFLAGS += -Idrivers/hisi/hifi_mailbox/ipcm
EXTRA_CFLAGS += -Isound/usb/hifi/

obj-$(CONFIG_HIFI_DSP_ONE_TRACK)	+= hifi_lpp.o
obj-$(CONFIG_HIFI_DSP_ONE_TRACK)	+= hifi_om.o

ifneq ($(HISI_EXTERNAL_MODEM), )
obj-$(CONFIG_HIFI_DSP_ONE_TRACK)	+= audio_pcie_proc.o
obj-$(CONFIG_HIFI_DSP_ONE_TRACK)	+= b5000_strategy_acore.o
EXTRA_CFLAGS += -DHISI_EXTERNAL_MODEM
endif

obj-y	+= voice_proxy/
ccflags-$(CONFIG_HIFI_DSP_ONE_TRACK) += -Idrivers/devkit/audiokit/
