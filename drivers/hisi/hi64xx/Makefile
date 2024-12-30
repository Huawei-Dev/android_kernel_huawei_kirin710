subdir-ccflags-y += -Wall -Werror

EXTRA_CFLAGS += -Idrivers/hisi/hi64xx_dsp/
EXTRA_CFLAGS += -Idrivers/hisi/soundtrigger/
EXTRA_CFLAGS += -Isound/soc/codecs/hisi/hi6xxx_fpga_test/
EXTRA_CFLAGS += -Isound/soc/codecs/hisi/hs_auto_calib/
EXTRA_CFLAGS += -Idrivers/hisi/mntn/blackbox/platform_hifi/

ifeq ($(CLT_IV), true)
EXTRA_CFLAGS += -DCLT_AUDIO
endif

ifeq ($(CONFIG_HI6402_MBHC_ANC),y)
EXTRA_CFLAGS += -DANC_HEADSET
EXTRA_CFLAGS += -DINVERT_HEADSET
endif

ccflags-y += -Idrivers/devkit/audiokit/

obj-y += hi_cdc_ctrl.o
obj-y += hi_cdc_ssi.o
obj-y += hi64xx_resmgr.o
obj-y += hi64xx_mbhc.o
obj-y += hi64xx_irq.o
obj-y += hi64xx_compat.o
obj-y += hi64xx_utils.o
obj-y += hi64xx_vad.o
obj-y += asp_dma.o
