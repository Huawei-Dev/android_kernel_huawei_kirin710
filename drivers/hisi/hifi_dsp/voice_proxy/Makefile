# hifi dsp device driver
EXTRA_CFLAGS += -Idrivers/hisi/hifi_mailbox/mailbox
EXTRA_CFLAGS += -Idrivers/hisi/hifi_mailbox/ipcm

ifeq ($(CONFIG_AUDIO_DEBUG),y)
EXTRA_CFLAGS += -DENABLE_HIFI_DEBUG
endif

EXTRA_CFLAGS += -Idrivers/hisi/hifi_dsp

obj-$(CONFIG_VOICE_PROXY) += voice_proxy.o
obj-$(CONFIG_VOICE_PROXY_VOLTE) += voice_proxy_volte.o
obj-$(CONFIG_VOICE_PROXY_VOWIFI) += voice_proxy_vowifi.o
obj-$(CONFIG_VOICE_PROXY_FUSION) += voice_proxy_fusion.o
