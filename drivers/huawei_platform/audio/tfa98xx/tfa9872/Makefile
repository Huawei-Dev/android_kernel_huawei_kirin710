# tfa9872 smartPA driver

ccflags-$(CONFIG_TFA9872) += -Idrivers/devkit/audiokit/
ifneq ($(TARGET_BUILD_VARIANT),user)
EXTRA_CFLAGS += -DTFA9872_DEBUG
endif
obj-$(CONFIG_TFA9872)	+= tfa9872.o
