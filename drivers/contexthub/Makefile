ccflags-y  += -I$(srctree)/drivers/huawei_platform/inputhub/$(TARGET_BOARD_PLATFORM)/
EXTRA_CFLAGS += -Idrivers/hisi/tzdriver

obj-$(CONFIG_CONTEXTHUB) += inputhub_api.o common.o
obj-$(CONFIG_CONTEXTHUB_SHMEM) += shmem.o
obj-$(CONFIG_CONTEXTHUB_LOADMONITOR) += loadmonitor.o
obj-$(CONFIG_HISI_FLP)   += flp/
