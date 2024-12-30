obj-$(CONFIG_HISI_COUL_HI6555V200)      += hi6xxx/

EXTRA_CFLAGS += -Idrivers/hisi/tzdriver/libhwsecurec/

ccflags-y  += -I$(srctree)/drivers/huawei_platform/inputhub/$(TARGET_BOARD_PLATFORM)/

ifneq ($(TARGET_BUILD_VARIANT),user)
ccflags-y += -DISC_TEST
endif

obj-$(CONFIG_HISI_COUL)             += hisi_coul_core.o hisi_coul_drv.o
obj-$(CONFIG_HISI_COUL)             += hisi_coul_event.o hisi_coul_imonitor.o
obj-$(CONFIG_HISI_COUL_TEST)        += hisi_coul_drv_test.o

