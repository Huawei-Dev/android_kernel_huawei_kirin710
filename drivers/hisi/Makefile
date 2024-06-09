obj-$(CONFIG_HISI_HKADC) += adc/
obj-$(CONFIG_HISI_CCI_EXTRA)		+= cci_extra/
obj-$(CONFIG_HISI_CMDLINE_PARSE)	+= cmdline/
obj-$(CONFIG_HISILICON_PLATFORM_MAILBOX)	+= mailbox/
obj-$(CONFIG_SND_SOC_HI6XXX_MBHC)		+= hi6xxx/
obj-$(CONFIG_HI6402_CODEC)			+= hi64xx/
obj-$(CONFIG_HI6403_CODEC)			+= hi64xx/
obj-$(CONFIG_HIFI_DSP_ONE_TRACK)		+= hifi_dsp/
obj-$(CONFIG_SOUND_TRIGGER)			+= soundtrigger/
obj-$(CONFIG_HIFI_MAILBOX)			+= hifi_mailbox/
obj-$(CONFIG_HISILICON_PLATFORM_MAINTAIN) += mntn/
obj-$(CONFIG_HISILICON_PLATFORM_KERNELDUMP) += memory_dump/
obj-$(CONFIG_HISILICON_PLATFORM_DDRC)   += ddrc/
obj-$(CONFIG_HISI_NOC)	+= noc/
obj-$(CONFIG_HISI_SYSCOUNTER) += hisi_syscounter/
obj-$(CONFIG_HISILICON_PLATFORM_SLIMBUS)+= slimbus/
obj-$(CONFIG_HISI_HHEE) += hhee/

obj-$(CONFIG_HI6402_HIFI_MISC) += hi64xx_dsp/
obj-$(CONFIG_HISI_HISEE) += hisee/
ifneq ($(strip $(CFG_HISI_OPENSOURCE)), true)
endif
obj-$(CONFIG_HISI_IVP) += ivp/
obj-$(CONFIG_HISI_HISTAR_ISP) += isp/
obj-$(CONFIG_DRMDRIVER)                         += drmdriver/
obj-$(CONFIG_HI3XXX_EFUSE)                      += efuse/
obj-$(CONFIG_HISI_CMA)                          += hisi_cma/
obj-y                                           += tzdriver/
obj-$(CONFIG_LOAD_IMAGE) += load_image/
obj-$(CONFIG_HISI_SECS_CTRL) += secs_power_ctrl/
obj-$(CONFIG_HISI_SR)                      += pm/
obj-$(CONFIG_HISI_HW_VOTE)                 += hw_vote/
obj-$(CONFIG_HISI_GPUFREQ)                 += gpufreq/
ifneq ($(link_kernel),false)
ifneq (,$(findstring $(CONFIG_HISI_BALONG_MODEM),y m))
obj-y += modem/
endif
endif
obj-$(CONFIG_HISI_PERFHUB) += perfhub/
obj-$(CONFIG_HISI_TIMEKEEPER) += timekeeper/
obj-$(CONFIG_TLB_CONFLICT_WORKAROUND) += tlb_conflict/
obj-$(CONFIG_HISI_PERF_CTRL) += perf_ctrl/
obj-$(CONFIG_HUAWEI_WPA_DMD) += wpa_dmd/
obj-$(CONFIG_SWITCH)		+= switch/
obj-$(CONFIG_OAE_FW_PATCH) += oae_fw_patch/
obj-$(CONFIG_LOGGER_EXTEND) += log/
obj-$(CONFIG_HW_ZEROHUNG) += hwzerohung/
obj-$(CONFIG_HW_FDLEAK) += hwfdleak/
obj-$(CONFIG_HUAWEI_DSM)        += dsm/
obj-$(CONFIG_HW_CPULOAD_NOTI) += cpuload/
obj-$(CONFIG_HISI_BOOTDEVICE)   += bootdevice/
