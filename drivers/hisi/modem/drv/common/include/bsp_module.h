#ifndef __BSP_MODULE_H
#define __BSP_MODULE_H

#if defined(__OS_RTOSCK_SMP__)|| defined(__OS_RTOSCK__) || defined(__OS_RTOSCK_TSP__)


#include <sre_buildef.h>

/*??????????????????module????*/
#ifndef CONFIG_MODULE_MAX_NUM
#define CONFIG_MODULE_MAX_NUM      200
#endif

/*????module????????????????*/
typedef enum _module_level
{
	mod_level_start = 0,
	mod_level_libc_init,
	mod_level_dts,
	mod_level_HardBoot_end, /*SRE_HardBootInit??????????????*/

	mod_level_l2cache,
	mod_level_gic,
	mod_level_syslog_cb,
	mod_level_serial,
	mod_level_HardDrv_end, /*SRE_HardDrvInit ??????????????*/

	mod_level_malloc,
	mod_level_sysctrl,
	mod_level_share_mem,
	mod_level_mdmcert,
	mod_level_timer,
	mod_level_log,
	mod_level_llram_mempt,
	mod_level_fiq,
	mod_level_smpcall,
	mod_level_socp,
	mod_level_dump_mem,
	mod_level_cpu,
	mod_level_dmesg,
	mod_level_coresight,
	mod_level_pdlock,
	mod_level_mid,
	mod_level_dump,
	/* bsp_drivers */
	mod_level_console,
	mod_level_pm_om_dump,
	mod_level_clk,
	mod_level_systimer,
	mod_level_rsracc,
	mod_level_wakelock,
	mod_level_dpm,
	mod_level_maa,
	mod_level_watchpoint,
	mod_level_hardtimer,
	mod_level_vic,
	mod_level_ipc,
	mod_level_ipc_msg,
	mod_level_dfc,
	mod_level_dump_phase2,
	mod_level_reset_node,
	mod_level_icc,
	mod_level_eicc,
	mod_level_pdlock2,
	mod_level_vshell,
	mod_level_nvm,
	mod_level_amon_mdm,
	mod_level_amon_cnt,
	mod_level_rfile,
	mod_level_sec_rfile,
	mod_level_version_core,
	mod_level_hwspinlock,
	mod_level_hkadc,
	mod_level_adc,
	mod_level_version,
	mod_level_hwadp,
	mod_level_softtimer,
	mod_level_edma,
	mod_level_hds,
	mod_level_scm,
	mod_level_ppm,
	mod_level_board_trace,
	mod_level_noc,
	mod_level_dual_modem,
	mod_level_dsp,
	mod_level_dsp_load,
	mod_level_nrdsp,
	mod_level_bbp,
	mod_level_board_fpga,
	mod_level_gpio,
	mod_level_pmu,
	mod_level_regulator,
	mod_level_mipi,
	mod_level_cross_mipi,
	mod_level_pinctrl,
	mod_level_rffe,
	mod_level_watchdog,
	mod_level_i2c,
	mod_level_efuse,
	mod_level_tsensor,
	mod_level_led,
    mod_level_crypto,
	mod_level_loadps_core,
	mod_level_ecipher,
	mod_level_cipher,
	mod_level_ipf,
	mod_level_psam,
	mod_level_mailbox,
	mod_level_xmailbox,
	mod_level_anten,
	mod_level_mem,
	mod_level_mloader,
	mod_level_l2hac_load,
    mod_level_abb_former,
	mod_level_abb,
	mod_level_abb_latter,
	mod_level_remote_clk,
	mod_level_onoff,
	mod_level_hotplug,
	mod_level_avs,
	mod_level_busfreq,
	mod_level_perf_stat,
	mod_level_perf_stat_sysbus,
	mod_level_cpufreq,
	mod_level_idlefreq,
	mod_level_pm,
	mod_level_reset,
    mod_level_sci_cfg,
	mod_level_modem_log,
	mod_level_pmomlog,
	mod_level_pm_wakeup_debug,
	mod_level_ddrtst_pm,
	mod_level_sysbus_core,
	mod_level_memlat_dfs,
	mod_level_sys_pmu,
	mod_level_mperf,
	mod_level_dsp_dvs,
	mod_level_dsp_dfs,                /* dspdfs??????????????dspdvs?????? */
	mod_level_dload,
	mod_level_rfic_load,
	mod_level_fault_inflood,
	mod_level_ocbc,
	mod_level_rsracc_late,
	mod_level_pan_rpc_ccore,
	mod_level_cpm,
	mod_level_ecdc,
	mod_level_easyrf,
	mod_level_rfverify,
    mod_level_lltshell,
	mod_level_iqi,
	mod_level_hcode,
	mod_level_eipf,
	mod_level_psroot,
	mod_level_simsock,
	mod_level_dump_mem_debug,
	mod_level_tickless,
	mod_level_regidle,
	mod_level_dump_init_tsk,
	mod_level_onoff_modem_ok,
	mod_level_rtc,

	mod_level_App_end/*SRE_AppInit??????????????*/
} module_level;


/*
 * module????????????????
 */
 typedef int (*modcall_t)(void);
struct module
{
	const char	name[32];
	modcall_t      init_fun;
	modcall_t      exit_fun;
	module_level  level;
	const char	init_func_name[64];
	const char	exit_func_name[64];
};

/*module??????????????*/
#define __init           __attribute__((section(".init.text")))
#define __exit          __attribute__((section(".exit.text")))
#define __used	    __attribute__((__used__))

#define module_init(name, initlevel, initcall,exitcall) \
	__used __attribute__((section(".mod.info"))) static struct module __mod_##initcall \
		= { name,  initcall, exitcall, initlevel,  #initcall ,#exitcall}

/**
 * @brief module????????????
 *
 * @par ????:
 * ??????????????????????????????????
 *
 * @attention
 * ????????????????????
 * *
 * @retval
 *??
 * @par ????:
 *??
*/
void bsp_module_init(module_level module_level_t);
/**
 * @brief module????
 *
 * @par ????:
 * ????????module????
 *
 * @attention
 * *????????????????????????????
 * *
 * @retval
 *??????????module????????????
 * @par ????:
 *rfile\icc\ipc\
*/

struct module * bsp_module_get(const char *module_name);
/**
 * @brief module????
 *
 * @par ????:
 * ????????module????
 *
 * @attention
 * *????????????????????????????
 * @retval
 * @par ????:
 *??
*/
int bsp_module_put(struct module *module);

#endif



#endif
