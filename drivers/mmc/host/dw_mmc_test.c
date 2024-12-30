/*
 * Copyright (c) 2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include "dw_mmc_hisi.h"
#include <linux/hisi/bootdevice.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/types.h>
#include <linux/hisi/kirin_partition.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/sd.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/host.h>
#include <linux/mmc/dw_mmc.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/pinctrl/consumer.h>
#include <linux/regulator/consumer.h>
#include <linux/of_address.h>
#include <linux/pm_runtime.h>
#include <linux/clk-provider.h>
#include <linux/hisi/util.h>
#include <linux/hwspinlock.h>

#include "dw_mmc.h"
#include "dw_mmc-pltfm.h"

/*sd loop test*/
struct workqueue_struct *sd_sdio_test_work;
int sd_init_loop_work = 0;
extern void __iomem *pericrg_base;

/*sd modus change*/
unsigned int sd_caps_modus = 0;
unsigned int sd_loop_flag = 0;

#define SD_SDR104    1
#define SD_SDR50      2
#define SD_SDR25      4
#define SD_SDR12      8

#define CRG_PRINT 0x1

#define SOC_CRGPERIPH_PERCLKEN0_UNION 0x008
#define SOC_CRGPERIPH_PERSTAT0_UNION 0x00c
#define SOC_CRGPERIPH_PERCLKEN4_UNION 0x048
#define SOC_CRGPERIPH_PERSTAT4_UNION 0x04C
#define SOC_CRGPERIPH_PERCLKEN5_UNION 0x058
#define SOC_CRGPERIPH_PERSTAT5_UNION 0x05c
#define SOC_CRGPERIPH_PERRSTSTAT4_UNION 0x098
#define SOC_CRGPERIPH_CLKDIV0_UNION 0x0a8
#define SOC_CRGPERIPH_CLKDIV1_UNION 0x0ac
#define SOC_CRGPERIPH_CLKDIV6_UNION 0x0c0
#define SOC_CRGPERIPH_CLKDIV17_UNION 0x0ec
#define SOC_CRGPERIPH_CLKDIV19_UNION 0x0f4
#define SOC_CRGPERIPH_PERI_AUTODIV_STAT_UNION 0x40c

unsigned int test_sd_data = 0;

void mmc_sd_test(unsigned int loop_enable_flag)
{
	sd_init_loop_work = 0;
	if (loop_enable_flag == 1)
		sd_loop_flag = 0x5a5a;
	else if (loop_enable_flag == 0)
		sd_loop_flag = 0;
	else
		printk(KERN_ERR "Don't support this argument, please input again!\n");
}

/*sd loop test*/
void mmc_sd_loop_test(void)
{
	sd_init_loop_work = 0x5a5a;
}

/*sd modus change*/
void test_sd_delete_host_caps(struct mmc_host *host)
{
        if(sd_caps_modus & SD_SDR104)
                host->caps &= ~MMC_CAP_UHS_SDR104;

        if(sd_caps_modus & SD_SDR50)
                host->caps &= ~MMC_CAP_UHS_SDR50;

        if(sd_caps_modus & SD_SDR25)
                host->caps &= ~MMC_CAP_UHS_SDR25;

        if(sd_caps_modus & SD_SDR12)
                host->caps &= ~MMC_CAP_UHS_SDR12;
        if(0x1f == sd_caps_modus)
                host->caps  |= MMC_CAP_UHS_SDR12 | MMC_CAP_UHS_SDR25 | MMC_CAP_UHS_SDR50 | MMC_CAP_UHS_SDR104;

}

/*sd data err*/
void test_sd_data_func(unsigned int input)
{
	if((SDMMC_INT_DRTO) == input)
		test_sd_data = SDMMC_INT_DRTO;
	else if((SDMMC_INT_DCRC) == input)
		test_sd_data = SDMMC_INT_DCRC;
	else if((SDMMC_INT_EBE) == input)
		test_sd_data = SDMMC_INT_EBE;
	else if((SDMMC_INT_SBE) == input)
		test_sd_data = SDMMC_INT_SBE;
	else
		test_sd_data = SDMMC_INT_HTO;
}

void sd_sdio_loop_test(struct work_struct *work)
{
        struct delayed_work *dwork = to_delayed_work(work);
        struct mmc_host *host = container_of(dwork, struct mmc_host, sd_sdio_test_work);
        /*struct dw_mci_slot *slot = mmc_priv(host);*/
        /*struct dw_mci *dw_host = slot->host;*/

        /*do what you want,example read 0x0 reg*/
        /*dev_err(dw_host->dev, ": CTRL:	0x%08x\n", mci_readl(dw_host, CTRL));*/
	if (sd_loop_flag == 0x5a5a) {
		printk(KERN_ERR "sd_sdio_loop_testXXXXXXXXX\n");
		queue_delayed_work(sd_sdio_test_work,&host->sd_sdio_test_work, msecs_to_jiffies(1000));
	}
}

void dw_mci_dump_crg(struct dw_mci *host)
{
        struct dw_mci_hs_priv_data *priv = host->priv;
        if(CRG_PRINT == priv->crg_print)
        {
                dev_err(host->dev, ": SOC_CRGPERIPH_PERCLKEN0_UNION:    offset:0x%x       val:0x%08x\n", SOC_CRGPERIPH_PERCLKEN0_UNION,readl(pericrg_base + SOC_CRGPERIPH_PERCLKEN0_UNION));
                dev_err(host->dev, ": SOC_CRGPERIPH_PERSTAT0_UNION:    offset:0x%x       val:0x%08x\n", SOC_CRGPERIPH_PERSTAT0_UNION,readl(pericrg_base + SOC_CRGPERIPH_PERSTAT0_UNION));
                dev_err(host->dev, ": SOC_CRGPERIPH_PERCLKEN4_UNION:    offset:0x%x       val:0x%08x\n", SOC_CRGPERIPH_PERCLKEN4_UNION,readl(pericrg_base + SOC_CRGPERIPH_PERCLKEN4_UNION));
                dev_err(host->dev, ": SOC_CRGPERIPH_PERSTAT4_UNION:    offset:0x%x       val:0x%08x\n", SOC_CRGPERIPH_PERSTAT4_UNION,readl(pericrg_base + SOC_CRGPERIPH_PERSTAT4_UNION));
                dev_err(host->dev, ": SOC_CRGPERIPH_PERCLKEN5_UNION:    offset:0x%x       val:0x%08x\n", SOC_CRGPERIPH_PERCLKEN5_UNION,readl(pericrg_base + SOC_CRGPERIPH_PERCLKEN5_UNION));
                dev_err(host->dev, ": SOC_CRGPERIPH_PERSTAT5_UNION:    offset:0x%x       val:0x%08x\n", SOC_CRGPERIPH_PERSTAT5_UNION,readl(pericrg_base + SOC_CRGPERIPH_PERSTAT5_UNION));
                dev_err(host->dev, ": SOC_CRGPERIPH_PERRSTSTAT4_UNION:    offset:0x%x       val:0x%08x\n", SOC_CRGPERIPH_PERRSTSTAT4_UNION,readl(pericrg_base + SOC_CRGPERIPH_PERRSTSTAT4_UNION));
                dev_err(host->dev, ": SOC_CRGPERIPH_CLKDIV0_UNION:    offset:0x%x       val:0x%08x\n", SOC_CRGPERIPH_CLKDIV0_UNION,readl(pericrg_base + SOC_CRGPERIPH_CLKDIV0_UNION));
                dev_err(host->dev, ": SOC_CRGPERIPH_CLKDIV1_UNION:    offset:0x%x       val:0x%08x\n", SOC_CRGPERIPH_CLKDIV1_UNION,readl(pericrg_base + SOC_CRGPERIPH_CLKDIV1_UNION));
                dev_err(host->dev, ": SOC_CRGPERIPH_CLKDIV6_UNION:    offset:0x%x       val:0x%08x\n", SOC_CRGPERIPH_CLKDIV6_UNION,readl(pericrg_base + SOC_CRGPERIPH_CLKDIV6_UNION));
                dev_err(host->dev, ": SOC_CRGPERIPH_CLKDIV17_UNION:    offset:0x%x       val:0x%08x\n", SOC_CRGPERIPH_CLKDIV17_UNION,readl(pericrg_base + SOC_CRGPERIPH_CLKDIV17_UNION));
                dev_err(host->dev, ": SOC_CRGPERIPH_CLKDIV19_UNION:    offset:0x%x       val:0x%08x\n", SOC_CRGPERIPH_CLKDIV19_UNION,readl(pericrg_base + SOC_CRGPERIPH_CLKDIV19_UNION));
                dev_err(host->dev, ": SOC_CRGPERIPH_PERI_AUTODIV_STAT_UNION:    offset:0x%x       val:0x%08x\n", SOC_CRGPERIPH_PERI_AUTODIV_STAT_UNION,readl(pericrg_base + SOC_CRGPERIPH_PERI_AUTODIV_STAT_UNION));
        }
}
