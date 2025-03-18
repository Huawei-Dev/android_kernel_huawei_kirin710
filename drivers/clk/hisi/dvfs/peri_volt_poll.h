/*
 * peri_volt_poll.h
 *
 * Hisilicon clock driver
 *
 * Copyright (c) 2017-2019 Huawei Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifndef __PERIVOLT_POLL_EXTERN_H_
#define __PERIVOLT_POLL_EXTERN_H_

#include "peri_volt_internal.h"
/*
 * chicago : 0.7v ,  ,  , 0.8v
 * boston ES : 0.7v ,  ,  , 0.8v
 * boston CS : 0.65v , , 0.75v, 0.8v
 * MIA: 0.7v,  , 0.8V, ;
 * ATLA: 0.65v, 0.7V, 0.8V, ;
 */
enum {
	PERI_VOLT_0 = 0,
	PERI_VOLT_1,
	PERI_VOLT_2,
	PERI_VOLT_3,
	PERI_VOLT_MAX,
};

enum {
	PERI_AVS_DISABLE = 0,
	PERI_AVS_ENABLE,
};

enum {
	DVFS_ISP_CHANEL = 3, /* buck13 need vote 0.8V when isp working */
	DVFS_DDR_CHANEL = 15,
	DVFS_CHANEL_MAX,
};

enum {
	DVFS_BUCK13_VOLT0 = 0,
	DVFS_BUCK13_VOLT1 = 1,
	DVFS_BUCK13_MAX,
};

struct peri_volt_poll *peri_volt_poll_get(unsigned int dev_id, const char *name);
unsigned int peri_get_volt(struct peri_volt_poll *pvp);
int peri_set_volt(struct peri_volt_poll *pvp, unsigned int volt);
int peri_get_temperature(struct peri_volt_poll *pvp);
int peri_set_avs(struct peri_volt_poll *pvp, unsigned int avs);
int peri_wait_avs_update(struct peri_volt_poll *pvp);
inline static void peri_buck13_mem_volt_set(unsigned int channel, unsigned int buck13_volt) { return; }

#endif /* __PERIVOLT_POLL_INTERNAL_H */
