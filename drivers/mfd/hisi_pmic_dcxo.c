/*
 * All other module's reference of nve.
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/mtd/hisi_nve_number.h>
#include "../mtd/hisi_nve.h"
#include "securec.h"

#define NVE_CALC1C2_NAME "CALC1C2"
extern int pmu_dcxo_set(uint16_t dcxo_ctrim, uint16_t dcxo_c2_fix);
extern int pmu_dcxo_get(uint16_t *dcxo_ctrim, uint16_t *dcxo_c2_fix);
EXPORT_SYMBOL(pmu_dcxo_get);
EXPORT_SYMBOL(pmu_dcxo_set);

int pmu_dcxo_set(uint16_t dcxo_ctrim, uint16_t dcxo_c2_fix){ return 0;}
int pmu_dcxo_get(uint16_t *dcxo_ctrim, uint16_t *dcxo_c2_fix){ return 0;}
