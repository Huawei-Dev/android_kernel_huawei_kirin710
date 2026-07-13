#if defined(PMU_6421_V800) || defined(FASTBOOT_PMU_HI6421V800) || defined(CONFIG_HISI_HI6421V800_PMU)
#include "pmic_interface_21v810.h"
#elif (defined PMU_6555_V500) || (defined FASTBOOT_PMU_HI6555V500) || (defined CONFIG_HISI_HI6555V500_PMU)
#include "pmic_interface_55v500.h"
#else
#include "pmic_interface_55v200.h"
#endif
