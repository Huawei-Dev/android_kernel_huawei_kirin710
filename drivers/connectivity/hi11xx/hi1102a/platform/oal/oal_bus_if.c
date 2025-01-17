

/* ?????????? */
#include "oal_bus_if.h"

#include "oal_ext_if.h"
#include "oam_ext_if.h"

/* ???????????? */
/* ????chip???? */
OAL_STATIC oal_uint8 g_bus_chip_num = 0;
#if ((_PRE_OS_VERSION_WIN32 == _PRE_OS_VERSION) && (_PRE_TEST_MODE == _PRE_TEST_MODE_UT))
#ifdef _PRE_WLAN_FEATURE_DOUBLE_CHIP
OAL_STATIC oal_bus_chip_stru g_bus_chip[WLAN_CHIP_MAX_NUM_PER_BOARD] = {{0}, {0}};
#else
OAL_STATIC oal_bus_chip_stru g_bus_chip[WLAN_CHIP_MAX_NUM_PER_BOARD] = {{0}};
#endif
#endif
/*
 * ?? ?? ??  : oal_bus_get_chip_num
 * ????????  : ????????????????????
 * ?? ?? ??  : chip ????
 */
oal_uint8 oal_bus_get_chip_num(oal_void)
{
    return g_bus_chip_num;
}

/*
 * ?? ?? ??  : oal_bus_inc_chip_num
 * ????????  : ????????????????????
 * ?? ?? ??  : chip ????
 */
oal_uint32 oal_bus_inc_chip_num(oal_void)
{
    if (g_bus_chip_num < WLAN_CHIP_MAX_NUM_PER_BOARD) {
        g_bus_chip_num++;
    } else {
        OAL_IO_PRINT("oal_bus_inc_chip_num FAIL: g_bus_chip_num = %d\n", g_bus_chip_num);
        return OAL_FAIL;
    }

    /* WINDOWS??UT???? */
#if (_PRE_OS_VERSION_WIN32 == _PRE_OS_VERSION) && (_PRE_TEST_MODE == _PRE_TEST_MODE_UT)
    g_bus_chip[0].uc_device_num = g_bus_chip_num;
#endif

    return OAL_SUCC;
}

oal_void oal_bus_init_chip_num(oal_void)
{
    g_bus_chip_num = 0;

    /* WINDOWS??UT???? */
#if (_PRE_OS_VERSION_WIN32 == _PRE_OS_VERSION) && (_PRE_TEST_MODE == _PRE_TEST_MODE_UT)
    g_bus_chip[0].uc_device_num = g_bus_chip_num;
#endif
    return;
}

#ifdef _PRE_WLAN_FEATURE_SMP_SUPPORT
/*
 * ?? ?? ??  : oal_bus_irq_affinity_init
 * ????????  : ??????????????????
 */
oal_void oal_bus_irq_affinity_init(oal_uint8 uc_chip_id, oal_uint8 uc_device_id, oal_uint32 ul_core_id)
{
    oal_bus_dev_stru *pst_bus_dev;

    pst_bus_dev = oal_bus_get_dev_instance(uc_chip_id, uc_device_id);
    if (pst_bus_dev == OAL_PTR_NULL) {
        return;
    }

    oal_irq_set_affinity(pst_bus_dev->st_irq_info.ul_irq, ul_core_id);
}
#endif

/*lint -e19*/
oal_module_symbol(oal_bus_get_chip_num);
#ifdef _PRE_WLAN_FEATURE_SMP_SUPPORT
oal_module_symbol(oal_bus_irq_affinity_init);
#endif
/*lint +e19*/
