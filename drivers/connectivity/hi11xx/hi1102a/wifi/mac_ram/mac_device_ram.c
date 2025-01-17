

/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "mac_device.h"
#include "mac_vap.h"
#if (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102A_HOST) && (_PRE_OS_VERSION == _PRE_OS_VERSION_LINUX)
#include "board.h"
#endif
#include "mac_resource.h"

#undef  THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_MAC_DEVICE_RAM_C

/*****************************************************************************
  2 ????????????
*****************************************************************************/
mac_phy_debug_switch_stru  g_st_mac_phy_debug_switch = {0};
mac_rom_device_stru g_ast_mac_device_rom[WLAN_MAC_DEV_MAX_CNT];

/*****************************************************************************
  3 ????????
*****************************************************************************/

oal_rom_cb_result_enum_uint8 mac_device_init_cb(
    mac_device_stru *pst_mac_device, oal_uint32 ul_chip_ver, oal_uint8 uc_chip_id,
    oal_uint8 uc_device_id, oal_uint32 *pul_cb_ret)
{
    *pul_cb_ret = OAL_SUCC;
    /* ROM???????? */
    pst_mac_device->pst_mac_device_rom = &g_ast_mac_device_rom[pst_mac_device->uc_device_id];
    memset_s(pst_mac_device->pst_mac_device_rom, OAL_SIZEOF(mac_rom_device_stru), 0, OAL_SIZEOF(mac_rom_device_stru));
    return OAL_CONTINUE;
}

#if (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102A_HOST) && (_PRE_OS_VERSION == _PRE_OS_VERSION_LINUX)

wlan_bw_cap_enum_uint8 mac_device_max_band_cb(oal_void)
{
    /* Host??????????????????FPGA/ASIC, Device????patch???? */
    if (is_asic() == VERSION_ASIC) {
        return WLAN_BW_CAP_80M;
    } else if (is_asic() == VERSION_FPGA) {
        return WLAN_BW_CAP_40M;
    } else {
        return WLAN_BW_CAP_80M;
    }
}
#else

wlan_bw_cap_enum_uint8 mac_device_max_band_cb(oal_void)
{
    /* Device????????ASIC?????? */
#if (_PRE_WLAN_CHIP_ASIC != _PRE_WLAN_CHIP_VERSION)
    return WLAN_BW_CAP_40M;
#else
    return WLAN_BW_CAP_80M;
#endif
}
#endif


