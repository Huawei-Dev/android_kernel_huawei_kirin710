#ifndef __MDRV_SLT_H__
#define __MDRV_SLT_H__
#ifdef __cplusplus
extern "C"
{
#endif

/*****************************************************************************
 ?? ?? ??  : mdrv_slt_set_bsn
 ????????  : mdrv_slt_set_bsn
 ????????  : bsn --- ??????bsn??
            
 ????????  : ??
 ?? ?? ??  : 0    - successful
             -1   - unsuccessful
*****************************************************************************/
int mdrv_slt_set_bsn(char * bsn);

/*****************************************************************************
 ?? ?? ??  : mdrv_slt_get_bsn
 ????????  : mdrv_slt_get_bsn
 ????????  : ??
 ????????  : *bsn --- ????bsn??
 ?? ?? ??  : 0    - successful
             -1 - unsuccessful
*****************************************************************************/
int mdrv_slt_get_bsn(char * bsn);

int mdrv_slt_pcie_test(void);

int mdrv_slt_usb_test(int usb_mode);

int mdrv_slt_SGMII_test(void);

int mdrv_slt_RGMII_test(void);

int mdrv_slt_spi_test(void);

int mdrv_slt_sdcard_test(void);

int mdrv_slt_acore_l2cache_test(void);

int mdrv_slt_hifi_test(void);

#ifdef __cplusplus
}
#endif
#endif