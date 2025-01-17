

#ifndef __HMAC_CALI_MGMT_H__
#define __HMAC_CALI_MGMT_H__

#if defined(_PRE_PRODUCT_ID_HI110X_HOST)
/* 1 ?????????????? */
#include "frw_ext_if.h"
#include "dmac_ext_if.h"
#include "hmac_vap.h"
#include "plat_cali.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HMAC_CALI_MGMT_H
/* 2 ?????? */
#define HI1102_CALI_MATRIX_DATA_NUMS (3)
/* NEW TRX IQ??LS ?????????????????????? */
#define HI1102_CALI_RXIQ_LS_FILTER_FEQ_NUM_160M 64
#define HI1102_CALI_RXIQ_LS_FILTER_FEQ_NUM_80M  32
#define HI1102_CALI_TXIQ_LS_FILTER_FEQ_NUM_320M 128
#define HI1102_CALI_TXIQ_LS_FILTER_FEQ_NUM_160M 64

/* 3 ???????? */
/* 4 ???????????? */
/* 5 ?????????? */
/* 6 ???????? */
/* 7 STRUCT???? */
/* 8 UNION???? */
/* 9 OTHERS???? */
/* 10 ???????? */
extern oal_uint32 hmac_save_cali_event(frw_event_mem_stru *pst_event_mem);
extern oal_uint32 hmac_send_cali_data(mac_vap_stru *pst_mac_vap, oal_uint16 us_len, oal_uint8 *puc_param);
extern oal_uint32 hmac_send_cali_matrix_data(mac_vap_stru *pst_mac_vap);
extern oal_uint32 wlan_pm_close(oal_void);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif

#endif /* end of hmac_mgmt_classifier.h */


