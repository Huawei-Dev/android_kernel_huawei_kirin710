
#ifndef __HMAC_BTCOEX_H__
#define __HMAC_BTCOEX_H__

#ifdef _PRE_WLAN_FEATURE_BTCOEX

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "frw_ext_if.h"
#include "oal_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
/*****************************************************************************
  2 ??????
*****************************************************************************/
#define MAX_BTCOEX_BSS_IN_BL 16

#define hmac_btcoex_get_blacklist_type(_pst_hmac_user) \
    ((_pst_hmac_user)->st_hmac_user_btcoex.st_hmac_btcoex_addba_req.en_blacklist_tpye)

#define hmac_btcoex_get_blacklist_delba_handle_allow(_pst_hmac_user) \
    ((_pst_hmac_user)->st_hmac_user_btcoex.st_hmac_btcoex_addba_req.en_ba_handle_allow)
typedef enum {
    BTCOEX_BLACKLIST_TPYE_FIX_BASIZE = 0,  // ????????????
    BTCOEX_BLACKLIST_TPYE_NOT_AGGR = 1,    // ??????

    BTCOEX_BLACKLIST_TPYE_BUTT
} btcoex_blacklist_type_enum;
typedef oal_uint8 btcoex_blacklist_type_enum_uint8;

typedef enum {
    BTCOEX_BA_TYPE_NORMAL,  // host??????????????
    BTCOEX_BA_TYPE_REJECT,  // ????????BA
    BTCOEX_BA_TYPE_SIZE_1,  // ??????????1
} btcoex_ba_type_enum;
typedef oal_uint8 btcoex_ba_type_enum_uint8;
typedef struct {
    oal_uint16 us_last_baw_start;                       /* ????????????ADDBA REQ????baw_start?? */
    oal_uint16 us_last_seq_num;                         /* ????????????ADDBA REQ????seq_num?? */
    btcoex_blacklist_type_enum_uint8 en_blacklist_tpye; /* ?????????? */
    oal_bool_enum_uint8 en_ba_handle_allow;             /* ??????????1:???????????????????? ??????????2:???????????????? */
    oal_uint8 auc_resv[2];
} hmac_btcoex_addba_req_stru;

typedef struct {
    oal_uint8 auc_user_mac_addr[WLAN_MAC_ADDR_LEN]; /* ??????MAC???? */
    oal_uint8 uc_type;                              /* ???????????????? */
    oal_uint8 uc_used;                              /* ??????????????????MAC???? */
} hmac_btcoex_delba_exception_stru;

typedef struct {
    frw_timeout_stru st_delba_opt_timer; /* ????ARP REQ???????????? */
    oal_atomic ul_rx_unicast_pkt_to_lan; /* ?????????????????? */
} hmac_btcoex_arp_req_process_stru;

typedef struct {
    hmac_btcoex_delba_exception_stru ast_hmac_btcoex_delba_exception[MAX_BTCOEX_BSS_IN_BL];
    oal_uint8 uc_exception_bss_index; /* ??????MAC?????????????? */
    oal_uint8 auc_resv[3];
    hal_btcoex_btble_status_stru st_btble_status;
} hmac_device_btcoex_stru;

typedef struct {
    hmac_btcoex_arp_req_process_stru st_hmac_btcoex_arp_req_process;
    hmac_btcoex_addba_req_stru st_hmac_btcoex_addba_req;
    oal_uint8 uc_ba_size;
    oal_uint8 uc_rx_no_pkt_count;                /* ?????????????????????????? */
    oal_bool_enum_uint8 en_delba_btcoex_trigger; /* ????btcoex????????BA */
    btcoex_ba_type_enum_uint8 en_ba_type;        /* ??????????????????????????BA???? */
} hmac_user_btcoex_stru;
extern oal_uint32 hmac_btcoex_check_exception_in_list(oal_void *p_arg, oal_uint8 *auc_addr);
extern oal_void hmac_btcoex_blacklist_handle_init(oal_void *p_arg);
extern oal_void hmac_btcoex_process_btble_status(mac_device_stru *pst_mac_device,
                                                 hal_btcoex_btble_status_stru *pst_btble_status_old,
                                                 hal_btcoex_btble_status_stru *pst_btble_status_new);

extern oal_void hmac_btcoex_ap_tpye_identify(mac_vap_stru *pst_mac_vap,
                                             oal_uint8 *puc_mac_addr,
                                             mac_bss_dscr_stru *pst_bss_dscr,
                                             mac_ap_type_enum_uint8 *pen_ap_type);

extern oal_void hmac_btcoex_process_exception_ap(mac_vap_stru *pst_mac_vap,
                                                 mac_user_stru *pst_mac_user,
                                                 mac_ap_type_enum_uint8 en_ap_type);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* #ifdef _PRE_WLAN_FEATURE_COEXIST_BT */

#endif /* end of __HMAC_BTCOEX_H__ */

