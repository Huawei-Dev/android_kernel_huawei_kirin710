

#ifndef __HMAC_TX_OPT_H__
#define __HMAC_TX_OPT_H__

/* 1 ?????????? */
#include "oal_ext_if.h"
#include "mac_vap.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HMAC_TX_OPT_H

/* 2 ?????? */
#define MAX_TX_OPT_SWITCH_CNT 3
#define MAX_TX_OPT_SWITCH_CNT_TCP_ACK 3

/* 3 ???????? */
/* 4 ???????????? */
/* 5 ?????????? */
/* 6 ???????? */
/* 7 STRUCT???? */
/* 8 UNION???? */
/* 9 OTHERS???? */
/* 10 ???????? */
extern oal_void hmac_tx_opt_switch(oal_uint32 ul_tx_large_pps);
extern oal_void hmac_tx_opt_switch_tcp_ack(oal_uint32 ul_rx_large_pps);
extern oal_void hmac_set_tx_opt_switch_cnt(oal_uint8 uc_opt_switch_cnt);
extern oal_void hmac_set_tx_opt_switch_cnt_tcp_ack(oal_uint8 uc_opt_switch_cnt);
extern oal_void hmac_tx_opt_set_ip_addr(mac_vap_stru *pst_mac_vap, oal_void *pst_ip_addr);
extern oal_void hmac_tx_opt_del_ip_addr(mac_vap_stru *pst_mac_vap, oal_void *pst_ip_addr);
extern oal_bool_enum_uint8 hmac_get_tx_opt_tcp_ack(oal_void);

#endif
