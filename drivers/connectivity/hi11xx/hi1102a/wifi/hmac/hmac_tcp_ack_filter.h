

#ifndef __HMAC_TCP_ACK_FILTER_H__
#define __HMAC_TCP_ACK_FILTER_H__

/* 1 ?????????????? */
#include "hmac_blockack.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef  THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HMAC_TCP_ACK_FILTER_H

/* 2 ?????? */
#define MAX_TCP_ACK_FILTER_SWITCH_CNT 3

/* 3 ???????? */
/* 4 ???????????? */
extern oal_bool_enum_uint8 g_en_tcp_ack_filter_switch;
extern oal_uint32 g_ul_2g_tx_large_pps_th;
extern oal_uint32 g_ul_5g_tx_large_pps_th;
extern oal_uint16 g_aus_tcp_ack_filter_th[WLAN_BAND_BUTT][4];

/* 5 ?????????? */
/* 6 ???????? */
/* 7 STRUCT???? */
/* 8 UNION???? */
/* 9 OTHERS???? */
/* 10 ???????? */

OAL_STATIC OAL_INLINE oal_void hmac_rx_process_tcp_ack_record_post_do(oal_netbuf_stru *pst_netbuf)
{
    /* ????netbuf??????tcp ack info */
    oal_netbuf_trim(pst_netbuf, OAL_SIZEOF(mac_tcp_ack_record_stru));
}

extern oal_void hmac_rx_process_tcp_ack_record(hmac_vap_stru *pst_hmac_vap, oal_netbuf_stru *pst_netbuf);
extern oal_void hmac_rx_tcp_ack_filter_switch(oal_uint32 ul_tx_large_pps, oal_uint32 ul_rx_large_pps,
                                              oal_uint32 ul_tx_small_pps, oal_uint32 ul_rx_small_pps);
extern oal_void hmac_set_filter_switch_cnt(oal_uint8 uc_filter_switch_cnt);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
