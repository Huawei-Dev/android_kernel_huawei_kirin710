
#ifndef __HMAC_EXT_IF_H__
#define __HMAC_EXT_IF_H__

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "oal_ext_if.h"
#include "frw_ext_if.h"
#include "mac_device.h"
#include "mac_vap.h"
#include "mac_user.h"
#include "mac_frame.h"
#include "mac_data.h"
#ifdef _PRE_WLAN_FEATURE_AUTO_FREQ
#include "oal_hcc_host_if.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HMAC_EXT_IF_H

/*****************************************************************************
  2 ??????
*****************************************************************************/
#define HMAC_RSP_MSG_MAX_LEN 64 /* get wid???????????????? */
/* ?????????????? */
typedef enum {
    HMAC_TX_PASS = 0, /* ???????? */
    HMAC_TX_BUFF = 1, /* ???????? */
    HMAC_TX_DONE = 2, /* ?????????????????? */

    HMAC_TX_DROP_PROXY_ARP = 3,    /* PROXY ARP?????????? */
    HMAC_TX_DROP_USER_UNKNOWN,     /* ????user */
    HMAC_TX_DROP_USER_NULL,        /* user????????NULL */
    HMAC_TX_DROP_USER_INACTIVE,    /* ????user?????? */
    HMAC_TX_DROP_SECURITY_FILTER,  /* ?????????????? */
    HMAC_TX_DROP_BA_SETUP_FAIL,    /* BA???????????? */
    HMAC_TX_DROP_AMSDU_ENCAP_FAIL, /* amsdu???????? */
    HMAC_TX_DROP_MUSER_NULL,       /* ????user??NULL */
    HMAC_TX_DROP_MTOU_FAIL,        /* ?????????????? */
    HMAC_TX_DROP_80211_ENCAP_FAIL, /* 802.11 head???????? */

    HMAC_TX_BUTT
} hmac_tx_return_type_enum;
typedef oal_uint8 hmac_tx_return_type_enum_uint8;

/*****************************************************************************
  ??????  : hmac_host_ctx_event_sub_type_enum_uint8
  ????????:
  ????????: HOST CTX??????????????
*****************************************************************************/
typedef enum {
    HMAC_HOST_CTX_EVENT_SUB_TYPE_SCAN_COMP_STA = 0, /* STA???????????????? */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_ASOC_COMP_STA,     /* STA ?????????????? */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_DISASOC_COMP_STA,  /* STA ?????????????? */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_STA_CONNECT_AP,    /* AP ??????????BSS??STA???? */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_STA_DISCONNECT_AP, /* AP ????????BSS??STA???? */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_MIC_FAILURE,       /* ????MIC???? */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_ACS_RESPONSE,      /* ????ACS???????????? */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_RX_MGMT,           /* ?????????????????? */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_LISTEN_EXPIRED,    /* ???????????? */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_INIT,
    HMAC_HOST_CTX_EVENT_SUB_TYPE_MGMT_TX_STATUS,
#ifdef _PRE_WLAN_FEATURE_ROAM
    HMAC_HOST_CTX_EVENT_SUB_TYPE_ROAM_COMP_STA, /* STA ?????????????? */
#endif                                          // _PRE_WLAN_FEATURE_ROAM
#ifdef _PRE_WLAN_FEATURE_11R
    HMAC_HOST_CTX_EVENT_SUB_TYPE_FT_EVENT_STA, /* STA ?????????????? */
#endif                                         // _PRE_WLAN_FEATURE_11R

#ifdef _PRE_WLAN_FEATURE_DFR
    HMAC_HOST_CTX_EVENT_SUB_TYPE_DEV_ERROR, /* device???????????? */
#endif                                      // _PRE_WLAN_FEATURE_DFR
#ifdef _PRE_WLAN_FEATURE_VOWIFI
    HMAC_HOST_CTX_EVENT_SUB_TYPE_VOWIFI_REPORT, /* ????vowifi?????????????????????? */
#endif                                          /* _PRE_WLAN_FEATURE_VOWIFI */

#if defined(_PRE_WLAN_FEATURE_DATA_SAMPLE)
    HMAC_HOST_CTX_EVENT_SUB_TYPE_SAMPLE_REPORT,
#endif
#ifdef _PRE_WLAN_FEATURE_SAE
    HMAC_HOST_CTX_EVENT_SUB_TYPE_EXT_AUTH_REQ, /* STA????SAE???????? */
#endif
#ifdef _PRE_WLAN_FEATURE_TAS_ANT_SWITCH
    HMAC_HOST_CTX_EVENT_SUB_TYPE_TAS_NOTIFY_RSSI, /* ????TAS???????????? */
#endif

    HMAC_HOST_CTX_EVENT_SUB_TYPE_BUTT
} hmac_host_ctx_event_sub_type_enum;
typedef oal_uint8 hmac_host_ctx_event_sub_type_enum_uint8;

typedef struct {
    oal_netbuf_head_stru st_msdu_head; /* msdu?????? */
    frw_timeout_stru st_amsdu_timer;
    oal_spin_lock_stru st_amsdu_lock; /* amsdu task lock */

    oal_uint8 uc_msdu_num;     /* Number of sub-MSDUs accumulated */
    oal_uint8 uc_last_pad_len; /* ????????msdu??pad???? */
    oal_uint8 uc_amsdu_maxnum;
    oal_uint8 auc_reserve[1];

    oal_uint16 us_amsdu_maxsize;
    oal_uint16 us_amsdu_size; /* Present size of the AMSDU */

    oal_uint8 auc_eth_da[WLAN_MAC_ADDR_LEN];
    oal_uint8 auc_eth_sa[WLAN_MAC_ADDR_LEN];
} hmac_amsdu_stru;

/* hmac???????????? */
typedef struct {
    oal_wait_queue_head_stru st_wait_queue_for_sdt_reg; /* ????wal_config??????????(wal_config-->hmac),??SDT???????????????????? */
    oal_bool_enum_uint8 en_wait_ack_for_sdt_reg;
    oal_uint8 auc_resv2[3];
    oal_int8 ac_rsp_msg[HMAC_RSP_MSG_MAX_LEN]; /* get wid???????????????? */
    oal_uint32 dog_tag;
} hmac_vap_cfg_priv_stru;

/* WAL????????HMAC????????PAYLOAD?????? */
typedef struct {
    oal_netbuf_stru *pst_netbuf; /* netbuf???????????? */
    mac_vap_stru *pst_vap;
} hmac_tx_event_stru;

/* HMAC?????????????????????? */
typedef struct {
    oal_uint8 *puc_msg;
} hmac_disasoc_comp_event_stru;

/* ???????? */
typedef struct {
    oal_uint8 uc_num_dscr;
    oal_uint8 uc_result_code;
    oal_uint8 auc_resv[2];
} hmac_scan_rsp_stru;

/* Status code for MLME operation confirm */
typedef enum {
    HMAC_MGMT_SUCCESS = 0,
    HMAC_MGMT_INVALID = 1,
    HMAC_MGMT_TIMEOUT = 2,
    HMAC_MGMT_REFUSED = 3,
    HMAC_MGMT_TOMANY_REQ = 4,
    HMAC_MGMT_ALREADY_BSS = 5
} hmac_mgmt_status_enum;
typedef oal_uint8 hmac_mgmt_status_enum_uint8;

/* ???????? */
typedef struct {
    hmac_mgmt_status_enum_uint8 en_result_code; /* ????????,?????? */
    oal_uint8 auc_resv1[1];
    mac_status_code_enum_uint16 en_status_code; /* ieee??????????16???????? */

    oal_uint8 auc_addr_ap[WLAN_MAC_ADDR_LEN];
    oal_uint8 auc_resv2[2];

    oal_uint32 ul_asoc_req_ie_len;
    oal_uint32 ul_asoc_rsp_ie_len;

    oal_uint8 *puc_asoc_req_ie_buff;
    oal_uint8 *puc_asoc_rsp_ie_buff;
} hmac_asoc_rsp_stru;
/* ???????? */
typedef struct {
    oal_uint8 auc_bssid[WLAN_MAC_ADDR_LEN];
    oal_uint8 auc_resv1[2];
    mac_channel_stru st_channel;
    oal_uint32 ul_asoc_req_ie_len;
    oal_uint32 ul_asoc_rsp_ie_len;
    oal_uint8 *puc_asoc_req_ie_buff;
    oal_uint8 *puc_asoc_rsp_ie_buff;
} hmac_roam_rsp_stru;

#ifdef _PRE_WLAN_FEATURE_11R
typedef struct {
    oal_uint8 auc_bssid[WLAN_MAC_ADDR_LEN];
    oal_uint16 us_ft_ie_len;
    oal_uint8 *puc_ft_ie_buff;
} hmac_roam_ft_stru;

#endif  // _PRE_WLAN_FEATURE_11R

/* mic???? */
typedef struct {
    oal_uint8 auc_user_mac[WLAN_MAC_ADDR_LEN];
    oal_uint8 auc_reserve[2];
    oal_nl80211_key_type en_key_type;
    oal_int32 l_key_id;
} hmac_mic_event_stru;

/* ?????????????????????????????? */
typedef struct {
    oal_uint8 *puc_buf;
    oal_uint16 us_len;
    oal_uint8 uc_rssi; /* ??????????????HMAC_FBT_RSSI_ADJUST_VALUE?????????????? */
    oal_uint8 uc_rsv[1];
    oal_int32 l_freq;
    oal_int8 ac_name[OAL_IF_NAME_SIZE];
} hmac_rx_mgmt_event_stru;

/* ???????????????????? */
typedef struct {
    oal_ieee80211_channel_stru st_listen_channel;
    oal_uint64 ull_cookie;
    oal_wireless_dev_stru *pst_wdev;
} hmac_p2p_listen_expired_stru;

/* ?????????????????????????????? */
typedef struct {
    oal_uint8 uc_dev_mode;
    oal_uint8 uc_vap_mode;
    oal_uint8 uc_vap_status;
    oal_uint8 uc_write_read;
    oal_uint32 ul_val;
} hmac_cfg_rx_filter_stru;

#ifdef _PRE_WLAN_FEATURE_SAE
/* ????SAE ?????????????????????? */
typedef struct {
    oal_nl80211_external_auth_action en_action;
    oal_uint8 auc_bssid[WLAN_MAC_ADDR_LEN];
    oal_ssids_stru st_ssid;
    oal_uint32 ul_key_mgmt_suite;
    oal_uint16 us_status;
} hmac_external_auth_req_stru;
#endif

/* ??device????mac_tx_ctl????????????????dmac_ext_if.h */
#if 1
struct mac_tx_ctl_cut {
    /* ????????????????netbuf?????? */
    oal_uint8 bit_mpdu_num : 7; /* ampdu????????MPDU????,????????????????????????-1 */
    /* ??????MPDU????????NETBUF?????? */
    oal_uint8 bit_netbuf_num : 1; /* ????MPDU??????netbuf???? */

    oal_uint8 bit_frame_header_length : 6;  // 51??????32 /* ??MPDU??802.11?????? */
    oal_uint8 en_is_first_msdu : 1;         /* ??????????????????OAL_FALSE???? OAL_TRUE?? */
    oal_uint8 en_is_amsdu : 1;              /* ????AMSDU: OAL_FALSE??????OAL_TRUE?? */

    /* ????:FRW_EVENT_TYPE_WLAN_DTX??FRW_EVENT_TYPE_HOST_DRX??????:??????????????????????netbuf???????????? */
    frw_event_type_enum_uint8 bit_en_event_type : 5;
    oal_uint8 bit_need_rsp : 1;                      /* WPAS send mgmt,need dmac response tx status */
    oal_uint8 bit_is_needretry : 1;
    oal_uint8 bit_is_vipframe : 1; /* ??????????EAPOL????DHCP?? */

    oal_uint8 bit_tx_user_idx : 4;  /* dmac tx ?? tx complete ??????user???????????????????? */
    oal_uint8 en_is_probe_data : 3; /* ?????????? */
    oal_uint8 en_ismcast : 1;       /* ??MPDU??????????????:OAL_FALSE??????OAL_TRUE???? */

    oal_uint8 bit_retried_num : 4;
    mac_data_type_enum_uint8 bit_data_frame_type : 4; /* ????????????0????????????tcp ack */

    oal_uint8 bit_tx_vap_index : 3;
    oal_uint8 bit_mgmt_frame_id : 4; /* wpas ????????????frame id */
    oal_uint8 bit_roam_data : 1;

    wlan_wme_ac_type_enum_uint8 bit_ac : 3;          /* ac */
    wlan_tx_ack_policy_enum_uint8 en_ack_policy : 3; /* ACK ???? */
    oal_uint8 bit_is_large_skb_amsdu : 1;            /* ??????????amsdu */
    oal_uint8 bit_ether_head_including : 1;          /* ??????ether head */

    oal_uint8 uc_alg_pktno; /* ?????????????????????????????? */

    oal_uint8 bit_tid : 4;
    oal_uint8 bit_align_padding_offset : 2; /* amsdu+ampdu??????????,????4????????MSDU?????? */
    oal_uint8 en_is_get_from_ps_queue : 1;  /* ????????????????????MPDU???????????????????????? */
    oal_uint8 bit_is_eapol_key_ptk : 1;     /* 4 ????????????????????????EAPOL KEY ?????? */

    // oal_time_us_stru                        st_timestamp_us;                         /* ??????????TID?????????????? */
    oal_uint8 reserved[8];
    oal_uint16 us_mpdu_bytes; /* mpdu??????????????????????????????????snap????????padding */
} __OAL_DECLARE_PACKED;
typedef struct mac_tx_ctl_cut mac_tx_ctl_cut_stru;
#endif

struct mac_rx_ctl_cut {
    /* word 0 */
    oal_uint8 bit_vap_id : 5;
    oal_uint8 bit_amsdu_enable : 1;
    oal_uint8 bit_is_first_buffer : 1;
    oal_uint8 bit_is_last_buffer : 1;

    oal_uint8 uc_msdu_in_buffer : 6;
    oal_uint8 bit_is_fragmented : 1;
    oal_uint8 bit_has_tcp_ack_info : 1;

    mac_data_type_enum_uint8 bit_data_frame_type : 4;
    oal_uint8 bit_ta_user_idx : 4;

    oal_uint8 bit_mac_header_len : 6; /* mac header???????? */
    oal_uint8 bit_is_beacon : 1;
    oal_uint8 bit_is_key_frame : 1;
    /* word 1 */
    oal_uint16 us_frame_len; /* ?????????????????? */
    oal_uint8 uc_mac_vap_id : 4;
    oal_uint8 bit_buff_nums : 4; /* ????MPDU??????buf?? */
    oal_uint8 uc_channel_number; /* ???????????? */
} __OAL_DECLARE_PACKED;
typedef struct mac_rx_ctl_cut mac_rx_ctl_cut_stru;

typedef struct {
    oal_wait_queue_head_stru st_wait_queue;
    oal_bool_enum_uint8 mgmt_tx_complete;
    oal_uint32 mgmt_tx_status;
    oal_uint8 mgmt_frame_id;
} oal_mgmt_tx_stru;

#ifdef _PRE_WLAN_WAKEUP_SRC_PARSE
extern oal_void hmac_parse_packet(oal_netbuf_stru *pst_netbuf_eth);

#define WIFI_WAKESRC_TAG "plat:wifi_wake_src,"
#define ipaddr(addr)     \
    ((oal_uint8 *)&addr)[0], \
        ((oal_uint8 *)&addr)[3]

#define ipaddr6(addr)           \
    ntohs((addr).s6_addr16[0]), \
        ntohs((addr).s6_addr16[7])

#define IPV6_ADDRESS_SIZEINBYTES 0x10

struct ieee8021x_hdr {
    oal_uint8 version;
    oal_uint8 type;
    oal_uint16 length;
};
#endif
extern oal_void hmac_board_get_instance(mac_board_stru **ppst_hmac_board);
extern oal_int32 hmac_main_init(oal_void);
extern oal_void hmac_main_exit(oal_void);
extern oal_uint32 hmac_tx_wlan_to_wlan_ap(frw_event_mem_stru *pst_event_mem);
#ifdef _PRE_WLAN_TCP_OPT
extern oal_uint32 hmac_tx_lan_to_wlan_no_tcp_opt(mac_vap_stru *pst_vap, oal_netbuf_stru *pst_buf);
#endif
extern oal_uint32 hmac_tx_lan_to_wlan(mac_vap_stru *pst_vap, oal_netbuf_stru *pst_buf);
extern oal_net_dev_tx_enum hmac_bridge_vap_xmit(oal_netbuf_stru *pst_buf, oal_net_device_stru *pst_dev);

extern oal_uint16 hmac_free_netbuf_list(oal_netbuf_stru *pst_buf);
extern oal_uint32 hmac_vap_get_priv_cfg(mac_vap_stru *pst_mac_vap, hmac_vap_cfg_priv_stru **ppst_cfg_priv);
extern oal_net_device_stru *hmac_vap_get_net_device(oal_uint8 uc_vap_id);
extern oal_int8 *hmac_vap_get_desired_country(oal_uint8 uc_vap_id);
#ifdef _PRE_WLAN_FEATURE_11D
extern oal_uint32 hmac_vap_get_updata_rd_by_ie_switch(oal_uint8 uc_vap_id,
                                                      oal_bool_enum_uint8 *us_updata_rd_by_ie_switch);
#endif
extern oal_uint32 hmac_vap_free_asoc_req_ie_ptr(oal_uint8 uc_vap_id);
extern oal_uint32 hmac_sta_initiate_scan(mac_vap_stru *pst_mac_vap, oal_uint16 us_len, oal_uint8 *puc_param);
extern oal_uint32 hmac_cfg80211_start_sched_scan(mac_vap_stru *pst_mac_vap, oal_uint16 us_len,
                                                 oal_uint8 *puc_param);
extern oal_uint32 hmac_cfg80211_stop_sched_scan(mac_vap_stru *pst_mac_vap, oal_uint16 us_len,
                                                oal_uint8 *puc_param);
extern oal_uint32 hmac_cfg80211_start_scan_sta(mac_vap_stru *pst_mac_vap, oal_uint16 us_len, oal_uint8 *puc_param);
extern oal_uint32 hmac_sta_initiate_join(mac_vap_stru *pst_mac_vap, mac_bss_dscr_stru *pst_bss_dscr);
extern oal_void hmac_mgmt_send_deauth_frame(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_da, oal_uint16 us_err_code,
                                            oal_bool_enum_uint8 en_is_protected);
extern oal_void hmac_mgmt_send_disassoc_frame(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_da, oal_uint16 us_err_code,
                                              oal_bool_enum_uint8 en_is_protected);
extern oal_uint32 hmac_check_capability_mac_phy_supplicant(mac_vap_stru *pst_mac_vap,
                                                           mac_bss_dscr_stru *pst_bss_dscr);
extern oal_uint32 hmac_sdt_recv_reg_cmd(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_buf, oal_uint16 us_len);
#if defined(_PRE_WLAN_FEATURE_DATA_SAMPLE)
extern oal_uint32 hmac_sdt_recv_sample_cmd(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_buf, oal_uint16 us_len);
#endif
extern oal_uint32 hmac_init_event_process(frw_event_mem_stru *pst_event_mem);
#ifdef _PRE_WLAN_FEATURE_BTCOEX
extern oal_uint32 hmac_btcoex_rx_delba_trigger(mac_vap_stru *pst_mac_vap, oal_uint8 uc_len, oal_uint8 *puc_param);
extern oal_void hmac_btcoex_arp_fail_delba_process(oal_netbuf_stru *pst_netbuf, mac_vap_stru *pst_mac_vap);
#endif
extern oal_uint32 hmac_tx_report_eth_frame(mac_vap_stru *pst_mac_vap, oal_netbuf_stru *pst_netbuf);
extern oal_uint32 hmac_wpas_mgmt_tx(mac_vap_stru *pst_mac_vap, oal_uint16 us_len, oal_uint8 *puc_param);
extern oal_uint32 hmac_init_user_security_port(mac_vap_stru *pst_mac_vap, mac_user_stru *pst_mac_user);
extern oal_uint32 hmac_user_set_asoc_state(mac_vap_stru *pst_mac_vap, mac_user_stru *pst_mac_user,
                                           mac_user_asoc_state_enum_uint8 en_value);
#ifdef _PRE_WLAN_FEATURE_AUTO_FREQ
oal_uint32 hmac_set_device_freq_mode(oal_uint8 uc_device_freq_type);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
extern oal_int32 hmac_cfg80211_dump_survey(oal_wiphy_stru *pst_wiphy, oal_net_device_stru *pst_netdev,
                                           oal_int32 l_idx, oal_survey_info_stru *pst_info);
#endif
#ifdef _PRE_WLAN_WAKEUP_SRC_PARSE
extern oal_void hmac_print_data_wakeup_en(oal_bool_enum_uint8 uc_en);
#endif
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#ifndef CONFIG_HAS_EARLYSUSPEND
extern oal_void hmac_do_suspend_action(mac_device_stru *pst_mac_device, oal_uint8 uc_in_suspend);
#endif
#endif
#ifdef _PRE_WLAN_FEATURE_11K
extern oal_uint32 hmac_config_send_neighbor_req(mac_vap_stru *pst_mac_vap, oal_uint16 us_len,
                                                oal_uint8 *puc_param);
extern oal_uint32 hmac_config_bcn_table_switch(mac_vap_stru *pst_mac_vap, oal_uint16 us_len, oal_uint8 *puc_param);
#endif
extern oal_uint32 hmac_config_voe_enable(mac_vap_stru *pst_mac_vap, oal_uint16 us_len, oal_uint8 *puc_param);
oal_uint32 hmac_config_vendor_cmd_get_channel_list(mac_vap_stru *pst_mac_vap, oal_uint16 *pus_len,
                                                   oal_uint8 *puc_param);

#ifdef _PRE_WLAN_FEATURE_CSI_RAM
extern oal_uint32 hmac_config_set_csi(mac_vap_stru *pst_mac_vap, oal_uint16 us_len, oal_uint8 *puc_param);
#endif

extern oal_uint32 hmac_config_protocol_debug_switch(mac_vap_stru *pst_mac_vap, oal_uint16 us_len,
                                                    oal_uint8 *puc_param);
extern oal_uint32 hmac_config_force_pass_filter(mac_vap_stru *pst_mac_vap, oal_uint16 us_len,
                                                oal_uint8 *puc_param);
extern oal_uint32 hmac_config_set_tx_ba_policy(mac_vap_stru *pst_mac_vap, oal_uint16 us_len, oal_uint8 *puc_param);
#ifdef _PRE_WLAN_FEATURE_BTCOEX
extern oal_uint32 hmac_config_set_btcoex_params(mac_vap_stru *pst_mac_vap, oal_uint16 us_len,
                                                oal_uint8 *puc_param);
#endif
extern oal_uint32 hmac_config_query_psm_flt_info(mac_vap_stru *pst_mac_vap, oal_uint16 us_len, oal_uint8 *puc_param);
extern oal_uint32 hmac_config_opmode_switch(mac_vap_stru *pst_mac_vap, oal_uint16 us_len, oal_uint8 *puc_param);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of hmac_ext_if.h */
