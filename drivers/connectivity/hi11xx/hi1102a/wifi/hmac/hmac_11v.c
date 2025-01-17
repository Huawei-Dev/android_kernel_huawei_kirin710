
/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "oal_ext_if.h"
#include "oal_net.h"
#include "mac_frame.h"
#include "mac_resource.h"
#include "mac_ie.h"
#include "mac_vap.h"
#include "mac_user.h"
#include "frw_ext_if.h"
#include "hal_ext_if.h"
#include "mac_resource.h"
#include "wlan_types.h"
#include "dmac_ext_if.h"
#include "hmac_mgmt_bss_comm.h"
#include "hmac_11v.h"
#include "hmac_config.h"
#ifdef _PRE_WLAN_FEATURE_ROAM
#include "hmac_roam_main.h"
#include "hmac_roam_connect.h"
#include "hmac_roam_alg.h"
#endif
#include "hmac_scan.h"
#include "securec.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HMAC_11V_C

/*****************************************************************************
  2 ????????????
*****************************************************************************/
#define MAX_REJECT_BSSTREQ_TIMES          5  /* ????????????5????????dmac???? */
#define NEIGHBOR_REPORT_IE_EID            1  /* EID */
#define NEIGHBOR_REPORT_IE_LEN            1  /* LEN */
#define NEIGHBOR_REPORT_IE_BSSID_INFO_1   8  /* BSSID_INFO BIT1 */
#define NEIGHBOR_REPORT_IE_BSSID_INFO_2   9  /* BSSID_INFO BIT2 */
#define NEIGHBOR_REPORT_IE_OPT_CLASS      12 /* OPT_CLASS */
#define NEIGHBOR_REPORT_IE_CHL_NUM        13 /* CHL_NUM */
#define NEIGHBOR_REPORT_IE_PHY_TYPE       14 /* PHY_TYPE */
#define NEIGHBOR_REPORT_IE_CANDIDATE_PERF 2  /* CANDIDATE_PERF */
#define NEIGHBOR_REPORT_IE_DURATION_MIN_1 11 /* DURATION_MIN BIT1 */
#define NEIGHBOR_REPORT_IE_DURATION_MIN_2 10 /* DURATION_MIN BIT2 */
#define NEIGHBOR_REPORT_IE_TERM_DURATION  8  /* TERM_DURATION */
#define NEIGHBOR_LIST_ONLY_ONE_BSS        1  /* ????????????BSS */
#ifdef _PRE_WLAN_FEATURE_11V_ENABLE

oal_void hmac_init_user_11v_ctl_info(hmac_user_11v_ctrl_stru *pst_11v_ctrl_info)
{
    pst_11v_ctrl_info->uc_user_bsst_token = 0;
    pst_11v_ctrl_info->uc_user_status = 0;
    pst_11v_ctrl_info->uc_11v_roam_scan_times = 0;
    pst_11v_ctrl_info->en_only_scan_one_time = 0;
    pst_11v_ctrl_info->mac_11v_callback_fn = OAL_PTR_NULL;
}

oal_void hmac_11v_bsst_req_filter(hmac_vap_stru *pst_hmac_vap, hmac_user_11v_ctrl_stru *pst_11v_ctrl_info)
{
    if (pst_11v_ctrl_info->uc_reject_bsstreq_times >= MAX_REJECT_BSSTREQ_TIMES) {
        if (hmac_config_filter_11v_bsstreq_switch(&(pst_hmac_vap->st_vap_base_info), OAL_TRUE) == OAL_SUCC) {
            pst_11v_ctrl_info->en_bsstreq_filter = OAL_TRUE;
            pst_11v_ctrl_info->uc_reject_bsstreq_times = 0;
        }
    } else {
        pst_11v_ctrl_info->en_bsstreq_filter = OAL_FALSE;
    }
}


oal_uint32 hmac_rx_bsst_req_candidate_info_check(hmac_vap_stru *pst_hmac_vap, oal_uint8 *puc_channel,
                                                 oal_uint8 *puc_bssid)
{
    wlan_channel_band_enum_uint8 en_channel_band;
    oal_uint32 ul_check;
    mac_bss_dscr_stru *pst_bss_dscr;
    oal_uint8 uc_candidate_channel;

    uc_candidate_channel = *puc_channel;
    en_channel_band = mac_get_band_by_channel_num(uc_candidate_channel);
    ul_check = mac_is_channel_num_valid(en_channel_band, uc_candidate_channel);
    pst_bss_dscr = (mac_bss_dscr_stru *)hmac_scan_get_scanned_bss_by_bssid(&pst_hmac_vap->st_vap_base_info, puc_bssid);
    if ((ul_check != OAL_SUCC) && (pst_bss_dscr == OAL_PTR_NULL)) { /* ???????? */
        oam_warning_log3(0, OAM_SF_CFG,
                         "{rxbsstreqcandicheck::channel[%d]is invalid,but bssid:XX:XX:XX:XX:%02X:%02X not in scanlist}",
                         uc_candidate_channel, puc_bssid[4], puc_bssid[5]); /* puc_bssid 4??5?????????????????? */
        return OAL_FAIL;
    } else { /* ???? */
        if ((pst_bss_dscr != OAL_PTR_NULL) && (uc_candidate_channel != pst_bss_dscr->st_channel.uc_chan_number)) {
            /* ?????????????? */
            *puc_channel = pst_bss_dscr->st_channel.uc_chan_number;
            oam_warning_log4(0, OAM_SF_CFG,
                             "{rxbsstreq_candicheck::bssid:XX:XX:XX:XX:%02X:%02X in bssinfo channel=[%d],not [%d]}",
                             puc_bssid[4], puc_bssid[5], /* puc_bssid 4??5?????????????????? */
                             pst_bss_dscr->st_channel.uc_chan_number, uc_candidate_channel);
        }
    }

    return OAL_SUCC;
}


OAL_STATIC oal_void hmac_rx_bsst_req_action_free_res(hmac_bsst_req_info_stru *pst_bsst_req_info)
{
    if (pst_bsst_req_info->puc_session_url != OAL_PTR_NULL) {
        oal_mem_free_m(pst_bsst_req_info->puc_session_url, OAL_TRUE);
        pst_bsst_req_info->puc_session_url = OAL_PTR_NULL;
    }
    if (pst_bsst_req_info->pst_neighbor_bss_list != OAL_PTR_NULL) {
        oal_mem_free_m(pst_bsst_req_info->pst_neighbor_bss_list, OAL_TRUE);
        pst_bsst_req_info->pst_neighbor_bss_list = OAL_PTR_NULL;
    }
}


OAL_STATIC oal_uint32 hmac_11v_check_invalid_bss_in_neighbor_list(mac_user_stru *pst_mac_user,
                                                                  hmac_neighbor_bss_info_stru *pst_neighbor_list_info)
{
    /* ????????????BSSID??????????/??0????/????????AP, ??????BSS???? */
    return ((ether_is_broadcast(pst_neighbor_list_info->auc_mac_addr)) ||
            (ether_is_all_zero(pst_neighbor_list_info->auc_mac_addr)) ||
            (!oal_memcmp(pst_mac_user->auc_user_mac_addr, pst_neighbor_list_info->auc_mac_addr, WLAN_MAC_ADDR_LEN)));
}


OAL_STATIC oal_bool_enum_uint8 hmac_rx_bsst_is_rejected(hmac_bsst_req_info_stru *pst_bsst_req_info,
                                                        mac_user_stru *pst_mac_user,
                                                        oal_uint32 ul_beacon_period)
{
    /* disassoc time >0 && disassoc time < 100ms, candidate bss is invalid, reject */
    return ((pst_bsst_req_info->us_disassoc_time > 0) &&
            (hmac_11v_check_invalid_bss_in_neighbor_list(pst_mac_user, pst_bsst_req_info->pst_neighbor_bss_list) ||
             (pst_bsst_req_info->us_disassoc_time * ul_beacon_period <
              HMAC_11V_REQUEST_DISASSOC_TIME_SCAN_ONE_CHANNEL_TIME)));
}


oal_bool_enum_uint8 hmac_11v_should_single_channel_scan(oal_bool_enum_uint8 en_need_roam,
                                                        oal_uint8 uc_bss_list_num)
{
    if ((en_need_roam == OAL_TRUE) && (uc_bss_list_num == 1)) {
        return OAL_TRUE;
    }
    return OAL_FALSE;
}


#define USERMAC pst_mac_user->auc_user_mac_addr
#define NEIMAC  st_req_info.pst_neighbor_bss_list->auc_mac_addr
void hmac_parse_bsst_req_info(hmac_bsst_req_info_stru *pst_req_info, oal_uint8 *puc_data)
{
    pst_req_info->st_request_mode.bit_candidate_list_include = puc_data[3] & BIT0; /* puc_data[3]??0bit */
    pst_req_info->st_request_mode.bit_abridged = (puc_data[3] & BIT1) ? OAL_TRUE : OAL_FALSE; /* puc_data[3]??1bit */
    /* puc_data[3]??2bit */
    pst_req_info->st_request_mode.bit_bss_disassoc_imminent = (puc_data[3] & BIT2) ? OAL_TRUE : OAL_FALSE;
    /* puc_data[3]??3bit */
    pst_req_info->st_request_mode.bit_termination_include = (puc_data[3] & BIT3) ? OAL_TRUE : OAL_FALSE;
    /* puc_data[3]??4bit */
    pst_req_info->st_request_mode.bit_ess_disassoc_imminent = (puc_data[3] & BIT4) ? OAL_TRUE : OAL_FALSE;
    /* puc_data[5]????8bit??puc_data[4]????16?????????????????????????? */
    pst_req_info->us_disassoc_time = ((oal_uint16)(puc_data[5]) << 8) | puc_data[4];
}

void hmac_process_term_duration(hmac_bsst_req_info_stru *pst_req_info, oal_uint8 *puc_data,
    oal_uint16 *pus_handle_len, oal_uint16 us_frame_len)
{
    oal_int32 l_ret = EOK;
    if ((pst_req_info->st_request_mode.bit_termination_include) &&
        (us_frame_len >= (*pus_handle_len) + MAC_IE_HDR_LEN + HMAC_11V_TERMINATION_TSF_LENGTH + 2)) { /* 2????duration?????????? */
        (*pus_handle_len) += MAC_IE_HDR_LEN; /* ?????????? */
        l_ret += memcpy_s(pst_req_info->st_term_duration.auc_termination_tsf, HMAC_11V_TERMINATION_TSF_LENGTH,
            puc_data + (*pus_handle_len), HMAC_11V_TERMINATION_TSF_LENGTH);
        if (l_ret != EOK) {
            OAM_ERROR_LOG0(0, OAM_SF_ANY, "hmac_process_term_duration::memcpy fail!");
        }
        (*pus_handle_len) += HMAC_11V_TERMINATION_TSF_LENGTH;
        pst_req_info->st_term_duration.us_duration_min =
            /* puc_data[us_handle_len + 1]????8????puc_data[us_handle_len]????16???? */
            (((oal_uint16)puc_data[(*pus_handle_len) + 1]) << 8) | (puc_data[(*pus_handle_len)]);
        (*pus_handle_len) += 2; /* 2????duration???????? */
    }
}

oal_uint32 hmac_parse_url(hmac_bsst_req_info_stru *pst_req_info, oal_uint8 *puc_data,
    oal_uint16 *pus_handle_len, oal_uint16 us_frame_len)
{
    oal_int32 l_ret = EOK;
    oal_uint16 us_url_count = 0;
    if ((pst_req_info->st_request_mode.bit_ess_disassoc_imminent) &&
        (us_frame_len >= (*pus_handle_len) + 1)) {
        if ((puc_data[(*pus_handle_len)] != 0) &&
            (us_frame_len >= (((*pus_handle_len) + 1) + puc_data[(*pus_handle_len)]))) {
            /* ??????????????1 ???????????????????? */
            us_url_count = puc_data[(*pus_handle_len)] * OAL_SIZEOF(oal_uint8) + 1;
            pst_req_info->puc_session_url =
                (oal_uint8 *)oal_mem_alloc_m(OAL_MEM_POOL_ID_LOCAL, us_url_count, OAL_TRUE);
            if (pst_req_info->puc_session_url == OAL_PTR_NULL) {
                OAM_ERROR_LOG0(0, OAM_SF_ANY, "{hmac_parse_url:: puc_session_url alloc fail.}");
                return OAL_FAIL;
            }
            l_ret += memcpy_s(pst_req_info->puc_session_url, us_url_count, puc_data + ((*pus_handle_len) + 1),
                              puc_data[(*pus_handle_len)]);
            if (l_ret != EOK) {
                OAM_ERROR_LOG0(0, OAM_SF_ANY, "hmac_parse_url::memcpy fail!");
            }
            /* ???????????? */
            pst_req_info->puc_session_url[puc_data[(*pus_handle_len)]] = '\0';
        }
        (*pus_handle_len) += (puc_data[(*pus_handle_len)] + 1);
    }
    return OAL_SUCC;
}
void hmac_process_11v(hmac_vap_stru *pst_hvap, hmac_user_stru *pst_hmac_user,
    hmac_bsst_req_info_stru *pst_req_info, oal_bool_enum_uint8 *pen_need_roam)
{
    oal_uint32 ul_ret;
    /* ???????????????????????????? */
    hmac_roam_info_stru *pst_roam_info = (hmac_roam_info_stru *)pst_hvap->pul_roam_info;
    hmac_user_11v_ctrl_stru *pst_11v_ctrl_info = &(pst_hmac_user->st_11v_ctrl_info);
    /* Signal Bridge disable 11v roaming */
    ul_ret = hmac_vap_check_signal_bridge(&pst_hvap->st_vap_base_info);
    if (ul_ret != OAL_SUCC) {
        (*pen_need_roam) = OAL_FALSE;
    }

    if (hmac_11v_should_single_channel_scan((*pen_need_roam), pst_req_info->uc_bss_list_num)) {
        pst_11v_ctrl_info->uc_11v_roam_scan_times = 1;
        hmac_roam_start(pst_hvap, ROAM_SCAN_CHANNEL_ORG_1, OAL_TRUE, ROAM_TRIGGER_11V);
    } else if ((*pen_need_roam) == OAL_TRUE) {
        hmac_roam_start(pst_hvap, ROAM_SCAN_CHANNEL_ORG_BUTT, OAL_TRUE, ROAM_TRIGGER_11V);
    } else {
        pst_roam_info->st_bsst_rsp_info.uc_status_code = WNM_BSS_TM_REJECT_NO_SUITABLE_CANDIDATES;
        hmac_tx_bsst_rsp_action(pst_hvap, pst_hmac_user, &(pst_roam_info->st_bsst_rsp_info));
    }
}
oal_uint32 hmac_process_neighbor_bss_list(hmac_vap_stru *pst_hvap, hmac_user_stru *pst_hmac_user,
    hmac_bsst_req_info_stru *pst_req_info, hmac_bsst_rsp_info_stru *pst_bsst_rsp_info, oal_uint32 ul_beacon_period)
{
    hmac_roam_info_stru *pst_roam_info = NULL;
    oal_bool_enum_uint8 en_need_roam = OAL_TRUE;
    hmac_user_11v_ctrl_stru *pst_11v_ctrl_info = OAL_PTR_NULL;
    mac_user_stru *pst_mac_user = OAL_PTR_NULL;
    oal_uint32 ul_ret;
    oal_int32 l_ret = EOK;

    pst_mac_user = &pst_hmac_user->st_user_base_info;
    pst_11v_ctrl_info = &(pst_hmac_user->st_11v_ctrl_info);

    /* ????channel num???????? */
    ul_ret = hmac_rx_bsst_req_candidate_info_check(pst_hvap, &(pst_req_info->pst_neighbor_bss_list->uc_chl_num),
        pst_req_info->pst_neighbor_bss_list->auc_mac_addr);
    if (ul_ret != OAL_SUCC) {
        en_need_roam = OAL_FALSE;
    }

    /* ??????????????MAC???? */
    l_ret += memcpy_s(pst_11v_ctrl_info->auc_target_bss_addr, WLAN_MAC_ADDR_LEN,
        pst_req_info->pst_neighbor_bss_list->auc_mac_addr, WLAN_MAC_ADDR_LEN);

    memset_s(pst_bsst_rsp_info, OAL_SIZEOF(*pst_bsst_rsp_info), 0, OAL_SIZEOF(*pst_bsst_rsp_info));
    /* ????????????????BSS ????????BSS ????Response??AP */
    pst_bsst_rsp_info->uc_status_code = 0;       /* ?????????????????? */
    pst_bsst_rsp_info->uc_termination_delay = 0; /* ????????????5??????????????????????0 */
    pst_bsst_rsp_info->uc_chl_num = pst_req_info->pst_neighbor_bss_list->uc_chl_num;
    /* ?????????????? ????request????????????AP?????? */
    l_ret += memcpy_s(pst_bsst_rsp_info->auc_target_bss_addr, WLAN_MAC_ADDR_LEN,
        pst_req_info->pst_neighbor_bss_list->auc_mac_addr, WLAN_MAC_ADDR_LEN);

    /* ????11v????????????rssi???????? */
    pst_bsst_rsp_info->c_rssi = hmac_get_rssi_from_scan_result(pst_hvap, pst_hvap->st_vap_base_info.auc_bssid);

    /* register BSS Transition Response callback function:
        * so that check roaming scan results firstly, and then send bsst rsp frame with right status code */
    pst_11v_ctrl_info->mac_11v_callback_fn = hmac_tx_bsst_rsp_action;

    pst_roam_info = (hmac_roam_info_stru *)pst_hvap->pul_roam_info;
    if (pst_roam_info == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_ROAM, "{hmac_rx_bsst_req_action::roam info is null}");
        hmac_rx_bsst_req_action_free_res(pst_req_info);
        return OAL_FAIL;
    }
    l_ret += memcpy_s(&(pst_roam_info->st_bsst_rsp_info), OAL_SIZEOF(pst_roam_info->st_bsst_rsp_info),
        pst_bsst_rsp_info, OAL_SIZEOF(*pst_bsst_rsp_info));

    /* broadcast address or assocaited AP's address, && disassociation time < 100, BSST reject */
    if (hmac_rx_bsst_is_rejected(pst_req_info, pst_mac_user, ul_beacon_period)) {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{bsstreqcandidate bssid is invalid, us_disassoc_time=%d, will reject}",
                         pst_req_info->us_disassoc_time * ul_beacon_period);
        en_need_roam = OAL_FALSE;
#ifdef _PRE_WLAN_1102A_CHR
        chr_exception_report(CHR_PLATFORM_EXCEPTION_EVENTID, CHR_SYSTEM_WIFI, CHR_LAYER_DRV,
            CHR_WIFI_DRV_EVENT_11V_ROAM_FAIL, CHR_WIFI_DRV_ERROR_INVALID_TARGET_BSS);
#endif
    }

    /* Signal Bridge disable 11v roaming */
    hmac_process_11v(pst_hvap, pst_hmac_user, pst_req_info, &en_need_roam);
    if (l_ret != EOK) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "hmac_process_neighbor_bss_list::memcpy fail!");
    }
    return OAL_SUCC;
}

oal_uint32 hmac_rx_bsst_req_action(hmac_vap_stru *pst_hvap, hmac_user_stru *pst_hmac_user,
                                   oal_netbuf_stru *pst_netbuf)
{
    oal_uint16 us_handle_len;
    dmac_rx_ctl_stru *pst_rx_ctrl = OAL_PTR_NULL;
    oal_uint16 us_frame_len;
    oal_uint8 *puc_data = OAL_PTR_NULL;
    hmac_bsst_req_info_stru st_req_info;
    hmac_bsst_rsp_info_stru st_bsst_rsp_info;
    hmac_user_11v_ctrl_stru *pst_11v_ctrl_info = OAL_PTR_NULL;
    mac_user_stru *pst_mac_user = OAL_PTR_NULL;
    oal_uint8 uc_vap_id = 0;
    oal_uint32 ul_beacon_period;

    if (oal_any_null_ptr3(pst_hvap, pst_hmac_user, pst_netbuf)) {
        oam_error_log3(uc_vap_id, OAM_SF_ANY, "{hmac_rx_bsst_req_action::null param, vap:0x%x user:0x%x buf:0x%x.}",
                       (uintptr_t)pst_hvap, (uintptr_t)pst_hmac_user, (uintptr_t)pst_netbuf);
        return OAL_ERR_CODE_PTR_NULL;
    }

    uc_vap_id = pst_hvap->st_vap_base_info.uc_vap_id;
    /* ???????????????? */
    if (mac_mib_get_MgmtOptionBSSTransitionActivated(&pst_hvap->st_vap_base_info) == OAL_FALSE) {
        oam_warning_log0(uc_vap_id, OAM_SF_ANY, "{hmac_rx_bsst_req_action:: BSSTransitionActivated is disabled}");
        return OAL_SUCC;
    }
    pst_mac_user = &pst_hmac_user->st_user_base_info;
    pst_11v_ctrl_info = &(pst_hmac_user->st_11v_ctrl_info);
    /* ??????11v?????? */
    hmac_init_user_11v_ctl_info(pst_11v_ctrl_info);
    pst_rx_ctrl = (dmac_rx_ctl_stru *)oal_netbuf_cb(pst_netbuf);
    /* ???????????? */
    puc_data = MAC_GET_RX_PAYLOAD_ADDR(&(pst_rx_ctrl->st_rx_info), pst_netbuf);
    us_frame_len = MAC_GET_RX_CB_PAYLOAD_LEN(&(pst_rx_ctrl->st_rx_info)); /* ???????? */
    /* ????????????????7 ????7?????????? */
    if (us_frame_len < HMAC_11V_REQUEST_FRAME_BODY_FIX) {
        OAM_ERROR_LOG1(pst_hvap->st_vap_base_info.uc_vap_id, OAM_SF_ROAM, "{rxbsstreq::len err%d.}", us_frame_len);
        return OAL_FAIL;
    }

    /* ?????????????????????? ?????????? */
    /* ????Token ?????????????????????? ????Token */
    if (puc_data[2] != pst_11v_ctrl_info->uc_user_bsst_token) { /* puc_data??2??????Token */
        pst_11v_ctrl_info->uc_user_bsst_token = puc_data[2];
    }
    /* ????request mode */
    memset_s(&st_req_info, OAL_SIZEOF(st_req_info), 0, OAL_SIZEOF(st_req_info));
    hmac_parse_bsst_req_info(&st_req_info, puc_data);
    ul_beacon_period = mac_mib_get_BeaconPeriod(&pst_hvap->st_vap_base_info);
    if (((st_req_info.us_disassoc_time * ul_beacon_period) >= HMAC_11V_REQUEST_DISASSOC_TIME_SCAN_ONE_CHANNEL_TIME) &&
        ((st_req_info.us_disassoc_time * ul_beacon_period) < HMAC_11V_REQUEST_DISASSOC_TIME_SCAN_ALL_CHANNEL_TIME)) {
        pst_11v_ctrl_info->en_only_scan_one_time = OAL_TRUE;
    }

    st_req_info.uc_validity_interval = puc_data[6]; /* puc_data??6??????????????????????  */
    us_handle_len = 7; /* ????7???????????????? */
    /* 12??????termination duration ?????????? */
    hmac_process_term_duration(&st_req_info, puc_data, &us_handle_len, us_frame_len);
    /* ????URL */
    /* URL???? ?????????? URL????????????URL???? ???????????????? */
    st_req_info.puc_session_url = OAL_PTR_NULL;
    if (hmac_parse_url(&st_req_info, puc_data, &us_handle_len, us_frame_len) != OAL_SUCC) {
        return OAL_FAIL;
    }

    if (us_handle_len > us_frame_len) {
        oam_warning_log2(0, OAM_SF_ANY, "{rxbssreq::handle_len [%d] > frame_len [%d]}", us_handle_len, us_frame_len);
        /* ?????????????????? */
        if (st_req_info.puc_session_url != OAL_PTR_NULL) {
            oal_mem_free_m(st_req_info.puc_session_url, OAL_TRUE);
            st_req_info.puc_session_url = OAL_PTR_NULL;
        }
        return OAL_FAIL;
    }
    /* Candidate bss list????STA??Response frame?????? ?????????????????????????? ?????????? */
    st_req_info.pst_neighbor_bss_list = OAL_PTR_NULL;
    if (st_req_info.st_request_mode.bit_candidate_list_include) {
        puc_data += us_handle_len;
        st_req_info.pst_neighbor_bss_list =
            hmac_get_target_bss_from_neighbor_list(pst_mac_user, puc_data, us_frame_len - us_handle_len,
                                                   &st_req_info.uc_bss_list_num);
    }

    oam_warning_log4(uc_vap_id, OAM_SF_ANY, "{hmac_rx_bsst_req_action::user=xx:xx:xx:%02x:%02x:%02x bss_list_num=%d}",
                     /* USERMAC ??3??4??5?????????????????? */
                     USERMAC[3], USERMAC[4], USERMAC[5], st_req_info.uc_bss_list_num);

    /* ????????????????11v???? */
    if (st_req_info.pst_neighbor_bss_list != OAL_PTR_NULL) {
        /* ????????????????????BSS????BSS????, ??????????????????0, ??????, ?????? */
        if ((st_req_info.pst_neighbor_bss_list->uc_valid_candidate_bss == OAL_FALSE) &&
            (st_req_info.uc_bss_list_num == NEIGHBOR_LIST_ONLY_ONE_BSS) && (st_req_info.us_disassoc_time == 0)) {
            oam_warning_log0(0, OAM_SF_ANY, "{hmac_rx_bsst_req_action::candidate bssid is invalid, will not roam}");
#ifdef _PRE_WLAN_1102A_CHR
            chr_exception_report(CHR_PLATFORM_EXCEPTION_EVENTID, CHR_SYSTEM_WIFI, CHR_LAYER_DRV,
                                 CHR_WIFI_DRV_EVENT_11V_ROAM_FAIL, CHR_WIFI_DRV_ERROR_ONLY_ONE_INVALID_BSS);
#endif
        } else {
            oam_warning_log4(uc_vap_id, OAM_SF_ANY, "{rxbsstreq::candibssid=xx:xx:xx:%02x:%02x:%02x, dst AP's chan=%d}",
                             /* NEIMAC??3??4??5?????????????????? */
                             NEIMAC[3], NEIMAC[4], NEIMAC[5], st_req_info.pst_neighbor_bss_list->uc_chl_num);
            if (hmac_process_neighbor_bss_list(pst_hvap, pst_hmac_user, &st_req_info, 
                &st_bsst_rsp_info, ul_beacon_period) != OAL_SUCC) {
                return OAL_FAIL;
            }
        }
    }
    /* ???????? */
    hmac_rx_bsst_req_action_free_res(&st_req_info);

    return OAL_SUCC;
}


oal_uint32 hmac_tx_bsst_rsp_action(void *pst_void1, void *pst_void2, void *pst_void3)
{
    hmac_vap_stru *pst_hmac_vap = (hmac_vap_stru *)pst_void1;
    hmac_user_stru *pst_hmac_user = (hmac_user_stru *)pst_void2;
    hmac_bsst_rsp_info_stru *pst_bsst_rsp_info = (hmac_bsst_rsp_info_stru *)pst_void3;
    oal_netbuf_stru *pst_bsst_rsp_buf = OAL_PTR_NULL;
    oal_uint16 us_frame_len;
    mac_tx_ctl_stru *pst_tx_ctl = OAL_PTR_NULL;
    oal_uint32 ul_ret;
    hmac_user_11v_ctrl_stru *pst_11v_ctrl_info = OAL_PTR_NULL;
    oal_uint8 uc_vap_id = 0;

    if ((pst_hmac_vap == OAL_PTR_NULL) || (pst_hmac_user == OAL_PTR_NULL) || (pst_bsst_rsp_info == OAL_PTR_NULL)) {
        oam_error_log3(uc_vap_id, OAM_SF_ANY, "{hmac_tx_bsst_rsp_action::null param, %x %x %x.}",
                       (uintptr_t)pst_hmac_vap, (uintptr_t)pst_hmac_user, (uintptr_t)pst_bsst_rsp_info);
        return OAL_ERR_CODE_PTR_NULL;
    }

    uc_vap_id = pst_hmac_vap->st_vap_base_info.uc_vap_id;
    pst_11v_ctrl_info = &(pst_hmac_user->st_11v_ctrl_info);

    /* ????bss transition request?????????? */
    pst_bsst_rsp_buf = oal_mem_netbuf_alloc(OAL_MGMT_NETBUF, WLAN_MGMT_NETBUF_SIZE, OAL_NETBUF_PRIORITY_HIGH);
    if (pst_bsst_rsp_buf == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_ANY, "{txbsst_rsp::pst_bsst_rsq_buf null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    oal_mem_netbuf_trace(pst_bsst_rsp_buf, OAL_TRUE);
    oal_set_netbuf_prev(pst_bsst_rsp_buf, OAL_PTR_NULL);
    oal_set_netbuf_next(pst_bsst_rsp_buf, OAL_PTR_NULL);
    oam_warning_log0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_ANY, "{tx bsst rsp::encap 11v bsst rsp start.}");
    /* ?????????????????? */
    us_frame_len = hmac_encap_bsst_rsp_action(pst_hmac_vap, pst_hmac_user, pst_bsst_rsp_info, pst_bsst_rsp_buf);
    if (us_frame_len == 0) {
        oal_netbuf_free(pst_bsst_rsp_buf);
        OAM_ERROR_LOG0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_ANY, "{txbsst_rspaction::encapbsstrspfailed.}");
        return OAL_FAIL;
    }
    /* ??????CB */
    memset_s(oal_netbuf_cb(pst_bsst_rsp_buf), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size());
    pst_tx_ctl = (mac_tx_ctl_stru *)oal_netbuf_cb(pst_bsst_rsp_buf);
    MAC_GET_CB_TX_USER_IDX(pst_tx_ctl) = pst_hmac_user->st_user_base_info.us_assoc_id;
    /* ???????????????? */
    pst_tx_ctl->uc_ac = WLAN_WME_AC_MGMT;
    MAC_GET_CB_MPDU_LEN(pst_tx_ctl) = us_frame_len;
    oal_netbuf_put(pst_bsst_rsp_buf, us_frame_len);
    oam_warning_log2(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_ANY,
                     "{hmac_tx_bsst_rsp_action::tx 11v bsst rsp frame, us_frame_len=%d frametype=%d.}",
                     us_frame_len, MAC_GET_CB_FRAME_TYPE(pst_tx_ctl));

    /* ????????dmac?????????? */
    ul_ret = hmac_tx_mgmt_send_event(&pst_hmac_vap->st_vap_base_info, pst_bsst_rsp_buf, us_frame_len);
    if (ul_ret != OAL_SUCC) {
        oal_netbuf_free(pst_bsst_rsp_buf);
        OAM_ERROR_LOG0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_ANY, "{tx_bsstreq_action::tx bsst rspfailed.}");
        return ul_ret;
    }
    /* STA??????Response?? ???????????????????? ??????user????Token????1 ?????????????? */
    if (pst_11v_ctrl_info->uc_user_bsst_token == HMAC_11V_TOKEN_MAX_VALUE) {
        pst_11v_ctrl_info->uc_user_bsst_token = 1;
    } else {
        pst_11v_ctrl_info->uc_user_bsst_token++;
    }

    return OAL_SUCC;
}


oal_uint16 hmac_encap_bsst_rsp_action(hmac_vap_stru *pst_hmac_vap,
                                      hmac_user_stru *pst_hmac_user,
                                      hmac_bsst_rsp_info_stru *pst_bsst_rsp_info,
                                      oal_netbuf_stru *pst_buffer)
{
    oal_uint16 us_index;
    oal_uint8 *puc_mac_header = OAL_PTR_NULL;
    oal_uint8 *puc_payload_addr = OAL_PTR_NULL;
    hmac_user_11v_ctrl_stru *pst_11v_ctrl_info = OAL_PTR_NULL;

    if ((pst_hmac_vap == OAL_PTR_NULL) || (pst_hmac_user == OAL_PTR_NULL) || (pst_bsst_rsp_info == OAL_PTR_NULL) ||
        (pst_buffer == OAL_PTR_NULL)) {
        oam_error_log4(0, OAM_SF_ANY, "{hmac_encap_bsst_rsp_action::null param.vap:%x user:%x info:%x buf:%x}",
                       (uintptr_t)pst_hmac_vap, (uintptr_t)pst_hmac_user, (uintptr_t)pst_bsst_rsp_info,
                       (uintptr_t)pst_buffer);
        return 0;
    }

    pst_11v_ctrl_info = &(pst_hmac_user->st_11v_ctrl_info);

    puc_mac_header = oal_netbuf_header(pst_buffer);
    /*************************************************************************/
    /* Management Frame Format */
    /* -------------------------------------------------------------------- */
    /* |Frame Control|Duration|DA|SA|BSSID|Sequence Control|Frame Body|FCS| */
    /* -------------------------------------------------------------------- */
    /* | 2           |2       |6 |6 |6    |2               |0 - 2312  |4  | */
    /* -------------------------------------------------------------------- */
    /*************************************************************************/
    /*************************************************************************/
    /* Set the fields in the frame header */
    /*************************************************************************/
    /* Frame Control Field ????????????Type/Subtype??????????????0 */
    mac_hdr_set_frame_control(puc_mac_header, WLAN_PROTOCOL_VERSION | WLAN_FC0_TYPE_MGT | WLAN_FC0_SUBTYPE_ACTION);
    /* DA is address of STA addr */
    oal_set_mac_addr(puc_mac_header + WLAN_HDR_ADDR1_OFFSET, pst_hmac_user->st_user_base_info.auc_user_mac_addr);
    /* SA????????????MAC???? */
    oal_set_mac_addr(puc_mac_header + WLAN_HDR_ADDR2_OFFSET, mac_mib_get_StationID(&pst_hmac_vap->st_vap_base_info));
    /* TA??????VAP??BSSID */
    oal_set_mac_addr(puc_mac_header + WLAN_HDR_ADDR3_OFFSET, pst_hmac_vap->st_vap_base_info.auc_bssid);

    /*************************************************************************************************************/
    /* Set the contents of the frame body */
    /*************************************************************************************************************/
    /*************************************************************************************************************/
    /* BSS Transition Response Frame - Frame Body */
    /* ---------------------------------------------------------------------------------------------------------- */
    /* |Category |Action | Token| Status Code | Termination Delay | Target BSSID |   BSS Candidate List Entry */
    /* --------------------------------------------------------------------------------------------------------- */
    /* |1        |1      | 1    |  1          | 1                 | 0-6          |    Optional */
    /* --------------------------------------------------------------------------------------------------------- */
    /*************************************************************************************************************/
    puc_payload_addr = puc_mac_header + MAC_80211_FRAME_LEN;

    /* ??????????frame body???????? */
    us_index = 0;
    /* ????Category */
    puc_payload_addr[us_index] = MAC_ACTION_CATEGORY_WNM;
    us_index++;
    /* ????Action */
    puc_payload_addr[us_index] = MAC_WNM_ACTION_BSS_TRANSITION_MGMT_RESPONSE;
    us_index++;
    /* ????Dialog Token */
    puc_payload_addr[us_index] = pst_11v_ctrl_info->uc_user_bsst_token;
    us_index++;
    /* ????Status Code */
    puc_payload_addr[us_index] = pst_bsst_rsp_info->uc_status_code;
    us_index++;
    /* ????Termination Delay */
    puc_payload_addr[us_index] = pst_bsst_rsp_info->uc_termination_delay;
    us_index++;
    /* ????Target BSSID */
    if (pst_bsst_rsp_info->uc_status_code == 0) {
        if (memcpy_s(puc_payload_addr + us_index, WLAN_MGMT_NETBUF_SIZE - MAC_80211_FRAME_LEN - us_index,
                     pst_bsst_rsp_info->auc_target_bss_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            OAM_ERROR_LOG0(0, OAM_SF_ANY, "hmac_encap_bsst_rsp_action::memcpy fail!");
            return 0;
        }
        us_index += WLAN_MAC_ADDR_LEN;
    }
    return us_index + MAC_80211_FRAME_LEN;
}


OAL_STATIC oal_uint8 hmac_get_bss_num_from_neighbor_list(oal_uint8 *puc_ie_data_find, oal_uint8 *puc_ie_data,
                                                         oal_uint16 us_len_find)
{
    oal_uint8 uc_bss_number = 0;

    while (puc_ie_data_find != OAL_PTR_NULL) {
        puc_ie_data = mac_find_ie(MAC_EID_NEIGHBOR_REPORT, puc_ie_data_find, us_len_find);
        /* ???????????????? */
        if (puc_ie_data == OAL_PTR_NULL) {
            break;
        }
        uc_bss_number++; /* Neighbor Report IE ??????1 */

        if (us_len_find >= puc_ie_data[1] + MAC_IE_HDR_LEN) {
            puc_ie_data_find += (puc_ie_data[1] + MAC_IE_HDR_LEN);
            us_len_find -= (puc_ie_data[1] + MAC_IE_HDR_LEN);
        } else {
            oam_warning_log2(0, OAM_SF_ANY,
                             "{hmac_get_bss_num_from_neighbor_list:: is_len[%d] greater than remain frame len [%d]!}",
                             puc_ie_data[1] + MAC_IE_EXT_HDR_LEN, us_len_find);
            break;
        }
    }

    return uc_bss_number;
}


OAL_STATIC oal_void hmac_11v_handle_bssid_info(oal_uint8 *puc_ie_data,
                                               hmac_neighbor_bss_info_stru *pst_neighbor_list_info)
{
    oal_uint8 uc_ie_data1 = puc_ie_data[NEIGHBOR_REPORT_IE_BSSID_INFO_1];
    oal_uint8 uc_ie_data2 = puc_ie_data[NEIGHBOR_REPORT_IE_BSSID_INFO_2];

    pst_neighbor_list_info->st_bssid_info.bit_ap_reachability = (uc_ie_data1 & BIT1) | (uc_ie_data1 & BIT0);
    pst_neighbor_list_info->st_bssid_info.bit_security = (uc_ie_data1 & BIT2) ? OAL_TRUE : OAL_FALSE;
    pst_neighbor_list_info->st_bssid_info.bit_key_scope = (uc_ie_data1 & BIT3) ? OAL_TRUE : OAL_FALSE;
    pst_neighbor_list_info->st_bssid_info.bit_spectrum_mgmt = (uc_ie_data1 & BIT4) ? OAL_TRUE : OAL_FALSE;
    pst_neighbor_list_info->st_bssid_info.bit_qos = (uc_ie_data1 & BIT5) ? OAL_TRUE : OAL_FALSE;
    pst_neighbor_list_info->st_bssid_info.bit_apsd = (uc_ie_data1 & BIT6) ? OAL_TRUE : OAL_FALSE;
    pst_neighbor_list_info->st_bssid_info.bit_radio_meas = (uc_ie_data1 & BIT7) ? OAL_TRUE : OAL_FALSE;
    pst_neighbor_list_info->st_bssid_info.bit_delay_block_ack = (uc_ie_data2 & BIT0) ? OAL_TRUE : OAL_FALSE;
    pst_neighbor_list_info->st_bssid_info.bit_immediate_block_ack = (uc_ie_data2 & BIT1) ? OAL_TRUE : OAL_FALSE;
    pst_neighbor_list_info->st_bssid_info.bit_mobility_domain = (uc_ie_data2 & BIT2) ? OAL_TRUE : OAL_FALSE;
    pst_neighbor_list_info->st_bssid_info.bit_high_throughput = (uc_ie_data2 & BIT3) ? OAL_TRUE : OAL_FALSE;

    /* ?????????????? */
    pst_neighbor_list_info->uc_opt_class = puc_ie_data[NEIGHBOR_REPORT_IE_OPT_CLASS];
    pst_neighbor_list_info->uc_chl_num = puc_ie_data[NEIGHBOR_REPORT_IE_CHL_NUM];
    pst_neighbor_list_info->uc_phy_type = puc_ie_data[NEIGHBOR_REPORT_IE_PHY_TYPE];
}


OAL_STATIC oal_void hmac_11v_handle_subelement(oal_uint8 uc_neighbor_ie_len, oal_uint8 *puc_ie_data,
                                               hmac_neighbor_bss_info_stru *pst_neighbor_list_info)
{
    const oal_uint8 uc_minmum_ie_len = 13;
    oal_int16 s_sub_ie_len;
    oal_int32 l_ret = EOK;

    s_sub_ie_len = uc_neighbor_ie_len - uc_minmum_ie_len; /* subelement???? */
    puc_ie_data += (uc_minmum_ie_len + MAC_IE_HDR_LEN);   /* ??????????????subelement?? */
    while (s_sub_ie_len > 0) {
        switch (puc_ie_data[0]) {
            case HMAC_NEIGH_SUB_ID_BSS_CANDIDATE_PERF: /* ????3?????? */
            {
                pst_neighbor_list_info->uc_candidate_perf = puc_ie_data[NEIGHBOR_REPORT_IE_CANDIDATE_PERF];
                s_sub_ie_len -= (HMAC_11V_PERFERMANCE_ELEMENT_LEN + MAC_IE_HDR_LEN);
                puc_ie_data += (HMAC_11V_PERFERMANCE_ELEMENT_LEN + MAC_IE_HDR_LEN);
            }
            break;
            case HMAC_NEIGH_SUB_ID_TERM_DURATION: /* ????12?????? */
            {
                l_ret = memcpy_s(pst_neighbor_list_info->st_term_duration.auc_termination_tsf,
                    HMAC_11V_TERMINATION_TSF_LENGTH,
                    puc_ie_data + NEIGHBOR_REPORT_IE_CANDIDATE_PERF, NEIGHBOR_REPORT_IE_TERM_DURATION);
                pst_neighbor_list_info->st_term_duration.us_duration_min =
                    (((oal_uint16)puc_ie_data[NEIGHBOR_REPORT_IE_DURATION_MIN_1]) << NEIGHBOR_REPORT_IE_TERM_DURATION) |
                    (puc_ie_data[NEIGHBOR_REPORT_IE_DURATION_MIN_2]);
                s_sub_ie_len -= (HMAC_11V_TERMINATION_ELEMENT_LEN + MAC_IE_HDR_LEN);
                puc_ie_data += (HMAC_11V_TERMINATION_ELEMENT_LEN + MAC_IE_HDR_LEN);
            }
            break;
            /* ????IE???? ?????? */
            default:
            {
                s_sub_ie_len -= (puc_ie_data[1] + MAC_IE_HDR_LEN);
                puc_ie_data += (puc_ie_data[1] + MAC_IE_HDR_LEN);
            }
            break;
        }
        if (l_ret != EOK) {
            OAM_ERROR_LOG0(0, OAM_SF_ANY, "{hmac_11v_handle_subelement::memcpy fail!}");
        }
    }
}


OAL_STATIC oal_void hmac_select_valid_bss_from_neighbor_list(oal_uint8 uc_bss_number, oal_uint8 *puc_ie_data,
                                                             oal_uint8 *puc_ie_data_find, oal_uint16 us_len_find,
                                                             mac_user_stru *pst_mac_user,
                                                             hmac_neighbor_bss_info_stru *pst_bss_list_alloc)
{
    oal_uint8 uc_bss_list_index = 0;
    oal_uint8 uc_neighbor_ie_len = 0;
    const oal_uint8 uc_minmum_ie_len = 13;
    hmac_neighbor_bss_info_stru st_neighbor_list_info;

    for (uc_bss_list_index = 0; uc_bss_list_index < uc_bss_number; uc_bss_list_index++) {
        memset_s(&st_neighbor_list_info, OAL_SIZEOF(hmac_neighbor_bss_info_stru),
                 0, OAL_SIZEOF(hmac_neighbor_bss_info_stru));

        /* ???????????????????????????????????????????????? */
        puc_ie_data = mac_find_ie(MAC_EID_NEIGHBOR_REPORT, puc_ie_data_find, us_len_find);
        if (puc_ie_data == OAL_PTR_NULL) {
            oam_error_log2(0, OAM_SF_ANY,
                           "{select_valid_bss_from_neighbor_list::cannot find ie.bss_list_index[%d], bss_number[%d].}",
                           uc_bss_list_index, uc_bss_number);
            break;
        }
        /*************************************************************************/
        /* Neighbor Report element Format */
        /* -------------------------------------------------------------------- */
        /* |EID|Len|BSSID|BSSID Info|Operating Class|Channel Number|PHY Type|Opt */
        /* -------------------------------------------------------------------- */
        /* | 1 | 1 |  6  |   4      |     1         |      1       |   1    | var */
        /* -------------------------------------------------------------------- */
        /*************************************************************************/
        uc_neighbor_ie_len = puc_ie_data[1]; /* ???????? */
        if (uc_neighbor_ie_len < uc_minmum_ie_len) {
            OAM_ERROR_LOG1(0, OAM_SF_ANY,
                           "{select_valid_bss_from_neighbor_list::netgh ie len [%d] is abnormal!}", uc_neighbor_ie_len);
            break;
        }

        /* ????Neighbor Report IE?????? ??????????subelement 3 4??????subelement?????????? */
        if (memcpy_s(st_neighbor_list_info.auc_mac_addr, WLAN_MAC_ADDR_LEN,
                     puc_ie_data + NEIGHBOR_REPORT_IE_EID + NEIGHBOR_REPORT_IE_LEN, WLAN_MAC_ADDR_LEN) != EOK) {
            OAM_ERROR_LOG0(0, OAM_SF_ANY, "{hmac_select_valid_bss_from_neighbor_list::memcpy fail!}");
            break;
        }

        /* ????BSSID Information?????????? */
        hmac_11v_handle_bssid_info(puc_ie_data, &st_neighbor_list_info);

        /* ????Subelement ????????????ie??????????subelement ??????3 4 subelement */
        if (uc_neighbor_ie_len > uc_minmum_ie_len) {
            hmac_11v_handle_subelement(uc_neighbor_ie_len, puc_ie_data, &st_neighbor_list_info);
        }

        puc_ie_data_find += (uc_neighbor_ie_len + MAC_IE_HDR_LEN);
        us_len_find -= (uc_neighbor_ie_len + MAC_IE_HDR_LEN);

        /* ????????????????BSS????????, ????Preference??????????????BSS */
        /* ????????????????????BSS */
        if (hmac_11v_check_invalid_bss_in_neighbor_list(pst_mac_user, &st_neighbor_list_info)) {
            continue;
        }

        st_neighbor_list_info.uc_valid_candidate_bss = OAL_TRUE;

        /* ????????bss??????????1.????????????bss; 2.????????????????????bss */
        if ((pst_bss_list_alloc->uc_valid_candidate_bss == OAL_FALSE) ||
            (pst_bss_list_alloc->uc_candidate_perf < st_neighbor_list_info.uc_candidate_perf)) {
            memcpy_s(pst_bss_list_alloc, OAL_SIZEOF(hmac_neighbor_bss_info_stru),
                     &st_neighbor_list_info, OAL_SIZEOF(hmac_neighbor_bss_info_stru));
        }
    }
}


hmac_neighbor_bss_info_stru *hmac_get_target_bss_from_neighbor_list(mac_user_stru *pst_mac_user, oal_uint8 *puc_data,
                                                                    oal_uint16 us_len, oal_uint8 *puc_bss_num)
{
    oal_uint8 *puc_ie_data_find = OAL_PTR_NULL;
    oal_uint8 *puc_ie_data = OAL_PTR_NULL;
    hmac_neighbor_bss_info_stru *pst_bss_list_alloc = OAL_PTR_NULL;
    oal_uint16 us_len_find = us_len;
    oal_uint8 uc_bss_number;

    if (oal_any_null_ptr2(puc_data, puc_bss_num)) {
        oam_warning_log2(0, OAM_SF_ANY,
                         "{hmac_get_target_bss_from_neighbor_list::null pointer puc_data[%x] puc_bss_num[%x].}",
                         (uintptr_t)puc_data, (uintptr_t)puc_bss_num);
        if (puc_bss_num != OAL_PTR_NULL) {
            *puc_bss_num = 0;
        }
        return OAL_PTR_NULL;
    }

    /* ??????????????0???????????????????? */
    if (us_len == 0) {
        *puc_bss_num = 0;
        return OAL_PTR_NULL;
    }
    puc_ie_data_find = puc_data;

    /* ????????????????neighbor list */
    uc_bss_number = hmac_get_bss_num_from_neighbor_list(puc_ie_data_find, puc_ie_data, us_len_find);
    /* ????neighbor ie ??????0 ???????? */
    if (uc_bss_number == 0) {
        *puc_bss_num = 0;
        return OAL_PTR_NULL;
    }

    /* ?????????????????????????? */
    puc_ie_data_find = puc_data;
    us_len_find = us_len;
    pst_bss_list_alloc = (hmac_neighbor_bss_info_stru *)oal_mem_alloc_m(OAL_MEM_POOL_ID_LOCAL,
                                                                        OAL_SIZEOF(hmac_neighbor_bss_info_stru),
                                                                        OAL_TRUE);
    if (pst_bss_list_alloc == OAL_PTR_NULL) {
        oam_error_log2(0, OAM_SF_ANY,
                       "{hmac_get_target_bss_from_neighbor_list::pst_bss_list null pointer.stru size[%d],bss num[%d]}",
                       OAL_SIZEOF(hmac_neighbor_bss_info_stru), uc_bss_number);
        *puc_bss_num = 0;
        return OAL_PTR_NULL;
    }

    memset_s(pst_bss_list_alloc, OAL_SIZEOF(hmac_neighbor_bss_info_stru), 0, OAL_SIZEOF(hmac_neighbor_bss_info_stru));

    /* ????Neighbor list????????bss */
    hmac_select_valid_bss_from_neighbor_list(uc_bss_number, puc_ie_data, puc_ie_data_find,
                                             us_len_find, pst_mac_user, pst_bss_list_alloc);

    *puc_bss_num = uc_bss_number;

    return pst_bss_list_alloc;
}


oal_uint32 hmac_11v_roam_scan_check(hmac_vap_stru *pst_hmac_vap)
{
    hmac_user_stru *pst_hmac_user = OAL_PTR_NULL;
    hmac_user_11v_ctrl_stru *pst_11v_ctrl_info = OAL_PTR_NULL;
    hmac_roam_info_stru *pst_roam_info;
    oal_uint8 uc_vap_id = pst_hmac_vap->st_vap_base_info.uc_vap_id;

    pst_roam_info = (hmac_roam_info_stru *)pst_hmac_vap->pul_roam_info;
    if (pst_roam_info == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(uc_vap_id, OAM_SF_ANY, "{hmac_11v_roam_scan_check::pst_roam_info IS NULL}");
        return OAL_ERR_CODE_ROAM_INVALID_VAP;
    }

    /* ???????????????????? */
    pst_hmac_user = mac_res_get_hmac_user(pst_hmac_vap->st_vap_base_info.uc_assoc_vap_id);
    if (pst_hmac_user == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(uc_vap_id, OAM_SF_ANY, "{hmac_11v_roam_scan_check::pst_hmac_user is NULL}");
        return OAL_ERR_CODE_ROAM_INVALID_USER;
    }
    pst_11v_ctrl_info = &(pst_hmac_user->st_11v_ctrl_info);

    if (pst_11v_ctrl_info->mac_11v_callback_fn == OAL_PTR_NULL) {
        return OAL_SUCC;
    }

    if (pst_11v_ctrl_info->uc_11v_roam_scan_times < MAC_11V_ROAM_SCAN_ONE_CHANNEL_LIMIT) { /* ?????????????????? */
        pst_11v_ctrl_info->uc_11v_roam_scan_times++;
        oam_warning_log3(uc_vap_id, OAM_SF_ANY, "{Trigger One channel scan roam,scan_times[%d],limit[%d].channel=[%d]}",
                         pst_11v_ctrl_info->uc_11v_roam_scan_times, MAC_11V_ROAM_SCAN_ONE_CHANNEL_LIMIT,
                         pst_roam_info->st_bsst_rsp_info.uc_chl_num);
        hmac_roam_start(pst_hmac_vap, ROAM_SCAN_CHANNEL_ORG_1, OAL_TRUE, ROAM_TRIGGER_11V);
    } else if (pst_11v_ctrl_info->uc_11v_roam_scan_times == MAC_11V_ROAM_SCAN_ONE_CHANNEL_LIMIT) { /* ?????????????????? */
        pst_11v_ctrl_info->uc_11v_roam_scan_times++;
        oam_warning_log0(uc_vap_id, OAM_SF_ANY, "{hmac_11v_roam_scan_check::Trigger ALL Channel scan roam.}");
        hmac_roam_start(pst_hmac_vap, ROAM_SCAN_CHANNEL_ORG_BUTT, OAL_TRUE, ROAM_TRIGGER_11V);
    }
    return OAL_SUCC;
}

#endif  // _PRE_WLAN_FEATURE_11V_ENABLE


