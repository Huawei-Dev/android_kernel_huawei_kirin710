
/* 1 ?????????? */
#include "hmac_rx_data.h"
#include "hmac_mgmt_bss_comm.h"
#include "hmac_mgmt_classifier.h"
#include "hmac_fsm.h"
#include "hmac_sme_sta.h"
#include "hmac_mgmt_sta.h"
#include "hmac_mgmt_ap.h"
#include "securec.h"
#ifdef _PRE_WLAN_FEATURE_ROAM
#include "hmac_roam_main.h"
#include "hmac_roam_connect.h"
#include "hmac_roam_alg.h"
#endif  // _PRE_WLAN_FEATURE_ROAM

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HMAC_MGMT_CLASSIFIER_C

/* 2 ???????????? */
#if (defined(_PRE_PRODUCT_ID_HI110X_DEV) && !defined(_PRE_PC_LINT) && !defined(WIN32))
OAL_STATIC oal_uint8 g_uclinklosslogswitch = 0;
#endif

/* 3 ???????? */

oal_void hmac_mgmt_tx_action(
    hmac_vap_stru *pst_hmac_vap, hmac_user_stru *pst_hmac_user, mac_action_mgmt_args_stru *pst_action_args)
{
    if ((pst_hmac_vap == OAL_PTR_NULL) ||
        (pst_hmac_user == OAL_PTR_NULL) ||
        (pst_action_args == OAL_PTR_NULL)) {
        oam_error_log3(0, OAM_SF_TX,
                       "{hmac_mgmt_tx_action::param null, %x %x %x.}",
                       (uintptr_t)pst_hmac_vap, (uintptr_t)pst_hmac_user, (uintptr_t)pst_action_args);
        return;
    }

    switch (pst_action_args->uc_category) {
        case MAC_ACTION_CATEGORY_BA:
            switch (pst_action_args->uc_action) {
                case MAC_BA_ACTION_ADDBA_REQ:
                    oam_info_log0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_TX,
                                  "{hmac_mgmt_tx_action::MAC_BA_ACTION_ADDBA_REQ.}");
                    hmac_mgmt_tx_addba_req(pst_hmac_vap, pst_hmac_user, pst_action_args);
                    break;
                case MAC_BA_ACTION_DELBA:
                    oam_info_log0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_TX,
                                  "{hmac_mgmt_tx_action::MAC_BA_ACTION_DELBA.}");
                    hmac_mgmt_tx_delba(pst_hmac_vap, pst_hmac_user, pst_action_args);
                    break;
                default:
                    OAM_WARNING_LOG1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_TX,
                                     "{hmac_mgmt_tx_action::invalid ba type[%d].}", pst_action_args->uc_action);
                    return; /* ?????????????? */
            }
            break;
        default:
            oam_info_log1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_TX,
                          "{hmac_mgmt_tx_action::invalid ba type[%d].}", pst_action_args->uc_category);
            break;
    }

    return;
}


oal_uint32 hmac_mgmt_tx_priv_req(hmac_vap_stru *pst_hmac_vap,
                                 hmac_user_stru *pst_hmac_user,
                                 mac_priv_req_args_stru *pst_priv_req)
{
    mac_priv_req_11n_enum_uint8 en_req_type;

    if ((pst_hmac_vap == OAL_PTR_NULL) || (pst_hmac_user == OAL_PTR_NULL) || (pst_priv_req == OAL_PTR_NULL)) {
        oam_error_log3(0, OAM_SF_TX,
                       "{hmac_mgmt_tx_priv_req::param null, %x %x %x.}",
                       (uintptr_t)pst_hmac_vap, (uintptr_t)pst_hmac_user, (uintptr_t)pst_priv_req);
        return OAL_ERR_CODE_PTR_NULL;
    }

    en_req_type = pst_priv_req->uc_type;

    switch (en_req_type) {
        case MAC_A_MPDU_START:
            hmac_mgmt_tx_ampdu_start(pst_hmac_vap, pst_hmac_user, pst_priv_req);
            break;
        case MAC_A_MPDU_END:
            hmac_mgmt_tx_ampdu_end(pst_hmac_vap, pst_hmac_user, pst_priv_req);
            break;
        default:
            oam_info_log1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_TX,
                          "{hmac_mgmt_tx_priv_req::invalid en_req_type[%d].}", en_req_type);
            break;
    };

    return OAL_SUCC;
}


oal_uint32 hmac_mgmt_rx_delba_event(frw_event_mem_stru *pst_event_mem)
{
    frw_event_stru *pst_event = OAL_PTR_NULL;
    frw_event_hdr_stru *pst_event_hdr = OAL_PTR_NULL;
    dmac_ctx_action_event_stru *pst_delba_event = OAL_PTR_NULL;
    oal_uint8 *puc_da = OAL_PTR_NULL;      /* ?????????????????????? */
    hmac_vap_stru *pst_vap = OAL_PTR_NULL; /* vap???? */
    hmac_user_stru *pst_hmac_user = OAL_PTR_NULL;
    mac_action_mgmt_args_stru st_action_args;

    if (pst_event_mem == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_BA, "{hmac_mgmt_rx_delba_event::pst_event_mem null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ?????????????????????????? */
    pst_event = (frw_event_stru *)pst_event_mem->puc_data;
    pst_event_hdr = &(pst_event->st_event_hdr);
    pst_delba_event = (dmac_ctx_action_event_stru *)(pst_event->auc_event_data);

    /* ????vap???????? */
    pst_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_event_hdr->uc_vap_id);
    if (oal_unlikely(pst_vap == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(pst_event_hdr->uc_vap_id, OAM_SF_BA,
                       "{hmac_mgmt_rx_delba_event::pst_vap null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ??????????????MAC ADDR */
    puc_da = pst_delba_event->auc_mac_addr;

    /* ???????????????????? */
    pst_hmac_user = mac_vap_get_hmac_user_by_addr(&pst_vap->st_vap_base_info, puc_da);
    if (pst_hmac_user == OAL_PTR_NULL) {
        oam_warning_log0(pst_event_hdr->uc_vap_id, OAM_SF_BA,
                         "{hmac_mgmt_rx_delba_event::mac_vap_find_user_by_macaddr failed.}");
        return OAL_FAIL;
    }

    st_action_args.uc_category = MAC_ACTION_CATEGORY_BA;
    st_action_args.uc_action = MAC_BA_ACTION_DELBA;
    st_action_args.ul_arg1 = pst_delba_event->uc_tidno;     /* ??????????????TID?? */
    st_action_args.ul_arg2 = pst_delba_event->uc_initiator; /* DELBA????????????BA???????????? */
    st_action_args.ul_arg3 = pst_delba_event->uc_status;    /* DELBA??????????reason */
    st_action_args.puc_arg5 = puc_da;                       /* DELBA?????????????? */

    hmac_mgmt_tx_action(pst_vap, pst_hmac_user, &st_action_args);

    return OAL_SUCC;
}


oal_uint32 hmac_rx_process_mgmt_event(frw_event_mem_stru *pst_event_mem)
{
    frw_event_stru *pst_event = OAL_PTR_NULL;
    frw_event_hdr_stru *pst_event_hdr = OAL_PTR_NULL;
    dmac_wlan_crx_event_stru *pst_crx_event = OAL_PTR_NULL;
    oal_netbuf_stru *pst_netbuf = OAL_PTR_NULL; /* ????????????????????NETBUF */
    hmac_vap_stru *pst_vap = OAL_PTR_NULL;      /* vap???? */
    oal_uint32 ul_ret;

    if (pst_event_mem == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_RX, "{hmac_rx_process_mgmt_event::param null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ?????????????????????????? */
    pst_event = (frw_event_stru *)pst_event_mem->puc_data;
    pst_event_hdr = &(pst_event->st_event_hdr);
    pst_crx_event = (dmac_wlan_crx_event_stru *)(pst_event->auc_event_data);
    pst_netbuf = pst_crx_event->pst_netbuf;

    /* ????vap???????? */
    pst_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_event_hdr->uc_vap_id);
    if (oal_unlikely(pst_vap == OAL_PTR_NULL)) {
        oam_warning_log0(pst_event_hdr->uc_vap_id, OAM_SF_BA,
                         "{hmac_mgmt_rx_delba_event::pst_vap null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ???????????????????????????????????????????? */
    if (pst_vap->st_vap_base_info.en_vap_mode == WLAN_VAP_MODE_BSS_AP) {
        ul_ret = hmac_fsm_call_func_ap(pst_vap, HMAC_FSM_INPUT_RX_MGMT, pst_crx_event);
        if (ul_ret != OAL_SUCC) {
            OAM_WARNING_LOG1(0, OAM_SF_BA,
                             "{hmac_rx_process_mgmt_event::hmac_fsm_call_func_ap fail.err code1 [%u]}", ul_ret);
        }
    } else if (pst_vap->st_vap_base_info.en_vap_mode == WLAN_VAP_MODE_BSS_STA) {
        ul_ret = hmac_fsm_call_func_sta(pst_vap, HMAC_FSM_INPUT_RX_MGMT, pst_crx_event);
        if (ul_ret != OAL_SUCC) {
            OAM_WARNING_LOG1(0, OAM_SF_BA,
                             "{hmac_rx_process_mgmt_event::hmac_fsm_call_func_ap fail.err code2 [%u]}", ul_ret);
        }
    }

    /* ?????????????????? */
    oal_netbuf_free(pst_netbuf);

    return OAL_SUCC;
}


oal_uint32 hmac_mgmt_tbtt_event(frw_event_mem_stru *pst_event_mem)
{
    frw_event_stru *pst_event = OAL_PTR_NULL;
    frw_event_hdr_stru *pst_event_hdr = OAL_PTR_NULL;
    hmac_vap_stru *pst_hmac_vap = OAL_PTR_NULL;
    hmac_misc_input_stru st_misc_input;
    oal_uint32 ul_ret;

    if (pst_event_mem == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{hmac_mgmt_tbtt_event::pst_event_mem null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    memset_s(&st_misc_input, OAL_SIZEOF(hmac_misc_input_stru), 0, OAL_SIZEOF(hmac_misc_input_stru));

    /* ?????????????????????????? */
    pst_event = (frw_event_stru *)pst_event_mem->puc_data;
    pst_event_hdr = &(pst_event->st_event_hdr);

    pst_hmac_vap = mac_res_get_hmac_vap(pst_event_hdr->uc_vap_id);
    if (pst_hmac_vap == OAL_PTR_NULL) {
        oam_warning_log0(pst_event_hdr->uc_vap_id, OAM_SF_ANY, "{hmac_mgmt_tbtt_event::pst_hmac_vap null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    st_misc_input.en_type = HMAC_MISC_TBTT;

    /* ????sta????????????sta??tbtt??????????hmac */
    ul_ret = hmac_fsm_call_func_sta(pst_hmac_vap, HMAC_FSM_INPUT_MISC, &st_misc_input);
    if (ul_ret != OAL_SUCC) {
        OAM_WARNING_LOG1(pst_event_hdr->uc_vap_id, OAM_SF_ANY,
                         "{hmac_mgmt_tbtt_event::hmac_fsm_call_func_sta fail. erro code is %u}", ul_ret);
    }

    return ul_ret;
}


oal_uint32 hmac_mgmt_send_disasoc_deauth_event(frw_event_mem_stru *pst_event_mem)
{
    frw_event_stru *pst_event = OAL_PTR_NULL;
    frw_event_hdr_stru *pst_event_hdr = OAL_PTR_NULL;
    dmac_diasoc_deauth_event *pst_disasoc_deauth_event = OAL_PTR_NULL;
    oal_uint8 *puc_da = OAL_PTR_NULL;      /* ?????????????????????? */
    hmac_vap_stru *pst_vap = OAL_PTR_NULL; /* vap???? */
    hmac_user_stru *pst_hmac_user = OAL_PTR_NULL;
    oal_uint32 ul_rslt;
    oal_uint16 us_user_idx;
    oal_uint8 uc_event;
    mac_vap_stru *pst_mac_vap = OAL_PTR_NULL;
    oal_uint16 us_err_code;
#ifdef _PRE_WLAN_FEATURE_P2P
    mac_vap_stru *pst_up_vap1;
    mac_vap_stru *pst_up_vap2;
    mac_device_stru *pst_mac_device;
#endif

    if (pst_event_mem == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_ASSOC, "{hmac_mgmt_send_disasoc_deauth_event::pst_event_mem null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ?????????????????????????? */
    pst_event = (frw_event_stru *)pst_event_mem->puc_data;
    pst_event_hdr = &(pst_event->st_event_hdr);
    pst_disasoc_deauth_event = (dmac_diasoc_deauth_event *)(pst_event->auc_event_data);

    /* ????vap???????? */
    pst_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_event_hdr->uc_vap_id);
    if (oal_unlikely(pst_vap == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(pst_event_hdr->uc_vap_id, OAM_SF_ASSOC, "{hmac_mgmt_send_disasoc_deauth_event::pst_vap null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }
    pst_mac_vap = &pst_vap->st_vap_base_info;

    /* ??????????????MAC ADDR */
    puc_da = pst_disasoc_deauth_event->auc_des_addr;
    uc_event = pst_disasoc_deauth_event->uc_event;
    us_err_code = pst_disasoc_deauth_event->uc_reason;

    /* ??????????, ?????????????????????? */
    if (uc_event == DMAC_WLAN_CRX_EVENT_SUB_TYPE_DEAUTH) {
        hmac_mgmt_send_deauth_frame(pst_mac_vap,
                                    puc_da,
                                    us_err_code,
                                    OAL_FALSE);  // ??PMF

#ifdef _PRE_WLAN_FEATURE_P2P
        pst_mac_device = mac_res_get_dev(pst_mac_vap->uc_device_id);
        if (pst_mac_device == OAL_PTR_NULL) {
            OAM_ERROR_LOG1(pst_event_hdr->uc_vap_id, OAM_SF_ASSOC,
                           "{hmac_mgmt_send_disasoc_deauth_event::pst_mac_device[%x] null.}",
                           (uintptr_t)pst_mac_device);
            return OAL_ERR_CODE_PTR_NULL;
        }

        /* ??????????DBAC?????????????????????????????????????????????????????????????? */
        ul_rslt = mac_device_find_2up_vap(pst_mac_device, &pst_up_vap1, &pst_up_vap2);
        if (ul_rslt != OAL_SUCC) {
            return OAL_SUCC;
        }

        if (pst_up_vap1->st_channel.uc_chan_number == pst_up_vap2->st_channel.uc_chan_number) {
            return OAL_SUCC;
        }

        /* ??????????VAP */
        if (pst_mac_vap->uc_vap_id != pst_up_vap1->uc_vap_id) {
            pst_up_vap2 = pst_up_vap1;
        }

        /* ????????VAP??????????????error code?????????????????????????????????????? */
        hmac_mgmt_send_deauth_frame(pst_up_vap2,
                                    puc_da,
                                    us_err_code | MAC_SEND_TWO_DEAUTH_FLAG,
                                    OAL_FALSE);
#endif

        return OAL_SUCC;
    }

    /* ???????????????????? */
    ul_rslt = mac_vap_find_user_by_macaddr(pst_mac_vap, puc_da, &us_user_idx);
    if (ul_rslt != OAL_SUCC) {
        oam_warning_log4(0, OAM_SF_RX,
                         "{disasoc_deauth_event::Hmac cannot find USER by[%02X:XX:XX:%02X:%02X:%02X],del DMAC user}",
                         puc_da[0], puc_da[3], puc_da[4], puc_da[5]); /* puc_da??0??3??4??5byte?????????????? */

        /* ????????????????????????????????????????????????????????????dmac????????(??????hmac_user_del??????????????) */
        return OAL_SUCC;
    }

    /* ??????hmac user,????protected???? */
    pst_hmac_user = mac_res_get_hmac_user(us_user_idx);

    hmac_mgmt_send_disassoc_frame(pst_mac_vap, puc_da, us_err_code, ((pst_hmac_user == OAL_PTR_NULL) ?
                                  OAL_FALSE : pst_hmac_user->st_user_base_info.st_cap_info.bit_pmf_active));

    if (pst_hmac_user != OAL_PTR_NULL) {
        hmac_handle_disconnect_rsp(pst_vap, pst_hmac_user, us_err_code);
    }

    /* ???????? */
    hmac_user_del(pst_mac_vap, pst_hmac_user);

    return OAL_SUCC;
}

OAL_STATIC mac_reason_code_enum_uint16 hmac_disassoc_reason_exchange(
    dmac_disasoc_misc_reason_enum_uint16 en_driver_disasoc_reason)
{
    switch (en_driver_disasoc_reason) {
        case DMAC_DISASOC_MISC_LINKLOSS:
        case DMAC_DISASOC_MISC_KEEPALIVE:
        case DMAC_DISASOC_MISC_GET_CHANNEL_IDX_FAIL:
            return MAC_DEAUTH_LV_SS;
        case DMAC_DISASOC_MISC_CHANNEL_MISMATCH:
            return MAC_UNSPEC_REASON;
        default:
            break;
    }
    OAM_WARNING_LOG1(0, OAM_SF_ASSOC,
                     "{hmac_disassoc_reason_exchange::Unkown driver_disasoc_reason[%d].}",
                     en_driver_disasoc_reason);

    return MAC_UNSPEC_REASON;
}


oal_uint32 hmac_proc_disasoc_misc_event(frw_event_mem_stru *pst_event_mem)
{
    frw_event_stru *pst_event = OAL_PTR_NULL;
    hmac_vap_stru *pst_hmac_vap = OAL_PTR_NULL;
    hmac_user_stru *pst_hmac_user = OAL_PTR_NULL;
    oal_bool_enum_uint8 en_is_protected = OAL_FALSE; /* PMF */
    dmac_disasoc_misc_stru *pdmac_disasoc_misc_stru = OAL_PTR_NULL;
    mac_reason_code_enum_uint16 en_disasoc_reason_code;

    if (oal_unlikely(pst_event_mem == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_ASSOC, "{hmac_proc_disasoc_misc_event::pst_event_mem is null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_event = (frw_event_stru *)pst_event_mem->puc_data;
    pdmac_disasoc_misc_stru = (dmac_disasoc_misc_stru *)pst_event->auc_event_data;
    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_event->st_event_hdr.uc_vap_id);
    if (oal_unlikely(pst_hmac_vap == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_ASSOC, "{hmac_proc_disasoc_misc_event::pst_hmac_vap is null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    oam_warning_log2(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_ASSOC, "{dissasoc user[%d] within reason[%d]!}",
                     pdmac_disasoc_misc_stru->us_user_idx, pdmac_disasoc_misc_stru->en_disasoc_reason);

#ifdef _PRE_WLAN_1102A_CHR
    hmac_chr_set_disasoc_reason(pdmac_disasoc_misc_stru->us_user_idx, pdmac_disasoc_misc_stru->en_disasoc_reason);
#endif

#if (defined(_PRE_PRODUCT_ID_HI110X_DEV) && !defined(_PRE_PC_LINT) && !defined(WIN32))
    /* ????????(????-65dBm)??????link loss??????Bcpu???????????????????????????????????? */
    /* ????????????????????????????????????????????????????????g_ucLinklossLogSwitch=1???????????? */
    if (g_uclinklosslogswitch && (pdmac_disasoc_misc_stru->en_disasoc_reason == DMAC_DISASOC_MISC_LINKLOSS) &&
        (pst_hmac_vap->station_info.signal > -65)) { /* -65dBm */
        wifi_open_bcpu_set(1);

#ifdef PLATFORM_DEBUG_ENABLE
        debug_uart_read_wifi_mem(OAL_TRUE);
#endif
    }
#endif

    if (pst_hmac_vap->st_vap_base_info.en_vap_mode == WLAN_VAP_MODE_BSS_AP) {
        pst_hmac_user = mac_res_get_hmac_user(pdmac_disasoc_misc_stru->us_user_idx);
        if (pst_hmac_user == OAL_PTR_NULL) {
            OAM_WARNING_LOG1(0, OAM_SF_ASSOC, "{pst_hmac_user[%d] is null.}", pdmac_disasoc_misc_stru->us_user_idx);
            return OAL_ERR_CODE_PTR_NULL;
        }

        en_is_protected = pst_hmac_user->st_user_base_info.st_cap_info.bit_pmf_active;
#ifdef _PRE_WLAN_1102A_CHR
        chr_exception_report(CHR_PLATFORM_EXCEPTION_EVENTID, CHR_SYSTEM_WIFI, CHR_LAYER_DRV,
                             CHR_WIFI_DRV_EVENT_SOFTAP_DISCONNECT, pdmac_disasoc_misc_stru->en_disasoc_reason);
#endif
        /* ??????????????????????????????STA */
        hmac_handle_disconnect_rsp_ap(pst_hmac_vap, pst_hmac_user);

        /* ?????????? */
        hmac_mgmt_send_disassoc_frame(&pst_hmac_vap->st_vap_base_info,
                                      pst_hmac_user->st_user_base_info.auc_user_mac_addr,
                                      MAC_ASOC_NOT_AUTH, en_is_protected);

        /* ???????? */
        hmac_user_del(&pst_hmac_vap->st_vap_base_info, pst_hmac_user);
    } else {
        /* ?????? */
        pst_hmac_user = mac_res_get_hmac_user(pst_hmac_vap->st_vap_base_info.uc_assoc_vap_id);
        if (pst_hmac_user == OAL_PTR_NULL) {
            OAM_WARNING_LOG1(0, OAM_SF_ASSOC, "{hmac_proc_disasoc_misc_event::user[%d] is null.}",
                             pst_hmac_vap->st_vap_base_info.uc_assoc_vap_id);
            return OAL_ERR_CODE_PTR_NULL;
        }

        en_is_protected = pst_hmac_user->st_user_base_info.st_cap_info.bit_pmf_active;

        /* ?????????????????? */
        en_disasoc_reason_code = hmac_disassoc_reason_exchange(pdmac_disasoc_misc_stru->en_disasoc_reason);

        if (pdmac_disasoc_misc_stru->en_disasoc_reason != DMAC_DISASOC_MISC_CHANNEL_MISMATCH) {
            /* ??????????????AP */
            hmac_mgmt_send_disassoc_frame(&pst_hmac_vap->st_vap_base_info,
                                          pst_hmac_user->st_user_base_info.auc_user_mac_addr,
                                          en_disasoc_reason_code, en_is_protected);
        }

        /* ???????????? */
        hmac_user_del(&pst_hmac_vap->st_vap_base_info, pst_hmac_user);
        hmac_sta_handle_disassoc_rsp(pst_hmac_vap, en_disasoc_reason_code);
    }

    return OAL_SUCC;
}

#ifdef _PRE_WLAN_FEATURE_ROAM

oal_uint32 hmac_proc_roam_trigger_event(frw_event_mem_stru *pst_event_mem)
{
    frw_event_stru *pst_event;
    hmac_vap_stru *pst_hmac_vap;
    oal_int8 c_rssi;

    if (oal_unlikely(pst_event_mem == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_ROAM, "{hmac_proc_roam_trigger_event::pst_event_mem is null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_event = (frw_event_stru *)pst_event_mem->puc_data;
    c_rssi = *(oal_int8 *)pst_event->auc_event_data;
    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_event->st_event_hdr.uc_vap_id);
    if (oal_unlikely(pst_hmac_vap == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_ROAM, "{hmac_proc_roam_trigger_event::pst_hmac_vap is null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    hmac_roam_trigger_handle(pst_hmac_vap, c_rssi, OAL_TRUE);

    return OAL_SUCC;
}
#endif  // _PRE_WLAN_FEATURE_ROAM

oal_module_symbol(hmac_mgmt_tx_priv_req);
