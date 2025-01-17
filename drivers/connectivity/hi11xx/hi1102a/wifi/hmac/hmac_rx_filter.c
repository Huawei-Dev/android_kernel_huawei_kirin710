
/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "wlan_types.h"
#include "mac_device.h"
#include "mac_resource.h"
#include "dmac_ext_if.h"
#include "hmac_rx_filter.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HMAC_RX_FILTER_C

/*****************************************************************************
  2 ????????????
*****************************************************************************/
oal_bool_enum_uint8 g_en_rx_filter_enable;
oal_uint32 g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BUTT][MAC_VAP_STATE_BUTT];
oal_uint32 g_ast_multi_staup_sta_rx_filter[MAC_VAP_STA_STATE_BUTT];
oal_uint32 g_ast_multi_staup_ap_rx_filter[MAC_VAP_AP_STATE_BUTT];
oal_uint32 g_ast_multi_apup_sta_rx_filter[MAC_VAP_STA_STATE_BUTT];
oal_uint32 g_rx_filter_val;

/*****************************************************************************
  3 ????????
*****************************************************************************/

oal_bool_enum_uint8 hmac_find_is_sta_up(mac_device_stru *pst_mac_device)
{
    mac_vap_stru *pst_vap = OAL_PTR_NULL;
    oal_uint8 uc_vap_idx;

    for (uc_vap_idx = 0; uc_vap_idx < pst_mac_device->uc_vap_num; uc_vap_idx++) {
        pst_vap = (mac_vap_stru *)mac_res_get_mac_vap(pst_mac_device->auc_vap_id[uc_vap_idx]);
        if (pst_vap == OAL_PTR_NULL) {
            OAM_ERROR_LOG1(0, OAM_SF_SCAN, "{hmac_find_is_sta_up::pst_mac_vap null,vap_idx=%d.}",
                           pst_mac_device->auc_vap_id[uc_vap_idx]);
            continue;
        }

        if ((pst_vap->en_vap_mode == WLAN_VAP_MODE_BSS_STA) && (pst_vap->en_vap_state == MAC_VAP_STATE_UP)) {
            return OAL_TRUE;
        }
    }

    return OAL_FALSE;
}


oal_bool_enum_uint8 hmac_find_is_ap_up(mac_device_stru *pst_mac_device)
{
    mac_vap_stru *pst_vap = OAL_PTR_NULL;
    oal_uint8 uc_vap_idx;

    for (uc_vap_idx = 0; uc_vap_idx < pst_mac_device->uc_vap_num; uc_vap_idx++) {
        pst_vap = (mac_vap_stru *)mac_res_get_mac_vap(pst_mac_device->auc_vap_id[uc_vap_idx]);
        if (pst_vap == OAL_PTR_NULL) {
            OAM_ERROR_LOG1(0, OAM_SF_SCAN, "{hmac_find_is_ap_up::pst_mac_vap null,vap_idx=%d.}",
                           pst_mac_device->auc_vap_id[uc_vap_idx]);
            continue;
        }

        if ((pst_vap->en_vap_state != MAC_VAP_STATE_INIT) && (pst_vap->en_vap_mode == WLAN_VAP_MODE_BSS_AP)) {
            return OAL_TRUE;
        }
    }

    return OAL_FALSE;
}


oal_uint32 hmac_calc_up_ap_num(mac_device_stru *pst_mac_device)
{
    mac_vap_stru *pst_vap = OAL_PTR_NULL;
    oal_uint8 uc_vap_idx;
    oal_uint8 ul_up_ap_num = 0;

    for (uc_vap_idx = 0; uc_vap_idx < pst_mac_device->uc_vap_num; uc_vap_idx++) {
        pst_vap = (mac_vap_stru *)mac_res_get_mac_vap(pst_mac_device->auc_vap_id[uc_vap_idx]);
        if (pst_vap == OAL_PTR_NULL) {
            OAM_ERROR_LOG1(0, OAM_SF_SCAN, "{hmac_calc_up_ap_num::pst_mac_vap null,vap_idx=%d.}",
                           pst_mac_device->auc_vap_id[uc_vap_idx]);
            continue;
        }

        if ((pst_vap->en_vap_state != MAC_VAP_STATE_INIT) && (pst_vap->en_vap_mode == WLAN_VAP_MODE_BSS_AP)) {
            ul_up_ap_num++;
        } else if ((pst_vap->en_vap_mode == WLAN_VAP_MODE_BSS_STA) && (pst_vap->en_vap_state == MAC_VAP_STATE_UP)) {
            ul_up_ap_num++;
        }
    }

    return ul_up_ap_num;
}


oal_uint32 hmac_find_up_vap(mac_device_stru *pst_mac_device, mac_vap_stru **ppst_mac_vap)
{
    oal_uint32 ul_ret;
    mac_vap_stru *pst_vap_up = OAL_PTR_NULL; /* ????UP??????VAP */

    /* find up VAP */
    ul_ret = mac_device_find_up_vap(pst_mac_device, &pst_vap_up);
    if ((ul_ret == OAL_SUCC) && (pst_vap_up != OAL_PTR_NULL)) {
        *ppst_mac_vap = pst_vap_up;
        /* find up AP */
        ul_ret = mac_device_find_up_ap(pst_mac_device, &pst_vap_up);
        if ((ul_ret == OAL_SUCC) && (pst_vap_up != OAL_PTR_NULL)) {
            *ppst_mac_vap = pst_vap_up;
        }

        return OAL_SUCC;
    } else {
        *ppst_mac_vap = OAL_PTR_NULL;
        return OAL_FALSE;
    }
}


oal_uint32 hmac_set_rx_filter_send_event(mac_vap_stru *pst_mac_vap, oal_uint32 ul_rx_filter_val)
{
    oal_uint32 ul_ret;
    frw_event_mem_stru *pst_event_mem = OAL_PTR_NULL;
    frw_event_stru *pst_event = OAL_PTR_NULL;
    mac_device_stru *pst_mac_device = mac_res_get_dev(pst_mac_vap->uc_device_id);
    if (pst_mac_device == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{hmac_set_rx_filter_send_event::mac_device null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ????????DMAC, ???????????? */
    pst_event_mem = frw_event_alloc_m(OAL_SIZEOF(oal_uint32));
    if (pst_event_mem == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{hmac_set_rx_filter_send_event::pst_event_mem null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }
    /* ???????? */
    pst_event = (frw_event_stru *)pst_event_mem->puc_data;

    frw_event_hdr_init(&(pst_event->st_event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX, DMAC_WLAN_CTX_EVENT_SUB_TYPE_SET_RX_FILTER, OAL_SIZEOF(oal_uint32),
                       FRW_EVENT_PIPELINE_STAGE_1, pst_mac_vap->uc_chip_id,
                       pst_mac_vap->uc_device_id, pst_mac_vap->uc_vap_id);
    /* ???????? */
    if (memcpy_s(pst_event->auc_event_data, OAL_SIZEOF(oal_uint32),
        (oal_void *)&ul_rx_filter_val, OAL_SIZEOF(oal_uint32)) != EOK) {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{hmac_set_rx_filter_send_event::memcpy fail!}");
        frw_event_free_m(pst_event_mem);
        return OAL_FAIL;
    }

    /* ???????? */
    ul_ret = frw_event_dispatch_event(pst_event_mem);
    if (ul_ret != OAL_SUCC) {
        frw_event_free_m(pst_event_mem);
        return OAL_FAIL;
    }

    frw_event_free_m(pst_event_mem);
    return OAL_SUCC;
}


oal_uint32 hmac_set_rx_filter_value(mac_vap_stru *pst_mac_vap)
{
#ifndef _PRE_WLAN_PHY_PERFORMANCE
    oal_uint32 ul_rx_filter_val;
    mac_device_stru *pst_mac_device = OAL_PTR_NULL;

    if (pst_mac_vap == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{hmac_set_rx_filter_value::pst_mac_vap null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_mac_device = mac_res_get_dev(pst_mac_vap->uc_device_id);
    if (pst_mac_device == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{hmac_set_rx_filter_value::pst_mac_vap null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }
    if (g_en_rx_filter_enable == OAL_FALSE) {
        return OAL_SUCC;
    }

    if (pst_mac_vap->en_vap_state == MAC_VAP_STATE_PAUSE) {
        return OAL_SUCC;
    }

    /* ??VAP??????AP????UP */
    if (hmac_find_is_ap_up(pst_mac_device)) {
        if ((pst_mac_vap->en_vap_state == MAC_VAP_STATE_INIT) ||
            (pst_mac_vap->en_vap_state == MAC_VAP_STATE_STA_FAKE_UP)) {
            return OAL_SUCC;
        }

        if (pst_mac_vap->en_vap_mode == WLAN_VAP_MODE_BSS_AP) {
            if (hmac_find_is_sta_up(pst_mac_device) && (pst_mac_vap->en_vap_state < MAC_VAP_AP_STATE_BUTT)) {
                ul_rx_filter_val = g_ast_multi_staup_ap_rx_filter[pst_mac_vap->en_vap_state];
            } else {
                ul_rx_filter_val = g_ast_single_vap_rx_filter[pst_mac_vap->en_vap_mode][pst_mac_vap->en_vap_state];
            }
        } else {
            /* ??VAP??????STA????(??STA????up??????STA up??????????????AP????????????????) */
            ul_rx_filter_val = g_ast_multi_apup_sta_rx_filter[pst_mac_vap->en_vap_state];
        }
        /* ??VAP??????STA????UP */
    } else if (hmac_find_is_sta_up(pst_mac_device)) {
        /* ??VAP??????STA????(??STA????up??????STA up??????????????AP????????????????) */
        if ((pst_mac_vap->en_vap_state == MAC_VAP_STATE_INIT) ||
            (pst_mac_vap->en_vap_state == MAC_VAP_STATE_STA_FAKE_UP)) {
            return OAL_SUCC;
        }
        /* STA????UP??????????STA?????? */
        if (pst_mac_vap->en_vap_mode == WLAN_VAP_MODE_BSS_STA) {
            ul_rx_filter_val = g_ast_multi_staup_sta_rx_filter[pst_mac_vap->en_vap_state];
        } else if (pst_mac_vap->en_vap_mode == WLAN_VAP_MODE_BSS_AP) {
            ul_rx_filter_val = g_ast_multi_staup_ap_rx_filter[pst_mac_vap->en_vap_state];
        } else {
            return OAL_SUCC;
        }
    } else {
        /* ????????????????UP??????????VAP???? */
        ul_rx_filter_val = g_ast_single_vap_rx_filter[pst_mac_vap->en_vap_mode][pst_mac_vap->en_vap_state];
    }
    /* ????rx  filter???? */
    g_rx_filter_val = ul_rx_filter_val;
#endif

    return hmac_set_rx_filter_send_event(pst_mac_vap, ul_rx_filter_val);
}


oal_void hmac_rx_filter_init_single_vap(oal_void)
{
    oal_uint32 ul_state;
    oal_uint32 ul_vap_mode;

    for (ul_vap_mode = WLAN_VAP_MODE_CONFIG; ul_vap_mode < WLAN_VAP_MODE_BUTT; ul_vap_mode++) {
        for (ul_state = MAC_VAP_STATE_INIT; ul_state < MAC_VAP_STATE_BUTT; ul_state++) {
            g_ast_single_vap_rx_filter[ul_vap_mode][ul_state] = (1 << 21); /* 1????21?? */
        }
    }

    /* WLAN_VAP_MODE_CONFIG, ???????? */
    /* +---------------------------+--------------------------+ */
    /* | FSM State                 | RX FILTER VALUE          | */
    /* +---------------------------+--------------------------+ */
    /* | All states                | 0x37BDEEFA               | */
    /* +---------------------------+--------------------------+ */
    for (ul_state = MAC_VAP_STATE_INIT; ul_state < MAC_VAP_STATE_BUTT; ul_state++) {
        g_ast_single_vap_rx_filter[WLAN_VAP_MODE_CONFIG][ul_state] = 0x37B9EEFA;
    }

    /* WLAN_VAP_MODE_BSS_STA          BSS STA???? */
    /* +----------------------------------+--------------------------+ */
    /* | FSM State                        | RX FILTER VALUE          | */
    /* +----------------------------------+--------------------------+ */
    /* | MAC_VAP_STATE_INIT               | 0x37BDEEFA               | */
    /* | MAC_VAP_STATE_UP                 | 0x37BDEADA               | */
    /* | MAC_VAP_STATE_STA_FAKE_UP        | 0x37BDEEFA               | */
    /* | MAC_VAP_STATE_STA_WAIT_SCAN      | 0x37BDCEEA               | */
    /* | MAC_VAP_STATE_STA_SCAN_COMP      | 0x37BDEEDA               | */
    /* | MAC_VAP_STATE_STA_WAIT_JOIN      | 0x37BDEEDA               | */
    /* | MAC_VAP_STATE_STA_JOIN_COMP      | 0x37BDEEDA               | */
    /* | MAC_VAP_STATE_STA_WAIT_AUTH_SEQ2 | 0x37BDEEDA               | */
    /* | MAC_VAP_STATE_STA_WAIT_AUTH_SEQ4 | 0x37BDEEDA               | */
    /* | MAC_VAP_STATE_STA_AUTH_COMP      | 0x37BDEEDA               | */
    /* | MAC_VAP_STATE_STA_WAIT_ASOC      | 0x37BDEEDA               | */
    /* | MAC_VAP_STATE_STA_OBSS_SCAN      | 0x37BDCEEA               | */
    /* | MAC_VAP_STATE_STA_BG_SCAN        | 0x37BDCEEA               | */
    /* | MAC_VAP_STATE_STA_LISTEN         | 0x33A9EECA               | */
    /* +----------------------------------+--------------------------+ */
    for (ul_state = MAC_VAP_STATE_INIT; ul_state < MAC_VAP_STATE_BUTT; ul_state++) {
        g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_STA][ul_state] = (1 << 21); /* 1????21?? */
    }

    g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_STA][MAC_VAP_STATE_INIT] = 0xF7B9EEFA;
    g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_STA][MAC_VAP_STATE_STA_FAKE_UP] = 0xF7B9EEFA;
    g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_STA][MAC_VAP_STATE_UP] = 0x73B9EADA;
    g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_STA][MAC_VAP_STATE_PAUSE] = 0x73B9EADA;

    for (ul_state = MAC_VAP_STATE_STA_SCAN_COMP; ul_state <= MAC_VAP_STATE_STA_WAIT_ASOC; ul_state++) {
        g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_STA][ul_state] = 0x73B9EADA;
    }

    g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_STA][MAC_VAP_STATE_STA_WAIT_SCAN] = 0x37B9CECA;
    g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_STA][MAC_VAP_STATE_STA_OBSS_SCAN] = 0x37B9CEEA;
    g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_STA][MAC_VAP_STATE_STA_BG_SCAN] = 0x37B9CEEA;
    g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_STA][MAC_VAP_STATE_STA_LISTEN] = 0x33A9EECA;

#ifdef _PRE_WLAN_FEATURE_ROAM
    g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_STA][MAC_VAP_STATE_ROAMING] = 0x73B9EADA;
#endif

    /* WLAN_VAP_MODE_BSS_AP                BSS AP???? */
    /* +----------------------------------+--------------------------+ */
    /* | FSM State                        | RX FILTER VALUE          | */
    /* +----------------------------------+--------------------------+ */
    /* | MAC_VAP_STATE_INIT               | 0xF7B9EEFA               | */
    /* | MAC_VAP_STATE_UP                 | 0x73B9EAEA               | */
    /* | MAC_VAP_STATE_PAUSE              | 0x73B9EAEA               | */
    /* | MAC_VAP_STATE_AP_WAIT_START      | 0x73B9EAEA               | */
    /* +----------------------------------+--------------------------+ */
    for (ul_state = MAC_VAP_STATE_INIT; ul_state < MAC_VAP_STATE_BUTT; ul_state++) {
        g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_AP][ul_state] = (1 << 21); /* 1????21?? */
    }

    g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_AP][MAC_VAP_STATE_INIT] = 0xF7B9EEFA;
    g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_AP][MAC_VAP_STATE_UP] = 0x73B9EAEA;
    g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_AP][MAC_VAP_STATE_PAUSE] = 0x73B9EAEA;
    g_ast_single_vap_rx_filter[WLAN_VAP_MODE_BSS_AP][MAC_VAP_STATE_AP_WAIT_START] = 0x73B9CAEA;
}


oal_void hmac_rx_filter_init_multi_vap(oal_uint32 ul_proxysta_enabled)
{
    oal_uint32 ul_state;

    for (ul_state = MAC_VAP_STATE_INIT; ul_state < MAC_VAP_STA_STATE_BUTT; ul_state++) {
        g_ast_multi_staup_sta_rx_filter[ul_state] = (1 << 21); /* 1????21?? */
        g_ast_multi_apup_sta_rx_filter[ul_state] = (1 << 21); /* 1????21?? */
    }
    for (ul_state = MAC_VAP_STATE_INIT; ul_state < MAC_VAP_AP_STATE_BUTT; ul_state++) {
        g_ast_multi_staup_ap_rx_filter[ul_state] = (1 << 21); /* 1????21?? */
    }

    /*
       proxysta????????????????????????????51????????????????????????????
       ????????????????????????proxysta??????????????????????????????????????????????????51????????
       ????????????????????????PROXYSTA????????
       ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????if 0??
 */
    {
        /* ??STA????    WLAN_VAP_MODE_BSS_STA          BSS STA???? */
        /* +----------------------------------+--------------------------+ */
        /* | FSM State                        | RX FILTER VALUE          | */
        /* +----------------------------------+--------------------------+ */
        /* | MAC_VAP_STATE_STA_WAIT_SCAN      | 0x33B9CACA               | */
        /* | MAC_VAP_STATE_STA_OBSS_SCAN      | 0x33B9CACA               | */
        /* | MAC_VAP_STATE_STA_BG_SCAN        | 0x33B9CACA               | */
        /* | MAC_VAP_STATE_STA_LISTEN         | 0x33A9EACA               | */
        /* | ALL OTHER STATE                  | 0x73B9EADA               | */
        /* +----------------------------------+--------------------------+ */
        for (ul_state = MAC_VAP_STATE_INIT; ul_state < MAC_VAP_STA_STATE_BUTT; ul_state++) {
            g_ast_multi_staup_sta_rx_filter[ul_state] = 0x73B9EADA;
        }

        g_ast_multi_staup_sta_rx_filter[MAC_VAP_STATE_STA_WAIT_SCAN] = 0x33B9CACA;
        g_ast_multi_staup_sta_rx_filter[MAC_VAP_STATE_STA_OBSS_SCAN] = 0x33B9CACA;
        g_ast_multi_staup_sta_rx_filter[MAC_VAP_STATE_STA_BG_SCAN] = 0x33B9CACA;
        g_ast_multi_staup_sta_rx_filter[MAC_VAP_STATE_STA_LISTEN] = 0x33A9EACA;

        /* ??AP UP??,STA????????:  WLAN_VAP_MODE_BSS_STA   BSS STA???? */
        /* +----------------------------------+--------------------------+ */
        /* | FSM State                        | RX FILTER VALUE          | */
        /* +----------------------------------+--------------------------+ */
        /* | MAC_VAP_STATE_INIT               | ????????????????         | */
        /* | MAC_VAP_STATE_UP                 | 0x73B9EACA               | */
        /* | MAC_VAP_STATE_STA_FAKE_UP        | ????????????????         | */
        /* | MAC_VAP_STATE_STA_WAIT_SCAN      | 0x33B9CACA               | */
        /* | MAC_VAP_STATE_STA_SCAN_COMP      | 0x73B9EACA               | */
        /* | MAC_VAP_STATE_STA_WAIT_JOIN      | 0x73B9EACA               | */
        /* | MAC_VAP_STATE_STA_JOIN_COMP      | 0x73B9EACA               | */
        /* | MAC_VAP_STATE_STA_WAIT_AUTH_SEQ2 | 0x73B9EACA               | */
        /* | MAC_VAP_STATE_STA_WAIT_AUTH_SEQ4 | 0x73B9EACA               | */
        /* | MAC_VAP_STATE_STA_AUTH_COMP      | 0x73B9EACA               | */
        /* | MAC_VAP_STATE_STA_WAIT_ASOC      | 0x73B9EACA               | */
        /* | MAC_VAP_STATE_STA_OBSS_SCAN      | 0x33B9CACA               | */
        /* | MAC_VAP_STATE_STA_BG_SCAN        | 0x33B9CACA               | */
        /* | MAC_VAP_STATE_STA_LISTEN         | 0x33A9EACA               | */
        /* +----------------------------------+--------------------------+ */
        for (ul_state = MAC_VAP_STATE_INIT; ul_state < MAC_VAP_STA_STATE_BUTT; ul_state++) {
            g_ast_multi_apup_sta_rx_filter[ul_state] = (1 << 21); /* 1????21?? */
        }
        g_ast_multi_apup_sta_rx_filter[MAC_VAP_STATE_STA_WAIT_SCAN] = 0x33B9CACA;
        g_ast_multi_apup_sta_rx_filter[MAC_VAP_STATE_STA_OBSS_SCAN] = 0x33B9CACA;
        g_ast_multi_apup_sta_rx_filter[MAC_VAP_STATE_STA_BG_SCAN] = 0x33B9CACA;
        g_ast_multi_apup_sta_rx_filter[MAC_VAP_STATE_STA_LISTEN] = 0x33A9EACA;
        g_ast_multi_apup_sta_rx_filter[MAC_VAP_STATE_UP] = 0x73B9EACA;
#ifdef _PRE_WLAN_FEATURE_ROAM
        g_ast_multi_apup_sta_rx_filter[MAC_VAP_STATE_ROAMING] = 0x73B9EACA;
#endif
        for (ul_state = MAC_VAP_STATE_STA_SCAN_COMP; ul_state <= MAC_VAP_STATE_STA_WAIT_ASOC; ul_state++) {
            g_ast_multi_apup_sta_rx_filter[ul_state] = 0x73B9EACA;
        }

        /* ??STA UP??,AP????????:  WLAN_VAP_MODE_BSS_AP    BSS AP???? */
        /* +----------------------------------+--------------------------+ */
        /* | FSM State                        | RX FILTER VALUE          | */
        /* +----------------------------------+--------------------------+ */
        /* | MAC_VAP_STATE_INIT               | ????????????????         | */
        /* | MAC_VAP_STATE_UP                 | 0x73B9EACA               | */
        /* | MAC_VAP_STATE_PAUSE              | 0x73B9EACA               | */
        /* | MAC_VAP_STATE_AP_WAIT_START      | 0x73B9EACA               | */
        /* +----------------------------------+--------------------------+ */
        for (ul_state = MAC_VAP_STATE_INIT; ul_state < MAC_VAP_AP_STATE_BUTT; ul_state++) {
            g_ast_multi_staup_ap_rx_filter[ul_state] = 0x73B9EACA;
        }

        g_ast_multi_staup_ap_rx_filter[MAC_VAP_STATE_INIT] = (1 << 21); /* 1????21?? */
    }
}

oal_void hmac_rx_filter_init(oal_void)
{
    g_en_rx_filter_enable = OAL_TRUE;

    /* Normal?????????????????? */
    hmac_rx_filter_init_single_vap();
    hmac_rx_filter_init_multi_vap(OAL_FALSE);
}


oal_void hmac_rx_filter_exit(oal_void)
{
    g_en_rx_filter_enable = OAL_FALSE;
}
