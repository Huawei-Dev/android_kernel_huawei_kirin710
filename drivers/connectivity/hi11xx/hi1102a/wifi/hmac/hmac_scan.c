

/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "oam_ext_if.h"
#include "mac_ie.h"
#include "mac_regdomain.h"
#include "mac_device.h"
#include "mac_resource.h"
#include "dmac_ext_if.h"
#include "hmac_fsm.h"
#include "hmac_sme_sta.h"
#include "hmac_resource.h"
#include "hmac_device.h"
#include "hmac_scan.h"
#include "hmac_mgmt_sta.h"
#include "hmac_204080_coexist.h"
#include "hmac_wpa_wpa2.h"
#include "frw_ext_if.h"

#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
#include "hisi_customize_wifi.h"
#endif
#include "hmac_chan_mgmt.h"
#include "hmac_p2p.h"

#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
#include "hisi_customize_wifi.h"
#endif /* #ifdef _PRE_PLAT_FEATURE_CUSTOMIZE */

#ifdef _PRE_WLAN_FEATURE_ROAM
#include "hmac_roam_main.h"
#endif  // _PRE_WLAN_FEATURE_ROAM
#include "oal_main.h"

#ifdef _PRE_WLAN_FEATURE_SNIFFER
#include <hwnet/ipv4/sysctl_sniffer.h>
#endif
#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HMAC_SCAN_C

#define ROAM_RSSI_DIFF_6_DB 6

/*****************************************************************************
  2 ????????????
*****************************************************************************/
hmac_scan_state_enum_uint8 g_en_bgscan_enable_flag = HMAC_BGSCAN_ENABLE;
hmac_scan_state_enum_uint8 hmac_scan_get_en_bgscan_enable_flag(oal_void)
{
    return g_en_bgscan_enable_flag;
}
oal_void hmac_scan_set_en_bgscan_enable_flag(hmac_scan_state_enum_uint8 en_bgscan_enable_flag)
{
    g_en_bgscan_enable_flag = en_bgscan_enable_flag;
}
oal_uint32 g_pd_bss_expire_time = 0;
oal_uint32 hmac_get_pd_bss_expire_time(oal_void)
{
    return g_pd_bss_expire_time;
}
oal_void hmac_set_pd_bss_expire_time(oal_uint32 pd_bss_expire_time)
{
    g_pd_bss_expire_time = pd_bss_expire_time;
}
/*****************************************************************************
  3 ????????
*****************************************************************************/
#define WLAN_INVALD_VHT_MCS                           0xff
#define wlan_get_vht_max_support_mcs(_us_vht_mcs_map) \
    (((_us_vht_mcs_map) == 3) ? WLAN_INVALD_VHT_MCS : \
    ((_us_vht_mcs_map) == 2) ? WLAN_VHT_MCS9 : \
    ((_us_vht_mcs_map) == 1) ? WLAN_VHT_MCS8 : WLAN_VHT_MCS7)


OAL_STATIC oal_void hmac_scan_print_scan_params(mac_scan_req_stru *pst_scan_params, mac_vap_stru *pst_mac_vap)
{
    oam_warning_log4(pst_scan_params->uc_vap_id, OAM_SF_SCAN,
                     "hmac_scan_print_scan_params::Now Scan channel_num[%d] in [%d]ms with scan_func[0x%x], \
                     and ssid_num[%d]!",
                     pst_scan_params->uc_channel_nums,
                     pst_scan_params->us_scan_time,
                     pst_scan_params->uc_scan_func,
                     pst_scan_params->uc_ssid_num);

    oam_warning_log3(pst_scan_params->uc_vap_id, OAM_SF_SCAN,
                     "hmac_scan_print_scan_params::Scan param, p2p_scan[%d], max_scan_count_per_channel[%d], \
                     need back home_channel[%d]!",
                     pst_scan_params->bit_is_p2p0_scan,
                     pst_scan_params->uc_max_scan_count_per_channel,
                     pst_scan_params->en_need_switch_back_home_channel);
    return;
}

OAL_STATIC oal_void hmac_wifi_hide_ssid(oal_uint8 *puc_frame_body, oal_uint16 us_mac_frame_len)
{
    oal_uint8 *puc_ssid_ie = OAL_PTR_NULL;
    oal_uint8 uc_ssid_len = 0;
    oal_uint8 uc_index = 0;

    if (puc_frame_body == OAL_PTR_NULL) {
        return;
    }

    puc_ssid_ie = mac_get_ssid(puc_frame_body, us_mac_frame_len, &uc_ssid_len);
    /* ????4????????????4???????????? */
    if ((puc_ssid_ie == OAL_PTR_NULL) || (uc_ssid_len < 4) || (uc_ssid_len > WLAN_SSID_MAX_LEN)) {
        return;
    }

    for (uc_index = 2; uc_index < uc_ssid_len - 2; uc_index++) { // ??????2??????2??
        *(puc_ssid_ie + uc_index) = 0x78;  // 0x78??????ASCII??????????'x'
    }
}


oal_void hmac_scan_print_scanned_bss_info(oal_uint8 uc_device_id)
{
    hmac_device_stru *pst_hmac_device = hmac_res_get_mac_dev(uc_device_id);
    hmac_bss_mgmt_stru *pst_bss_mgmt = OAL_PTR_NULL;
    hmac_scanned_bss_info *pst_scanned_bss = OAL_PTR_NULL;
    mac_bss_dscr_stru *pst_bss_dscr = OAL_PTR_NULL;
    oal_dlist_head_stru *pst_entry = OAL_PTR_NULL;
    mac_ieee80211_frame_stru *pst_frame_hdr = OAL_PTR_NULL;
    oal_uint8 auc_sdt_parse_hdr[MAC_80211_FRAME_LEN];
    oal_uint8 *puc_tmp_mac_body_addr = OAL_PTR_NULL;
    oal_uint8 uc_frame_sub_type;
    oal_int32 l_ret;

    if (pst_hmac_device == OAL_PTR_NULL) {
        oam_warning_log0(0, OAM_SF_SCAN, "{hmac_scan_print_scanned_bss_info::pst_hmac_device null.}");
        return;
    }

    /* ???????????????????????????????? */
    pst_bss_mgmt = &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt.st_bss_mgmt);

    /* ?????? */
    oal_spin_lock(&(pst_bss_mgmt->st_lock));

    /* ????????????bss???? */
    oal_dlist_search_for_each(pst_entry, &(pst_bss_mgmt->st_bss_list_head)) {
        pst_scanned_bss = oal_dlist_get_entry(pst_entry, hmac_scanned_bss_info, st_dlist_head);
        pst_bss_dscr = &(pst_scanned_bss->st_bss_dscr_info);

        /* ????????????????BSS?? */
        if (pst_scanned_bss->st_bss_dscr_info.en_new_scan_bss == OAL_TRUE) {
            /* ????beacon??probe?? */
            pst_frame_hdr = (mac_ieee80211_frame_stru *)pst_bss_dscr->auc_mgmt_buff;

            /* ??beacon??duration????(2????)??????rssi????channel,????SDT???? */
            l_ret = memcpy_s(auc_sdt_parse_hdr, MAC_80211_FRAME_LEN, (oal_uint8 *)pst_frame_hdr, MAC_80211_FRAME_LEN);

            auc_sdt_parse_hdr[2] = (oal_uint8)pst_bss_dscr->c_rssi; /* auc_sdt_parse_hdr??2????????rssi */
            auc_sdt_parse_hdr[3] = pst_bss_dscr->st_channel.uc_chan_number; /* auc_sdt_parse_hdr??3????????channel */
            if (pst_bss_dscr->ul_mgmt_len < MAC_80211_FRAME_LEN) {
                OAM_ERROR_LOG1(0, OAM_SF_SCAN,
                    "{hmac_scan_print_scanned_bss_info::mgmt len[%d] invalid.}", pst_bss_dscr->ul_mgmt_len);
                continue;
            }

            puc_tmp_mac_body_addr = (oal_uint8 *)oal_memalloc(pst_bss_dscr->ul_mgmt_len - MAC_80211_FRAME_LEN);
            if (oal_unlikely(puc_tmp_mac_body_addr == OAL_PTR_NULL)) {
                oam_warning_log0(0, OAM_SF_SCAN, "{hmac_scan_print_scanned_bss_info::alloc memory failed!!}");
                continue;
            }

            l_ret += memcpy_s(puc_tmp_mac_body_addr, pst_bss_dscr->ul_mgmt_len - MAC_80211_FRAME_LEN,
                              (oal_uint8 *)(pst_bss_dscr->auc_mgmt_buff + MAC_80211_FRAME_LEN),
                              pst_bss_dscr->ul_mgmt_len - MAC_80211_FRAME_LEN);
            if (l_ret != EOK) {
                OAM_ERROR_LOG0(0, OAM_SF_SCAN, "hmac_scan_print_scanned_bss_info::memcpy fail!");
                oal_free(puc_tmp_mac_body_addr);
                puc_tmp_mac_body_addr = OAL_PTR_NULL;
                continue;
            }

            uc_frame_sub_type = mac_get_frame_type_and_subtype((oal_uint8 *)pst_frame_hdr);
            if ((uc_frame_sub_type == WLAN_FC0_SUBTYPE_BEACON) || (uc_frame_sub_type == WLAN_FC0_SUBTYPE_PROBE_RSP)) {
                hmac_wifi_hide_ssid(puc_tmp_mac_body_addr, pst_bss_dscr->ul_mgmt_len - MAC_80211_FRAME_LEN);
            }

            /* ????beacon??????probe rsp?? */
            /*lint -e416*/
            oam_report_80211_frame(BROADCAST_MACADDR, (oal_uint8 *)auc_sdt_parse_hdr, MAC_80211_FRAME_LEN,
                                   puc_tmp_mac_body_addr, (oal_uint16)pst_bss_dscr->ul_mgmt_len,
                                   OAM_OTA_FRAME_DIRECTION_TYPE_RX);

            oal_free(puc_tmp_mac_body_addr);
            /*lint +e416*/
#ifdef _PRE_WLAN_FEATURE_SNIFFER
            proc_sniffer_write_file(NULL, 0, pst_bss_dscr->auc_mgmt_buff, (oal_uint16)pst_bss_dscr->ul_mgmt_len, 0);
#endif
        }
    }

    /* ?????? */
    oal_spin_unlock(&(pst_bss_mgmt->st_lock));

    return;
}


OAL_STATIC hmac_scanned_bss_info *hmac_scan_alloc_scanned_bss(oal_uint32 ul_mgmt_len)
{
    hmac_scanned_bss_info *pst_scanned_bss;

    /* ??????????????????????bss???? */
    pst_scanned_bss = oal_memalloc(OAL_SIZEOF(hmac_scanned_bss_info) + ul_mgmt_len -
                                   OAL_SIZEOF(pst_scanned_bss->st_bss_dscr_info.auc_mgmt_buff));
    if (oal_unlikely(pst_scanned_bss == OAL_PTR_NULL)) {
        oam_warning_log0(0, OAM_SF_SCAN,
                         "{hmac_scan_alloc_scanned_bss::alloc memory failed for storing scanned result.}");
        return OAL_PTR_NULL;
    }

    /* ???????????????? */
    memset_s(pst_scanned_bss, OAL_SIZEOF(hmac_scanned_bss_info) + ul_mgmt_len -
             OAL_SIZEOF(pst_scanned_bss->st_bss_dscr_info.auc_mgmt_buff), 0,
             OAL_SIZEOF(hmac_scanned_bss_info) + ul_mgmt_len -
             OAL_SIZEOF(pst_scanned_bss->st_bss_dscr_info.auc_mgmt_buff));

    /* ???????????????????? */
    oal_dlist_init_head(&(pst_scanned_bss->st_dlist_head));

    return pst_scanned_bss;
}


OAL_STATIC oal_void hmac_scan_add_bss_to_list(hmac_scanned_bss_info *pst_scanned_bss,
                                              hmac_device_stru *pst_hmac_device)
{
    hmac_bss_mgmt_stru *pst_bss_mgmt; /* ???????????????????? */

    pst_bss_mgmt = &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt.st_bss_mgmt);
    pst_scanned_bss->st_bss_dscr_info.en_new_scan_bss = OAL_TRUE;

    /* ?????????????????? */
    oal_spin_lock(&(pst_bss_mgmt->st_lock));

    /* ????????????????????????????????????bss???? */
    oal_dlist_add_tail(&(pst_scanned_bss->st_dlist_head), &(pst_bss_mgmt->st_bss_list_head));

    pst_bss_mgmt->ul_bss_num++;
    /* ???? */
    oal_spin_unlock(&(pst_bss_mgmt->st_lock));

    return;
}


OAL_STATIC oal_void hmac_scan_del_bss_from_list_nolock(hmac_scanned_bss_info *pst_scanned_bss,
                                                       hmac_device_stru *pst_hmac_device)
{
    hmac_bss_mgmt_stru *pst_bss_mgmt; /* ???????????????????? */

    pst_bss_mgmt = &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt.st_bss_mgmt);

    /* ????????????????????????????????bss???? */
    oal_dlist_delete_entry(&(pst_scanned_bss->st_dlist_head));

    pst_bss_mgmt->ul_bss_num--;

    return;
}


oal_void hmac_scan_clean_scan_record(hmac_scan_record_stru *pst_scan_record)
{
    oal_dlist_head_stru *pst_entry = OAL_PTR_NULL;
    hmac_scanned_bss_info *pst_scanned_bss = OAL_PTR_NULL;
    hmac_bss_mgmt_stru *pst_bss_mgmt = OAL_PTR_NULL;

    /* ?????????????? */
    if (pst_scan_record == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_scan_clean_scan_record::pst_scan_record is null.}");
        return;
    }

    /* 1.????????????????????bss???????????????????? */
    pst_bss_mgmt = &(pst_scan_record->st_bss_mgmt);

    /* ?????????????????? */
    oal_spin_lock(&(pst_bss_mgmt->st_lock));

    /* ??????????????????????bss???? */
    while (oal_dlist_is_empty(&(pst_bss_mgmt->st_bss_list_head)) == OAL_FALSE) {
        pst_entry = oal_dlist_delete_head(&(pst_bss_mgmt->st_bss_list_head));
        pst_scanned_bss = oal_dlist_get_entry(pst_entry, hmac_scanned_bss_info, st_dlist_head);

        pst_bss_mgmt->ul_bss_num--;

        /* ???????????????????? */
        oal_free(pst_scanned_bss);
    }

    /* ?????????????????? */
    oal_spin_unlock(&(pst_bss_mgmt->st_lock));

    /* 2.???????????? */
    memset_s(pst_scan_record, OAL_SIZEOF(hmac_scan_record_stru), 0, OAL_SIZEOF(hmac_scan_record_stru));
    pst_scan_record->en_scan_rsp_status = MAC_SCAN_STATUS_BUTT; /* ?????????????????????????????? */
    pst_scan_record->en_vap_last_state = MAC_VAP_STATE_BUTT;    /* ??????BUTT,????aput????????vap?????????? */

    /* 3.??????????bss???????????????? */
    pst_bss_mgmt = &(pst_scan_record->st_bss_mgmt);
    oal_dlist_init_head(&(pst_bss_mgmt->st_bss_list_head));
    oal_spin_lock_init(&(pst_bss_mgmt->st_lock));

    oam_info_log0(0, OAM_SF_SCAN, "{hmac_scan_clean_scan_record::cleaned scan record success.}");

    return;
}


OAL_STATIC oal_int32 hmac_is_connected_ap_bssid(oal_uint8 uc_device_id, oal_uint8 auc_bssid[WLAN_MAC_ADDR_LEN])
{
    oal_uint8 uc_vap_idx;
    mac_vap_stru *pst_mac_vap = OAL_PTR_NULL;
    mac_device_stru *pst_mac_device;

    pst_mac_device = mac_res_get_dev(uc_device_id);
    if (oal_unlikely(pst_mac_device == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_is_connected_ap_bssid::mac_res_get_dev return null.}");
        return OAL_FALSE;
    }

    for (uc_vap_idx = 0; uc_vap_idx < pst_mac_device->uc_vap_num; uc_vap_idx++) {
        pst_mac_vap = mac_res_get_mac_vap(pst_mac_device->auc_vap_id[uc_vap_idx]);
        if (oal_unlikely(pst_mac_vap == OAL_PTR_NULL)) {
            OAM_WARNING_LOG1(0, OAM_SF_P2P, "{hmac_is_connected_ap_bssid::mac_res_get_mac_vap fail! vap id is %d}",
                             pst_mac_device->auc_vap_id[uc_vap_idx]);
            continue;
        }

        if (IS_LEGACY_VAP(pst_mac_vap) && (pst_mac_vap->en_vap_state == MAC_VAP_STATE_UP)) {
            if (oal_memcmp(auc_bssid, pst_mac_vap->auc_bssid, WLAN_MAC_ADDR_LEN) == 0) {
                /* ????????????????AP */
                oam_info_log3(pst_mac_vap->uc_vap_id, OAM_SF_SCAN,
                              "{hmac_is_connected_ap_bssid::connected AP bssid:%02X:XX:XX:XX:%02X:%02X}",
                              auc_bssid[0], auc_bssid[4], auc_bssid[5]); /* auc_bssid??0??4??5???????????????? */

                return OAL_TRUE;
            }
        }
    }

    return OAL_FALSE;
}


OAL_STATIC oal_void hmac_scan_clean_expire_scanned_bss(hmac_vap_stru *pst_hmac_vap,
                                                       hmac_scan_record_stru *pst_scan_record)
{
    oal_dlist_head_stru *pst_entry = OAL_PTR_NULL;
    oal_dlist_head_stru *pst_entry_tmp = OAL_PTR_NULL;
    hmac_bss_mgmt_stru *pst_bss_mgmt = OAL_PTR_NULL;
    hmac_scanned_bss_info *pst_scanned_bss = OAL_PTR_NULL;
    mac_bss_dscr_stru *pst_bss_dscr = OAL_PTR_NULL;
    oal_uint32 ul_curr_time_stamp;

    /* ?????????????? */
    if (pst_scan_record == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_scan_clean_expire_scanned_bss::scan record is null.}");
        return;
    }

    /* ??????????bss???????????? */
    pst_bss_mgmt = &(pst_scan_record->st_bss_mgmt);

    ul_curr_time_stamp = (oal_uint32)oal_time_get_stamp_ms();

    /* ?????????????????? */
    oal_spin_lock(&(pst_bss_mgmt->st_lock));

    /* ????????????????????????????????????bss???? */
    oal_dlist_search_for_each_safe(pst_entry, pst_entry_tmp, &(pst_bss_mgmt->st_bss_list_head))
    {
        pst_scanned_bss = oal_dlist_get_entry(pst_entry, hmac_scanned_bss_info, st_dlist_head);
        pst_bss_dscr = &(pst_scanned_bss->st_bss_dscr_info);

        pst_scanned_bss->st_bss_dscr_info.en_new_scan_bss = OAL_FALSE;

        if (oal_time_after32(ul_curr_time_stamp,
                             (pst_bss_dscr->ul_timestamp + HMAC_SCAN_MAX_SCANNED_BSS_EXPIRE)) == OAL_FALSE) {
            continue;
        }
        /* ???????????? */
        if ((hmac_get_pd_bss_expire_time() != 0) &&
            /* 1s????1000ms */
            (ul_curr_time_stamp - pst_bss_dscr->ul_timestamp < hmac_get_pd_bss_expire_time() * 1000)) {
            continue;
        }

        /* ????????????????????AP */
        if (hmac_is_connected_ap_bssid(pst_scan_record->uc_device_id, pst_bss_dscr->auc_bssid)) {
            pst_bss_dscr->c_rssi = pst_hmac_vap->station_info.signal;
            continue;
        }

        /* ????????????????????????????????bss???? */
        oal_dlist_delete_entry(&(pst_scanned_bss->st_dlist_head));
        pst_bss_mgmt->ul_bss_num--;

        /* ???????????? */
        oal_free(pst_scanned_bss);
    }

    /* ?????????????????? */
    oal_spin_unlock(&(pst_bss_mgmt->st_lock));
    return;
}


mac_bss_dscr_stru *hmac_scan_find_scanned_bss_dscr_by_index(oal_uint8 uc_device_id,
                                                            oal_uint32 ul_bss_index)
{
    oal_dlist_head_stru *pst_entry = OAL_PTR_NULL;
    hmac_scanned_bss_info *pst_scanned_bss = OAL_PTR_NULL;
    hmac_device_stru *pst_hmac_device;
    hmac_bss_mgmt_stru *pst_bss_mgmt = OAL_PTR_NULL;
    oal_uint8 ul_loop;

    /* ????hmac device ???? */
    pst_hmac_device = hmac_res_get_mac_dev(uc_device_id);
    if (pst_hmac_device == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_scan_find_scanned_bss_by_index::pst_hmac_device is null.}");
        return OAL_PTR_NULL;
    }

    pst_bss_mgmt = &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt.st_bss_mgmt);

    /* ?????????????????? */
    oal_spin_lock(&(pst_bss_mgmt->st_lock));

    /* ??????????????????????bss?????????????? */
    if (ul_bss_index >= pst_bss_mgmt->ul_bss_num) {
        oam_warning_log0(0, OAM_SF_SCAN, "{hmac_scan_find_scanned_bss_by_index::no such bss in bss list!}");

        /* ???? */
        oal_spin_unlock(&(pst_bss_mgmt->st_lock));
        return OAL_PTR_NULL;
    }

    ul_loop = 0;
    /* ??????????????????index??bss dscr???? */
    oal_dlist_search_for_each(pst_entry, &(pst_bss_mgmt->st_bss_list_head))
    {
        pst_scanned_bss = oal_dlist_get_entry(pst_entry, hmac_scanned_bss_info, st_dlist_head);

        /* ??????bss index???? */
        if (ul_bss_index == ul_loop) {
            /* ???? */
            oal_spin_unlock(&(pst_bss_mgmt->st_lock));
            return &(pst_scanned_bss->st_bss_dscr_info);
        }

        ul_loop++;
    }
    /* ???? */
    oal_spin_unlock(&(pst_bss_mgmt->st_lock));

    return OAL_PTR_NULL;
}


hmac_scanned_bss_info *hmac_scan_find_scanned_bss_by_bssid(hmac_bss_mgmt_stru *pst_bss_mgmt, oal_uint8 *puc_bssid)
{
    oal_dlist_head_stru *pst_entry = OAL_PTR_NULL;
    hmac_scanned_bss_info *pst_scanned_bss = OAL_PTR_NULL;

    /* ????????????????????????????????????bssid??bss???? */
    oal_dlist_search_for_each(pst_entry, &(pst_bss_mgmt->st_bss_list_head))
    {
        pst_scanned_bss = oal_dlist_get_entry(pst_entry, hmac_scanned_bss_info, st_dlist_head);
        /* ??????bssid???? */
        if (oal_compare_mac_addr(pst_scanned_bss->st_bss_dscr_info.auc_bssid, puc_bssid) == 0) {
            return pst_scanned_bss;
        }
    }

    return OAL_PTR_NULL;
}

oal_void *hmac_scan_get_scanned_bss_by_bssid(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_mac_addr)
{
    hmac_bss_mgmt_stru *pst_bss_mgmt = OAL_PTR_NULL; /* ??????????bss???????????? */
    hmac_scanned_bss_info *pst_scanned_bss_info = OAL_PTR_NULL;
    hmac_device_stru *pst_hmac_device;

    /* ????hmac device ???? */
    pst_hmac_device = hmac_res_get_mac_dev(pst_mac_vap->uc_device_id);
    if (pst_hmac_device == OAL_PTR_NULL) {
        OAM_WARNING_LOG1(0, OAM_SF_SCAN, "{hmac_scan_get_scanned_bss_by_bssid::pst_hmac_device is null, dev id[%d].}",
                         pst_mac_vap->uc_device_id);
        return OAL_PTR_NULL;
    }

    /* ??????????????bss???????????? */
    pst_bss_mgmt = &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt.st_bss_mgmt);

    oal_spin_lock(&(pst_bss_mgmt->st_lock));

    pst_scanned_bss_info = hmac_scan_find_scanned_bss_by_bssid(pst_bss_mgmt, puc_mac_addr);
    if (pst_scanned_bss_info == OAL_PTR_NULL) {
        oam_warning_log4(pst_mac_vap->uc_vap_id, OAM_SF_SCAN,
                         "{hmac_scan_get_scanned_bss_by_bssid::find the bss failed[%02X:XX:XX:%02X:%02X:%02X]}",
                         /* puc_mac_addr??0??3??4??5???????????????? */
                         puc_mac_addr[0], puc_mac_addr[3], puc_mac_addr[4], puc_mac_addr[5]);

        /* ???? */
        oal_spin_unlock(&(pst_bss_mgmt->st_lock));
        return OAL_PTR_NULL;
    }

    /* ???? */
    oal_spin_unlock(&(pst_bss_mgmt->st_lock));

    return &(pst_scanned_bss_info->st_bss_dscr_info);
}

#ifdef _PRE_WLAN_NARROW_BAND

OAL_STATIC oal_void hmac_scan_update_bss_list_nb(mac_bss_dscr_stru *pst_bss_dscr, oal_uint8 *puc_frame_body,
                                                 oal_uint16 us_frame_len)
{
    oal_uint8 *puc_ie;

    /* ???????????? */
    if (oal_unlikely((pst_bss_dscr == OAL_PTR_NULL) || (puc_frame_body == OAL_PTR_NULL))) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{hmac_scan_update_bss_list_nb: input pointer is null!}");
        return;
    }

    puc_ie = mac_find_vendor_ie(MAC_HUAWEI_VENDER_IE, MAC_HISI_NB_IE, puc_frame_body, us_frame_len);
    /* ??????????????IE */
    if (puc_ie == OAL_PTR_NULL) {
        pst_bss_dscr->en_nb_capable = OAL_FALSE;
    } else {
        pst_bss_dscr->en_nb_capable = OAL_TRUE;
    }
}
#endif


OAL_STATIC OAL_INLINE oal_void hmac_scan_update_bss_list_wmm(mac_bss_dscr_stru *pst_bss_dscr,
                                                             oal_uint8 *puc_frame_body,
                                                             oal_uint16 us_frame_len)
{
    oal_uint8 *puc_ie = OAL_PTR_NULL;

    pst_bss_dscr->uc_wmm_cap = OAL_FALSE;
    pst_bss_dscr->uc_uapsd_cap = OAL_FALSE;

    if (us_frame_len <= (MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN)) {
        OAM_WARNING_LOG1(0, OAM_SF_ASSOC, "{hmac_scan_update_bss_list_wmm::us_frame_len[%d]!}", us_frame_len);
        return;
    }

    us_frame_len -= (MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN);
    puc_frame_body += (MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN);

    puc_ie = mac_get_wmm_ie(puc_frame_body, us_frame_len);
    if (puc_ie != OAL_PTR_NULL) {
        pst_bss_dscr->uc_wmm_cap = OAL_TRUE;

        /* --------------------------------------------------------------------------------- */
        /* WMM Information/Parameter Element Format */
        /* ---------------------------------------------------------------------------------- */
        /* EID | IE LEN | OUI | OUIType | OUISubtype | Version | QoSInfo | OUISubtype based | */
        /* --------------------------------------------------------------------------------- */
        /* 1   |   1    |  3  | 1       | 1          | 1       | 1       | ---------------- | */
        /* --------------------------------------------------------------------------------- */
        /* puc_ie[1] IE len ??????EID??LEN????,????QoSInfo??uc_ie_len????????7???????? */
        /* Check if Bit 7 is set indicating U-APSD capability */
        if ((puc_ie[1] >= 7) && (puc_ie[8] & BIT7)) {  /* wmm ie????8????????QoS info???? */
            pst_bss_dscr->uc_uapsd_cap = OAL_TRUE;
        }
    } else {
        puc_ie = mac_find_ie(MAC_EID_HT_CAP, puc_frame_body, us_frame_len);
        if (puc_ie != OAL_PTR_NULL) {
            pst_bss_dscr->uc_wmm_cap = OAL_TRUE;
        }
    }
}

#ifdef _PRE_WLAN_FEATURE_11D

OAL_STATIC oal_void hmac_scan_update_bss_list_country(mac_bss_dscr_stru *pst_bss_dscr,
                                                      oal_uint8 *puc_frame_body,
                                                      oal_uint16 us_frame_len)
{
    oal_uint8 *puc_ie;
    oal_uint8 uc_offset;

    uc_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;

    puc_ie = mac_find_ie(MAC_EID_COUNTRY, puc_frame_body + uc_offset, us_frame_len - uc_offset);
    /* ????????????, ??????????0 */
    if (puc_ie == OAL_PTR_NULL) {
        pst_bss_dscr->ac_country[0] = 0;
        pst_bss_dscr->ac_country[1] = 0; /* ????????????, ac_country??1??????????0 */
        pst_bss_dscr->ac_country[2] = 0; /* ????????????, ac_country??2??????????0 */

        return;
    }

    /* ??????????2??????,IE LEN????????????2 */
    if (puc_ie[1] >= 2) {
        pst_bss_dscr->ac_country[0] = (oal_int8)puc_ie[MAC_IE_HDR_LEN];
        pst_bss_dscr->ac_country[1] = (oal_int8)puc_ie[MAC_IE_HDR_LEN + 1];
        pst_bss_dscr->ac_country[2] = 0; /* ac_country??2??????????0 */
    }
}
#endif

#if defined(_PRE_WLAN_FEATURE_11K) || defined(_PRE_WLAN_FEATURE_FTM)

OAL_STATIC oal_void hmac_scan_update_bss_list_rrm(mac_bss_dscr_stru *pst_bss_dscr, oal_uint8 *puc_frame_body,
                                                  oal_uint16 us_frame_len, oal_uint16 us_offset)
{
    oal_uint8 *puc_ie;

    /* ???????????? */
    if (oal_unlikely((pst_bss_dscr == OAL_PTR_NULL) || (puc_frame_body == OAL_PTR_NULL))) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{hmac_scan_update_bss_list_rrm: input pointer is null!}");
        return;
    }

    puc_ie = mac_find_ie(MAC_EID_RRM, puc_frame_body + us_offset, us_frame_len - us_offset);
    if (puc_ie == OAL_PTR_NULL) {
        pst_bss_dscr->en_support_rrm = OAL_FALSE;
    } else {
        pst_bss_dscr->en_support_rrm = OAL_TRUE;
    }
}
#endif


OAL_STATIC oal_void hmac_scan_update_bss_list_11n(mac_bss_dscr_stru *pst_bss_dscr,
                                                  oal_uint8 *puc_frame_body,
                                                  oal_uint16 us_frame_len,
                                                  oal_uint16 us_offset)
{
    oal_uint8 *puc_ie;
    mac_ht_opern_stru *pst_ht_op = OAL_PTR_NULL;
    oal_uint8 uc_sec_chan_offset;
    wlan_bw_cap_enum_uint8 en_ht_cap_bw = WLAN_BW_CAP_20M;
    wlan_bw_cap_enum_uint8 en_ht_op_bw = WLAN_BW_CAP_20M;

    /* 11n */
    puc_ie = mac_find_ie(MAC_EID_HT_CAP, puc_frame_body + us_offset, us_frame_len - us_offset);
    if ((puc_ie != OAL_PTR_NULL) && (puc_ie[1] >= 2) && /* puc_ie??1????(ie????)????????2 */
        (hmac_is_ht_mcs_set_valid(puc_ie, pst_bss_dscr->st_channel.en_band) == OAL_TRUE)) {
        /* puc_ie[2]??HT Capabilities Info????1?????? */
        pst_bss_dscr->en_ht_capable = OAL_TRUE;        /* ????ht */
        pst_bss_dscr->en_ht_ldpc = (puc_ie[2] & BIT0); /* ????ldpc(puc_ie??2??????BIT0??????) */
        en_ht_cap_bw = ((puc_ie[2] & BIT1) >> 1);      /* ??????????????(puc_ie??2??????BIT1??????????????1) */
        pst_bss_dscr->en_ht_stbc = ((puc_ie[2] & BIT7) >> 7); /* stbc(puc_ie??2??????BIT7??????????????7) */
    }

    /* ????20M,????????????????HT_OPERATION???????????????????? */
    pst_bss_dscr->en_channel_bandwidth = WLAN_BAND_WIDTH_20M;

    puc_ie = mac_find_ie(MAC_EID_HT_OPERATION, puc_frame_body + us_offset, us_frame_len - us_offset);
    if ((puc_ie != OAL_PTR_NULL) && (puc_ie[1] >= 2)) { /* ????ie????????????(puc_ie??1????<ie????>????????2) */
        pst_ht_op = (mac_ht_opern_stru *)(puc_ie + MAC_IE_HDR_LEN);

        /* ?????????????? */
        uc_sec_chan_offset = pst_ht_op->bit_secondary_chan_offset;

        /* ????ap??channel width=0, ??channel offset = 1????3 ??????channel width???? */
        /* ht cap 20/40 enabled && ht operation 40 enabled */
        if ((pst_ht_op->bit_sta_chan_width != 0) && (en_ht_cap_bw > WLAN_BW_CAP_20M)) { // cap > 20M????channel bw
            if (uc_sec_chan_offset == MAC_SCB) {
                pst_bss_dscr->en_channel_bandwidth = WLAN_BAND_WIDTH_40MINUS;
                en_ht_op_bw = WLAN_BW_CAP_40M;
            } else if (uc_sec_chan_offset == MAC_SCA) {
                pst_bss_dscr->en_channel_bandwidth = WLAN_BAND_WIDTH_40PLUS;
                en_ht_op_bw = WLAN_BW_CAP_40M;
            }
        }
    }

    /* ??AP????????????????????????????????AP?????????????????????????????????????? */
    pst_bss_dscr->en_bw_cap = oal_min(en_ht_cap_bw, en_ht_op_bw);

    puc_ie = mac_find_ie(MAC_EID_EXT_CAPS, puc_frame_body + us_offset, us_frame_len - us_offset);
    if ((puc_ie != OAL_PTR_NULL) && (puc_ie[1] >= 1)) {
        /* Extract 20/40 BSS Coexistence Management Support */
        pst_bss_dscr->uc_coex_mgmt_supp = (puc_ie[2] & BIT0);
    }
}

OAL_STATIC oal_void hmac_scan_update_vht_cap(mac_bss_dscr_stru *pst_bss_dscr, oal_uint8 *puc_ie)
{
    oal_uint32 ul_vht_cap_field;
    oal_uint16 us_rx_mcs_map;

    /* ????VHT capablities info field */
    /* puc_ie??2??3??4??5??????????vht_cap_field 32bit */
    ul_vht_cap_field = oal_join_word32(puc_ie[2], puc_ie[3], puc_ie[4], puc_ie[5]);
    us_rx_mcs_map = oal_make_word16(puc_ie[6], puc_ie[7]); /* puc_ie??6??7??????????rx_mcs_map 16bit */
    if ((ul_vht_cap_field != 0) || (us_rx_mcs_map != 0xffff)) {
        pst_bss_dscr->en_vht_capable = OAL_TRUE; /* ????vht */
    }
}

OAL_STATIC oal_void hmac_scan_update_bss_list_11ac(mac_bss_dscr_stru *pst_bss_dscr,
                                                   oal_uint8 *puc_frame_body,
                                                   oal_uint16 us_frame_len,
                                                   oal_uint16 us_offset,
                                                   oal_uint en_is_vendor_ie)
{
    oal_uint8 *puc_ie;
    oal_uint8 uc_vht_chan_width;
    oal_uint8 uc_chan_center_freq;
    oal_uint8 uc_supp_ch_width;

    puc_ie = mac_find_ie(MAC_EID_VHT_CAP, puc_frame_body + us_offset, us_frame_len - us_offset);
    if ((puc_ie != OAL_PTR_NULL) && (puc_ie[1] >= MAC_VHT_CAP_IE_LEN)) {
        hmac_scan_update_vht_cap(pst_bss_dscr, puc_ie);

        /* ????epigram vendor??????VHT ie????????????????assoc req??????????vendor+vht ie */
        if (en_is_vendor_ie == OAL_TRUE) {
            pst_bss_dscr->en_epigram_vht_capable = OAL_TRUE;
        }

        /* ????Supported Channel Width Set??puc_ie[2]??2-3bit?? */
        uc_supp_ch_width = ((puc_ie[2] & (BIT3 | BIT2)) >> 2);

        if (uc_supp_ch_width == 0) {
            pst_bss_dscr->en_bw_cap = WLAN_BW_CAP_80M; /* 80MHz */
        } else if (uc_supp_ch_width == 1) {
            pst_bss_dscr->en_bw_cap = WLAN_BW_CAP_160M; /* 160MHz */
        }
    } else {
        /* ????epigram vendor????????vht ie??????5g 20M ???????? */
        if (en_is_vendor_ie == OAL_TRUE) {
            pst_bss_dscr->en_epigram_novht_capable = OAL_TRUE;
        }
    }

    puc_ie = mac_find_ie(MAC_EID_VHT_OPERN, puc_frame_body + us_offset, us_frame_len - us_offset);
    if ((puc_ie != OAL_PTR_NULL) && (puc_ie[1] >= MAC_VHT_OPERN_LEN)) {
        uc_vht_chan_width = puc_ie[2]; /* puc_ie??2??????vht?????? */
        uc_chan_center_freq = puc_ie[3]; /* puc_ie??3???????????????????? */

        /* ???????????? */
        if (uc_vht_chan_width == 0) { /* 40MHz */
            /* do nothing??en_channel_bandwidth??????HT Operation IE?????? */
        } else if (uc_vht_chan_width == 1) { /* 80MHz */
            switch (uc_chan_center_freq - pst_bss_dscr->st_channel.uc_chan_number) {
                case 6:
                    /***********************************************************************
                | ??20 | ??20 | ??40       |
                              |
                              |????????????????20??6??????
                ************************************************************************/
                    pst_bss_dscr->en_channel_bandwidth = WLAN_BAND_WIDTH_80PLUSPLUS;
                    break;

                case -2:
                    /***********************************************************************
                | ??40        | ??20 | ??20 |
                              |
                              |????????????????20??-2??????
                ************************************************************************/
                    pst_bss_dscr->en_channel_bandwidth = WLAN_BAND_WIDTH_80PLUSMINUS;
                    break;

                case 2:
                    /***********************************************************************
                | ??20 | ??20 | ??40       |
                              |
                              |????????????????20??2??????
                ************************************************************************/
                    pst_bss_dscr->en_channel_bandwidth = WLAN_BAND_WIDTH_80MINUSPLUS;
                    break;

                case -6:
                    /***********************************************************************
                | ??40        | ??20 | ??20 |
                              |
                              |????????????????20??-6??????
                ************************************************************************/
                    pst_bss_dscr->en_channel_bandwidth = WLAN_BAND_WIDTH_80MINUSMINUS;
                    break;

                default:
                    break;
            }
        } else {
            /* Unsupported Channel BandWidth */
        }
    }
}

#ifdef _PRE_WLAN_FEATURE_BTCOEX


oal_void hmac_scan_btcoex_backlist_check_by_oui(mac_bss_dscr_stru *pst_bss_dscr,
                                                oal_uint8 *puc_frame_body,
                                                oal_uint16 us_frame_len,
                                                oal_uint16 us_offset)
{
    pst_bss_dscr->en_btcoex_blacklist_chip_oui = OAL_FALSE;
    if (OAL_PTR_NULL !=
        mac_find_vendor_ie(MAC_WLAN_CHIP_OUI_RALINK, MAC_WLAN_CHIP_OUI_TYPE_RALINK, puc_frame_body + us_offset,
                           us_frame_len - us_offset) ||
        OAL_PTR_NULL !=
        mac_find_vendor_ie(MAC_WLAN_CHIP_OUI_RALINK, MAC_WLAN_CHIP_OUI_TYPE_RALINK1, puc_frame_body + us_offset,
                           us_frame_len - us_offset) ||
        OAL_PTR_NULL !=
        mac_find_vendor_ie(MAC_WLAN_CHIP_OUI_SHENZHEN, MAC_WLAN_CHIP_OUI_TYPE_SHENZHEN, puc_frame_body + us_offset,
                           us_frame_len - us_offset) ||
        OAL_PTR_NULL !=
        mac_find_vendor_ie(MAC_WLAN_CHIP_OUI_ATHEROS, MAC_WLAN_CHIP_OUI_TYPE_ATHEROS, puc_frame_body + us_offset,
                           us_frame_len - us_offset) ||
        OAL_PTR_NULL !=
        mac_find_vendor_ie(MAC_WLAN_CHIP_OUI_BROADCOM, MAC_WLAN_CHIP_OUI_TYPE_BROADCOM, puc_frame_body + us_offset,
                           us_frame_len - us_offset) ||
        OAL_PTR_NULL !=
        mac_find_vendor_ie(MAC_WLAN_CHIP_OUI_MARVELL, MAC_WLAN_CHIP_OUI_TYPE_MARVELL, puc_frame_body + us_offset,
                           us_frame_len - us_offset)) {
        pst_bss_dscr->en_btcoex_blacklist_chip_oui = OAL_TRUE;
    }

    if (OAL_PTR_NULL !=
        mac_find_vendor_ie(MAC_WLAN_CHIP_OUI_REALTEKS, MAC_WLAN_CHIP_OUI_TYPE_REALTEKS, puc_frame_body + us_offset,
                           us_frame_len - us_offset)) {
        pst_bss_dscr->en_is_tplink_oui = WLAN_AP_CHIP_OUI_REALTEKS;
    }
}
#endif
OAL_STATIC oal_void hmac_scan_chip_oui_process(mac_bss_dscr_stru *pst_bss_dscr,
                                               oal_uint8 *puc_frame_body,
                                               oal_uint16 us_frame_len,
                                               oal_uint16 us_offset)
{
    if (mac_find_vendor_ie(MAC_WLAN_CHIP_OUI_ATHEROSC, MAC_WLAN_CHIP_OUI_TYPE_ATHEROSC, puc_frame_body + us_offset,
                           us_frame_len - us_offset) != OAL_PTR_NULL) {
        pst_bss_dscr->en_is_tplink_oui = WLAN_AP_CHIP_OUI_ATHEROS;
    }

    if (mac_find_vendor_ie(MAC_WLAN_CHIP_OUI_SHENZHEN, MAC_WLAN_CHIP_OUI_TYPE_SHENZHEN, puc_frame_body + us_offset,
                           us_frame_len - us_offset) != OAL_PTR_NULL) {
        pst_bss_dscr->en_is_tplink_oui = WLAN_AP_CHIP_OUI_SHENZHEN;
    }

    if (mac_find_vendor_ie(MAC_WLAN_CHIP_OUI_REALTEKS, MAC_WLAN_CHIP_OUI_TYPE_REALTEKS, puc_frame_body + us_offset,
                           us_frame_len - us_offset) != OAL_PTR_NULL) {
        pst_bss_dscr->en_is_realtek_chip_oui = OAL_TRUE;
    }
}

OAL_INLINE OAL_STATIC oal_void hmac_scan_update_bss_list_protocol(mac_bss_dscr_stru *pst_bss_dscr,
                                                                  oal_uint8 *puc_frame_body,
                                                                  oal_uint16 us_frame_len)
{
    oal_uint16 us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
    oal_uint8 *puc_ie = OAL_PTR_NULL;
    oal_uint16 us_offset_vendor_vht = MAC_WLAN_OUI_VENDOR_VHT_HEADER + MAC_IE_HDR_LEN;

    /*************************************************************************/
    /* Beacon Frame - Frame Body */
    /* ---------------------------------------------------------------------- */
    /* |Timestamp|BcnInt|CapInfo|SSID|SupRates|DSParamSet|TIM  |CountryElem | */
    /* ---------------------------------------------------------------------- */
    /* |8        |2     |2      |2-34|3-10    |3         |6-256|8-256       | */
    /* ---------------------------------------------------------------------- */
    /* |PowerConstraint |Quiet|TPC Report|ERP |RSN  |WMM |Extended Sup Rates| */
    /* ---------------------------------------------------------------------- */
    /* |3               |8    |4         |3   |4-255|26  | 3-257            | */
    /* ---------------------------------------------------------------------- */
    /* |BSS Load |HT Capabilities |HT Operation |Overlapping BSS Scan       | */
    /* ---------------------------------------------------------------------- */
    /* |7        |28              |24           |16                         | */
    /* ---------------------------------------------------------------------- */
    /* |Extended Capabilities | */
    /* ---------------------------------------------------------------------- */
    /* |3-8                   | */
    /*************************************************************************/
    /* wmm */
    hmac_scan_update_bss_list_wmm(pst_bss_dscr, puc_frame_body, us_frame_len);

#if defined(_PRE_WLAN_FEATURE_WPA) || defined(_PRE_WLAN_FEATURE_WPA2)
    /* 11i */
    hmac_scan_update_bss_list_security(pst_bss_dscr, puc_frame_body, us_frame_len, us_offset);
#endif

#ifdef _PRE_WLAN_FEATURE_11D
    /* 11d */
    hmac_scan_update_bss_list_country(pst_bss_dscr, puc_frame_body, us_frame_len);
#endif

    /* rrm */
#if defined(_PRE_WLAN_FEATURE_11K) || defined(_PRE_WLAN_FEATURE_FTM)
    hmac_scan_update_bss_list_rrm(pst_bss_dscr, puc_frame_body, us_frame_len, us_offset);
#endif

    /* 11n */
    hmac_scan_update_bss_list_11n(pst_bss_dscr, puc_frame_body, us_frame_len, us_offset);

    /* 11ac */
    hmac_scan_update_bss_list_11ac(pst_bss_dscr, puc_frame_body, us_frame_len, us_offset, OAL_FALSE);
    /* ????????vendor ie */
    puc_ie = mac_find_vendor_ie(MAC_WLAN_OUI_BROADCOM_EPIGRAM, MAC_WLAN_OUI_VENDOR_VHT_TYPE,
                                puc_frame_body + us_offset, us_frame_len - us_offset);
    if ((puc_ie != OAL_PTR_NULL) && (puc_ie[1] >= MAC_WLAN_OUI_VENDOR_VHT_HEADER)) {
        hmac_scan_update_bss_list_11ac(pst_bss_dscr, puc_ie + us_offset_vendor_vht,
                                       puc_ie[1] - MAC_WLAN_OUI_VENDOR_VHT_HEADER, 0, OAL_TRUE);
    }
#ifdef _PRE_WLAN_FEATURE_BTCOEX
    hmac_scan_btcoex_backlist_check_by_oui(pst_bss_dscr, puc_frame_body, us_frame_len, us_offset);
#endif
#ifdef _PRE_WLAN_FEATURE_ROAM
    if (OAL_PTR_NULL !=
        mac_find_vendor_ie(MAC_WLAN_CHIP_OUI_BROADCOM, MAC_WLAN_CHIP_OUI_TYPE_BROADCOM, puc_frame_body + us_offset,
                           us_frame_len - us_offset)) {
        pst_bss_dscr->en_roam_blacklist_chip_oui = OAL_TRUE;
    } else {
        pst_bss_dscr->en_roam_blacklist_chip_oui = OAL_FALSE;
    }
#endif

#ifdef _PRE_WLAN_NARROW_BAND
    if (g_hitalk_status & NARROW_BAND_ON_MASK) {
        /* nb */
        hmac_scan_update_bss_list_nb(pst_bss_dscr, puc_frame_body + us_offset, us_frame_len - us_offset);
    }
#endif
    hmac_scan_chip_oui_process(pst_bss_dscr, puc_frame_body, us_frame_len, us_offset);
}


oal_uint8 hmac_scan_check_bss_supp_rates(mac_device_stru *pst_mac_dev,
                                         oal_uint8 *puc_rate,
                                         oal_uint8 uc_bss_rate_num,
                                         oal_uint8 *puc_update_rate,
                                         oal_uint8 uc_rate_size)
{
    mac_data_rate_stru *pst_rates = OAL_PTR_NULL;
    oal_uint32 i, j, k;
    oal_uint8 uc_rate_num = 0;

    if (uc_rate_size > WLAN_MAX_SUPP_RATES) {
        OAM_ERROR_LOG1(0, OAM_SF_SCAN, "{hmac_scan_check_bss_supp_rates::uc_rate_size err[%d].}", uc_rate_size);
        return uc_rate_num;
    }

    pst_rates = mac_device_get_all_rates(pst_mac_dev);
    if (puc_rate != OAL_PTR_NULL) {
        for (i = 0; i < uc_bss_rate_num; i++) {
            for (j = 0; j < MAC_DATARATES_PHY_80211G_NUM; j++) {
                if ((is_equal_rates(pst_rates[j].uc_mac_rate, puc_rate[i])) &&
                    (uc_rate_num < MAC_DATARATES_PHY_80211G_NUM)) {
                    /* ???????????? */
                    for (k = 0; k < uc_rate_num; k++) {
                        if (is_equal_rates(puc_update_rate[k], puc_rate[i])) {
                            break;
                        }
                    }
                    /* ????????????????????k????uc_rate_num */
                    if (k == uc_rate_num) {
                        puc_update_rate[uc_rate_num++] = puc_rate[i];
                    }
                    break;
                }
            }
        }
    }

    return uc_rate_num;
}


oal_uint8 hmac_scan_check_chan(oal_netbuf_stru *pst_netbuf, hmac_scanned_bss_info *pst_scanned_bss)
{
    dmac_rx_ctl_stru *pst_rx_ctrl;
    oal_uint8 uc_curr_chan;
    oal_uint8 *puc_frame_body;
    oal_uint16 us_frame_body_len;
    oal_uint16 us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
    oal_uint8 *puc_ie_start_addr;
    oal_uint8 uc_chan_num;

    pst_rx_ctrl = (dmac_rx_ctl_stru *)oal_netbuf_cb(pst_netbuf);
    uc_curr_chan = pst_rx_ctrl->st_rx_info.uc_channel_number;
    puc_frame_body = pst_scanned_bss->st_bss_dscr_info.auc_mgmt_buff + MAC_80211_FRAME_LEN; /*lint !e416*/
    us_frame_body_len = pst_scanned_bss->st_bss_dscr_info.ul_mgmt_len - MAC_80211_FRAME_LEN;

    /* ??DSSS Param set ie??????chan num */
    puc_ie_start_addr = mac_find_ie(MAC_EID_DSPARMS, puc_frame_body + us_offset,
                                    us_frame_body_len - us_offset); /*lint !e416*/
    if ((puc_ie_start_addr != OAL_PTR_NULL) && (puc_ie_start_addr[1] == MAC_DSPARMS_LEN)) {
        uc_chan_num = puc_ie_start_addr[2]; /* puc_ie_start_addr??2???????????? */
        if (mac_is_channel_num_valid(mac_get_band_by_channel_num(uc_chan_num), uc_chan_num) != OAL_SUCC) {
            return OAL_FALSE;
        }
    }

    /* ??HT operation ie?????? chan num */
    puc_ie_start_addr = mac_find_ie(MAC_EID_HT_OPERATION, puc_frame_body + us_offset,
                                    us_frame_body_len - us_offset); /*lint !e416*/
    if ((puc_ie_start_addr != OAL_PTR_NULL) && (puc_ie_start_addr[1] >= 1)) {
        uc_chan_num = puc_ie_start_addr[2]; /* puc_ie_start_addr??2???????????? */
        if (mac_is_channel_num_valid(mac_get_band_by_channel_num(uc_chan_num), uc_chan_num) != OAL_SUCC) {
            return OAL_FALSE;
        }
    }

    uc_chan_num = pst_scanned_bss->st_bss_dscr_info.st_channel.uc_chan_number;

#ifdef _PRE_WLAN_NARROW_BAND
    if ((g_hitalk_status & NBFH_ON_MASK) == 0) {
        if (((uc_curr_chan > uc_chan_num) &&
            (uc_curr_chan - uc_chan_num >= 3)) || /* ????????????????????20MHz??????????3?????????? */
            ((uc_curr_chan < uc_chan_num) &&
             (uc_chan_num - uc_curr_chan >= 3))) { /* ????????????????????20MHz??????????3?????????? */
            return OAL_FALSE;
        }
    }
#endif

    return OAL_TRUE;
}


oal_void hmac_scan_rm_repeat_sup_exsup_rates(mac_bss_dscr_stru *pst_bss_dscr,
                                             oal_uint8 *puc_rates,
                                             oal_uint8 uc_exrate_num)
{
    int i, j;
    for (i = 0; i < uc_exrate_num; i++) {
        /* ???????????? */
        for (j = 0; j < pst_bss_dscr->uc_num_supp_rates; j++) {
            if (is_equal_rates(puc_rates[i], pst_bss_dscr->auc_supp_rates[j])) {
                break;
            }
        }

        /* ??????????????????????j????pst_bss_dscr->uc_num_supp_rates */
        if ((j == pst_bss_dscr->uc_num_supp_rates) && (pst_bss_dscr->uc_num_supp_rates < WLAN_MAX_SUPP_RATES)) {
            pst_bss_dscr->auc_supp_rates[pst_bss_dscr->uc_num_supp_rates++] = puc_rates[i];
        }
    }
}


OAL_INLINE OAL_STATIC oal_void hmac_scan_update_bss_list_rates(
    mac_bss_dscr_stru *pst_bss_dscr, oal_uint8 *puc_frame_body, oal_uint16 us_frame_len, mac_device_stru *pst_mac_dev)
{
    oal_uint8 *puc_ie;
    oal_uint8 uc_num_rates = 0;
    oal_uint8 uc_num_ex_rates = 0;
    oal_uint8 us_offset;
    oal_uint8 auc_rates[MAC_DATARATES_PHY_80211G_NUM] = { 0 };

    /* ????Beacon????field?????? */
    us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;

    puc_ie = mac_find_ie(MAC_EID_RATES, puc_frame_body + us_offset, us_frame_len - us_offset);
    if (puc_ie != OAL_PTR_NULL) {
        uc_num_rates = hmac_scan_check_bss_supp_rates(pst_mac_dev, puc_ie + MAC_IE_HDR_LEN, puc_ie[1], auc_rates,
                                                      OAL_SIZEOF(auc_rates));
        
        if (uc_num_rates > WLAN_MAX_SUPP_RATES) {
            OAM_WARNING_LOG1(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_rates::uc_num_rates=%d.}", uc_num_rates);
            uc_num_rates = WLAN_MAX_SUPP_RATES;
        }

        if (memcpy_s(pst_bss_dscr->auc_supp_rates, WLAN_MAX_SUPP_RATES, auc_rates, uc_num_rates) != EOK) {
            OAM_ERROR_LOG0(0, OAM_SF_SCAN, "hmac_scan_update_bss_list_rates::memcpy fail!");
            return;
        }
        pst_bss_dscr->uc_num_supp_rates = uc_num_rates;
    }

    puc_ie = mac_find_ie(MAC_EID_XRATES, puc_frame_body + us_offset, us_frame_len - us_offset);
    if (puc_ie != OAL_PTR_NULL) {
        uc_num_ex_rates = hmac_scan_check_bss_supp_rates(pst_mac_dev, puc_ie + MAC_IE_HDR_LEN, puc_ie[1], auc_rates,
                                                         OAL_SIZEOF(auc_rates));
        if (uc_num_rates + uc_num_ex_rates > WLAN_MAX_SUPP_RATES) { /* ???????????????? */
            oam_warning_log2(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_rates::number of rates too large, \
                uc_num_rates=%d, uc_num_ex_rates=%d.}", uc_num_rates, uc_num_ex_rates);
        }

        if (uc_num_ex_rates > 0) {
            /* support_rates??extended_rates???????????????????????????????????????? */
            hmac_scan_rm_repeat_sup_exsup_rates(pst_bss_dscr, auc_rates, uc_num_ex_rates);
        }
    }

    return;
}

oal_uint8 *hmac_ie_find_vendor_vht_ie(oal_uint8 *puc_frame, oal_uint16 us_frame_len)
{
    oal_uint8 *puc_vendor_ie = OAL_PTR_NULL;
    oal_uint8 *puc_vht_ie = OAL_PTR_NULL;
    oal_uint16 us_offset_vendor_vht = MAC_WLAN_OUI_VENDOR_VHT_HEADER + MAC_IE_HDR_LEN;

    puc_vendor_ie = mac_find_vendor_ie(MAC_WLAN_OUI_BROADCOM_EPIGRAM,
                                       MAC_WLAN_OUI_VENDOR_VHT_TYPE,
                                       puc_frame,
                                       us_frame_len);
    if ((puc_vendor_ie != OAL_PTR_NULL) && (puc_vendor_ie[1] >= MAC_WLAN_OUI_VENDOR_VHT_HEADER)) {
        puc_vht_ie = mac_find_ie(MAC_EID_VHT_CAP, puc_vendor_ie + us_offset_vendor_vht,
                                 puc_vendor_ie[1] - MAC_WLAN_OUI_VENDOR_VHT_HEADER);
    }

    return puc_vht_ie;
}


wlan_nss_enum_uint8 hmac_scan_get_bss_max_nss(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_frame_body,
                                              oal_uint16 us_frame_len, oal_bool_enum_uint8 en_assoc_status)
{
    oal_uint8 *puc_ie = OAL_PTR_NULL;
    oal_uint8 *puc_ht_mcs_bitmask = OAL_PTR_NULL;
    wlan_nss_enum_uint8 en_nss = WLAN_SINGLE_NSS;
    oal_uint16 us_vht_mcs_map;
    oal_uint16 us_msg_idx = 0;
    oal_uint16 us_offset;

    /* ????Beacon????field?????? */
    us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;

    /* ??ht ie */
    puc_ie = mac_find_ie(MAC_EID_HT_CAP, puc_frame_body + us_offset, us_frame_len - us_offset);
    if (puc_ie != OAL_PTR_NULL) {
        us_msg_idx = MAC_IE_HDR_LEN + MAC_HT_CAPINFO_LEN + MAC_HT_AMPDU_PARAMS_LEN;
        puc_ht_mcs_bitmask = &puc_ie[us_msg_idx];
        for (en_nss = WLAN_SINGLE_NSS; en_nss < WLAN_NSS_BUTT; en_nss++) {
            if (puc_ht_mcs_bitmask[en_nss] == 0) {
                break;
            }
        }
        if (en_nss != WLAN_SINGLE_NSS) {
            en_nss--;
        }

        /* ??????????up????????????ht???????????????????? */
        if ((en_assoc_status == OAL_TRUE) &&
            ((pst_mac_vap->en_protocol == WLAN_HT_MODE) || (pst_mac_vap->en_protocol == WLAN_HT_ONLY_MODE) ||
             (pst_mac_vap->en_protocol == WLAN_HT_11G_MODE))) {
            return en_nss;
        }
    }

    /* ??vht ie */
    puc_ie = mac_find_ie(MAC_EID_VHT_CAP, puc_frame_body + us_offset, us_frame_len - us_offset);
    /* ??????????????????????vendor ie????????vht ie */
    if (puc_ie == OAL_PTR_NULL) {
        puc_ie = hmac_ie_find_vendor_vht_ie(puc_frame_body + us_offset, us_frame_len - us_offset);
    }

    if (puc_ie != OAL_PTR_NULL) {
        us_msg_idx = MAC_IE_HDR_LEN + MAC_VHT_CAP_INFO_FIELD_LEN;

        us_vht_mcs_map = oal_make_word16(puc_ie[us_msg_idx], puc_ie[us_msg_idx + 1]);

        for (en_nss = WLAN_SINGLE_NSS; en_nss < WLAN_NSS_BUTT; en_nss++) {
            if (wlan_get_vht_max_support_mcs(us_vht_mcs_map & 0x3) == WLAN_INVALD_VHT_MCS) {
                break;
            }
            us_vht_mcs_map >>= 2; /* ??us_vht_mcs_map????2?? */
        }
        if (en_nss != WLAN_SINGLE_NSS) {
            en_nss--;
        }

        /* ??????????up????????????vht???????????????????? */
        if ((en_assoc_status == OAL_TRUE) &&
            ((pst_mac_vap->en_protocol == WLAN_VHT_MODE) || (pst_mac_vap->en_protocol == WLAN_VHT_ONLY_MODE))) {
            return en_nss;
        }
    }

    return en_nss;
}


oal_uint8 hmac_scan_get_num_sounding_dim(oal_uint8 *puc_frame_body, oal_uint16 us_frame_len)
{
    oal_uint8 *puc_vht_cap_ie = OAL_PTR_NULL;
    oal_uint16 us_offset;
    oal_uint16 us_vht_cap_filed_low;
    oal_uint16 us_vht_cap_filed_high;
    oal_uint32 ul_vht_cap_field;
    oal_uint16 us_msg_idx;
    oal_uint8 uc_num_sounding_dim = 0;

    /* ????Beacon????field?????? */
    us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
    puc_vht_cap_ie = mac_find_ie(MAC_EID_VHT_CAP, puc_frame_body + us_offset, us_frame_len - us_offset);
    if (puc_vht_cap_ie == OAL_PTR_NULL) {
        puc_vht_cap_ie = hmac_ie_find_vendor_vht_ie(puc_frame_body + us_offset, us_frame_len - us_offset);
        if (puc_vht_cap_ie == OAL_PTR_NULL) {
            return uc_num_sounding_dim;
        }
    }
    us_msg_idx = MAC_IE_HDR_LEN;

    /* ????VHT capablities info field */
    us_vht_cap_filed_low = oal_make_word16(puc_vht_cap_ie[us_msg_idx], puc_vht_cap_ie[us_msg_idx + 1]);
    /* ??2byte????3byte??????vht_cap_filed??????16bit */
    us_vht_cap_filed_high = oal_make_word16(puc_vht_cap_ie[us_msg_idx + 2], puc_vht_cap_ie[us_msg_idx + 3]);
    ul_vht_cap_field = oal_make_word32(us_vht_cap_filed_low, us_vht_cap_filed_high);
    /* ????num_sounding_dim??ul_vht_cap_field??16-18bit?? */
    uc_num_sounding_dim = ((ul_vht_cap_field & (BIT18 | BIT17 | BIT16)) >> 16);
    return uc_num_sounding_dim;
}

oal_void hmac_scan_get_11v_ability(mac_bss_dscr_stru *pst_bss_dscr, oal_uint8 *puc_frame_body,
                                   oal_uint16 us_frame_body_len, oal_uint16 us_offset)
{
    mac_ext_cap_ie_stru *pst_ext_cap_ie;
    oal_uint8 *puc_temp;
    puc_temp = mac_find_ie(MAC_EID_EXT_CAPS, puc_frame_body + us_offset,
                           (oal_int32)(us_frame_body_len - us_offset));
    if (puc_temp != OAL_PTR_NULL) {
        puc_temp += MAC_IE_HDR_LEN;
        pst_ext_cap_ie = (mac_ext_cap_ie_stru *)puc_temp;
        pst_bss_dscr->en_11v_capable = (pst_ext_cap_ie->bit_bss_transition == 1) ? OAL_TRUE : OAL_FALSE;
    }
}


oal_void hmac_scan_get_11k_ability(mac_bss_dscr_stru *pst_bss_dscr, oal_uint8 *puc_frame_body,
                                   oal_uint16 us_frame_body_len, oal_uint16 us_offset)
{
    oal_uint8 *puc_temp;
    puc_temp = mac_find_ie(MAC_EID_RRM, puc_frame_body + us_offset, (oal_int32)(us_frame_body_len - us_offset));
    if (puc_temp != OAL_PTR_NULL) {
        pst_bss_dscr->en_11k_capable = OAL_TRUE;
    } else {
        pst_bss_dscr->en_11k_capable = OAL_FALSE;
    }
}

#ifdef _PRE_WLAN_FEATURE_TXBF
oal_void hmac_get_11ntxbf_by_ie(oal_uint8 *puc_mgmt_frame, oal_uint16 us_frame_len, mac_bss_dscr_stru *pst_bss_dscr)
{
    oal_uint8 *puc_frame_body;
    oal_uint16 us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
    mac_11ntxbf_vendor_ie_stru *pst_txbf_vendor_ie;

    puc_frame_body = (oal_uint8 *)(puc_mgmt_frame + MAC_80211_FRAME_LEN);
    pst_txbf_vendor_ie = (mac_11ntxbf_vendor_ie_stru *)mac_find_vendor_ie(MAC_HUAWEI_VENDER_IE, MAC_EID_11NTXBF,
        puc_frame_body + us_offset, (oal_int32)(us_frame_len - MAC_80211_FRAME_LEN - us_offset));
    if ((pst_txbf_vendor_ie != OAL_PTR_NULL) &&
        (pst_txbf_vendor_ie->uc_len >= (OAL_SIZEOF(mac_11ntxbf_vendor_ie_stru) - MAC_IE_HDR_LEN))) {
        pst_bss_dscr->en_11ntxbf = (pst_txbf_vendor_ie->st_11ntxbf.bit_11ntxbf == 1) ? OAL_TRUE : OAL_FALSE;
    }
}
#endif

OAL_STATIC oal_uint32 hmac_scan_update_bss_dscr(
    hmac_scanned_bss_info *pst_scanned_bss, dmac_tx_event_stru *pst_dtx_event,
    oal_uint8 uc_device_id, oal_uint8 uc_vap_id)
{
    oal_netbuf_stru *pst_netbuf = pst_dtx_event->pst_netbuf;
    mac_scanned_result_extend_info_stru *pst_scan_result_extend_info = OAL_PTR_NULL;
    mac_device_stru *pst_mac_device = OAL_PTR_NULL;
    hmac_vap_stru *pst_hmac_vap = mac_res_get_hmac_vap(uc_vap_id); /* ????hmac vap */
    mac_vap_stru *pst_mac_vap = OAL_PTR_NULL;
    mac_ieee80211_frame_stru *pst_frame_header = OAL_PTR_NULL;
    oal_uint8 *puc_frame_body = OAL_PTR_NULL;
    mac_bss_dscr_stru *pst_bss_dscr = OAL_PTR_NULL;
    oal_uint8 *puc_ssid = OAL_PTR_NULL; /* ????beacon??????ssid */
    oal_uint8 *puc_mgmt_frame = OAL_PTR_NULL;
    dmac_rx_ctl_stru *pst_rx_ctrl = OAL_PTR_NULL;
    oal_uint16 us_netbuf_len = pst_dtx_event->us_frame_len;
    oal_uint16 us_frame_len;
    oal_uint16 us_frame_body_len;
    oal_uint16 us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
    oal_uint8 uc_ssid_len;
    oal_uint8 uc_frame_channel;
    oal_int32 l_ret = OAL_SUCC;

    if (pst_hmac_vap == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_scan_update_bss_dscr::pst_hmac_vap is null.}");
        return OAL_FAIL;
    }

    pst_mac_vap = &pst_hmac_vap->st_vap_base_info;

    /* ????mac device */
    pst_mac_device = mac_res_get_dev(uc_device_id);
    if (oal_unlikely(pst_mac_device == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_scan_update_bss_dscr::pst_mac_device is null.}");
        return OAL_FAIL;
    }

    /* ????device????????????????????????????????bss???????????? */
    us_frame_len = us_netbuf_len - OAL_SIZEOF(mac_scanned_result_extend_info_stru);
    puc_mgmt_frame = (oal_uint8 *)oal_netbuf_data(pst_netbuf);
    pst_rx_ctrl = (dmac_rx_ctl_stru *)oal_netbuf_cb(pst_netbuf);

    /* ????netbuf?????????????????????????????????? */
    pst_scan_result_extend_info = (mac_scanned_result_extend_info_stru *)(puc_mgmt_frame + us_frame_len);

    /* ?????????????????????????? */
    pst_frame_header = (mac_ieee80211_frame_stru *)puc_mgmt_frame;
    puc_frame_body = (oal_uint8 *)(puc_mgmt_frame + MAC_80211_FRAME_LEN);
    us_frame_body_len = us_frame_len - MAC_80211_FRAME_LEN;

    /* ?????????????????? */
    uc_frame_channel = mac_ie_get_chan_num(puc_frame_body, us_frame_body_len, us_offset,
                                           pst_rx_ctrl->st_rx_info.uc_channel_number);

    /* ????bss???? */
    pst_bss_dscr = &(pst_scanned_bss->st_bss_dscr_info);

    /*****************************************************************************
        ????beacon/probe rsp??????????pst_bss_dscr
    *****************************************************************************/
    /* ??????????ssid */
    puc_ssid = mac_get_ssid(puc_frame_body, (oal_int32)us_frame_body_len, &uc_ssid_len);
    if ((puc_ssid != OAL_PTR_NULL) && (uc_ssid_len != 0)) {
        /* ??????????ssid??????bss???????????? */
        l_ret = memcpy_s(pst_bss_dscr->ac_ssid, WLAN_SSID_MAX_LEN, puc_ssid, uc_ssid_len);
        pst_bss_dscr->ac_ssid[uc_ssid_len] = '\0';
    }

    /* ????bssid */
    oal_set_mac_addr(pst_bss_dscr->auc_mac_addr, pst_frame_header->auc_address2);
    oal_set_mac_addr(pst_bss_dscr->auc_bssid, pst_frame_header->auc_address3);

    /* bss???????? */
    pst_bss_dscr->en_bss_type = pst_scan_result_extend_info->en_bss_type;

    pst_bss_dscr->us_cap_info = *((oal_uint16 *)(puc_frame_body + MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN));

    pst_bss_dscr->c_rssi = (oal_int8)pst_scan_result_extend_info->l_rssi;

    /* ????beacon??????tim???? */
    pst_bss_dscr->us_beacon_period = mac_get_beacon_period(puc_frame_body);
    pst_bss_dscr->uc_dtim_period = mac_get_dtim_period(puc_frame_body, us_frame_body_len);
    pst_bss_dscr->uc_dtim_cnt = mac_get_dtim_cnt(puc_frame_body, us_frame_body_len);

    /* ???? */
    pst_bss_dscr->st_channel.uc_chan_number = uc_frame_channel;
    pst_bss_dscr->st_channel.en_band = mac_get_band_by_channel_num(uc_frame_channel);

    /* ?????????? */
    hmac_scan_update_bss_list_rates(pst_bss_dscr, puc_frame_body, us_frame_body_len, pst_mac_device);

    /* ???????????? */
    pst_bss_dscr->en_support_max_nss = hmac_scan_get_bss_max_nss(pst_mac_vap, puc_frame_body, us_frame_body_len,
                                                                 OAL_FALSE);
    pst_bss_dscr->uc_num_sounding_dim = hmac_scan_get_num_sounding_dim(puc_frame_body, us_frame_body_len);

    /* ???????????????????????? */
    hmac_scan_update_bss_list_protocol(pst_bss_dscr, puc_frame_body, us_frame_body_len);
    /* ????Ext Cap 11v???? */
    hmac_scan_get_11v_ability(pst_bss_dscr, puc_frame_body, us_frame_body_len, us_offset);
    /* ????Ext Cap 11k???? */
    hmac_scan_get_11k_ability(pst_bss_dscr, puc_frame_body, us_frame_body_len, us_offset);

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    pst_bss_dscr->st_channel.en_bandwidth = pst_bss_dscr->en_channel_bandwidth;
    mac_get_channel_idx_from_num(pst_bss_dscr->st_channel.en_band,
                                 pst_bss_dscr->st_channel.uc_chan_number, &pst_bss_dscr->st_channel.uc_idx);
#endif

#ifdef _PRE_WLAN_FEATURE_TXBF
    hmac_get_11ntxbf_by_ie(puc_mgmt_frame, us_frame_len, pst_bss_dscr);
#endif

    /* ?????????? */
    pst_bss_dscr->ul_timestamp = (oal_uint32)oal_time_get_stamp_ms();

    pst_bss_dscr->ul_mgmt_len = us_frame_len;

    /* ?????????????? */
    l_ret += memcpy_s((oal_uint8 *)pst_scanned_bss->st_bss_dscr_info.auc_mgmt_buff, (oal_uint32)us_frame_len,
        puc_mgmt_frame, (oal_uint32)us_frame_len);
    if (l_ret != EOK) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "hmac_scan_update_bss_dscr::memcpy fail!");
        return OAL_FAIL;
    }
    return OAL_SUCC;
}


OAL_STATIC oal_bool_enum_uint8 hmac_scan_need_update_timestamp(
    oal_uint8 uc_vap_id, hmac_scanned_bss_info *pst_new_bss, hmac_scanned_bss_info *pst_old_bss)
{
    if ((pst_new_bss->st_bss_dscr_info.ac_ssid[0] == '\0') &&
        (pst_old_bss->st_bss_dscr_info.ac_ssid[0] != '\0')) {
        return OAL_FALSE;
    }

    return OAL_TRUE;
}


oal_bool_enum_uint8 hmac_scan_need_update_old_scan_result(oal_uint8 uc_vap_id, hmac_scanned_bss_info *pst_new_bss,
                                                          hmac_scanned_bss_info *pst_old_bss)
{
    
    if ((((mac_ieee80211_frame_stru *)pst_old_bss->st_bss_dscr_info.auc_mgmt_buff)->st_frame_control.bit_sub_type ==
         WLAN_PROBE_RSP) &&
        (((mac_ieee80211_frame_stru *)pst_new_bss->st_bss_dscr_info.auc_mgmt_buff)->st_frame_control.bit_sub_type
         == WLAN_BEACON) && (pst_old_bss->st_bss_dscr_info.en_new_scan_bss == OAL_TRUE)) {
        return OAL_FALSE;
    }
    return OAL_TRUE;
}

#ifdef _PRE_WLAN_FEATURE_11V_ENABLE
oal_void hmac_scan_11v_bsstreq_filter_switch(hmac_vap_stru *pst_hmac_vap, hmac_scanned_bss_info *pst_new_scanned_bss)
{
    hmac_user_stru *pst_hmac_user = OAL_PTR_NULL;
    mac_vap_stru *pst_vap = &(pst_hmac_vap->st_vap_base_info);
    hmac_user_11v_ctrl_stru *pst_11v_ctrl_info = OAL_PTR_NULL;

    /* ????STA??????????11V */
    if (pst_vap->en_vap_mode != WLAN_VAP_MODE_BSS_STA) {
        return;
    }

    pst_hmac_user = mac_res_get_hmac_user((oal_uint16)pst_vap->uc_assoc_vap_id);
    if (pst_hmac_user == OAL_PTR_NULL) {
        return;
    }

    pst_11v_ctrl_info = &pst_hmac_user->st_11v_ctrl_info;

    /* 11v ????????,??????????????target bss rssi????-72dB(-78????????????????6dB)????11v???? */
    if ((oal_memcmp(pst_11v_ctrl_info->auc_target_bss_addr, pst_new_scanned_bss->st_bss_dscr_info.auc_mac_addr,
                    WLAN_MAC_ADDR_LEN) == 0) &&
         pst_11v_ctrl_info->en_bsstreq_filter == OAL_TRUE
#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
        && pst_new_scanned_bss->st_bss_dscr_info.c_rssi >= g_wlan_customize.c_roam_trigger_a + ROAM_RSSI_DIFF_6_DB
#endif
) {
        if (hmac_config_filter_11v_bsstreq_switch(pst_vap, OAL_FALSE) == OAL_SUCC) {
            OAM_WARNING_LOG1(0, OAM_SF_ANY, "hmac_scan_11v_bsstreq_filter_switch: disable filter,RSSI[%d]",
                             pst_new_scanned_bss->st_bss_dscr_info.c_rssi);

            pst_11v_ctrl_info->en_bsstreq_filter = OAL_FALSE;
        }
    }
    return;
}
#endif

oal_uint32 hmac_scan_proc_scanned_bss(frw_event_mem_stru *pst_event_mem)
{
    frw_event_stru *pst_event = OAL_PTR_NULL;
    frw_event_hdr_stru *pst_event_hdr = OAL_PTR_NULL;
    hmac_vap_stru *pst_hmac_vap = OAL_PTR_NULL;
    oal_netbuf_stru *pst_bss_mgmt_netbuf = OAL_PTR_NULL;
    hmac_device_stru *pst_hmac_device = OAL_PTR_NULL;
    dmac_tx_event_stru *pst_dtx_event = OAL_PTR_NULL;
    hmac_scanned_bss_info *pst_new_scanned_bss = OAL_PTR_NULL;
    hmac_scanned_bss_info *pst_old_scanned_bss = OAL_PTR_NULL;
    oal_uint32 ul_ret;
    oal_uint16 us_mgmt_len;
    oal_uint8 uc_vap_id;
    hmac_bss_mgmt_stru *pst_bss_mgmt = OAL_PTR_NULL;
    oal_uint32 ul_curr_time_stamp;

    if (oal_unlikely(pst_event_mem == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_scan_proc_scanned_bss::pst_event_mem null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ?????????????????????????? */
    pst_event = (frw_event_stru *)pst_event_mem->puc_data;
    pst_event_hdr = &(pst_event->st_event_hdr);
    pst_dtx_event = (dmac_tx_event_stru *)pst_event->auc_event_data;
    pst_bss_mgmt_netbuf = pst_dtx_event->pst_netbuf;

    pst_hmac_vap = mac_res_get_hmac_vap(pst_event_hdr->uc_vap_id);
    if (oal_unlikely(pst_hmac_vap == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_scan_proc_scanned_bss::pst_hmac_vap null.}");

        /* ??????????bss??????beacon????probe rsp???????? */
        oal_netbuf_free(pst_bss_mgmt_netbuf);
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ????vap id */
    uc_vap_id = pst_hmac_vap->st_vap_base_info.uc_vap_id;

    /* ????hmac device ???? */
    pst_hmac_device = hmac_res_get_mac_dev(pst_event_hdr->uc_device_id);
    if (oal_unlikely(pst_hmac_device == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_proc_scanned_bss::pst_hmac_device null.}");

        /* ??????????bss??????beacon????probe rsp???????? */
        oal_netbuf_free(pst_bss_mgmt_netbuf);
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ??dmac??????netbuf?????????????????????????? */
    /***********************************************************************************************/
    /* netbuf data?????????????????????????????? */
    /* ------------------------------------------------------------------------------------------ */
    /* beacon/probe rsp body  |     ????????????????(mac_scanned_result_extend_info_stru) */
    /* ----------------------------------------------------------------------------------------- */
    /* ??????beacon/rsp??body | rssi(4????) | channel num(1????)| band(1????)|bss_tye(1????)|???? */
    /* ------------------------------------------------------------------------------------------ */
    /***********************************************************************************************/
    /* ??????????????????????netbuf???????????????????????????????????????? */
    us_mgmt_len = pst_dtx_event->us_frame_len - OAL_SIZEOF(mac_scanned_result_extend_info_stru);

    /* ?????????????????????? */
    pst_new_scanned_bss = hmac_scan_alloc_scanned_bss(us_mgmt_len);
    if (oal_unlikely(pst_new_scanned_bss == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(uc_vap_id, OAM_SF_SCAN,
                       "{hmac_scan_proc_scanned_bss::alloc memory failed for storing scanned result.}");

        /* ??????????bss??????beacon????probe rsp???????? */
        oal_netbuf_free(pst_bss_mgmt_netbuf);
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ??????????????????bss dscr?????? */
    ul_ret = hmac_scan_update_bss_dscr(pst_new_scanned_bss, pst_dtx_event, pst_event_hdr->uc_device_id,
                                       pst_event_hdr->uc_vap_id);
    if (oal_unlikely(ul_ret != OAL_SUCC)) {
        OAM_ERROR_LOG1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_proc_scanned_bss::hmac_scan_update_bss_dscr failed[%d].}",
                       ul_ret);

        /* ??????????bss??????beacon????probe rsp???????? */
        oal_netbuf_free(pst_bss_mgmt_netbuf);

        /* ??????????????bss?????????? */
        oal_free(pst_new_scanned_bss);
        return ul_ret;
    }

    /* ??????????????bss???????????? */
    pst_bss_mgmt = &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt.st_bss_mgmt);
    /* ?????????????????? */
    oal_spin_lock(&(pst_bss_mgmt->st_lock));
    /* ????????bssid??bss?????????????? */
    pst_old_scanned_bss = hmac_scan_find_scanned_bss_by_bssid(pst_bss_mgmt,
                                                              pst_new_scanned_bss->st_bss_dscr_info.auc_bssid);
    if (pst_old_scanned_bss == OAL_PTR_NULL) {
        /* ???? */
        oal_spin_unlock(&(pst_bss_mgmt->st_lock));

        /*lint -e801*/
        goto add_bss;
        /*lint +e801*/
    }

    /* ??????????????bss??????????????????????????bss???????????????????????????????????????????????????? */
    if (pst_old_scanned_bss->st_bss_dscr_info.c_rssi > pst_new_scanned_bss->st_bss_dscr_info.c_rssi) {
        /* 1s??????????????????BSS??????RSSI????????????????????RSSI???? */
        ul_curr_time_stamp = (oal_uint32)oal_time_get_stamp_ms();
        if (oal_time_after32((ul_curr_time_stamp),
                             (pst_old_scanned_bss->st_bss_dscr_info.ul_timestamp +
                             HMAC_SCAN_MAX_SCANNED_RSSI_EXPIRE)) == OAL_FALSE) {
            pst_new_scanned_bss->st_bss_dscr_info.c_rssi = pst_old_scanned_bss->st_bss_dscr_info.c_rssi;
        }
    }
    if (hmac_scan_need_update_timestamp(uc_vap_id, pst_new_scanned_bss, pst_old_scanned_bss) == OAL_FALSE) {
        /* ???? */
        oal_spin_unlock(&(pst_bss_mgmt->st_lock));

        /* ??????????????bss?????????? */
        oal_free(pst_new_scanned_bss);

        /* ??????????bss??????beacon????probe rsp???????? */
        oal_netbuf_free(pst_bss_mgmt_netbuf);

        return OAL_SUCC;
    }
    if ((hmac_scan_need_update_old_scan_result(uc_vap_id, pst_new_scanned_bss, pst_old_scanned_bss) == OAL_FALSE) ||
        (hmac_scan_check_chan(pst_bss_mgmt_netbuf, pst_new_scanned_bss) == OAL_FALSE)) {
        pst_old_scanned_bss->st_bss_dscr_info.ul_timestamp = (oal_uint32)oal_time_get_stamp_ms();
        pst_old_scanned_bss->st_bss_dscr_info.c_rssi = pst_new_scanned_bss->st_bss_dscr_info.c_rssi;

        /* ???? */
        oal_spin_unlock(&(pst_bss_mgmt->st_lock));

        /* ??????????????bss?????????? */
        oal_free(pst_new_scanned_bss);

        /* ??????????bss??????beacon????probe rsp???????? */
        oal_netbuf_free(pst_bss_mgmt_netbuf);

        return OAL_SUCC;
    }

    /* ??????????????????????????bssid??bss???????? */
    hmac_scan_del_bss_from_list_nolock(pst_old_scanned_bss, pst_hmac_device);
    /* ???? */
    oal_spin_unlock(&(pst_bss_mgmt->st_lock));
    /* ???????? */
    oal_free(pst_old_scanned_bss);

add_bss:
    /* ?????????????????????? */
    hmac_scan_add_bss_to_list(pst_new_scanned_bss, pst_hmac_device);
#ifdef _PRE_WLAN_FEATURE_11V_ENABLE
    /* ????????????????11v filter???? */
    hmac_scan_11v_bsstreq_filter_switch(pst_hmac_vap, pst_new_scanned_bss);
#endif
    /* ??????????bss??????beacon????probe rsp???????? */
    oal_netbuf_free(pst_bss_mgmt_netbuf);

    return OAL_SUCC;
}


OAL_STATIC oal_void hmac_scan_print_channel_statistics_info(hmac_scan_record_stru *pst_scan_record)
{
    mac_scan_chan_stats_stru *pst_chan_stats = pst_scan_record->ast_chan_results;
    oal_uint8 uc_vap_id = pst_scan_record->uc_vap_id;
    oal_uint8 uc_idx = 0;

    /* ???????????????????????????????????????????????? */
    if (pst_chan_stats[0].uc_stats_valid == 0) {
        oam_info_log0(uc_vap_id, OAM_SF_SCAN,
                      "{hmac_scan_print_channel_statistics_info:: curr scan don't enable channel measure.\n}");
        return;
    }

    /* ???????????????? */
    oam_info_log0(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info:: The chan measure result: \n}");

    for (uc_idx = 0; uc_idx < pst_scan_record->uc_chan_numbers; uc_idx++) {
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Chan num      : %d\n}",
                      pst_chan_stats[uc_idx].uc_channel_number);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Stats cnt     : %d\n}",
                      pst_chan_stats[uc_idx].uc_stats_cnt);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Stats valid   : %d\n}",
                      pst_chan_stats[uc_idx].uc_stats_valid);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Stats time us : %d\n}",
                      pst_chan_stats[uc_idx].ul_total_stats_time_us);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Free time 20M : %d\n}",
                      pst_chan_stats[uc_idx].ul_total_free_time_20M_us);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Free time 40M : %d\n}",
                      pst_chan_stats[uc_idx].ul_total_free_time_40M_us);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Free time 80M : %d\n}",
                      pst_chan_stats[uc_idx].ul_total_free_time_80M_us);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Send time     : %d\n}",
                      pst_chan_stats[uc_idx].ul_total_send_time_us);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Recv time     : %d\n}",
                      pst_chan_stats[uc_idx].ul_total_recv_time_us);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Free power cnt: %d\n}",
                      pst_chan_stats[uc_idx].uc_free_power_cnt);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Free power 20M: %d\n}",
                      (oal_int32)pst_chan_stats[uc_idx].s_free_power_stats_20M);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Free power 40M: %d\n}",
                      (oal_int32)pst_chan_stats[uc_idx].s_free_power_stats_40M);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Free power 80M: %d\n}",
                      (oal_int32)pst_chan_stats[uc_idx].s_free_power_stats_80M);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Radar detected: %d\n}",
                      pst_chan_stats[uc_idx].uc_radar_detected);
        oam_info_log1(uc_vap_id, OAM_SF_SCAN, "{hmac_scan_print_channel_statistics_info::Radar bw      : %d\n}",
                      pst_chan_stats[uc_idx].uc_radar_bw);
    }

    return;
}


OAL_STATIC oal_void hmac_scan_print_scan_record_info(hmac_vap_stru *pst_hmac_vap,
                                                     hmac_scan_record_stru *pst_scan_record)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) && (defined(_PRE_PRODUCT_ID_HI110X_HOST))
    oal_time_t_stru st_timestamp_diff;

    /* ?????????????????? */
    st_timestamp_diff = oal_ktime_sub(oal_ktime_get(), pst_scan_record->st_scan_start_time);

    /* ?????????????????????????????? */
    oam_warning_log4(pst_scan_record->uc_vap_id, OAM_SF_SCAN,
                     "{hmac_scan_print_scan_record_info::scan comp, scan_status[%d],vap ch_num:%d, \
         cookie[%x], duration time is: [%lu]ms.}",
                     pst_scan_record->en_scan_rsp_status,
                     pst_hmac_vap->st_vap_base_info.st_channel.uc_chan_number,
                     pst_scan_record->ull_cookie,
                     ktime_to_ms(st_timestamp_diff));
#endif

    /* ????????????bss???? */
    hmac_scan_print_scanned_bss_info(pst_scan_record->uc_device_id);

    /* ???????????? */
    hmac_scan_print_channel_statistics_info(pst_scan_record);

    return;
}
OAL_STATIC oal_void hmac_scan_complete_result_to_sme(hmac_scan_stru *pst_scan_mgmt, hmac_vap_stru *pst_hmac_vap,
                                                     mac_scan_rsp_stru *pst_d2h_scan_rsp_info)
{
    oal_bool_enum_uint8 en_scan_abort_sync_state = OAL_FALSE;

    if ((pst_hmac_vap->st_vap_base_info.en_vap_mode == WLAN_VAP_MODE_BSS_STA) &&
        (pst_scan_mgmt->st_scan_record_mgmt.en_scan_rsp_status == MAC_SCAN_ABORT_SYNC)) {
        /* MAC_SCAN_ABORT_SYNC??????????host??????????????????????d2h???????????? */
        en_scan_abort_sync_state = OAL_TRUE;
    }

    if ((pst_hmac_vap->st_vap_base_info.en_vap_mode == WLAN_VAP_MODE_BSS_AP) &&
        (pst_scan_mgmt->st_scan_record_mgmt.en_vap_last_state != MAC_VAP_STATE_BUTT)) {
        hmac_fsm_change_state(pst_hmac_vap, pst_scan_mgmt->st_scan_record_mgmt.en_vap_last_state);
        pst_scan_mgmt->st_scan_record_mgmt.en_vap_last_state = MAC_VAP_STATE_BUTT;
    }
    /* ????device????????????????????sme */
    /* ??????????????(????????????????????????????????)?????????????????????????? */
    pst_scan_mgmt->st_scan_record_mgmt.en_scan_rsp_status = pst_d2h_scan_rsp_info->en_scan_rsp_status;
    pst_scan_mgmt->st_scan_record_mgmt.ull_cookie = pst_d2h_scan_rsp_info->ull_cookie;

    hmac_scan_print_scan_record_info(pst_hmac_vap, &(pst_scan_mgmt->st_scan_record_mgmt));

#ifdef _PRE_WLAN_FEATURE_ROAM
    /* STA???????????????????????????????? */
    hmac_roam_check_bkscan_result(pst_hmac_vap, &(pst_scan_mgmt->st_scan_record_mgmt));
#endif  // _PRE_WLAN_FEATURE_ROAM

    /* ?????????????????????????????????????? */
    if (pst_scan_mgmt->st_scan_record_mgmt.p_fn_cb != OAL_PTR_NULL) {
        /* ????????????????????,??????????????????????????PNO?????????? */
        pst_scan_mgmt->st_scan_record_mgmt.p_fn_cb(&(pst_scan_mgmt->st_scan_record_mgmt));
    } else {
        if (en_scan_abort_sync_state == OAL_TRUE) {
            hmac_cfg80211_scan_comp_cb(&(pst_scan_mgmt->st_scan_record_mgmt));
        }
    }
}


oal_uint32 hmac_scan_proc_scan_comp_event(frw_event_mem_stru *pst_event_mem)
{
    frw_event_stru *pst_event = OAL_PTR_NULL;
    frw_event_hdr_stru *pst_event_hdr = OAL_PTR_NULL;
    hmac_vap_stru *pst_hmac_vap = OAL_PTR_NULL;
    hmac_device_stru *pst_hmac_device = OAL_PTR_NULL;
    mac_scan_rsp_stru *pst_d2h_scan_rsp_info = OAL_PTR_NULL;
    hmac_scan_stru *pst_scan_mgmt = OAL_PTR_NULL;

    if (oal_unlikely(pst_event_mem == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_scan_proc_scan_comp_event::pst_event_mem null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ?????????????????????????? */
    pst_event = (frw_event_stru *)pst_event_mem->puc_data;
    pst_event_hdr = &(pst_event->st_event_hdr);

    /* ????hmac device */
    pst_hmac_device = hmac_res_get_mac_dev(pst_event_hdr->uc_device_id);
    if (oal_unlikely(pst_hmac_device == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_scan_proc_scan_comp_event::pst_hmac_device null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_d2h_scan_rsp_info = (mac_scan_rsp_stru *)(pst_event->auc_event_data);
    pst_scan_mgmt = &(pst_hmac_device->st_scan_mgmt);

    if ((pst_event_hdr->uc_vap_id != pst_scan_mgmt->st_scan_record_mgmt.uc_vap_id) ||
        (pst_d2h_scan_rsp_info->ull_cookie != pst_scan_mgmt->st_scan_record_mgmt.ull_cookie)) {
        oam_warning_log4(pst_event_hdr->uc_vap_id, OAM_SF_SCAN, "{hmac_scan_proc_scan_comp_event::Report vap(%d) \
            Scan_complete(cookie %d), but there have anoter vap(%d) scaning(cookie %d) !}", pst_event_hdr->uc_vap_id,
                         pst_d2h_scan_rsp_info->ull_cookie, pst_scan_mgmt->st_scan_record_mgmt.uc_vap_id,
                         pst_scan_mgmt->st_scan_record_mgmt.ull_cookie);
        return OAL_SUCC;
    }

    OAM_WARNING_LOG1(pst_event_hdr->uc_vap_id, OAM_SF_SCAN, "{hmac_scan_proc_scan_comp_event::scan status:%d !}",
                     pst_d2h_scan_rsp_info->en_scan_rsp_status);

    /* ?????????????????????? */
    if ((pst_scan_mgmt->st_scan_timeout.en_is_registerd == OAL_TRUE) &&
        (pst_d2h_scan_rsp_info->en_scan_rsp_status != MAC_SCAN_PNO)) {
        /* PNO??????????????????,??????????PNO????,????????????????,PNO?????????????????????????????????? */
        frw_immediate_destroy_timer(&(pst_scan_mgmt->st_scan_timeout));
    }

    /* ????hmac vap */
    pst_hmac_vap = mac_res_get_hmac_vap(pst_event_hdr->uc_vap_id);
    if (oal_unlikely(pst_hmac_vap == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(pst_event_hdr->uc_vap_id, OAM_SF_SCAN, "{hmac_scan_proc_scan_comp_event::pst_hmac_vap null.}");

        /* ?????????????????????? */
        pst_scan_mgmt->en_is_scanning = OAL_FALSE;
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ????????????????????????vap????????????????vap??????????????????????????????????vap?????? */
    if ((pst_hmac_vap->st_vap_base_info.en_vap_mode == WLAN_VAP_MODE_BSS_STA) &&
        (pst_d2h_scan_rsp_info->en_scan_rsp_status != MAC_SCAN_PNO)) {
        if (pst_hmac_vap->st_vap_base_info.en_vap_state == MAC_VAP_STATE_STA_WAIT_SCAN) {
            /* ????vap??????SCAN_COMP */
            hmac_fsm_change_state(pst_hmac_vap, MAC_VAP_STATE_STA_SCAN_COMP);
        } else if (pst_hmac_vap->st_vap_base_info.en_vap_state == MAC_VAP_STATE_UP) {
            /* ?????????????????????????????? */
            hmac_set_rx_filter_value(&(pst_hmac_vap->st_vap_base_info));
        }
    }

    hmac_scan_complete_result_to_sme(pst_scan_mgmt, pst_hmac_vap, pst_d2h_scan_rsp_info);

    /* ?????????????????????? */
    if (pst_d2h_scan_rsp_info->en_scan_rsp_status != MAC_SCAN_PNO) {
        /* PNO????????????????OAL_TRUE,PNO????????,?????????????????????? */
        pst_scan_mgmt->en_is_scanning = OAL_FALSE;
    }
#ifdef _PRE_WLAN_FEATURE_P2P
    if (pst_hmac_vap->st_vap_base_info.en_vap_state == MAC_VAP_STATE_STA_LISTEN) {
        hmac_p2p_listen_timeout(pst_hmac_vap, &pst_hmac_vap->st_vap_base_info);
    }
    if (pst_hmac_vap->en_wait_roc_end == OAL_TRUE) {
        OAM_WARNING_LOG1(pst_event_hdr->uc_vap_id, OAM_SF_SCAN, "{hmac_scan_proc_scan_comp_event::scan rsp status[%d]}",
                         pst_d2h_scan_rsp_info->en_scan_rsp_status);
        oal_complete(&(pst_hmac_vap->st_roc_end_ready));
        pst_hmac_vap->en_wait_roc_end = OAL_FALSE;
    }
#endif

    return OAL_SUCC;
}

oal_uint32 hmac_scan_proc_scan_req_event_exception(hmac_vap_stru *pst_hmac_vap, oal_void *p_params)
{
    frw_event_mem_stru *pst_event_mem = OAL_PTR_NULL;
    frw_event_stru *pst_event = OAL_PTR_NULL;
    hmac_scan_rsp_stru st_scan_rsp;
    hmac_scan_rsp_stru *pst_scan_rsp = OAL_PTR_NULL;

    if (oal_unlikely((pst_hmac_vap == OAL_PTR_NULL) || (p_params == OAL_PTR_NULL))) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_scan_proc_scan_req_event_exception::param null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ?????????????????????????????? */
    OAM_WARNING_LOG1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                     "{hmac_scan_proc_scan_req_event_exception::vap state is=%x.}",
                     pst_hmac_vap->st_vap_base_info.en_vap_state);

    memset_s(&st_scan_rsp, OAL_SIZEOF(hmac_scan_rsp_stru), 0, OAL_SIZEOF(hmac_scan_rsp_stru));

    /* ????????????????WAL, ????SCAN_DONE , ???????????????? */
    pst_event_mem = frw_event_alloc_m(OAL_SIZEOF(hmac_scan_rsp_stru));
    if (pst_event_mem == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                       "{hmac_scan_proc_scan_req_event_exception::pst_event_mem null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    st_scan_rsp.uc_result_code = MAC_SCAN_REFUSED;
    st_scan_rsp.uc_num_dscr = 0;
#ifdef _PRE_WLAN_FEATURE_ROAM
    /* When STA is roaming, scan req return success instead of failure,
       in case roaming failure which will cause UI scan list null */
    if (pst_hmac_vap->st_vap_base_info.en_vap_state == MAC_VAP_STATE_ROAMING) {
        st_scan_rsp.uc_result_code = MAC_SCAN_SUCCESS;
    }
#endif

    /* ???????? */
    pst_event = (frw_event_stru *)pst_event_mem->puc_data;

    frw_event_hdr_init(&(pst_event->st_event_hdr),
                       FRW_EVENT_TYPE_HOST_CTX,
                       HMAC_HOST_CTX_EVENT_SUB_TYPE_SCAN_COMP_STA,
                       OAL_SIZEOF(hmac_scan_rsp_stru),
                       FRW_EVENT_PIPELINE_STAGE_0,
                       pst_hmac_vap->st_vap_base_info.uc_chip_id,
                       pst_hmac_vap->st_vap_base_info.uc_device_id,
                       pst_hmac_vap->st_vap_base_info.uc_vap_id);

    pst_scan_rsp = (hmac_scan_rsp_stru *)pst_event->auc_event_data;

    if (memcpy_s(pst_scan_rsp, OAL_SIZEOF(hmac_scan_rsp_stru),
                 (oal_void *)(&st_scan_rsp), OAL_SIZEOF(hmac_scan_rsp_stru)) != EOK) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "hmac_scan_proc_scan_req_event_exception_etc::memcpy fail!");
        frw_event_free_m(pst_event_mem);
        return OAL_FAIL;
    }

    /* ???????? */
    frw_event_dispatch_event(pst_event_mem);
    frw_event_free_m(pst_event_mem);

    return OAL_SUCC;
}


oal_void hmac_scan_set_sour_mac_addr_in_probe_req(hmac_vap_stru *pst_hmac_vap,
                                                  oal_uint8 *puc_sour_mac_addr,
                                                  oal_bool_enum_uint8 en_is_rand_mac_addr_scan,
                                                  oal_bool_enum_uint8 en_is_p2p0_scan)
{
    mac_device_stru *pst_mac_device = OAL_PTR_NULL;
    hmac_device_stru *pst_hmac_device = OAL_PTR_NULL;

    if ((pst_hmac_vap == OAL_PTR_NULL) || (puc_sour_mac_addr == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_CFG,
                       "{hmac_scan_set_sour_mac_addr_in_probe_req::param null}");
        return;
    }

    pst_mac_device = mac_res_get_dev(pst_hmac_vap->st_vap_base_info.uc_device_id);
    if (pst_mac_device == OAL_PTR_NULL) {
        oam_warning_log0(0, OAM_SF_CFG, "{hmac_scan_set_sour_mac_addr_in_probe_req::pst_mac_device is null.}");
        return;
    }
    pst_hmac_device = hmac_res_get_mac_dev(pst_hmac_vap->st_vap_base_info.uc_device_id);
    if (pst_hmac_device == OAL_PTR_NULL) {
        OAM_WARNING_LOG1(0, OAM_SF_CFG,
                         "{hmac_scan_set_sour_mac_addr_in_probe_req::pst_hmac_device is null. device_id %d}",
                         pst_hmac_vap->st_vap_base_info.uc_device_id);
        return;
    }

#ifdef _PRE_WLAN_FEATURE_P2P
    /* WLAN/P2P ????????????p2p0 ??p2p-p2p0 cl ?????????????????????????? */
    if (en_is_p2p0_scan == OAL_TRUE) {
        oal_set_mac_addr(puc_sour_mac_addr,
                         pst_hmac_vap->st_vap_base_info.pst_mib_info->st_wlan_mib_sta_config.auc_p2p0_dot11StationID);
    } else
#endif /* _PRE_WLAN_FEATURE_P2P */
    {
        /* ????????mac addr????????????????P2P??????????????mac addr??probe req???? */
        if ((en_is_rand_mac_addr_scan == OAL_TRUE) && (IS_LEGACY_VAP(&(pst_hmac_vap->st_vap_base_info))) &&
            ((pst_mac_device->auc_mac_oui[0] != 0) || (pst_mac_device->auc_mac_oui[1] != 0) ||
             (pst_mac_device->auc_mac_oui[2] != 0))) { /*  ????mac????OUI????0??1??2??????????0 */
            /* ????????wps??????hilink????????????,??mac oui??0 */
            /* ????????mac ????,????????????MAC OUI ??????????mac ?????????????? */
            oal_set_mac_addr(puc_sour_mac_addr, pst_hmac_device->st_scan_mgmt.auc_random_mac);
        } else {
            /* ????????????????MAC???? */
            oal_set_mac_addr(puc_sour_mac_addr,
                             pst_hmac_vap->st_vap_base_info.pst_mib_info->st_wlan_mib_sta_config.auc_dot11StationID);
        }
    }

    return;
}


OAL_STATIC oal_uint32 hmac_scan_update_scan_params(
    hmac_vap_stru *pst_hmac_vap, mac_scan_req_stru *pst_scan_params, oal_bool_enum_uint8 en_is_random_mac_addr_scan)
{
    mac_device_stru *pst_mac_device;
    mac_vap_stru *pst_mac_vap_temp = OAL_PTR_NULL;
    oal_uint32 ul_ret;
    wlan_vap_mode_enum_uint8 en_vap_mode;

    /* ????mac device */
    pst_mac_device = mac_res_get_dev(pst_hmac_vap->st_vap_base_info.uc_device_id);
    if (pst_mac_device == OAL_PTR_NULL) {
        oam_warning_log0(pst_hmac_vap->st_vap_base_info.uc_device_id, OAM_SF_SCAN,
                         "{hmac_scan_update_scan_params::pst_mac_device null.}");
        return OAL_ERR_CODE_MAC_DEVICE_NULL;
    }

    /* 1.??????????????vap id?????????? */
    pst_scan_params->uc_vap_id = pst_hmac_vap->st_vap_base_info.uc_vap_id;
    pst_scan_params->en_scan_mode = WLAN_SCAN_MODE_FOREGROUND;
    pst_scan_params->en_need_switch_back_home_channel = OAL_FALSE;

    /* 2.??????????????????????????: ????????????up????????vap?????????????????????????????????????????????? */
    ul_ret = mac_device_find_up_vap(pst_mac_device, &pst_mac_vap_temp);
    if ((ul_ret == OAL_SUCC) && (pst_mac_vap_temp != OAL_PTR_NULL)) {
        /* ????vap??????????????sta????sta??????????????????ap??????ap??????????????????????vap???????????????? */
        en_vap_mode = pst_hmac_vap->st_vap_base_info.en_vap_mode;
        if (en_vap_mode == WLAN_VAP_MODE_BSS_STA) {
            /* ??????????????sta?????????? */
            pst_scan_params->en_scan_mode = WLAN_SCAN_MODE_BACKGROUND_STA;
        } else if (en_vap_mode == WLAN_VAP_MODE_BSS_AP) {
            /* ??????????????sta?????????? */
            pst_scan_params->en_scan_mode = WLAN_SCAN_MODE_BACKGROUND_AP;
        } else {
            OAM_ERROR_LOG1(0, OAM_SF_SCAN,
                           "{hmac_scan_update_scan_params::vap mode[%d], not support bg scan.}", en_vap_mode);
            return OAL_FAIL;
        }
        pst_scan_params->en_need_switch_back_home_channel = OAL_TRUE;

        if ((mac_device_calc_up_vap_num(pst_mac_device) == 1) && !IS_LEGACY_VAP(pst_mac_vap_temp) &&
            IS_LEGACY_VAP(&pst_hmac_vap->st_vap_base_info)) {
            /* ????????????????(2)????????????????????(60ms):????????P2P??????????????wlan??????????????,wlan?????????? */
            pst_scan_params->uc_scan_channel_interval = MAC_SCAN_CHANNEL_INTERVAL_PERFORMANCE;
            pst_scan_params->us_work_time_on_home_channel = MAC_WORK_TIME_ON_HOME_CHANNEL_PERFORMANCE;

            if ((pst_scan_params->us_scan_time > WLAN_DEFAULT_ACTIVE_SCAN_TIME) &&
                (pst_scan_params->en_scan_type == WLAN_SCAN_TYPE_ACTIVE)) {
                /* ????SSID????????3??,????????????????????40ms(??????20ms) */
                /* P2P??????wlan??????????,????????????????????p2p wfd??????????,????????????????????1??(??????2??) */
                pst_scan_params->uc_max_scan_count_per_channel = 1;
            }
        } else {
            /* ????????????????6????????home????????100ms */
            pst_scan_params->uc_scan_channel_interval = MAC_SCAN_CHANNEL_INTERVAL_DEFAULT;
            pst_scan_params->us_work_time_on_home_channel = MAC_WORK_TIME_ON_HOME_CHANNEL_DEFAULT;
        }
    }
    /* 3.??????????probe req??????mac addr */
    pst_scan_params->en_is_random_mac_addr_scan = en_is_random_mac_addr_scan;
    hmac_scan_set_sour_mac_addr_in_probe_req(pst_hmac_vap, pst_scan_params->auc_sour_mac_addr,
                                             en_is_random_mac_addr_scan, pst_scan_params->bit_is_p2p0_scan);

    return OAL_SUCC;
}


OAL_STATIC oal_uint32 hmac_scan_check_can_enter_scan_state(mac_vap_stru *pst_mac_vap)
{
    /* p2p??????????????????????????scan req???????????????????????????????????????????????????????????????????? */
    return hmac_p2p_check_can_enter_state(pst_mac_vap, HMAC_FSM_INPUT_SCAN_REQ);
}


OAL_STATIC oal_uint32 hmac_scan_check_is_dispatch_scan_req(hmac_vap_stru *pst_hmac_vap,
                                                           hmac_device_stru *pst_hmac_device)
{
    oal_uint32 ul_ret;

    /* 1.??????????vap?????????????????????????????????????????????????????????????????? */
    ul_ret = hmac_scan_check_can_enter_scan_state(&(pst_hmac_vap->st_vap_base_info));
    if (ul_ret != OAL_SUCC) {
        OAM_WARNING_LOG1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                         "hmac_scan_check_is_dispatch_scan_req::Because of err_code[%d], can't enter into scan state",
                         ul_ret);
        return ul_ret;
    }

    /* 2.???????????????????????? */
    if (pst_hmac_device->st_scan_mgmt.en_is_scanning == OAL_TRUE) {
        oam_warning_log0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                         "{hmac_scan_check_is_dispatch_scan_req::the scan request is rejected.}");
        return OAL_FAIL;
    }

#ifdef _PRE_WLAN_FEATURE_ROAM
    /* 3.???????????????????????? */
    if (pst_hmac_vap->st_vap_base_info.en_vap_state == MAC_VAP_STATE_ROAMING) {
        oam_warning_log0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                         "{hmac_scan_check_is_dispatch_scan_req:: roam reject new scan.}");
        return OAL_FAIL;
    }
#endif  // _PRE_WLAN_FEATURE_ROAM

    return OAL_SUCC;
}


OAL_STATIC oal_void hmac_scan_proc_last_scan_record(hmac_vap_stru *pst_hmac_vap,
                                                    hmac_device_stru *pst_hmac_device)
{
    oam_info_log0(0, OAM_SF_SCAN, "{hmac_scan_proc_scan_req_event:: start clean last scan record.}");

    /* ??????????????????????????????????????????????bss???? */
    hmac_scan_clean_expire_scanned_bss(pst_hmac_vap, &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt));

    return;
}


OAL_STATIC oal_uint32 hmac_scan_proc_scan_timeout_fn(void *p_arg)
{
    hmac_device_stru *pst_hmac_device = (hmac_device_stru *)p_arg;
    hmac_vap_stru *pst_hmac_vap = OAL_PTR_NULL;
    hmac_scan_record_stru *pst_scan_record = OAL_PTR_NULL;
    oal_uint32 ul_pedding_data = 0;

    /* ???????????????? */
    pst_scan_record = &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt);

    /* ????hmac vap */
    pst_hmac_vap = mac_res_get_hmac_vap(pst_scan_record->uc_vap_id);
    if (oal_unlikely(pst_hmac_vap == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(pst_scan_record->uc_vap_id, OAM_SF_SCAN, "{hmac_scan_proc_scan_timeout_fn::pst_hmac_vap null.}");

        /* ???????????????????????????? */
        pst_hmac_device->st_scan_mgmt.en_is_scanning = OAL_FALSE;
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ????????????????????????vap????????????????vap??????????????????????????????????vap?????? */
    if (pst_hmac_vap->st_vap_base_info.en_vap_mode == WLAN_VAP_MODE_BSS_STA) {
        if (pst_hmac_vap->st_vap_base_info.en_vap_state == MAC_VAP_STATE_STA_WAIT_SCAN) {
            /* ????vap??????SCAN_COMP */
            hmac_fsm_change_state(pst_hmac_vap, MAC_VAP_STATE_STA_SCAN_COMP);
        } else if (pst_hmac_vap->st_vap_base_info.en_vap_state == MAC_VAP_STATE_UP) {
            /* ?????????????????????????????? */
            hmac_set_rx_filter_value(&(pst_hmac_vap->st_vap_base_info));
        }
    }

    if ((pst_hmac_vap->st_vap_base_info.en_vap_mode == WLAN_VAP_MODE_BSS_AP) &&
        (pst_scan_record->en_vap_last_state != MAC_VAP_STATE_BUTT)) {
        hmac_fsm_change_state(pst_hmac_vap, pst_scan_record->en_vap_last_state);
        pst_scan_record->en_vap_last_state = MAC_VAP_STATE_BUTT;
    }
    /* ?????????????????????? */
    pst_scan_record->en_scan_rsp_status = MAC_SCAN_TIMEOUT;
    OAM_WARNING_LOG1(pst_scan_record->uc_vap_id, OAM_SF_SCAN,
                     "{hmac_scan_proc_scan_timeout_fn::scan time out cookie [%x].}", pst_scan_record->ull_cookie);

    /* ?????????????????????????????????????? */
    if (pst_scan_record->p_fn_cb != OAL_PTR_NULL) {
        oam_warning_log0(pst_scan_record->uc_vap_id, OAM_SF_SCAN,
                         "{hmac_scan_proc_scan_timeout_fn::scan callback func proc.}");
        pst_scan_record->p_fn_cb(pst_scan_record);
    }

    /* DMAC ????????????????????HMAC ??????????????????????DMAC ???? */
    hmac_config_scan_abort(&pst_hmac_vap->st_vap_base_info, OAL_SIZEOF(oal_uint32), (oal_uint8 *)&ul_pedding_data);

    /* ???????????????????????????? */
    pst_hmac_device->st_scan_mgmt.en_is_scanning = OAL_FALSE;

#ifdef _PRE_WLAN_1102A_CHR
    chr_exception_report(CHR_PLATFORM_EXCEPTION_EVENTID, CHR_SYSTEM_WIFI, CHR_LAYER_DRV,
                         CHR_WIFI_DRV_EVENT_SCAN, CHR_WIFI_DRV_ERROR_SCAN_TIMEOUT);
#endif
    return OAL_SUCC;
}
OAL_STATIC oal_void hmac_fill_scan_record(hmac_vap_stru *pst_hmac_vap, mac_scan_req_stru *pst_scan_params,
    hmac_device_stru *pst_hmac_device)
{
    hmac_scan_record_stru *pst_scan_record = OAL_PTR_NULL;
    /* ?????????????????????????????????????????? */
    pst_scan_record = &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt);
    pst_scan_record->uc_chip_id = pst_hmac_device->pst_device_base_info->uc_chip_id;
    pst_scan_record->uc_device_id = pst_hmac_device->pst_device_base_info->uc_device_id;
    pst_scan_record->uc_vap_id = pst_scan_params->uc_vap_id;
    pst_scan_record->uc_chan_numbers = pst_scan_params->uc_channel_nums;
    pst_scan_record->p_fn_cb = pst_scan_params->p_fn_cb;

    if (pst_hmac_vap->st_vap_base_info.en_vap_mode == WLAN_VAP_MODE_BSS_AP) {
        OAM_WARNING_LOG1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN, "{hmac_scan_proc_scan_req_event: \
            save last en_vap_state:%d}", pst_hmac_vap->st_vap_base_info.en_vap_state);
        pst_scan_record->en_vap_last_state = pst_hmac_vap->st_vap_base_info.en_vap_state;
    }
    pst_scan_record->ull_cookie = pst_scan_params->ull_cookie;
    /* ???????????????? */
    pst_scan_record->st_scan_start_time = oal_ktime_get();
}

OAL_STATIC oal_void hmac_change_scan_state(hmac_vap_stru *pst_hmac_vap, mac_scan_req_stru *pst_scan_params)
{
    /* ??????????????vap????????sta??????????????????????up??????????p2p?????????????????????????? */
    if ((pst_hmac_vap->st_vap_base_info.en_vap_mode == WLAN_VAP_MODE_BSS_STA) &&
        (pst_scan_params->uc_scan_func != MAC_SCAN_FUNC_P2P_LISTEN)) {
        if (pst_hmac_vap->st_vap_base_info.en_vap_state != MAC_VAP_STATE_UP) {
            /* ????vap????????WAIT_SCAN???? */
            hmac_fsm_change_state(pst_hmac_vap, MAC_VAP_STATE_STA_WAIT_SCAN);
        } else {
            /* ?????????????????????????????? */
            pst_hmac_vap->st_vap_base_info.en_vap_state = MAC_VAP_STATE_STA_WAIT_SCAN;
            hmac_set_rx_filter_value(&(pst_hmac_vap->st_vap_base_info));
            pst_hmac_vap->st_vap_base_info.en_vap_state = MAC_VAP_STATE_UP;
        }
    } else if (pst_hmac_vap->st_vap_base_info.en_vap_mode == WLAN_VAP_MODE_BSS_AP) {
        mac_vap_state_enum_uint8 en_state_bak = pst_hmac_vap->st_vap_base_info.en_vap_state;
        pst_hmac_vap->st_vap_base_info.en_vap_state = MAC_VAP_STATE_AP_WAIT_START;
        hmac_set_rx_filter_value(&(pst_hmac_vap->st_vap_base_info));
        pst_hmac_vap->st_vap_base_info.en_vap_state = en_state_bak;
    }

    /* AP????????????????????????hostapd????????????????VAP??????INIT???? */
    if ((pst_hmac_vap->st_vap_base_info.en_vap_mode == WLAN_VAP_MODE_BSS_AP) &&
        (pst_hmac_vap->st_vap_base_info.en_vap_state == MAC_VAP_STATE_INIT)) {
        oam_warning_log0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                         "{hmac_scan_proc_scan_req_event::ap startup scan.}");
        hmac_fsm_change_state(pst_hmac_vap, MAC_VAP_STATE_AP_WAIT_START);
    }
}

oal_uint32 hmac_scan_proc_scan_req_event(hmac_vap_stru *pst_hmac_vap, oal_void *p_params)
{
    frw_event_mem_stru *pst_event_mem = OAL_PTR_NULL;
    frw_event_stru *pst_event = OAL_PTR_NULL;
    mac_scan_req_stru *pst_h2d_scan_req_params = OAL_PTR_NULL; /* hmac??????dmac?????????????? */
    mac_scan_req_stru *pst_scan_params = OAL_PTR_NULL;
    hmac_device_stru *pst_hmac_device = OAL_PTR_NULL;
    oal_uint32 ul_scan_timeout;
    oal_uint32 ul_ret;

    /* ?????????????? */
    if (oal_unlikely(oal_any_null_ptr2(pst_hmac_vap, p_params))) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_scan_proc_scan_req_event::param null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ???????????????? */
    if (((hmac_scan_get_en_bgscan_enable_flag() == HMAC_BGSCAN_DISABLE) &&
         (pst_hmac_vap->st_vap_base_info.en_vap_state == MAC_VAP_STATE_UP))
        || (hmac_scan_get_en_bgscan_enable_flag() == HMAC_SCAN_DISABLE)) {
        OAM_WARNING_LOG1(0, OAM_SF_SCAN, "hmac_scan_proc_scan_req_event: g_en_bgscan_enable_flag= %d.",
                         hmac_scan_get_en_bgscan_enable_flag());
        return OAL_FAIL;
    }

    pst_scan_params = (mac_scan_req_stru *)p_params;

    /* ????????: ????????????????0 */
    if (pst_scan_params->uc_channel_nums == 0) {
        oam_warning_log0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                         "{hmac_scan_proc_scan_req_event::channel_nums=0.}");
        return OAL_FAIL;
    }

    /* ????hmac device */
    pst_hmac_device = hmac_res_get_mac_dev(pst_hmac_vap->st_vap_base_info.uc_device_id);
    if (pst_hmac_device == OAL_PTR_NULL) {
        OAM_WARNING_LOG1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                         "{hmac_scan_proc_scan_req_event::pst_hmac_device[%d] null.}",
                         pst_hmac_vap->st_vap_base_info.uc_device_id);
        return OAL_ERR_CODE_MAC_DEVICE_NULL;
    }

    /* ?????????????????????????? */
    if (pst_scan_params->uc_scan_func == MAC_SCAN_FUNC_P2P_LISTEN) {
        ul_ret = hmac_scan_update_scan_params(pst_hmac_vap, pst_scan_params, OAL_FALSE);
    } else {
#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
        ul_ret = hmac_scan_update_scan_params(pst_hmac_vap, pst_scan_params, g_wlan_customize.uc_random_mac_addr_scan);
#else
        ul_ret = hmac_scan_update_scan_params(pst_hmac_vap, pst_scan_params,
                                              pst_hmac_device->st_scan_mgmt.en_is_random_mac_addr_scan);
#endif
    }
    if (ul_ret != OAL_SUCC) {
        OAM_WARNING_LOG1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                         "{hmac_scan_proc_scan_req_event::update scan mode failed, error[%d].}", ul_ret);
        return ul_ret;
    }

    /* ???????????????????????????????????????????????????? */
    ul_ret = hmac_scan_check_is_dispatch_scan_req(pst_hmac_vap, pst_hmac_device);
    if (ul_ret != OAL_SUCC) {
        if (pst_scan_params->uc_scan_func == MAC_SCAN_FUNC_P2P_LISTEN) {
            mac_vap_state_change(&pst_hmac_vap->st_vap_base_info,
                                 pst_hmac_device->pst_device_base_info->st_p2p_info.en_last_vap_state);
        }

        OAM_WARNING_LOG1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                         "{hmac_scan_proc_scan_req_event::Because of error[%d], can't dispatch scan req.}", ul_ret);
        return ul_ret;
    }

    /* ???????????????????????????????????????????? */
    pst_hmac_device->st_scan_mgmt.en_is_scanning = OAL_TRUE;

    /* ???????????????????????????????????????????????????????????????????? */
    hmac_scan_proc_last_scan_record(pst_hmac_vap, pst_hmac_device);

    /* ?????????????????????????????????????????? */
    hmac_fill_scan_record(pst_hmac_vap, pst_scan_params, pst_hmac_device);

    /* ????????????????DMAC, ???????????? */
    pst_event_mem = frw_event_alloc_m(OAL_SIZEOF(mac_scan_req_stru));
    if (pst_event_mem == OAL_PTR_NULL) {
        OAM_ERROR_LOG1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                       "{hmac_scan_proc_scan_req_event::alloc memory(%u) failed.}", OAL_SIZEOF(mac_scan_req_stru));

        /* ???????????????????????? */
        pst_hmac_device->st_scan_mgmt.en_is_scanning = OAL_FALSE;
        return OAL_ERR_CODE_PTR_NULL;
    }

    hmac_change_scan_state(pst_hmac_vap, pst_scan_params);

    /* ???????? */
    pst_event = (frw_event_stru *)pst_event_mem->puc_data;

    frw_event_hdr_init(&(pst_event->st_event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WLAN_CTX_EVENT_SUB_TYPE_SCAN_REQ,
                       OAL_SIZEOF(mac_scan_req_stru),
                       FRW_EVENT_PIPELINE_STAGE_1,
                       pst_hmac_vap->st_vap_base_info.uc_chip_id,
                       pst_hmac_vap->st_vap_base_info.uc_device_id,
                       pst_hmac_vap->st_vap_base_info.uc_vap_id);

    /* ???????????????????????????? */
    pst_h2d_scan_req_params = (mac_scan_req_stru *)(pst_event->auc_event_data);

    /* ??????????????????????data???? */
    memcpy_s(pst_h2d_scan_req_params, OAL_SIZEOF(mac_scan_req_stru), pst_scan_params, OAL_SIZEOF(mac_scan_req_stru));

    /* ?????????????????????? */
    /* ??????P2P ????????????????HMAC ??????????????P2P ???????? */
    if (pst_scan_params->uc_scan_func == MAC_SCAN_FUNC_P2P_LISTEN) {
        ul_scan_timeout = pst_scan_params->us_scan_time * 2; /* HMAC ??????????????2???????????????? */
    } else {
        ul_scan_timeout = WLAN_DEFAULT_MAX_TIME_PER_SCAN;
    }
    hmac_scan_print_scan_params(pst_h2d_scan_req_params, &pst_hmac_vap->st_vap_base_info);

    /* ????????????????????????????????????????????????????????????????????????????????????????4.5?? */
    frw_create_timer(&(pst_hmac_device->st_scan_mgmt.st_scan_timeout),
                     hmac_scan_proc_scan_timeout_fn,
                     ul_scan_timeout,
                     pst_hmac_device,
                     OAL_FALSE,
                     OAM_MODULE_ID_HMAC,
                     pst_hmac_device->pst_device_base_info->ul_core_id);

    /* ???????? */
    frw_event_dispatch_event(pst_event_mem);
    frw_event_free_m(pst_event_mem);

    return OAL_SUCC;
}


oal_uint32 hmac_scan_proc_sched_scan_req_event(hmac_vap_stru *pst_hmac_vap, oal_void *p_params)
{
    frw_event_mem_stru *pst_event_mem = OAL_PTR_NULL;
    frw_event_stru *pst_event = OAL_PTR_NULL;
    hmac_device_stru *pst_hmac_device = OAL_PTR_NULL;
    hmac_scan_record_stru *pst_scan_record = OAL_PTR_NULL;
    mac_pno_scan_stru *pst_pno_scan_params = OAL_PTR_NULL;
    oal_uint32 ul_ret;

    /* ?????????????? */
    if (oal_unlikely((pst_hmac_vap == OAL_PTR_NULL) || (p_params == OAL_PTR_NULL))) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_scan_proc_sched_scan_req_event::param is null!}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_pno_scan_params = (mac_pno_scan_stru *)p_params;

    /* ????PNO????????????????????ssid????????????0 */
    if (pst_pno_scan_params->l_ssid_count <= 0) {
        oam_warning_log0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                         "{hmac_scan_proc_sched_scan_req_event::ssid_count <=0.}");
        return OAL_FAIL;
    }

    /* ????hmac device */
    pst_hmac_device = hmac_res_get_mac_dev(pst_hmac_vap->st_vap_base_info.uc_device_id);
    if (pst_hmac_device == OAL_PTR_NULL) {
        OAM_WARNING_LOG1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN, "hmac_scan_proc_sched_scan_req_event: \
            pst_hmac_device[%d] null", pst_hmac_vap->st_vap_base_info.uc_device_id);
        return OAL_ERR_CODE_MAC_DEVICE_NULL;
    }

    /* ???????????????????????????????????????????????????? */
    ul_ret = hmac_scan_check_is_dispatch_scan_req(pst_hmac_vap, pst_hmac_device);
    if (ul_ret != OAL_SUCC) {
        OAM_WARNING_LOG1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN, "hmac_scan_proc_sched_scan_req_event: \
            Because of error[%d], can't dispatch scan req.}", ul_ret);
        return ul_ret;
    }

    /* ???????????????????? */
    hmac_scan_proc_last_scan_record(pst_hmac_vap, pst_hmac_device);

    /* ?????????????????????????????????????????? */
    pst_scan_record = &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt);
    pst_scan_record->uc_chip_id = pst_hmac_device->pst_device_base_info->uc_chip_id;
    pst_scan_record->uc_device_id = pst_hmac_device->pst_device_base_info->uc_device_id;
    pst_scan_record->uc_vap_id = pst_hmac_vap->st_vap_base_info.uc_vap_id;
    pst_scan_record->p_fn_cb = pst_pno_scan_params->p_fn_cb;

    /* ????????????????DMAC, ???????????? */
    pst_event_mem = frw_event_alloc_m(OAL_SIZEOF(mac_pno_scan_stru *));
    if (pst_event_mem == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                       "{hmac_scan_proc_sched_scan_req_event::pst_event_mem null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ???????? */
    pst_event = (frw_event_stru *)pst_event_mem->puc_data;

    frw_event_hdr_init(&(pst_event->st_event_hdr), FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WLAN_CTX_EVENT_SUB_TYPE_SCHED_SCAN_REQ,
                       OAL_SIZEOF(mac_pno_scan_stru *), FRW_EVENT_PIPELINE_STAGE_1,
                       pst_hmac_vap->st_vap_base_info.uc_chip_id,
                       pst_hmac_vap->st_vap_base_info.uc_device_id, pst_hmac_vap->st_vap_base_info.uc_vap_id);

    /* ????data????????PNO???????????? */
    if (memcpy_s(frw_get_event_payload(pst_event_mem), OAL_SIZEOF(mac_pno_scan_stru *),
                 (oal_uint8 *)&pst_pno_scan_params, OAL_SIZEOF(mac_pno_scan_stru *)) != EOK) {
        OAM_ERROR_LOG0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_SCAN,
                       "hmac_scan_proc_sched_scan_req_event::memcpy fail!");
        frw_event_free_m(pst_event_mem);
        return OAL_FAIL;
    }

    /* ???????? */
    frw_event_dispatch_event(pst_event_mem);
    frw_event_free_m(pst_event_mem);

    return OAL_SUCC;
}


oal_uint32 hmac_scan_process_chan_result_event(frw_event_mem_stru *pst_event_mem)
{
    frw_event_stru *pst_event;
    frw_event_hdr_stru *pst_event_hdr;
    hmac_device_stru *pst_hmac_device;
    dmac_crx_chan_result_stru *pst_chan_result_param;
    hmac_scan_record_stru *pst_scan_record = OAL_PTR_NULL;
    oal_uint8 uc_scan_idx;

    /* ???????????? */
    pst_event = (frw_event_stru *)pst_event_mem->puc_data;
    pst_event_hdr = &(pst_event->st_event_hdr);
    pst_chan_result_param = (dmac_crx_chan_result_stru *)(pst_event->auc_event_data);
    uc_scan_idx = pst_chan_result_param->uc_scan_idx;

    /* ????hmac device */
    pst_hmac_device = hmac_res_get_mac_dev(pst_event_hdr->uc_device_id);
    if (pst_hmac_device == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{hmac_scan_process_chan_result_event::pst_hmac_device is null.}");
        return OAL_FAIL;
    }

    pst_scan_record = &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt);

    /* ?????????????????????? */
    if (uc_scan_idx >= pst_scan_record->uc_chan_numbers) {
        /* dmac???????????????????????????????????? */
        oam_warning_log2(0, OAM_SF_SCAN,
                         "{hmac_scan_process_chan_result_event:result from dmac error!scan_idx[%d], chan_numbers[%d]}",
                         uc_scan_idx, pst_scan_record->uc_chan_numbers);

        return OAL_FAIL;
    }

    pst_scan_record->ast_chan_results[uc_scan_idx] = pst_chan_result_param->st_chan_result;

    return OAL_SUCC;
}
#ifdef _PRE_WLAN_FEATURE_11K
OAL_STATIC oal_uint8 hmac_scan_rrm_pro_encap_meas_rpt_ie(
    hmac_vap_stru *pst_hmac_vap, hmac_bss_mgmt_stru *pst_bss_mgmt, mac_vap_rrm_trans_req_info2_stru *pst_trans_req_info,
    mac_meas_rpt_ie_stru *pst_meas_rpt_ie, oal_uint16 *pus_len)
{
    oal_dlist_head_stru *pst_entry;
    hmac_scanned_bss_info *pst_scanned_bss;
    mac_bcn_rpt_stru *pst_bcn_rpt;
    oal_uint8 uc_bss_num = 0;

    oal_dlist_search_for_each(pst_entry, &(pst_bss_mgmt->st_bss_list_head)) {
        pst_scanned_bss = oal_dlist_get_entry(pst_entry, hmac_scanned_bss_info, st_dlist_head);
        /* BSSID???? */
        if (!ether_is_broadcast(pst_trans_req_info->auc_bssid) &&
            oal_memcmp(pst_scanned_bss->st_bss_dscr_info.auc_bssid, pst_trans_req_info->auc_bssid, WLAN_MAC_ADDR_LEN)) {
            continue;
        }

        /* SSID??????????????ssid??????0?????????? */
        if ((pst_trans_req_info->us_ssid_len != 0) &&
            oal_memcmp(pst_scanned_bss->st_bss_dscr_info.ac_ssid,
                       pst_trans_req_info->auc_ssid, pst_trans_req_info->us_ssid_len)) {
            continue;
        }

        /*************************************************************************/
        /* Measurement Report IE - Frame Body */
        /* --------------------------------------------------------------------- */
        /* |Element ID |Length |Meas Token| Meas Rpt Mode | Meas Type | Meas Rpt| */
        /* --------------------------------------------------------------------- */
        /* |1          |1      | 1        |  1            | 1         | var */
        /* --------------------------------------------------------------------- */
        /*************************************************************************/
        pst_meas_rpt_ie->uc_eid = MAC_EID_MEASREP;
        pst_meas_rpt_ie->uc_len = 3 + MAC_BEACON_RPT_FIX_LEN; /* Length??????29??3 + 26?? */
        pst_meas_rpt_ie->uc_token = pst_trans_req_info->uc_meas_token;
        memset_s(&(pst_meas_rpt_ie->st_rptmode), OAL_SIZEOF(mac_meas_rpt_mode_stru), 0,
                 OAL_SIZEOF(mac_meas_rpt_mode_stru));
        pst_meas_rpt_ie->uc_rpttype = 5; /* Meas Type??????5 */

        pst_bcn_rpt = (mac_bcn_rpt_stru *)pst_meas_rpt_ie->auc_meas_rpt;
        memset_s(pst_bcn_rpt, OAL_SIZEOF(mac_bcn_rpt_stru), 0, OAL_SIZEOF(mac_bcn_rpt_stru));
        memcpy_s(pst_bcn_rpt->auc_bssid, WLAN_MAC_ADDR_LEN, pst_scanned_bss->st_bss_dscr_info.auc_bssid,
                 WLAN_MAC_ADDR_LEN);
        pst_bcn_rpt->uc_channum = pst_scanned_bss->st_bss_dscr_info.st_channel.uc_chan_number;
        if (pst_hmac_vap->bit_11k_auth_oper_class != 0) {
            pst_bcn_rpt->uc_optclass = pst_hmac_vap->bit_11k_auth_oper_class;
        } else {
            pst_bcn_rpt->uc_optclass = pst_trans_req_info->uc_oper_class;
        }
        oam_warning_log4(0, OAM_SF_RRM, "{hmac_scan_rrm_pro_encap_meas_rpt_ie:In Channel [%d] Find BSS \
            %02X:XX:XX:XX:%02X:%02X.}", pst_scanned_bss->st_bss_dscr_info.st_channel.uc_chan_number,
                         pst_scanned_bss->st_bss_dscr_info.auc_bssid[0],
                         pst_scanned_bss->st_bss_dscr_info.auc_bssid[4], /* auc_bssid ??4??5?????????????????? */
                         pst_scanned_bss->st_bss_dscr_info.auc_bssid[5]);

        *pus_len += (MAC_MEASUREMENT_RPT_FIX_LEN + MAC_BEACON_RPT_FIX_LEN);
        uc_bss_num++;
        if ((WLAN_MEM_NETBUF_SIZE2 - (*pus_len)) < (MAC_MEASUREMENT_RPT_FIX_LEN + MAC_BEACON_RPT_FIX_LEN)) {
            break;
        }
        pst_meas_rpt_ie = (mac_meas_rpt_ie_stru *)pst_bcn_rpt->auc_subelm;
    }

    return uc_bss_num;
}


oal_uint32 hmac_scan_rrm_proc_save_bss(mac_vap_stru *pst_mac_vap, oal_uint8 uc_len, oal_uint8 *puc_param)
{
    oal_netbuf_stru *pst_action_table_bcn_rpt;
    oal_uint8 *puc_data;
    mac_user_stru *pst_mac_user;
    oal_uint16 us_index;
    mac_meas_rpt_ie_stru *pst_meas_rpt_ie;
    mac_tx_ctl_stru *pst_tx_ctl;
    mac_vap_rrm_trans_req_info2_stru *pst_trans_req_info;
    oal_uint32 ul_ret;
    hmac_device_stru *pst_hmac_device;
    hmac_bss_mgmt_stru *pst_bss_mgmt;
    oal_uint8 uc_bss_num;
    hmac_vap_stru *pst_hmac_vap;
    oal_uint16 us_len;

    if (puc_param == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ASSOC, "{hmac_scan_rrm_proc_save_bss::puc_param null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ????hmac vap */
    pst_hmac_vap = mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (pst_hmac_vap == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_SCAN, "{hmac_scan_rrm_proc_save_bss_etc::pst_hmac_vap null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_hmac_device = hmac_res_get_mac_dev(pst_mac_vap->uc_device_id);
    if (oal_unlikely(pst_hmac_device == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_SCAN, "{hmac_scan_rrm_proc_save_bss::pst_hmac_device null.}");

        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_mac_user = mac_res_get_mac_user(pst_mac_vap->uc_assoc_vap_id);
    if (pst_mac_user == OAL_PTR_NULL) {
        OAM_ERROR_LOG1(0, OAM_SF_TX,
                       "{hmac_scan_rrm_proc_save_bss::pst_mac_user[%d] null.", pst_mac_vap->uc_assoc_vap_id);

        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_trans_req_info = (mac_vap_rrm_trans_req_info2_stru *)puc_param;

    pst_action_table_bcn_rpt = (oal_netbuf_stru *)oal_mem_netbuf_alloc(OAL_NORMAL_NETBUF, WLAN_MEM_NETBUF_SIZE2,
                                                                       OAL_NETBUF_PRIORITY_MID);
    if (pst_action_table_bcn_rpt == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ASSOC,
                       "{hmac_scan_rrm_proc_save_bss::pst_action_table_bcn_rpt null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    memset_s(oal_netbuf_cb(pst_action_table_bcn_rpt), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size());

    puc_data = (oal_uint8 *)oal_netbuf_header(pst_action_table_bcn_rpt);

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
    /* All the fields of the Frame Control Field are set to zero. Only the */
    /* Type/Subtype field is set. */
    mac_hdr_set_frame_control(puc_data, WLAN_PROTOCOL_VERSION | WLAN_FC0_TYPE_MGT | WLAN_FC0_SUBTYPE_ACTION);

    /* duration */
    puc_data[2] = 0; /* puc_data??2??3????(????????)??0 */
    puc_data[3] = 0;

    /* DA is address of STA requesting association */
    oal_set_mac_addr(puc_data + 4, pst_mac_user->auc_user_mac_addr); /* puc_data????4??????DA */

    /* SA is the dot11MACAddress */
    /* puc_data????10??????SA */
    oal_set_mac_addr(puc_data + 10, pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.auc_dot11StationID);

    oal_set_mac_addr(puc_data + 16, pst_mac_vap->auc_bssid); /* puc_data????16??????BSSID */

    /* seq control */
    puc_data[22] = 0; /* puc_data??22??23????(seq control)??0 */
    puc_data[23] = 0;

    /*************************************************************************/
    /* Radio Measurement Report Frame - Frame Body */
    /* --------------------------------------------------------------------- */
    /* |Category |Action |Dialog Token| Measurement Report Elements         | */
    /* --------------------------------------------------------------------- */
    /* |1        |1      | 1          |  var */
    /* --------------------------------------------------------------------- */
    /*************************************************************************/
    /* Initialize index and the frame data pointer */
    us_index = MAC_80211_FRAME_LEN;

    /* Category */
    puc_data[us_index++] = MAC_ACTION_CATEGORY_RADIO_MEASURMENT;

    /* Action */
    puc_data[us_index++] = MAC_RM_ACTION_RADIO_MEASUREMENT_REPORT;

    /* Dialog Token */
    puc_data[us_index++] = pst_trans_req_info->uc_action_dialog_token;

    us_len = us_index;

    /* ??????????????bss???????????? */
    pst_bss_mgmt = &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt.st_bss_mgmt);

    if ((WLAN_MEM_NETBUF_SIZE2 - us_len) < (MAC_MEASUREMENT_RPT_FIX_LEN + MAC_BEACON_RPT_FIX_LEN)) {
        /* ????bcn_rpt???? */
        oal_netbuf_free(pst_action_table_bcn_rpt);
        return OAL_SUCC;
    }
    pst_meas_rpt_ie = (mac_meas_rpt_ie_stru *)(puc_data + us_index);

    /* ?????????????????? */
    oal_spin_lock(&(pst_bss_mgmt->st_lock));

    uc_bss_num = hmac_scan_rrm_pro_encap_meas_rpt_ie(pst_hmac_vap, pst_bss_mgmt, pst_trans_req_info,
                                                     pst_meas_rpt_ie, &us_len);

    oal_spin_unlock(&(pst_bss_mgmt->st_lock));

    oam_warning_log3(pst_mac_vap->uc_vap_id, OAM_SF_ANY,
                     "{hmac_scan_rrm_proc_save_bss:: Find BSS Num = [%d],us_len=[%d], buf_size=[%d].}",
                     uc_bss_num, us_len, WLAN_MEM_NETBUF_SIZE2);

    pst_tx_ctl = (mac_tx_ctl_stru *)oal_netbuf_cb(pst_action_table_bcn_rpt);
    pst_tx_ctl->us_mpdu_len = us_len;
    /* ????????user_idex */
    ul_ret = mac_vap_set_cb_tx_user_idx(pst_mac_vap, pst_tx_ctl, pst_mac_user->auc_user_mac_addr);
    if (ul_ret != OAL_SUCC) {
        oam_warning_log3(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "(hmac_scan_rrm_proc_save_bss:fail to find user by \
            xx:xx:xx:0x:0x:0x.}", pst_mac_user->auc_user_mac_addr[3], /* auc_user_mac_addr??3??4??5?????????????????? */
                         pst_mac_user->auc_user_mac_addr[4], pst_mac_user->auc_user_mac_addr[5]);
    }

    if (MAC_GET_CB_MPDU_LEN(pst_tx_ctl) > WLAN_MEM_NETBUF_SIZE2) {
        oal_netbuf_free(pst_action_table_bcn_rpt);
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{hmac_scan_rrm_proc_save_bss_etc::invalid us_len=[%d].}",
                         MAC_GET_CB_MPDU_LEN(pst_tx_ctl));
        return OAL_SUCC;
    }

    oal_netbuf_put(pst_action_table_bcn_rpt, pst_tx_ctl->us_mpdu_len);

    ul_ret = hmac_tx_mgmt_send_event(pst_mac_vap, pst_action_table_bcn_rpt, pst_tx_ctl->us_mpdu_len);
    if (ul_ret != OAL_SUCC) {
        oal_netbuf_free(pst_action_table_bcn_rpt);
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "hmac_scan_rrm_proc_save_bss:send_event failed[%d]", ul_ret);
    }

    return OAL_SUCC;
}
#endif

oal_void hmac_scan_init(hmac_device_stru *pst_hmac_device)
{
    hmac_scan_stru *pst_scan_mgmt;
    hmac_bss_mgmt_stru *pst_bss_mgmt = OAL_PTR_NULL;

    /* ???????????????????????? */
    pst_scan_mgmt = &(pst_hmac_device->st_scan_mgmt);
    memset_s(pst_scan_mgmt, OAL_SIZEOF(hmac_scan_stru), 0, OAL_SIZEOF(hmac_scan_stru));
    pst_scan_mgmt->en_is_scanning = OAL_FALSE;
    pst_scan_mgmt->st_scan_record_mgmt.en_vap_last_state = MAC_VAP_STATE_BUTT;

    /* ??????bss???????????????? */
    pst_bss_mgmt = &(pst_scan_mgmt->st_scan_record_mgmt.st_bss_mgmt);
    oal_dlist_init_head(&(pst_bss_mgmt->st_bss_list_head));
    oal_spin_lock_init(&(pst_bss_mgmt->st_lock));

    /* ??????????????????request?????? */
    oal_spin_lock_init(&(pst_scan_mgmt->st_scan_request_spinlock));

    /* ?????? st_wiphy_mgmt ???? */
    oal_wait_queue_init_head(&(pst_scan_mgmt->st_wait_queue));
    /* ??????????????????MAC ???? */
    oal_random_ether_addr(pst_hmac_device->st_scan_mgmt.auc_random_mac);
    return;
}


oal_void hmac_scan_exit(hmac_device_stru *pst_hmac_device)
{
    hmac_scan_stru *pst_scan_mgmt = OAL_PTR_NULL;

    /* ???????????????? */
    hmac_scan_clean_scan_record(&(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt));

    /* ?????????????????????? */
    pst_scan_mgmt = &(pst_hmac_device->st_scan_mgmt);
    memset_s(pst_scan_mgmt, OAL_SIZEOF(hmac_scan_stru), 0, OAL_SIZEOF(hmac_scan_stru));
    pst_scan_mgmt->en_is_scanning = OAL_FALSE;
    return;
}


oal_uint32 hmac_bgscan_enable(mac_vap_stru *pst_mac_vap, oal_uint16 us_len, oal_uint8 *puc_param)
{
    hmac_scan_state_enum_uint8 pen_bgscan_enable_flag;

    pen_bgscan_enable_flag = *puc_param; /* ?????????????????? */

    /* ???????????????? */
    switch (pen_bgscan_enable_flag) {
        case 0:
            hmac_scan_set_en_bgscan_enable_flag(HMAC_BGSCAN_DISABLE);
            break;
        case 1:
            hmac_scan_set_en_bgscan_enable_flag(HMAC_BGSCAN_ENABLE);
            break;
        case 2:
            hmac_scan_set_en_bgscan_enable_flag(HMAC_SCAN_DISABLE);
            break;
        default:
            hmac_scan_set_en_bgscan_enable_flag(HMAC_BGSCAN_ENABLE);
            break;
    }

    OAM_WARNING_LOG1(0, OAM_SF_SCAN, "hmac_bgscan_enable: g_en_bgscan_enable_flag= %d.",
        hmac_scan_get_en_bgscan_enable_flag());

    return OAL_SUCC;
}

#ifdef _PRE_WLAN_FEATURE_DBAC

oal_uint32 hmac_scan_start_dbac(mac_device_stru *pst_dev)
{
    oal_uint8 auc_cmd[32];
    oal_uint16 us_len;
    oal_uint32 ul_ret = OAL_FAIL;
    oal_uint8 uc_idx;
#define DBAC_START_STR     " dbac start"
#define DBAC_START_STR_LEN 11
    mac_vap_stru *pst_mac_vap = OAL_PTR_NULL;

    mac_ioctl_alg_config_stru *pst_alg_config = (mac_ioctl_alg_config_stru *)auc_cmd;

    if (memcpy_s(auc_cmd + OAL_SIZEOF(mac_ioctl_alg_config_stru),
                 OAL_SIZEOF(auc_cmd) - OAL_SIZEOF(mac_ioctl_alg_config_stru),
                 (const oal_int8 *)DBAC_START_STR, 11) != EOK) { /* ??????????11 */
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "hmac_scan_start_dbac::memcpy fail!");
        return OAL_FAIL;
    }
    auc_cmd[OAL_SIZEOF(mac_ioctl_alg_config_stru) + DBAC_START_STR_LEN] = 0;

    pst_alg_config->uc_argc = 2; /* ????????????????????????????2 */
    pst_alg_config->auc_argv_offset[0] = 1;
    pst_alg_config->auc_argv_offset[1] = 6; /* ????????????????6 */

    for (uc_idx = 0; uc_idx < pst_dev->uc_vap_num; uc_idx++) {
        pst_mac_vap = mac_res_get_mac_vap(pst_dev->auc_vap_id[uc_idx]);
        if ((pst_mac_vap != OAL_PTR_NULL) &&
            (pst_mac_vap->en_vap_mode == WLAN_VAP_MODE_BSS_AP)) {
            break;
        }
    }
    if (pst_mac_vap) {
        us_len = OAL_SIZEOF(mac_ioctl_alg_config_stru) + DBAC_START_STR_LEN + 1;
        ul_ret = hmac_config_send_event(pst_mac_vap, WLAN_CFGID_ALG, us_len, auc_cmd);
        if (oal_unlikely(ul_ret != OAL_SUCC)) {
            OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_CFG,
                             "{hmac_config_alg::hmac_config_send_event failed[%d].}", ul_ret);
        }
        OAL_IO_PRINT("start dbac\n");
    } else {
        OAL_IO_PRINT("no vap found to start dbac\n");
    }

    return ul_ret;
}
#endif

oal_void hmac_start_all_bss_of_device(hmac_device_stru *pst_hmac_dev)
{
    oal_uint8 uc_idx;
    hmac_vap_stru *pst_hmac_vap = OAL_PTR_NULL;
    mac_device_stru *pst_dev = pst_hmac_dev->pst_device_base_info;

    OAM_WARNING_LOG1(0, OAM_SF_ACS, "{hmac_start_all_bss_of_device:device id=%d}",
                     pst_hmac_dev->pst_device_base_info->uc_device_id);
    if (oal_unlikely(pst_dev == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{hmac_start_all_bss_of_device::pst_device_base_info null!}");
        return;
    }

    for (uc_idx = 0; uc_idx < pst_dev->uc_vap_num; uc_idx++) {
        pst_hmac_vap = mac_res_get_hmac_vap(pst_dev->auc_vap_id[uc_idx]);
        if (pst_hmac_vap == OAL_PTR_NULL) {
            oam_warning_log2(0, OAM_SF_ACS, "hmac_start_all_bss_of_device:null ap, idx=%d id=%d", uc_idx,
                             pst_dev->auc_vap_id[uc_idx]);
            continue;
        }

        if ((pst_hmac_vap != OAL_PTR_NULL) &&
            (pst_hmac_vap->st_vap_base_info.en_vap_state == MAC_VAP_STATE_AP_WAIT_START
#ifdef _PRE_WLAN_FEATURE_DBAC
             || (mac_is_dbac_enabled(pst_dev) && (pst_hmac_vap->st_vap_base_info.en_vap_state == MAC_VAP_STATE_PAUSE))
#endif
             || (pst_hmac_vap->st_vap_base_info.en_vap_state == MAC_VAP_STATE_UP))) {
            if (hmac_chan_start_bss(pst_hmac_vap, OAL_PTR_NULL, WLAN_PROTOCOL_BUTT) == OAL_SUCC) {
                oam_warning_log4(0, OAM_SF_ACS, "start vap %d on ch=%d band=%d bw=%d\n",
                                 pst_dev->auc_vap_id[uc_idx],
                                 pst_hmac_vap->st_vap_base_info.st_channel.uc_chan_number,
                                 pst_hmac_vap->st_vap_base_info.st_channel.en_band,
                                 pst_hmac_vap->st_vap_base_info.st_channel.en_bandwidth);
            }
        } else {
            oam_warning_log0(0, OAM_SF_ACS, "start vap error\n");
            continue;
        }
    }

#ifdef _PRE_WLAN_FEATURE_DBAC
    if (mac_is_dbac_enabled(pst_dev)) {
        hmac_scan_start_dbac(pst_dev);
    }
#endif

    return;
}
/*lint -e578*//*lint -e19*/
oal_module_symbol(hmac_scan_find_scanned_bss_dscr_by_index);
oal_module_symbol(hmac_scan_find_scanned_bss_by_bssid);
/*lint -e578*//*lint -e19*/


