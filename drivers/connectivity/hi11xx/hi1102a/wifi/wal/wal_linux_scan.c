

/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "oal_net.h"
#include "oal_cfg80211.h"
#include "oal_schedule.h"
#include "wal_linux_event.h"
#include "wal_linux_scan.h"
#include "wal_linux_cfg80211.h"
#include "wal_main.h"
#include "wal_linux_rx_rsp.h"
#include "hmac_vap.h"
#include "hmac_device.h"
#include "mac_device.h"
#include "hmac_resource.h"

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include "plat_pm_wlan.h"
#endif

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <net/cfg80211.h>
#elif (_PRE_OS_VERSION_WIN32 == _PRE_OS_VERSION)

#endif
#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_WAL_LINUX_SCAN_C

/*****************************************************************************
  2 ????????????
*****************************************************************************/
/*****************************************************************************
  3 ????????
*****************************************************************************/

OAL_STATIC oal_void wal_inform_bss_frame(wal_scanned_bss_info_stru *pst_scanned_bss_info, oal_void *p_data)
{
    oal_cfg80211_bss_stru *pst_cfg80211_bss = OAL_PTR_NULL;
    oal_wiphy_stru *pst_wiphy = OAL_PTR_NULL;
    oal_ieee80211_channel_stru *pst_ieee80211_channel = OAL_PTR_NULL;

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39))
    struct timespec ts;
#else
    struct timeval tv;
#endif
#endif

    if ((pst_scanned_bss_info == OAL_PTR_NULL) || (p_data == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN,
            "{wal_inform_bss_frame::input param pointer is null!}");
        return;
    }

    pst_wiphy = (oal_wiphy_stru *)p_data;

    pst_ieee80211_channel = oal_ieee80211_get_channel(pst_wiphy, (oal_int32)pst_scanned_bss_info->s_freq);
    if (pst_ieee80211_channel == NULL) {
        OAM_WARNING_LOG1(0, OAM_SF_SCAN, "{wal_inform_bss_frame::get channel failed, wrong s_freq[%d]}",
                         (oal_int32)pst_scanned_bss_info->s_freq);
        return;
    }

    pst_scanned_bss_info->l_signal = pst_scanned_bss_info->l_signal * 100; /* ????????????????????100?? */

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    /* ??????????????????????????cts????2????????bss??timestamp????????(????????????????) */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39))
    get_monotonic_boottime(&ts);
    pst_scanned_bss_info->pst_mgmt->u.probe_resp.timestamp = ((u64)ts.tv_sec * 1000000) /* 1s ???? 1000000us */
                                                             + ts.tv_nsec / 1000; /* 1us ???? 1000ns */
#else
    do_gettimeofday(&tv);
    pst_scanned_bss_info->pst_mgmt->u.probe_resp.timestamp = ((u64)tv.tv_sec * 1000000) /* 1s ???? 1000000us */
                                                             + tv.tv_usec;
#endif
#endif
    /* ????????????bss ???? */
    pst_cfg80211_bss = oal_cfg80211_inform_bss_frame(pst_wiphy, pst_ieee80211_channel, pst_scanned_bss_info->pst_mgmt,
                                                     pst_scanned_bss_info->ul_mgmt_len,
                                                     pst_scanned_bss_info->l_signal, GFP_ATOMIC);
    if (pst_cfg80211_bss != NULL) {
        oal_cfg80211_put_bss(pst_wiphy, pst_cfg80211_bss);
    }

    return;
}


oal_void wal_update_bss(oal_wiphy_stru *pst_wiphy,
                        hmac_bss_mgmt_stru *pst_bss_mgmt,
                        oal_uint8 *puc_bssid)
{
    wal_scanned_bss_info_stru st_scanned_bss_info;
    oal_cfg80211_bss_stru *pst_cfg80211_bss = OAL_PTR_NULL;
    hmac_scanned_bss_info *pst_scanned_bss = OAL_PTR_NULL;
    mac_ieee80211_frame_stru *pst_frame_hdr = OAL_PTR_NULL;
    oal_dlist_head_stru *pst_entry = OAL_PTR_NULL;
    mac_bss_dscr_stru *pst_bss_dscr = OAL_PTR_NULL;
    oal_uint8 uc_chan_number;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0))
    enum nl80211_band en_band;
#else
    enum ieee80211_band en_band;
#endif
    oal_int32 l_channel;
    oal_bool_enum_uint8 en_inform_bss = OAL_TRUE;

    if ((pst_wiphy == OAL_PTR_NULL) || (pst_bss_mgmt == OAL_PTR_NULL) || (puc_bssid == OAL_PTR_NULL)) {
        oam_warning_log0(0, OAM_SF_ASSOC, "{wal_update_bss::null pointer.");
        return;
    }

    pst_bss_dscr = OAL_PTR_NULL;
    /* ?????? */
    oal_spin_lock(&(pst_bss_mgmt->st_lock));

    /* ????????????????????bssid ??????bss ???? */
    oal_dlist_search_for_each(pst_entry, &(pst_bss_mgmt->st_bss_list_head))
    {
        pst_scanned_bss = oal_dlist_get_entry(pst_entry, hmac_scanned_bss_info, st_dlist_head);
        pst_bss_dscr = &(pst_scanned_bss->st_bss_dscr_info);

        /* ??????????????????????MAC ?????????????????????????? */
        if (oal_memcmp(puc_bssid, pst_bss_dscr->auc_bssid, WLAN_MAC_ADDR_LEN) == 0) {
            break;
        }
        pst_bss_dscr = OAL_PTR_NULL;
    }

    /* ?????? */
    oal_spin_unlock(&(pst_bss_mgmt->st_lock));

    if (pst_bss_dscr == OAL_PTR_NULL) {
        oam_warning_log4(0, OAM_SF_ASSOC, "{wal_update_bss::do not find correspond bss from scan result.\
                         %02X:XX:XX:%02X:%02X:%02X}",
                         /* puc_bssid??3??4??5byte???????????????? */
                         puc_bssid[0], puc_bssid[3], puc_bssid[4], puc_bssid[5]);
        return;
    }

    /* ????????????????????????????bss  ????????bss ??????????bss ???? */
    pst_cfg80211_bss = oal_cfg80211_get_bss(pst_wiphy,
                                            OAL_PTR_NULL,
                                            puc_bssid,
                                            (oal_uint8 *)(pst_bss_dscr->ac_ssid),
                                            OAL_STRLEN(pst_bss_dscr->ac_ssid));
    if (pst_cfg80211_bss != OAL_PTR_NULL) {
        l_channel = (oal_int32)oal_ieee80211_frequency_to_channel((oal_int32)pst_cfg80211_bss->channel->center_freq);
        /* ????????????????????????????????????????????????????????bss info????????????????????bss?????????????????????????????????????????? */
        if (pst_bss_dscr->st_channel.uc_chan_number != l_channel) {
            oam_warning_log2(0, OAM_SF_ASSOC,
                             "{wal_update_bss::Current kernel bss channel[%d] need to update to channel[%d].}",
                             l_channel, pst_bss_dscr->st_channel.uc_chan_number);
            oal_cfg80211_unlink_bss(pst_wiphy, pst_cfg80211_bss);
        } else {
            oal_cfg80211_put_bss(pst_wiphy, pst_cfg80211_bss);
            en_inform_bss = OAL_FALSE;
        }
    }

    if (en_inform_bss == OAL_TRUE) {
        uc_chan_number = pst_bss_dscr->st_channel.uc_chan_number;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0))
        en_band = (enum nl80211_band)pst_bss_dscr->st_channel.en_band;
#else
        en_band = (enum ieee80211_band)pst_bss_dscr->st_channel.en_band;
#endif

        /* ?????? */
        memset_s(&st_scanned_bss_info, OAL_SIZEOF(wal_scanned_bss_info_stru),
                 0, OAL_SIZEOF(wal_scanned_bss_info_stru));

        /* ????BSS ???????? */
        st_scanned_bss_info.l_signal = pst_bss_dscr->c_rssi;

        /* ??bss?????????????????? */
        st_scanned_bss_info.s_freq = (oal_int16)oal_ieee80211_channel_to_frequency(uc_chan_number, en_band);

        /* ?????????????????? */
        st_scanned_bss_info.pst_mgmt = (oal_ieee80211_mgmt_stru *)(pst_bss_dscr->auc_mgmt_buff);
        st_scanned_bss_info.ul_mgmt_len = pst_bss_dscr->ul_mgmt_len;

        /* ???????????????????????????????? */
        pst_frame_hdr = (mac_ieee80211_frame_stru *)pst_bss_dscr->auc_mgmt_buff;

        /* ????????????????????????????beacon????????????????probe rsp??????????
           ??????????????????????????beacon????????????????????????????01?????? */
        if (pst_frame_hdr->st_frame_control.bit_sub_type == WLAN_BEACON) {
            /* ????beacon????????probe rsp */
            pst_frame_hdr->st_frame_control.bit_sub_type = WLAN_PROBE_RSP;
        }

        wal_inform_bss_frame(&st_scanned_bss_info, pst_wiphy);
    }

    return;
}


OAL_STATIC oal_void wal_inform_all_bss_init(wal_scanned_bss_info_stru *pst_scanned_bss_info,
                                            mac_bss_dscr_stru *pst_bss_dscr)
{
    oal_uint8 uc_chan_number;
    mac_ieee80211_frame_stru *pst_frame_hdr = OAL_PTR_NULL;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0))
    enum nl80211_band en_band;
#else
    enum ieee80211_band en_band;
#endif

    uc_chan_number = pst_bss_dscr->st_channel.uc_chan_number;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0))
    en_band = (enum nl80211_band)pst_bss_dscr->st_channel.en_band;
#else
    en_band = (enum ieee80211_band)pst_bss_dscr->st_channel.en_band;
#endif

    pst_scanned_bss_info->l_signal = pst_bss_dscr->c_rssi;
    /* ??bss?????????????????? */
    pst_scanned_bss_info->s_freq = (oal_int16)oal_ieee80211_channel_to_frequency(uc_chan_number, en_band);
    /* ?????????????????? */
    pst_scanned_bss_info->pst_mgmt = (oal_ieee80211_mgmt_stru *)(pst_bss_dscr->auc_mgmt_buff);
    pst_scanned_bss_info->ul_mgmt_len = pst_bss_dscr->ul_mgmt_len;
    /* ???????????????????????????????? */
    pst_frame_hdr = (mac_ieee80211_frame_stru *)pst_bss_dscr->auc_mgmt_buff;

    /* ????????????????????????????beacon????????????????probe rsp??????????
       ??????????????????????????beacon????????????????????????????01?????? */
    if (pst_frame_hdr->st_frame_control.bit_sub_type == WLAN_BEACON) {
        /* ????beacon????????probe rsp */
        pst_frame_hdr->st_frame_control.bit_sub_type = WLAN_PROBE_RSP;
    }
}


oal_void wal_inform_all_bss(oal_wiphy_stru *pst_wiphy, hmac_bss_mgmt_stru *pst_bss_mgmt, oal_uint8 uc_vap_id)
{
    mac_bss_dscr_stru *pst_bss_dscr = OAL_PTR_NULL;
    hmac_scanned_bss_info *pst_scanned_bss = OAL_PTR_NULL;
    oal_dlist_head_stru *pst_entry = OAL_PTR_NULL;
    wal_scanned_bss_info_stru st_scanned_bss_info;
    oal_uint32 ul_ret;
    oal_uint32 ul_bss_num_not_in_regdomain = 0;
    oal_uint32 ul_bss_num = 0;
    oal_uint8 uc_chan_number;
    oal_uint8 *puc_payload = OAL_PTR_NULL;
    oal_uint8 *puc_wfd_ie = OAL_PTR_NULL;
    oal_uint16 us_offset = MAC_80211_FRAME_LEN + MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0))
    enum nl80211_band en_band;
#else
    enum ieee80211_band en_band;
#endif

#if defined(_PRE_WLAN_FEATURE_11K) || defined(_PRE_WLAN_FEATURE_11R)
    hmac_vap_stru *pst_hmac_vap;
    oal_uint8 uc_voe_11r_auth;
    /* ????hmac vap */
    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(uc_vap_id);
    if (pst_hmac_vap == OAL_PTR_NULL) {
        oam_warning_log0(uc_vap_id, OAM_SF_SCAN, "{wal_inform_all_bss::hmac_vap is null, vap_id[%d]!}");
        return;
    }

    uc_voe_11r_auth = pst_hmac_vap->bit_voe_11r_auth;
    if (uc_voe_11r_auth == 1) {
        OAM_WARNING_LOG1(uc_vap_id, OAM_SF_SCAN, "{wal_inform_all_bss::uc_11r_auth=[%d]!}", uc_voe_11r_auth);
    }
#endif

    /* ?????? */
    oal_spin_lock(&(pst_bss_mgmt->st_lock));

    /* ????????????bss???? */
    oal_dlist_search_for_each(pst_entry, &(pst_bss_mgmt->st_bss_list_head))
    {
        pst_scanned_bss = oal_dlist_get_entry(pst_entry, hmac_scanned_bss_info, st_dlist_head);
        if (pst_scanned_bss == OAL_PTR_NULL) {
            OAM_ERROR_LOG0(uc_vap_id, OAM_SF_SCAN, "{wal_inform_all_bss::pst_scanned_bss is null. }");
            continue;
        }

        pst_bss_dscr = &(pst_scanned_bss->st_bss_dscr_info);

        uc_chan_number = pst_bss_dscr->st_channel.uc_chan_number;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0))
        en_band = (enum nl80211_band)pst_bss_dscr->st_channel.en_band;
#else
        en_band = (enum ieee80211_band)pst_bss_dscr->st_channel.en_band;
#endif

        /* ???????????????????????????????????????????????? */
        ul_ret = mac_is_channel_num_valid(en_band, uc_chan_number);
        if (ul_ret != OAL_SUCC) {
            oam_warning_log2(uc_vap_id, OAM_SF_SCAN,
                             "{wal_inform_all_bss::curr channel[%d]band[%d]not in regdomain}", uc_chan_number, en_band);
            ul_bss_num_not_in_regdomain++;
            continue;
        }

#if defined(_PRE_WLAN_FEATURE_11K) || defined(_PRE_WLAN_FEATURE_11R)
        if (uc_voe_11r_auth == 0)
#endif
        {   /* voe 11r ???????????????????? */
            /* ????WAL_SCAN_REPORT_LIMIT?????????????? */
            if (oal_time_after32(oal_time_get_stamp_ms(), (pst_bss_dscr->ul_timestamp + WAL_SCAN_REPORT_LIMIT))) {
                continue;
            }
        }

        if (pst_bss_dscr->ul_mgmt_len < us_offset) {
            continue;
        }
        /*lint -e416*/
        puc_payload = (oal_uint8 *)(pst_bss_dscr->auc_mgmt_buff + us_offset);
        /*lint +e416*/
        puc_wfd_ie = mac_find_vendor_ie(MAC_WLAN_OUI_WFA, MAC_WLAN_OUI_TYPE_WFA_WFD,
                                        puc_payload, (pst_bss_dscr->ul_mgmt_len - us_offset));
        if ((puc_wfd_ie != OAL_PTR_NULL) && (puc_wfd_ie[1] > MAC_P2P_MIN_IE_LEN) &&
            (pst_bss_dscr->en_new_scan_bss == OAL_FALSE)) {
            oam_warning_log2(uc_vap_id, OAM_SF_SCAN,
                             "wal_inform_all_bss::[%02X:%02X] include WFD ie, is an old scan result",
                             /* puc_bssid??4??5byte???????????????? */
                             pst_bss_dscr->auc_bssid[4], pst_bss_dscr->auc_bssid[5]);
            continue;
        }

        /* ?????? */
        memset_s(&st_scanned_bss_info, OAL_SIZEOF(wal_scanned_bss_info_stru),
                 0, OAL_SIZEOF(wal_scanned_bss_info_stru));

        wal_inform_all_bss_init(&st_scanned_bss_info, pst_bss_dscr);

        /* ?????????????????? */
        wal_inform_bss_frame(&st_scanned_bss_info, pst_wiphy);
        ul_bss_num++;
    }

    /* ?????? */
    oal_spin_unlock(&(pst_bss_mgmt->st_lock));

    oam_warning_log3(uc_vap_id, OAM_SF_SCAN,
                     "{wal_inform_all_bss::there are %d bss not in regdomain,so inform kernal bss num [%d] in [%d]!}",
                     ul_bss_num_not_in_regdomain, ul_bss_num, (pst_bss_mgmt->ul_bss_num - ul_bss_num_not_in_regdomain));

    return;
}


OAL_STATIC oal_void free_scan_param_resource(mac_cfg80211_scan_param_stru *pst_scan_param)
{
    if (pst_scan_param->pul_channels_2G != OAL_PTR_NULL) {
        oal_free(pst_scan_param->pul_channels_2G);
        pst_scan_param->pul_channels_2G = OAL_PTR_NULL;
    }
    if (pst_scan_param->pul_channels_5G != OAL_PTR_NULL) {
        oal_free(pst_scan_param->pul_channels_5G);
        pst_scan_param->pul_channels_5G = OAL_PTR_NULL;
    }

    if (pst_scan_param->puc_ie != OAL_PTR_NULL) {
        oal_free(pst_scan_param->puc_ie);
        pst_scan_param->puc_ie = OAL_PTR_NULL;
    }
}


OAL_STATIC oal_uint32 wal_set_scan_channel(oal_cfg80211_scan_request_stru *pst_request,
                                           mac_cfg80211_scan_param_stru *pst_scan_param)
{
    oal_uint32 ul_loop;
    oal_uint32 ul_num_chan_2g;
    oal_uint32 ul_num_chan_5g;

    if ((pst_request == OAL_PTR_NULL) || (pst_scan_param == OAL_PTR_NULL)) {
        oam_error_log2(0, OAM_SF_ANY,
                       "{wal_get_scan_channel_num::pst_request[%p] null ptr or pst_scan_param[%p] null ptr.}",
                       (uintptr_t)pst_request, (uintptr_t)pst_scan_param);
        return OAL_ERR_CODE_PTR_NULL;
    }

    if (pst_request->n_channels == 0) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_get_scan_channel_num::channels in scan requst is zero.}");
        return OAL_FAIL;
    }

    pst_scan_param->pul_channels_2G = oal_memalloc(pst_request->n_channels * OAL_SIZEOF(oal_uint32));
    if (oal_unlikely(pst_scan_param->pul_channels_2G == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_scan_work_func::2.4G channel alloc mem return null ptr!}");
        return OAL_ERR_CODE_ALLOC_MEM_FAIL;
    }

    pst_scan_param->pul_channels_5G = oal_memalloc(pst_request->n_channels * OAL_SIZEOF(oal_uint32));
    if (oal_unlikely(pst_scan_param->pul_channels_5G == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_scan_work_func::5G channel alloc mem return null ptr!}");
        free_scan_param_resource(pst_scan_param);
        return OAL_ERR_CODE_ALLOC_MEM_FAIL;
    }

    ul_num_chan_2g = 0;
    ul_num_chan_5g = 0;

    for (ul_loop = 0; ul_loop < pst_request->n_channels; ul_loop++) {
        oal_uint16 us_center_freq;
        oal_uint32 ul_chan;

        us_center_freq = pst_request->channels[ul_loop]->center_freq;

        /* ???????????????????????? */
        ul_chan = (oal_uint32)oal_ieee80211_frequency_to_channel((oal_int32)us_center_freq);

        if (us_center_freq <= WAL_MAX_FREQ_2G) {
            pst_scan_param->pul_channels_2G[ul_num_chan_2g++] = ul_chan;
        } else {
            pst_scan_param->pul_channels_5G[ul_num_chan_5g++] = ul_chan;
        }
    }

    pst_scan_param->uc_num_channels_2G = (oal_uint8)ul_num_chan_2g;
    pst_scan_param->uc_num_channels_5G = (oal_uint8)ul_num_chan_5g;

    if (ul_num_chan_2g == 0) {
        oal_free(pst_scan_param->pul_channels_2G);
        pst_scan_param->pul_channels_2G = OAL_PTR_NULL;
    }
    if (ul_num_chan_5g == 0) {
        oal_free(pst_scan_param->pul_channels_5G);
        pst_scan_param->pul_channels_5G = OAL_PTR_NULL;
    }

    return OAL_SUCC;
}


OAL_STATIC oal_void wal_set_scan_ssid(oal_cfg80211_scan_request_stru *pst_request,
                                      mac_cfg80211_scan_param_stru *pst_scan_param)
{
    oal_int32 l_loop;
    oal_int32 l_ssid_num;

    if ((pst_request == OAL_PTR_NULL) || (pst_scan_param == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_set_scan_ssid::scan failed, null ptr.}");

        return;
    }

    pst_scan_param->en_scan_type = OAL_ACTIVE_SCAN; /* active scan */
    pst_scan_param->l_ssid_num = 0;

    /* ????????????ssid?????? */
    l_ssid_num = pst_request->n_ssids;
    if (l_ssid_num > WLAN_SCAN_REQ_MAX_SSID) {
        /* ??????????????????ssid????????????????????????????????????????????????ssid?????????? */
        l_ssid_num = WLAN_SCAN_REQ_MAX_SSID;
    }

    /* ????????????ssid???????????????????????? */
    if ((l_ssid_num > 0) && (pst_request->ssids != OAL_PTR_NULL)) {
        pst_scan_param->l_ssid_num = l_ssid_num;

        for (l_loop = 0; l_loop < l_ssid_num; l_loop++) {
            pst_scan_param->st_ssids[l_loop].uc_ssid_len = pst_request->ssids[l_loop].ssid_len;
            if (pst_scan_param->st_ssids[l_loop].uc_ssid_len > OAL_IEEE80211_MAX_SSID_LEN) {
                oam_warning_log2(0, OAM_SF_ANY, "{wal_set_scan_ssid::ssid set failed,ssid_len[%d]is exceed max[%d]}",
                                 pst_scan_param->st_ssids[l_loop].uc_ssid_len, OAL_IEEE80211_MAX_SSID_LEN);

                pst_scan_param->st_ssids[l_loop].uc_ssid_len = OAL_IEEE80211_MAX_SSID_LEN;
            }
            if (memcpy_s(pst_scan_param->st_ssids[l_loop].auc_ssid, OAL_IEEE80211_MAX_SSID_LEN,
                         pst_request->ssids[l_loop].ssid, pst_scan_param->st_ssids[l_loop].uc_ssid_len) != EOK) {
                OAM_ERROR_LOG0(0, OAM_SF_ANY, "wal_set_scan_ssid::memcpy fail!");
            }
        }
    }
}


OAL_STATIC oal_uint32 wal_wait_for_scan_timeout_fn(void *p_arg)
{
    hmac_vap_stru *pst_hmac_vap = (hmac_vap_stru *)p_arg;
    mac_vap_stru *pst_mac_vap = &(pst_hmac_vap->st_vap_base_info);
    hmac_device_stru *pst_hmac_device = OAL_PTR_NULL;
    hmac_bss_mgmt_stru *pst_bss_mgmt = OAL_PTR_NULL;
    hmac_scan_stru *pst_scan_mgmt = OAL_PTR_NULL;
    oal_wiphy_stru *pst_wiphy = OAL_PTR_NULL;

    oam_warning_log0(pst_mac_vap->uc_vap_id, OAM_SF_SCAN,
                     "{wal_wait_for_scan_timeout_fn:: 5 seconds scan timeout proc.}");

    /* ????????????????????????vap????????????????vap?????????????????????????????????????????????????? */
    if ((pst_mac_vap->en_vap_mode == WLAN_VAP_MODE_BSS_STA) &&
        (pst_mac_vap->en_vap_state == MAC_VAP_STATE_STA_WAIT_SCAN)) {
        /* ????vap??????SCAN_COMP */
        mac_vap_state_change(pst_mac_vap, MAC_VAP_STATE_STA_SCAN_COMP);
    }

    /* ????hmac device */
    pst_hmac_device = hmac_res_get_mac_dev(pst_mac_vap->uc_device_id);
    if (pst_hmac_device == OAL_PTR_NULL) {
        OAM_WARNING_LOG1(0, OAM_SF_SCAN, "{wal_wait_for_scan_complete_time_out::pst_hmac_device[%d] is null.}",
                         pst_mac_vap->uc_device_id);
        return OAL_FAIL;
    }

    pst_scan_mgmt = &(pst_hmac_device->st_scan_mgmt);
    pst_wiphy = pst_hmac_device->pst_device_base_info->pst_wiphy;

    /* ?????????????????????????? */
    pst_bss_mgmt = &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt.st_bss_mgmt);

    /* ??????????????????request???????? */
    oal_spin_lock(&(pst_scan_mgmt->st_scan_request_spinlock));

    if (pst_scan_mgmt->pst_request != OAL_PTR_NULL) {
        /* ??????????????????bss */
        wal_inform_all_bss(pst_wiphy, pst_bss_mgmt, pst_mac_vap->uc_vap_id);

        /* ???? kernel scan ???????? */
        oal_cfg80211_scan_done(pst_scan_mgmt->pst_request, 0);

        pst_scan_mgmt->pst_request = OAL_PTR_NULL;
        pst_scan_mgmt->en_complete = OAL_TRUE;

        /* ??????????????????OAL_WAIT_QUEUE_WAKE_UP?????????? */
        oal_smp_mb();
        oal_wait_queue_wake_up_interrupt(&pst_scan_mgmt->st_wait_queue);
    }

    /* ?????????????????????????? */
    oal_spin_unlock(&(pst_scan_mgmt->st_scan_request_spinlock));

    return OAL_SUCC;
}


OAL_STATIC oal_void wal_start_timer_for_scan_timeout(oal_uint8 uc_vap_id)
{
    hmac_vap_stru *pst_hmac_vap = OAL_PTR_NULL;
    mac_device_stru *pst_mac_device = OAL_PTR_NULL;
    oal_uint32 ul_timeout;

    /* ??????????5?? */
    ul_timeout = WAL_MAX_SCAN_TIME_PER_SCAN_REQ;

    /* ????hmac vap */
    pst_hmac_vap = mac_res_get_hmac_vap(uc_vap_id);
    if (pst_hmac_vap == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(uc_vap_id, OAM_SF_SCAN, "{wal_start_timer_for_scan_timeout::pst_hmac_vap is null!}");
        return;
    }

    /* ????mac device */
    pst_mac_device = mac_res_get_dev(pst_hmac_vap->st_vap_base_info.uc_device_id);
    if (pst_mac_device == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(uc_vap_id, OAM_SF_SCAN, "{wal_start_timer_for_scan_timeout::pst_mac_device is null!}");
        return;
    }

    /* ???????????????????????????????????????????????????????????????? */
    frw_create_timer(&(pst_hmac_vap->st_scan_timeout),
                     wal_wait_for_scan_timeout_fn,
                     ul_timeout,
                     pst_hmac_vap,
                     OAL_FALSE,
                     OAM_MODULE_ID_WAL,
                     pst_mac_device->ul_core_id);

    return;
}


oal_uint32 wal_scan_work_func(hmac_scan_stru *pst_scan_mgmt,
                              oal_net_device_stru *pst_netdev,
                              oal_cfg80211_scan_request_stru *pst_request)
{
    mac_cfg80211_scan_param_stru st_scan_param;
    oal_uint32 ul_ret;
    mac_vap_stru *pst_mac_vap = oal_net_dev_priv(pst_netdev);
    oal_uint8 uc_vap_id;
    oal_uint8 *puc_ie = OAL_PTR_NULL;

    if (pst_mac_vap == NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_scan_work_func::pst_mac_vap is null!}");
        return OAL_FAIL;
    }

    uc_vap_id = pst_mac_vap->uc_vap_id;

    memset_s(&st_scan_param, OAL_SIZEOF(mac_cfg80211_scan_param_stru), 0, OAL_SIZEOF(mac_cfg80211_scan_param_stru));

    /* ?????????????????????????? */
    ul_ret = wal_set_scan_channel(pst_request, &st_scan_param);
    if (ul_ret != OAL_SUCC) {
        OAM_ERROR_LOG1(0, OAM_SF_CFG, "{wal_scan_work_func::wal_set_scan_channel proc failed, err_code[%d]!}", ul_ret);
        return OAL_FAIL;
    }

    /* ??????????????ssid */
    wal_set_scan_ssid(pst_request, &st_scan_param);

    /* ??????????????ie */
    st_scan_param.ul_ie_len = pst_request->ie_len;
    if (st_scan_param.ul_ie_len > 0) {
        puc_ie = (oal_uint8 *)oal_memalloc(pst_request->ie_len);
        if (puc_ie == OAL_PTR_NULL) {
            OAM_ERROR_LOG1(0, OAM_SF_CFG, "{wal_scan_work_func::alloc mem puc_ie(%d)return null ptr!}",
                           pst_request->ie_len);
            free_scan_param_resource(&st_scan_param);
            return OAL_ERR_CODE_ALLOC_MEM_FAIL;
        }
        st_scan_param.puc_ie = puc_ie;
        if (memcpy_s(puc_ie, pst_request->ie_len, pst_request->ie, st_scan_param.ul_ie_len) != EOK) {
            OAM_ERROR_LOG0(0, OAM_SF_CFG, "wal_scan_work_func::memcpy fail!");
            free_scan_param_resource(&st_scan_param);
            return OAL_FAIL;
        }
    }

    /* P2P WLAN/P2P ??????????????????????ssid ??????????p2p device ????????????
        ssid ??"DIRECT-"????????p2p device ?????????? */
    /* ??????????????device ??????p2p device(p2p0) */
    st_scan_param.bit_is_p2p0_scan = OAL_FALSE;

    if (is_p2p_scan_req(pst_request)) {
        st_scan_param.bit_is_p2p0_scan = OAL_TRUE;
    }

    /* ??????????????????????????????,???????????? */
    pst_scan_mgmt->en_complete = OAL_FALSE;

    /* ???????????????????????? */
    ul_ret = wal_cfg80211_start_scan(pst_netdev, &st_scan_param);
    if (ul_ret != OAL_SUCC) {
        OAM_ERROR_LOG1(0, OAM_SF_CFG, "{wal_scan_work_func::wal_cfg80211_start_scan proc failed,err_code[%d]}", ul_ret);
        /* ??????????????hmac???? */
        free_scan_param_resource(&st_scan_param);

        pst_scan_mgmt->en_complete = OAL_TRUE;
        return OAL_FAIL;
    }

    /* win32 UT?????????????????????? */
#if (_PRE_OS_VERSION_WIN32 == _PRE_OS_VERSION) && (_PRE_TEST_MODE == _PRE_TEST_MODE_UT)
    frw_event_process_all_event(0);
#endif

    /* ???????????????????????????? */
    wal_start_timer_for_scan_timeout(uc_vap_id);

    return OAL_SUCC;
}


oal_int32 wal_send_scan_abort_msg(oal_net_device_stru *pst_net_dev)
{
    wal_msg_write_stru st_write_msg;
    oal_uint32 ul_pedding_data = 0; /* ?????????????????????????????????? */
    oal_int32 l_ret;
    wal_msg_stru *pst_rsp_msg = OAL_PTR_NULL;

    /* ??????????device?????????? */
    wal_write_msg_hdr_init(&st_write_msg, WLAN_CFGID_SCAN_ABORT, OAL_SIZEOF(ul_pedding_data));

    if (memcpy_s(st_write_msg.auc_value, OAL_SIZEOF(ul_pedding_data),
                 (oal_int8 *)&ul_pedding_data, OAL_SIZEOF(ul_pedding_data)) != EOK) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "wal_send_scan_abort_msg::memcpy fail!");
        return -OAL_EINVAL;
    }

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(ul_pedding_data),
                               (oal_uint8 *)&st_write_msg,
                               OAL_TRUE,
                               &pst_rsp_msg);
    if (l_ret != OAL_SUCC) {
        OAM_WARNING_LOG1(0, OAM_SF_SCAN, "{wal_send_scan_abort_msg::fail to stop scan, error[%d]}", l_ret);
        return l_ret;
    }

    if (wal_check_and_release_msg_resp(pst_rsp_msg) != OAL_SUCC) {
        oam_warning_log0(0, OAM_SF_SCAN, "{wal_send_scan_abort_msg::wal_check_and_release_msg_resp fail.}");
    }

    return OAL_SUCC;
}


oal_int32 wal_force_scan_complete(oal_net_device_stru *pst_net_dev,
                                  oal_bool_enum en_is_aborted)
{
    mac_vap_stru *pst_mac_vap;
    hmac_vap_stru *pst_hmac_vap = OAL_PTR_NULL;
    hmac_device_stru *pst_hmac_device = OAL_PTR_NULL;
    hmac_scan_stru *pst_scan_mgmt = OAL_PTR_NULL;

    pst_mac_vap = oal_net_dev_priv(pst_net_dev);
    if (pst_mac_vap == OAL_PTR_NULL) {
        oam_warning_log0(0, OAM_SF_SCAN, "{wal_force_scan_complete::Cannot find mac_vap by net_dev!}");
        return -OAL_EINVAL;
    }

    /* ????hmac device */
    pst_hmac_device = hmac_res_get_mac_dev(pst_mac_vap->uc_device_id);
    if (pst_hmac_device == OAL_PTR_NULL) {
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_SCAN,
                         "{wal_force_scan_complete::pst_hmac_device[%d] is null!}",
                         pst_mac_vap->uc_device_id);
        return -OAL_EINVAL;
    }

    pst_scan_mgmt = &(pst_hmac_device->st_scan_mgmt);

    /* ???????????????????? */
    if (pst_scan_mgmt->pst_request == OAL_PTR_NULL) {
        /* ?????????????????????????????????????????? */
        if ((pst_hmac_device->st_scan_mgmt.en_is_scanning == OAL_TRUE) &&
            (pst_mac_vap->uc_vap_id == pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt.uc_vap_id)) {
            oam_warning_log0(pst_mac_vap->uc_vap_id, OAM_SF_SCAN,
                             "{wal_force_scan_complete::may be internal scan, stop scan!}");
            /* ???????? */
            wal_send_scan_abort_msg(pst_net_dev);
        }

        return OAL_SUCC;
    }

    /* ????hmac vap */
    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (pst_hmac_vap == OAL_PTR_NULL) {
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_SCAN,
                         "{wal_force_scan_complete::hmac_vap is null, vap_id[%d]!}", pst_mac_vap->uc_vap_id);
        return -OAL_EINVAL;
    }

    /* ??????????????????request???????? */
    oal_spin_lock(&(pst_scan_mgmt->st_scan_request_spinlock));

    /* ?????????????????????????????????????????????????????????????? */
    if ((pst_scan_mgmt->pst_request != OAL_PTR_NULL)
        && (pst_net_dev->ieee80211_ptr == pst_scan_mgmt->pst_request->wdev)) {
        /* ?????????????????????? */
        if (pst_hmac_vap->st_scan_timeout.en_is_registerd == OAL_TRUE) {
            frw_immediate_destroy_timer(&(pst_hmac_vap->st_scan_timeout));
        }

        /* ???????????????? */
        wal_inform_all_bss(pst_hmac_device->pst_device_base_info->pst_wiphy,
                           &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt.st_bss_mgmt),
                           pst_mac_vap->uc_vap_id);

        /* ???????????????? */
        oal_cfg80211_scan_done(pst_scan_mgmt->pst_request, en_is_aborted);

        pst_scan_mgmt->pst_request = OAL_PTR_NULL;
        pst_scan_mgmt->en_complete = OAL_TRUE;
        /* ?????????????????????????? */
        oal_spin_unlock(&(pst_scan_mgmt->st_scan_request_spinlock));
        /* ????device???????? */
        wal_send_scan_abort_msg(pst_net_dev);

        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_SCAN,
                         "{wal_force_scan_complete::vap_id[%d] notify kernel scan abort!}",
                         pst_mac_vap->uc_vap_id);

        /* ??????????????????OAL_WAIT_QUEUE_WAKE_UP?????????? */
        oal_smp_mb();
        oal_wait_queue_wake_up_interrupt(&pst_scan_mgmt->st_wait_queue);
    } else {
        /* ?????????????????????????? */
        oal_spin_unlock(&(pst_scan_mgmt->st_scan_request_spinlock));
    }

    return OAL_SUCC;
}


oal_int32 wal_force_scan_complete_for_disconnect_scene(oal_net_device_stru *pst_net_dev)
{
    mac_vap_stru *pst_mac_vap;
    hmac_vap_stru *pst_hmac_vap = OAL_PTR_NULL;
    hmac_device_stru *pst_hmac_device = OAL_PTR_NULL;
    hmac_scan_stru *pst_scan_mgmt = OAL_PTR_NULL;

    pst_mac_vap = oal_net_dev_priv(pst_net_dev);
    if (pst_mac_vap == OAL_PTR_NULL) {
        OAM_WARNING_LOG1(0, OAM_SF_SCAN,
                         "{wal_force_scan_complete_for_disconnect_scene:: mac_vap of net_dev is deleted!iftype:[%d]}",
                         pst_net_dev->ieee80211_ptr->iftype);
        return OAL_SUCC;
    }

    /* ????hmac device */
    pst_hmac_device = hmac_res_get_mac_dev(pst_mac_vap->uc_device_id);
    if (pst_hmac_device == OAL_PTR_NULL) {
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_SCAN,
                         "{wal_force_scan_complete_for_disconnect_scene::pst_hmac_device[%d] is null!}",
                         pst_mac_vap->uc_device_id);
        return -OAL_EINVAL;
    }

    /* ????hmac vap */
    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (pst_hmac_vap == OAL_PTR_NULL) {
        oam_warning_log0(pst_mac_vap->uc_vap_id, OAM_SF_SCAN,
                         "{wal_force_scan_complete_for_disconnect_scene::hmac_vap is null!}");
        return -OAL_EINVAL;
    }

    pst_scan_mgmt = &(pst_hmac_device->st_scan_mgmt);

    /* ???????????????????? */
    if (pst_scan_mgmt->pst_request == OAL_PTR_NULL) {
        /* ?????????????????????????????????????????? */
        if ((pst_scan_mgmt->en_is_scanning == OAL_TRUE) &&
            (pst_mac_vap->uc_vap_id == pst_scan_mgmt->st_scan_record_mgmt.uc_vap_id)) {
            oam_warning_log0(pst_mac_vap->uc_vap_id, OAM_SF_SCAN,
                             "{wal_force_scan_complete_for_disconnect_scene::may be internal scan, stop scan!}");
            /* ???????? */
            wal_send_scan_abort_msg(pst_net_dev);
        }

        return OAL_SUCC;
    }

    if ((pst_scan_mgmt->pst_request != OAL_PTR_NULL) &&
        (pst_net_dev->ieee80211_ptr == pst_scan_mgmt->pst_request->wdev)) {
        /* ????device???????? */
        wal_send_scan_abort_msg(pst_net_dev);
        pst_scan_mgmt->st_scan_record_mgmt.en_scan_rsp_status = MAC_SCAN_ABORT_SYNC;
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_SCAN,
                         "{wal_force_scan_complete_for_disconnect_scene::notify kernel scan abort,scan_rsp_status[%d]}",
                         pst_scan_mgmt->st_scan_record_mgmt.en_scan_rsp_status);
    }

    return OAL_SUCC;
}


oal_int32 wal_stop_sched_scan(oal_net_device_stru *pst_netdev)
{
    hmac_device_stru *pst_hmac_device = OAL_PTR_NULL;
    hmac_scan_stru *pst_scan_mgmt = OAL_PTR_NULL;
    mac_vap_stru *pst_mac_vap = OAL_PTR_NULL;
    wal_msg_write_stru st_write_msg;
    oal_uint32 ul_pedding_data = 0; /* ?????????????????????????????????? */
    oal_int32 l_ret = 0;

    /* ?????????????? */
    if (pst_netdev == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_SCAN, "{wal_stop_sched_scan::pst_netdev is null}");
        return -OAL_EINVAL;
    }

    /* ????net_device ??????????mac_device_stru ???? */
    pst_mac_vap = oal_net_dev_priv(pst_netdev);
    if (pst_mac_vap == OAL_PTR_NULL) {
        oam_warning_log0(0, OAM_SF_SCAN, "{wal_stop_sched_scan:: pst_mac_vap is null!}");
        return -OAL_EINVAL;
    }

    pst_hmac_device = (hmac_device_stru *)hmac_res_get_mac_dev(pst_mac_vap->uc_device_id);
    if (pst_hmac_device == OAL_PTR_NULL) {
        OAM_ERROR_LOG1(0, OAM_SF_SCAN, "{wal_stop_sched_scan:: pst_mac_device[%d] is null!}",
                       pst_mac_vap->uc_device_id);
        return -OAL_EINVAL;
    }

    pst_scan_mgmt = &(pst_hmac_device->st_scan_mgmt);

    OAM_WARNING_LOG1(0, OAM_SF_SCAN,
                     "{wal_stop_sched_scan::sched scan complete[%d]}", pst_scan_mgmt->en_sched_scan_complete);

    if ((pst_scan_mgmt->pst_sched_scan_req != OAL_PTR_NULL) &&
        (pst_scan_mgmt->en_sched_scan_complete != OAL_TRUE)) {
        /* ?????????????????????????????????????????? */
        {
            oal_cfg80211_sched_scan_result(pst_hmac_device->pst_device_base_info->pst_wiphy);
        }

        pst_scan_mgmt->pst_sched_scan_req = OAL_PTR_NULL;
        pst_scan_mgmt->en_sched_scan_complete = OAL_TRUE;

        /* ??????????device??????PNO???????? */
        wal_write_msg_hdr_init(&st_write_msg, WLAN_CFGID_CFG80211_STOP_SCHED_SCAN, OAL_SIZEOF(ul_pedding_data));

        if (memcpy_s(st_write_msg.auc_value, OAL_SIZEOF(ul_pedding_data),
                     (oal_int8 *)&ul_pedding_data, OAL_SIZEOF(ul_pedding_data)) != EOK) {
            OAM_ERROR_LOG0(0, OAM_SF_SCAN, "wal_stop_sched_scan::memcpy fail!");
            return -OAL_EINVAL;
        }

        l_ret = wal_send_cfg_event(pst_netdev,
                                   WAL_MSG_TYPE_WRITE,
                                   WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(ul_pedding_data),
                                   (oal_uint8 *)&st_write_msg,
                                   OAL_FALSE,
                                   OAL_PTR_NULL);
        if (l_ret != OAL_SUCC) {
            OAM_WARNING_LOG1(0, OAM_SF_SCAN, "{wal_stop_sched_scan::fail to stop pno sched scan, error[%d]}", l_ret);
        }
    }

    return OAL_SUCC;
}

