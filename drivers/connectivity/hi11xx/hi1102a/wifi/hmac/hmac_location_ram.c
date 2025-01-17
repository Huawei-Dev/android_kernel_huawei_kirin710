

/* 1 ?????????? */
#include "hmac_location_ram.h"
#include "hmac_mgmt_sta.h"
#if defined(_PRE_WLAN_FEATURE_FTM) || defined(_PRE_WLAN_FEATURE_LOCATION_RAM)
#include "oal_kernel_file.h"
#endif

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HMAC_LOCATION_RAM_C

#ifdef _PRE_WLAN_FEATURE_LOCATION_RAM
oal_uint8 g_auc_send_csi_buf[HMAC_CSI_SEND_BUF_LEN] = { 0 };
oal_uint8 g_auc_send_ftm_buf[HMAC_FTM_SEND_BUF_LEN] = { 0 };
#endif

#ifdef _PRE_WLAN_FEATURE_LOCATION_RAM


oal_uint32 hmac_netlink_location_send(hmac_vap_stru *pst_hmac_vap, oal_netbuf_stru *pst_netbuf)
{
    mac_location_event_stru *pst_location_event;
    struct timeval st_tv;
    oal_time_stru st_local_time;
    oal_uint16 us_action_len;
    oal_uint8 *puc_payload;
    mac_rx_ctl_stru *pst_rx_ctrl;
    oal_uint32 ul_index = 0;
    oal_uint32 *pul_len = OAL_PTR_NULL;
    oal_uint8 *puc_send_csi_buf = g_auc_send_csi_buf;
    oal_uint8 *puc_send_ftm_buf = g_auc_send_ftm_buf;
    oal_int32 l_ret = EOK;

    pst_rx_ctrl = (mac_rx_ctl_stru *)oal_netbuf_cb(pst_netbuf);
    pst_location_event = (mac_location_event_stru *)((oal_uint8 *)pst_rx_ctrl->pul_mac_hdr_start_addr +
                                                     pst_rx_ctrl->uc_mac_header_len);
    us_action_len = pst_rx_ctrl->us_frame_len;

    if (us_action_len < MAC_CSI_LOCATION_INFO_LEN) {
        OAM_ERROR_LOG1(0, OAM_SF_FTM, "{hmac_netlink_location_send: unexpected len %d}", us_action_len);
        return OAL_ERR_CODE_MSG_LENGTH_ERR;
    }
    do_gettimeofday(&st_tv);
    oal_get_real_time(&st_local_time);

    switch (pst_location_event->uc_location_type) {
        case MAC_HISI_LOCATION_RSSI_IE:
            break;
        case MAC_HISI_LOCATION_CSI_IE:
            puc_payload = (oal_uint8 *)(pst_location_event->auc_payload);

            /* ?????? */
            if ((puc_payload[0] == 0) &&
                ((puc_payload[1] == 0) || (puc_payload[1] == 1))) {
                memset_s(puc_send_csi_buf, HMAC_CSI_SEND_BUF_LEN, 0, HMAC_CSI_SEND_BUF_LEN);

                /* Type 4Bytes */
                *(oal_uint32 *)&puc_send_csi_buf[ul_index] = (oal_uint32)2; /* 2??????types */
                ul_index += 4; /* ????Type 4Bytes */

                /* len 4Bytes */
                pul_len = (oal_uint32 *)&puc_send_csi_buf[ul_index];
                ul_index += 4;  /* ????len 4Bytes */

                /* mac1 6Bytes */
                l_ret += memcpy_s(&puc_send_csi_buf[ul_index], HMAC_CSI_SEND_BUF_LEN - ul_index,
                                  pst_location_event->auc_mac_server, WLAN_MAC_ADDR_LEN);
                ul_index += WLAN_MAC_ADDR_LEN;

                /* mac2 6Bytes */
                l_ret += memcpy_s(&puc_send_csi_buf[ul_index], HMAC_CSI_SEND_BUF_LEN - ul_index,
                                  pst_location_event->auc_mac_client, WLAN_MAC_ADDR_LEN);
                ul_index += WLAN_MAC_ADDR_LEN;

                /* timestamp23Bytes */
                ul_index += snprintf_s(puc_send_csi_buf + ul_index, HMAC_CSI_SEND_BUF_LEN - ul_index,
                    HMAC_FTM_SEND_BUF_LEN - ul_index - 1, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
                    st_local_time.tm_year + 1900, st_local_time.tm_mon + 1, st_local_time.tm_mday, /* ??????1900???? */
                    /* 1ms????1000us */
                    st_local_time.tm_hour, st_local_time.tm_min, st_local_time.tm_sec, st_tv.tv_usec / 1000);

                /* rssi snr */
                l_ret += memcpy_s(&puc_send_csi_buf[ul_index], HMAC_CSI_SEND_BUF_LEN - ul_index,
                                  puc_payload + 3, MAC_REPORT_RSSIINFO_SNR_LEN); /* puc_payload + 3????10byte??csi buf */

                *pul_len = ul_index + MAC_REPORT_RSSIINFO_SNR_LEN;
            }

            pul_len = (oal_uint32 *)&puc_send_csi_buf[4]; /* puc_send_csi_buf??4byte??pul_len */
            if (*pul_len + us_action_len - MAC_CSI_LOCATION_INFO_LEN > HMAC_CSI_SEND_BUF_LEN) {
                OAM_ERROR_LOG0(0, OAM_SF_FTM, "{hmac_netlink_location_send::puc_send_buf not enough.}");
                return OAL_FAIL;
            }

            l_ret += memcpy_s(&puc_send_csi_buf[*pul_len], HMAC_CSI_SEND_BUF_LEN - (*pul_len),
                              /* puc_payload??????3+10????????memcpy???????? */
                              puc_payload + 3 + MAC_REPORT_RSSIINFO_SNR_LEN, us_action_len - MAC_CSI_LOCATION_INFO_LEN);
            *pul_len += us_action_len - MAC_CSI_LOCATION_INFO_LEN;
            break;
        case MAC_HISI_LOCATION_FTM_IE:
            memset_s(puc_send_ftm_buf, HMAC_FTM_SEND_BUF_LEN, 0, HMAC_FTM_SEND_BUF_LEN);
            *(oal_uint32 *)&puc_send_ftm_buf[ul_index] = (oal_uint32)3; /* 3??????types */
            ul_index += 4; /* ????Type 4Bytes */
            *(oal_uint32 *)&puc_send_ftm_buf[ul_index] = 99; /* 99??????len */
            ul_index += 4;  /* ????len 4Bytes */
            l_ret += memcpy_s(&puc_send_ftm_buf[ul_index], HMAC_FTM_SEND_BUF_LEN - ul_index,
                              pst_location_event->auc_mac_server, WLAN_MAC_ADDR_LEN);
            ul_index += WLAN_MAC_ADDR_LEN;
            l_ret += memcpy_s(&puc_send_ftm_buf[ul_index], HMAC_FTM_SEND_BUF_LEN - ul_index,
                              pst_location_event->auc_mac_client, WLAN_MAC_ADDR_LEN);
            ul_index += WLAN_MAC_ADDR_LEN;
            ul_index += snprintf_s(puc_send_ftm_buf + ul_index, HMAC_FTM_SEND_BUF_LEN - ul_index,
                HMAC_FTM_SEND_BUF_LEN - ul_index - 1, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
                /* ??????????1900???? */
                st_local_time.tm_year + 1900, st_local_time.tm_mon + 1, st_local_time.tm_mday, st_local_time.tm_hour,
                st_local_time.tm_min, st_local_time.tm_sec, st_tv.tv_usec / 1000); /* 1ms????1000us */
            puc_payload = (oal_uint8 *)(pst_location_event->auc_payload);
            /* 56?????????? */
            l_ret += memcpy_s(&puc_send_ftm_buf[ul_index], HMAC_FTM_SEND_BUF_LEN - ul_index, puc_payload, 56);
            break;
        default:
            return OAL_SUCC;
    }
    if (l_ret != EOK) {
        OAM_ERROR_LOG1(0, OAM_SF_FTM, "hmac_netlink_location_send:memcpy fail, l_ret=%d", l_ret);
    }
    return OAL_SUCC;
}
oal_void hmac_check_location_type(mac_location_event_stru *pst_lca, oal_int32 *pl_str_len, oal_file *f_file)
{
    if ((pst_lca->uc_location_type == MAC_HISI_LOCATION_RSSI_IE) ||
        (pst_lca->uc_location_type == MAC_HISI_LOCATION_FTM_IE) ||
        /* ??????????auc_payload[2]??????1 */
        ((pst_lca->uc_location_type == MAC_HISI_LOCATION_CSI_IE) && ((pst_lca->auc_payload[2] == 1) &&
        ((pst_lca->auc_payload[1] == 0) || (pst_lca->auc_payload[1] == 2))))) { /* ????auc_payload[1]????0????????2 */
        *pl_str_len += oal_kernel_file_print(f_file, "\n");
    }
}

oal_uint32 hmac_proc_location_action(hmac_vap_stru *pst_hmac_vap, oal_netbuf_stru *pst_netbuf)
{
    mac_location_event_stru *pst_lca;
    struct timeval st_tv;
    oal_time_stru st_time;
    oal_uint8 auc_filename[128];
    oal_uint16 us_action_len;
    oal_uint16 us_delta_len;

    oal_int32 l_str_len;
    oal_file *f_file;
    oal_mm_segment_t old_fs;
    oal_uint8 *puc_payload;
    mac_rx_ctl_stru *pst_rx_ctrl;

    /* ???????????? */
    if (oal_unlikely((pst_hmac_vap == OAL_PTR_NULL) || (pst_netbuf == OAL_PTR_NULL))) {
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* Vendor Public Action Header| EID |Length |OUI | type | mac_s | mac_c | rssi */
    /* ??????????????????us 2017-11-03-23-50-12-xxxxxxxx */
    pst_rx_ctrl = (mac_rx_ctl_stru *)oal_netbuf_cb(pst_netbuf);
    pst_lca = (mac_location_event_stru *)((oal_uint8 *)pst_rx_ctrl->pul_mac_hdr_start_addr +
                                          pst_rx_ctrl->uc_mac_header_len);
    us_action_len = pst_rx_ctrl->us_frame_len;

    if (us_action_len < MAC_CSI_LOCATION_INFO_LEN) {
        return OAL_ERR_CODE_MSG_LENGTH_ERR;
    }
    do_gettimeofday(&st_tv);
    oal_get_real_time(&st_time);

    /* ????????????\data\log\location\wlan0\ */
    l_str_len = snprintf_s(auc_filename, OAL_SIZEOF(auc_filename), OAL_SIZEOF(auc_filename) - 1,
        "/data/log/location/%s/", pst_hmac_vap->auc_name);

    switch (pst_lca->uc_location_type) {
        case MAC_HISI_LOCATION_RSSI_IE:
            /* ?????????? MAC_ADDR_S_MAC_ADDR_C_RSSI */
            l_str_len += snprintf_s(auc_filename + l_str_len, OAL_SIZEOF(auc_filename) - l_str_len,
                OAL_SIZEOF(auc_filename) - l_str_len - 1, "RSSI.TXT");
            break;
        case MAC_HISI_LOCATION_CSI_IE:
            /* ?????????? MAC_ADDR_S_MAC_ADDR_C_CSI */
            l_str_len += snprintf_s(auc_filename + l_str_len, OAL_SIZEOF(auc_filename) - l_str_len,
                OAL_SIZEOF(auc_filename) - l_str_len - 1, "CSI.TXT");
            break;
        case MAC_HISI_LOCATION_FTM_IE:
            /* ?????????? MAC_ADDR_S_MAC_ADDR_C_FTM */
            l_str_len += snprintf_s(auc_filename + l_str_len, OAL_SIZEOF(auc_filename) - l_str_len,
                OAL_SIZEOF(auc_filename) - l_str_len - 1, "FTM.TXT");
            break;
        default:
            return OAL_SUCC;
    }

    f_file = oal_kernel_file_open(auc_filename, OAL_O_RDWR | OAL_O_CREAT | OAL_O_APPEND);
    if (IS_ERR_OR_NULL(f_file)) {
        OAM_ERROR_LOG1(0, OAM_SF_FTM, "{hmac_proc_location_action: ****************save file failed %d }", l_str_len);
        return OAL_ERR_CODE_OPEN_FILE_FAIL;
    }
    old_fs = oal_get_fs();

    /* ????CSI??????payload[0]??????????????????????payload[1]??????????????????????0????????????1??????????????
       payload[2]?????????????????????????? */
    if (pst_lca->uc_location_type == MAC_HISI_LOCATION_CSI_IE) {
        if ((pst_lca->auc_payload[0] == 0) && ((pst_lca->auc_payload[1] == 0) || (pst_lca->auc_payload[1] == 1))) {
            /* ??????????1900???? */
            oal_kernel_file_print(f_file, "%04d-%02d-%02d-", st_time.tm_year + 1900, st_time.tm_mon + 1,
                                  st_time.tm_mday);
            oal_kernel_file_print(f_file, "%02d-%02d-%02d-%08d : ", st_time.tm_hour, st_time.tm_min,
                                  st_time.tm_sec, st_tv.tv_usec);
            /* rssi snr */
            puc_payload = (oal_uint8 *)(pst_lca->auc_payload);
            l_str_len = 0;
            while (l_str_len < MAC_REPORT_RSSIINFO_SNR_LEN) {
                oal_kernel_file_print(f_file, "%02X ", *(puc_payload++));
                l_str_len++;
            }
        }
    } else {
        /* ??????????1900???? */
        oal_kernel_file_print(f_file, "%04d-%02d-%02d-", st_time.tm_year + 1900, st_time.tm_mon + 1, st_time.tm_mday);
        oal_kernel_file_print(f_file, "%02d-%02d-%02d-%08d : ", st_time.tm_hour, st_time.tm_min,
                              st_time.tm_sec, st_tv.tv_usec);
    }

    l_str_len = 0;

    puc_payload = (oal_uint8 *)(pst_lca->auc_payload);

    if (pst_lca->uc_location_type == MAC_HISI_LOCATION_CSI_IE) {
        us_delta_len = us_action_len - MAC_CSI_LOCATION_INFO_LEN;
        puc_payload += MAC_REPORT_RSSIINFO_SNR_LEN + 3; /* MAC????????????????????????snr????3 */
    } else {
        us_delta_len = us_action_len - MAC_FTM_LOCATION_INFO_LEN + MAC_REPORT_RSSIINFO_LEN;
    }

    while (l_str_len < us_delta_len) {
        oal_kernel_file_print(f_file, "%02X ", *(puc_payload++));
        l_str_len++;
    }

    /* ??????80M???? TBD */
    hmac_check_location_type(pst_lca, &l_str_len, f_file);
    oal_kernel_file_close(f_file);
    oal_set_fs(old_fs);

    return OAL_SUCC;
}

#ifdef _PRE_WLAN_FEATURE_LOCATION_RAM

oal_uint32 hmac_huawei_action_process(hmac_vap_stru *pst_hmac_vap, oal_netbuf_stru *pst_netbuf, oal_uint8 uc_type)
{
    /* ???????????? */
    if (oal_unlikely((pst_hmac_vap == OAL_PTR_NULL) || (pst_netbuf == OAL_PTR_NULL))) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{hmac_huawei_action_process: input pointer is null!}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    switch (uc_type) {
        case MAC_HISI_LOCATION_RSSI_IE:
        case MAC_HISI_LOCATION_CSI_IE:
        case MAC_HISI_LOCATION_FTM_IE:
            /* ????????????????????????????ie??????????hmac???????? */
            /* type | mac_s | mac_c   | csi or ftm or rssi */
            /* csi ???????????? */
            hmac_proc_location_action(pst_hmac_vap, pst_netbuf);
            hmac_netlink_location_send(pst_hmac_vap, pst_netbuf);
            break;
        default:
            break;
    }

    return OAL_SUCC;
}
#endif

oal_void hmac_sta_up_rx_action_nonuser(hmac_vap_stru *pst_hmac_vap, oal_netbuf_stru *pst_netbuf)
{
    dmac_rx_ctl_stru *pst_rx_ctrl;
    oal_uint8 *puc_data;
    mac_ieee80211_frame_stru *pst_frame_hdr; /* ????mac???????? */

    if (oal_unlikely((pst_hmac_vap == OAL_PTR_NULL) || (pst_netbuf == OAL_PTR_NULL))) {
        OAM_ERROR_LOG0(0, OAM_SF_FTM, "{hmac_sta_up_rx_action_nonuser::PTR null .}");
        return;
    }

    pst_rx_ctrl = (dmac_rx_ctl_stru *)oal_netbuf_cb(pst_netbuf);

    /* ???????????? */
    pst_frame_hdr = (mac_ieee80211_frame_stru *)pst_rx_ctrl->st_rx_info.pul_mac_hdr_start_addr;

    /* ???????????? */
    puc_data = (oal_uint8 *)pst_rx_ctrl->st_rx_info.pul_mac_hdr_start_addr + pst_rx_ctrl->st_rx_info.uc_mac_header_len;

    /* Category */
    switch (puc_data[MAC_ACTION_OFFSET_CATEGORY]) {
        case MAC_ACTION_CATEGORY_PUBLIC: {
            /* Action */
            switch (puc_data[MAC_ACTION_OFFSET_ACTION]) {
                case MAC_PUB_VENDOR_SPECIFIC: {
                    if (oal_memcmp(puc_data + MAC_ACTION_CATEGORY_AND_CODE_LEN, g_auc_huawei_oui, MAC_OUI_LEN) == 0) {
                        oam_warning_log0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_RX,
                                         "{hmac_sta_up_rx_action_nonuser::hmac location get.}");
                        hmac_huawei_action_process(pst_hmac_vap, pst_netbuf,
                                                   puc_data[MAC_ACTION_CATEGORY_AND_CODE_LEN + MAC_OUI_LEN]);
                    }
                    break;
                }
                default:
                    break;
            }
        }
        break;

        default:
            break;
    }
    return;
}
#endif
