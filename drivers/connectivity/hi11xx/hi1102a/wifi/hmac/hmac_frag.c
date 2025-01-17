

/* 1 ?????????? */
#include "hmac_frag.h"
#include "hmac_11i.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HMAC_FRAG_C
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)

OAL_STATIC oal_uint32 hmac_frag_process(hmac_vap_stru *pst_hmac_vap,
                                        oal_netbuf_stru *pst_netbuf_original,
                                        mac_tx_ctl_stru *pst_tx_ctl,
                                        oal_uint32 ul_cip_hdrsize,
                                        oal_uint32 ul_max_tx_unit)
{
    mac_ieee80211_frame_stru *pst_mac_header;
    mac_ieee80211_frame_stru *pst_frag_header = OAL_PTR_NULL;
    oal_netbuf_stru *pst_netbuf = OAL_PTR_NULL;
    oal_netbuf_stru *pst_netbuf_prev = pst_netbuf_original;
    oal_uint32 ul_total_hdrsize;
    oal_uint32 ul_frag_num = 1;
    oal_uint32 ul_frag_size;
    oal_int32 l_remainder;
    oal_uint32 ul_payload = 0;
    mac_tx_ctl_stru *pst_tx_ctl_copy = OAL_PTR_NULL;
    oal_uint32 ul_mac_hdr_size = MAC_80211_QOS_HTC_4ADDR_FRAME_LEN;
    oal_uint32 ul_offset = ul_max_tx_unit - ul_cip_hdrsize - ul_mac_hdr_size;
    oal_int32 l_ret;

    pst_mac_header = pst_tx_ctl->pst_frame_header;
    pst_mac_header->st_frame_control.bit_more_frag = OAL_TRUE;
    ul_total_hdrsize = ul_mac_hdr_size + ul_cip_hdrsize;
    /* ?????????????????????????????????????????????????????????????? */
    l_remainder = (oal_int32)(oal_netbuf_len(pst_netbuf_original) - ul_offset - ul_mac_hdr_size);
    do {
        ul_frag_size = ul_total_hdrsize + (oal_uint32)l_remainder;

        /* ?????????????????????? */
        if (ul_frag_size > ul_max_tx_unit) {
            ul_frag_size = ul_max_tx_unit;
        }

        pst_netbuf = oal_netbuf_alloc(ul_frag_size + MAC_80211_QOS_HTC_4ADDR_FRAME_LEN,
                                      MAC_80211_QOS_HTC_4ADDR_FRAME_LEN, 4); /* ????4???????? */
        if (pst_netbuf == OAL_PTR_NULL) {
            /* ???????????????????????? */
            OAM_ERROR_LOG0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_ANY, "{hmac_frag_process::netbuf null.}");
            return OAL_ERR_CODE_PTR_NULL;
        }

        pst_tx_ctl_copy = (mac_tx_ctl_stru *)oal_netbuf_cb(pst_netbuf);
        /* ????cb???? */
        l_ret = memcpy_s(pst_tx_ctl_copy, MAC_TX_CTL_SIZE, pst_tx_ctl, MAC_TX_CTL_SIZE);

        oal_netbuf_copy_queue_mapping(pst_netbuf, pst_netbuf_original);

        /* netbuf??headroom????802.11 mac?????? */
        pst_frag_header =
           (mac_ieee80211_frame_stru *)(get_netbuf_payload(pst_netbuf) - MAC_80211_QOS_HTC_4ADDR_FRAME_LEN);
        pst_tx_ctl_copy->bit_80211_mac_head_type = 1; /* ????mac??????skb?? */

        /* ???????????? */
        l_ret += memcpy_s(pst_frag_header, pst_tx_ctl->uc_frame_header_length,
            pst_mac_header, pst_tx_ctl->uc_frame_header_length);
        if (l_ret != EOK) {
            OAM_ERROR_LOG0(0, OAM_SF_ANY, "hmac_frag_process::memcpy fail!");
        }
        /* ?????????? */
        pst_frag_header->bit_frag_num = ul_frag_num;
        ul_frag_num++;
        /* ???????????????????? */
        ul_payload = ul_frag_size - ul_total_hdrsize;

        oal_netbuf_copydata(pst_netbuf_original, (ul_offset + ul_mac_hdr_size), get_netbuf_payload(pst_netbuf),
                            ul_payload);

        oal_netbuf_set_len(pst_netbuf, ul_payload);
        ((mac_tx_ctl_stru *)oal_netbuf_cb(pst_netbuf))->pst_frame_header = pst_frag_header;
        ((mac_tx_ctl_stru *)oal_netbuf_cb(pst_netbuf))->us_mpdu_len = (oal_uint16)ul_payload;
        oal_netbuf_next(pst_netbuf_prev) = pst_netbuf;
        pst_netbuf_prev = pst_netbuf;

        if (pst_tx_ctl_copy->bit_80211_mac_head_type == 1) {
            oal_netbuf_push(pst_netbuf, MAC_80211_QOS_HTC_4ADDR_FRAME_LEN);
        }

        /* ?????????????????????????????? */
        l_remainder -= (oal_int32)ul_payload;
        ul_offset += ul_payload;
    } while (l_remainder > 0);

    pst_frag_header->st_frame_control.bit_more_frag = OAL_FALSE;
    oal_netbuf_next(pst_netbuf) = OAL_PTR_NULL;

    /* ???????????????????????????? */
    oal_netbuf_trim(pst_netbuf_original, oal_netbuf_len(pst_netbuf_original) - (ul_max_tx_unit - ul_cip_hdrsize));
    pst_tx_ctl->us_mpdu_len = (oal_uint16)(oal_netbuf_len(pst_netbuf_original) - ul_mac_hdr_size);

    return OAL_SUCC;
}
#else

OAL_STATIC oal_uint32 hmac_frag_process(hmac_vap_stru *pst_hmac_vap,
                                        oal_netbuf_stru *pst_netbuf_original,
                                        mac_tx_ctl_stru *pst_tx_ctl,
                                        oal_uint32 ul_cip_hdrsize,
                                        oal_uint32 ul_max_tx_unit)
{
    mac_ieee80211_frame_stru *pst_mac_header;
    mac_ieee80211_frame_stru *pst_frag_header = OAL_PTR_NULL;
    oal_netbuf_stru *pst_netbuf = OAL_PTR_NULL;
    oal_netbuf_stru *pst_netbuf_prev = pst_netbuf_original;
    oal_uint32 ul_total_hdrsize;
    oal_uint32 ul_frag_num = 1;
    oal_uint32 ul_frag_size;
    oal_int32 l_remainder;
    oal_uint32 ul_payload = 0;
    oal_uint32 ul_offset;
    mac_tx_ctl_stru *pst_tx_ctl_copy = OAL_PTR_NULL;
    oal_uint32 ul_mac_hdr_size = pst_tx_ctl->uc_frame_header_length;

    pst_mac_header = pst_tx_ctl->pst_frame_header;
    pst_mac_header->st_frame_control.bit_more_frag = OAL_TRUE;
    ul_total_hdrsize = ul_mac_hdr_size + ul_cip_hdrsize;
    /* ?????????????????????????????????????????????????????????????? */
    ul_offset = ul_max_tx_unit - ul_cip_hdrsize - ul_mac_hdr_size;
    l_remainder = (oal_int32)(oal_netbuf_len(pst_netbuf_original) - ul_offset);

    do {
        ul_frag_size = ul_total_hdrsize + (oal_uint32)l_remainder;

        /* ?????????????????????? */
        if (ul_frag_size > ul_max_tx_unit) {
            ul_frag_size = ul_max_tx_unit;
        }

        pst_netbuf = oal_netbuf_alloc(ul_frag_size + MAC_80211_QOS_HTC_4ADDR_FRAME_LEN,
                                      MAC_80211_QOS_HTC_4ADDR_FRAME_LEN, 4); /* ????4???????? */
        if (pst_netbuf == OAL_PTR_NULL) {
            /* ???????????????????????? */
            OAM_ERROR_LOG0(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_ANY, "{hmac_frag_process::netbuf null.}");
            return OAL_ERR_CODE_PTR_NULL;
        }

        pst_tx_ctl_copy = (mac_tx_ctl_stru *)oal_netbuf_cb(pst_netbuf);
        /* ????cb???? */
        memcpy_s(pst_tx_ctl_copy, MAC_TX_CTL_SIZE, pst_tx_ctl, MAC_TX_CTL_SIZE);

        /* netbuf??headroom????802.11 mac?????? */
        pst_frag_header = (mac_ieee80211_frame_stru *)(get_netbuf_payload(pst_netbuf) - ul_mac_hdr_size);
        pst_tx_ctl_copy->bit_80211_mac_head_type = 1; /* ????mac??????skb?? */

        /* ???????????? */
        memcpy_s(pst_frag_header, pst_tx_ctl->uc_frame_header_length, pst_mac_header,
                 pst_tx_ctl->uc_frame_header_length);
        /* ?????????? */
        pst_frag_header->bit_frag_num = ul_frag_num;
        ul_frag_num++;
        /* ???????????????????? */
        ul_payload = ul_frag_size - ul_total_hdrsize;

        oal_netbuf_copydata(pst_netbuf_original, ul_offset, get_netbuf_payload(pst_netbuf), ul_payload);

        oal_netbuf_set_len(pst_netbuf, ul_payload);
        ((mac_tx_ctl_stru *)oal_netbuf_cb(pst_netbuf))->pst_frame_header = pst_frag_header;
        ((mac_tx_ctl_stru *)oal_netbuf_cb(pst_netbuf))->us_mpdu_len = (oal_uint16)ul_payload;
        oal_netbuf_next(pst_netbuf_prev) = pst_netbuf;
        pst_netbuf_prev = pst_netbuf;
        if (pst_tx_ctl_copy->bit_80211_mac_head_type == 1) {
            oal_netbuf_push(pst_netbuf, MAC_80211_QOS_HTC_4ADDR_FRAME_LEN);
        }

        /* ?????????????????????????????? */
        l_remainder -= (oal_int32)ul_payload;
        ul_offset += ul_payload;
    } while (l_remainder > 0);

    pst_frag_header->st_frame_control.bit_more_frag = OAL_FALSE;
    oal_netbuf_next(pst_netbuf) = OAL_PTR_NULL;

    /* ???????????????????????????? */
    oal_netbuf_trim(pst_netbuf_original,
                    oal_netbuf_len(pst_netbuf_original) - (ul_max_tx_unit - ul_cip_hdrsize - ul_mac_hdr_size));
    pst_tx_ctl->us_mpdu_len = (oal_uint16)(oal_netbuf_len(pst_netbuf_original));

    return OAL_SUCC;
}

#endif


oal_uint32 hmac_frag_process_proc(hmac_vap_stru *pst_hmac_vap, hmac_user_stru *pst_hmac_user,
                                  oal_netbuf_stru *pst_netbuf, mac_tx_ctl_stru *pst_tx_ctl)
{
    oal_uint32 ul_threshold;
    oal_uint8 uc_ic_header = 0;
    oal_uint32 ul_ret;

    /* ???????????? */
    ul_threshold = pst_hmac_vap->st_vap_base_info.pst_mib_info->st_wlan_mib_operation.ul_dot11FragmentationThreshold;

    /* ??????????????????TKIP????MSDU???????????????????? */
    ul_ret = hmac_en_mic(pst_hmac_vap, pst_hmac_user, pst_netbuf, &uc_ic_header);
    if (ul_ret != OAL_SUCC) {
        OAM_ERROR_LOG1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_ANY,
                       "{hmac_frag_process::hmac_en_mic failed[%d].}", ul_ret);
        return ul_ret;
    }
    ul_threshold = (ul_threshold & (~(BIT0 | BIT1))) + 2;

    /* ???????????? */
    ul_ret = hmac_frag_process(pst_hmac_vap, pst_netbuf, pst_tx_ctl, (oal_uint32)uc_ic_header, ul_threshold);

    return ul_ret;
}


oal_uint32 hmac_defrag_timeout_fn(oal_void *p_arg)
{
    hmac_user_stru *pst_hmac_user;
    oal_netbuf_stru *pst_netbuf = OAL_PTR_NULL;
    pst_hmac_user = (hmac_user_stru *)p_arg;

    /* ???????????????????????????? */
    if (pst_hmac_user->pst_defrag_netbuf != OAL_PTR_NULL) {
        pst_netbuf = pst_hmac_user->pst_defrag_netbuf;

        oal_mem_netbuf_trace(pst_netbuf, OAL_FALSE);
        oal_netbuf_free(pst_netbuf);
        pst_hmac_user->pst_defrag_netbuf = OAL_PTR_NULL;
    }

    return OAL_SUCC;
}
static void hmac_defrag_get_dev_fail(hmac_user_stru *hmac_user)
{
    oam_error_log4(hmac_user->st_user_base_info.uc_vap_id, OAM_SF_ANY,
                   "{hmac_defrag_process::user index[%d] user mac:XX:XX:XX:%02X:%02X:%02X}",
                   hmac_user->st_user_base_info.us_assoc_id,
                   hmac_user->st_user_base_info.auc_user_mac_addr[3], /* auc_user_mac_addr??3byte???????? */
                   hmac_user->st_user_base_info.auc_user_mac_addr[4], /* auc_user_mac_addr??4byte???????? */
                   hmac_user->st_user_base_info.auc_user_mac_addr[5]); /* auc_user_mac_addr??5byte???????? */
}
static void hmac_create_defrag_timer(hmac_user_stru *hmac_user, mac_device_stru *mac_device)
{
    frw_create_timer(&hmac_user->st_defrag_timer,
                     hmac_defrag_timeout_fn,
                     HMAC_FRAG_TIMEOUT,
                     hmac_user,
                     OAL_FALSE,
                     OAM_MODULE_ID_HMAC,
                     mac_device->ul_core_id);
}

static void hmac_process_defrag_netbuf(oal_netbuf_stru *new_buf,
                                       oal_netbuf_stru *netbuf, hmac_user_stru *hmac_user)
{
    mac_rx_ctl_stru *rx_ctl = OAL_PTR_NULL;

    oal_netbuf_init(new_buf, oal_netbuf_len(netbuf));
    oal_netbuf_copydata(netbuf, 0, oal_netbuf_data(new_buf), oal_netbuf_len(netbuf));
    if (memcpy_s(oal_netbuf_cb(new_buf), MAC_TX_CTL_SIZE, oal_netbuf_cb(netbuf), MAC_TX_CTL_SIZE) != EOK) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "hmac_process_defrag_netbuf::memcpy fail!");
    }
    rx_ctl = (mac_rx_ctl_stru *)oal_netbuf_cb(new_buf);
    rx_ctl->pul_mac_hdr_start_addr = (oal_uint32 *)oal_netbuf_header(new_buf);
    hmac_user->pst_defrag_netbuf = new_buf;
}

oal_netbuf_stru *hmac_defrag_process(hmac_user_stru *pst_hmac_user, oal_netbuf_stru *pst_netbuf,
                                     oal_uint32 ul_hrdsize)
{
    mac_ieee80211_frame_stru *pst_mac_hdr = OAL_PTR_NULL;
    mac_ieee80211_frame_stru *pst_last_hdr = OAL_PTR_NULL;
    oal_uint16 us_rx_seq;
    oal_uint16 us_last_seq = 0;
    oal_uint8 uc_frag_num;
    oal_uint8 uc_last_frag_num = 0;
    oal_bool_enum_uint8 en_more_frag;
    oal_netbuf_stru *pst_new_buf = OAL_PTR_NULL;
    oal_uint32 ul_ret;
    oal_uint8 uc_device_id;
    mac_device_stru *pst_mac_device = OAL_PTR_NULL;

    if (ul_hrdsize == 0) {
        oal_netbuf_free(pst_netbuf);
        oam_warning_log0(pst_hmac_user->st_user_base_info.uc_vap_id, OAM_SF_ANY,
                         "{hmac_defrag_process_etc::mac head len is 0.}");
        return OAL_PTR_NULL;
    }

    pst_mac_hdr = (mac_ieee80211_frame_stru *)oal_netbuf_data(pst_netbuf);
    us_rx_seq = pst_mac_hdr->bit_seq_num;
    uc_frag_num = (oal_uint8)pst_mac_hdr->bit_frag_num;

    en_more_frag = (oal_bool_enum_uint8)pst_mac_hdr->st_frame_control.bit_more_frag;

    /* ?????????????????????????????????? */
    if (!en_more_frag && (uc_frag_num == 0) && (pst_hmac_user->pst_defrag_netbuf == OAL_PTR_NULL)) {
        return pst_netbuf;
    }

    oal_mem_netbuf_trace(pst_netbuf, OAL_FALSE);

    /* ?????????????????????????????????????????????????? */
    if (pst_hmac_user->pst_defrag_netbuf != OAL_PTR_NULL) {
        frw_timer_restart_timer(&pst_hmac_user->st_defrag_timer, HMAC_FRAG_TIMEOUT, OAL_FALSE);

        pst_last_hdr = (mac_ieee80211_frame_stru *)oal_netbuf_data(pst_hmac_user->pst_defrag_netbuf);

        us_last_seq = pst_last_hdr->bit_seq_num;
        uc_last_frag_num = (oal_uint8)pst_last_hdr->bit_frag_num;

        /* ?????????????????????????????????????????????????????????????????? */
        if ((us_rx_seq != us_last_seq) ||
            (uc_frag_num != (uc_last_frag_num + 1)) ||
            oal_compare_mac_addr(pst_last_hdr->auc_address1, pst_mac_hdr->auc_address1) ||
            oal_compare_mac_addr(pst_last_hdr->auc_address2, pst_mac_hdr->auc_address2)) {
            frw_immediate_destroy_timer(&pst_hmac_user->st_defrag_timer);
            oal_netbuf_free(pst_hmac_user->pst_defrag_netbuf);
            pst_hmac_user->pst_defrag_netbuf = OAL_PTR_NULL;
        }
    }

    /* ?????????????????????????????????? */
    if (pst_hmac_user->pst_defrag_netbuf == OAL_PTR_NULL) {
        /* ????????,???????? */
        if ((en_more_frag == 0) && (uc_frag_num == 0)) {
            return pst_netbuf;
        }

        /* ????????????????????0?????? */
        if (uc_frag_num != 0) {
            oal_netbuf_free(pst_netbuf);
            oam_stat_vap_incr(pst_hmac_user->st_user_base_info.uc_vap_id, rx_defrag_process_dropped, 1);
            return OAL_PTR_NULL;
        }

        uc_device_id = pst_hmac_user->st_user_base_info.uc_device_id;
        pst_mac_device = mac_res_get_dev((oal_uint32)uc_device_id);
        if (pst_mac_device == OAL_PTR_NULL) {
            hmac_defrag_get_dev_fail(pst_hmac_user);
            /* user?????????????? */
            oal_netbuf_free(pst_netbuf);
            oam_stat_vap_incr(pst_hmac_user->st_user_base_info.uc_vap_id, rx_defrag_process_dropped, 1);
            return OAL_PTR_NULL;
        }

        /* ???????????????????????????????? */
        hmac_create_defrag_timer(pst_hmac_user, pst_mac_device);
        /* ??????netbuf????1600 ??????????????A????????2500?????????????????? */
        pst_new_buf = oal_mem_netbuf_alloc(OAL_NORMAL_NETBUF, HMAC_MAX_FRAG_SIZE, OAL_NETBUF_PRIORITY_MID);
        if (pst_new_buf == OAL_PTR_NULL) {
            OAM_ERROR_LOG1(pst_hmac_user->st_user_base_info.uc_vap_id, OAM_SF_ANY,
                           "{hmac_defrag_process::Alloc new_buf null,size[%d].}", HMAC_MAX_FRAG_SIZE);
            return OAL_PTR_NULL;
        }
        oal_mem_netbuf_trace(pst_new_buf, OAL_FALSE);

        /* ?????????????????????????????????????????????????????????????????? */
        hmac_process_defrag_netbuf(pst_new_buf, pst_netbuf, pst_hmac_user);
        oal_netbuf_free(pst_netbuf);
    } else {
        /* ???????????????????????????????????????????????? */
        frw_timer_restart_timer(&pst_hmac_user->st_defrag_timer, HMAC_FRAG_TIMEOUT, OAL_FALSE);

        pst_last_hdr = (mac_ieee80211_frame_stru *)oal_netbuf_data(pst_hmac_user->pst_defrag_netbuf);

        /* ???????????????????????? */
        pst_last_hdr->bit_seq_num = pst_mac_hdr->bit_seq_num;
        pst_last_hdr->bit_frag_num = pst_mac_hdr->bit_frag_num;

        oal_netbuf_pull(pst_netbuf, ul_hrdsize);

        /* ??????????????dev_kfree_skb */
        oal_netbuf_concat(pst_hmac_user->pst_defrag_netbuf, pst_netbuf);
    }

    /* ???????????????????????????????????????????????????????????????? */
    if (en_more_frag) {
        pst_netbuf = OAL_PTR_NULL;
    } else {
        frw_immediate_destroy_timer(&pst_hmac_user->st_defrag_timer);

        pst_netbuf = pst_hmac_user->pst_defrag_netbuf;

        pst_hmac_user->pst_defrag_netbuf = OAL_PTR_NULL;

        /* ??????????????????mic???? */
        ul_ret = hmac_de_mic(pst_hmac_user, pst_netbuf);
        if (ul_ret != OAL_SUCC) {
            oal_netbuf_free(pst_netbuf);

            oam_stat_vap_incr(pst_hmac_user->st_user_base_info.uc_vap_id, rx_de_mic_fail_dropped, 1);
            OAM_WARNING_LOG1(pst_hmac_user->st_user_base_info.uc_vap_id, OAM_SF_ANY,
                             "{hmac_defrag_process_etc::hmac_de_mic_etc failed[%d].}", ul_ret);
            return OAL_PTR_NULL;
        }

        pst_last_hdr = (mac_ieee80211_frame_stru *)oal_netbuf_data(pst_netbuf);
        pst_last_hdr->bit_frag_num = 0;
    }

    return pst_netbuf;
}

