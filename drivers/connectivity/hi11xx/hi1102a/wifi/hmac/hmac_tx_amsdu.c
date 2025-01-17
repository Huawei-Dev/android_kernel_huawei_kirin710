

/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "hmac_tx_amsdu.h"
#include "hmac_tx_data.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HMAC_TX_AMSDU_C

/*****************************************************************************
  2 ????????????
*****************************************************************************/
OAL_STATIC oal_uint32 hmac_amsdu_tx_timeout_process(oal_void *p_arg);
OAL_STATIC oal_bool_enum_uint8 hmac_tx_amsdu_is_overflow(hmac_amsdu_stru *pst_amsdu,
                                                         mac_tx_ctl_stru *pst_tx_ctl,
                                                         oal_uint32 ul_frame_len,
                                                         hmac_user_stru *pst_user);

/*****************************************************************************
  3 ????????
*****************************************************************************/
#if defined(_PRE_PRODUCT_ID_HI110X_HOST)

OAL_STATIC oal_uint32 hmac_amsdu_encap_hdr(hmac_amsdu_stru *pst_amsdu, oal_netbuf_stru **pst_netbuf,
                                           oal_uint32 ul_framelen)
{
    oal_uint32 ul_headroom;                /* ????skb???????????? */
    oal_uint32 ul_tailroom;                /* ????skb???????????? */
    oal_uint8 uc_align;                    /* ??4???????????????????????? */
    mac_ether_header_stru st_ether_head;   /* ????????????????skb?????????? */
    mac_ether_header_stru *pst_amsdu_head; /* ??????amsdu???????????????? */
    mac_llc_snap_stru *pst_snap_head;      /* ??????snap???????????? */
    mac_tx_ctl_stru *pst_cb;
    oal_netbuf_stru *pst_first_netbuf;
    mac_tx_ctl_stru *pst_first_cb;
    oal_netbuf_stru *pst_buf;
    oal_uint32 ul_netbuf_len;
    /* ???????? */
    if (oal_unlikely((pst_netbuf == OAL_PTR_NULL)
                     ||  (pst_amsdu == OAL_PTR_NULL))) {
        OAM_ERROR_LOG0(0, OAM_SF_AMPDU, "{hmac_amsdu_encap::input error}");

        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_first_netbuf = oal_netbuf_peek(&pst_amsdu->st_msdu_head);
    pst_first_cb = (mac_tx_ctl_stru *)oal_netbuf_cb(pst_first_netbuf);
    pst_buf = *pst_netbuf;
    pst_cb = (mac_tx_ctl_stru *)oal_netbuf_cb(pst_buf);
    pst_first_cb->us_mpdu_bytes += pst_cb->us_mpdu_bytes;

    /* ???????????????????? */
    ul_headroom = oal_netbuf_headroom(pst_buf);
    ul_tailroom = oal_netbuf_tailroom(pst_buf);
    if (ul_framelen < oal_netbuf_get_len(pst_buf)) {
        ul_netbuf_len = oal_netbuf_get_len(pst_buf);
        oam_error_log2(0, OAM_SF_SCAN, "{hmac_amsdu_encap::framelen[%d] < netbuflen[%d]!}", ul_framelen, ul_netbuf_len);
        return OAL_FAIL;
    }

    uc_align = (oal_uint8)(ul_framelen - oal_netbuf_get_len(pst_buf));

    oam_info_log3(0, OAM_SF_AMSDU, "{hmac_amsdu_encap::headroom[%d] tailroom[%d] offset[%d].}", ul_headroom,
                  ul_tailroom, uc_align);

    /* ???????????????????????????????? */
    if (oal_unlikely(ul_headroom < SNAP_LLC_FRAME_LEN)) {
        oam_info_log1(0, OAM_SF_AMSDU, "{hmac_amsdu_encap::headroom[%d] need realloc.}", ul_headroom);
        pst_buf = oal_netbuf_realloc_headroom(pst_buf, (SNAP_LLC_FRAME_LEN - ul_headroom));
        if (pst_buf == OAL_PTR_NULL) {
            OAM_ERROR_LOG1(0, OAM_SF_AMSDU, "{hmac_amsdu_encap::headroom[%d] realloc fail.}", ul_headroom);
            return OAL_FAIL;
        }
        *pst_netbuf = pst_buf;
    }

    /* ?????????????????? */
    st_ether_head.us_ether_type = ((mac_ether_header_stru *)oal_netbuf_data(pst_buf))->us_ether_type;
    oal_set_mac_addr(st_ether_head.auc_ether_dhost,
                     ((mac_ether_header_stru *)oal_netbuf_data(pst_buf))->auc_ether_dhost);
    oal_set_mac_addr(st_ether_head.auc_ether_shost,
                     ((mac_ether_header_stru *)oal_netbuf_data(pst_buf))->auc_ether_shost);
    oal_set_mac_addr(pst_amsdu->auc_eth_da, ((mac_ether_header_stru *)oal_netbuf_data(pst_buf))->auc_ether_dhost);
    oal_set_mac_addr(pst_amsdu->auc_eth_sa, ((mac_ether_header_stru *)oal_netbuf_data(pst_buf))->auc_ether_shost);

    /* ????snap?? */
    pst_snap_head = (mac_llc_snap_stru *)oal_netbuf_pull(pst_buf, ETHER_HDR_LEN - SNAP_LLC_FRAME_LEN);
    if (pst_snap_head == OAL_PTR_NULL) {
        return OAL_FAIL;
    }

    pst_snap_head->uc_llc_dsap = SNAP_LLC_LSAP;
    pst_snap_head->uc_llc_ssap = SNAP_LLC_LSAP;
    pst_snap_head->uc_control = LLC_UI;
    pst_snap_head->auc_org_code[0] = SNAP_RFC1042_ORGCODE_0;
    pst_snap_head->auc_org_code[1] = SNAP_RFC1042_ORGCODE_1;
    pst_snap_head->auc_org_code[2] = SNAP_RFC1042_ORGCODE_2; /* ??auc_org_code??2byte???? */
    pst_snap_head->us_ether_type = st_ether_head.us_ether_type;

    /* ????amsdu?????? */
    pst_amsdu_head = (mac_ether_header_stru *)oal_netbuf_push(pst_buf, ETHER_HDR_LEN);

    oal_set_mac_addr(pst_amsdu_head->auc_ether_dhost, st_ether_head.auc_ether_dhost);
    oal_set_mac_addr(pst_amsdu_head->auc_ether_shost, st_ether_head.auc_ether_shost);
    pst_amsdu_head->us_ether_type =
        oal_byteorder_host_to_net_uint16((oal_uint16)(oal_netbuf_get_len(pst_buf) - ETHER_HDR_LEN));

    /* ?????????????????????????????????? */
    if (oal_unlikely(ul_tailroom < uc_align)) {
        oam_info_log1(0, OAM_SF_AMSDU, "{hmac_amsdu_encap::tailroom[%d] need realloc.}", ul_tailroom);
        pst_buf = oal_netbuf_realloc_tailroom(pst_buf, uc_align - ul_tailroom);
        if (pst_buf == OAL_PTR_NULL) {
            OAM_ERROR_LOG1(0, OAM_SF_AMSDU, "{hmac_amsdu_encap::tailroom[%d] realloc fail.}", ul_tailroom);
            return OAL_FAIL;
        }
        *pst_netbuf = pst_buf;
    }

    oal_netbuf_put(pst_buf, uc_align);

    pst_amsdu->uc_last_pad_len = uc_align;

    /* ????amsdu???? */
    pst_amsdu->uc_msdu_num++;
    pst_amsdu->us_amsdu_size += (oal_uint16)oal_netbuf_get_len(pst_buf);

    /* ????frame len */
    pst_cb->us_mpdu_len = (oal_uint16)oal_netbuf_get_len(pst_buf);

    oam_info_log2(0, OAM_SF_AMSDU, "{hmac_amsdu_encap::msdu_num[%d] amsdu_size[%d].}", pst_amsdu->uc_msdu_num,
                  pst_amsdu->us_amsdu_size);

    return OAL_SUCC;
}


OAL_STATIC oal_uint32 hmac_amsdu_send(hmac_vap_stru *pst_vap, hmac_user_stru *pst_user, hmac_amsdu_stru *pst_amsdu)
{
    frw_event_mem_stru *pst_amsdu_send_event_mem;
    frw_event_stru *pst_amsdu_send_event;
    oal_uint32 ul_ret;
    mac_tx_ctl_stru *pst_cb;
    oal_netbuf_stru *pst_buf_temp;
    oal_netbuf_stru *pst_net_buf;
    dmac_tx_event_stru *pst_amsdu_event;
    mac_ieee80211_qos_htc_frame_stru *mac_header;

    /* ???????? */
    if (oal_unlikely((pst_vap == OAL_PTR_NULL) || (pst_user == OAL_PTR_NULL) || (pst_amsdu == OAL_PTR_NULL))) {
        oam_error_log3(0, OAM_SF_AMPDU, "{hmac_amsdu_send::input error %x %x %x}", (uintptr_t)pst_vap,
                       (uintptr_t)pst_user, (uintptr_t)pst_amsdu);
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ??dmac??????amsdu??????????????802.11?????? */
    pst_net_buf = oal_netbuf_peek(&(pst_amsdu->st_msdu_head));
    if (oal_unlikely(pst_net_buf == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMPDU, "{hmac_amsdu_send::pst_net_buf null}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_cb = (mac_tx_ctl_stru *)oal_netbuf_cb(pst_net_buf);
    pst_cb->us_mpdu_len = pst_amsdu->us_amsdu_size - pst_amsdu->uc_last_pad_len;
    pst_cb->uc_mpdu_num = 1;

    /* ??????amsdu????802.11?? */
    ul_ret = hmac_tx_encap(pst_vap, pst_user, pst_net_buf);
    if (oal_unlikely(ul_ret != OAL_SUCC)) {
        pst_buf_temp = oal_netbuf_delist(&(pst_amsdu->st_msdu_head));

        oal_netbuf_free(pst_buf_temp);

        oam_stat_vap_incr(pst_vap->st_vap_base_info.uc_vap_id, tx_abnormal_msdu_dropped, 1);

        OAM_ERROR_LOG1(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMPDU, "{hmac_amsdu_send::hmac_tx_encap failed[%d]}",
                       ul_ret);
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ????amsdu */
    mac_header = (mac_ieee80211_qos_htc_frame_stru *)pst_cb->pst_frame_header;
    mac_header->bit_qc_amsdu = 1;

    /* ????????????????PAD???? */
    oal_netbuf_trim(pst_net_buf, pst_amsdu->uc_last_pad_len);

    /* ??????????????(amsdu??????????tid??????????amsdu??????????????????????????
       msdu????)??????????????????????????????AMSDU????
 */
    if (pst_amsdu->uc_msdu_num == 1) {
        oal_netbuf_pull(pst_net_buf, ETHER_HDR_LEN);
        if (pst_vap->st_vap_base_info.en_vap_mode == WLAN_VAP_MODE_BSS_STA) {
            oal_set_mac_addr(pst_cb->pst_frame_header->auc_address3, pst_amsdu->auc_eth_da);
        } else if (!(pst_cb->en_use_4_addr)) { /* ????AP */
            oal_set_mac_addr(pst_cb->pst_frame_header->auc_address3, pst_amsdu->auc_eth_sa);
        } else { /* WDS  TBD ???????? */
            oal_set_mac_addr(pst_cb->pst_frame_header->auc_address3, pst_amsdu->auc_eth_da); /* ????3?? DA */
        }

        pst_cb->en_is_amsdu = OAL_FALSE;
        pst_cb->us_mpdu_len -= ETHER_HDR_LEN;
        mac_header->bit_qc_amsdu = 0;
    }

    /* ???????????? */
    if ((oal_netbuf_tail(&pst_amsdu->st_msdu_head) != OAL_PTR_NULL) &&
        (oal_netbuf_peek(&pst_amsdu->st_msdu_head) != OAL_PTR_NULL)) {
        oal_netbuf_prev(oal_netbuf_peek(&pst_amsdu->st_msdu_head)) = OAL_PTR_NULL;
        oal_netbuf_next(oal_netbuf_tail(&pst_amsdu->st_msdu_head)) = OAL_PTR_NULL;
    }
    /* ?????? */
    pst_amsdu_send_event_mem = frw_event_alloc_m(OAL_SIZEOF(dmac_tx_event_stru));
    if (oal_unlikely(pst_amsdu_send_event_mem == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMPDU,
                       "{hmac_amsdu_send::pst_amsdu_send_event_mem null}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ???????? */
    pst_amsdu_send_event = (frw_event_stru *)(pst_amsdu_send_event_mem->puc_data);
    if (oal_unlikely(pst_amsdu_send_event == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMPDU, "hmac_amsdu_send:pst_amsdu_send_event null");
        frw_event_free_m(pst_amsdu_send_event_mem);
        return OAL_ERR_CODE_PTR_NULL;
    }

    frw_event_hdr_init(&(pst_amsdu_send_event->st_event_hdr),
                       FRW_EVENT_TYPE_HOST_DRX,
                       DMAC_TX_HOST_DRX,
                       OAL_SIZEOF(dmac_tx_event_stru),
                       FRW_EVENT_PIPELINE_STAGE_1,
                       pst_vap->st_vap_base_info.uc_chip_id,
                       pst_vap->st_vap_base_info.uc_device_id,
                       pst_vap->st_vap_base_info.uc_vap_id);

    pst_amsdu_send_event = (frw_event_stru *)(pst_amsdu_send_event_mem->puc_data);

    pst_amsdu_event = (dmac_tx_event_stru *)(pst_amsdu_send_event->auc_event_data);
    pst_amsdu_event->pst_netbuf = oal_netbuf_peek(&pst_amsdu->st_msdu_head);

    ul_ret = frw_event_dispatch_event(pst_amsdu_send_event_mem);
    if (oal_unlikely(ul_ret != OAL_SUCC)) {
        hmac_free_netbuf_list(pst_amsdu_event->pst_netbuf);
    }

    /* ????amsdu?????????? */
    pst_amsdu->us_amsdu_size = 0;
    pst_amsdu->uc_msdu_num = 0;
    oal_netbuf_list_head_init(&pst_amsdu->st_msdu_head);

    /* ???????????? */
    frw_event_free_m(pst_amsdu_send_event_mem);

    oam_info_log0(0, OAM_SF_AMSDU, "{hmac_amsdu_send::amsdu send success.");

    return ul_ret;
}


OAL_STATIC OAL_INLINE oal_void hmac_amsdu_build_netbuf(hmac_vap_stru *pst_vap, hmac_amsdu_stru *pst_amsdu,
                                                       oal_netbuf_stru *pst_buf)
{
    oal_uint16 us_buf_len;
    oal_uint16 us_offset;
    oal_netbuf_stru *pst_dest_buf;

    us_buf_len = (oal_uint16)oal_netbuf_get_len(pst_buf);
    pst_dest_buf = oal_netbuf_peek(&pst_amsdu->st_msdu_head);
    if (pst_dest_buf == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_AMSDU, "{hmac_amsdu_build_netbuf::oal_netbuf_peek return NULL}");
        oal_netbuf_free(pst_buf);
        return;
    }

    /* ????pad???????? ????last pad */
    if (oal_netbuf_tailroom(pst_dest_buf) < us_buf_len) {
        us_buf_len -= pst_amsdu->uc_last_pad_len;
        pst_amsdu->uc_last_pad_len = 0;
    }

    us_offset = (oal_uint16)oal_netbuf_get_len(pst_dest_buf);
    oal_netbuf_put(pst_dest_buf, us_buf_len);
    if (memcpy_s(oal_netbuf_data(pst_dest_buf) + us_offset, us_buf_len, oal_netbuf_data(pst_buf), us_buf_len) != EOK) {
        OAM_ERROR_LOG0(0, OAM_SF_AMSDU, "{hmac_amsdu_build_netbuf::memcpy fail!}");
    }

    oal_netbuf_free(pst_buf);

    return;
}

OAL_STATIC OAL_INLINE oal_uint32 hmac_amsdu_alloc_netbuf(hmac_amsdu_stru *pst_amsdu, oal_netbuf_stru *pst_dest_buf,
                                                         oal_netbuf_stru *pst_buf)
{
    mac_tx_ctl_stru *pst_cb;

    pst_dest_buf = oal_mem_netbuf_alloc(OAL_NORMAL_NETBUF, WLAN_MEM_NETBUF_SIZE2, OAL_NETBUF_PRIORITY_MID);
    if (pst_dest_buf == OAL_PTR_NULL) {
        return OAL_FAIL;
    }

    if (memcpy_s(oal_netbuf_cb(pst_dest_buf), OAL_SIZEOF(mac_tx_ctl_stru),
                 oal_netbuf_cb(pst_buf), OAL_SIZEOF(mac_tx_ctl_stru)) != EOK) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "hmac_amsdu_alloc_netbuf::memcpy fail!");
        oal_netbuf_free(pst_dest_buf);
        return OAL_FAIL;
    }
    /* ????????amsdu???? */
    oal_netbuf_add_to_list_tail(pst_dest_buf, &pst_amsdu->st_msdu_head);

    oal_netbuf_copy_queue_mapping(pst_dest_buf, pst_buf);

    pst_cb = (mac_tx_ctl_stru *)oal_netbuf_cb(pst_dest_buf);
    pst_cb->uc_is_first_msdu = OAL_TRUE;
    pst_cb->en_is_amsdu = OAL_TRUE;
    pst_cb->uc_netbuf_num = 1;
    pst_cb->us_mpdu_bytes = 0;

    return OAL_SUCC;
}


oal_uint32 hmac_amsdu_tx_process(hmac_vap_stru *pst_vap, hmac_user_stru *pst_user, oal_netbuf_stru *pst_buf)
{
    oal_uint8 uc_tid_no;
    oal_uint32 ul_frame_len;
    oal_uint32 ul_ret;
    oal_netbuf_stru *pst_dest_buf = NULL;
    hmac_amsdu_stru *pst_amsdu;
    mac_tx_ctl_stru *pst_tx_ctl;

#ifdef _PRE_WLAN_NARROW_BAND
    if (g_hitalk_status & NARROW_BAND_ON_MASK) {
        return HMAC_TX_PASS;
    }
#endif

    pst_tx_ctl = (mac_tx_ctl_stru *)(oal_netbuf_cb(pst_buf));

    ul_frame_len = oal_netbuf_get_len(pst_buf);

    /* ?????????????????????????????????????? */
    pst_tx_ctl->us_mpdu_bytes = (oal_uint16)(ul_frame_len - ETHER_HDR_LEN);

    uc_tid_no = pst_tx_ctl->uc_tid;
    pst_amsdu = &(pst_user->ast_hmac_amsdu[uc_tid_no]);

    if (hmac_tx_amsdu_is_overflow(pst_amsdu, pst_tx_ctl, ul_frame_len, pst_user)) {
        oam_info_log0(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMSDU,
                      "{hmac_amsdu_process::the length of amsdu is exceeded, so it is to be sent.}");

        /* ?????????? */
        frw_immediate_destroy_timer(&pst_amsdu->st_amsdu_timer);

        ul_ret = hmac_amsdu_send(pst_vap, pst_user, pst_amsdu);
        if (oal_unlikely(ul_ret != OAL_SUCC)) {
            OAM_WARNING_LOG1(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMSDU,
                             "{hmac_amsdu_process::in amsdu notify, in the situation of length or number overflow, \
                             amsdu send fails. erro code is %d}",
                             (oal_int32)ul_ret);
            return HMAC_TX_PASS;
        }
    }
    if (pst_amsdu->uc_msdu_num == 0) {
        oam_info_log0(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMSDU,
                      "{hmac_amsdu_process::there is no msdu in the amsdu.}");

        oal_netbuf_list_head_init(&(pst_amsdu->st_msdu_head));

        /* ????netbuf????????amsdu */
        if (hmac_amsdu_alloc_netbuf(pst_amsdu, pst_dest_buf, pst_buf) != OAL_SUCC) {
            OAM_ERROR_LOG0(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMSDU,
                           "{hmac_amsdu_process::failed to alloc netbuf.}");
            return HMAC_TX_DROP_AMSDU_ENCAP_FAIL;
        }

        /* ?????????? */
        frw_create_timer(&pst_amsdu->st_amsdu_timer, hmac_amsdu_tx_timeout_process,
                         HMAC_AMSDU_LIFE_TIME, pst_amsdu, OAL_FALSE, OAM_MODULE_ID_HMAC,
                         pst_vap->st_vap_base_info.ul_core_id);
    }
    /* 4???????????????????? */
    ul_frame_len = oal_roundup(ul_frame_len, 4);

    ul_ret = hmac_amsdu_encap_hdr(pst_amsdu, &pst_buf, ul_frame_len);
    if (oal_unlikely(ul_ret != OAL_SUCC)) {
        OAM_WARNING_LOG1(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMSDU,
                         "{in amsdu notify, amsdu encapsulation fails. erro code is %d.}", (oal_int32)ul_ret);
        oam_stat_vap_incr(pst_vap->st_vap_base_info.uc_vap_id, tx_abnormal_msdu_dropped, 1);
        return HMAC_TX_DROP_AMSDU_ENCAP_FAIL;
    }

    /* ????????amsdu ????buffer */
    hmac_amsdu_build_netbuf(pst_vap, pst_amsdu, pst_buf);

    return HMAC_TX_BUFF;
}


OAL_STATIC oal_bool_enum_uint8 hmac_tx_amsdu_is_overflow(hmac_amsdu_stru *pst_amsdu,
                                                         mac_tx_ctl_stru *pst_tx_ctl,
                                                         oal_uint32 ul_frame_len,
                                                         hmac_user_stru *pst_user)
{
    mac_tx_ctl_stru *pst_head_ctl;
    oal_netbuf_stru *pst_head_buf;

    if (pst_amsdu->uc_msdu_num == 0) {
        oam_info_log0(0, OAM_SF_TX, "{hmac_tx_amsdu_is_overflow::uc_msdu_num=0.}");
        return OAL_FALSE;
    }

    pst_head_buf = oal_netbuf_peek(&pst_amsdu->st_msdu_head);
    if (pst_head_buf == OAL_PTR_NULL) {
        oam_info_log0(0, OAM_SF_TX, "{hmac_tx_amsdu_is_overflow::pst_head_buf null.}");
        return OAL_FALSE;
    }

    pst_head_ctl = (mac_tx_ctl_stru *)oal_netbuf_cb(pst_head_buf);
    /* amsdu????????????amsdu????????????(lan????wlan)??????????????netbuf??????????amsdu??????????
       ????????????????????????????????mpdu????????????????netbuf??cb????????????????????????????????
       ????????mpdu????netbuf????????????????????????
 */
    if (pst_tx_ctl->en_event_type != pst_head_ctl->en_event_type) {
        oam_info_log2(0, OAM_SF_TX, "{hmac_tx_amsdu_is_overflow::en_event_type mismatched. %d %d.}",
                      pst_tx_ctl->en_event_type, pst_head_ctl->en_event_type);
        return OAL_TRUE;
    }

    oam_info_log3(0, OAM_SF_TX, "{hmac_tx_amsdu_is_overflow::us_amsdu_size=%d uc_msdu_num=%d us_amsdu_maxsize=%d.}",
                  pst_amsdu->us_amsdu_size, pst_amsdu->uc_msdu_num, pst_amsdu->us_amsdu_maxsize);

    /* payload + padmax(3) ????????1568 */
    if (((pst_amsdu->us_amsdu_size + ul_frame_len + SNAP_LLC_FRAME_LEN + 3) > 1568)
        ||  ((pst_amsdu->uc_msdu_num + 1) > pst_amsdu->uc_amsdu_maxnum) ||
        ((pst_amsdu->us_amsdu_size + ul_frame_len + SNAP_LLC_FRAME_LEN) > WLAN_AMSDU_FRAME_MAX_LEN)) {
        return OAL_TRUE;
    }

    return OAL_FALSE;
}
#endif


oal_uint32 hmac_amsdu_notify(hmac_vap_stru *pst_vap, hmac_user_stru *pst_user, oal_netbuf_stru *pst_buf)
{
    oal_uint8 uc_tid_no;
    oal_uint32 ul_ret; /* ?????????????????? */
    mac_tx_ctl_stru *pst_tx_ctl;
    hmac_amsdu_stru *pst_amsdu;

    pst_tx_ctl = (mac_tx_ctl_stru *)(oal_netbuf_cb(pst_buf));

    /* ????cb????tid???? */
    uc_tid_no = pst_tx_ctl->uc_tid;

    pst_amsdu = &(pst_user->ast_hmac_amsdu[uc_tid_no]);
    oal_spin_lock_bh(&pst_amsdu->st_amsdu_lock);

    /* ????????WMM????QOS?????? */
    if (pst_user->st_user_base_info.st_cap_info.bit_qos == OAL_FALSE) {
        oam_info_log0(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_TX, "{hmac_amsdu_notify::UnQos Frame pass!!}");
        oal_spin_unlock_bh(&pst_amsdu->st_amsdu_lock);
        return HMAC_TX_PASS;
    }
    /* ??????VAP????amsdu?????????????????????? */
    if (pst_vap->en_small_amsdu_switch == OAL_FALSE) {
        oal_spin_unlock_bh(&pst_amsdu->st_amsdu_lock);
        return HMAC_TX_PASS;
    }
    /* ??????tid??????ampdu??????????amsdu?????? */
    if (hmac_user_is_amsdu_support(pst_user, uc_tid_no) == 0) {
        oam_info_log2(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMSDU,
                      "{hmac_amsdu_notify::AMPDU NOT SUPPORT AMSDU uc_tid_no=%d uc_amsdu_supported=%d}",
                      uc_tid_no, pst_user->uc_amsdu_supported);
        oal_spin_unlock_bh(&pst_amsdu->st_amsdu_lock);
        return HMAC_TX_PASS;
    }

    /* 1102A ????TCP ACK???? */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) && (_PRE_PRODUCT_ID != _PRE_PRODUCT_ID_HI1102A_HOST) && \
    (_PRE_PRODUCT_ID != _PRE_PRODUCT_ID_HI1102_HOST)
    if (oal_netbuf_is_tcp_ack((oal_ip_header_stru *)(oal_netbuf_data(pst_buf) + ETHER_HDR_LEN)) == OAL_TRUE) {
        oal_spin_unlock_bh(&pst_amsdu->st_amsdu_lock);
        return HMAC_TX_PASS;
    }
#endif

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    /* ??????????????????ping???????????? */
    if (oal_netbuf_is_icmp((oal_ip_header_stru *)(oal_netbuf_data(pst_buf) + ETHER_HDR_LEN)) == OAL_TRUE) {
        oal_spin_unlock_bh(&pst_amsdu->st_amsdu_lock);
        return HMAC_TX_PASS;
    }
#endif

    if (oal_netbuf_get_len(pst_buf) > WLAN_MSDU_MAX_LEN) {
        if (pst_amsdu->uc_msdu_num) {
            /* ?????????? */
            frw_immediate_destroy_timer(&pst_amsdu->st_amsdu_timer);

            ul_ret = hmac_amsdu_send(pst_vap, pst_user, pst_amsdu);
            if (ul_ret != OAL_SUCC) {
                OAM_WARNING_LOG1(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMSDU,
                                 "{hmac_amsdu_process:in amsdu notify, in the situation of length or number overflow, \
                                 amsdu send fails. erro code is %d}", ul_ret);
            }
        }
        oal_spin_unlock_bh(&pst_amsdu->st_amsdu_lock);
        return HMAC_TX_PASS;
    }

    /* ????amsdu???????????? */
    if (pst_vap->en_amsdu_active != OAL_TRUE) {
        oam_info_log0(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMSDU,
                      "{hmac_amsdu_notify::amsdu is unenable in amsdu notify}");
        oal_spin_unlock_bh(&pst_amsdu->st_amsdu_lock);
        return HMAC_TX_PASS;
    }

    /* ??????????????HT/VHT */
    if (hmac_user_xht_support(pst_user) == OAL_FALSE) {
        oam_info_log0(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMSDU,
                      "{hmac_amsdu_notify::user is not qos in amsdu notify}");
        oal_spin_unlock_bh(&pst_amsdu->st_amsdu_lock);
        return HMAC_TX_PASS;
    }

    if (oal_unlikely(uc_tid_no >= WLAN_TID_MAX_NUM)) {
        OAM_ERROR_LOG0(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMSDU,
                       "{hmac_amsdu_notify::invalid tid number obtained from the cb in asmdu notify function}");
        oal_spin_unlock_bh(&pst_amsdu->st_amsdu_lock);
        return HMAC_TX_PASS;
    }

    if (uc_tid_no == WLAN_TIDNO_VOICE) {
        oam_info_log2(pst_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMSDU,
                      "{hmac_amsdu_notify::VO TID NOT SUPPORT AMSDU uc_tid_no=%d uc_amsdu_supported=%d",
                      uc_tid_no, pst_user->uc_amsdu_supported);
        oal_spin_unlock_bh(&pst_amsdu->st_amsdu_lock);

        return HMAC_TX_PASS;
    }

    ul_ret = hmac_amsdu_tx_process(pst_vap, pst_user, pst_buf);
    oal_spin_unlock_bh(&pst_amsdu->st_amsdu_lock);
    return ul_ret;
}


OAL_STATIC oal_uint32 hmac_amsdu_tx_timeout_process(oal_void *p_arg)
{
    hmac_amsdu_stru *pst_temp_amsdu = OAL_PTR_NULL;
    mac_tx_ctl_stru *pst_cb = OAL_PTR_NULL;
    hmac_user_stru *pst_user = OAL_PTR_NULL;
    oal_uint32 ul_ret;
    oal_netbuf_stru *pst_netbuf = OAL_PTR_NULL;
    hmac_vap_stru *pst_hmac_vap = OAL_PTR_NULL;
    if (oal_unlikely(p_arg == OAL_PTR_NULL)) {
        OAM_ERROR_LOG0(0, OAM_SF_AMPDU, "{hmac_amsdu_tx_timeout_process::input null}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_temp_amsdu = (hmac_amsdu_stru *)p_arg;

    oal_spin_lock_bh(&pst_temp_amsdu->st_amsdu_lock);

    if (pst_temp_amsdu->uc_msdu_num == 0) {
        OAM_WARNING_LOG1(0, OAM_SF_AMSDU, "hmac_amsdu_tx_timeout_process::msdu_num error[%d]",
                         pst_temp_amsdu->uc_msdu_num);
        oal_spin_unlock_bh(&pst_temp_amsdu->st_amsdu_lock);
        return OAL_FAIL;
    }

    /* ????????????amsdu????????msdu??????cb???????????????????????????? */
    pst_netbuf = oal_netbuf_peek(&pst_temp_amsdu->st_msdu_head);
    if (pst_netbuf == OAL_PTR_NULL) {
        OAM_ERROR_LOG1(0, OAM_SF_AMSDU, "hmac_amsdu_tx_timeout_process::pst_netbuf NULL. msdu_num[%d]",
                       pst_temp_amsdu->uc_msdu_num);
        oal_spin_unlock_bh(&pst_temp_amsdu->st_amsdu_lock);
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_cb = (mac_tx_ctl_stru *)oal_netbuf_cb(pst_netbuf);
    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_cb->uc_tx_vap_index);
    if (oal_unlikely(pst_hmac_vap == OAL_PTR_NULL)) {
        oal_spin_unlock_bh(&pst_temp_amsdu->st_amsdu_lock);
        OAM_ERROR_LOG0(0, OAM_SF_AMPDU, "{hmac_amsdu_tx_timeout_process::pst_hmac_vap null}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_user = (hmac_user_stru *)mac_res_get_hmac_user(pst_cb->us_tx_user_idx);
    if (oal_unlikely(pst_user == OAL_PTR_NULL)) {
        oal_spin_unlock_bh(&pst_temp_amsdu->st_amsdu_lock);
        OAM_WARNING_LOG1(0, OAM_SF_AMPDU, "{hmac_amsdu_tx_timeout_process::pst_user[%d] null}", pst_cb->us_tx_user_idx);
        return OAL_ERR_CODE_PTR_NULL;
    }

    ul_ret = hmac_amsdu_send(pst_hmac_vap, pst_user, pst_temp_amsdu);
    if (ul_ret != OAL_SUCC) {
        OAM_WARNING_LOG1(pst_hmac_vap->st_vap_base_info.uc_vap_id, OAM_SF_AMSDU,
                         "hmac_amsdu_tx_timeout_process::hmac_amsdu_send fail[%d]", ul_ret);
    }

    oal_spin_unlock_bh(&pst_temp_amsdu->st_amsdu_lock);

    return OAL_SUCC;
}


oal_void hmac_amsdu_init_user(hmac_user_stru *pst_hmac_user_sta)
{
    oal_uint32 ul_amsdu_idx;
    hmac_amsdu_stru *pst_amsdu = OAL_PTR_NULL;

    if (pst_hmac_user_sta == OAL_PTR_NULL) {
        OAM_ERROR_LOG0(0, OAM_SF_AMPDU, "{hmac_amsdu_init_user::pst_hmac_user_sta null}");
        return;
    }
    /* ????amsdu?? */
    pst_hmac_user_sta->us_amsdu_maxsize = WLAN_AMSDU_FRAME_MAX_LEN_LONG;
    pst_hmac_user_sta->uc_amsdu_supported = AMSDU_ENABLE_ALL_TID;

    for (ul_amsdu_idx = 0; ul_amsdu_idx < WLAN_WME_MAX_TID_NUM; ul_amsdu_idx++) {
        pst_amsdu = &(pst_hmac_user_sta->ast_hmac_amsdu[ul_amsdu_idx]);
        hmac_amsdu_set_maxsize(pst_amsdu, pst_hmac_user_sta, WLAN_AMSDU_FRAME_MAX_LEN_LONG);
        hmac_amsdu_set_maxnum(pst_amsdu, WLAN_AMSDU_MAX_NUM);

        oal_spin_lock_init(&pst_amsdu->st_amsdu_lock);
    }
}

#ifdef _PRE_WLAN_FEATURE_MULTI_NETBUF_AMSDU

oal_void hmac_tx_encap_large_skb_amsdu(hmac_vap_stru *pst_hmac_vap, hmac_user_stru *pst_user,
                                       oal_netbuf_stru *pst_buf, mac_tx_ctl_stru *pst_tx_ctl)
{
    mac_ether_header_stru *pst_ether_hdr_temp;
    mac_ether_header_stru *pst_ether_hdr;
    oal_uint8 uc_tid_no;
    oal_uint16 us_mpdu_len;
    oal_uint16 us_80211_frame_len;
    oal_int32 l_ret;
    mac_tx_large_amsdu_ampdu_stru *tx_large_amsdu = mac_get_tx_large_amsdu_addr();

    /* AMPDU+AMSDU??????????,??????????????????????300Mbps??????amsdu???????? */
    if (tx_large_amsdu->uc_cur_amsdu_ampdu_enable[pst_hmac_vap->st_vap_base_info.uc_vap_id] == OAL_FALSE) {
        return;
    }

    /* ????????WMM????QOS?????? */
    if (pst_user->st_user_base_info.st_cap_info.bit_qos == OAL_FALSE) {
        return;
    }

    /* VO????????????????AMPDU+AMSDU */
    uc_tid_no = MAC_GET_CB_WME_TID_TYPE(pst_tx_ctl);
    if (uc_tid_no >= WLAN_TIDNO_VOICE) {
        return;
    }

    /* ??????tid????????AMPDU+AMSDU */
    if (hmac_user_is_amsdu_support(pst_user, uc_tid_no) == OAL_FALSE) {
        return;
    }

    /* ????????????AMPDU+AMSDU */
    us_mpdu_len = (oal_uint16)oal_netbuf_get_len(pst_buf);
    if ((us_mpdu_len < MAC_AMSDU_SKB_LEN_DOWN_LIMIT) || (us_mpdu_len > MAC_AMSDU_SKB_LEN_UP_LIMIT)) {
        return;
    }

    /* ????????????????????AMPDU+AMSDU,????????????????????EHER HEAD LEN??????????,MAC HEAD???????????? */
    us_80211_frame_len = us_mpdu_len + SNAP_LLC_FRAME_LEN + 2 + MAC_80211_QOS_HTC_4ADDR_FRAME_LEN; /* 2????duration */
    if (us_80211_frame_len > mac_mib_get_FragmentationThreshold(&pst_hmac_vap->st_vap_base_info)) {
        return;
    }

    /* ??????????AMSDU???? */
    if (mac_get_cb_is_amsdu(pst_tx_ctl) == OAL_TRUE) {
        return;
    }

    /* ETHER HEAD????????????,4????????;????????????????,?????????? */
    if (oal_netbuf_headroom(pst_buf) < (SNAP_LLC_FRAME_LEN + 2)) { /* 2????duration */
        return;
    }

    /* 80211 FRAME INCLUDE EHTER HEAD */
    MAC_GET_CB_HAS_EHTER_HEAD(pst_tx_ctl) = OAL_TRUE;

    pst_ether_hdr = (mac_ether_header_stru *)oal_netbuf_data(pst_buf);

    /* ????LLC HEAD???? */
    oal_netbuf_push(pst_buf, SNAP_LLC_FRAME_LEN);
    pst_ether_hdr_temp = (mac_ether_header_stru *)oal_netbuf_data(pst_buf);
    /* ????mac head */
    l_ret = memmove_s((oal_uint8 *)pst_ether_hdr_temp, SNAP_LLC_FRAME_LEN + ETHER_HDR_LEN,
                      (oal_uint8 *)pst_ether_hdr, ETHER_HDR_LEN);
    if (l_ret != EOK) {
        OAM_ERROR_LOG1(0, OAM_SF_AMSDU, "{hmac_tx_encap_large_skb_amsdu::memmove fail[%d]}", l_ret);
        return;
    }
    /* ????AMSDU?????? */
    pst_ether_hdr_temp->us_ether_type = oal_byteorder_host_to_net_uint16((oal_uint16)(us_mpdu_len - ETHER_HDR_LEN
                                                                          + SNAP_LLC_FRAME_LEN));
}
#endif




