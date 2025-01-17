

/*****************************************************************************
  1??????????
*****************************************************************************/

#include "hmac_traffic_classify.h"
#include "securec.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HMAC_TRAFFIC_CLASSIFY_C

/*****************************************************************************
  2??????
*****************************************************************************/
#define RTP_VERSION          2      /* RTP??????????????2????????????????????2 */
#define RTP_VER_SHIFT        6      /* RTP???????????????? */
#define RTP_CSRC_MASK        0x0f   /* CSRC??????????4????????CSRC???????????? */
#define RTP_CSRC_LEN_BYTE    4      /* ????CSRC????????32??????4???? */
#define RTP_HDR_LEN_BYTE     12     /* RTP??????????????(??????CSRC????) */
#define TCP_HTTP_VI_LEN_THR  1000   /* HTTP?????????????????? */
#define JUDGE_CACHE_LIFETIME 1      /* ??????????????????: 1s */
#define IP_FRAGMENT_MASK     0x1FFF /* IP????Fragment Offset???? */
/* RTP Payload_Type ????:RFC3551 */
#define RTP_PT_VO_G729 18 /* RTP????????:18-Audio-G729 */
#define RTP_PT_VI_CELB 25 /* RTP????????:25-Video-CelB */
#define RTP_PT_VI_JPEG 26 /* RTP????????:26-Video-JPEG */
#define RTP_PT_VI_NV   28 /* RTP????????:28-Video-nv */
#define RTP_PT_VI_H261 31 /* RTP????????:31-Video-H261 */
#define RTP_PT_VI_MPV  32 /* RTP????????:32-Video-MPV */
#define RTP_PT_VI_MP2T 33 /* RTP????????:33-Video-MP2T */
#define RTP_PT_VI_H263 34 /* RTP????????:34-Video-H263 */
/* HTTP?????????? */
#define HTTP_PORT_80   80   /* HTTP??????????????80 */
#define HTTP_PORT_8080 8080 /* HTTP??????????????8080 */

/*****************************************************************************
  3 ????????
*****************************************************************************/

OAL_STATIC oal_uint32 hmac_tx_add_cfm_traffic(hmac_user_stru *pst_hmac_user, oal_uint8 uc_tid,
                                              hmac_tx_major_flow_stru *pst_max)
{
    oal_uint32 ul_time_stamp = 0;
    oal_uint8 uc_mark = 0;
    oal_uint8 uc_traffic_idx = 0;

    hmac_tx_cfm_flow_stru *pst_cfm_info = OAL_PTR_NULL;

    if (pst_hmac_user->uc_cfm_num == MAX_CONFIRMED_FLOW_NUM) {
        /* ?????????????????????????????????????????????????????? */
        ul_time_stamp = pst_hmac_user->ast_cfm_flow_list[uc_traffic_idx].ul_last_jiffies;

        for (uc_traffic_idx = 1; uc_traffic_idx < MAX_CONFIRMED_FLOW_NUM; uc_traffic_idx++) {
            pst_cfm_info = (pst_hmac_user->ast_cfm_flow_list + uc_traffic_idx);
            /*lint -e718*//*lint -e746*/
            if (oal_time_after(ul_time_stamp, pst_cfm_info->ul_last_jiffies)) {
                ul_time_stamp = pst_cfm_info->ul_last_jiffies;
                uc_mark = uc_traffic_idx;
            }
            /*lint +e718*//*lint +e746*/
        }
    } else {
        /* ????????????????????????????index */
        for (uc_traffic_idx = 0; uc_traffic_idx < MAX_CONFIRMED_FLOW_NUM; uc_traffic_idx++) {
            pst_cfm_info = (pst_hmac_user->ast_cfm_flow_list + uc_traffic_idx);
            if (pst_cfm_info->us_cfm_flag == OAL_FALSE) {
                uc_mark = uc_traffic_idx;
                pst_hmac_user->uc_cfm_num++;
                pst_cfm_info->us_cfm_flag = OAL_TRUE;
                break;
            }
        }
    }

    /* ???????? */
    pst_cfm_info = (pst_hmac_user->ast_cfm_flow_list + uc_mark);

    memcpy_s(&pst_cfm_info->st_cfm_flow_info,
             OAL_SIZEOF(hmac_tx_flow_info_stru),
             &pst_max->st_flow_info,
             OAL_SIZEOF(hmac_tx_flow_info_stru));

    pst_cfm_info->us_cfm_tid = uc_tid;
    pst_cfm_info->ul_last_jiffies = OAL_TIME_JIFFY;

    return OAL_SUCC;
}


OAL_STATIC oal_uint32 hmac_tx_traffic_judge(hmac_user_stru *pst_hmac_user,
                                            hmac_tx_major_flow_stru *pst_major_flow,
                                            oal_uint8 *puc_tid)
{
    oal_uint32 ul_ret = OAL_FAIL;
    oal_uint8 uc_cache_idx;
    oal_uint32 ul_pt;

    hmac_tx_judge_list_stru *pst_judge_list = &(pst_hmac_user->st_judge_list);
    hmac_tx_judge_info_stru *pst_judge_info = OAL_PTR_NULL;

    /* ????????????UDP????????RTP?????? */
    for (uc_cache_idx = 0; uc_cache_idx < MAX_JUDGE_CACHE_LENGTH; uc_cache_idx++) {
        pst_judge_info = (hmac_tx_judge_info_stru *)(pst_judge_list->ast_judge_cache + uc_cache_idx);

        if (!oal_memcmp(&pst_judge_info->st_flow_info,
                        &pst_major_flow->st_flow_info,
                        OAL_SIZEOF(hmac_tx_flow_info_stru))) {
            /* RTP??????????:version????????2??SSRC??PT??????????????????????RTP???????? */
            if (((pst_judge_info->uc_rtpver >> RTP_VER_SHIFT) != RTP_VERSION) ||
                (pst_major_flow->ul_rtpssrc != pst_judge_info->ul_rtpssrc) ||
                (pst_major_flow->ul_payload_type != pst_judge_info->ul_payload_type) ||
                (pst_major_flow->ul_average_len <
                 (oal_uint32)(pst_judge_info->uc_rtpver & RTP_CSRC_MASK) * RTP_CSRC_LEN_BYTE + RTP_HDR_LEN_BYTE)) {
                pst_hmac_user->st_judge_list.ul_to_judge_num = 0; /* ?????????????????? */
                pst_hmac_user->us_clear_judge_count += 1;
                return OAL_FAIL;
            }
        }
    }

    ul_pt = pst_major_flow->ul_payload_type;
    if (ul_pt <= RTP_PT_VO_G729) { /* ????PayloadType????RTP???????? */
        *puc_tid = WLAN_TIDNO_VOICE;
    } else if ((ul_pt == RTP_PT_VI_CELB) || (ul_pt == RTP_PT_VI_JPEG) || (ul_pt == RTP_PT_VI_NV) ||
               ((ul_pt >= RTP_PT_VI_H261) && (ul_pt <= RTP_PT_VI_H263))) {
        *puc_tid = WLAN_TIDNO_VIDEO;
    }

    /* ?????????????????????????????? */
    if ((*puc_tid == WLAN_TIDNO_VOICE) || (*puc_tid == WLAN_TIDNO_VIDEO)) {
        ul_ret = hmac_tx_add_cfm_traffic(pst_hmac_user, *puc_tid, pst_major_flow);
    }
    pst_hmac_user->st_judge_list.ul_to_judge_num = 0; /* ?????????????????? */

    return ul_ret;
}


OAL_STATIC oal_uint32 hmac_tx_find_major_traffic(hmac_user_stru *pst_hmac_user, oal_uint8 *puc_tid)
{
    oal_uint8 uc_cache_idx_i;
    oal_uint8 uc_cache_idx_j;

    hmac_tx_major_flow_stru st_mark;
    hmac_tx_major_flow_stru st_max;

    hmac_tx_judge_list_stru *pst_judge_list = &(pst_hmac_user->st_judge_list);
    hmac_tx_judge_info_stru *pst_judge_info = OAL_PTR_NULL;

    /* ?????? */
    st_max.ul_wait_check_num = 0;

    /* ?????????????????????? */
    if (((oal_int32)pst_judge_list->ul_jiffies_end - (oal_int32)pst_judge_list->ul_jiffies_st) >
        (JUDGE_CACHE_LIFETIME * OAL_TIME_HZ)) {           /* ??????????long????jiffies???? */
        pst_hmac_user->st_judge_list.ul_to_judge_num = 0; /* ???????? */
        return OAL_FAIL;
    }

    /* ???????????????? */
    for (uc_cache_idx_i = 0; uc_cache_idx_i < (MAX_JUDGE_CACHE_LENGTH >> 1); uc_cache_idx_i++) {
        pst_judge_info = (hmac_tx_judge_info_stru *)(pst_judge_list->ast_judge_cache + uc_cache_idx_i);

        if (pst_judge_info->uc_flag == OAL_FALSE) {
            continue;
        }

        pst_judge_info->uc_flag = OAL_FALSE;
        if (memcpy_s(&st_mark, OAL_SIZEOF(hmac_tx_major_flow_stru),
                     pst_judge_info, OAL_SIZEOF(hmac_tx_judge_info_stru)) != EOK) {
            OAM_ERROR_LOG0(0, OAM_SF_ANY, "hmac_tx_find_major_traffic::memcpy fail!");
            return OAL_FAIL;
        }
        st_mark.ul_wait_check_num = 1;

        for (uc_cache_idx_j = 0; uc_cache_idx_j < MAX_JUDGE_CACHE_LENGTH; uc_cache_idx_j++) {
            pst_judge_info = (hmac_tx_judge_info_stru *)(pst_judge_list->ast_judge_cache + uc_cache_idx_j);

            if ((pst_judge_info->uc_flag == OAL_TRUE) && !oal_memcmp(&pst_judge_info->st_flow_info,
                                                                     &st_mark.st_flow_info,
                                                                     OAL_SIZEOF(hmac_tx_flow_info_stru))) {
                pst_judge_info->uc_flag = OAL_FALSE;
                st_mark.ul_average_len += pst_judge_info->ul_len;
                st_mark.ul_wait_check_num += 1;
            }

            if (st_mark.ul_wait_check_num > st_max.ul_wait_check_num) {
                memcpy_s(&st_max, OAL_SIZEOF(hmac_tx_major_flow_stru),
                         &st_mark, OAL_SIZEOF(hmac_tx_major_flow_stru));
                if (st_max.ul_wait_check_num >= (MAX_JUDGE_CACHE_LENGTH >> 1)) {
                    /* ?????????????????????????????? */
                    st_max.ul_average_len = st_max.ul_average_len / st_max.ul_wait_check_num;
                    return hmac_tx_traffic_judge(pst_hmac_user, &st_max, puc_tid);
                }
            }
        }
    }
    /* ????????????????????????????????????5??MAX_JUDGE_CACHE_LENGTH????2???? */
    if (st_max.ul_wait_check_num < (MAX_JUDGE_CACHE_LENGTH >> 2)) {
        /* ?????????????????? */
        pst_hmac_user->st_judge_list.ul_to_judge_num = 0; /* ???????? */
        pst_hmac_user->us_clear_judge_count += 1;
        return OAL_FAIL;
    }

    st_max.ul_average_len = st_max.ul_average_len / st_max.ul_wait_check_num;
    return hmac_tx_traffic_judge(pst_hmac_user, &st_max, puc_tid);
}


oal_void hmac_tx_traffic_classify(mac_tx_ctl_stru *pst_tx_ctl,
                                  mac_ip_header_stru *pst_ip,
                                  oal_uint8 *puc_tid)
{
    udp_hdr_stru *pst_udp_hdr = OAL_PTR_NULL;
    hmac_tx_rtp_hdr *pst_rtp_hdr = OAL_PTR_NULL;
    hmac_tx_flow_info_stru st_flow_info;

    hmac_tx_judge_list_stru *pst_judge_list = OAL_PTR_NULL;
    hmac_tx_judge_info_stru *pst_judge_info = OAL_PTR_NULL;
    hmac_tx_cfm_flow_stru *pst_cfm_info = OAL_PTR_NULL;

    oal_uint8 uc_rtp_payload_type;
    oal_uint8 uc_rtp_ver;

    oal_uint8 uc_loop;
    oal_uint32 ul_ret;
    hmac_user_stru *pst_hmac_user = (hmac_user_stru *)mac_res_get_hmac_user(MAC_GET_CB_TX_USER_IDX(pst_tx_ctl));

    if (pst_hmac_user == OAL_PTR_NULL) {
        OAM_WARNING_LOG1(0, OAM_SF_TX, "hmac_tx_traffic_classify::cannot find hmac_user_stru[%d]!",
                         MAC_GET_CB_TX_USER_IDX(pst_tx_ctl));
        return;
    }

    /* ????????????????UDP???? */
    if (pst_ip->uc_protocol == MAC_TCP_PROTOCAL) {
        /* RTSP ??????????????hmac_tx_classify_lan_to_wlan?? */
        return;
    }

    /* ????IP???????????????????????????? */
    if ((oal_ntoh_16(pst_ip->us_frag_off) & IP_FRAGMENT_MASK) != 0) {
        return;
    }

    pst_udp_hdr = (udp_hdr_stru *)(pst_ip + 1); /* ????????IP??????UDP?? */

    /* ?????????? */
    st_flow_info.us_dport = pst_udp_hdr->us_des_port;
    st_flow_info.us_sport = pst_udp_hdr->us_src_port;
    st_flow_info.ul_dip = pst_ip->ul_daddr;
    st_flow_info.ul_sip = pst_ip->ul_saddr;
    st_flow_info.ul_proto = (oal_uint32)(pst_ip->uc_protocol);

    /* ??????????????????????????????????TID */
    for (uc_loop = 0; uc_loop < pst_hmac_user->uc_cfm_num; uc_loop++) {
        pst_cfm_info = (hmac_tx_cfm_flow_stru *)(pst_hmac_user->ast_cfm_flow_list + uc_loop);

        if (!oal_memcmp(&pst_cfm_info->st_cfm_flow_info,
                        &st_flow_info,
                        OAL_SIZEOF(hmac_tx_flow_info_stru))) {
            *puc_tid = (oal_uint8)(pst_cfm_info->us_cfm_tid);
            pst_cfm_info->ul_last_jiffies = OAL_TIME_JIFFY; /* ???????????????????? */
            return;
        }
    }

    /* ???????????????????????????????? */
    pst_judge_list = &(pst_hmac_user->st_judge_list);
    pst_judge_info = (hmac_tx_judge_info_stru *)(pst_judge_list->ast_judge_cache + pst_judge_list->ul_to_judge_num);

    if (pst_judge_list->ul_to_judge_num >= MAX_JUDGE_CACHE_LENGTH) { /* ?????????????????????????????????? */
        return;
    }

    pst_judge_list->ul_jiffies_end = OAL_TIME_JIFFY; /* ???????????????? */
    if (pst_judge_list->ul_to_judge_num == 0) { /* ?????????? */
        pst_judge_list->ul_jiffies_st = OAL_TIME_JIFFY; /* ???????????????? */
    }
    pst_judge_list->ul_to_judge_num += 1; /* ???????????? */

    memset_s(pst_judge_info, OAL_SIZEOF(hmac_tx_judge_info_stru), 0, OAL_SIZEOF(hmac_tx_judge_info_stru));
    memcpy_s(&(pst_judge_info->st_flow_info), OAL_SIZEOF(hmac_tx_flow_info_stru),
             &st_flow_info, OAL_SIZEOF(hmac_tx_flow_info_stru));

    pst_rtp_hdr = (hmac_tx_rtp_hdr *)(pst_udp_hdr + 1); /* ????????UDP??????RTP?? */

    pst_judge_info->uc_flag = OAL_TRUE;
    pst_judge_info->ul_len = OAL_NET2HOST_SHORT(pst_ip->us_tot_len) -
                             OAL_SIZEOF(mac_ip_header_stru) - OAL_SIZEOF(udp_hdr_stru);
    pst_judge_info->uc_rtpver = pst_rtp_hdr->uc_version_and_csrc;
    pst_judge_info->ul_payload_type = (oal_uint32)((pst_rtp_hdr->uc_payload_type) & (~BIT7));
    pst_judge_info->ul_rtpssrc = pst_rtp_hdr->ul_ssrc;

    /* ???????????????????????????????????????? */
    if ((pst_hmac_user->us_clear_judge_count < MAX_CLEAR_JUDGE_TH) &&
        (pst_judge_list->ul_to_judge_num >= 1)) {
        uc_rtp_payload_type = (pst_rtp_hdr->uc_payload_type) & (~BIT7);
        uc_rtp_ver = pst_rtp_hdr->uc_version_and_csrc >> RTP_VER_SHIFT;
        if (uc_rtp_ver == RTP_VERSION) {
            if (uc_rtp_payload_type == RTP_PT_VO_G729) {
                oam_warning_log2(0, 0, "rtp seq=0x%x tid=%d to WLAN_TIDNO_VOICE", pst_rtp_hdr->us_rtp_idx, *puc_tid);
                *puc_tid = WLAN_TIDNO_VOICE;
            } else if ((uc_rtp_payload_type == RTP_PT_VI_CELB) || (uc_rtp_payload_type == RTP_PT_VI_JPEG) ||
                       (uc_rtp_payload_type == RTP_PT_VI_NV) || ((uc_rtp_payload_type >= RTP_PT_VI_H261) &&
                                                                 (uc_rtp_payload_type <= RTP_PT_VI_H263))) {
                oam_warning_log2(0, 0, "rtp seq=0x%x tid=%d to WLAN_TIDNO_VIDEO", pst_rtp_hdr->us_rtp_idx,
                                 *puc_tid);
                *puc_tid = WLAN_TIDNO_VIDEO;
            }
        }
    }

    /* ???????????????????????????????????????????????????? */
    if (pst_judge_list->ul_to_judge_num >= MAX_JUDGE_CACHE_LENGTH) {
        ul_ret = hmac_tx_find_major_traffic(pst_hmac_user, puc_tid);
        if (ul_ret != OAL_SUCC) {
            oam_info_log0(0, OAM_SF_TX, "hmac_tx_traffic_classify::the classify process failed.");
        }
    }
}
oal_module_symbol(hmac_tx_traffic_classify);
