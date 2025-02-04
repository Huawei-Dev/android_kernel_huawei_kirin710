

#ifndef __DMAC_RX_DATA_H__
#define __DMAC_RX_DATA_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "oal_ext_if.h"
#include "frw_ext_if.h"
#include "hal_ext_if.h"
#include "dmac_vap.h"
#include "dmac_ext_if.h"
#include "dmac_main.h"
#include "dmac_uapsd.h"
#include "dmac_alg.h"
#include "dmac_psm_ap.h"
#include "dmac_uapsd.h"
#include "dmac_11i.h"
#include "dmac_arp_offload.h"
#include "oam_ext_if.h"
#include "mac_device.h"

#ifdef _PRE_WLAN_FEATURE_STA_PM
#include "dmac_psm_sta.h"
#endif
#if _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE
#include "pm_extern.h"
#endif

#undef  THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_DMAC_RX_DATA_H

/*****************************************************************************
  2 ??????
*****************************************************************************/
#ifdef _PRE_WLAN_DFT_STAT
#define DMAC_EVALUATED_AVG_PADDING_LEN   2
#endif

#define DMAC_STAT_RX_PKT_COUNT (2048)
#define DMAC_STAT_RX_PKT_COUNT_OFFSET (11)

/*****************************************************************************
  3 ????????
*****************************************************************************/



/*****************************************************************************
  4 ????????????
*****************************************************************************/


/*****************************************************************************
  5 ??????????
*****************************************************************************/


/*****************************************************************************
  6 ????????
*****************************************************************************/


/*****************************************************************************
  7 STRUCT????
*****************************************************************************/
/* MAC ERROR?????????????? */
typedef struct
{
    oal_void      (* p_func)(mac_device_stru *pst_dev, oal_uint32 ul_para);
    oal_uint32    ul_param;
}dmac_error_proc_stru;


/*****************************************************************************
  8 UNION????
*****************************************************************************/


/*****************************************************************************
  9 OTHERS????
*****************************************************************************/
#ifdef _PRE_WLAN_FEATURE_IP_FILTER
extern dmac_rx_frame_ctrl_enum_uint8 dmac_rx_ip_filter_process(dmac_vap_stru *pst_dmac_vap, oal_netbuf_stru *pst_netbuf, dmac_rx_ctl_stru *pst_cb_ctrl);
#endif //_PRE_WLAN_FEATURE_IP_FILTER
extern oal_uint32  dmac_rx_filter_frame_ap(
                mac_vap_stru               *pst_vap,
                dmac_rx_ctl_stru           *pst_cb_ctrl);
extern oal_uint32  dmac_rx_filter_frame_sta(
                mac_vap_stru               *pst_vap,
                dmac_rx_ctl_stru           *pst_cb_ctrl,
                dmac_user_stru             *pst_dmac_user);
extern oal_bool_enum_uint8  dmac_rx_check_mgmt_replay_failure(dmac_rx_ctl_stru  *pst_cb_ctrl);

#if (!defined(_PRE_PRODUCT_ID_HI110X_DEV))

OAL_STATIC OAL_INLINE oal_void  dmac_rx_fcs_statistic_info(
                mac_ieee80211_frame_stru    *pst_frame_hdr,
                mac_vap_stru                *pst_vap,
                dmac_rx_ctl_stru            *pst_cb_ctrl)
{
    oal_uint8   *puc_destination_addr;  /* ???????? */
    oal_uint32   ul_mac_addr_cmp;       /* MAC ADDR????????????0 */

    /* ???????????? */
    mac_rx_get_da(pst_frame_hdr, &puc_destination_addr);

    g_ast_rx_fcs_statistic[pst_vap->uc_vap_id].ul_total_num++;

    if (HAL_RX_SUCCESS == pst_cb_ctrl->st_rx_status.bit_dscr_status)            /* FCS???? */
    {
        /* ?????????????????????? */
        ul_mac_addr_cmp = oal_compare_mac_addr(pst_vap->pst_mib_info->st_wlan_mib_sta_config.auc_dot11StationID, puc_destination_addr);
        if (0 == ul_mac_addr_cmp)   /* ???????? */
        {
            g_ast_rx_fcs_statistic[pst_vap->uc_vap_id].ul_self_fcs_correct++;
        }
        else
        {
            g_ast_rx_fcs_statistic[pst_vap->uc_vap_id].ul_other_fcs_correct++;
        }
    }
    else if (HAL_RX_FCS_ERROR == pst_cb_ctrl->st_rx_status.bit_dscr_status)     /* FCS???? */
    {
        /* ?????????????????????????????????? */
        g_ast_rx_fcs_statistic[pst_vap->uc_vap_id].ul_total_fcs_error++;
    }
}
#endif


OAL_STATIC OAL_INLINE oal_void  dmac_rx_get_dscr_info(
                hal_to_dmac_device_stru    *pst_device,
                oal_uint32                 *pul_dscr,
                dmac_rx_ctl_stru           *pst_cb_ctrl)
{
    hal_rx_ctl_stru *pst_hal_rx_ctl;
    oal_uint32       ul_rx_dscr_len;

    pst_hal_rx_ctl = (hal_rx_ctl_stru *)pst_cb_ctrl;

    /* ?????????????????? */
    hal_rx_get_info_dscr(pst_device,
                         pul_dscr,
                         pst_hal_rx_ctl,
                         &pst_cb_ctrl->st_rx_status,
                         &pst_cb_ctrl->st_rx_statistic);

    if (OAL_UNLIKELY(MAC_GET_RX_CB_MAC_HEADER_LEN(&(pst_cb_ctrl->st_rx_info)) > pst_cb_ctrl->st_rx_info.us_frame_len))
    {
        hal_rx_get_size_dscr(pst_device, &ul_rx_dscr_len);
        oam_report_dscr(BROADCAST_MACADDR, (oal_uint8 *)pul_dscr, (oal_uint16)ul_rx_dscr_len, OAM_OTA_TYPE_RX_DSCR);
    }
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC != _PRE_MULTI_CORE_MODE)
    mac_set_rx_cb_mac_hdr(&(pst_cb_ctrl->st_rx_info), pst_hal_rx_ctl->pul_mac_hdr_start_addr);
#endif
   // pst_cb_ctrl->st_rx_info.pul_mac_hdr_start_addr   = st_hal_rx_ctl.pul_mac_hdr_start_addr;
}


OAL_STATIC OAL_INLINE oal_uint32  dmac_rx_data_ps_process(
                mac_device_stru        *pst_mac_device,
                dmac_vap_stru          *pst_dmac_vap,
                dmac_user_stru         *pst_dmac_user,
                oal_netbuf_stru        *pst_netbuf,
                dmac_rx_ctl_stru       *pst_cb_ctrl)
{

    if (WLAN_VAP_MODE_BSS_STA == dmac_vap_get_bss_type(&(pst_dmac_vap->st_vap_base_info)))
    {
#ifdef _PRE_WLAN_FEATURE_STA_PM
        /* ??????????????
           ????????????????????????????????????????????????????????DMAC_RX_FRAME_CTRL_DROP */
        if (DMAC_RX_FRAME_CTRL_DROP == dmac_psm_rx_process_data_sta(pst_dmac_vap, pst_netbuf))
        {
            return OAL_FAIL;
        }
#endif

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
        if ((pst_cb_ctrl->st_rx_info.bit_amsdu_enable != OAL_TRUE) &&
            (PM_WLAN_IsHostSleep() == OAL_TRUE) &&
            (pst_mac_device->uc_arpoffload_switch == OAL_TRUE))
        {
            mac_llc_snap_stru           *pst_snap;

            pst_snap = (mac_llc_snap_stru *)oal_netbuf_data(pst_netbuf);
            if ((pst_snap != OAL_PTR_NULL) && (pst_snap->uc_llc_dsap != SNAP_LLC_LSAP))
            {
                return OAL_FAIL;
            }
        }
#endif /* _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE */
    }
    else if (WLAN_VAP_MODE_BSS_AP == dmac_vap_get_bss_type(&(pst_dmac_vap->st_vap_base_info)))
    {
        /* psm???????? */
        dmac_psm_rx_process(pst_dmac_vap, pst_dmac_user, pst_netbuf);

#ifdef _PRE_WLAN_FEATURE_UAPSD
        /* uapsd???????? */
        dmac_uapsd_rx_trigger_check( pst_dmac_vap, pst_dmac_user, pst_netbuf);
#endif
    }

#ifndef _PRE_WLAN_PROFLING_MIPS
     /* arp offload ?????????????????????????? */
#ifdef _PRE_WLAN_FEATURE_ARP_OFFLOAD
    if (DMAC_RX_FRAME_CTRL_DROP == dmac_ao_process_arp_and_mcast(pst_dmac_vap, pst_dmac_user, pst_netbuf))
    {
        g_ul_arpoffload_drop_frame++;
        return OAL_FAIL;
    }
#endif
#endif /* _PRE_WLAN_PROFLING_MIPS */

    return OAL_SUCC;
}


OAL_STATIC OAL_INLINE oal_void dmac_rx_rssi_rate_stat(dmac_user_stru *pst_dmac_user, hal_rx_statistic_stru *pst_rx_stats, mac_device_stru *pst_mac_device)
{
    hal_to_dmac_device_stru *pst_hal_device;
    oal_uint32 ul_rate_kbps = 0;

    pst_hal_device = pst_mac_device->pst_device_stru;

    pst_hal_device->l_rx_rssi = pst_rx_stats->c_rssi_dbm;

    /* ???????????? */
    dmac_alg_get_rate_by_table(&pst_dmac_user->st_user_base_info, pst_rx_stats, &ul_rate_kbps);

    pst_hal_device->ul_rx_rate = ul_rate_kbps;
    pst_dmac_user->ul_rx_rate = ul_rate_kbps;
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC != _PRE_MULTI_CORE_MODE)
    if (ul_rate_kbps > pst_dmac_user->ul_rx_rate_max)
    {
        pst_dmac_user->ul_rx_rate_max = ul_rate_kbps;
    }

    if ((0 == pst_dmac_user->ul_rx_rate_min) || (ul_rate_kbps < pst_dmac_user->ul_rx_rate_min))
    {
        pst_dmac_user->ul_rx_rate_min = ul_rate_kbps;
    }
#endif
}


OAL_STATIC OAL_INLINE oal_uint32  dmac_rx_process_data_frame(
                mac_vap_stru                   *pst_vap,
                dmac_rx_ctl_stru               *pst_cb_ctrl,
                oal_netbuf_stru                *pst_netbuf)
{
    dmac_vap_stru                      *pst_dmac_vap;
    dmac_user_stru                     *pst_dmac_user;
    mac_ieee80211_frame_stru           *pst_frame_hdr;
    mac_device_stru                    *pst_mac_device;

    pst_dmac_vap  = (dmac_vap_stru *)mac_res_get_dmac_vap(pst_vap->uc_vap_id);
    pst_dmac_user = (dmac_user_stru *)mac_res_get_dmac_user(MAC_GET_RX_CB_TA_USER_IDX(&(pst_cb_ctrl->st_rx_info)));
   // pst_frame_hdr = (mac_ieee80211_frame_stru *)(pst_cb_ctrl->st_rx_info.pul_mac_hdr_start_addr);
    pst_frame_hdr = (mac_ieee80211_frame_stru *)(mac_get_rx_cb_mac_hdr(&(pst_cb_ctrl->st_rx_info)));

    if (OAL_PTR_NULL == pst_dmac_user)
    {
        OAM_ERROR_LOG0(pst_vap->uc_vap_id, OAM_SF_RX, "{dmac_rx_process_feature::pst_dmac_user null.}");

        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ??????:??????????MPDU??????netbuf????????????mac_rx_ctl_stru???????? */
    dmac_alg_rx_notify(pst_vap,
                                &(pst_dmac_user->st_user_base_info),
                                pst_netbuf,
                                &pst_cb_ctrl->st_rx_statistic);

    pst_mac_device = mac_res_get_dev(pst_vap->uc_device_id);
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mac_device))
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{dmac_rx_process_feature::pst_mac_device[%d] null!}", pst_vap->uc_device_id);
        return OAL_ERR_CODE_PTR_NULL;
    }

    dmac_rx_rssi_rate_stat(pst_dmac_user, &pst_cb_ctrl->st_rx_statistic, pst_mac_device);

    /* ??????:DMAC???????????????? */
    if (OAL_SUCC != dmac_rx_data_ps_process(pst_mac_device, pst_dmac_vap, pst_dmac_user, pst_netbuf, pst_cb_ctrl))
    {
        return OAL_FAIL;
    }

    /* ??????:????????????????MPDU */
    if ((WLAN_NULL_FRAME == pst_frame_hdr->st_frame_control.bit_sub_type)
     || (WLAN_QOS_NULL_FRAME == pst_frame_hdr->st_frame_control.bit_sub_type))
    {
        /* ?????????????? */
        //OAM_INFO_LOG0(pst_vap->uc_vap_id, OAM_SF_RX, "dmac_rx_process_data_frame: the frame is a null frame");
        OAM_STAT_VAP_INCR(pst_vap->uc_vap_id, rx_null_frame_dropped, 1);
        DMAC_VAP_DFT_STATS_PKT_INCR(pst_dmac_vap->st_query_stats.ul_rx_null_frame_dropped, 1);

        return OAL_FAIL;
    }

    /* ??????:????ip???????????? */
#ifdef _PRE_WLAN_FEATURE_IP_FILTER
    if (DMAC_RX_FRAME_CTRL_DROP == dmac_rx_ip_filter_process(pst_dmac_vap, pst_netbuf, pst_cb_ctrl))
    {
        return OAL_FAIL;
    }
#endif //_PRE_WLAN_FEATURE_IP_FILTER

    return OAL_SUCC;
}


OAL_STATIC OAL_INLINE oal_uint32 dmac_rx_record_tid(mac_vap_stru  *pst_vap, mac_ieee80211_frame_stru  *pst_frame)
{
    mac_device_stru          *pst_mac_dev;
    oal_uint8                *pucTid = OAL_PTR_NULL;
    oal_uint8                ucTid = 0;

    if(OAL_UNLIKELY(OAL_PTR_NULL == pst_frame || OAL_PTR_NULL == pst_vap))
    {
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ????Qos Data */
    if((WLAN_DATA_BASICTYPE != pst_frame->st_frame_control.bit_type)
    || (WLAN_QOS_DATA != pst_frame->st_frame_control.bit_sub_type))
    {
        return OAL_FAIL;
    }

    pst_mac_dev = mac_res_get_dev(pst_vap->uc_device_id);
    if(OAL_PTR_NULL == pst_mac_dev)
    {
        return OAL_ERR_CODE_PTR_NULL;
    }

    pucTid = (oal_uint8 *)pst_frame + MAC_80211_FRAME_LEN;
    ucTid  = (*pucTid & 0xf); /* tid????QOS Ctl ????????4?? */
    pst_mac_dev->en_tid = ucTid;
    return OAL_SUCC;


}



OAL_STATIC OAL_INLINE oal_void dmac_rx_update_aggr_mib(mac_vap_stru *pst_vap, oal_uint16 us_mpdu_num)
{
    if ((0 == us_mpdu_num) || (0 == pst_vap->uc_vap_id))
    {
        return;
    }

    pst_vap->pst_mib_info->st_wlan_mib_counters.ul_dot11MPDUInReceivedAMPDUCount += us_mpdu_num;
}


OAL_STATIC OAL_INLINE oal_void  dmac_rx_update_mib_11n(mac_vap_stru *pst_vap, dmac_rx_ctl_stru *pst_cb_ctrl)
{
    /* ????ul_dot11ReceivedAMSDUCount?? */
    if (pst_cb_ctrl->st_rx_info.bit_amsdu_enable)
    {
        /* ????receive amsdu nums??*/
        pst_vap->pst_mib_info->st_wlan_mib_counters.ul_dot11ReceivedAMSDUCount++;

        /* ????receive amsdu nums??*/
        pst_vap->pst_mib_info->st_wlan_mib_counters.ull_dot11dot11ReceivedOctetsInAMSDUCount += pst_cb_ctrl->st_rx_info.us_frame_len;
    }
}

OAL_STATIC OAL_INLINE oal_void dmac_rx_pingpong_list_lock(hal_to_dmac_device_stru  *pst_device)
{
    /*AMP????????CPU????????MIPS????????SMP????????MAC RX????!*/
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    oal_irq_disable();
#else
    /*TBD:lock the mac rx irq,????????????0*/
    oal_irq_disable();
    #if (_PRE_TEST_MODE_UT != _PRE_TEST_MODE)
    hal_mask_interrupt(pst_device, 0);
    #endif
#endif
}

OAL_STATIC OAL_INLINE oal_void dmac_rx_pingpong_list_unlock(hal_to_dmac_device_stru  *pst_device)
{
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    oal_irq_enable();
#else
    /*TBD:unlock the mac rx irq,????????????0*/
    #if (_PRE_TEST_MODE_UT != _PRE_TEST_MODE)
    hal_unmask_interrupt(pst_device, 0);
    #endif
    oal_irq_enable();
#endif
}

/*****************************************************************************
  10 ????????
*****************************************************************************/
extern oal_uint32  dmac_rx_process_data_event(frw_event_mem_stru *pst_event_mem);
extern oal_uint32  dmac_mac_error_process_event(frw_event_mem_stru *pst_event_mem);
#if (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1151)
extern oal_uint32  dmac_soc_error_process_event(frw_event_mem_stru *pst_event_mem);
#endif
OAL_STATIC OAL_INLINE oal_uint32  dmac_rx_filter_mpdu(dmac_rx_ctl_stru *pst_cb_ctrl, oal_uint16 us_dscr_num)
{
    /* ??????????:??????????A-MSDU????????????????????MPDU?????????????? */
    if (OAL_UNLIKELY((OAL_TRUE == pst_cb_ctrl->st_rx_info.bit_amsdu_enable) && (OAL_FALSE == pst_cb_ctrl->st_rx_info.bit_is_first_buffer)))
    {
        //OAM_WARNING_LOG0(0, OAM_SF_RX, "{dmac_rx_filter_mpdu::the control netbuf is not the first netbuf of a amsdu.}");
        return OAL_ERR_CODE_RX_DSCR_AMSDU_DISORDER;
    }

    /* ??????????:??????buffer?????????????????????????? */
    if (OAL_UNLIKELY(pst_cb_ctrl->st_rx_info.bit_buff_nums > us_dscr_num))
    {
        //OAM_WARNING_LOG0(0, OAM_SF_RX, "{dmac_rx_filter_mpdu::the numbers of netbuf exceeds the remianing netbufs.}");
        return OAL_ERR_CODE_RX_DSCR_LOSE;
    }

    return OAL_SUCC;
}

OAL_STATIC OAL_INLINE oal_uint32  dmac_rx_filter_frame(
                                    mac_vap_stru           *pst_vap,
                                    dmac_rx_ctl_stru       *pst_cb_ctrl,
                                    dmac_user_stru             *pst_dmac_user)
{
    if (WLAN_VAP_MODE_BSS_AP == dmac_vap_get_bss_type(pst_vap))
    {
        return dmac_rx_filter_frame_ap(pst_vap, pst_cb_ctrl);
    }
    else if (WLAN_VAP_MODE_BSS_STA == dmac_vap_get_bss_type(pst_vap))
    {
        return dmac_rx_filter_frame_sta(pst_vap, pst_cb_ctrl, pst_dmac_user);
    }

    return OAL_FAIL;
}

extern dmac_rx_frame_ctrl_enum_uint8  dmac_rx_process_frame(
                mac_vap_stru                   *pst_vap,
                dmac_rx_ctl_stru               *pst_cb_ctrl,
                oal_netbuf_stru                *pst_netbuf,
                oal_netbuf_head_stru           *pst_netbuf_header);

#if 0
extern oal_uint32 dmac_start_stat_rssi(dmac_user_stru *pst_dmac_user);
extern oal_uint32 dmac_get_stat_rssi(dmac_user_stru *pst_dmac_user, oal_int8 *pc_tx_rssi, oal_int8 *pc_rx_rssi);
extern oal_uint32 dmac_stop_stat_rssi(dmac_user_stru *pst_dmac_user);
#endif
extern oal_uint32 dmac_get_stat_rate(dmac_user_stru *pst_dmac_user, oal_uint32 *pul_tx_rate, oal_uint32 *pul_rx_rate);


#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

#endif /* end of dmac_rx_data.h */
