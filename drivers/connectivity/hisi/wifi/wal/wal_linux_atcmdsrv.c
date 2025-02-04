


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "oal_ext_if.h"
#include "oal_profiling.h"
#include "oal_kernel_file.h"

#include "oam_ext_if.h"
#include "frw_ext_if.h"

#include "wlan_spec.h"
#include "wlan_types.h"

#include "mac_vap.h"
#include "mac_resource.h"
#include "mac_ie.h"
#include "hmac_resource.h"
#include "hmac_scan.h"

#include "hmac_ext_if.h"
#include "hmac_chan_mgmt.h"

#include "wal_main.h"
#include "wal_config.h"
#include "wal_regdb.h"
#include "wal_linux_scan.h"
#include "wal_linux_atcmdsrv.h"
#include "wal_linux_bridge.h"
#include "wal_linux_flowctl.h"
#include "wal_linux_event.h"

#if ((defined(_PRE_PRODUCT_ID_HI110X_DEV)) || (defined(_PRE_PRODUCT_ID_HI110X_HOST)))
#include "plat_cali.h"
#include "oal_hcc_host_if.h"
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/pinctrl/consumer.h>
#include "board.h"
#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
#include "hisi_customize_wifi.h"
#endif /* #ifdef _PRE_PLAT_FEATURE_CUSTOMIZE */
#endif
#endif

#undef  THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_WAL_LINUX_ATCMDSRV_C

/*****************************************************************************
  2 ??????????
*****************************************************************************/
#if (defined(_PRE_PRODUCT_ID_HI110X_DEV) || defined(_PRE_PRODUCT_ID_HI110X_HOST))
typedef enum
{
    CHECK_LTE_GPIO_INIT            = 0,    /* ?????? */
    CHECK_LTE_GPIO_LOW             = 1,    /* ???????????? */
    CHECK_LTE_GPIO_HIGH            = 2,    /*???????????? */
    CHECK_LTE_GPIO_RESUME          = 3,    /*?????????????? */
    CHECK_LTE_GPIO_DEV_LEVEL       = 4,    /*????device GPIO??????????*/
    CHECK_LTE_GPIO_BUTT
}check_lte_gpio_step;

typedef struct
{
    oal_uint8                     uc_mode;          /* ????*/
    oal_uint8                     uc_band;          /* ???? */
}wal_atcmdsrv_mode_stru;

typedef struct
{
    oal_uint32                   ul_datarate;          /* at???????????????? */
    oal_int8                    *puc_datarate;          /* ??????????*/
}wal_atcmdsrv_datarate_stru;

OAL_CONST wal_atcmdsrv_mode_stru g_ast_atcmdsrv_mode_table[] =
{
    {WLAN_LEGACY_11A_MODE, WLAN_BAND_5G},    /* 11a, 5G, OFDM */
    {WLAN_LEGACY_11B_MODE, WLAN_BAND_2G},    /* 11b, 2.4G */
    {WLAN_LEGACY_11G_MODE, WLAN_BAND_2G},    /* ????11g only??????, 2.4G, OFDM */
    {WLAN_MIXED_ONE_11G_MODE, WLAN_BAND_2G},    /* 11bg, 2.4G */
    {WLAN_MIXED_TWO_11G_MODE, WLAN_BAND_2G},    /* 11g only, 2.4G */
    {WLAN_HT_MODE, WLAN_BAND_5G},    /* 11n(11bgn????11an??????????????) */
    {WLAN_VHT_MODE, WLAN_BAND_5G},    /* 11ac */
    {WLAN_HT_ONLY_MODE, WLAN_BAND_5G},    /* 11n only 5Gmode,??????HT???????????????? */
    {WLAN_VHT_ONLY_MODE, WLAN_BAND_5G},    /* 11ac only mode ??????VHT???????????????? */
    {WLAN_HT_11G_MODE, WLAN_BAND_2G},    /* 11ng,??????11b*/
    {WLAN_HT_ONLY_MODE_2G, WLAN_BAND_2G},/* 11nonlg 2Gmode*/
    {WLAN_VHT_ONLY_MODE_2G, WLAN_BAND_2G},    /* 11ac 2g mode ??????VHT???????????????? */
    {WLAN_PROTOCOL_BUTT,WLAN_BAND_2G},
};

OAL_STATIC OAL_CONST wal_atcmdsrv_datarate_stru   past_atcmdsrv_non_ht_rate_table[] =
{
    {1," 1 "},
    {2," 2 "},
    {5," 5.5 "},
    {6," 6 "},
    {7," 7 "},
    {8," 8 "},
    {9," 9 "},
    {11," 11 "},
    {12," 12 "},
    {18," 18 "},
    {24," 24 "},
    {36," 36 "},
    {48," 48 "},
    {54," 54 "},
};
oal_uint8 uc_channel_idx[WAL_ATCMDSRV_CHANNEL_NUM] ={48,64,112,128,144,165};
oal_uint64                      ul_chipcheck_total_time;
oal_uint16                      g_us_efuse_buffer[WAL_ATCMDSRV_EFUSE_BUFF_LEN];

wal_efuse_bits                  *st_efuse_bits = OAL_PTR_NULL;
oal_int32                       g_l_bandwidth;
oal_int32                       g_l_mode;

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
extern BOARD_INFO               g_board_info;
#endif

#ifdef _PRE_WLAN_FEATURE_SMARTANT
wal_atcmdsrv_ant_info_stru g_st_atcmdsrv_ant_info;
#endif

#endif
extern oal_int32 wal_ioctl_reduce_sar(oal_net_device_stru *pst_net_dev, oal_uint8 uc_tx_power);
extern oal_uint32  wal_hipriv_sta_pm_on(oal_net_device_stru * pst_cfg_net_dev, oal_int8 * pc_param);


/*****************************************************************************
  3 ????????
*****************************************************************************/

oal_int32  wal_atcmsrv_ioctl_get_rx_pckg(oal_net_device_stru *pst_net_dev, oal_int32 *pl_rx_pckg_succ_num)
{
    oal_int32                   l_ret;
    mac_cfg_rx_fcs_info_stru   *pst_rx_fcs_info;
    wal_msg_write_stru          st_write_msg;
    mac_vap_stru               *pst_mac_vap;
    hmac_vap_stru              *pst_hmac_vap;
    oal_int32                   i_leftime;

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_dbb_num::OAL_NET_DEV_PRIV, return null!}");
        return -OAL_EINVAL;
    }

    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ANY,"{wal_atcmsrv_ioctl_get_dbb_num::mac_res_get_hmac_vap failed!}");
        return OAL_FAIL;
    }

    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    pst_hmac_vap->st_atcmdsrv_get_status.uc_get_rx_pkct_flag = OAL_FALSE;
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_RX_FCS_INFO, OAL_SIZEOF(mac_cfg_rx_fcs_info_stru));

    /* ???????????????? */
    pst_rx_fcs_info = (mac_cfg_rx_fcs_info_stru *)(st_write_msg.auc_value);
    /*????????????02????????????*/
    pst_rx_fcs_info->ul_data_op    = 1;
    pst_rx_fcs_info->ul_print_info = 0;

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_rx_fcs_info_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_hipriv_rx_fcs_info::return err code %d!}\r\n", l_ret);
        return l_ret;
    }

    /*????????dmac????*/
    i_leftime = OAL_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(pst_hmac_vap->query_wait_q,(oal_uint32)(OAL_TRUE == pst_hmac_vap->st_atcmdsrv_get_status.uc_get_rx_pkct_flag),WAL_ATCMDSRB_GET_RX_PCKT);

    if ( 0 == i_leftime)
    {
        /* ?????????????????????? */
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_rx_pckg::dbb_num wait for %ld ms timeout!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else if (i_leftime < 0)
    {
        /* ?????????????? */
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_rx_pckg::dbb_num wait for %ld ms error!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else
    {
        /* ????????  */
        OAM_INFO_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_rx_pckg::dbb_num wait for %ld ms error!}",
                      ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        *pl_rx_pckg_succ_num = (oal_int)pst_hmac_vap->st_atcmdsrv_get_status.ul_rx_pkct_succ_num;
        return OAL_SUCC;
    }
}


oal_int32  wal_atcmsrv_ioctl_set_hw_addr(oal_net_device_stru *pst_net_dev, oal_uint8 *pc_hw_addr)
{
    oal_int32                       l_ret;
    mac_cfg_staion_id_param_stru   *pst_mac_cfg_para;
    wal_msg_write_stru              st_write_msg;


    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_STATION_ID, OAL_SIZEOF(mac_cfg_staion_id_param_stru));

    /* ???????????????? */
    pst_mac_cfg_para = (mac_cfg_staion_id_param_stru *)(st_write_msg.auc_value);
    /*????????????02????????????*/
    pst_mac_cfg_para->en_p2p_mode = WLAN_LEGACY_VAP_MODE;
    oal_set_mac_addr(pst_mac_cfg_para->auc_station_id, pc_hw_addr);

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_staion_id_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

#ifdef _PRE_WLAN_FEATURE_EQUIPMENT_TEST
    wal_hipriv_wait_rsp(pst_net_dev, pc_hw_addr);
#endif

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_hipriv_rx_fcs_info::return err code %d!}\r\n", l_ret);
        return l_ret;
    }
    return OAL_SUCC;
}

#if (defined(_PRE_PRODUCT_ID_HI110X_DEV) || defined(_PRE_PRODUCT_ID_HI110X_HOST))

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_set_freq(oal_net_device_stru *pst_net_dev, oal_int32 l_freq)
{
    wal_msg_write_stru          st_write_msg;

    oal_int32                   l_ret;

    OAM_WARNING_LOG1(0, OAM_SF_ANY, "wal_atcmsrv_ioctl_set_freq:l_freq[%d]", l_freq);
    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /* ???????? */
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CURRENT_CHANEL, OAL_SIZEOF(oal_int32));
    *((oal_int32 *)(st_write_msg.auc_value)) = l_freq;

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(oal_int32),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_freq::return err code %d!}", l_ret);
        return l_ret;
    }

    return OAL_SUCC;
}

OAL_STATIC oal_int32 wal_atcmsrv_ioctl_set_country(oal_net_device_stru *pst_net_dev, oal_int8 *puc_countrycode)
{
#ifdef _PRE_WLAN_FEATURE_11D
    oal_int32       l_ret;

    l_ret = wal_regdomain_update_for_dfs(pst_net_dev, puc_countrycode);
    if (OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_country::regdomain_update_for_dfs return err code %d!}\r\n", l_ret);
        return l_ret;
    }

    l_ret = wal_regdomain_update(pst_net_dev, puc_countrycode);
    if(OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_country::regdomain_update return err code %d!}\r\n", l_ret);
        return l_ret;
    }
#endif
    return OAL_SUCC;
}

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_set_txpower(oal_net_device_stru *pst_net_dev, oal_int32 l_txpower)
{
    wal_msg_write_stru          st_write_msg;

    oal_int32                   l_ret;

    OAM_WARNING_LOG1(0, OAM_SF_ANY, "wal_atcmsrv_ioctl_set_txpower:l_txpower[%d]", l_txpower);

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /* ???????? */
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_TX_POWER, OAL_SIZEOF(oal_int32));
    *((oal_int32 *)(st_write_msg.auc_value)) = l_txpower;

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(oal_int32),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_txpower::return err code %d!}", l_ret);
        return l_ret;
    }

    return OAL_SUCC;
}

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_set_mode(oal_net_device_stru *pst_net_dev, oal_int32 l_mode)
{
    wal_msg_write_stru          st_write_msg;
    mac_cfg_mode_param_stru    *pst_mode_param;
    oal_uint8                   uc_prot_idx;
    mac_vap_stru                *pst_mac_vap;

    oal_int32                   l_ret = 0;

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_mode::OAL_NET_DEV_PRIV, return null!}");
        return -OAL_EINVAL;
    }

    /*??????????????band*/
    for (uc_prot_idx = 0; uc_prot_idx < WAL_ATCMDSRV_IOCTL_MODE_NUM; uc_prot_idx++)
    {
        if (g_ast_atcmdsrv_mode_table[uc_prot_idx].uc_mode == (oal_uint8)l_mode)
        {
            break;
        }
    }

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /* ???????? */
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_MODE, OAL_SIZEOF(mac_cfg_mode_param_stru));

    /*??????????????????????????????????????20M*/
    pst_mode_param = (mac_cfg_mode_param_stru *)(st_write_msg.auc_value);
    if(WLAN_HT_ONLY_MODE_2G == l_mode)
    {
        pst_mode_param->en_protocol  = WLAN_HT_ONLY_MODE;
    }
    else if(WLAN_VHT_ONLY_MODE_2G == l_mode)
    {
        pst_mode_param->en_protocol  = WLAN_VHT_MODE;
    }
    else
    {
        pst_mode_param->en_protocol  = (oal_uint8)l_mode;
    }
    if (uc_prot_idx >= WAL_ATCMDSRV_IOCTL_MODE_NUM)
    {
        OAM_ERROR_LOG1(0,OAM_SF_ANY,"{wal_atcmsrv_ioctl_set_mode:err code[%u]}",uc_prot_idx);
        return l_ret;
    }
    pst_mode_param->en_band      = (wlan_channel_band_enum_uint8)g_ast_atcmdsrv_mode_table[uc_prot_idx].uc_band;
    pst_mode_param->en_bandwidth = WLAN_BAND_WIDTH_20M;
    /*????????????????????*/
    OAM_WARNING_LOG3(pst_mac_vap->uc_vap_id, OAM_SF_CFG, "{wal_atcmsrv_ioctl_set_mode::protocol[%d],band[%d],bandwidth[%d]!}\r\n",
                            pst_mode_param->en_protocol, pst_mode_param->en_band, pst_mode_param->en_bandwidth);

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_mode_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_mode::return err code %d!}\r\n", l_ret);
        return l_ret;
    }
    g_l_mode = pst_mode_param->en_protocol;
    return OAL_SUCC;
}

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_set_datarate(oal_net_device_stru *pst_net_dev, oal_int32 l_datarate)
{
    oal_uint8                   uc_prot_idx;
    oal_uint32                  ul_ret;
    mac_vap_stru                *pst_mac_vap;
    oal_uint8                   en_bw_index = 0;
    mac_cfg_tx_comp_stru        *pst_set_bw_param;
    wal_msg_write_stru          st_write_msg;
    oal_int32                   l_ret;

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_datarate::OAL_NET_DEV_PRIV, return null!}");
        return -OAL_EINVAL;
    }


    OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "wal_atcmsrv_ioctl_set_datarate:l_datarate[%d]", l_datarate);

    /*??????????????????????????????????????????????*/
    for (uc_prot_idx = 0; uc_prot_idx < WAL_ATCMDSRV_IOCTL_DATARATE_NUM; uc_prot_idx++)
    {
        if (past_atcmdsrv_non_ht_rate_table[uc_prot_idx].ul_datarate == (oal_uint32)l_datarate)
        {
            break;
        }
    }
    if (uc_prot_idx >= WAL_ATCMDSRV_IOCTL_DATARATE_NUM)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY,"uc_prot_idx Overrunning!");
        return -OAL_EINVAL;
    }
    if(WLAN_HT_ONLY_MODE == g_l_mode)/*????????????7??????MCS7*/
    {
        ul_ret = wal_hipriv_set_mcs(pst_net_dev,(oal_int8 *)past_atcmdsrv_non_ht_rate_table[uc_prot_idx].puc_datarate);
    }
    else if(WLAN_VHT_MODE == g_l_mode)
    {
        ul_ret = wal_hipriv_set_mcsac(pst_net_dev,(oal_int8 *)past_atcmdsrv_non_ht_rate_table[uc_prot_idx].puc_datarate);
    }
    else
    {
        ul_ret = wal_hipriv_set_rate(pst_net_dev,(oal_int8 *)past_atcmdsrv_non_ht_rate_table[uc_prot_idx].puc_datarate);
    }
    if (OAL_SUCC != ul_ret)
    {
        return -OAL_EFAIL;
    }
    /*??????????????????*/
   /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_SET_BW, OAL_SIZEOF(mac_cfg_tx_comp_stru));

    /* ?????????????????????? */
    pst_set_bw_param = (mac_cfg_tx_comp_stru *)(st_write_msg.auc_value);
    if ((WLAN_BAND_WIDTH_80PLUSPLUS <= g_l_bandwidth)
        && (g_l_bandwidth<=WLAN_BAND_WIDTH_80MINUSMINUS)) {
        en_bw_index = 8;
    }
    else if ((WLAN_BAND_WIDTH_40PLUS <= g_l_bandwidth)
        && (g_l_bandwidth<=WLAN_BAND_WIDTH_40MINUS)) {
        en_bw_index = 4;
    }
    else {
        en_bw_index = 0;
    }
    pst_set_bw_param->uc_param = (oal_uint8)(en_bw_index);

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_tx_comp_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret)) {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_hipriv_set_bw::return err code [%d]!}\r\n", l_ret);
        return l_ret;
    }
    return OAL_SUCC;
}

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_set_bandwidth(oal_net_device_stru *pst_net_dev, oal_int32 l_bandwidth)
{
    wal_msg_write_stru          st_write_msg;
    mac_cfg_mode_param_stru    *pst_mode_param;

    oal_int32                   l_ret;


    OAM_WARNING_LOG1(0, OAM_SF_ANY, "wal_atcmsrv_ioctl_set_bandwidth:l_bandwidth[%d]", l_bandwidth);
    g_l_bandwidth = l_bandwidth;

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /* ???????? */
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_BANDWIDTH, OAL_SIZEOF(oal_int32));

    /*??????????????????????????????????????????????*/
    pst_mode_param = (mac_cfg_mode_param_stru *)(st_write_msg.auc_value);

    pst_mode_param->en_bandwidth = (oal_uint8)l_bandwidth;

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_mode_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_mode::return err code %d!}\r\n", l_ret);
        return l_ret;
    }

    return OAL_SUCC;

}

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_set_always_tx(oal_net_device_stru *pst_net_dev,oal_int32 l_always_tx)
{
    wal_msg_write_stru               st_write_msg;
    oal_int32                        l_ret;
    mac_cfg_tx_comp_stru             *pst_set_bcast_param;
    oal_int8                          pc_param;
    oal_uint8                         auc_param[] = {"all"};
    oal_uint16                        us_len;


    OAM_WARNING_LOG1(0, OAM_SF_ANY, "wal_atcmsrv_ioctl_set_always_tx:l_always_tx[%d]", l_always_tx);

    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_SET_ALWAYS_TX_1102, OAL_SIZEOF(mac_cfg_tx_comp_stru));

    /* ?????????????????????? */
    pst_set_bcast_param = (mac_cfg_tx_comp_stru *)(st_write_msg.auc_value);

    /* ???????????????????????????????????? */
    pst_set_bcast_param->en_payload_flag = RF_PAYLOAD_ALL_ONE;
    pst_set_bcast_param->ul_payload_len = WAL_ATCMDSRB_IOCTL_AL_TX_LEN;
    pst_set_bcast_param->uc_param = (oal_uint8)l_always_tx;

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_tx_comp_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_always_tx::return err code [%d]!}", l_ret);
        return l_ret;
    }

    /*????????????*/
    l_ret = (oal_int32)wal_hipriv_vap_info(pst_net_dev,&pc_param);
    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_always_tx::return err code [%d]!}", l_ret);
    }
    /*??????????????*/
    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    oal_memcopy(st_write_msg.auc_value, auc_param, OAL_STRLEN((oal_int8*)auc_param));

    st_write_msg.auc_value[OAL_STRLEN((oal_int8*)auc_param)] = '\0';
    us_len = (oal_uint16)(OAL_STRLEN((oal_int8*)auc_param) + 1);

    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_REG_INFO, us_len);

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_always_tx::return err code [%d]!}\r\n", l_ret);
    }

    return OAL_SUCC;
}



OAL_STATIC oal_void wal_atcmdsrv_ioctl_convert_dbb_num(oal_uint32 ul_dbb_num,oal_uint8 *pc_dbb_num)
{
    oal_uint8  uc_temp          = 0;

    /* MAC H/w version register format                  */
    /* ------------------------------------------------ */
    /* | 31 - 24 | 23 - 16 | 15 - 12 | 11 - 0 | */
    /* ------------------------------------------------ */
    /* | BN      | Y1      | Y2      |   Y3   | */
    /* ------------------------------------------------ */

    /* Format the version as BN.Y1.Y2.Y3 with all values in hex i.e. the  */
    /* version string would be XX.XX.X.XXX.                                 */
    /* For e.g. 0225020A saved in the version register would translate to */
    /* the configuration interface version number 02.25.0.20A             */

    uc_temp = (ul_dbb_num & 0xF0000000) >> 28;
    pc_dbb_num[0] = WAL_ATCMDSRV_GET_HEX_CHAR(uc_temp);
    uc_temp = (ul_dbb_num & 0x0F000000) >> 24;
    pc_dbb_num[1] = WAL_ATCMDSRV_GET_HEX_CHAR(uc_temp);

    pc_dbb_num[2] = '.';

    uc_temp = (ul_dbb_num & 0x00F00000) >> 20;
    pc_dbb_num[3] = WAL_ATCMDSRV_GET_HEX_CHAR(uc_temp);
    uc_temp = (ul_dbb_num & 0x000F0000) >> 16;
    pc_dbb_num[4] = WAL_ATCMDSRV_GET_HEX_CHAR(uc_temp);
    pc_dbb_num[5] = '.';

    uc_temp = (ul_dbb_num & 0x0000F000) >> 12;
    pc_dbb_num[6] = WAL_ATCMDSRV_GET_HEX_CHAR(uc_temp);
    pc_dbb_num[7] = '.';

    uc_temp = (ul_dbb_num & 0x00000F00) >> 8;
    pc_dbb_num[8] = WAL_ATCMDSRV_GET_HEX_CHAR(uc_temp);
    uc_temp = (ul_dbb_num & 0x000000F0) >> 4;
    pc_dbb_num[9] = WAL_ATCMDSRV_GET_HEX_CHAR(uc_temp);
    uc_temp = (ul_dbb_num & 0x0000000F) >> 0;
    pc_dbb_num[10] = WAL_ATCMDSRV_GET_HEX_CHAR(uc_temp);


    return ;
}


OAL_STATIC oal_int32  wal_atcmsrv_ioctl_get_dbb_num(oal_net_device_stru *pst_net_dev, oal_int8 *pc_dbb_num)
{
    wal_msg_write_stru              st_write_msg;
    oal_int32                       l_ret;
    oal_int32                       i_leftime;
    mac_vap_stru                   *pst_mac_vap;
    hmac_vap_stru                  *pst_hmac_vap;

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_dbb_num::OAL_NET_DEV_PRIV, return null!}");
        return -OAL_EINVAL;
    }

    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ANY,"{wal_atcmsrv_ioctl_get_dbb_num::mac_res_get_hmac_vap failed!}");
        return OAL_FAIL;
    }

    /***************************************************************************
                              ????????wal??????
    ***************************************************************************/
    pst_hmac_vap->st_atcmdsrv_get_status.uc_get_dbb_completed_flag = OAL_FALSE;
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_GET_VERSION, 0);

    l_ret = wal_send_cfg_event(pst_net_dev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH,
                             (oal_uint8 *)&st_write_msg,
                             OAL_FALSE,
                             OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_dbb_num::wal_send_cfg_event return err_code [%d]!}", l_ret);
        return l_ret;
    }
    /*????????dmac????*/
    /*lint -e730*/
    i_leftime = OAL_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(pst_hmac_vap->query_wait_q,(OAL_TRUE == pst_hmac_vap->st_atcmdsrv_get_status.uc_get_dbb_completed_flag),WAL_ATCMDSRB_DBB_NUM_TIME);
    /*lint +e730*/
    if ( 0 == i_leftime)
    {
        /* ?????????????????????? */
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_dbb_num::dbb_num wait for %ld ms timeout!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else if (i_leftime < 0)
    {
        /* ?????????????? */
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_dbb_num::dbb_num wait for %ld ms error!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else
    {
        /* ????????  */
        OAM_INFO_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_dbb_num::dbb_num wait for %ld ms error!}",
                      ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        if(0x0225020a != pst_hmac_vap->st_atcmdsrv_get_status.ul_dbb_num)
        {
            OAM_ERROR_LOG1(0, OAM_SF_ANY, "wal_atcmsrv_ioctl_get_dbb_num:ul_dbb_num[0x%x],not match 0x0225020a", pst_hmac_vap->st_atcmdsrv_get_status.ul_dbb_num);
            return -OAL_EINVAL;
        }
        wal_atcmdsrv_ioctl_convert_dbb_num(pst_hmac_vap->st_atcmdsrv_get_status.ul_dbb_num,(oal_uint8 *)pc_dbb_num);
        return OAL_SUCC;
    }


}


OAL_STATIC oal_int32  wal_atcmsrv_ioctl_lte_gpio_mode(oal_net_device_stru *pst_net_dev, oal_int32 l_check_lte_gpio_step)
{
    wal_msg_write_stru              st_write_msg;
    oal_int32                       l_ret;
    oal_int32                       i_leftime;
    mac_vap_stru                   *pst_mac_vap;
    hmac_vap_stru                  *pst_hmac_vap;

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_lte_gpio_mode::OAL_NET_DEV_PRIV, return null!}");
        return -OAL_EINVAL;
    }

    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ANY,"{wal_atcmsrv_ioctl_lte_gpio_mode::mac_res_get_hmac_vap failed!}");
        return -OAL_EINVAL;
    }

    pst_hmac_vap->st_atcmdsrv_get_status.uc_lte_gpio_check_flag = OAL_FALSE;

    /***************************************************************************
         ????????wal??????
     ***************************************************************************/
     /* ???????? */
     WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CHECK_LTE_GPIO, OAL_SIZEOF(oal_int32));

     /*????LTE??????????????*/
     *(oal_int32 *)(st_write_msg.auc_value) = l_check_lte_gpio_step;

     /* ???????? */
     l_ret = wal_send_cfg_event(pst_net_dev,
                                WAL_MSG_TYPE_WRITE,
                                WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(oal_int32),
                                (oal_uint8 *)&st_write_msg,
                                OAL_FALSE,
                                OAL_PTR_NULL);

     if (OAL_UNLIKELY(OAL_SUCC != l_ret))
     {
         OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_lte_gpio_mode::return err code %d!}\r\n", l_ret);
         return l_ret;
     }
    /*????????dmac????*/
    /*lint -e730*/
    i_leftime = OAL_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(pst_hmac_vap->query_wait_q,(OAL_TRUE == pst_hmac_vap->st_atcmdsrv_get_status.uc_lte_gpio_check_flag),WAL_ATCMDSRB_DBB_NUM_TIME);
    /*lint +e730*/
    if ( 0 == i_leftime)
    {
        /* ?????????????????????? */
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_lte_gpio_mode:: wait for %ld ms timeout!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else if (i_leftime < 0)
    {
        /* ?????????????? */
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_lte_gpio_mode:: wait for %ld ms error!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else
    {
        return OAL_SUCC;
    }
}


OAL_STATIC oal_int32  wal_atcmsrv_ioctl_lte_gpio_level_set(oal_int32 l_gpio_level)
{
    oal_int32 l_ret = OAL_SUCC;

    OAM_WARNING_LOG1(0, 0, "wal_atcmsrv_ioctl_lte_gpio_level_set:SET LTE GPIO %d!", l_gpio_level);

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    l_ret = gpio_direction_output(g_st_wlan_customize.ul_lte_ism_priority, l_gpio_level);
    if (OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_level_set:SET LTE ISM PRIORITY FAIL!");
        return l_ret;
    }

    l_ret = gpio_direction_output(g_st_wlan_customize.ul_lte_rx_act, l_gpio_level);
    if (OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_level_set:SET LTE RX ACT FAIL!");
        return l_ret;
    }

    l_ret = gpio_direction_output(g_st_wlan_customize.ul_lte_tx_act, l_gpio_level);
    if (OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_level_set:SET LTE TX ACT FAIL!");
        return l_ret;
    }
#endif

    return l_ret;
}


oal_uint8 g_uc_dev_lte_gpio_level = 0x0;
OAL_STATIC oal_int32  wal_atcmsrv_ioctl_lte_gpio_level_check(oal_net_device_stru *pst_net_dev, oal_int32 l_gpio_level)
{
    oal_int32 l_ret;

    l_ret = wal_atcmsrv_ioctl_lte_gpio_mode(pst_net_dev, CHECK_LTE_GPIO_DEV_LEVEL);
    if (l_ret < 0)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_lte_gpio_level_check::GET DEV LTE GPIO LEVEL FAIL!}");
        return -OAL_EINVAL;
    }

    l_ret = -OAL_EINVAL;

    if (0 == l_gpio_level)
    {
        if (0x0 == g_uc_dev_lte_gpio_level)
        {
            OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_lte_gpio_level_check::check gpio low mode SUCC!}");
            l_ret = OAL_SUCC;
        }
    }
    else if (1 == l_gpio_level)
    {
        /*CHECK BIT_2 BIT_5 BIT_6*/
        if (0x64 == g_uc_dev_lte_gpio_level)
        {
            OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_lte_gpio_level_check::check gpio high mode SUCC!}");
            l_ret = OAL_SUCC;
        }
    }
    else
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_lte_gpio_level_check::unknown param l_gpio_level %d!}", l_gpio_level);
    }

    return l_ret;
}


OAL_STATIC oal_int32  wal_atcmsrv_ioctl_lte_gpio_set(oal_void)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_int32       l_ret = -OAL_EFAIL;
    /*????????????????gpio????*/
    if (g_board_info.need_power_prepare)
    {
        /* set LowerPower mode */
        l_ret = pinctrl_select_state(g_board_info.pctrl, g_board_info.pins_idle);
        if (l_ret)
        {
            OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_set:set mode gpio fail");
            return -OAL_EFAIL;
        }
    }

    l_ret = gpio_request_one(g_st_wlan_customize.ul_lte_ism_priority, GPIOF_OUT_INIT_LOW, WAL_ATCMDSRV_LTE_ISM_PRIORITY_NAME);
    if (l_ret)
    {
        OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_set:set LTE_ISM_PRIORITY mode gpio fail");
        if (g_board_info.need_power_prepare)
        {
            l_ret = pinctrl_select_state(g_board_info.pctrl, g_board_info.pins_normal);
            if (l_ret)
            {
                OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_set:set pinctrl_select_state fail");
            }
        }
        return -OAL_EFAIL;
    }

    l_ret = gpio_request_one(g_st_wlan_customize.ul_lte_rx_act, GPIOF_OUT_INIT_LOW, WAL_ATCMDSRV_LTE_RX_ACT_NAME);
    if (l_ret)
    {
        OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_set:set LTE_RX_ACT mode gpio fail");
        gpio_free(g_st_wlan_customize.ul_lte_ism_priority);
        if (g_board_info.need_power_prepare)
        {
            l_ret = pinctrl_select_state(g_board_info.pctrl, g_board_info.pins_normal);
            if (l_ret)
            {
                OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_set:set pinctrl_select_state fail");
            }
        }
        return -OAL_EFAIL;
    }

    l_ret = gpio_request_one(g_st_wlan_customize.ul_lte_tx_act, GPIOF_OUT_INIT_LOW, WAL_ATCMDSRV_LTE_TX_ACT_NAME);
    if (l_ret)
    {
        OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_set:set LTE_TX_ACT mode gpio fail");
        gpio_free(g_st_wlan_customize.ul_lte_ism_priority);
        gpio_free(g_st_wlan_customize.ul_lte_rx_act);
        if (g_board_info.need_power_prepare)
        {
            l_ret = pinctrl_select_state(g_board_info.pctrl, g_board_info.pins_normal);
            if (l_ret)
            {
                OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_set:set pinctrl_select_state fail");
            }
        }
        return -OAL_EFAIL;
    }
#endif
    return OAL_SUCC;
}

OAL_STATIC oal_void  wal_atcmsrv_ioctl_lte_gpio_free(oal_net_device_stru *pst_net_dev)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    wal_msg_write_stru              st_write_msg;
    oal_int32                       l_ret;

    gpio_free(g_st_wlan_customize.ul_lte_ism_priority);

    gpio_free(g_st_wlan_customize.ul_lte_rx_act);

    gpio_free(g_st_wlan_customize.ul_lte_tx_act);
    if (g_board_info.need_power_prepare)
    {
        l_ret = pinctrl_select_state(g_board_info.pctrl, g_board_info.pins_normal);
        if (l_ret)
        {
            OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_free:set pinctrl_select_state fail");
        }
    }
    /***************************************************************************
         ????????wal??????
     ***************************************************************************/
     /* ???????? */
     WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CHECK_LTE_GPIO, OAL_SIZEOF(oal_int32));

     /*????LTE??????????????*/
     *(oal_int32 *)(st_write_msg.auc_value) = CHECK_LTE_GPIO_RESUME;

     /* ???????? */
     l_ret = wal_send_cfg_event(pst_net_dev,
                                WAL_MSG_TYPE_WRITE,
                                WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(oal_int32),
                                (oal_uint8 *)&st_write_msg,
                                OAL_FALSE,
                                OAL_PTR_NULL);

     if (OAL_UNLIKELY(OAL_SUCC != l_ret))
     {
         OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_lte_gpio_mode::return err code %d!}\r\n", l_ret);
     }
#endif
}

#if 0
OAL_STATIC oal_int32  wal_atcmsrv_ioctl_lte_gpio_get(oal_int32 l_check_lte_gpio)
{
    oal_int32   l_fail_gpio_cnt = 0;
 #if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    if(l_check_lte_gpio != gpio_get_value(WAL_ATCMDSRV_LTE_ISM_PRIORITY))
    {
        OAM_ERROR_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_get:LTE_ISM_PRIORITY FAIL");
        l_fail_gpio_cnt++;
    }

    if(l_check_lte_gpio != gpio_get_value(WAL_ATCMDSRV_LTE_RX_ACT))
    {
        OAM_ERROR_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_get:LTE_RX_ACT FAIL");
        l_fail_gpio_cnt++;
    }

    if(l_check_lte_gpio != gpio_get_value(WAL_ATCMDSRV_LTE_TX_ACT))
    {
        OAM_ERROR_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_get:LTE_TX_ACT FAIL");
        l_fail_gpio_cnt++;
    }
    OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_get:ALL GPIO IS OK");
 #endif
    return l_fail_gpio_cnt;
}
#endif


OAL_STATIC oal_int32  wal_atcmsrv_ioctl_lte_gpio_check(oal_net_device_stru *pst_net_dev)
{
    oal_int32 l_ret;

    /*********step1 ??????????gpio????********/
    OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_check:enter lte gpio check!");
    /*??????host????*/
    l_ret = wal_atcmsrv_ioctl_lte_gpio_set();
    if(OAL_SUCC != l_ret)
    {
        return l_ret;
    }

    /*??????device lte????????????*/
    l_ret = wal_atcmsrv_ioctl_lte_gpio_mode(pst_net_dev,CHECK_LTE_GPIO_INIT);
    if(OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_check:CHECK_LTE_GPIO_INIT FAIL!");
        wal_atcmsrv_ioctl_lte_gpio_free(pst_net_dev);
        return l_ret;
    }

    /*********step2 ????host??????????????device????********/
    /*??gpio????????????*/
    l_ret = wal_atcmsrv_ioctl_lte_gpio_level_set(0);
    if(OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_check:SET LTE GPIO LOW FAIL!");
        wal_atcmsrv_ioctl_lte_gpio_free(pst_net_dev);
        return l_ret;
    }

    /*????device GPIO????????*/
    l_ret = wal_atcmsrv_ioctl_lte_gpio_level_check(pst_net_dev, 0);
    if(OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG1(0, 0, "wal_atcmsrv_ioctl_lte_gpio_check:check gpio low mode FAIL[%x]!", g_uc_dev_lte_gpio_level);
        wal_atcmsrv_ioctl_lte_gpio_free(pst_net_dev);
        return l_ret;
    }

    /*********step3 ????host??????????????device????********/
    /*??gpio????????????*/
    l_ret = wal_atcmsrv_ioctl_lte_gpio_level_set(1);
    if(OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_lte_gpio_check:SET LTE GPIO HIGH FAIL!");
        wal_atcmsrv_ioctl_lte_gpio_free(pst_net_dev);
        return l_ret;
    }

    /*????device GPIO????????*/
    l_ret = wal_atcmsrv_ioctl_lte_gpio_level_check(pst_net_dev, 1);
    if(0 != l_ret)
    {
        OAM_WARNING_LOG1(0, 0, "wal_atcmsrv_ioctl_lte_gpio_check:check gpio high mode FAIL[%x]!", g_uc_dev_lte_gpio_level);
        wal_atcmsrv_ioctl_lte_gpio_free(pst_net_dev);
        return l_ret;
    }

    wal_atcmsrv_ioctl_lte_gpio_free(pst_net_dev);

    return OAL_SUCC;
 }
 oal_uint64                      ul_gpio_wakeup_host_int_get_save;

oal_int32  wal_atcmsrv_ioctl_get_hw_status(oal_net_device_stru *pst_net_dev, oal_int32 *pl_fem_pa_status)
{
    oal_cali_param_stru            *pst_cali_data;
    oal_uint64                      ul_gpio_wakeup_host_int_get;
    oal_uint32                      ul_check_gpio_wakeup_host_status = 0;
    oal_int32                       l_ret = 0;
    oal_int8                        auc_dbb[WAL_ATCMDSRV_IOCTL_DBB_LEN];
    oal_uint32                      ul_lte_status = 0;
    /*device????????????????????????????????????*/
    l_ret = wal_atcmsrv_ioctl_get_dbb_num(pst_net_dev,auc_dbb);
    if(OAL_SUCC != l_ret)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY,"wal_atcmsrv_ioctl_get_fem_pa_status:Failed to get dbb num !");
    }

    /*device????host gpio????????*/
    ul_gpio_wakeup_host_int_get = oal_get_gpio_int_count_para();

    if(ul_gpio_wakeup_host_int_get_save == ul_gpio_wakeup_host_int_get)
    {
        ul_check_gpio_wakeup_host_status = 1;

        OAM_ERROR_LOG0(0, OAM_SF_ANY, "wal_atcmsrv_ioctl_get_fem_pa_status:check wl_host_wake_up gpio fail!");
    }
    ul_gpio_wakeup_host_int_get_save = ul_gpio_wakeup_host_int_get;


    pst_cali_data = (oal_cali_param_stru *)get_cali_data_buf_addr();
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    if(g_st_wlan_customize.ul_lte_gpio_check_switch == 1)
    {
        /*????lte????????????*/
        l_ret = wal_atcmsrv_ioctl_lte_gpio_check(pst_net_dev);
        if(OAL_SUCC != l_ret)
        {
            ul_lte_status = 1;
        }
    }
    else
    {
        ul_lte_status = 0;
    }
#else
    /*????lte????????????*/
    l_ret = wal_atcmsrv_ioctl_lte_gpio_check(pst_net_dev);
    if(OAL_SUCC != l_ret)
    {
        ul_lte_status = 1;
    }
#endif
    *pl_fem_pa_status = (oal_int32)(pst_cali_data->ul_check_hw_status|(ul_check_gpio_wakeup_host_status << 4)|(ul_lte_status << 5));

    if(0 != *pl_fem_pa_status)
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_fem_pa_status::fem_pa_status[bit0-bit1],lna_status[bit2-bit3],gpio[bit4],lte_gpio[bit5];ul_check_hw_status[0x%x]}", *pl_fem_pa_status);
    }


    return OAL_SUCC;


}


oal_void  wal_atcmsrv_ioctl_get_fem_pa_status(oal_net_device_stru *pst_net_dev, oal_int32 *pl_fem_pa_status)
{
    oal_cali_param_stru            *pst_cali_data;
    oal_uint64                      ul_gpio_wakeup_host_int_get;
    oal_uint32                      ul_check_gpio_wakeup_host_status = 0;
    oal_int32                       l_ret = 0;
    oal_int8                        auc_dbb[WAL_ATCMDSRV_IOCTL_DBB_LEN];
    /*device????????????????????????????????????*/
    l_ret = wal_atcmsrv_ioctl_get_dbb_num(pst_net_dev,auc_dbb);
    if(OAL_SUCC != l_ret)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY,"wal_atcmsrv_ioctl_get_fem_pa_status:Failed to get dbb num !");
    }

    /*device????host gpio????????*/
    ul_gpio_wakeup_host_int_get = oal_get_gpio_int_count_para();

    if(ul_gpio_wakeup_host_int_get_save == ul_gpio_wakeup_host_int_get)
    {
        ul_check_gpio_wakeup_host_status = 1;

        OAM_ERROR_LOG0(0, OAM_SF_ANY, "wal_atcmsrv_ioctl_get_fem_pa_status:check wl_host_wake_up gpio fail!");
    }
    ul_gpio_wakeup_host_int_get_save = ul_gpio_wakeup_host_int_get;


    pst_cali_data = (oal_cali_param_stru *)get_cali_data_buf_addr();

    *pl_fem_pa_status = (oal_int32)(pst_cali_data->ul_check_hw_status|(ul_check_gpio_wakeup_host_status << 4));

    if(0 != *pl_fem_pa_status)
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_fem_pa_status::fem_pa_status[bit0-bit1],lna_status[bit2-bit3],gpio[bit4];ul_check_hw_status[0x%x]}", *pl_fem_pa_status);
        CHR_EXCEPTION(CHR_WIFI_DEV(CHR_WIFI_DEV_EVENT_CHIP, CHR_WIFI_DEV_ERROR_FEM_FAIL));
#ifdef CONFIG_HUAWEI_DSM
        hw_1102_dsm_client_notify(DSM_WIFI_FEMERROR, "%s: fem error",  __FUNCTION__);
#endif
    }


}

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_set_always_rx(oal_net_device_stru *pst_net_dev, oal_int32 l_always_rx)
{
    wal_msg_write_stru               st_write_msg;
    oal_int32                        l_ret;
    oal_uint8                        auc_param[] = {"all"};
    oal_uint16                       us_len;

     /*??????????*/
     *(oal_uint8 *)(st_write_msg.auc_value) = (oal_uint8)l_always_rx;

    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_SET_ALWAYS_RX, OAL_SIZEOF(oal_uint8));

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(oal_uint8),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_hipriv_always_rx::return err code [%d]!}\r\n", l_ret);
        return l_ret;
    }

     /*??????????????*/
    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    oal_memcopy(st_write_msg.auc_value, auc_param, OAL_STRLEN((oal_int8*)auc_param));

    st_write_msg.auc_value[OAL_STRLEN((oal_int8*)auc_param)] = '\0';
    us_len = (oal_uint16)(OAL_STRLEN((oal_int8*)auc_param) + 1);

    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_REG_INFO, us_len);

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_always_rx::return err code [%d]!}\r\n", l_ret);
    }
    return OAL_SUCC;
}


OAL_STATIC oal_int32  wal_atcmsrv_ioctl_set_pm_switch(oal_net_device_stru *pst_net_dev, oal_int32 l_pm_switch)
{
    wal_msg_write_stru          st_write_msg;

    oal_int32                   l_ret;
    oal_uint8                   sta_pm_on[5] = " 0 ";

    OAM_WARNING_LOG1(0, OAM_SF_ANY, "wal_atcmsrv_ioctl_set_pm_switch:l_pm_switch[%d]", l_pm_switch);

    *(oal_uint8 *)(st_write_msg.auc_value) = (oal_uint8)l_pm_switch;

    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_SET_PM_SWITCH, OAL_SIZEOF(oal_int32));

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(oal_int32),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_pm_switch::return err code [%d]!}\r\n", l_ret);
        return l_ret;
    }
#ifdef _PRE_WLAN_FEATURE_STA_PM
    l_ret = wal_hipriv_sta_pm_on(pst_net_dev, sta_pm_on);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_pm_switch::CMD_SET_STA_PM_ON return err code [%d]!}\r\n", l_ret);
        return l_ret;
    }

#endif

    return OAL_SUCC;

}

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_get_rx_rssi(oal_net_device_stru *pst_net_dev, oal_int32 *pl_rx_rssi)
{
    oal_int32                   l_ret;
    mac_cfg_rx_fcs_info_stru   *pst_rx_fcs_info;
    wal_msg_write_stru          st_write_msg;
    mac_vap_stru               *pst_mac_vap;
    hmac_vap_stru              *pst_hmac_vap;
    oal_int32                   i_leftime;

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_rx_rssi::OAL_NET_DEV_PRIV, return null!}");
        return -OAL_EINVAL;
    }

    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ANY,"{wal_atcmsrv_ioctl_get_rx_rssi::mac_res_get_hmac_vap failed!}");
        return OAL_FAIL;
    }

    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    pst_hmac_vap->st_atcmdsrv_get_status.uc_get_rx_pkct_flag = OAL_FALSE;
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_RX_FCS_INFO, OAL_SIZEOF(mac_cfg_rx_fcs_info_stru));

    /* ???????????????? */
    pst_rx_fcs_info = (mac_cfg_rx_fcs_info_stru *)(st_write_msg.auc_value);
    /*????????????02????????????*/
    pst_rx_fcs_info->ul_data_op    = 0;
    pst_rx_fcs_info->ul_print_info = 0;

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_rx_fcs_info_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_rx_rssi::return err code %d!}\r\n", l_ret);
        return l_ret;
    }

    /*????????dmac????*/
    i_leftime = OAL_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(pst_hmac_vap->query_wait_q,(oal_uint32)(OAL_TRUE == pst_hmac_vap->st_atcmdsrv_get_status.uc_get_rx_pkct_flag),WAL_ATCMDSRB_GET_RX_PCKT);

    if ( 0 == i_leftime)
    {
        /* ?????????????????????? */
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_rx_rssi::dbb_num wait for %ld ms timeout!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else if (i_leftime < 0)
    {
        /* ?????????????? */
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_rx_rssi::dbb_num wait for %ld ms error!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else
    {
        /* ????????  */
        OAM_INFO_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_rx_rssi::dbb_num wait for %ld ms error!}",
                      ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        *pl_rx_rssi = (oal_int)pst_hmac_vap->st_atcmdsrv_get_status.s_rx_rssi;
        return OAL_SUCC;
    }
}

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_set_chipcheck(oal_net_device_stru *pst_net_dev, oal_int32 *l_chipcheck_result)
{
    oal_int32                ul_ret;
    ul_ret = wlan_device_mem_check();

    return ul_ret;
}

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_get_chipcheck_result(oal_net_device_stru *pst_net_dev, oal_int32 *l_chipcheck_result)
{

    *l_chipcheck_result = wlan_device_mem_check_result(&ul_chipcheck_total_time);

    OAM_WARNING_LOG1(0, OAM_SF_ANY, "wal_atcmsrv_ioctl_get_chipcheck_result:result[%d]",*l_chipcheck_result);
    return OAL_SUCC;
}


OAL_STATIC oal_int32  wal_atcmsrv_ioctl_get_chipcheck_time(oal_net_device_stru *pst_net_dev, oal_uint64 *ul_chipcheck_time)
{
    *ul_chipcheck_time = ul_chipcheck_total_time;

    OAM_WARNING_LOG1(0, OAM_SF_ANY, "wal_atcmsrv_ioctl_get_chipcheck_time:[%d]",ul_chipcheck_total_time);
    return OAL_SUCC;
}

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_set_uart_loop(oal_net_device_stru *pst_net_dev, oal_int32 *l_uart_loop_set)
{
    return conn_test_uart_loop((oal_int8 *)&l_uart_loop_set);
}

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_set_sdio_loop(oal_net_device_stru *pst_net_dev, oal_int32 *l_sdio_loop_set)
{
    return conn_test_sdio_loop((oal_int8 *)&l_sdio_loop_set);
}
#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_fetch_caldata(oal_uint8* auc_caldata)
{
    return hwifi_fetch_ori_caldata(auc_caldata, WAL_ATCMDSRV_NV_WINVRAM_LENGTH);
}

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_set_caldata(oal_net_device_stru *pst_net_dev)
{
    hwifi_atcmd_update_host_nv_params();
    hwifi_config_init_nvram_main(pst_net_dev);
    return OAL_SUCC;
}
#endif
/*efuse????*/

OAL_STATIC oal_int32 wal_atcmdsrv_efuse_regs_read(oal_net_device_stru *pst_net_dev)
{
    oal_int32                   l_ret;
    wal_msg_write_stru          st_write_msg;
    mac_vap_stru               *pst_mac_vap;
    hmac_vap_stru              *pst_hmac_vap;
    oal_int32                   i_leftime;
    oal_uint8                   auc_param[] = {"efuse"};
    oal_uint16                  us_len;

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmdsrv_efuse_regs_read::OAL_NET_DEV_PRIV, return null!}");
        return -OAL_EINVAL;
    }

    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ANY,"{wal_atcmdsrv_efuse_regs_read::mac_res_get_hmac_vap failed!}");
        return -OAL_EINVAL;
    }

    pst_hmac_vap->st_atcmdsrv_get_status.uc_report_efuse_reg_flag = OAL_FALSE;

     /*??????????????*/
    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    oal_memcopy(st_write_msg.auc_value, auc_param, OAL_STRLEN((oal_int8*)auc_param));
    st_write_msg.auc_value[OAL_STRLEN((oal_int8*)auc_param)] = '\0';

    us_len = (oal_uint16)(OAL_STRLEN((oal_int8*)auc_param) + 1);

    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_REG_INFO, us_len);

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmdsrv_efuse_regs_read::return err code [%d]!}\r\n", l_ret);
        return -OAL_EINVAL;
    }

    /*????????dmac????*/
    i_leftime = OAL_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(pst_hmac_vap->query_wait_q,(oal_uint32)(OAL_TRUE == pst_hmac_vap->st_atcmdsrv_get_status.uc_report_efuse_reg_flag),WAL_ATCMDSRB_DBB_NUM_TIME);

    if ( 0 == i_leftime)
    {
        /* ?????????????????????? */
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmdsrv_efuse_regs_read::efuse_regs wait for %ld ms timeout!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else if (i_leftime < 0)
    {
        /* ?????????????? */
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmdsrv_efuse_regs_read::efuse_regs wait for %ld ms error!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else
    {
        return OAL_SUCC;
    }

}

OAL_STATIC void wal_atcmdsrv_efuse_info_print(void)
{
    oal_uint32 loop         = 0;
    oal_uint32 high_bit     = WAL_ATCMDSRV_EFUSE_REG_WIDTH - 1;
    oal_uint32 low_bit      = 0;
    for (loop = 0; loop < WAL_ATCMDSRV_EFUSE_BUFF_LEN; loop++)
    {
        OAM_WARNING_LOG3(0,0,"HI1102_DIE_ID: ATE bits:[%d:%d] value[0x%x]",high_bit,low_bit,g_us_efuse_buffer[loop]);
	    high_bit += WAL_ATCMDSRV_EFUSE_REG_WIDTH;
        low_bit  += WAL_ATCMDSRV_EFUSE_REG_WIDTH;
    }
}


OAL_STATIC oal_int32 wal_atcmdsrv_ioctl_efuse_bits_check(void)
{
    oal_int32 result     = OAL_SUCC;

    st_efuse_bits = (wal_efuse_bits*)g_us_efuse_buffer;

    /*????????efuse????*/
    wal_atcmdsrv_efuse_info_print();
/***********************************************
    (1): DIE_ID [154:0]
    (2): ??????????
            1): die_id_0 [31:   0]
            2): die_id_1 [63:  32]
            3): die_id_2 [95:  64]
            4): die_id_3 [127: 96]
            5): die_id_4 [154:128]
    (3): ??????????
    (4): ????die ID
************************************************/

/*************************************************
    (1): Reserve0 [159:155]
    (2): ????,????,??????????
**************************************************/
    if (0 != st_efuse_bits->reserve0)
    {
        OAM_ERROR_LOG1(0,0,"HI1102_DIE_ID Reserve0[159:155]:expect value[0x00] error value[0x%x]",st_efuse_bits->reserve0);
        result = -OAL_EINVAL;
    }

/**************************************************
    (1): CHIP ID [167:160]
    (2): ????0x02
    (4): ??????????
***************************************************/
    if (WAL_ATCMDSRV_EFUSE_CHIP_ID != st_efuse_bits->chip_id)
    {
        OAM_ERROR_LOG1(0,0,"HI1102_DIE_ID CHIP_ID[167:160]:expect value[0x02] error value[0x%x]\n",st_efuse_bits->chip_id);
        result = -OAL_EINVAL;
    }

/*****************************************************
    (1): Reserve1 [170:169]
    (2): ????,????,??????????
******************************************************/
    if ( 0 != st_efuse_bits->reserve1)
    {
        OAM_ERROR_LOG1(0,0,"HI1102_DIE_ID Reserve1[170:169]:expect value[0x00] error value[0x%x]\n",st_efuse_bits->reserve1);
        result = -OAL_EINVAL;
    }

/******************************************************
    (1): CHIP FUNCTION Value [202:171]
    (2): ??????????
            1):chip_function_value_low  [191:171]
            2):chip_function_value_high [202:192]
    (3): ??????????
*******************************************************/

/*******************************************************
    (1): ADC [206:203]
    (2): [205]??[206]??????????1
    (3): ??????????
********************************************************/
    if (WAL_ATCMDSRV_EFUSE_ADC_ERR_FLAG == ((st_efuse_bits->adc) & WAL_ATCMDSRV_EFUSE_ADC_ERR_FLAG))
    {
        OAM_ERROR_LOG1(0,0,"HI1102_DIE_ID ADC[206:203]:expect value others error value[0x%x]\n",st_efuse_bits->adc);
        result = -OAL_EINVAL;
    }

/*******************************************************
    (1): Reserve2 [207:207]
    (2): ????,????,??????????
*******************************************************/
    if (0 != st_efuse_bits->reserve2)
    {
        OAM_ERROR_LOG1(0,0,"HI1102_DIE_ID Reserve2:expect value[0x00] error value[207:207][0x%x]\n",st_efuse_bits->reserve2);
        result = -OAL_EINVAL;
    }

/****************************************************
    (1): BCPU [208:208]
    (2): ??????????
*****************************************************/

/******************************************************
    (1): Reserve3 [227:209]
    (2): ??????????
            1): reserve3_low  [223:209]
            2): reserve3_high [227:224]
    (3): ????,????,??????????
******************************************************/
    if (0 != st_efuse_bits->reserve3_low || 0 != st_efuse_bits->reserve3_high)
    {
        OAM_ERROR_LOG1(0,0,"HI1102_DIE_ID Reserve3[223:209]:expect value[0x00] error value[0x%x]\n",st_efuse_bits->reserve3_low);
        OAM_ERROR_LOG1(0,0,"HI1102_DIE_ID Reserve3[227:224]:expect value[0x00] error value[0x%x]\n",st_efuse_bits->reserve3_high);
        result = -OAL_EINVAL;
    }

/*******************************************************
    (1): PMU TRIM Value [247:228]
    (2): ??????????
********************************************************/

/*********************************************************
    (1): NFC PMU TRIM Value [253:248]
    (2): ??????????
*********************************************************/

/**********************************************************
    (1): Reserve4 [255:254]
    (2): ????,????,??????????
**********************************************************/
    if (0 != st_efuse_bits->reserve4)
    {
        OAM_ERROR_LOG1(0,0,"HI1102_DIE_ID Reserve4[255:254]:expect value[0x00] error value[0x%x]\n",st_efuse_bits->reserve4);
        result = -OAL_EINVAL;
    }


    return result;
}

OAL_STATIC oal_int32 wal_atcmsrv_ioctl_dieid_inform(oal_net_device_stru *pst_net_dev, oal_uint16 *pl_die_id)
{
    oal_int32    l_ret;
    oal_uint16                               ul_loop = 0;

    /*????efuse????*/
    l_ret = wal_atcmdsrv_efuse_regs_read(pst_net_dev);
    if(OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_efuse_check:get efuse reg fail");
        return l_ret;
    }
    /*????efuse????*/
    for(ul_loop = 0;ul_loop < 16;ul_loop++)
    {
        pl_die_id[ul_loop] = g_us_efuse_buffer[ul_loop];
    }
    return OAL_SUCC;
}


OAL_STATIC oal_int32 wal_atcmsrv_ioctl_efuse_check(oal_net_device_stru *pst_net_dev, oal_int32 *pl_efuse_check_result)
{
    oal_int32    l_ret;

    /*????efuse????*/
    l_ret = wal_atcmdsrv_efuse_regs_read(pst_net_dev);
    if(OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_efuse_check:get efuse reg fail");
        *pl_efuse_check_result = OAL_TRUE;
        return l_ret;
    }
    /*????efuse????*/
    l_ret = wal_atcmdsrv_ioctl_efuse_bits_check();
    if(OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG0(0, 0, "wal_atcmsrv_ioctl_efuse_check:check efuse reg fail");
        *pl_efuse_check_result = OAL_TRUE;
        return l_ret;
    }
    return OAL_SUCC;
}


OAL_STATIC oal_int32 wal_atcmsrv_ioctl_set_ant(oal_net_device_stru *pst_net_dev, oal_int32 *pl_pm_switch)
{
    wal_msg_write_stru              st_write_msg;
    oal_int32                       l_ret;
    oal_int32                       i_leftime;
    mac_vap_stru                   *pst_mac_vap;
    hmac_vap_stru                  *pst_hmac_vap;

    OAM_WARNING_LOG1(0, OAM_SF_ANY, "wal_atcmsrv_ioctl_set_ant: ant[%d]", *pl_pm_switch);

    *(oal_uint8 *)(st_write_msg.auc_value) = (oal_uint8)*pl_pm_switch;

    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_SET_ANT, OAL_SIZEOF(oal_int32));

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(oal_int32),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_ant::return err code [%d]!}\r\n", l_ret);
        return l_ret;
    }

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_ant::OAL_NET_DEV_PRIV, return null!}");
        return -OAL_EINVAL;
    }

    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ANY,"{wal_atcmsrv_ioctl_set_ant::mac_res_get_hmac_vap failed!}");
        return -OAL_FAIL;
    }

    /***************************************************************************
                              ????????wal??????
    ***************************************************************************/
    pst_hmac_vap->st_atcmdsrv_get_status.uc_get_ant_flag = OAL_FALSE;
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_GET_ANT, 0);

    l_ret = wal_send_cfg_event(pst_net_dev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH,
                             (oal_uint8 *)&st_write_msg,
                             OAL_FALSE,
                             OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_ant::wal_send_cfg_event return err_code [%d]!}", l_ret);
        return l_ret;
    }
    /*????????dmac????*/
    /*lint -e730*/
    i_leftime = OAL_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(pst_hmac_vap->query_wait_q,(OAL_TRUE == pst_hmac_vap->st_atcmdsrv_get_status.uc_get_ant_flag),WAL_ATCMDSRB_DBB_NUM_TIME);
    /*lint +e730*/
    if ( 0 == i_leftime)
    {
        /* ?????????????????????? */
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_ant::dbb_num wait for %ld ms timeout!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else if (i_leftime < 0)
    {
        /* ?????????????? */
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_ant::dbb_num wait for %ld ms error!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else
    {
        /* ????????  */
        OAM_INFO_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_atcmsrv_ioctl_set_ant::dbb_num wait for %ld ms error!}",
                      ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        if(*pl_pm_switch != pst_hmac_vap->st_atcmdsrv_get_status.uc_ant_status)
        {
            OAM_ERROR_LOG2(0, OAM_SF_ANY, "wal_atcmsrv_ioctl_set_ant:set[%d],not match get[%d]", *pl_pm_switch, pst_hmac_vap->st_atcmdsrv_get_status.uc_ant_status);
            return -OAL_EINVAL;
        }

        return OAL_SUCC;
    }

}

OAL_STATIC oal_int32  wal_atcmsrv_ioctl_get_upccode(oal_net_device_stru *pst_net_dev, oal_int32 *l_upc_code)
{
    oal_cali_param_stru            *pst_cali_data;
    mac_vap_stru                   *pst_mac_vap;
    oal_uint8                       uc_chnnel_num;
    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_upccode::OAL_NET_DEV_PRIV, return null!}");
        return -OAL_EINVAL;
    }
    if((pst_mac_vap->st_channel.uc_chan_number < 1)||(pst_mac_vap->st_channel.uc_chan_number > 14))
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_get_upccode::uc_chan_number[%d], wrong number!}",pst_mac_vap->st_channel.uc_chan_number);
        return -OAL_EINVAL;
    }
    pst_cali_data = (oal_cali_param_stru *)get_cali_data_buf_addr();
    /*????5G??????????????????*/
    for(uc_chnnel_num=0;uc_chnnel_num < WAL_ATCMDSRV_CHANNEL_NUM;uc_chnnel_num++)
    {
        if(uc_channel_idx[uc_chnnel_num] >= pst_mac_vap->st_channel.uc_chan_number)
        {
            break;
        }
    }
    if(WLAN_BAND_2G == pst_mac_vap->st_channel.en_band)
    {
        *l_upc_code = (oal_int32)pst_cali_data->ast_2Gcali_param[pst_mac_vap->st_channel.uc_chan_number - 1].g_st_cali_tx_power_cmp_2G.ac_atx_pwr_cmp;
    }
    else
    {
        if(uc_chnnel_num >= WAL_ATCMDSRV_CHANNEL_NUM)
        {
            return -OAL_EINVAL;
        }
        if(WLAN_BAND_WIDTH_80PLUSPLUS == pst_mac_vap->st_channel.en_bandwidth)
        {
        *l_upc_code = (oal_int32)pst_cali_data->ast_5Gcali_param[uc_chnnel_num + OAL_5G_20M_CHANNEL_NUM + 1].g_st_cali_tx_power_cmp_5G.ac_atx_pwr_cmp;
        }
        else
        {
        *l_upc_code = (oal_int32)pst_cali_data->ast_5Gcali_param[uc_chnnel_num + 1].g_st_cali_tx_power_cmp_5G.ac_atx_pwr_cmp;
        }
    }
    return OAL_SUCC;


}


#ifdef _PRE_WLAN_FEATURE_SMARTANT
#if 0//??????????????????????
OAL_STATIC oal_int32 wal_atcmsrv_ioctl_get_ant_info(oal_net_device_stru *pst_net_dev, oal_uint8 *puc_ant_type,
                                                oal_uint32 *pul_last_ant_change_time_ms,
                                                oal_uint32 *pul_ant_change_number,
                                                oal_uint32 *pul_main_ant_time_s,
                                                oal_uint32 *pul_aux_ant_time_s,
                                                oal_uint32 *pul_total_time_s)
{
    oal_int32                   l_ret;
    wal_msg_write_stru          st_write_msg;
    mac_vap_stru               *pst_mac_vap;
    hmac_vap_stru              *pst_hmac_vap;
    oal_int32                   i_leftime;
    oal_uint16                  us_len;
    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        *puc_ant_type                 = g_st_atcmdsrv_ant_info.uc_ant_type;
        *pul_last_ant_change_time_ms  = g_st_atcmdsrv_ant_info.ul_last_ant_change_time_ms;
        *pul_ant_change_number        = g_st_atcmdsrv_ant_info.ul_ant_change_number;
        *pul_main_ant_time_s          = g_st_atcmdsrv_ant_info.ul_main_ant_time_s;
        *pul_aux_ant_time_s           = g_st_atcmdsrv_ant_info.ul_aux_ant_time_s;
        *pul_total_time_s             = g_st_atcmdsrv_ant_info.ul_total_time_s;

        return OAL_SUCC;
    }

    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ANY,"{wal_atcmsrv_ioctl_get_ant_info::mac_res_get_hmac_vap failed!}");
        return OAL_FAIL;
    }

    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    us_len = 0;
    pst_hmac_vap->en_ant_info_query_completed_flag = OAL_FALSE;
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_GET_ANT_INFO, us_len);

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_CFG, "{wal_ioctl_get_ant_info::return err code [%d]!}\r\n", l_ret);
        return l_ret;
    }
    /*????????dmac????*/
    i_leftime = OAL_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(pst_hmac_vap->query_wait_q,(oal_uint32)(OAL_TRUE == pst_hmac_vap->en_ant_info_query_completed_flag),WAL_ATCMDSRB_DBB_NUM_TIME);

    if (0 == i_leftime)
    {
        /* ?????????????????????? */
        OAM_WARNING_LOG1(0, OAM_SF_CFG, "{wal_ioctl_get_ant_info::query info wait for %ld ms timeout!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else if (i_leftime < 0)
    {
        /* ?????????????? */
        OAM_WARNING_LOG1(0, OAM_SF_CFG, "{wal_ioctl_get_ant_info::query info wait for %ld ms error!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else
    {
        *puc_ant_type                 = g_st_atcmdsrv_ant_info.uc_ant_type;
        *pul_last_ant_change_time_ms  = g_st_atcmdsrv_ant_info.ul_last_ant_change_time_ms;
        *pul_ant_change_number        = g_st_atcmdsrv_ant_info.ul_ant_change_number;
        *pul_main_ant_time_s          = g_st_atcmdsrv_ant_info.ul_main_ant_time_s;
        *pul_aux_ant_time_s           = g_st_atcmdsrv_ant_info.ul_aux_ant_time_s;
        *pul_total_time_s             = g_st_atcmdsrv_ant_info.ul_total_time_s;

        return OAL_SUCC;
    }
}

OAL_STATIC oal_int32 wal_atcmsrv_ioctl_double_ant_switch(oal_net_device_stru *pst_net_dev, oal_uint32 ul_double_ant_sw,
                                                oal_uint32 *pul_ret)
{
    oal_int32                   l_ret;
    wal_msg_write_stru          st_write_msg;
    mac_vap_stru               *pst_mac_vap;
    hmac_vap_stru              *pst_hmac_vap;
    oal_int32                   i_leftime;
    oal_uint16                  us_len;

    *pul_ret                 = OAL_FAIL;

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_double_ant_switch::OAL_NET_DEV_PRIV, return null!}");

        return OAL_SUCC;
    }

    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ANY,"{wal_atcmsrv_ioctl_double_ant_switch::mac_res_get_hmac_vap failed!}");
        return OAL_FAIL;
    }

    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    st_write_msg.auc_value[0] = (oal_uint8)ul_double_ant_sw;
    st_write_msg.auc_value[1] = 0;
    us_len = OAL_SIZEOF(oal_int32);
    pst_hmac_vap->en_double_ant_switch_query_completed_flag = OAL_FALSE;
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_DOUBLE_ANT_SW, us_len);

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_CFG, "{wal_atcmsrv_ioctl_double_ant_switch::return err code [%d]!}\r\n", l_ret);
        return l_ret;
    }
    /*????????dmac????*/
    i_leftime = OAL_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(pst_hmac_vap->query_wait_q,(oal_uint32)(OAL_TRUE == pst_hmac_vap->en_double_ant_switch_query_completed_flag),WAL_ATCMDSRB_DBB_NUM_TIME);

    if (0 == i_leftime)
    {
        /* ?????????????????????? */
        OAM_WARNING_LOG1(0, OAM_SF_CFG, "{wal_atcmsrv_ioctl_double_ant_switch::query info wait for %ld ms timeout!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else if (i_leftime < 0)
    {
        /* ?????????????? */
        OAM_WARNING_LOG1(0, OAM_SF_CFG, "{wal_atcmsrv_ioctl_double_ant_switch::query info wait for %ld ms error!}",
                         ((WAL_ATCMDSRB_DBB_NUM_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else
    {
        *pul_ret = pst_hmac_vap->ul_double_ant_switch_ret;

        return OAL_SUCC;
    }
}

#endif
#endif


OAL_STATIC oal_int32  wal_atcmsrv_ioctl_set_bss_expire_age(oal_net_device_stru *pst_net_dev, oal_uint32 ul_expire_age)
{
    g_pd_bss_expire_time = (ul_expire_age < WAL_ATCMSRV_MIN_BSS_EXPIRATION_AGE)?WAL_ATCMSRV_MIN_BSS_EXPIRATION_AGE:ul_expire_age;
    g_pd_bss_expire_time = (g_pd_bss_expire_time > WAL_ATCMSRV_MAX_BSS_EXPIRATION_AGE)?WAL_ATCMSRV_MAX_BSS_EXPIRATION_AGE:g_pd_bss_expire_time;

    OAM_WARNING_LOG2(0, OAM_SF_CFG, "wal_atcmsrv_ioctl_set_bss_expire_age::pd_bss_expire_time %d, input expire time %d",
                        g_pd_bss_expire_time, ul_expire_age);

    return OAL_SUCC;
}


OAL_STATIC oal_int32  wal_atcmsrv_ioctl_get_wifi_connect_info(oal_net_device_stru *pst_net_dev,struct wal_atcmdsrv_wifi_connect_info *pst_connect_info)
{
    mac_vap_stru                *pst_mac_vap;
    hmac_vap_stru               *pst_hmac_vap;
    hmac_device_stru            *pst_hmac_device;
    hmac_bss_mgmt_stru          *pst_bss_mgmt;          /*??????????bss???????????? */
    hmac_scanned_bss_info       *pst_scanned_bss_info   = OAL_PTR_NULL;

    if (pst_net_dev == OAL_PTR_NULL || pst_connect_info == OAL_PTR_NULL)
    {
        OAM_ERROR_LOG2(0, OAM_SF_CFG, "wal_atcmsrv_ioctl_get_wifi_connect_info::null pointer. net_dev %p, connect_info %p",
                            pst_net_dev, pst_connect_info);
        return -OAL_EFAIL;
    }

    OAL_MEMZERO(pst_connect_info, OAL_SIZEOF(*pst_connect_info));

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0,OAM_SF_ANY,"{wal_atcmsrv_ioctl_get_wifi_connect_info::vap is null.}");
        return -OAL_EINVAL;
    }

    if (pst_mac_vap->en_vap_mode != WLAN_VAP_MODE_BSS_STA)
    {
        OAM_ERROR_LOG1(0,OAM_SF_ANY,"{wal_atcmsrv_ioctl_get_wifi_connect_info::invalid vap mode.vap_mode [%d]}", pst_mac_vap->en_vap_mode);
        return -OAL_EINVAL;
    }

    if (pst_mac_vap->en_vap_state == MAC_VAP_STATE_UP)
    {

        pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
        if (OAL_PTR_NULL == pst_hmac_vap)
        {
            OAM_ERROR_LOG1(0,OAM_SF_ANY,"{wal_atcmsrv_ioctl_get_wifi_connect_info::mac_res_get_hmac_vap fail.vap_id[%u]}",pst_mac_vap->uc_vap_id);
            return -OAL_EINVAL;
        }

        /* ????hmac device ???? */
        pst_hmac_device = hmac_res_get_mac_dev(pst_mac_vap->uc_device_id);
        if (OAL_PTR_NULL == pst_hmac_device)
        {
            OAM_WARNING_LOG0(0, OAM_SF_SCAN, "{wal_atcmsrv_ioctl_get_wifi_connect_info::hmac_device is null.}");
            return -OAL_EINVAL;
        }

        pst_connect_info->en_status = ATCMDSRV_WIFI_CONNECTED;
        pst_connect_info->c_rssi    = pst_hmac_vap->station_info.signal;
        oal_memcopy(pst_connect_info->auc_bssid, pst_mac_vap->auc_bssid, WLAN_MAC_ADDR_LEN);

        /* ??????????????bss???????????? */
        pst_bss_mgmt = &(pst_hmac_device->st_scan_mgmt.st_scan_record_mgmt.st_bss_mgmt);
        /* ??????????????????*/
        oal_spin_lock(&(pst_bss_mgmt->st_lock));
        pst_scanned_bss_info = hmac_scan_find_scanned_bss_by_bssid(pst_bss_mgmt, pst_connect_info->auc_bssid);
        if (OAL_PTR_NULL == pst_scanned_bss_info)
        {
        OAM_WARNING_LOG4(pst_mac_vap->uc_vap_id, OAM_SF_CFG,
                             "{wal_atcmsrv_ioctl_get_wifi_connect_info::find the bss failed by bssid:%02X:XX:XX:%02X:%02X:%02X}",
                             pst_connect_info->auc_bssid[0],
                             pst_connect_info->auc_bssid[3],
                             pst_connect_info->auc_bssid[4],
                             pst_connect_info->auc_bssid[5]);

            /* ???? */
        oal_spin_unlock(&(pst_bss_mgmt->st_lock));
    return -OAL_EINVAL;
        }
        /* ????*/
        oal_spin_unlock(&(pst_bss_mgmt->st_lock));

        oal_memcopy(pst_connect_info->auc_ssid, pst_scanned_bss_info->st_bss_dscr_info.ac_ssid, WLAN_SSID_MAX_LEN);
    }
    else
    {
        pst_connect_info->en_status = ATCMDSRV_WIFI_DISCONNECT;
    }

        OAM_WARNING_LOG4(0, OAM_SF_CFG, "wal_atcmsrv_ioctl_get_wifi_connect_info::state %d, rssi %d, BSSID[XX:XX:XX:XX:%02X:%02X]",
                        pst_connect_info->en_status, pst_connect_info->c_rssi,
                        pst_connect_info->auc_bssid[4], pst_connect_info->auc_bssid[5]);

    return OAL_SUCC;
}



oal_int32 wal_atcmdsrv_wifi_priv_cmd(oal_net_device_stru *pst_net_dev, oal_ifreq_stru *pst_ifr, oal_int32 ul_cmd)
{
    wal_atcmdsrv_wifi_priv_cmd_stru  st_priv_cmd;
    oal_int32    l_ret              = OAL_SUCC;


    if ((OAL_PTR_NULL == pst_ifr->ifr_data)||(OAL_PTR_NULL == pst_net_dev))
    {
        l_ret = -OAL_EINVAL;
        return l_ret;
    }
    /*????????????????????????*/
    if (oal_copy_from_user(&st_priv_cmd, pst_ifr->ifr_data, sizeof(wal_atcmdsrv_wifi_priv_cmd_stru)))
    {
		l_ret = -OAL_EINVAL;
		return l_ret;
	}
    if(st_priv_cmd.l_verify != WAL_ATCMDSRV_IOCTL_VERIFY_CODE)
    {
        OAM_WARNING_LOG2(0, OAM_SF_ANY,"wal_atcmdsrv_wifi_priv_cmd:ioctl verify failed,verify code is:%d(not equal %d)", st_priv_cmd.l_verify, WAL_ATCMDSRV_IOCTL_VERIFY_CODE);
        return -OAL_EINVAL;
    }
    switch(st_priv_cmd.ul_cmd)
    {
        case WAL_ATCMDSRV_IOCTL_CMD_WI_FREQ_SET:
             l_ret = wal_atcmsrv_ioctl_set_freq(pst_net_dev,st_priv_cmd.pri_data.l_freq);
             break;
        case WAL_ATCMDSRV_IOCTL_CMD_WI_POWER_SET:
             l_ret = wal_atcmsrv_ioctl_set_txpower(pst_net_dev,st_priv_cmd.pri_data.l_pow);
             break;
        case WAL_ATCMDSRV_IOCTL_CMD_MODE_SET:
             l_ret = wal_atcmsrv_ioctl_set_mode(pst_net_dev,st_priv_cmd.pri_data.l_mode);
             break;
        case WAL_ATCMDSRV_IOCTL_CMD_DATARATE_SET:
             l_ret = wal_atcmsrv_ioctl_set_datarate(pst_net_dev,st_priv_cmd.pri_data.l_datarate);
             break;
        case WAL_ATCMDSRV_IOCTL_CMD_BAND_SET:
             l_ret = wal_atcmsrv_ioctl_set_bandwidth(pst_net_dev,st_priv_cmd.pri_data.l_bandwidth);
             break;
        case WAL_ATCMDSRV_IOCTL_CMD_ALWAYS_TX_SET:
             l_ret = wal_atcmsrv_ioctl_set_always_tx(pst_net_dev,st_priv_cmd.pri_data.l_awalys_tx);
             break;
        case WAL_ATCMDSRV_IOCTL_CMD_DBB_GET:
             l_ret = wal_atcmsrv_ioctl_get_dbb_num(pst_net_dev,st_priv_cmd.pri_data.auc_dbb);
            if(oal_copy_to_user(pst_ifr->ifr_data,&st_priv_cmd,sizeof(wal_atcmdsrv_wifi_priv_cmd_stru)))
            {
                OAM_ERROR_LOG0(0, OAM_SF_ANY,"wal_atcmdsrv_wifi_priv_cmd:Failed to copy ioctl_data to user !");
                l_ret = -OAL_EINVAL;
            }
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_HW_STATUS_GET:
            l_ret = wal_atcmsrv_ioctl_get_hw_status(pst_net_dev,&st_priv_cmd.pri_data.l_fem_pa_status);
            if(oal_copy_to_user(pst_ifr->ifr_data,&st_priv_cmd,sizeof(wal_atcmdsrv_wifi_priv_cmd_stru)))
            {
                OAM_ERROR_LOG0(0, OAM_SF_ANY,"wal_atcmdsrv_wifi_priv_cmd:Failed to copy ioctl_data to user !");
                l_ret = -OAL_EINVAL;
            }
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_ALWAYS_RX_SET:
            l_ret = wal_atcmsrv_ioctl_set_always_rx(pst_net_dev,st_priv_cmd.pri_data.l_awalys_rx);
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_HW_ADDR_SET:
            l_ret = wal_atcmsrv_ioctl_set_hw_addr(pst_net_dev,st_priv_cmd.pri_data.auc_mac_addr);
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_RX_PCKG_GET:
            l_ret = wal_atcmsrv_ioctl_get_rx_pckg(pst_net_dev,&st_priv_cmd.pri_data.l_rx_pkcg);
            if(oal_copy_to_user(pst_ifr->ifr_data,&st_priv_cmd,sizeof(wal_atcmdsrv_wifi_priv_cmd_stru)))
            {
                OAM_ERROR_LOG0(0, OAM_SF_ANY,"wal_atcmdsrv_wifi_priv_cmd:Failed to copy ioctl_data to user !");
                l_ret = -OAL_EINVAL;
            }
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_PM_SWITCH:
            l_ret = wal_atcmsrv_ioctl_set_pm_switch(pst_net_dev,st_priv_cmd.pri_data.l_pm_switch);
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_RX_RSSI:
            l_ret = wal_atcmsrv_ioctl_get_rx_rssi(pst_net_dev,&st_priv_cmd.pri_data.l_rx_rssi);
            if(oal_copy_to_user(pst_ifr->ifr_data,&st_priv_cmd,sizeof(wal_atcmdsrv_wifi_priv_cmd_stru)))
            {
                OAM_ERROR_LOG0(0, OAM_SF_ANY,"wal_atcmdsrv_wifi_priv_cmd:Failed to copy ioctl_data to user !");
                l_ret = -OAL_EINVAL;
            }
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_CHIPCHECK_SET:
            l_ret = wal_atcmsrv_ioctl_set_chipcheck(pst_net_dev,&st_priv_cmd.pri_data.l_chipcheck_result);
            if(oal_copy_to_user(pst_ifr->ifr_data,&st_priv_cmd,sizeof(wal_atcmdsrv_wifi_priv_cmd_stru)))
            {
                OAM_ERROR_LOG0(0, OAM_SF_ANY,"wal_atcmdsrv_wifi_priv_cmd:Failed to copy ioctl_data to user !");
                l_ret = -OAL_EINVAL;
            }
            break;
         case WAL_ATCMDSRV_IOCTL_CMD_CHIPCHECK_RESULT:
            l_ret = wal_atcmsrv_ioctl_get_chipcheck_result(pst_net_dev,&st_priv_cmd.pri_data.l_chipcheck_result);
            if(oal_copy_to_user(pst_ifr->ifr_data,&st_priv_cmd,sizeof(wal_atcmdsrv_wifi_priv_cmd_stru)))
            {
                OAM_ERROR_LOG0(0, OAM_SF_ANY,"wal_atcmdsrv_wifi_priv_cmd:Failed to copy ioctl_data to user !");
                l_ret = -OAL_EINVAL;
            }
            break;
         case WAL_ATCMDSRV_IOCTL_CMD_CHIPCHECK_TIME:
            l_ret = wal_atcmsrv_ioctl_get_chipcheck_time(pst_net_dev,&st_priv_cmd.pri_data.l_chipcheck_time);
            if(oal_copy_to_user(pst_ifr->ifr_data,&st_priv_cmd,sizeof(wal_atcmdsrv_wifi_priv_cmd_stru)))
            {
                OAM_ERROR_LOG0(0, OAM_SF_ANY,"wal_atcmdsrv_wifi_priv_cmd:Failed to copy ioctl_data to user !");
                l_ret = -OAL_EINVAL;
            }
            break;
         case WAL_ATCMDSRV_IOCTL_CMD_UART_LOOP_SET:
            l_ret = wal_atcmsrv_ioctl_set_uart_loop(pst_net_dev,&st_priv_cmd.pri_data.l_uart_loop_set);
            break;
         case WAL_ATCMDSRV_IOCTL_CMD_SDIO_LOOP_SET:
            l_ret = wal_atcmsrv_ioctl_set_sdio_loop(pst_net_dev,&st_priv_cmd.pri_data.l_sdio_loop_set);
            break;
#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
        case WAL_ATCMDSRV_IOCTL_CMD_RD_CALDATA:
            l_ret = wal_atcmsrv_ioctl_fetch_caldata(st_priv_cmd.pri_data.auc_caldata);
            if(oal_copy_to_user(pst_ifr->ifr_data,&st_priv_cmd,sizeof(wal_atcmdsrv_wifi_priv_cmd_stru)))
            {
                OAM_ERROR_LOG0(0, OAM_SF_ANY,"wal_atcmdsrv_wifi_priv_cmd:Failed to copy ioctl_data(caldata) to user !");
                l_ret = -OAL_EINVAL;
            }
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_SET_CALDATA:
           l_ret = wal_atcmsrv_ioctl_set_caldata(pst_net_dev);
           break;
#endif
        case WAL_ATCMDSRV_IOCTL_CMD_EFUSE_CHECK:
            l_ret = wal_atcmsrv_ioctl_efuse_check(pst_net_dev,&st_priv_cmd.pri_data.l_efuse_check_result);
            if(oal_copy_to_user(pst_ifr->ifr_data,&st_priv_cmd,sizeof(wal_atcmdsrv_wifi_priv_cmd_stru)))
            {
                OAM_ERROR_LOG0(0, OAM_SF_ANY,"wal_atcmdsrv_wifi_priv_cmd:Failed to copy ioctl_data to user !");
                l_ret = -OAL_EINVAL;
            }
            break;

        case WAL_ATCMDSRV_IOCTL_CMD_SET_ANT:
            l_ret = wal_atcmsrv_ioctl_set_ant(pst_net_dev,&st_priv_cmd.pri_data.l_set_ant);
            if(oal_copy_to_user(pst_ifr->ifr_data,&st_priv_cmd,sizeof(wal_atcmdsrv_wifi_priv_cmd_stru)))
            {
                OAM_ERROR_LOG0(0, OAM_SF_ANY,"wal_atcmdsrv_wifi_priv_cmd:Failed to copy ioctl_data to user !");
                l_ret = -OAL_EINVAL;
            }
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_DIEID_INFORM:
             l_ret = wal_atcmsrv_ioctl_dieid_inform(pst_net_dev,(oal_uint16*)st_priv_cmd.pri_data.die_id);
             oal_copy_to_user(pst_ifr->ifr_data,&st_priv_cmd,sizeof(wal_atcmdsrv_wifi_priv_cmd_stru));
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_SET_COUNTRY:
            l_ret = wal_atcmsrv_ioctl_set_country(pst_net_dev,st_priv_cmd.pri_data.auc_country_code);
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_GET_UPCCODE:
            l_ret = wal_atcmsrv_ioctl_get_upccode(pst_net_dev,&st_priv_cmd.pri_data.upc_code);
            oal_copy_to_user(pst_ifr->ifr_data,&st_priv_cmd,sizeof(wal_atcmdsrv_wifi_priv_cmd_stru));
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_SET_CONN_POWER:
            l_ret = wal_ioctl_reduce_sar(pst_net_dev, (oal_uint8)st_priv_cmd.pri_data.l_pow);
            break;

        case WAL_ATCMDSRV_IOCTL_CMD_SET_BSS_EXPIRE_AGE:
            l_ret = wal_atcmsrv_ioctl_set_bss_expire_age(pst_net_dev, st_priv_cmd.pri_data.ul_bss_expire_age);
            break;

        case WAL_ATCMDSRV_IOCTL_CMD_GET_CONN_INFO:
            l_ret = wal_atcmsrv_ioctl_get_wifi_connect_info(pst_net_dev, &st_priv_cmd.pri_data.st_connect_info);

            OAL_IO_PRINT("wal_atcmsrv_ioctl_get_wifi_connect_info::status %d, %.32s,%02x:%02x:xx:xx:%02x:%02x,%d",
                         st_priv_cmd.pri_data.st_connect_info.en_status,
                         st_priv_cmd.pri_data.st_connect_info.auc_ssid,
                         st_priv_cmd.pri_data.st_connect_info.auc_bssid[0], st_priv_cmd.pri_data.st_connect_info.auc_bssid[1],
                         st_priv_cmd.pri_data.st_connect_info.auc_bssid[4], st_priv_cmd.pri_data.st_connect_info.auc_bssid[5],
                         st_priv_cmd.pri_data.st_connect_info.c_rssi);

            oal_copy_to_user(pst_ifr->ifr_data, &st_priv_cmd, sizeof(wal_atcmdsrv_wifi_priv_cmd_stru));
            break;

        default:
            break;
    }

    return l_ret;
}
#endif

#if (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1151) && defined(_PRE_WLAN_FEATURE_EQUIPMENT_TEST)

oal_int32  wal_atcmdsrv_ioctl_chip_check(oal_net_device_stru *pst_net_dev)
{
    wal_msg_write_stru          st_write_msg;
    oal_int32                   l_ret;
    oal_uint32                  ul_off_set;
    oal_int8                    ac_arg[WAL_HIPRIV_CMD_NAME_MAX_LEN];
    oal_uint32                  ul_ret;
    oal_int32                   l_idx = 0;
    oal_switch_enum_uint8       en_chip_check_flag = OAL_TRUE;
    mac_vap_stru                *pst_mac_vap;
    hmac_vap_stru               *pst_hmac_vap;
    oal_int                     i_leftime;

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG1(0,OAM_SF_ANY,"{wal_atcmsrv_ioctl_chip_check::mac_res_get_hmac_vap fail.vap_id[%u]}",pst_mac_vap->uc_vap_id);
        return -OAL_EINVAL;
    }

    /***************************************************************************
                                    ????????wal??????
    ***************************************************************************/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CHIP_CHECK_SWITCH, OAL_SIZEOF(oal_uint8));
    *((oal_uint8 *)(st_write_msg.auc_value)) = en_chip_check_flag;  /* ???????????????? */

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(oal_uint8),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_atcmsrv_ioctl_chip_check::return err code %d!}\r\n", l_ret);
        return (oal_int32)l_ret;
    }

    /*????????dmac????*/
    i_leftime = OAL_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(pst_hmac_vap->query_wait_q,(oal_uint32)(OAL_TRUE == pst_hmac_vap->st_hipriv_ack_stats.uc_get_hipriv_ack_flag),WAL_ATCMDSRB_GET_RX_PCKT);

    if(i_leftime > 0)
    {
        /* ????????  */
        l_ret = (OAL_TRUE == pst_hmac_vap->st_hipriv_ack_stats.uc_get_hipriv_ack_flag)?
                    OAL_SUCC: (-OAL_EINVAL);
        return l_ret;
    }
    else
    {
        return -OAL_EINVAL;
    }
}


oal_int32 wal_atcmdsrv_wifi_priv_cmd(oal_int8 *ac_dev_name, oal_int32 ul_cmd, oal_uint8 * puc_param)
{
    oal_int32                        l_ret              = OAL_SUCC;
    oal_net_device_stru*             pst_net_dev;
    oal_uint8                        uc_cw_param;
    oal_uint32                       ul_rx_pckg_succ_num;
    mac_vap_stru                     *pst_mac_vap;
    hmac_vap_stru                    *pst_hmac_vap;

    if (OAL_PTR_NULL == ac_dev_name)
    {
        l_ret = -OAL_EINVAL;
        return l_ret;
    }

    /* ????dev_name????dev */
    pst_net_dev = oal_dev_get_by_name(ac_dev_name);
    if (OAL_PTR_NULL == pst_net_dev)
    {
        OAL_IO_PRINT("wal_atcmdsrv_wifi_priv_cmd_set::oal_dev_get_by_name return null ptr!\n");
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_atcmdsrv_wifi_priv_cmd_set::oal_dev_get_by_name return null ptr!}\r\n");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ????oal_dev_get_by_name????????????oal_dev_put??net_dev?????????????? */
    oal_dev_put(pst_net_dev);

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_atcmdsrv_wifi_priv_cmd_set::OAL_NET_DEV_PRIV, return null!}");
        return -OAL_EINVAL;
    }

    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ANY,"{wal_atcmdsrv_wifi_priv_cmd_set::mac_res_get_hmac_vap failed!}");
        return OAL_FAIL;
    }

    pst_hmac_vap->st_hipriv_ack_stats.uc_get_hipriv_ack_flag = OAL_FALSE;

    switch(ul_cmd)
    {
        case WAL_ATCMDSRV_IOCTL_CMD_NORM_SET:
            l_ret = wal_hipriv_parse_cmd(puc_param);
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_RX_PCKG_GET:
            l_ret = wal_atcmsrv_ioctl_get_rx_pckg(pst_net_dev, &ul_rx_pckg_succ_num);
            puc_param[0] = (ul_rx_pckg_succ_num >> 8)&0xFF;
            puc_param[1] = ul_rx_pckg_succ_num & 0xFF;
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_VAP_DOWN_SET:
            l_ret = wal_netdev_stop(pst_net_dev);
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_HW_ADDR_SET:
            l_ret = wal_atcmsrv_ioctl_set_hw_addr(pst_net_dev, puc_param);
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_VAP_UP_SET:
            l_ret = wal_netdev_open(pst_net_dev);
            break;
        case WAL_ATCMDSRV_IOCTL_CMD_CHIPCHECK_SET:
            l_ret = wal_atcmdsrv_ioctl_chip_check(pst_net_dev);
            break;

        default:
             break;
    }

    return l_ret;
}

#endif

#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

