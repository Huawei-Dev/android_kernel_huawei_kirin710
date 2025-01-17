

#ifndef __HAL_COMMOM_OPS_H__
#define __HAL_COMMOM_OPS_H__

/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "oal_types.h"
#include "wlan_spec.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************/
/*****************************************************************************/
/* HI1102 ???????????????? */
/*****************************************************************************/
/*****************************************************************************/
#if ((_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102_DEV) || (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102_HOST)) ||  \
    ((_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1103_DEV) || (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1103_HOST)) ||  \
    ((_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102A_DEV) || (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102A_HOST))
/*****************************************************************************
  2 ??????
*****************************************************************************/
#if ((_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102_DEV) || (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102_HOST)) ||  \
    ((_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102A_DEV) || (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102A_HOST))
#define HAL_PUBLIC_HOOK_FUNC(_func) \
    hi1102##_func
#endif
#if ((_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1103_DEV) || (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1103_HOST))
#define HAL_PUBLIC_HOOK_FUNC(_func) \
    hi1103##_func
#endif

#define HAL_RX_DSCR_GET_SW_ADDR(_addr)   hal_rx_dscr_get_sw_addr(_addr)   /* ????????????????bit???? */
#define HAL_RX_DSCR_GET_REAL_ADDR(_addr) hal_rx_dscr_get_real_addr(_addr) /* ????????????????bit???? */

#define HAL_MAX_AP_NUM  2                                               /* HAL AP???? */
#define HAL_MAX_STA_NUM 3                                               /* HAL STA???? */
#define HAL_MAX_VAP_NUM              (HAL_MAX_AP_NUM + HAL_MAX_STA_NUM) /* HAL VAP???? */

#define HAL_VAP_ID_IS_VALID(_vap_id) ((_vap_id == 0) || (_vap_id == 1) ||  \
                                      (_vap_id == 4) || (_vap_id == 5) || (_vap_id == 6))
#define HAL_VAP_ID_IS_VALID_PSTA(_vap_id) ((uc_vap_id < WLAN_HAL_OHTER_BSS_ID) ||  \
                                           ((uc_vap_id >= WLAN_PROXY_STA_START_ID) && \
                                           (uc_vap_id <= WLAN_PROXY_STA_END_ID)))

#define GNSS_SCAN_MAX_AP_NUM_TO_GNSS 32
#define GNSS_SCAN_RESULTS_VALID_MS   5000

#define HAL_DEVICE_2G_BAND_NUM_FOR_LOSS 3 /* 2g ??????band???????????????????????? */
#define HAL_DEVICE_5G_BAND_NUM_FOR_LOSS WLAN_5G_SUB_BAND_NUM

#define HAL_DEVICE_2G_DELTA_RSSI_NUM 2 /* 20M/40M */
#define HAL_DEVICE_5G_DELTA_RSSI_NUM 3 /* 20M/40M/80M */

#ifdef _PRE_WLAN_FIT_BASED_REALTIME_CALI
#define HAL_AL_TX_DYN_CAL_INTERVAL_NUM 10 /* ???????????????????????????? */
#endif

#ifdef _PRE_WLAN_FEATURE_NRCOEX
#define HAL_NRCOEX_RULE_NUM        4  /* NR???????????? */
#define HAL_NRCOEX_RULE_PARAMS_NUM 11 /* NR???????????????????????? */
#endif
#define HAL_RATE_100KBPS_TO_KBPS 100 /* ??????100Kbps????????Kbps???????????? */
/*****************************************************************************
  3 ????
*****************************************************************************/
typedef enum {
    HAL_TX_QUEUE_BE = 0, /* ???????????? */
    HAL_TX_QUEUE_BK = 1, /* ???????? */
    HAL_TX_QUEUE_VI = 2, /* ???????? */
    HAL_TX_QUEUE_VO = 3, /* ???????? */
    HAL_TX_QUEUE_HI = 4, /* ????????????(??????/??????????????) */
    HAL_TX_QUEUE_BUTT
} hal_tx_queue_type_enum;
typedef oal_uint8 hal_tx_queue_type_enum_uint8;
#ifdef _PRE_WLAN_FEATURE_BTCOEX
/* sw preempt????????????????????a2dp|transfer  page|inquiry ????  both */
typedef enum {
    HAL_BTCOEX_PS_STATUE_ACL = 1,       /* only a2dp|???? BIT0 */
    HAL_BTCOEX_PS_STATUE_PAGE_INQ = 2,  /* only  page|inquiry BIT1 */
    HAL_BTCOEX_PS_STATUE_PAGE_ACL = 3,  /* both a2dp|???? and page|inquiry BIT0|BIT1 */
    HAL_BTCOEX_PS_STATUE_LDAC = 4,      /* only ldac BIT2 */
    HAL_BTCOEX_PS_STATUE_LDAC_ACL = 5,  /* ldac and a2dp|???? BIT2|BIT0 */
    HAL_BTCOEX_PS_STATUE_LDAC_PAGE = 6, /* ldac and page|inquiry BIT2|BIT1 */
    HAL_BTCOEX_PS_STATUE_TRIPLE = 7,    /* ldac and page|inquiry and a2dp|???? BIT2|BIT1|BIT0 */

    HAL_BTCOEX_PS_STATUE_BUTT
} hal_btcoex_ps_status_enum;
typedef oal_uint8 hal_btcoex_ps_status_enum_uint8;

/* mode?????????????????????????????? */
typedef enum {
    HAL_BTCOEX_SW_POWSAVE_MODE_0 = 0,
    HAL_BTCOEX_SW_POWSAVE_MODE_1 = 1,
    HAL_BTCOEX_SW_POWSAVE_MODE_NORMAL = 2,  // ??????????  BIT1(02????)
    HAL_BTCOEX_SW_POWSAVE_MODE_3 = 3,
    HAL_BTCOEX_SW_POWSAVE_MODE_4 = 4,
    HAL_BTCOEX_SW_POWSAVE_MODE_5 = 5,
    HAL_BTCOEX_SW_POWSAVE_MODE_6 = 6,
    HAL_BTCOEX_SW_POWSAVE_MODE_7 = 7,
    HAL_BTCOEX_SW_POWSAVE_MODE_8 = 8,
    HAL_BTCOEX_SW_POWSAVE_MODE_9 = 9,
    HAL_BTCOEX_SW_POWSAVE_MODE_10 = 10,
    HAL_BTCOEX_SW_POWSAVE_MODE_11 = 11,
    HAL_BTCOEX_SW_POWSAVE_MODE_12 = 12,
    HAL_BTCOEX_SW_POWSAVE_MODE_13 = 13,
    HAL_BTCOEX_SW_POWSAVE_MODE_14 = 14,
    HAL_BTCOEX_SW_POWSAVE_MODE_15 = 15,

    HAL_BTCOEX_SW_POWSAVE_MODE_BUTT
} hal_coex_sw_preempt_mode;
typedef oal_uint8 hal_coex_sw_preempt_mode_uint8;

typedef enum {
    HAL_BTCOEX_SW_POWSAVE_IDLE = 0,
    HAL_BTCOEX_SW_POWSAVE_WORK = 1,
    HAL_BTCOEX_SW_POWSAVE_TIMEOUT = 2,
    HAL_BTCOEX_SW_POWSAVE_SCAN = 3,
    HAL_BTCOEX_SW_POWSAVE_SCAN_BEGIN = 4,
    HAL_BTCOEX_SW_POWSAVE_SCAN_WAIT = 5,
    HAL_BTCOEX_SW_POWSAVE_SCAN_ABORT = 6,
    HAL_BTCOEX_SW_POWSAVE_SCAN_END = 7,
    HAL_BTCOEX_SW_POWSAVE_PSM_START = 8,
    HAL_BTCOEX_SW_POWSAVE_PSM_END = 9,
    HAL_BTCOEX_SW_POWSAVE_PSM_STOP = 10,

    HAL_BTCOEX_SW_POWSAVE_BUTT
} hal_coex_sw_preempt_type;
typedef oal_uint8 hal_coex_sw_preempt_type_uint8;

typedef enum {
    HAL_BTCOEX_SW_POWSAVE_SUB_ACTIVE = 0,
    HAL_BTCOEX_SW_POWSAVE_SUB_IDLE = 1,
    HAL_BTCOEX_SW_POWSAVE_SUB_SCAN = 2,
    HAL_BTCOEX_SW_POWSAVE_SUB_CONNECT = 3,
    /* ??????????????????????????ps=1????????????psm ????????????????soc?????????? */
    HAL_BTCOEX_SW_POWSAVE_SUB_PSM_FORBIT = 4,

    HAL_BTCOEX_SW_POWSAVE_SUB_BUTT
} hal_coex_sw_preempt_subtype_enum;
typedef oal_uint8 hal_coex_sw_preempt_subtype_uint8;

typedef enum {
    HAL_BTCOEX_ONEPKT_NORMAL = 0,    // ??????????
    HAL_BTCOEX_ONEPKT_PRIORITY = 1,  // priority
    HAL_BTCOEX_ONEPKT_OCCUPIED = 2,  // OCCUPIED
    HAL_BTCOEX_PRIORITY_BUTT
} hal_coex_priority_type_enum;
typedef oal_uint8 hal_coex_priority_type_uint8;

/* sco ????mode???? */
typedef enum {
    HAL_BTCOEX_SCO_MODE_NONE = 0,   /* ???????? */
    HAL_BTCOEX_SCO_MODE_12SLOT = 1, /* 12slot???? */
    HAL_BTCOEX_SCO_MODE_6SLOT = 2,  /* 6slot???? */

    HAL_BTCOEX_SCO_MODE_BUTT
} hal_btcoex_sco_mode_enum;
typedef oal_uint8 hal_btcoex_sco_mode_enum_uint8;

typedef enum {
    HAL_BTCOEX_AGGR_TIME_OTHER,
    HAL_BTCOEX_AGGR_TIME_TRANSFER,
    HAL_BTCOEX_AGGR_TIME_12SLOT,
    HAL_BTCOEX_AGGR_TIME_6SLOT,
    HAL_BTCOEX_AGGR_TIME_BLE_HID,
    HAL_BTCOEX_AGGR_TIME_SCO_SHORT,
    HAL_BTCOEX_AGGR_TIME_BUTT
} hal_btcoex_aggr_tiyme_type;
typedef oal_uint8 hal_btcoex_aggr_time_type_uint8;
#endif
/* NR???????????????? */
#ifdef _PRE_WLAN_FEATURE_NRCOEX
/* ??????????????????WiFi????????????????0???? */
typedef enum {
    HAL_NRCOEX_PRIORITY_HIGH = 0,
    HAL_NRCOEX_PRIORITY_LOW = 1,
    HAL_NRCOEX_PRIORITY_SAME = 2,
    HAL_NRCOEX_PRIORITY_BUTT
} hal_nrcoex_priority_enum;
/* ??????MODEM??WiFi??????????????1???? */
typedef enum {
    HAL_MSG_WIFI_PRIORITY_HIGH = 1,
    HAL_MSG_WIFI_PRIORITY_LOW = 2,
    HAL_MSG_WIFI_PRIORITY_SAME = 3,
    HAL_MSG_WIFI_PRIORITY_BUTT
} hal_msg_wifi_priority_enum;
typedef oal_uint8 hal_nrcoex_priority_enum_uint8;
typedef enum {
    WLAN_NRCOEX_CMD_DISPLAY_INFO,
    WLAN_NRCOEX_CMD_NRCOEX_EVENT,
    WLAN_NRCOEX_CMD_MODEM_FREQ,
    WLAN_NRCOEX_CMD_MODEM_BW,
    WLAN_NRCOEX_CMD_BUTT
} wlan_nrcoex_cmd_enum;
typedef oal_uint8 wlan_nrcoex_cmd_enum_uint8;

typedef enum {
    HAL_NRCOEX_MODEM_CHAIN_RFIC0_TX0 = 0,
    HAL_NRCOEX_MODEM_CHAIN_RFIC0_TX1 = 1,
    HAL_NRCOEX_MODEM_CHAIN_RFIC1_TX0 = 2,
    HAL_NRCOEX_MODEM_CHAIN_RFIC1_TX1 = 3,
    HAL_NRCOEX_MODEM_CHAIN_RFIC0_TX01 = 4,
    HAL_NRCOEX_MODEM_CHAIN_RFIC1_TX01 = 5,

    HAL_NRCOEX_MODEM_CHAIN_BUTT
} hal_nrcoex_modem_chain_enum;
typedef oal_uint8 hal_nrcoex_modem_chain_enum_uint8;

typedef enum {
    HAL_NRCOEX_MODEM_BW_200K = 0,
    HAL_NRCOEX_MODEM_BW_1M2288 = 1,
    HAL_NRCOEX_MODEM_BW_1M28 = 2,
    HAL_NRCOEX_MODEM_BW_1M4 = 3,
    HAL_NRCOEX_MODEM_BW_3M = 4,
    HAL_NRCOEX_MODEM_BW_5M = 5,
    HAL_NRCOEX_MODEM_BW_10M = 6,
    HAL_NRCOEX_MODEM_BW_15M = 7,
    HAL_NRCOEX_MODEM_BW_20M = 8,
    HAL_NRCOEX_MODEM_BW_25M = 9,
    HAL_NRCOEX_MODEM_BW_30M = 10,
    HAL_NRCOEX_MODEM_BW_40M = 11,
    HAL_NRCOEX_MODEM_BW_50M = 12,
    HAL_NRCOEX_MODEM_BW_60M = 13,
    HAL_NRCOEX_MODEM_BW_80M = 14,
    HAL_NRCOEX_MODEM_BW_90M = 15,
    HAL_NRCOEX_MODEM_BW_100M = 16,
    HAL_NRCOEX_MODEM_BW_200M = 17,
    HAL_NRCOEX_MODEM_BW_400M = 18,
    HAL_NRCOEX_MODEM_BW_800M = 19,
    HAL_NRCOEX_MODEM_BW_1G = 20,
    HAL_NRCOEX_MODEM_BW_BUTT
} hal_nrcoex_modem_bw_enum;
typedef oal_uint8 hal_nrcoex_modem_bw_enum_uint8;

typedef enum {
    HAL_NRCOEX_AVOID_FLAG_NORMAL = 0, /* ?????????????????? */
    HAL_NRCOEX_AVOID_FLAG_LP = 1,     /* ??1?????? */
    HAL_NRCOEX_AVOID_FLAG_TB = 2,     /* ???????? */

    HAL_NRCOEX_AVOID_FLAG_BUTT
} hal_nrcoex_avoid_flag_enum;
typedef oal_uint8 hal_nrcoex_avoid_flag_enum_uint8;

#endif
#ifdef _PRE_WLAN_FIT_BASED_REALTIME_CALI

typedef enum {
    HAL_DYN_CALI_PDET_ADJUST_INIT = 0,
    HAL_DYN_CALI_PDET_ADJUST_ASCEND,  /* while real_pdet < expect_pdet */
    HAL_DYN_CALI_PDET_ADJUST_DECLINE, /* while real_pdet > expect_pdet */
    HAL_DYN_CALI_PDET_ADJUST_VARIED,
    HAL_DYN_CALI_PDET_ADJUST_BUTT,
} hal_dyn_cali_adj_type_enum;
typedef oal_uint8 hal_dyn_cali_adj_type_enum_uint8;

#endif

/*****************************************************************************
  4 ????????
*****************************************************************************/
OAL_STATIC OAL_INLINE oal_uint32 *hal_rx_dscr_get_real_addr(oal_uint32 *pul_rx_dscr)
{
    /* ????????2????hi1102_rx_buffer_addr_stru??????????prev????????????next???????? */
    if (pul_rx_dscr == OAL_PTR_NULL) {
        return pul_rx_dscr;
    }
    return pul_rx_dscr + 2;
}

OAL_STATIC OAL_INLINE oal_uint32 *hal_rx_dscr_get_sw_addr(oal_uint32 *pul_rx_dscr)
{
    /* ????????2????hi1102_rx_buffer_addr_stru??????????prev????????????next???????? */
    if (pul_rx_dscr == OAL_PTR_NULL) {
        OAL_IO_PRINT("[file = %s, line = %d], hal_rx_dscr_get_sw_addr, dscr is NULL!\r\n",
                     __FILE__, __LINE__);
        return pul_rx_dscr;
    }
    return pul_rx_dscr - 2;
}

#endif /* end of #if (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102_DEV) */

/*****************************************************************************/
/*****************************************************************************/
/* ???????????????????????? */
/*****************************************************************************/
/*****************************************************************************/
/* ?????????????????????????? */
#define HAL_GET_DATA_PROTOCOL_MODE(_val) ((_val) >> 6)

/* ?????????????? */
#define HAL_TPC_11B_RATE_NUM 4 /* 11b???????? */
#define HAL_TPC_11G_RATE_NUM 8 /* 11g???????? */
#define HAL_TPC_11A_RATE_NUM 8 /* 11a???????? */
#ifdef _PRE_WLAN_FEATURE_11AC_20M_MCS9
#define HAL_TPC_11AC_20M_NUM 10 /* 11n_11ac_2g???????? */
#else
#define HAL_TPC_11AC_20M_NUM 9 /* 11n_11ac_2g???????? */
#endif
#define HAL_TPC_11AC_40M_NUM 11 /* 11n_11ac_2g???????? */
#define HAL_TPC_11AC_80M_NUM 10 /* 11n_11ac_2g???????? */

/* rate-tpccode table?????????? */
#define HAL_TPC_RATE_TPC_CODE_TABLE_LEN (HAL_TPC_11B_RATE_NUM + HAL_TPC_11G_RATE_NUM + HAL_TPC_11AC_20M_NUM \
                                                + HAL_TPC_11AC_40M_NUM + HAL_TPC_11AC_80M_NUM)
#define HAL_TPC_RATE_TPC_CODE_TABLE_LEN_2G (HAL_TPC_RATE_TPC_CODE_TABLE_LEN - HAL_TPC_11AC_80M_NUM)
#define HAL_TPC_RATE_TPC_CODE_TABLE_LEN_5G HAL_TPC_RATE_TPC_CODE_TABLE_LEN

#define HAL_POW_CUSTOM_24G_11B_RATE_NUM    2
#define HAL_DBB_SCALING_FOR_MAX_TXPWR_BASE 128

#define CUS_NUM_OF_SAR_PARAMS 8 /* ????????SAR???? 5G_BAND1~7 2.4G */

#define NUM_OF_NV_MAX_TXPOWER 47 /* NVRAM???????????????????????????????????????? */

#define CUS_BASE_PWR_NUM_2G 1
#define CUS_BASE_PWR_NUM_5G 7 /* 5g Base power 7?? band 1~7 */
#define CUS_BASE_POWER_NUM  (CUS_BASE_PWR_NUM_2G + CUS_BASE_PWR_NUM_5G)

#define CUS_SAR_NUM_2G 1
#define CUS_SAR_NUM_5G 7 /* 5g Base power 7?? band 1~7 */
#define CUS_SAR_NUM    (CUS_SAR_NUM_2G + CUS_SAR_NUM_5G)

#define CUS_BT_TXPWR_FREQ_NUM_MAX 8  // BT Tx Power calibration max frequency number
#define CUS_BT_FREQ_NUM           79 // BT frequency number

#define FCC_CE_SIG_TYPE_NUM_2G   3 /* FCC CE ??????2g 11B+OFDM_20M+OFDM_40M */
#define FCC_CE_CH_NUM_5G_20M     9 /* FCC CE ?????? 5g 20MHz ???????? */
#define FCC_CE_CH_NUM_5G_40M     6 /* FCC CE ?????? 5g 40MHz ???????? */
#define FCC_CE_CH_NUM_5G_80M     5 /* FCC CE ?????? 5g 80MHz ???????? */
#define FCC_CE_CH_NUM_5G_160M    2 /* FCC CE ?????? 5g 160MHz ???????? */
#define FCC_CE_EXT_CH_NUM_5G_20M 4 /* FCC CE?????? ??????5g 20M???????? */
#define FCC_CE_EXT_CH_NUM_5G_40M 4 /* FCC CE?????? ??????5g 40M???????? */

/*****************************************************************************
  3 ????????
*****************************************************************************/
typedef enum {
    HAL_REGDOMAIN_FCC = 0,
    HAL_REGDOMAIN_ETSI = 1,
    HAL_REGDOMAIN_JAPAN = 2,
    HAL_REGDOMAIN_COMMON = 3,

    HAL_REGDOMAIN_COUNT
} hal_regdomain_enum;
typedef oal_uint8 hal_regdomain_enum_uint8;

/* 2.4GHz????: ?????????????????????? */
typedef enum {
    HAL_2G_CHANNEL1 = 0,
    HAL_2G_CHANNEL2 = 1,
    HAL_2G_CHANNEL3 = 2,
    HAL_2G_CHANNEL4 = 3,
    HAL_2G_CHANNEL5 = 4,
    HAL_2G_CHANNEL6 = 5,
    HAL_2G_CHANNEL7 = 6,
    HAL_2G_CHANNEL8 = 7,
    HAL_2G_CHANNEL9 = 8,
    HAL_2G_CHANNEL10 = 9,
    HAL_2G_CHANNEL11 = 10,
    HAL_2G_CHANNEL12 = 11,
    HAL_2G_CHANNEL13 = 12,
    HAL_2G_CHANNEL14 = 13,

    HAL_CHANNEL_FREQ_2G_BUTT = 14
} hal_channel_freq_2g_enum;
typedef oal_uint8 hal_channel_freq_2g_enum_uint8;

typedef enum {
    HAL_FCS_PROTECT_TYPE_NONE = 0,  /* NONE */
    HAL_FCS_PROTECT_TYPE_SELF_CTS,  /* SELF CTS */
    HAL_FCS_PROTECT_TYPE_NULL_DATA, /* NULL DATA */
    HAL_FCS_PROTECT_TYPE_QOSNULL,
    HAL_FCS_PROTECT_TYPE_BUTT
} hal_fcs_protect_type_enum;
typedef oal_uint8 hal_fcs_protect_type_enum_uint8;

typedef enum {
    HAL_FCS_PROTECT_COEX_PRI_NORMAL = 0,   /* b00 */
    HAL_FCS_PROTECT_COEX_PRI_PRIORITY = 1, /* b01 */
    HAL_FCS_PROTECT_COEX_PRI_OCCUPIED = 2, /* b10 */

    HAL_FCS_PROTECT_COEX_PRI_BUTT
} hal_fcs_protect_coex_pri_enum;
typedef oal_uint8 hal_fcs_protect_coex_pri_enum_uint8;

typedef enum {
    HAL_FCS_SERVICE_TYPE_DBAC = 0,      /* DBAC???? */
    HAL_FCS_SERVICE_TYPE_SCAN,          /* ???????? */
    HAL_FCS_SERVICE_TYPE_M2S,           /* m2s???????? */
    HAL_FCS_SERVICE_TYPE_BTCOEX_NORMAL, /* btcoex???????? */
    HAL_FCS_SERVICE_TYPE_BTCOEX_LDAC,   /* btcoex???????? */

    HAL_FCS_PROTECT_NOTIFY_BUTT
} hal_fcs_service_type_enum;
typedef oal_uint8 hal_fcs_service_type_enum_uint8;

typedef enum {
    HAL_FCS_PROTECT_CNT_1 = 1, /* 1 */
    HAL_FCS_PROTECT_CNT_2 = 2, /* 2 */
    HAL_FCS_PROTECT_CNT_3 = 3, /* 3 */
    HAL_FCS_PROTECT_CNT_20 = 20,
    HAL_FCS_PROTECT_CNT_BUTT
} hal_fcs_protect_cnt_enum;
typedef oal_uint8 hal_fcs_protect_cnt_enum_uint8;

typedef enum {
    HAL_OPER_MODE_NORMAL,
    HAL_OPER_MODE_HUT,

    HAL_OPER_MODE_BUTT
} hal_oper_mode_enum;
typedef oal_uint8 hal_oper_mode_enum_uint8;

/* RF????????????????????TX?????????? */
typedef enum {
    HAL_RF_TEST_DATA_RATE_ZERO,
    HAL_RF_TEST_BAND_WIDTH,
    HAL_RF_TEST_CHAN_CODE,
    HAL_RF_TEST_POWER,
    HAL_RF_TEST_BUTT
} hal_rf_test_sect_enum;
typedef oal_uint8 hal_rf_test_sect_enum_uint8;
/*****************************************************************************
  3.1 ????????????????
*****************************************************************************/
#define HAL_AC_TO_Q_NUM(_ac) (\
    ((_ac) == WLAN_WME_AC_VO) ? HAL_TX_QUEUE_VO : ((_ac) == WLAN_WME_AC_VI) ? HAL_TX_QUEUE_VI : \
    ((_ac) == WLAN_WME_AC_BK) ? HAL_TX_QUEUE_BK : ((_ac) == WLAN_WME_AC_BE) ? HAL_TX_QUEUE_BE : \
    ((_ac) == WLAN_WME_AC_MGMT) ? HAL_TX_QUEUE_HI : HAL_TX_QUEUE_BK)

#define HAL_Q_NUM_TO_AC(_q) (\
    ((_q) == HAL_TX_QUEUE_VO) ? WLAN_WME_AC_VO : ((_q) == HAL_TX_QUEUE_VI) ? WLAN_WME_AC_VI : \
    ((_q) == HAL_TX_QUEUE_BK) ? WLAN_WME_AC_BK : ((_q) == HAL_TX_QUEUE_BE) ? WLAN_WME_AC_BE : \
    ((_q) == HAL_TX_QUEUE_HI) ? WLAN_WME_AC_MGMT : WLAN_WME_AC_BE)

#define HAL_TX_QUEUE_MGMT HAL_TX_QUEUE_HI /* 0~3????AC??????????4?????????????????????????? */

/*****************************************************************************
  3.3 ??????????????????
*****************************************************************************/
typedef enum {
    HAL_TX_RATE_RANK_0 = 0,
    HAL_TX_RATE_RANK_1,
    HAL_TX_RATE_RANK_2,
    HAL_TX_RATE_RANK_3,

    HAL_TX_RATE_RANK_BUTT
} hal_tx_rate_rank_enum;
typedef oal_uint8 hal_tx_rate_rank_enum_uint8;
typedef enum {
    HAL_DFS_RADAR_TYPE_NULL = 0,
    HAL_DFS_RADAR_TYPE_FCC = 1,
    HAL_DFS_RADAR_TYPE_ETSI = 2,
    HAL_DFS_RADAR_TYPE_MKK = 3,
    HAL_DFS_RADAR_TYPE_KOREA = 4,

    HAL_DFS_RADAR_TYPE_BUTT
} hal_dfs_radar_type_enum;
typedef oal_uint8 hal_dfs_radar_type_enum_uint8;

typedef enum {
    HAL_RX_NEW = 0x0,
    HAL_RX_SUCCESS = 0x1,
    HAL_RX_DUP_DETECTED = 0x2,
    HAL_RX_FCS_ERROR = 0x3,
    HAL_RX_KEY_SEARCH_FAILURE = 0x4,
    HAL_RX_CCMP_MIC_FAILURE = 0x5,
    HAL_RX_ICV_FAILURE = 0x6,
    HAL_RX_TKIP_REPLAY_FAILURE = 0x7,
    HAL_RX_CCMP_REPLAY_FAILURE = 0x8,
    HAL_RX_TKIP_MIC_FAILURE = 0x9,
    HAL_RX_BIP_MIC_FAILURE = 0xA,
    HAL_RX_BIP_REPLAY_FAILURE = 0xB,
    HAL_RX_MUTI_KEY_SEARCH_FAILURE = 0xC /* ???????? */
} hal_rx_status_enum;
typedef oal_uint8 hal_rx_status_enum_uint8;

/* ?????????????????? */
typedef enum {
    HAL_TX_INVALID = 0,                 /* ???? */
    HAL_TX_SUCC,                        /* ???? */
    HAL_TX_FAIL,                        /* ???????????????????????????????????????? */
    HAL_TX_TIMEOUT,                     /* lifetime?????????????????? */
    HAL_TX_RTS_FAIL,                    /* RTS ????????????????????????????cts?????? */
    HAL_TX_NOT_COMPRASS_BA,             /* ??????BA?????????????? */
    HAL_TX_TID_MISMATCH,                /* ??????BA??TID????????????????????????TID?????? */
    HAL_TX_KEY_SEARCH_FAIL,             /* Key search failed */
    HAL_TX_AMPDU_MISMATCH,              /* ?????????? */
    HAL_TX_PENDING,                     /* 02:????????????pending;03:????????????pending */
    HAL_TX_FAIL_ACK_ERROR,              /* ???????????????????????????????????????????? */
    HAL_TX_RTS_FAIL_CTS_ERROR,          /* RTS????????????????????????????????CTS?????? */
    HAL_TX_FAIL_ABORT,                  /* ??????????????abort?? */
    HAL_TX_FAIL_STATEMACHINE_PHY_ERROR, /* MAC??????????????????????????????phy???????????????? */
    HAL_TX_SOFT_PSM_BACK,               /* ???????????? */
    HAL_TX_SOFT_RESERVE,                /* reserved */
} hal_tx_dscr_status_enum;
typedef oal_uint8 hal_tx_status_enum_uint8;

/* ?????????????????? */
typedef enum {
    HAL_DSCR_QUEUE_INVALID = 0,
    HAL_DSCR_QUEUE_VALID,
    HAL_DSCR_QUEUE_SUSPENDED,

    HAL_DSCR_QUEUE_STATUS_BUTT
} hal_dscr_queue_status_enum;
typedef oal_uint8 hal_dscr_queue_status_enum_uint8;

/* ???????????????? */
typedef enum {
    HAL_RX_DSCR_NORMAL_PRI_QUEUE = 0,
    HAL_RX_DSCR_HIGH_PRI_QUEUE,
    HAL_RX_DSCR_SMALL_QUEUE,

    HAL_RX_DSCR_QUEUE_ID_BUTT
} hal_rx_dscr_queue_id_enum;
typedef oal_uint8 hal_rx_dscr_queue_id_enum_uint8;

/* TX ?????? 12?? b23:b22 phy???????? */
typedef enum {
    WLAN_11B_PHY_PROTOCOL_MODE = 0,         /* 11b CCK */
    WLAN_LEGACY_OFDM_PHY_PROTOCOL_MODE = 1, /* 11g/a OFDM */
    WLAN_HT_PHY_PROTOCOL_MODE = 2,          /* 11n HT */
    WLAN_VHT_PHY_PROTOCOL_MODE = 3,         /* 11ac VHT */

    WLAN_PHY_PROTOCOL_BUTT
} wlan_phy_protocol_enum;
typedef oal_uint8 wlan_phy_protocol_enum_uint8;

/* HAL??????????????WLAN_DRX????????????????
 ????:????????????dmac_wlan_drx_event_sub_type_enum_uint8???????????? */
typedef enum {
    HAL_WLAN_DRX_EVENT_SUB_TYPE_RX, /* WLAN DRX ???? */

    HAL_WLAN_DRX_EVENT_SUB_TYPE_BUTT
} hal_wlan_drx_event_sub_type_enum;
typedef oal_uint8 hal_wlan_drx_event_sub_type_enum_uint8;

/* HAL??????????????WLAN_CRX????????????????
   ????:????????????dmac_wlan_crx_event_sub_type_enum_uint8???????????? */
typedef enum {
    HAL_WLAN_CRX_EVENT_SUB_TYPE_RX, /* WLAN CRX ???? */

#ifdef _PRE_WLAN_FEATURE_FTM
    HAL_EVENT_DMAC_MISC_FTM_ACK_COMPLETE, /* FTM ACK???????????? */
#endif

    HAL_WLAN_CRX_EVENT_SUB_TYPE_BUTT
} hal_wlan_crx_event_sub_type_enum;
typedef oal_uint8 hal_wlan_crx_event_sub_type_enum_uint8;

typedef enum {
    HAL_TX_COMP_SUB_TYPE_TX,
#ifdef _PRE_WLAN_FEATURE_ALWAYS_TX
    HAL_TX_COMP_SUB_TYPE_AL_TX,
#endif

    HAL_TX_COMP_SUB_TYPE_BUTT
} hal_tx_comp_sub_type_enum;
typedef oal_uint8 hal_tx_comp_sub_type_enum_uint8;

typedef enum {
    HAL_EVENT_TBTT_SUB_TYPE,

    HAL_EVENT_TBTT_SUB_TYPE_BUTT
} hal_event_tbtt_sub_type_enum;
typedef oal_uint8 hal_event_tbtt_sub_type_enum_uint8;

typedef enum {
    HAL_COEX_SW_IRQ_LTE_RX_ASSERT = 0x1,   /* BIT0 */
    HAL_COEX_SW_IRQ_LTE_RX_DEASSERT = 0x2, /* BIT1 */
    HAL_COEX_SW_IRQ_LTE_TX_ASSERT = 0x4,   /* BIT2 */
    HAL_COEX_SW_IRQ_LTE_TX_DEASSERT = 0x8, /* BIT3 */
#if ((_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102_DEV) || (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102A_DEV))
    HAL_COEX_SW_IRQ_BT = 0x20, /* 02????????????????????BIT5 */
#else
    HAL_COEX_SW_IRQ_BT = 0x10, /* BIT4 */
#endif

    HAL_COEX_SW_IRQ_TYPE_BUTT
} hal_coex_sw_irq_type_enum;
typedef oal_uint8 hal_coex_sw_irq_type_enum_uint8;

/*****************************************************************************
  3.4 ????????????????
*****************************************************************************/
/* 3.4.1  ???????????????? */
typedef enum {
    HAL_EVENT_ERROR_IRQ_SOC_ERROR, /* SOC???????????? */
#ifdef _PRE_WLAN_FEATURE_BTCOEX
    HAL_EVENT_DMAC_HIGH_PRIO_BTCOEX_PS,
#endif
    HAL_EVENT_ERROR_IRQ_SUB_TYPE_BUTT
} hal_event_error_irq_sub_type_enum;
typedef oal_uint8 hal_event_error_irq_sub_type_enum_uint8;

/* 3.4.2  MAC???????????? (??????????????????????????????????????!) */
typedef enum {
    /* ??????????????????,????AMPDU??????????????,AMPDU??MPDU????????,sub msdu num???? */
    HAL_MAC_ERROR_PARA_CFG_ERR = 0,
    HAL_MAC_ERROR_RXBUFF_LEN_TOO_SMALL = 1,       /* ??????AMSDU????????RxBuff???????? */
    HAL_MAC_ERROR_BA_ENTRY_NOT_FOUND = 2,         /* ??????BA????????????0 */
    HAL_MAC_ERROR_PHY_TRLR_TIME_OUT = 3,          /* PHY_RX_TRAILER???? */
    HAL_MAC_ERROR_PHY_RX_FIFO_OVERRUN = 4,        /* PHY_RX_FIFO???????? */
    HAL_MAC_ERROR_TX_DATAFLOW_BREAK = 5,          /* ?????????????? */
    HAL_MAC_ERROR_RX_FSM_ST_TIMEOUT = 6,          /* RX_FSM?????????? */
    HAL_MAC_ERROR_TX_FSM_ST_TIMEOUT = 7,          /* TX_FSM?????????? */
    HAL_MAC_ERROR_RX_HANDLER_ST_TIMEOUT = 8,      /* RX_HANDLER?????????? */
    HAL_MAC_ERROR_TX_HANDLER_ST_TIMEOUT = 9,      /* TX_HANDLER?????????? */
    HAL_MAC_ERROR_TX_INTR_FIFO_OVERRUN = 10,      /* TX ????FIFO???? */
    HAL_MAC_ERROR_RX_INTR_FIFO_OVERRUN = 11,      /* RX???? FIFO???? */
    HAL_MAC_ERROR_HIRX_INTR_FIFO_OVERRUN = 12,    /* HIRX????FIFO???? */
    HAL_MAC_ERROR_UNEXPECTED_RX_Q_EMPTY = 13,     /* ????????????????????????RX BUFFER???????? */
    HAL_MAC_ERROR_UNEXPECTED_HIRX_Q_EMPTY = 14,   /* ??????????????????????HI RX BUFFER???????? */
    HAL_MAC_ERROR_BUS_RLEN_ERR = 15,              /* ????????????????0???? */
    HAL_MAC_ERROR_BUS_RADDR_ERR = 16,             /* ?????????????????????? */
    HAL_MAC_ERROR_BUS_WLEN_ERR = 17,              /* ????????????????0???? */
    HAL_MAC_ERROR_BUS_WADDR_ERR = 18,             /* ?????????????????????? */
    HAL_MAC_ERROR_TX_ACBK_Q_OVERRUN = 19,         /* tx acbk????fifo???? */
    HAL_MAC_ERROR_TX_ACBE_Q_OVERRUN = 20,         /* tx acbe????fifo???? */
    HAL_MAC_ERROR_TX_ACVI_Q_OVERRUN = 21,         /* tx acvi????fifo???? */
    HAL_MAC_ERROR_TX_ACVO_Q_OVERRUN = 22,         /* tx acv0????fifo???? */
    HAL_MAC_ERROR_TX_HIPRI_Q_OVERRUN = 23,        /* tx hipri????fifo???? */
    HAL_MAC_ERROR_MATRIX_CALC_TIMEOUT = 24,       /* matrix???????? */
    HAL_MAC_ERROR_CCA_TIME_OUT = 25,              /* cca???? */
    HAL_MAC_ERROR_DCOL_DATA_OVERLAP = 26,         /* ????overlap???? */
    HAL_MAC_ERROR_BEACON_MISS = 27,               /* ????????beacon???? */
    HAL_MAC_ERROR_INTR_FIFO_UNEXPECTED_READ = 28, /* interrupt fifo???????? */
    HAL_MAC_ERROR_UNEXPECTED_RX_DESC_ADDR = 29,   /* rx desc???????????? */
    HAL_MAC_ERROR_RX_OVERLAP_ERR = 30,            /* mac????????????????,phy???????????????? */
    HAL_MAC_ERROR_RESERVED_31 = 31,
    HAL_MAC_ERROR_TX_ACBE_BACKOFF_TIMEOUT = 32,  /* ????BE???????????? */
    HAL_MAC_ERROR_TX_ACBK_BACKOFF_TIMEOUT = 33,  /* ????BK???????????? */
    HAL_MAC_ERROR_TX_ACVI_BACKOFF_TIMEOUT = 34,  /* ????VI???????????? */
    HAL_MAC_ERROR_TX_ACVO_BACKOFF_TIMEOUT = 35,  /* ????VO???????????? */
    HAL_MAC_ERROR_TX_HIPRI_BACKOFF_TIMEOUT = 36, /* ???????????????????????? */
    HAL_MAC_ERROR_RX_SMALL_Q_EMPTY = 37,         /* ???????????????????????????????????????? */
    HAL_MAC_ERROR_PARA_CFG_2ERR = 38,            /* ????????????AMPDU??MPDU???????? */
    HAL_MAC_ERROR_PARA_CFG_3ERR = 39,            /* ????????????11a??11b??11g????????mpdu????????????4095 */
    HAL_MAC_ERROR_EDCA_ST_TIMEOUT = 40,          /* CH_ACC_EDCA_CTRL?????????? */

    HAL_MAC_ERROR_TYPE_BUTT
} hal_mac_error_type_enum;
typedef oal_uint8 hal_mac_error_type_enum_uint8;

/* 3.4.3 SOC???????????? (??????DMAC??????????????error irq??????????) */
typedef enum {
    /* SOC???????? */
    HAL_SOC_ERROR_BUCK_OCP,     /* PMU BUCK???????? */
    HAL_SOC_ERROR_BUCK_SCP,     /* PMU BUCK???????? */
    HAL_SOC_ERROR_OCP_RFLDO1,   /* PMU RFLDO1???????? */
    HAL_SOC_ERROR_OCP_RFLDO2,   /* PMU RFLDO2???????? */
    HAL_SOC_ERROR_OCP_CLDO,     /* PMU CLDO???????? */
    HAL_SOC_ERROR_RF_OVER_TEMP, /* RF???????? */
    HAL_SOC_ERROR_CMU_UNLOCK,   /* CMU PLL???????? */
    HAL_SOC_ERROR_PCIE_SLV_ERR, /* PCIE???????????? */

    HAL_SOC_ERROR_TYPE_BUTT
} hal_soc_error_type_enum;
typedef oal_uint8 hal_soc_error_type_enum_uint8;

/* DMAC MISC ?????????????? */
typedef enum {
    HAL_EVENT_DMAC_MISC_CH_STATICS_COMP, /* ????????/???????????? */
    HAL_EVENT_DMAC_MISC_RADAR_DETECTED,  /* ?????????????? */
    HAL_EVENT_DMAC_MISC_DFS_AUTH_CAC,    /* DFS????CAC???? */
    HAL_EVENT_DMAC_MISC_DBAC,            /* DBAC */
    HAL_EVENT_DMAC_MISC_MWO_DET,
#ifdef _PRE_WLAN_FEATURE_BTCOEX
    HAL_EVENT_DMAC_BT_A2DP,
    HAL_EVENT_DMAC_BT_SCO,
    HAL_EVENT_DMAC_BT_TRANSFER,
    HAL_EVENT_DMAC_BT_PAGE_SCAN,
    HAL_EVENT_DMAC_BT_INQUIRY,
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
    HAL_EVENT_DMAC_P2P_NOA_ABSENT_START,
    HAL_EVENT_DMAC_P2P_NOA_ABSENT_END,
    HAL_EVENT_DMAC_P2P_CTWINDOW_END,
#endif
    HAL_EVENT_DMAC_BEACON_TIMEOUT, /* ????beacon?????? */
    HAL_EVENT_DMAC_CALI_TO_HMAC,   /* ??????????dmac????hmac */
    HAL_EVENT_DMAC_MISC_WOW_WAKE,

    HAL_EVENT_DMAC_MISC_GREEN_AP, /* Green ap timer */

#ifdef _PRE_WLAN_FEATURE_GNSS_SCAN
    HAL_EVENT_DMAC_MISC_IPC_IRQ, /* IPC???? */
#endif
    HAL_EVENT_DMAC_MISC_CHR,               /* dmac??????????chr???? */
    HAL_EVENT_ERROR_IRQ_MAC_ERROR,         /* MAC???????????? */
    HAL_EVENT_DMAC_MISC_BTCOEX_LDAC,       /* LDAC???? */
    HAL_EVENT_DMAC_MISC_NBFH_BACK_HOME,    /* ???????????????????? */
    HAL_EVENT_DMAC_MISC_NBFH_SWT_BCAST,    /* ??????????????????????Beacon */
    HAL_EVENT_DMAC_MISC_NBFH_HOME_TO_HOME, /* ???????????????????????????? */
#ifdef _PRE_WLAN_FEATURE_BTCOEX
    HAL_EVENT_DMAC_BTCOEX_STATUS_SYN, /* BT??????????????BT??????HOST */
    HAL_EVENT_DMAC_BLE_HID,           /* ???????? */
#endif
#ifdef _PRE_WLAN_FEATURE_NRCOEX
    HAL_EVENT_DMAC_MODEM_MSG, /* MODEM??????????????DMAC?????? */
#endif
    HAL_EVENT_DMAC_MISC_SUB_TYPE_BUTT
} hal_dmac_misc_sub_type_enum;
typedef oal_uint8 hal_dmac_misc_sub_type_enum_uint8;

/*****************************************************************************
  3.5 ????????????????
*****************************************************************************/
/****3.5.1  ?????????????????? **********************************************/
typedef enum {
    HAL_RESET_HW_TYPE_ALL = 0,
    HAL_RESET_HW_TYPE_PHY,
    HAL_RESET_HW_TYPE_MAC,
    HAL_RESET_HW_TYPE_RF,
    HAL_RESET_HW_TYPE_MAC_PHY,
    HAL_RESET_HW_TYPE_TCM,
    HAL_RESET_HW_TYPE_CPU,
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    HAL_RESET_HW_TYPE_MAC_TSF,
    HAL_RESET_HW_TYPE_MAC_CRIPTO,
    HAL_RESET_HW_TYPE_MAC_NON_CRIPTO,
    HAL_RESET_HW_TYPE_PHY_RADAR,
#endif
    HAL_RESET_HW_NORMAL_TYPE_PHY,
    HAL_RESET_HW_NORMAL_TYPE_MAC,
    HAL_RESET_HW_TYPE_DUMP_MAC,
    HAL_RESET_HW_TYPE_DUMP_PHY,

    HAL_RESET_HW_TYPE_BUTT
} hal_reset_hw_type_enum;
typedef oal_uint8 hal_reset_hw_type_enum_uint8;

/****3.5.1  ????MAC?????????? **********************************************/
typedef enum {
    HAL_RESET_MAC_ALL = 0,
    HAL_RESET_MAC_PA,
    HAL_RESET_MAC_CE,
    HAL_RESET_MAC_TSF,
    HAL_RESET_MAC_DUP,
#if defined(_PRE_PRODUCT_ID_HI110X_DEV)
    HAL_RESET_MAC_LOGIC,
#endif
    HAL_RESET_MAC_BUTT
} hal_reset_mac_submod_enum;
typedef oal_uint8 hal_reset_mac_submod_enum_uint8;

typedef enum {
    HAL_LPM_SOC_BUS_GATING = 0,
    HAL_LPM_SOC_PCIE_RD_BYPASS = 1,
    HAL_LPM_SOC_MEM_PRECHARGE = 2,
    HAL_LPM_SOC_PCIE_L0 = 3,
    HAL_LPM_SOC_PCIE_L1_PM = 4,
    HAL_LPM_SOC_AUTOCG_ALL = 5,
    HAL_LPM_SOC_ADC_FREQ = 6,

    HAL_LPM_SOC_SET_BUTT
} hal_lpm_soc_set_enum;
typedef oal_uint8 hal_lpm_soc_set_enum_uint8;

typedef enum {
    HAL_ALG_ISR_NOTIFY_DBAC,
#if (_PRE_PRODUCT_ID != _PRE_PRODUCT_ID_HI1102A_DEV)
    HAL_ALG_ISR_NOTIFY_MWO_DET,
#endif
    HAL_ALG_ISR_NOTIFY_ANTI_INTF,
    HAL_ALG_ISR_NOTIFY_BUTT,
} hal_alg_noify_enum;
typedef oal_uint8 hal_alg_noify_enum_uint8;

typedef enum {
    HAL_ISR_TYPE_TBTT,
    HAL_ISR_TYPE_ONE_PKT,

#if (_PRE_PRODUCT_ID != _PRE_PRODUCT_ID_HI1102A_DEV)
    HAL_ISR_TYPE_MWO_DET,
#endif
    HAL_ISR_TYPE_NOA_START,
    HAL_ISR_TYPE_NOA_END,

    HAL_ISR_TYPE_BUTT,
} hal_isr_type_enum;
typedef oal_uint8 hal_isr_type_enum_uint8;

/* ???????????? */
typedef enum {
    HAL_ALWAYS_TX_DISABLE,      /* ???????? */
    HAL_ALWAYS_TX_RF,           /* ??????RF???????????? */
    HAL_ALWAYS_TX_AMPDU_ENABLE, /* ????AMPDU?????????? */
    HAL_ALWAYS_TX_MPDU,         /* ???????????????? */
    HAL_ALWAYS_TX_BUTT
} hal_device_always_tx_state_enum;
typedef oal_uint8 hal_device_always_tx_enum_uint8;

typedef enum {
    HAL_ALWAYS_RX_DISABLE,      /* ???????? */
    HAL_ALWAYS_RX_RESERVED,     /* ??????RF???????????? */
    HAL_ALWAYS_RX_AMPDU_ENABLE, /* ????AMPDU?????????? */
    HAL_ALWAYS_RX_ENABLE,       /* ???????????????? */
    HAL_ALWAYS_RX_BUTT
} hal_device_always_rx_state_enum;
typedef oal_uint8 hal_device_always_rx_enum_uint8;

typedef enum {
    WLAN_PHY_RATE_1M = 0,      /* 0000 */
    WLAN_PHY_RATE_2M = 1,      /* 0001 */
    WLAN_PHY_RATE_5HALF_M = 2, /* 0010 */
    WLAN_PHY_RATE_11M = 3,     /* 0011 */

    WLAN_PHY_RATE_48M = 8,  /* 1000 */
    WLAN_PHY_RATE_24M = 9,  /* 1001 */
    WLAN_PHY_RATE_12M = 10, /* 1010 */
    WLAN_PHY_RATE_6M = 11,  /* 1011 */

    WLAN_PHY_RATE_54M = 12, /* 1100 */
    WLAN_PHY_RATE_36M = 13, /* 1101 */
    WLAN_PHY_RATE_18M = 14, /* 1110 */
    WLAN_PHY_RATE_9M = 15,  /* 1111 */

    WLAN_PHY_RATE_BUTT
} wlan_phy_rate_enum;

typedef enum {
    HAL_PHY_AGC_TARGET_ADLUST_DEFAULT = 0,
    HAL_PHY_AGC_TARGET_ADLUST_DE2DB = 1,
    HAL_PHY_AGC_TARGET_ADLUST_DE4DB = 2,

    HAL_PHY_AGC_TARGET_ADLUST_BUTT
} hal_phy_agc_target_adjust_enum;
typedef oal_uint8 hal_phy_agc_target_adjust_enmu_uint8;

/*****************************************************************************
  3.6 ????????????????
*****************************************************************************/
/****3.6.1  ???????????????? ************************************************/
typedef enum {
    HAL_KEY_TYPE_TX_GTK = 0, /* Hi1102:HAL_KEY_TYPE_TX_IGTK */
    HAL_KEY_TYPE_PTK = 1,
    HAL_KEY_TYPE_RX_GTK = 2,
    HAL_KEY_TYPE_RX_GTK2 = 3, /* 02???? */
    HAL_KEY_TYPE_BUTT
} hal_cipher_key_type_enum;
typedef oal_uint8 hal_cipher_key_type_enum_uint8;

/****3.6.2  ?????????????????????????????? **********************************/
typedef enum {
    HAL_WEP40 = 0,
    HAL_TKIP = 1,
    HAL_CCMP = 2,
    HAL_NO_ENCRYP = 3,
    HAL_WEP104 = 4,
    HAL_BIP = 5,
    HAL_GCMP = 6,
    HAL_GCMP_256 = 7,
    HAL_CCMP_256 = 8,
    HAL_BIP_256 = 9,
    HAL_CIPER_PROTOCOL_TYPE_BUTT
} hal_cipher_protocol_type_enum;
typedef oal_uint8 hal_cipher_protocol_type_enum_uint8;

/****3.6.3  ??????????????????CE_LUT_CONFIG AP/STA **************************/
typedef enum {
    HAL_AUTH_KEY = 0, /* ?????????????????? */
    HAL_SUPP_KEY = 1, /* ?????????????????? */

    HAL_KEY_ORIGIN_BUTT,
} hal_key_origin_enum;
typedef oal_uint8 hal_key_origin_enum_uint8;

/* ?????????????????????????????????????????????????????????????????????????????????? */
typedef enum {
    MAC_SCAN_STATE_IDLE,
    MAC_SCAN_STATE_RUNNING,

    MAC_SCAN_STATE_BUTT
} mac_scan_state_enum;
typedef oal_uint8 mac_scan_state_enum_uint8;

typedef enum {
    HAL_CHR_CALI_ERR_TX_POWER = 0,
    HAL_CHR_CALI_ERR_TIMEOUT,
    HAL_CHR_CALI_ERR_PHASE0_SHIFT,
    HAL_CHR_CALI_ERR_PHASE1_SHIFT,
    HAL_CHR_CALI_ERR_PHASE2_SHIFT,
    HAL_CHR_CALI_ERR_PHASE3_SHIFT,
    HAL_CHR_CALI_ERR_GET_TONE,
    HAL_CHR_CALI_ERR_AUTO_AGC,
    HAL_CHR_CALI_ERR_RX_IQ_GNSS_WORK,
    HAL_CHR_CALI_ERR_TX_IQ_GNSS_WORK,
    HAL_CHR_CALI_ERR_PLL_UPC_2G,
    HAL_CHR_CALI_ERR_SA_REPORT,
    HAL_CHR_CALI_ERR_TXIQ_ILLEGAL_VAL,
    HAL_CHR_CALI_ERR_RXIQ_ILLEGAL_VAL,

    HAL_CHR_CALI_ERR_RC_CODE_ILLEGAL_VAL, /* 02a???? */
    HAL_CHR_CALI_ERR_RX_DC_REMAIN_ILLEGAL_VAL,
    HAL_CHR_CALI_ERR_PLL_CFG_CHECK,
    HAL_CHR_CALI_ERR_DYN_ADJUST_UPC,
    HAL_CHR_CALI_ERR_PLL_UPC_5G,
    HAL_CHR_CALI_ERR_MATRIX_NULL,
    HAL_CHR_CALI_ERR_FEM_FAIL,
    HAL_CHR_CALI_ERR_RECOVER_FAIL,
    HAL_CHR_CALI_ERR_BUTT
} hal_chr_cali_err_enum;
typedef oal_uint8 hal_chr_cali_err_enum_uint8;

typedef struct tag_hal_chr_cali_err_stru {
    hal_chr_cali_err_enum_uint8 uc_chr_cali_err;
} hal_chr_cali_err_stru;

typedef enum {
    HAL_SUSPEND_BY_NRCOEX = BIT0,
    HAL_SUSPEND_BY_OTHER = BIT1
} hal_tx_suspend_enum;

typedef enum {
    HAL_SEND_BY_BLE = BIT0,
    HAL_SEND_BY_OTHER = BIT1
} hal_onepacket_enum;
#define HAL_SEND_BY_NULL 0
/*****************************************************************************
  7 STRUCT????
*****************************************************************************/
typedef struct {
    oal_int32 l_pow_par2; /* ?????????? */
    oal_int32 l_pow_par1; /* ???? */
    oal_int32 l_pow_par0; /* ?????? */
} wlan_cus_pwr_fit_para_stru;

typedef struct hal_pwr_efuse_amend_stru {
    oal_int16 s_efuse_gain; /* pdbuf-VGA Gain */
    oal_int16 s_efuse_dc;   /* pdbuf-VGA offset */
} hal_pwr_efuse_amend_stru;

typedef struct {
    hal_fcs_protect_type_enum_uint8 en_protect_type;
    hal_fcs_protect_cnt_enum_uint8 en_protect_cnt;

    oal_uint16 us_wait_timeout; /* ?????????????????? */
    oal_uint32 ul_tx_mode;
    oal_uint32 ul_tx_data_rate;
    oal_uint16 us_duration; /* ???? us */
    oal_uint16 us_timeout;
    oal_uint8 *puc_protect_frame;
} hal_one_packet_cfg_stru;

typedef struct {
    oal_bool_enum_uint8 en_mac_in_one_pkt_mode : 1;
    oal_bool_enum_uint8 en_self_cts_success : 1;
    oal_bool_enum_uint8 en_null_data_success : 1;
    oal_bool_enum_uint8 ul_resv : 5;
} hal_one_packet_status_stru;

typedef struct {
    oal_uint8 uc_pn_tid;      /* tid,0~7, ??rx pn lut???? */
    oal_uint8 uc_pn_peer_idx; /* ????peer????,0~31 */
    oal_uint8 uc_pn_key_type; /* 1151 0:multicast,1:unicast */
    /* 1102 tx pn: 0x0??GTK(multicast) 0x1??PTK(unicast) 0x2??IGTK others??reserved */
    /* 1102 rx pn: 0x0??????/?????????? 0x1??????qos?????? 0x2????????qos??????
                                         0x3????????????  0x4??????/?????????? others?????? */
    oal_uint8 uc_all_tid; /* 0:??????TID,1:????TID ??rx pn lut???? */
    oal_uint32 ul_pn_msb; /* pn??????32??,???????????????????????????????? */
    oal_uint32 ul_pn_lsb; /* pn??????32???????????????????????????????????? */
} hal_pn_lut_cfg_stru;

#ifdef _PRE_WLAN_FEATURE_BTCOEX
typedef struct {
    oal_uint16 bit_bt_on : 1,
               bit_bt_cali : 1,
               bit_bt_ps : 1,
               bit_bt_inquiry : 1,
               bit_bt_page : 1,
               bit_bt_acl : 1,
               bit_bt_a2dp : 1,
               bit_bt_sco : 1,
               bit_bt_data_trans : 1,
               bit_bt_acl_num : 3,
               bit_bt_link_role : 4;
} bt_status_stru;

typedef union {
    oal_uint16 us_bt_status_reg;
    bt_status_stru st_bt_status;
} btcoex_bt_status_union;

typedef struct {
    oal_uint16 bit_ble_on : 1,
               bit_ble_scan : 1,
               bit_ble_con : 1,
               bit_ble_adv : 1,
               bit_bt_transfer : 1, /* not use (only wifi self) */
               bit_bt_6slot : 2,
               bit_ble_init : 1,
               bit_bt_acl : 1,
               bit_bt_ldac : 1,
               bit_resv1 : 1,
               bit_bt_hid : 1,
               bit_ble_hid : 1,
               bit_ble_scan_flag : 1,  // ????02A??????20db,????????????????????????????
               bit_sco_notify : 1,
               bit_bt_ba : 1;
} ble_status_stru;

typedef union {
    oal_uint16 us_ble_status_reg;
    ble_status_stru st_ble_status;
} btcoex_ble_status_union;

typedef struct hal_btcoex_btble_status {
    btcoex_bt_status_union un_bt_status;
    btcoex_ble_status_union un_ble_status;
} hal_btcoex_btble_status_stru;

typedef struct {
    oal_uint16 bit_freq : 1,
               bit_channel_num : 5,
               bit_band : 3,
               bit_join_state : 1,
               bit_key_frame : 3,
               bit_vap_state : 1,
               bit_p2p_scan_state : 1,
               bit_p2p_conn_state : 1;
} wifi_status0_stru;

typedef union {
    oal_uint16 us_wifi_status0_reg;
    wifi_status0_stru st_wifi_status0;
} btcoex_wifi_status0_union;

typedef struct {
    oal_uint16 bit_wifi_on : 1,
               bit_scan_state : 1,
               bit_connecting_state : 1,
               bit_connect_state : 1,
               bit_low_rate : 2,
               bit_low_power_state : 1,
               bit_ps_state : 1,
               bit_resv : 8;
} wifi_status1_stru;

typedef union {
    oal_uint16 us_wifi_status1_reg;
    wifi_status1_stru st_wifi_status1;
} btcoex_wifi_status1_union;

typedef struct {
    btcoex_wifi_status0_union un_wifi_status0;
    btcoex_wifi_status1_union un_wifi_status1;
} btcoex_wifi_status_stru;
typedef struct {
    oal_uint32 ul_abort_start_cnt;
    oal_uint32 ul_abort_done_cnt;
    oal_uint32 ul_abort_end_cnt;
    oal_uint32 ul_preempt_cnt;
    oal_uint32 ul_post_preempt_cnt;
    oal_uint32 ul_post_premmpt_fail_cnt;
    oal_uint32 ul_abort_duration_on;
    oal_uint32 ul_abort_duration_start_us;
    oal_uint32 ul_abort_duration_us;
    oal_uint32 ul_abort_duration_s;
} hal_btcoex_statistics_stru;
#endif
typedef struct {
    oal_uint32 bit_nrcoex_machw_tx_suspend : 1,
               bit_nrcoex_resume_machw_tx : 1,
               bit_nrcoex_disable_ack_trans : 1,
               bit_nrcoex_enable_ack_trans : 1,
               bit_nrcoex_disable_cts_trans : 1,
               bit_nrcoex_enable_cts_trans : 1,
               bit_resv : 26;
} hal_suspend_stru;

/* nr????????????device??host?????????????????? */
#ifdef _PRE_WLAN_FEATURE_NRCOEX
#if (defined(_PRE_PRODUCT_ID_HI110X_DEV))
#pragma pack(1)
#endif
typedef struct {
    oal_uint16 us_relative_freq_gap0;  // WiFi??????????modem????????????0??????
    oal_uint16 us_relative_freq_gap1;  // WiFi??????????modem????????????1??????
    oal_uint16 us_relative_freq_gap2;  // WiFi??????????modem????????????2??????
    oal_uint8 uc_limit_power_gear0;    // WiFi??????????????????????0????????
    oal_uint8 uc_limit_power_gear1;    // WiFi??????????????????????1????????
    oal_uint8 uc_limit_power_gear2;    // WiFi??????????????????????2????????
    oal_int8 c_rssi_th;                // WiFi????modem??????????????rssi????
    oal_uint8 auc_res[2];
} __OAL_DECLARE_PACKED wlan_nrcoex_threshold_stru;

typedef struct {
    oal_uint16 us_high_freq_th;                                         // NR????????????????WiFi????????????
    oal_uint16 us_low_freq_th;                                          // NR????????????????WiFi????????????
    wlan_nrcoex_threshold_stru ast_threshold_params[WLAN_BW_CAP_BUTT];  // ??????????????????????rssi??????
} __OAL_DECLARE_PACKED wlan_nrcoex_rule_stru;

typedef struct {
    oal_uint8 en_wifi_nrcoex_switch;  // NR????????????
    oal_uint8 auc_res[3];
    wlan_nrcoex_rule_stru ast_nrcoex_rule[HAL_NRCOEX_RULE_NUM];  // ??????????????????????rssi??????
} __OAL_DECLARE_PACKED wlan_nrcoex_ini_stru;
#if (defined(_PRE_PRODUCT_ID_HI110X_DEV))
#pragma pack()
#endif

typedef struct {
    oal_uint16 us_wifi_center_freq;                      /* WiFi???????? */
    oal_uint16 us_modem_center_freq;                     /* Modem???????? */
    wlan_bw_cap_enum_uint8 en_wifi_bw;                   /* WiFi???? */
    hal_nrcoex_modem_bw_enum_uint8 en_modem_bw;          /* Modem???? */
    hal_nrcoex_avoid_flag_enum_uint8 en_wifi_avoid_flag; /* WiFi???????????? */
    hal_nrcoex_priority_enum_uint8 en_wifi_priority;     /* WiFi?????? */
} wlan_nrcoex_info_stru;

typedef oal_void (*p_nrcoex_set_tx_pow_cb)(oal_void);

typedef struct {
    oal_uint8 uc_cur_limit_power;                          // ????????????????????????????,??????0xff
    oal_uint8 uc_lp_power;                                 // LP????????????????
    oal_bool_enum_uint8 en_modem_nrcoex_switch;            // ????modem????NR????????????????
    oal_bool_enum_uint8 en_wifi_status;                    // WiFi??????????????
    wlan_nrcoex_rule_stru *pst_cur_nrcoex_rule;            // ????NR????????????INI????????
    frw_timeout_stru st_key_frame_protect_timer;           // ????????????????
    oal_uint32 ul_key_frame_timestamp;                     // ????????????????
    oal_uint16 us_key_frame_protect_time;                  // ??????????????????
    oal_bool_enum_uint8 en_key_frame_protect_flag;         // ??????????????????
    hal_nrcoex_modem_chain_enum_uint8 en_modem_chain;      // modem????????
    oal_uint16 us_wifi_center_freq;                        // WiFi????????
    oal_uint16 us_modem_center_freq;                       // modem????????
    wlan_bw_cap_enum_uint8 en_wifi_bw;                     // WiFi????
    hal_nrcoex_modem_bw_enum_uint8 en_modem_bw;            // modem????
    hal_nrcoex_priority_enum_uint8 en_wifi_priority;       // WiFi??????
    hal_nrcoex_priority_enum_uint8 en_modem_priority;      // modem??????
    hal_nrcoex_avoid_flag_enum_uint8 en_wifi_avoid_flag;   // WiFi??????????????
    hal_nrcoex_avoid_flag_enum_uint8 en_modem_avoid_flag;  // modem??????????????
    oal_bool_enum_uint8 en_rssi_high;                      // ????rssi????????NR??????rssi??????
    oal_uint8 uc_rssi_valid_cnt;                           // ??????????rssi????
    oal_bool_enum_uint8 en_dbac_status;                    // dbac????
    oal_bool_enum_uint8 en_clear_freq_bw;                  // ??????????????user????????????????????????0
    oal_bool_enum_uint8 en_is_fsm_attached;
    oal_uint8 auc_res[1];
    oal_fsm_stru st_nrcoex_fsm;
    oal_uint32 ul_rxslot_begin_ts;  // wifi rx slot????????
    oal_uint32 ul_rxslot_end_ts;    // wifi rx slot????????
    p_nrcoex_set_tx_pow_cb p_nrcoex_set_tx_pow;
} hal_nrcoex_mgr_stru;

typedef struct {
    wlan_nrcoex_cmd_enum_uint8 en_nrcoex_cmd;
    oal_uint8 auc_res[1];
    oal_uint16 us_value;
} wlan_nrcoex_cmd_stru;
#endif

typedef struct hal_wifi_channel_status {
    oal_uint8 uc_chan_number; /* ??20MHz?????? */
    oal_uint8 uc_band;        /* ???? */
    oal_uint8 uc_bandwidth;   /* ???????? */
    oal_uint8 uc_idx;         /* ?????????? */
} hal_wifi_channel_status_stru;
#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
#define CUS_DY_CALI_DPN_PARAMS_NUM 4 /* ??????????????2.4G DPN????????11b OFDM20/40 CW OR 5G 160/80/40/20 */
#define CUS_DY_CALI_NUM_5G_BAND    5 /* ????????5g band1 2&3 4&5 6 7 */
#define CUS_2G_CHANNEL_NUM         13
#define CUS_DY_CALI_PARAMS_NUM     14  /* ????????????????,2.4g 3??(ofdm 20/40 11b cw),5g 5*2??band */
#define CUS_DY_CALI_PARAMS_TIMES   3   /* ?????????????????????????? */
#define CUS_DY_CALI_2G_VAL_DPN_MAX 50  /* ????????2g dpn????nvram?????? */
#define CUS_DY_CALI_2G_VAL_DPN_MIN -50 /* ????????2g dpn????nvram?????? */
#endif
#ifdef _PRE_WLAN_FIT_BASED_REALTIME_CALI
typedef struct {
    oal_int32 al_dy_cali_base_ratio_params[CUS_DY_CALI_PARAMS_NUM][CUS_DY_CALI_PARAMS_TIMES]; /* ?????????????????? */
    oal_int8 ac_dy_cali_2g_dpn_params[CUS_2G_CHANNEL_NUM][CUS_DY_CALI_DPN_PARAMS_NUM];
    oal_int8 ac_dy_cali_5g_dpn_params[CUS_DY_CALI_NUM_5G_BAND][WLAN_BW_CAP_160M];
    oal_int8 c_5g_iq_cali_backoff_pow;                     /* 5G IQ???????????? */
    oal_uint16 aus_dyn_cali_dscr_interval[WLAN_BAND_BUTT]; /* ????????????2.4g 5g */
    oal_int16 as_extre_point_val[CUS_DY_CALI_NUM_5G_BAND];
    oal_int16 s_gm0_dB10;
    oal_int32 al_dy_cali_base_ratio_ppa_params[CUS_DY_CALI_PARAMS_TIMES]; /* ppa-pow?????????????? */
    oal_uint8 uc_tx_power_pdbuf_opt;
    oal_uint8 uc_5g_upc_upper_limit; /* 5G????????UPC?????? */
    oal_uint16 us_5g_iq_cali_pow;    /* 5G IQ??????????????rx iq--??8??, tx iq--??8?? */
    oal_int32 al_bt_power_fit_params[CUS_DY_CALI_PARAMS_TIMES];
    oal_int32 al_bt_ppavdet_fit_params[CUS_DY_CALI_PARAMS_TIMES];
} wlan_cus_dy_cali_param_stru;
#endif

/*****************************************************************************
  7.0 ??????????????
*****************************************************************************/
/*lint -e958*/
#if (_PRE_WLAN_CHIP_VERSION == _PRE_WLAN_CHIP_FPGA_HI1101RF)
struct witp_reg_cfg {
    oal_uint16 us_soft_index;
    oal_uint8 uc_addr;
    oal_uint32 ul_val;
} __OAL_DECLARE_PACKED;
#elif (_PRE_WLAN_CHIP_VERSION == _PRE_WLAN_CHIP_FPGA_HI1151RF) /* End of _PRE_WLAN_CHIP_FPGA_HI1101RF */
struct witp_reg16_cfg {
    oal_uint16 us_addr;
    oal_uint16 us_val;
} __OAL_DECLARE_PACKED;
typedef struct witp_reg16_cfg witp_reg16_cfg_stru;

struct witp_reg_cfg {
    oal_uint16 us_addr;
    oal_uint16 us_val;
} __OAL_DECLARE_PACKED;
#elif (_PRE_WLAN_CHIP_VERSION == _PRE_WLAN_CHIP_FPGA)          /* End of _PRE_WLAN_CHIP_FPGA_HI1151RF */
struct witp_reg16_cfg {
    oal_uint16 us_addr;
    oal_uint16 us_val;
} __OAL_DECLARE_PACKED;
typedef struct witp_reg16_cfg witp_reg16_cfg_stru;

struct witp_reg_cfg {
    oal_uint16 us_addr;
    oal_uint16 us_val;
} __OAL_DECLARE_PACKED;

#elif (_PRE_WLAN_CHIP_ASIC == _PRE_WLAN_CHIP_VERSION) /* End of _PRE_WLAN_CHIP_FPGA_HI1151RF */
struct witp_reg16_cfg {
    oal_uint16 us_addr;
    oal_uint16 us_val;
} __OAL_DECLARE_PACKED;
typedef struct witp_reg16_cfg witp_reg16_cfg_stru;

struct witp_reg_cfg {
    oal_uint16 us_addr;
    oal_uint16 us_val;
} __OAL_DECLARE_PACKED;
#endif                                                /* End of _PRE_WLAN_CHIP_ASIC */

typedef struct witp_reg_cfg witp_reg_cfg_stru;

struct witp_single_tune_reg_cfg {
    oal_uint16 us_addr;
    oal_int32 ul_val;
} __OAL_DECLARE_PACKED;

typedef struct witp_single_tune_reg_cfg witp_single_tune_reg_cfg_stru;

/*lint +e958*/
/*****************************************************************************
  7.1 ??????????????????
*****************************************************************************/
typedef struct tag_hal_tx_dscr_stru {
    oal_dlist_head_stru st_entry;
    oal_netbuf_stru *pst_skb_start_addr;   /* Sub MSDU 0 Skb Address */
    oal_uint16 us_original_mpdu_len;       /* mpdu???? ?????? */
    hal_tx_queue_type_enum_uint8 uc_q_num; /* ?????????????? */
    oal_uint8 bit_is_retried : 1;          /* ???????????? */
    oal_uint8 bit_is_ampdu : 1;            /* ??????ampdu */
    oal_uint8 bit_is_rifs : 1;             /* ??????rifs???? */
    oal_uint8 bit_is_first : 1;            /* ?????????????????????? */
    oal_uint8 bit_resv : 4;
    oal_uint8 data[4];
} hal_tx_dscr_stru;

/*****************************************************************************
  7.2 ??????????????????
*****************************************************************************/
#ifndef _PRE_LINUX_TEST
typedef struct tag_hal_rx_dscr_stru {
    oal_uint32 *pul_prev_rx_dscr; /* ?????????????????? */
    oal_uint32 ul_skb_start_addr; /* ??????????????netbuf???????? */
    oal_uint32 *pul_next_rx_dscr; /* ??????????????????(????????) */
} hal_rx_dscr_stru;
#else
typedef struct tag_hal_rx_dscr_stru {
    oal_uint32 *pul_prev_rx_dscr; /* ?????????????????? */
    oal_uint   ul_skb_start_addr; /* ??????????????netbuf???????? */
    oal_uint32 *pul_next_rx_dscr; /* ??????????????????(????????) */
} hal_rx_dscr_stru;
#endif
/*****************************************************************************
  7.3 ??????????????????????????????
*****************************************************************************/
/*****************************************************************************
  ??????  : hal_channel_matrix_dsc_stru
  ????????: ??????????????
*****************************************************************************/
typedef struct {
    /* (??10 23??) */
    oal_uint8 bit_codebook : 2;
    oal_uint8 bit_grouping : 2;
    oal_uint8 bit_row_num : 4;

    oal_uint8 bit_column_num : 4;
    oal_uint8 bit_response_flag : 1; /* ??Tx ??????????????????????;?????????????????????????????????????????? */
    oal_uint8 bit_reserve1 : 3;

    oal_uint16 us_channel_matrix_length; /* ????????????????(Byte)?? */
    oal_uint32 ul_steering_matrix;       /* txbf??????????????????,?????????????????????? */
} hal_channel_matrix_dsc_stru;

typedef struct {
    /* PHY TX MODE 1(??13??) */
    /* (1) ?????????????? */
    oal_uint8 uc_extend_spatial_streams;          /* ?????????????? */
    wlan_channel_code_enum_uint8 en_channel_code; /* ????????(BCC??LDPC) */

    /* (2) ACS???? */
    hal_channel_assemble_enum_uint8 uc_channel_bandwidth; /* ???????? */

    oal_uint8 bit_lsig_txop : 1;
    oal_uint8 bit_reserved : 7;

    oal_uint8 dyn_bandwidth_in_non_ht;
    oal_uint8 dyn_bandwidth_in_non_ht_exist;
    oal_uint8 ch_bandwidth_in_non_ht_exist;

#if defined(_PRE_PRODUCT_ID_HI110X_DEV)
    oal_uint8 bit_lpf_gain_level : 2;
    oal_uint8 bit_upc_gain_level : 4;
    oal_uint8 bit_pa_gain_level : 2;

    oal_uint8 bit_dpd_enable : 1;
    oal_uint8 auc_reserve1 : 7;

    /* 02??????????????????????????tx?????????? */
    oal_uint8 bit_anti_intf_1thr : 2;
    oal_uint8 bit_anti_intf_0thr : 2;
    oal_uint8 bit_anti_intf_en : 1;
    oal_uint8 bit_reserve : 3;
#else
    oal_uint8 bit_upc_gain_level : 1;            /* UPC???????? */
    oal_uint8 bit_pa_gain_level : 1;             /* PA???????? */
    oal_uint8 bit_micro_tx_power_gain_level : 4; /* Micro Tx power???????? */
    oal_uint8 bit_dac_gain_level : 2;            /* DAC???????? */

    oal_uint8 auc_reserve1[2];
#endif

    oal_uint8 uc_smoothing; /* ?????????????????????????????? */

    wlan_sounding_enum_uint8 en_sounding_mode; /* sounding???? */
} hal_tx_txop_rate_params_stru;

typedef union {
    oal_uint32 ul_value;
    /* (??14 19 20 21??) */
    struct {
        oal_uint8 bit_tx_count : 4; /* ???????? */
        oal_uint8 bit_tx_chain_selection : 4; /* ???????????? (??????:0x1, ??????:0x3, ??????:0x7, ??????:0xf) */
        oal_uint8 uc_tx_data_antenna;         /* ?????????????????????? */

        union {
            struct {
                oal_uint8 bit_vht_mcs : 4;
                oal_uint8 bit_nss_mode : 2;      /* ???????????????????????? */
                oal_uint8 bit_protocol_mode : 2; /* ???????? */
            } st_vht_nss_mcs;
            struct {
                oal_uint8 bit_ht_mcs : 6;
                oal_uint8 bit_protocol_mode : 2; /* ???????? */
            } st_ht_rate;
            struct {
                oal_uint8 bit_legacy_rate : 4;
                oal_uint8 bit_reserved1 : 2;
                oal_uint8 bit_protocol_mode : 2; /* ???????? */
            } st_legacy_rate;
        } un_nss_rate;

        oal_uint8 bit_rts_cts_enable : 1;  /* ????????RTS */
        oal_uint8 bit_txbf_mode : 2;       /* txbf???? */
        oal_uint8 bit_preamble_mode : 1;   /* ?????? */
        oal_uint8 bit_short_gi_enable : 1; /* ?????????? */
        oal_uint8 bit_reserve : 3;
    } rate_bit_stru;
} hal_tx_txop_per_rate_params_union;

typedef struct {
    /* PHY TX MODE 2 (??15??) */
    oal_uint8 uc_tx_rts_antenna;  /* ????RTS?????????????? */
    oal_uint8 uc_rx_ctrl_antenna; /* ????CTS/ACK/BA?????????????? */
    oal_uint8 auc_reserve1[1];    /* TX VAP index ????????????????????????0 */
    oal_uint8 bit_txop_ps_not_allowed : 1;
    oal_uint8 bit_long_nav_enable : 1;
    oal_uint8 bit_group_id : 6;
} hal_tx_txop_antenna_params_stru;

#if ((_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102_DEV) || (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1103_DEV) ||  \
       (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102A_DEV) || (_PRE_TEST_MODE != _PRE_TEST_MODE_OFF) ||  \
       (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102_HOST) || (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1103_HOST) ||  \
       (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102A_HOST))
typedef struct {
    /* TX POWER (??14??) */
    oal_uint8 bit_lpf_gain_level0 : 2;
    oal_uint8 bit_upc_gain_level0 : 4;
    oal_uint8 bit_pa_gain_level0 : 2;

    oal_uint8 bit_lpf_gain_level1 : 2;
    oal_uint8 bit_upc_gain_level1 : 4;
    oal_uint8 bit_pa_gain_level1 : 2;

    oal_uint8 bit_lpf_gain_level2 : 2;
    oal_uint8 bit_upc_gain_level2 : 4;
    oal_uint8 bit_pa_gain_level2 : 2;

    oal_uint8 bit_lpf_gain_level3 : 2;
    oal_uint8 bit_upc_gain_level3 : 4;
    oal_uint8 bit_pa_gain_level3 : 2;
} hal_tx_txop_tx_power_stru;
#endif

typedef struct {
    wlan_tx_ack_policy_enum_uint8 en_ack_policy; /* ACK ???? */
    oal_uint8 uc_tid_no;                         /* ?????????? */
    oal_uint8 uc_qos_enable;                     /* ????????QoS */
    oal_uint8 auc_resv[1];
} hal_wmm_txop_params_stru;

/* ??12 17?? */
typedef struct {
    oal_uint16 us_tsf_timestamp;
    oal_uint8 uc_mac_hdr_len;
    oal_uint8 uc_num_sub_msdu;
} hal_tx_mpdu_mac_hdr_params_stru;

typedef struct {
    oal_uint32 ul_mac_hdr_start_addr;
    oal_netbuf_stru *pst_skb_start_addr;
} hal_tx_mpdu_address_params_stru;

typedef struct {
    oal_uint8 uc_ra_lut_index;
    oal_uint8 uc_tx_vap_index;
    oal_uint8 auc_resv[2];
} hal_tx_ppdu_addr_index_params_stru;

typedef struct {
    oal_uint32 ul_msdu_addr0;
    oal_uint16 us_msdu0_len;
    oal_uint16 us_msdu1_len;
    oal_uint32 ul_msdu_addr1;
} hal_tx_msdu_address_params;

typedef struct {
    oal_uint8 uc_long_retry;
    oal_uint8 uc_short_retry;
    oal_uint8 uc_rts_succ;
    oal_uint8 uc_cts_failure;
    oal_int8 c_last_ack_rssi;
    oal_uint8 uc_mpdu_num;
    oal_uint8 uc_error_mpdu_num;
    oal_uint8 uc_last_rate_rank;
    oal_uint8 uc_tid;
    hal_tx_queue_type_enum_uint8 uc_ac;
    oal_uint16 us_mpdu_len;
    oal_uint8 uc_is_retried;
    oal_uint8 uc_bandwidth;
    oal_uint8 uc_sounding_mode;      /* ????????sounding???? */
    oal_uint8 uc_status;             /* ?????????????? */
    oal_uint8 uc_ampdu_enable;       /* ??????????????AMPDU?????? */
    oal_uint16 us_origin_mpdu_lenth; /* mpdu???? */
    oal_uint8 en_channel_code;
    oal_uint64 ull_ampdu_result;
    hal_channel_matrix_dsc_stru st_tx_dsc_chnl_matrix; /* ?????????????????????????? */
    hal_tx_txop_per_rate_params_union ast_per_rate[HAL_TX_RATE_MAX_NUM];
    oal_uint32 ul_ampdu_length;
    hal_tx_txop_tx_power_stru st_tx_power;
    oal_uint8 uc_tx_desc_rate_rank; /* ??????????????????????????status=1?????? */

    oal_uint32 ul_now_time_ms; /* ?????????? */
} hal_tx_dscr_ctrl_one_param;

typedef struct {
    /* ?????????????? */
    wlan_security_txop_params_stru *pst_security; /* ??16?? MAC TX MODE 2 */

    /* groupid??partial_aid */
    wlan_groupid_partial_aid_stru st_groupid_partial_aid; /* ??12??15?????? */
} hal_tx_txop_feature_stru;
/*****************************************************************************
  ??????  : hal_tx_txop_alg_stru
  ????????: DMAC????TXOP????????????
*****************************************************************************/
typedef struct {
    /* tx dscr???????????????? */
    hal_tx_txop_rate_params_stru st_rate;                                /* ??13??(HY TX MODE 1) */
    hal_tx_txop_per_rate_params_union ast_per_rate[HAL_TX_RATE_MAX_NUM]; /* ??14(PHY TX RATA 1) 19 20 21 ?? */
    hal_tx_txop_tx_power_stru st_tx_power; /* ??22??(TX POWER) */
} hal_tx_txop_alg_stru;

typedef struct {
    oal_uint8 auc_tpc_code_level[HAL_TPC_POW_LEVEL_NUM];
    oal_int16 as_tpc_gain_level[HAL_TPC_POW_LEVEL_NUM];
} hal_rate_tpc_code_gain_table_stru;

typedef struct {
    hal_rate_tpc_code_gain_table_stru *pst_rate_tpc_table; /* EVM?????????????????? */
    hal_tx_txop_alg_stru *pst_txop_param;                  /* ???????????????????????? */
    oal_bool_enum_uint8 en_rf_limit_pow;                   /* ????????RF limit???? */
    oal_uint8 auc_res[3];
} hal_user_pow_info_stru;

/*****************************************************************************
  ??????  : hal_tx_ppdu_feature_stru
  ????????: DMAC????PPDU????????????
*****************************************************************************/
typedef struct {
    /* ??15 16?? TX VAP index ?? RA LUT Index */
    hal_tx_ppdu_addr_index_params_stru st_ppdu_addr_index;

    /* ??16 17?? */
    oal_uint32 ul_ampdu_length;    /* ??????null data??ampdu?????? */
    oal_uint16 us_min_mpdu_length; /* ??????????????????ampdu????mpdu?????? */

    /* ??13?? */
    oal_uint8 uc_ampdu_enable; /* ????????AMPDU */

    oal_uint8 uc_rifs_enable; /* rifs??????????????MPDU????????????????BAR?? */
    /* ??12??  MAC TX MODE 1 */
    oal_uint16 us_tsf;
    oal_uint8 en_retry_flag_hw_bypass;
    oal_uint8 en_duration_hw_bypass;
    oal_uint8 en_seq_ctl_hw_bypass;
    oal_uint8 en_timestamp_hw_bypass;
    oal_uint8 en_addba_ssn_hw_bypass;
    oal_uint8 en_tx_pn_hw_bypass;
    oal_uint8 en_long_nav_enable;
    oal_uint8 uc_mpdu_num; /* ampdu??mpdu?????? */
    oal_uint8 auc_resv[2];
} hal_tx_ppdu_feature_stru;

/*****************************************************************************
  ??????  : hal_tx_mpdu_stru
  ????????: DMAC????MPDU????????????
*****************************************************************************/
typedef struct {
    /* ??11MAC?????????? ????MPDU */
    hal_wmm_txop_params_stru st_wmm;
    hal_tx_mpdu_mac_hdr_params_stru st_mpdu_mac_hdr;                      /* ??12 17??(PHY TX MODE 2) */
    hal_tx_mpdu_address_params_stru st_mpdu_addr;                         /* ??18??(MAC TX MODE 2) */
    hal_tx_msdu_address_params ast_msdu_addr[WLAN_DSCR_SUBTABEL_MAX_NUM]; /* ??24,25...?? */
} hal_tx_mpdu_stru;

/* Beacon?????????? */
typedef struct {
    oal_uint32 ul_pkt_ptr;
    oal_uint32 us_pkt_len;
    hal_tx_txop_alg_stru *pst_tx_param;
    oal_uint32 ul_tx_chain_mask;

    // dmac??????????????????????????????????hal
    // oal_uint32  ul_phy_tx_mode;     /* ??tx?????? phy tx mode 1 */
    // oal_uint32  ul_tx_data_rate;    /* ??tx?????? data rate 0 */
} hal_beacon_tx_params_stru;

/*****************************************************************************
  ??????  : hal_security_key_stru
  ????????: DMAC??????????????????????
*****************************************************************************/
typedef struct {
    oal_uint8 uc_key_id;
    wlan_cipher_key_type_enum_uint8 en_key_type;
    oal_uint8 uc_lut_idx;
    wlan_ciper_protocol_type_enum_uint8 en_cipher_type;
    oal_bool_enum_uint8 en_update_key;
    wlan_key_origin_enum_uint8 en_key_origin;
    oal_uint8 auc_reserve[2];
    oal_uint8 *puc_cipher_key;
    oal_uint8 *puc_mic_key;
} hal_security_key_stru;

/*****************************************************************************
  7.4 ????VAP??Device????
*****************************************************************************/
typedef struct {
    oal_uint8 auc_resv[4];
} hal_to_dmac_vap_rom_stru;

typedef struct {
    oal_uint32 ul_training_data;
    oal_uint16 us_training_cnt;
    oal_uint8 uc_is_trained;
    oal_uint8 auc_resv[1];
} hal_tbtt_offset_training_hdl_stru;

typedef struct {
    oal_uint32 ul_probe_beacon_rx_cnt;
    oal_uint32 ul_probe_tbtt_cnt;
    oal_uint16 us_inner_tbtt_offset_base;
    oal_uint8 uc_beacon_rx_ratio;
    oal_uint8 uc_best_beacon_rx_ratio;
    oal_uint8 uc_probe_state;
    oal_uint8 uc_probe_suspend;
    oal_int8 i_cur_probe_index;
    oal_int8 i_best_probe_index;
} hal_tbtt_offset_probe_stru;

#define TBTT_OFFSET_PROBE_STEP_US 30
#define TBTT_OFFSET_PROBE_MAX     10 /* ????????30*10 = 300us */

#define TBTT_OFFSET_UP_PROBE_STEP    2 /* up probe */
#define TBTT_OFFSET_DOWN_PROBE_STEP  1
#define TBTT_OFFSET_PROBE_ACCETP_DIF 3

#define TBTT_OFFSET_PROBE_CALCURATE_PERIOD 100 /* beacon?????????????? */

/* state define */
#define TBTT_OFFSET_PROBE_STATE_INIT    0
#define TBTT_OFFSET_PROBE_STATE_START   1
#define TBTT_OFFSET_PROBE_STATE_UP_DONE 2
#define TBTT_OFFSET_PROBE_STATE_END     3

#ifdef _PRE_PRODUCT_ID_HI110X_DEV
typedef struct {
    oal_uint16 us_inner_tbtt_offset;
    oal_uint8 auc_resv[2];
    oal_uint32 ul_rf_on_time;    // ?????????????????? hi1102_pm_enable_front_end????????
    oal_uint32 ul_tbtt_bh_time;  // tbtt??????????????????
    oal_uint32 ul_tbtt_th_time;  // tbtt??????????????????
    /* ????????beacon??????????hal device??????awake???????????? */
#ifdef _PRE_PM_DYN_SET_TBTT_OFFSET
    hal_tbtt_offset_training_hdl_stru st_training_handle;
#endif

#ifdef _PRE_PM_TBTT_OFFSET_PROBE
    hal_tbtt_offset_probe_stru st_tbtt_offset_probe;
#endif

    oal_uint8 _rom[4];
} hal_pm_info_stru;
#endif

typedef struct tag_hal_to_dmac_vap_stru {
    oal_uint8 uc_chip_id;                 /* ????ID */
    oal_uint8 uc_device_id;               /* ????ID */
    oal_uint8 uc_vap_id;                  /* VAP ID */
    wlan_vap_mode_enum_uint8 en_vap_mode; /* VAP???????? */
    oal_uint8 uc_mac_vap_id;              /* ????mac vap id */
    oal_uint8 uc_dtim_cnt;                /* dtim count */
    oal_uint16 us_reg_pow;                /* ????0.1db */
    oal_uint8 uc_service_id;
    wlan_channel_band_enum_uint8 en_freq_band;
    oal_uint8 uc_active_upc_lut_len;
    oal_uint8 auc_pow_cali_upc_code[HAL_MAX_CHAIN_NUM];    /* TX????????????UPC code */
    hal_rate_tpc_code_gain_table_stru *pst_rate_tpc_table; /* ????-TPC code&TPC gain?????? */
    oal_int16 as_upc_gain_lut[HAL_MAX_CHAIN_NUM][HAL_TPC_UPC_LUT_NUM];
    oal_uint8 auc_upc_code_lut[HAL_MAX_CHAIN_NUM][HAL_TPC_UPC_LUT_NUM];
#ifdef _PRE_PRODUCT_ID_HI110X_DEV
    hal_pm_info_stru *pst_pm_info;
#endif

    hal_to_dmac_vap_rom_stru *pst_hal_vap_rom;
} hal_to_dmac_vap_stru;

/*****************************************************************************
  7.5 ??????????????????????????????
*****************************************************************************/
typedef struct {
    oal_int8 c_rssi_dbm;
    union {
        struct {
            oal_uint8 bit_vht_mcs : 4;
            oal_uint8 bit_nss_mode : 2;
            oal_uint8 bit_protocol_mode : 2;
        } st_vht_nss_mcs; /* 11ac???????????? */
        struct {
            oal_uint8 bit_ht_mcs : 6;
            oal_uint8 bit_protocol_mode : 2;
        } st_ht_rate; /* 11n???????????? */
        struct {
            oal_uint8 bit_legacy_rate : 4;
            oal_uint8 bit_reserved1 : 2;
            oal_uint8 bit_protocol_mode : 2;
        } st_legacy_rate; /* 11a/b/g???????????? */
    } un_nss_rate;

    oal_uint8 uc_short_gi;
    oal_uint8 uc_bandwidth;
} hal_rx_statistic_stru;

#if (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102_DEV) || (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1103_DEV) ||  \
    (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102A_DEV)
/* ????????????????????????HMAC??????????????mac_rx_ctl_stru?????????????? */
/* hal_rx_ctl_stru????????????????hi1102_rx_get_info_dscr????????????
????????????????????dmac_ext_if.h??hmac_ext_if.h ???????????? */
#pragma pack(push, 1)
typedef struct {
    /* word 0 */
    oal_uint8 bit_vap_id : 5;
    oal_uint8 bit_amsdu_enable : 1;
    oal_uint8 bit_is_first_buffer : 1;
    oal_uint8 bit_is_last_buffer : 1;

    oal_uint8 uc_msdu_in_buffer : 6;
    oal_uint8 bit_is_fragmented : 1;
    oal_uint8 bit_has_tcp_ack_info : 1;

    oal_uint8 bit_data_frame_type : 4;
    oal_uint8 bit_ta_user_idx : 4;
    oal_uint8 bit_mac_header_len : 6; /* mac header???????? */
    oal_uint8 bit_is_beacon : 1;
    oal_uint8 bit_is_key_frame : 1;
    /* word 1 */
    oal_uint16 us_frame_len; /* ?????????????????? */
    oal_uint8 uc_mac_vap_id : 4;
    oal_uint8 bit_buff_nums : 4; /* ????MPDU??????buf?? */
    oal_uint8 uc_channel_number; /* ???????????? */
    /* word 2 */
} hal_rx_ctl_stru;
#pragma pack(pop)
#else
/* ??????????????HMAC??????????????mac_rx_ctl_stru?????????????? */
typedef struct {
    /* word 0 */
    oal_uint8 bit_vap_id : 5; /* ????hal vap id */
    oal_uint8 bit_amsdu_enable : 1;
    oal_uint8 bit_is_first_buffer : 1;
    oal_uint8 bit_is_fragmented : 1;
    oal_uint8 uc_msdu_in_buffer : 6;
    oal_uint8 bit_reserved1 : 2;
    oal_uint8 bit_buff_nums : 4; /* ????MPDU??????buf???? */
    oal_uint8 bit_reserved2 : 4;
    oal_uint8 uc_mac_header_len; /* mac header???????? */
    /* word 1 */
    oal_uint16 us_frame_len;   /* ?????????????????? */
    oal_uint16 us_da_user_idx; /* ???????????????? */
    /* word 2 */
    oal_uint32 *pul_mac_hdr_start_addr; /* ??????????????????,???????? */
} hal_rx_ctl_stru;

#endif

/* ??DMAC SCAN ??????????????MAC/PHY?????????????????? */
typedef struct {
    /* ???????? */
    oal_uint32 ul_ch_stats_time_us;
    oal_uint32 ul_pri20_free_time_us;
    oal_uint32 ul_pri40_free_time_us;
    oal_uint32 ul_pri80_free_time_us;
    oal_uint32 ul_ch_rx_time_us;
    oal_uint32 ul_ch_tx_time_us;

    /* ???????? */
    oal_uint8 uc_ch_estimate_time_ms;
    oal_int8 c_pri20_idle_power;
    oal_int8 c_pri40_idle_power;
    oal_int8 c_pri80_idle_power;

    oal_uint32 ul_stats_cnt;
    oal_uint32 ul_meas_cnt;
    oal_uint32 ul_test_cnt;
} hal_ch_statics_irq_event_stru;

/* ??DMAC SCAN???????????????????????????????? */
typedef struct {
    oal_uint8 uc_radar_type;
    oal_uint8 uc_radar_freq_offset;
    oal_uint8 uc_radar_bw;
    oal_uint8 uc_band;
    oal_uint8 uc_channel_num;
    oal_uint8 uc_working_bw;
    oal_uint8 auc_resv[2];
} hal_radar_det_event_stru;

typedef struct {
    oal_uint32 ul_reg_band_info;
    oal_uint32 ul_reg_bw_info;
    oal_uint32 ul_reg_ch_info;
} hal_radar_irq_reg_list_stru;

#if (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102_DEV) || (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1103_DEV) ||  \
    (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102A_DEV)
/*
 * ??????????????????????????????
 * frame_len????
 * 802.11????????(uc_mac_hdr_len)
 */
#pragma pack(push, 1)

typedef struct {
    /* word 0 */
    oal_uint8 bit_cipher_protocol_type : 4;
    oal_uint8 bit_dscr_status : 4;
    /* word 1 */
    oal_uint8 bit_channel_code : 1;
    oal_uint8 bit_STBC : 2;
    oal_uint8 bit_GI : 1;
    oal_uint8 bit_rsvd : 1;
    oal_uint8 bit_AMPDU : 1;
    oal_uint8 bit_sounding_mode : 2;
    /* word 2 */
    oal_uint8 bit_ext_spatial_streams : 2;
    oal_uint8 bit_smoothing : 1;
    oal_uint8 bit_freq_bandwidth_mode : 4;
    oal_uint8 bit_preabmle : 1;
    // oal_uint16  us_rx_frame_length;     /* ??hcc?? */
    /* word 3 */
    // oal_uint8   bit_amsdu_flag            : 1;              /* AMSDU?? */
    // oal_uint8   bit_buffer_start_flag     : 1;              /* AMSDU?,??MSDU?? */
    // oal_uint8   bit_frag_flag             : 1;              /* MSDU???? */
    oal_uint8 bit_reserved2 : 3;
    oal_uint8 bit_rsp_flag : 1;

    oal_uint8 bit_column_number : 4;

    /* word 4?5 */
    oal_uint16 us_channel_matrix_len;

    /* word 6 */
    oal_uint8 bit_code_book : 2; /* ???????? */
    oal_uint8 bit_grouping : 2;
    oal_uint8 bit_row_number : 4;
} hal_rx_status_stru;
#pragma pack(pop)

#else
/*
 * ??????????????????????
 * frame_len????
 * 802.11????????(uc_mac_hdr_len)
 */
typedef struct {
    /* word 0 */
    oal_uint8 bit_dscr_status : 4;          /* ?????????????? */
    oal_uint8 bit_cipher_protocol_type : 4; /* ???????????? */
    oal_uint8 bit_ext_spatial_streams : 2;
    oal_uint8 bit_smoothing : 1;
    oal_uint8 bit_freq_bandwidth_mode : 4;
    oal_uint8 bit_preabmle : 1;
    oal_uint8 bit_channel_code : 1;
    oal_uint8 bit_STBC : 2;
    oal_uint8 bit_GI : 1;
    oal_uint8 bit_reserved1 : 1;
    oal_uint8 bit_AMPDU : 1;
    oal_uint8 bit_sounding_mode : 2;
    oal_uint8 uc_reserved1;
    /* word 1 */
    oal_uint8 bit_code_book : 2; /* ???????????????? */
    oal_uint8 bit_grouping : 2;
    oal_uint8 bit_row_number : 4;
    oal_uint8 bit_column_number : 4;
    oal_uint8 bit_rsp_flag : 3;
    oal_uint8 bit_reserved2 : 1;
    oal_uint16 us_channel_matrix_len; /* ???????????? */
    /* word 2 */
    oal_uint32 ul_tsf_timestamp; /* TSF?????? */
    /* word 3 */
} hal_rx_status_stru;
#endif
/*
 * ??????????????????????
 *
 */
#ifndef _PRE_LINUX_TEST
typedef struct {
    oal_uint32 ul_skb_start_addr;
} hal_rx_addr_stru;

/* ?????????????????????? */
typedef struct {
    oal_uint32 ul_mac_hdr_start_addr;
    oal_uint32 ul_skb_start_addr;
} hal_rx_ctrl_stru;
#else
typedef struct {
    oal_uint ul_skb_start_addr;
} hal_rx_addr_stru;

/* ?????????????????????? */
typedef struct {
    oal_uint ul_mac_hdr_start_addr;
    oal_uint ul_skb_start_addr;
} hal_rx_ctrl_stru;
#endif
/*****************************************************************************
  7.6 ????????????VAP????????????????????????????????????????????????????????
*****************************************************************************/
typedef struct {
    hal_to_dmac_vap_stru st_vap_base;
    oal_uint32 ul_vap_base_addr;
} hal_vap_stru;

/*****************************************************************************
  ??????  : hal_rx_dscr_queue_header_stru
  ????????: ????????????????????????
*****************************************************************************/
typedef struct {
    oal_uint32 *pul_element_head;                     /* ?????????????????????????????? */
    oal_uint32 *pul_element_tail;                     /* ???????????????????????????????? */
    oal_uint16 us_element_cnt;                        /* ?????????????????????????? */
    hal_dscr_queue_status_enum_uint8 uc_queue_status; /* ???????????????????? */
    oal_uint8 auc_resv[1];
} hal_rx_dscr_queue_header_stru;
/*****************************************************************************
  ??????  : dmac_tx_dscr_queue_header_stru
  ????????: ????????????????????????
*****************************************************************************/
typedef struct {
    oal_dlist_head_stru st_header;                    /* ???????????????????? */
    hal_dscr_queue_status_enum_uint8 en_queue_status; /* ?????????????????? */
    oal_uint8 uc_ppdu_cnt;                            /* ?????????????????????????? */
    oal_uint8 uc_queue_depth;                         /* ?????????????????????? */
    oal_uint8 uc_resv;
} hal_tx_dscr_queue_header_stru;

/*****************************************************************************
  ??????  : dmac_tx_dscr_queue_header_stru
  ????????: ????????????????????????
*****************************************************************************/
typedef struct {
    oal_uint8 uc_nulldata_awake;    /* AP??????????????0??null data???????? */
    oal_uint8 uc_nulldata_phy_mode; /* STA??????null data??phy mode */
    oal_uint8 uc_nulldata_rate;     /* STA??????null data?????? */
    oal_uint8 uc_rsv[1];
    oal_uint32 ul_nulldata_interval;      /* STA??????null data?????? */
    oal_uint32 ul_nulldata_address;       /* STA??????null data?????? */
    oal_uint32 ul_ap0_probe_resp_address; /* AP0??probe response???????? */
    oal_uint32 ul_ap0_probe_resp_len;     /* AP0??probe response???? */
    oal_uint32 ul_ap1_probe_resp_address; /* AP1??probe response???????? */
    oal_uint32 ul_ap1_probe_resp_len;     /* AP1??probe response???? */
    oal_uint8 uc_ap0_probe_resp_phy;      /* AP0??probe response????phy???? */
    oal_uint8 uc_ap0_probe_resp_rate;     /* AP0??probe response????reate */
    oal_uint8 uc_ap1_probe_resp_phy;      /* AP1??probe response????phy???? */
    oal_uint8 uc_ap1_probe_resp_rate;     /* AP1??probe response????reate */

    oal_uint32 ul_set_bitmap; /* wow???? */
} hal_wow_param_stru;

typedef enum {
    HAL_WOW_PARA_EN = BIT0,
    HAL_WOW_PARA_NULLDATA = BIT1,
    HAL_WOW_PARA_NULLDATA_INTERVAL = BIT2,
    HAL_WOW_PARA_NULLDATA_AWAKE = BIT3,
    HAL_WOW_PARA_AP0_PROBE_RESP = BIT4,
    HAL_WOW_PARA_AP1_PROBE_RESP = BIT5,

    HAL_WOW_PARA_BUTT
} hal_wow_para_set_enum;
typedef oal_uint32 hal_tx_status_enum_uint32;

/*****************************************************************************
  ??????  : hal_lpm_chip_state
  ????????: ??????????????????
*****************************************************************************/
typedef enum {
    HAL_LPM_STATE_POWER_DOWN,
    HAL_LPM_STATE_IDLE,
    HAL_LPM_STATE_LIGHT_SLEEP,
    HAL_LPM_STATE_DEEP_SLEEP,
    HAL_LPM_STATE_NORMAL_WORK,
    HAL_LPM_STATE_WOW,

    HAL_LPM_STATE_BUTT
} hal_lpm_state_enum;
typedef oal_uint8 hal_lpm_state_enum_uint8;

/*****************************************************************************
  ??????  : hal_lpm_state_para
  ????????: ??????????????????????
*****************************************************************************/
typedef struct {
    oal_uint8 uc_dtim_count; /* ??????DTIM count????STA?????????????? */
    oal_uint8 uc_dtim_period;
    oal_uint8 bit_gpio_sleep_en : 1, /* soc??????????????,GPIO???????????? */
              bit_soft_sleep_en : 1,       /* soc??????????????,?????????????? */
              bit_set_bcn_interval : 1,    /* ????????beacon inter */
              bit_rsv : 6;
    oal_uint8 uc_rx_chain;           /* ?????????? */
    oal_uint32 ul_idle_bcn_interval; /* idle??????beaon inter */
    oal_uint32 ul_sleep_time;        /* ????????????????????ms */
} hal_lpm_state_param_stru;

/*****************************************************************************
  ??????  : hal_cfg_rts_tx_param_stru
  ????????: RTS????????????
*****************************************************************************/
typedef struct {
    wlan_legacy_rate_value_enum_uint8 auc_rate[HAL_TX_RATE_MAX_NUM]; /* ??????????????mpbs */
    wlan_phy_protocol_enum_uint8 auc_protocol_mode[HAL_TX_RATE_MAX_NUM];
    wlan_channel_band_enum_uint8 en_band;
    oal_uint8 auc_recv[3];
} hal_cfg_rts_tx_param_stru;

/*****************************************************************************
  7.7 ????????????????????????????????????????????????????????????????????????
*****************************************************************************/
typedef oal_void (*p_hal_alg_isr_func)(oal_uint8 uc_vap_id, oal_void *p_hal_to_dmac_device);
typedef oal_void (*p_hal_gap_isr_func)(oal_uint8 uc_vap_id, oal_void *p_hal_to_dmac_device);

typedef struct {
    oal_uint32 ul_phy_addr;
    oal_uint8 uc_status;
    oal_uint8 uc_q;
    oal_uint8 auc_resv[2];
    oal_uint32 ul_timestamp;

    oal_uint32 ul_arrive_time; /* ?????????????? */
    oal_uint32 ul_handle_time; /* ?????????????? */
    oal_uint32 ul_irq_cnt;
    oal_cpu_usage_stat_stru st_cpu_state;
} hal_rx_dpart_track_stru;

/* ???????????????????????????? */
typedef struct {
    oal_dlist_head_stru st_dlist_head;
    oal_uint32 *pul_base_dscr; /* ?????????????????? */
    oal_uint16 us_dscr_num;    /* ???????????????????? */
    // oal_bool_enum_uint8         en_used;
    oal_uint8 uc_channel_num; /* ???????????????????????? */
    oal_uint8 uc_queue_id;
} hal_hw_rx_dscr_info_stru;
typedef struct tag_hal_to_dmac_chip_stru {
    oal_uint8 uc_chip_id;
} hal_to_dmac_chip_stru;

typedef enum {
    HAL_DFR_TIMER_STEP_1 = 0,
    HAL_DFR_TIMER_STEP_2 = 1,
} hal_dfr_timer_step_enum;
typedef oal_uint8 hal_dfr_timer_step_enum_uint8;
typedef struct {
    oal_uint16 us_tbtt_cnt; /* TBTT????????????10??TBTT????????us_err_cnt???? */
    oal_uint16 us_err_cnt;  /* ??10??TBTT????????????MAC???????????? */
} hal_dfr_err_opern_stru;

typedef struct {
    oal_uint32 ul_error1_val; /* ????1???????? */
    oal_uint32 ul_error2_val; /* ????2???????? */
} hal_error_state_stru;

typedef struct {
    oal_dlist_head_stru st_entry;
    oal_uint32 ul_phy_addr; /* ?????????????????? */
} witp_rx_dscr_recd_stru;

/*****************************************************************************
  ??????  : hal_phy_tpc_param_stru
  ????????: PHY TPC??????????, ??2.4G/5G??????????????
*****************************************************************************/
typedef struct {
    oal_uint32 ul_pa_bias_addr;                                               /* PA_BIAS???? */
    oal_uint32 aul_pa_bias_gain_code[WLAN_BAND_BUTT];                         /* 2G/5G PA_BIAS CODE */
    oal_uint32 ul_pa_addr;                                                    /* PA???? */
    oal_uint32 aul_pa_gain_code[WLAN_BAND_BUTT];                              /* 2G/5G PAIN CODE */
    oal_uint32 aul_2g_upc_addr[WLAN_2G_SUB_BAND_NUM];                         /* 2G UPC???? */
    oal_uint32 aul_5g_upc_addr[WLAN_5G_SUB_BAND_NUM];                         /* 5G UPC???? */
    oal_uint32 aul_2g_upc1_data[WLAN_2G_SUB_BAND_NUM][WLAN_UPC_DATA_REG_NUM]; /* 2G ????1 UPC DATA */
    oal_uint32 aul_5g_upc1_data[WLAN_5G_SUB_BAND_NUM][WLAN_UPC_DATA_REG_NUM]; /* 5G ????1 UPC DATA */
    oal_uint32 ul_dac_addr;                                                   /* DAC???? */
    oal_uint32 aul_dac_data[WLAN_BAND_BUTT];                                  /* 2G/5G DAC DATA */
    oal_uint32 ul_lpf_addr;                                                   /* DAC???? */
    oal_uint32 aul_lpf_data[WLAN_BAND_BUTT];                                  /* 2G/5G LPF DATA */
    oal_uint8 auc_2g_cali_upc_code[HAL_MAX_CHAIN_NUM][WLAN_2G_SUB_BAND_NUM];  /* 2G??????UPC Code */
    oal_uint8
    auc_5g_cali_upc_code[HAL_MAX_CHAIN_NUM][WLAN_5G_CALI_SUB_BAND_NUM]; /* 5G??????UPC Code(????20M??80M) */
    oal_uint8 auc_reserve_addr[2];

    /* ????????tpc code */
    oal_uint32 aul_2g_ofdm_ack_cts_tpc_code[WLAN_2G_SUB_BAND_NUM];
    oal_uint32 aul_5g_ack_cts_tpc_code[WLAN_5G_SUB_BAND_NUM];
    oal_uint8 auc_2g_dsss_ack_cts_tpc_code[WLAN_2G_SUB_BAND_NUM];
    oal_uint8 auc_2g_rts_tpc_code[WLAN_2G_SUB_BAND_NUM];
    oal_uint8 auc_2g_one_pkt_tpc_code[WLAN_2G_SUB_BAND_NUM];
    oal_uint8 auc_2g_abort_selfcts_tpc_code[WLAN_2G_SUB_BAND_NUM];
    oal_uint8 auc_2g_abort_cfend_tpc_code[WLAN_2G_SUB_BAND_NUM];
    oal_uint8 auc_2g_abort_null_data_tpc_code[WLAN_2G_SUB_BAND_NUM];
    oal_uint8 auc_2g_cfend_tpc_code[WLAN_2G_SUB_BAND_NUM];
    oal_uint8 auc_5g_rts_tpc_code[WLAN_5G_SUB_BAND_NUM];
    oal_uint8 auc_5g_one_pkt_tpc_code[WLAN_5G_SUB_BAND_NUM];
    oal_uint8 auc_5g_abort_cfend_tpc_code[WLAN_5G_SUB_BAND_NUM];
    oal_uint8 auc_5g_cfend_tpc_code[WLAN_5G_SUB_BAND_NUM];
    oal_uint8 auc_5g_ndp_tpc_code[WLAN_5G_SUB_BAND_NUM];
    oal_uint8 auc_5g_vht_report_tpc_code[WLAN_5G_SUB_BAND_NUM];
    oal_uint8 auc_5g_abort_null_data_tpc_code[WLAN_5G_SUB_BAND_NUM];
    /* ???????????????????? */
    oal_uint32 ul_rate_ofdm_ack_cts;
    oal_uint8 uc_rate_rts;
    oal_uint8 uc_rate_one_pkt;
    oal_uint8 uc_rate_abort_selfcts;
    oal_uint8 uc_rate_abort_cfend;
    oal_uint8 uc_rate_cfend;
    oal_uint8 uc_rate_ndp;
    oal_uint8 uc_rate_vht_report;
    oal_uint8 uc_rate_abort_null_data;
} hal_phy_tpc_param_stru;

#if (defined(_PRE_PRODUCT_ID_HI110X_DEV))
typedef struct {
    oal_uint16 us_max_offset_tsf; /* ?????????????? */
    oal_uint16 us_mpdu_len;       /* ??????????mpdu???? */
    oal_uint16 us_tx_excp_cnt;    /* ???????????????????? */
    oal_uint8 uc_q_num;           /* ??????????q_num */
    oal_uint8 auc_resv;
} hal_tx_excp_info_stru;
#endif

typedef struct {
    oal_uint32 ul_tkipccmp_rep_fail_cnt;    /* ????????????????TKIP + CCMP */
    oal_uint32 ul_tx_mpdu_cnt;              /* ??????????ampdu???????? + ?????????? + ampdu??mpdu */
    oal_uint32 ul_rx_passed_mpdu_cnt;       /* ????AMPDU MPDU??FCS??????MPDU???? */
    oal_uint32 ul_rx_failed_mpdu_cnt;       /* ????AMPDU MPDU??FCS??????MPDU???? */
    oal_uint32 ul_rx_tkipccmp_mic_fail_cnt; /* kip mic + ccmp mic fail?????? */
    oal_uint32 ul_key_search_fail_cnt;      /* ????key serach fail?????? */
    oal_uint32 ul_phy_rx_dotb_ok_frm_cnt;   /* PHY????dotb ok???????? */
    oal_uint32 ul_phy_rx_htvht_ok_frm_cnt;  /* PHY????vht ht ok???????? */
    oal_uint32 ul_phy_rx_lega_ok_frm_cnt;   /* PHY????legace ok???????? */
    oal_uint32 ul_phy_rx_dotb_err_frm_cnt;  /* PHY????dotb err???????? */
    oal_uint32 ul_phy_rx_htvht_err_frm_cnt; /* PHY????vht ht err???????? */
    oal_uint32 ul_phy_rx_lega_err_frm_cnt;  /* PHY????legace err???????? */
} hal_mac_key_statis_info_stru;

/* ??????????vdet???????????? */
typedef union {
    struct {
        wlan_channel_band_enum_uint8 en_freq : 4;  // 2G or 5G
        wlan_bw_cap_enum_uint8 en_band_width : 4;
        oal_uint8 uc_channel;
        wlan_mod_enum_uint8 en_mod;
        oal_uint8 uc_tx_pow;
    } st_rf_core_para;
    oal_uint32 ul_para;
} hal_dyn_cali_record_union;

typedef struct {
    oal_err_code_enum_uint32 en_get_tx_power_status;
    hal_dyn_cali_record_union un_record_para;
    oal_int16 s_real_pdet;
    oal_int16 s_pdet_val_i;
    oal_int16 s_pdet_val_q;
    wlan_phy_protocol_enum_uint8 en_cur_protocol;
    oal_uint8 uc_upc_gain_idx;
    oal_bool_enum_uint8 en_get_tx_power_log_flag;
    oal_uint8 auc_resv[3];
} hal_pdet_info_stru;
#ifdef _PRE_WLAN_FIT_BASED_REALTIME_CALI
typedef struct {
    hal_dyn_cali_record_union un_record_para;
    oal_int16 s_real_pdet;
    oal_int16 s_exp_pdet;
    oal_uint8 auc_resv[4];
} hal_dyn_cali_usr_record_stru;
#endif

typedef struct hal_dyn_cali_val {
    oal_uint16 aus_cali_en_cnt[WLAN_BAND_BUTT];
    oal_uint16 aus_cali_en_interval[WLAN_BAND_BUTT];   /* ?????????????????????????? */
    oal_uint8 uc_cali_pdet_min_th;                     /* ???????????????? */
    oal_uint8 uc_cali_pdet_max_th;                     /* ???????????????? */
    oal_bool_enum_uint8 en_realtime_cali_adjust;       /* ???????????????????? */
    oal_bool_enum_uint8 en_dyn_cali_pdet_need_en_flag; /* ????????????pdet_en????????????(????????????????????false??????????????true) */
    oal_bool_enum_uint8 en_dyn_cali_complete_flag;     /* ???????????????????? */
} hal_dyn_cali_val_stru;

typedef struct {
    hal_dyn_cali_val_stru st_dyn_cali_val;        /* ????????N??1???? */
    frw_timeout_stru st_dyn_cali_per_frame_timer; /* ???????????????????? */
} hal_dmac_dyn_cali_stru;

#ifdef _PRE_WLAN_FEATURE_BTCOEX
/* ps mode?????????? */
typedef struct {
    oal_uint8 bit_ps_on : 1,    /* ps????????: 0=????, 1=???? */
              bit_delba_on : 1,       /* ????????????: 0=????, 1=???? */
              bit_reply_cts : 1,      /* ????????CTS?? 0=???????? 1=???? */
              bit_rsp_frame_ps : 1,   /* resp???????????????? 0=???????? 1=???? */
              bit_ps_slot_detect : 1, /* ????????????slot??????????delba??????????????????????????vap?? 0=???????? 1=???? */
              bit_resv : 3;
} hal_coex_sw_preempt_mode_stru;

typedef struct {
    oal_timer_list_stru st_btcoex_ps_slot_timer;
    oal_void *p_drv_arg; /* ????????????????,??????pst_dmac_vap */
} hal_btcoex_ps_slot_timer_stru;

typedef struct {
    hal_coex_sw_preempt_mode_stru st_sw_preempt_mode;
    hal_coex_sw_preempt_type_uint8 en_sw_preempt_type;
    hal_coex_sw_preempt_subtype_uint8 en_sw_preempt_subtype;
    hal_fcs_protect_coex_pri_enum_uint8 en_protect_coex_pri; /* one pkt???????????? */
    oal_bool_enum_uint8 en_ps_occu_down_delay;               /* ps??occu??????????????????slot?????? */
    oal_bool_enum_uint8 en_dynamic_slot_pause;               /* ????slot???????? */
    oal_uint16 us_timeout_ms;                                /* ps??????????page????190slot ??????????30slot */
    oal_bool_enum_uint8 en_last_acl_status;                  /* ??????????acl???? */
    oal_bool_enum_uint8 en_ps_stop;                          /* ??????????????????????ps??????????????????ps???? */
    oal_bool_enum_uint8 en_ps_pause;                         /* ????????????????????ps????????ps????????????????wifi???????????? */
    oal_bool_enum_uint8 en_coex_pri_forbit;                  /* coex pri??????????ldac???????????????? */
    oal_uint32 ul_ps_cur_time;                               /* ????ps???????????????????????? */
    oal_atomic ul_ps_event_num;                              /* ps????event???? */
    oal_atomic ul_acl_en_cnt;                                /* ????acl cnt?????????????????????????????????????????????? */
    hal_btcoex_ps_slot_timer_stru st_ps_slot_timer;          /* ????????PS??????????slot???????????????? */
} hal_device_btcoex_sw_preempt_stru;
#endif

struct tag_hal_to_dmac_device_stru;
typedef oal_uint32 (*p_mac_get_work_status_cb)(struct tag_hal_to_dmac_device_stru *pst_hal_device);
typedef oal_uint32 (*p_mac_get_scan_status_cb)(struct tag_hal_to_dmac_device_stru *pst_hal_device);

typedef struct {
    p_mac_get_work_status_cb p_mac_get_work_status;
    p_mac_get_scan_status_cb p_mac_get_scan_status;
} hal_device_cb;

#ifdef _PRE_WLAN_FEATURE_FTM_RAM
typedef struct hal_csi_agc_stru {
    oal_uint8 uc_rpt_lna_code_0ch;
    oal_uint8 uc_rpt_vga_code_0ch;
    oal_uint8 auc_reserv[2];
} hal_csi_agc_stru;
#endif

typedef struct {
    oal_uint16 aus_pending_pkt_cnt[HAL_RX_DSCR_QUEUE_ID_BUTT]; /* ????pending???????????????????? */
} hal_rx_dscr_ctrl_stru;

typedef struct {
    hal_dmac_dyn_cali_stru st_hal_dmac_dyn_cali;

    hal_device_cb st_hal_dev_cb; /* ???????? */

#ifdef _PRE_WLAN_FEATURE_TEMP_PROTECT
    oal_uint8 uc_ping_pong_disable;  /* ????????????????????,?????????????? */
    oal_uint8 uc_temp_pro_aggr_size; /* ?????????????????????????????????? */
    oal_uint8 auc_reserv1[2];
#endif
    oal_uint8 uc_tx_power;          /* ????????????????????????,??????0.1db */
    oal_uint8 uc_btcoex_ps_channel; /* ??????????????PS???????????? */
    oal_uint8 uc_print_all;         /* dmac_tx_pause_info????????????user?????? */
    oal_uint8 auc_reserv2[1];

#ifdef _PRE_WLAN_FEATURE_FTM_RAM
    hal_csi_agc_stru st_csi_agc;
#endif
    hal_rx_dscr_ctrl_stru st_rx_dscr_ctrl;
#ifdef _PRE_WLAN_FEATURE_BTCOEX
    oal_bool_enum_uint8 en_onepkt_occupied;       /* ????onepkt????????occupied */
    oal_bool_enum_uint8 en_enterprise_eapol_flag; /* ??????????eapol???????? */
    hal_btcoex_aggr_time_type_uint8 en_btcoex_aggr_time_type;
    oal_bool_enum_uint8 en_btcoex_disable_auto_freq; /* ?????????????????????????????????? */
    frw_timeout_stru st_onepkt_priority_timer; /* onepkt???????????????? */
    oal_uint32 ul_occupied_timestamp;          /* ????????ARP occpuied?????????? */
    oal_uint16 us_btcoex_ps_num; /* ????????PS?????????? */
    oal_uint16 us_ps_delay_mark; /* ????PS?????????????????????? */
    oal_uint32 ul_ps_timestamp;  /* ????PS???????????????????? */
#endif
    oal_uint32 ul_filtered_tcp_ack_cnt;
#ifdef _PRE_WLAN_FEATURE_NRCOEX
    wlan_nrcoex_ini_stru st_nrcoex_ini;
    hal_nrcoex_mgr_stru st_nrcoex_mgr;
#endif
    hal_suspend_stru st_suspend_state;
    oal_uint8 uc_tx_suspend_flag;
    oal_uint8 uc_ack_suspend_flag;
    oal_uint8 uc_cts_suspend_flag;
    oal_uint8 uc_onepacket_flag;
    oal_bool_enum_uint8 en_bt_only_on_blacklist;
    oal_uint8 auc_reserv3[3]; /* 3??pad */
} hal_to_dmac_device_rom_stru;

#ifdef _PRE_WLAN_FEATURE_GNSS_SCAN
#pragma pack(1)
/* scan parameter */
typedef struct {
    oal_uint8 uc_chan_number;             /* ??20MHz?????? */
    wlan_channel_band_enum_uint8 en_band; /* ???? */
} gnss_scan_channel_stru;

typedef struct {
    oal_uint8 uc_ch_valid_num;
    gnss_scan_channel_stru ast_wlan_channel[WLAN_MAX_CHANNEL_NUM];
} hal_gscan_params_stru;

/* scan results */
typedef struct {
    oal_uint8 auc_bssid[WLAN_MAC_ADDR_LEN]; /* ????bssid */
    oal_uint8 uc_channel_num;
    oal_int8 c_rssi; /* bss?????????? */
    oal_uint8 uc_serving_flag;
    oal_uint8 uc_rtt_unit;
    oal_uint8 uc_rtt_acc;
    oal_uint32 ul_rtt_value;
} wlan_ap_measurement_info_stru;

/* Change Feature: ??????GNSS??????????????????????DMAC???????????????????? */
typedef struct {
    oal_uint8 auc_bssid[WLAN_MAC_ADDR_LEN]; /* ????bssid */
    oal_uint8 uc_channel_num;
    oal_int8 c_rssi; /* bss?????????? */
} wlan_ap_report_info_stru;

/* ??????gnss???????????????? */
typedef struct {
    oal_uint32 ul_interval_from_last_scan;
    oal_uint8 uc_ap_valid_number;
    wlan_ap_report_info_stru ast_wlan_ap_measurement_info[GNSS_SCAN_MAX_AP_NUM_TO_GNSS];
} hal_gscan_report_info_stru;
#pragma pack()

typedef struct {
    oal_dlist_head_stru st_entry;                              /* ???????? */
    wlan_ap_measurement_info_stru st_wlan_ap_measurement_info; /* ????gnss?????????? */
} hal_scanned_bss_info_stru;

typedef struct {
    oal_uint32 ul_scan_end_timstamps; /* ????????????????????,????????????????,??????????ap???????? */
    oal_dlist_head_stru st_dmac_scan_info_list;
    oal_dlist_head_stru st_scan_info_res_list; /* ???????????????????? */
    hal_scanned_bss_info_stru ast_scan_bss_info_member[GNSS_SCAN_MAX_AP_NUM_TO_GNSS];
} hal_scan_for_gnss_stru;
#endif

typedef struct tag_hal_to_dmac_device_stru {
    oal_uint8 uc_chip_id;
    oal_uint8 uc_device_id;
    oal_uint8 uc_mac_device_id;             /* ????mac device id */
    hal_lpm_state_enum_uint8 uc_curr_state; /* ???????????????????? */
    oal_uint32 ul_core_id;

    hal_dfr_err_opern_stru st_dfr_err_opern[HAL_MAC_ERROR_TYPE_BUTT]; /* ????MAC???????????? */

    hal_rx_dscr_queue_header_stru ast_rx_dscr_queue[HAL_RX_QUEUE_NUM];
    hal_tx_dscr_queue_header_stru ast_tx_dscr_queue[HAL_TX_QUEUE_NUM];

#ifdef _PRE_DEBUG_MODE
    /* ?????????????????????????????????????? */
    witp_rx_dscr_recd_stru st_nor_rx_dscr_recd[HAL_NORMAL_RX_MAX_BUFFS];
    witp_rx_dscr_recd_stru st_hi_rx_dscr_recd[HAL_HIGH_RX_MAX_BUFFS];
#endif

    hal_tx_dscr_queue_header_stru ast_tx_dscr_queue_fake[HAL_TX_FAKE_QUEUE_NUM][HAL_TX_QUEUE_NUM];

    oal_uint32 ul_rx_normal_dscr_cnt;

    oal_uint32 ul_track_stop_flag;
    oal_uint8 uc_al_tx_flag;
    hal_regdomain_enum_uint8 en_regdomain_type; /* ??????????????FCC CE???? */
    oal_uint8 uc_full_phy_freq_user_cnt;        // device????????????vap(ap)/sta(user) ????
    oal_uint8 uc_over_temp;
    oal_uint32 bit_al_tx_flag : 3;        /* 0: ????????; 1:??????RF????; 2: ampdu??????????; 3:???????????? */
    oal_uint32 bit_al_rx_flag : 3;        /* 0: ????????; 1:??????RF??????2: ampdu??????????; 3:???????????? */
    oal_uint32 bit_one_packet_st : 1;     /* 0????DBC???? 1????DBAC???????? */
    oal_uint32 bit_clear_fifo_st : 1;     /* 0??????clear fifo??????1????clear fifo???? */
    oal_uint32 bit_al_txrx_ampdu_num : 8; /* ???????????????????????????? */
    oal_uint32 bit_track_cnt : 8;         /* ????qempty ?????????????? */
    oal_uint32 bit_track_cnt_down : 8;    /* ???????????????????? */
    oal_netbuf_stru *pst_altx_netbuf;     /* ?????????????????????????????? */
    oal_netbuf_stru *pst_alrx_netbuf;     /* ?????????????????????????????? */
    oal_uint32 ul_rx_normal_mdpu_succ_num;
    oal_uint32 ul_rx_ampdu_succ_num;
    oal_uint32 ul_tx_ppdu_succ_num;
    oal_uint32 ul_rx_ppdu_fail_num;
    oal_uint32 ul_tx_ppdu_fail_num;
#ifdef _PRE_DEBUG_MODE
    oal_uint32 ul_dync_txpower_flag;
#endif

    oal_dlist_head_stru ast_rx_isr_info_list[HAL_HW_RX_DSCR_LIST_NUM];
    hal_hw_rx_dscr_info_stru ast_rx_isr_info_member[HAL_HW_RX_ISR_INFO_MAX_NUMS];
    oal_dlist_head_stru st_rx_isr_info_res_list; /* ???????????????????????? */
    oal_uint8 uc_current_rx_list_index;
    oal_uint8 uc_current_chan_number;
    wlan_p2p_mode_enum_uint8 en_p2p_mode;
    oal_bool_enum_uint8 en_rx_intr_fifo_resume_flag; /* RX INTR FIFO OVERRUN???????????? */

#ifdef _PRE_DEBUG_MODE
    /* ?????????????????? */
    oal_uint32 aul_nor_rx_dscr[HAL_NORMAL_RX_MAX_BUFFS];
    oal_uint32 aul_hi_rx_dscr[HAL_HIGH_RX_MAX_BUFFS];

    oal_uint32 ul_dpart_save_idx;
    oal_uint32 ul_rx_irq_loss_cnt;
    hal_rx_dpart_track_stru ast_dpart_track[HAL_DOWM_PART_RX_TRACK_MEM];

    /* ?????????????????? */
    oal_uint32 ul_exception_free;
    oal_uint32 ul_irq_cnt;

#endif
#ifdef _PRE_DEBUG_MODE_USER_TRACK
    oam_user_track_rx_ampdu_stat st_user_track_rx_ampdu_stat;
#endif
    /* TPC????PHY???? */
    hal_phy_tpc_param_stru st_phy_tpc_param;
    oal_int16 s_upc_amend;
    oal_uint8 uc_mag_mcast_frm_power_level; /* ???????????????? */
    oal_uint8 uc_control_frm_power_level;   /* ???????????????? */

    /* RTS???????????? */
    wlan_legacy_rate_value_enum_uint8 auc_rts_rate[WLAN_BAND_BUTT][HAL_TX_RATE_MAX_NUM]; /* ??????????RTS???????? */
    wlan_phy_protocol_enum_uint8 auc_rts_protocol[WLAN_BAND_BUTT][HAL_TX_RATE_MAX_NUM];  /* ??????????RTS???????? */

    /* ???????? */
    p_hal_alg_isr_func pa_hal_alg_isr_func_table[HAL_ISR_TYPE_BUTT][HAL_ALG_ISR_NOTIFY_BUTT];
    p_hal_gap_isr_func pa_hal_gap_isr_func_table[HAL_ISR_TYPE_BUTT];

    oal_uint8 *puc_mac_reset_reg;
    oal_uint8 *puc_phy_reset_reg;
    oal_uint16 uc_cali_check_hw_status; /* FEM&PA???????? */
    oal_int16 s_always_rx_rssi;

    hal_wifi_channel_status_stru st_wifi_channel_status;
    oal_uint32 ul_rx_rate;
    oal_int32 l_rx_rssi;
#ifdef _PRE_WLAN_FEATURE_BTCOEX
    hal_btcoex_btble_status_stru st_btcoex_btble_status;
    hal_btcoex_statistics_stru st_btcoex_statistics;
    frw_timeout_stru st_btcoex_powersave_timer;
    hal_device_btcoex_sw_preempt_stru st_btcoex_sw_preempt;
#endif
#ifdef _PRE_WLAN_FEATURE_LTECOEX
    oal_uint32 ul_lte_coex_status;
#endif
#if (defined(_PRE_PRODUCT_ID_HI110X_DEV))
    hal_tx_excp_info_stru st_tx_excp_info;
#endif

#ifdef _PRE_WLAN_FEATURE_FTM
    oal_uint64 ull_t1;
    oal_uint64 ull_t4;
#endif

#ifdef _PRE_WLAN_FEATURE_DFR
#ifdef _PRE_DEBUG_MODE
    oal_uint32 ul_cfg_loss_tx_comp_cnt; /* ???????????????????????????????? */
#endif
    oal_bool_enum_uint8 en_dfr_enable; /* dfr????enable */
#endif
    oal_bool_enum_uint8 en_last_over_temperature_flag; /* ???????????????????? */
    oal_uint8 uc_fe_print_ctrl;
    oal_uint8 en_last_p2p_mode;
    oal_uint8 auc_resv[1];

#ifdef _PRE_WLAN_FEATURE_GNSS_SCAN
    hal_scan_for_gnss_stru st_scan_for_gnss_info;
    oal_uint8 uc_gscan_mac_vap_id; /* gscan ??????vap */
#endif

#ifdef _PRE_WLAN_FEATURE_CSI
    oal_uint8 uc_csi_status;
    oal_uint8 auc_reserv3[3];
#endif

#ifdef _PRE_WLAN_NARROW_BAND
    oal_bool_enum_uint8 en_narrow_bw_open;
    oal_uint8 uc_narrow_bw;
    oal_uint8 uc_narrow_bw_chn_extend; /* ???????????? */
    oal_uint8 uc_narrow_chn_num;       /* ????????????????????1~16 */
#endif
#ifdef _PRE_WLAN_FEATURE_ALWAYS_TX
    oal_uint32 ul_al_tx_thr;               // ????????????????
    oal_uint32 ul_al_tx_num;               // ????????????????
    oal_bool_enum_uint8 en_al_tx_dyncali;  // ??????????????????????,????????????????????03??????????????????????????
    oal_uint8 auc_reserved[3];
#endif
    oal_uint8 uc_dyn_offset_switch;
    wlan_legacy_rate_value_enum_uint8 en_rts_rate;  // rts????
    wlan_vht_mcs_enum_uint8 en_latest_mcs;          // ??????????????mcs
#ifdef _PRE_WLAN_FEATURE_AGC_BUGFIX
    hal_phy_agc_target_adjust_enmu_uint8 en_agc_target_adjust_type;  // ??????????agc_target
#endif

    /* ROM???????????????? */
    hal_to_dmac_device_rom_stru *pst_hal_dev_rom;
} hal_to_dmac_device_stru;

/* HAL??????DMAC??????????WLAN RX?????? */
typedef struct {
    oal_uint32 *pul_base_dscr;       /* ???????????? */
    oal_bool_enum_uint8 en_sync_req; /* ???????????? */
    oal_uint16 us_dscr_num;          /* ???????????????????? */
    oal_uint8 uc_queue_id;           /* ?????????? */
    hal_to_dmac_device_stru *pst_hal_device;
    oal_uint8 uc_channel_num;
    oal_uint8 auc_resv[3];
} hal_wlan_rx_event_stru;

#ifdef _PRE_WLAN_FEATURE_FTM
/* HAL??????DMAC??????????FTM TIME RX?????? */
typedef struct {
    oal_uint64 ull_t2;
    oal_uint64 ull_t3;
    oal_uint8 uc_dialog_token;
    oal_uint8 auc_reserve[3];
} hal_wlan_ftm_t2t3_rx_event_stru;
#endif

typedef struct {
    hal_tx_dscr_stru *pst_base_dscr; /* ?????????????????????????????????? */
    hal_to_dmac_device_stru *pst_hal_device;
    oal_uint8 uc_dscr_num; /* ?????????????????????????????? */
#ifdef _PRE_WLAN_FIT_BASED_REALTIME_CALI
    oal_bool_enum_uint8 en_pdet_enable : 1;
    oal_bool_enum_uint8 en_invalid : 1;
    oal_bool_enum_uint8 en_cur_dscr_pdet_en : 1;
    oal_uint8 uc_resv : 5;
    oal_int16 s_pdet_val_i;
    oal_int16 s_pdet_val_q;
    oal_int16 us_resv[1];
#else
    oal_uint8 auc_resv[3];
#endif

#ifdef _PRE_WLAN_FEATURE_FTM
    oal_uint64 ull_t1;
    oal_uint64 ull_t4;
#endif
} hal_tx_complete_event_stru;

typedef struct {
    hal_error_state_stru st_error_state;
    hal_to_dmac_device_stru *pst_hal_device;
} hal_error_irq_event_stru;

typedef struct {
    oal_uint8 p2p_noa_status; /* 0: ????noa ????????????1: ????noa ?????????????? */
    oal_uint8 auc_resv[3];
} hal_p2p_pm_event_stru;

/* NVRAM ?????????? */
typedef struct {
    oal_int8 c_delt_txpower; /* ???????????? */
} hal_cfg_customize_nvram_params_stru;

#if (defined(_PRE_PRODUCT_ID_HI110X_DEV))
#pragma pack(1)
#endif

/* customize rf cfg struct */
typedef struct {
    oal_int8 c_rf_gain_db_mult4;  /* ????PA/LNA bypass????????(0.25dB) */
    oal_int8 c_rf_gain_db_mult10; /* ????PA/LNA bypass????????(0.1dB) */
} __OAL_DECLARE_PACKED hal_cfg_customize_gain_db_per_band;

typedef struct {
    /* 2g */
    hal_cfg_customize_gain_db_per_band ac_gain_db_2g[HAL_DEVICE_2G_BAND_NUM_FOR_LOSS];
    /* 5g */
    hal_cfg_customize_gain_db_per_band ac_gain_db_5g[HAL_DEVICE_5G_BAND_NUM_FOR_LOSS];

    oal_uint16 us_lna_on2off_time_ns_5g; /* LNA????LNA????????(ns) */
    oal_uint16 us_lna_off2on_time_ns_5g; /* LNA????LNA????????(ns) */

    oal_int8 c_rf_line_rx_gain_db_5g;   /* ????LNA bypass????????(dB) */
    oal_int8 c_lna_gain_db_5g;          /* ????LNA????(dB) */
    oal_int8 c_rf_line_tx_gain_db_5g;   /* ????LNA bypass????????(dB) */
    oal_uint8 uc_ext_switch_isexist_5g; /* ????????????switch */

    oal_uint8 uc_ext_pa_isexist_5g;                  /* ????????????pa */
    oal_uint8 uc_ext_lna_isexist_5g;                 /* ????????????lna */
    oal_uint8 uc_far_dist_pow_gain_switch;           /* ???????????????????? */
    oal_uint8 uc_far_dist_dsss_scale_promote_switch; /* ??????11b 1m 2m dbb scale???????????? */

    oal_int8 c_delta_cca_ed_high_20th_2g;
    oal_int8 c_delta_cca_ed_high_40th_2g;
    oal_int8 c_delta_cca_ed_high_20th_5g;
    oal_int8 c_delta_cca_ed_high_40th_5g;

    oal_int8 c_delta_pwr_ref_2g_20m; /* pwr ref 2g 20m delta?? */
    oal_int8 c_delta_pwr_ref_2g_40m; /* pwr ref 2g 40m delta?? */
    oal_int8 c_delta_pwr_ref_5g_20m; /* pwr ref 5g 20m delta?? */
    oal_int8 c_delta_pwr_ref_5g_40m; /* pwr ref 5g 40m delta?? */

    oal_int8 c_delta_pwr_ref_5g_80m; /* pwr ref 5g 80m delta?? */
    oal_int8 auc_resv[3];
} __OAL_DECLARE_PACKED wlan_cfg_customize_rf;

/* ?????? DTS???????? */
typedef struct
{
    /* dts */
    /* no used var Begin:: 1102A ASIC no used ini */
    oal_int16 aus_cali_txpwr_pa_dc_ref_2g_val[13]; /* txpwr??????ref?? */
    oal_int16 us_cali_txpwr_pa_dc_ref_5g_val_band[7];
    /* no used var End:: 1102A ASIC no used ini */
    oal_int8 uc_band_5g_enable;
    oal_uint8 uc_tone_amp_grade;
    oal_uint8 auc_resv_wifi_cali[2];
    /* bt tmp */
    oal_int8 ac_cali_bt_txpwr_dpn_params[CUS_BT_FREQ_NUM];
    oal_int16 s_cali_bt_txpwr_num;
    oal_uint8 auc_cali_bt_txpwr_freq[CUS_BT_TXPWR_FREQ_NUM_MAX];
    oal_uint8 uc_bt_insertion_loss;
    oal_uint8 uc_bt_gm_cali_en;
    oal_int16 s_bt_gm0_dB10;
    oal_uint8 uc_bt_base_power;
    oal_uint8 uc_bt_is_dpn_calc;
} __OAL_DECLARE_PACKED wlan_cus_cali_stru;

/* no used struct Begin:: 1102A ASIC no used ini */
/* RF?????????????????? */
typedef struct
{
    oal_uint16 us_rf_reg117;
    oal_uint16 us_rf_reg123;
    oal_uint16 us_rf_reg124;
    oal_uint16 us_rf_reg125;
    oal_uint16 us_rf_reg126;
    oal_uint8 auc_resv[2];
} __OAL_DECLARE_PACKED wlan_cfg_customize_rf_reg;

typedef struct
{
    oal_uint8 uc_temp_pro_enable;            /* ?????????????????? */
    oal_uint8 uc_temp_pro_reduce_pwr_enable; /* ?????????????????????????????? */
    oal_int16 us_temp_pro_safe_th;           /* ?????????????????????? */
    oal_int16 us_temp_pro_over_th;           /* ?????????????????? */
    oal_int16 us_temp_pro_pa_off_th;         /* ??????????????pa???? */
} __OAL_DECLARE_PACKED hal_temp_pri_custom_stru;

/* ?????????????? */
typedef struct
{
    oal_uint16 us_cali_mask;
    oal_int16 s_dsss2ofdm_dbb_pwr_bo_val; /* ????scaling????????????????DSSS????????OFDM???????????????? ????0.01db */
    oal_uint32 ul_resv;
    oal_uint8 uc_fast_check_cnt;
    oal_uint8 uc_voe_switch;  // ????????11k,11v,11r
    /* dyn cali */
    oal_uint16 aus_dyn_cali_dscr_interval[WLAN_BAND_BUTT]; /* ????????????2.4g 5g */
    oal_uint8 uc_5g_ext_fem_type;
    oal_uint8 close_filter_switch;
    hal_temp_pri_custom_stru st_temp_pri_custom;
#ifdef _PRE_WLAN_FEATURE_DYN_BYPASS_EXTLNA
    oal_uint8 uc_dyn_bypass_extlna_enable;
#endif
    oal_uint8 uc_hcc_flowctrl_type;
    oal_uint8 uc_i3c_switch;
} __OAL_DECLARE_PACKED wlan_cfg_customize_priv;

typedef struct
{
    /* FCC??CE???????????????? */
    oal_uint8 auc_5g_txpwr_20M[FCC_CE_CH_NUM_5G_20M];
    oal_uint8 auc_5g_txpwr_40M[FCC_CE_CH_NUM_5G_40M];
    oal_uint8 auc_5g_txpwr_80M[FCC_CE_CH_NUM_5G_80M];
    oal_uint8 auc_5g_txpwr_160M[FCC_CE_CH_NUM_5G_160M];
    oal_uint8 auc_2g_txpwr[WLAN_2G_SUB_BAND_NUM][FCC_CE_SIG_TYPE_NUM_2G];
} __OAL_DECLARE_PACKED wlan_fcc_ce_power_limit_stru;

typedef struct {
    oal_uint8 auc_5g_txpwr_20M[FCC_CE_EXT_CH_NUM_5G_20M];
    oal_uint8 auc_5g_txpwr_40M[FCC_CE_EXT_CH_NUM_5G_40M];
} __OAL_DECLARE_PACKED wlan_ext_fcc_ce_power_limit_stru;
/* ?????? ?????? */
typedef struct
{
    /* delt power */
    oal_int8 ac_delt_txpower[NUM_OF_NV_MAX_TXPOWER]; /* ??????????????????base power???????? */

    /* BASE POWER */
    oal_uint8 auc_base_power[CUS_BASE_POWER_NUM]; /* ????????????????2G,5G band1~band7,2G */

    /* SAR CTRL */
    oal_uint8 auc_sar_ctrl_params[CUS_SAR_NUM]; /* CE????SAR???????????????? */

    /* ????????????FCC??CE???????? */
    wlan_fcc_ce_power_limit_stru st_fcc_ce_txpwer_limit;
    /* ?????????????????? */
    wlan_ext_fcc_ce_power_limit_stru st_ext_fcc_ce_txpwer_limit;
    /* 5G??band???????????? */
    oal_uint8 uc_5g_high_band_max_pow;

    /* ????2.4G???????? */
    oal_uint8 uc_nb_base_power;
} __OAL_DECLARE_PACKED wlan_customize_power_params_stru;

#if (defined(_PRE_PRODUCT_ID_HI110X_DEV))
#pragma pack()
#endif

/*****************************************************************************
  10.2 ??????????????????
*****************************************************************************/
#if ((_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102_DEV) || (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102_HOST) ||  \
     (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102A_DEV) || (_PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102A_HOST))

/************************  1102  CHIP********************************************/
#define HAL_CHIP_LEVEL_FUNC_EXTERN
extern oal_void hi1102_get_chip_version(hal_to_dmac_chip_stru *pst_hal_chip, oal_uint32 *pul_chip_ver);
/************************  1102  DEVICE********************************************/
#define HAL_DEVICE_LEVEL_FUNC_EXTERN
extern oal_void hi1102_rx_init_dscr_queue(hal_to_dmac_device_stru *pst_device, oal_uint8 uc_set_hw);
extern oal_void hi1102_rx_destroy_dscr_queue(hal_to_dmac_device_stru *pst_device, oal_uint8 uc_destroy_netbuf);
extern oal_void hi1102_al_rx_init_dscr_queue(hal_to_dmac_device_stru *pst_device);

extern oal_void hi1102_al_rx_destroy_dscr_queue(hal_to_dmac_device_stru *pst_device);
extern oal_void hi1102_tx_init_dscr_queue(hal_to_dmac_device_stru *pst_device);
extern oal_void hi1102_tx_destroy_dscr_queue(hal_to_dmac_device_stru *pst_device);
extern oal_void hi1102_init_hw_rx_isr_list(hal_to_dmac_device_stru *pst_device);
extern oal_void hi1102_destroy_hw_rx_isr_list(hal_to_dmac_device_stru *pst_device);
extern oal_void hi1102_flush_tx_complete_irq(hal_to_dmac_device_stru *pst_hal_dev);
extern oal_void hi1102_tx_fill_basic_ctrl_dscr(hal_tx_dscr_stru *p_tx_dscr, hal_tx_mpdu_stru *pst_mpdu);
extern oal_void hi1102_tx_ctrl_dscr_link(hal_tx_dscr_stru *pst_tx_dscr_prev, hal_tx_dscr_stru *pst_tx_dscr);
extern oal_void hi1102_get_tx_dscr_next(hal_tx_dscr_stru *pst_tx_dscr, hal_tx_dscr_stru **ppst_tx_dscr_next);
extern oal_void hi1102_tx_ctrl_dscr_unlink(hal_tx_dscr_stru *pst_tx_dscr);
extern oal_void hi1102_tx_ucast_data_set_dscr(hal_to_dmac_device_stru *pst_hal_device,
                                              hal_tx_dscr_stru *pst_tx_dscr,
                                              hal_tx_txop_feature_stru *pst_txop_feature,
                                              hal_tx_txop_alg_stru *pst_txop_alg,
                                              hal_tx_ppdu_feature_stru *pst_ppdu_feature);
extern oal_void hi1102_tx_non_ucast_data_set_dscr(hal_to_dmac_device_stru *pst_hal_device,
                                                  hal_tx_dscr_stru *pst_tx_dscr,
                                                  hal_tx_txop_feature_stru *pst_txop_feature,
                                                  hal_tx_txop_alg_stru *pst_txop_alg,
                                                  hal_tx_ppdu_feature_stru *pst_ppdu_feature);
extern oal_void hi1102_tx_ucast_data_set_dscr_rts_params(hal_to_dmac_device_stru *pst_device,
                                                         hal_tx_dscr_stru *pst_tx_dscr);
extern oal_void hi1102_tx_set_dscr_modify_mac_header_length(hal_tx_dscr_stru *pst_tx_dscr,
                                                            oal_uint8 uc_mac_header_length);
extern oal_void hi1102_tx_set_dscr_seqno_sw_generate(hal_tx_dscr_stru *pst_tx_dscr,
                                                     oal_uint8 uc_sw_seqno_generate);
extern oal_void hi1102_tx_get_size_dscr(oal_uint8 us_msdu_num, oal_uint32 *pul_dscr_one_size,
                                        oal_uint32 *pul_dscr_two_size);
extern oal_void hi1102_tx_get_vap_id(hal_tx_dscr_stru *pst_tx_dscr, oal_uint8 *puc_vap_id);
extern oal_void hi1102_tx_get_dscr_ctrl_one_param(hal_tx_dscr_stru *pst_tx_dscr,
                                                  hal_tx_dscr_ctrl_one_param *pst_tx_dscr_one_param);
extern oal_void hi1102_tx_get_dscr_seq_num(hal_tx_dscr_stru *pst_tx_dscr, oal_uint16 *pus_seq_num);
extern oal_void hi1102_tx_get_dscr_tx_cnt(hal_tx_dscr_stru *pst_tx_dscr, oal_uint8 *puc_tx_count);
extern oal_void hi1102_tx_dscr_get_rate3(hal_tx_dscr_stru *pst_tx_dscr, oal_uint8 *puc_rate);
extern oal_void hi1102_tx_set_dscr_status(hal_tx_dscr_stru *pst_tx_dscr, oal_uint8 uc_status);
extern oal_void hi1102_tx_get_dscr_status(hal_tx_dscr_stru *pst_tx_dscr, oal_uint8 *puc_status);
extern oal_void hi1102_tx_get_dscr_send_rate_rank(hal_tx_dscr_stru *pst_tx_dscr, oal_uint8 *puc_send_rate_rank);
extern oal_void hi1102_tx_get_dscr_chiper_type(hal_tx_dscr_stru *pst_tx_dscr, oal_uint8 *puc_chiper_type,
                                               oal_uint8 *puc_chiper_key_id);
extern oal_void hi1102_tx_get_dscr_ba_ssn(hal_tx_dscr_stru *pst_tx_dscr, oal_uint16 *pus_ba_ssn);
extern oal_void hi1102_tx_get_dscr_ba_bitmap(hal_tx_dscr_stru *pst_tx_dscr, oal_uint32 *pul_ba_bitmap);
extern oal_void hi1102_tx_put_dscr(hal_to_dmac_device_stru *pst_hal_device,
                                   hal_tx_queue_type_enum_uint8 en_tx_queue_type, hal_tx_dscr_stru *past_tx_dscr);
extern oal_void hi1102_get_tx_q_status(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pul_status,
                                       oal_uint8 uc_qnum);
extern oal_void hi1102_tx_get_ampdu_len(hal_to_dmac_device_stru *pst_hal_device, hal_tx_dscr_stru *pst_dscr,
                                        oal_uint32 *pul_ampdu_len);
extern oal_void hi1102_tx_get_protocol_mode(hal_to_dmac_device_stru *pst_hal_device, hal_tx_dscr_stru *pst_dscr,
                                            oal_uint8 *puc_protocol_mode);
extern oal_void hi1102_tx_get_bw_mode(hal_to_dmac_device_stru *pst_hal_device, hal_tx_dscr_stru *pst_dscr,
                                      wlan_bw_cap_enum_uint8 *pen_bw_mode);
extern oal_void hi1102_rx_get_info_dscr(oal_uint32 *pul_rx_dscr, hal_rx_ctl_stru *pst_rx_ctl,
                                        hal_rx_status_stru *pst_rx_status, hal_rx_statistic_stru *pst_rx_statistics);
extern oal_void hi1102_get_hal_vap(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_vap_id,
                                   hal_to_dmac_vap_stru **ppst_hal_vap);
extern oal_void hi1102_rx_get_netbuffer_addr_dscr(oal_uint32 *pul_rx_dscr, oal_netbuf_stru **ppul_mac_hdr_addr);
extern oal_void hi1102_rx_show_dscr_queue_info(hal_to_dmac_device_stru *pst_hal_device,
                                               hal_rx_dscr_queue_id_enum_uint8 en_rx_dscr_type);
extern oal_void hi1102_rx_sync_invalid_dscr(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pul_dscr,
                                            oal_uint8 en_queue_num);
extern oal_void hi1102_rx_free_dscr_list(hal_to_dmac_device_stru *pst_hal_device,
                                         hal_rx_dscr_queue_id_enum_uint8 en_queue_num, oal_uint32 *pul_rx_dscr);
extern oal_void hi1102_dump_tx_dscr(oal_uint32 *pul_tx_dscr);
extern oal_void hi1102_reg_write(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_addr, oal_uint32 ul_val);
extern oal_void hi1102_reg_write16(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_addr, oal_uint16 us_val);
extern oal_void hi1102_set_counter_clear(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_set_machw_rx_buff_addr(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_rx_dscr,
                                              hal_rx_dscr_queue_id_enum_uint8 en_queue_num);
extern oal_uint32 hi1102_set_machw_rx_buff_addr_sync(hal_to_dmac_device_stru *pst_hal_device,
                                                     oal_uint32 ul_rx_dscr,
                                                     hal_rx_dscr_queue_id_enum_uint8 en_queue_num);
extern oal_void hi1102_rx_add_dscr(hal_to_dmac_device_stru *pst_hal_device,
                                   hal_rx_dscr_queue_id_enum_uint8 en_queue_num, oal_uint16 us_rx_dscr_num);
extern oal_void hi1102_free_rx_isr_list(hal_to_dmac_device_stru *pst_hal_device,
                                        oal_dlist_head_stru *pst_rx_isr_list, oal_bool_enum_uint8 en_recycle);
extern oal_void hi1102_set_machw_tx_suspend(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_set_machw_tx_resume(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_reset_phy_machw(hal_to_dmac_device_stru *pst_hal_device,
                                       hal_reset_hw_type_enum_uint8 en_type,
                                       oal_uint8 sub_mod, oal_uint8 uc_reset_phy_reg, oal_uint8 uc_reset_mac_reg);
extern oal_void hi1102_disable_machw_phy_and_pa(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_enable_machw_phy_and_pa(hal_to_dmac_device_stru *pst_hal_device);
extern oal_bool_enum_uint8 hi1102_is_machw_enabled(hal_to_dmac_device_stru *pst_device);
extern oal_void hi1102_rf_temperature_trig_cali(hal_to_dmac_device_stru *pst_hal_device);

extern oal_void hi1102_initialize_machw(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_set_freq_band(hal_to_dmac_device_stru *pst_hal_device,
                                     wlan_channel_band_enum_uint8 en_band);
extern oal_void hi1102_set_bandwidth_mode(hal_to_dmac_device_stru *pst_hal_device,
                                          wlan_channel_bandwidth_enum_uint8 en_bandwidth);

extern oal_void hi1102_set_upc_data(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_band,
                                    oal_uint8 uc_subband_idx);
extern oal_void hi1102_get_subband_index(wlan_channel_band_enum_uint8 en_band, oal_uint8 uc_channel_num,
                                         oal_uint8 *puc_subband_idx);
extern oal_void hi1102_get_legacy_data_rate_idx(oal_uint8 uc_rate, oal_uint8 *puc_rate_idx);
extern oal_void hi1102_get_pow_index(hal_user_pow_info_stru *pst_user_power_info,
                                     oal_uint8 uc_cur_rate_pow_idx,
                                     hal_tx_txop_tx_power_stru *pst_tx_power,
                                     oal_uint8 *puc_pow_idx);

extern oal_void hi1102_set_band_spec_frame_tx_power(hal_to_dmac_device_stru *pst_hal_device,
                                                    wlan_channel_band_enum_uint8 en_band,
                                                    oal_uint8 uc_chan_num,
                                                    hal_rate_tpc_code_gain_table_stru *pst_rate_tpc_table,
                                                    oal_uint8 uc_pow_level_idx);
extern oal_void hi1102_pow_update_upc_code(hal_to_dmac_vap_stru *pst_hal_vap,
                                           hal_to_dmac_device_stru *pst_hal_device,
                                           oal_uint8 uc_cur_ch_num, wlan_channel_bandwidth_enum_uint8 en_bandwidth);

extern oal_void hi1102_pow_update_p2p_upc(hal_to_dmac_device_stru *pst_hal_device,
                                          wlan_channel_band_enum_uint8 en_freq_band,
                                          oal_uint8 uc_ch_num,
                                          wlan_channel_bandwidth_enum_uint8 en_bandwidth);

extern oal_void hi1102_pow_init_tx_power(hal_to_dmac_device_stru *pst_hal_dev);
extern oal_void hi1102_pow_get_rf_dev_base_power(hal_to_dmac_device_stru *pst_hal_device,
                                                 wlan_channel_band_enum_uint8 en_freq_band,
                                                 oal_uint8 *puc_base_power,
                                                 oal_uint8 uc_subband_idx);
extern oal_void hi1102_get_rate_limit_tx_power(hal_to_dmac_device_stru *pst_hal_device,
                                               oal_uint8 uc_rate_idx,
                                               oal_uint8 uc_base_pow,
                                               wlan_channel_band_enum_uint8 en_freq_band,
                                               oal_uint8 *puc_rate_txpwr_limit);

extern oal_uint32 hi1102_get_center_freq_chan_num(oal_uint8 uc_chan_number,
                                                  wlan_channel_bandwidth_enum_uint8 en_bandwidth,
                                                  oal_uint8 *puc_center_freq_chn);

extern oal_void hi1102_pow_set_rf_regctl_enable(hal_to_dmac_device_stru *pst_hal_dev,
                                                oal_bool_enum_uint8 en_rf_regctl);
extern oal_void hi1102_config_fft_window_offset(oal_uint32 ul_offset_window);

#ifdef _PRE_WLAN_FEATURE_TPC
extern oal_void hi1102_set_tpc_params(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_band,
                                      oal_uint8 uc_channel_num);
#endif
extern oal_void hi1102_process_phy_freq(hal_to_dmac_device_stru *pst_hal_device);

extern oal_void hi1102_set_primary_channel(hal_to_dmac_device_stru *pst_hal_device,
                                           oal_uint8 uc_channel_num,
                                           oal_uint8 uc_band,
                                           oal_uint8 uc_channel_idx,
                                           wlan_channel_bandwidth_enum_uint8 en_bandwidth);
extern oal_void hi1102_set_txop_check_cca(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint8 en_txop_check_cca);
extern oal_void hi1102_add_machw_ba_lut_entry(hal_to_dmac_device_stru *pst_hal_device,
                                              oal_uint8 uc_lut_index, oal_uint8 *puc_dst_addr, oal_uint8 uc_tid,
                                              oal_uint16 uc_seq_no, oal_uint8 uc_win_size);
extern oal_void hi1102_remove_machw_ba_lut_entry(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_lut_index);
extern oal_void hi1102_get_machw_ba_params(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_index,
                                           oal_uint32 *pst_addr_h, oal_uint32 *pst_addr_l, oal_uint32 *pst_ba_para);
extern oal_void hi1102_restore_machw_ba_params(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_index,
                                               oal_uint32 ul_addr_h, oal_uint32 ul_addr_l, oal_uint32 ul_ba_para);
extern oal_void hi1102_set_tx_sequence_num(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_lut_index,
                                           oal_uint8 uc_tid, oal_uint8 uc_qos_flag, oal_uint32 ul_val_write);
extern oal_void hi1102_get_tx_sequence_num(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_lut_index,
                                           oal_uint8 uc_tid, oal_uint8 uc_qos_flag, oal_uint16 *pus_val_read);
extern oal_void hi1102_reset_init(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_reset_destroy(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_reset_reg_restore(hal_to_dmac_device_stru *pst_hal_device,
                                         hal_reset_hw_type_enum_uint8 en_type);
extern oal_void hi1102_reset_reg_save(hal_to_dmac_device_stru *pst_hal_device,
                                      hal_reset_hw_type_enum_uint8 en_type);
extern oal_void hi1102_reset_reg_dma_save(hal_to_dmac_device_stru *pst_hal, oal_uint8 *uc_dmach0,
                                          oal_uint8 *uc_dmach1, oal_uint8 *uc_dmach2);
extern oal_void hi1102_reset_reg_dma_restore(hal_to_dmac_device_stru *pst_hal, oal_uint8 *uc_dmach0,
                                             oal_uint8 *uc_dmach1, oal_uint8 *uc_dmach2);
extern oal_void hi1102_disable_machw_ack_trans(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_enable_machw_ack_trans(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_disable_machw_cts_trans(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_enable_machw_cts_trans(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_initialize_phy(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_phy_update_scaling_reg(oal_uint8 *puc_dbb_scaling);
extern oal_void hi1102_radar_config_reg(hal_to_dmac_device_stru *pst_hal_device,
                                        hal_dfs_radar_type_enum_uint8 en_dfs_domain);
extern oal_void hi1102_initialize_rf_sys(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_set_rf_custom_reg(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_cali_matrix_data_send_func(oal_uint8 *puc_matrix_data, oal_uint16 us_frame_len,
                                                  oal_uint16 us_remain);
extern oal_void hi1102_cali_send_func(oal_uint8 *puc_cali_data, oal_uint16 us_frame_len, oal_uint16 us_remain);
extern oal_void hi1102_psm_rf_sleep(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_restore_reg);
extern oal_void hi1102_psm_rf_awake(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_restore_reg);
extern oal_void hi1102_pll_cfg_check(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_rf_get_line_control_value(hal_to_dmac_device_stru *pst_hal_device, oal_uint16 *pus_value);
extern oal_void hi1102_initialize_soc(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_get_mac_int_status(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pul_status);
extern oal_void hi1102_clear_mac_int_status(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_status);
extern oal_void hi1102_get_mac_error_int_status(hal_to_dmac_device_stru *pst_hal_device,
                                                hal_error_state_stru *pst_state);
extern oal_void hi1102_clear_mac_error_int_status(hal_to_dmac_device_stru *pst_hal_device,
                                                  hal_error_state_stru *pst_status);
extern oal_void hi1102_unmask_mac_error_init_status(hal_to_dmac_device_stru *pst_hal_device,
                                                    hal_error_state_stru *pst_status);
extern oal_void hi1102_unmask_mac_init_status(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_status);
extern oal_void hi1102_show_irq_info(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_param);
extern oal_void hi1102_dump_all_rx_dscr(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_clear_irq_stat(hal_to_dmac_device_stru *pst_hal_device);

extern oal_void hi1102_get_vap(hal_to_dmac_device_stru *pst_hal_device, wlan_vap_mode_enum_uint8 vap_mode,
                               oal_uint8 vap_id, hal_to_dmac_vap_stru **ppst_hal_vap);
extern oal_void hi1102_add_vap(hal_to_dmac_device_stru *pst_hal_device, wlan_vap_mode_enum_uint8 vap_mode,
                               oal_uint8 uc_mac_vap_id, hal_to_dmac_vap_stru **ppst_hal_vap);
extern oal_void hi1102_del_vap(hal_to_dmac_device_stru *pst_hal_device, wlan_vap_mode_enum_uint8 vap_mode,
                               oal_uint8 vap_id);

extern oal_void hi1102_config_eifs_time(hal_to_dmac_device_stru *pst_hal_device,
                                        wlan_protocol_enum_uint8 en_protocol);
extern oal_void hi1102_register_alg_isr_hook(hal_to_dmac_device_stru *pst_hal_device,
                                             hal_isr_type_enum_uint8 en_isr_type,
                                             hal_alg_noify_enum_uint8 en_alg_notify, p_hal_alg_isr_func p_func);
extern oal_void hi1102_unregister_alg_isr_hook(hal_to_dmac_device_stru *pst_hal_device,
                                               hal_isr_type_enum_uint8 en_isr_type,
                                               hal_alg_noify_enum_uint8 en_alg_notify);
extern oal_void hi1102_register_gap_isr_hook(hal_to_dmac_device_stru *pst_hal_device,
                                             hal_isr_type_enum_uint8 en_isr_type, p_hal_gap_isr_func p_func);
extern oal_void hi1102_unregister_gap_isr_hook(hal_to_dmac_device_stru *pst_hal_device,
                                               hal_isr_type_enum_uint8 en_isr_type);
extern oal_void hi1102_one_packet_start(struct tag_hal_to_dmac_device_stru *pst_hal_device,
                                        hal_one_packet_cfg_stru *pst_cfg);
extern oal_void hi1102_one_packet_stop(struct tag_hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_one_packet_get_status(struct tag_hal_to_dmac_device_stru *pst_hal_device,
                                             hal_one_packet_status_stru *pst_status);
extern oal_void hi1102_reset_nav_timer(struct tag_hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_clear_hw_fifo(struct tag_hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_mask_interrupt(struct tag_hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_offset);
extern oal_void hi1102_unmask_interrupt(struct tag_hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_offset);
extern oal_void hi1102_reg_info(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_addr, oal_uint32 *pul_val);
extern oal_void hi1102_reg_info16(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_addr,
                                  oal_uint16 *pus_val);
#ifdef _PRE_WLAN_FEATURE_DATA_SAMPLE
extern oal_void hi1102_free_sample_mem(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_set_sample_memory(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 **pul_start_addr,
                                         oal_uint32 *ul_reg_num);
extern oal_void hi1102_get_sample_state(hal_to_dmac_device_stru *pst_hal_device, oal_uint16 *pus_reg_val);
extern oal_void hi1102_set_pktmem_bus_access(hal_to_dmac_device_stru *pst_hal_device);
#endif
extern oal_void hi1102_get_all_tx_q_status(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pul_val);
extern oal_void hi1102_get_ampdu_bytes(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pul_tx_bytes,
                                       oal_uint32 *pul_rx_bytes);
extern oal_void hi1102_get_rx_err_count(hal_to_dmac_device_stru *pst_hal_device,
                                        oal_uint32 *pul_cnt1,
                                        oal_uint32 *pul_cnt2,
                                        oal_uint32 *pul_cnt3,
                                        oal_uint32 *pul_cnt4,
                                        oal_uint32 *pul_cnt5,
                                        oal_uint32 *pul_cnt6);
extern oal_void hi1102_show_fsm_info(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_mac_error_msg_report(hal_to_dmac_device_stru *pst_hal_device,
                                            hal_mac_error_type_enum_uint8 en_error_type);
extern oal_void hi1102_en_soc_intr(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_enable_beacon_filter(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_disable_beacon_filter(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_enable_non_frame_filter(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_disable_non_frame_mgmt_filter(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_enable_monitor_mode(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_disable_monitor_mode(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_set_pmf_crypto(hal_to_dmac_vap_stru *pst_hal_vap, oal_bool_enum_uint8 en_crypto);
extern oal_void hi1102_ce_add_key(hal_to_dmac_device_stru *pst_hal_device, hal_security_key_stru *pst_security_key,
                                  oal_uint8 *puc_addr);
extern oal_void hi1102_ce_del_key(hal_to_dmac_device_stru *pst_hal_device,
                                  hal_security_key_stru *pst_security_key);
extern oal_void hi1102_disable_ce(hal_to_dmac_device_stru *pst_device);
extern oal_void hi1102_ce_add_peer_macaddr(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_lut_idx,
                                           oal_uint8 *puc_addr);
extern oal_void hi1102_ce_del_peer_macaddr(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_lut_idx);
extern oal_void hi1102_set_rx_pn(hal_to_dmac_device_stru *pst_hal_device, hal_pn_lut_cfg_stru *pst_pn_lut_cfg);
extern oal_void hi1102_get_rx_pn(hal_to_dmac_device_stru *pst_hal_device, hal_pn_lut_cfg_stru *pst_pn_lut_cfg);
extern oal_void hi1102_set_tx_pn(hal_to_dmac_device_stru *pst_hal_device, hal_pn_lut_cfg_stru *pst_pn_lut_cfg);
extern oal_void hi1102_get_tx_pn(hal_to_dmac_device_stru *pst_hal_device, hal_pn_lut_cfg_stru *pst_pn_lut_cfg);
extern oal_void hi1102_get_rate_80211g_table(oal_void **pst_rate);
extern oal_void hi1102_get_rate_80211g_num(oal_uint32 *pst_data_num);
extern oal_void hi1102_get_hw_addr(oal_uint8 *puc_addr);
extern oal_void hi1102_enable_ch_statics(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_enable);
extern oal_void hi1102_set_ch_statics_period(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_period);
extern oal_void hi1102_set_ch_measurement_period(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_period);
extern oal_void hi1102_get_ch_statics_result(hal_to_dmac_device_stru *pst_hal_device,
                                             hal_ch_statics_irq_event_stru *pst_ch_statics);
extern oal_void hi1102_get_ch_measurement_result(hal_to_dmac_device_stru *pst_hal_device,
                                                 hal_ch_statics_irq_event_stru *pst_ch_statics);
extern oal_void hi1102_enable_radar_det(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_enable);

extern oal_void hi1102_enable_sigB(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_enable);
extern oal_void hi1102_enable_improve_ce(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_enable);

#ifdef _PRE_WLAN_PHY_BUGFIX_IMPROVE_CE_TH
extern oal_void hi1102_set_acc_symb_num(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_num);
extern oal_void hi1102_set_improve_ce_threshold(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_val);
#endif
extern oal_void hi1102_get_radar_det_result(hal_to_dmac_device_stru *pst_hal_device,
                                            hal_radar_det_event_stru *pst_radar_info);
extern oal_void hi1102_update_rts_rate_params(hal_to_dmac_device_stru *pst_hal_device,
                                              wlan_channel_band_enum_uint8 en_band);
extern oal_void hi1102_set_rts_rate_params(hal_to_dmac_device_stru *pst_hal_device,
                                           hal_cfg_rts_tx_param_stru *pst_hal_rts_tx_param);
extern oal_void hi1102_set_rts_rate_selection_mode(hal_to_dmac_device_stru *pst_hal_device,
                                                   oal_uint8 uc_rts_rate_select_mode);
#ifdef _PRE_WLAN_FEATURE_TPC
extern oal_void hi1102_get_rf_temp(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 *puc_cur_temp);
extern oal_void hi1102_set_tpc_init_rate_dac_lpf_table(oal_uint8 *pauc_rate_pow_table_2G,
                                                       oal_uint8 *pauc_rate_pow_table_5G,
                                                       oal_uint8 *pauc_mode_len, oal_uint8 uc_pow_mode);

extern oal_void hi1102_set_spec_frm_phy_tx_mode(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_band,
                                                oal_uint8 uc_subband_idx);
extern oal_void hi1102_get_tpc_delay_reg_param(hal_to_dmac_device_stru *pst_hal_device,
                                               oal_uint32 *pul_phy_tx_up_down_time_reg,
                                               oal_uint32 *pul_phy_rx_up_down_time_reg,
                                               oal_uint32 *pul_rf_reg_wr_delay1, oal_uint32 *pul_rf_reg_wr_delay2);
extern oal_void hi1102_set_tpc_delay_reg_param(hal_to_dmac_device_stru *pst_hal_device,
                                               oal_uint32 ul_phy_tx_up_down_time_reg,
                                               oal_uint32 ul_phy_rx_up_down_time_reg,
                                               oal_uint32 ul_rf_reg_wr_delay1, oal_uint32 ul_rf_reg_wr_delay2);
extern oal_void hi1102_get_tpc_rf_reg_param(hal_to_dmac_device_stru *pst_hal_device,
                                            oal_uint16 *pus_dac_val, oal_uint16 *pus_pa_val, oal_uint16 *pus_lpf_val,
                                            oal_uint16 *paus_2g_upc_val, oal_uint16 *paus_5g_upc_val,
                                            oal_uint8 uc_chain_idx);
extern oal_void hi1102_set_tpc_rf_reg_param(hal_to_dmac_device_stru *pst_hal_device,
                                            oal_uint16 us_dac_val, oal_uint16 us_pa_val, oal_uint16 us_lpf_val,
                                            oal_uint16 *paus_2g_upc_val, oal_uint16 *paus_5g_upc_val,
                                            oal_uint8 uc_chain_idx);
extern oal_void hi1102_set_dpd_by_power(hal_tx_txop_rate_params_stru *pst_rate,
                                        oal_uint8 uc_power_level, oal_uint32 ul_dpd_configure, oal_uint32 ul_rate_idx);

#endif
extern oal_void hi1102_set_tpc_ctrl_reg_param(hal_to_dmac_device_stru *pst_hal_device,
                                              oal_uint32 ul_tpc_ctrl_param);
extern oal_void hi1102_set_tpc_phy_reg_param(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_get_bcn_rate(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint8 *puc_data_rate);
extern oal_void hi1102_set_bcn_phy_tx_mode(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint8 uc_tpc_code);
extern oal_void hi1102_get_spec_frm_rate(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_set_dac_lpc_pa_upc_level(oal_uint8 uc_dac_lpf_code,
                                                oal_int8 *pac_tpc_level_table, oal_uint8 uc_tpc_level_num,
                                                oal_uint8 *pauc_dac_lpf_pa_code_table, oal_int16 *pas_upc_gain_table,
                                                oal_int16 *pas_other_gain_table,
                                                wlan_channel_band_enum_uint8 en_freq_band);

extern oal_void hi1102_irq_affinity_init(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_core_id);

#ifdef _PRE_WLAN_FEATURE_TXBF
extern oal_void hi1102_set_legacy_matrix_buf_pointer(hal_to_dmac_device_stru *pst_hal_device,
                                                     oal_uint32 ul_matrix);
extern oal_void hi1102_get_legacy_matrix_buf_pointer(hal_to_dmac_device_stru *pst_hal_device,
                                                     oal_uint32 *pul_matrix);
extern oal_void hi1102_set_vht_report_rate(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_rate);
extern oal_void hi1102_set_vht_report_phy_mode(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_phy_mode);
extern oal_void hi1102_set_ndp_rate(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_rate);
extern oal_void hi1102_set_ndp_phy_mode(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_phy_mode);
extern oal_void hi1102_set_ndp_max_time(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_ndp_time);
extern oal_void hi1102_set_ndpa_duration(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_ndpa_duration);
extern oal_void hi1102_set_ndp_group_id(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_group_id);
extern oal_void hi1102_set_ndp_partial_aid(hal_to_dmac_device_stru *pst_hal_device, oal_uint16 ul_reg_value);
extern oal_void hi1102_set_phy_legacy_bf_en(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_reg_value);
extern oal_void hi1102_set_phy_txbf_legacy_en(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_reg_value);
extern oal_void hi1102_set_phy_pilot_bf_en(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_reg_value);
extern oal_void hi1102_set_ht_buffer_num(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 ul_reg_value);
extern oal_void hi1102_set_ht_buffer_step(hal_to_dmac_device_stru *pst_hal_device, oal_uint16 ul_reg_value);
extern oal_void hi1102_set_ht_buffer_pointer(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_reg_value);
extern oal_void hi1102_delete_txbf_lut_info(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_lut_index);
extern oal_void hi1102_set_txbf_lut_info(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_lut_index,
                                         oal_uint16 ul_reg_value);
extern oal_void hi1102_get_txbf_lut_info(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_lut_index,
                                         oal_uint32 *pst_reg_value);
extern oal_void hi1102_set_h_matrix_timeout(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_reg_value);
extern oal_void hi1102_set_dl_mumimo_ctrl(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 value);
extern oal_void hi1102_set_mu_aid_matrix_info(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 us_aid,
                                              oal_uint8 *p_matrix);
extern oal_void hi1102_set_sta_membership_status_63_32(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 value);
extern oal_void hi1102_set_sta_membership_status_31_0(hal_to_dmac_device_stru *pst_hal_device,
                                                      oal_uint32 ul_value);
extern oal_void hi1102_set_sta_user_p_63_48(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_value);
extern oal_void hi1102_set_sta_user_p_47_32(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_value);
extern oal_void hi1102_set_sta_user_p_31_16(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_value);
extern oal_void hi1102_set_sta_user_p_15_0(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_value);

#endif
extern oal_void hi1102_set_peer_lut_info(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 *puc_mac_addr,
                                         oal_uint8 uc_lut_index);

extern oal_void hi1102_enable_smart_antenna_gpio_set_default_antenna(hal_to_dmac_device_stru *pst_hal_device,
                                                                     oal_uint32 ul_reg_value);
extern oal_void hi1102_delete_smart_antenna_value(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_lut_index);
extern oal_void hi1102_set_smart_antenna_value(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_lut_index,
                                               oal_uint16 ul_reg_value);
extern oal_void hi1102_get_smart_antenna_value(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_lut_index,
                                               oal_uint32 *pst_reg_value);

#ifdef _PRE_WLAN_FEATURE_ANTI_INTERF
extern oal_void hi1102_set_weak_intf_rssi_th(hal_to_dmac_device_stru *pst_device, oal_int32 l_reg_val);
extern oal_void hi1102_set_agc_unlock_min_th(hal_to_dmac_device_stru *pst_hal_device, oal_int32 l_tx_reg_val,
                                             oal_int32 l_rx_reg_val);
extern oal_void hi1102_set_nav_max_duration(hal_to_dmac_device_stru *pst_hal_device, oal_uint16 us_bss_dur,
                                            oal_uint32 us_obss_dur);
#endif
#ifdef _PRE_WLAN_FEATURE_EDCA_OPT
extern oal_void hi1102_set_counter1_clear(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_get_txrx_frame_time(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *ul_reg_val);
extern oal_void hi1102_set_mac_clken(hal_to_dmac_device_stru *pst_hal_device, oal_bool_enum_uint8 en_wctrl_enable);
#endif
extern oal_void hi1102_get_mac_statistics_data(hal_to_dmac_device_stru *pst_hal_device,
                                               hal_mac_key_statis_info_stru *pst_mac_key_statis);

#ifdef _PRE_WLAN_FEATURE_CCA_OPT
extern oal_void hi1102_get_ed_high_th(hal_to_dmac_device_stru *pst_hal_device, oal_int8 *l_ed_high_reg_val);
extern oal_void hi1102_set_ed_high_th(hal_to_dmac_device_stru *pst_hal_device, oal_int32 l_ed_high_20_reg_val,
                                      oal_int32 l_ed_high_40_reg_val);
extern oal_void hi1102_enable_sync_error_counter(hal_to_dmac_device_stru *pst_hal_device,
                                                 oal_int32 l_enable_cnt_reg_val);
extern oal_void hi1102_get_sync_error_cnt(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *ul_reg_val);
extern oal_void hi1102_set_sync_err_counter_clear(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_get_cca_reg_th(hal_to_dmac_device_stru *pst_hal_device, oal_int8 *ac_reg_val);
#endif
extern oal_void hi1102_set_soc_lpm(hal_to_dmac_device_stru *pst_hal_device, hal_lpm_soc_set_enum_uint8 en_type,
                                   oal_uint8 uc_on_off, oal_uint8 uc_pcie_idle);
extern oal_void hi1102_set_psm_status(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_on_off);
extern oal_void hi1102_set_psm_wakeup_mode(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_mode);
extern oal_void hi1102_set_psm_listen_interval(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 us_interval);
extern oal_void hi1102_set_psm_listen_interval_count(hal_to_dmac_vap_stru *pst_hal_vap,
                                                     oal_uint16 us_interval_count);
extern oal_void hi1102_set_psm_tbtt_offset(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 us_offset);
extern oal_void hi1102_set_psm_ext_tbtt_offset(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 us_offset);
extern oal_void hi1102_set_psm_beacon_period(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint32 ul_beacon_period);
#if defined(_PRE_WLAN_FEATURE_TXOPPS)
extern oal_void hi1102_set_txop_ps_enable(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_on_off);
extern oal_void hi1102_set_txop_ps_condition1(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_on_off);
extern oal_void hi1102_set_txop_ps_condition2(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_on_off);
extern oal_void hi1102_set_txop_ps_partial_aid(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 us_partial_aid);
#endif
extern oal_void hi1102_set_wow_en(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_set_bitmap,
                                  hal_wow_param_stru *pst_para);
extern oal_void hi1102_set_lpm_state(hal_to_dmac_device_stru *pst_hal_device,
                                     hal_lpm_state_enum_uint8 uc_state_from, hal_lpm_state_enum_uint8 uc_state_to,
                                     oal_void *pst_para,
                                     oal_void *pst_wow_para);
extern oal_void hi1102_disable_machw_edca(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_enable_machw_edca(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_set_tx_abort_en(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_abort_en);
extern oal_void hi1102_set_coex_ctrl(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_mac_ctrl,
                                     oal_uint32 ul_rf_ctrl);
extern oal_void hi1102_get_hw_version(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pul_hw_vsn,
                                      oal_uint32 *pul_hw_vsn_data, oal_uint32 *pul_hw_vsn_num);

#ifdef _PRE_DEBUG_MODE
extern oal_void hi1102_get_all_reg_value(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_get_cali_data(hal_to_dmac_device_stru *pst_hal_device);
#endif
extern oal_void hi1102_set_tx_dscr_field(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_data,
                                         hal_rf_test_sect_enum_uint8 en_sect);
extern oal_void hi1102_rf_test_disable_al_tx(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_rf_test_enable_al_tx(hal_to_dmac_device_stru *pst_hal_device,
                                            hal_tx_dscr_stru *pst_tx_dscr);
#ifdef _PRE_WLAN_FEATURE_ALWAYS_TX
extern oal_void hi1102_al_tx_set_agc_phy_reg(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_value);
#endif

#ifdef _PRE_WLAN_PHY_PLL_DIV
extern oal_void hi1102_rf_set_freq_skew(oal_uint16 us_idx, oal_uint16 us_chn, oal_int16 as_corr_data[]);
#endif
extern oal_void hi1102_set_daq_mac_reg(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pul_addr,
                                       oal_uint16 us_unit_len, oal_uint16 us_unit_num, oal_uint16 us_depth);
extern oal_void hi1102_set_daq_phy_reg(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_reg_value);
extern oal_void hi1102_set_daq_en(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_reg_value);
extern oal_void hi1102_get_daq_status(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pul_reg_value);

#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
extern oal_void hi1102_set_dac_lpf_gain(hal_to_dmac_device_stru *pst_hal_device,
                                        oal_uint8 en_band, oal_uint8 en_bandwidth, oal_uint8 en_protocol_mode,
                                        oal_uint8 en_rate);
extern oal_void hi1102_get_pwr_comp_val(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_tx_ratio,
                                        oal_int16 *ps_pwr_comp_val);
extern oal_void hi1102_over_temp_handler(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_agc_threshold_handle(hal_to_dmac_device_stru *pst_hal_device, oal_int8 c_rssi);

#endif

extern oal_void hi1102_set_rx_filter(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_rx_filter_val);
extern oal_void hi1102_get_rx_filter(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pst_reg_value);
extern oal_void hi1102_set_beacon_timeout_val(hal_to_dmac_device_stru *pst_hal_device, oal_uint16 us_value);
extern oal_void hi1102_psm_clear_mac_rx_isr(hal_to_dmac_device_stru *pst_hal_device);

#define HAL_VAP_LEVEL_FUNC_EXTERN
extern oal_void hi1102_vap_tsf_get_32bit(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint32 *pul_tsf_lo);
extern oal_void hi1102_vap_tsf_set_32bit(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint32 ul_tsf_lo);
extern oal_void hi1102_vap_tsf_get_64bit(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint32 *pul_tsf_hi,
                                         oal_uint32 *pul_tsf_lo);
extern oal_void hi1102_vap_tsf_set_64bit(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint32 ul_tsf_hi,
                                         oal_uint32 ul_tsf_lo);
extern oal_void hi1102_vap_send_beacon_pkt(hal_to_dmac_vap_stru *pst_hal_vap,
                                           hal_beacon_tx_params_stru *pst_params);
extern oal_void hi1102_vap_set_beacon_rate(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint32 ul_beacon_rate);
extern oal_void hi1102_vap_beacon_suspend(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_vap_beacon_resume(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_vap_set_machw_prot_params(hal_to_dmac_vap_stru *pst_hal_vap,
                                                 hal_tx_txop_rate_params_stru *pst_phy_tx_mode,
                                                 hal_tx_txop_per_rate_params_union *pst_data_rate);

extern oal_void hi1102_vap_set_macaddr(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint8 *puc_mac_addr);
extern oal_void hi1102_vap_set_opmode(hal_to_dmac_vap_stru *pst_hal_vap, wlan_vap_mode_enum_uint8 en_vap_mode);

extern oal_void hi1102_vap_clr_opmode(hal_to_dmac_vap_stru *pst_hal_vap, wlan_vap_mode_enum_uint8 en_vap_mode);
extern oal_void hi1102_vap_set_machw_aifsn_all_ac(hal_to_dmac_vap_stru *pst_hal_vap,
                                                  oal_uint8 uc_bk,
                                                  oal_uint8 uc_be,
                                                  oal_uint8 uc_vi,
                                                  oal_uint8 uc_vo);
extern oal_void hi1102_vap_set_machw_aifsn_ac(hal_to_dmac_vap_stru *pst_hal_vap,
                                              wlan_wme_ac_type_enum_uint8 en_ac,
                                              oal_uint8 uc_aifs);
extern oal_void hi1102_vap_set_machw_aifsn_ac_wfa(hal_to_dmac_vap_stru *pst_hal_vap,
                                                  wlan_wme_ac_type_enum_uint8 en_ac,
                                                  oal_uint8 uc_aifs,
                                                  wlan_wme_ac_type_enum_uint8 en_wfa_lock);
extern oal_void hi1102_vap_set_edca_machw_cw(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint8 uc_cwmax,
                                             oal_uint8 uc_cwmin, oal_uint8 uc_ac_type);
extern oal_void hi1102_vap_set_edca_machw_cw_wfa(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint8 uc_cwmaxmin,
                                                 oal_uint8 uc_ac_type, wlan_wme_ac_type_enum_uint8 en_wfa_lock);
extern oal_void hi1102_vap_get_edca_machw_cw(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint8 *puc_cwmax,
                                             oal_uint8 *puc_cwmin, oal_uint8 uc_ac_type);

extern oal_void hi1102_vap_set_machw_txop_limit_bkbe(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 us_be,
                                                     oal_uint16 us_bk);

extern oal_void hi1102_vap_get_machw_txop_limit_bkbe(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 *pus_be,
                                                     oal_uint16 *pus_bk);
extern oal_void hi1102_vap_set_machw_txop_limit_vivo(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 us_vo,
                                                     oal_uint16 us_vi);
extern oal_void hi1102_vap_get_machw_txop_limit_vivo(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 *pus_vo,
                                                     oal_uint16 *pus_vi);
extern oal_void hi1102_vap_set_machw_edca_bkbe_lifetime(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 us_be,
                                                        oal_uint16 us_bk);
extern oal_void hi1102_vap_get_machw_edca_bkbe_lifetime(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 *pus_be,
                                                        oal_uint16 *pus_bk);
extern oal_void hi1102_vap_set_machw_edca_vivo_lifetime(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 us_vo,
                                                        oal_uint16 us_vi);
extern oal_void hi1102_vap_get_machw_edca_vivo_lifetime(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 *pus_vo,
                                                        oal_uint16 *pus_vi);
extern oal_void hi1102_vap_set_machw_prng_seed_val_all_ac(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_vap_start_tsf(hal_to_dmac_vap_stru *pst_hal_vap, oal_bool_enum_uint8 en_dbac_enable);
extern oal_void hi1102_vap_read_tbtt_timer(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint32 *pul_value);
extern oal_void hi1102_vap_write_tbtt_timer(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint32 ul_value);
extern oal_void hi1102_vap_set_machw_tsf_disable(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_vap_set_machw_beacon_period(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 us_beacon_period);
extern oal_void hi1102_vap_update_beacon_period(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 us_beacon_period);
extern oal_void hi1102_vap_get_beacon_period(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint32 *pul_beacon_period);
extern oal_void hi1102_vap_set_noa(hal_to_dmac_vap_stru *pst_hal_vap,
                                   oal_uint32 ul_start_tsf,
                                   oal_uint32 ul_duration,
                                   oal_uint32 ul_interval,
                                   oal_uint8 uc_count);

extern oal_void hi1102_sta_tsf_restore(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_sta_tsf_save(hal_to_dmac_vap_stru *pst_hal_vap, oal_bool_enum_uint8 en_need_restore);
#ifdef _PRE_WLAN_FEATURE_P2P
extern oal_void hi1102_vap_set_ops(hal_to_dmac_vap_stru *pst_hal_vap,
                                   oal_uint8 en_ops_ctrl,
                                   oal_uint8 uc_ct_window);
extern oal_void hi1102_vap_enable_p2p_absent_suspend(hal_to_dmac_vap_stru *pst_hal_vap,
                                                     oal_bool_enum_uint8 en_suspend_enable);
#endif
extern oal_void hi1102_set_sta_bssid(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint8 *puc_byte);
extern oal_void hi1102_set_sta_dtim_period(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint32 ul_dtim_period);
extern oal_void hi1102_get_sta_dtim_period(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint32 *pul_dtim_period);
extern oal_void hi1102_set_sta_dtim_count(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint32 ul_dtim_count);
extern oal_void hi1102_get_psm_dtim_count(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint8 *uc_dtim_count);
extern oal_void hi1102_set_psm_dtim_count(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint8 uc_dtim_count);
extern oal_void hi1102_set_psm_dtim_period(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint8 uc_dtim_period,
                                           oal_uint8 uc_listen_intvl_to_dtim_times,
                                           oal_bool_enum_uint8 en_receive_dtim);
extern oal_void hi1102_enable_sta_tsf_tbtt(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_disable_sta_tsf_tbtt(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_mwo_det_enable_mac_counter(hal_to_dmac_device_stru *pst_hal_device,
                                                  oal_int32 l_enable_reg_val);
extern oal_void hi1102_tx_enable_peer_sta_ps_ctrl(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_lut_index);
extern oal_void hi1102_tx_disable_peer_sta_ps_ctrl(hal_to_dmac_device_stru *pst_hal_device,
                                                   oal_uint8 uc_lut_index);
extern oal_void hi1102_cfg_slottime_type(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_slottime_type);
extern oal_void hi1102_cfg_rsp_dyn_bw(oal_bool_enum_uint8 en_set, wlan_bw_cap_enum_uint8 en_dyn_bw);
extern oal_void hi1102_get_cfg_rsp_rate_mode(oal_uint32 *pul_rsp_rate_cfg_mode);
extern oal_void hi1102_set_rsp_rate(oal_uint32 ul_rsp_rate_val);

#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
extern oal_void hi1102_get_hw_status(hal_to_dmac_device_stru *pst_hal_device,
                                     oal_uint32 *ul_cali_check_hw_status);
extern oal_void hi1102_pm_wlan_servid_register(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint32 *pul_ret);
extern oal_void hi1102_pm_enable_front_end(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_enable_paldo);
extern oal_void hi1102_dyn_set_tbtt_offset(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_pm_wlan_servid_unregister(hal_to_dmac_vap_stru *pst_hal_vap);
#endif

#ifdef _PRE_WLAN_FEATURE_BTCOEX
extern oal_void hi1102_coex_irq_en_set(oal_uint8 uc_intr_en);
extern oal_void hi1102_coex_sw_irq_clr_set(oal_uint8 uc_irq_clr);
extern oal_void hi1102_set_rx_rsp_other_pri_mode(hal_coex_priority_type_uint8 en_mode);
extern oal_void hi1102_set_rx_rsp_cts_pri_mode(hal_coex_priority_type_uint8 en_mode);
extern oal_void hi1102_set_rx_rsp_ba_pri_mode(hal_coex_priority_type_uint8 en_mode);
extern oal_void hi1102_set_tx_rsp_other_pri_mode(hal_coex_priority_type_uint8 en_mode);
extern oal_void hi1102_set_tx_rsp_cts_pri_mode(hal_coex_priority_type_uint8 en_mode);
extern oal_void hi1102_set_tx_rsp_ba_pri_mode(hal_coex_priority_type_uint8 en_mode);
extern oal_void hi1102_set_tx_one_pkt_pri_mode(hal_coex_priority_type_uint8 en_mode);
extern oal_void hi1102_coex_sw_irq_set(oal_uint8 uc_irq_en);
extern oal_void hi1102_coex_sw_irq_status_get(oal_uint8 *uc_irq_status);
extern oal_void hi1102_get_btcoex_abort_qos_null_seq_num(oal_uint32 *ul_qosnull_seq_num);
extern oal_void hi1102_get_btcoex_occupied_period(oal_uint16 *ul_occupied_period);
extern oal_void hi1102_get_btcoex_pa_status(oal_uint32 *ul_pa_status);
extern oal_void hi1102_btcoex_wait_bt_release_pa(oal_uint16 ul_period);
extern oal_void hi1102_update_btcoex_btble_status(hal_to_dmac_device_stru *pst_hal_device);
extern oal_uint32 hi1102_btcoex_init(oal_void *p_arg);
extern oal_void hi1102_get_btcoex_statistic(oal_bool_enum_uint8 en_enable_abort_stat);
extern oal_uint32 hi1102_mpw_soc_write_reg(oal_uint32 ulQuryRegAddrTemp, oal_uint16 usQuryRegValueTemp);
extern oal_void hi1102_btcoex_update_ap_beacon_count(oal_uint32 *pul_beacon_count);
extern oal_void hi1102_btcoex_post_event(hal_to_dmac_device_stru *pst_hal_device,
                                         hal_dmac_misc_sub_type_enum_uint8 uc_sub_type);
extern oal_void hi1102_btcoex_have_small_ampdu(hal_to_dmac_device_stru *pst_hal_base_device,
                                               oal_uint32 *pul_have_ampdu);
extern oal_void hi1102_btcoex_process_bt_status(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_print);
extern oal_void hi1102_btcoex_get_ps_service_status(hal_to_dmac_device_stru *pst_hal_device,
                                                    hal_btcoex_ps_status_enum_uint8 *en_ps_status);
extern oal_void hi1102_btcoex_get_bt_sco_status(hal_to_dmac_device_stru *pst_hal_device,
                                                oal_bool_enum_uint8 *en_sco_status);
extern oal_void hi1102_btcoex_get_bt_acl_status(hal_to_dmac_device_stru *pst_hal_device,
                                                oal_bool_enum_uint8 *en_acl_status);
extern oal_uint32 hi1102_btcoex_sw_preempt_init(hal_to_dmac_device_stru *pst_hal_device);
#ifdef _PRE_WLAN_FEATURE_LTECOEX
extern oal_void hi1102_ltecoex_req_mask_ctrl(oal_uint16 req_mask_ctrl);
#endif
extern oal_void hi1102_set_btcoex_abort_null_buff_addr(oal_uint32 ul_abort_null_buff_addr);
extern oal_void hi1102_set_btcoex_abort_qos_null_seq_num(oal_uint32 ul_qosnull_seq_num);
extern oal_void hi1102_set_btcoex_hw_rx_priority_dis(oal_uint8 uc_hw_rx_prio_dis);
extern oal_void hi1102_set_btcoex_hw_priority_en(oal_uint8 uc_hw_prio_en);
extern oal_void hi1102_set_btcoex_occupied_period(oal_uint16 ul_occupied_period);
extern oal_void hi1102_btcoex_get_rf_control(oal_uint16 ul_occupied_period, oal_uint32 *pul_wlbt_mode_sel,
                                             oal_uint16 us_wait_cnt);
extern oal_void hi1102_set_btcoex_sw_all_abort_ctrl(oal_uint8 uc_sw_abort_ctrl);
extern oal_void hi1102_set_btcoex_sw_priority_flag(oal_uint8 uc_sw_prio_flag);
extern oal_void hi1102_set_btcoex_soc_gpreg0(oal_uint8 uc_val, oal_uint16 us_mask, oal_uint8 uc_offset);
extern oal_void hi1102_set_btcoex_soc_gpreg1(oal_uint8 uc_val, oal_uint16 us_mask, oal_uint8 uc_offset);
extern oal_void hi1102_btcoex_get_bt_status(oal_uint16 *pus_bt_status, oal_uint16 *pus_ble_status);
#endif
extern oal_void hi1102_tx_get_dscr_iv_word(hal_tx_dscr_stru *pst_dscr, oal_uint32 *pul_iv_ms_word,
                                           oal_uint32 *pul_iv_ls_word, oal_uint8 uc_chiper_type,
                                           oal_uint8 uc_chiper_keyid);
#ifdef _PRE_WLAN_DFT_STAT
extern oal_void hi1102_dft_get_machw_stat_info(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pst_machw_stat,
                                               oal_uint8 us_bank_select, oal_uint32 *pul_len);
extern oal_void hi1102_dft_set_phy_stat_node(hal_to_dmac_device_stru *pst_hal_device,
                                             oam_stats_phy_node_idx_stru *pst_phy_node_idx);
extern oal_void hi1102_dft_get_phyhw_stat_info(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pst_phyhw_stat,
                                               oal_uint8 us_bank_select, oal_uint32 *pul_len);
extern oal_void hi1102_dft_get_rfhw_stat_info(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pst_rfhw_stat,
                                              oal_uint32 *pul_len);
extern oal_void hi1102_dft_get_sochw_stat_info(hal_to_dmac_device_stru *pst_hal_device, oal_uint16 *pst_sochw_stat,
                                               oal_uint32 *pul_len);
extern oal_void hi1102_dft_print_machw_stat(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_dft_print_phyhw_stat(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_dft_print_rfhw_stat(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_dft_report_all_reg_state(hal_to_dmac_device_stru *pst_hal_device);

#endif
extern oal_void hi1102_set_lte_gpio_mode(oal_uint32 ul_mode_value);

extern oal_void hi1102_cfg_cw_signal_reg(hal_to_dmac_device_stru *pst_hal_device,
                                         oal_uint8 uc_chain_idx, wlan_channel_band_enum_uint8 en_band);
extern oal_void hi1102_get_cw_signal_reg(hal_to_dmac_device_stru *pst_hal_device,
                                         oal_uint8 uc_chain_idx, wlan_channel_band_enum_uint8 en_band);
extern oal_void hi1102_revert_cw_signal_reg(hal_to_dmac_device_stru *pst_hal_device,
                                            wlan_channel_band_enum_uint8 en_band);
extern oal_void hi1102_check_test_value_reg(hal_to_dmac_device_stru *pst_hal_device, oal_uint16 us_value,
                                            oal_uint32 *pul_result);
extern oal_uint32 hi1102_rf_get_pll_div_idx(wlan_channel_band_enum_uint8 en_band, oal_uint8 uc_channel_idx,
                                            wlan_channel_bandwidth_enum_uint8 en_bandwidth,
                                            oal_uint8 *puc_pll_div_idx);
extern oal_void hi1102_dscr_set_iv_value(hal_tx_dscr_stru *pst_tx_dscr, oal_uint32 ul_iv_ls_word,
                                         oal_uint32 ul_iv_ms_word);
extern oal_void hi1102_dscr_set_tx_pn_hw_bypass(hal_tx_dscr_stru *pst_tx_dscr, oal_bool_enum_uint8 en_bypass);
extern oal_void hi1102_dscr_get_tx_pn_hw_bypass(hal_tx_dscr_stru *pst_tx_dscr, oal_bool_enum_uint8 *pen_bypass);

#ifdef _PRE_WLAN_FIT_BASED_REALTIME_CALI
extern oal_int16 hi1102_get_tx_pdet_by_pow(hal_to_dmac_device_stru *OAL_CONST pst_hal_device,
                                           hal_pdet_info_stru *OAL_CONST pst_pdet_info,
                                           hal_dyn_cali_usr_record_stru *OAL_CONST pst_user_pow,
                                           oal_int16 *pst_exp_pdet);
extern oal_void hi1102_init_dyn_cali_tx_pow(hal_to_dmac_device_stru *pst_hal_device);

extern oal_void hi1102_rf_cali_realtime_entrance(hal_to_dmac_vap_stru *OAL_CONST pst_hal_vap,
                                                 hal_to_dmac_device_stru *OAL_CONST pst_hal_device,
                                                 hal_pdet_info_stru *OAL_CONST pst_pdet_info,
                                                 hal_dyn_cali_usr_record_stru *OAL_CONST pst_user_pow,
                                                 hal_tx_dscr_stru *OAL_CONST pst_base_dscr);
extern oal_uint32 hi1102_config_custom_dyn_cali(oal_uint8 *puc_param);
extern oal_void hi1102_tx_get_bw_mode(hal_to_dmac_device_stru *pst_hal_device, hal_tx_dscr_stru *pst_dscr,
                                      wlan_bw_cap_enum_uint8 *pen_bw_mode);
extern oal_void hi1102_config_set_dyn_cali_dscr_interval(hal_to_dmac_device_stru *pst_hal_device,
                                                         wlan_channel_band_enum_uint8 uc_band, oal_uint16 us_param_val);
extern oal_void hi1102_rf_init_dyn_cali_reg_conf(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_tx_set_pdet_en(hal_to_dmac_device_stru *pst_hal_device, hal_tx_dscr_stru *pst_tx_dscr,
                                      oal_bool_enum_uint8 en_pdet_en_flag);
extern oal_void hi1102_tx_get_pdet_en(hal_to_dmac_device_stru *pst_hal_device, hal_tx_dscr_stru *pst_tx_dscr,
                                      oal_bool_enum_uint8 *pen_pdet_en_flag);
extern oal_uint32 hi1102_dyn_cali_vdet_val_amend(hal_to_dmac_device_stru *pst_hal_device,
                                                 hal_pdet_info_stru *pst_pdet_info);
#endif  // _PRE_WLAN_FIT_BASED_REALTIME_CALI
extern oal_void hi1102_get_target_tx_power_by_tx_dscr(hal_to_dmac_vap_stru *pst_hal_vap,
                                                      hal_to_dmac_device_stru *pst_hal_device,
                                                      hal_tx_dscr_stru *pst_tx_dscr,
                                                      hal_pdet_info_stru *pst_pdet_info,
                                                      oal_uint8 uc_channel_idx,
                                                      wlan_channel_bandwidth_enum_uint8 en_bandwidth,
                                                      oal_int16 *ps_tx_pow);

#ifdef _PRE_WLAN_FEATURE_FTM
extern oal_uint64 hi1102_get_ftm_time(hal_to_dmac_device_stru *pst_hal_device, oal_uint64 ull_time);
extern oal_uint64 hi1102_check_ftm_t4(hal_to_dmac_device_stru *pst_hal_device, oal_uint64 ull_time);
extern oal_int8 hi1102_get_ftm_t4_intp(hal_to_dmac_device_stru *pst_hal_device, oal_uint64 ull_time);
extern oal_uint64 hi1102_check_ftm_t2(hal_to_dmac_device_stru *pst_hal_device, oal_uint64 ull_time);
extern oal_int8 hi1102_get_ftm_t2_intp(hal_to_dmac_device_stru *pst_hal_device, oal_uint64 ull_time);
extern oal_void hi1102_get_ftm_tod(hal_to_dmac_device_stru *pst_hal_device, oal_uint64 *pull_tod);
extern oal_void hi1102_get_ftm_toa(hal_to_dmac_device_stru *pst_hal_device, oal_uint64 *pull_toa);
extern oal_void hi1102_get_ftm_t2(hal_to_dmac_device_stru *pst_hal_device, oal_uint64 *pull_t2);
extern oal_void hi1102_get_ftm_t3(hal_to_dmac_device_stru *pst_hal_device, oal_uint64 *pull_t3);
extern oal_void hi1102_get_ftm_ctrl_status(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pul_ftm_status);
extern oal_void hi1102_get_ftm_config_status(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pul_ftm_status);
extern oal_void hi1102_set_ftm_ctrl_status(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_ftm_status);
extern oal_void hi1102_set_ftm_config_status(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_ftm_status);
extern oal_void hi1102_set_ftm_enable(hal_to_dmac_device_stru *pst_hal_device, oal_bool_enum_uint8 en_ftm_status);
extern oal_void hi1102_set_ftm_sample(hal_to_dmac_device_stru *pst_hal_device, oal_bool_enum_uint8 en_ftm_status);
extern oal_void hi1102_ftm_get_divider(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 *pul_divider);
extern oal_void hi1102_get_ftm_dialog(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 *puc_dialog);
extern oal_void hi1102_get_ftm_cali_rx_time(hal_to_dmac_device_stru *pst_hal_device,
                                            oal_uint32 *pul_ftm_cali_rx_time);
extern oal_void hi1102_get_ftm_cali_rx_intp_time(hal_to_dmac_device_stru *pst_hal_device,
                                                 oal_uint32 *pul_ftm_cali_rx_time);
extern oal_void hi1102_get_ftm_cali_tx_time(hal_to_dmac_device_stru *pst_hal_device,
                                            oal_uint32 *pul_ftm_cali_tx_time);
extern oal_void hi1102_set_ftm_cali(hal_to_dmac_device_stru *pst_hal_device, hal_tx_dscr_stru *pst_tx_dscr,
                                    oal_bool_enum_uint8 en_ftm_cali);
extern oal_void hi1102_set_ftm_tx_cnt(hal_to_dmac_device_stru *pst_hal_device, hal_tx_dscr_stru *pst_tx_dscr,
                                      oal_uint8 uc_ftm_tx_cnt);
extern oal_void hi1102_set_ftm_bandwidth(hal_to_dmac_device_stru *pst_hal_device, hal_tx_dscr_stru *pst_tx_dscr,
                                         wlan_bw_cap_enum_uint8 en_band_cap);
extern oal_void hi1102_set_ftm_protocol(hal_to_dmac_device_stru *pst_hal_device, hal_tx_dscr_stru *pst_tx_dscr,
                                        wlan_phy_protocol_enum_uint8 uc_prot_format);
extern oal_void hi1102_get_ftm_rtp_reg_ram(hal_to_dmac_device_stru *pst_hal_device, void **pp_ftm_ext_rpt_reg,
                                           oal_uint8 uc_session_index);
extern oal_void hi1102_get_csi_agc(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_get_ftm_rtp_reg(hal_to_dmac_device_stru *pst_hal_device,
                                       oal_uint32 *pul_reg0,
                                       oal_uint32 *pul_reg1,
                                       oal_uint32 *pul_reg2,
                                       oal_uint32 *pul_reg3,
                                       oal_uint32 *pul_reg4);
extern oal_void hi1102_set_tx_dscr_ftm_enable(hal_to_dmac_device_stru *pst_hal_device,
                                              hal_tx_dscr_stru *pst_tx_dscr, oal_bool_enum_uint8 en_ftm_cali);
#endif
extern oal_void hi1102_set_tx_rts_dup_enable(oal_bool_enum_uint8 en_status);
extern oal_void hi1102_set_rx_dyn_bw_select(oal_bool_enum_uint8 en_status);
extern oal_void hi1102_rx_non_ht_rsp_dup_enable(oal_bool_enum_uint8 en_status);
extern oal_void hi1102_rx_vht_rsp_dup_enable(oal_bool_enum_uint8 en_status);
extern oal_void hi1102_rx_ht_rsp_dup_enable(oal_bool_enum_uint8 en_status);
extern oal_void hi1102_set_rx_legacy_adj_val(oal_uint8 uc_time);
extern oal_void hi1102_set_rx_11b_long_adj_val(oal_uint8 uc_time);
extern oal_void hi1102_set_rx_11b_short_adj_val(oal_uint8 uc_time);
extern oal_void hi1102_set_rx_vht_adj_val(oal_uint8 uc_time);
extern oal_void hi1102_set_cca_th(oal_int8 c_pri_20_th, oal_int8 c_sec_20_th, oal_int8 c_sec_40_th);
extern oal_void hi1102_get_cca_th(oal_int8 *pc_th_val);
extern oal_void hi1102_set_cca_bimr_th(oal_uint8 uc_pri_20_th, oal_uint8 uc_sec_20_th, oal_uint8 uc_sec_40_th);
extern oal_void hi1102_get_cca_bimr_th(oal_int8 *pc_th_val);
extern oal_void hi1102_set_cca_mode(oal_uint32 ul_mode);
extern oal_void hi1102_get_cca_mode(oal_uint32 *pul_mode);
extern oal_void hi1102_set_idle_channel_statistics_mode(oal_uint32 ul_mode);
extern oal_void hi1102_get_idle_channel_statistics_mode(oal_uint32 *pul_mode);
extern oal_void hi1102_set_agc_cca_timeout(oal_uint32 ul_time);
extern oal_void hi1102_set_agc_cca_busy_bypass_mode(oal_uint32 ul_mode);
extern oal_void hi1102_set_rssi_fredomain_mode(oal_uint32 ul_mode);
extern oal_void hi1102_tpc_select_upc_level(oal_int16 *pas_upc_gain_table,
                                            oal_uint8 uc_upc_gain_table_len,
                                            hal_to_dmac_vap_stru *pst_hal_vap,
                                            oal_uint8 uc_start_chain);
extern oal_uint32 hi1102_rf_dev_init(oal_void *p_rf_dev);
extern oal_void hi1102_read_max_temperature(oal_int16 *ps_temperature);
extern oal_void hi1102_rf_dev_update_pwr_fit_para(hal_to_dmac_device_stru *pst_device, oal_uint8 uc_subband_idx,
                                                  oal_uint8 uc_pll_div_idx);

extern oal_void hi1102_tpc_store_phy_reg_upc_lut_param(hal_to_dmac_vap_stru *pst_hal_vap,
                                                       hal_to_dmac_device_stru *pst_hal_device,
                                                       oal_uint8 uc_subband_idx);

extern oal_void hi1102_get_sar_ctrl_params(wlan_channel_band_enum_uint8 en_band,
                                           oal_uint8 uc_channel_num,
                                           oal_uint8 *puc_sar_pwr);

extern oal_void hi1102_set_pow_to_tpc_code(hal_to_dmac_vap_stru *pst_hal_vap,
                                           hal_to_dmac_device_stru *pst_hal_dev,
                                           wlan_channel_band_enum_uint8 en_freq_band,
                                           oal_uint8 uc_cur_ch_num,
                                           wlan_channel_bandwidth_enum_uint8 en_bandwidth);

extern oal_void hi1102_adjust_pow_cali_upc_code_by_amend(hal_to_dmac_vap_stru *pst_hal_vap,
                                                         hal_to_dmac_device_stru *pst_hal_device,
                                                         oal_uint8 uc_cur_ch_num);

extern oal_void hi1102_far_dis_is_need_gain_pwr(wlan_channel_band_enum_uint8 en_band,
                                                oal_uint8 uc_channel_num,
                                                oal_bool_enum_uint8 *pen_need_gain);
extern oal_void hi1102_get_gnss_status(oal_bool_enum_uint8 *pen_gnss_on);
extern oal_void hi1102_cfg_anti_intf(hal_to_dmac_vap_stru *pst_hal_vap, oal_int8 c_rssi);
extern oal_void hi1102_reset_anti_intf(oal_void);

#ifdef _PRE_WLAN_FEATURE_CSI
extern oal_void hi1102_set_csi_en(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_reg_value);
extern oal_void hi1102_set_csi_ta(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 *puc_addr);
extern oal_void hi1102_set_csi_ta_check(hal_to_dmac_device_stru *pst_hal_device, oal_bool_enum_uint8 en_check_ta,
                                        oal_bool_enum_uint8 en_check_ftm, oal_uint8 *puc_addr);
extern oal_void hi1102_get_mac_csi_info(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_get_phy_csi_info(hal_to_dmac_device_stru *pst_hal_device,
                                        wlan_channel_bandwidth_enum_uint8 *pen_bandwidth, oal_uint8 *puc_frame_type);
extern oal_void hi1102_prepare_csi_sample_setup(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_set_pktmem_csi_bus_access(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_get_mac_csi_ta(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 *puc_addr);
extern oal_void hi1102_get_csi_end_addr(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 **puc_reg_num);
extern oal_void hi1102_get_pktmem_start_addr(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 **puc_reg_num);
extern oal_void hi1102_get_pktmem_end_addr(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 **pul_reg_num);
extern oal_void hi1102_get_csi_frame_type(hal_to_dmac_device_stru *pst_hal_device,
                                          wlan_channel_bandwidth_enum_uint8 *pen_bandwidth, oal_uint8 *puc_frame_type);
extern oal_void hi1102_free_csi_sample_mem(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_set_csi_memory(hal_to_dmac_device_stru *pst_hal_device, oal_uint32 ul_start_addr,
                                      oal_uint32 ul_reg_num);
extern oal_void hi1102_disable_csi_sample(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_clear_sample_state(hal_to_dmac_device_stru *pst_hal_device);
extern oal_void hi1102_restart_csi_sample(hal_to_dmac_device_stru *pst_hal_device,
                                          oal_bool_enum_uint8 uc_need_pktram);
#endif
extern oal_void hi1102_get_rts_cts_time_non_11b(oal_uint32 *pul_rts_cts_time);
extern oal_void hi1102_get_rts_cts_time_11b(oal_uint32 *pul_rts_cts_time);
extern oal_void hi1102_get_rts_fail_time_non_11b(oal_uint32 *pul_rts_fail_time);
extern oal_void hi1102_get_rts_fail_time_11b(oal_uint32 *pul_rts_fail_time);
extern oal_void hi1102_get_ack_ba_time_non_11b_ampdu(oal_uint32 *pul_ack_ba_time);
extern oal_void hi1102_get_ack_ba_time_non_11b_non_ampdu(oal_uint32 *pul_ack_ba_time);
extern oal_void hi1102_get_ack_ba_time_11b_non_ampdu(oal_uint32 *pul_ack_ba_time);
extern oal_void hi1102_get_vht_phy_time(oal_uint32 *pul_phy_time);
extern oal_void hi1102_get_ht_phy_time(oal_uint32 *pul_phy_time);
extern oal_void hi1102_get_legacy_phy_time(oal_uint32 *pul_phy_time);
extern oal_void hi1102_get_long_preamble_time(oal_uint32 *pul_phy_time);
extern oal_void hi1102_get_short_preamble_time(oal_uint32 *pul_phy_time);
extern oal_void hi1102_pm_set_tbtt_offset(hal_to_dmac_vap_stru *pst_hal_vap, oal_uint16 us_adjust_val);
extern oal_void hi1102_init_pm_info(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_dyn_tbtt_offset_switch(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_switch);
extern oal_void hi1102_dyn_set_tbtt_offset_resv(hal_to_dmac_device_stru *pst_hal_device, oal_uint16 uc_val);

#ifdef _PRE_PM_TBTT_OFFSET_PROBE
extern oal_void hi1102_tbtt_offset_probe_init(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_tbtt_offset_probe_suspend(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_tbtt_offset_probe_resume(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_tbtt_offset_probe_tbtt_cnt_incr(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_tbtt_offset_probe_beacon_cnt_incr(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_tbtt_offset_probe(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_tbtt_offset_probe_state_init(hal_tbtt_offset_probe_stru *pst_probe);
extern oal_void hi1102_tbtt_offset_probe_state_start(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_tbtt_offset_probe_state_up_done(hal_to_dmac_vap_stru *pst_hal_vap);
extern oal_void hi1102_tbtt_offset_probe_state_end(hal_to_dmac_vap_stru *pst_hal_vap);

#endif
extern oal_void hi1102_set_agc_target_adjust(hal_to_dmac_device_stru *pst_hal_device,
                                             hal_phy_agc_target_adjust_enmu_uint8 en_agc_target_adjust_type);
extern oal_void hi1102_set_cca_prot_th(hal_to_dmac_device_stru *pst_hal_device, oal_int8 c_ed_low_th_dsss_reg_val,
                                       oal_int8 c_ed_low_th_ofdm_reg_val);
#ifdef _PRE_WLAN_FIT_BASED_REALTIME_CALI
extern oal_void hi1102_report_gm_val(hal_to_dmac_device_stru *pst_hal_device);
#endif
extern oal_void hi1102_pow_cfg_show_log(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 *puc_rate_idx);
#ifdef _PRE_WLAN_FEATURE_DYN_BYPASS_EXTLNA
extern oal_void hi1102_set_extlna_threshold(hal_to_dmac_device_stru *pst_hal_device,
                                            oal_bool_enum_uint8 en_disable_dyn_extlna_bypass);
extern oal_void hi1102_set_dyn_bypass_extlna_pm_flag(oal_bool_enum_uint8 en_value);
extern oal_bool_enum_uint8 hi1102_get_dyn_bypass_extlna_pm_flag(oal_void);
extern oal_void hi1102_set_dyn_bypass_extlna_enable(oal_uint8 uc_dyn_bypass_extlna_enable);
extern oal_uint8 hi1102_get_dyn_bypass_extlna_enable(oal_void);
#endif
extern oal_void hi1102_clear_user_ptk_key(hal_to_dmac_device_stru *pst_hal_device, oal_uint8 uc_lut_idx);
#ifdef _PRE_BT_FITTING_DATA_COLLECT
extern oal_int32 bt_init_env(oal_void);
extern oal_void bt_cfg_write_txup_cali(oal_uint8 uc_freq);
extern oal_void bt_cfg_txpwr_upc_code(oal_uint8 freq);
extern oal_void bt_print_gm(oal_void);
#endif
extern oal_void hi1102_set_ddc_en(oal_bool_enum_uint8 en_ddc_enable);
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif


