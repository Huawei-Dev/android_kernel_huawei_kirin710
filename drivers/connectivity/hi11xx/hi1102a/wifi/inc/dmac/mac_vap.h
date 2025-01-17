

#ifndef __MAC_VAP_H__
#define __MAC_VAP_H__

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "oal_ext_if.h"
#include "wlan_mib.h"
#include "mac_user.h"
#include "oam_ext_if.h"
#include "mac_regdomain.h"
#include "hal_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_MAC_VAP_H

/*****************************************************************************
  2 ??????
*****************************************************************************/
#define MAC_NUM_DR_802_11A  8 /* 11A 5g????????????????(DR)???? */
#define MAC_NUM_BR_802_11A  3 /* 11A 5g????????????????(BR)???? */
#define MAC_NUM_NBR_802_11A 5 /* 11A 5g??????????????????(NBR)???? */

#define MAC_NUM_DR_802_11B  4 /* 11B 2.4G????????????????(DR)???? */
#define MAC_NUM_BR_802_11B  2 /* 11B 2.4G????????????????(BR)???? */
#define MAC_NUM_NBR_802_11B 2 /* 11B 2.4G????????????????(NBR)???? */

#define MAC_NUM_DR_802_11G  8 /* 11G 2.4G????????????????(DR)???? */
#define MAC_NUM_BR_802_11G  3 /* 11G 2.4G????????????????(BR)???? */
#define MAC_NUM_NBR_802_11G 5 /* 11G 2.4G??????????????????(NBR)???? */

#define MAC_NUM_DR_802_11G_MIXED      12 /* 11G ????????????????????(DR)???? */
#define MAC_NUM_BR_802_11G_MIXED_ONE  4  /* 11G ????1????????????????(BR)???? */
#define MAC_NUM_NBR_802_11G_MIXED_ONE 8  /* 11G ????1??????????????????(NBR)???? */

#define MAC_NUM_BR_802_11G_MIXED_TWO  7 /* 11G ????2????????????????(BR)???? */
#define MAC_NUM_NBR_802_11G_MIXED_TWO 5 /* 11G ????2??????????????????(NBR)???? */

/* 11N MCS?????????? */
#define MAC_MAX_RATE_SINGLE_NSS_20M_11N 0 /* 1????????20MHz?????????? */
#define MAC_MAX_RATE_SINGLE_NSS_40M_11N 0 /* 1????????40MHz?????????? */
#define MAC_MAX_RATE_DOUBLE_NSS_20M_11N 0 /* 1????????80MHz?????????? */
#define MAC_MAX_RATE_DOUBLE_NSS_40M_11N 0 /* 2????????20MHz?????????? */

/* 11AC MCS?????????? */
#define MAC_MAX_SUP_MCS7_11AC_EACH_NSS  0 /* 11AC??????????????????MCS??????????0-7 */
#define MAC_MAX_SUP_MCS8_11AC_EACH_NSS  1 /* 11AC??????????????????MCS??????????0-8 */
#define MAC_MAX_SUP_MCS9_11AC_EACH_NSS  2 /* 11AC??????????????????MCS??????????0-9 */
#define MAC_MAX_UNSUP_MCS_11AC_EACH_NSS 3 /* 11AC??????????????????MCS????????????n???????? */

/* ????????????(9.4.2.158.3????)????????long gi???? */
#define MAC_MAX_RATE_SINGLE_NSS_20M_11AC 86  /* 1????????20MHz?????????? */
#define MAC_MAX_RATE_SINGLE_NSS_40M_11AC 180 /* 1????????40MHz?????????? */
#define MAC_MAX_RATE_SINGLE_NSS_80M_11AC 390 /* 1????????80MHz?????????? */
#define MAC_MAX_RATE_DOUBLE_NSS_20M_11AC 173 /* 2????????20MHz?????????? */
#define MAC_MAX_RATE_DOUBLE_NSS_40M_11AC 360 /* 2????????40MHz?????????? */
#define MAC_MAX_RATE_DOUBLE_NSS_80M_11AC 780 /* 2????????80MHz?????????? */

#define MAC_VAP_USER_HASH_INVALID_VALUE 0xFFFFFFFF                          /* HSAH?????? */
#define MAC_VAP_USER_HASH_MAX_VALUE     (WLAN_ASSOC_USER_MAX_NUM_LIMIT * 2) /* 2?????????? */

#define MAC_VAP_CAP_ENABLE  1
#define MAC_VAP_CAP_DISABLE 0

#define MAC_VAP_FEATURE_ENABLE            1
#define MAC_VAP_FEATRUE_DISABLE           0
#define CIPHER_SUITE_SELECTOR(a, b, c, d) \
    ((((oal_uint32)(d)) << 24) | (((oal_uint32)(c)) << 16) | (((oal_uint32)(b)) << 8) | (oal_uint32)(a))

#define IS_ONLY_SUPPORT_SAE(_puc_suites) ((*(_puc_suites) == 8) && (*((_puc_suites) + 1) == 0))

#define MAC_CALCULATE_HASH_VALUE(_puc_mac_addr) \
    (((_puc_mac_addr)[0] + (_puc_mac_addr)[1]           \
    + (_puc_mac_addr)[2] + (_puc_mac_addr)[3]           \
    + (_puc_mac_addr)[4] + (_puc_mac_addr)[5])          \
    & (MAC_VAP_USER_HASH_MAX_VALUE - 1))

#define IS_AP(_pst_mac_vap)  ((_pst_mac_vap)->en_vap_mode == WLAN_VAP_MODE_BSS_AP)
#define IS_STA(_pst_mac_vap) ((_pst_mac_vap)->en_vap_mode == WLAN_VAP_MODE_BSS_STA)

#define IS_LEGACY_AP_OR_STA(_pst_mac_vap) (IS_AP(_pst_mac_vap) || IS_STA(_pst_mac_vap))

#define IS_P2P_DEV(_pst_mac_vap)    ((_pst_mac_vap)->en_p2p_mode == WLAN_P2P_DEV_MODE)
#define IS_P2P_GO(_pst_mac_vap)     ((_pst_mac_vap)->en_p2p_mode == WLAN_P2P_GO_MODE)
#define IS_P2P_CL(_pst_mac_vap)     ((_pst_mac_vap)->en_p2p_mode == WLAN_P2P_CL_MODE)
#define IS_LEGACY_VAP(_pst_mac_vap) ((_pst_mac_vap)->en_p2p_mode == WLAN_LEGACY_VAP_MODE)
#define IS_LEGACY_STA(_pst_mac_vap) (IS_STA(_pst_mac_vap) && IS_LEGACY_VAP(_pst_mac_vap))
#define IS_LEGACY_AP(_pst_mac_vap)  (IS_AP(_pst_mac_vap) && IS_LEGACY_VAP(_pst_mac_vap))

/* For csec: patch cc */
#define MAC_VAP_STA_UP_STATUS(_pst_mac_vap) \
    (((_pst_mac_vap)->en_vap_state == MAC_VAP_STATE_UP) && ((_pst_mac_vap)->en_vap_mode == WLAN_VAP_MODE_BSS_STA))
#define MAC_VAP_STA_NOT_UP_STATUS(_pst_mac_vap) \
    (((_pst_mac_vap)->en_vap_state != MAC_VAP_STATE_UP) && ((_pst_mac_vap)->en_vap_mode == WLAN_VAP_MODE_BSS_STA))

#define HMAC_VAP_IN_ASSOCING_STAT(_pst_mac_vap) (((_pst_mac_vap)->en_vap_state >= MAC_VAP_STATE_STA_JOIN_COMP) && \
                                                 ((_pst_mac_vap)->en_vap_state <= MAC_VAP_STATE_STA_WAIT_ASOC))

#define CIPHER_IS_WEP(cipher) (((cipher) == WLAN_CIPHER_SUITE_WEP40) || ((cipher) == WLAN_CIPHER_SUITE_WEP104))

#ifdef _PRE_WLAN_DFT_STAT
#define MAC_VAP_STATS_PKT_INCR(_member, _cnt)  ((_member) += (_cnt))
#define MAC_VAP_STATS_BYTE_INCR(_member, _cnt) ((_member) += (_cnt))
#endif

#define MAC_DATA_CONTAINER_HEADER_LEN 4
#define MAC_DATA_CONTAINER_MAX_LEN    512
#define MAC_DATA_CONTAINER_MIN_LEN    8 /* ??????????1?????? */
#define MAC_DATA_HEADER_LEN           4

#define MAC_SEND_TWO_DEAUTH_FLAG 0xf000

#define MAC_DBB_SCALING_2G_RATE_NUM               12 /* 2G rate?????????? */
#define MAC_DBB_SCALING_5G_RATE_NUM               8  /* 2G rate?????????? */
#define MAC_DBB_SCALING_2G_RATE_OFFSET            0  /* 2G Rate dbb scaling ?????????? */
#define MAC_DBB_SCALING_2G_HT20_MCS_OFFSET        12 /* 2G HT20 dbb scaling ?????????? */
#define MAC_DBB_SCALING_2G_HT40_MCS_OFFSET        20 /* 2G HT40 dbb scaling ?????????? */
#define MAC_DBB_SCALING_2G_HT40_MCS32_OFFSET      61 /* 2G HT40 mcs32 dbb scaling ?????????? */
#define MAC_DBB_SCALING_5G_RATE_OFFSET            28 /* 5G Rate dbb scaling ?????????? */
#define MAC_DBB_SCALING_5G_HT20_MCS_OFFSET        40 /* 5G HT20 dbb scaling ?????????? */
#define MAC_DBB_SCALING_5G_HT20_MCS8_OFFSET       36 /* 5G HT20 mcs8 dbb scaling ?????????? */
#define MAC_DBB_SCALING_5G_HT40_MCS_OFFSET        48 /* 5G HT40 dbb scaling ?????????? */
#define MAC_DBB_SCALING_5G_HT40_MCS32_OFFSET      60 /* 5G HT40 mcs32 dbb scaling ?????????? */
#define MAC_DBB_SCALING_5G_HT80_MCS_OFFSET        66 /* 5G HT80 dbb scaling ?????????? */
#define MAC_DBB_SCALING_5G_HT80_MCS0_DELTA_OFFSET 2  /* 5G HT80 mcs0/1 dbb scaling ???????????????? */
#define MAC_DBB_SCALING_CFG_BITS                  8  /* dbb scaling?????????????? */
#define MAC_DBB_SCALING_FIX_POINT_BITS            8  /* dbb scaling ?????????????? 256 (8 bits) */
#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
#define MAC_NUM_2G_BAND 3 /* 2g band?? */
#define MAC_NUM_5G_BAND 7 /* 5g band?? */
#endif

#ifdef _PRE_WLAN_FEATURE_VOWIFI
/* VoWiFi???????????????? */
#define MAC_VOWIFI_PERIOD_MIN         1  /* ????s */
#define MAC_VOWIFI_PERIOD_MAX         30 /* ????s */
#define MAC_VOWIFI_TRIGGER_COUNT_MIN  1
#define MAC_VOWIFI_TRIGGER_COUNT_MAX  100
#define MAC_VOWIFI_LOW_THRESHOLD_MIN  -100
#define MAC_VOWIFI_LOW_THRESHOLD_MAX  -1
#define MAC_VOWIFI_HIGH_THRESHOLD_MIN -100
#define MAC_VOWIFI_HIGH_THRESHOLD_MAX -1

#define MAC_VAP_VOWIFI_MODE_DEFAULT          VOWIFI_MODE_BUTT
#define MAC_VAP_VOWIFI_TRIGGER_COUNT_DEFAULT 5
#define MAC_VAP_VOWIFI_PERIOD_DEFAULT_MS     1000 /* ????ms */
#define MAC_VAP_VOWIFI_HIGH_THRES_DEFAULT    -65
#define MAC_VAP_VOWIFI_LOW_THRES_DEFAULT     -80

#endif

#ifdef _PRE_WLAN_FEATURE_11K
#define MAC_11K_SUPPORT_AP_CHAN_RPT_NUM 8
#define MAC_MEASUREMENT_RPT_FIX_LEN     5
#define MAC_BEACON_RPT_FIX_LEN          26
#define MAC_MAX_RPT_DETAIL_LEN          224 /* 255 - 26(bcn fix) - 3(Meas rpt fix) - 2(subid 1) */
#endif

#define VOWIFI_NAT_KEEP_ALIVE_MAX_NUM 6

#define MAC_VAP_FOREACH_USER(_pst_user, _pst_vap, _pst_list_pos)                          \
    for ((_pst_list_pos) = (_pst_vap)->st_mac_user_list_head.pst_next,                    \
        (_pst_user) = oal_dlist_get_entry((_pst_list_pos), mac_user_stru, st_user_dlist); \
         (_pst_list_pos) != &((_pst_vap)->st_mac_user_list_head);                         \
         (_pst_list_pos) = (_pst_list_pos)->pst_next,                                     \
        (_pst_user) = oal_dlist_get_entry((_pst_list_pos), mac_user_stru, st_user_dlist)) \
        if ((_pst_user) != OAL_PTR_NULL)

#define MAC_DEVICE_FOREACH_VAP(_pst_vap, _pst_device, _uc_vap_index)  \
    for ((_uc_vap_index) = 0,  \
        (_pst_vap) = ((_pst_device)->uc_vap_num > 0) ? \
        ((mac_vap_stru *)mac_res_get_mac_vap((_pst_device)->auc_vap_id[0])) : OAL_PTR_NULL;  \
         (_uc_vap_index) < (_pst_device)->uc_vap_num;   \
         (_uc_vap_index)++, \
        (_pst_vap) = ((_uc_vap_index) < (_pst_device)->uc_vap_num) ? \
        ((mac_vap_stru *)mac_res_get_mac_vap((_pst_device)->auc_vap_id[_uc_vap_index])) : OAL_PTR_NULL) \
        if ((_pst_vap) != OAL_PTR_NULL)

#if defined(_PRE_WLAN_FEATURE_FTM) || defined(_PRE_WLAN_FEATURE_LOCATION)
#define MAC_FTM_TIMER_CNT         4
#define MAX_FTM_RANGE_ENTRY_COUNT 15
#define MAX_FTM_ERROR_ENTRY_COUNT 11
#define MAX_MINIMUN_AP_COUNT      14
#define MAX_REPEATER_NUM          3 /* ??????????????ap???? */
#endif

/*****************************************************************************
  3 ????????
*****************************************************************************/
/* VAP????????AP STA???????????????? */
typedef enum {
    /* ap sta???????? */
    MAC_VAP_STATE_INIT = 0,
    MAC_VAP_STATE_UP = 1,    /* VAP UP */
    MAC_VAP_STATE_PAUSE = 2, /* pause , for ap &sta */

    /* ap ???????? */
    MAC_VAP_STATE_AP_WAIT_START = 3,

    /* sta???????? */
    MAC_VAP_STATE_STA_FAKE_UP = 4,
    MAC_VAP_STATE_STA_WAIT_SCAN = 5,
    MAC_VAP_STATE_STA_SCAN_COMP = 6,
    MAC_VAP_STATE_STA_JOIN_COMP = 7,
    MAC_VAP_STATE_STA_WAIT_AUTH_SEQ2 = 8,
    MAC_VAP_STATE_STA_WAIT_AUTH_SEQ4 = 9,
    MAC_VAP_STATE_STA_AUTH_COMP = 10,
    MAC_VAP_STATE_STA_WAIT_ASOC = 11,
    MAC_VAP_STATE_STA_OBSS_SCAN = 12,
    MAC_VAP_STATE_STA_BG_SCAN = 13,
    MAC_VAP_STATE_STA_LISTEN = 14, /* p2p0 ???? */
#ifdef _PRE_WLAN_FEATURE_ROAM
    MAC_VAP_STATE_ROAMING = 15,       /* ???? */
#endif                                // _PRE_WLAN_FEATURE_ROAM
    MAC_VAP_STATE_STA_NBFH_COMP = 16, /* ???????? */
    MAC_VAP_STATE_BUTT,
} mac_vap_state_enum;
typedef oal_uint8 mac_vap_state_enum_uint8;

/* ????????????????/?????????? */
typedef enum {
    MAC_TEST_MGMT_BCST = 0,    /* ??beacon?????????? */
    MAC_TEST_MGMT_MCST = 1,    /* ??beacon?????????? */
    MAC_TEST_ATIM_UCST = 2,    /* ????ATIM?? */
    MAC_TEST_UCST = 3,         /* ?????????? */
    MAC_TEST_CTL_BCST = 4,     /* ?????????? */
    MAC_TEST_CTL_MCST = 5,     /* ?????????? */
    MAC_TEST_CTL_UCST = 6,     /* ?????????? */
    MAC_TEST_ACK_UCST = 7,     /* ACK?????? */
    MAC_TEST_CTS_UCST = 8,     /* CTS?????? */
    MAC_TEST_RTS_UCST = 9,     /* RTS?????? */
    MAC_TEST_BA_UCST = 10,     /* BA?????? */
    MAC_TEST_CF_END_UCST = 11, /* CF-End?????? */
    MAC_TEST_TA_RA_EUQAL = 12, /* RA,TA?????? */
    MAC_TEST_MAX_TYPE_NUM
} mac_test_frame_type;
typedef oal_uint8 mac_test_frame_type_enum_uint8;

/* ???????????????????? */
typedef enum {
    MAC_SET_POW_RF_REG_CTL = 0, /* ????????RF???????? */
    MAC_SET_POW_MAG_LEVEL,      /* ?????????????? */
    MAC_SET_POW_CTL_LEVEL,      /* ?????????????? */
    MAC_SET_POW_SHOW_LOG,       /* ???????? */

    MAC_SET_POW_BUTT
} mac_set_pow_type_enum;
typedef oal_uint8 mac_set_pow_type_enum_uint8;

typedef enum {
    MAC_VAP_CONFIG_UCAST_DATA = 0,
    MAC_VAP_CONFIG_MCAST_DATA,
    MAC_VAP_CONFIG_BCAST_DATA,
    MAC_VAP_CONFIG_UCAST_MGMT_2G,
    MAC_VAP_CONFIG_UCAST_MGMT_5G,
    MAC_VAP_CONFIG_MBCAST_MGMT_2G,
    MAC_VAP_CONFIG_MBCAST_MGMT_5G,
    MAC_VAP_CONFIG_BUTT,
} mac_vap_config_dscr_frame_type_enum;
typedef oal_uint8 mac_vap_config_dscr_frame_type_uint8;

typedef enum {
    /* ????????????????????,??????????????START??END???? */
    MAC_ALG_CFG_SCHEDULE_START,

    MAC_ALG_CFG_SCHEDULE_VI_CTRL_ENA,
    MAC_ALG_CFG_SCHEDULE_BEBK_MIN_BW_ENA,
    MAC_ALG_CFG_SCHEDULE_MVAP_SCH_ENA,
    MAC_ALG_CFG_FLOWCTRL_ENABLE_FLAG,
    MAC_ALG_CFG_SCHEDULE_VI_SCH_LIMIT,
    MAC_ALG_CFG_SCHEDULE_VO_SCH_LIMIT,
    MAC_ALG_CFG_SCHEDULE_VI_DROP_LIMIT,
    MAC_ALG_CFG_SCHEDULE_VI_MSDU_LIFE_MS,
    MAC_ALG_CFG_SCHEDULE_VO_MSDU_LIFE_MS,
    MAC_ALG_CFG_SCHEDULE_BE_MSDU_LIFE_MS,
    MAC_ALG_CFG_SCHEDULE_BK_MSDU_LIFE_MS,
    MAC_ALG_CFG_SCHEDULE_VI_LOW_DELAY_MS,
    MAC_ALG_CFG_SCHEDULE_VI_HIGH_DELAY_MS,
    MAC_ALG_CFG_SCHEDULE_VI_CTRL_MS,
    MAC_ALG_CFG_SCHEDULE_SCH_CYCLE_MS,
    MAC_ALG_CFG_SCHEDULE_TRAFFIC_CTRL_CYCLE,
    MAC_ALG_CFG_SCHEDULE_CIR_NVIP_KBPS,
    MAC_ALG_CFG_SCHEDULE_CIR_NVIP_KBPS_BE,
    MAC_ALG_CFG_SCHEDULE_CIR_NVIP_KBPS_BK,
    MAC_ALG_CFG_SCHEDULE_CIR_VIP_KBPS,
    MAC_ALG_CFG_SCHEDULE_CIR_VIP_KBPS_BE,
    MAC_ALG_CFG_SCHEDULE_CIR_VIP_KBPS_BK,
    MAC_ALG_CFG_SCHEDULE_CIR_VAP_KBPS,
    MAC_ALG_CFG_SCHEDULE_SM_TRAIN_DELAY,
    MAC_ALG_CFG_VIDEO_DROP_PKT_LIMIT,
    MAC_ALG_CFG_SCHEDULE_LOG_START,
    MAC_ALG_CFG_SCHEDULE_VAP_SCH_PRIO,

    MAC_ALG_CFG_SCHEDULE_LOG_END,

    MAC_ALG_CFG_SCHEDULE_END,

    /* AUTORATE????????????????????????????START??END???? */
    MAC_ALG_CFG_AUTORATE_START,

    MAC_ALG_CFG_AUTORATE_ENABLE,
    MAC_ALG_CFG_AUTORATE_USE_LOWEST_RATE,
    MAC_ALG_CFG_AUTORATE_SHORT_STAT_NUM,
    MAC_ALG_CFG_AUTORATE_SHORT_STAT_SHIFT,
    MAC_ALG_CFG_AUTORATE_LONG_STAT_NUM,
    MAC_ALG_CFG_AUTORATE_LONG_STAT_SHIFT,
    MAC_ALG_CFG_AUTORATE_MIN_PROBE_UP_INTVL_PKTNUM,
    MAC_ALG_CFG_AUTORATE_MIN_PROBE_DOWN_INTVL_PKTNUM,
    MAC_ALG_CFG_AUTORATE_MAX_PROBE_INTVL_PKTNUM,
    MAC_ALG_CFG_AUTORATE_PROBE_INTVL_KEEP_TIMES,
    MAC_ALG_CFG_AUTORATE_DELTA_GOODPUT_RATIO,
    MAC_ALG_CFG_AUTORATE_VI_PROBE_PER_LIMIT,
    MAC_ALG_CFG_AUTORATE_VO_PROBE_PER_LIMIT,
    MAC_ALG_CFG_AUTORATE_AMPDU_DURATION,
    MAC_ALG_CFG_AUTORATE_MCS0_CONT_LOSS_NUM,
    MAC_ALG_CFG_AUTORATE_UP_PROTOCOL_DIFF_RSSI,
    MAC_ALG_CFG_AUTORATE_RTS_MODE,
    MAC_ALG_CFG_AUTORATE_LEGACY_1ST_LOSS_RATIO_TH,
    MAC_ALG_CFG_AUTORATE_HT_VHT_1ST_LOSS_RATIO_TH,
    MAC_ALG_CFG_AUTORATE_LOG_ENABLE,
    MAC_ALG_CFG_AUTORATE_VO_RATE_LIMIT,
    MAC_ALG_CFG_AUTORATE_JUDGE_FADING_PER_TH,
    MAC_ALG_CFG_AUTORATE_AGGR_OPT,
    MAC_ALG_CFG_AUTORATE_AGGR_PROBE_INTVL_NUM,
    MAC_ALG_CFG_AUTORATE_AGGR_STAT_SHIFT,
    MAC_ALG_CFG_AUTORATE_DBAC_AGGR_TIME,
    MAC_ALG_CFG_AUTORATE_DBG_VI_STATUS,
    MAC_ALG_CFG_AUTORATE_DBG_AGGR_LOG,
    MAC_ALG_CFG_AUTORATE_AGGR_NON_PROBE_PCK_NUM,
    MAC_ALG_CFG_AUTORATE_AGGR_MIN_AGGR_TIME_IDX,
    MAC_ALG_CFG_AUTORATE_MAX_AGGR_NUM,
    MAC_ALG_CFG_AUTORATE_LIMIT_1MPDU_PER_TH,
    MAC_ALG_CFG_AUTORATE_BTCOEX_PROBE_ENABLE,
    MAC_ALG_CFG_AUTORATE_BTCOEX_AGGR_ENABLE,
    MAC_ALG_CFG_AUTORATE_COEX_STAT_INTVL,
    MAC_ALG_CFG_AUTORATE_COEX_LOW_ABORT_TH,
    MAC_ALG_CFG_AUTORATE_COEX_HIGH_ABORT_TH,
    MAC_ALG_CFG_AUTORATE_COEX_AGRR_NUM_ONE_TH,
    MAC_ALG_CFG_AUTORATE_DYNAMIC_BW_ENABLE,
    MAC_ALG_CFG_AUTORATE_THRPT_WAVE_OPT,
    MAC_ALG_CFG_AUTORATE_GOODPUT_DIFF_TH,
    MAC_ALG_CFG_AUTORATE_PER_WORSE_TH,
    MAC_ALG_CFG_AUTORATE_RX_CTS_NO_BA_NUM,
    MAL_ALG_CFG_AUTORATE_VOICE_AGGR,
    MAC_ALG_CFG_AUTORATE_FAST_SMOOTH_SHIFT,
    MAC_ALG_CFG_AUTORATE_FAST_SMOOTH_AGGR_NUM,
    MAC_ALG_CFG_AUTORATE_SGI_PUNISH_PER,
    MAC_ALG_CFG_AUTORATE_SGI_PUNISH_NUM,

    MAC_ALG_CFG_AUTORATE_END,

    /* AUTORATE????????????????????????????????START??END???? */
    MAC_ALG_CFG_AUTORATE_LOG_START,

    MAC_ALG_CFG_AUTORATE_STAT_LOG_START,
    MAC_ALG_CFG_AUTORATE_SELECTION_LOG_START,
    MAC_ALG_CFG_AUTORATE_FIX_RATE_LOG_START,
    MAC_ALG_CFG_AUTORATE_STAT_LOG_WRITE,
    MAC_ALG_CFG_AUTORATE_SELECTION_LOG_WRITE,
    MAC_ALG_CFG_AUTORATE_FIX_RATE_LOG_WRITE,
    MAC_ALG_CFG_AUTORATE_AGGR_STAT_LOG_START,
    MAC_ALG_CFG_AUTORATE_AGGR_STAT_LOG_WRITE,

    MAC_ALG_CFG_AUTORATE_LOG_END,

    /* AUTORATE????????????????????????????????START??END???? */
    MAC_ALG_CFG_AUTORATE_TEST_START,

    MAC_ALG_CFG_AUTORATE_DISPLAY_RATE_SET,
    MAC_ALG_CFG_AUTORATE_CONFIG_FIX_RATE,
    MAC_ALG_CFG_AUTORATE_CYCLE_RATE,
    MAC_ALG_CFG_AUTORATE_DISPLAY_RX_RATE,

    MAC_ALG_CFG_AUTORATE_TEST_END,

    /* SMARTANT?????????????? ??????????????START??END???? */
    MAC_ALG_CFG_SMARTANT_START,

    MAC_ALG_CFG_SMARTANT_ENABLE,
    MAC_ALG_CFG_SMARTANT_CERTAIN_ANT,
    MAC_ALG_CFG_SMARTANT_TRAINING_PACKET_NUMBER,
    MAC_ALG_CFG_SMARTANT_CHANGE_ANT,
    MAC_ALG_CFG_SMARTANT_START_TRAIN,
    MAC_ALG_CFG_SMARTANT_SET_TRAINING_PACKET_NUMBER,
    MAC_ALG_CFG_SMARTANT_SET_LEAST_PACKET_NUMBER,
    MAC_ALG_CFG_SMARTANT_SET_ANT_CHANGE_INTERVAL,
    MAC_ALG_CFG_SMARTANT_SET_USER_CHANGE_INTERVAL,
    MAC_ALG_CFG_SMARTANT_SET_PERIOD_MAX_FACTOR,
    MAC_ALG_CFG_SMARTANT_SET_ANT_CHANGE_FREQ,
    MAC_ALG_CFG_SMARTANT_SET_ANT_CHANGE_THRESHOLD,

    MAC_ALG_CFG_SMARTANT_END,
    /* TXBF????????????????????????????START??END???? */
    MAC_ALG_CFG_TXBF_START,
    MAC_ALG_CFG_TXBF_MASTER_SWITCH,
    MAC_ALG_CFG_TXBF_TXMODE_ENABLE,
    MAC_ALG_CFG_TXBF_TXBFER_ENABLE,
    MAC_ALG_CFG_TXBF_TXBFEE_ENABLE,
    MAC_ALG_CFG_TXBF_11N_BFEE_ENABLE,
    MAC_ALG_CFG_TXBF_TXSTBC_ENABLE,
    MAC_ALG_CFG_TXBF_RXSTBC_ENABLE,
    MAC_ALG_CFG_TXBF_2G_BFER_ENABLE,
    MAC_ALG_CFG_TXBF_2NSS_BFER_ENABLE,
    MAC_ALG_CFG_TXBF_FIX_MODE,
    MAC_ALG_CFG_TXBF_FIX_SOUNDING,
    MAC_ALG_CFG_TXBF_PROBE_INT,
    MAC_ALG_CFG_TXBF_REMOVE_WORST,
    MAC_ALG_CFG_TXBF_STABLE_NUM,
    MAC_ALG_CFG_TXBF_PROBE_COUNT,
    MAC_ALG_CFG_TXBF_LOG_ENABLE,
    MAC_ALG_CFG_TXBF_END,
    /* TXBF LOG????????????????????????START??END???? */
    MAC_ALG_CFG_TXBF_LOG_START,
    MAC_ALG_CFG_TXBF_RECORD_LOG_START,
    MAC_ALG_CFG_TXBF_LOG_OUTPUT,
    MAC_ALG_CFG_TXBF_LOG_END,

    /* ??????????????????????????????????START??END???? */
    MAC_ALG_CFG_ANTI_INTF_START,

    MAC_ALG_CFG_ANTI_INTF_IMM_ENABLE,
    MAC_ALG_CFG_ANTI_INTF_UNLOCK_ENABLE,
    MAC_ALG_CFG_ANTI_INTF_RSSI_STAT_CYCLE,
    MAC_ALG_CFG_ANTI_INTF_UNLOCK_CYCLE,
    MAC_ALG_CFG_ANTI_INTF_UNLOCK_DUR_TIME,
    MAC_ALG_CFG_ANTI_INTF_NAV_IMM_ENABLE,
    MAC_ALG_CFG_ANTI_INTF_GOODPUT_FALL_TH,
    MAC_ALG_CFG_ANTI_INTF_KEEP_CYC_MAX_NUM,
    MAC_ALG_CFG_ANTI_INTF_KEEP_CYC_MIN_NUM,
    MAC_ALG_CFG_ANTI_INTF_TX_TIME_FALL_TH,
    MAC_ALG_CFG_ANTI_INTF_PER_PROBE_EN,
    MAC_ALG_CFG_ANTI_INTF_PER_FALL_TH,
    MAC_ALG_CFG_ANTI_INTF_GOODPUT_JITTER_TH,
    MAC_ALG_CFG_ANTI_INTF_DEBUG_MODE,

    MAC_ALG_CFG_ANTI_INTF_END,

    /* EDCA????????????????????????????????START??END???? */
    MAC_ALG_CFG_EDCA_OPT_START,

    MAC_ALG_CFG_EDCA_OPT_CO_CH_DET_CYCLE,
    MAC_ALG_CFG_EDCA_TEL_PK_OPT_ENABLE,
    MAC_ALG_CFG_EDCA_FIX_PARAM_ENABLE,
    MAC_ALG_CFG_EDCA_OPT_AP_EN_MODE,
    MAC_ALG_CFG_EDCA_OPT_STA_EN,
    MAC_ALG_CFG_TXOP_LIMIT_STA_EN,
    MAC_ALG_CFG_EDCA_OPT_STA_WEIGHT,
    MAC_ALG_CFG_EDCA_OPT_NONDIR_TH,
    MAC_ALG_CFG_EDCA_OPT_TH_UDP,
    MAC_ALG_CFG_EDCA_OPT_TH_TCP,
    MAC_ALG_CFG_EDCA_OPT_DEBUG_MODE,
    MAC_ALG_CFG_EDCA_OPT_FE_PORT_OPT,
    MAC_ALG_CFG_EDCA_OPT_FE_PORT_DBG,
    MAC_ALG_CFG_EDCA_OPT_MPDU_DEC_RATIO_TH,
    MAC_ALG_CFG_EDCA_OPT_DEFAULT_CW_MPDU_TH,

    MAC_ALG_CFG_EDCA_OPT_END,

    /* CCA????????????????????????????????START??END???? */
    MAC_ALG_CFG_CCA_OPT_START,

    MAC_ALG_CFG_CCA_OPT_ALG_EN_MODE,
    MAC_ALG_CFG_CCA_OPT_DEBUG_MODE,
    MAC_ALG_CFG_CCA_OPT_SET_T1_COUNTER_TIME,
    MAC_ALG_CFG_CCA_OPT_SET_T2_COUNTER_TIME,
    MAC_ALG_CFG_CCA_OPT_SET_ILDE_CNT_TH,
    MAC_ALG_CFG_CCA_OPT_SET_DUTY_CYC_TH,
    MAC_ALG_CFG_CCA_OPT_SET_AVEG_RSSI_TH,
    MAC_ALG_CFG_CCA_OPT_SET_CHN_SCAN_CYC,
    MAC_ALG_CFG_CCA_OPT_SET_SYNC_ERR_TH,
    MAC_ALG_CFG_CCA_OPT_SET_CCA_TH_DEBUG,
    MAC_ALG_CFG_CCA_OPT_LOG,
    MAC_ALG_CFG_CCA_OPT_SET_COLLISION_RATIO_TH,
    MAC_ALG_CFG_CCA_OPT_SET_GOODPUT_LOSS_TH,
    MAC_ALG_CFG_CCA_OPT_SET_MAX_INTVL_NUM,
    MAC_ALG_CFG_CCA_OPT_NON_INTF_CYCLE_NUM_TH,
    MAC_ALG_CFG_CCA_OPT_NON_INTF_DUTY_CYC_TH,
    MAC_ALG_CFG_CCA_OPT_END,

    /* CCA OPT????????????????????????????????START??END???? */
    MAC_ALG_CFG_CCA_OPT_LOG_START,
    MAC_ALG_CFG_CCA_OPT_STAT_LOG_START,
    MAC_ALG_CFG_CCA_OPT_STAT_LOG_WRITE,
    MAC_ALG_CFG_CCA_OPT_LOG_END,

    /* TPC????????????, ??????????????START??END???? */
    MAC_ALG_CFG_TPC_START,

    MAC_ALG_CFG_TPC_MODE,
    MAC_ALG_CFG_TPC_DEBUG,
    MAC_ALG_CFG_TPC_POWER_LEVEL,
    MAC_ALG_CFG_TPC_LOG,
    MAC_ALG_CFG_TPC_OVER_TMP_TH,
    MAC_ALG_CFG_TPC_DPD_ENABLE_RATE,
    MAC_ALG_CFG_TPC_TARGET_RATE_11B,
    MAC_ALG_CFG_TPC_TARGET_RATE_11AG,
    MAC_ALG_CFG_TPC_TARGET_RATE_HT20,
    MAC_ALG_CFG_TPC_TARGET_RATE_HT40,
    MAC_ALG_CFG_TPC_TARGET_RATE_VHT20,
    MAC_ALG_CFG_TPC_TARGET_RATE_VHT40,
    MAC_ALG_CFG_TPC_TARGET_RATE_VHT80,
    MAC_ALG_CFG_TPC_SHOW_LOG_INFO,
    MAC_ALG_CFG_TPC_NO_MARGIN_POW,
    MAC_ALG_CFG_TPC_POWER_AMEND,

    MAC_ALG_CFG_TPC_END,

    /* TPC????????????????????????????????START??END???? */
    MAC_ALG_CFG_TPC_LOG_START,

    MAC_ALG_CFG_TPC_STAT_LOG_START,
    MAC_ALG_CFG_TPC_STAT_LOG_WRITE,
    MAC_ALG_CFG_TPC_PER_PKT_LOG_START,
    MAC_ALG_CFG_TPC_PER_PKT_LOG_WRITE,
    MAC_ALG_CFG_TPC_GET_FRAME_POW,
    MAC_ALG_CFG_TPC_RESET_STAT,
    MAC_ALG_CFG_TPC_RESET_PKT,

    MAC_ALG_CFG_TPC_LOG_END,

    /* TEMP_PRO????????????????????????????????START??END???? */
    MAC_ALG_CFG_TEMP_PRO_START,
    MAC_ALG_CFG_TEMP_PRO_GET_INFO,
    MAC_ALG_CFG_TEMP_PRO_END,

    MAC_ALG_CFG_BUTT
} mac_alg_cfg_enum;
typedef oal_uint8 mac_alg_cfg_enum_uint8;

typedef enum {
    NO_TXBF = 0,
    ENABLE_TXBF = 1,
    COMPABILITY_TXBF = 2,

    TXBF_BUTT
} mac_txbf_mode_enum;
typedef oal_uint8 mac_txbf_mode_enum_uint8;

typedef enum {
    SHORTGI_20_CFG_ENUM,
    SHORTGI_40_CFG_ENUM,
    SHORTGI_80_CFG_ENUM,
    SHORTGI_BUTT_CFG
} short_gi_cfg_type;

typedef enum {
    MAC_SET_BEACON = 0,
    MAC_ADD_BEACON = 1,

    MAC_BEACON_OPERATION_BUTT
} mac_beacon_operation_type;
typedef oal_uint8 mac_beacon_operation_type_uint8;

typedef enum {
    MAC_WMM_SET_PARAM_TYPE_DEFAULT,
    MAC_WMM_SET_PARAM_TYPE_UPDATE_EDCA,

    MAC_WMM_SET_PARAM_TYPE_BUTT
} mac_wmm_set_param_type_enum;
typedef oal_uint8 mac_wmm_set_param_type_enum_uint8;

#define MAC_VAP_AP_STATE_BUTT  (MAC_VAP_STATE_AP_WAIT_START + 1)
#define MAC_VAP_STA_STATE_BUTT MAC_VAP_STATE_BUTT

#define H2D_SYNC_MASK_BARK_PREAMBLE (1 << 1)
#define H2D_SYNC_MASK_MIB           (1 << 2)
#define H2D_SYNC_MASK_PROT          (1 << 3)
#ifdef _PRE_WLAN_FEATURE_AUTO_FREQ
enum {
    FREQ_IDLE = 0,

    FREQ_MIDIUM = 1,

    FREQ_HIGHER = 2,

    FREQ_HIGHEST = 3,

    FREQ_BUTT = 4
};
typedef oal_uint8 oal_device_freq_type_enum_uint8;
#endif

#ifdef _PRE_WLAN_FEATURE_FTM
typedef enum {
    MAC_FTM_DISABLE_MODE = 0,
    MAC_FTM_RESPONDER_MODE = 1,
    MAC_FTM_INITIATOR_MODE = 2,
    MAC_FTM_MIX_MODE = 3,

    MAC_FTM_MODE_BUTT,
} mac_ftm_mode_enum;
typedef oal_uint8 mac_ftm_mode_enum_uint8;
#endif

#ifdef _PRE_WLAN_FEATURE_TCP_ACK_BUFFER
typedef enum {
    MAC_TCP_ACK_BUF_ENABLE,
    MAC_TCP_ACK_BUF_TIMEOUT,
    MAC_TCP_ACK_BUF_MAX,

    MAC_TCP_ACK_BUF_TYPE_BUTT
} mac_tcp_ack_buf_cfg_cmd_enum;
typedef oal_uint8 mac_tcp_ack_buf_cfg_cmd_enum_uint8;

typedef struct {
    oal_int8 *puc_string;
    mac_tcp_ack_buf_cfg_cmd_enum_uint8 en_tcp_ack_buf_cfg_id;
    oal_uint8 auc_resv[3];
} mac_tcp_ack_buf_cfg_table_stru;
#endif

typedef enum {
    MAC_PS_PARAMS_TIMEOUT,
    MAC_PS_PARAMS_RESTART_COUNT,
    MAC_PS_PARAMS_ALL,

    MAC_PS_PARAMS_TYPE_BUTT
} mac_ps_params_cfg_cmd_enum;
typedef oal_uint8 mac_ps_params_cfg_cmd_enum_uint8;

typedef struct {
    oal_int8 *puc_string;
    mac_ps_params_cfg_cmd_enum_uint8 en_ps_params_cfg_id;
    oal_uint8 auc_resv[3];
} mac_ps_params_cfg_table_stru;

#ifdef _PRE_WLAN_FEATURE_ROAM
/* ????????????????????????,?????????? */
typedef enum {
    ROAM_SCAN_CHANNEL_ORG_0 = 0, /* no scan */
    ROAM_SCAN_CHANNEL_ORG_1 = 1, /* scan only one channel */
    ROAM_SCAN_CHANNEL_ORG_3 = 2, /* 2.4G channel 1\6\11 */
    ROAM_SCAN_CHANNEL_ORG_4 = 3, /* 2.4G channel 1\5\7\11 */
    ROAM_SCAN_CHANNEL_ORG_BUTT
} roam_channel_org_enum;
typedef oal_uint8 roam_channel_org_enum_uint8;

#endif

#ifdef _PRE_WLAN_FIT_BASED_REALTIME_CALI
typedef enum {
    MAC_DYN_CALI_CFG_SET_EN_REALTIME_CALI_ADJUST,
    MAC_DYN_CALI_CFG_SET_2G_DSCR_INT,
    MAC_DYN_CALI_CFG_SET_5G_DSCR_INT,
    MAC_DYN_CALI_CFG_SET_PDET_MIN_TH,
    MAC_DYN_CALI_CFG_SET_PDET_MAX_TH,
    MAC_DYN_CALI_CFG_BUFF,
} mac_dyn_cali_cfg_enum;
typedef oal_uint8 mac_dyn_cali_cfg_enum_uint8;
#endif
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
#ifdef _PRE_WLAN_FEATURE_MULTI_NETBUF_AMSDU
typedef struct {
    /* ??????????????amsdu_ampdu???????? */
    oal_uint8 uc_tx_amsdu_ampdu_en;
    /* ??????????????amsdu???? */
    oal_uint8 uc_cur_amsdu_ampdu_enable[WLAN_VAP_SUPPORT_MAX_NUM_LIMIT];
    oal_uint16 us_amsdu_ampdu_throughput_high;
    oal_uint16 us_amsdu_ampdu_throughput_low;
    oal_uint8 uc_compability_en; /* ???????????????? */
    oal_uint8 uc_resv;
} mac_tx_large_amsdu_ampdu_stru;
extern mac_tx_large_amsdu_ampdu_stru g_tx_large_amsdu;
#endif

typedef struct {
    oal_uint8 uc_ini_tcp_ack_buf_en;
    oal_uint8 uc_cur_tcp_ack_buf_en;
    oal_uint16 us_tcp_ack_buf_throughput_high;
    oal_uint16 us_tcp_ack_buf_throughput_low;
    oal_uint16 us_tcp_ack_buf_throughput_high_40M;
    oal_uint16 us_tcp_ack_buf_throughput_low_40M;
    oal_uint16 us_tcp_ack_buf_throughput_high_80M;
    oal_uint16 us_tcp_ack_buf_throughput_low_80M;
    oal_uint16 us_resv;
} mac_tcp_ack_buf_switch_stru;
/* channel?????? */
typedef struct {
    oal_uint8 uc_chan_number;                       /* ??20MHz?????? */
    wlan_channel_band_enum_uint8 en_band;           /* ???? */
    wlan_channel_bandwidth_enum_uint8 en_bandwidth; /* ???????? */
    oal_uint8 uc_idx;                               /* ?????????? */
} mac_channel_stru;

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
typedef struct {
    oal_uint8 uc_shortgi_type; /* shortgi 20/40/80 */
    oal_uint8 uc_enable;       /* 1:enable; 0:disable */
    oal_uint8 auc_resv[2];
} shortgi_cfg_stru;
#endif
#define SHORTGI_CFG_STRU_LEN 4

typedef struct {
    oal_uint8 uc_announced_channel;                           /* ???????? */
    wlan_channel_bandwidth_enum_uint8 en_announced_bandwidth; /* ?????????? */
    oal_uint8 uc_ch_switch_cnt;                               /* ???????????? */
    wlan_ch_switch_status_enum_uint8 en_ch_switch_status;     /* ???????????? */
    wlan_bw_switch_status_enum_uint8 en_bw_switch_status;     /* ???????????? */
    oal_bool_enum_uint8 en_csa_present_in_bcn;                /* Beacon????????????CSA IE */

    oal_uint8 uc_start_chan_idx;
    oal_uint8 uc_end_chan_idx;
    wlan_channel_bandwidth_enum_uint8 en_user_pref_bandwidth;

    /* VAP??STA????????????
     *
     *  ---|--------|--------------------|-----------------|-----------
     *     0        3                    0                 0
     *     X        A                    B                 C
     *
     *  sta????????????????????????????, ??????????????????
     *  X->A A??????????????????????????,????????????0
     *  ??A->B????????sta????????????: en_waiting_to_shift_channel??true
     *  ??B->C??sta??????????,??????ap??beacon????: en_waiting_for_ap??true
     *  C-> ??sta??????ap??beacon??????????????????
     *
     *  A????????????csa ie(beacon/action...), B????????tbtt????????????????????
     *  0????csa ie??????????0??C??????????beacon
     *
     *  ??A->C??????????????????????????csa ie????????????????
     *
 */
    // oal_bool_enum_uint8                  en_bw_change;             /* STA???????????????????? */
    // oal_bool_enum_uint8                  en_waiting_for_ap;
    oal_uint8 uc_new_channel;                           /* ?????????????????? */
    wlan_channel_bandwidth_enum_uint8 en_new_bandwidth; /* ?????????????????? */
    oal_uint8 uc_new_ch_swt_cnt;                        /* ?????????????????? */
    oal_bool_enum_uint8 en_waiting_to_shift_channel;    /* ???????????? */
    oal_bool_enum_uint8 en_channel_swt_cnt_zero;

    oal_bool_enum_uint8 en_te_b;
    oal_uint8 bit_wait_bw_change : 4; /* ????action??,???????????? */
    oal_uint8 bit_bad_ap : 4;         /* ??????????ap????beacon??csa?????????? */
    oal_uint8 uc_ch_swt_start_cnt;    /* ap???????????????????? */
    oal_uint8 uc_csa_rsv_cnt;         /* ap csa ?????????????? */
    wlan_csa_mode_tx_enum_uint8 en_csa_mode;
    oal_bool_enum_uint8 en_waiting_to_scan; /* csa??????tbtt????scan */
    oal_uint32 ul_chan_report_for_te_a;

    /* ROM???????????????? */
    oal_uint8 _rom[4];
} mac_ch_switch_info_stru;

typedef struct {
    oal_uint8 uc_mac_rate; /* MAC???????? */
    oal_uint8 uc_phy_rate; /* PHY???????? */
    oal_uint8 uc_mbps;     /* ???? */
    oal_uint8 auc_resv[1];
} mac_data_rate_stru;

typedef struct {
    oal_uint8 uc_rs_nrates; /* ???????? */
    oal_uint8 auc_resv[3];
    mac_data_rate_stru ast_rs_rates[WLAN_RATE_MAXSIZE];
} mac_rateset_stru;

typedef struct {
    oal_uint8 uc_br_rate_num;  /* ???????????? */
    oal_uint8 uc_nbr_rate_num; /* ?????????????? */
    oal_uint8 uc_max_rate;     /* ???????????? */
    oal_uint8 uc_min_rate;     /* ???????????? */
    mac_rateset_stru st_rate;
} mac_curr_rateset_stru;

/* wme???? */
typedef struct {
    oal_uint32 ul_aifsn;      /* AIFSN parameters */
    oal_uint32 ul_logcwmin;   /* cwmin in exponential form, ????2^n -1 slot */
    oal_uint32 ul_logcwmax;   /* cwmax in exponential form, ????2^n -1 slot */
    oal_uint32 ul_txop_limit; /* txopLimit, us */
} mac_wme_param_stru;

/* MAC vap???????????? */
typedef struct {
    oal_uint32 bit_uapsd : 1,
               bit_txop_ps : 1,
               bit_wpa : 1,
               bit_wpa2 : 1,
               bit_dsss_cck_mode_40mhz : 1, /* ??????????40M??????DSSS/CCK, 1-????, 0-?????? */
               bit_rifs_tx_on : 1,
               bit_tdls_prohibited : 1,                /* tdls?????????????? 0-??????, 1-???? */
               bit_tdls_channel_switch_prohibited : 1, /* tdls?????????????????????? 0-??????, 1-???? */
               bit_hide_ssid : 1,                      /* AP????????ssid,  0-????, 1-???? */
               bit_wps : 1,                            /* AP WPS????:0-????, 1-???? */
               bit_11ac2g : 1,                         /* 2.4G????11ac:0-????, 1-???? */
               bit_keepalive : 1,                      /* vap KeepAlive????????: 0-????, 1-???? */
               bit_smps : 2,                           /* vap ????SMPS???? */
               bit_dpd_enbale : 1,                     /* dpd???????? */
               bit_dpd_done : 1,                       /* dpd???????? */
               bit_11ntxbf : 1,                        /* 11n txbf???? */
               bit_disable_2ght40 : 1,                 /* 2ght40????????1-??????0-?????? */
               bit_peer_obss_scan : 1,                 /* ????????obss scan????: 0-??????, 1-???? */
               bit_ip_filter : 1,                      /* rx????ip???????????? */
#ifdef _PRE_WLAN_NARROW_BAND
               bit_nb : 1,              /* ???????????????? */
               bit_2040_autoswitch : 1, /* ??????????????????2040???????? */
               bit_icmp_filter : 1,     /* rx????icmp???????????? */
               bit_resv : 9;
#else
               bit_2040_autoswitch : 1, /* ??????????????????2040???????? */
               bit_icmp_filter : 1,     /* rx????icmp???????????? */
               bit_resv : 10;
#endif
} mac_cap_flag_stru;

/* VAP?????????? */
typedef struct {
    /* net_device??????????, net_device???????????????????? */
    oal_uint32 ul_rx_packets_to_lan;                /* ??????????LAN?????? */
    oal_uint32 ul_rx_bytes_to_lan;                  /* ??????????LAN???????? */
    oal_uint32 ul_rx_dropped_packets;               /* ???????????????????? */
    oal_uint32 ul_rx_vap_non_up_dropped;            /* vap????up?????????????? */
    oal_uint32 ul_rx_dscr_error_dropped;            /* ???????????????????????? */
    oal_uint32 ul_rx_first_dscr_excp_dropped;       /* ???????????????????????????? */
    oal_uint32 ul_rx_alg_filter_dropped;            /* ?????????????????????? */
    oal_uint32 ul_rx_feature_ap_dropped;            /* AP?????????????????? */
    oal_uint32 ul_rx_null_frame_dropped;            /* ????NULL???????? */
    oal_uint32 ul_rx_transmit_addr_checked_dropped; /* ?????????????????????? */
    oal_uint32 ul_rx_dest_addr_checked_dropped;     /* ???????????????????? */
    oal_uint32 ul_rx_multicast_dropped;             /* ??????????(netbuf copy????)???? */

    oal_uint32 ul_tx_packets_from_lan; /* ????????LAN?????????? */
    oal_uint32 ul_tx_bytes_from_lan;   /* ????????LAN???????????? */
    oal_uint32 ul_tx_dropped_packets;  /* ???????????????????? */
    /* ???????????????? */
} mac_vap_stats_stru;
#ifdef _PRE_WLAN_FEATURE_CUSTOM_SECURITY
/* ?????? */
typedef struct {
    oal_uint8 auc_mac_addr[OAL_MAC_ADDR_LEN]; /* mac???? */
    oal_uint8 auc_reserved[2];                /* ???????? */
    oal_uint32 ul_cfg_time;                   /* ???????????????? */
    oal_uint32 ul_aging_time;                 /* ???????? */
    oal_uint32 ul_drop_counter;               /* ???????????? */
} mac_blacklist_stru;

/* ?????????? */
typedef struct {
    oal_uint8 auc_mac_addr[OAL_MAC_ADDR_LEN]; /* mac???? */
    oal_uint8 auc_reserved[2];                /* ???????? */
    oal_uint32 ul_cfg_time;                   /* ???????? */
    oal_uint32 ul_asso_counter;               /* ???????? */
} mac_autoblacklist_stru;

/* ?????????????? */
typedef struct {
    oal_uint8 uc_enabled;                                          /* ???????? 0:??????  1:???? */
    oal_uint8 list_num;                                            /* ?????????????????? */
    oal_uint8 auc_reserved[2];                                     /* ???????? */
    oal_uint32 ul_threshold;                                       /* ???? */
    oal_uint32 ul_reset_time;                                      /* ???????? */
    oal_uint32 ul_aging_time;                                      /* ???????? */
    mac_autoblacklist_stru ast_autoblack_list[WLAN_BLACKLIST_MAX]; /* ???????????? */
} mac_autoblacklist_info_stru;

/* ???????????? */
typedef struct {
    oal_uint8 uc_mode;                                     /* ???????????? */
    oal_uint8 uc_list_num;                                 /* ?????? */
    oal_uint8 auc_reserved[2];                             /* ???????? */
    mac_autoblacklist_info_stru st_autoblacklist_info;     /* ?????????????? */
    mac_blacklist_stru ast_black_list[WLAN_BLACKLIST_MAX]; /* ?????????????? */
} mac_blacklist_info_stru;

/* ???????? */
typedef struct {
    oal_uint8 uc_type;           /* ???????? */
    oal_uint8 uc_mode;           /* ????????bit0?????????? bit1?????????? bit2?????????? */
    oal_uint8 uc_forward;        /* forwarding???? */
    oal_uint8 auc_reserved[1];   /* ???????? */
    oal_uint32 ul_counter_bcast; /* ?????????????? */
    oal_uint32 ul_counter_mcast; /* ?????????????? */
    oal_uint32 ul_counter_ucast; /* ?????????????? */
} mac_isolation_info_stru;
#endif /* _PRE_WLAN_FEATURE_CUSTOM_SECURITY */
typedef struct {
    oal_uint16 us_user_idx;
    wlan_protocol_enum_uint8 en_avail_protocol_mode; /* ???????????? */
    wlan_protocol_enum_uint8 en_cur_protocol_mode;
    wlan_protocol_enum_uint8 en_protocol_mode;
    oal_uint8 auc_resv[3];
} mac_h2d_user_protocol_stru;

typedef struct {
    oal_uint16 us_user_idx;
    oal_uint8 uc_arg1;
    oal_uint8 uc_arg2;

    /* ???????????? */
    wlan_protocol_enum_uint8 en_cur_protocol_mode;
    wlan_protocol_enum_uint8 en_protocol_mode;
    oal_uint8 en_avail_protocol_mode; /* ??????VAP????????????, ?????????? */

    wlan_bw_cap_enum_uint8 en_bandwidth_cap;   /* ???????????????? */
    wlan_bw_cap_enum_uint8 en_avail_bandwidth; /* ??????VAP????????????,?????????? */
    wlan_bw_cap_enum_uint8 en_cur_bandwidth;   /* ????????en_avail_bandwidth????,?????????????? */

    oal_bool_enum_uint8 en_user_pmf;
    mac_user_asoc_state_enum_uint8 en_user_asoc_state; /* ???????????? */
} mac_h2d_usr_info_stru;

typedef struct {
    mac_user_cap_info_stru st_user_cap_info; /* ???????????? */
    oal_uint16 us_user_idx;
    oal_uint8 auc_resv[2];
} mac_h2d_usr_cap_stru;


typedef struct {
    oal_uint16 us_user_idx;

    /* vht?????????? */
    mac_vht_hdl_stru st_vht_hdl;

    /* ht?????????? */
    mac_user_ht_hdl_stru st_ht_hdl;

    /* legacy?????????? */
    oal_uint8 uc_avail_rs_nrates;
    oal_uint8 auc_avail_rs_rates[WLAN_RATE_MAXSIZE];

    wlan_protocol_enum_uint8 en_protocol_mode; /* ???????????? */
} mac_h2d_usr_rate_info_stru;

typedef struct {
    oal_uint16 us_sta_aid;
    oal_uint8 uc_uapsd_cap;
    oal_uint8 auc_resv[1];
} mac_h2d_vap_info_stru;

typedef struct {
    oal_uint16 us_user_idx;
    wlan_protocol_enum_uint8 en_avail_protocol_mode; /* ???????????? */
    wlan_bw_cap_enum_uint8 en_bandwidth_cap;         /* ???????????????? */
    wlan_bw_cap_enum_uint8 en_avail_bandwidth;       /* ??????VAP????????????,?????????? */
    wlan_bw_cap_enum_uint8 en_cur_bandwidth;         /* ????????en_avail_bandwidth????,?????????????? */
    oal_uint8 auc_rsv[2];
} mac_h2d_user_bandwidth_stru;

typedef struct {
    mac_channel_stru st_channel;
    oal_uint16 us_user_idx;
    wlan_bw_cap_enum_uint8 en_bandwidth_cap;   /* ???????????????? */
    wlan_bw_cap_enum_uint8 en_avail_bandwidth; /* ??????VAP????????????,?????????? */
    wlan_bw_cap_enum_uint8 en_cur_bandwidth;   /* ????????en_avail_bandwidth????,?????????????? */
    oal_uint8 auc_rsv[3];
} mac_d2h_syn_info_stru;

#pragma pack(push, 1)
typedef struct {
    oal_uint64 aull_ba_bitmap[2];
    oal_uint16 us_start_seq_num;
    oal_uint16 us_end_seq_num;
    oal_uint8 uc_user_index;
    oal_uint8 uc_rx_filtered_small_pkt;
    oal_uint8 uc_rx_filtered_large_pkt;
    oal_bool_enum_uint8 en_ba_info_recorded;
    oal_uint32 ul_rx_filtered_bytes;
} __OAL_DECLARE_PACKED mac_tcp_ack_record_stru;
#pragma pack(pop)

typedef struct {
    oal_uint16 us_user_idx;
    mac_user_asoc_state_enum_uint8 en_asoc_state;
    oal_uint8 uc_rsv[1];
} mac_h2d_user_asoc_state_stru;

typedef struct {
    oal_uint32 ul_large_queue_th;
    oal_uint32 ul_small_queue_th;
} mac_h2d_dscr_th_stru;

typedef struct {
    oal_uint16 us_user_idx;
    oal_bool_enum_uint8 en_txbf_enable;
} mac_h2d_txbf_ability_stru;

typedef struct {
    oal_uint8 auc_addr[WLAN_MAC_ADDR_LEN];
    oal_uint8 auc_pmkid[WLAN_PMKID_LEN];
    oal_uint8 auc_resv0[2];
} mac_pmkid_info_stu;

typedef struct {
    oal_uint8 uc_num_elems;
    oal_uint8 auc_resv0[3];
    mac_pmkid_info_stu ast_elem[WLAN_PMKID_CACHE_SIZE];
} mac_pmkid_cache_stru;

#ifdef _PRE_WLAN_FEATURE_AUTO_FREQ
enum {
    FREQ_SET_MODE = 0,
    /* sync ini data */
    FREQ_SYNC_DATA = 1,
    /* for device debug */
    FREQ_SET_FREQ = 2,
    FREQ_GET_FREQ = 4,
    FREQ_SET_BUTT
};
typedef oal_uint8 oal_freq_sync_enum_uint8;

typedef struct {
    oal_uint32 ul_speed_level;    /* ?????????? */
    oal_uint32 ul_cpu_freq_level; /* CPU????level */
} device_level_stru;

typedef struct {
    oal_uint8 uc_set_type;
    oal_uint8 uc_set_freq;
    oal_uint8 uc_device_freq_enable;
    oal_uint8 uc_resv;
    device_level_stru st_device_data[4];
} config_device_freq_h2d_stru;
#endif

#ifdef _PRE_WLAN_FEATURE_TXBF
typedef struct {
    oal_uint8 bit_imbf_receive_cap : 1, /* ????TxBf???????? */
              bit_exp_comp_txbf_cap : 1,      /* ????????????????TxBf?????? */
              bit_min_grouping : 2,           /* 0=????????1=1,2??????2=1,4??????3=1,2,4???? */
              bit_csi_bfee_max_rows : 2,      /* bfer??????????bfee??CSI?????????????????? */
              bit_channel_est_cap : 2;        /* ????????????????0=1???????????????? */
    oal_uint8 auc_resv0[3];
} mac_vap_txbf_add_stru;
#endif

typedef struct {
    /* word 0 */
    wlan_prot_mode_enum_uint8 en_protection_mode; /* ???????? */
    oal_uint8 uc_obss_non_erp_aging_cnt;          /* ????OBSS??non erp ?????????????? */
    oal_uint8 uc_obss_non_ht_aging_cnt;           /* ????OBSS??non ht ?????????????? */
    /* ??????????????????????OAL_SWITCH_ON ?????? OAL_SWITCH_OFF ???? */
    oal_uint8 bit_auto_protection : 1;
    oal_uint8 bit_obss_non_erp_present : 1; /* ????obss??????????non ERP?????? */
    oal_uint8 bit_obss_non_ht_present : 1;  /* ????obss??????????non HT?????? */
    /* ??rts_cts ????????????????, OAL_SWITCH_ON ?????? OAL_SWITCH_OFF ???? */
    oal_uint8 bit_rts_cts_protect_mode : 1;
    /* ????L-SIG protect????????, OAL_SWITCH_ON ?????? OAL_SWITCH_OFF ???? */
    oal_uint8 bit_lsig_txop_protect_mode : 1;
    oal_uint8 bit_reserved : 3;

    /* word 1 */
    oal_uint8 uc_sta_no_short_slot_num;     /* ??????short slot??STA???? */
    oal_uint8 uc_sta_no_short_preamble_num; /* ??????short preamble??STA???? */
    oal_uint8 uc_sta_non_erp_num;           /* ??????ERP??STA???? */
    oal_uint8 uc_sta_non_ht_num;            /* ??????HT??STA???? */
    /* word 2 */
    oal_uint8 uc_sta_non_gf_num;        /* ????ERP/HT,??????GF??STA???? */
    oal_uint8 uc_sta_20M_only_num;      /* ??????20M ??????STA???? */
    oal_uint8 uc_sta_no_40dsss_cck_num; /* ????40M DSSS-CCK STA???? */
    oal_uint8 uc_sta_no_lsig_txop_num;  /* ??????L-SIG TXOP Protection STA???? */
} mac_protection_stru;

/* ?????????????????????? */
typedef struct {
    oal_uint32 ul_sync_mask;

    mac_user_cap_info_stru st_user_cap_info;
    oal_uint16 us_user_idx;
    oal_uint8 auc_resv[2];

    wlan_mib_ht_protection_enum_uint8 en_dot11HTProtection;
    oal_bool_enum_uint8 en_dot11RIFSMode;
    oal_bool_enum_uint8 en_dot11LSIGTXOPFullProtectionActivated;
    oal_bool_enum_uint8 en_dot11NonGFEntitiesPresent;

    mac_protection_stru st_protection;
} mac_h2d_protection_stru;

typedef struct {
    oal_uint8 *puc_ie;        /* APP ???????? */
    oal_uint32 ul_ie_len;     /* APP ???????????? */
    oal_uint32 ul_ie_max_len; /* APP ???????????????? */
} mac_app_ie_stru;

/* ???????? ????cfgid: WLAN_CFGID_MODE */
typedef struct {
    wlan_protocol_enum_uint8 en_protocol;           /* ???? */
    wlan_channel_band_enum_uint8 en_band;           /* ???? */
    wlan_channel_bandwidth_enum_uint8 en_bandwidth; /* ???? */
    oal_uint8 en_channel_idx;                       /* ??20M?????? */
} mac_cfg_mode_param_stru;

typedef struct {
    oal_uint32 ul_queue_id;
    oal_uint32 ul_start_th;
    oal_uint32 ul_interval;
} mac_cfg_dscr_th_stru;

typedef struct {
    oal_uint32 ul_switch;
} mac_cfg_tcp_ack_filter;

#ifdef _PRE_WLAN_DFT_STAT
typedef oam_stats_vap_stat_stru mac_vap_dft_stats_stru;

typedef struct {
    mac_vap_dft_stats_stru *pst_vap_dft_stats;
    frw_timeout_stru st_vap_dft_timer;
    oal_uint32 ul_flg; /* ???????????? */
} mac_vap_dft_stru;
#endif

typedef struct {
    oal_uint8 flags;
    oal_uint8 mcs;
    oal_uint16 legacy;
    oal_uint8 nss;
    oal_uint8 bw;
    oal_bool_enum_uint8 en_co_intf_state : 1;
    oal_uint8 rsv1 : 7;
    oal_uint8 rsv2[2];
} mac_rate_info_stru;

typedef enum mac_rate_info_flags {
    MAC_RATE_INFO_FLAGS_MCS = BIT(0),
    MAC_RATE_INFO_FLAGS_VHT_MCS = BIT(1),
    MAC_RATE_INFO_FLAGS_40_MHZ_WIDTH = BIT(2),
    MAC_RATE_INFO_FLAGS_80_MHZ_WIDTH = BIT(3),
    MAC_RATE_INFO_FLAGS_80P80_MHZ_WIDTH = BIT(4),
    MAC_RATE_INFO_FLAGS_160_MHZ_WIDTH = BIT(5),
    MAC_RATE_INFO_FLAGS_SHORT_GI = BIT(6),
    MAC_RATE_INFO_FLAGS_60G = BIT(7),
} mac_rate_info_flags;

#ifdef _PRE_WLAN_FEATURE_STA_PM
/* STA UAPSD ???????? */
typedef struct {
    oal_uint8 uc_max_sp_len;
    oal_uint8 uc_delivery_enabled[WLAN_WME_AC_BUTT];
    oal_uint8 uc_trigger_enabled[WLAN_WME_AC_BUTT];
} mac_cfg_uapsd_sta_stru;

/* Power save modes specified by the user */
typedef enum {
    NO_POWERSAVE = 0,
    MIN_FAST_PS = 1,
    MAX_FAST_PS = 2,
    MIN_PSPOLL_PS = 3,
    MAX_PSPOLL_PS = 4,
    NUM_PS_MODE = 5
} ps_user_mode_enum;

#endif

typedef struct {
    oal_uint32 ul_nbfh_tbtt_offset;
    oal_uint32 ul_nbfh_tbtt_sync_time;
    oal_uint32 ul_nbfh_dwell_time;
    oal_uint32 ul_nbfh_beacon_time;
} mac_cfg_nbfh_param_stru;

#ifdef _PRE_WLAN_FEATURE_TXOPPS
/* STA txopps aid???? */
typedef struct {
    oal_uint16 us_partial_aid;
    oal_uint8 en_protocol;
    oal_uint8 uc_resv;
} mac_cfg_txop_sta_stru;
#endif

#ifdef _PRE_WLAN_FEATURE_VOWIFI
/* vowifi???????????????????????? */
typedef enum {
    VOWIFI_SET_MODE = 0,
    VOWIFI_GET_MODE,
    VOWIFI_SET_PERIOD,
    VOWIFI_GET_PERIOD,
    VOWIFI_SET_LOW_THRESHOLD,
    VOWIFI_GET_LOW_THRESHOLD,
    VOWIFI_SET_HIGH_THRESHOLD,
    VOWIFI_GET_HIGH_THRESHOLD,
    VOWIFI_SET_TRIGGER_COUNT,
    VOWIFI_GET_TRIGGER_COUNT,
    VOWIFI_SET_IS_SUPPORT,

    VOWIFI_CMD_BUTT
} mac_vowifi_cmd_enum;
typedef oal_uint8 mac_vowifi_cmd_enum_uint8;

/* vowifi?????????????????????????? */
typedef struct {
    mac_vowifi_cmd_enum_uint8 en_vowifi_cfg_cmd; /* ???????? */
    oal_uint8 uc_value;                          /* ?????? */
    oal_uint8 auc_resv[2];
} mac_cfg_vowifi_stru;

/* VoWiFi???????????? ?? ?????????????? */
typedef enum {
    VOWIFI_DISABLE_REPORT = 0,
    VOWIFI_LOW_THRES_REPORT,
    VOWIFI_HIGH_THRES_REPORT,
    VOWIFI_CLOSE_REPORT = 3, /* ????VoWIFI */

    VOWIFI_MODE_BUTT = 3
} mac_vowifi_mode;
typedef oal_uint8 mac_vowifi_mode_enum_uint8;

typedef struct {
    /* MODE
    0: disable report of rssi change
    1: enable report when rssi lower than threshold(vowifi_low_thres)
    2: enable report when rssi higher than threshold(vowifi_high_thres)
 */
    mac_vowifi_mode_enum_uint8 en_vowifi_mode;
    /* ??1??100??, the continuous counters of lower or higher than threshold which will trigger the report to host */
    oal_uint8 uc_trigger_count_thres;
    oal_int8 c_rssi_low_thres;  /* [-1, -100],vowifi_low_thres */
    oal_int8 c_rssi_high_thres; /* [-1, -100],vowifi_high_thres */
    /* ????ms, ??????1s??30s??, the period of monitor the RSSI when host suspended */
    oal_uint16 us_rssi_period_ms;

    oal_bool_enum_uint8 en_vowifi_reported; /* ????vowifi??????????????"????????????"?????????????? */
    /* ??????????????vowifi??????????????????????????????????????????????????????????????????vowifi???????????????? */
    oal_uint8 uc_cfg_cmd_cnt;

    /* ROM???????????????? */
    oal_void *_rom;
} mac_vowifi_param_stru;

#endif /* _PRE_WLAN_FEATURE_VOWIFI */

#define MAC_VAP_INVAILD 0x0 /* 0??vap???? */
#define MAC_VAP_VAILD   0x2b

#ifdef _PRE_WLAN_NARROW_BAND
typedef struct {
    oal_bool_enum_uint8 en_open;    /* ?????????????? */
    mac_narrow_bw_enum_uint8 en_bw; /* 1M,5M,10M */
    oal_uint8 uc_chn_extend;        /* ????????idx??????????????2?? */
    oal_uint8 uc_rsv;
} mac_cfg_narrow_bw_stru;

typedef struct {
    oal_bool_enum_uint8 en_enable; /* ????or???? */
    oal_uint16 us_work_time_ms;    /* idle???? ????ms */
    oal_uint16 us_listen_time_ms;  /* ???????? ????ms */
} mac_cfg_hitalk_listen_stru;

#endif

typedef struct {
    oal_bool_enum_uint8 en_wfd_status;
    oal_bool_enum_uint8 en_aggr_limit_on;
    oal_uint8 uc_rsv1;
    oal_uint8 uc_rsv2;
} wfd_status_aggr_limit_stru;

typedef struct {
    oal_bool_enum_uint8 en_wfd_status;
    oal_bool_enum_uint8 en_aggr_limit_on;
    oal_uint16 us_tx_pkts;
    uint8_t ch_switch_fail; /* ?????????? */
    uint8_t resv[3];
} mac_vap_rom_stru;

/* VAP?????????? */
typedef struct {
    /* VAP??AP????STA???????? */
    /* word0~word1 */
    oal_uint8 uc_vap_id; /* vap ID */ /* ?????????????? */
    oal_uint8 uc_device_id;                 /* ????ID */
    oal_uint8 uc_chip_id;                   /* chip ID */
    wlan_vap_mode_enum_uint8 en_vap_mode;   /* vap???? */
    oal_uint32 ul_core_id;

    /* word2~word3 */
    /* BSSID????MAC??????MAC??????mib????auc_dot11StationID */
    oal_uint8 auc_bssid[WLAN_MAC_ADDR_LEN];
    mac_vap_state_enum_uint8 en_vap_state; /* VAP???? */
    wlan_protocol_enum_uint8 en_protocol;  /* ?????????????? */

    /* word4~word5 */
    mac_channel_stru st_channel; /* vap?????????? */
    mac_ch_switch_info_stru st_ch_switch_info;

    /* word6 */
    oal_uint8 bit_has_user_bw_limit : 1; /* ??vap????????user???? */
    oal_uint8 bit_vap_bw_limit : 1;      /* ??vap?????????? */
    oal_uint8 bit_voice_aggr : 1;        /* ??vap????????VO???????????? */
    oal_uint8 bit_one_tx_tcp_be : 1;     /* ??vap????????1??????TCP BE???? */
    oal_uint8 bit_resv : 4;

    oal_uint8 uc_tx_power;            /* ????????, ????dBm */
    oal_uint8 uc_channel_utilization; /* ?????????????? */
    /* ??????0??AP??????????????????wmm??????????????1,??beacon????assoc rsp????????
       4bit??????????15??STA???????????????????????? */
    oal_uint8 uc_wmm_params_update_count;

    /* word7 */
    oal_uint16 us_user_nums;                                        /* VAP?????????????????? */
    oal_uint16 us_multi_user_idx;                                   /* ????????ID */
    oal_uint8 auc_cache_user_mac_addr[WLAN_MAC_ADDR_LEN];           /* cache user??????MAC???? */
    oal_uint16 us_cache_user_id;                                    /* cache user??????userID */
    oal_dlist_head_stru ast_user_hash[MAC_VAP_USER_HASH_MAX_VALUE]; /* hash????,????HASH????????DLIST */
    oal_dlist_head_stru st_mac_user_list_head;                      /* ????????????????????,????USER????????DLIST */

    /* word8 */
    wlan_nss_enum_uint8 en_vap_rx_nss; /* vap???????????????? */

    /* vap????????????????VAP??????????????,
      DMAC OFFLOAD????VAP???????????????????? */
    oal_uint8 uc_init_flag;
    oal_bool_enum_uint8 en_txbf_enable;         /* host??dmac??????txbf???? */
    mac_txbf_mode_enum_uint8 en_host_txbf_mode; /* host????????txbf????,0?? 1???? 2?????? */

    /* ???????? */
    /* ??????????????4???????? */
    // mac_key_mgmt_stru                   st_key_mgmt;      /*????????????ptk gtk??????????????AP/STA????????????????*/
    mac_cap_flag_stru st_cap_flag; /* vap???????????? */
    wlan_mib_ieee802dot11_stru *pst_mib_info; /* mib????(????????vap??????????????????????NULL??????????) */

    mac_curr_rateset_stru st_curr_sup_rates; /* ???????????????? */
    /* ????sta??????????????????????????????????????ie????2.4??5G */
    mac_curr_rateset_stru ast_sta_sup_rates_ie[WLAN_BAND_BUTT];

#ifdef _PRE_WLAN_DFT_STAT
    /* user ???????? */
    oal_uint32 ul_dlist_cnt; /* dlsit???? */
    oal_uint32 ul_hash_cnt;  /* hash???????? */

#endif

#ifdef _PRE_WLAN_FEATURE_TXBF
    mac_vap_txbf_add_stru st_txbf_add_cap;
#endif

    /* VAP??AP????STA???????? ???????? */
    /* VAP??AP?????????? ???????? */
    mac_protection_stru st_protection; /* ?????????????? */
    mac_app_ie_stru ast_app_ie[OAL_APP_IE_NUM];
    /* VAP??AP?????????? ???????? */
    /* VAP??STA?????????? ???????? */
    /* VAP??STA??????????AP??????STA??AID(????????????),????????1~2007; VAP??AP?????????????????????? */
    oal_uint16 us_sta_aid;
    /* VAP??STA??????????user(ap)??????????????VAP??AP?????????????????????? */
    oal_uint8 uc_assoc_vap_id;
    oal_uint8 uc_wmm_cap; /* ??????STA??????AP????????wmm???????? */

    oal_uint8 uc_uapsd_cap;            /* ??????STA??????AP????????uapsd???????? */
    oal_uint16 us_assoc_user_cap_info; /* sta?????????????????????? */
    oal_uint8 bit_ap_11ntxbf : 1,      /* sta??????????????11n txbf???????? */
              bit_sta_rx_beacon_tsf_sync : 1,
              bit_sta_11v_info : 1, /* sta????????????11v ???????? */
              bit_sta_11k_info : 1, /* sta????????????11k ???????? */
              bit_resv7 : 4;
#ifdef _PRE_WLAN_NARROW_BAND
    mac_cfg_narrow_bw_stru st_nb;
#endif

    /* ???????????? */
    oal_uint8 bit_al_tx_flag : 1;   /* ???????? */
    oal_uint8 bit_payload_flag : 2; /* payload????:0:??0  1:??1  2:random */
    oal_uint8 bit_first_run : 1;    /* ???????????????????? */
    oal_uint8 bit_reserved : 4;

    wlan_p2p_mode_enum_uint8 en_p2p_mode; /* 0:??P2P????; 1:P2P_GO; 2:P2P_Device; 3:P2P_CL */
    oal_uint8 uc_p2p_gocl_hal_vap_id;     /* p2p go / cl??hal vap id */
    oal_uint8 uc_p2p_listen_channel;      /* P2P Listen channel */

#ifdef _PRE_WLAN_FEATURE_STA_PM
    mac_cfg_uapsd_sta_stru st_sta_uapsd_cfg; /* UAPSD?????????? */
#endif

#if (_PRE_WLAN_FEATURE_PMF != _PRE_PMF_NOT_SUPPORT)
    oal_bool_enum_uint8 en_user_pmf_cap; /* STA??????????user????????????user??pmf???????? */
#endif

    oal_spin_lock_stru st_cache_user_lock; /* cache_user lock */
#ifdef _PRE_WLAN_FEATURE_VOWIFI
    mac_vowifi_param_stru *pst_vowifi_cfg_param; /* ??????????"VoWiFi????????????"?????????? */
#endif                                           /* _PRE_WLAN_FEATURE_VOWIFI */

    /* ROM???????????????? */
    oal_void *_rom;
} mac_vap_stru;

/* cfg id??????get set???? */
typedef struct {
    wlan_cfgid_enum_uint16 en_cfgid;
    oal_uint8 auc_resv[2]; /* ???????? */
    oal_uint32 (*p_get_func)(mac_vap_stru *pst_vap, oal_uint8 *puc_len, oal_uint8 *puc_param);
    oal_uint32 (*p_set_func)(mac_vap_stru *pst_vap, oal_uint8 uc_len, oal_uint8 *puc_param);
} mac_cfgid_stru;

/* cfg id???????????????? */
/* ????VAP??????????, ????cfgid: WLAN_CFGID_ADD_VAP */
typedef struct {
    wlan_vap_mode_enum_uint8 en_vap_mode;
    oal_uint8 uc_cfg_vap_indx;
    oal_uint16 us_muti_user_id; /* ????vap ??????muti user index */

    oal_uint8 uc_vap_id;                  /* ??????????vap id */
    wlan_p2p_mode_enum_uint8 en_p2p_mode; /* 0:??P2P????; 1:P2P_GO; 2:P2P_Device; 3:P2P_CL */
#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
    oal_uint8 bit_11ac2g_enable : 1;
    oal_uint8 bit_disable_capab_2ght40 : 1;
    oal_uint8 bit_reserve : 6;
    oal_uint8 auc_resv0[1];
#else
    oal_uint8 auc_resv0[2];
#endif
#ifdef _PRE_WLAN_FEATURE_UAPSD
    oal_uint8 bit_uapsd_enable : 1;
    oal_uint8 bit_reserve1 : 7;
    oal_uint8 auc_resv1[3];
#endif
    oal_net_device_stru *pst_net_dev;
} mac_cfg_add_vap_param_stru;

typedef mac_cfg_add_vap_param_stru mac_cfg_del_vap_param_stru;

/* ????VAP?????????? ????cfgid: WLAN_CFGID_START_VAP */
typedef struct {
    oal_bool_enum_uint8 en_mgmt_rate_init_flag; /* start vap?????????????????????????????? */
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    oal_uint8 uc_protocol;
    oal_uint8 uc_band;
    oal_uint8 uc_bandwidth;
#else
    oal_uint8 auc_resv1[3];
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
    wlan_p2p_mode_enum_uint8 en_p2p_mode;
    oal_uint8 auc_resv2[3];
#endif
    oal_net_device_stru *pst_net_dev; /* ??????????Host(WAL&HMAC)??????Device??(DMAC&ALG&HAL??)?????? */
} mac_cfg_start_vap_param_stru;
typedef mac_cfg_start_vap_param_stru mac_cfg_down_vap_param_stru;

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
/* CFG VAP h2d */
typedef struct {
    oal_net_device_stru *pst_net_dev;
} mac_cfg_vap_h2d_stru;
#endif

/* ????mac???????? ????cfgid: WLAN_CFGID_STATION_ID */
typedef struct {
    oal_uint8 auc_station_id[WLAN_MAC_ADDR_LEN];
    wlan_p2p_mode_enum_uint8 en_p2p_mode;
    oal_uint8 auc_resv[1];
} mac_cfg_staion_id_param_stru;

/* SSID???? ????cfgid: WLAN_CFGID_SSID */
typedef struct {
    oal_uint8 uc_ssid_len;
    oal_uint8 auc_resv[2];
    oal_int8 ac_ssid[WLAN_SSID_MAX_LEN];
} mac_cfg_ssid_param_stru;

/* HOSTAPD ???????????????????????????? */
typedef struct {
    wlan_channel_band_enum_uint8 en_band;           /* ???? */
    wlan_channel_bandwidth_enum_uint8 en_bandwidth; /* ???? */
    oal_uint8 uc_channel;                           /* ???????? */
    oal_uint8 auc_resv[1];                          /* ?????? */
} mac_cfg_channel_param_stru;

/* HOSTAPD ????wiphy ??????????????????RTS ?????????????????????? */
typedef struct {
    oal_uint8 uc_frag_threshold_changed;
    oal_uint8 uc_rts_threshold_changed;
    oal_uint8 uc_rsv[2];
    oal_uint32 ul_frag_threshold;
    oal_uint32 ul_rts_threshold;
} mac_cfg_wiphy_param_stru;

/* HOSTAPD ???? Beacon ???? */
typedef struct {
    oal_int32 l_interval;    /* beacon interval */
    oal_int32 l_dtim_period; /* DTIM period */
    oal_bool_enum_uint8 en_privacy;
    oal_uint8 uc_crypto_mode;                                           /* WPA/WPA2 */
    oal_uint8 uc_group_crypto;                                          /* ???????????? */
    oal_bool_enum_uint8 uc_hidden_ssid;                                 /* ????ssid */
    oal_uint8 auc_auth_type[MAC_AUTHENTICATION_SUITE_NUM];              /* akm ???? */
    oal_uint8 auc_pairwise_crypto_wpa[MAC_PAIRWISE_CIPHER_SUITES_NUM];  /* wpa???????????? */
    oal_uint8 auc_pairwise_crypto_wpa2[MAC_PAIRWISE_CIPHER_SUITES_NUM]; /* rsn???????????? */
    oal_uint8 uc_group_mgmt_cipher;                                     /* ?????????????? */
    oal_uint16 us_rsn_capability;                                       /* rsn???? */

    oal_bool_enum_uint8 en_shortgi_20;
    oal_bool_enum_uint8 en_shortgi_40;
    oal_bool_enum_uint8 en_shortgi_80;
    wlan_protocol_enum_uint8 en_protocol;

    oal_uint8 uc_smps_mode;
    oal_uint8 auc_resv1[3];
} mac_beacon_param_stru;

/* ????log?????????????????????? */
typedef struct {
    oam_module_id_enum_uint16 en_mod_id; /* ??????????id */
    oal_bool_enum_uint8 en_switch;       /* ?????????????? */
    oal_uint8 auc_resv[1];
} mac_cfg_log_module_param_stru;

/* ?????????????????????? */
typedef struct {
    oal_uint8 auc_mac_addr[WLAN_MAC_ADDR_LEN]; /* MAC???? */
    oal_bool_enum_uint8 en_ht_cap;             /* ht???? */
    oal_uint8 auc_resv[3];
    oal_uint16 us_user_idx; /* ???????? */
} mac_cfg_add_user_param_stru;

typedef mac_cfg_add_user_param_stru mac_cfg_del_user_param_stru;

/* ????????FCS???????? */
typedef struct {
    oal_uint32 ul_data_op; /* ????????????:<0>????,<1>???? */
    /* ????????????:<0>???????? <1>?????? <2>self fcs correct, <3>other fcs correct, <4>fcs error */
    oal_uint32 ul_print_info;
} mac_cfg_rx_fcs_info_stru;

/* ???????????????????? */
typedef struct {
    oal_uint8 auc_mac_addr[WLAN_MAC_ADDR_LEN]; /* MAC???? */
    oal_uint16 us_reason_code;                 /* ?????? reason code */
} mac_cfg_kick_user_param_stru;

/* ????tid???????????? */
typedef struct {
    oal_uint8 auc_mac_addr[WLAN_MAC_ADDR_LEN]; /* MAC???? */
    oal_uint8 uc_tid;
    oal_uint8 uc_is_paused;
} mac_cfg_pause_tid_param_stru;

#ifdef _PRE_WLAN_FEATURE_TCP_ACK_BUFFER
typedef struct {
    mac_tcp_ack_buf_cfg_cmd_enum_uint8 en_cmd;
    oal_bool_enum_uint8 en_enable;
    oal_uint8 uc_timeout_ms;
    oal_uint8 uc_count_limit;
} mac_cfg_tcp_ack_buf_stru;
#endif

typedef struct {
    mac_ps_params_cfg_cmd_enum_uint8 en_cmd;
    oal_uint8 uc_timeout_ms;
    oal_uint8 uc_restart_count;
} mac_cfg_ps_params_stru;

typedef enum mac_vowifi_mkeep_alive_type {
    VOWIFI_MKEEP_ALIVE_TYPE_STOP = 0,
    VOWIFI_MKEEP_ALIVE_TYPE_START = 1,
    VOWIFI_MKEEP_ALIVE_TYPE_BUTT
} mac_vowifi_nat_keep_alive_type_enum;
typedef oal_uint8 mac_vowifi_nat_keep_alive_type_enum_uint8;

typedef struct {
    oal_uint8 uc_keep_alive_id;
    mac_vowifi_nat_keep_alive_type_enum_uint8 en_type;
    oal_uint8 auc_rsv[2];
} mac_vowifi_nat_keep_alive_basic_info_stru;

typedef struct {
    mac_vowifi_nat_keep_alive_basic_info_stru st_basic_info;
    oal_uint8 auc_src_mac[WLAN_MAC_ADDR_LEN];
    oal_uint8 auc_dst_mac[WLAN_MAC_ADDR_LEN];
    oal_uint32 ul_period_msec;
    oal_uint16 us_ip_pkt_len;
    oal_uint8 auc_rsv[2];
    oal_uint8 auc_ip_pkt_data[4];
} mac_vowifi_nat_keep_alive_start_info_stru;

/* ??????????????vip */
typedef struct {
    oal_uint8 auc_mac_addr[WLAN_MAC_ADDR_LEN]; /* MAC???? */
    oal_uint8 uc_vip_flag;
} mac_cfg_user_vip_param_stru;

/* ????tid???????????? */
typedef struct {
    oal_uint8 uc_aggr_tx_on;
    oal_uint8 uc_tid;
    oal_uint16 us_packet_len;
} mac_cfg_ampdu_tx_on_param_stru;

/* ????host????????????????????????????low_waterline, high_waterline */
typedef struct {
    oal_uint8 uc_queue_type;
    oal_uint8 auc_resv[1];
    oal_uint16 us_burst_limit;
    oal_uint16 us_low_waterline;
    oal_uint16 us_high_waterline;
} mac_cfg_flowctl_param_stru;

/* ????qempty???? */
typedef struct {
    oal_uint8 uc_is_on;
    oal_uint8 auc_resv[3];
} mac_cfg_resume_qempty_stru;

typedef struct {
    oal_uint8 uc_packet_num;
} mac_cfg_packet_check_param_stru;

/* ????mpdu/ampdu???????? */
typedef struct {
    oal_uint8 uc_tid;
    oal_uint8 uc_packet_num;
    oal_uint16 us_packet_len;
    oal_uint8 auc_ra_mac[OAL_MAC_ADDR_LEN];
} mac_cfg_mpdu_ampdu_tx_param_stru;
/* AMPDU?????????????????? */
typedef struct {
    oal_uint8 auc_mac_addr[WLAN_MAC_ADDR_LEN]; /* ??????MAC ADDR */
    oal_uint8 uc_tidno;                        /* ??????tid?? */
    oal_uint8 auc_reserve[1];                  /* ???????? */
} mac_cfg_ampdu_start_param_stru;

typedef mac_cfg_ampdu_start_param_stru mac_cfg_ampdu_end_param_stru;

/* BA?????????????????????? */
typedef struct {
    oal_uint8 auc_mac_addr[WLAN_MAC_ADDR_LEN]; /* ??????MAC ADDR */
    oal_uint8 uc_tidno;                        /* ??????tid?? */
    mac_ba_policy_enum_uint8 en_ba_policy;     /* BA???????? */
    oal_uint16 us_buff_size;                   /* BA?????????? */
    oal_uint16 us_timeout;                     /* BA?????????????? */
} mac_cfg_addba_req_param_stru;

typedef struct {
    oal_uint8 auc_mac_addr[WLAN_MAC_ADDR_LEN];   /* ??????MAC ADDR */
    oal_uint8 uc_tidno;                          /* ??????tid?? */
    mac_delba_initiator_enum_uint8 en_direction; /* ????ba???????????? */
    oal_uint8 auc_reserve[1];                    /* ???????? */
} mac_cfg_delba_req_param_stru;

#ifdef _PRE_WLAN_FEATURE_CSI
typedef struct {
    oal_bool_enum_uint8 en_csi;                /* csi???? */
    oal_bool_enum_uint8 en_ta_check;           /* ????CSI??????check ta */
    oal_bool_enum_uint8 en_ftm_check;          /* ????CSI??????check ftm */
    oal_uint8 auc_mac_addr[WLAN_MAC_ADDR_LEN]; /* csi??????MAC ADDR */
    oal_uint8 auc_resv[3];
} mac_cfg_csi_param_stru;
#endif

#ifdef _PRE_WLAN_FEATURE_WMMAC
/* TSPEC?????????????????? */
typedef struct {
    mac_ts_info_stru ts_info;
    oal_uint8 uc_rsvd;
    oal_uint16 us_norminal_msdu_size;
    oal_uint16 us_max_msdu_size;
    oal_uint32 ul_min_data_rate;
    oal_uint32 ul_mean_data_rate;
    oal_uint32 ul_peak_data_rate;
    oal_uint32 ul_min_phy_rate;
    oal_uint16 us_surplus_bw;
    oal_uint16 us_medium_time;
} mac_cfg_wmm_tspec_stru_param_stru;

typedef struct {
    oal_switch_enum_uint8 en_wmm_ac_switch;
    oal_switch_enum_uint8 en_auth_flag;     /* WMM AC???????? */
    wlan_wme_ac_type_enum_uint8 en_ac_type; /* ac?? */
    oal_uint8 auc_rsv[1];
    oal_uint32 ul_limit_time; /* ????medium time,????:32 us */
} mac_cfg_wmm_ac_param_stru;
#endif

/* ???????????????????? */
typedef struct {
    mac_set_pow_type_enum_uint8 en_type;
    oal_uint8 uc_reserve;
    oal_uint8 auc_value[18];
} mac_cfg_set_tx_pow_param_stru;

typedef struct {
    oal_uint8 auc_mac_addr[6];
    oal_uint8 uc_amsdu_max_num; /* amsdu???????? */
    oal_uint8 auc_reserve[3];
    oal_uint16 us_amsdu_max_size; /* amsdu???????? */
} mac_cfg_amsdu_start_param_stru;

/* ???????????????? */
typedef struct {
    oal_uint8 uc_function_index;
    oal_uint8 auc_reserve[2];
    mac_vap_config_dscr_frame_type_uint8 en_type; /* ???????????? */
    oal_int32 l_value;
} mac_cfg_set_dscr_param_stru;

typedef struct {
    mac_vap_stru *pst_mac_vap;
    oal_int8 pc_param[4]; /* ?????????????? */
} mac_cfg_event_stru;

/* non-HT???????????????????????? */
typedef struct {
    wlan_legacy_rate_value_enum_uint8 en_rate;     /* ?????? */
    wlan_phy_protocol_enum_uint8 en_protocol_mode; /* ?????????? */
    oal_uint8 auc_reserve[2];                      /* ???? */
} mac_cfg_non_ht_rate_stru;

/* ???????????????????????????? */
typedef enum {
    RF_PAYLOAD_ALL_ZERO = 0,
    RF_PAYLOAD_ALL_ONE,
    RF_PAYLOAD_RAND,
    RF_PAYLOAD_BUTT
} mac_rf_payload_enum;
typedef oal_uint8 mac_rf_payload_enum_uint8;

typedef struct {
    oal_uint8 uc_param; /* ?????????????? */
    wlan_phy_protocol_enum_uint8 en_protocol_mode;
    mac_rf_payload_enum_uint8 en_payload_flag;
    wlan_tx_ack_policy_enum_uint8 en_ack_policy;
    oal_uint32 ul_payload_len;
} mac_cfg_tx_comp_stru;

typedef struct {
    oal_uint8 uc_offset_addr_a;
    oal_uint8 uc_offset_addr_b;
    oal_uint16 us_delta_gain;
} mac_cfg_dbb_scaling_stru;

/* ???????????????? */
typedef struct {
    oal_uint16 us_idx;         /* ?????????????? */
    oal_uint16 us_chn;         /* ???????? */
    oal_int16 as_corr_data[8]; /* ???????? */
} mac_cfg_freq_skew_stru;

/* wfa edca???????? */
typedef struct {
    oal_bool_enum_uint8 en_switch;     /* ???? */
    wlan_wme_ac_type_enum_uint8 en_ac; /* AC */
    oal_uint16 us_val;                 /* ???? */
} mac_edca_cfg_stru;

/* PPM???????????? */
typedef struct {
    oal_int8 c_ppm_val;      /* PPM???? */
    oal_uint8 uc_clock_freq; /* ???????? */
    oal_uint8 uc_resv[1];
} mac_cfg_adjust_ppm_stru;

typedef struct {
    oal_uint8 uc_pcie_pm_level; /* pcie??????????,0->normal;1->L0S;2->L1;3->L1PM;4->L1s */
    oal_uint8 uc_resv[3];
} mac_cfg_pcie_pm_level_stru;

/* ?????????????????????????? */
typedef struct {
    oal_uint16 us_user_idx; /* ???????? */
    oal_uint8 auc_reserve[2];
} mac_cfg_user_info_param_stru;

/* ???????????????????? */
typedef struct {
    oal_void *p_mac_regdom;
} mac_cfg_country_stru;

/* ?????????????????????? */
typedef struct {
    oal_uint8 uc_pwr;
    oal_uint8 en_exceed_reg;
    oal_uint8 auc_resv[2];
} mac_cfg_regdomain_max_pwr_stru;

/* ?????????????????????????????????????? */
typedef struct {
    oal_int8 ac_country[3];
    oal_uint8 auc_resv[1];
} mac_cfg_get_country_stru;

/* query????????:2????WID x N */
typedef struct {
    wlan_tidno_enum_uint8 en_tid;
    oal_uint8 uc_resv[3];
} mac_cfg_get_tid_stru;

typedef struct {
    oal_uint16 us_user_id;
    oal_int8 c_rssi;
    oal_uint8 auc_resv[1];
} mac_cfg_query_rssi_stru;

#ifdef _PRE_WLAN_DFT_STAT
typedef struct {
    oal_uint8 uc_device_distance;
    oal_uint8 uc_intf_state_cca;
    oal_uint8 uc_intf_state_co;
    oal_uint8 auc_resv[1];
} mac_cfg_query_ani_stru;
#endif

typedef struct {
    oal_uint16 us_user_id;
#ifdef _PRE_WLAN_DFT_STAT
    oal_uint8 uc_cur_per;
    oal_uint8 uc_bestrate_per;
#else
    oal_uint8 auc_resv[2];
#endif
    oal_uint32 ul_tx_rate;     /* ???????????? */
    oal_uint32 ul_tx_rate_min; /* ?????????????????????? */
    oal_uint32 ul_tx_rate_max; /* ?????????????????????? */
    oal_uint32 ul_rx_rate;     /* ???????????? */
    oal_uint32 ul_rx_rate_min; /* ?????????????????????? */
    oal_uint32 ul_rx_rate_max; /* ?????????????????????? */
} mac_cfg_query_rate_stru;

/* ???????????????????????????????????????????????????? */
/* ?????????????????????????????????????????????? */
typedef struct {
    oal_ssids_stru st_ssids[WLAN_SCAN_REQ_MAX_SSID];
    oal_int32 l_ssid_num;

    oal_uint8 *puc_ie;
    oal_uint32 ul_ie_len;

    oal_scan_enum_uint8 en_scan_type;
    oal_uint8 uc_num_channels_2G;
    oal_uint8 uc_num_channels_5G;
    oal_uint8 auc_arry[1];

    oal_uint32 *pul_channels_2G;
    oal_uint32 *pul_channels_5G;

    /* WLAN/P2P ????????????p2p0 ??p2p-p2p0 cl ????????????????????????????????bit_is_p2p0_scan?????? */
    oal_uint8 bit_is_p2p0_scan : 1; /* ??????p2p0 ???????? */
    oal_uint8 bit_rsv : 7;          /* ?????? */
    oal_uint8 auc_rsv[3];           /* ?????? */
} mac_cfg80211_scan_param_stru;

typedef struct {
    mac_cfg80211_scan_param_stru *pst_mac_cfg80211_scan_param;
} mac_cfg80211_scan_param_pst_stru;

/* ??????????????connect????????????????????connect???? */
typedef struct {
    oal_uint8 wpa_versions;
    oal_uint8 cipher_group;
    oal_uint8 uc_group_mgmt_suite;
    oal_uint8 n_ciphers_pairwise;
    oal_uint8 ciphers_pairwise[OAL_NL80211_MAX_NR_CIPHER_SUITES];
    oal_uint8 n_akm_suites;
    oal_uint8 akm_suites[OAL_NL80211_MAX_NR_AKM_SUITES];

    oal_bool_enum_uint8 control_port;
} mac_cfg80211_crypto_settings_stru;

/**
 * enum nl80211_mfp - Management frame protection state
 * @NL80211_MFP_NO: Management frame protection not used
 * @NL80211_MFP_REQUIRED: Management frame protection required
 */
typedef enum {
    MAC_NL80211_MFP_NO,
    MAC_NL80211_MFP_REQUIRED,

    MAC_NL80211_MFP_BUTT
} mac_nl80211_mfp_enum;
typedef oal_uint8 mac_nl80211_mfp_enum_uint8;

typedef struct {
    oal_uint8 uc_channel;  /* ap??????????????eg 1,2,11,36,40... */
    oal_uint8 uc_ssid_len; /* SSID ???? */
    mac_nl80211_mfp_enum_uint8 en_mfp;
    oal_uint8 uc_wapi;

    oal_uint8 *puc_ie;
    oal_uint8 auc_ssid[WLAN_SSID_MAX_LEN];  /* ??????????AP SSID */
    oal_uint8 auc_bssid[WLAN_MAC_ADDR_LEN]; /* ??????????AP BSSID */
    oal_uint8 auc_rsv[1];

    oal_bool_enum_uint8 en_privacy;                /* ???????????? */
    oal_nl80211_auth_type_enum_uint8 en_auth_type; /* ??????????OPEN or SHARE-KEY */

    oal_uint8 uc_wep_key_len;   /* WEP KEY???? */
    oal_uint8 uc_wep_key_index; /* WEP KEY???? */
    oal_uint8 *puc_wep_key;     /* WEP KEY???? */

    mac_cfg80211_crypto_settings_stru st_crypto; /* ???????????? */
    oal_uint32 ul_ie_len;
} mac_cfg80211_connect_param_stru;

typedef struct {
    oal_bool_enum_uint8 en_privacy;                /* ???????????? */
    oal_nl80211_auth_type_enum_uint8 en_auth_type; /* ??????????OPEN or SHARE-KEY */
    oal_uint8 uc_wep_key_len;                      /* WEP KEY???? */
    oal_uint8 uc_wep_key_index;                    /* WEP KEY???? */
    oal_uint8 auc_wep_key[WLAN_WEP104_KEY_LEN];    /* WEP KEY???? */
    mac_nl80211_mfp_enum_uint8 en_mgmt_proteced;   /* ????????pmf???????? */
    wlan_pmf_cap_status_uint8 en_pmf_cap;          /* ????pmf???? */
    oal_bool_enum_uint8 en_wps_enable;

    mac_cfg80211_crypto_settings_stru st_crypto; /* ???????????? */
#ifdef _PRE_WLAN_FEATURE_11R
    oal_uint8 auc_mde[8]; /* MD IE???? */
#endif                    // _PRE_WLAN_FEATURE_11R
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    oal_int8 c_rssi;                              /* ????AP??RSSI???? */
    oal_bool_enum_uint8 en_ap_support_triple_nss; /* ????AP??????????>=3, ????Device DDC???????????? */
    oal_uint8 auc_rsv[2];
#endif /* _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE */
} mac_cfg80211_connect_security_stru;

#ifdef _PRE_WLAN_FEATURE_11R
#define MAC_MAX_FTE_LEN 257

typedef struct {
    oal_uint16 us_mdid; /* Mobile Domain ID */
    oal_uint16 us_len;  /* FTE ?????? */
    oal_uint8 auc_ie[MAC_MAX_FTE_LEN];
} mac_cfg80211_ft_ies_stru;

typedef struct {
    oal_cfg80211_bss_stru *pst_bss;
    const oal_uint8 *puc_ie;
    oal_uint8 uc_ie_len;
    oal_nl80211_auth_type_enum_uint8 en_auth_type;
    const oal_uint8 *puc_key;
    oal_uint8 uc_key_len;
    oal_uint8 uc_key_idx;
} mac_cfg80211_auth_req_stru;

#endif  // _PRE_WLAN_FEATURE_11R

typedef struct {
    oal_uint8 auc_mac_addr[OAL_MAC_ADDR_LEN];
    oal_uint8 auc_rsv[2];
} mac_cfg80211_init_port_stru;

/* ??????????????disconnect????????????????????disconnect???? */
typedef struct mac_cfg80211_disconnect_param_tag {
    oal_uint16 us_reason_code; /* disconnect reason code */
    oal_uint16 us_aid;

    oal_uint8 uc_type;
    oal_uint8 auc_arry[3];
} mac_cfg80211_disconnect_param_stru;

typedef struct {
    oal_uint8 auc_mac_da[WLAN_MAC_ADDR_LEN];
    oal_uint8 uc_category;
    oal_uint8 auc_resv[1];
} mac_cfg_send_action_param_stru;

typedef struct {
    oal_int32 l_is_psm; /* ???????????? */
    oal_int32 l_is_qos; /* ??????qosnull */
    oal_int32 l_tidno;  /* tid?? */
} mac_cfg_tx_nulldata_stru;

/* ???????????????????????? */
typedef struct {
    oam_ota_frame_direction_type_enum_uint8 en_frame_direction;
    oal_switch_enum_uint8 en_switch;
    oal_uint8 auc_user_macaddr[WLAN_MAC_ADDR_LEN];
} mac_cfg_eth_switch_param_stru;

/* ????80211???????????????????? */
typedef struct {
    oam_ota_frame_direction_type_enum_uint8 en_frame_direction;
    oam_user_track_frame_type_enum_uint8 en_frame_type;
    oal_switch_enum_uint8 en_frame_switch;
    oal_switch_enum_uint8 en_cb_switch;
    oal_switch_enum_uint8 en_dscr_switch;
    oal_uint8 auc_resv[1];
    oal_uint8 auc_user_macaddr[WLAN_MAC_ADDR_LEN];
} mac_cfg_80211_ucast_switch_stru;
#ifdef _PRE_DEBUG_MODE_USER_TRACK
/* ?????????????????????????????????? */
typedef struct {
    oal_uint8 auc_user_macaddr[WLAN_MAC_ADDR_LEN];
    oam_user_txrx_param_type_enum_uint8 en_type;
    oal_switch_enum_uint8 en_switch;
    oal_uint32 ul_period;
} mac_cfg_report_txrx_param_stru;
#endif
#ifdef _PRE_WLAN_FEATURE_TXOPPS
/* ????????mac txopps???????????????????????? */
typedef struct {
    oal_switch_enum_uint8 en_machw_txopps_en;         /* sta????????txopps */
    oal_switch_enum_uint8 en_machw_txopps_condition1; /* txopps????1 */
    oal_switch_enum_uint8 en_machw_txopps_condition2; /* txopps????2 */
    oal_uint8 auc_resv[1];
} mac_txopps_machw_param_stru;
#endif
/* ????80211????\???????????????????? */
typedef struct {
    oam_ota_frame_direction_type_enum_uint8 en_frame_direction;
    oam_user_track_frame_type_enum_uint8 en_frame_type;
    oal_switch_enum_uint8 en_frame_switch;
    oal_switch_enum_uint8 en_cb_switch;
    oal_switch_enum_uint8 en_dscr_switch;
    oal_uint8 auc_resv[3];
} mac_cfg_80211_mcast_switch_stru;

/* ????probe request??probe response?????????????? */
typedef struct {
    oam_ota_frame_direction_type_enum_uint8 en_frame_direction;
    oal_switch_enum_uint8 en_frame_switch;
    oal_switch_enum_uint8 en_cb_switch;
    oal_switch_enum_uint8 en_dscr_switch;
} mac_cfg_probe_switch_stru;

/* ????mpdu?????????????? */
typedef struct {
    oal_uint8 auc_user_macaddr[WLAN_MAC_ADDR_LEN];
    oal_uint8 auc_resv[2];
} mac_cfg_get_mpdu_num_stru;

typedef struct {
    oal_bool_enum_uint8 en_tpc_disable;
    oal_bool_enum_uint8 en_edca_opt;
    oal_bool_enum_uint8 en_ppdu_sch;
    oal_bool_enum_uint8 en_txop_opt;
    oal_uint8 uc_cwmin;
    oal_uint8 uc_cwmax;
    oal_uint16 us_txoplimit;
    oal_uint16 us_dyn_txoplimit;
    oal_uint16 us_resv;
} mac_cfg_tx_opt;

#ifdef _PRE_WLAN_DFT_STAT
typedef struct {
    oal_uint8 auc_user_macaddr[WLAN_MAC_ADDR_LEN];
    oal_uint8 uc_param;
    oal_uint8 uc_resv;
} mac_cfg_usr_queue_param_stru;
#endif

#ifdef _PRE_DEBUG_MODE
typedef struct {
    oal_uint8 auc_user_macaddr[WLAN_MAC_ADDR_LEN];
    oal_uint8 uc_param;
    oal_uint8 uc_tid_no;
} mac_cfg_ampdu_stat_stru;
#endif

typedef struct {
    oal_uint8 uc_aggr_num_switch; /* ???????????????? */
    oal_uint8 uc_aggr_num;        /* ???????? */
    oal_uint8 auc_resv[2];
} mac_cfg_aggr_num_stru;

#ifdef _PRE_DEBUG_MODE_USER_TRACK
typedef struct {
    oal_uint8 auc_user_macaddr[WLAN_MAC_ADDR_LEN];
    oal_uint8 uc_param;
    oal_uint8 uc_resv;
} mac_cfg_usr_thrput_stru;

#endif

typedef struct {
    oal_uint32 ul_coext_info;
    oal_uint32 ul_channel_report;
} mac_cfg_set_2040_coexist_stru;

typedef struct {
    oal_uint32 ul_mib_idx;
    oal_uint32 ul_mib_value;
} mac_cfg_set_mib_stru;

typedef struct {
    oal_uint8 uc_bypass_type;
    oal_uint8 uc_value;
    oal_uint8 auc_resv[2];
} mac_cfg_set_thruput_bypass_stru;

#ifdef _PRE_WLAN_FEATURE_AUTO_FREQ
typedef struct {
    oal_uint8 uc_cmd_type;
    oal_uint8 uc_value;
    oal_uint8 auc_resv[2];
} mac_cfg_set_auto_freq_stru;
#endif
typedef struct {
    oal_uint8 uc_performance_log_switch_type;
    oal_uint8 uc_value;
    oal_uint8 auc_resv[2];
} mac_cfg_set_performance_log_switch_stru;

#ifdef _PRE_WLAN_FEATURE_ROAM
typedef struct {
    roam_channel_org_enum_uint8 en_scan_type;
    oal_bool_enum_uint8 en_current_bss_ignore;
    oal_uint8 auc_bssid[OAL_MAC_ADDR_LEN];
} mac_cfg_set_roam_start_stru;
#endif
typedef struct {
    oal_uint8 uc_thread_id;
    oal_uint8 uc_thread_mask;
    oal_uint8 auc_resv[2];
} mac_cfg_set_bindcpu_stru;
typedef struct {
    oal_bool_enum_uint8 en_napi_weight_adjust;
    oal_uint8 uc_napi_weight;
    oal_uint8 auc_resv[2];
} mac_cfg_set_napi_weight_stru;
typedef struct {
    oal_uint32 ul_timeout;
    oal_uint8 uc_is_period;
    oal_uint8 uc_stop_start;
    oal_uint8 auc_resv[2];
} mac_cfg_test_timer_stru;

typedef struct {
    oal_uint16 us_user_idx;
    oal_uint16 us_rx_pn;
} mac_cfg_set_rx_pn_stru;

typedef struct {
    oal_uint32 ul_frag_threshold;
} mac_cfg_frag_threshold_stru;

typedef struct {
    oal_uint32 ul_rts_threshold;
} mac_cfg_rts_threshold_stru;

typedef struct {
    /* software_retry?? */
    oal_uint8 uc_software_retry;
    /* ??????test????????????0???????????????? */
    oal_uint8 uc_retry_test;

    oal_uint8 uc_pad[2];
} mac_cfg_set_soft_retry_stru;

typedef struct {
    oal_bool_enum_uint8 en_default_key;
    oal_uint8 uc_key_index;
    oal_uint8 uc_key_len;
    oal_uint8 auc_wep_key[WLAN_WEP104_KEY_LEN];
} mac_wep_key_param_stru;

typedef struct mac_pmksa_tag {
    oal_uint8 auc_bssid[OAL_MAC_ADDR_LEN];
    oal_uint8 auc_pmkid[OAL_PMKID_LEN];
} mac_pmksa_stru;

typedef struct {
    oal_uint8 uc_key_index;
    oal_bool_enum_uint8 en_pairwise;
    oal_uint8 auc_mac_addr[OAL_MAC_ADDR_LEN];
    mac_key_params_stru st_key;
} mac_addkey_param_stru;

typedef struct {
    oal_int32 key_len;
    oal_uint8 auc_key[OAL_WPA_KEY_LEN];
} mac_key_stru;

typedef struct {
    oal_int32 seq_len;
    oal_uint8 auc_seq[OAL_WPA_SEQ_LEN];
} mac_seq_stru;

typedef struct {
    oal_uint8 uc_key_index;
    oal_bool_enum_uint8 en_pairwise;

    oal_uint8 auc_mac_addr[OAL_MAC_ADDR_LEN];

    oal_uint8 cipher;

    oal_uint8 auc_rsv[3];
    mac_key_stru st_key;
    mac_seq_stru st_seq;
} mac_addkey_hmac2dmac_param_stru;

typedef struct {
    oal_net_device_stru *pst_netdev;
    oal_uint8 uc_key_index;
    oal_bool_enum_uint8 en_pairwise;
    oal_uint8 auc_resv1[2];
    oal_uint8 *puc_mac_addr;
    oal_void *cookie;
    oal_void (*callback)(oal_void *cookie, oal_key_params_stru *key_param);
} mac_getkey_param_stru;

typedef struct {
    oal_uint8 uc_key_index;
    oal_bool_enum_uint8 en_pairwise;

    oal_uint8 auc_mac_addr[OAL_MAC_ADDR_LEN];
} mac_removekey_param_stru;

typedef struct {
    oal_uint8 uc_key_index;
    oal_bool_enum_uint8 en_unicast;
    oal_bool_enum_uint8 en_multicast;
    oal_uint8 auc_resv1[1];
} mac_setdefaultkey_param_stru;

typedef struct {
    oal_uint32 ul_dfs_mode;
    oal_int32 al_para[3];
} mac_cfg_dfs_param_stru;

typedef struct {
    oal_uint8 uc_total_channel_num;
    oal_uint8 auc_channel_number[15];
} mac_cfg_dfs_auth_channel_stru;

typedef struct {
    oal_uint ul_addr;
    oal_uint32 ul_len;
} mac_cfg_dump_memory_stru;

/* ???????????????????? */
typedef struct {
    mac_alg_cfg_enum_uint8 en_alg_cfg; /* ???????????? */
    oal_uint8 uc_resv[3];              /* ???????? */
    oal_uint32 ul_value;               /* ?????????? */
} mac_ioctl_alg_param_stru;

/* AUTORATE LOG ???????????????????? */
typedef struct {
    mac_alg_cfg_enum_uint8 en_alg_cfg;         /* ???????????? */
    oal_uint8 auc_mac_addr[WLAN_MAC_ADDR_LEN]; /* MAC???? */
    oal_uint8 uc_ac_no;                        /* AC???? */
    oal_uint8 auc_resv[2];
    oal_uint16 us_value; /* ?????????? */
} mac_ioctl_alg_ar_log_param_stru;

/* AUTORATE ?????????????????? */
typedef struct {
    mac_alg_cfg_enum_uint8 en_alg_cfg;         /* ???????????? */
    oal_uint8 auc_mac_addr[WLAN_MAC_ADDR_LEN]; /* MAC???? */
    oal_uint8 auc_resv[1];
    oal_uint16 us_value; /* ???????? */
} mac_ioctl_alg_ar_test_param_stru;

/* TXMODE LOG ???????????????????? */
typedef struct {
    mac_alg_cfg_enum_uint8 en_alg_cfg;         /* ???????????? */
    oal_uint8 uc_ac_no;                        /* AC???? */
    oal_uint8 auc_mac_addr[WLAN_MAC_ADDR_LEN]; /* MAC???? */
    oal_uint8 auc_resv1[2];
    oal_uint16 us_value; /* ?????????? */
} mac_ioctl_alg_txbf_log_param_stru;
/* ???????????????? */
typedef struct {
    oal_uint8 uc_argc;
    oal_uint8 auc_argv_offset[DMAC_ALG_CONFIG_MAX_ARG];
} mac_ioctl_alg_config_stru;

/* TPC LOG ???????????????????? */
typedef struct {
    mac_alg_cfg_enum_uint8 en_alg_cfg;         /* ???????????? */
    oal_uint8 auc_mac_addr[WLAN_MAC_ADDR_LEN]; /* MAC???? */
    oal_uint8 uc_ac_no;                        /* AC???? */
    oal_uint16 us_value;                       /* ?????????? */
    oal_int8 *pc_frame_name;                   /* ???????????????????????? */
} mac_ioctl_alg_tpc_log_param_stru;

/* cca opt LOG ???????????????????? */
typedef struct {
    mac_alg_cfg_enum_uint8 en_alg_cfg; /* ???????????? */
    oal_uint16 us_value;               /* ?????????? */
    oal_uint8 auc_resv;
} mac_ioctl_alg_cca_opt_log_param_stru;

#ifdef _PRE_DEBUG_MODE
/* ???????????? */
typedef struct {
    oal_int8 ac_scan_type[15];
    wlan_channel_bandwidth_enum_uint8 en_bandwidth;
} mac_ioctl_scan_test_config_stru;
#endif

/* RTS ???????? */
typedef struct {
    wlan_legacy_rate_value_enum_uint8 auc_rate[HAL_TX_RATE_MAX_NUM]; /* ??????????????mpbs */
    /* ????????, ????????wlan_phy_protocol_enum_uint8 */
    wlan_phy_protocol_enum_uint8 auc_protocol_mode[HAL_TX_RATE_MAX_NUM];
    wlan_channel_band_enum_uint8 en_band;
    oal_uint8 auc_recv[3];
} mac_cfg_rts_tx_param_stru;

/* ?????????? ???????? */
typedef struct {
    oal_uint8 uc_m2u_mcast_mode;
    oal_uint8 uc_m2u_snoop_on;
} mac_cfg_m2u_snoop_on_param_stru;

/* ?????????????????? */
typedef struct {
    oal_uint32 ul_deny_group_addr;
} mac_add_m2u_deny_table_stru;

/* ???????????????????? */
typedef struct {
    oal_uint8 uc_m2u_clear_deny_table;
    oal_uint8 uc_m2u_show_deny_table;
} mac_clg_m2u_deny_table_stru;

/* print snoop table */
typedef struct {
    oal_uint8 uc_m2u_show_snoop_table;
} mac_show_m2u_snoop_table_stru;

/* add snoop table */
typedef struct {
    oal_uint8 uc_m2u_add_snoop_table;
} mac_add_m2u_snoop_table_stru;

typedef struct {
    oal_bool_enum_uint8 en_proxyarp;
    oal_uint8 auc_rsv[3];
} mac_proxyarp_en_stru;

typedef struct {
    oal_uint8 auc_bssid[WLAN_MAC_ADDR_LEN];
    oal_uint8 auc_resv0[2];
    oal_uint8 auc_pmkid[WLAN_PMKID_LEN];
} mac_cfg_pmksa_param_stru;

typedef struct {
    oal_uint64 ull_cookie;
    oal_uint32 ul_listen_duration;                            /* ???????? */
    oal_uint8 uc_listen_channel;                              /* ?????????? */
    wlan_channel_bandwidth_enum_uint8 en_listen_channel_type; /* ???????????? */
    oal_uint8 uc_home_channel;                                /* ?????????????????? */
    wlan_channel_bandwidth_enum_uint8 en_home_channel_type;   /* ???????????????????????? */
    /* P2P0??P2P_CL ????VAP ????????????????????VAP ???????????????????????????????? */
    mac_vap_state_enum_uint8 en_last_vap_state;
    wlan_channel_band_enum_uint8 en_band;
    wlan_ieee80211_roc_type_uint8 en_roc_type; /* roc???? */
    oal_uint8 en_rev;
    oal_ieee80211_channel_stru st_listen_channel;
} mac_remain_on_channel_param_stru;

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
typedef enum {
    MAC_MEMINFO_POOL_INFO = 0,
    MAC_MEMINFO_SAMPLE_ALLOC,
    MAC_MEMINFO_SAMPLE_FREE,

    MAC_MEMINFO_BUTT
} mac_meminfo_cmd_enum;
typedef oal_uint8 mac_meminfo_cmd_enum_uint8;

typedef struct {
    mac_meminfo_cmd_enum_uint8 uc_meminfo_type;
    oal_uint8 uc_pool_id;
} mac_device_pool_id_stru;
#endif

/* WPAS ?????????????? */
typedef struct {
    oal_int32 channel;
    oal_uint8 mgmt_frame_id;
    oal_uint8 uc_rsv;
    oal_uint16 us_len;
    OAL_CONST oal_uint8 *puc_frame;
} mac_mgmt_frame_stru;

/* STA PS ???????? */
#ifdef _PRE_WLAN_FEATURE_STA_PM
typedef struct {
    oal_uint8 uc_vap_ps_mode;
} mac_cfg_ps_mode_param_stru;

typedef struct {
    oal_uint16 us_beacon_timeout;
    oal_uint16 us_tbtt_offset;
    oal_uint16 us_ext_tbtt_offset;
    oal_uint16 us_dtim3_on;
} mac_cfg_ps_param_stru;

#ifdef _PRE_PSM_DEBUG_MODE
typedef struct {
    oal_uint8 uc_psm_info_enable : 2;  // ????psm??????????????
    oal_uint8 uc_psm_debug_mode : 2;   // ????psm??debug????????
    oal_uint8 uc_psm_resd : 4;
} mac_cfg_ps_info_stru;
#endif

#endif
typedef struct {
    oal_uint8 uc_show_ip_addr : 4;          // show ip addr
    oal_uint8 uc_show_arpoffload_info : 4;  // show arpoffload ????
} mac_cfg_arpoffload_info_stru;

typedef struct {
    oal_uint8 uc_in_suspend;         // ??????
    oal_uint8 uc_arpoffload_switch;  // arpoffload????
    oal_uint8 uc_apf_switch;         // apf????
} mac_cfg_suspend_stru;

typedef enum {
    MAC_STA_PM_SWITCH_OFF = 0,      /* ?????????? */
    MAC_STA_PM_SWITCH_ON = 1,       /* ?????????? */
    MAC_STA_PM_MANUAL_MODE_ON = 2,  /* ????????sta pm mode */
    MAC_STA_PM_MANUAL_MODE_OFF = 3, /* ????????sta pm mode */
    MAC_STA_PM_SWITCH_BUTT,         /* ???????? */
} mac_pm_switch_enum;
typedef oal_uint8 mac_pm_switch_enum_uint8;

typedef enum {
    MAC_STA_PM_CTRL_TYPE_HOST = 0, /* ?????????????? HOST */
    MAC_STA_PM_CTRL_TYPE_DBAC = 1, /* ?????????????? DBAC */
    MAC_STA_PM_CTRL_TYPE_ROAM = 2, /* ?????????????? ROAM */
    MAC_STA_PM_CTRL_TYPE_CMD = 3,  /* ?????????????? CMD */
    MAC_STA_PM_CTRL_TYPE_BUTT,     /* ???????????????? 8 */
} mac_pm_ctrl_type_enum;
typedef oal_uint8 mac_pm_ctrl_type_enum_uint8;

typedef struct {
    mac_pm_ctrl_type_enum_uint8 uc_pm_ctrl_type; /* mac_pm_ctrl_type_enum */
    mac_pm_switch_enum_uint8 uc_pm_enable;       /* mac_pm_switch_enum */
} mac_cfg_ps_open_stru;

/* P2P OPS ???????????? */
typedef struct {
    oal_uint8 en_ops_ctrl;
    oal_uint8 uc_ct_window;
    oal_uint8 en_pause_ops;
    oal_uint8 auc_rsv[1];
} mac_cfg_p2p_ops_param_stru;

/* P2P NOA???????????? */
typedef struct {
    oal_uint32 ul_start_time;
    oal_uint32 ul_duration;
    oal_uint32 ul_interval;
    oal_uint8 uc_count;
    oal_uint8 auc_rsv[3];
} mac_cfg_p2p_noa_param_stru;

/* P2P ???????????? */
typedef struct {
    oal_uint8 uc_p2p_statistics_ctrl; /* 0:????P2P ???????? 1:?????????????? */
    oal_uint8 auc_rsv[3];
} mac_cfg_p2p_stat_param_stru;

#ifdef _PRE_WLAN_FEATURE_ROAM
typedef enum {
    WPAS_CONNECT_STATE_INIT = 0,
    WPAS_CONNECT_STATE_START = 1,
    WPAS_CONNECT_STATE_ASSOCIATED = 2,
    WPAS_CONNECT_STATE_HANDSHAKED = 3,
    WPAS_CONNECT_STATE_IPADDR_OBTAINED = 4,
    WPAS_CONNECT_STATE_IPADDR_REMOVED = 5,
    WPAS_CONNECT_STATE_BUTT
} wpas_connect_state_enum;
typedef oal_uint32 wpas_connect_state_enum_uint32;
/* roam trigger ?????????? */
typedef struct {
    oal_int8 c_trigger_2G;
    oal_int8 c_trigger_5G;
    oal_uint8 auc_resv[2];
} mac_roam_trigger_stru;

/* roam hmac ???? dmac?????????? */
typedef struct {
    oal_uint16 us_sta_aid;
    oal_uint16 us_pad;
    mac_channel_stru st_channel;
    mac_user_cap_info_stru st_cap_info;
    mac_key_mgmt_stru st_key_info;
    mac_user_tx_param_stru st_user_tx_info;
    oal_uint32 ul_back_to_old;
} mac_h2d_roam_sync_stru;
#endif  // _PRE_WLAN_FEATURE_ROAM
#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE

#ifdef _PRE_WLAN_FIT_BASED_REALTIME_CALI
/* ???????????????????????? */
typedef struct {
    mac_dyn_cali_cfg_enum_uint8 en_dyn_cali_cfg; /* ???????????? */
    oal_uint8 uc_resv;                           /* ???????? */
    oal_uint16 us_value;                         /* ?????????? */
} mac_ioctl_dyn_cali_param_stru;
#endif

/* ?????? linkloss???????????? */
typedef struct {
    oal_uint8 uc_linkloss_threshold_wlan_bt;
    oal_uint8 uc_linkloss_threshold_wlan_dbac;
    oal_uint8 uc_linkloss_threshold_wlan_normal;
    oal_uint8 auc_resv[1];
} mac_cfg_linkloss_threshold;
/* ?????? power ref 2g 5g???????? */
typedef struct {
    oal_uint32 ul_power_ref_5g;
} mac_cfg_power_ref;
/* customize rf cfg struct */
typedef struct {
    oal_int8 c_rf_gain_db_mult4;  /* ????PA/LNA bypass????????(????0.25dB) */
    oal_int8 c_rf_gain_db_mult10; /* ????PA/LNA bypass????????(????0.1dB) */
} mac_cfg_gain_db_per_band;

/* FCC???? ?????????? */
typedef struct {
    oal_uint8 uc_index;       /* ???????????? */
    oal_uint8 uc_max_txpower; /* ???????????? */
    oal_uint8 uc_dbb_scale;   /* dbb scale */
    oal_uint8 uc_resv;
} mac_cus_band_edge_limit_stru;
#endif /* #ifdef _PRE_PLAT_FEATURE_CUSTOMIZE */

#ifdef _PRE_WLAN_FEATURE_UAPSD
extern oal_uint8 g_uc_uapsd_cap;
extern oal_uint8 mac_get_uapsd_cap(oal_void);
extern oal_void mac_set_uapsd_cap(oal_uint8 uc_uapsd_cap);
#endif

/* 1102 wiphy Vendor CMD???? ????cfgid: WLAN_CFGID_VENDOR_CMD */
typedef struct mac_vendor_cmd_channel_list_info {
    oal_uint8 uc_channel_num_2g;
    oal_uint8 uc_channel_num_5g;
    oal_uint8 auc_channel_list_2g[MAC_CHANNEL_FREQ_2_BUTT];
    oal_uint8 auc_channel_list_5g[MAC_CHANNEL_FREQ_5_BUTT];
} mac_vendor_cmd_channel_list_stru;

/* CHR2.0??????STA???????? */
typedef struct {
    oal_uint8 uc_distance;  /* ??????tpc??????????dmac_alg_tpc_user_distance_enum */
    oal_uint8 uc_cca_intr;  /* ??????cca_intr??????????alg_cca_opt_intf_enum */
    oal_uint16 us_chload;   /* ?????????? */
    oal_uint32 ul_bcn_cnt;  /* ??????beacon???? */
    oal_uint32 ul_tbtt_cnt; /* tbtt????????????????bcn_tout_cnt????,?????????????????? */
} station_info_extend_stru;

typedef struct {
    oal_uint32 ul_tbtt_cnt;
    oal_uint32 ul_rx_beacon_cnt;
    oal_uint8 auc_is_paused[WLAN_TID_MAX_NUM]; /* tid??????????paused */
    oal_uint32 ul_upc1_01_data;                /* UPC???????? */
    oal_uint8 en_distance_id;                  /* ????:?????? */
    oal_uint8 en_tas_state;
    oal_uint16 us_reserve;
} chr_wifi_ext_info_stru;

typedef struct {
    oal_wait_queue_head_stru st_query_chr_wait_q; /* chr???????????? */
    oal_bool_enum_uint8 en_chr_info_ext_query_completed_flag;
    chr_wifi_ext_info_stru st_chr_wifi_ext_info;
} chr_wifi_ext_info_query_stru;

#ifdef _PRE_WLAN_FEATURE_FTM
/* FTM???????????????????? */
typedef struct {
    oal_uint8 uc_channel_num;
    oal_uint8 uc_burst_num;
    oal_bool_enum_uint8 measure_req;
    oal_uint8 uc_ftms_per_burst;

    oal_bool_enum_uint8 en_asap;
    oal_uint8 uc_format_bw;
    oal_uint8 auc_bssid[WLAN_MAC_ADDR_LEN];
} mac_send_iftmr_stru;

typedef struct {
    oal_uint32 ul_bursts_timeout;
    oal_uint32 ul_ftms_timeout;
} mac_ftm_timeout_stru;

typedef struct {
    oal_uint32 ul_ftm_correct_time1;
    oal_uint32 ul_ftm_correct_time2;
    oal_uint32 ul_ftm_correct_time3;
    oal_uint32 ul_ftm_correct_time4;
} mac_set_ftm_time_stru;

typedef struct {
    oal_uint8 auc_resv[2];
    oal_uint8 auc_mac[WLAN_MAC_ADDR_LEN];
} mac_send_ftm_stru;

typedef struct {
    oal_uint8 auc_mac[WLAN_MAC_ADDR_LEN];
    oal_uint8 uc_dialog_token;
    oal_uint8 uc_meas_token;

    oal_uint16 us_num_rpt;

    oal_uint16 us_start_delay;
    oal_uint8 auc_reserve[1];
    oal_uint8 uc_minimum_ap_count;
    oal_uint8 aauc_bssid[MAX_MINIMUN_AP_COUNT][WLAN_MAC_ADDR_LEN];
    oal_uint8 auc_channel[MAX_MINIMUN_AP_COUNT];
} mac_send_ftm_range_req_stru; /* ??ftm_range_req_stru ???????? */
typedef struct {
    oal_uint8 auc_bssid[WLAN_MAC_ADDR_LEN];
} mac_neighbor_report_req_stru;

typedef struct {
    oal_bool_enum_uint8 en_lci_enable;
    oal_bool_enum_uint8 en_interworking_enable;
    oal_bool_enum_uint8 en_civic_enable;
    oal_bool_enum_uint8 en_geo_enable;
    oal_uint8 auc_bssid[WLAN_MAC_ADDR_LEN];
} mac_send_gas_init_req_stru;

typedef struct {
    oal_uint32 ul_cmd_bit_map;

    oal_bool_enum_uint8 en_ftm_initiator_bit0;          /* ftm_initiator???? */
    mac_send_iftmr_stru st_send_iftmr_bit1;             /* ????iftmr???? */
    oal_bool_enum_uint8 en_enable_bit2;                 /* ????FTM */
    oal_bool_enum_uint8 en_cali_bit3;                   /* FTM???? */
    mac_send_ftm_stru st_send_ftm_bit4;                 /* ????ftm???? */
    oal_bool_enum_uint8 en_ftm_resp_bit5;               /* ftm_resp???? */
    mac_set_ftm_time_stru st_ftm_time_bit6;             /* ftm_time???? */
    mac_send_ftm_range_req_stru st_send_range_req_bit7; /* ????ftm_range_req???? */
    oal_bool_enum_uint8 en_ftm_range_bit8;              /* ftm_range???? */
    oal_uint8 uc_get_cali_reserv_bit9;
    oal_bool_enum_uint8 en_multipath_bit12;
    mac_ftm_timeout_stru st_ftm_timeout_bit14;                 /* ??????????ftm?????????????? */
    mac_neighbor_report_req_stru st_neighbor_report_req_bit15; /* ????neighbour report request???? */
    mac_send_gas_init_req_stru st_gas_init_req_bit16;          /* ????gas init req ???? */
} mac_ftm_debug_switch_stru;

typedef struct {
    oal_int8 *pc_cmd_name;      /* ?????????? */
    oal_uint8 uc_is_check_para; /* ?????????????????? */
    oal_uint32 ul_bit;          /* ?????????????? */
} wal_ftm_cmd_entry_stru;

#ifdef _PRE_WLAN_FEATURE_FTM
typedef struct {
    oal_uint8 uc_is_gas_request_sent;
    oal_uint8 uc_gas_dialog_token;
    oal_uint8 uc_gas_response_dialog_token;
    oal_uint8 auc_resv[1];
} mac_gas_mgmt_stru;
#endif
#endif

#if (_PRE_WLAN_FEATURE_PMF != _PRE_PMF_NOT_SUPPORT)
typedef struct {
    oal_bool_enum_uint8 en_pmf_capable;
    oal_bool_enum_uint8 en_pmf_required;
} mac_cfg_pmf_cap_stru;
#endif

#ifdef _PRE_WLAN_FEATURE_TAS_ANT_SWITCH
typedef struct {
    oal_int32 l_core_idx;
    oal_int32 l_rssi;
    oal_int32 aul_rsv[4  // ??????????????????????4??int32\r
                        ];
} mac_tas_rssi_notify_stru;
#endif

typedef oal_rom_cb_result_enum_uint8 (*p_mac_vap_init_cb)(mac_vap_stru *pst_vap,
                                                          oal_uint8 uc_chip_id,
                                                          oal_uint8 uc_device_id,
                                                          oal_uint8 uc_vap_id,
                                                          mac_cfg_add_vap_param_stru *pst_param,
                                                          oal_uint32 *pul_cb_ret);

typedef oal_rom_cb_result_enum_uint8 (*p_mac_vap_init_privacy_cb)(
    mac_vap_stru *pst_mac_vap, mac_cfg80211_connect_security_stru *pst_mac_security_param, oal_uint32 *pul_ret);

typedef oal_rom_cb_result_enum_uint8 (*p_mac_vap_set_beacon_cb)(mac_vap_stru *pst_mac_vap,
                                                                mac_beacon_param_stru *pst_beacon_param,
                                                                oal_uint32 *pul_ret);
typedef oal_rom_cb_result_enum_uint8 (*p_mac_vap_del_user_cb)(mac_vap_stru *pst_vap,
                                                              oal_uint16 us_user_idx,
                                                              oal_uint32 *pul_ret);

typedef struct {
    p_mac_vap_init_cb p_mac_vap_init;
    p_mac_vap_init_privacy_cb p_mac_vap_init_privacy;
    p_mac_vap_set_beacon_cb p_mac_vap_set_beacon;
    p_mac_vap_del_user_cb p_mac_vap_del_user;
} mac_vap_rom_cb_stru;

typedef struct {
    oal_uint16 us_beacon_period;
    oal_uint8 auc_resv[2];
} mac_d2h_mib_update_info_stru;
typedef struct {
    oal_uint8 uc_auth_req_st;
    oal_uint8 uc_asoc_req_st;
} mac_cfg_query_mgmt_send_status_stru;

/*****************************************************************************
  8 UNION????
*****************************************************************************/
/*****************************************************************************
  9 OTHERS????
*****************************************************************************/
extern oal_bool_enum_uint8 mac_is_wep_enabled(mac_vap_stru *pst_mac_vap);


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_privacyinvoked(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.en_dot11PrivacyInvoked;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_privacyinvoked(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_privacyinvoked)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.en_dot11PrivacyInvoked = en_privacyinvoked;
}


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_rsnaactivated(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.en_dot11RSNAActivated;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_rsnaactivated(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_rsnaactivated)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.en_dot11RSNAActivated = en_rsnaactivated;
}


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_is_wep_allowed(mac_vap_stru *pst_mac_vap)
{
    if (mac_mib_get_rsnaactivated(pst_mac_vap) == OAL_TRUE) {
        return OAL_FALSE;
    } else {
        return mac_is_wep_enabled(pst_mac_vap);
    }
}


OAL_STATIC OAL_INLINE oal_void mac_set_wep_default_keyid(mac_vap_stru *pst_mac_vap, oal_uint8 uc_default_key_id)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.uc_dot11WEPDefaultKeyID = uc_default_key_id;
}


OAL_STATIC OAL_INLINE oal_uint8 mac_get_wep_default_keyid(mac_vap_stru *pst_mac_vap)
{
    return (pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.uc_dot11WEPDefaultKeyID);
}


OAL_STATIC OAL_INLINE oal_uint8 mac_get_wep_default_keysize(mac_vap_stru *pst_mac_vap)
{
    wlan_mib_Dot11WEPDefaultKeysEntry_stru *pst_wlan_mib_Dot11WEPDefaultKeysEntry;

    pst_wlan_mib_Dot11WEPDefaultKeysEntry =
        &pst_mac_vap->pst_mib_info->ast_wlan_mib_wep_dflt_key[mac_get_wep_default_keyid(pst_mac_vap)];
    return (pst_wlan_mib_Dot11WEPDefaultKeysEntry->auc_dot11WEPDefaultKeyValue[WLAN_WEP_SIZE_OFFSET]);
}


OAL_STATIC OAL_INLINE oal_uint8 mac_get_wep_keysize(mac_vap_stru *pst_mac_vap, oal_uint8 uc_idx)
{
    wlan_mib_Dot11WEPDefaultKeysEntry_stru *pst_wlan_mib_Dot11WEPDefaultKeysEntry;

    pst_wlan_mib_Dot11WEPDefaultKeysEntry = &pst_mac_vap->pst_mib_info->ast_wlan_mib_wep_dflt_key[uc_idx];
    return (pst_wlan_mib_Dot11WEPDefaultKeysEntry->auc_dot11WEPDefaultKeyValue[WLAN_WEP_SIZE_OFFSET]);
}


OAL_STATIC OAL_INLINE oal_uint8 *mac_get_wep_default_keyvalue(mac_vap_stru *pst_mac_vap)
{
    wlan_mib_Dot11WEPDefaultKeysEntry_stru *pst_wlan_mib_Dot11WEPDefaultKeysEntry;

    pst_wlan_mib_Dot11WEPDefaultKeysEntry =
        &pst_mac_vap->pst_mib_info->ast_wlan_mib_wep_dflt_key[mac_get_wep_default_keyid(pst_mac_vap)];
    return (&pst_wlan_mib_Dot11WEPDefaultKeysEntry->auc_dot11WEPDefaultKeyValue[WLAN_WEP_KEY_VALUE_OFFSET]);
}


OAL_STATIC OAL_INLINE oal_uint8 *mac_get_wep_key_value(mac_vap_stru *pst_mac_vap, oal_uint8 uc_idx)
{
    wlan_mib_Dot11WEPDefaultKeysEntry_stru *pst_wlan_mib_Dot11WEPDefaultKeysEntry;

    pst_wlan_mib_Dot11WEPDefaultKeysEntry = &pst_mac_vap->pst_mib_info->ast_wlan_mib_wep_dflt_key[uc_idx];
    return (&pst_wlan_mib_Dot11WEPDefaultKeysEntry->auc_dot11WEPDefaultKeyValue[WLAN_WEP_KEY_VALUE_OFFSET]);
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_DeauthenticateReason(mac_vap_stru *pst_mac_vap, oal_uint16 us_err_code)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.ul_dot11DeauthenticateReason = (oal_uint32)us_err_code;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_DeauthenticateStation(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_da)
{
    if (memcpy_s(pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.auc_dot11DeauthenticateStation, WLAN_MAC_ADDR_LEN,
                 puc_da, WLAN_MAC_ADDR_LEN) != EOK) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{mac_mib_set_DeauthenticateStation::memcpy fail!}");
    }
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_AuthenticateFailStation(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_da)
{
    if (memcpy_s(pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.auc_dot11AuthenticateFailStation, WLAN_MAC_ADDR_LEN,
                 puc_da, WLAN_MAC_ADDR_LEN) != EOK) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{mac_mib_set_AuthenticateFailStation::memcpy fail!}");
    }
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_AuthenticateFailStatus(mac_vap_stru *pst_mac_vap, oal_uint16 us_err_code)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.ul_dot11AuthenticateFailStatus = (oal_uint32)us_err_code;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_DisassocStation(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_da)
{
    if (memcpy_s(pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.auc_dot11DisassociateStation, WLAN_MAC_ADDR_LEN,
                 puc_da, WLAN_MAC_ADDR_LEN) != EOK) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{mac_mib_set_DisassocStation::memcpy fail!}");
    }
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_DisassocReason(mac_vap_stru *pst_mac_vap, oal_uint16 us_err_code)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.ul_dot11DisassociateReason = (oal_uint32)us_err_code;
}


OAL_STATIC OAL_INLINE oal_uint8 *mac_mib_get_StationID(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.auc_dot11StationID;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_StationID(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_sta_id)
{
    oal_set_mac_addr(pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.auc_dot11StationID, puc_sta_id);
}


OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_OBSSScanPassiveDwell(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11OBSSScanPassiveDwell;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_OBSSScanPassiveDwell(mac_vap_stru *pst_mac_vap, oal_uint32 ul_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11OBSSScanPassiveDwell = ul_val;
}


OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_OBSSScanActiveDwell(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11OBSSScanActiveDwell;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_OBSSScanActiveDwell(mac_vap_stru *pst_mac_vap, oal_uint32 ul_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11OBSSScanActiveDwell = ul_val;
}


OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_BSSWidthTriggerScanInterval(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11BSSWidthTriggerScanInterval;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_BSSWidthTriggerScanInterval(mac_vap_stru *pst_mac_vap, oal_uint32 ul_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11BSSWidthTriggerScanInterval = ul_val;
}


OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_OBSSScanPassiveTotalPerChannel(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11OBSSScanPassiveTotalPerChannel;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_OBSSScanPassiveTotalPerChannel(mac_vap_stru *pst_mac_vap, oal_uint32 ul_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11OBSSScanPassiveTotalPerChannel = ul_val;
}


OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_OBSSScanActiveTotalPerChannel(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11OBSSScanActiveTotalPerChannel;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_OBSSScanActiveTotalPerChannel(mac_vap_stru *pst_mac_vap, oal_uint32 ul_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11OBSSScanActiveTotalPerChannel = ul_val;
}


OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_BSSWidthChannelTransitionDelayFactor(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11BSSWidthChannelTransitionDelayFactor;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_BSSWidthChannelTransitionDelayFactor(
    mac_vap_stru *pst_mac_vap, oal_uint32 ul_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11BSSWidthChannelTransitionDelayFactor = ul_val;
}


OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_OBSSScanActivityThreshold(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11OBSSScanActivityThreshold;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_OBSSScanActivityThreshold(mac_vap_stru *pst_mac_vap, oal_uint32 ul_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11OBSSScanActivityThreshold = ul_val;
}


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_HighThroughputOptionImplemented(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11HighThroughputOptionImplemented;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_HighThroughputOptionImplemented(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11HighThroughputOptionImplemented = en_val;
}


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_VHTOptionImplemented(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11VHTOptionImplemented;
}


OAL_STATIC OAL_INLINE oal_uint8 mac_mib_get_VHTChannelWidthOptionImplemented(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_phy_vht.uc_dot11VHTChannelWidthOptionImplemented;
}


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_FortyMHzOperationImplemented(mac_vap_stru *pst_mac_vap)
{
    if (pst_mac_vap->st_channel.en_band == WLAN_BAND_2G) {
        return pst_mac_vap->pst_mib_info->st_phy_ht.en_dot112GFortyMHzOperationImplemented;
    } else {
        return pst_mac_vap->pst_mib_info->st_phy_ht.en_dot115GFortyMHzOperationImplemented;
    }
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_FortyMHzOperationImplemented(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    if (pst_mac_vap->st_channel.en_band == WLAN_BAND_2G) {
        pst_mac_vap->pst_mib_info->st_phy_ht.en_dot112GFortyMHzOperationImplemented = en_val;
    } else {
        pst_mac_vap->pst_mib_info->st_phy_ht.en_dot115GFortyMHzOperationImplemented = en_val;
    }
}


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_SpectrumManagementImplemented(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11SpectrumManagementImplemented;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_SpectrumManagementImplemented(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11SpectrumManagementImplemented = en_val;
}


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_FortyMHzIntolerant(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_operation.en_dot11FortyMHzIntolerant;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_FortyMHzIntolerant(mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.en_dot11FortyMHzIntolerant = en_val;
}


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_2040BSSCoexistenceManagementSupport(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_operation.en_dot112040BSSCoexistenceManagementSupport;
}


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_dot11RSNAProtectedManagementFramesActivated(
    mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11RSNAProtectedManagementFramesActivated;
}

OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_dot11RSNAMFPC(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.en_dot11RSNAMFPC;
}

OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_dot11RSNAMFPR(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.en_dot11RSNAMFPR;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_dot11RSNAProtectedManagementFramesActivated(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 ul_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11RSNAProtectedManagementFramesActivated = ul_val;
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_dot11RSNAMFPC(mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 ul_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.en_dot11RSNAMFPC = ul_val;
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_dot11RSNAMFPR(mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 ul_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.en_dot11RSNAMFPR = ul_val;
}


OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_dot11AssociationSAQueryMaximumTimeout(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.ul_dot11AssociationSAQueryMaximumTimeout;
}

OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_dot11AssociationSAQueryRetryTimeout(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.ul_dot11AssociationSAQueryRetryTimeout;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_dot11AssociationSAQueryMaximumTimeout(
    mac_vap_stru *pst_mac_vap, oal_uint32 ul_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.ul_dot11AssociationSAQueryMaximumTimeout = ul_val;
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_dot11AssociationSAQueryRetryTimeout(
    mac_vap_stru *pst_mac_vap, oal_uint32 ul_val)
{
#if (_PRE_WLAN_FEATURE_PMF != _PRE_PMF_NOT_SUPPORT)
    pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.ul_dot11AssociationSAQueryRetryTimeout = ul_val;
#endif
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_2040BSSCoexistenceManagementSupport(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.en_dot112040BSSCoexistenceManagementSupport = en_val;
}
#ifdef _PRE_WLAN_FEATURE_11K

OAL_STATIC OAL_INLINE oal_void mac_mib_set_dot11RadioMeasurementActivated(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11RadioMeasurementActivated = en_val;
}

OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_dot11RadioMeasurementActivated(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11RadioMeasurementActivated;
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_dot11RMBeaconTableMeasurementActivated(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11RMBeaconTableMeasurementActivated = en_val;
}

OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_dot11RMBeaconTableMeasurementActivated(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11RMBeaconTableMeasurementActivated;
}
#endif

OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_dot11dtimperiod(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.ul_dot11DTIMPeriod;
}

OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_BeaconPeriod(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.ul_dot11BeaconPeriod;
}

OAL_STATIC OAL_INLINE oal_uint8 *mac_mib_get_DesiredSSID(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.auc_dot11DesiredSSID;
}

OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_AuthenticationResponseTimeOut(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.ul_dot11AuthenticationResponseTimeOut;
}

#if defined(_PRE_WLAN_FEATURE_FTM) || defined(_PRE_WLAN_FEATURE_11V_ENABLE)

OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_MgmtOptionBSSTransitionActivated(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_wireless_mgmt_op.en_dot11MgmtOptionBSSTransitionActivated;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_MgmtOptionBSSTransitionActivated(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_wireless_mgmt_op.en_dot11MgmtOptionBSSTransitionActivated = en_val;
}

OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_MgmtOptionBSSTransitionImplemented(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_wireless_mgmt_op.en_dot11MgmtOptionBSSTransitionImplemented;
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_MgmtOptionBSSTransitionImplemented(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_wireless_mgmt_op.en_dot11MgmtOptionBSSTransitionImplemented = en_val;
}
OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_WirelessManagementImplemented(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11WirelessManagementImplemented;
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_WirelessManagementImplemented(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11WirelessManagementImplemented = en_val;
}
#endif

#ifdef _PRE_WLAN_FEATURE_FTM
extern mac_ftm_mode_enum_uint8 mac_check_ftm_enable(mac_vap_stru *pst_mac_vap);
#endif

#if defined(_PRE_WLAN_FEATURE_FTM) || defined(_PRE_WLAN_FEATURE_11V_ENABLE)
OAL_STATIC OAL_INLINE oal_void mac_mib_set_FineTimingMsmtInitActivated(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_wireless_mgmt_op.en_dot11FineTimingMsmtInitActivated = en_val;
}
OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_FineTimingMsmtInitActivated(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_wireless_mgmt_op.en_dot11FineTimingMsmtInitActivated;
}
OAL_STATIC OAL_INLINE oal_void mac_mib_set_FineTimingMsmtRespActivated(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_wireless_mgmt_op.en_dot11FineTimingMsmtRespActivated = en_val;
}
OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_FineTimingMsmtRespActivated(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_wireless_mgmt_op.en_dot11FineTimingMsmtRespActivated;
}
OAL_STATIC OAL_INLINE oal_void mac_mib_set_FineTimingMsmtRangeRepActivated(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_wireless_mgmt_op.en_dot11RMFineTimingMsmtRangeRepActivated = en_val;
}
OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_FineTimingMsmtRangeRepActivated(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_wireless_mgmt_op.en_dot11RMFineTimingMsmtRangeRepActivated;
}
#endif


OAL_STATIC OAL_INLINE oal_void mac_mib_set_dot11dtimperiod(mac_vap_stru *pst_mac_vap, oal_uint32 ul_val)
{
    if (ul_val != 0) {
        pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.ul_dot11DTIMPeriod = ul_val;
    }
}


OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_powermanagementmode(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.uc_dot11PowerManagementMode;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_powermanagementmode(mac_vap_stru *pst_mac_vap, oal_uint8 uc_val)
{
    if (uc_val != 0) {
        pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.uc_dot11PowerManagementMode = uc_val;
    }
}

#if defined _PRE_WLAN_FEATURE_OPMODE_NOTIFY || (_PRE_OS_VERSION_WIN32_RAW == _PRE_OS_VERSION)

OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_OperatingModeNotificationImplemented(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11OperatingModeNotificationImplemented;
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_OperatingModeNotificationImplemented(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11OperatingModeNotificationImplemented = en_val;
}
#endif


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_LsigTxopFullProtectionActivated(mac_vap_stru *pst_mac_vap)
{
    return (pst_mac_vap->pst_mib_info->st_wlan_mib_operation.en_dot11LSIGTXOPFullProtectionActivated);
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_LsigTxopFullProtectionActivated(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_lsig_txop_full_protection_activated)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.en_dot11LSIGTXOPFullProtectionActivated =
        en_lsig_txop_full_protection_activated;
}


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_NonGFEntitiesPresent(mac_vap_stru *pst_mac_vap)
{
    return (pst_mac_vap->pst_mib_info->st_wlan_mib_operation.en_dot11NonGFEntitiesPresent);
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_NonGFEntitiesPresent(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_non_gf_entities_present)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.en_dot11NonGFEntitiesPresent = en_non_gf_entities_present;
}


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_RifsMode(mac_vap_stru *pst_mac_vap)
{
    return (pst_mac_vap->pst_mib_info->st_wlan_mib_operation.en_dot11RIFSMode);
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_RifsMode(mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_rifs_mode)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.en_dot11RIFSMode = en_rifs_mode;
}


OAL_STATIC OAL_INLINE wlan_mib_ht_protection_enum_uint8 mac_mib_get_HtProtection(mac_vap_stru *pst_mac_vap)
{
    return (pst_mac_vap->pst_mib_info->st_wlan_mib_operation.en_dot11HTProtection);
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_HtProtection(
    mac_vap_stru *pst_mac_vap, wlan_mib_ht_protection_enum_uint8 en_ht_protection)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.en_dot11HTProtection = en_ht_protection;
}


OAL_STATIC OAL_INLINE wlan_11b_mib_preamble_enum_uint8 mac_mib_get_ShortPreambleOptionImplemented(
    mac_vap_stru *pst_mac_vap)
{
    return (pst_mac_vap->pst_mib_info->st_phy_hrdsss.en_dot11ShortPreambleOptionImplemented);
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_ShortPreambleOptionImplemented(
    mac_vap_stru *pst_mac_vap, wlan_11b_mib_preamble_enum_uint8 en_preamble)
{
    pst_mac_vap->pst_mib_info->st_phy_hrdsss.en_dot11ShortPreambleOptionImplemented = en_preamble;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_SpectrumManagementRequired(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.en_dot11SpectrumManagementRequired = en_val;
}


OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_ShortGIOptionInFortyImplemented(mac_vap_stru *pst_mac_vap)
{
    if (pst_mac_vap->st_channel.en_band == WLAN_BAND_2G) {
        return pst_mac_vap->pst_mib_info->st_phy_ht.en_dot112GShortGIOptionInFortyImplemented;
    } else {
        return pst_mac_vap->pst_mib_info->st_phy_ht.en_dot115GShortGIOptionInFortyImplemented;
    }
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_ShortGIOptionInFortyImplemented(
    mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_val)
{
    if (pst_mac_vap->st_channel.en_band == WLAN_BAND_2G) {
        pst_mac_vap->pst_mib_info->st_phy_ht.en_dot112GShortGIOptionInFortyImplemented = en_val;
    } else {
        pst_mac_vap->pst_mib_info->st_phy_ht.en_dot115GShortGIOptionInFortyImplemented = en_val;
    }
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_frag_threshold(mac_vap_stru *pst_mac_vap, oal_uint32 ul_frag_threshold)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11FragmentationThreshold = ul_frag_threshold;
}

OAL_STATIC OAL_INLINE oal_uint32 mac_mib_get_FragmentationThreshold(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11FragmentationThreshold;
}


OAL_STATIC OAL_INLINE oal_void mac_mib_set_rts_threshold(mac_vap_stru *pst_mac_vap, oal_uint32 ul_rts_threshold)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_operation.ul_dot11RTSThreshold = ul_rts_threshold;
}

OAL_STATIC OAL_INLINE oal_bool_enum_uint8 mac_mib_get_pre_auth_actived(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.en_dot11RSNAPreauthenticationActivated;
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_pre_auth_actived(mac_vap_stru *pst_mac_vap, oal_bool_enum_uint8 en_pre_auth)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.en_dot11RSNAPreauthenticationActivated = en_pre_auth;
}

OAL_STATIC OAL_INLINE oal_uint8 mac_mib_get_rsnacfg_ptksareplaycounters(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.st_wlan_mib_rsna_cfg.uc_dot11RSNAConfigPTKSAReplayCounters;
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_rsnacfg_ptksareplaycounters(
    mac_vap_stru *pst_mac_vap, oal_uint8 uc_ptksa_replay_counters)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.st_wlan_mib_rsna_cfg.uc_dot11RSNAConfigPTKSAReplayCounters =
        uc_ptksa_replay_counters;
}

OAL_STATIC OAL_INLINE oal_uint8 mac_mib_get_rsnacfg_gtksareplaycounters(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.st_wlan_mib_rsna_cfg.uc_dot11RSNAConfigGTKSAReplayCounters;
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_rsnacfg_gtksareplaycounters(
    mac_vap_stru *pst_mac_vap, oal_uint8 uc_gtksa_replay_counters)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.st_wlan_mib_rsna_cfg.uc_dot11RSNAConfigGTKSAReplayCounters =
        uc_gtksa_replay_counters;
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_wpa_group_suite(mac_vap_stru *pst_mac_vap, oal_uint8 uc_suite)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.st_wlan_mib_rsna_cfg.uc_wpa_group_suite = uc_suite;
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_rsn_group_suite(mac_vap_stru *pst_mac_vap, oal_uint8 uc_suite)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.st_wlan_mib_rsna_cfg.uc_rsn_group_suite = uc_suite;
}

OAL_STATIC OAL_INLINE oal_void mac_mib_set_rsn_group_mgmt_suite(mac_vap_stru *pst_mac_vap, oal_uint8 uc_suite)
{
    pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.st_wlan_mib_rsna_cfg.uc_rsn_group_mgmt_suite = uc_suite;
}

OAL_STATIC OAL_INLINE oal_uint8 mac_mib_get_wpa_group_suite(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.st_wlan_mib_rsna_cfg.uc_wpa_group_suite;
}

OAL_STATIC OAL_INLINE oal_uint8 mac_mib_get_rsn_group_suite(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.st_wlan_mib_rsna_cfg.uc_rsn_group_suite;
}

OAL_STATIC OAL_INLINE oal_uint8 mac_mib_get_rsn_group_mgmt_suite(mac_vap_stru *pst_mac_vap)
{
    return pst_mac_vap->pst_mib_info->st_wlan_mib_privacy.st_wlan_mib_rsna_cfg.uc_rsn_group_mgmt_suite;
}

/*****************************************************************************
  10 ????????
*****************************************************************************/
#ifdef _PRE_WLAN_FEATURE_MULTI_NETBUF_AMSDU
extern mac_tx_large_amsdu_ampdu_stru *mac_get_tx_large_amsdu_addr(oal_void);
#endif
extern mac_tcp_ack_buf_switch_stru *mac_get_tcp_ack_buf_switch_addr(oal_void);
extern oal_uint32 mac_vap_init(mac_vap_stru *pst_vap,
                               oal_uint8 uc_chip_id,
                               oal_uint8 uc_device_id,
                               oal_uint8 uc_vap_id,
                               mac_cfg_add_vap_param_stru *pst_param);
extern oal_void mac_vap_init_rates(mac_vap_stru *pst_vap);
extern oal_void mac_sta_init_bss_rates(mac_vap_stru *pst_vap, oal_void *pst_bss_dscr);
extern oal_void mac_vap_init_rates_by_protocol(
    mac_vap_stru *pst_vap, wlan_protocol_enum_uint8 en_vap_protocol, mac_data_rate_stru *pst_rates);
extern oal_uint32 mac_vap_exit(mac_vap_stru *pst_vap);
extern oal_uint32 mac_vap_del_user(mac_vap_stru *pst_vap, oal_uint16 us_user_idx);
extern oal_uint32 mac_vap_find_user_by_macaddr(mac_vap_stru *pst_vap,
                                               oal_uint8 *puc_sta_mac_addr,
                                               oal_uint16 *pus_user_idx);

extern oal_uint32 mac_device_find_user_by_macaddr(mac_vap_stru *pst_vap,
                                                  oal_uint8 *puc_sta_mac_addr,
                                                  oal_uint16 *pus_user_idx);

extern oal_uint32 mac_vap_add_assoc_user(mac_vap_stru *pst_vap, oal_uint16 us_user_idx);
extern oal_uint32 mac_vap_check_signal_bridge(mac_vap_stru *pst_mac_vap);

/*****************************************************************************
    mib????????
*****************************************************************************/
extern oal_uint8 mac_vap_get_bandwith(wlan_bw_cap_enum_uint8 en_dev_cap, wlan_channel_bandwidth_enum_uint8 en_bss_cap);
extern oal_uint32 mac_mib_get_beacon_period(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_len, oal_uint8 *puc_param);
extern oal_uint32 mac_mib_get_dtim_period(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_len, oal_uint8 *puc_param);
extern oal_uint32 mac_mib_get_bss_type(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_len, oal_uint8 *puc_param);
extern oal_uint32 mac_mib_get_ssid(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_len, oal_uint8 *puc_param);
extern oal_uint32 mac_mib_set_beacon_period(mac_vap_stru *pst_mac_vap, oal_uint8 uc_len, oal_uint8 *puc_param);
extern oal_uint32 mac_mib_set_dtim_period(mac_vap_stru *pst_mac_vap, oal_uint8 uc_len, oal_uint8 *puc_param);
extern oal_uint32 mac_mib_set_bss_type(mac_vap_stru *pst_mac_vap, oal_uint8 uc_len, oal_uint8 *puc_param);
extern oal_uint32 mac_mib_set_ssid(mac_vap_stru *pst_mac_vap, oal_uint8 uc_len, oal_uint8 *puc_param);
extern oal_uint32 mac_mib_set_station_id(mac_vap_stru *pst_mac_vap, oal_uint8 uc_len, oal_uint8 *puc_param);
extern oal_void mac_set_wep_key_value(
    mac_vap_stru *pst_mac_vap, oal_uint8 uc_idx, OAL_CONST oal_uint8 *puc_key, oal_uint8 uc_size);
extern wlan_ciper_protocol_type_enum_uint8 mac_get_wep_type(mac_vap_stru *pst_mac_vap, oal_uint8 uc_key_id);
extern oal_void mac_mib_init_2040(mac_vap_stru *pst_mac_vap);
extern oal_void mac_mib_init_obss_scan(mac_vap_stru *pst_mac_vap);
extern oal_void mac_mib_init_rsnacfg_suites(mac_vap_stru *pst_mac_vap);
extern oal_void mac_mib_set_wpa_pair_suites(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_suites, oal_uint8 uc_cipher_num);
extern oal_void mac_mib_set_rsn_pair_suites(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_suites, oal_uint8 uc_cipher_num);
extern oal_void mac_mib_set_wpa_akm_suites(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_suites, oal_uint8 uc_akm_num);
extern oal_void mac_mib_set_rsn_akm_suites(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_suites, oal_uint8 uc_akm_num);
extern oal_uint8 mac_mib_wpa_pair_match_suites(
    mac_vap_stru *pst_mac_vap, oal_uint8 *puc_suites, oal_uint8 uc_suite_num);
extern oal_uint8 mac_mib_rsn_pair_match_suites(
    mac_vap_stru *pst_mac_vap, oal_uint8 *puc_suites, oal_uint8 uc_suite_num);
extern oal_uint8 mac_mib_wpa_akm_match_suites(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_suites, oal_uint8 uc_suite_num);
extern oal_uint8 mac_mib_rsn_akm_match_suites(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_suites, oal_uint8 uc_suite_num);
extern oal_uint8 mac_mib_get_wpa_pair_suites(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_suites);
extern oal_uint8 mac_mib_get_rsn_pair_suites(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_suites);
extern oal_uint8 mac_mib_get_wpa_akm_suites(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_suites);
extern oal_uint8 mac_mib_get_rsn_akm_suites(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_suites);
extern oal_uint32 mac_mib_get_shpreamble(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_len, oal_uint8 *puc_param);
extern oal_uint32 mac_mib_set_shpreamble(mac_vap_stru *pst_mac_vap, oal_uint8 uc_len, oal_uint8 *puc_param);
extern oal_uint32 mac_vap_set_bssid(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_bssid);
extern oal_uint32 mac_vap_set_current_channel(
    mac_vap_stru *pst_vap, wlan_channel_band_enum_uint8 en_band, oal_uint8 uc_channel);
extern oal_uint8 mac_vap_get_curr_baserate(mac_vap_stru *pst_mac_ap, oal_uint8 uc_br_idx);
extern void mibset_rsnaclearwpapairwisecipherimplemented(mac_vap_stru *pst_vap);
extern void mibset_rsnaclearwpa2pairwisecipherimplemented(mac_vap_stru *pst_vap);
extern oal_void mac_vap_state_change(mac_vap_stru *pst_mac_vap, mac_vap_state_enum_uint8 en_vap_state);
extern oal_uint32 mac_vap_config_vht_ht_mib_by_protocol(mac_vap_stru *pst_mac_vap);
extern oal_uint32 mac_vap_init_wme_param(mac_vap_stru *pst_mac_vap);

#ifdef _PRE_WLAN_FEATURE_UAPSD
extern oal_uint32 mac_vap_set_uapsd_en(mac_vap_stru *pst_mac_vap, oal_uint8 uc_value);
extern oal_uint8 mac_vap_get_uapsd_en(mac_vap_stru *pst_mac_vap);
#endif
extern oal_uint32 mac_vap_init_by_protocol(mac_vap_stru *pst_mac_vap, wlan_protocol_enum_uint8 en_protocol);

extern oal_bool_enum_uint8 mac_vap_check_bss_cap_info_phy_ap(oal_uint16 us_cap_info, mac_vap_stru *pst_mac_vap);
extern mac_wme_param_stru *mac_get_wmm_cfg(wlan_vap_mode_enum_uint8 en_vap_mode);
extern oal_void mac_vap_get_bandwidth_cap(mac_vap_stru *pst_mac_vap, wlan_bw_cap_enum_uint8 *pen_cap);
extern oal_void mac_vap_change_mib_by_bandwidth(
    mac_vap_stru *pst_mac_vap, wlan_channel_bandwidth_enum_uint8 en_bandwidth);

extern oal_void mac_vap_init_rx_nss_by_protocol(mac_vap_stru *pst_mac_vap);
extern oal_void mac_dec_p2p_num(mac_vap_stru *pst_vap);
extern oal_void mac_inc_p2p_num(mac_vap_stru *pst_vap);
extern oal_void mac_vap_set_p2p_mode(mac_vap_stru *pst_vap, wlan_p2p_mode_enum_uint8 en_p2p_mode);
extern wlan_p2p_mode_enum_uint8 mac_get_p2p_mode(mac_vap_stru *pst_vap);
extern oal_void mac_vap_set_aid(mac_vap_stru *pst_vap, oal_uint16 us_aid);
extern oal_void mac_vap_set_uapsd_cap(mac_vap_stru *pst_vap, oal_uint8 uc_uapsd_cap);
extern oal_void mac_vap_set_assoc_id(mac_vap_stru *pst_vap, oal_uint8 uc_assoc_vap_id);
extern oal_void mac_vap_set_tx_power(mac_vap_stru *pst_vap, oal_uint8 uc_tx_power);
extern oal_void mac_vap_set_al_tx_flag(mac_vap_stru *pst_vap, oal_bool_enum_uint8 en_flag);
extern oal_void mac_vap_set_al_tx_first_run(mac_vap_stru *pst_vap, oal_bool_enum_uint8 en_flag);
extern oal_void mac_vap_set_al_tx_payload_flag(mac_vap_stru *pst_vap, oal_uint8 uc_paylod);
extern oal_uint32 mac_dump_protection(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_param);
extern oal_void mac_vap_set_multi_user_idx(mac_vap_stru *pst_vap, oal_uint16 us_multi_user_idx);
#ifdef _PRE_WLAN_FEATURE_STA_PM
extern oal_void mac_vap_set_uapsd_para(mac_vap_stru *pst_mac_vap, mac_cfg_uapsd_sta_stru *pst_uapsd_info);
#endif
extern oal_void mac_vap_set_wmm_params_update_count(mac_vap_stru *pst_vap, oal_uint8 uc_update_count);
extern oal_void mac_vap_set_rifs_tx_on(mac_vap_stru *pst_vap, oal_uint8 uc_value);
extern oal_void mac_vap_set_11ac2g(mac_vap_stru *pst_vap, oal_uint8 uc_value);
extern oal_void mac_vap_set_hide_ssid(mac_vap_stru *pst_vap, oal_uint8 uc_value);
extern oal_uint8 mac_vap_get_peer_obss_scan(mac_vap_stru *pst_vap);
extern oal_void mac_vap_set_peer_obss_scan(mac_vap_stru *pst_vap, oal_uint8 uc_value);
extern oal_void hmac_vap_clear_app_ie(mac_vap_stru *pst_mac_vap, en_app_ie_type_uint8 en_type);
extern oal_uint32 mac_vap_clear_app_ie(mac_vap_stru *pst_mac_vap, en_app_ie_type_uint8 en_type);
extern oal_uint32 mac_vap_save_app_ie(
    mac_vap_stru *pst_mac_vap, oal_app_ie_stru *pst_app_ie, en_app_ie_type_uint8 en_type);
extern oal_void mac_vap_set_rx_nss(mac_vap_stru *pst_vap, oal_uint8 uc_rx_nss);

extern oal_uint32 mac_vap_init_privacy(mac_vap_stru *pst_mac_vap,
                                       mac_cfg80211_connect_security_stru *pst_mac_security_param);

extern oal_void mac_mib_set_wep(mac_vap_stru *pst_mac_vap, oal_uint8 uc_key_id);
extern oal_uint32 mac_check_group_policy(mac_vap_stru *pst_mac_vap, oal_uint8 uc_grp_policy,
                                         oal_uint8 uc_80211i_mode);
extern oal_uint32 mac_check_auth_policy(mac_vap_stru *pst_mac_vap, oal_uint8 *auc_auth_policy,
                                        oal_uint8 uc_80211i_mode);
extern mac_user_stru *mac_vap_get_user_by_addr(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_mac_addr);
extern oal_uint32 mac_vap_add_key(
    mac_vap_stru *pst_mac_vap, mac_user_stru *pst_mac_user, oal_uint8 uc_key_id, mac_key_params_stru *pst_key);
extern oal_uint8 mac_vap_get_default_key_id(mac_vap_stru *pst_mac_vap);
extern oal_uint32 mac_vap_set_default_key(mac_vap_stru *pst_mac_vap, oal_uint8 uc_key_index);
extern oal_uint32 mac_vap_set_default_mgmt_key(mac_vap_stru *pst_mac_vap, oal_uint8 uc_key_index);
extern void mac_vap_init_user_security_port(mac_vap_stru *pst_mac_vap,
                                            mac_user_stru *pst_mac_user);
extern oal_uint32 mac_vap_set_beacon(mac_vap_stru *pst_mac_vap, mac_beacon_param_stru *pst_beacon_param);
extern oal_uint8 *mac_vap_get_mac_addr(mac_vap_stru *pst_mac_vap);
#ifdef _PRE_WLAN_FEATURE_11R
extern oal_uint32 mac_mib_init_ft_cfg(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_mde);
extern oal_uint32 mac_mib_get_md_id(mac_vap_stru *pst_mac_vap, oal_uint16 *pus_mdid);
#endif  // _PRE_WLAN_FEATURE_11R
extern oal_switch_enum_uint8 mac_vap_protection_autoprot_is_enabled(mac_vap_stru *pst_mac_vap);
extern wlan_prot_mode_enum_uint8 mac_vap_get_user_protection_mode(
    mac_vap_stru *pst_mac_vap_sta, mac_user_stru *pst_mac_user);
extern oal_void mac_protection_set_rts_tx_param(
    mac_vap_stru *pst_mac_vap, oal_switch_enum_uint8 en_flag,
    wlan_prot_mode_enum_uint8 en_prot_mode, mac_cfg_rts_tx_param_stru *pst_rts_tx_param);

extern oal_bool_enum mac_protection_lsigtxop_check(mac_vap_stru *pst_mac_vap);
extern oal_void mac_protection_set_lsig_txop_mechanism(mac_vap_stru *pst_mac_vap, oal_switch_enum_uint8 en_flag);

#ifdef _PRE_WLAN_FEATURE_VOWIFI
extern oal_uint32 mac_vap_set_vowifi_param(
    mac_vap_stru *pst_mac_vap, mac_vowifi_cmd_enum_uint8 en_vowifi_cfg_cmd, oal_uint8 uc_value);
#endif /* _PRE_WLAN_FEATURE_VOWIFI */

extern oal_rom_cb_result_enum_uint8 mac_vap_init_cb(mac_vap_stru *pst_vap,
                                                    oal_uint8 uc_chip_id,
                                                    oal_uint8 uc_device_id,
                                                    oal_uint8 uc_vap_id,
                                                    mac_cfg_add_vap_param_stru *pst_param,
                                                    oal_uint32 *pul_cb_ret);
extern oal_rom_cb_result_enum_uint8 mac_vap_init_privacy_cb(mac_vap_stru *pst_mac_vap,
                                                            mac_cfg80211_connect_security_stru *pst_mac_security_param,
                                                            oal_uint32 *pul_ret);

extern oal_rom_cb_result_enum_uint8 mac_vap_set_beacon_cb(mac_vap_stru *pst_mac_vap,
                                                          mac_beacon_param_stru *pst_beacon_param,
                                                          oal_uint32 *pul_ret);
extern oal_rom_cb_result_enum_uint8 mac_vap_del_user_cb(mac_vap_stru *pst_vap,
                                                        oal_uint16 us_user_idx,
                                                        oal_uint32 *pul_ret);
extern oal_void mac_vap_disable_amsdu_ampdu(mac_vap_stru *pst_mac_vap);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of mac_vap.h */
