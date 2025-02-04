


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "wlan_types.h"

#include "oal_net.h"
#include "oal_cfg80211.h"
#include "oal_ext_if.h"
#include "frw_ext_if.h"

#include "dmac_ext_if.h"

#include "mac_device.h"
#include "mac_vap.h"
#include "mac_ie.h"
#include "mac_resource.h"

#include "hmac_device.h"
#include "hmac_resource.h"
#include "hmac_ext_if.h"
#include "hmac_vap.h"
#include "hmac_p2p.h"

#include "wal_linux_cfg80211.h"
#include "wal_linux_scan.h"
#include "wal_linux_event.h"
#include "wal_main.h"
#include "wal_ext_if.h"
#include "wal_config.h"
#include "wal_regdb.h"
#include "wal_linux_ioctl.h"

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)&&(_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include "plat_pm_wlan.h"
#include "wal_linux_cfgvendor.h"
#endif
#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
#include "hisi_customize_wifi.h"
#endif

#undef  THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_WAL_LINUX_CFG80211_C

/*****************************************************************************
  2 ????????????
*****************************************************************************/
extern oal_uint32 band_5g_enabled;
#ifdef _PRE_WLAN_FEATURE_DFR
extern  hmac_dfr_info_stru    g_st_dfr_info;
#endif // _PRE_WLAN_FEATURE_DFR
#define hi1151_a_rates           (hi1151_rates + 4)
#define hi1151_a_rates_size      8
#define hi1151_g_rates           (hi1151_rates + 0)
#define hi1151_g_rates_size      12

/* ?????????????? */
OAL_STATIC oal_ieee80211_rate hi1151_rates[] = {
    RATETAB_ENT(10,  0x1,   0),
    RATETAB_ENT(20,  0x2,   0),
    RATETAB_ENT(55,  0x4,   0),
    RATETAB_ENT(110, 0x8,   0),
    RATETAB_ENT(60,  0x10,  0),
    RATETAB_ENT(90,  0x20,  0),
    RATETAB_ENT(120, 0x40,  0),
    RATETAB_ENT(180, 0x80,  0),
    RATETAB_ENT(240, 0x100, 0),
    RATETAB_ENT(360, 0x200, 0),
    RATETAB_ENT(480, 0x400, 0),
    RATETAB_ENT(540, 0x800, 0),
};

/* 2.4G ???? */
OAL_STATIC oal_ieee80211_channel hi1151_2ghz_channels[] = {
    CHAN2G(1, 2412, 0),
    CHAN2G(2, 2417, 0),
    CHAN2G(3, 2422, 0),
    CHAN2G(4, 2427, 0),
    CHAN2G(5, 2432, 0),
    CHAN2G(6, 2437, 0),
    CHAN2G(7, 2442, 0),
    CHAN2G(8, 2447, 0),
    CHAN2G(9, 2452, 0),
    CHAN2G(10, 2457, 0),
    CHAN2G(11, 2462, 0),
    CHAN2G(12, 2467, 0),
    CHAN2G(13, 2472, 0),
    CHAN2G(14, 2484, 0),
};

/* 5G ???? */
OAL_STATIC oal_ieee80211_channel hi1151_5ghz_channels[] = {
    CHAN5G(36, 0),
    CHAN5G(40, 0),
    CHAN5G(44, 0),
    CHAN5G(48, 0),
    CHAN5G(52, 0),
    CHAN5G(56, 0),
    CHAN5G(60, 0),
    CHAN5G(64, 0),
    CHAN5G(100, 0),
    CHAN5G(104, 0),
    CHAN5G(108, 0),
    CHAN5G(112, 0),
    CHAN5G(116, 0),
    CHAN5G(120, 0),
    CHAN5G(124, 0),
    CHAN5G(128, 0),
    CHAN5G(132, 0),
    CHAN5G(136, 0),
    CHAN5G(140, 0),
    CHAN5G(144, 0),
    CHAN5G(149, 0),
    CHAN5G(153, 0),
    CHAN5G(157, 0),
    CHAN5G(161, 0),
    CHAN5G(165, 0),
    /* 4.9G */
    CHAN4_9G(184, 0),
    CHAN4_9G(188, 0),
    CHAN4_9G(192, 0),
    CHAN4_9G(196, 0),
};

/* ?????????????????? */
OAL_STATIC const oal_uint32 hi1151_cipher_suites[] = {
    WLAN_CIPHER_SUITE_WEP40,
    WLAN_CIPHER_SUITE_WEP104,
    WLAN_CIPHER_SUITE_TKIP,
    WLAN_CIPHER_SUITE_CCMP,
    WLAN_CIPHER_SUITE_AES_CMAC,
    WLAN_CIPHER_SUITE_SMS4,
};

extern OAL_CONST wal_ioctl_mode_map_stru g_ast_mode_map[];
oal_workqueue_stru *g_pst_del_virtual_inf_workqueue = OAL_PTR_NULL;

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)

/* 2.4G ???????? */
oal_ieee80211_supported_band hi1151_band_2ghz = {
    .channels   = hi1151_2ghz_channels,
    .n_channels = sizeof(hi1151_2ghz_channels)/sizeof(oal_ieee80211_channel),
    .bitrates   = hi1151_g_rates,
    .n_bitrates = hi1151_g_rates_size,
    .ht_cap = {
        .ht_supported = OAL_TRUE,
        .cap = IEEE80211_HT_CAP_SUP_WIDTH_20_40 | IEEE80211_HT_CAP_SGI_20 | IEEE80211_HT_CAP_SGI_40,
    },
};

/* 5G ???????? */
OAL_STATIC oal_ieee80211_supported_band hi1151_band_5ghz = {
    .channels   = hi1151_5ghz_channels,
    .n_channels = sizeof(hi1151_5ghz_channels)/sizeof(oal_ieee80211_channel),
    .bitrates   = hi1151_a_rates,
    .n_bitrates = hi1151_a_rates_size,
    .ht_cap = {
        .ht_supported = OAL_TRUE,
        .cap = IEEE80211_HT_CAP_SUP_WIDTH_20_40 | IEEE80211_HT_CAP_SGI_20 | IEEE80211_HT_CAP_SGI_40,
    },
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0))
    .vht_cap = {
        .vht_supported = OAL_TRUE,
        .cap = IEEE80211_VHT_CAP_SHORT_GI_80 | IEEE80211_VHT_CAP_HTC_VHT,
    },
#endif
};

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44))
#ifdef _PRE_WLAN_FEATURE_P2P
OAL_STATIC oal_ieee80211_iface_limit sta_p2p_limits[] = {
    {
    .max = 2,
    .types = BIT(NL80211_IFTYPE_STATION),
    },
    {
    .max = 2,
    .types = BIT(NL80211_IFTYPE_P2P_GO) | BIT(NL80211_IFTYPE_P2P_CLIENT),
    },
    {
    .max = 1,
    .types = BIT(NL80211_IFTYPE_P2P_DEVICE),
    },
};

OAL_STATIC oal_ieee80211_iface_combination
sta_p2p_iface_combinations[] = {
    {
    .num_different_channels = 2,
    .max_interfaces = 3,
    .limits = sta_p2p_limits,
    .n_limits = OAL_ARRAY_SIZE(sta_p2p_limits),
    },
};

#else  /* ??p2p???? */
/* E5??????????????????vap */
OAL_STATIC oal_ieee80211_iface_limit ap_dbac_limits[] = {
    {
    .max = 2,
    .types = BIT(NL80211_IFTYPE_AP),
    },
    {
    .max = 1,
    .types = BIT(NL80211_IFTYPE_STATION),
    },
};

OAL_STATIC oal_ieee80211_iface_combination
ap_dbac_iface_combinations[] = {
    {
    .num_different_channels = 2,
    .max_interfaces = 2,
    .limits = ap_dbac_limits,
    .n_limits = OAL_ARRAY_SIZE(ap_dbac_limits),
    },
};
#endif

/* There isn't a lot of sense in it, but you can transmit anything you like */
static const struct ieee80211_txrx_stypes
wal_cfg80211_default_mgmt_stypes[NUM_NL80211_IFTYPES] = {
    [NL80211_IFTYPE_ADHOC] = {
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ACTION >> 4)
    },
    [NL80211_IFTYPE_STATION] = {
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
        BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
    },
    [NL80211_IFTYPE_AP] = {
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
        BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
        BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
        BIT(IEEE80211_STYPE_DISASSOC >> 4) |
        BIT(IEEE80211_STYPE_AUTH >> 4) |
        BIT(IEEE80211_STYPE_DEAUTH >> 4) |
        BIT(IEEE80211_STYPE_ACTION >> 4)
    },
    [NL80211_IFTYPE_AP_VLAN] = {
        /* copy AP */
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
        BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
        BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
        BIT(IEEE80211_STYPE_DISASSOC >> 4) |
        BIT(IEEE80211_STYPE_AUTH >> 4) |
        BIT(IEEE80211_STYPE_DEAUTH >> 4) |
        BIT(IEEE80211_STYPE_ACTION >> 4)
    },
    [NL80211_IFTYPE_P2P_CLIENT] = {
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
        BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
    },
    [NL80211_IFTYPE_P2P_GO] = {
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
        BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
        BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
        BIT(IEEE80211_STYPE_DISASSOC >> 4) |
        BIT(IEEE80211_STYPE_AUTH >> 4) |
        BIT(IEEE80211_STYPE_DEAUTH >> 4) |
        BIT(IEEE80211_STYPE_ACTION >> 4)
    },
#if defined(_PRE_WLAN_FEATURE_P2P)
    [NL80211_IFTYPE_P2P_DEVICE] = {
        .tx = 0xffff,
        .rx = BIT(IEEE80211_STYPE_ACTION >> 4) |
        BIT(IEEE80211_STYPE_PROBE_REQ >> 4)
    },
#endif /* WL_CFG80211_P2P_DEV_IF */
};

#endif   /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44) */

#elif (_PRE_OS_VERSION_WIN32 == _PRE_OS_VERSION)

/* 2.4G ???????? */
OAL_STATIC struct ieee80211_supported_band hi1151_band_2ghz = {
    hi1151_2ghz_channels,
    hi1151_g_rates,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0))
    NL80211_BAND_2GHZ,
#else
    IEEE80211_BAND_2GHZ,
#endif
    sizeof(hi1151_2ghz_channels)/sizeof(oal_ieee80211_channel),
    hi1151_g_rates_size,
    {
        IEEE80211_HT_CAP_SUP_WIDTH_20_40 | IEEE80211_HT_CAP_SGI_20 | IEEE80211_HT_CAP_SGI_40,
        OAL_TRUE,
    },
};

/* 5G ???????? */
OAL_STATIC oal_ieee80211_supported_band hi1151_band_5ghz = {
    hi1151_5ghz_channels,
    hi1151_a_rates,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0))
    NL80211_BAND_5GHZ,
#else
    IEEE80211_BAND_5GHZ,
#endif
    sizeof(hi1151_5ghz_channels)/sizeof(oal_ieee80211_channel),
    hi1151_a_rates_size,
    {
        IEEE80211_HT_CAP_SUP_WIDTH_20_40 | IEEE80211_HT_CAP_SGI_20 | IEEE80211_HT_CAP_SGI_40,
        OAL_TRUE,
    },
};
#endif

oal_uint8               g_uc_cookie_array_bitmap = 0;   /* ????bit ????cookie array ????????????1 - ????????0 - ?????? */
cookie_arry_stru        g_cookie_array[WAL_COOKIE_ARRAY_SIZE];

/*****************************************************************************
  3 ????????
*****************************************************************************/
#ifdef _PRE_WLAN_FEATURE_UAPSD

OAL_STATIC oal_bool_enum_uint8 wal_find_wmm_uapsd(oal_uint8 *puc_wmm_ie)
{

    /* ???? WMM UAPSD ???????? */
    if (puc_wmm_ie[1] < MAC_WMM_QOS_INFO_POS)
    {
        return OAL_FALSE;
    }

    if (puc_wmm_ie[MAC_WMM_QOS_INFO_POS] & BIT7)
    {
        return OAL_TRUE;
    }
    return OAL_FALSE;
}
#endif


oal_uint32 wal_cfg80211_open_wmm(mac_vap_stru *pst_mac_vap, oal_uint16 us_len, oal_uint8 *puc_param)
{
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mac_vap || OAL_PTR_NULL == puc_param))
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_open_wmm::pst_mac_vap/puc_param is null ptr!}\r\n");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ????????vap?????? */
    if (WLAN_VAP_MODE_CONFIG == pst_mac_vap->en_vap_mode)
    {
        OAM_WARNING_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_CFG, "{wal_cfg80211_open_wmm::this is config vap! can't get info.}");
        return OAL_FAIL;
    }

    return hmac_config_sync_cmd_common(pst_mac_vap, WLAN_CFGID_WMM_SWITCH, us_len, puc_param);
}


oal_uint32 wal_parse_rsn_ie(const oal_uint8 *puc_ie, mac_beacon_param_stru *pst_beacon_param)
{
    oal_uint8                    uc_index               = 0;
    oal_uint16                   us_temp                = 0;
    oal_uint16                   us_ver                 = 0;
    oal_uint16                   us_pcip_num            = 0;
    oal_uint16                   us_auth_num            = 0;
    oal_uint8                   *puc_oui                = OAL_PTR_NULL;
    oal_uint8                   *puc_grp_policy         = OAL_PTR_NULL;
    oal_uint8                   *puc_pcip_policy        = OAL_PTR_NULL;
    oal_uint8                   *puc_auth_policy        = OAL_PTR_NULL;

    /*************************************************************************/
    /*                  RSN Element Format                                   */
    /* --------------------------------------------------------------------- */
    /* |Element ID | Length | Version | Group Cipher Suite | Pairwise Cipher */
    /* --------------------------------------------------------------------- */
    /* |     1     |    1   |    2    |         4          |       2         */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* Suite Count| Pairwise Cipher Suite List | AKM Suite Count | AKM Suite List */
    /* --------------------------------------------------------------------- */
    /*            |         4*m                |     2           |   4*n     */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* |RSN Capabilities|PMKID Count|PMKID List|Group Management Cipher Suite*/
    /* --------------------------------------------------------------------- */
    /* |        2       |    2      |   16 *s  |               4           | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/

    puc_grp_policy  = &(pst_beacon_param->uc_group_crypto);
    puc_pcip_policy = pst_beacon_param->auc_pairwise_crypto_wpa2;
    puc_auth_policy = pst_beacon_param->auc_auth_type;

    puc_oui = g_auc_rsn_oui;

    /* ??????????2???????????????????? */
    if (puc_ie[1] < MAC_MIN_RSN_LEN)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_parse_rsn_ie::invalid RSN IE len[%d]!}\r\n", puc_ie[1]);
        return OAL_FAIL;
    }

    /* ???? RSN IE ?? IE ???? */
    uc_index += 2;

    /* ????RSN ?????? */
    us_ver = OAL_MAKE_WORD16(puc_ie[uc_index], puc_ie[uc_index + 1]);
    if (MAC_RSN_IE_VERSION != us_ver)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_parse_rsn_ie::RSN version illegal!}\r\n");
        return OAL_FAIL;
    }

    /* ???? RSN ?????????? */
    uc_index += 2;

    /* ???????????????? */
    if (0 != oal_memcmp(puc_oui, puc_ie + uc_index, MAC_OUI_LEN))
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_parse_rsn_ie::RSN group OUI illegal!}\r\n");
        return OAL_FAIL;
    }
    *puc_grp_policy = puc_ie[uc_index + MAC_OUI_LEN];

    /* ???? ???????????? ???? */
    uc_index += 4;

    /* ???????????????? */
    us_pcip_num = OAL_MAKE_WORD16(puc_ie[uc_index] ,puc_ie[uc_index+1]);
    if (us_pcip_num > MAC_PAIRWISE_CIPHER_SUITES_NUM)
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_parse_rsn_ie::pairwise chiper num illegal!}\r\n", us_pcip_num);
        return OAL_FAIL;
    }

    /*??????????????????0xff*/
    oal_memset(puc_pcip_policy, 0xff, MAC_PAIRWISE_CIPHER_SUITES_NUM);

    uc_index += 2;
    for (us_temp = 0; us_temp < us_pcip_num; us_temp++)
    {
        if (0 != oal_memcmp(puc_oui, puc_ie + uc_index, MAC_OUI_LEN))
        {
            OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_parse_rsn_ie::RSN paerwise OUI illegal!}\r\n");
            return OAL_FAIL;
        }
        puc_pcip_policy[us_temp] = puc_ie[uc_index + MAC_OUI_LEN];

        uc_index += 4;
    }

    /* ???????????????? */
    us_auth_num = OAL_MAKE_WORD16(puc_ie[uc_index], puc_ie[uc_index+1]);
    us_auth_num = OAL_MIN(us_auth_num, WLAN_AUTHENTICATION_SUITES);
    uc_index += 2;

    /*??????????????????0xff*/
    oal_memset(puc_auth_policy, 0xff, us_auth_num);

    /* ???????????? */
    for (us_temp = 0; us_temp < us_auth_num; us_temp++)
    {
        if (0 != oal_memcmp(puc_oui, puc_ie + uc_index, MAC_OUI_LEN))
        {
            OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_parse_rsn_ie::RSN auth OUI illegal!}\r\n");
            return OAL_FAIL;
        }
        puc_auth_policy[us_temp] = puc_ie[uc_index + MAC_OUI_LEN];
        uc_index += 4;
    }

    /* ????RSN ???????? */
    pst_beacon_param->us_rsn_capability = OAL_MAKE_WORD16(puc_ie[uc_index] ,puc_ie[uc_index+1]);

    /* ???????????? */
    pst_beacon_param->uc_crypto_mode |= WLAN_WPA2_BIT;

    return OAL_SUCC;
}


oal_uint32 wal_parse_wpa_ie(oal_uint8 *puc_ie, mac_beacon_param_stru *pst_beacon_param)
{
    oal_uint8                    uc_index               = 0;
    oal_uint16                   us_temp                = 0;
    oal_uint16                   us_ver                 = 0;
    oal_uint16                   us_pcip_num            = 0;
    oal_uint16                   us_auth_num            = 0;
    oal_uint8                   *puc_oui                = OAL_PTR_NULL;
    oal_uint8                   *puc_pcip_policy        = OAL_PTR_NULL;
    oal_uint8                   *puc_grp_policy         = OAL_PTR_NULL;
    oal_uint8                   *puc_auth_policy        = OAL_PTR_NULL;

    /*************************************************************************/
    /*                  WPA Element Format                                   */
    /* --------------------------------------------------------------------- */
    /* |Element ID | Length |    WPA OUI    |  Version |  Group Cipher Suite */
    /* --------------------------------------------------------------------- */
    /* |     1     |   1    |        4      |     2    |         4           */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* Pairwise Cipher |  Pairwise Cipher   |                 |              */
    /* Suite Count     |    Suite List      | AKM Suite Count |AKM Suite List*/
    /* --------------------------------------------------------------------- */
    /*        2        |          4*m       |         2       |     4*n      */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/

    puc_oui = g_auc_wpa_oui;

    puc_grp_policy  = &(pst_beacon_param->uc_group_crypto);
    puc_pcip_policy = pst_beacon_param->auc_pairwise_crypto_wpa;
    puc_auth_policy = pst_beacon_param->auc_auth_type;

    /* ???? WPA IE(1 ????) ??IE ????(1 ????) ??WPA OUI(4 ????)  */
    uc_index = 2 + 4;

    us_ver = OAL_MAKE_WORD16(puc_ie[uc_index], puc_ie[uc_index + 1]);
    /* ????WPA ???????? */
    if (MAC_WPA_IE_VERSION != us_ver)
    {
        OAM_ERROR_LOG0(0, OAM_SF_WPA, "{wal_parse_wpa_ie::WPA version illegal!}\r\n");
        return OAL_FAIL;
    }

    /* ???? ?????? ???? */
    uc_index += 2;

    /* ???????????????? */
    if (0 != oal_memcmp(puc_oui, puc_ie + uc_index, MAC_OUI_LEN))
    {
        OAM_ERROR_LOG0(0, OAM_SF_WPA, "{wal_parse_wpa_ie::WPA group OUI illegal!}\r\n");
        return OAL_FAIL;
    }
    *puc_grp_policy = puc_ie[uc_index + MAC_OUI_LEN];

    /* ???????????????????? */
    uc_index += 4;

    /* ???????????????? */
    us_pcip_num = OAL_MAKE_WORD16(puc_ie[uc_index], puc_ie[uc_index+1]);

    if (us_pcip_num > MAC_PAIRWISE_CIPHER_SUITES_NUM)
    {
        OAM_ERROR_LOG1(0, OAM_SF_WPA, "{wal_parse_wpa_ie::pairwise chiper num illegal %d!}\r\n", us_pcip_num);
        return OAL_FAIL;
    }

    /*??????????????????0xff*/
    oal_memset(puc_pcip_policy, 0xff, MAC_PAIRWISE_CIPHER_SUITES_NUM);

    uc_index += 2;
    for (us_temp = 0; us_temp < us_pcip_num; us_temp++)
    {
        if (0 != oal_memcmp(puc_oui, puc_ie + uc_index, MAC_OUI_LEN))
        {
            OAM_ERROR_LOG0(0, OAM_SF_WPA, "{wal_parse_wpa_ie::WPA pairwise OUI illegal!}\r\n");
            return OAL_FAIL;
        }
        puc_pcip_policy[us_temp] = puc_ie[uc_index + MAC_OUI_LEN];
        uc_index += 4;
    }

    /* ???????????????? */
    us_auth_num = OAL_MAKE_WORD16(puc_ie[uc_index], puc_ie[uc_index+1]);
    us_auth_num = OAL_MIN(us_auth_num, WLAN_AUTHENTICATION_SUITES);
    uc_index += 2;

    /*??????????????????0xff*/
    oal_memset(puc_auth_policy, 0xff, us_auth_num);

    /* ???????????? */
    for (us_temp = 0; us_temp < us_auth_num; us_temp++)
    {
        if (0 != oal_memcmp(puc_oui, puc_ie + uc_index, MAC_OUI_LEN))
        {
            OAM_ERROR_LOG0(0, OAM_SF_WPA, "{wal_parse_wpa_ie::WPA auth OUI illegal!}\r\n");
            return OAL_FAIL;
        }
        puc_auth_policy[us_temp] = puc_ie[uc_index + MAC_OUI_LEN];
        uc_index += 4;
    }

    /* ???????????? */
    pst_beacon_param->uc_crypto_mode |= WLAN_WPA_BIT;

    return OAL_SUCC;
}


oal_uint32 wal_parse_wpa_wpa2_ie(oal_beacon_parameters *pst_beacon_info,
                                 mac_beacon_param_stru *pst_beacon_param)
{

    const oal_uint8         *puc_rsn_ie;
    oal_uint8               *puc_wpa_ie;
    oal_uint32               ul_ret = OAL_SUCC;
    oal_ieee80211_mgmt      *pst_mgmt             = OAL_PTR_NULL;
    oal_uint16               us_capability_info = 0;

    /* ???????????? */
    pst_mgmt = (oal_ieee80211_mgmt *)pst_beacon_info->head;

    us_capability_info = pst_mgmt->u.beacon.capab_info;
    pst_beacon_param->en_privacy = OAL_FALSE;

    if (WLAN_WITP_CAPABILITY_PRIVACY & us_capability_info)
    {
        pst_beacon_param->en_privacy = OAL_TRUE;

        /* ???? RSN ???????? */
        puc_rsn_ie = mac_find_ie(MAC_EID_RSN, pst_beacon_info->tail, pst_beacon_info->tail_len);
        if (OAL_PTR_NULL != puc_rsn_ie)
        {
            /* ????RSN ?????????????????????? */
            ul_ret = wal_parse_rsn_ie(puc_rsn_ie, pst_beacon_param);
            if (OAL_SUCC != ul_ret)
            {
                OAM_WARNING_LOG0(0, OAM_SF_WPA, "{wal_parse_wpa_wpa2_ie::Failed to parse RSN ie!}\r\n");
                return OAL_FAIL;
            }
        }

        /* ???? WPA ?????????????????????????? */
        puc_wpa_ie = mac_find_vendor_ie(MAC_WLAN_OUI_MICROSOFT, MAC_OUITYPE_WPA, pst_beacon_info->tail, pst_beacon_info->tail_len);
        if (OAL_PTR_NULL != puc_wpa_ie)
        {
            ul_ret = wal_parse_wpa_ie(puc_wpa_ie, pst_beacon_param);
            if (OAL_SUCC != ul_ret)
            {
                OAM_WARNING_LOG0(0, OAM_SF_WPA, "{wal_parse_wpa_wpa2_ie::Failed to parse WPA ie!}\r\n");
                return OAL_FAIL;
            }
        }
    }

    return OAL_SUCC;
}


oal_uint32 wal_parse_wmm_ie(oal_net_device_stru *pst_dev,
                                   mac_vap_stru *pst_mac_vap, oal_beacon_parameters *pst_beacon_info)
{
    oal_uint8               *puc_wmm_ie;
    oal_uint16               us_len = OAL_SIZEOF(oal_uint8);
    oal_uint8                uc_wmm = OAL_TRUE;
    oal_uint32               ul_ret = OAL_SUCC;

#ifdef _PRE_WLAN_FEATURE_UAPSD
    oal_uint8    uc_uapsd = OAL_TRUE;
    wal_msg_write_stru    st_write_msg;
#endif

    /*  ????wmm_ie  */
    puc_wmm_ie = mac_find_vendor_ie(MAC_WLAN_OUI_MICROSOFT, MAC_WLAN_OUI_TYPE_MICROSOFT_WMM,
                                            pst_beacon_info->tail, pst_beacon_info->tail_len);

    if (OAL_PTR_NULL == puc_wmm_ie)
    {
    /* wmm ie??????????????wmm ?? */
        uc_wmm = OAL_FALSE;
    }
#ifdef _PRE_WLAN_FEATURE_UAPSD
    /*  ????wmm ie????????????uapsd???????? */
    else
    {
        if(OAL_FALSE == wal_find_wmm_uapsd(puc_wmm_ie))
        {
        /* ????UAPSD ??*/
            uc_uapsd = OAL_FALSE;
            OAM_WARNING_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_CFG, "{wal_parse_wmm_ie::uapsd is disabled!!}");
        }

        /* ???? msg ??????*/
        WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_UAPSD_EN, OAL_SIZEOF(oal_uint32));

        /* ???? msg ?????? */
 #if defined(_PRE_PRODUCT_ID_HI110X_HOST)
        uc_uapsd = OAL_FALSE;
 #endif
        oal_memcopy(st_write_msg.auc_value, &uc_uapsd, OAL_SIZEOF(oal_uint32));

        /* ???????? */
        ul_ret = (oal_uint32)wal_send_cfg_event(pst_dev,
                                   WAL_MSG_TYPE_WRITE,
                                   WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(oal_uint32),
                                   (oal_uint8 *)&st_write_msg,
                                   OAL_FALSE,
                                   OAL_PTR_NULL);

        if (OAL_UNLIKELY(OAL_SUCC != ul_ret))
        {
            ul_ret = OAL_FAIL;
            OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_CFG, "{wal_parse_wmm_ie::uapsd switch set failed[%d].}",ul_ret);
        }
    }
#endif
    /*  wmm ????/???? ????  */
    ul_ret = wal_cfg80211_open_wmm(pst_mac_vap, us_len, &uc_wmm);
    if (OAL_SUCC != ul_ret)
    {
        ul_ret = OAL_FAIL;
        OAM_WARNING_LOG0(0, OAM_SF_TX, "{wal_parse_wmm_ie::can not open wmm!}\r\n");
    }

    return ul_ret;
}


#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)


oal_uint32 wal_cfg80211_add_vap(mac_cfg_add_vap_param_stru *pst_add_vap_param)
{
    
    oal_int32                   l_ret;
    oal_net_device_stru        *pst_net_dev;
    oal_net_device_stru        *pst_cfg_net_dev;
    wal_msg_write_stru          st_write_msg;
    wal_msg_stru               *pst_rsp_msg = OAL_PTR_NULL;
    oal_uint32                  ul_err_code;

    oal_wireless_dev_stru      *pst_wdev;
    mac_wiphy_priv_stru        *pst_wiphy_priv;

    mac_vap_stru               *pst_cfg_mac_vap;
    hmac_vap_stru              *pst_cfg_hmac_vap;
    mac_device_stru            *pst_mac_device;
    wlan_vap_mode_enum_uint8    en_vap_mode;
#ifdef _PRE_WLAN_FEATURE_P2P
    wlan_p2p_mode_enum_uint8    en_p2p_mode = WLAN_LEGACY_VAP_MODE;
    en_p2p_mode = pst_add_vap_param->en_p2p_mode;
#endif

    en_vap_mode = pst_add_vap_param->en_vap_mode;

    /* ????mac device */
    pst_net_dev     = pst_add_vap_param->pst_net_dev;
    pst_wdev        = pst_net_dev->ieee80211_ptr;
    pst_wiphy_priv  = (mac_wiphy_priv_stru *)oal_wiphy_priv(pst_wdev->wiphy);
    pst_mac_device  = pst_wiphy_priv->pst_mac_device;
    pst_cfg_mac_vap = (mac_vap_stru *)mac_res_get_mac_vap(pst_mac_device->uc_cfg_vap_id);
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_cfg_mac_vap))
    {
        OAM_WARNING_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_add_vap::pst_cfg_mac_vap is null mac_vap:%d!}\r\n",pst_mac_device->uc_cfg_vap_id);
        return OAL_ERR_CODE_PTR_NULL;
    }
    pst_cfg_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_device->uc_cfg_vap_id);
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_cfg_hmac_vap))
    {
        OAM_WARNING_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_add_vap::pst_cfg_hmac_vap is null vap_id:%d!}\r\n",pst_mac_device->uc_cfg_vap_id);
        return OAL_ERR_CODE_PTR_NULL;
    }
    pst_cfg_net_dev = pst_cfg_hmac_vap->pst_net_device;
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mac_device))
    {
        OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_add_vap::pst_mac_device is null ptr!}\r\n");
        return OAL_ERR_CODE_PTR_NULL;
    }


    if (WLAN_VAP_MODE_BSS_AP == en_vap_mode)
    {
        pst_wdev->iftype = NL80211_IFTYPE_AP;
    }
    else if (WLAN_VAP_MODE_BSS_STA == en_vap_mode)
    {
        pst_wdev->iftype = NL80211_IFTYPE_STATION;
    }
#ifdef _PRE_WLAN_FEATURE_P2P
    if (WLAN_P2P_DEV_MODE == en_p2p_mode)
    {
        pst_wdev->iftype = NL80211_IFTYPE_P2P_DEVICE;
    }
    else if (WLAN_P2P_CL_MODE == en_p2p_mode)
    {
        pst_wdev->iftype = NL80211_IFTYPE_P2P_CLIENT;
    }
    else if (WLAN_P2P_GO_MODE == en_p2p_mode)
    {
        pst_wdev->iftype = NL80211_IFTYPE_P2P_GO;
    }
#endif  /* _PRE_WLAN_FEATURE_P2P */

    OAL_NETDEVICE_FLAGS(pst_net_dev) &= ~OAL_IFF_RUNNING;   /* ??net device??flag????down */

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /* ???????? */
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_ADD_VAP, OAL_SIZEOF(mac_cfg_add_vap_param_stru));
    ((mac_cfg_add_vap_param_stru *)st_write_msg.auc_value)->pst_net_dev     = pst_net_dev;
    ((mac_cfg_add_vap_param_stru *)st_write_msg.auc_value)->en_vap_mode     = en_vap_mode;
    ((mac_cfg_add_vap_param_stru *)st_write_msg.auc_value)->uc_cfg_vap_indx = pst_cfg_mac_vap->uc_vap_id;
#ifdef _PRE_WLAN_FEATURE_P2P
    ((mac_cfg_add_vap_param_stru *)st_write_msg.auc_value)->en_p2p_mode      = en_p2p_mode;
#endif
#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
    ((mac_cfg_add_vap_param_stru *)st_write_msg.auc_value)->bit_11ac2g_enable = (oal_uint8)!!hwifi_get_init_value(CUS_TAG_INI, WLAN_CFG_INIT_11AC2G_ENABLE);
    ((mac_cfg_add_vap_param_stru *)st_write_msg.auc_value)->bit_disable_capab_2ght40 = g_st_wlan_customize.uc_disable_capab_2ght40;
#endif
    /* ???????? */
    l_ret = wal_send_cfg_event(pst_cfg_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_add_vap_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_TRUE,
                               &pst_rsp_msg);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAL_MEM_FREE(pst_wdev, OAL_TRUE);
        oal_net_free_netdev(pst_net_dev);
        OAM_WARNING_LOG1(pst_cfg_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_vap::return err code %d!}\r\n", l_ret);
        return (oal_uint32)l_ret;
    }

    /* ???????????????? */
    ul_err_code = wal_check_and_release_msg_resp(pst_rsp_msg);
    if(OAL_SUCC != ul_err_code)
    {
        OAM_WARNING_LOG1(pst_cfg_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_vap::hmac add vap fail, ul_err_code[%u]!}\r\n",
                          ul_err_code);
        /* ?????????????????? */
        OAL_MEM_FREE(pst_wdev, OAL_TRUE);
        oal_net_free_netdev(pst_net_dev);
        return ul_err_code;
    }

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    wal_set_random_mac_to_mib(pst_net_dev); /* set random mac to mib ; for hi1102-cb */
#endif

    return OAL_SUCC;
}


oal_uint32 wal_cfg80211_del_vap(mac_cfg_del_vap_param_stru *pst_del_vap_param)
{
    wal_msg_write_stru           st_write_msg;
    wal_msg_stru                *pst_rsp_msg = OAL_PTR_NULL;
    oal_net_device_stru         *pst_net_dev;

    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_del_vap_param))
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_del_vap::pst_del_vap_param null ptr !}\r\n");
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_net_dev = pst_del_vap_param->pst_net_dev;
    /* ??????up??????????????????????down */
    if (OAL_UNLIKELY(0 != (OAL_IFF_RUNNING & OAL_NETDEVICE_FLAGS(pst_net_dev))))
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_del_vap::device is busy, please down it first %d!}\r\n", OAL_NETDEVICE_FLAGS(pst_net_dev));
        return OAL_ERR_CODE_CONFIG_BUSY;
    }

    /* ??????????net_device ????????wireless_dev ???? */
    //OAL_MEM_FREE(OAL_NETDEVICE_WDEV(pst_net_dev), OAL_TRUE);

    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/
    /* ??????????vap ???? */
    ((mac_cfg_del_vap_param_stru *)st_write_msg.auc_value)->pst_net_dev = pst_net_dev;
#ifdef _PRE_WLAN_FEATURE_P2P
    ((mac_cfg_del_vap_param_stru *)st_write_msg.auc_value)->en_p2p_mode = pst_del_vap_param->en_p2p_mode;
#endif
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_DEL_VAP, OAL_SIZEOF(mac_cfg_del_vap_param_stru));

    if (OAL_SUCC != wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_del_vap_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_TRUE,
                               &pst_rsp_msg))
    {
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_del_vap::wal_send_cfg_event fail!}");
        return -OAL_EFAIL;
    }

    if (OAL_SUCC != wal_check_and_release_msg_resp(pst_rsp_msg))
    {
         OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_del_vap::wal_check_and_release_msg_resp fail!}");
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}
#else

oal_uint32 wal_cfg80211_add_vap(mac_cfg_add_vap_param_stru *pst_add_vap_param)
{
    return OAL_SUCC;
}

oal_uint32 wal_cfg80211_del_vap(mac_cfg_del_vap_param_stru *pst_del_vap_param)
{
    return OAL_SUCC;
}
#endif
#ifdef _PRE_WLAN_FEATURE_VOWIFI

oal_uint32 wal_cfg80211_vowifi_report(frw_event_mem_stru *pst_event_mem)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34))
    frw_event_stru                  *pst_event;
    hmac_vap_stru                   *pst_hmac_vap;

    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_event_mem))
    {
      OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_vowifi_report::pst_event_mem is null!}");
      return OAL_ERR_CODE_PTR_NULL;
    }

    pst_event  = (frw_event_stru *)pst_event_mem->puc_data;
    pst_hmac_vap = mac_res_get_hmac_vap(pst_event->st_event_hdr.uc_vap_id);
    if(OAL_PTR_NULL == pst_hmac_vap)
    {
      OAM_ERROR_LOG1(0, OAM_SF_TX, "{wal_cfg80211_vowifi_report::pst_hmac_vap null.vap_id[%d]}", pst_event->st_event_hdr.uc_vap_id);
      return OAL_ERR_CODE_PTR_NULL;
    }

    /* ????vowifi???????? */
    oal_cfg80211_vowifi_report(pst_hmac_vap->pst_net_device, GFP_KERNEL);
#endif /* (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)) */

    return OAL_SUCC;

}
#endif /* _PRE_WLAN_FEATURE_VOWIFI */

//#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 44))

OAL_STATIC oal_bool_enum wal_check_support_basic_rate_6M(oal_uint8   *puc_supported_rates_ie,
                                                            oal_uint8    uc_supported_rates_num,
                                                            oal_uint8   *puc_extended_supported_rates_ie,
                                                            oal_uint8    uc_extended_supported_rates_num)
{
    oal_uint8     uc_loop;
    oal_bool_enum en_support = OAL_FALSE;
    for (uc_loop = 0; uc_loop < uc_supported_rates_num; uc_loop++)
    {
        if (OAL_PTR_NULL == puc_supported_rates_ie)
        {
            break;
        }
        if (0x8c == puc_supported_rates_ie[2 + uc_loop])
        {
            en_support = OAL_TRUE;
        }
    }

    for (uc_loop = 0; uc_loop < uc_extended_supported_rates_num; uc_loop++)
    {
        if (OAL_PTR_NULL == puc_extended_supported_rates_ie)
        {
            break;
        }
        if (0x8c == puc_extended_supported_rates_ie[2 + uc_loop])
        {
            en_support = OAL_TRUE;
        }
    }

    return en_support;
}


OAL_STATIC oal_uint32  wal_parse_protocol_mode(
                wlan_channel_band_enum_uint8 en_band,
                oal_beacon_parameters       *pst_beacon_info,
                oal_uint8                   *puc_ht_ie,
                oal_uint8                   *puc_vht_ie,
                wlan_protocol_enum_uint8    *pen_protocol)
{
    oal_uint8   *puc_supported_rates_ie             = OAL_PTR_NULL;
    oal_uint8   *puc_extended_supported_rates_ie    = OAL_PTR_NULL;
    oal_uint8    uc_supported_rates_num             = 0;
    oal_uint8    uc_extended_supported_rates_num    = 0;
    oal_uint16   us_offset;


    if (OAL_PTR_NULL != puc_vht_ie)
    {
        /* ????AP ??11ac ???? */
        *pen_protocol = WLAN_VHT_MODE;
        return OAL_SUCC;
    }
    if (OAL_PTR_NULL != puc_ht_ie)
    {
        /* ????AP ??11n ???? */
        *pen_protocol = WLAN_HT_MODE;
        return OAL_SUCC;
    }

    /* hostapd ??????????????????add beacon ??????add beacon??????????????????????????????????????AP ????(a/b/g) */
    if (WLAN_BAND_5G == en_band)
    {
        *pen_protocol = WLAN_LEGACY_11A_MODE;
        return OAL_SUCC;
    }
    if (WLAN_BAND_2G == en_band)
    {
        us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
        //puc_supported_rates_ie = mac_get_supported_rates_ie(pst_beacon_info->head + 24, (oal_uint16)pst_beacon_info->head_len, us_offset);
        puc_supported_rates_ie = mac_find_ie(MAC_EID_RATES, pst_beacon_info->head + 24 + us_offset, pst_beacon_info->head_len - us_offset);
        if (OAL_PTR_NULL != puc_supported_rates_ie)
        {
            uc_supported_rates_num = puc_supported_rates_ie[1];
        }
        //puc_extended_supported_rates_ie = mac_get_exsup_rates_ie(pst_beacon_info->tail, (oal_uint16)pst_beacon_info->tail_len, 0);
        puc_extended_supported_rates_ie = mac_find_ie(MAC_EID_XRATES, pst_beacon_info->tail, pst_beacon_info->tail_len);
        if (OAL_PTR_NULL != puc_extended_supported_rates_ie)
        {
            uc_extended_supported_rates_num = puc_extended_supported_rates_ie[1];
        }

        if (4 == uc_supported_rates_num + uc_extended_supported_rates_num)
        {
            *pen_protocol = WLAN_LEGACY_11B_MODE;
            return OAL_SUCC;
        }
        if (8 == uc_supported_rates_num + uc_extended_supported_rates_num)
        {
            *pen_protocol = WLAN_LEGACY_11G_MODE;
            return OAL_SUCC;
        }
        if (12 == uc_supported_rates_num + uc_extended_supported_rates_num)
        {
            /* ?????????????????? 11gmix1 ???? 11gmix2 */
            /* ?????????????????? 6M , ???????? 11gmix2 */
            *pen_protocol = WLAN_MIXED_ONE_11G_MODE;
            if (OAL_TRUE == wal_check_support_basic_rate_6M(puc_supported_rates_ie,
                                                            uc_supported_rates_num,
                                                            puc_extended_supported_rates_ie,
                                                            uc_extended_supported_rates_num))
            {
                *pen_protocol = WLAN_MIXED_TWO_11G_MODE;
            }
            return OAL_SUCC;
        }
    }

    /* ???????????????????????? */
    *pen_protocol = WLAN_PROTOCOL_BUTT;

    return OAL_FAIL;
}


OAL_STATIC oal_uint32 wal_parse_ht_vht_ie(
                mac_vap_stru           *pst_mac_vap,
                oal_beacon_parameters  *pst_beacon_info,
                mac_beacon_param_stru  *pst_beacon_param)
{
    oal_uint8              *puc_ht_ie;
    oal_uint8              *puc_vht_ie;
    oal_uint32              ul_ret;
    mac_frame_ht_cap_stru  *pst_ht_cap;
    mac_vht_cap_info_stru  *pst_vht_cap;

    //puc_ht_ie  = mac_get_ht_cap_ie(pst_beacon_info->tail, (oal_uint16)pst_beacon_info->tail_len, 0);
    //puc_vht_ie = mac_get_vht_cap_ie(pst_beacon_info->tail, (oal_uint16)pst_beacon_info->tail_len, 0);
    puc_ht_ie  = mac_find_ie(MAC_EID_HT_CAP, pst_beacon_info->tail, pst_beacon_info->tail_len);
    puc_vht_ie = mac_find_ie(MAC_EID_VHT_CAP, pst_beacon_info->tail, pst_beacon_info->tail_len);

    /* ???????????? */
    ul_ret = wal_parse_protocol_mode(pst_mac_vap->st_channel.en_band, pst_beacon_info, puc_ht_ie, puc_vht_ie, &pst_beacon_param->en_protocol);
    if (OAL_SUCC != ul_ret)
    {
        OAM_ERROR_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_parse_ht_vht_ie::return err code!}\r\n", ul_ret);

        return ul_ret;
    }

#ifdef _PRE_WLAN_FEATURE_P2P
    /* ??????????P2P GO 2.4G??????????11ac ???????? */
    if(IS_P2P_GO(pst_mac_vap)
       && (WLAN_BAND_2G == pst_mac_vap->st_channel.en_band))
    {
       pst_beacon_param->en_protocol = ((OAL_TRUE == pst_mac_vap->st_cap_flag.bit_11ac2g) ? WLAN_VHT_MODE : WLAN_HT_MODE);
    }

#endif /* _PRE_WLAN_FEATURE_P2P */

    /* ????short gi???? */
    if (OAL_PTR_NULL == puc_ht_ie)
    {
        return OAL_SUCC;
    }

    /* ????ht cap ie??????????2?????? */
    if (puc_ht_ie[1] < OAL_SIZEOF(mac_frame_ht_cap_stru))
    {
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_parse_ht_vht_ie::invalid ht cap ie len[%d]!}\r\n", puc_ht_ie[1]);
        return OAL_SUCC;
    }

    pst_ht_cap = (mac_frame_ht_cap_stru *)(puc_ht_ie + MAC_IE_HDR_LEN);

    pst_beacon_param->en_shortgi_20 = (oal_uint8)pst_ht_cap->bit_short_gi_20mhz;
	pst_beacon_param->en_shortgi_40 = 0;

	if ((pst_mac_vap->st_channel.en_bandwidth > WLAN_BAND_WIDTH_20M)
		&& (WLAN_BAND_WIDTH_BUTT != pst_mac_vap->st_channel.en_bandwidth))
	{
        pst_beacon_param->en_shortgi_40 = (oal_uint8)pst_ht_cap->bit_short_gi_40mhz;
	}

    pst_beacon_param->uc_smps_mode  = (oal_uint8)pst_ht_cap->bit_sm_power_save;

    if (OAL_PTR_NULL == puc_vht_ie)
    {
        return OAL_SUCC;
    }

    /* ????vht cap ie??????????4?????? */
    if (puc_vht_ie[1] < OAL_SIZEOF(mac_vht_cap_info_stru))
    {
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_parse_ht_vht_ie::invalid ht cap ie len[%d]!}\r\n", puc_vht_ie[1]);
        return OAL_SUCC;
    }

    pst_vht_cap = (mac_vht_cap_info_stru *)(puc_vht_ie + MAC_IE_HDR_LEN);

    pst_beacon_param->en_shortgi_80 = 0;

	if ((pst_mac_vap->st_channel.en_bandwidth > WLAN_BAND_WIDTH_40MINUS)
		&& (WLAN_BAND_WIDTH_BUTT != pst_mac_vap->st_channel.en_bandwidth))
	{
        pst_beacon_param->en_shortgi_80 = pst_vht_cap->bit_short_gi_80mhz;
	}

    return OAL_SUCC;
}

//#endif
#if 0

OAL_STATIC oal_uint32 wal_parse_beacon_wps_ie(mac_vap_stru *pst_mac_vap, oal_beacon_parameters *pst_beacon_info)
{
    oal_app_ie_stru  st_wps_ie;
    oal_uint8       *puc_wps_ie         = OAL_PTR_NULL;
    oal_uint32       ul_ret;


    puc_wps_ie  = mac_get_wps_ie(pst_beacon_info->tail, (oal_uint16)pst_beacon_info->tail_len, 0);
    if (OAL_PTR_NULL == puc_wps_ie)
    {
        /* WPS ??????????????????WPS ???????? */
        pst_mac_vap->st_cap_flag.bit_wps = OAL_FALSE;
        if (OAL_PTR_NULL != pst_mac_vap->ast_app_ie[OAL_APP_BEACON_IE].puc_ie)
        {
            OAL_MEM_FREE(pst_mac_vap->ast_app_ie[OAL_APP_BEACON_IE].puc_ie, OAL_TRUE);
            pst_mac_vap->ast_app_ie[OAL_APP_BEACON_IE].puc_ie = OAL_PTR_NULL;
        }
        pst_mac_vap->ast_app_ie[OAL_APP_BEACON_IE].ul_ie_len     = 0;
        pst_mac_vap->ast_app_ie[OAL_APP_BEACON_IE].ul_ie_max_len = 0;
        return OAL_SUCC;
    }

    /* ????WPS????????BEACON ????VAP ?????? */
    st_wps_ie.puc_ie    = puc_wps_ie;
    st_wps_ie.ul_ie_len = puc_wps_ie[1];
    ul_ret = hmac_config_set_app_ie_to_vap(pst_mac_vap, &st_wps_ie, OAL_APP_BEACON_IE);

    return ul_ret;
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
OAL_STATIC oal_int32 wal_cfg80211_sched_scan_stop(oal_wiphy_stru          *pst_wiphy,
                                                  oal_net_device_stru     *pst_netdev,
                                                  oal_uint64               ul_reqid);

#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44))
OAL_STATIC oal_int32 wal_cfg80211_sched_scan_stop(oal_wiphy_stru          *pst_wiphy,
                                                  oal_net_device_stru     *pst_netdev);
#else
/* do nothing */
#endif


/*lint -e801*/
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44))//TBD:?????????? Linux ??????
OAL_STATIC oal_int32  wal_cfg80211_scan(
                    oal_wiphy_stru                        *pst_wiphy,
                    oal_cfg80211_scan_request_stru        *pst_request)
#else
OAL_STATIC oal_int32  wal_cfg80211_scan(
                    oal_wiphy_stru                        *pst_wiphy,
                    oal_net_device_stru                   *pst_netdev,
                    oal_cfg80211_scan_request_stru        *pst_request)
#endif
{
    hmac_device_stru               *pst_hmac_device;
    mac_vap_stru                   *pst_mac_vap;
    hmac_scan_stru                 *pst_scan_mgmt;
    oal_int32                       l_ret = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44))//TBD:?????????? Linux ??????
    oal_net_device_stru            *pst_netdev;
#endif

    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_request))
    {
        OAM_ERROR_LOG2(0, OAM_SF_CFG, "{wal_cfg80211_scan::scan failed, null ptr, pst_wiphy[%p], pst_request[%p]!}", pst_wiphy, pst_request);
        goto fail;
    }

    /* ?????????????????????????????????????????????????????????????? */
    if (pst_request->ie_len > WLAN_WPS_IE_MAX_SIZE)
    {
        OAM_ERROR_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_scan:: scan ie is too large to save. [%d]!}",
                        pst_request->ie_len);
        return -OAL_EFAIL;
    }

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44))//TBD:?????????? Linux ??????
    pst_netdev = pst_request->wdev->netdev;
#endif
    if (OAL_PTR_NULL == pst_netdev)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_scan::scan failed, null ptr, pst_netdev = null!}");
        goto fail;
    }
#ifdef _PRE_WLAN_FEATURE_DFR
    if (g_st_dfr_info.bit_device_reset_process_flag)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_scan:: dfr_process_status[%d]!}",
            g_st_dfr_info.bit_device_reset_process_flag);
        return -OAL_EFAIL;
    }
#endif //#ifdef _PRE_WLAN_FEATURE_DFR

    /* ????net_device ??????????mac_device_stru ???? */
    pst_mac_vap    = OAL_NET_DEV_PRIV(pst_netdev);
    if(NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_scan::can't get mac vap from netdevice priv data!}");
        goto fail;
    }

#ifdef _PRE_WLAN_FEATURE_WAPI
    if (IS_P2P_SCAN_REQ(pst_request)
    && (OAL_TRUE == hmac_user_is_wapi_connected(pst_mac_vap->uc_device_id)))
    {
        OAM_WARNING_LOG0(0, OAM_SF_CFG, "{stop p2p scan under wapi!}");
        goto fail;
    }
#endif/* #ifdef _PRE_WLAN_FEATURE_WAPI */

    pst_hmac_device = hmac_res_get_mac_dev(pst_mac_vap->uc_device_id);
    if (NULL == pst_hmac_device)
    {
        OAM_ERROR_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_scan::scan failed, null ptr, pst_hmac_device = null device_id:%d!}",pst_mac_vap->uc_device_id);
        goto fail;
    }
    pst_scan_mgmt = &(pst_hmac_device->st_scan_mgmt);

    OAM_WARNING_LOG3(pst_mac_vap->uc_vap_id, OAM_SF_CFG, "{wal_cfg80211_scan::start a new normal scan. n_channels[%d], ie_len[%d], n_ssid[%d]}",
      pst_request->n_channels, pst_request->ie_len, pst_request->n_ssids);

    /* TBD: gong ??????????????, ??????????????????????busy  */
    /* ?????????????????????? */
    /*lint -e730*//* info, boolean argument to function */
    l_ret = OAL_WAIT_EVENT_INTERRUPTIBLE(pst_scan_mgmt->st_wait_queue,(OAL_PTR_NULL == pst_scan_mgmt->pst_request));
    /*lint +e730*/
    if (l_ret < 0)
    {
        OAM_WARNING_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_CFG, "{wal_cfg80211_scan::start a new scan failed, wait return error.}");
        /*lint -e801*/
        goto fail;
        /*lint +e801*/
    }

    /* ???????????????????????????????? */
    pst_scan_mgmt->pst_request = pst_request;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44))
    /* ?????????????????????????????????????? */
    if (OAL_PTR_NULL != pst_scan_mgmt->pst_sched_scan_req)
    {
        OAM_WARNING_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_CFG, "{wal_cfg80211_scan::stop sched scan, before normal scan.}");
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
        wal_cfg80211_sched_scan_stop(pst_wiphy, pst_netdev, 0);
#else
        wal_cfg80211_sched_scan_stop(pst_wiphy, pst_netdev);
#endif
    }
#endif

    /* ???????? */
    if (OAL_SUCC != wal_scan_work_func(pst_scan_mgmt, pst_netdev, pst_request))
    {
        pst_scan_mgmt->pst_request = OAL_PTR_NULL;
        return -OAL_EFAIL;
    }

    return OAL_SUCC;

fail:
    return -OAL_EFAIL;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34))
#if 0

OAL_STATIC oal_int32 wal_set_auth_type(mac_cfg80211_connect_param_stru     *pst_connect_param,
                                       oal_cfg80211_connect_params_stru    *pst_sme)
{
    switch(pst_sme->auth_type)
    {
        case NL80211_AUTHTYPE_OPEN_SYSTEM:
            pst_connect_param->en_auth_type = NL80211_AUTHTYPE_OPEN_SYSTEM;
            break;
        case NL80211_AUTHTYPE_SHARED_KEY:
            pst_connect_param->en_auth_type = WLAN_WITP_AUTH_SHARED;
            break;
        case NL80211_AUTHTYPE_AUTOMATIC:

            pst_connect_param->en_auth_type = WLAN_WITP_AUTH_OPEN;
            break;
        default:
            return OAL_FAIL;
    }

    return OAL_SUCC;
}


OAL_STATIC oal_int32 wal_set_akm_suites(mac_cfg80211_connect_param_stru     *pst_connect_param,
                                                oal_cfg80211_connect_params_stru    *pst_sme)
{
    if (0 != pst_sme->crypto.n_akm_suites)
    {
        switch(pst_sme->crypto.akm_suites[0])
        {
            case WITP_WLAN_AKM_SUITE_PSK:
                break;
            case WITP_WLAN_AKM_SUITE_8021X:
                pst_connect_param->uc_auth_mode |= WLAN_8021X_BIT;
                break;

            default:
                return OAL_FAIL;
        }
    }

    return OAL_SUCC;
}


OAL_STATIC oal_int32  wal_set_wpa_wpa2(mac_cfg80211_connect_param_stru     *pst_connect_param,
                                                oal_cfg80211_connect_params_stru    *pst_sme)
{
    switch(pst_sme->crypto.wpa_versions)
    {
        case 0:
            break;
        case WITP_WPA_VERSION_1:
            pst_connect_param->uc_crypto_type |= WLAN_WPA_BIT;
            break;
        case WITP_WPA_VERSION_2:
            pst_connect_param->uc_crypto_type |= WLAN_WPA2_BIT;
            break;

        default:
            return OAL_FAIL;
    }

    return OAL_SUCC;
}
#endif

#if 0

OAL_STATIC oal_int32 wal_set_cipher_suite(oal_uint32 ul_cipher_suite, oal_uint8 *puc_crypto)
{
    switch(ul_cipher_suite)
    {
        case 0:
            break;
        case WLAN_CIPHER_SUITE_WEP40:
            *puc_crypto      |= WLAN_WEP_BIT;
            break;
        case WLAN_CIPHER_SUITE_WEP104:
            *puc_crypto      |= WLAN_WEP104_BIT;
            break;
        case WLAN_CIPHER_SUITE_TKIP:
            *puc_crypto      |= WLAN_TKIP_BIT;
            break;
        case WLAN_CIPHER_SUITE_CCMP:
        case WLAN_CIPHER_SUITE_AES_CMAC:
            *puc_crypto      |= WLAN_CCMP_BIT;
            break;
        default:
            return OAL_FAIL;
    }

    return OAL_SUCC;
}


OAL_STATIC oal_int32 wal_set_cipher_info(mac_cfg80211_connect_param_stru     *pst_connect_param,
                                       oal_cfg80211_connect_params_stru    *pst_sme)
{
    oal_int32   l_ret   = OAL_SUCC ;

    /*????????????????*/
    l_ret = wal_set_cipher_suite(pst_sme->crypto.cipher_group,&(pst_connect_param->uc_group_crypto));
    if(OAL_SUCC != l_ret)
    {
        return l_ret;
    }

    /*????????????????*/
    if (0 != pst_sme->crypto.n_ciphers_pairwise)
    {
        l_ret = wal_set_cipher_suite(pst_sme->crypto.ciphers_pairwise[0],&(pst_connect_param->uc_pairwise_crypto));
        if(OAL_SUCC != l_ret)
        {
            return l_ret;
        }
    }

    if (0 != pst_connect_param->uc_crypto_type)
    {
        pst_connect_param->uc_crypto_type |= WLAN_ENCRYPT_BIT;
    }

    if ((0 == pst_connect_param->uc_pairwise_crypto) && (0 == pst_connect_param->uc_group_crypto) && (pst_connect_param->uc_crypto_type & WLAN_WPA_BIT))
    {
        /* ????????????????????????????crypto_type??wpa1??????crypto_type??????????wpa_supplicant??bug????
         * ??????wps IE??????????wpa_supplicant????wpa version??1??????????????????????wpa ie??
         */
        pst_connect_param->uc_crypto_type = 0;
    }

    return l_ret;
}
#endif


OAL_STATIC oal_uint32 wal_set_wep_key(mac_cfg80211_connect_param_stru      *pst_connect_param,
                                            oal_cfg80211_connect_params_stru   *pst_sme)
{
    pst_connect_param->puc_wep_key            = pst_sme->key;
    pst_connect_param->uc_wep_key_len         = pst_sme->key_len;
    pst_connect_param->uc_wep_key_index       = pst_sme->key_idx;
    pst_connect_param->st_crypto.cipher_group = (oal_uint8)pst_sme->crypto.cipher_group;

    return OAL_SUCC;
}


OAL_STATIC oal_uint32 wal_set_crypto_info(mac_cfg80211_connect_param_stru   *pst_connect_param,
                                            oal_cfg80211_connect_params_stru    *pst_sme)
{
    oal_uint8   uc_loop                 = 0;
    oal_uint8   uc_akm_suite_num        = 0;
    oal_uint8   uc_pairwise_cipher_num  = 0;
    oal_uint32  ul_ret                  = OAL_SUCC;
    oal_uint8  *puc_ie                  = OAL_PTR_NULL;
    oal_uint32  ul_offset               = 0;

    //puc_ie = mac_get_rsn_ie(pst_sme->ie, pst_sme->ie_len, 0);
    puc_ie = mac_find_ie(MAC_EID_RSN, (oal_uint8 *)pst_sme->ie, (oal_int32)(pst_sme->ie_len));

    if ((0 != pst_sme->key_len) && (0 == pst_sme->crypto.n_akm_suites))
    {
        /* ????wep???????? */
        ul_ret = wal_set_wep_key(pst_connect_param, pst_sme);
    }
    else if (0 != pst_sme->crypto.n_akm_suites)
    {
        /* ????WPA/WPA2 ???????? */
        pst_connect_param->st_crypto.wpa_versions = (oal_uint8)pst_sme->crypto.wpa_versions;
        pst_connect_param->st_crypto.cipher_group = (oal_uint8)pst_sme->crypto.cipher_group;
        pst_connect_param->st_crypto.n_ciphers_pairwise = (oal_uint8)pst_sme->crypto.n_ciphers_pairwise;
        pst_connect_param->st_crypto.n_akm_suites = (oal_uint8)pst_sme->crypto.n_akm_suites;
        pst_connect_param->st_crypto.control_port = (oal_uint8)pst_sme->crypto.control_port;

        uc_pairwise_cipher_num = OAL_MIN(pst_connect_param->st_crypto.n_ciphers_pairwise, OAL_NL80211_MAX_NR_CIPHER_SUITES);
        for (uc_loop = 0; uc_loop < uc_pairwise_cipher_num; uc_loop++)
        {
            pst_connect_param->st_crypto.ciphers_pairwise[uc_loop] = (oal_uint8)pst_sme->crypto.ciphers_pairwise[uc_loop];
        }

        uc_akm_suite_num = OAL_MIN(pst_connect_param->st_crypto.n_akm_suites, OAL_NL80211_MAX_NR_AKM_SUITES);
        for (uc_loop = 0; uc_loop < uc_akm_suite_num; uc_loop++)
        {
            pst_connect_param->st_crypto.akm_suites[uc_loop] = (oal_uint8)pst_sme->crypto.akm_suites[uc_loop];
        }
    }
    else if (OAL_PTR_NULL != puc_ie)
    {
        /* ????????PMF STAUT????n_akm_suites==0??RSN???????? */
        /* ????WPA/WPA2 ???????? */
        pst_connect_param->st_crypto.control_port = (oal_uint8)pst_sme->crypto.control_port;
        pst_connect_param->st_crypto.wpa_versions = (oal_uint8)pst_sme->crypto.wpa_versions;

        /* ???????? */
        ul_offset = MAC_IE_HDR_LEN;

        /* ????group cipher type */
        ul_offset += MAC_RSN_VERSION_LEN + MAC_OUI_LEN;
        pst_connect_param->st_crypto.cipher_group = puc_ie[ul_offset];

        /* ????pairwise cipher cout */
        ul_offset += MAC_OUITYPE_WPA;
        pst_connect_param->st_crypto.n_ciphers_pairwise = puc_ie[ul_offset];
        pst_connect_param->st_crypto.n_ciphers_pairwise += (oal_uint8)(puc_ie[ul_offset+1] << 8);

        /* ????pairwise cipher type */
        ul_offset += MAC_RSN_CIPHER_COUNT_LEN;
        if (pst_connect_param->st_crypto.n_ciphers_pairwise)
        {
            uc_pairwise_cipher_num = OAL_MIN(pst_connect_param->st_crypto.n_ciphers_pairwise, OAL_NL80211_MAX_NR_CIPHER_SUITES);
            for (uc_loop = 0; uc_loop < uc_pairwise_cipher_num; uc_loop++)
            {
                ul_offset += MAC_OUI_LEN;
                pst_connect_param->st_crypto.ciphers_pairwise[uc_loop] = (oal_uint8)puc_ie[ul_offset];
                ul_offset += MAC_OUITYPE_WPA;
            }
        }

        /* ????AKM cout */
        pst_connect_param->st_crypto.n_akm_suites = puc_ie[ul_offset];
        pst_connect_param->st_crypto.n_akm_suites += (oal_uint8)(puc_ie[ul_offset+1] << 8);


        /* ????AKM type */
        ul_offset += MAC_RSN_CIPHER_COUNT_LEN;
        if (pst_connect_param->st_crypto.n_akm_suites)
        {
            uc_akm_suite_num = OAL_MIN(pst_connect_param->st_crypto.n_akm_suites, OAL_NL80211_MAX_NR_AKM_SUITES);
            for (uc_loop = 0; uc_loop < uc_akm_suite_num; uc_loop++)
            {
                ul_offset += MAC_OUI_LEN;
                pst_connect_param->st_crypto.akm_suites[uc_loop] = (oal_uint8)puc_ie[ul_offset];
                ul_offset += MAC_OUITYPE_WPA;
            }
        }
    }
    //else if (mac_get_wps_ie(pst_sme->ie, (oal_uint16)(pst_sme->ie_len), 0))
    else if (mac_find_vendor_ie(MAC_WLAN_OUI_MICROSOFT, MAC_WLAN_OUI_TYPE_MICROSOFT_WPS, (oal_uint8 *)pst_sme->ie, (oal_int32)(pst_sme->ie_len)))
    {
        OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_set_crypto_info:connect use wps method!}");
        ul_ret = OAL_SUCC;
    }
    else
    {
        ul_ret = OAL_FAIL;
    }

    return ul_ret;
}

#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)) */
#if 0

OAL_STATIC oal_uint32  wal_add_beacon_wep(mac_vap_stru *pst_mac_vap,mac_beacon_param_stru *pst_beacon_param,
                                                oal_beacon_parameters *pst_beacon_info)
{
    oal_ieee80211_mgmt       *pst_mgmt             = OAL_PTR_NULL;
    wlan_priv_key_param_stru *pst_key              = OAL_PTR_NULL;
    oal_uint16                us_beacon_capability = 0;
    oal_uint8                 uc_key_index;

    /* ??????????wep???? */
    pst_mgmt = (oal_ieee80211_mgmt *)pst_beacon_info->head;
    if (OAL_PTR_NULL == pst_mgmt)
    {
        return OAL_FAIL;
    }

    us_beacon_capability = pst_mgmt->u.beacon.capab_info;

    if (WLAN_WITP_CAPABILITY_PRIVACY & us_beacon_capability)
    {
        /* WEP ???????? */

#if 0
        /* WEP??????????????open*/
        pst_mac_vap->en_auth_mode = WLAN_WITP_AUTH_OPEN;
#endif
        uc_key_index = pst_mac_vap->st_key_mgmt.uc_default_index;
        if(WLAN_MAX_WEP_KEY_COUNT <= uc_key_index)
        {
            return OAL_FAIL;
        }

        pst_key = &pst_mac_vap->st_key_mgmt.ast_gtk[uc_key_index];
        if (WLAN_CIPHER_SUITE_WEP40 == pst_key->ul_cipher)
        {
            pst_beacon_param->uc_crypto_mode |= WLAN_WEP_BIT;
            pst_beacon_param->uc_group_crypto = WLAN_WEP_BIT;
        }
        else if(WLAN_CIPHER_SUITE_WEP104 == pst_key->ul_cipher)
        {
            pst_beacon_param->uc_crypto_mode |= WLAN_WEP104_BIT;
            pst_beacon_param->uc_group_crypto = WLAN_WEP104_BIT;
        }
        else
        {
            return OAL_FAIL;
        }
        pst_beacon_param->uc_crypto_mode |= WLAN_ENCRYPT_BIT;

    }

    return OAL_SUCC;
}

OAL_STATIC oal_uint32  wal_add_beacon_auth_info(mac_vap_stru *pst_mac_vap,mac_beacon_param_stru *pst_beacon_param)
{
    if (WLAN_WITP_AUTH_SHARED_KEY == pst_mac_vap->en_auth_mode)
    {
        /* ??????WEP SHARE KEY */
        if ((WLAN_WPA_BIT | WLAN_WPA2_BIT) & pst_beacon_param->uc_crypto_mode)
        {
            return OAL_FAIL;
        }
        pst_beacon_param->uc_auth_type = WLAN_WITP_AUTH_SHARED_KEY;
    }
    else
    {
        pst_beacon_param->uc_auth_type |= WLAN_WITP_AUTH_OPEN_SYSTEM;
    }

    return OAL_SUCC;
}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)


OAL_STATIC oal_bool_enum_uint8 wal_is_p2p_device(oal_net_device_stru *pst_net_device)
{
#ifdef _PRE_WLAN_FEATURE_P2P
    mac_vap_stru                       *pst_mac_vap;
    hmac_vap_stru                      *pst_hmac_vap;

    pst_mac_vap  = OAL_NET_DEV_PRIV(pst_net_device);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        return OAL_FALSE;
    }

    pst_hmac_vap = mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if ((pst_hmac_vap != OAL_PTR_NULL)
        && (pst_hmac_vap->pst_p2p0_net_device != OAL_PTR_NULL)
        && (pst_net_device == pst_hmac_vap->pst_p2p0_net_device))
    {
        return OAL_TRUE;
    }
    else
    {
        return OAL_FALSE;
    }
#else
    return OAL_FALSE;
#endif /* _PRE_WLAN_FEATURE_P2P */
}


OAL_STATIC oal_int32  wal_cfg80211_connect(
                    oal_wiphy_stru                        *pst_wiphy,
                    oal_net_device_stru                   *pst_net_device,
                    oal_cfg80211_connect_params_stru      *pst_sme)
{
    mac_cfg80211_connect_param_stru     st_mac_cfg80211_connect_param;
    oal_uint32                          ul_ret;
    oal_int32                           l_ret;

    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_net_device) || (OAL_PTR_NULL == pst_sme))
    {
        OAM_ERROR_LOG3(0, OAM_SF_ANY, "{wal_cfg80211_connect::connect failed, pst_wiphy, pst_netdev, pst_sme %p, %p, %p!}\r\n",
                       pst_wiphy, pst_net_device, pst_sme);

        return -OAL_EINVAL;
    }
#ifdef _PRE_WLAN_FEATURE_DFR
    if (g_st_dfr_info.bit_device_reset_process_flag)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_connect::dfr_process_status[%d]!}",
            g_st_dfr_info.bit_device_reset_process_flag);
        return -OAL_EFAIL;
    }

#endif //#ifdef _PRE_WLAN_FEATURE_DFR
    if (wal_is_p2p_device(pst_net_device))
    {
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "wal_cfg80211_connect:connect stop, p2p device should not connect.");
        return -OAL_EINVAL;
    }

    /* ?????????????????? */
    oal_memset(&st_mac_cfg80211_connect_param, 0, OAL_SIZEOF(mac_cfg80211_connect_param_stru));

/* iw???????????????????????????????????????????????????????????????????????????????????????????????????? */
#if 0
    /* ?????????????? freq to channel_number eg.1,2,36,40...  */
    st_mac_cfg80211_connect_param.uc_channel    = (oal_uint8)oal_ieee80211_frequency_to_channel(pst_sme->channel->center_freq);
#endif

    /* ?????????????? ssid */
    st_mac_cfg80211_connect_param.puc_ssid      = (oal_uint8 *)pst_sme->ssid;
    st_mac_cfg80211_connect_param.uc_ssid_len   = (oal_uint8)pst_sme->ssid_len;

    if (pst_sme->bssid)
    {
        st_mac_cfg80211_connect_param.puc_bssid = (oal_uint8 *)pst_sme->bssid;
    }
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0))
    else if (pst_sme->bssid_hint)
    {
        st_mac_cfg80211_connect_param.puc_bssid = (oal_uint8 *)pst_sme->bssid_hint;
    }
#endif
    else
    {
        OAM_WARNING_LOG0(0, OAM_SF_ASSOC, "{wal_cfg80211_connect::bssid and bssid_hint is NULL.}");
        return -OAL_EFAIL;
    }

    /* ?????????????????????????? */
    /* ???????????? */
    st_mac_cfg80211_connect_param.en_auth_type  = pst_sme->auth_type;

    /* ???????????? */
    st_mac_cfg80211_connect_param.en_privacy    = pst_sme->privacy;

    /* ??????????????pmf???????????? */
    st_mac_cfg80211_connect_param.en_mfp        = pst_sme->mfp;

    OAM_WARNING_LOG4(0, OAM_SF_ANY, "{wal_cfg80211_connect::start a new connect, ssid_len[%d], auth_type[%d], privacy[%d], mfp[%d]}\r\n",
      pst_sme->ssid_len, pst_sme->auth_type, pst_sme->privacy, pst_sme->mfp);

    /* ???????????? */

#ifdef _PRE_WLAN_FEATURE_WAPI
    if(WITP_WAPI_VERSION == pst_sme->crypto.wpa_versions)
    {

        OAM_WARNING_LOG0(0, OAM_SF_ANY, "wal_cfg80211_connect::crypt ver is wapi!");
        st_mac_cfg80211_connect_param.uc_wapi = OAL_TRUE;
    }
    else
    {
        st_mac_cfg80211_connect_param.uc_wapi = OAL_FALSE;
    }
#endif

    if (pst_sme->privacy)
    {
        ul_ret = wal_set_crypto_info(&st_mac_cfg80211_connect_param, pst_sme);

        if(OAL_SUCC != ul_ret)
        {
            OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_connect::connect failed, wal_set_wep_key fail:%d!}\r\n", ul_ret);
            return -OAL_EFAIL;
        }
    }

    /* ????????P2P/WPS ie */
    st_mac_cfg80211_connect_param.puc_ie        = (oal_uint8 *)pst_sme->ie;
    st_mac_cfg80211_connect_param.ul_ie_len     = (oal_uint32)(pst_sme->ie_len);

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)&&(_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    wlan_pm_set_timeout(WLAN_SLEEP_LONG_CHECK_CNT);
#endif

    
    wal_force_scan_complete(pst_net_device, OAL_TRUE);
    

    /* ?????????????????????? */
    l_ret = wal_cfg80211_start_connect(pst_net_device, &st_mac_cfg80211_connect_param);

    if( OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_connect::wal_cfg80211_start_connect fail %d!}\r\n", l_ret);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}


OAL_STATIC oal_int32  wal_cfg80211_disconnect(
                    oal_wiphy_stru                   *pst_wiphy,
                    oal_net_device_stru              *pst_net_device,
                    oal_uint16                        us_reason_code)
{
    mac_cfg_kick_user_param_stru    st_mac_cfg_kick_user_param;
    oal_int32                       l_ret;

    mac_user_stru                   *pst_mac_user;
    mac_vap_stru                    *pst_mac_vap;

    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_net_device))
    {
        OAM_ERROR_LOG2(0, OAM_SF_ANY, "{wal_cfg80211_disconnect::input param pointer is null,pst_wiphy, pst_netdev %d, %d!}\r\n", pst_wiphy, pst_net_device);

        return -OAL_EINVAL;
    }

#ifdef _PRE_WLAN_FEATURE_DFR
    if (g_st_dfr_info.bit_device_reset_process_flag)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_disconnect::dfr_process_status[%d]!}",
            g_st_dfr_info.bit_device_reset_process_flag);
        return -OAL_EFAIL;
    }

#endif //#ifdef _PRE_WLAN_FEATURE_DFR
    /* ??????????????connect???? */
    oal_memset(&st_mac_cfg_kick_user_param, 0, OAL_SIZEOF(mac_cfg_kick_user_param_stru));

    /* ????????????????????????  */
    st_mac_cfg_kick_user_param.us_reason_code = us_reason_code;

    /* ??????sta??????ap mac ????*/
    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_device);
    if(OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_disconnect::pst_mac_vap is null!}\r\n");
        return -OAL_EFAIL;
    }
    pst_mac_user = mac_res_get_mac_user(pst_mac_vap->uc_assoc_vap_id);
    if (OAL_PTR_NULL == pst_mac_user)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_disconnect::mac_res_get_mac_user pst_mac_user is null, user idx[%d]!}\r\n", pst_mac_vap->uc_assoc_vap_id);
        return OAL_SUCC;
    }

    oal_memcopy(st_mac_cfg_kick_user_param.auc_mac_addr, pst_mac_user->auc_user_mac_addr, WLAN_MAC_ADDR_LEN);

    l_ret = wal_cfg80211_start_disconnect(pst_net_device, &st_mac_cfg_kick_user_param);
    if( OAL_SUCC != l_ret)
    {
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}
#endif


#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
OAL_STATIC oal_int32 wal_cfg80211_add_key(oal_wiphy_stru          *pst_wiphy,
                                          oal_net_device_stru     *pst_netdev,
                                          oal_uint8                uc_key_index,
                                        #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44)
                                          bool                     en_pairwise,
                                        #endif
                                        #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
                                          OAL_CONST oal_uint8     *puc_mac_addr,
                                        #else
                                          oal_uint8               *puc_mac_addr,
                                        #endif
                                          oal_key_params_stru     *pst_params)
#elif (_PRE_OS_VERSION_WIN32 == _PRE_OS_VERSION)
OAL_STATIC oal_int32 wal_cfg80211_add_key(oal_wiphy_stru          *pst_wiphy,
                                          oal_net_device_stru     *pst_netdev,
                                          oal_uint8                uc_key_index,
                                          oal_bool_enum            en_pairwise,
                                          OAL_CONST oal_uint8     *puc_mac_addr,
                                          oal_key_params_stru     *pst_params)

#endif
{
    wal_msg_write_stru             st_write_msg;
    mac_addkey_param_stru          st_payload_params;
    wal_msg_stru                  *pst_rsp_msg = NULL;

    /*1.1 ????????*/
    if ((OAL_PTR_NULL == pst_wiphy)
        || (OAL_PTR_NULL == pst_netdev)
        || (OAL_PTR_NULL == pst_params))
    {
        OAM_ERROR_LOG3(0, OAM_SF_ANY, "{wal_cfg80211_add_key::Param Check ERROR,pst_wiphy, pst_netdev, pst_params %d, %d, %d!}\r\n",
                       pst_wiphy, pst_netdev, pst_params);
        return -OAL_EINVAL;
    }

    /*1.2 key??????????????????????*/
    if ((pst_params->key_len > OAL_WPA_KEY_LEN) || (pst_params->key_len < 0)
        || (pst_params->seq_len > OAL_WPA_SEQ_LEN) || (pst_params->seq_len < 0))
    {
        OAM_ERROR_LOG2(0, OAM_SF_ANY, "{wal_cfg80211_add_key::Param Check ERROR! key_len[%x]  seq_len[%x]!}\r\n",
                      (oal_int32)pst_params->key_len, (oal_int32)pst_params->seq_len);
        return -OAL_EINVAL;
    }


    /*2.1 ????????????*/
    oal_memset(&st_payload_params, 0, OAL_SIZEOF(st_payload_params));
    st_payload_params.uc_key_index = uc_key_index;

    OAL_MEMZERO(st_payload_params.auc_mac_addr, WLAN_MAC_ADDR_LEN);
    if (OAL_PTR_NULL != puc_mac_addr)
    {
        /*??????????????????mac??????????????????????????????????????*/
        oal_memcopy(st_payload_params.auc_mac_addr, puc_mac_addr, WLAN_MAC_ADDR_LEN);
    }

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44)
    st_payload_params.en_pairwise  = en_pairwise;
#else
    st_payload_params.en_pairwise  = (OAL_PTR_NULL != puc_mac_addr) ? OAL_TRUE : OAL_FALSE;
#endif
#else
    st_payload_params.en_pairwise  = en_pairwise;
#endif

    /*2.2 ??????????????*/
    st_payload_params.st_key.key_len = pst_params->key_len;
    st_payload_params.st_key.seq_len = pst_params->seq_len;
    st_payload_params.st_key.cipher  = pst_params->cipher;
    oal_memcopy(st_payload_params.st_key.auc_key, pst_params->key, (oal_uint32)pst_params->key_len);
    oal_memcopy(st_payload_params.st_key.auc_seq, pst_params->seq, (oal_uint32)pst_params->seq_len);
    OAM_INFO_LOG3(0, OAM_SF_ANY, "{wal_cfg80211_add_key::key_len:%d, seq_len:%d, cipher:0x%08x!}\r\n",
                  pst_params->key_len, pst_params->seq_len, pst_params->cipher);

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /*3.1 ???? msg ??????*/
    st_write_msg.en_wid = WLAN_CFGID_ADD_KEY;
    st_write_msg.us_len = OAL_SIZEOF(mac_addkey_param_stru);

    /*3.2 ???? msg ?????? */
    oal_memcopy(st_write_msg.auc_value, &st_payload_params, OAL_SIZEOF(mac_addkey_param_stru));

    /*??????????????????????????????????????????????????????????????????hmac??????????????????*/
    if (OAL_SUCC != wal_send_cfg_event(pst_netdev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_addkey_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_TRUE,
                               &pst_rsp_msg))
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_add_key::wal_send_cfg_event fail!}");
        return -OAL_EFAIL;
    }
    if (OAL_SUCC != wal_check_and_release_msg_resp(pst_rsp_msg))
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_add_key::wal_check_and_release_msg_resp fail!}");
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}

 
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
 OAL_STATIC oal_int32 wal_cfg80211_get_key(oal_wiphy_stru          *pst_wiphy,
                                           oal_net_device_stru     *pst_netdev,
                                           oal_uint8                uc_key_index,
                                       #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44)
                                           bool            en_pairwise,
                                       #endif
                                       #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
                                           OAL_CONST oal_uint8     *puc_mac_addr,
                                       #else
                                           oal_uint8               *puc_mac_addr,
                                       #endif
                                           void                    *cookie,
                                           void                    (*callback)(void *cookie, oal_key_params_stru*))
#else
OAL_STATIC oal_int32 wal_cfg80211_get_key(oal_wiphy_stru *pst_wiphy,
                                         oal_net_device_stru     *pst_netdev,
                                         oal_uint8                uc_key_index,
                                         oal_bool_enum            en_pairwise,
                                         OAL_CONST oal_uint8     *puc_mac_addr,
                                         void                    *cookie,
                                         void                    (*callback)(void *cookie, oal_key_params_stru*))


#endif

{
    wal_msg_write_stru            st_write_msg;
    mac_getkey_param_stru         st_payload_params  = {0};
    oal_uint8                     auc_mac_addr[WLAN_MAC_ADDR_LEN];
    wal_msg_stru                  *pst_rsp_msg = NULL;

    /*1.1 ????????*/
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_wiphy) || OAL_UNLIKELY(OAL_PTR_NULL == pst_netdev)
        ||OAL_UNLIKELY(OAL_PTR_NULL == cookie)|| OAL_UNLIKELY(OAL_PTR_NULL == callback))
    {
        OAM_ERROR_LOG4(0, OAM_SF_ANY, "{wal_cfg80211_get_key::Param Check ERROR,pst_wiphy, pst_netdev, cookie, callback %d, %d, %d, %d!}\r\n", pst_wiphy, pst_netdev, cookie, callback);
        return -OAL_EINVAL;
    }

    /*2.1 ????????????*/
    st_payload_params.pst_netdev   = pst_netdev;
    st_payload_params.uc_key_index = uc_key_index;

    if (OAL_PTR_NULL != puc_mac_addr)
    {
        /*??????????????????mac??????????????????????????????????????*/
        oal_memcopy(auc_mac_addr, puc_mac_addr, WLAN_MAC_ADDR_LEN);
        st_payload_params.puc_mac_addr = auc_mac_addr;
    }
    else
    {
        st_payload_params.puc_mac_addr = OAL_PTR_NULL;
    }

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44)
    st_payload_params.en_pairwise  = en_pairwise;
#else
    if (OAL_PTR_NULL != puc_mac_addr)
    {
        st_payload_params.en_pairwise  = OAL_TRUE;
    }
    else
    {
        st_payload_params.en_pairwise  = OAL_FALSE;
    }
#endif
#else
    st_payload_params.en_pairwise  = en_pairwise;
#endif
    st_payload_params.cookie       = cookie;
    st_payload_params.callback     = callback;

    OAM_INFO_LOG2(0, OAM_SF_ANY, "{wal_cfg80211_get_key::key_idx:%d, en_pairwise:%d!}\r\n", uc_key_index, st_payload_params.en_pairwise);
    if (OAL_PTR_NULL != puc_mac_addr)
    {
        OAM_INFO_LOG4(0, OAM_SF_ANY, "{wal_cfg80211_get_key::MAC ADDR: %02X:XX:XX:%02X:%02X:%02X!}\r\n",
                puc_mac_addr[0], puc_mac_addr[3], puc_mac_addr[4], puc_mac_addr[5]);
    }
    else
    {
        OAM_INFO_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_get_key::MAC ADDR IS null!}\r\n");
    }
    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /*3.1 ???? msg ??????*/
    st_write_msg.en_wid = WLAN_CFGID_GET_KEY;
    st_write_msg.us_len = OAL_SIZEOF(mac_getkey_param_stru);

    /*3.2 ???? msg ?????? */
    oal_memcopy(st_write_msg.auc_value, &st_payload_params, OAL_SIZEOF(mac_getkey_param_stru));

    /*??????????????????????????????????????????????????????????????????hmac??????????????????*/
    if (OAL_SUCC != wal_send_cfg_event(pst_netdev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_getkey_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_TRUE,
                               &pst_rsp_msg))
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_get_key::wal_send_cfg_event fail.}");
        return -OAL_EINVAL;
    }

    if (OAL_SUCC != wal_check_and_release_msg_resp(pst_rsp_msg))
    {
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_get_key::wal_check_and_release_msg_resp fail.}");
        return -OAL_EINVAL;
    }

    return OAL_SUCC;
}


#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
OAL_STATIC oal_int32 wal_cfg80211_remove_key(oal_wiphy_stru         *pst_wiphy,
                                             oal_net_device_stru    *pst_netdev,
                                             oal_uint8               uc_key_index,
                                         #if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,37)
                                             bool           en_pairwise,
                                         #endif
                                         #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
                                             OAL_CONST oal_uint8    *puc_mac_addr)
                                         #else
                                             oal_uint8              *puc_mac_addr)
                                         #endif
#else
OAL_STATIC oal_int32 wal_cfg80211_remove_key(oal_wiphy_stru *pst_wiphy,
                                              oal_net_device_stru    *pst_netdev,
                                              oal_uint8               uc_key_index,
                                              oal_bool_enum           en_pairwise,
                                              OAL_CONST oal_uint8    *puc_mac_addr)


#endif

{
    mac_removekey_param_stru         st_payload_params  = {0};
    wal_msg_write_stru               st_write_msg       = {0};
    wal_msg_stru                    *pst_rsp_msg = NULL;

    /*1.1 ????????*/
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_wiphy) || OAL_UNLIKELY(OAL_PTR_NULL == pst_netdev))
    {
        OAM_ERROR_LOG2(0, OAM_SF_ANY, "{wal_cfg80211_remove_key::Param Check ERROR,pst_wiphy, pst_netdev %d, %d!}\r\n", pst_wiphy, pst_netdev);
        return -OAL_EINVAL;
    }

#ifdef _PRE_WLAN_FEATURE_DFR
    if (g_st_dfr_info.bit_device_reset_process_flag)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_remove_key::dfr_process_status[%d]!}",
            g_st_dfr_info.bit_device_reset_process_flag);
        return OAL_SUCC;
    }
#endif //#ifdef _PRE_WLAN_FEATURE_DFR

    /*2.1 ????????????*/
    st_payload_params.uc_key_index = uc_key_index;
    OAL_MEMZERO(st_payload_params.auc_mac_addr, OAL_MAC_ADDR_LEN);
    if (OAL_PTR_NULL != puc_mac_addr)
    {
        /*??????????????????mac??????????????????????????????????????*/
        oal_memcopy(st_payload_params.auc_mac_addr, puc_mac_addr, WLAN_MAC_ADDR_LEN);
    }

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,37)
    st_payload_params.en_pairwise  = en_pairwise;
#else
    if (OAL_PTR_NULL != puc_mac_addr)
    {
        st_payload_params.en_pairwise  = OAL_TRUE;
        OAM_INFO_LOG4(0, OAM_SF_ANY, "{wal_cfg80211_remove_key::MAC ADDR: %02X:XX:XX:%02X:%02X:%02X!}\r\n",
            puc_mac_addr[0], puc_mac_addr[3], puc_mac_addr[4], puc_mac_addr[5]);
    }
    else
    {
        st_payload_params.en_pairwise  = OAL_FALSE;
        OAM_INFO_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_remove_key::MAC ADDR IS null!}\r\n");
    }
#endif
#else
    st_payload_params.en_pairwise  = en_pairwise;
#endif

    OAM_INFO_LOG2(0, OAM_SF_ANY, "{wal_cfg80211_remove_key::uc_key_index:%d, en_pairwise:%d!}\r\n", uc_key_index, st_payload_params.en_pairwise);

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /*3.1 ???? msg ??????*/
    st_write_msg.en_wid = WLAN_CFGID_REMOVE_KEY;
    st_write_msg.us_len = OAL_SIZEOF(mac_removekey_param_stru);

    /*3.2 ???? msg ?????? */
    oal_memcopy(st_write_msg.auc_value, &st_payload_params, OAL_SIZEOF(mac_removekey_param_stru));

    if(OAL_SUCC != wal_send_cfg_event(pst_netdev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_removekey_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_TRUE,
                               &pst_rsp_msg))
    {
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_remove_key::wal_send_cfg_event fail.}");
        return -OAL_EFAIL;
    }

    if(OAL_SUCC != wal_check_and_release_msg_resp(pst_rsp_msg))
    {
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_remove_key::wal_check_and_release_msg_resp fail.}");
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}


#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
OAL_STATIC oal_int32 wal_cfg80211_set_default_key(oal_wiphy_stru *pst_wiphy,
                                                    oal_net_device_stru     *pst_netdev,
                                                    oal_uint8                uc_key_index
                                                #if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,38)
                                                      ,
                                                    bool            en_unicast,
                                                    bool            en_multicast
                                                #endif
                                                        )
#else
OAL_STATIC oal_int32 wal_cfg80211_set_default_key(oal_wiphy_stru *pst_wiphy,
                                                      oal_net_device_stru     *pst_netdev,
                                                      oal_uint8                uc_key_index,
                                                      oal_bool_enum            en_unicast,
                                                      oal_bool_enum            en_multicast
                                                        )

#endif
{
    mac_setdefaultkey_param_stru  st_payload_params  = {0};
    oal_int32                     l_ret;
    wal_msg_write_stru            st_write_msg      = {0};

    /*1.1 ????????*/
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_wiphy) || OAL_UNLIKELY(OAL_PTR_NULL == pst_netdev))
    {
        OAM_ERROR_LOG2(0, OAM_SF_ANY, "{wal_cfg80211_set_default_key::pst_wiphy or pst_netdev ptr is null,error %d, %d!}\r\n",
                       pst_wiphy, pst_netdev);
        return -OAL_EINVAL;
    }

    /*2.1 ????????????*/
    st_payload_params.uc_key_index = uc_key_index;

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44)
    st_payload_params.en_unicast   = en_unicast;
    st_payload_params.en_multicast = en_multicast;
#else
    st_payload_params.en_unicast   = OAL_TRUE;
    st_payload_params.en_multicast = OAL_TRUE;
#endif
#else
    st_payload_params.en_unicast   = en_unicast;
    st_payload_params.en_multicast = en_multicast;
#endif

    OAM_INFO_LOG3(0, OAM_SF_ANY, "{wal_cfg80211_set_default_key::key_index:%d, unicast:%d, multicast:%d!}\r\n",
                  uc_key_index, st_payload_params.en_unicast, st_payload_params.en_multicast);

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /*3.1 ???? msg ??????*/
    st_write_msg.en_wid = WLAN_CFGID_DEFAULT_KEY;
    st_write_msg.us_len = OAL_SIZEOF(mac_setdefaultkey_param_stru);

    /*3.2 ???? msg ?????? */
    oal_memcopy(st_write_msg.auc_value, &st_payload_params, OAL_SIZEOF(mac_setdefaultkey_param_stru));

    l_ret = wal_send_cfg_event(pst_netdev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_setdefaultkey_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_set_default_key::wal_send_cfg_event return err code %d!}\r\n", l_ret);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}


oal_int32 wal_cfg80211_set_default_mgmt_key(oal_wiphy_stru          *pst_wiphy,
                                            oal_net_device_stru     *pst_netdev,
                                            oal_uint8                uc_key_index)
{
    /* TBD: ???????????? */
//#if
    return -OAL_EFAIL;
}




/*lint -e40*/
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)) || ((_PRE_OS_VERSION_WIN32_RAW == _PRE_OS_VERSION) ||(_PRE_OS_VERSION_WIN32 == _PRE_OS_VERSION) )
OAL_STATIC oal_int32 wal_cfg80211_set_channel(oal_wiphy_stru           *pst_wiphy,
                                                    oal_ieee80211_channel    *pst_chan,
                                                    oal_nl80211_channel_type  en_channel_type)
{
#if 1
    /* ????HOSTAPD ????????????????wal_ioctl_set_channel */
    OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_set_channel::should not call this function. call wal_ioctl_set_channel!}\r\n");
    return -OAL_EFAIL;
#else
    oal_net_device_stru         *pst_cfg_net_dev;
    mac_cfg_channel_param_stru  *pst_channel_param;
    wal_msg_write_stru           st_write_msg;
    wlan_channel_bandwidth_enum_uint8   en_bandwith;
    oal_int32                    l_ret;

    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_chan))
    {
        return -OAL_EINVAL;
    }

    pst_cfg_net_dev = oal_dev_get_by_name("Hisilicon0");    /* ????????VAP ??net_device ???? */

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /* ????????????????WITP ?????????? */
    switch(en_channel_type)
    {
        case NL80211_CHAN_NO_HT:
            en_bandwith = WLAN_BAND_WIDTH_20M;
            break;
        case NL80211_CHAN_HT20:
            en_bandwith = WLAN_BAND_WIDTH_20M;
            break;
        case NL80211_CHAN_HT40MINUS:
            en_bandwith = WLAN_BAND_WIDTH_40MINUS;
            break;
        case NL80211_CHAN_HT40PLUS:
            en_bandwith = WLAN_BAND_WIDTH_40PLUS;
            break;
        default:
            return -OAL_EINVAL;
    }

    /* ???????? */
    pst_channel_param = (mac_cfg_channel_param_stru *)(st_write_msg.auc_value);
    pst_channel_param->uc_channel   = (oal_uint8)pst_chan->hw_value;
    pst_channel_param->en_band      = pst_chan->band;
    pst_channel_param->en_bandwidth = en_bandwith;

    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_SET_CHANNEL, OAL_SIZEOF(mac_cfg_channel_param_stru));

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_cfg_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_channel_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
#endif
}
#endif
/*lint +e40*/


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34))
OAL_STATIC oal_int32 wal_cfg80211_set_wiphy_params(oal_wiphy_stru *pst_wiphy, oal_uint32 ul_changed)
{
#if 1
        /* ????HOSTAPD ????RTS ?????????????? ????????wal_ioctl_set_frag?? wal_ioctl_set_rts */
        OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_set_wiphy_params::should not call this function.call wal_ioctl_set_frag/wal_ioctl_set_rts!}\r\n");
        return OAL_SUCC;
#else

    oal_net_device_stru         *pst_cfg_net_dev;
    mac_cfg_wiphy_param_stru    *pst_wiphy_param;
    wal_msg_write_stru           st_write_msg;
    oal_int32                    l_ret;

    if (OAL_PTR_NULL == pst_wiphy)
    {
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_set_wiphy_params::pst_wiphy = NULL!}\r\n");
        return -OAL_EINVAL;
    }

    pst_cfg_net_dev = oal_dev_get_by_name("Hisilicon0");    /* ????????VAP ??net_device ???? */
    /* ????oal_dev_get_by_name????????????oal_dev_put??net_dev?????????????? */
    oal_dev_put(pst_cfg_net_dev);

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/

    /* ???????? */
    pst_wiphy_param = (mac_cfg_wiphy_param_stru *)(st_write_msg.auc_value);
    oal_memset(pst_wiphy_param, 0, sizeof(mac_cfg_wiphy_param_stru));

    if (ul_changed & WIPHY_PARAM_FRAG_THRESHOLD)
    {
        OAM_INFO_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_set_wiphy_params::wiphy->frag_threshold = %08X!}\r\n", pst_wiphy->frag_threshold);
        pst_wiphy_param->ul_frag_threshold         = pst_wiphy->frag_threshold;
        pst_wiphy_param->uc_frag_threshold_changed = OAL_TRUE;

        if (pst_wiphy_param->ul_frag_threshold > WAL_MAX_FRAG_THRESHOLD)
        {
            pst_wiphy_param->ul_frag_threshold = WAL_MAX_FRAG_THRESHOLD;
        }
        if (pst_wiphy_param->ul_frag_threshold < WAL_MIN_FRAG_THRESHOLD)
        {
            pst_wiphy_param->ul_frag_threshold = WAL_MIN_FRAG_THRESHOLD;
        }
    }

    if (ul_changed & WIPHY_PARAM_RTS_THRESHOLD)
    {
        OAM_INFO_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_set_wiphy_params::wiphy->frag_threshold = %08X!}\r\n", pst_wiphy->frag_threshold);
        pst_wiphy_param->ul_rts_threshold         = pst_wiphy->rts_threshold;
        pst_wiphy_param->uc_rts_threshold_changed = OAL_TRUE;

        if (pst_wiphy_param->ul_rts_threshold < WAL_MIN_RTS_THRESHOLD)
        {
            pst_wiphy_param->ul_rts_threshold = WAL_MIN_RTS_THRESHOLD;
        }

        if (pst_wiphy_param->ul_rts_threshold > WAL_MAX_RTS_THRESHOLD)
        {
            pst_wiphy_param->ul_rts_threshold = WAL_MAX_RTS_THRESHOLD;
        }
    }

    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_SET_WIPHY_PARAMS, OAL_SIZEOF(mac_cfg_wiphy_param_stru));

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_cfg_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_wiphy_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_set_wiphy_params::return err code %d!}\r\n", l_ret);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
#endif
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 44))


OAL_STATIC oal_int32 wal_cfg80211_set_beacon(
                oal_wiphy_stru        *pst_wiphy,
                oal_net_device_stru   *pst_dev,
                oal_beacon_parameters *pst_beacon_info)
{
    mac_beacon_param_stru    st_beacon_param;  /* beacon info struct */
    wal_msg_write_stru       st_write_msg;
    mac_vap_stru            *pst_mac_vap;
    oal_int32                l_loop = 0;
    oal_uint32               ul_ret = 0;
    oal_int32                l_ret = 0;
    oal_uint8                uc_vap_id;
    oal_uint8               *puc_ie;
    mac_cfg_ssid_param_stru *pst_ssid_param;
    oal_uint8                uc_ssid_len;

    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_dev) || (OAL_PTR_NULL == pst_beacon_info))
    {
        OAM_ERROR_LOG3(0, OAM_SF_ANY, "{wal_cfg80211_set_beacon::pst_wiphy = %x, pst_dev = %x, pst_beacon_info = %x!}\r\n",
                         pst_wiphy, pst_dev, pst_beacon_info);
        return -OAL_EINVAL;
    }

    if(OAL_PTR_NULL == pst_beacon_info->head)
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_set_beacon::pst_beacon_info->head %x!}\r\n", pst_beacon_info->head);
        return -OAL_EINVAL;
    }

    /* ????vap id */
    pst_mac_vap = OAL_NET_DEV_PRIV(pst_dev);
    uc_vap_id   = pst_mac_vap->uc_vap_id;

    /* ??????beacon interval ??DTIM_PERIOD ???? */
    oal_memset(&st_beacon_param, 0, sizeof(mac_beacon_param_stru));
    st_beacon_param.l_interval    = pst_beacon_info->interval;
    st_beacon_param.l_dtim_period = pst_beacon_info->dtim_period;

    puc_ie = mac_get_ssid(pst_beacon_info->head + MAC_80211_FRAME_LEN, (pst_beacon_info->head_len - MAC_80211_FRAME_LEN), &uc_ssid_len);
    /* ????SSID????????:(1)??????0??(2)??????????ssid???????????????? */
    st_beacon_param.uc_hidden_ssid = 0;
    if (OAL_TRUE == mac_is_hide_ssid(puc_ie, uc_ssid_len))
    {
        st_beacon_param.uc_hidden_ssid = 1;
    }

    /*****************************************************************************
        1. ????????????????
    *****************************************************************************/
    /* ???? WPA/WPA2 ???????? */
    if (OAL_PTR_NULL == pst_beacon_info->tail || OAL_PTR_NULL == pst_beacon_info->head)
    {
        OAM_ERROR_LOG2(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_set_beacon::beacon frame error tail = %d, head = %d!}\r\n",
                       pst_beacon_info->tail, pst_beacon_info->head);
        return -OAL_EINVAL;
    }

    ul_ret = wal_parse_wpa_wpa2_ie(pst_beacon_info, &st_beacon_param);
    if (OAL_SUCC != ul_ret)
    {
        OAM_WARNING_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_set_beacon::Failed to parse WPA/WPA2 ie!}\r\n");
        return -OAL_EINVAL;
    }

    ul_ret = wal_parse_ht_vht_ie(pst_mac_vap, pst_beacon_info, &st_beacon_param);
    if (OAL_SUCC != ul_ret)
    {
        OAM_WARNING_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_set_beacon::Failed to parse HT/VHT ie!}\r\n");
        return -OAL_EINVAL;
    }


   OAM_INFO_LOG3(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_set_beacon::crypto_mode=%d, group_crypt=%d, en_protocol=%d!}\r\n",
                  st_beacon_param.uc_crypto_mode,
                  st_beacon_param.uc_group_crypto,
                  st_beacon_param.en_protocol);

   OAM_INFO_LOG3(uc_vap_id, OAM_SF_ANY, "auth_type[0]=%d, auth_type[1]=%d, hidden_ssid=%d",
                 st_beacon_param.auc_auth_type[0],
                 st_beacon_param.auc_auth_type[1],
                 st_beacon_param.uc_hidden_ssid);
 #ifdef _PRE_WLAN_FEATURE_11D
    /* ??????14????????????????????11b??????????????14????11b???? ????11b */
    if ((14 == pst_mac_vap->st_channel.uc_chan_number) && (WLAN_LEGACY_11B_MODE != st_beacon_param.en_protocol))
    {
        OAM_ERROR_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_set_beacon::Now change protocol to 11b!}\r\n");
        st_beacon_param.en_protocol = WLAN_LEGACY_11B_MODE;
    }
#endif

    for (l_loop = 0; l_loop < MAC_PAIRWISE_CIPHER_SUITES_NUM; l_loop++)
    {
        OAM_INFO_LOG2(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_set_beacon::Wpa pariwise[%d] = %d!}\r\n", l_loop, st_beacon_param.auc_pairwise_crypto_wpa[l_loop]);
    }

    for (l_loop = 0; l_loop < MAC_PAIRWISE_CIPHER_SUITES_NUM; l_loop++)
    {
        OAM_INFO_LOG2(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_set_beacon::Wpa2 pariwise[%d] = %d!}\r\n",
                     l_loop, st_beacon_param.auc_pairwise_crypto_wpa2[l_loop]);
    }

    /*????????????*/
    st_beacon_param.en_operation_type = MAC_SET_BEACON;

    /* ???? msg ??????*/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_CONFIG_BEACON, OAL_SIZEOF(mac_beacon_param_stru));

    /* ???? msg ?????? */
    oal_memcopy(st_write_msg.auc_value, &st_beacon_param, OAL_SIZEOF(mac_beacon_param_stru));

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_beacon_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_beacon::Failed to start addset beacon!}\r\n");
        return -OAL_EFAIL;
    }

    /*****************************************************************************
        2. ????SSID????????
    *****************************************************************************/
    if (0 != uc_ssid_len)
    {
        WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_SSID, OAL_SIZEOF(mac_cfg_ssid_param_stru));

        pst_ssid_param = (mac_cfg_ssid_param_stru *)(st_write_msg.auc_value);
        pst_ssid_param->uc_ssid_len = uc_ssid_len;
        oal_memcopy(pst_ssid_param->ac_ssid, puc_ie, uc_ssid_len);

        l_ret = wal_send_cfg_event(pst_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_ssid_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

        if (OAL_SUCC != l_ret)
        {
            OAM_WARNING_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_beacon::fail to send ssid cfg msg!}\r\n");
            return -OAL_EFAIL;
        }

    }

    /* 3. ????WPS???????? */
#if 0
    ul_ret = wal_parse_beacon_wps_ie(pst_mac_vap, pst_beacon_info);
    if (OAL_SUCC != ul_ret)
    {
        return -OAL_EINVAL;
    }
#endif

    return OAL_SUCC;
}


OAL_STATIC oal_int32 wal_cfg80211_add_beacon(
                oal_wiphy_stru        *pst_wiphy,
                oal_net_device_stru   *pst_dev,
                oal_beacon_parameters *pst_beacon_info)
{
    mac_beacon_param_stru    st_beacon_param;  /* beacon info struct */
    wal_msg_write_stru       st_write_msg;
    mac_vap_stru            *pst_mac_vap;
    oal_int32                l_loop = 0;
    oal_uint32               ul_ret = 0;
    oal_int32                l_ret = 0;
    oal_uint8                uc_vap_id;
    oal_uint8               *puc_ie;
    mac_cfg_ssid_param_stru *pst_ssid_param;
    oal_uint8                uc_ssid_len;

    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_dev) || (OAL_PTR_NULL == pst_beacon_info))
    {
        OAM_ERROR_LOG3(0, OAM_SF_ANY, "{wal_cfg80211_add_beacon::pst_wiphy = %x, pst_dev = %x, pst_beacon_info = %x!}\r\n",
                         pst_wiphy, pst_dev, pst_beacon_info);
        return -OAL_EINVAL;
    }

    if(OAL_PTR_NULL == pst_beacon_info->head)
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_add_beacon::pst_beacon_info->head %x!}\r\n", pst_beacon_info->head);
        return -OAL_EINVAL;
    }

    /* ????vap id */
    pst_mac_vap = OAL_NET_DEV_PRIV(pst_dev);
    uc_vap_id   = pst_mac_vap->uc_vap_id;

    /* ??????beacon interval ??DTIM_PERIOD ???? */
    oal_memset(&st_beacon_param, 0, sizeof(mac_beacon_param_stru));
    st_beacon_param.l_interval    = pst_beacon_info->interval;
    st_beacon_param.l_dtim_period = pst_beacon_info->dtim_period;

    puc_ie = mac_get_ssid(pst_beacon_info->head + MAC_80211_FRAME_LEN, (pst_beacon_info->head_len - MAC_80211_FRAME_LEN), &uc_ssid_len);
    /* ????SSID????????:(1)??????0??(2)??????????ssid???????????????? */
    st_beacon_param.uc_hidden_ssid = 0;
    if (OAL_TRUE == mac_is_hide_ssid(puc_ie, uc_ssid_len))
    {
        st_beacon_param.uc_hidden_ssid = 1;
    }

    /*****************************************************************************
        1. ????????????????
    *****************************************************************************/
    /* ???? WPA/WPA2 ???????? */
    if (OAL_PTR_NULL == pst_beacon_info->tail || OAL_PTR_NULL == pst_beacon_info->head)
    {
        OAM_ERROR_LOG2(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_beacon::beacon frame error tail = %d, head = %d!}\r\n",
                       pst_beacon_info->tail, pst_beacon_info->head);
        return -OAL_EINVAL;
    }

    ul_ret = wal_parse_wpa_wpa2_ie(pst_beacon_info, &st_beacon_param);
    if (OAL_SUCC != ul_ret)
    {
        OAM_WARNING_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_beacon::Failed to parse WPA/WPA2 ie!}\r\n");
        return -OAL_EINVAL;
    }

    ul_ret = wal_parse_ht_vht_ie(pst_mac_vap, pst_beacon_info, &st_beacon_param);
    if (OAL_SUCC != ul_ret)
    {
        OAM_WARNING_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_beacon::Failed to parse HT/VHT ie!}\r\n");
        return -OAL_EINVAL;
    }


   OAM_INFO_LOG3(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_beacon::crypto_mode=%d, group_crypt=%d, en_protocol=%d!}\r\n",
                  st_beacon_param.uc_crypto_mode,
                  st_beacon_param.uc_group_crypto,
                  st_beacon_param.en_protocol);

   OAM_INFO_LOG3(uc_vap_id, OAM_SF_ANY, "auth_type[0]=%d, auth_type[1]=%d, hidden_ssid=%d",
                 st_beacon_param.auc_auth_type[0],
                 st_beacon_param.auc_auth_type[1],
                 st_beacon_param.uc_hidden_ssid);
 #ifdef _PRE_WLAN_FEATURE_11D
    /* ??????14????????????????????11b??????????????14????11b???? ????11b */
    if ((14 == pst_mac_vap->st_channel.uc_chan_number) && (WLAN_LEGACY_11B_MODE != st_beacon_param.en_protocol))
    {
        OAM_ERROR_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_beacon::Now change protocol to 11b!}\r\n");
        st_beacon_param.en_protocol = WLAN_LEGACY_11B_MODE;
    }
#endif

    for (l_loop = 0; l_loop < MAC_PAIRWISE_CIPHER_SUITES_NUM; l_loop++)
    {
        OAM_INFO_LOG2(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_beacon::Wpa pariwise[%d] = %d!}\r\n", l_loop, st_beacon_param.auc_pairwise_crypto_wpa[l_loop]);
    }

    for (l_loop = 0; l_loop < MAC_PAIRWISE_CIPHER_SUITES_NUM; l_loop++)
    {
        OAM_INFO_LOG2(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_beacon::Wpa2 pariwise[%d] = %d!}\r\n",
                     l_loop, st_beacon_param.auc_pairwise_crypto_wpa2[l_loop]);
    }

    /*????????????*/
    st_beacon_param.en_operation_type = MAC_ADD_BEACON;

    /* ???? msg ??????*/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_CONFIG_BEACON, OAL_SIZEOF(mac_beacon_param_stru));

    /* ???? msg ?????? */
    oal_memcopy(st_write_msg.auc_value, &st_beacon_param, OAL_SIZEOF(mac_beacon_param_stru));

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_beacon_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_beacon::Failed to start addset beacon!}\r\n");
        return -OAL_EFAIL;
    }

    /*****************************************************************************
        2. ????SSID????????
    *****************************************************************************/
    if (0 != uc_ssid_len)
    {
        WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_SSID, OAL_SIZEOF(mac_cfg_ssid_param_stru));

        pst_ssid_param = (mac_cfg_ssid_param_stru *)(st_write_msg.auc_value);
        pst_ssid_param->uc_ssid_len = uc_ssid_len;
        oal_memcopy(pst_ssid_param->ac_ssid, puc_ie, uc_ssid_len);

        l_ret = wal_send_cfg_event(pst_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_ssid_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

        if (OAL_SUCC != l_ret)
        {
            OAM_WARNING_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_beacon::fail to send ssid cfg msg!}\r\n");
            return -OAL_EFAIL;
        }

    }

    /* 3. ????WPS???????? */
#if 0
    ul_ret = wal_parse_beacon_wps_ie(pst_mac_vap, pst_beacon_info);
    if (OAL_SUCC != ul_ret)
    {
        return -OAL_EINVAL;
    }
#endif
    /* 4.????Wmm???????? */
    ul_ret = wal_parse_wmm_ie(pst_dev, pst_mac_vap, pst_beacon_info);
    if (OAL_SUCC != ul_ret)
    {
        OAM_WARNING_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_beacon::Failed to parse wmm ie!}\r\n");
        return -OAL_EINVAL;
    }

    return OAL_SUCC;
}
#endif

#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 44)) || (_PRE_OS_VERSION_WIN32 == _PRE_OS_VERSION))
#if 0

OAL_STATIC oal_int32 wal_cfg80211_bringup_ap(oal_net_device_stru *pst_netdev)
{
    wal_msg_write_stru st_write_msg;
    oal_int32          l_ret = 0;

    /* ???????? */
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_START_VAP, OAL_SIZEOF(mac_cfg_start_vap_param_stru));
    ((mac_cfg_start_vap_param_stru *)st_write_msg.auc_value)->pst_net_dev = pst_netdev;

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_netdev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_start_vap_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_bringup_ap::failed to bring up ap, error[%d]}", l_ret);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}
#endif


OAL_STATIC oal_int32 wal_cfg80211_set_ssid(oal_net_device_stru *pst_netdev,
                                                oal_uint8           *puc_ssid_ie,
                                                oal_uint8            uc_ssid_len)
{
    wal_msg_write_stru           st_write_msg;
    mac_cfg_ssid_param_stru     *pst_ssid_param;
    oal_int32                    l_ret = 0;

    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_SSID, OAL_SIZEOF(mac_cfg_ssid_param_stru));

    pst_ssid_param = (mac_cfg_ssid_param_stru *)(st_write_msg.auc_value);
    pst_ssid_param->uc_ssid_len = uc_ssid_len;
    oal_memcopy(pst_ssid_param->ac_ssid, (oal_int8 *)puc_ssid_ie, uc_ssid_len);

    l_ret = wal_send_cfg_event(pst_netdev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_ssid_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_set_ssid::fail to send ssid cfg msg, error[%d]}", l_ret);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}




OAL_STATIC oal_int32 wal_cfg80211_fill_beacon_param(mac_vap_stru               *pst_mac_vap,
                                                           oal_beacon_data_stru        *pst_beacon_info,
                                                           mac_beacon_param_stru       *pst_beacon_param)
{
    oal_beacon_parameters st_beacon_info_tmp;
    oal_uint32  ul_loop;
    oal_uint32  ul_ret;
    oal_uint8  *puc_beacon_info_tmp;
    oal_uint32  ul_beacon_head_len;
    oal_uint32  ul_beacon_tail_len;
    oal_uint8   uc_vap_id;


    if (OAL_PTR_NULL == pst_mac_vap
       || OAL_PTR_NULL == pst_beacon_info
       || OAL_PTR_NULL == pst_beacon_param)
    {
        OAM_ERROR_LOG3(0, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::param is NULL. pst_mac_vap=0x%x, pst_beacon_info=0x%x, pst_beacon_param=0x%x",
           pst_mac_vap, pst_beacon_info, pst_beacon_param);
        return -OAL_EINVAL;
    }

    uc_vap_id = pst_mac_vap->uc_vap_id;
    /*****************************************************************************
        1.????????ie??????
    *****************************************************************************/
    if (OAL_PTR_NULL == pst_beacon_info->tail || OAL_PTR_NULL == pst_beacon_info->head)
    {
        OAM_ERROR_LOG2(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::beacon frame error tail = %x, head = %x!}",
                       pst_beacon_info->tail, pst_beacon_info->head);
        return -OAL_EINVAL;
    }

    /* ??????????????????????beacon header????????????????(24)+TSF(8)+BEACON_INTERVAL(2)+CAP_INFO(2) */
    if (pst_beacon_info->head_len < (MAC_80211_FRAME_LEN + MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN))
    {
        OAM_ERROR_LOG1(uc_vap_id, OAM_SF_CFG, "{wal_cfg80211_fill_beacon_param::beacon_info head len[%d] is too short.}",
                        pst_beacon_info->head_len);
        return -OAL_EINVAL;
    }

    ul_beacon_head_len = (oal_uint32)pst_beacon_info->head_len;
    ul_beacon_tail_len = (oal_uint32)pst_beacon_info->tail_len;

    if ((ul_beacon_head_len + ul_beacon_tail_len) < ul_beacon_head_len) {
        OAM_ERROR_LOG2(0, OAM_SF_CFG,
            "{wal_cfg80211_fill_beacon_param::beacon_head_len[%d], beacon_tail_len[%d]. len abnormal.}",
            ul_beacon_head_len,
            ul_beacon_tail_len);
        return -OAL_EINVAL;
    }

    puc_beacon_info_tmp = (oal_uint8 *)(oal_memalloc(ul_beacon_head_len + ul_beacon_tail_len));
    if (OAL_PTR_NULL == puc_beacon_info_tmp) {
        OAM_ERROR_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::puc_beacon_info_tmp memalloc failed.}");
        return -OAL_EINVAL;
    }

    oal_memcopy(puc_beacon_info_tmp, pst_beacon_info->head, ul_beacon_head_len);
    oal_memcopy(puc_beacon_info_tmp + ul_beacon_head_len, pst_beacon_info->tail, ul_beacon_tail_len);

    /* ????????51??????????????????????????????????????51?????????????????????????????????? */
    OAL_MEMZERO(&st_beacon_info_tmp, sizeof(st_beacon_info_tmp));
    st_beacon_info_tmp.head     = puc_beacon_info_tmp;
    st_beacon_info_tmp.head_len = (oal_int32)ul_beacon_head_len;
    st_beacon_info_tmp.tail     = puc_beacon_info_tmp + ul_beacon_head_len;
    st_beacon_info_tmp.tail_len = (oal_int32)ul_beacon_tail_len;

    /* ???? WPA/WPA2 ???????? */
    ul_ret = wal_parse_wpa_wpa2_ie(&st_beacon_info_tmp, pst_beacon_param);
    if (OAL_SUCC != ul_ret)
    {
        OAM_WARNING_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::failed to parse WPA/WPA2 ie!}");
        oal_free(puc_beacon_info_tmp);
        return -OAL_EINVAL;
    }

    /* ????????????????linux??????????????win32???? TBD */
    ul_ret = wal_parse_ht_vht_ie(pst_mac_vap, &st_beacon_info_tmp, pst_beacon_param);
    if (OAL_SUCC != ul_ret)
    {
        OAM_WARNING_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::failed to parse HT/VHT ie!}");
        oal_free(puc_beacon_info_tmp);
        return -OAL_EINVAL;
    }

    /* ?????????????????? */
    oal_free(puc_beacon_info_tmp);

    OAM_WARNING_LOG3(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::crypto_mode=%d, group_crypt=%d, en_protocol=%d!}",
                  pst_beacon_param->uc_crypto_mode,
                  pst_beacon_param->uc_group_crypto,
                  pst_beacon_param->en_protocol);

    OAM_WARNING_LOG2(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::auth_type[0]=%d, auth_type[1]=%d}",
                  pst_beacon_param->auc_auth_type[0],
                  pst_beacon_param->auc_auth_type[1]);

#ifdef _PRE_WLAN_FEATURE_11D
    /* ??????14????????????????????11b??????????????14????11b???? ????11b */
    if ((14 == pst_mac_vap->st_channel.uc_chan_number) && (WLAN_LEGACY_11B_MODE != pst_beacon_param->en_protocol))
    {
        OAM_ERROR_LOG1(uc_vap_id, OAM_SF_ANY,
                       "{wal_cfg80211_fill_beacon_param::ch 14 should in 11b, but is %d!}", pst_beacon_param->en_protocol);
        OAM_ERROR_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::change protocol to 11b!}");
        pst_beacon_param->en_protocol = WLAN_LEGACY_11B_MODE;
    }
#endif

    for (ul_loop = 0; ul_loop < MAC_PAIRWISE_CIPHER_SUITES_NUM; ul_loop++)
    {
        OAM_WARNING_LOG2(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::wpa pariwise[%d] = %d!}",
                      ul_loop, pst_beacon_param->auc_pairwise_crypto_wpa[ul_loop]);
    }

    for (ul_loop = 0; ul_loop < MAC_PAIRWISE_CIPHER_SUITES_NUM; ul_loop++)
    {
        OAM_WARNING_LOG2(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::wpa2 pariwise[%d] = %d!}",
                     ul_loop, pst_beacon_param->auc_pairwise_crypto_wpa2[ul_loop]);
    }

    return OAL_SUCC;
}


OAL_STATIC oal_int32 wal_cfg80211_change_beacon(oal_wiphy_stru         *pst_wiphy,
                                                        oal_net_device_stru     *pst_netdev,
                                                        oal_beacon_data_stru    *pst_beacon_info)
{
    mac_beacon_param_stru        st_beacon_param;  /* beacon info struct */
    wal_msg_write_stru           st_write_msg;
    mac_vap_stru                *pst_mac_vap;
    oal_int32                    l_ret = 0;

    OAM_INFO_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_change_beacon::enter here.}");

    /* ?????????????? */
    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_netdev) || (OAL_PTR_NULL == pst_beacon_info))
    {
        OAM_ERROR_LOG3(0, OAM_SF_ANY, "{wal_cfg80211_change_beacon::pst_wiphy = %x, pst_netdev = %x, pst_beacon_info = %x!}",
                         pst_wiphy, pst_netdev, pst_beacon_info);
        return -OAL_EINVAL;
    }
#ifdef _PRE_WLAN_FEATURE_DFR
    if (g_st_dfr_info.bit_device_reset_process_flag)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_change_beacon::dfr_process_status[%d]!}",
            g_st_dfr_info.bit_device_reset_process_flag);
        return OAL_SUCC;
    }
#endif //#ifdef _PRE_WLAN_FEATURE_DFR

    /* ????vap id */
    pst_mac_vap = OAL_NET_DEV_PRIV(pst_netdev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_change_beacon::pst_mac_vap = %x}", pst_mac_vap);
        return -OAL_EINVAL;
    }

    /* ??????beacon interval ??DTIM_PERIOD ???? */
    oal_memset(&st_beacon_param, 0, sizeof(mac_beacon_param_stru));

    l_ret = wal_cfg80211_fill_beacon_param(pst_mac_vap, pst_beacon_info, &st_beacon_param);
    if (OAL_SUCC != l_ret)
    {
        OAM_ERROR_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_change_beacon::failed to fill beacon param, error[%d]}", l_ret);
        return -OAL_EINVAL;
    }

    /*????????????*/
    st_beacon_param.en_operation_type = MAC_SET_BEACON;

    /* ???? msg ??????*/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_CONFIG_BEACON, OAL_SIZEOF(mac_beacon_param_stru));

    /* ???? msg ?????? */
    oal_memcopy(st_write_msg.auc_value, &st_beacon_param, OAL_SIZEOF(mac_beacon_param_stru));

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_netdev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_beacon_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_change_beacon::Failed to start addset beacon, error[%d]}", l_ret);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}


OAL_STATIC oal_int32 wal_cfg80211_convert_width_to_value(oal_int32 l_channel_width)
{
    oal_int32 l_channel_width_value = 0;

    switch (l_channel_width)
    {
        case 0:
        case 1:
            l_channel_width_value = 20;
            break;
        case 2:
            l_channel_width_value = 40;
            break;
        case 3:
        case 4:
            l_channel_width_value = 80;
            break;
        case 5:
            l_channel_width_value = 160;
            break;
        default:
            break;
    }

    return l_channel_width_value;
}


OAL_STATIC oal_int32 wal_cfg80211_set_channel_info(oal_wiphy_stru      *pst_wiphy,
                                                          oal_net_device_stru *pst_netdev)
{
    mac_cfg_channel_param_stru          *pst_channel_param;
    oal_ieee80211_channel               *pst_channel;
    wlan_channel_bandwidth_enum_uint8    en_bandwidth;
    wal_msg_write_stru                   st_write_msg;
    oal_uint32                           ul_err_code;
    oal_int32                            l_channel;
    oal_int32                            l_center_freq1;
    oal_int32                            l_bandwidth;
    oal_int32                            l_bandwidth_value;
    wal_msg_stru                        *pst_rsp_msg = OAL_PTR_NULL;
    oal_int32                            l_ret;
    mac_vap_stru                        *pst_mac_vap;
    oal_uint8                            uc_vap_id;
    oal_int32                            l_channel_center_freq;

    /* ????vap id */
    pst_mac_vap = OAL_NET_DEV_PRIV(pst_netdev);
    uc_vap_id   = pst_mac_vap->uc_vap_id;

    l_bandwidth    = pst_netdev->ieee80211_ptr->preset_chandef.width;
    l_center_freq1 = pst_netdev->ieee80211_ptr->preset_chandef.center_freq1;
    pst_channel    = pst_netdev->ieee80211_ptr->preset_chandef.chan;
    l_channel      = pst_channel->hw_value;

    OAM_WARNING_LOG3(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_set_channel::l_bandwidth = %d, l_center_freq1 = %d, l_channel = %d.}",
                  l_bandwidth, l_center_freq1, l_channel);

    /* ?????????????????????? */
    l_ret = (oal_int32)mac_is_channel_num_valid(pst_channel->band, (oal_uint8)l_channel);
    if (l_ret != OAL_SUCC)
    {
        OAM_WARNING_LOG2(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_set_channel::channel num is invalid. band, ch num [%d] [%d]!}\r\n", pst_channel->band, l_channel);
        return -OAL_EINVAL;
    }

    /* ????????????????WITP ?????????? */
    l_channel_center_freq = oal_ieee80211_frequency_to_channel(l_center_freq1);
    l_bandwidth_value = wal_cfg80211_convert_width_to_value(l_bandwidth);
    if (0 == l_bandwidth_value)
    {
        OAM_ERROR_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_set_channel::channel width is invalid, l_bandwidth = %d.\r\n", l_bandwidth);
        return -OAL_EINVAL;
    }

    if (80 == l_bandwidth_value)
    {
        en_bandwidth = mac_get_bandwith_from_center_freq_seg0((oal_uint8)l_channel, (oal_uint8)l_channel_center_freq);
#if (_PRE_WLAN_CHIP_ASIC != _PRE_WLAN_CHIP_VERSION)
        if((WLAN_BAND_WIDTH_80PLUSPLUS == en_bandwidth) || (WLAN_BAND_WIDTH_80PLUSMINUS == en_bandwidth))
        {
            en_bandwidth = WLAN_BAND_WIDTH_40PLUS;
        }
        else
        {
            en_bandwidth = WLAN_BAND_WIDTH_40MINUS;
        }
        OAM_WARNING_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_set_channel::FGPA is not support 80M,Set en_bandwidth = %d.\r\n", en_bandwidth);
#endif
    }
    else if (40 == l_bandwidth_value)
    {
        switch (l_channel_center_freq - l_channel)
        {
            case -2:
                en_bandwidth = WLAN_BAND_WIDTH_40MINUS;
                break;
            case 2:
                en_bandwidth = WLAN_BAND_WIDTH_40PLUS;
                break;
            default:
                en_bandwidth = WLAN_BAND_WIDTH_20M;
                break;
        }
    }
    else
    {
        en_bandwidth = WLAN_BAND_WIDTH_20M;
    }

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/

    /* ???????? */
    pst_channel_param = (mac_cfg_channel_param_stru *)(st_write_msg.auc_value);
    pst_channel_param->uc_channel   = (oal_uint8)pst_channel->hw_value;
    pst_channel_param->en_band      = pst_channel->band;
    pst_channel_param->en_bandwidth = en_bandwidth;

    OAM_WARNING_LOG3(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_set_channel::uc_channel = %d, en_band = %d, en_bandwidth = %d.}",
                     pst_channel_param->uc_channel,
                     pst_channel_param->en_band,
                     pst_channel_param->en_bandwidth);

    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_SET_CHANNEL, OAL_SIZEOF(mac_cfg_channel_param_stru));

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_netdev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_channel_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_TRUE,
                               &pst_rsp_msg);

    if(OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG1(0, OAM_SF_P2P, "{wal_cfg80211_set_channel_info::wal_send_cfg_event return err code: [%d]!}\r\n", l_ret);
        return -OAL_EFAIL;
    }

    /* ???????????????? */
    ul_err_code = wal_check_and_release_msg_resp(pst_rsp_msg);
    if(OAL_SUCC != ul_err_code)
    {
        OAM_ERROR_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_set_channel::wal_send_cfg_event return err code: [%u].}",
                       ul_err_code);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}


OAL_STATIC oal_int32 wal_cfg80211_start_ap(oal_wiphy_stru           *pst_wiphy,
                                                oal_net_device_stru      *pst_netdev,
                                                oal_ap_settings_stru     *pst_ap_settings)
{
    mac_beacon_param_stru        st_beacon_param;  /* beacon info struct */
    wal_msg_write_stru           st_write_msg;
    mac_vap_stru                *pst_mac_vap;
    oal_beacon_data_stru        *pst_beacon_info;
    oal_uint8                   *puc_ssid_ie;
    oal_int32                    l_ret = 0;
    oal_uint8                    uc_ssid_len;
    oal_uint8                    uc_vap_id;
    oal_uint8                    auc_ssid_ie[32];
    oal_int32                    l_ssid_len = 0;

    OAM_INFO_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_start_ap::enter here.}");

    /* ?????????????? */
    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_netdev) || (OAL_PTR_NULL == pst_ap_settings))
    {
        OAM_ERROR_LOG3(0, OAM_SF_ANY, "{wal_cfg80211_start_ap::pst_wiphy = %x, pst_netdev = %x, pst_ap_settings = %x!}",
                       pst_wiphy, pst_netdev, pst_ap_settings);
        return -OAL_EINVAL;
    }

    /* ????vap id */
    pst_mac_vap = OAL_NET_DEV_PRIV(pst_netdev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_start_ap::pst_mac_vap = %x}", pst_mac_vap);
        return -OAL_EINVAL;
    }

    uc_vap_id = pst_mac_vap->uc_vap_id;

    /*****************************************************************************
        1.????????
    *****************************************************************************/
    l_ret = wal_cfg80211_set_channel_info(pst_wiphy, pst_netdev);
    if (OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_start_ap::failed to set channel, return err code[%x]}", l_ret);
        return -OAL_EFAIL;
    }

    /*****************************************************************************
        2.????ssid??????
    *****************************************************************************/
    l_ssid_len = pst_ap_settings->ssid_len;
    if ((l_ssid_len > 32) || (l_ssid_len <= 0))
    {
         OAM_WARNING_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_start_ap::ssid len error, len[%d].}", l_ssid_len);
         return -OAL_EFAIL;
    }
    oal_memset(auc_ssid_ie, 0, sizeof(auc_ssid_ie));
    oal_memcopy(auc_ssid_ie, pst_ap_settings->ssid, (oal_uint32)l_ssid_len);
    puc_ssid_ie = auc_ssid_ie;
    uc_ssid_len = (oal_uint8)l_ssid_len;

    if (0 != uc_ssid_len)
    {
        l_ret = wal_cfg80211_set_ssid(pst_netdev, puc_ssid_ie, uc_ssid_len);
        if (OAL_SUCC != l_ret)
        {
            OAM_WARNING_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_start_ap::fail to send ssid cfg msg, error[%d]}", l_ret);
            return -OAL_EFAIL;
        }
    }

    /*****************************************************************************
        3.????beacon??????????tim period??????????????????
    *****************************************************************************/

    /* ??????beacon interval ??DTIM_PERIOD ???? */
    oal_memset(&st_beacon_param, 0, sizeof(mac_beacon_param_stru));
    st_beacon_param.l_interval    = pst_ap_settings->beacon_interval;
    st_beacon_param.l_dtim_period = pst_ap_settings->dtim_period;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 44))//TBD:1102 ??????????????????????????
    st_beacon_param.uc_hidden_ssid = (pst_ap_settings->hidden_ssid == 1);

    OAM_WARNING_LOG3(0, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::beacon_interval=%d, dtim_period=%d, hidden_ssid=%d!}",
                  pst_ap_settings->beacon_interval,
                  pst_ap_settings->dtim_period,
                  pst_ap_settings->hidden_ssid);
#endif
    pst_beacon_info               = &(pst_ap_settings->beacon);
    l_ret = wal_cfg80211_fill_beacon_param(pst_mac_vap, pst_beacon_info, &st_beacon_param);
    if (OAL_SUCC != l_ret)
    {
        OAM_ERROR_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_start_ap::failed to fill beacon param, error[%d]}", l_ret);
        return -OAL_EINVAL;
    }

    /*????????????*/
    st_beacon_param.en_operation_type = MAC_ADD_BEACON;

    /* ???? msg ??????*/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_CONFIG_BEACON, OAL_SIZEOF(mac_beacon_param_stru));

    /* ???? msg ?????? */
    oal_memcopy(st_write_msg.auc_value, &st_beacon_param, OAL_SIZEOF(mac_beacon_param_stru));

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_netdev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_beacon_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_start_ap::failed to start addset beacon, error[%d]}", l_ret);
        return -OAL_EFAIL;
    }

    /*****************************************************************************
        4.????ap
    *****************************************************************************/
#if defined(_PRE_PRODUCT_ID_HI110X_HOST)
    l_ret = wal_start_vap(pst_netdev);
#else
    l_ret = wal_netdev_open(pst_netdev);
#endif
    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_start_ap::failed to start ap, error[%d]}", l_ret);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}


OAL_STATIC oal_int32 wal_cfg80211_stop_ap(oal_wiphy_stru        *pst_wiphy,
                                                oal_net_device_stru *pst_netdev)
{
    wal_msg_write_stru           st_write_msg;
    mac_vap_stru                *pst_mac_vap;
    oal_int32                    l_ret = 0;
    oal_uint8                    uc_vap_id;

#ifdef _PRE_WLAN_FEATURE_P2P
    wlan_p2p_mode_enum_uint8 en_p2p_mode;
    oal_wireless_dev_stru   *pst_wdev;
#endif

    /* ?????????????? */
    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_netdev))
    {
        OAM_ERROR_LOG2(0, OAM_SF_ANY, "{wal_cfg80211_stop_ap::pst_wiphy = %x, pst_netdev = %x!}",
                       pst_wiphy, pst_netdev);
        return -OAL_EINVAL;
    }

#ifdef _PRE_WLAN_FEATURE_DFR
    if (g_st_dfr_info.bit_device_reset_process_flag)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_stop_ap::dfr_process_status[%d]!}",
            g_st_dfr_info.bit_device_reset_process_flag);
        return OAL_SUCC;
    }

#endif

    /* ????vap id */
    pst_mac_vap = OAL_NET_DEV_PRIV(pst_netdev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_stop_ap::can't get mac vap from netdevice priv data!}");
        return -OAL_EINVAL;
    }

    uc_vap_id   = pst_mac_vap->uc_vap_id;

    /* ????????????ap???? */
    if (WLAN_VAP_MODE_BSS_AP != pst_mac_vap->en_vap_mode)
    {
        OAM_ERROR_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_stop_ap::vap is not in ap mode!}");
        return -OAL_EINVAL;
    }

    /* ????netdev????running??????????????down */
    if (0 == (OAL_NETDEVICE_FLAGS(pst_netdev) & OAL_IFF_RUNNING))
    {
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_stop_ap::vap is already down!}\r\n");
        return OAL_SUCC;
    }

    /*****************************************************************************
        ??????????????ap
    *****************************************************************************/
    /* ???????? */
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_DOWN_VAP, OAL_SIZEOF(mac_cfg_start_vap_param_stru));

#ifdef _PRE_WLAN_FEATURE_P2P
    pst_wdev    = pst_netdev->ieee80211_ptr;
    en_p2p_mode = wal_wireless_iftype_to_mac_p2p_mode(pst_wdev->iftype);
    if (WLAN_P2P_BUTT == en_p2p_mode)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_stop_ap::wal_wireless_iftype_to_mac_p2p_mode return BUFF}\r\n");
        return -OAL_EINVAL;
    }
    OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_stop_ap::en_p2p_mode=%u}\r\n", en_p2p_mode);

    ((mac_cfg_start_vap_param_stru *)st_write_msg.auc_value)->en_p2p_mode = en_p2p_mode;
#endif

    ((mac_cfg_start_vap_param_stru *)st_write_msg.auc_value)->pst_net_dev = pst_netdev;

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_netdev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_start_vap_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_stop_ap::failed to stop ap, error[%d]}", l_ret);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}

#if 0

OAL_STATIC oal_int32 wal_cfg80211_get_mode(oal_net_device_stru      *pst_netdev,
                                                  wlan_protocol_enum_uint8 *puc_protocol_mode)
{
    oal_int32                       l_ret;
    wal_msg_query_stru              st_query_msg;
    wal_msg_stru                   *pst_rsp_msg;
    wal_msg_rsp_stru               *pst_query_rsp_msg;
    oal_uint8                       uc_prot_idx;
    mac_cfg_mode_param_stru        *pst_mode_param;
    mac_vap_stru                   *pst_mac_vap;

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/

    st_query_msg.en_wid = WLAN_CFGID_MODE;

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_netdev,
                               WAL_MSG_TYPE_QUERY,
                               WAL_MSG_WID_LENGTH,
                               (oal_uint8 *)&st_query_msg,
                               OAL_TRUE,
                               &pst_rsp_msg);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_get_mode::wal_alloc_cfg_event return err code %d!}", l_ret);
        return l_ret;
    }
#error  wal_send_cfg_event API had changed,please recode!

    /* ???????????? */
    pst_query_rsp_msg = (wal_msg_rsp_stru *)(pst_rsp_msg->auc_msg_data);
    OAM_INFO_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_get_mode::rsp msg wid %d!}", pst_query_rsp_msg->en_wid);

    pst_mode_param = (mac_cfg_mode_param_stru *)(pst_query_rsp_msg->auc_value);

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_netdev);
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mac_vap))
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_get_mode::null pointer.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    if (WLAN_VAP_MODE_BSS_AP == pst_mac_vap->en_vap_mode)
    {
        for (uc_prot_idx = 0; OAL_PTR_NULL != g_ast_mode_map[uc_prot_idx].pc_name; uc_prot_idx++)
        {
            if ((g_ast_mode_map[uc_prot_idx].en_mode == pst_mode_param->en_protocol) &&
                (g_ast_mode_map[uc_prot_idx].en_band == pst_mode_param->en_band) &&
                (g_ast_mode_map[uc_prot_idx].en_bandwidth == pst_mode_param->en_bandwidth))
            {
                break;
            }
        }
    }
    /* STA????????????????????AP?????????????????????????????????? */
    else if (WLAN_VAP_MODE_BSS_STA == pst_mac_vap->en_vap_mode)
    {
        for (uc_prot_idx = 0; OAL_PTR_NULL != g_ast_mode_map[uc_prot_idx].pc_name; uc_prot_idx++)
        {
            if (g_ast_mode_map[uc_prot_idx].en_mode == pst_mode_param->en_protocol)
            {
                break;
            }
        }
    }
    else
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_get_mode::vap mode error, vap mode = %d.}",
                       pst_mac_vap->en_vap_mode);
        return OAL_SUCC;
    }

    if (OAL_PTR_NULL == g_ast_mode_map[uc_prot_idx].pc_name)
    {
        OAM_ERROR_LOG2(0, OAM_SF_ANY, "{wal_cfg80211_get_mode::uc_prot_idx[%d], en_protocol[%d].}",
                       uc_prot_idx, pst_mode_param->en_protocol);
        return OAL_SUCC;
    }

    *puc_protocol_mode = g_ast_mode_map[uc_prot_idx].en_mode;
    return OAL_SUCC;
}


OAL_STATIC oal_int32 wal_cfg80211_set_mode(oal_net_device_stru      *pst_netdev,
                                                  wlan_protocol_enum_uint8 *puc_protocol_mode)
{
    mac_cfg_mode_param_stru    *pst_mode_param;
    wal_msg_write_stru          st_write_msg;
    oal_int32                   l_ret;
    oal_uint8                   uc_prot_idx;

    if (OAL_UNLIKELY((OAL_PTR_NULL == pst_netdev) || (OAL_PTR_NULL == puc_protocol_mode)))
    {
        OAM_ERROR_LOG2(0, OAM_SF_ANY, "{wal_cfg80211_set_mode::pst_net_dev = %x, puc_protocol_mode = %x.}",
                       pst_netdev, puc_protocol_mode);
        return -OAL_EFAUL;
    }

    for (uc_prot_idx = 0; OAL_PTR_NULL != g_ast_mode_map[uc_prot_idx].pc_name; uc_prot_idx++)
    {
        if (g_ast_mode_map[uc_prot_idx].en_mode == *puc_protocol_mode)
        {
            break;
        }
    }

    if (OAL_PTR_NULL == g_ast_mode_map[uc_prot_idx].pc_name)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_set_mode::un recognized protocol mode[%d]!}",
                         *puc_protocol_mode);
        return -OAL_EINVAL;
    }

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_MODE, OAL_SIZEOF(mac_cfg_mode_param_stru));

    pst_mode_param = (mac_cfg_mode_param_stru *)(st_write_msg.auc_value);
    pst_mode_param->en_protocol  = g_ast_mode_map[uc_prot_idx].en_mode;
    pst_mode_param->en_band      = g_ast_mode_map[uc_prot_idx].en_band;
    pst_mode_param->en_bandwidth = g_ast_mode_map[uc_prot_idx].en_bandwidth;

    OAM_INFO_LOG3(0, OAM_SF_CFG, "{wal_cfg80211_set_mode::protocol[%d],band[%d],bandwidth[%d]!}\r\n",
                  pst_mode_param->en_protocol, pst_mode_param->en_band, pst_mode_param->en_bandwidth);

    /* ???????? */
    l_ret = wal_send_cfg_event(pst_netdev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_mode_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_set_mode::wal_alloc_cfg_event return err code[%d]}", l_ret);
        return l_ret;
    }

    return OAL_SUCC;
}
#endif


OAL_STATIC oal_int32 wal_cfg80211_change_bss(oal_wiphy_stru        *pst_wiphy,
                                                    oal_net_device_stru   *pst_netdev,
                                                    oal_bss_parameters    *pst_bss_params)
{
#if 0
    mac_vap_stru                *pst_mac_vap;
    oal_int32                    l_ret = 0;
    oal_uint8                    uc_vap_id;
    wlan_protocol_enum_uint8     en_prev_protocol_mode = WLAN_PROTOCOL_BUTT;
    wlan_protocol_enum_uint8     en_curr_protocol_mode = WLAN_PROTOCOL_BUTT;

    OAM_INFO_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_change_bss::enter here.}");

    /* ?????????????? */
    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_netdev) || (OAL_PTR_NULL == pst_bss_params))
    {
        OAM_ERROR_LOG3(0, OAM_SF_ANY, "{wal_cfg80211_change_bss::pst_wiphy = %p, pst_netdev = %p, pst_bss_params = %p!}",
                       pst_wiphy, pst_netdev, pst_bss_params);
        return -OAL_EINVAL;
    }

    /* ????vap id */
    pst_mac_vap = OAL_NET_DEV_PRIV(pst_netdev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_change_bss::pst_mac_vap is null!}");
        return -OAL_EINVAL;
    }

    uc_vap_id = pst_mac_vap->uc_vap_id;

    /* ??????????bss??????cts???????????????????? */
    if (pst_bss_params->use_cts_prot >= 0)
    {
        /* do noting */
    }

    /* ??????????bss????????????????????0???????????? */
    if (pst_bss_params->use_short_preamble >= 0)
    {
        /* do noting */
    }

    if (pst_bss_params->use_short_slot_time >= 0)
    {
        /* do noting */
    }

    /* set ap isolate */
    if (pst_bss_params->ap_isolate >= 0)
    {
        /* do noting */
    }

    /* ?????????????????????????????????????? */
    if (pst_bss_params->basic_rates)
    {
        switch ((int)(pst_bss_params->basic_rates[pst_bss_params->basic_rates_len - 1]))
        {
            case 22: /* B only , rate 11 */
                en_curr_protocol_mode = WLAN_LEGACY_11B_MODE;
                break;
            case 108: /* G only , rate 54 */
                en_curr_protocol_mode = WLAN_MIXED_TWO_11G_MODE;
                break;
            default:
                en_curr_protocol_mode = WLAN_LEGACY_11B_MODE;
                break;
        }
    }

    if (pst_bss_params->ht_opmode >= 0)
    {
        en_curr_protocol_mode = WLAN_HT_MODE;
    }

    /*****************************************************************************
        1.????????????????????????????????????????????????????
    *****************************************************************************/
    l_ret = wal_cfg80211_get_mode(pst_netdev, &en_prev_protocol_mode);
    if (OAL_SUCC == l_ret)
    {
        /* ?????????????????????????????????????????????????????? */
        if (en_prev_protocol_mode == en_curr_protocol_mode)
        {
            OAM_INFO_LOG0(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_change_bss::old protocol mode = new protocol mode.}");
            return OAL_SUCC;
        }
    }
    else
    {
        OAM_ERROR_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_change_bss:: get mode failed, error[%d]}", l_ret);
    }

    /*****************************************************************************
        2.????ap
    *****************************************************************************/
    l_ret = wal_cfg80211_stop_ap(pst_wiphy, pst_netdev);
    if (OAL_SUCC != l_ret)
    {
        OAM_ERROR_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_change_bss::failed to stop ap, error[%d].}", l_ret);
        return -OAL_EINVAL;
    }

    /*****************************************************************************
        3.????????????
    *****************************************************************************/
    l_ret = wal_cfg80211_set_mode(pst_netdev, &en_curr_protocol_mode);
    if (OAL_SUCC != l_ret)
    {
        OAM_ERROR_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_change_bss::failed to set mode, error[%d].}", l_ret);
        return -OAL_EINVAL;
    }

    /*****************************************************************************
        4.????????ap
    *****************************************************************************/
    l_ret = wal_netdev_open(pst_netdev);
    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_ERROR_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_start_ap::failed to start ap, error[%d]}", l_ret);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
#else
    return OAL_SUCC;
#endif
}


OAL_STATIC oal_void  wal_cfg80211_print_sched_scan_req_info(oal_cfg80211_sched_scan_request_stru  *pst_request)
{
    oal_int8      ac_tmp_buff[200];
    oal_int32     l_loop = 0;

    /* ???????????? */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0))
    OAM_WARNING_LOG3(0, OAM_SF_SCAN,"wal_cfg80211_print_sched_scan_req_info::channels[%d],flags[%d],rssi_thold[%d]",
                pst_request->n_channels,
                pst_request->flags,
                pst_request->min_rssi_thold);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
    OAM_WARNING_LOG4(0, OAM_SF_SCAN,"wal_cfg80211_print_sched_scan_req_info::channels[%d],interval[%d]ms,flags[%d],rssi_thold[%d]",
                pst_request->n_channels,
                pst_request->interval,
                pst_request->flags,
                pst_request->min_rssi_thold);
#else
    OAM_WARNING_LOG4(0, OAM_SF_SCAN,"wal_cfg80211_print_sched_scan_req_info::channels[%d],interval[%d]ms,flags[%d],rssi_thold[%d]",
                pst_request->n_channels,
                pst_request->interval,
                pst_request->flags,
                pst_request->rssi_thold);
#endif


    /* ????ssid?????????? */
    for (l_loop = 0; l_loop < pst_request->n_match_sets; l_loop++)
    {
        OAL_MEMZERO(ac_tmp_buff, OAL_SIZEOF(ac_tmp_buff));
        OAL_SPRINTF(ac_tmp_buff, OAL_SIZEOF(ac_tmp_buff), "mactch_sets[%d] info, ssid_len[%d], ssid: %.32s.\n",
                   l_loop, pst_request->match_sets[l_loop].ssid.ssid_len, pst_request->match_sets[l_loop].ssid.ssid);
        oam_print(ac_tmp_buff);
    }

    for (l_loop = 0; l_loop < pst_request->n_ssids; l_loop++)
    {
        OAL_MEMZERO(ac_tmp_buff, OAL_SIZEOF(ac_tmp_buff));
        OAL_SPRINTF(ac_tmp_buff, OAL_SIZEOF(ac_tmp_buff), "ssids[%d] info, ssid_len[%d], ssid: %.32s.\n",
                   l_loop, pst_request->ssids[l_loop].ssid_len, pst_request->ssids[l_loop].ssid);
        oam_print(ac_tmp_buff);
    }

    return;
}



OAL_STATIC oal_bool_enum_uint8 wal_pno_scan_with_assigned_ssid(oal_cfg80211_ssid_stru *pst_ssid,
                                                                        oal_cfg80211_ssid_stru *pst_ssid_list,
                                                                        oal_int32 l_count)
{
    oal_int32 l_loop;

    if ((OAL_PTR_NULL == pst_ssid) || (OAL_PTR_NULL == pst_ssid_list))
    {
        return OAL_FALSE;
    }

    for (l_loop = 0; l_loop < l_count; l_loop++)
    {
        if ((pst_ssid->ssid_len == pst_ssid_list[l_loop].ssid_len)
            && (0 == oal_memcmp(pst_ssid->ssid, pst_ssid_list[l_loop].ssid, pst_ssid->ssid_len)))
        {
           return OAL_TRUE;
        }
    }
    return OAL_FALSE;
}


OAL_STATIC oal_int32 wal_cfg80211_sched_scan_start(oal_wiphy_stru                        *pst_wiphy,
                                                           oal_net_device_stru                   *pst_netdev,
                                                           oal_cfg80211_sched_scan_request_stru  *pst_request)
{
    hmac_device_stru               *pst_hmac_device;
    hmac_scan_stru                 *pst_scan_mgmt;
    mac_vap_stru                   *pst_mac_vap;
    oal_cfg80211_ssid_stru         *pst_ssid_tmp;
    oal_cfg80211_ssid_stru         *pst_scan_ssid_list;
    mac_pno_scan_stru               st_pno_scan_info;
    oal_int32                       l_loop = 0;
    oal_uint32                      ul_ret;

    /* ?????????????? */
    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_netdev) || (OAL_PTR_NULL == pst_request))
    {
        OAM_ERROR_LOG3(0, OAM_SF_CFG, "{wal_cfg80211_sched_scan_start::input param pointer is null, pst_wiphy[%p], pst_netdev[%p], pst_request[%p]!}",
                       pst_wiphy, pst_netdev, pst_request);
        return -OAL_EINVAL;
    }

#ifdef _PRE_WLAN_FEATURE_DFR
    if (g_st_dfr_info.bit_device_reset_process_flag)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_sched_scan_start:: dfr_process_status[%d]!}",
            g_st_dfr_info.bit_device_reset_process_flag);
        return -OAL_EFAIL;
    }
#endif //#ifdef _PRE_WLAN_FEATURE_DFR

    /* ????net_device ??????????mac_device_stru ???? */
    pst_mac_vap    = OAL_NET_DEV_PRIV(pst_netdev);
    if(NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_sched_scan_start:: pst_mac_vap is null!}");
        return -OAL_EINVAL;
    }

    pst_hmac_device = hmac_res_get_mac_dev(pst_mac_vap->uc_device_id);
    if (OAL_PTR_NULL == pst_hmac_device)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_sched_scan_start:: pst_mac_device is null!}");
        return -OAL_EINVAL;
    }

    pst_scan_mgmt = &(pst_hmac_device->st_scan_mgmt);

    /* ??????????????????????????abort???????? */
    if (OAL_PTR_NULL != pst_scan_mgmt->pst_request)
    {
        OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_sched_scan_start:: device is busy, stop current scan!}");

        wal_force_scan_complete(pst_netdev, OAL_TRUE);
    }

    /* ????????????????????????ssid?????????????????? */
    if (pst_request->n_match_sets <= 0)
    {
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_SCAN, "{wal_cfg80211_sched_scan_start::match_sets = %d!}", pst_request->n_match_sets);
        return -OAL_EINVAL;
    }

    /* ??????pno???????????????? */
    OAL_MEMZERO(&st_pno_scan_info, OAL_SIZEOF(st_pno_scan_info));

    /* ??????????????????ssid?????????????? */
    pst_scan_ssid_list = OAL_PTR_NULL;
    if (pst_request->n_ssids > 0)
    {
        pst_scan_ssid_list = pst_request->ssids;
    }
    for (l_loop = 0; l_loop < OAL_MIN(pst_request->n_match_sets, MAX_PNO_SSID_COUNT); l_loop++)
    {
        pst_ssid_tmp = &(pst_request->match_sets[l_loop].ssid);
        if (pst_ssid_tmp->ssid_len >= WLAN_SSID_MAX_LEN)
        {
            OAM_WARNING_LOG1(0, OAM_SF_SCAN, "{wal_cfg80211_sched_scan_start:: wrong ssid_len[%d]!}", pst_ssid_tmp->ssid_len);
            continue;
        }
        oal_memcopy(st_pno_scan_info.ast_match_ssid_set[l_loop].auc_ssid, pst_ssid_tmp->ssid, pst_ssid_tmp->ssid_len);
        st_pno_scan_info.ast_match_ssid_set[l_loop].auc_ssid[pst_ssid_tmp->ssid_len] = '\0';
        st_pno_scan_info.ast_match_ssid_set[l_loop].en_scan_ssid = wal_pno_scan_with_assigned_ssid(pst_ssid_tmp, pst_scan_ssid_list, pst_request->n_ssids);
        st_pno_scan_info.l_ssid_count++;
    }

    /* ???????????? */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
    st_pno_scan_info.l_rssi_thold         = pst_request->min_rssi_thold;
#else
    st_pno_scan_info.l_rssi_thold         = pst_request->rssi_thold;
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)) */
    //st_pno_scan_info.ul_pno_scan_interval = pst_request->interval;        /* ??????????????????10s */
    st_pno_scan_info.ul_pno_scan_interval = PNO_SCHED_SCAN_INTERVAL;        /* ??????????????60s */
    st_pno_scan_info.uc_pno_scan_repeat   = MAX_PNO_REPEAT_TIMES;

    /* ??????????PNO???????????????? */
    pst_scan_mgmt->pst_sched_scan_req     = pst_request;
    pst_scan_mgmt->en_sched_scan_complete = OAL_FALSE;

    /* ?????????????????????????????????????? */
    wal_cfg80211_print_sched_scan_req_info(pst_request);

    /* ????pno??????????hmac */
    ul_ret = wal_cfg80211_start_sched_scan(pst_netdev, &st_pno_scan_info);
    if (ul_ret != OAL_SUCC)
    {
        OAM_WARNING_LOG1(0, OAM_SF_SCAN, "{wal_cfg80211_sched_scan_start::wal_cfg80211_start_sched_scan fail[%d]!}",ul_ret);
        return -OAL_EBUSY;
    }

    return OAL_SUCC;
}


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
OAL_STATIC oal_int32 wal_cfg80211_sched_scan_stop(oal_wiphy_stru          *pst_wiphy,
                                                  oal_net_device_stru     *pst_netdev,
                                                  oal_uint64               ul_reqid)

#else
OAL_STATIC oal_int32 wal_cfg80211_sched_scan_stop(oal_wiphy_stru          *pst_wiphy,
                                                  oal_net_device_stru     *pst_netdev)
#endif
{
    /* ?????????????? */
    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_netdev))
    {
        OAM_ERROR_LOG2(0, OAM_SF_CFG, "{wal_cfg80211_sched_scan_stop::input param pointer is null, pst_wiphy[%p], pst_netdev[%p]!}",
                       pst_wiphy, pst_netdev);
        return -OAL_EINVAL;
    }

#ifdef _PRE_WLAN_FEATURE_DFR
        if (g_st_dfr_info.bit_device_reset_process_flag)
        {
            OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_sched_scan_stop:: dfr_process_status[%d]!}",
                g_st_dfr_info.bit_device_reset_process_flag);
            return -OAL_EFAIL;
        }
#endif //#ifdef _PRE_WLAN_FEATURE_DFR

    return wal_stop_sched_scan(pst_netdev);
}

#endif


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0))
oal_int32 wal_cfg80211_change_virtual_intf(oal_wiphy_stru        *pst_wiphy,
                                           oal_net_device_stru   *pst_net_dev,
                                           enum nl80211_iftype    en_type,
                                           oal_vif_params_stru   *pst_params)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34))
oal_int32 wal_cfg80211_change_virtual_intf(oal_wiphy_stru        *pst_wiphy,
                                           oal_net_device_stru   *pst_net_dev,
                                           enum nl80211_iftype    en_type,
                                           oal_uint32            *pul_flags,
                                           oal_vif_params_stru   *pst_params)
#else
oal_int32 wal_cfg80211_change_virtual_intf(oal_wiphy_stru        *pst_wiphy,
                                           oal_int32              l_ifindex,
                                           enum nl80211_iftype    en_type,
                                           oal_uint32            *pul_flags,
                                           oal_vif_params_stru   *pst_params)
#endif
{
#ifdef _PRE_WLAN_FEATURE_P2P
    wlan_p2p_mode_enum_uint8    en_p2p_mode;
    wlan_vap_mode_enum_uint8    en_vap_mode;
    mac_cfg_del_vap_param_stru  st_del_vap_param;
    mac_cfg_add_vap_param_stru  st_add_vap_param;
    mac_vap_stru               *pst_mac_vap;

#if defined(_PRE_PRODUCT_ID_HI110X_HOST)
    oal_int32                   l_ret;
#endif

    /* 1.1 ???????? */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34))
    if (OAL_PTR_NULL == pst_net_dev)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::pst_dev is null!}\r\n");
        return -OAL_EINVAL;
    }
#else
    oal_net_device_stru   *pst_net_dev;
    pst_net_dev = oal_dev_get_by_index(l_ifindex);
    if (OAL_PTR_NULL == pst_net_dev)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::pst_dev is null!}\r\n");
        return -OAL_EINVAL;
    }
    oal_dev_put(pst_net_dev);/* ????oal_dev_get_by_index????????????oal_dev_put??net_dev?????????????? */
#endif
#ifdef _PRE_WLAN_FEATURE_DFR
    if (g_st_dfr_info.bit_device_reset_process_flag)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_change_virtual_intf::dfr_process_status[%d]!}",
            g_st_dfr_info.bit_device_reset_process_flag);
        return OAL_SUCC;
    }

#endif //#ifdef _PRE_WLAN_FEATURE_DFR

    if ((OAL_PTR_NULL == pst_wiphy)
        || (OAL_PTR_NULL == pst_params))
    {
        OAM_ERROR_LOG2(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::pst_wiphy or pul_flag or pst_params ptr is null,error %d, %d, %d!}\r\n",
                        pst_wiphy, pst_params);
        return -OAL_EINVAL;
    }

    /* ????VAP ?????????????????????????????????????????????? */
    if (pst_net_dev->ieee80211_ptr->iftype == en_type)
    {
        OAM_WARNING_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::same iftype[%d],do not need change !}\r\n", en_type);
        return OAL_SUCC;
    }

    OAL_IO_PRINT("wal_cfg80211_change_virtual_intf,dev_name is:%.16s\n", pst_net_dev->name);
    OAM_WARNING_LOG2(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::from [%d] to [%d]}\r\n",
                    (pst_net_dev->ieee80211_ptr->iftype), en_type);

    switch (en_type) {
        case NL80211_IFTYPE_MONITOR:
        case NL80211_IFTYPE_WDS:
        case NL80211_IFTYPE_MESH_POINT:
        case NL80211_IFTYPE_ADHOC:
            OAM_ERROR_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::currently we do not support this type[%d]}\r\n", en_type);
            return -OAL_EINVAL;

        case NL80211_IFTYPE_STATION:
#if 0/*??????????????*/
            en_vap_mode = WLAN_VAP_MODE_BSS_STA;
            en_p2p_mode = WLAN_LEGACY_VAP_MODE;
#endif

#if defined(_PRE_PRODUCT_ID_HI110X_HOST)
            if(NL80211_IFTYPE_AP == pst_net_dev->ieee80211_ptr->iftype)
            {
                /* ????APUT??????netdev??????station */
                l_ret = wal_netdev_stop_ap(pst_net_dev);

                return l_ret;
            }
#endif
            //if(pst_net_dev->ieee80211_ptr->iftype != NL80211_IFTYPE_P2P_CLIENT)
            {
                pst_net_dev->ieee80211_ptr->iftype = en_type;//TBD:P2P BUG P2P_DEVICE ????????????????????wpa_supplicant ????
                OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::change to station}\r\n");
            }
            return OAL_SUCC;
            //break;
        case NL80211_IFTYPE_P2P_CLIENT:
            en_vap_mode = WLAN_VAP_MODE_BSS_STA;
            en_p2p_mode = WLAN_P2P_CL_MODE;
            break;
        case NL80211_IFTYPE_AP:
        case NL80211_IFTYPE_AP_VLAN:
            en_vap_mode = WLAN_VAP_MODE_BSS_AP;
            en_p2p_mode = WLAN_LEGACY_VAP_MODE;
            break;
        case NL80211_IFTYPE_P2P_GO:
            en_vap_mode = WLAN_VAP_MODE_BSS_AP;
            en_p2p_mode = WLAN_P2P_GO_MODE;
            break;
        default:
            OAM_ERROR_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::currently we do not support this type[%d]}\r\n", en_type);
            return -OAL_EINVAL;
    }

#if defined(_PRE_PRODUCT_ID_HI110X_HOST)
    if(NL80211_IFTYPE_AP == en_type)
    {
        l_ret = wal_setup_ap(pst_net_dev);
        return l_ret;
    }
#endif

    /* ??????P2P ??????????????change virtual interface */
    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if(OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::can't get mac vap from netdevice priv data.}\r\n");
        return -OAL_EINVAL;
    }

    if (IS_LEGACY_VAP(pst_mac_vap))
    {
        pst_net_dev->ieee80211_ptr->iftype = en_type;
        return OAL_SUCC;
    }

    if (0 == (oal_strcmp("p2p0", pst_net_dev->name)))
    {
        /* ??????????????,wpa_supplicant????p2p0??????????p2p go/cli????????fastboot?????? */
        OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::p2p0 netdevice can not change to P2P CLI/GO.}\r\n");
        return -OAL_EINVAL;
    }

    /* ??????????????????????????????????:
       1. ???? VAP
       2. ???? VAP
       3. ????????????????VAP
       4. ????VAP
    */
    /* ????VAP */
    wal_netdev_stop(pst_net_dev);

    OAL_MEMZERO(&st_del_vap_param, OAL_SIZEOF(st_del_vap_param));
    /* ????VAP */
    st_del_vap_param.pst_net_dev = pst_net_dev;
    /* ????p2p ??????????net_device ?????? */
    st_del_vap_param.en_p2p_mode = wal_wireless_iftype_to_mac_p2p_mode(pst_net_dev->ieee80211_ptr->iftype);
    if (wal_cfg80211_del_vap(&st_del_vap_param))
    {
        return -OAL_EFAIL;
    }

    OAL_MEMZERO(&st_add_vap_param, OAL_SIZEOF(st_add_vap_param));
    /* ????????????????VAP */
    st_add_vap_param.pst_net_dev = pst_net_dev;
    st_add_vap_param.en_vap_mode = en_vap_mode;
    st_add_vap_param.en_p2p_mode = en_p2p_mode;
    wal_cfg80211_add_vap(&st_add_vap_param);

    /* ????VAP */
    wal_netdev_open(pst_net_dev);
#endif /* _PRE_WLAN_FEATURE_P2P */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34))
    pst_net_dev->ieee80211_ptr->iftype = en_type;
#else
    l_ifindex = l_ifindex;
#endif
    return OAL_SUCC;
}


OAL_STATIC oal_int32 wal_cfg80211_add_station(oal_wiphy_stru            *pst_wiphy,
                                                oal_net_device_stru     *pst_dev,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
                                                const
#endif
                                                oal_uint8               *puc_mac,
                                                oal_station_parameters_stru *pst_sta_parms)
{
    return OAL_SUCC;
}


OAL_STATIC oal_int32 wal_cfg80211_del_station(oal_wiphy_stru        *pst_wiphy,
                                                oal_net_device_stru *pst_dev,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
                                                struct station_del_parameters *params
#else
                                                oal_uint8           *puc_mac
#endif
)
{
    mac_vap_stru                  *pst_mac_vap        = OAL_PTR_NULL;
    mac_cfg_kick_user_param_stru  st_kick_user_param;
    oal_int32                     int_user_count_ok   = 0;
    oal_int32                     int_user_count_fail = 0;
    oal_int32                     uint_ret            = OAL_FAIL;
    oal_uint8                     auc_mac_boardcast[OAL_MAC_ADDR_LEN];
    oal_uint16                    us_reason_code = MAC_INACTIVITY;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
    oal_uint8                    *puc_mac;
    if (params == OAL_PTR_NULL)
    {
        return -OAL_EFAUL;
    }
    puc_mac = (oal_uint8 *)params->mac;

    us_reason_code = params->reason_code;
#endif

    if (OAL_PTR_NULL == pst_wiphy || OAL_PTR_NULL == pst_dev)
    {
        return -OAL_EFAUL;
    }
#ifdef _PRE_WLAN_FEATURE_DFR
    if (g_st_dfr_info.bit_device_reset_process_flag)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_del_station::dfr_process_status[%d]!}",
            g_st_dfr_info.bit_device_reset_process_flag);
        return OAL_SUCC;
    }

#endif //#ifdef _PRE_WLAN_FEATURE_DFR

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_del_station::can't get mac vap from netdevice priv data!}\r\n");
        return -OAL_EFAUL;
    }

    /* ??????????AP????*/
    if (WLAN_VAP_MODE_BSS_AP != pst_mac_vap->en_vap_mode)
    {
        OAM_ERROR_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_del_station::WLAN_VAP_MODE_BSS_AP != vap_mode[%d]!}\r\n", pst_mac_vap->en_vap_mode);
        return -OAL_EINVAL;
    }

    if (OAL_PTR_NULL == puc_mac)
    {
        oal_memset(auc_mac_boardcast,0xff,OAL_MAC_ADDR_LEN);
        puc_mac = auc_mac_boardcast;
        OAM_INFO_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_del_station::deleting all user!}\r\n");
    }
    else
    {
        OAM_INFO_LOG4(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_del_station::deleting user:%02X:XX:XX:%02X:%02X:%02X!}\r\n",
                    puc_mac[0], puc_mac[3], puc_mac[4], puc_mac[5]);
    }

    st_kick_user_param.us_reason_code = us_reason_code;
    oal_memcopy(st_kick_user_param.auc_mac_addr, puc_mac, OAL_MAC_ADDR_LEN);
    uint_ret = wal_cfg80211_start_disconnect(pst_dev, &st_kick_user_param);
    if (OAL_SUCC != uint_ret)
    {
        /* ????????????????????????????????????????????????????????????????????ERROR????????????warning */
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_del_station::hmac_config_kick_user fail[%d]!}\r\n", uint_ret);
        int_user_count_fail++;
    }
    else
    {
        int_user_count_ok++;
    }

    if (int_user_count_fail > 0)
    {
        OAM_INFO_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_del_station::%d user is failed to be deleted!}\r\n", int_user_count_fail);
        return -OAL_EINVAL;
    }

    OAM_INFO_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_del_station::%d user is deleted!}\r\n", int_user_count_ok);
    return OAL_SUCC;

}


OAL_STATIC oal_int32 wal_cfg80211_change_station(oal_wiphy_stru                 *pst_wiphy,
                                                    oal_net_device_stru         *pst_dev,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
                                                    const
#endif
                                                    oal_uint8                   *puc_mac,
                                                    oal_station_parameters_stru *pst_sta_parms)
{
    return OAL_SUCC;
}

#define QUERY_STATION_INFO_TIME  (5 * OAL_TIME_HZ)

OAL_STATIC oal_void wal_cfg80211_fill_station_info(oal_station_info_stru  *pst_sta_info,
                                                       oal_station_info_stru  *pst_stats)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
    /* ????linux 4.1.??????BIT(NL80211_STA_INFO_SIGNAL)??. */

    pst_sta_info->filled |= BIT(NL80211_STA_INFO_SIGNAL);

    pst_sta_info->signal = pst_stats->signal;

    pst_sta_info->filled |= BIT(NL80211_STA_INFO_RX_PACKETS);
    pst_sta_info->filled |= BIT(NL80211_STA_INFO_TX_PACKETS);

    pst_sta_info->rx_packets = pst_stats->rx_packets;
    pst_sta_info->tx_packets = pst_stats->tx_packets;

    pst_sta_info->filled   |= BIT(NL80211_STA_INFO_RX_BYTES);
    pst_sta_info->filled   |= BIT(NL80211_STA_INFO_TX_BYTES);
    pst_sta_info->rx_bytes  = pst_stats->rx_bytes;
    pst_sta_info->tx_bytes  = pst_stats->tx_bytes;


    pst_sta_info->filled |= BIT(NL80211_STA_INFO_TX_RETRIES);
    pst_sta_info->filled |= BIT(NL80211_STA_INFO_TX_FAILED);
    pst_sta_info->filled |= BIT(NL80211_STA_INFO_RX_DROP_MISC);

    pst_sta_info->tx_retries       = pst_stats->tx_retries;
    pst_sta_info->tx_failed        = pst_stats->tx_failed;
    pst_sta_info->rx_dropped_misc  = pst_stats->rx_dropped_misc;

    pst_sta_info->filled |= BIT(NL80211_STA_INFO_TX_BITRATE);
    pst_sta_info->txrate.legacy = (oal_uint16)(pst_stats->txrate.legacy * 10); /* ????????????100kbps */
    pst_sta_info->txrate.flags  = pst_stats->txrate.flags;
    pst_sta_info->txrate.mcs    = pst_stats->txrate.mcs;
    pst_sta_info->txrate.nss    = pst_stats->txrate.nss;
    pst_sta_info->txrate.bw     = pst_stats->txrate.bw;
#else
    pst_sta_info->filled |= STATION_INFO_SIGNAL;

    pst_sta_info->signal = pst_stats->signal;

    pst_sta_info->filled |= STATION_INFO_RX_PACKETS;
    pst_sta_info->filled |= STATION_INFO_TX_PACKETS;

    pst_sta_info->rx_packets = pst_stats->rx_packets;
    pst_sta_info->tx_packets = pst_stats->tx_packets;

    pst_sta_info->filled   |= STATION_INFO_RX_BYTES;
    pst_sta_info->filled   |= STATION_INFO_TX_BYTES;
    pst_sta_info->rx_bytes  = pst_stats->rx_bytes;
    pst_sta_info->tx_bytes  = pst_stats->tx_bytes;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37))
    pst_sta_info->filled |= STATION_INFO_TX_RETRIES;
    pst_sta_info->filled |= STATION_INFO_TX_FAILED;
    pst_sta_info->filled |= STATION_INFO_RX_DROP_MISC;

    pst_sta_info->tx_retries       = pst_stats->tx_retries;
    pst_sta_info->tx_failed        = pst_stats->tx_failed;
    pst_sta_info->rx_dropped_misc  = pst_stats->rx_dropped_misc;
#endif

    pst_sta_info->filled |= STATION_INFO_TX_BITRATE ;
    pst_sta_info->txrate.legacy = (oal_uint16)(pst_stats->txrate.legacy * 10); /* ????????????100kbps */
    pst_sta_info->txrate.flags  = pst_stats->txrate.flags;
    pst_sta_info->txrate.mcs    = pst_stats->txrate.mcs;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0))
    pst_sta_info->txrate.nss    = pst_stats->txrate.nss;
#endif
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)) */
}


oal_uint8 wal_cfg80211_get_station_filter(mac_vap_stru *pst_mac_vap, oal_uint8 *puc_mac)
{
    hmac_user_stru *pst_hmac_user;
    oal_uint32      ul_current_time = (oal_uint32)OAL_TIME_GET_STAMP_MS();
    oal_uint32      ul_runtime;
    oal_uint32      ul_get_station_threshold;

#ifdef _PRE_WLAN_FEATURE_VOWIFI
    mac_device_stru *pst_mac_dev;
#endif


    pst_hmac_user = mac_vap_get_hmac_user_by_addr(pst_mac_vap, puc_mac);
    if(OAL_PTR_NULL == pst_hmac_user)
    {
        OAM_WARNING_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_CFG, "{wal_cfg80211_get_station_filter::user is null.}");
        return OAL_FALSE;
    }

#ifdef _PRE_WLAN_FEATURE_VOWIFI
    pst_mac_dev = mac_res_get_dev(pst_mac_vap->uc_device_id);
    if(OAL_PTR_NULL == pst_mac_dev)
    {
        OAM_WARNING_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_CFG, "{wal_cfg80211_get_station_filter::dev is null.}");
        return OAL_FALSE;
    }
    if (IS_LEGACY_STA(pst_mac_vap) &&
        (OAL_PTR_NULL != pst_mac_vap->pst_vowifi_cfg_param && VOWIFI_DISABLE_REPORT == pst_mac_vap->pst_vowifi_cfg_param->en_vowifi_mode))
    {
        /*??????vowifi??????????*/
        ul_get_station_threshold = WAL_VOWIFI_GET_STATION_THRESHOLD;
    }
    else
#endif
    {
        ul_get_station_threshold = WAL_GET_STATION_THRESHOLD;
    }


    ul_runtime = (oal_uint32)OAL_TIME_GET_RUNTIME(pst_hmac_user->ul_rssi_last_timestamp, ul_current_time);

    if(ul_get_station_threshold > ul_runtime)
    {
        return OAL_FALSE;
    }

    pst_hmac_user->ul_rssi_last_timestamp = ul_current_time;
    return OAL_TRUE;
}


oal_int32 wal_cfg80211_get_station(oal_wiphy_stru *pst_wiphy,
                                   oal_net_device_stru *pst_dev,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0))
                                   const
#endif
                                   oal_uint8 *puc_mac,
                                   oal_station_info_stru *pst_sta_info)
{
    mac_vap_stru                          *pst_mac_vap;
    hmac_vap_stru                         *pst_hmac_vap;
    dmac_query_request_event               st_dmac_query_request_event;
    dmac_query_station_info_request_event *pst_query_station_info;
    wal_msg_write_stru                     st_write_msg;
    oal_int                                i_leftime;
    oal_int32                              l_ret;
    oal_uint8                              uc_vap_id;

    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_dev) ||
        (OAL_PTR_NULL == puc_mac)|| (OAL_PTR_NULL == pst_sta_info))
    {
        OAM_ERROR_LOG4(0, OAM_SF_ANY,
                       "{wal_cfg80211_get_station::pst_wiphy[0x%p],pst_dev[0x%p],puc_mac[0x%p],pst_sta_info[0x%p]!}",
                       pst_wiphy, pst_dev, puc_mac, pst_sta_info);
        return -OAL_EINVAL;
    }

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_get_station::OAL_NET_DEV_PRIV, return null!}");
        return -OAL_EINVAL;
    }

    uc_vap_id = pst_mac_vap->uc_vap_id;

    pst_query_station_info = (dmac_query_station_info_request_event *)&st_dmac_query_request_event;
    pst_query_station_info->query_event = OAL_QUERY_STATION_INFO_EVENT;
    oal_set_mac_addr(pst_query_station_info->auc_query_sta_addr, (oal_uint8 *)puc_mac);

    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG1(0,OAM_SF_ANY,"{wal_cfg80211_get_station::mac_res_get_hmac_vap fail.vap_id[%u]}",pst_mac_vap->uc_vap_id);
        return -OAL_EINVAL;
    }

    /* ??????????????????????RSSI */
    if(OAL_FALSE == wal_cfg80211_get_station_filter(&pst_hmac_vap->st_vap_base_info, (oal_uint8 *)puc_mac))
    {
        wal_cfg80211_fill_station_info(pst_sta_info, &pst_hmac_vap->station_info);
        return OAL_SUCC;
    }

    pst_hmac_vap->station_info_query_completed_flag = OAL_FALSE;

    /********************************************************************************
        ????????wal?????? ??????????????????????????????????????????????????????????
        ??????????????beacon??????????????????????
    ********************************************************************************/
    /*3.1 ???? msg ??????*/
    st_write_msg.en_wid = WLAN_CFGID_QUERY_STATION_STATS;
    st_write_msg.us_len = OAL_SIZEOF(st_dmac_query_request_event);

    /*3.2 ???? msg ?????? */
    oal_memcopy(st_write_msg.auc_value, pst_query_station_info, OAL_SIZEOF(dmac_query_station_info_request_event));

    l_ret = wal_send_cfg_event(pst_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(dmac_query_station_info_request_event),
                               (oal_uint8 *)&st_write_msg,
                               OAL_FALSE,
                               OAL_PTR_NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_get_station::wal_send_cfg_event return err code %d!}", l_ret);
        return -OAL_EFAIL;
    }
    /*lint -e730*//* info, boolean argument to function */
    i_leftime = OAL_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(pst_hmac_vap->query_wait_q,(OAL_TRUE == pst_hmac_vap->station_info_query_completed_flag),QUERY_STATION_INFO_TIME);
    /*lint +e730*/
    if (0 == i_leftime)
    {
        /* ?????????????????????? */
        OAM_WARNING_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_get_station::query info wait for %ld ms timeout!}",
                         ((QUERY_STATION_INFO_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else if (i_leftime < 0)
    {
        /* ?????????????? */
        OAM_WARNING_LOG1(uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_get_station::query info wait for %ld ms error!}",
                         ((QUERY_STATION_INFO_TIME * 1000)/OAL_TIME_HZ));
        return -OAL_EINVAL;
    }
    else
    {
        /* ????????  */
        wal_cfg80211_fill_station_info(pst_sta_info, &pst_hmac_vap->station_info);
/*lint -e571*/
        OAM_WARNING_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_get_station::rssi %d.}",  pst_hmac_vap->station_info.signal);
/*lint +e571*/
        return OAL_SUCC;
    }
}


OAL_STATIC oal_int32 wal_cfg80211_dump_station(oal_wiphy_stru           *pst_wiphy,
                                                oal_net_device_stru     *pst_dev,
                                                oal_int32                int_index,
                                                oal_uint8               *puc_mac,
                                                oal_station_info_stru   *pst_sta_info)
{
    return OAL_SUCC;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 44)) //TBD:1102 ??????????????????????????
#if (_PRE_CONFIG_TARGET_PRODUCT != _PRE_TARGET_PRODUCT_TYPE_E5)


OAL_STATIC oal_uint32 wal_is_p2p_group_exist(mac_device_stru *pst_mac_device)
{
    if (OAL_SUCC != hmac_check_p2p_vap_num(pst_mac_device, WLAN_P2P_GO_MODE)
        || OAL_SUCC != hmac_check_p2p_vap_num(pst_mac_device, WLAN_P2P_CL_MODE))
    {
        return OAL_TRUE;
    }
    else
    {
        return OAL_FALSE;
    }
}


oal_uint32 wal_del_p2p_group(mac_device_stru *pst_mac_device)
{
    oal_uint8                    uc_vap_idx;
    mac_vap_stru                *pst_mac_vap;
    hmac_vap_stru               *pst_hmac_vap;
    oal_net_device_stru         *pst_net_dev;
    mac_cfg_del_vap_param_stru   st_del_vap_param;

    for (uc_vap_idx = 0; uc_vap_idx < pst_mac_device->uc_vap_num; uc_vap_idx++)
    {
        pst_mac_vap = mac_res_get_mac_vap(pst_mac_device->auc_vap_id[uc_vap_idx]);
        if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mac_vap))
        {
            OAM_WARNING_LOG1(0, OAM_SF_P2P, "{wal_del_p2p_group::get mac vap resource fail! vap id is %d}",
                            pst_mac_device->auc_vap_id[uc_vap_idx]);
            continue;
        }

        pst_hmac_vap = mac_res_get_hmac_vap(pst_mac_device->auc_vap_id[uc_vap_idx]);
        if (OAL_UNLIKELY(OAL_PTR_NULL == pst_hmac_vap))
        {
            OAM_WARNING_LOG1(0, OAM_SF_P2P, "{wal_del_p2p_group::get hmac vap resource fail! vap id is %d}",
                            pst_mac_device->auc_vap_id[uc_vap_idx]);
            continue;
        }

        pst_net_dev = pst_hmac_vap->pst_net_device;
        if (OAL_UNLIKELY(OAL_PTR_NULL == pst_net_dev))
        {
            OAM_WARNING_LOG1(0, OAM_SF_P2P, "{wal_del_p2p_group::get net device fail! vap id is %d}",
                            pst_mac_device->auc_vap_id[uc_vap_idx]);
            continue;
        }

        if (IS_P2P_GO(pst_mac_vap) || IS_P2P_CL(pst_mac_vap))
        {
            OAL_MEMZERO(&st_del_vap_param, OAL_SIZEOF(st_del_vap_param));
            OAL_IO_PRINT("wal_del_p2p_group:: ifname %.16s\r\n", pst_net_dev->name);
            st_del_vap_param.pst_net_dev = pst_net_dev;
            st_del_vap_param.en_vap_mode = pst_mac_vap->en_vap_mode;
            st_del_vap_param.en_p2p_mode = mac_get_p2p_mode(pst_mac_vap);
            OAM_WARNING_LOG2(pst_mac_vap->uc_vap_id, OAM_SF_P2P, "{wal_del_p2p_group:: vap mode[%d], p2p mode[%d]}\r\n",
                                st_del_vap_param.en_vap_mode, st_del_vap_param.en_p2p_mode);
            /* ??????????????P2P group */
            wal_force_scan_complete(pst_net_dev, OAL_TRUE);
            wal_stop_vap(pst_net_dev);
            if(OAL_SUCC == wal_cfg80211_del_vap(&st_del_vap_param))
            {
                wal_cfg80211_unregister_netdev(pst_net_dev);
            }
        }
    }
    return OAL_SUCC;
}



oal_uint32 wal_cfg80211_register_netdev(oal_net_device_stru *pst_net_dev)
{
    oal_uint8    uc_rollback_lock = OAL_FALSE;
    oal_uint32   ul_ret = 0;

    if (rtnl_is_locked())
    {
        rtnl_unlock();
        uc_rollback_lock = OAL_TRUE;
    }

    /* ????????net_device, ??????0 */
    ul_ret = (oal_uint32)oal_net_register_netdev(pst_net_dev);

    if (uc_rollback_lock)
    {
        rtnl_lock();
    }

    return ul_ret;
}


oal_void wal_cfg80211_unregister_netdev(oal_net_device_stru *pst_net_dev)
{
    oal_uint8    uc_rollback_lock = OAL_FALSE;

    if (rtnl_is_locked())
    {
        rtnl_unlock();
        uc_rollback_lock = OAL_TRUE;
    }

    /* ??????netdev */
    oal_net_unregister_netdev(pst_net_dev);

    if (uc_rollback_lock)
    {
        rtnl_lock();
    }
}


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0))
OAL_STATIC oal_wireless_dev_stru * wal_cfg80211_add_virtual_intf(oal_wiphy_stru     *pst_wiphy,
                                                                const char          *puc_name,
                                                                unsigned char name_assign_type,
                                                                enum nl80211_iftype  en_type,
                                                                oal_vif_params_stru *pst_params)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
OAL_STATIC oal_wireless_dev_stru * wal_cfg80211_add_virtual_intf(oal_wiphy_stru     *pst_wiphy,
                                                                const char          *puc_name,
                                                                unsigned char name_assign_type,
                                                                enum nl80211_iftype  en_type,
                                                                oal_uint32          *pul_flags,
                                                                oal_vif_params_stru *pst_params)
#else
OAL_STATIC oal_wireless_dev_stru * wal_cfg80211_add_virtual_intf(oal_wiphy_stru     *pst_wiphy,
                                                                const char          *puc_name,
                                                                enum nl80211_iftype  en_type,
                                                                oal_uint32          *pul_flags,
                                                                oal_vif_params_stru *pst_params)
#endif
{
    oal_wireless_dev_stru      *pst_wdev    = OAL_PTR_NULL;
    wlan_p2p_mode_enum_uint8    en_p2p_mode;
    wlan_vap_mode_enum_uint8    en_vap_mode;
    oal_net_device_stru        *pst_net_dev;
    mac_wiphy_priv_stru        *pst_wiphy_priv;
    mac_device_stru            *pst_mac_device;
    hmac_device_stru           *pst_hmac_device;
#if (!defined(_PRE_PRODUCT_ID_HI110X_HOST))
    hmac_vap_stru              *pst_p2p0_hmac_vap;
    oal_uint8                   uc_p2p0_vap_idx;
#endif
    wal_msg_write_stru          st_write_msg;
    wal_msg_stru               *pst_rsp_msg = OAL_PTR_NULL;
    oal_uint8                   uc_cfg_vap_id;
    mac_vap_stru               *pst_cfg_mac_vap;
    hmac_vap_stru              *pst_cfg_hmac_vap;
    mac_vap_stru               *pst_mac_vap;
    oal_net_device_stru        *pst_cfg_net_dev;
    oal_uint32                  ul_ret;
    oal_int32                   l_ret;
    mac_cfg_add_vap_param_stru *pst_add_vap_param;
    oal_uint8                   auc_name[OAL_IF_NAME_SIZE] = {0};
    oal_uint8                   uc_rollback_lock=0;
    oal_int32                   l_timeout;

    /* 1.1 ???????? */
    if ((OAL_PTR_NULL == pst_wiphy)
        || (OAL_PTR_NULL == puc_name)
        || (OAL_PTR_NULL == pst_params))
    {
        OAM_ERROR_LOG3(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf:: ptr is null,error pst_wiphy %d, puc_name %d, pst_params %d!}\r\n",
                        pst_wiphy, puc_name, pst_params);
        return ERR_PTR(-EINVAL);
    }

    /* ????????????????????????????OAL???????? */
    pst_wiphy_priv = oal_wiphy_priv(pst_wiphy);
    if (pst_wiphy_priv == OAL_PTR_NULL)
    {
        OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf::pst_wiphy_priv is null!}\r\n");
        return ERR_PTR(-EINVAL);
    }

    pst_mac_device = pst_wiphy_priv->pst_mac_device;
    if (pst_mac_device == OAL_PTR_NULL)
    {
        OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf::pst_mac_device is null!}\r\n");
        return ERR_PTR(-EINVAL);
    }

    OAM_WARNING_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf::en_type[%d]!}\r\n", en_type);
    /* ????:SDT????????%s?????????? */
    OAL_IO_PRINT("wal_cfg80211_add_virtual_intf,dev_name is:%.16s\n", puc_name);

    switch (en_type)
    {
        case NL80211_IFTYPE_ADHOC:
        case NL80211_IFTYPE_AP_VLAN:
        case NL80211_IFTYPE_WDS:
        case NL80211_IFTYPE_MESH_POINT:
        case NL80211_IFTYPE_MONITOR:
            OAM_ERROR_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf::Unsupported interface type[%d]!}\r\n", en_type);
            return ERR_PTR(-EINVAL);
        case NL80211_IFTYPE_P2P_DEVICE:
#if defined(_PRE_PRODUCT_ID_HI110X_HOST)
            pst_net_dev       = pst_mac_device->st_p2p_info.pst_p2p_net_device;
            pst_wdev          = pst_net_dev->ieee80211_ptr;
#else
            /* p2p0 ??????wifi ??????????????????????????????????????????????????p2p0 wireless device ???? */
            uc_p2p0_vap_idx   = pst_mac_device->st_p2p_info.uc_p2p0_vap_idx;
            pst_p2p0_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(uc_p2p0_vap_idx);
            if (OAL_UNLIKELY(OAL_PTR_NULL == pst_p2p0_hmac_vap))
            {
                OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::pst_p2p0_hmac_vap[id=%d] null!!}",
                            uc_p2p0_vap_idx);
                return ERR_PTR(-ENODEV);
            }
            pst_net_dev       = pst_p2p0_hmac_vap->pst_p2p0_net_device;
            pst_wdev          = pst_net_dev->ieee80211_ptr;
#endif
            return pst_wdev;
        case NL80211_IFTYPE_P2P_CLIENT:
            en_vap_mode = WLAN_VAP_MODE_BSS_STA;
            en_p2p_mode = WLAN_P2P_CL_MODE;
            break;
        case NL80211_IFTYPE_STATION:
            en_vap_mode = WLAN_VAP_MODE_BSS_STA;
            en_p2p_mode = WLAN_LEGACY_VAP_MODE;
            break;
        case NL80211_IFTYPE_P2P_GO:
            en_vap_mode = WLAN_VAP_MODE_BSS_AP;
            en_p2p_mode = WLAN_P2P_GO_MODE;
            break;
        case NL80211_IFTYPE_AP:
            en_vap_mode = WLAN_VAP_MODE_BSS_AP;
            en_p2p_mode = WLAN_LEGACY_VAP_MODE;
            break;
        default:
            OAM_ERROR_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf::Unsupported interface type[%d]!}\r\n", en_type);
            return ERR_PTR(-EINVAL);
    }
    /* ??????????net device?????????????????? */
    /* ????dev_name????dev */
    pst_net_dev = oal_dev_get_by_name(puc_name);
    if (OAL_PTR_NULL != pst_net_dev)
    {
        /* ????oal_dev_get_by_name????????????oal_dev_put??net_dev?????????????? */
        oal_dev_put(pst_net_dev);

        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::the net_device is already exist!}\r\n");
        pst_wdev = pst_net_dev->ieee80211_ptr;
        return pst_wdev;
    }

    /* ????net_device ????????????????????????net_device ??????
        ????????????net_device???????????????????????? */
    pst_hmac_device = hmac_res_get_mac_dev(pst_mac_device->uc_device_id);
    if (pst_hmac_device == OAL_PTR_NULL)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::hmac_device is null!}\r\n", pst_mac_device->uc_device_id);
        return ERR_PTR(-ENODEV);
    }

    if (hmac_get_p2p_status(pst_hmac_device->ul_p2p_intf_status, P2P_STATUS_IF_DELETING) == OAL_TRUE)
    {
        /* ???????????? */
        if (rtnl_is_locked()) {
            rtnl_unlock();
            uc_rollback_lock = OAL_TRUE;
        }
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf:Released the lock and wait till IF_DEL is complete!}\r\n");
        l_timeout = OAL_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(pst_hmac_device->st_netif_change_event,
                        (hmac_get_p2p_status(pst_hmac_device->ul_p2p_intf_status, P2P_STATUS_IF_DELETING) == OAL_FALSE),
                        OAL_MSECS_TO_JIFFIES(WAL_MAX_WAIT_TIME));

        /* put back the rtnl_lock again */
        if (uc_rollback_lock) {
            rtnl_lock();
        }

        if (l_timeout > 0)
        {
            OAM_WARNING_LOG0(0, OAM_SF_ANY,"{wal_cfg80211_add_virtual_intf::IF DEL is Success!}\r\n");
        }
        else
        {
            OAM_WARNING_LOG0(0, OAM_SF_ANY,"{wal_cfg80211_add_virtual_intf::timeount < 0, return -EAGAIN!}\r\n");
            return ERR_PTR(-EAGAIN);
        }
    }

    /* ????wifi ????????P2P group ??????????????????P2P group ??????????
        ??????P2P group ??????????????????P2P group */
    if (OAL_TRUE == wal_is_p2p_group_exist(pst_mac_device))
    {
        OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf::found exist p2p group, delet it first!}\r\n");
        if (OAL_SUCC != wal_del_p2p_group(pst_mac_device))
        {
            return ERR_PTR(-EAGAIN);
        }
    }

    /* ????????VAP ???? */
    uc_cfg_vap_id   = pst_mac_device->uc_cfg_vap_id;
    pst_cfg_mac_vap = (mac_vap_stru *)mac_res_get_mac_vap(uc_cfg_vap_id);
    if (OAL_PTR_NULL == pst_cfg_mac_vap)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::pst_cfg_mac_vap is null vap_id:%d!}\r\n",uc_cfg_vap_id);
        return ERR_PTR(-ENODEV);
    }
    pst_cfg_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(uc_cfg_vap_id);
    if (OAL_PTR_NULL == pst_cfg_hmac_vap)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::pst_cfg_hmac_vap is null vap_id:%d!}\r\n",uc_cfg_vap_id);
        return ERR_PTR(-ENODEV);
    }
    pst_cfg_net_dev = pst_cfg_hmac_vap->pst_net_device;
    oal_memcopy(auc_name, puc_name, OAL_MIN(OAL_IF_NAME_SIZE, OAL_STRLEN(puc_name)));
#if defined(_PRE_WLAN_FEATURE_FLOWCTL)
    pst_net_dev = oal_net_alloc_netdev_mqs(0, auc_name, oal_ether_setup, WAL_NETDEV_SUBQUEUE_MAX_NUM, 1);    /* ??????????????????????????????????????????0 */
#elif defined(_PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL)
    pst_net_dev = oal_net_alloc_netdev_mqs(0, auc_name, oal_ether_setup, WLAN_NET_QUEUE_BUTT, 1);    /* ??????????????????????????????????????????0 */
#else
    pst_net_dev = oal_net_alloc_netdev(0, auc_name, oal_ether_setup);    /* ??????????????????????????????????????????0 */
#endif

    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_net_dev))
    {
        OAM_ERROR_LOG0(pst_cfg_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::pst_net_dev null ptr error!}\r\n");
        return ERR_PTR(-ENOMEM);
    }

    pst_wdev = (oal_wireless_dev_stru *)OAL_MEM_ALLOC(OAL_MEM_POOL_ID_LOCAL,OAL_SIZEOF(oal_wireless_dev_stru), OAL_FALSE);
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_wdev))
    {
        OAM_ERROR_LOG0(pst_cfg_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::alloc mem, pst_wdev is null ptr!}\r\n");
        /* ?????????????????? */
        oal_net_free_netdev(pst_net_dev);
        return ERR_PTR(-ENOMEM);
    }

    oal_memset(pst_wdev, 0, OAL_SIZEOF(oal_wireless_dev_stru));

    /* ??netdevice???????? */
    /* ??????????net_device ?????????????? */
#ifdef CONFIG_WIRELESS_EXT
    pst_net_dev->wireless_handlers             = &g_st_iw_handler_def;
#endif /* CONFIG_WIRELESS_EXT */
    /* OAL_NETDEVICE_OPS(pst_net_dev)             = &g_st_wal_net_dev_ops; */
    pst_net_dev->netdev_ops                    = &g_st_wal_net_dev_ops;

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    pst_net_dev->ethtool_ops                   = &g_st_wal_ethtool_ops;
#endif

    OAL_NETDEVICE_DESTRUCTOR(pst_net_dev)      = oal_net_free_netdev;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,10,44))
    OAL_NETDEVICE_MASTER(pst_net_dev)          = OAL_PTR_NULL;
#endif

    OAL_NETDEVICE_IFALIAS(pst_net_dev)         = OAL_PTR_NULL;
    OAL_NETDEVICE_WATCHDOG_TIMEO(pst_net_dev)  = 5;
    OAL_NETDEVICE_WDEV(pst_net_dev)            = pst_wdev;
    OAL_NETDEVICE_QDISC(pst_net_dev, OAL_PTR_NULL);
#ifdef _PRE_WLAN_FEATURE_SMP_SUPPORT
//    OAL_NETDEVICE_TX_QUEUE_LEN(pst_net_dev) = 0;
#endif

    pst_wdev->iftype = en_type;
    pst_wdev->wiphy  = pst_mac_device->pst_wiphy;
    pst_wdev->netdev = pst_net_dev;/* ??wdev ????net_device ???? */
#ifdef _PRE_WLAN_FEATURE_P2P
    if ((WLAN_LEGACY_VAP_MODE == en_p2p_mode) && (WLAN_VAP_MODE_BSS_STA == en_vap_mode))
    {
        /* ????????wlan0?? ??????wlan0 ????net_device,p2p0 ??p2p-p2p0 MAC ????????netdevice ???? */
        if (pst_mac_device->st_p2p_info.pst_primary_net_device == OAL_PTR_NULL)
        {
            /* ????wlan0 ??????wifi ???????????????????????? */
            OAM_ERROR_LOG0(pst_cfg_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::should not go here!}\r\n");
            OAL_MEM_FREE(pst_wdev, OAL_TRUE);
            oal_net_free_netdev(pst_net_dev);
            return ERR_PTR(-ENODEV);
        }
    }
#endif
    OAL_NETDEVICE_FLAGS(pst_net_dev) &= ~OAL_IFF_RUNNING;   /* ??net device??flag????down */

    ul_ret = wal_cfg80211_register_netdev(pst_net_dev);
    if (OAL_UNLIKELY(OAL_SUCC != ul_ret))
    {
        /* ???????????????????? */
        OAL_MEM_FREE(pst_wdev, OAL_TRUE);
        oal_net_free_netdev(pst_net_dev);
        return ERR_PTR(-EBUSY);
    }

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /* ???????? */
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_ADD_VAP, OAL_SIZEOF(mac_cfg_add_vap_param_stru));

    pst_add_vap_param = (mac_cfg_add_vap_param_stru *)(st_write_msg.auc_value);
    pst_add_vap_param->pst_net_dev     = pst_net_dev;
    pst_add_vap_param->en_vap_mode     = en_vap_mode;
    pst_add_vap_param->uc_cfg_vap_indx = uc_cfg_vap_id;
#ifdef _PRE_WLAN_FEATURE_P2P
    pst_add_vap_param->en_p2p_mode     = en_p2p_mode;
#endif
#ifdef _PRE_PLAT_FEATURE_CUSTOMIZE
    pst_add_vap_param->bit_11ac2g_enable = (oal_uint8)!!hwifi_get_init_value(CUS_TAG_INI, WLAN_CFG_INIT_11AC2G_ENABLE);
    pst_add_vap_param->bit_disable_capab_2ght40 = g_st_wlan_customize.uc_disable_capab_2ght40;
#endif
    /* ???????? */
    l_ret = wal_send_cfg_event(pst_cfg_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_add_vap_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_TRUE,
                               &pst_rsp_msg);

    if(OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::wal_send_cfg_event return err code: [%d]!}", l_ret);
        /*lint -e801*/
        goto ERR_STEP;
        /*lint +e801*/
    }

    /* ???????????????? */
    if(OAL_SUCC != wal_check_and_release_msg_resp(pst_rsp_msg))
    {
        OAM_WARNING_LOG0(pst_cfg_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::wal_check_and_release_msg_resp fail:ul_err_code!}");
        goto ERR_STEP;
    }

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    wal_set_random_mac_to_mib(pst_net_dev); /* set random mac to mib ; for hi1102-cb */
#endif

    /* ????netdevice??MAC??????MAC??????HMAC????????????MIB?? */
    pst_mac_vap = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mac_vap))
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::OAL_NET_DEV_PRIV(pst_net_dev) is null ptr.}");
        goto ERR_STEP;
    }
    oal_set_mac_addr((oal_uint8 *)OAL_NETDEVICE_MAC_ADDR(pst_net_dev), pst_mac_vap->pst_mib_info->st_wlan_mib_sta_config.auc_dot11StationID);

    /* ????VAP UP */
    wal_netdev_open(pst_net_dev);

    OAM_WARNING_LOG2(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf::succ. en_type[%d],vap_id[%d]!}\r\n",
                    en_type, pst_mac_vap->uc_vap_id);

    return pst_wdev;


/* ???????? */
ERR_STEP:
    wal_cfg80211_unregister_netdev(pst_net_dev);
    /* ???????????????? */
    OAL_MEM_FREE(pst_wdev, OAL_FALSE);
    return ERR_PTR(-EAGAIN);
}

OAL_STATIC oal_bool_enum_uint8 wal_cfg80211_check_is_primary_netdev(oal_wiphy_stru *wiphy, oal_net_device_stru *net_dev)
{
    mac_device_stru *mac_device;
    mac_wiphy_priv_stru *wiphy_priv;
    wiphy_priv = oal_wiphy_priv(wiphy);
    if (wiphy_priv == OAL_PTR_NULL) {
        OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_check_is_primary_netdev::pst_wiphy_priv is null!}");
        return OAL_FALSE;
    }
    mac_device = wiphy_priv->pst_mac_device;
    if (mac_device == OAL_PTR_NULL) {
        OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_check_is_primary_netdev::pst_mac_device is null!}");
        return OAL_FALSE;
    }
    return mac_device->st_p2p_info.pst_primary_net_device == net_dev;
}


OAL_STATIC oal_int32 wal_cfg80211_del_virtual_intf(oal_wiphy_stru           *pst_wiphy,
                                                   oal_wireless_dev_stru    *pst_wdev)
{
    /* ??????????net_device */
    wal_msg_write_stru           st_write_msg;
    wal_msg_stru               *pst_rsp_msg;
    oal_int32                    l_ret;
    oal_net_device_stru         *pst_net_dev;
    mac_vap_stru                *pst_mac_vap;
    hmac_vap_stru               *pst_hmac_vap;
    hmac_device_stru            *pst_hmac_device;

    if (OAL_UNLIKELY((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_wdev)))
    {
        OAM_ERROR_LOG2(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::pst_wiphy or pst_wdev null ptr error %d, %d!}\r\n",
                       pst_wiphy, pst_wdev);
        return -OAL_EINVAL;
    }

#ifdef _PRE_WLAN_FEATURE_DFR
    if (g_st_dfr_info.bit_device_reset_process_flag)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::dfr_process_status[%d]!}",
            g_st_dfr_info.bit_device_reset_process_flag);
        return OAL_SUCC;
    }

#endif //#ifdef _PRE_WLAN_FEATURE_DFR

    pst_net_dev = pst_wdev->netdev;
    if (pst_net_dev == OAL_PTR_NULL)
    {
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::pst_net_dev is null by netdev, mode[%d]!}\r\n");
        return -OAL_EINVAL;
    }

    pst_mac_vap  = OAL_NET_DEV_PRIV(pst_net_dev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::mac_vap is null by netdev, mode[%d]!}\r\n", pst_net_dev->ieee80211_ptr->iftype);
        return -OAL_EINVAL;
    }
    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG1(0,OAM_SF_ANY,"{wal_cfg80211_del_virtual_intf::mac_res_get_hmac_vap fail.vap_id[%u]}",pst_mac_vap->uc_vap_id);
        return -OAL_EINVAL;
    }
    if (wal_cfg80211_check_is_primary_netdev(pst_wiphy, pst_net_dev)) {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::cannot del primary netdev}");
        return -OAL_EINVAL;
    }

    oal_net_tx_stop_all_queues(pst_net_dev);
    wal_netdev_stop(pst_net_dev);
    /* ????????net_device ??????wireless device */
    //OAL_MEM_FREE(OAL_NETDEVICE_WDEV(pst_net_dev), OAL_TRUE);

    /***************************************************************************
                                ????????wal??????
    ***************************************************************************/

    /* ??????????vap ???? */
    ((mac_cfg_del_vap_param_stru *)st_write_msg.auc_value)->pst_net_dev = pst_net_dev;
#ifdef _PRE_WLAN_FEATURE_P2P
    pst_wdev = pst_net_dev->ieee80211_ptr;
    if (wal_wireless_iftype_to_mac_p2p_mode(pst_wdev->iftype) == WLAN_P2P_BUTT)
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::wal_wireless_iftype_to_mac_p2p_mode return BUTT}\r\n");
        return -OAL_EINVAL;
    }

    ((mac_cfg_del_vap_param_stru *)st_write_msg.auc_value)->en_p2p_mode = mac_get_p2p_mode(pst_mac_vap);
#endif

    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_DEL_VAP, OAL_SIZEOF(mac_cfg_del_vap_param_stru));

    /* ????????net_device ???? */
    pst_hmac_device = hmac_res_get_mac_dev(pst_mac_vap->uc_device_id);
    if (pst_hmac_device == OAL_PTR_NULL)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::hmac_device is null!}\r\n", pst_mac_vap->uc_device_id);
        return -OAL_EINVAL;
    }
    hmac_set_p2p_status(&pst_hmac_device->ul_p2p_intf_status, P2P_STATUS_IF_DELETING);

    /* ????linux work ????net_device */
    pst_hmac_vap->pst_del_net_device = pst_net_dev;
    oal_queue_work(g_pst_del_virtual_inf_workqueue, &(pst_hmac_vap->st_del_virtual_inf_worker));

    l_ret = wal_send_cfg_event(pst_net_dev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_del_vap_param_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_TRUE,
                               &pst_rsp_msg);

    if (OAL_SUCC != wal_check_and_release_msg_resp(pst_rsp_msg))
    {
        OAM_WARNING_LOG0(0,OAM_SF_ANY,"{wal_cfg80211_del_virtual_intf::wal_check_and_release_msg_resp fail}");
    }

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::return err code %d}\r\n", l_ret);
        l_ret = -OAL_EFAIL;
    }

    OAM_WARNING_LOG2(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::pst_hmac_device->ul_p2p_intf_status %d, del result: %d}\r\n",
                            pst_hmac_device->ul_p2p_intf_status, l_ret);

    return l_ret;
}
#endif  /* _PRE_CONFIG_TARGET_PRODUCT != _PRE_TARGET_PRODUCT_TYPE_E5 */

#else  /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 44) */

oal_uint32 wal_del_p2p_group(mac_device_stru *pst_mac_device)
{
    return OAL_SUCC;
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 44))
#if (_PRE_CONFIG_TARGET_PRODUCT != _PRE_TARGET_PRODUCT_TYPE_E5)


OAL_STATIC oal_int32 wal_cfg80211_mgmt_tx_cancel_wait(oal_wiphy_stru        *pst_wiphy,
                                                    oal_wireless_dev_stru   *pst_wdev,
                                                    oal_uint64               ull_cookie)
{
    /* TBD */
    return -OAL_EFAIL;
}
#endif  /* _PRE_CONFIG_TARGET_PRODUCT != _PRE_TARGET_PRODUCT_TYPE_E5 */
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 44))//TBD:?????????? Linux ??????
#if (_PRE_CONFIG_TARGET_PRODUCT != _PRE_TARGET_PRODUCT_TYPE_E5)


OAL_STATIC oal_int32 wal_cfg80211_set_pmksa(oal_wiphy_stru           *pst_wiphy,
                                                      oal_net_device_stru      *pst_net_device,
                                                      oal_cfg80211_pmksa_stru  *pmksa)
{
    wal_msg_write_stru                       st_write_msg           = {0};
    mac_cfg_pmksa_param_stru                *pst_cfg_pmksa;
    oal_int32                                l_ret;

    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_net_device) || (OAL_PTR_NULL == pmksa))
    {
        OAM_ERROR_LOG3(0, OAM_SF_CFG,
                       "{wal_cfg80211_set_pmksa::param null! pst_wiphy[%d], pst_net_device[%d], pmksa[%d]!!}\r\n",
                       pst_wiphy, pst_net_device, pmksa);
        return -OAL_EINVAL;
    }

    if ((OAL_PTR_NULL == pmksa->bssid) || (OAL_PTR_NULL == pmksa->pmkid))
    {
        OAM_ERROR_LOG2(0, OAM_SF_CFG, "{wal_cfg80211_set_pmksa::param null! bssid[%d] pmkid[%d]}\r\n",
                       pmksa->bssid, pmksa->pmkid);
        return -OAL_EINVAL;
    }

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_SET_PMKSA, OAL_SIZEOF(mac_cfg_pmksa_param_stru));
    pst_cfg_pmksa = (mac_cfg_pmksa_param_stru *)st_write_msg.auc_value;
    oal_memcopy(pst_cfg_pmksa->auc_bssid, pmksa->bssid, WLAN_MAC_ADDR_LEN);
    oal_memcopy(pst_cfg_pmksa->auc_pmkid, pmksa->pmkid, WLAN_PMKID_LEN);

    l_ret = wal_send_cfg_event(pst_net_device,
                                WAL_MSG_TYPE_WRITE,
                                WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_pmksa_param_stru),
                                (oal_uint8 *)&st_write_msg,
                                OAL_FALSE,
                                OAL_PTR_NULL);

    if (OAL_SUCC != l_ret)
    {
        OAM_ERROR_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_set_pmksa::wal_send_cfg_event fail[%d]!}\r\n", l_ret);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}


OAL_STATIC oal_int32 wal_cfg80211_del_pmksa(oal_wiphy_stru           *pst_wiphy,
                                                      oal_net_device_stru      *pst_net_device,
                                                      oal_cfg80211_pmksa_stru  *pmksa)
{
    wal_msg_write_stru                       st_write_msg           = {0};
    mac_cfg_pmksa_param_stru                *pst_cfg_pmksa;
    oal_int32                                l_ret;

    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_net_device) || (OAL_PTR_NULL == pmksa))
    {
        OAM_ERROR_LOG3(0, OAM_SF_CFG,
                       "{wal_cfg80211_del_pmksa::param null! pst_wiphy[%d], pst_net_device[%d], pmksa[%d]!!}\r\n",
                       pst_wiphy, pst_net_device, pmksa);
        return -OAL_EINVAL;
    }

    if ((OAL_PTR_NULL == pmksa->bssid) || (OAL_PTR_NULL == pmksa->pmkid))
    {
        OAM_ERROR_LOG2(0, OAM_SF_CFG, "{wal_cfg80211_del_pmksa::param null! bssid[%d] pmkid[%d]}\r\n",
                       pmksa->bssid, pmksa->pmkid);
        return -OAL_EINVAL;
    }

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_DEL_PMKSA, OAL_SIZEOF(mac_cfg_pmksa_param_stru));
    pst_cfg_pmksa = (mac_cfg_pmksa_param_stru *)st_write_msg.auc_value;
    oal_memcopy(pst_cfg_pmksa->auc_bssid, pmksa->bssid, WLAN_MAC_ADDR_LEN);
    oal_memcopy(pst_cfg_pmksa->auc_pmkid, pmksa->pmkid, WLAN_PMKID_LEN);

    l_ret = wal_send_cfg_event(pst_net_device,
                                WAL_MSG_TYPE_WRITE,
                                WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_pmksa_param_stru),
                                (oal_uint8 *)&st_write_msg,
                                OAL_FALSE,
                                OAL_PTR_NULL);

    if (OAL_SUCC != l_ret)
    {
        OAM_ERROR_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_del_pmksa::wal_send_cfg_event fail[%d]!}\r\n", l_ret);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}



OAL_STATIC oal_int32 wal_cfg80211_flush_pmksa(oal_wiphy_stru *pst_wiphy, oal_net_device_stru *pst_net_device)
{
    wal_msg_write_stru                       st_write_msg           = {0};
    oal_int32                                l_ret;

    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_net_device))
    {
        OAM_ERROR_LOG2(0, OAM_SF_CFG,
                       "{wal_cfg80211_flush_pmksa::param null! pst_wiphy[%d], pst_net_device[%d]!!}\r\n",
                       pst_wiphy, pst_net_device);
        return -OAL_EINVAL;
    }

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_FLUSH_PMKSA, 0);

    l_ret = wal_send_cfg_event(pst_net_device,
                                WAL_MSG_TYPE_WRITE,
                                WAL_MSG_WRITE_MSG_HDR_LENGTH,
                                (oal_uint8 *)&st_write_msg,
                                OAL_FALSE,
                                OAL_PTR_NULL);

    if (OAL_SUCC != l_ret)
    {
        OAM_ERROR_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_flush_pmksa::wal_send_cfg_event fail[%d]!}\r\n", l_ret);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}



OAL_STATIC oal_int32 wal_cfg80211_remain_on_channel(oal_wiphy_stru           *pst_wiphy,
                                                    oal_wireless_dev_stru    *pst_wdev,
                                                    struct ieee80211_channel *pst_chan,
                                                    oal_uint32                ul_duration,
                                                    oal_uint64               *pull_cookie)
{
    wal_msg_write_stru                       st_write_msg           = {0};
    wal_msg_stru                            *pst_rsp_msg            = OAL_PTR_NULL;
    oal_uint32                               ul_err_code;
    oal_net_device_stru                     *pst_netdev;
    mac_remain_on_channel_param_stru         st_remain_on_channel   = {0};
    oal_uint16                               us_center_freq;
    oal_int32                                l_channel;
    oal_int32                                l_ret;
    mac_device_stru                         *pst_mac_device;
    mac_vap_stru                            *pst_mac_vap;

    /* 1.1 ???????? */
    if ((OAL_PTR_NULL == pst_wiphy)
        || (OAL_PTR_NULL == pst_wdev)
        || (OAL_PTR_NULL == pst_chan)
        || (OAL_PTR_NULL == pull_cookie))
    {
        OAM_ERROR_LOG4(0, OAM_SF_P2P, "{wal_cfg80211_remain_on_channel::pst_wiphy or pst_wdev or pst_chan or pull_cookie ptr is null,error %d, %d, %d, %d!}\r\n",
                        pst_wiphy, pst_wdev, pst_chan, pull_cookie);
        return -OAL_EINVAL;
    }

    pst_netdev = pst_wdev->netdev;
    if (OAL_PTR_NULL == pst_netdev)
    {
        OAM_ERROR_LOG0(0, OAM_SF_P2P, "{wal_cfg80211_remain_on_channel::pst_netdev ptr is null!}\r\n");
        return -OAL_EINVAL;
    }

    /* ????net_device ??????????mac_device_stru ???? */
    pst_mac_vap    = OAL_NET_DEV_PRIV(pst_netdev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_P2P, "{wal_cfg80211_remain_on_channel::can't get mac vap from netdevice priv data!}\r\n");
        return -OAL_EINVAL;
    }

    pst_mac_device = (mac_device_stru *)mac_res_get_dev(pst_mac_vap->uc_device_id);
    if (OAL_PTR_NULL == pst_mac_device)
    {
        OAM_ERROR_LOG0(0, OAM_SF_P2P, "{wal_cfg80211_remain_on_channel::pst_mac_device ptr is null!}\r\n");
        return -OAL_EINVAL;
    }

#ifdef _PRE_WLAN_FEATURE_WAPI
        if (OAL_TRUE == hmac_user_is_wapi_connected(pst_mac_vap->uc_device_id))
        {
            OAM_WARNING_LOG0(0, OAM_SF_CFG, "{stop p2p remaining under wapi!}");
            return -OAL_EINVAL;
        }
#endif/* #ifdef _PRE_WLAN_FEATURE_WAPI */

    /* 2.1 ???????????? */
    us_center_freq  = pst_chan->center_freq;
    l_channel       = (oal_int32)oal_ieee80211_frequency_to_channel((oal_int32)us_center_freq);

    st_remain_on_channel.uc_listen_channel  = (oal_uint8)l_channel;
    st_remain_on_channel.ul_listen_duration = ul_duration;
    st_remain_on_channel.st_listen_channel  = *pst_chan;
    st_remain_on_channel.en_listen_channel_type =  WLAN_BAND_WIDTH_20M;

    if (pst_chan->band == HISI_IEEE80211_BAND_2GHZ)
    {
        st_remain_on_channel.en_band = WLAN_BAND_2G;
    }
    else if (pst_chan->band == HISI_IEEE80211_BAND_5GHZ)
    {
        st_remain_on_channel.en_band = WLAN_BAND_5G;
    }
    else
    {
        OAM_WARNING_LOG1(0, OAM_SF_P2P, "{wal_cfg80211_remain_on_channel::wrong band type[%d]!}\r\n", pst_chan->band);
        return -OAL_EINVAL;
    }
    /* ????cookie ?? */
    *pull_cookie = ++pst_mac_device->st_p2p_info.ull_last_roc_id;   /* cookie????????????????????????????????????????callback */
    if (*pull_cookie == 0)
    {
        *pull_cookie = ++pst_mac_device->st_p2p_info.ull_last_roc_id;
    }

    /* ????cookie ??????????HMAC ??DMAC */
    st_remain_on_channel.ull_cookie         = pst_mac_device->st_p2p_info.ull_last_roc_id;

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /* 3.1 ???? msg ?????? */
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_REMAIN_ON_CHANNEL, OAL_SIZEOF(mac_remain_on_channel_param_stru));


    /* 3.2 ???? msg ?????? */
    oal_memcopy(st_write_msg.auc_value, &st_remain_on_channel, OAL_SIZEOF(mac_remain_on_channel_param_stru));

    /* 3.3 ???????? */
    l_ret = wal_send_cfg_event(pst_netdev,
                                WAL_MSG_TYPE_WRITE,
                                WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_remain_on_channel_param_stru),
                                (oal_uint8 *)&st_write_msg,
                                OAL_TRUE,
                                &pst_rsp_msg);

    if (OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG1(0, OAM_SF_P2P, "{wal_cfg80211_remain_on_channel::wal_send_cfg_event return err code:[%d]!}\r\n",l_ret);
        return -OAL_EFAIL;
    }

    /* 4.1 ???????????????? */
    ul_err_code = wal_check_and_release_msg_resp(pst_rsp_msg);
    if(OAL_SUCC != ul_err_code)
    {
        OAM_WARNING_LOG1(0, OAM_SF_CFG, "{wal_cfg80211_remain_on_channel::wal_send_cfg_event return err code:[%u]!}\r\n",
                         ul_err_code);
        return -OAL_EFAIL;
    }

    /* ?????????????????????? */
    oal_cfg80211_ready_on_channel(pst_wdev, *pull_cookie, pst_chan, ul_duration, GFP_KERNEL);
    OAM_WARNING_LOG4(0, OAM_SF_P2P,
                  "{wal_cfg80211_remain_on_channel::SUCC! l_channel=%d, ul_duration=%d, cookie 0x%x, band= %d!}\r\n",
                  l_channel, ul_duration, *pull_cookie, st_remain_on_channel.en_band);
    return OAL_SUCC;
}



OAL_STATIC oal_int32 wal_cfg80211_cancel_remain_on_channel(oal_wiphy_stru           *pst_wiphy,
                                                            oal_wireless_dev_stru   *pst_wdev,
                                                            oal_uint64               ull_cookie)
{
    wal_msg_write_stru                       st_write_msg                 = {0};
    mac_remain_on_channel_param_stru         st_cancel_remain_on_channel  = {0};
    wal_msg_stru                            *pst_rsp_msg                  = OAL_PTR_NULL;
    oal_uint32                               ul_err_code;
    oal_net_device_stru                     *pst_netdev;
    oal_int32                                l_ret;

    if ((OAL_PTR_NULL == pst_wiphy)
        || (OAL_PTR_NULL == pst_wdev))
    {
        OAM_ERROR_LOG2(0, OAM_SF_P2P, "{wal_cfg80211_cancel_remain_on_channel::pst_wiphy or pst_wdev is null,error %d, %d!}\r\n",
                        pst_wiphy, pst_wdev);
        return -OAL_EINVAL;
    }

    pst_netdev = pst_wdev->netdev;
    if (OAL_PTR_NULL == pst_netdev)
    {
        OAM_ERROR_LOG0(0, OAM_SF_P2P, "{wal_cfg80211_cancel_remain_on_channel::pst_netdev ptr is null!}\r\n");
        return -OAL_EINVAL;
    }

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    OAM_WARNING_LOG1(0, OAM_SF_P2P, "wal_cfg80211_cancel_remain_on_channel[0x%x].", ull_cookie);

    /* 3.1 ???? msg ?????? */
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_CANCEL_REMAIN_ON_CHANNEL, OAL_SIZEOF(mac_remain_on_channel_param_stru));


    /* 3.2 ???? msg ?????? */
    oal_memcopy(st_write_msg.auc_value, &st_cancel_remain_on_channel, OAL_SIZEOF(mac_remain_on_channel_param_stru));

    /* 3.3 ???????? */
    l_ret = wal_send_cfg_event(pst_netdev,
                                WAL_MSG_TYPE_WRITE,
                                WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_remain_on_channel_param_stru),
                                (oal_uint8 *)&st_write_msg,
                                OAL_TRUE,
                                &pst_rsp_msg);

    if(OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG1(0, OAM_SF_P2P, "{wal_cfg80211_cancel_remain_on_channel::wal_send_cfg_event return err code: [%d]!}\r\n", l_ret);
        return -OAL_EFAIL;
    }

    /* 4.1 ???????????????? */
    ul_err_code = wal_check_and_release_msg_resp(pst_rsp_msg);
    if(OAL_SUCC != ul_err_code)
    {
        OAM_ERROR_LOG1(0, OAM_SF_P2P, "{wal_cfg80211_cancel_remain_on_channel::wal_send_cfg_event return err code:[%u]!}\r\n",
                        ul_err_code);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;
}




OAL_STATIC oal_void wal_check_cookie_timeout(cookie_arry_stru  *pst_cookie_array,
                                    oal_uint8       *puc_cookie_bitmap,
                                    oal_uint32       ul_current_time)
{
    oal_uint8           uc_loops = 0;
    cookie_arry_stru   *pst_tmp_cookie;

    OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_check_cookie_timeout::time_out!}\r\n");
    for (uc_loops = 0; uc_loops < WAL_COOKIE_ARRAY_SIZE; uc_loops++)
    {
        pst_tmp_cookie = &pst_cookie_array[uc_loops];
        if (oal_time_is_before(pst_tmp_cookie->ul_record_time + OAL_MSECS_TO_JIFFIES(WAL_MGMT_TX_TIMEOUT_MSEC)))
        {
            /* cookie array ????????cookie ?????? */
            /* ????cookie array ????????cookie */
            pst_tmp_cookie->ul_record_time = 0;
            pst_tmp_cookie->ull_cookie     = 0;
            /* ??????????cookie bitmap?? */
            oal_bit_clear_bit_one_byte(puc_cookie_bitmap, uc_loops);
        }
    }
}


OAL_STATIC oal_uint32 wal_del_cookie_from_array(cookie_arry_stru   *pst_cookie_array,
                                        oal_uint8       *puc_cookie_bitmap,
                                        oal_uint8        uc_cookie_idx)
{
    cookie_arry_stru   *pst_tmp_cookie;

    /* ????????cookie bitmap ?? */
    oal_bit_clear_bit_one_byte(puc_cookie_bitmap, uc_cookie_idx);

    /* ????cookie array ????????cookie */
    pst_tmp_cookie = &pst_cookie_array[uc_cookie_idx];
    pst_tmp_cookie->ull_cookie     = 0;
    pst_tmp_cookie->ul_record_time = 0;
    return OAL_SUCC;
}



OAL_STATIC oal_uint32 wal_add_cookie_to_array(cookie_arry_stru *pst_cookie_array,
                                    oal_uint8       *puc_cookie_bitmap,
                                    oal_uint64      *pull_cookie,
                                    oal_uint8       *puc_cookie_idx)
{
    oal_uint8           uc_idx;
    cookie_arry_stru   *pst_tmp_cookie;

    if (*puc_cookie_bitmap == 0xFF)
    {
        /* cookie array ???????????? */
        OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_add_cookie_to_array::array full!}\r\n");
        return OAL_FAIL;
    }

    /* ??cookie ??????array ?? */
    uc_idx = oal_bit_get_num_one_byte(*puc_cookie_bitmap);
    oal_bit_set_bit_one_byte(puc_cookie_bitmap, uc_idx);

    pst_tmp_cookie = &pst_cookie_array[uc_idx];
    pst_tmp_cookie->ull_cookie      = *pull_cookie;
    pst_tmp_cookie->ul_record_time  = OAL_TIME_JIFFY;

    *puc_cookie_idx = uc_idx;
    return OAL_SUCC;
}


OAL_STATIC oal_uint32 wal_check_cookie_from_array(oal_uint8 *puc_cookie_bitmap,oal_uint8 uc_cookie_idx)
{
    /* ??cookie bitmap????????????cookie index????????????0????????????del */
    if(*puc_cookie_bitmap & (BIT(uc_cookie_idx)))
    {
        return OAL_SUCC;
    }
    /* ????????????FAIL */
    return OAL_FAIL;
}


OAL_STATIC oal_uint32 wal_mgmt_do_tx(oal_net_device_stru    *pst_netdev,
                                                mac_mgmt_frame_stru *pst_mgmt_tx_param)
{
    mac_vap_stru                    *pst_mac_vap;
    hmac_vap_stru                   *pst_hmac_vap;
    oal_mgmt_tx_stru                *pst_mgmt_tx;
    wal_msg_write_stru               st_write_msg;
    oal_int32                        l_ret = 0;
    oal_int                          i_leftime;

    pst_mac_vap = OAL_NET_DEV_PRIV(pst_netdev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_mgmt_do_tx::can't get mac vap from netdevice priv data.}\r\n");
        return OAL_FAIL;
    }

    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG0(pst_mac_vap->uc_vap_id, OAM_SF_CFG, "{wal_mgmt_do_tx::pst_hmac_vap ptr is null!}\r\n");
        return OAL_FAIL;
    }

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /* 3.1 ???? msg ?????? */
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_MGMT_TX, OAL_SIZEOF(mac_mgmt_frame_stru));

    /* 3.2 ???? msg ?????? */
    oal_memcopy(st_write_msg.auc_value, pst_mgmt_tx_param, OAL_SIZEOF(mac_mgmt_frame_stru));

    /* 3.3 ???????? */
    l_ret = wal_send_cfg_event(pst_netdev,
                                WAL_MSG_TYPE_WRITE,
                                WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_mgmt_frame_stru),
                                (oal_uint8 *)&st_write_msg,
                                OAL_FALSE,
                                OAL_PTR_NULL);
    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_mgmt_do_tx::wal_send_cfg_event return err code %d!}\r\n", l_ret);
        return OAL_FAIL;
    }

    pst_mgmt_tx = &(pst_hmac_vap->st_mgmt_tx);
    pst_mgmt_tx->mgmt_tx_complete= OAL_FALSE;
    pst_mgmt_tx->mgmt_tx_status  = OAL_FAIL;
    /*lint -e730*/
    i_leftime = OAL_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(pst_mgmt_tx->st_wait_queue, OAL_TRUE== pst_mgmt_tx->mgmt_tx_complete,  (oal_uint32)OAL_MSECS_TO_JIFFIES(WAL_MGMT_TX_TIMEOUT_MSEC));

    if ( 0 == i_leftime)
    {
        /* ?????????? */
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_mgmt_do_tx::mgmt tx timeout!}\r\n");
        return OAL_FAIL;
    }
    else if (i_leftime < 0)
    {
        /* ?????????????? */
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_mgmt_do_tx::mgmt tx timer error!}\r\n");
        return OAL_FAIL;
    }
    else
    {
        /* ????????  */
        OAM_INFO_LOG0(0, OAM_SF_ANY, "{wal_mgmt_do_tx::mgmt tx commpleted!}\r\n");
        return (OAL_SUCC != pst_mgmt_tx->mgmt_tx_status)?OAL_FAIL:OAL_SUCC;/* [false alarm]:??????????????0????1????????*/
    }
}



OAL_STATIC oal_int32 wal_cfg80211_mgmt_tx(oal_wiphy_stru                *pst_wiphy,
                                            oal_wireless_dev_stru       *pst_wdev,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
                                            struct cfg80211_mgmt_tx_params *pst_params,
#else
                                            oal_ieee80211_channel       *pst_chan,
                                            bool                         en_offchan,
                                            oal_uint32                   ul_wait,
                                            OAL_CONST oal_uint8         *puc_buf,
                                            oal_size_t                   ul_len,
                                            bool                         en_no_cck,
                                            bool                         en_dont_wait_for_ack,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)) */
                                            oal_uint64                  *pull_cookie)
{
    oal_net_device_stru             *pst_netdev;
    mac_device_stru                 *pst_mac_device;
    mac_vap_stru                    *pst_mac_vap;
    OAL_CONST oal_ieee80211_mgmt    *pst_mgmt;
    oal_int32                       ul_ret = 0;
    mac_mgmt_frame_stru             st_mgmt_tx;
    oal_uint8                       uc_cookie_idx;
    oal_uint8                       uc_retry;
    mac_p2p_info_stru               *pst_p2p_info;
    hmac_vap_stru                   *pst_hmac_vap;
    oal_mgmt_tx_stru                *pst_mgmt_tx;
    unsigned long                    ul_start_time_stamp;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
    oal_ieee80211_channel       *pst_chan;
    OAL_CONST oal_uint8         *puc_buf;
    oal_size_t                   ul_len;
    if (pst_params == OAL_PTR_NULL)
    {
        return -OAL_EINVAL;
    }
    pst_chan = pst_params->chan;
    puc_buf  = pst_params->buf;
    ul_len   = pst_params->len;
#endif

    /* 1.1 ???????? */
    if ((OAL_PTR_NULL == pst_wiphy)
        || (OAL_PTR_NULL == pst_wdev)
        || (OAL_PTR_NULL == pst_chan)
        || (OAL_PTR_NULL == pull_cookie)
        || (OAL_PTR_NULL == puc_buf))
    {
        OAM_ERROR_LOG4(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx::pst_wiphy or pst_wdev or pst_chan or pull_cookie or puc_buf ptr is null,error %d, %d, %d, %d!}\r\n",
                        pst_wiphy, pst_wdev, pst_chan, pull_cookie);
        return -OAL_EINVAL;
    }

    /* ????net_device ??????????mac_device_stru ???? */
    pst_netdev = pst_wdev->netdev;
    if (OAL_PTR_NULL == pst_netdev)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx::pst_netdev ptr is null!}\r\n");
        return -OAL_EINVAL;
    }

    pst_mac_vap    = OAL_NET_DEV_PRIV(pst_netdev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx::can't get mac vap from netdevice priv data!}\r\n");
        return -OAL_EINVAL;
    }

    pst_mac_device = (mac_device_stru *)mac_res_get_dev(pst_mac_vap->uc_device_id);
    if (OAL_PTR_NULL == pst_mac_device)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx::pst_mac_device ptr is null!}\r\n");
        return -OAL_EINVAL;
    }

    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx::pst_hmac_vap ptr is null!}\r\n");
        return -OAL_EINVAL;
    }

    pst_p2p_info = &pst_mac_device->st_p2p_info;
    *pull_cookie = pst_p2p_info->ull_send_action_id++;   /* cookie????????????????????????????????????????callback */
    if (*pull_cookie == 0)
    {
        *pull_cookie = pst_p2p_info->ull_send_action_id++;
    }
    pst_mgmt = (const struct ieee80211_mgmt *)puc_buf;
    if (oal_ieee80211_is_probe_resp(pst_mgmt->frame_control))
    {
        *pull_cookie = 0; /* set cookie default value */
        /* host should not send PROE RESPONSE,
           device will send immediately when receive probe request packet */
        oal_cfg80211_mgmt_tx_status(pst_wdev, *pull_cookie, puc_buf, ul_len, OAL_TRUE, GFP_KERNEL);
        return OAL_SUCC;
    }

    /* 2.1 ???????????? */
    OAL_MEMZERO(&st_mgmt_tx, OAL_SIZEOF(st_mgmt_tx));
    st_mgmt_tx.channel = oal_ieee80211_frequency_to_channel(pst_chan->center_freq);
    ul_ret = wal_add_cookie_to_array(g_cookie_array, &g_uc_cookie_array_bitmap, pull_cookie, &uc_cookie_idx);
    if (OAL_SUCC != ul_ret)
    {
        OAM_WARNING_LOG1(pst_mac_vap->uc_vap_id, OAM_SF_ANY, "{wal_cfg80211_mgmt_tx::Failed to add cookies, ul_ret[%d]!}\r\n", ul_ret);
        return -OAL_EINVAL;
    }
    else
    {
        st_mgmt_tx.mgmt_frame_id = uc_cookie_idx;
    }
    st_mgmt_tx.us_len       = ul_len;
    st_mgmt_tx.puc_frame    = puc_buf;

    pst_mgmt_tx = &(pst_hmac_vap->st_mgmt_tx);
    pst_mgmt_tx->mgmt_tx_complete= OAL_FALSE;
    pst_mgmt_tx->mgmt_tx_status = OAL_FAIL;

    ul_start_time_stamp = OAL_TIME_JIFFY;

    uc_retry = 0;
    /* ???????????????????? */
    do
    {
        ul_ret = wal_mgmt_do_tx(pst_netdev, &st_mgmt_tx);
        uc_retry++;
    }while((ul_ret != OAL_SUCC) && time_before(OAL_TIME_JIFFY, ul_start_time_stamp + OAL_MSECS_TO_JIFFIES(2 * WAL_MGMT_TX_TIMEOUT_MSEC)));

    if (ul_ret != OAL_SUCC)
    {
        /* ??????????????????????bitmap */
        wal_check_cookie_timeout(g_cookie_array, &g_uc_cookie_array_bitmap, OAL_TIME_JIFFY);
        oal_cfg80211_mgmt_tx_status(pst_wdev, *pull_cookie, puc_buf, ul_len, OAL_FALSE, GFP_KERNEL);
    }
    else
    {
        /* ????????  */
        *pull_cookie = g_cookie_array[pst_mgmt_tx->mgmt_frame_id].ull_cookie;
        wal_del_cookie_from_array(g_cookie_array, &g_uc_cookie_array_bitmap, pst_mgmt_tx->mgmt_frame_id);
        oal_cfg80211_mgmt_tx_status(pst_wdev, *pull_cookie, puc_buf, ul_len, OAL_TRUE, GFP_KERNEL);
    }

    OAM_WARNING_LOG3(0, OAM_SF_ANY, "{wal_cfg80211_mgmt_tx::tx status [%d], retry cnt[%d]}, delta_time[%d]\r\n",
                    ul_ret, uc_retry, OAL_JIFFIES_TO_MSECS(OAL_TIME_JIFFY - ul_start_time_stamp));


    return OAL_SUCC;
}


oal_uint32  wal_cfg80211_mgmt_tx_status(frw_event_mem_stru *pst_event_mem)
{
    frw_event_stru                  *pst_event;
    dmac_crx_mgmt_tx_status_stru    *pst_mgmt_tx_status_param;
    hmac_vap_stru                   *pst_hmac_vap;
    oal_mgmt_tx_stru                *pst_mgmt_tx;

    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_event_mem))
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_mgmt_tx_status::pst_event_mem is null!}\r\n");
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_event  = (frw_event_stru *)pst_event_mem->puc_data;
    pst_hmac_vap = mac_res_get_hmac_vap(pst_event->st_event_hdr.uc_vap_id);
    if(OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG1(0, OAM_SF_TX, "{wal_cfg80211_mgmt_tx_status::pst_hmac_vap null.vap_id[%d]}", pst_event->st_event_hdr.uc_vap_id);
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_mgmt_tx_status_param   = (dmac_crx_mgmt_tx_status_stru *)(pst_event->auc_event_data);
    pst_mgmt_tx = &(pst_hmac_vap->st_mgmt_tx);
    pst_mgmt_tx->mgmt_tx_complete = OAL_TRUE;
    pst_mgmt_tx->mgmt_tx_status   = pst_mgmt_tx_status_param->uc_dscr_status;
    pst_mgmt_tx->mgmt_frame_id    = pst_mgmt_tx_status_param->mgmt_frame_id;

    /* ????????????cookie???????????????????????????????????? */
    if(OAL_SUCC == wal_check_cookie_from_array(&g_uc_cookie_array_bitmap, pst_mgmt_tx->mgmt_frame_id))
    {
         /* ??????????????????OAL_WAIT_QUEUE_WAKE_UP?????????? */
        OAL_SMP_MB();
        OAL_WAIT_QUEUE_WAKE_UP_INTERRUPT(&pst_mgmt_tx->st_wait_queue);
    }

    return OAL_SUCC;
}

/* P2P ??????????CFG80211???? */
oal_void wal_cfg80211_mgmt_frame_register(struct wiphy *wiphy,
                                        struct wireless_dev *wdev,
                                        oal_uint16 frame_type,
                                        bool reg)
{
    //OAL_IO_PRINT("wal_cfg80211_mgmt_frame_register::net_device_name:%.16s, if_type:%d", wdev->netdev->name, wdev->iftype);
    OAM_INFO_LOG3(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_frame_register::enter.frame_type[0x%04x], reg[%d], if_type[%d]}",
                    frame_type, reg, wdev->iftype);

    return;
}

oal_int32 wal_cfg80211_set_bitrate_mask(struct wiphy *wiphy,
                                        struct net_device *dev,
                                        const u8 *peer,
                                        const struct cfg80211_bitrate_mask *mask)
{
    OAM_INFO_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_set_bitrate_mask::enter 000.}");

    return OAL_SUCC;
}

#endif  /* _PRE_CONFIG_TARGET_PRODUCT != _PRE_TARGET_PRODUCT_TYPE_E5 */

#else

oal_void wal_check_cookie_timeout(cookie_arry_stru  *pst_cookie_array,
                                    oal_uint8       *puc_cookie_bitmap,
                                    oal_uint32       ul_current_time)
{
    oal_uint8           uc_loops = 0;
    cookie_arry_stru   *pst_tmp_cookie;

    OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_check_cookie_timeout::time_out!}\r\n");
    for (uc_loops = 0; uc_loops < WAL_COOKIE_ARRAY_SIZE; uc_loops++)
    {
        pst_tmp_cookie = &pst_cookie_array[uc_loops];
        if (oal_time_is_before(pst_tmp_cookie->ul_record_time + OAL_MSECS_TO_JIFFIES(WAL_MGMT_TX_TIMEOUT_MSEC)))
        {
            /* cookie array ????????cookie ?????? */
            /* ????cookie array ????????cookie */
            pst_tmp_cookie->ul_record_time = 0;
            pst_tmp_cookie->ull_cookie     = 0;
            /* ??????????cookie bitmap?? */
            oal_bit_clear_bit_one_byte(puc_cookie_bitmap, uc_loops);
        }
    }
}


oal_uint32 wal_del_cookie_from_array(cookie_arry_stru   *pst_cookie_array,
                                        oal_uint8       *puc_cookie_bitmap,
                                        oal_uint8        uc_cookie_idx)
{
    cookie_arry_stru   *pst_tmp_cookie;

    /* ????????cookie bitmap ?? */
    oal_bit_clear_bit_one_byte(puc_cookie_bitmap, uc_cookie_idx);

    /* ????cookie array ????????cookie */
    pst_tmp_cookie = &pst_cookie_array[uc_cookie_idx];
    pst_tmp_cookie->ull_cookie     = 0;
    pst_tmp_cookie->ul_record_time = 0;
    return OAL_SUCC;
}



oal_uint32 wal_add_cookie_to_array(cookie_arry_stru *pst_cookie_array,
                                    oal_uint8       *puc_cookie_bitmap,
                                    oal_uint64      *pull_cookie,
                                    oal_uint8       *puc_cookie_idx)
{
    oal_uint8           uc_idx;
    cookie_arry_stru   *pst_tmp_cookie;

    if (*puc_cookie_bitmap == 0xFF)
    {
        /* cookie array ???????????? */
        OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_add_cookie_to_array::array full!}\r\n");
        return OAL_FAIL;
    }

    /* ??cookie ??????array ?? */
    uc_idx = oal_bit_get_num_one_byte(*puc_cookie_bitmap);
    oal_bit_set_bit_one_byte(puc_cookie_bitmap, uc_idx);

    pst_tmp_cookie = &pst_cookie_array[uc_idx];
    pst_tmp_cookie->ull_cookie      = *pull_cookie;
    pst_tmp_cookie->ul_record_time  = OAL_TIME_JIFFY;

    *puc_cookie_idx = uc_idx;
    return OAL_SUCC;
}



oal_int32 wal_cfg80211_mgmt_tx(oal_wiphy_stru                *pst_wiphy,
                                            oal_wireless_dev_stru       *pst_wdev,
                                            oal_ieee80211_channel       *pst_chan,
                                            oal_bool_enum_uint8          en_offchan,
                                            oal_uint32                   ul_wait,
                                            OAL_CONST oal_uint8         *puc_buf,
                                            size_t                       ul_len,
                                            oal_bool_enum_uint8          en_no_cck,
                                            oal_bool_enum_uint8          en_dont_wait_for_ack,
                                            oal_uint64                  *pull_cookie)
{
    wal_msg_write_stru              st_write_msg;
    oal_net_device_stru             *pst_netdev;
    mac_device_stru                 *pst_mac_device;
    mac_vap_stru                    *pst_mac_vap;
    OAL_CONST oal_ieee80211_mgmt    *pst_mgmt;
    oal_int32                       l_ret = 0;
    oal_uint32                      ul_ret = 0;
    mac_mgmt_frame_stru             st_mgmt_tx;
    oal_int                         i_leftime;
    oal_uint8                       uc_cookie_idx;
    mac_p2p_info_stru               *pst_p2p_info;
    hmac_vap_stru                   *pst_hmac_vap;
    oal_mgmt_tx_stru                *pst_mgmt_tx;

    /* 1.1 ???????? */
    if ((OAL_PTR_NULL == pst_wiphy)
        || (OAL_PTR_NULL == pst_wdev)
        || (OAL_PTR_NULL == pst_chan)
        || (OAL_PTR_NULL == pull_cookie)
        || (OAL_PTR_NULL == puc_buf))
    {
        OAM_ERROR_LOG4(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx::pst_wiphy or pst_wdev or pst_chan or pull_cookie or puc_buf ptr is null,error %d, %d!}\r\n",
                        pst_wiphy, pst_wdev, pst_chan, pull_cookie);
        return -OAL_EINVAL;
    }

    /* ????net_device ??????????mac_device_stru ???? */
    pst_netdev = pst_wdev->netdev;
    if (OAL_PTR_NULL == pst_netdev)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx::pst_netdev ptr is null!}\r\n");
        return -OAL_EINVAL;
    }

    pst_mac_vap    = OAL_NET_DEV_PRIV(pst_netdev);
    if (OAL_PTR_NULL == pst_mac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx::pst_mac_vap ptr is null!}\r\n");
        return -OAL_EINVAL;
    }

    pst_mac_device = (mac_device_stru *)mac_res_get_dev(pst_mac_vap->uc_device_id);
    if (OAL_PTR_NULL == pst_mac_device)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx::pst_mac_device ptr is null!}\r\n");
        return -OAL_EINVAL;
    }

    pst_hmac_vap = (hmac_vap_stru *)mac_res_get_hmac_vap(pst_mac_vap->uc_vap_id);
    if (OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx::pst_hmac_vap ptr is null!}\r\n");
        return -OAL_EINVAL;
    }

    pst_p2p_info = &pst_mac_device->st_p2p_info;
    *pull_cookie = pst_p2p_info->ull_send_action_id++;   /* cookie????????????????????????????????????????callback */
    if (*pull_cookie == 0)
    {
        *pull_cookie = pst_p2p_info->ull_send_action_id++;
    }
    pst_mgmt = (const struct ieee80211_mgmt *)puc_buf;
    if (oal_ieee80211_is_probe_resp(pst_mgmt->frame_control))
    {
        *pull_cookie = 0; /* set cookie default value */
        /* host should not send PROE RESPONSE,
           device will send immediately when receive probe request packet */
        oal_cfg80211_mgmt_tx_status(pst_wdev, *pull_cookie, puc_buf, ul_len, OAL_TRUE, GFP_KERNEL);
        return OAL_SUCC;
    }

    /* 2.1 ???????????? */
    OAL_MEMZERO(&st_mgmt_tx, OAL_SIZEOF(st_mgmt_tx));
    st_mgmt_tx.channel = oal_ieee80211_frequency_to_channel((oal_int32)pst_chan->center_freq);
    ul_ret = wal_add_cookie_to_array(g_cookie_array, &g_uc_cookie_array_bitmap, pull_cookie, &uc_cookie_idx);
    if (OAL_SUCC != ul_ret)
    {
        OAM_WARNING_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_mgmt_tx::Failed to add cookies!}\r\n");
        return -OAL_EINVAL;
    }
    else
    {
        st_mgmt_tx.mgmt_frame_id = uc_cookie_idx;
    }
    st_mgmt_tx.us_len = (oal_uint16)ul_len;
    st_mgmt_tx.puc_frame = puc_buf;

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    /* 3.1 ???? msg ?????? */
    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_CFG80211_MGMT_TX, OAL_SIZEOF(st_mgmt_tx));


    /* 3.2 ???? msg ?????? */
    oal_memcopy(st_write_msg.auc_value, &st_mgmt_tx, OAL_SIZEOF(st_mgmt_tx));

    /* 3.3 ???????? */
    l_ret = wal_send_cfg_event(pst_netdev,
                                WAL_MSG_TYPE_WRITE,
                                WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(st_mgmt_tx),
                                (oal_uint8 *)&st_write_msg,
                                OAL_FALSE,
                                NULL);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_mgmt_tx::wal_send_cfg_event return err code %d!}\r\n", l_ret);
        return -OAL_EINVAL;
    }

    pst_mgmt_tx = &(pst_hmac_vap->st_mgmt_tx);
    pst_mgmt_tx->mgmt_tx_complete= OAL_FALSE;
    pst_mgmt_tx->mgmt_tx_status = OAL_FAIL;
    /*lint -e730*/
    i_leftime = OAL_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(pst_mgmt_tx->st_wait_queue, OAL_TRUE== pst_mgmt_tx->mgmt_tx_complete,  (oal_uint32)OAL_MSECS_TO_JIFFIES(WAL_MGMT_TX_TIMEOUT_MSEC));
   /*lint +e730*/

    if ( 0 == i_leftime)
    {
        /* ?????????????????????? */
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_mgmt_tx::mgmt tx wait for %ld ms timeout!}\r\n",((oal_uint32)WAL_MGMT_TX_TIMEOUT_MSEC));
        wal_check_cookie_timeout(g_cookie_array, &g_uc_cookie_array_bitmap, OAL_TIME_JIFFY);

    }
    else if (i_leftime < 0)
    {
        /* ?????????????? */
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_mgmt_tx::mgmt tx wait for %ld ms error!}\r\n",((oal_uint32)WAL_MGMT_TX_TIMEOUT_MSEC));
    }
    else
    {
        /* ????????  */
        OAM_INFO_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_mgmt_tx::mgmt tx wait for %ld ms complete!}\r\n",((oal_uint32)WAL_MGMT_TX_TIMEOUT_MSEC));
        *pull_cookie = g_cookie_array[pst_mgmt_tx->mgmt_frame_id].ull_cookie;
        wal_del_cookie_from_array(g_cookie_array, &g_uc_cookie_array_bitmap, pst_mgmt_tx->mgmt_frame_id);
    }


    if(pst_mgmt_tx->mgmt_tx_status != OAL_SUCC)
    {
        oal_cfg80211_mgmt_tx_status(pst_wdev, *pull_cookie, puc_buf, ul_len, OAL_FALSE, GFP_KERNEL);
        return -OAL_EINVAL;
    }
    else
    {
        oal_cfg80211_mgmt_tx_status(pst_wdev, *pull_cookie, puc_buf, ul_len, OAL_TRUE, GFP_KERNEL);
        return OAL_SUCC;
    }
}
/*lint +e774*/



oal_uint32  wal_cfg80211_mgmt_tx_status(frw_event_mem_stru *pst_event_mem)
{
    frw_event_stru                  *pst_event;
    dmac_crx_mgmt_tx_status_stru    *pst_mgmt_tx_status_param;
    hmac_vap_stru                   *pst_hmac_vap;
    oal_mgmt_tx_stru                *pst_mgmt_tx;

    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_event_mem))
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_mgmt_tx_status::pst_event_mem is null!}\r\n");
        return OAL_ERR_CODE_PTR_NULL;
    }
    pst_event  = (frw_event_stru *)pst_event_mem->puc_data;
    pst_hmac_vap = mac_res_get_hmac_vap(pst_event->st_event_hdr.uc_vap_id);
    if(OAL_PTR_NULL == pst_hmac_vap)
    {
        OAM_ERROR_LOG0(0, OAM_SF_TX, "{wal_cfg80211_mgmt_tx_status::pst_hmac_vap null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_mgmt_tx_status_param   = (dmac_crx_mgmt_tx_status_stru *)(pst_event->auc_event_data);
    pst_mgmt_tx = &(pst_hmac_vap->st_mgmt_tx);
    pst_mgmt_tx->mgmt_tx_complete = OAL_TRUE;
    pst_mgmt_tx->mgmt_tx_status   = pst_mgmt_tx_status_param->uc_dscr_status;
    pst_mgmt_tx->mgmt_frame_id    = pst_mgmt_tx_status_param->mgmt_frame_id;

     /* ??????????????????OAL_WAIT_QUEUE_WAKE_UP?????????? */
    OAL_SMP_MB();
    OAL_WAIT_QUEUE_WAKE_UP_INTERRUPT(&pst_mgmt_tx->st_wait_queue);

    return OAL_SUCC;
}

#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 44))
#if (_PRE_CONFIG_TARGET_PRODUCT != _PRE_TARGET_PRODUCT_TYPE_E5)


OAL_STATIC oal_int32 wal_cfg80211_start_p2p_device(oal_wiphy_stru       *pst_wiphy,
                                                oal_wireless_dev_stru   *pst_wdev)
{
    /* TBD */
    return -OAL_EFAIL;
}



OAL_STATIC void wal_cfg80211_stop_p2p_device(oal_wiphy_stru       *pst_wiphy,
                                                oal_wireless_dev_stru   *pst_wdev)
{
    /* TBD */
}


static oal_int32 wal_cfg80211_set_power_mgmt(oal_wiphy_stru  *pst_wiphy,
				oal_net_device_stru *pst_netdev,
				bool enabled, oal_int32 timeout)
{
#ifdef _PRE_WLAN_FEATURE_STA_PM
    wal_msg_write_stru           st_write_msg;
    mac_cfg_ps_open_stru        *pst_sta_pm_open;
    oal_int32                    l_ret = 0;
    mac_vap_stru                *pst_mac_vap;

    if (OAL_UNLIKELY((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_netdev)))
    {
        OAM_ERROR_LOG2(0, OAM_SF_ANY, "{wal_cfg80211_set_power_mgmt::pst_wiphy or pst_wdev null ptr error %d, %d!}\r\n",
                       pst_wiphy, pst_netdev);
        return -OAL_EINVAL;
    }

    /* host????????????,????????device???????? */
    if(!g_wlan_pm_switch)
    {
        return OAL_SUCC;
    }

    WAL_WRITE_MSG_HDR_INIT(&st_write_msg, WLAN_CFGID_SET_STA_PM_ON, OAL_SIZEOF(mac_cfg_ps_open_stru));

#if 1
    pst_mac_vap    = OAL_NET_DEV_PRIV(pst_netdev);
    if (OAL_UNLIKELY(NULL == pst_mac_vap))
    {
        OAM_WARNING_LOG0(0, OAM_SF_PWR, "{wal_cfg80211_set_power_mgmt::get mac vap failed.}");
        return OAL_SUCC;
    }

    /* P2P dev?????? */
    if (IS_P2P_DEV(pst_mac_vap))
    {
        OAM_WARNING_LOG0(0, OAM_SF_PWR,"wal_cfg80211_set_power_mgmt:vap is p2p dev return");
        return OAL_SUCC;
    }

    OAM_WARNING_LOG3(0, OAM_SF_PWR, "{wal_cfg80211_set_power_mgmt::vap mode[%d]p2p mode[%d]set pm:[%d]}",pst_mac_vap->en_vap_mode,pst_mac_vap->en_p2p_mode,enabled);
#endif
    pst_sta_pm_open = (mac_cfg_ps_open_stru *)(st_write_msg.auc_value);
    /* MAC_STA_PM_SWITCH_ON / MAC_STA_PM_SWITCH_OFF */
    pst_sta_pm_open->uc_pm_enable      = enabled;
    pst_sta_pm_open->uc_pm_ctrl_type   = MAC_STA_PM_CTRL_TYPE_HOST;

    l_ret = wal_send_cfg_event(pst_netdev,
                           WAL_MSG_TYPE_WRITE,
                           WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg_ps_open_stru),
                           (oal_uint8 *)&st_write_msg,
                           OAL_FALSE,
                           OAL_PTR_NULL);


    if (OAL_SUCC != l_ret)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_set_power_mgmt::fail to send pm cfg msg, error[%d]}", l_ret);
        return -OAL_EFAIL;
    }
#endif
    return OAL_SUCC;

}
#ifdef _PRE_WLAN_FEATURE_11R


OAL_STATIC oal_int32 wal_cfg80211_update_ft_ies(oal_wiphy_stru                  *pst_wiphy,
                                                         oal_net_device_stru             *pst_netdev,
                                                         oal_cfg80211_update_ft_ies_stru *pst_fties)
{
    wal_msg_write_stru                  st_write_msg;
    mac_cfg80211_ft_ies_stru           *pst_mac_ft_ies;
    wal_msg_stru                       *pst_rsp_msg;
    oal_int32                           l_ret;

    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_netdev) || (OAL_PTR_NULL == pst_fties))
    {
        OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_update_ft_ies::param is null.}\r\n");

        return -OAL_EINVAL;
    }

    if ((pst_fties->ie == OAL_PTR_NULL) || (pst_fties->ie_len == 0) || (MAC_MAX_FTE_LEN <= pst_fties->ie_len))
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_update_ft_ies::unexpect ie or len[%d].}\r\n", pst_fties->ie_len);

        return -OAL_EINVAL;
    }

    /***************************************************************************
        ????????wal??????
    ***************************************************************************/
    st_write_msg.en_wid = WLAN_CFGID_SET_FT_IES;
    st_write_msg.us_len = OAL_SIZEOF(mac_cfg80211_ft_ies_stru);

    pst_mac_ft_ies = (mac_cfg80211_ft_ies_stru *)st_write_msg.auc_value;
    pst_mac_ft_ies->us_mdid = pst_fties->md;
    pst_mac_ft_ies->us_len  = pst_fties->ie_len;
    oal_memcopy(pst_mac_ft_ies->auc_ie, pst_fties->ie, pst_fties->ie_len);

    l_ret = wal_send_cfg_event(pst_netdev,
                               WAL_MSG_TYPE_WRITE,
                               WAL_MSG_WRITE_MSG_HDR_LENGTH + OAL_SIZEOF(mac_cfg80211_ft_ies_stru),
                               (oal_uint8 *)&st_write_msg,
                               OAL_TRUE,
                               &pst_rsp_msg);

    wal_check_and_release_msg_resp(pst_rsp_msg);

    if (OAL_UNLIKELY(OAL_SUCC != l_ret))
    {
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_update_ft_ies::wal_send_cfg_event: return err code %d!}\r\n", l_ret);
        return -OAL_EFAIL;
    }

    return OAL_SUCC;


}
#endif //_PRE_WLAN_FEATURE_11R
#endif  /* _PRE_CONFIG_TARGET_PRODUCT != _PRE_TARGET_PRODUCT_TYPE_E5 */
#endif

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0))

oal_int32   wal_cfg80211_dump_survey(oal_wiphy_stru *pst_wiphy, oal_net_device_stru *pst_netdev,
                            oal_int32 l_idx, oal_survey_info_stru *pst_info)
{
#ifdef _PRE_WLAN_FEATURE_DFR
    if (g_st_dfr_info.bit_device_reset_process_flag)
    {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "{wal_cfg80211_dump_survey::dfr_process_status[%d]!}",
            g_st_dfr_info.bit_device_reset_process_flag);
        return -OAL_EFAIL;
    }
#endif //#ifdef _PRE_WLAN_FEATURE_DFR
    return hmac_cfg80211_dump_survey(pst_wiphy, pst_netdev, l_idx, pst_info);
}
#endif

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
OAL_STATIC oal_void wal_cfg80211_abort_scan(oal_wiphy_stru         *pst_wiphy,
                                            oal_wireless_dev_stru  *pst_wdev)
{
    oal_net_device_stru *pst_netdev;

    /* 1.1 ???????? */
    if ((OAL_PTR_NULL == pst_wiphy) || (OAL_PTR_NULL == pst_wdev))
    {
        OAM_ERROR_LOG2(0, OAM_SF_CFG, "{wal_cfg80211_abort_scan::wiphy or wdev is null, %p, %p!}\r\n",
                        pst_wiphy, pst_wdev);
        return;
    }

    pst_netdev = pst_wdev->netdev;
    if (OAL_PTR_NULL == pst_netdev)
    {
        OAM_ERROR_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_abort_scan::netdev is null!}\r\n");
        return;
    }
    OAM_WARNING_LOG0(0, OAM_SF_CFG, "{wal_cfg80211_abort_scan::enter!}\r\n");
    wal_force_scan_complete(pst_netdev, OAL_TRUE);
    return;
}
#endif

/* ??????????????????????????????????*/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
OAL_STATIC oal_cfg80211_ops_stru  g_wal_cfg80211_ops =
{
    .scan                     = wal_cfg80211_scan,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
    .connect                  = wal_cfg80211_connect,
    .disconnect               = wal_cfg80211_disconnect,
#endif
    .add_key                  = wal_cfg80211_add_key,
    .get_key                  = wal_cfg80211_get_key,
    .del_key                  = wal_cfg80211_remove_key,
    .set_default_key          = wal_cfg80211_set_default_key,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44)//TBD:?????????? Linux ??????
    .set_default_mgmt_key     = wal_cfg80211_set_default_mgmt_key,
#else
    .set_default_mgmt_key     = wal_cfg80211_set_default_key,
#endif
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,34))
    .set_channel              = wal_cfg80211_set_channel,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
    .set_wiphy_params         = wal_cfg80211_set_wiphy_params,
#endif
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,34))
    .add_beacon               = wal_cfg80211_add_beacon,
    .set_beacon               = wal_cfg80211_set_beacon,
#else/* Hi1102 ????AP ???????? */
    .change_beacon            = wal_cfg80211_change_beacon,
    .start_ap                 = wal_cfg80211_start_ap,
    .stop_ap                  = wal_cfg80211_stop_ap,
    .change_bss               = wal_cfg80211_change_bss,
    .sched_scan_start         = wal_cfg80211_sched_scan_start,
    .sched_scan_stop          = wal_cfg80211_sched_scan_stop,
#endif
    .change_virtual_intf      = wal_cfg80211_change_virtual_intf,
    .add_station              = wal_cfg80211_add_station,
    .del_station              = wal_cfg80211_del_station,
    .change_station           = wal_cfg80211_change_station,
    .get_station              = wal_cfg80211_get_station,
    .dump_station             = wal_cfg80211_dump_station,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
    .dump_survey              = wal_cfg80211_dump_survey,
#endif
#if (_PRE_CONFIG_TARGET_PRODUCT != _PRE_TARGET_PRODUCT_TYPE_E5)  //E5??hostapd??????????????
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 44))//TBD:?????????? Linux ??????
    .set_pmksa                = wal_cfg80211_set_pmksa,
    .del_pmksa                = wal_cfg80211_del_pmksa,
    .flush_pmksa              = wal_cfg80211_flush_pmksa,
    .remain_on_channel        = wal_cfg80211_remain_on_channel,
    .cancel_remain_on_channel = wal_cfg80211_cancel_remain_on_channel,
    .mgmt_tx                  = wal_cfg80211_mgmt_tx,
    .mgmt_frame_register      = wal_cfg80211_mgmt_frame_register,
    .set_bitrate_mask         = wal_cfg80211_set_bitrate_mask,
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 44))//TBD:1102 ??????????????????????????
    .add_virtual_intf         = wal_cfg80211_add_virtual_intf,
    .del_virtual_intf         = wal_cfg80211_del_virtual_intf,
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44))
    .mgmt_tx_cancel_wait      = wal_cfg80211_mgmt_tx_cancel_wait,
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44))
    .start_p2p_device         = wal_cfg80211_start_p2p_device,
    .stop_p2p_device          = wal_cfg80211_stop_p2p_device,
    .set_power_mgmt           = wal_cfg80211_set_power_mgmt,
#ifdef _PRE_WLAN_FEATURE_11R
    .update_ft_ies            = wal_cfg80211_update_ft_ies,
#endif //_PRE_WLAN_FEATURE_11R
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
    .abort_scan               = wal_cfg80211_abort_scan,
#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)) */
#endif /* _PRE_CONFIG_TARGET_PRODUCT != _PRE_TARGET_PRODUCT_TYPE_E5 */
};
#elif (_PRE_OS_VERSION_WIN32 == _PRE_OS_VERSION)
OAL_STATIC oal_cfg80211_ops_stru  g_wal_cfg80211_ops =
{
    wal_cfg80211_add_key,
    wal_cfg80211_get_key,
    wal_cfg80211_remove_key,
    wal_cfg80211_set_default_key,
    wal_cfg80211_set_default_key,
    wal_cfg80211_scan,
    wal_cfg80211_connect,
    wal_cfg80211_disconnect,
    wal_cfg80211_set_channel,
    wal_cfg80211_set_wiphy_params,
    wal_cfg80211_add_beacon,
    wal_cfg80211_change_virtual_intf,
    wal_cfg80211_add_station,
    wal_cfg80211_del_station,
    wal_cfg80211_change_station,
    wal_cfg80211_get_station,
    wal_cfg80211_dump_station,
    wal_cfg80211_change_beacon,
    wal_cfg80211_start_ap,
    wal_cfg80211_stop_ap,
    wal_cfg80211_change_bss,
};

#endif


oal_void wal_cfg80211_reset_bands(oal_void)
{
    int i;

    /* ??????????????,flags??????????,????????????????????????,??????????????????????????????,????????????????????flag???? */
    for(i = 0; i < hi1151_band_2ghz.n_channels; i++)
    {
        hi1151_band_2ghz.channels[i].flags = 0;
    }

    if(band_5g_enabled)
    {
        for(i = 0; i < hi1151_band_5ghz.n_channels; i++)
        {
            hi1151_band_5ghz.channels[i].flags = 0;
        }
    }
}


oal_void wal_cfg80211_save_bands(oal_void)
{
    int i;

    /* ??????????????,flags??????????,????????????????????????,
       ??????????????????????????????,????????????????????flag??????
       ??????????????flag ??????????????????orig_flags??
     */
    for(i = 0; i < hi1151_band_2ghz.n_channels; i++)
    {
        hi1151_band_2ghz.channels[i].orig_flags = hi1151_band_2ghz.channels[i].flags;
    }

    if(band_5g_enabled)
    {
        for(i = 0; i < hi1151_band_5ghz.n_channels; i++)
        {
            hi1151_band_5ghz.channels[i].orig_flags = hi1151_band_5ghz.channels[i].flags;
        }
    }
}



oal_uint32  wal_cfg80211_init(oal_void)
{
    oal_uint32           ul_chip;
    oal_uint8            uc_device;
    oal_int32            l_return;
    oal_uint8            uc_dev_id;
    mac_device_stru     *pst_device;
    oal_uint32           ul_chip_max_num;
    mac_board_stru      *pst_hmac_board;
    oal_wiphy_stru      *pst_wiphy;
    mac_wiphy_priv_stru *pst_wiphy_priv;

    hmac_board_get_instance(&pst_hmac_board);

    ul_chip_max_num = oal_bus_get_chip_num();

    for (ul_chip = 0; ul_chip < ul_chip_max_num; ul_chip++)
    {
        for (uc_device = 0; uc_device < pst_hmac_board->ast_chip[ul_chip].uc_device_nums; uc_device++)
        {
            /* ????device_id */
            uc_dev_id = pst_hmac_board->ast_chip[ul_chip].auc_device_id[uc_device];

            pst_device = mac_res_get_dev(uc_dev_id);

            if (OAL_UNLIKELY(OAL_PTR_NULL == pst_device))
            {
                OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_init::mac_res_get_dev,pst_dev null!}\r\n");
                return OAL_FAIL;
            }

            pst_device->pst_wiphy = oal_wiphy_new(&g_wal_cfg80211_ops, OAL_SIZEOF(mac_wiphy_priv_stru));

            if (OAL_PTR_NULL == pst_device->pst_wiphy)
            {
                OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_init::oal_wiphy_new failed!}\r\n");
                return OAL_FAIL;
            }

            /* ??????wiphy ?????????? */
            pst_wiphy = pst_device->pst_wiphy;

#ifdef _PRE_WLAN_FEATURE_P2P
            pst_wiphy->interface_modes  = BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP)
                                            |BIT(NL80211_IFTYPE_P2P_CLIENT)
                                            |BIT(NL80211_IFTYPE_P2P_GO)
                                            |BIT(NL80211_IFTYPE_P2P_DEVICE);
#else
            pst_wiphy->interface_modes  = BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP);
#endif

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44))
#ifdef _PRE_WLAN_FEATURE_P2P
            pst_wiphy->iface_combinations   = sta_p2p_iface_combinations;
            pst_wiphy->n_iface_combinations = OAL_ARRAY_SIZE(sta_p2p_iface_combinations);
            pst_wiphy->mgmt_stypes          = wal_cfg80211_default_mgmt_stypes;
            pst_wiphy->max_remain_on_channel_duration = 5000;
            /* ???????????? */
            pst_wiphy->flags |= WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL;
            pst_wiphy->flags |= WIPHY_FLAG_HAVE_AP_SME; /* ????GO ?????? */

#if defined(_PRE_PRODUCT_ID_HI110X_HOST)
            /* 1102????????pno???????????????????? */
            pst_wiphy->max_sched_scan_ssids  = MAX_PNO_SSID_COUNT;
            pst_wiphy->max_match_sets        = MAX_PNO_SSID_COUNT;
            pst_wiphy->max_sched_scan_ie_len = WAL_MAX_SCAN_IE_LEN;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0))
            pst_wiphy->max_sched_scan_reqs  = 1;
#else
            pst_wiphy->flags |= WIPHY_FLAG_SUPPORTS_SCHED_SCAN;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44) */
#endif   /* _PRE_PRODUCT_ID == _PRE_PRODUCT_ID_HI1102_HOST */

#else    /* ??p2p??????????vap */
            pst_wiphy->iface_combinations   = ap_dbac_iface_combinations;
            pst_wiphy->n_iface_combinations = OAL_ARRAY_SIZE(ap_dbac_iface_combinations);
#endif
#endif   /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,44) */
#endif   /* _PRE_OS_VERSION_LINUX == _PRE_OS_VERSION */

            pst_wiphy->max_scan_ssids             = WLAN_SCAN_REQ_MAX_SSID;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34))
            pst_wiphy->max_scan_ie_len            = WAL_MAX_SCAN_IE_LEN;
            pst_wiphy->cipher_suites              = hi1151_cipher_suites;
            pst_wiphy->n_cipher_suites            = sizeof(hi1151_cipher_suites)/sizeof(oal_uint32);

            /* ?????????? */
            pst_wiphy->flags &= ~WIPHY_FLAG_PS_ON_BY_DEFAULT;

#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)) */

#if defined (_PRE_WLAN_FEATURE_ROAM) && (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0))
    /* wifi ????????????FW_ROAM,??????(cfg80211_connect)??????bssid_hint ????bssid??*/
    pst_wiphy->flags |= WIPHY_FLAG_SUPPORTS_FW_ROAM;
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
            /* linux 3.14 ???????????????????????? */
            pst_wiphy->regulatory_flags |= REGULATORY_CUSTOM_REG;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34))
            /* ?????????? */
            pst_wiphy->flags |= WIPHY_FLAG_CUSTOM_REGULATORY;
#else
             /* linux-2.6.30  ?????????? */
            pst_wiphy->custom_regulatory |= WIPHY_FLAG_CUSTOM_REGULATORY;
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0))
            pst_wiphy->bands[NL80211_BAND_2GHZ] = &hi1151_band_2ghz;        /* ?????????????? 2.4G */
            if(band_5g_enabled)
            {
                pst_wiphy->bands[NL80211_BAND_5GHZ] = &hi1151_band_5ghz;        /* ?????????????? 5G */
            }
#else
            pst_wiphy->bands[IEEE80211_BAND_2GHZ] = &hi1151_band_2ghz;        /* ?????????????? 2.4G */
            if(band_5g_enabled)
            {
                pst_wiphy->bands[IEEE80211_BAND_5GHZ] = &hi1151_band_5ghz;        /* ?????????????? 5G */
            }
#endif
            pst_wiphy->signal_type                = CFG80211_SIGNAL_TYPE_MBM;

            oal_wiphy_apply_custom_regulatory(pst_wiphy, &g_st_default_regdom);

#if (defined(_PRE_PRODUCT_ID_HI110X_HOST) || (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
            wal_cfgvendor_init(pst_wiphy);
#endif

            OAL_IO_PRINT("wiphy_register start.\n");
            l_return = oal_wiphy_register(pst_wiphy);
            if(l_return != 0)
            {
                oal_wiphy_free(pst_device->pst_wiphy);
                OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_init::oal_wiphy_register failed!}\r\n");
                return (oal_uint32)l_return;
            }

            /* P2P add_virtual_intf ????wiphy ????????wiphy priv ????????wifi ????mac_devie_stru ???????? */
            pst_wiphy_priv  = (mac_wiphy_priv_stru *)(oal_wiphy_priv(pst_wiphy));
            pst_wiphy_priv->pst_mac_device = pst_device;

#if defined(_PRE_PRODUCT_ID_HI110X_HOST)
            OAL_IO_PRINT("wal_init_wlan_netdev wlan0.\n");
            l_return = wal_init_wlan_netdev(pst_wiphy, "wlan0");
            if(OAL_SUCC != l_return)
            {
                OAL_IO_PRINT("wal_init_wlan_netdev wlan0 failed.l_return:%d\n", l_return);
                return (oal_uint32)l_return;
            }

            OAL_IO_PRINT("wal_init_wlan_netdev p2p0.\n");
            l_return = wal_init_wlan_netdev(pst_wiphy, "p2p0");
            if(OAL_SUCC != l_return)
            {
                OAL_IO_PRINT("wal_init_wlan_netdev p2p0 failed.l_return:%d\n", l_return);

                /* ????wlan0???????????? */
                OAL_MEM_FREE(OAL_NETDEVICE_WDEV(pst_device->st_p2p_info.pst_primary_net_device), OAL_TRUE);
                oal_net_unregister_netdev(pst_device->st_p2p_info.pst_primary_net_device);
                return (oal_uint32)l_return;
            }
#endif
        }
    }

    return OAL_SUCC;
}


oal_void  wal_cfg80211_exit(oal_void)
{
    oal_uint32          ul_chip;
    oal_uint8           uc_device;
    oal_uint8           uc_dev_id;
    mac_device_stru    *pst_device;
    oal_uint32          ul_chip_max_num;
    mac_board_stru     *pst_hmac_board;

    hmac_board_get_instance(&pst_hmac_board);

    ul_chip_max_num = oal_bus_get_chip_num(); /* ?????????????? */

    for (ul_chip = 0; ul_chip < ul_chip_max_num; ul_chip++)
    {
        for (uc_device = 0; uc_device < pst_hmac_board->ast_chip[ul_chip].uc_device_nums; uc_device++)
        {
            /* ????device_id */
            uc_dev_id = pst_hmac_board->ast_chip[ul_chip].auc_device_id[uc_device];

            pst_device = mac_res_get_dev(uc_dev_id);

            if (OAL_PTR_NULL == pst_device)
            {
                OAM_ERROR_LOG0(0, OAM_SF_ANY, "{wal_cfg80211_init::mac_res_get_dev pst_device is null!}\r\n");
                return ;
            }
#if (defined(_PRE_PRODUCT_ID_HI110X_HOST) || (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
            wal_cfgvendor_deinit(pst_device->pst_wiphy);
#endif

            /* ???????? wiphy device*/
            oal_wiphy_unregister(pst_device->pst_wiphy);

            /* ????wiphy device */
            oal_wiphy_free(pst_device->pst_wiphy);
        }
    }

    return;
}


oal_uint32  wal_cfg80211_init_evt_handle(frw_event_mem_stru *pst_event_mem)
{

    wal_cfg80211_init();
    return OAL_SUCC;
}

#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

