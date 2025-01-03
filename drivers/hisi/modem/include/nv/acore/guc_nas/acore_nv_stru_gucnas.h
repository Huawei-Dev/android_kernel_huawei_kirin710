/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2012-2015. All rights reserved.
 * foss@huawei.com
 *
 * If distributed as part of the Linux kernel, the following license terms
 * apply:
 *
 * * This program is free software; you can redistribute it and/or modify
 * * it under the terms of the GNU General Public License version 2 and
 * * only version 2 as published by the Free Software Foundation.
 * *
 * * This program is distributed in the hope that it will be useful,
 * * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * * GNU General Public License for more details.
 * *
 * * You should have received a copy of the GNU General Public License
 * * along with this program; if not, write to the Free Software
 * * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 * Otherwise, the following license terms apply:
 *
 * * Redistribution and use in source and binary forms, with or without
 * * modification, are permitted provided that the following conditions
 * * are met:
 * * 1) Redistributions of source code must retain the above copyright
 * *    notice, this list of conditions and the following disclaimer.
 * * 2) Redistributions in binary form must reproduce the above copyright
 * *    notice, this list of conditions and the following disclaimer in the
 * *    documentation and/or other materials provided with the distribution.
 * * 3) Neither the name of Huawei nor the names of its contributors may
 * *    be used to endorse or promote products derived from this software
 * *    without specific prior written permission.
 *
 * * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef __ACORE_NV_STRU_GUCNAS_H__
#define __ACORE_NV_STRU_GUCNAS_H__

#include "vos.h"
#include "acore_nv_id_gucnas.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/****************************************************************************
  1 ??????????????
*****************************************************************************/
#pragma pack(push, 4)

/*****************************************************************************
  2 ??????
*****************************************************************************/
#define AT_MDATE_STRING_LENGTH                                  (20)
#define TAF_AT_NVIM_CLIENT_CFG_LEN                              (128)
#define AT_DISSD_PWD_LEN                                        (16)
#define AT_OPWORD_PWD_LEN                                       (16)
#define AT_FACINFO_INFO1_LENGTH                                 (128)
#define AT_FACINFO_INFO2_LENGTH                                 (128)
#define AT_FACINFO_STRING_LENGTH                                ((AT_FACINFO_INFO1_LENGTH + 1) + (AT_FACINFO_INFO2_LENGTH + 1))
#define AT_FACINFO_INFO1_STR_LENGTH                             (AT_FACINFO_INFO1_LENGTH + 1)
#define AT_FACINFO_INFO2_STR_LENGTH                             (AT_FACINFO_INFO2_LENGTH + 1)
#define AT_NVIM_SETZ_LEN                                        (16)
#define AT_NOTSUPPORT_STR_LEN                                   (16)
#define AT_NVIM_RIGHT_PWD_LEN                                   (16)
#define ADS_UL_QUEUE_SCHEDULER_PRI_MAX                          (9)             /* ???????????????? */
#define AT_WIFI_SSID_LEN_MAX                                    (33)            /* WIFI SSID KEY???????? */
#define AT_WIFI_KEY_LEN_MAX                                     (27)
#define AT_WIFI_WLAUTHMODE_LEN                                  (16)            /* ?????????????????? */
#define AT_WIFI_ENCRYPTIONMODES_LEN                             (5)             /* ?????????????????? */
#define AT_WIFI_WLWPAPSK_LEN                                    (65)            /* WPA???????????????? */
#define AT_WIFI_MAX_SSID_NUM                                    (4)             /* ????????4??SSID */
#define AT_WIFI_KEY_NUM                                         (AT_WIFI_MAX_SSID_NUM)
#define AT_MAX_ABORT_CMD_STR_LEN                                (16)
#define AT_MAX_ABORT_RSP_STR_LEN                                (16)
#define AT_PRODUCT_NAME_MAX_NUM                                 (29)
#define AT_PRODUCT_NAME_LENGHT                                  (AT_PRODUCT_NAME_MAX_NUM + 1)
#define AT_WEBUI_PWD_MAX                                        (16)            /*WEB UI ????????????*/
#define AT_AP_XML_RPT_SRV_URL_LEN                               (127)
#define AT_AP_XML_RPT_SRV_URL_STR_LEN                           (AT_AP_XML_RPT_SRV_URL_LEN + 1)
#define AT_AP_NVIM_XML_RPT_INFO_TYPE_LEN                        (127)
#define AT_AP_NVIM_XML_RPT_INFO_TYPE_STR_LEN                    (AT_AP_NVIM_XML_RPT_INFO_TYPE_LEN + 1)


/*****************************************************************************
  3 ????????
*****************************************************************************/
enum AT_UART_LINK_TYPE_ENUM
{
    AT_UART_LINK_TYPE_OM        = 1,          /* OM???? */
    AT_UART_LINK_TYPE_AT        = 2,          /* AT???? */
    AT_UART_LINK_TYPE_BUTT
};
typedef VOS_UINT16 AT_UART_LINK_TYPE_ENUM_UINT16;


enum NAPI_WEIGHT_ADJ_MODE_ENUM
{
    NAPI_WEIGHT_ADJ_STATIC_MODE           = 0x00,
    NAPI_WEIGHT_ADJ_DYNAMIC_MODE          = 0x01,

    NAPI_WEIGHT_ADJ_MODE_BUTT
};
typedef VOS_UINT8 NAPI_WEIGHT_ADJ_MODE_ENUM_UINT8;

/*****************************************************************************
  4 STRUCT????
*****************************************************************************/
/*****************************************************************************
 ????????  : USB_ENUM_STATUS_STRU
 ????????  : en_NV_Item_USB_Enum_Status(21)????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          status;
    VOS_UINT32                          value;
    VOS_UINT32                          reserve1;
    VOS_UINT32                          reserve2;
}USB_ENUM_STATUS_STRU;


typedef struct
{
    VOS_UINT32                          ulCommDebugFlag;
}TAF_AT_NVIM_COMMDEGBUG_CFG_STRU;

/*****************************************************************************
 ??????    : nv_pid_enable_type
 ????????  : en_NV_Item_PID_Enable_Type(31)????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulPidEnabled;
}nv_pid_enable_type;


typedef struct
{
    VOS_UINT32                          ulNvSwVerFlag;                          /*[0,1]*/
}OM_SW_VER_FLAG_STRU;


typedef struct
{
    VOS_INT8                           acATE5DissdPwd[AT_DISSD_PWD_LEN];
}TAF_AT_NVIM_DISSD_PWD_STRU;


typedef struct
{
    VOS_INT8                           acATOpwordPwd[AT_OPWORD_PWD_LEN];
}TAF_AT_NVIM_DISLOG_PWD_NEW_STRU;


typedef struct
{
    AT_UART_LINK_TYPE_ENUM_UINT16       enUartLinkType;
    VOS_UINT8                           ucReserve1;
    VOS_UINT8                           ucReserve2;
}TAF_AT_NVIM_DEFAULT_LINK_OF_UART_STRU;

/*****************************************************************************
 ??????    : VBAT_CALIBART_TYPE
 ????????  : en_NV_Item_BATTERY_ADC(90)???? ????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          min_value;
    VOS_UINT16                          max_value;
}VBAT_CALIBART_TYPE;


typedef struct
{
    VOS_UINT8                           aucFactInfo1[AT_FACINFO_INFO1_STR_LENGTH];
    VOS_UINT8                           aucFactInfo2[AT_FACINFO_INFO2_STR_LENGTH];
    VOS_UINT8                           ucReserve1;
    VOS_UINT8                           ucReserve2;
}TAF_AT_NVIM_FACTORY_INFO_STRU;


typedef struct
{
    VOS_UINT8                           aucMDate[AT_MDATE_STRING_LENGTH];
}TAF_AT_NVIM_MANUFACTURE_DATE_STRU;


typedef struct
{
    VOS_UINT32                          ulSmsRiOnInterval;      /* ????RI??????????????(ms) */
    VOS_UINT32                          ulSmsRiOffInterval;     /* ????RI??????????????(ms) */
    VOS_UINT32                          ulVoiceRiOnInterval;    /* ????RI??????????????(ms) */
    VOS_UINT32                          ulVoiceRiOffInterval;   /* ????RI??????????????(ms) */
    VOS_UINT8                           ucVoiceRiCycleTimes;    /* ????RI????????????     */
    VOS_UINT8                           aucReserved[3];
} TAF_NV_UART_RI_STRU;


typedef struct
{
    VOS_UINT8                           ucFormat;               /* UART ???????????????? */
    VOS_UINT8                           ucParity;               /* UART???????? */
    VOS_UINT8                           aucReserved[2];

} TAF_NV_UART_FRAME_STRU;


typedef struct
{
    VOS_UINT32                          ulBaudRate;             /* UART?????? */
    TAF_NV_UART_FRAME_STRU              stFrame;                /* UART?????? */
    TAF_NV_UART_RI_STRU                 stRiConfig;             /* UART Ring?????? */
} TAF_NV_UART_CFG_STRU;


typedef struct
{
    VOS_UINT8                           ucEnableFlg;
    VOS_UINT8                           aucReserved[3];
} TAF_NV_PORT_BUFF_CFG_STRU;


typedef struct
{
    VOS_UINT8                           ucEnableFlg;                            /* CDMAMODEMSWITCH??????????NV????, 1: ??????0?????? */
    VOS_UINT8                           aucReversed[7];                         /* ?????????? */
} TAF_NVIM_CDMAMODEMSWITCH_NOT_RESET_CFG_STRU;


typedef struct
{
    VOS_UINT32                          ulIpv6AddrTestModeCfg;                  /* 0x55aa55aa???????????????????????????? */
}TAF_NVIM_IPV6_ADDR_TEST_MODE_CFG_STRU;


typedef struct
{
    VOS_UINT8                           ucIpfMode;                              /* IPF????ADS??????????????, 0: ??????????(????)??1???????????? */
    VOS_UINT8                           ucReserved0;
    VOS_UINT8                           ucReserved1;
    VOS_UINT8                           ucReserved2;
} TAF_NV_ADS_IPF_MODE_CFG_STRU;


typedef struct
{
    VOS_UINT8                           aucInfo[128];
}OM_MANUFACTUREINFO_STRU;


typedef struct
{
    VOS_UINT32                          ulEnable;                               /* ???????? */
    VOS_UINT32                          ulTxWakeTimeout;                        /* ???????????????????? */
    VOS_UINT32                          ulRxWakeTimeout;                        /* ???????????????????? */
    VOS_UINT32                          ulReserved;
} TAF_NV_ADS_WAKE_LOCK_CFG_STRU;


typedef struct
{
    VOS_UINT8                           ucPrintModemLogType;                    /* 0:????modem log??1:??????modem log??default:0 */
    VOS_UINT8                           ucReserved0;
    VOS_UINT8                           ucReserved1;
    VOS_UINT8                           ucReserved2;
} TAF_NV_PRINT_MODEM_LOG_TYPE_STRU;


typedef struct
{
    VOS_UINT16                          usBlkNum;
    VOS_UINT16                          usReserved0;
    VOS_UINT16                          usReserved1;
    VOS_UINT16                          usReserved2;

} TAF_NV_ADS_MEM_CFG_STRU;


typedef struct
{
    VOS_UINT32                          ulEnable;
    TAF_NV_ADS_MEM_CFG_STRU             astMemCfg[2];
} TAF_NV_ADS_MEM_POOL_CFG_STRU;


typedef struct
{
    VOS_UINT32                          ulEnabled;                              /* ???????? */
    VOS_UINT32                          ulErrorRateThreshold;                   /* ????????????????(??????) */
    VOS_UINT32                          ulDetectDuration;                       /* ????????(????) */
    VOS_UINT32                          ulReserved;                             /* ???? */

} TAF_NV_ADS_ERROR_FEEDBACK_CFG_STRU;


typedef struct
{
    VOS_UINT8                           ucUserRebootConfig;
    VOS_UINT8                           ucReserved1;
    VOS_UINT8                           ucReserved2;
    VOS_UINT8                           ucReserved3;
}TAF_NVIM_USER_REBOOT_SUPPORT_STRU;


typedef struct
{
    VOS_UINT8                           ucEnable;                               /* ????????????????????????, 1: ??????0?????? */
    VOS_UINT8                           aucReversed[3];                         /* ?????????? */
} TAF_NV_PDP_REDIAL_FOR_NO_CAUSE_CFG_STRU;


typedef struct
{
    VOS_UINT32                          ulDlPktNumPerSecLevel1;                 /* ??????????????Level1 */
    VOS_UINT32                          ulDlPktNumPerSecLevel2;                 /* ??????????????Level2 */
    VOS_UINT32                          ulDlPktNumPerSecLevel3;                 /* ??????????????Level3 */
    VOS_UINT32                          ulDlPktNumPerSecLevel4;                 /* ??????????????Level4 */
    VOS_UINT32                          ulReserved0;                            /* ?????? */
    VOS_UINT32                          ulReserved1;                            /* ?????? */
    VOS_UINT32                          ulReserved2;                            /* ?????? */
    VOS_UINT32                          ulReserved3;                            /* ?????? */

} RNIC_NAPI_DL_PKT_NUM_PER_SEC_LEVEL_STRU;


typedef struct
{
    VOS_UINT8                           ucNapiWeightLevel1;                     /* NAPI Weight??????Level1 */
    VOS_UINT8                           ucNapiWeightLevel2;                     /* NAPI Weight??????Level2 */
    VOS_UINT8                           ucNapiWeightLevel3;                     /* NAPI Weight??????Level3 */
    VOS_UINT8                           ucNapiWeightLevel4;                     /* NAPI Weight??????Level4 */
    VOS_UINT8                           ucReserved0;                            /* ?????? */
    VOS_UINT8                           ucReserved1;                            /* ?????? */
    VOS_UINT8                           ucReserved2;                            /* ?????? */
    VOS_UINT8                           ucReserved3;                            /* ?????? */

} RNIC_NAPI_WEIGHT_LEVEL_STRU;


typedef struct
{
    RNIC_NAPI_DL_PKT_NUM_PER_SEC_LEVEL_STRU   stDlPktNumPerSecLevel;            /* RNIC?????????????????????????? */
    RNIC_NAPI_WEIGHT_LEVEL_STRU               stNapiWeightLevel;                /* NAPI Weight?????? */

} RNIC_NAPI_WEIGHT_DYNAMIC_ADJ_CFG_STRU;


typedef struct
{
    VOS_UINT8                                     ucNapiEnable;                 /* NAPI???? */
    NAPI_WEIGHT_ADJ_MODE_ENUM_UINT8               enNapiWeightAdjMode;          /* NAPI Weight????????, 0: ??????????1?????????????? */
    VOS_UINT8                                     ucNapiPollWeight;             /* RNIC????NAPI????????poll???????????? */
    VOS_UINT8                                     ucGroEnable;                  /* GRO???? */
    VOS_UINT16                                    usNapiPollQueMaxLen;          /* Napi poll???????????????? */
    VOS_UINT8                                     ucReserved1;                  /* ?????? */
    VOS_UINT8                                     ucReserved2;                  /* ?????? */
    RNIC_NAPI_WEIGHT_DYNAMIC_ADJ_CFG_STRU         stNapiWeightDynamicAdjCfg;    /* Napi Weight???????????? */

} TAF_NV_RNIC_NAPI_CFG_STRU;


typedef struct
{
    VOS_UINT8                          aucAtClientConfig[TAF_AT_NVIM_CLIENT_CFG_LEN];     /*??????nv??????32??????*/
}TAF_AT_NVIM_AT_CLIENT_CFG_STRU;


typedef struct
{
    VOS_UINT8                           ucEnablePolicy;                         /* ????????28????????????????????, 1: ??????0?????? */
    VOS_UINT8                           ucReserved1;
    VOS_UINT8                           ucReserved2;
    VOS_UINT8                           ucReserved3;
} TAF_NV_PDP_REDIAL_FOR_NO_PDP_TYPE_CAUSE_CFG_STRU;


typedef struct
{
    VOS_UINT8                           aucGmmInfo[2];
    VOS_UINT8                           ucReserve1;
    VOS_UINT8                           ucReserve2;
}TAF_AT_NV_GMM_INFO_STRU;



typedef struct
{
    VOS_UINT8                           ucVaild;
    VOS_UINT8                           ucReserved1;
    VOS_UINT8                           ucReserved2;
    VOS_UINT8                           ucReserved3;
}TAF_AT_NVIM_RXDIV_CONFIG_STRU;


typedef struct
{
    VOS_UINT16                          usReportRegActFlg;
    VOS_UINT8                           ucReserve1;
    VOS_UINT8                           ucReserve2;
}TAF_AT_NVIM_REPORT_REG_ACT_FLG_STRU;

/*****************************************************************************
??????    : NDIS_NV_DHCP_LEASE_HOUR_STRU
????????  : en_NV_Item_NDIS_DHCP_DEF_LEASE_TIME 8344 ????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulDhcpLeaseHour;                        /* Range:[0x1,0x2250] */
}NDIS_NV_DHCP_LEASE_HOUR_STRU;


typedef struct
{
    VOS_UINT8                           ucStatus;                               /* 1: NV????????????0?????? */
    VOS_UINT8                           ucCiBytesRpt;                           /* <CI>??????????????????0??2????????, 1??4???????? */
    VOS_UINT8                           ucReserve1;
    VOS_UINT8                           ucReserve2;
}NAS_NV_CREG_CGREG_CI_FOUR_BYTE_RPT_STRU; /* VDF????: CREG/CGREG????<CI>????????4??????????NV???????????? */


typedef struct
{
    VOS_INT8                            acTz[AT_NVIM_SETZ_LEN];
}TAF_AT_TZ_STRU;


typedef struct
{
    VOS_INT8                            acErrorText[AT_NOTSUPPORT_STR_LEN];
}TAF_AT_NOT_SUPPORT_CMD_ERROR_TEXT_STRU;


typedef struct
{
    VOS_UINT32                          enRightOpenFlg;
    VOS_INT8                            acPassword[AT_NVIM_RIGHT_PWD_LEN];
}TAF_AT_NVIM_RIGHT_OPEN_FLAG_STRU;


typedef struct
{
    VOS_UINT32                          ulIpv6RouterMtu;
}TAF_NDIS_NV_IPV6_ROUTER_MTU_STRU;

/*****************************************************************************
 ????????   : AT_IPV6_CAPABILITY_STRU
 ????????   :
 ASN.1 ???? :
 ????????   : en_NV_Item_IPV6_CAPABILITY(8514)  IPV6????NV????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT8                           ucStatus;           /* NV????????, 1: ??????0?????? */
    VOS_UINT8                           ucIpv6Capablity;    /* IPV6???? */
    VOS_UINT8                           aucReversed[2];     /* ?????????? */
} AT_NV_IPV6_CAPABILITY_STRU;


typedef struct
{
    VOS_UINT8                           ucGsmConnectRate;
    VOS_UINT8                           ucGprsConnectRate;
    VOS_UINT8                           ucEdgeConnectRate;
    VOS_UINT8                           ucWcdmaConnectRate;
    VOS_UINT8                           ucDpaConnectRate;
    VOS_UINT8                           ucReserve1;
    VOS_UINT8                           ucReserve2;
    VOS_UINT8                           ucReserve3;
}AT_NVIM_DIAL_CONNECT_DISPLAY_RATE_STRU;


typedef struct
{
    VOS_UINT32                          ulStatus;                               /* ??NV???????? 0:?????????????????????????????????????? 1:???????????????????? */
    VOS_UINT16                          ausPriWeightedNum[ADS_UL_QUEUE_SCHEDULER_PRI_MAX];  /* ?????????????????????? */
    VOS_UINT8                           aucRsv[2];
}ADS_UL_QUEUE_SCHEDULER_PRI_NV_STRU;


typedef struct
{
    VOS_UINT32                          bitOpbSupport       : 1;
    VOS_UINT32                          bitOpgSupport       : 1;
    VOS_UINT32                          bitOpnSupport       : 1;
    VOS_UINT32                          bitOpSpare          : 29;
    VOS_UINT8                           usbHighChannel;                         /* 802.11b?????????????? */
    VOS_UINT8                           usbLowChannel;                          /* 802.11b?????????????? */
    VOS_UINT8                           aucRsv1[2];
    VOS_UINT16                          ausbPower[2];                           /* 802.11b?????????????? */
    VOS_UINT8                           usgHighChannel;                         /* 802.11g?????????????? */
    VOS_UINT8                           usgLowChannel;                          /* 802.11g?????????????? */
    VOS_UINT8                           aucRsv2[2];
    VOS_UINT16                          ausgPower[2];                           /* 802.11g?????????????? */
    VOS_UINT8                           usnHighChannel;                         /* 802.11n?????????????? */
    VOS_UINT8                           usnLowChannel;                          /* 802.11n?????????????? */
    VOS_UINT8                           aucRsv3[2];
    VOS_UINT16                          ausnPower[2];                           /* 802.11n?????????????? */
}AT_WIFI_INFO_STRU;

/*****************************************************************************
 ??????    : nv_wifi_info (9040 XML????????????????)
 ????????  : en_NV_Item_WIFI_INFO(9040)   nv_wifi_info????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulOpSupport;
    VOS_UINT8                           usbHighChannel;
    VOS_UINT8                           usbLowChannel;
    VOS_UINT8                           aucRsv1[2];
    VOS_UINT16                          ausbPower[2];
    VOS_UINT8                           usgHighsChannel;
    VOS_UINT8                           usgLowChannel;
    VOS_UINT8                           aucRsv2[2];
    VOS_UINT16                          ausgPower[2];
    VOS_UINT8                           usnHighsChannel;
    VOS_UINT8                           usnLowChannel;
    VOS_UINT8                           ausnRsv3[2];
    VOS_UINT16                          ausnPower[2];
}nv_wifi_info;


typedef struct
{
    VOS_UINT16                          usPlatform;
    VOS_UINT8                           ucReserve1;
    VOS_UINT8                           ucReserve2;
}NAS_NVIM_PLATFORM_STRU;


typedef struct
{
    VOS_UINT16                          usEqver;
    VOS_UINT8                           ucReserve1;
    VOS_UINT8                           ucReserve2;
}TAF_AT_EQ_VER_STRU;


typedef struct
{
    VOS_UINT16                          usCsver;
    VOS_UINT8                           ucReserve1;
    VOS_UINT8                           ucReserve2;
}TAF_NVIM_CS_VER_STRU;


typedef struct
{
    VOS_UINT8                           ucMuxSupportFlg;
    VOS_UINT8                           ucReserved1;
    VOS_UINT8                           ucReserved2;
    VOS_UINT8                           ucReserved3;
}TAF_AT_NVIM_MUX_SUPPORT_FLG_STRU;


typedef struct
{
    VOS_UINT8                           aucWifiAuthmode[AT_WIFI_WLAUTHMODE_LEN];
    VOS_UINT8                           aucWifiBasicencryptionmodes[AT_WIFI_ENCRYPTIONMODES_LEN];
    VOS_UINT8                           aucWifiWpaencryptionmodes[AT_WIFI_ENCRYPTIONMODES_LEN];
    VOS_UINT8                           aucWifiWepKey1[AT_WIFI_MAX_SSID_NUM][AT_WIFI_KEY_LEN_MAX];
    VOS_UINT8                           aucWifiWepKey2[AT_WIFI_MAX_SSID_NUM][AT_WIFI_KEY_LEN_MAX];
    VOS_UINT8                           aucWifiWepKey3[AT_WIFI_MAX_SSID_NUM][AT_WIFI_KEY_LEN_MAX];
    VOS_UINT8                           aucWifiWepKey4[AT_WIFI_MAX_SSID_NUM][AT_WIFI_KEY_LEN_MAX];
    VOS_UINT8                           ucWifiWepKeyIndex[AT_WIFI_MAX_SSID_NUM];
    VOS_UINT8                           aucWifiWpapsk[AT_WIFI_MAX_SSID_NUM][AT_WIFI_WLWPAPSK_LEN];
    VOS_UINT8                           ucWifiWpsenbl;
    VOS_UINT8                           ucWifiWpscfg;
}TAF_AT_MULTI_WIFI_SEC_STRU;


typedef struct
{
    VOS_UINT8                           aucWifiSsid[AT_WIFI_MAX_SSID_NUM][AT_WIFI_SSID_LEN_MAX];
    VOS_UINT8                           aucReserved[84];
}TAF_AT_MULTI_WIFI_SSID_STRU;


typedef struct
{
    VOS_UINT8                           ucAbortEnableFlg;                           /* AT???????????? */
    VOS_UINT8                           ucReserve1;
    VOS_UINT8                           ucReserve2;
    VOS_UINT8                           ucReserve3;
    VOS_UINT8                           aucAbortAtCmdStr[AT_MAX_ABORT_CMD_STR_LEN]; /* ????AT?????? */
    VOS_UINT8                           aucAbortAtRspStr[AT_MAX_ABORT_RSP_STR_LEN]; /* ?????????????????? */
}AT_NVIM_ABORT_CMD_PARA_STRU;


typedef struct
{
    VOS_UINT32                          ulMuxReportCfg;
}TAF_AT_NVIM_MUX_REPORT_CFG_STRU;


typedef struct
{
    VOS_UINT32                          ulCimiPortCfg;
}TAF_AT_NVIM_CIMI_PORT_CFG_STRU;


typedef struct
{
    VOS_UINT8                           ucStatus;                               /* NV????????????,  */
    VOS_UINT8                           ucSsCmdCustomize;
    VOS_UINT8                           aucReserved1[2];
} AT_SS_CUSTOMIZE_PARA_STRU;


typedef struct
{
    VOS_UINT8                           ucEnableFlag;                           /* ????????Share PDP????, 0 - ????;  1 - ???? */
    VOS_UINT8                           ucReserved;                             /* ???? */
    VOS_UINT16                          usAgingTimeLen;                         /* ?????????????????? */
} TAF_NVIM_SHARE_PDP_INFO_STRU;


typedef struct
{
    VOS_UINT32                          ulWaterLevel1;                          /* ????????1 */
    VOS_UINT32                          ulWaterLevel2;                          /* ????????2 */
    VOS_UINT32                          ulWaterLevel3;                          /* ????????3 */
    VOS_UINT32                          ulWaterLevel4;                          /* ????????4,???? */
} ADS_UL_WATER_MARK_LEVEL_STRU;


typedef struct
{
    VOS_UINT32                          ulThreshold1;                           /* ????????1 */
    VOS_UINT32                          ulThreshold2;                           /* ????????2 */
    VOS_UINT32                          ulThreshold3;                           /* ????????3 */
    VOS_UINT32                          ulThreshold4;                           /* ????????4 */
} ADS_UL_THRESHOLD_LEVEL_STRU;


typedef struct
{
    VOS_UINT32                          ulActiveFlag;                           /* ????????: 0??????????,1???????? */
    VOS_UINT32                          ulProtectTmrExpCnt;                     /* ?????????????????????? */
    ADS_UL_WATER_MARK_LEVEL_STRU        stWaterMarkLevel;
    ADS_UL_THRESHOLD_LEVEL_STRU         stThresholdLevel;
    VOS_UINT32                          aulReserved[6];
} ADS_NV_DYNAMIC_THRESHOLD_STRU;


typedef struct
{
    VOS_UINT32                          ulDebugLevel;                           /* VCOM DEBUG????:ERR,NORMAL,INFO,DEBUG */
    VOS_UINT32                          ulAppVcomPortIdMask;                    /* VCOM????ID???? */
    VOS_UINT32                          ulReserved[4];                          /* ???? */
} TAF_NV_PORT_DEBUG_CFG_STRU;


typedef struct
{
    VOS_UINT8                           aucMacAddr[32];
}OM_MAC_ADDR_STRU;


typedef struct
{
    VOS_UINT32                          ulNvStatus;
    VOS_UINT8                           aucProductId[AT_PRODUCT_NAME_LENGHT];   /* product id */
    VOS_UINT8                           ucReserve1;
    VOS_UINT8                           ucReserve2;
}TAF_AT_PRODUCT_ID_STRU;


typedef struct
{
    VOS_UINT8                           ucStatus;                               /* 1: NV????????????0?????? */
    VOS_UINT8                           ucErrCodeRpt;                           /*??????????????1: 0????????,  1??????*/
}NAS_NV_PPP_DIAL_ERR_CODE_STRU;  /* ????TIM??????????NV???????? */

/*****************************************************************************
 ??????    : AT_DYNAMIC_PID_TYPE_STRU
 ????????  : en_NV_Item_Huawei_Dynamic_PID_Type(50091)????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulNvStatus;
    VOS_UINT8                           aucFirstPortStyle[17];                  /* ?????????????????? */
    VOS_UINT8                           aucRewindPortStyle[17];                 /* ?????????????????? */
    VOS_UINT8                           aucReserved[22];                        /* ???? */
}AT_DYNAMIC_PID_TYPE_STRU;


typedef struct
{
    VOS_UINT8                           aucWebPwd[AT_WEBUI_PWD_MAX];
}TAF_AT_NVIM_WEB_ADMIN_PASSWORD_STRU;


typedef struct
{
    VOS_UINT8                           aucApRptSrvUrl[AT_AP_XML_RPT_SRV_URL_STR_LEN];
}TAF_AT_NVIM_AP_RPT_SRV_URL_STRU;


typedef struct
{
    VOS_UINT8                           aucApXmlInfoType[AT_AP_NVIM_XML_RPT_INFO_TYPE_STR_LEN];
}TAF_AT_NVIM_AP_XML_INFO_TYPE_STRU;


typedef struct
{
    VOS_UINT8                           ucApXmlRptFlg;
    VOS_UINT8                           ucReserve[3];
}TAF_AT_NVIM_AP_XML_RPT_FLG_STRU;


typedef struct
{
    VOS_UINT8                           ucUtranRelationLteFlg;      /* ??????^IMSSWITCH??????????<utran_enable>??????????????????????<lte_enable>???? */
    VOS_UINT8                           ucGsmRelationLteFlg;        /* ??????^IMSSWITCH??????????<gsm_enable>??????????????????????<lte_enable>???? */
    VOS_UINT8                           ucReserved1;
    VOS_UINT8                           ucReserved2;
}TAF_NV_IMS_SWITCH_RAT_RELATION_CFG_STRU;


#pragma pack(pop)

#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

#endif /* __ACORE_NV_STRU_GUCNAS_H__ */


