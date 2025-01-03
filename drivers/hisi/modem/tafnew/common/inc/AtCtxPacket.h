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

#ifndef __ATCTXPACKET_H__
#define __ATCTXPACKET_H__

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "VosPidDef.h"
#include "v_id.h"
#include "hi_list.h"
#include "AtTypeDef.h"
#include "MnClient.h"
#include "TafPsApi.h"
#include "acore_nv_stru_gucnas.h"
#include "nv_stru_gucnas.h"
#include "AtTimer.h"
#include "ImsaWifiInterface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


#pragma pack(4)

/*****************************************************************************
  2 ??????
*****************************************************************************/
#define AT_IPV6_CAPABILITY_IPV4_ONLY            (1)
#define AT_IPV6_CAPABILITY_IPV6_ONLY            (2)
#define AT_IPV6_CAPABILITY_IPV4V6_OVER_ONE_PDP  (4)
#define AT_IPV6_CAPABILITY_IPV4V6_OVER_TWO_PDP  (8)

/* PS?????????????? */
#define AT_PS_MAX_CALL_NUM              (3)


#define AT_PS_RABID_OFFSET              (5)                 /* RABID???? */
#define AT_PS_RABID_MAX_NUM             (11)                /* RABID???? */
#define AT_PS_MIN_RABID                 (5)                 /* RABID?????? */
#define AT_PS_MAX_RABID                 (15)                /* RABID?????? */
#define AT_PS_INVALID_RABID             (0xFF)              /* RABID?????? */
#define AT_PS_RABID_MODEM_1_MASK        (0x40)

#define IPV6_ADDRESS_TEST_MODE_ENABLE                    (0x55aa55aa)           /* 0x55aa55aa??IPV6?????????????? */

#define AT_PS_IPV6_IID_MGR_TBL_SIZE     (8)

#define AT_PS_PDP_TYPE_CHG_MAX_NUM      (7)
#define AT_PS_PDP_TYPE_CHG_MGR_TBL_SIZE (8)


/*****************************************************************************
  3 ????????
*****************************************************************************/
enum AT_PDP_STATE_ENUM
{
    AT_PDP_STATE_IDLE                = 0,
    AT_PDP_STATE_ACTED               = 1,
    AT_PDP_STATE_ACTING              = 2,
    AT_PDP_STATE_DEACTING            = 3,
    AT_PDP_STATE_BUTT
};
typedef VOS_UINT8 AT_PDP_STATE_ENUM_U8;

/* ID??????IMSA??MAPCON????ID???? */
typedef WIFI_IMSA_MSG_ID_ENUM_INT32 WLAN_AT_MSG_ID_ENUM_INT32;

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

/*****************************************************************************
 ????????   : AT_DIAL_PARAM_STRU
 ????????   :
 ASN.1 ???? :
 ????????   : ????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT8                           ucCid;
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType;
    VOS_UINT8                           ucPdpTypeValidFlag;

    VOS_UINT8                           ucAPNLen;
    VOS_UINT8                           aucAPN[TAF_MAX_APN_LEN + 1];

    VOS_UINT16                          usUsernameLen;
    VOS_UINT16                          usRsv3;
    VOS_UINT8                           aucUsername[TAF_MAX_AUTHDATA_USERNAME_LEN + 1];

    VOS_UINT16                          usPasswordLen;
    VOS_UINT16                          usRsv5;
    VOS_UINT8                           aucPassword[TAF_MAX_AUTHDATA_PASSWORD_LEN + 1];

    VOS_UINT16                          usAuthType;
    VOS_UINT8                           ucBitRatType;
    VOS_UINT8                           aucRsv7[1];

    VOS_UINT32                          ulIPv4ValidFlag;
    VOS_UINT8                           aucIPv4Addr[TAF_MAX_IPV4_ADDR_STR_LEN];

    VOS_UINT32                          ulPrimIPv4DNSValidFlag;
    VOS_UINT8                           aucPrimIPv4DNSAddr[TAF_MAX_IPV4_ADDR_STR_LEN];

    VOS_UINT32                          ulSndIPv4DNSValidFlag;
    VOS_UINT8                           aucSndIPv4DNSAddr[TAF_MAX_IPV4_ADDR_STR_LEN];

    VOS_UINT32                          ulPrimIPv4WINNSValidFlag;
    VOS_UINT8                           aucPrimIPv4WINNSAddr[TAF_MAX_IPV4_ADDR_STR_LEN];

    VOS_UINT32                          ulSndIPv4WINNSValidFlag;
    VOS_UINT8                           aucSndIPv4WINNSAddr[TAF_MAX_IPV4_ADDR_STR_LEN];

    VOS_UINT32                          ulPrimIPv6DNSValidFlag;
    VOS_UINT8                           aucPrimIPv6DNSAddr[TAF_IPV6_ADDR_LEN];

    VOS_UINT32                          ulSndIPv6DNSValidFlag;
    VOS_UINT8                           aucSndIPv6DNSAddr[TAF_IPV6_ADDR_LEN];

    VOS_UINT32                          ulPrimIPv6WINNSValidFlag;
    VOS_UINT8                           aucPrimIPv6WINNSAddr[TAF_IPV6_ADDR_LEN];

    VOS_UINT32                          ulSndIPv6WINNSValidFlag;
    VOS_UINT8                           aucSndIPv6WINNSAddr[TAF_IPV6_ADDR_LEN];

}AT_DIAL_PARAM_STRU;



typedef struct
{
    VOS_UINT8                           ucIpv4PcscfAddrNum;                     /* IPV4??P-CSCF??????????????????[0,8] */
    VOS_UINT8                           aucRsv[3];                              /* ???? */

    VOS_UINT32                          aulIpv4PcscfAddrList[TAF_PCSCF_ADDR_MAX_NUM];
} AT_IPV4_PCSCF_LIST_STRU;


typedef struct
{
    VOS_UINT8                           aucPcscfAddr[TAF_IPV6_ADDR_LEN];
} AT_PDP_IPV6_PCSCF_STRU;


typedef struct
{
    VOS_UINT8                           ucIpv6PcscfAddrNum;                     /* IPV6??P-CSCF??????????????????[0,8] */
    VOS_UINT8                           aucRsv[7];                              /* ???? */

    AT_PDP_IPV6_PCSCF_STRU              astIpv6PcscfAddrList[TAF_PCSCF_ADDR_MAX_NUM];
} AT_IPV6_PCSCF_LIST_STRU;

/*****************************************************************************
 ??????    : AT_IPV6_DHCP_PARAM_STRU
 ????????  :
 ASN.1???? :
 ????????  : IPV6??????PDP??????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          bitOpIpv6PriDns   : 1;
    VOS_UINT32                          bitOpIpv6SecDns   : 1;
    VOS_UINT32                          bitOpIpv6Spare    : 30;

    VOS_UINT8                           ucRabId;                                /* RAB??????????????:[5,15] */
    VOS_UINT8                           ucPduSessionId;
    VOS_UINT8                           aucRsv[2];

    VOS_UINT8                           aucIpv6TmpAddr[TAF_IPV6_ADDR_LEN];      /* ?? PDP????????????IPV6????????????????":" */
    VOS_UINT8                           aucIpv6Addr[TAF_IPV6_ADDR_LEN];         /* ?? PDP????????????IPV6????????????????":" */

    VOS_UINT8                           aucIpv6PrimDNS[TAF_IPV6_ADDR_LEN];      /* ?? PDP????????????IPV6??DNS????????????":" */
    VOS_UINT8                           aucIpv6SecDNS[TAF_IPV6_ADDR_LEN];       /* ?? PDP????????????IPV6??DNS????????????":" */

    AT_IPV6_PCSCF_LIST_STRU             stIpv6PcscfList;
}AT_IPV6_DHCP_PARAM_STRU;

/*****************************************************************************
 ??????    : AT_IPV4_DHCP_PARAM_STRU
 ????????  :
 ASN.1???? :
 ????????  : IPV4??????PDP??????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          bitOpIpv4PriDns   : 1;
    VOS_UINT32                          bitOpIpv4SecDns   : 1;
    VOS_UINT32                          bitOpIpv4PriWINNS : 1;
    VOS_UINT32                          bitOpIpv4SecWINNS : 1;
    VOS_UINT32                          bitOpSpare        : 28;

    VOS_UINT8                           ucRabId;                                /* RAB??????????????:[5,15] */
    VOS_UINT8                           ucPduSessionId;                         /* ucPduSessionId???? */
    VOS_UINT8                           aucRsv1[2];

    VOS_UINT32                          ulIpv4Addr;                             /* IPV4??IP???????????? */
    VOS_UINT32                          ulIpv4NetMask;                          /* IPV4?????????????? */
    VOS_UINT32                          ulIpv4GateWay;                          /* IPV4?????????????????? */
    VOS_UINT32                          ulIpv4PrimDNS;                          /* IPV4????DNS???????? */
    VOS_UINT32                          ulIpv4SecDNS;                           /* IPV4????DNS???????? */
    VOS_UINT32                          ulIpv4PrimWINNS;                        /* IPV4????WINNS???????? */
    VOS_UINT32                          ulIpv4SecWINNS;                         /* IPV4????WINNS???????? */
    AT_IPV4_PCSCF_LIST_STRU             stIpv4PcscfList;                        /* 8??Pcscf */
}AT_IPV4_DHCP_PARAM_STRU;



typedef struct
{
    AT_CLIENT_TAB_INDEX_UINT8           enPortIndex;
    AT_CLIENT_TAB_INDEX_UINT8           enUserIndex;
    AT_USER_TYPE                        ucUsrType;
    VOS_UINT8                           ucUsrCid;
} AT_PS_USER_INFO_STRU;

/*****************************************************************************
 ????????   : AT_IPV6_RA_INFO_STRU
 ????????   :
 ASN.1 ???? :
 ????????   : RA????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          bitOpLanAddr            : 1;
    VOS_UINT32                          bitOpPrefixAddr         : 1;
    VOS_UINT32                          bitOpMtuSize            : 1;
    VOS_UINT32                          bitOpPreferredLifetime  : 1;
    VOS_UINT32                          bitOpValidLifetime      : 1;
    VOS_UINT32                          bitOpSpare              : 27;


    VOS_UINT8                           aucLanAddr[TAF_IPV6_ADDR_LEN];       /* IPv6 ??????LAN???????? */
    VOS_UINT8                           aucPrefixAddr[TAF_IPV6_ADDR_LEN];    /* IPv6???? */
    VOS_UINT32                          ulPrefixBitLen;                         /* IPv6???????? */
    VOS_UINT32                          ulMtuSize;                              /* RA????????????IPv6??MTU?????? */
    VOS_UINT32                          ulPreferredLifetime;                    /* IPv6??????Preferred lifetime */
    VOS_UINT32                          ulValidLifetime;                        /* IPv6??????Valid lifetime */
} AT_IPV6_RA_INFO_STRU;


/*????????????????*/
typedef VOS_VOID (*AT_PS_RPT_CONN_RSLT_FUNC)(\
    VOS_UINT8                           ucCid, \
    VOS_UINT8                           ucPortIndex, \
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType);


typedef struct
{
    AT_USER_TYPE                        ucUsrType;
    AT_PS_RPT_CONN_RSLT_FUNC            pRptConnRsltFunc;
}AT_PS_REPORT_CONN_RESULT_STRU;

/*????????????????*/
typedef VOS_VOID (*AT_PS_RPT_END_RSLT_FUNC)(\
    VOS_UINT8                           ucCid, \
    VOS_UINT8                           ucPortIndex, \
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType, \
    TAF_PS_CAUSE_ENUM_UINT32            enCause);


typedef struct
{
    AT_USER_TYPE                        ucUsrType;
    AT_PS_RPT_END_RSLT_FUNC             pRptEndRsltFunc;
}AT_PS_REPORT_END_RESULT_STRU;

/*????????????????*/
typedef VOS_VOID (*AT_PS_REG_FC_POINT_FUNC)(\
    VOS_UINT8                           ucCid, \
    TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU  *pstEvent);


typedef struct
{
    AT_USER_TYPE                        ucUsrType;
    AT_PS_REG_FC_POINT_FUNC             pRegFcPoint;
}AT_PS_REG_FC_POINT_STRU;

/*????????????????*/
typedef VOS_VOID (*AT_PS_DEREG_FC_POINT_FUNC)(\
    VOS_UINT8                           ucCid, \
    TAF_PS_CALL_PDP_DEACTIVATE_CNF_STRU *pstEvent);


typedef struct
{
    AT_USER_TYPE                        ucUsrType;
    AT_PS_DEREG_FC_POINT_FUNC           pDeRegFcPoint;
}AT_PS_DEREG_FC_POINT_STRU;


typedef struct
{
    VOS_UINT32                          ulUsed;                                 /* ????CID????????????CHDATA????????????????VOS_TRUE:??????????VOS_FALSE:?????? */
    VOS_UINT32                          ulRmNetId;                              /* ????????ID
                                                                                   HSIC???? :UDI_ACM_HSIC_ACM1_ID??UDI_ACM_HSIC_ACM3_ID??UDI_ACM_HSIC_ACM5_ID??????????????????????UDI_INVAL_DEV_ID
                                                                                   VCOM???? :RNIC_DEV_ID_RMNET0 ~ RNIC_DEV_ID_RMNET4
                                                                                   */
    VOS_UINT32                          ulIfaceld;
    VOS_UINT32                          ulRmNetActFlg;                          /* ????CID????????PDP??????VOS_TRUE:??????????VOS_FALSE:?????? */
}AT_PS_DATA_CHANL_CFG_STRU;

#if (FEATURE_ON == FEATURE_IPV6)


typedef struct
{
    VOS_UINT32                          ulCauseNum;
    VOS_UINT8                           aucReserved[4];
    TAF_PS_CAUSE_ENUM_UINT32            aenPsCause[TAF_NV_IPV6_FALLBACK_EXT_CAUSE_MAX_NUM];
} AT_PS_IPV6_BACKPROC_EXT_CAUSE_STRU;
#endif


typedef struct
{
    VOS_UINT8                               ucDataSysInfoFlg;                   /* TRUE:????????????????; FALSE:??????????????????  */
    VOS_UINT8                               ucDataSysPolicyIndex;               /* ??APN???????????????? */
    TAF_PS_APN_DATA_SYS_ENUM_UINT8          enCurrentDataSys;                   /* ???????????????????????????????? */
    VOS_UINT8                               ucIsHandOver;                       /* ??????HandOver?????? */
    TAF_PS_CAUSE_ENUM_UINT32                enHoFailCause;                      /* ????HANDOVER??????????????????????????DEND???????? */
} AT_PS_APN_DATA_SYS_INFO_STRU;


typedef struct
{
    HTIMER                              hWaitWlanActCnfTmrHdl;                  /* ????WLAN???????????????????? */
    HTIMER                              hWaitWlanDeActCnfTmrHdl;                /* ????WLAN?????????????????????? */
    HTIMER                              hProtectInDataSysTmrHdl;                /* ???????????????? */
} AT_PS_CALL_TIMER_INFO_STRU;


typedef struct
{
    VOS_UINT32                          ulUsedFlg;          /* ???????????????? */

    VOS_UINT8                           ucRmNetId;
    VOS_UINT8                           ucIfaceId;

    TAF_PDP_TYPE_ENUM_UINT8             enCurrPdpType;      /* ???????????? */
    TAF_PDP_TYPE_ENUM_UINT8             enWlanPdpType;      /* Wlan???????? */
    TAF_PDP_TYPE_ENUM_UINT8             enHoPdpType;        /* handover???????? */
    VOS_UINT8                           aucRsv1[7];         /* ?????? */
    AT_PS_USER_INFO_STRU                stUserInfo;         /* ???????????????? */
    AT_DIAL_PARAM_STRU                  stUsrDialParam;     /* ???????????????? */

    VOS_UINT8                           ucIpv4Cid;          /* IPv4 CID */
    AT_PDP_STATE_ENUM_U8                enIpv4State;        /* IPv4 ???? */
    AT_PDP_STATE_ENUM_U8                enWlanIpv4State;    /* Wlan IPv4 ???? */
    VOS_UINT8                           ucIpv4DendRptFlg;   /* IPV4 DEND?????????????? */
    VOS_UINT8                           aucRsv2[2];         /* ?????? */
    VOS_UINT16                          usIpv4Mtu;          /* IPv4 MTU */
    AT_IPV4_DHCP_PARAM_STRU             stIpv4DhcpInfo;     /* IPv4 DHCP???? */

#if (FEATURE_ON == FEATURE_IPV6)
    VOS_UINT8                           ucIpv6Cid;          /* IPv6 CID */
    AT_PDP_STATE_ENUM_U8                enIpv6State;        /* IPv6 ???? */
    AT_PDP_STATE_ENUM_U8                enWlanIpv6State;    /* Wlan IPv6 ???? */
    VOS_UINT8                           ucIpv6DendRptFlg;   /* IPV6 DEND?????????????? */
    VOS_UINT8                           aucRsv3[4];         /* ?????? */
    AT_IPV6_RA_INFO_STRU                stIpv6RaInfo;       /* IPv6 ???????????? */
    AT_IPV6_DHCP_PARAM_STRU             stIpv6DhcpInfo;     /* IPv6 DHCP???? */
#endif

    AT_PS_APN_DATA_SYS_INFO_STRU        stApnDataSysInfo;                       /* ??APN???????? */
    AT_PS_CALL_TIMER_INFO_STRU          stPsCallTimerInfo;                      /* PS CALL???????????????? */
} AT_PS_CALL_ENTITY_STRU;

/*????????????????*/
typedef VOS_VOID (*AT_PS_SND_PDP_ACT_IND_FUNC)(\
    AT_PS_CALL_ENTITY_STRU             *pstCallEntity, \
    TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU  *pstEvent, \
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType);


typedef struct
{
    AT_USER_TYPE                        ucUsrType;
    AT_PS_SND_PDP_ACT_IND_FUNC          pSndPdpActInd;
}AT_PS_SND_PDP_ACT_IND_STRU;

/*????????????????*/
typedef VOS_VOID (*AT_PS_SND_PDP_DEACT_IND_FUNC)(\
    AT_PS_CALL_ENTITY_STRU             *pstCallEntity, \
    TAF_PS_CALL_PDP_DEACTIVATE_CNF_STRU *pstEvent, \
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType);


typedef struct
{
    AT_USER_TYPE                        ucUsrType;
    AT_PS_SND_PDP_DEACT_IND_FUNC        pSndPdpDeActInd;
}AT_PS_SND_PDP_DEACT_IND_STRU;

/*****************************************************************************
 ????????  : AT_IMS_EMC_IPV4_PDN_INFO_STRU
 ????????  : IMS EMC IPV4 PDN????
*****************************************************************************/
typedef struct
{
    VOS_UINT8                           aucIpAddr[TAF_IPV4_ADDR_LEN];
    VOS_UINT8                           aucDnsPrimAddr[TAF_IPV4_ADDR_LEN];
    VOS_UINT8                           aucDnsSecAddr[TAF_IPV4_ADDR_LEN];
    VOS_UINT16                          usMtu;
    VOS_UINT16                          usReserved;

} AT_IMS_EMC_IPV4_PDN_INFO_STRU;

/*****************************************************************************
 ????????  : AT_IMS_EMC_IPV6_PDN_INFO_STRU
 ????????  : IMS EMC IPV6 PDN????
*****************************************************************************/
typedef struct
{
    VOS_UINT8                           aucIpAddr[TAF_IPV6_ADDR_LEN];
    VOS_UINT8                           aucDnsPrimAddr[TAF_IPV6_ADDR_LEN];
    VOS_UINT8                           aucDnsSecAddr[TAF_IPV6_ADDR_LEN];
    VOS_UINT16                          usMtu;
    VOS_UINT16                          usReserved;

} AT_IMS_EMC_IPV6_PDN_INFO_STRU;

/*****************************************************************************
 ????????  : AT_IMS_EMC_RDP_STRU
 ????????  : IMS EMC ????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          bitOpIPv4PdnInfo    : 1;
    VOS_UINT32                          bitOpIPv6PdnInfo    : 1;
    VOS_UINT32                          bitOpSpare          : 30;

    AT_IMS_EMC_IPV4_PDN_INFO_STRU       stIPv4PdnInfo;
    AT_IMS_EMC_IPV6_PDN_INFO_STRU       stIPv6PdnInfo;

} AT_IMS_EMC_RDP_STRU;


typedef struct
{
    VOS_UINT8                           ucRedialForNoCausePolicy;               /* ?????????????????????????? 0: ??????  1: ???? */
    VOS_UINT8                           ucRedialForNoPdpTypeCausePolicy;        /* ????????28?????????????????? 0: ??????  1: ???? */
    VOS_UINT8                           aucReserved[6];
}AT_PS_REDIAL_FOR_NW_CAUSE_CFG_STRU;


typedef struct
{
#if (FEATURE_ON == FEATURE_IPV6)
    VOS_UINT8                           ucIpv6Capability;
    VOS_UINT8                           bitOpIpv6AddrFormat     : 1;            /* IPv6???????? 0: ??????????????; 1: 16???????????????? */
    VOS_UINT8                           bitOpIpv6SubnetNotation : 1;            /* IPv6???????????? 0: IP????????????????????????????????????; 1: ???????????????? */
    VOS_UINT8                           bitOpIpv6LeadingZeros   : 1;            /* ????IPv6????????????????0 0: ????????0; 1: ??????????0 */
    VOS_UINT8                           bitOpIpv6CompressZeros  : 1;            /* ????IPv6???????????????? 0: ??????0; 1: ????0 */
    VOS_UINT8                           bitOpSpare              : 4;
    VOS_UINT8                           aucReserved1[2];
    VOS_UINT32                          ulIpv6AddrTestModeCfg;

    /* ????????????????????????????PS???????? */
    AT_PS_IPV6_BACKPROC_EXT_CAUSE_STRU  stIpv6BackProcExtCauseTbl;
#endif

    VOS_UINT8                           ucSharePdpFlag;
    VOS_UINT8                           aucReserved2[7];
    AT_PS_REDIAL_FOR_NW_CAUSE_CFG_STRU  stRedialForNwCauseCfg;

    VOS_INT32                           lSpePort;
    VOS_UINT32                          ulIpfPortFlg;

    TAF_PS_PDP_TYPE_CHG_POLICY_CFG_STRU  astPdpTypeChgPolicyCfg[MODEM_ID_BUTT];

    TAF_PS_APN_DATA_SYS_POLICY_CONFIG_STRU      astApnDataSysCfgList[MODEM_ID_BUTT];
    TAF_PS_DATA_SYSTEM_STATUS_STRU              astDataSystemStatus[MODEM_ID_BUTT];

}AT_COMM_PS_CTX_STRU;

/*****************************************************************************
 ????????  : AT_PS_IPV6_IID_INFO_STRU
 ????????  : PS??IPv6????????ID????
*****************************************************************************/
typedef struct
{
    VOS_UINT64                          ullIID;

} AT_PS_IPV6_IID_INFO_STRU;

/*****************************************************************************
 ????????  : AT_PS_IPV6_IID_ENTRY_STRU
 ????????  : PS??IPv6????????ID????????
*****************************************************************************/
typedef struct
{
    VOS_UINT8                           aucApn[TAF_MAX_APN_LEN + 1];
    VOS_UINT8                           aucReserved[4];
    VOS_UINT8                           aucPrefix[TAF_IPV6_ADDR_LEN];
    VOS_UINT64                          ullIID;
    HI_LIST_S                           stList;

} AT_PS_IPV6_IID_ENTRY_STRU;

/*****************************************************************************
 ????????  : AT_PS_IPV6_IID_MGR_INFO_STRU
 ????????  :
*****************************************************************************/
typedef struct
{
    HI_LIST_S                           stListHead;

} AT_PS_IPV6_IID_MGR_INFO_STRU;


typedef struct
{
    VOS_UINT8                           aucApn[TAF_MAX_APN_LEN + 1];
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType;
    VOS_UINT8                           aucReserved[3];
    HI_LIST_S                           stList;

} AT_PS_PDP_TYPE_CHG_ENTRY_STRU;


typedef struct
{
    HI_LIST_S                           stListHead;
} AT_PS_PDP_TYPE_CHG_MGR_INFO_STRU;


typedef struct
{
    /* ??????CID??????PS???????????????? */
    VOS_UINT8                           aucCidToIndexTbl[TAF_MAX_CID + 1];

    /* PS?????????? */
    AT_PS_CALL_ENTITY_STRU              astCallEntity[AT_PS_MAX_CALL_NUM];

    /* CID???????????????????? */
    AT_PS_DATA_CHANL_CFG_STRU           astChannelCfg[TAF_MAX_CID + 1];

    /* PS???????????? */
    TAF_PS_CAUSE_ENUM_UINT32            enPsErrCause;

    /* IP??????RABID????????, IP???????????? */
    VOS_UINT32                          aulIpAddrRabIdMap[AT_PS_RABID_MAX_NUM];

#if (FEATURE_ON == FEATURE_IMS)
    /* IMS EMC PDN ???????? */
    AT_IMS_EMC_RDP_STRU                 stImsEmcRdp;
#endif

} AT_MODEM_PS_CTX_STRU;


typedef IMSA_WIFI_IMS_PDN_ACTIVATE_REQ_STRU AT_WLAN_PDN_ACTIVATE_REQ_STRU;


typedef WIFI_IMSA_IMS_PDN_ACTIVATE_CNF_STRU WLAN_AT_PDN_ACTIVATE_CNF_STRU;


typedef IMSA_WIFI_IMS_PDN_DEACTIVATE_REQ_STRU AT_WLAN_PDN_DEACTIVATE_REQ_STRU;


typedef WIFI_IMSA_IMS_PDN_DEACTIVATE_CNF_STRU WLAN_AT_PDN_DEACTIVATE_CNF_STRU;


typedef WIFI_IMSA_IMS_PDN_DEACTIVATE_IND_STRU WLAN_AT_PDN_DEACTIVATE_IND_STRU;


/*****************************************************************************
  8 UNION????
*****************************************************************************/


/*****************************************************************************
  9 OTHERS????
*****************************************************************************/

/*****************************************************************************
  10 ????????
*****************************************************************************/

#if (VOS_OS_VER == VOS_WIN32)
#pragma pack()
#else
#pragma pack(0)
#endif




#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

#endif /* end of AtCtxPacket.h */
