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
#ifndef _TAF_PS_API_H_
#define _TAF_PS_API_H_


/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "vos.h"
#include "TafTypeDef.h"
#include "PsTypeDef.h"
#include "TafApi.h"
#include "TafPsTypeDef.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifdef WIN32
#pragma warning(disable:4200) /* zero-sized array in struct/union */
#endif

#pragma pack(4)


/*****************************************************************************
  2 ??????
*****************************************************************************/
#define TAF_MAX_ACCESS_NUM_LEN          (32)
#define TAF_MAX_GW_AUTH_USERNAME_LEN    (255)
#define TAF_MAX_GW_AUTH_PASSWORD_LEN    (255)

#define TAF_MAX_PDP_PROFILE_NUM         (32)

/*????????????PDP????????????*/

#if (FEATURE_ON == FEATURE_LTE)
#define TAF_MAX_CID                     (31)
#else
#define TAF_MAX_CID                     (11)
#endif
#define TAF_MAX_CID_NV                  (11)

#define TAF_INVALID_CID                 (0xFF)

/* 4 x 3 char dec nums + 3 x '.' + '\0' */
#define TAF_MAX_IPV4_ADDR_STR_LEN       (16)

/* 8 x 4 ????(HEX) + 7 x ':' + '\0' */
#define TAF_MAX_IPV6_ADDR_COLON_STR_LEN (40)

/* 32 x 3 ????(DEC) + 31 x '.' + '\0' */
#define TAF_MAX_IPV6_ADDR_DOT_STR_LEN   (128)

#define TAF_IPV6_STR_MAX_TOKENS         (16)                                    /* IPV6?????????????????????????????????? */

#define TAF_IPV6_STR_RFC2373_TOKENS     (8)                                     /* RFC2373??????IPV6?????????????????????????????????? */

#define TAF_IPV4_STR_DELIMITER          '.'                                     /* RFC??????????IPV4???????????????????????? */
#define TAF_IPV6_STR_DELIMITER          ':'                                     /* RFC2373??????IPV6???????????????????????? */

#define TAF_IPV6_PREFIX_LEN             (8)                                     /* IPv6???????????? */
#define TAF_IPV6_IID_LEN                (8)                                     /* IPv6????????ID???? */


#define TAF_PS_MAX_PDPID                (11)


/* password+auth */
#define TAF_PPP_PAP_REQ_MAX_LEN             (100 + 100)

/* code(1B)+id(1B)+length(2B)+challenge_size(1B)+challenge+name */
#define TAF_PPP_CHAP_CHALLENGE_MAX_LEN      (1 + 1 + 2 + 1 + 48 + 100)

/* code(1B)+id(1B)+length(2B)+response_size(1B)+response+name */
#define TAF_PPP_CHAP_RESPONSE_MAX_LEN       (1 + 1 + 2 + 1 + 100 + 100)

#define TAF_PPP_AUTH_FRAME_BUF_MAX_LEN      (256)

#define TAF_PPP_IPCP_FRAME_BUF_MAX_LEN      (256)

#define TAF_DEFAULT_DSFLOW_NV_WR_INTERVAL   (2)             /* DSFLOW????????NV??????, ????(min) */

#define TAF_PS_CALL_TYPE_DOWN_NORMAL        (0)
#define TAF_PS_CALL_TYPE_UP                 (1)
#define TAF_PS_CALL_TYPE_DOWN_FORCE         (2)



#define TAF_PS_IS_SM_CAUSE_VALID(sm_cause)\
            ( (((sm_cause) + TAF_PS_CAUSE_SM_NW_SECTION_BEGIN) >= TAF_PS_CAUSE_SM_NW_OPERATOR_DETERMINED_BARRING)\
             && (((sm_cause) + TAF_PS_CAUSE_SM_NW_SECTION_BEGIN) <= TAF_PS_CAUSE_SM_NW_APN_RESTRICTION_INCOMPATIBLE) )

#define TAF_PS_CONVERT_SM_CAUSE_TO_PS_CAUSE(sm_cause)\
            ((sm_cause) + TAF_PS_CAUSE_SM_NW_SECTION_BEGIN)

#define TAF_PS_GET_MSG_CONTENT(pstMsg)\
            ((VOS_VOID *)(((TAF_PS_MSG_STRU *)(pstMsg))->aucContent))

#define TAF_PS_BUILD_EXCLIENTID(usModemId,usClientId)\
            ((VOS_UINT16)(((usModemId) & 0x000F) << 12) | (usClientId))

#define TAF_PS_GET_MODEMID_FROM_EXCLIENTID(usExClientId)\
            ((VOS_UINT16)(((usExClientId) & 0xF000) >> 12))

#define TAF_PS_GET_CLIENTID_FROM_EXCLIENTID(usExClientId)\
            ((VOS_UINT16)((usExClientId) & 0x0FFF))

/*????????????????????AT??????????????????????APP????????????????????3GPP
??????????????????*/
#define TAF_PS_APPQOS_TRAFFCLASS_SUBSCRIB           4
#define TAF_PS_APPQOS_DELIVERORDER_SUBSCRIB         2
#define TAF_PS_APPQOS_DELIVEReRRSDU_SUBSCRIB        3
#define TAF_PS_APPQOS_MAXSDUSIZE_SUBSCRIB           0
#define TAF_PS_APPQOS_MAXBITUL_SUBSCRIB             0
#define TAF_PS_APPQOS_MAXBITDL_SUBSCRIB             0
#define TAF_PS_APPQOS_RESIDUALBER_SUBSCRIB          0
#define TAF_PS_APPQOS_SDUERRRATIO_SUBSCRIB          0
#define TAF_PS_APPQOS_TRANSDELAY_SUBSCRIB           0
#define TAF_PS_APPQOS_TRAFFHANDPRIOR_SUBSCRIB       0
#define TAF_PS_APPQOS_GUARANTBITUL_SUBSCRIB         0
#define TAF_PS_APPQOS_GUARANTBITDL_SUBSCRIB         0
#define TAF_PS_APPQOS_SRCSTATISTICSDES_SUBSCRIB     0
#define TAF_PS_APPQOS_SIGNALINDICATION_SUBSCRIB     0

#define TAF_PS_PDP_RESELECT_CID                     (12)
#define TAF_PS_PDP_MAX_CID                          (20)

#define TAF_PS_MAX_VZWAPNE_NUM          (8)
#define TAF_PS_PDP_TYPE_CHG_MAX_NUM     (7)

#define TAF_PS_APN_DATA_SYS_INFO_MAX_NUM     (6)
#define TAF_PS_APN_DATA_SYS_SUBSID_MAX_NUM  (2)

#define TAF_PS_APN_DATA_SYS_PROTECT_IN_CELLULAR_MIN_TIME    (10)
#define TAF_PS_APN_DATA_SYS_PROTECT_IN_WLAN_MIN_TIME        (2)

/*****************************************************************************
  3 ????????
*****************************************************************************/


enum TAF_PS_MSG_ID_ENUM
{
    /*----------------------------------------------------------------------
       ????????DSM????[0x0000, 0x004F]
    *---------------------------------------------------------------------*/
    /* +CGACT */
    ID_MSG_TAF_PS_SET_PDP_CONTEXT_STATE_REQ                 = TAF_PS_MSG_ID_BASE + 0x0001,  /* _H2ASN_MsgChoice TAF_PS_SET_PDP_STATE_REQ_STRU */

    /* +CGCMOD */
    ID_MSG_TAF_PS_CALL_MODIFY_REQ                           = TAF_PS_MSG_ID_BASE + 0x0002,  /* _H2ASN_MsgChoice TAF_PS_CALL_MODIFY_REQ_STRU */

    /* +CGANS */
    ID_MSG_TAF_PS_CALL_ANSWER_REQ                           = TAF_PS_MSG_ID_BASE + 0x0003,  /* _H2ASN_MsgChoice TAF_PS_CALL_ANSWER_REQ_STRU */
    ID_MSG_TAF_PS_CALL_HANGUP_REQ                           = TAF_PS_MSG_ID_BASE + 0x0004,  /* _H2ASN_MsgChoice TAF_PS_CALL_HANGUP_REQ_STRU */

    /* ??????????????ID???????????????? */
    /* +CGQREQ */
    ID_MSG_TAF_PS_SET_GPRS_QOS_INFO_REQ                     = TAF_PS_MSG_ID_BASE + 0x0007,  /* _H2ASN_MsgChoice */
    ID_MSG_TAF_PS_GET_GPRS_QOS_INFO_REQ                     = TAF_PS_MSG_ID_BASE + 0x0008,  /* _H2ASN_MsgChoice */

    /* +CGQMIN */
    ID_MSG_TAF_PS_SET_GPRS_QOS_MIN_INFO_REQ                 = TAF_PS_MSG_ID_BASE + 0x0009,  /* _H2ASN_MsgChoice */
    ID_MSG_TAF_PS_GET_GPRS_QOS_MIN_INFO_REQ                 = TAF_PS_MSG_ID_BASE + 0x000A,  /* _H2ASN_MsgChoice */

    /*----------------------------------------------------------------------
       ????????DSM????[0x0050, 0x00CF]
    *---------------------------------------------------------------------*/
    /* ^NDISCONN/^NDISDUP */
    ID_MSG_TAF_PS_CALL_ORIG_REQ                             = TAF_PS_MSG_ID_BASE + 0x0051,  /* _H2ASN_MsgChoice TAF_PS_CALL_ORIG_REQ_STRU */
    ID_MSG_TAF_PS_CALL_END_REQ                              = TAF_PS_MSG_ID_BASE + 0x0052,  /* _H2ASN_MsgChoice TAF_PS_CALL_END_REQ_STRU */

    /* PPP */
    ID_MSG_TAF_PS_PPP_DIAL_ORIG_REQ                         = TAF_PS_MSG_ID_BASE + 0x0053,  /* _H2ASN_MsgChoice TAF_PS_PPP_DIAL_ORIG_REQ_STRU */

    /* ????????????SDF???? */
    ID_MSG_TAF_PS_GET_CID_SDF_REQ                           = TAF_PS_MSG_ID_BASE + 0x0054,  /* _H2ASN_MsgChoice TAF_SDF_PARA_QUERY_INFO_STRU */

    /* ????????????CID */
    ID_MSG_TAF_PS_GET_UNUSED_CID_REQ                        = TAF_PS_MSG_ID_BASE + 0x0055,  /* _H2ASN_MsgChoice */


    /*----------------------------------------------------------------------
       ????????APS????[0x00D0, 0x00FF]
    *---------------------------------------------------------------------*/
    /* ^DSFLOWQRY */
    ID_MSG_TAF_PS_GET_DSFLOW_INFO_REQ                       = TAF_PS_MSG_ID_BASE + 0x00D1,  /* _H2ASN_MsgChoice TAF_PS_GET_DSFLOW_INFO_REQ_STRU */

    /* ^DSFLOWCLR */
    ID_MSG_TAF_PS_CLEAR_DSFLOW_REQ                          = TAF_PS_MSG_ID_BASE + 0x00D2,  /* _H2ASN_MsgChoice TAF_PS_CLEAR_DSFLOW_REQ_STRU */

    /* ^DSFLOWRPT */
    ID_MSG_TAF_PS_CONFIG_DSFLOW_RPT_REQ                     = TAF_PS_MSG_ID_BASE + 0x00D3,  /* _H2ASN_MsgChoice TAF_PS_CONFIG_DSFLOW_RPT_REQ_STRU */

    /* ^TRIG */
    ID_MSG_TAF_PS_TRIG_GPRS_DATA_REQ                        = TAF_PS_MSG_ID_BASE + 0x00D4,  /* _H2ASN_MsgChoice TAF_PS_TRIG_GPRS_DATA_REQ_STRU */

    /*^LTECS*/
    ID_MSG_TAF_PS_GET_LTE_CS_REQ                            = TAF_PS_MSG_ID_BASE + 0x00D5,  /* _H2ASN_MsgChoice TAF_PS_LTECS_REQ_STRU */

    /* ^CEMODE */
    ID_MSG_TAF_PS_GET_CEMODE_REQ                            = TAF_PS_MSG_ID_BASE + 0x00D6,  /* _H2ASN_MsgChoice TAF_PS_CEMODE_REQ_STRU */

    /* CDMA????????DORMANT???????? */
    ID_MSG_TAF_PS_CALL_ENTER_DORMANT_IND                    = TAF_PS_MSG_ID_BASE + 0x00D7,  /* _H2ASN_MsgChoice TAF_PS_CALL_ENTER_DORMANT_IND_STRU */

    ID_MSG_TAF_PS_HAI_CHANGE_IND                            = TAF_PS_MSG_ID_BASE + 0x00D8,  /* _H2ASN_MsgChoice TAF_PS_HAI_CHANGE_IND_STRU */

    /* ^APDSFLOWRPT */
    ID_MSG_TAF_PS_SET_APDSFLOW_RPT_CFG_REQ                  = TAF_PS_MSG_ID_BASE + 0x00D9,  /* _H2ASN_MsgChoice TAF_PS_SET_APDSFLOW_RPT_CFG_REQ_STRU */
    ID_MSG_TAF_PS_GET_APDSFLOW_RPT_CFG_REQ                  = TAF_PS_MSG_ID_BASE + 0x00DA,  /* _H2ASN_MsgChoice TAF_PS_GET_APDSFLOW_RPT_CFG_REQ_STRU */

    ID_MSG_TAF_PS_SET_DSFLOW_NV_WRITE_CFG_REQ               = TAF_PS_MSG_ID_BASE + 0x00DB,  /* _H2ASN_MsgChoice TAF_PS_SET_DSFLOW_NV_WRITE_CFG_REQ_STRU */
    ID_MSG_TAF_PS_GET_DSFLOW_NV_WRITE_CFG_REQ               = TAF_PS_MSG_ID_BASE + 0x00DC,  /* _H2ASN_MsgChoice TAF_PS_GET_DSFLOW_NV_WRITE_CFG_REQ_STRU */

    ID_MSG_TAF_PS_SET_CDMA_DIAL_MODE_REQ                    = TAF_PS_MSG_ID_BASE + 0x00DD,  /* _H2ASN_MsgChoice TAF_PS_CDATA_DIAL_MODE_REQ_STRU */

    /* ^VTFLOWRPT */
    ID_MSG_TAF_PS_CONFIG_VTFLOW_RPT_REQ                     = TAF_PS_MSG_ID_BASE + 0x00DE,  /* _H2ASN_MsgChoice TAF_PS_CONFIG_VTFLOW_RPT_REQ_STRU */

    /* ^PDPROFMOD */
    ID_MSG_TAF_PS_SET_PDPROFMOD_INFO_REQ                    = TAF_PS_MSG_ID_BASE + 0x00DF,  /* _H2ASN_MsgChoice TAF_PS_SET_PROFILE_INFO_REQ_STRU */

    /* ??????????????ID???????????????? */
    ID_MSG_TAF_PS_SET_CQOS_PRI_REQ                          = TAF_PS_MSG_ID_BASE + 0x00E0,  /* _H2ASN_MsgChoice TAF_PS_SET_1X_CQOS_PRI_REQ_STRU */


    /* ^DATASWITCH*/
    ID_MSG_TAF_PS_SET_DATA_SWITCH_REQ                       = TAF_PS_MSG_ID_BASE + 0x00E1, /* _H2ASN_MsgChoice TAF_PS_SET_DATA_SWITCH_REQ_STRU */
    ID_MSG_TAF_PS_GET_DATA_SWITCH_REQ                       = TAF_PS_MSG_ID_BASE + 0x00E2, /* _H2ASN_MsgChoice TAF_PS_GET_DATA_SWITCH_REQ_STRU */

    /* ^DATAROAMSWITCH*/
    ID_MSG_TAF_PS_SET_DATA_ROAM_SWITCH_REQ                  = TAF_PS_MSG_ID_BASE + 0x00E3, /* _H2ASN_MsgChoice TAF_PS_SET_DATA_ROAM_SWITCH_REQ_STRU */
    ID_MSG_TAF_PS_GET_DATA_ROAM_SWITCH_REQ                  = TAF_PS_MSG_ID_BASE + 0x00E4, /* _H2ASN_MsgChoice TAF_PS_GET_DATA_ROAM_SWITCH_REQ_STRU */

    /* ??????????????????????????????TAF_PS_APP_PROFILE_ID_BASE???? */
    /*----------------------------------------------------------------------
       ????????
    *---------------------------------------------------------------------*/
    /* +CGDCONT */
    ID_MSG_TAF_PS_SET_PRIM_PDP_CONTEXT_INFO_REQ             = TAF_PS_APP_PROFILE_ID_BASE + 0x0001,  /* _H2ASN_MsgChoice TAF_PS_SET_PRIM_PDP_CONTEXT_INFO_REQ_STRU */
    ID_MSG_TAF_PS_GET_PRIM_PDP_CONTEXT_INFO_REQ             = TAF_PS_APP_PROFILE_ID_BASE + 0x0002,  /* _H2ASN_MsgChoice TAF_PS_GET_PRIM_PDP_CONTEXT_INFO_REQ_STRU */

    /* +CGDSCONT */
    ID_MSG_TAF_PS_SET_SEC_PDP_CONTEXT_INFO_REQ              = TAF_PS_APP_PROFILE_ID_BASE + 0x0003,  /* _H2ASN_MsgChoice TAF_PS_SET_SEC_PDP_CONTEXT_INFO_REQ_STRU */
    ID_MSG_TAF_PS_GET_SEC_PDP_CONTEXT_INFO_REQ              = TAF_PS_APP_PROFILE_ID_BASE + 0x0004,  /* _H2ASN_MsgChoice TAF_PS_GET_SEC_PDP_CONTEXT_INFO_REQ_STRU */

    /* +CGTFT */
    ID_MSG_TAF_PS_SET_TFT_INFO_REQ                          = TAF_PS_APP_PROFILE_ID_BASE + 0x0005,  /* _H2ASN_MsgChoice TAF_PS_SET_TFT_INFO_REQ_STRU */
    ID_MSG_TAF_PS_GET_TFT_INFO_REQ                          = TAF_PS_APP_PROFILE_ID_BASE + 0x0006,  /* _H2ASN_MsgChoice TAF_PS_GET_TFT_INFO_REQ_STRU */

    /* +CGEQREQ */
    ID_MSG_TAF_PS_SET_UMTS_QOS_INFO_REQ                     = TAF_PS_APP_PROFILE_ID_BASE + 0x0007,  /* _H2ASN_MsgChoice TAF_PS_SET_UMTS_QOS_INFO_REQ_STRU */
    ID_MSG_TAF_PS_GET_UMTS_QOS_INFO_REQ                     = TAF_PS_APP_PROFILE_ID_BASE + 0x0008,  /* _H2ASN_MsgChoice TAF_PS_GET_UMTS_QOS_INFO_REQ_STRU */

    /* +CGEQMIN */
    ID_MSG_TAF_PS_SET_UMTS_QOS_MIN_INFO_REQ                 = TAF_PS_APP_PROFILE_ID_BASE + 0x0009,  /* _H2ASN_MsgChoice TAF_PS_SET_UMTS_QOS_MIN_INFO_REQ_STRU */
    ID_MSG_TAF_PS_GET_UMTS_QOS_MIN_INFO_REQ                 = TAF_PS_APP_PROFILE_ID_BASE + 0x000A,  /* _H2ASN_MsgChoice TAF_PS_GET_UMTS_QOS_MIN_INFO_REQ_STRU */

    /* +CGEQNEG */
    ID_MSG_TAF_PS_GET_DYNAMIC_UMTS_QOS_INFO_REQ             = TAF_PS_APP_PROFILE_ID_BASE + 0x000B,  /* _H2ASN_MsgChoice TAF_PS_GET_DYNAMIC_UMTS_QOS_INFO_REQ_STRU */

    /* +CGACT */
    ID_MSG_TAF_PS_GET_PDP_CONTEXT_STATE_REQ                 = TAF_PS_APP_PROFILE_ID_BASE + 0x000C,  /* _H2ASN_MsgChoice TAF_PS_GET_PDP_STATE_REQ_STRU */

    /* +CGPADDR */
    ID_MSG_TAF_PS_GET_PDP_IP_ADDR_INFO_REQ                  = TAF_PS_APP_PROFILE_ID_BASE + 0x000D,  /* _H2ASN_MsgChoice TAF_PS_GET_PDP_IP_ADDR_INFO_REQ_STRU */

    ID_MSG_TAF_PS_GET_PDPCONT_INFO_REQ                      = TAF_PS_APP_PROFILE_ID_BASE + 0x000E, /* _H2ASN_MsgChoice TAF_PS_GET_PDP_CONTEXT_INFO_REQ_STRU */

    /* +CGAUTO */
    ID_MSG_TAF_PS_SET_ANSWER_MODE_INFO_REQ                  = TAF_PS_APP_PROFILE_ID_BASE + 0x000F,  /* _H2ASN_MsgChoice TAF_PS_SET_ANSWER_MODE_INFO_REQ_STRU */
    ID_MSG_TAF_PS_GET_ANSWER_MODE_INFO_REQ                  = TAF_PS_APP_PROFILE_ID_BASE + 0x0010,  /* _H2ASN_MsgChoice TAF_PS_GET_ANSWER_MODE_INFO_REQ_STRU */

    /* +CGCONTRDP */
    ID_MSG_TAF_PS_GET_DYNAMIC_PRIM_PDP_CONTEXT_INFO_REQ     = TAF_PS_APP_PROFILE_ID_BASE + 0x0011,  /* _H2ASN_MsgChoice TAF_PS_GET_DYNAMIC_PRIM_PDP_CONTEXT_INFO_REQ_STRU */

    /* +CGSCONTRDP */
    ID_MSG_TAF_PS_GET_DYNAMIC_SEC_PDP_CONTEXT_INFO_REQ      = TAF_PS_APP_PROFILE_ID_BASE + 0x0012,  /* _H2ASN_MsgChoice TAF_PS_GET_DYNAMIC_SEC_PDP_CONTEXT_INFO_REQ_STRU */

    /* +CGTFTRDP */
    ID_MSG_TAF_PS_GET_DYNAMIC_TFT_INFO_REQ                  = TAF_PS_APP_PROFILE_ID_BASE + 0x0013,  /* _H2ASN_MsgChoice TAF_PS_GET_DYNAMIC_TFT_INFO_REQ_STRU */

    /* +CGEQOS */
    ID_MSG_TAF_PS_SET_EPS_QOS_INFO_REQ                      = TAF_PS_APP_PROFILE_ID_BASE + 0x0014,  /* _H2ASN_MsgChoice TAF_PS_SET_EPS_QOS_INFO_REQ_STRU */
    ID_MSG_TAF_PS_GET_EPS_QOS_INFO_REQ                      = TAF_PS_APP_PROFILE_ID_BASE + 0x0015,  /* _H2ASN_MsgChoice TAF_PS_GET_EPS_QOS_INFO_REQ_STRU */

    /* +CGEQOSRDP */
    ID_MSG_TAF_PS_GET_DYNAMIC_EPS_QOS_INFO_REQ              = TAF_PS_APP_PROFILE_ID_BASE + 0x0016,  /* _H2ASN_MsgChoice TAF_PS_GET_DYNAMIC_EPS_QOS_INFO_REQ_STRU */

    /* D */
    ID_MSG_TAF_PS_GET_D_GPRS_ACTIVE_TYPE_REQ                = TAF_PS_APP_PROFILE_ID_BASE + 0x0017,  /* _H2ASN_MsgChoice TAF_PS_GET_D_GPRS_ACTIVE_TYPE_REQ_STRU */

    /* ^DWINS */
    ID_MSG_TAF_PS_CONFIG_NBNS_FUNCTION_REQ                  = TAF_PS_APP_PROFILE_ID_BASE + 0x0018,  /* _H2ASN_MsgChoice TAF_PS_CONFIG_NBNS_FUNCTION_REQ_STRU */

    /* ^AUTHDATA */
    ID_MSG_TAF_PS_SET_AUTHDATA_INFO_REQ                     = TAF_PS_APP_PROFILE_ID_BASE + 0x0019,  /* _H2ASN_MsgChoice TAF_PS_SET_AUTHDATA_INFO_REQ_STRU */
    ID_MSG_TAF_PS_GET_AUTHDATA_INFO_REQ                     = TAF_PS_APP_PROFILE_ID_BASE + 0x001A,  /* _H2ASN_MsgChoice TAF_PS_GET_AUTHDATA_INFO_REQ_STRU */

    /* ^DNSQUERY */
    ID_MSG_TAF_PS_GET_NEGOTIATION_DNS_REQ                   = TAF_PS_APP_PROFILE_ID_BASE + 0x001B,  /* _H2ASN_MsgChoice TAF_PS_GET_NEGOTIATION_DNS_REQ_STRU */

     /* ^CGDNS */
    ID_MSG_TAF_PS_SET_PDP_DNS_INFO_REQ                      = TAF_PS_APP_PROFILE_ID_BASE + 0x001C,  /* _H2ASN_MsgChoice TAF_PS_SET_PDP_DNS_INFO_REQ_STRU */
    ID_MSG_TAF_PS_GET_PDP_DNS_INFO_REQ                      = TAF_PS_APP_PROFILE_ID_BASE + 0x001D,  /* _H2ASN_MsgChoice TAF_PS_GET_PDP_DNS_INFO_REQ_STRU */

    /* +CTA*/
    ID_MSG_TAF_PS_SET_CTA_INFO_REQ                          = TAF_PS_APP_PROFILE_ID_BASE + 0x001E,  /* _H2ASN_MsgChoice TAF_PS_SET_CTA_INFO_REQ_STRU */
    ID_MSG_TAF_PS_GET_CTA_INFO_REQ                          = TAF_PS_APP_PROFILE_ID_BASE + 0x001F,  /* _H2ASN_MsgChoice TAF_PS_GET_1X_CTA_INFO_REQ_STRU */

    ID_MSG_TAF_PS_GET_CGMTU_VALUE_REQ                       = TAF_PS_APP_PROFILE_ID_BASE + 0x0020,  /* _H2ASN_MsgChoice TAF_PS_GET_CGMTU_VALUE_REQ_STRU */

    /* ^IMSPDPCFG */
    ID_MSG_TAF_PS_SET_IMS_PDP_CFG_REQ                       = TAF_PS_APP_PROFILE_ID_BASE + 0x0021,  /* _H2ASN_MsgChoice TAF_PS_SET_IMS_PDP_CFG_REQ_STRU */

    /* ^CDORMTIMER */
    ID_MSG_TAF_PS_SET_1X_DORM_TIMER_REQ                     = TAF_PS_APP_PROFILE_ID_BASE + 0x0022,  /* _H2ASN_MsgChoice TAF_PS_SET_1X_DORMANT_TIMER_REQ_STRU */
    ID_MSG_TAF_PS_GET_1X_DORM_TIEMR_REQ                     = TAF_PS_APP_PROFILE_ID_BASE + 0X0023,  /* _H2ASN_MsgChoice TAF_PS_GET_1X_DORMANT_TIMER_REQ_STRU */

    ID_MSG_TAF_PS_SET_MIP_MODE_REQ                          = TAF_PS_APP_PROFILE_ID_BASE + 0x0024,  /* _H2ASN_MsgChoice TAF_PS_SET_MIP_MODE_REQ_STRU */
    ID_MSG_TAF_PS_GET_MIP_MODE_REQ                          = TAF_PS_APP_PROFILE_ID_BASE + 0X0025,  /* _H2ASN_MsgChoice TAF_PS_GET_MIP_MODE_REQ_STRU */

    ID_MSG_TAF_PS_SET_VZWAPNE_REQ                           = TAF_PS_APP_PROFILE_ID_BASE + 0X0026,  /* _H2ASN_MsgChoice TAF_PS_SET_VZWAPNE_REQ_STRU */
    ID_MSG_TAF_PS_GET_VZWAPNE_REQ                           = TAF_PS_APP_PROFILE_ID_BASE + 0X0027,  /* _H2ASN_MsgChoice TAF_PS_GET_VZWAPNE_REQ_STRU */

    ID_MSG_TAF_PS_SET_APN_THROT_INFO_REQ                    = TAF_PS_APP_PROFILE_ID_BASE + 0X0028,   /* _H2ASN_MsgChoice TAF_PS_SET_APN_THROT_INFO_REQ_STRU */

    ID_MSG_TAF_PS_GET_LTE_ATTACH_INFO_REQ                   = TAF_PS_APP_PROFILE_ID_BASE + 0X0029,  /* _H2ASN_MsgChoice TAF_PS_GET_LTE_ATTACH_INFO_REQ_STRU */

    ID_MSG_TAF_PS_BUTT

};
typedef VOS_UINT32 TAF_PS_MSG_ID_ENUM_UINT32;


enum TAF_PS_EVT_ID_ENUM
{
    /* PS CALL */
    ID_EVT_TAF_PS_CALL_PDP_ACTIVATE_CNF                     = TAF_PS_EVT_ID_BASE + 0x0001,           /* _H2ASN_MsgChoice TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU           */
    ID_EVT_TAF_PS_CALL_PDP_ACTIVATE_REJ                     = TAF_PS_EVT_ID_BASE + 0x0002,           /* _H2ASN_MsgChoice TAF_PS_CALL_PDP_ACTIVATE_REJ_STRU           */
    ID_EVT_TAF_PS_CALL_PDP_ACTIVATE_IND                     = TAF_PS_EVT_ID_BASE + 0x0003,           /* _H2ASN_MsgChoice TAF_PS_CALL_PDP_ACTIVATE_IND_STRU           */
    ID_EVT_TAF_PS_CALL_PDP_MANAGE_IND                       = TAF_PS_EVT_ID_BASE + 0x0004,           /* _H2ASN_MsgChoice TAF_PS_CALL_PDP_MANAGE_IND_STRU             */
    ID_EVT_TAF_PS_CALL_PDP_MODIFY_CNF                       = TAF_PS_EVT_ID_BASE + 0x0005,           /* _H2ASN_MsgChoice TAF_PS_CALL_PDP_MODIFY_CNF_STRU             */
    ID_EVT_TAF_PS_CALL_PDP_MODIFY_REJ                       = TAF_PS_EVT_ID_BASE + 0x0006,           /* _H2ASN_MsgChoice TAF_PS_CALL_PDP_MODIFY_REJ_STRU             */
    ID_EVT_TAF_PS_CALL_PDP_MODIFY_IND                       = TAF_PS_EVT_ID_BASE + 0x0007,           /* _H2ASN_MsgChoice TAF_PS_CALL_PDP_MODIFY_IND_STRU             */
    ID_EVT_TAF_PS_CALL_PDP_DEACTIVATE_CNF                   = TAF_PS_EVT_ID_BASE + 0x0008,           /* _H2ASN_MsgChoice TAF_PS_CALL_PDP_DEACTIVATE_CNF_STRU         */
    ID_EVT_TAF_PS_CALL_PDP_DEACTIVATE_IND                   = TAF_PS_EVT_ID_BASE + 0x0009,           /* _H2ASN_MsgChoice TAF_PS_CALL_PDP_DEACTIVATE_IND_STRU         */
    ID_EVT_TAF_PS_CALL_PDP_DISCONNECT_IND                   = TAF_PS_EVT_ID_BASE + 0x000A,           /* _H2ASN_MsgChoice TAF_PS_CALL_PDP_PDP_DISCONNECT_IND_STRU     */
    ID_EVT_TAF_PS_CALL_PDP_IPV6_INFO_IND                    = TAF_PS_EVT_ID_BASE + 0x000B,           /* _H2ASN_MsgChoice TAF_PS_IPV6_INFO_IND_STRU                   */
    ID_EVT_TAF_PS_CALL_PDP_RABID_CHANGE_IND                 = TAF_PS_EVT_ID_BASE + 0x000C,           /* _H2ASN_MsgChoice TAF_PS_CALL_PDP_RABID_CHANGE_IND_STRU       */

    ID_EVT_TAF_PS_CALL_ORIG_CNF                             = TAF_PS_EVT_ID_BASE + 0x0031,           /* _H2ASN_MsgChoice TAF_PS_CALL_ORIG_CNF_STRU                   */
    ID_EVT_TAF_PS_CALL_END_CNF                              = TAF_PS_EVT_ID_BASE + 0x0032,           /* _H2ASN_MsgChoice TAF_PS_CALL_END_CNF_STRU                    */
    ID_EVT_TAF_PS_CALL_MODIFY_CNF                           = TAF_PS_EVT_ID_BASE + 0x0033,           /* _H2ASN_MsgChoice TAF_PS_CALL_MODIFY_CNF_STRU                 */
    ID_EVT_TAF_PS_CALL_ANSWER_CNF                           = TAF_PS_EVT_ID_BASE + 0x0034,           /* _H2ASN_MsgChoice TAF_PS_CALL_ANSWER_CNF_STRU                 */
    ID_EVT_TAF_PS_CALL_HANGUP_CNF                           = TAF_PS_EVT_ID_BASE + 0x0035,           /* _H2ASN_MsgChoice TAF_PS_CALL_HANGUP_CNF_STRU                 */

    /* D */
    ID_EVT_TAF_PS_GET_D_GPRS_ACTIVE_TYPE_CNF                = TAF_PS_EVT_ID_BASE + 0x0100,           /* _H2ASN_MsgChoice TAF_PS_GET_D_GPRS_ACTIVE_TYPE_CNF_STRU      */

    /* PPP */
    ID_EVT_TAF_PS_PPP_DIAL_ORIG_CNF                         = TAF_PS_EVT_ID_BASE + 0x0101,           /* _H2ASN_MsgChoice TAF_PS_PPP_DIAL_ORIG_CNF_STRU               */

    /* +CGDCONT */
    ID_EVT_TAF_PS_SET_PRIM_PDP_CONTEXT_INFO_CNF             = TAF_PS_EVT_ID_BASE + 0x0102,           /* _H2ASN_MsgChoice TAF_PS_SET_PRIM_PDP_CONTEXT_INFO_CNF_STRU   */
    ID_EVT_TAF_PS_GET_PRIM_PDP_CONTEXT_INFO_CNF             = TAF_PS_EVT_ID_BASE + 0x0103,           /* _H2ASN_MsgChoice TAF_PS_GET_PRIM_PDP_CONTEXT_INFO_CNF_STRU   */

    /* +CGDSCONT */
    ID_EVT_TAF_PS_SET_SEC_PDP_CONTEXT_INFO_CNF              = TAF_PS_EVT_ID_BASE + 0x0104,           /* _H2ASN_MsgChoice TAF_PS_SET_SEC_PDP_CONTEXT_INFO_CNF_STRU    */
    ID_EVT_TAF_PS_GET_SEC_PDP_CONTEXT_INFO_CNF              = TAF_PS_EVT_ID_BASE + 0x0105,           /* _H2ASN_MsgChoice TAF_PS_GET_SEC_PDP_CONTEXT_INFO_CNF_STRU    */

    /* +CGTFT */
    ID_EVT_TAF_PS_SET_TFT_INFO_CNF                          = TAF_PS_EVT_ID_BASE + 0x0106,           /* _H2ASN_MsgChoice TAF_PS_SET_TFT_INFO_CNF_STRU                */
    ID_EVT_TAF_PS_GET_TFT_INFO_CNF                          = TAF_PS_EVT_ID_BASE + 0x0107,           /* _H2ASN_MsgChoice TAF_PS_GET_TFT_INFO_CNF_STRU                */



    /* +CGEQREQ */
    ID_EVT_TAF_PS_SET_UMTS_QOS_INFO_CNF                     = TAF_PS_EVT_ID_BASE + 0x010C,           /* _H2ASN_MsgChoice TAF_PS_SET_UMTS_QOS_INFO_CNF_STRU           */
    ID_EVT_TAF_PS_GET_UMTS_QOS_INFO_CNF                     = TAF_PS_EVT_ID_BASE + 0x010D,           /* _H2ASN_MsgChoice TAF_PS_GET_UMTS_QOS_INFO_CNF_STRU           */

    /* +CGEQMIN */
    ID_EVT_TAF_PS_SET_UMTS_QOS_MIN_INFO_CNF                 = TAF_PS_EVT_ID_BASE + 0x010E,           /* _H2ASN_MsgChoice TAF_PS_SET_UMTS_QOS_MIN_INFO_CNF_STRU       */
    ID_EVT_TAF_PS_GET_UMTS_QOS_MIN_INFO_CNF                 = TAF_PS_EVT_ID_BASE + 0x010F,           /* _H2ASN_MsgChoice TAF_PS_GET_UMTS_QOS_MIN_INFO_CNF_STRU       */

    /* +CGEQNEG */
    ID_EVT_TAF_PS_GET_DYNAMIC_UMTS_QOS_INFO_CNF             = TAF_PS_EVT_ID_BASE + 0x0110,           /* _H2ASN_MsgChoice TAF_PS_GET_DYNAMIC_UMTS_QOS_INFO_CNF_STRU   */

    /* +CGACT */
    ID_EVT_TAF_PS_SET_PDP_CONTEXT_STATE_CNF                 = TAF_PS_EVT_ID_BASE + 0x0111,           /* _H2ASN_MsgChoice TAF_PS_SET_PDP_STATE_CNF_STRU       */
    ID_EVT_TAF_PS_GET_PDP_CONTEXT_STATE_CNF                 = TAF_PS_EVT_ID_BASE + 0x0112,           /* _H2ASN_MsgChoice TAF_PS_GET_PDP_STATE_CNF_STRU       */

    /* +CGPADDR */
    ID_EVT_TAF_PS_GET_PDP_IP_ADDR_INFO_CNF                  = TAF_PS_EVT_ID_BASE + 0x0113,           /* _H2ASN_MsgChoice TAF_PS_GET_PDP_IP_ADDR_INFO_CNF_STRU        */
    ID_EVT_TAF_PS_GET_PDP_CONTEXT_INFO_CNF                  = TAF_PS_EVT_ID_BASE + 0x0114,           /* _H2ASN_MsgChoice TAF_PS_GET_PDP_CONTEXT_INFO_CNF_STRU        */

    /* +CGAUTO */
    ID_EVT_TAF_PS_SET_ANSWER_MODE_INFO_CNF                  = TAF_PS_EVT_ID_BASE + 0x0115,           /* _H2ASN_MsgChoice TAF_PS_SET_ANSWER_MODE_INFO_CNF_STRU        */
    ID_EVT_TAF_PS_GET_ANSWER_MODE_INFO_CNF                  = TAF_PS_EVT_ID_BASE + 0x0116,           /* _H2ASN_MsgChoice TAF_PS_GET_ANSWER_MODE_INFO_CNF_STRU        */

    /* +CGCONTRDP */
    ID_EVT_TAF_PS_GET_DYNAMIC_PRIM_PDP_CONTEXT_INFO_CNF     = TAF_PS_EVT_ID_BASE + 0x0117,           /* _H2ASN_MsgChoice TAF_PS_GET_DYNAMIC_PRIM_PDP_CONTEXT_INFO_CNF_STRU */

    /* +CGSCONTRDP */
    ID_EVT_TAF_PS_GET_DYNAMIC_SEC_PDP_CONTEXT_INFO_CNF      = TAF_PS_EVT_ID_BASE + 0x0118,           /* _H2ASN_MsgChoice TAF_PS_GET_DYNAMIC_SEC_PDP_CONTEXT_INFO_CNF_STRU */

    /* +CGTFTRDP */
    ID_EVT_TAF_PS_GET_DYNAMIC_TFT_INFO_CNF                  = TAF_PS_EVT_ID_BASE + 0x0119,           /* _H2ASN_MsgChoice TAF_PS_GET_DYNAMIC_TFT_INFO_CNF_STRU        */

    /* +CGEQOS */
    ID_EVT_TAF_PS_SET_EPS_QOS_INFO_CNF                      = TAF_PS_EVT_ID_BASE + 0x011A,           /* _H2ASN_MsgChoice TAF_PS_SET_EPS_QOS_INFO_CNF_STRU            */
    ID_EVT_TAF_PS_GET_EPS_QOS_INFO_CNF                      = TAF_PS_EVT_ID_BASE + 0x011B,           /* _H2ASN_MsgChoice TAF_PS_GET_EPS_QOS_INFO_CNF_STRU            */

    /* +CGEQOSRDP */
    ID_EVT_TAF_PS_GET_DYNAMIC_EPS_QOS_INFO_CNF              = TAF_PS_EVT_ID_BASE + 0x011C,           /* _H2ASN_MsgChoice TAF_PS_GET_DYNAMIC_EPS_QOS_INFO_CNF_STRU    */

    /* ^DSFLOWQRY */
    ID_EVT_TAF_PS_GET_DSFLOW_INFO_CNF                       = TAF_PS_EVT_ID_BASE + 0x011D,           /* _H2ASN_MsgChoice TAF_PS_GET_DSFLOW_INFO_CNF_STRU             */

    /* ^DSFLOWCLR */
    ID_EVT_TAF_PS_CLEAR_DSFLOW_CNF                          = TAF_PS_EVT_ID_BASE + 0x011E,           /* _H2ASN_MsgChoice TAF_PS_CLEAR_DSFLOW_CNF_STRU                */

    /* ^DSFLOWRPT */
    ID_EVT_TAF_PS_CONFIG_DSFLOW_RPT_CNF                     = TAF_PS_EVT_ID_BASE + 0x011F,           /* _H2ASN_MsgChoice TAF_PS_CONFIG_DSFLOW_RPT_CNF_STRU           */

    /* ^DSFLOWRPT */
    ID_EVT_TAF_PS_REPORT_DSFLOW_IND                         = TAF_PS_EVT_ID_BASE + 0x0120,           /* _H2ASN_MsgChoice TAF_PS_REPORT_DSFLOW_IND_STRU               */



    /* ^CGDNS */
    ID_EVT_TAF_PS_SET_PDP_DNS_INFO_CNF                      = TAF_PS_EVT_ID_BASE + 0x0123,           /* _H2ASN_MsgChoice TAF_PS_SET_PDP_DNS_INFO_CNF_STRU            */
    ID_EVT_TAF_PS_GET_PDP_DNS_INFO_CNF                      = TAF_PS_EVT_ID_BASE + 0x0124,           /* _H2ASN_MsgChoice TAF_PS_GET_PDP_DNS_INFO_CNF_STRU            */

    /* ^TRIG */
    /* ^DWINS */

    /* ^AUTHDATA */
    ID_EVT_TAF_PS_SET_AUTHDATA_INFO_CNF                     = TAF_PS_EVT_ID_BASE + 0x0127,           /* _H2ASN_MsgChoice TAF_PS_SET_AUTHDATA_INFO_CNF_STRU           */
    ID_EVT_TAF_PS_GET_AUTHDATA_INFO_CNF                     = TAF_PS_EVT_ID_BASE + 0x0128,           /* _H2ASN_MsgChoice TAF_PS_GET_AUTHDATA_INFO_CNF_STRU           */

    /* ^DNSQUERY */
    ID_EVT_TAF_PS_GET_NEGOTIATION_DNS_CNF                   = TAF_PS_EVT_ID_BASE + 0x0129,           /* _H2ASN_MsgChoice TAF_PS_GET_NEGOTIATION_DNS_CNF_STRU         */

    /* ^LTECS */
    ID_EVT_TAF_PS_LTECS_INFO_CNF                            = TAF_PS_EVT_ID_BASE + 0x012A,           /* _H2ASN_MsgChoice TAF_PS_LTECS_CNF_STRU                       */

    /* ^PDPROFMOD */
    ID_EVT_TAF_PS_SET_PDP_PROF_INFO_CNF                     = TAF_PS_EVT_ID_BASE + 0x012B,           /* _H2ASN_MsgChoice TAF_PS_SET_PDP_PROF_INFO_CNF_STRU           */

    /* +CEMODE */
    ID_EVT_TAF_PS_CEMODE_INFO_CNF                           = TAF_PS_EVT_ID_BASE + 0x012C,           /* _H2ASN_MsgChoice TAF_PS_CEMODE_CNF_STRU                      */

    /* ????????????SDF???? */
    ID_EVT_TAF_PS_GET_CID_SDF_CNF                           = TAF_PS_EVT_ID_BASE + 0x012D,           /* _H2ASN_MsgChoice TAF_PS_SDF_INFO_CNF_STRU                    */

    /* ???????????????????????? */
    /* ^CQOSPRI */
    ID_EVT_TAF_PS_SET_CQOS_PRI_CNF                          = TAF_PS_EVT_ID_BASE + 0x012E,           /* _H2ASN_MsgChoice TAF_PS_SET_CQOS_PRI_CNF_STRU                */

    /* ^APDSFLOWRPT */
    ID_EVT_TAF_PS_SET_APDSFLOW_RPT_CFG_CNF                  = TAF_PS_EVT_ID_BASE + 0x012F,           /* _H2ASN_MsgChoice TAF_PS_SET_APDSFLOW_RPT_CFG_CNF_STRU */
    ID_EVT_TAF_PS_GET_APDSFLOW_RPT_CFG_CNF                  = TAF_PS_EVT_ID_BASE + 0x0130,           /* _H2ASN_MsgChoice TAF_PS_GET_APDSFLOW_RPT_CFG_CNF_STRU */
    ID_EVT_TAF_PS_APDSFLOW_REPORT_IND                       = TAF_PS_EVT_ID_BASE + 0x0131,           /* _H2ASN_MsgChoice TAF_PS_APDSFLOW_REPORT_IND_STRU */

    ID_EVT_TAF_PS_SET_DSFLOW_NV_WRITE_CFG_CNF               = TAF_PS_EVT_ID_BASE + 0x0132,           /* _H2ASN_MsgChoice TAF_PS_SET_DSFLOW_NV_WRITE_CFG_CNF_STRU */
    ID_EVT_TAF_PS_GET_DSFLOW_NV_WRITE_CFG_CNF               = TAF_PS_EVT_ID_BASE + 0x0133,           /* _H2ASN_MsgChoice TAF_PS_GET_DSFLOW_NV_WRITE_CFG_CNF_STRU */

    /* +CTA */
    ID_EVT_TAF_PS_SET_CTA_INFO_CNF                          = TAF_PS_EVT_ID_BASE + 0x0134,           /* _H2ASN_MsgChoice TAF_PS_SET_CTA_INFO_CNF_STRU */
    ID_EVT_TAF_PS_GET_CTA_INFO_CNF                          = TAF_PS_EVT_ID_BASE + 0x0135,           /* _H2ASN_MsgChoice TAF_PS_GET_CTA_INFO_CNF_STRU */

    /* +CRM */
    ID_EVT_TAF_PS_SET_CDMA_DIAL_MODE_CNF                    = TAF_PS_EVT_ID_BASE + 0x0136,           /* _H2ASN_MsgChoice TAF_PS_CDATA_DIAL_MODE_CNF_STRU                */

    ID_EVT_TAF_PS_GET_CGMTU_VALUE_CNF                       = TAF_PS_EVT_ID_BASE + 0x0137,          /* _H2ASN_MsgChoice TAF_PS_GET_CGMTU_VALUE_CNF_STRU                */
    ID_EVT_TAF_PS_CGMTU_VALUE_CHG_IND                       = TAF_PS_EVT_ID_BASE + 0x0138,          /* _H2ASN_MsgChoice TAF_PS_CGMTU_VALUE_CHG_IND_STRU                */

    /* ^LIMITPDPACT */
    ID_EVT_TAF_PS_CALL_LIMIT_PDP_ACT_IND                    = TAF_PS_EVT_ID_BASE + 0x0139,          /* _H2ASN_MsgChoice TAF_PS_CALL_LIMIT_PDP_ACT_IND_STRU */

    ID_EVT_TAF_PS_SET_IMS_PDP_CFG_CNF                       = TAF_PS_EVT_ID_BASE + 0x013A,           /* _H2ASN_MsgChoice TAF_PS_SET_IMS_PDP_CFG_CNF_STRU */

    /* ^VTFLOWRPT */
    ID_EVT_TAF_PS_REPORT_VTFLOW_IND                         = TAF_PS_EVT_ID_BASE + 0x013B,           /* _H2ASN_MsgChoice TAF_PS_REPORT_VTFLOW_IND_STRU               */

    /* ^VTFLOWRPT */
    ID_EVT_TAF_PS_CONFIG_VTFLOW_RPT_CNF                     = TAF_PS_EVT_ID_BASE + 0x013C,           /* _H2ASN_MsgChoice TAF_PS_CONFIG_VTFLOW_RPT_CNF_STRU           */

    ID_EVT_TAF_PS_SET_1X_DORM_TIMER_CNF                     = TAF_PS_EVT_ID_BASE + 0x013D,           /* _H2ASN_MsgChoice TAF_PS_SET_1X_DORM_TIMER_CNF_STRU */
    ID_EVT_TAF_PS_GET_1X_DORM_TIMER_CNF                     = TAF_PS_EVT_ID_BASE + 0x013E,           /* _H2ASN_MsgChoice TAF_PS_GET_1X_DORM_TIMER_CNF_STRU */

    ID_EVT_TAF_PS_SET_MIP_MODE_CNF                          = TAF_PS_EVT_ID_BASE + 0x013F,           /* _H2ASN_MsgChoice TAF_PS_SET_MIP_MODE_CNF_STRU */
    ID_EVT_TAF_PS_GET_MIP_MODE_CNF                          = TAF_PS_EVT_ID_BASE + 0x0140,           /* _H2ASN_MsgChoice TAF_PS_GET_MIP_MODE_CNF_STRU */


    ID_EVT_TAF_PS_SET_VZWAPNE_CNF                           = TAF_PS_EVT_ID_BASE + 0x0141,           /* _H2ASN_MsgChoice TAF_PS_SET_VZWAPNE_CNF_STRU */
    ID_EVT_TAF_PS_GET_VZWAPNE_CNF                           = TAF_PS_EVT_ID_BASE + 0x0142,           /* _H2ASN_MsgChoice TAF_PS_GET_VZWAPNE_CNF_STRU */
    ID_EVT_TAF_PS_PS_REG_STATUS_IND                         = TAF_PS_EVT_ID_BASE + 0x0143,           /* _H2ASN_MsgChoice TAF_PS_REG_STATUS_IND_STRU*/
    ID_EVT_TAF_PS_PDP_CHG_POLICY_IND                        = TAF_PS_EVT_ID_BASE + 0x0144,           /* _H2ASN_MsgChoice TAF_PS_PDP_TYPE_CHG_POLICY_IND_STRU */
    ID_EVT_TAF_PS_REPORT_PCO_INFO_IND                       = TAF_PS_EVT_ID_BASE + 0x0145,           /* _H2ASN_MsgChoice TAF_PS_REPORT_PCO_INFO_IND_STRU */

    /* ^DATASWITCH */
    ID_EVT_TAF_PS_SET_DATA_SWITCH_CNF                        = TAF_PS_EVT_ID_BASE + 0x0146,           /* _H2ASN_MsgChoice TAF_PS_SET_DATA_SWITCH_CNF_STRU */
    ID_EVT_TAF_PS_GET_DATA_SWITCH_CNF                        = TAF_PS_EVT_ID_BASE + 0x0147,           /* _H2ASN_MsgChoice TAF_PS_GET_DATA_SWITCH_CNF_STRU */

    /* ^DATAROAMSWITCH */
    ID_EVT_TAF_PS_SET_DATA_ROAM_SWITCH_CNF                    = TAF_PS_EVT_ID_BASE + 0x0148,           /* _H2ASN_MsgChoice TAF_PS_SET_DATA_ROAM_SWITCH_CNF_STRU */
    ID_EVT_TAF_PS_GET_DATA_ROAM_SWITCH_CNF                    = TAF_PS_EVT_ID_BASE + 0x0149,           /* _H2ASN_MsgChoice TAF_PS_GET_DATA_ROAM_SWITCH_REQ_STRU */

    ID_EVT_TAF_PS_SET_APN_THROT_INFO_CNF                      = TAF_PS_EVT_ID_BASE + 0x014A,           /* _H2ASN_MsgChoice TAF_PS_SET_APN_THROT_INFO_CNF_STRU */


    ID_EVT_TAF_PS_DATA_SYSTEM_CHG_NTF                         = TAF_PS_EVT_ID_BASE + 0x014B,
    ID_EVT_TAF_PS_APN_DATA_SYS_POLICY_IND                     = TAF_PS_EVT_ID_BASE + 0x014C,

    ID_MSG_TAF_PS_GET_LTE_ATTACH_INFO_CNF                     = TAF_PS_EVT_ID_BASE + 0x014D,

    /* ???????? */
    /* APS->IMSA????SRVCC CANCEL */
    ID_EVT_TAF_PS_SRVCC_CANCEL_NOTIFY_IND                     = TAF_PS_EVT_ID_BASE + 0x0200,           /* _H2ASN_MsgChoice TAF_SRVCC_CANCEL_NOTIFY_IND_STRU */

    ID_EVT_TAF_PS_BUTT
};
typedef VOS_UINT32 TAF_PS_EVT_ID_ENUM_UINT32;




/** ****************************************************************************
 * Name        : TAF_PS_CDATA_BEAR_STATUS_ENUM_UINT8
 *
 * Description :
 *******************************************************************************/
enum TAF_PS_CDATA_BEAR_STATUS_ENUM
{
    TAF_PS_CDATA_BEAR_STATUS_INACTIVE     = 0x00,
    TAF_PS_CDATA_BEAR_STATUS_IDLE         = 0x01,
    TAF_PS_CDATA_BEAR_STATUS_ACTIVE       = 0x02,
    TAF_PS_CDATA_BEAR_STATUS_SUSPEND      = 0x03,
    TAF_PS_CDATA_BEAR_STATUS_BUTT         = 0x04
};
typedef VOS_UINT8 TAF_PS_CDATA_BEAR_STATUS_ENUM_UINT8;


/* ????TAF_AUTH_TYPE_ENUM_UINT8 */


enum TAF_PDP_ACTIVE_STATUS_ENUM
{
    TAF_PDP_INACTIVE                    = 0x00,                                 /*PDP??????*/
    TAF_PDP_ACTIVE                      = 0x01,                                 /*PDP??????*/

    TAF_PDP_ACTIVE_BUTT                 = 0xFF
};
typedef VOS_UINT8 TAF_PDP_ACTIVE_STATUS_ENUM_UINT8;



enum TAF_GPRS_ACTIVE_TYPE_ENUM
{
    TAF_IP_ACTIVE_TE_PPP_MT_PPP_TYPE            = 0x00,
    TAF_PPP_ACTIVE_TE_PPP_MT_NOT_PPP_TYPE       = 0x01,
    TAF_IP_ACTIVE_TE_NOT_PPP_MT_NOT_PPP_TYPE    = 0x02,

    TAF_IP_ACTIVE_TE_BUTT
};
typedef VOS_UINT8 TAF_GPRS_ACTIVE_TYPE_UINT8;



enum TAF_L2P_TYPE_ENUM
{
    TAF_L2P_PPP                         = 0x00,
    TAF_L2P_NULL                        = 0x01,

    TAF_L2P_BUTT
};
typedef VOS_UINT8 TAF_L2P_TYPE_ENUM_UINT8;


/* ????TAF_UMTS_QOS_TRAFFIC_CLASS_ENUM_UINT8 */


enum TAF_DSFLOW_CLEAR_MODE_ENUM
{
    TAF_DSFLOW_CLEAR_TOTAL              = 1,   /*????????RABID??????*/
    TAF_DSFLOW_CLEAR_WITH_RABID,               /*????????RABID??????*/

    TAF_DSFLOW_CLEAR_BUTT
};
typedef VOS_UINT8 TAF_DSFLOW_CLEAR_MODE_ENUM_UINT8;

#if (FEATURE_ON == FEATURE_IMS)
/*****************************************************************************
 ????????: TAF_SRVCC_CANCEL_NOTIFY_ENUM
 ????????: DSM->IMSA????SRVCC CANECL
*****************************************************************************/
enum TAF_SRVCC_CANCEL_NOTIFY_ENUM
{
    TAF_SRVCC_CANCEL_NOTIFY_HO_CANCELLED    = 0,

    TAF_SRVCC_CANCEL_NOTIFY_IND_BUTT
};
typedef VOS_UINT32 TAF_SRVCC_CANCEL_NOTIFY_ENUM_UINT32;

#endif

/* ????TAF_PS_CDATA_1X_QOS_NON_ASSURED_PRI_ENUM_UINT8 */


enum TAF_PS_MIP_MODE_ENUM
{
    TAF_PS_MIP_MODE_SIP_ONLY            = 0x00,                                 /* Simple IP ONLY???? */
    TAF_PS_MIP_MODE_MIP_PREFERED        = 0x01,                                 /* Mobile IP Prefered with SIP fallback ???? */
    TAF_PS_MIP_MODE_MIP_ONLY            = 0x02,                                 /* Mobile IP ONLY????  */
    TAF_PS_MIP_MODE_BUTT
};
typedef VOS_UINT8 TAF_PS_MIP_MODE_ENUM_UINT8;


/* ?????????????????????????????????????? */
/** ****************************************************************************
 * Name        : TAF_PS_CDATA_1X_QOS_NON_ASSURED_PRI_ENUM_UINT8
 *
 * Description : User Priority Adjustment Values
 * Refer to  C.S0017-012-A_v2.0_060522 2.2.8 Table 15
 *******************************************************************************/
enum TAF_PS_CDATA_1X_QOS_NON_ASSURED_PRI_ENUM
{
    TAF_PS_CDATA_1X_QOS_DESIRED_NON_ASSURED_PRI_MIN         = 0x00, /**< min value */
    TAF_PS_CDATA_1X_QOS_DESIRED_NON_ASSURED_PRI_DEFAULT     = 0x0D, /**< default value */
    TAF_PS_CDATA_1X_QOS_DESIRED_NON_ASSURED_PRI_MAX         = 0x0F, /**< max value */
    TAF_PS_CDATA_1X_QOS_NON_ASSURED_PRI_BUTT                = 0x10
};
typedef VOS_UINT8 TAF_PS_CDATA_1X_QOS_NON_ASSURED_PRI_ENUM_UINT8;



enum TAF_PS_IPV6_INFO_RESULT_ENUM
{
    TAF_PS_IPV6_INFO_RESULT_SUCCESS                 = 0x00,                     /* IPV6????????/???????? */
    TAF_PS_IPV6_INFO_RESULT_ALLOC_FAIL              = 0x01,                     /* IPV6???????????? */
    TAF_PS_IPV6_INFO_RESULT_REFRESH_FAIL            = 0x02,                     /* IPV6???????????? */

    TAF_PS_IPV6_INFO_RESULT_BUTT
};
typedef VOS_UINT8 TAF_PS_IPV6_INFO_RESULT_ENUM_UINT8;


enum TAF_PS_ROAMING_LTE_CHG_IP_TYPE_ENUM
{
    TAF_PS_ROAMING_LTE_CHG_IP_TYPE_NO_CHANGE         = 0x00,
    TAF_PS_ROAMING_LTE_CHG_IP_TYPE_IPV4V6_TO_IPV4    = 0x01,
    TAF_PS_ROAMING_LTE_CHG_IP_TYPE_IPV4V6_TO_IPV6    = 0x02,

    TAF_PS_ROAMING_LTE_CHG_IP_TYPE_BUTT
};

typedef VOS_UINT8 TAF_PS_ROAMING_LTE_CHG_IP_TYPE_ENUM_UINT8;


enum TAF_PS_REG_RESUL_ENUM
{
    TAF_PS_REG_RESULT_SUCCESS    = 0,    /*PS??????????*/
    TAF_PS_REG_RESULT_FAILURE    = 1,    /*PS??????????*/
    TAF_PS_REG_RESULT_BUTT
};
typedef VOS_UINT32 TAF_PS_REG_RESUL_ENUM_UINT32;


enum TAF_PS_REG_TYPE_ENUM
{
    TAF_PS_REG_TYPE_ATTACH      = 0,                                        /* PS????????????ATTACH */
    TAF_PS_REG_TYPE_RAU         = 1,                                        /* PS????????????RAU */
    TAF_PS_REG_TYPE_TAU         = 2,                                        /* PS????????????TAU */
    TAF_PS_REG_TYPE_BUTT
};
typedef VOS_UINT32 TAF_PS_REG_TYPE_ENUM_UINT32;


enum TAF_PS_PDN_OPERATE_TYPE_ENUM
{
    TAF_PS_PDN_OPERATE_TYPE_DEACTIVE    = 0,
    TAF_PS_PDN_OPERATE_TYPE_ACTIVE      = 1,
    TAF_PS_PDN_OPERATE_TYPE_MODIFY      = 2,
    TAF_PS_PDN_OPERATE_TYPE_BUTT
};
typedef VOS_UINT8 TAF_PS_PDN_OPERATE_TYPE_ENUM_UINT8;


enum TAF_PS_APN_DATA_SYS_POLICY_ENUM
{
    TAF_PS_APN_DATA_SYS_POLICY_ONLY_CELLULAR              = 0,                    /* ??????CELLULAR */
    TAF_PS_APN_DATA_SYS_POLICY_ONLY_WLAN                  = 1,                    /* ??????WLAN */
    TAF_PS_APN_DATA_SYS_POLICY_CELLULAR_PREFER            = 2,                    /* ????CELLULAR??WLAN??????CELLULAR???? */

    TAF_PS_APN_DATA_SYS_POLICY_BUTT
};
typedef VOS_UINT8 TAF_PS_APN_DATA_SYS_POLICY_ENUM_UINT8;


enum TAF_PS_APN_DATA_SYS_ENUM
{
    TAF_PS_APN_DATA_SYS_NONE                              = 0,                    /* ???????? */
    TAF_PS_APN_DATA_SYS_CELLULAR                          = 1,                    /* ??CELLULAR */
    TAF_PS_APN_DATA_SYS_WLAN                              = 2,                    /* ??WLAN */

    TAF_PS_APN_CURRENT_DOMAIN_BUTT
};
typedef VOS_UINT8 TAF_PS_APN_DATA_SYS_ENUM_UINT8;


enum TAF_PS_APN_DEST_DOMAIN_ENUM
{
    TAF_PS_APN_DEST_DOMAIN_NONE                      = 0,                       /* ???????????????? */
    TAF_PS_APN_DEST_DOMAIN_CELLULAR                  = 1,                       /* ????????????CELLULAR */
    TAF_PS_APN_DEST_DOMAIN_WLAN                      = 2,                       /* ????????????WLAN */
    TAF_PS_APN_DEST_DOMAIN_CELLULAR_WLAN             = 3,                       /* ????????????CELLULAR??WLAN */

    TAF_PS_APN_DEST_DOMAIN_BUTT
};
typedef VOS_UINT8 TAF_PS_APN_DEST_DOMAIN_ENUM_UINT8;


enum TAF_PS_WLAN_SERVICE_STATUS_ENUM
{
    TAF_PS_WLAN_SERVICE_STATUS_NORMAL_SERVICE = 0,                            /* WLAN??????     */
    TAF_PS_WLAN_SERVICE_STATUS_LIMITED_SERVICE,                               /* WLAN?????????? */
    TAF_PS_WLAN_SERVICE_STATUS_NO_SERVICE,                                    /* WLAN????????   */

    TAF_PS_WLAN_SERVICE_BUTT
};
typedef VOS_UINT8 TAF_PS_WLAN_SERVICE_STATUS_ENUM_UINT8;


enum TAF_PS_CELLULAR_SERVICE_STATUS_ENUM
{
    TAF_PS_CELLULAR_SERVICE_STATUS_NORMAL_SERVICE = 0,                            /* CELLULAR??????     */
    TAF_PS_CELLULAR_SERVICE_STATUS_LIMITED_SERVICE,                               /* CELLULAR?????????? */
    TAF_PS_CELLULAR_SERVICE_STATUS_NO_SERVICE,                                    /* CELLULAR????????   */

    TAF_PS_CELLULAR_SERVICE_BUTT
};
typedef VOS_UINT8 TAF_PS_CELLULAR_SERVICE_STATUS_ENUM_UINT8;


enum TAF_PS_CELLULAR_RAT_TYPE_ENUM
{
    TAF_PS_CELLULAR_RAT_TYPE_GSM              =0,
    TAF_PS_CELLULAR_RAT_TYPE_UTRAN,
    TAF_PS_CELLULAR_RAT_TYPE_LTE,
    TAF_PS_CELLULAR_RAT_TYPE_CDMA_1X,

    TAF_PS_CELLULAR_RAT_TYPE_BUTT
};
typedef VOS_UINT8 TAF_PS_CELLULAR_RAT_TYPE_ENUM_UINT8;

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


typedef struct
{
    MSG_HEADER_STRU                     stHeader;
    VOS_UINT32                          ulEvtId;
    VOS_UINT8                           aucContent[4];

} TAF_PS_EVT_STRU;



typedef struct
{
    VOS_UINT32                          ulDSLinkTime;                           /* DS???????? */
    VOS_UINT32                          ulDSSendFluxLow;                        /* DS?????????????????? */
    VOS_UINT32                          ulDSSendFluxHigh;                       /* DS?????????????????? */
    VOS_UINT32                          ulDSReceiveFluxLow;                     /* DS?????????????????? */
    VOS_UINT32                          ulDSReceiveFluxHigh;                    /* DS?????????????????? */

} TAF_DSFLOW_INFO_STRU;



typedef struct
{
    VOS_UINT32                          ulCurrentSendRate;                      /*????????????*/
    VOS_UINT32                          ulCurrentReceiveRate;                   /*????????????*/
    VOS_UINT32                          ulQosSendRate;                          /*QOS????????????*/
    VOS_UINT32                          ulQosReceiveRate;                       /*QOS????????????*/
    TAF_DSFLOW_INFO_STRU                stCurrentFlowInfo;                      /*????????????????*/

} TAF_DSFLOW_REPORT_STRU;


typedef TAF_DSFLOW_INFO_STRU            TAF_VTFLOW_REPORT_STRU;


typedef struct
{
    TAF_DSFLOW_INFO_STRU                stCurrentFlowInfo;  /*????????????????*/
    TAF_DSFLOW_INFO_STRU                stTotalFlowInfo;    /*????????????*/

} TAF_DSFLOW_QUERY_INFO_STRU;






typedef struct
{
    TAF_PDP_AUTH_TYPE_ENUM_UINT8        enAuth;                                   /*??????????????????????????????????????????????*/

    VOS_UINT8                           aucReserved[3];

    /* aucUserName[0]?????????????? */
    VOS_UINT8                           aucUserName[TAF_MAX_AUTHDATA_USERNAME_LEN + 1];

    /* aucPassword[0]???????????? */
    VOS_UINT8                           aucPassword[TAF_MAX_AUTHDATA_PASSWORD_LEN + 1];

} TAF_PDP_AUTH_STRU;








typedef struct
{
    VOS_UINT8                           ucCid;
    VOS_UINT8                           aucReserved[3];
    TAF_PDP_PRIM_CONTEXT_STRU           stPriPdpInfo;

}TAF_PRI_PDP_QUERY_INFO_STRU;



typedef struct
{
    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucPfNum;                                /* pf???? */
    VOS_UINT8                           aucReserved[2];
    TAF_PDP_PF_STRU                     astPfInfo[TAF_MAX_SDF_PF_NUM];          /* pf?? */

}TAF_TFT_QUREY_INFO_STRU;


typedef struct
{
    VOS_UINT8                           ucCid;
    VOS_UINT8                           aucReserved[3];
    TAF_UMTS_QOS_STRU                   stQosInfo;

} TAF_UMTS_QOS_QUERY_INFO_STRU;



typedef struct
{
    VOS_UINT8                           ucCid;
    VOS_UINT8                           aucReserved[3];
    TAF_PDP_DNS_STRU                    stDnsInfo;

}TAF_DNS_QUERY_INFO_STRU;


typedef struct
{
    VOS_UINT8                           ucCid;
    VOS_UINT8                           aucReserved[3];
    TAF_PDP_AUTH_STRU                   stAuthInfo;

}TAF_AUTH_QUERY_INFO_STRU;


typedef struct
{
    VOS_UINT8                           ucCid;
    VOS_UINT8                           aucReserved[3];
    TAF_PDP_AUTHDATA_STRU               stAuthDataInfo;

}TAF_AUTHDATA_QUERY_INFO_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT32                          bitOpLinkdRabId     : 1;
    VOS_UINT32                          bitOpPdpAddr        : 1;
    VOS_UINT32                          bitOpApn            : 1;
    VOS_UINT32                          bitOpEmergencyInd   : 1;
    VOS_UINT32                          bitOpImCnSignalFlg  : 1;
    VOS_UINT32                          bitOpCause          : 1;
    VOS_UINT32                          bitOpUmtsQos        : 1;
    VOS_UINT32                          bitOpEpsQos         : 1;
    VOS_UINT32                          bitOpTft            : 1;
    VOS_UINT32                          bitOpIpv4Mtu        : 1;
    VOS_UINT32                          bitOpCustomPco      : 1; /* ????VERRIZON??????????,????FF00H?????????? 1:???? 0:?????? */
    VOS_UINT32                          bitOpEpdgInfo       : 1; /* ????R1??????????,??EPDG??????????APS??,????EPDG?????????????????? 1:???? 0:?????? */
    VOS_UINT32                          bitOpLinkedQfi      : 1;
    VOS_UINT32                          bitOpNrQos          : 1;
    VOS_UINT32                          bitOpSpare          : 18;

    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucRabId;
    VOS_UINT8                           ucLinkdRabId;
    TAF_PDP_EMC_IND_ENUM_UINT8          enEmergencyInd;
    TAF_PDP_IM_CN_SIG_FLAG_ENUM_UINT8   enImCnSignalFlg;

    VOS_UINT8                           ucPduSessionId;
    VOS_UINT8                           ucQfi;
    VOS_UINT8                           ucLinkedQfi;
    TAF_PS_CAUSE_ENUM_UINT32            enCause;

    TAF_PDP_ADDR_STRU                   stPdpAddr;
    TAF_PDP_APN_STRU                    stApn;
    TAF_UMTS_QOS_STRU                   stUmtsQos;
    TAF_EPS_QOS_STRU                    stEpsQos;
    TAF_PS_NR_QOS_STRU                  stNrQos;

    TAF_PDP_DNS_STRU                    stDns;
    TAF_PDP_NBNS_STRU                   stNbns;

    TAF_PDP_IPV4_PCSCF_LIST_STRU        stIpv4PcscfList;

    TAF_PDP_GATEWAY_STRU                stGateWay;
    TAF_PDP_IPV6_DNS_STRU               stIpv6Dns;

    TAF_PDP_IPV6_PCSCF_LIST_STRU        stIpv6PcscfList;

    TAF_PDP_TFT_STRU                    stTft;

    VOS_UINT16                          usIpv4Mtu;
    VOS_UINT8                           aucReserved1[2];

    TAF_PS_CUSTOM_PCO_INFO_STRU         stCustomPcoInfo;

    TAF_EPDG_INFO_STRU                  stEpdgInfo;

} TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU;



typedef TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU TAF_PS_CALL_PDP_ACTIVATE_IND_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT32                          bitOpCauseEx        : 1;
    VOS_UINT32                          bitOpSpare          : 31;

    VOS_UINT8                           ucCid;
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType;
    VOS_UINT8                           aucReserved[2];
    TAF_PS_CAUSE_ENUM_UINT32            enCause;

    /*----------------------------------------------------------------------
       enCauseEx????????:
       enPdpType??IPv4/IPv6/PPP.

       enCauseEx??????????:
       TAF_PS_CAUSE_SM_NW_PDP_TYPE_IPV4_ONLY_ALLOWED
       TAF_PS_CAUSE_SM_NW_PDP_TYPE_IPV6_ONLY_ALLOWED
       TAF_PS_CAUSE_SM_NW_SINGLE_ADDR_BEARERS_ONLY_ALLOWED

       enCauseEx????????:
       ????????????????????????(IPv4v6), TAF??????REJECT????, ????enPdpType
       ??????(IPv4/IPv6), ????????????enCauseEx, ????????????????????????.

       enCauseEx????????:
       ????????????????????????(IPv4v6), ????????IPv4????????, ??????????????
       TAF_PS_CAUSE_SM_NW_SINGLE_ADDR_BEARERS_ONLY_ALLOWED, ????????????????
       ????QOS, ????????????, TAF????REJECT????, IP??????IPv4, enCause??
       QOS_NOT_ACCEPT, enCauseEx??TAF_PS_CAUSE_SM_NW_SINGLE_ADDR_BEARERS_ONLY_ALLOWED,
       ????????????????IPv6????????????.
    *---------------------------------------------------------------------*/
    TAF_PS_CAUSE_ENUM_UINT32            enCauseEx;

} TAF_PS_CALL_PDP_ACTIVATE_REJ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT32                          bitOpApn            : 1;
    VOS_UINT32                          bitOpPdpAddr        : 1;
    VOS_UINT32                          bitLinkdRabId       : 1;
    VOS_UINT32                          bitEmergencyInd     : 1;
    VOS_UINT32                          bitImCnSignalFlg    : 1;
    VOS_UINT32                          bitOpSpare          : 27;

    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucRabId;
    VOS_UINT8                           ucLinkdRabId;
    TAF_PDP_EMC_IND_ENUM_UINT8          enEmergencyInd;
    TAF_PDP_IM_CN_SIG_FLAG_ENUM_UINT8   enImCnSignalFlg;
    VOS_UINT8                           aucReserved[3];

    TAF_PDP_ADDR_STRU                   stPdpAddr;
    TAF_PDP_APN_STRU                    stApn;

} TAF_PS_CALL_PDP_MANAGE_IND_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT32                          bitOpLinkdRabId     : 1;
    VOS_UINT32                          bitOpLinkedQfi      : 1;
    VOS_UINT32                          bitOpUmtsQos        : 1;
    VOS_UINT32                          bitOpEpsQos         : 1;
    VOS_UINT32                          bitOpNrQos          : 1;
    VOS_UINT32                          bitOpTft            : 1;
    VOS_UINT32                          bitOpIpv4Mtu        : 1;
    VOS_UINT32                          bitOpCustomPco      : 1; /* ????VERRIZON??????????,????FF00H?????????? 1:???? 0:?????? */
    VOS_UINT32                          bitOpSpare          : 24;

    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucRabId;
    VOS_UINT8                           ucLinkdRabId;
    VOS_UINT8                           ucPduSessionId;
    VOS_UINT8                           ucQfi;
    VOS_UINT8                           ucLinkedQfi;
    VOS_UINT8                           aucReserved[2];

    TAF_UMTS_QOS_STRU                   stUmtsQos;
    TAF_EPS_QOS_STRU                    stEpsQos;
    TAF_PS_NR_QOS_STRU                  stNrQos;

    TAF_PDP_DNS_STRU                    stDns;
    TAF_PDP_NBNS_STRU                   stNbns;

    TAF_PDP_IPV4_PCSCF_LIST_STRU        stIpv4PcscfList;

    TAF_PDP_IPV6_DNS_STRU               stIpv6Dns;

    TAF_PDP_IPV6_PCSCF_LIST_STRU        stIpv6PcscfList;

    TAF_PDP_TFT_STRU                    stTft;

    VOS_UINT16                          usIpv4Mtu;
    VOS_UINT8                           aucReserved1[2];

    TAF_PS_CUSTOM_PCO_INFO_STRU         stCustomPcoInfo;
} TAF_PS_CALL_PDP_MODIFY_CNF_STRU;


typedef TAF_PS_CALL_PDP_MODIFY_CNF_STRU TAF_PS_CALL_PDP_MODIFY_IND_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucRabId;
    VOS_UINT8                           ucPduSessionId;
    VOS_UINT8                           ucQfi;
    TAF_PS_CAUSE_ENUM_UINT32            enCause;

} TAF_PS_CALL_PDP_MODIFY_REJ_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT32                          bitOpCustomPco      : 1; /* ????VERRIZON??????????,????FF00H?????????? 1:???? 0:?????? */
    VOS_UINT32                          bitOpSpare          : 31;

    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucRabId;
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType;

    VOS_UINT8                           ucPduSessionId;
    VOS_UINT8                           ucQfi;
    VOS_UINT8                           aucReserved[3];
    TAF_PS_CAUSE_ENUM_UINT32            enCause;

    TAF_PS_CUSTOM_PCO_INFO_STRU         stCustomPcoInfo;
} TAF_PS_CALL_PDP_DEACTIVATE_CNF_STRU;



typedef TAF_PS_CALL_PDP_DEACTIVATE_CNF_STRU TAF_PS_CALL_PDP_DEACTIVATE_IND_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

} TAF_PS_CALL_PDP_PDP_DISCONNECT_IND_STRU;


typedef struct
{
    TAF_CTRL_STRU                           stCtrl;
    VOS_UINT8                               ucLimitFlg;                         /* 1:????PDP???? 0:????PDP????*/
    VOS_UINT8                               aucReserve[3];
    TAF_PS_CAUSE_ENUM_UINT32                enCause;                            /* PDP????????????????????FLG??1????????FLG??0????CAUSE????????0 */
}TAF_PS_CALL_LIMIT_PDP_ACT_IND_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
} TAF_PS_COMMON_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_COMMON_REQ_STRU;


typedef struct
{
    VOS_UINT32                          bitOpPdpType        : 1;                /* PdpType*/
    VOS_UINT32                          bitOpApn            : 1;                /* aucApn*/
    VOS_UINT32                          bitOpPdpAddr        : 1;                /* aucPdpAddr*/
    VOS_UINT32                          bitOpPdpDcomp       : 1;                /* PdpDcomp*/
    VOS_UINT32                          bitOpPdpHcomp       : 1;                /* PdpHcomp*/
    VOS_UINT32                          bitOpIpv4AddrAlloc  : 1;                /* Ipv4AddrAlloc*/
    VOS_UINT32                          bitOpEmergencyInd   : 1;                /* Emergency Indication*/
    VOS_UINT32                          bitOpPcscfDiscovery : 1;                /* P-CSCF discovery */
    VOS_UINT32                          bitOpImCnSignalFlg  : 1;                /* IM CN Signalling Flag */
    VOS_UINT32                          bitOpNasSigPrioInd  : 1;                /* Nas Signaling Low pri Ind */
    VOS_UINT32                          bitOpSpare          : 22;

    VOS_UINT8                           ucDefined;                              /* 0:undefined, 1:defined */

    VOS_UINT8                           ucCid;

    /* 1 IP Internet Protocol (IETF STD 5) */
    /* 2 IPV6 Internet Protocol, version 6 (IETF RFC 2460) */
    /* 3 IPV4V6 Virtual <PDP_type> introduced to handle dual IP stack UE capability. (See 3GPP TS 24.301 [83]) */
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType;

    VOS_UINT8                           aucReserved[1];

    /* Access Point Name*/
    VOS_UINT8                           aucApn[TAF_MAX_APN_LEN + 1];

    /* the MT in the address space applicable to the PDP.*/
    TAF_PDP_ADDR_STRU                   stPdpAddr;

    /* 0 - off  (default if value is omitted) */
    /* 1 - on (manufacturer preferred compression) */
    /* 2 - V.42bis */
    /* 3 - V.44 */
    TAF_PDP_D_COMP_ENUM_UINT8           enPdpDcomp;

    /* 0 - off (default if value is omitted) */
    /* 1 - on (manufacturer preferred compression) */
    /* 2 - RFC1144 (applicable for SNDCP only) */
    /* 3 - RFC2507*/
    /* 4 - RFC3095 (applicable for PDCP only)*/
    TAF_PDP_H_COMP_ENUM_UINT8           enPdpHcomp;

    /* 0 - IPv4 Address Allocation through NAS Signaling (default if omitted) */
    /* 1 - IPv4 Address Allocated through DHCP */
    TAF_PDP_IPV4_ADDR_ALLOC_TYPE_ENUM_UINT8 enIpv4AddrAlloc;

    /* 0 - PDP context is not for emergency bearer services */
    /* 1 - PDP context is for emergency bearer services */
    TAF_PDP_EMC_IND_ENUM_UINT8          enEmergencyFlg;

    /* 0 - Preference of P-CSCF address discovery not influenced by +CGDCONT */
    /* 1 - Preference of P-CSCF address discovery through NAS Signalling */
    /* 2 - Preference of P-CSCF address discovery through DHCP */
    TAF_PDP_PCSCF_DISCOVERY_ENUM_UINT8  enPcscfDiscovery;

    /* 0 - UE indicates that the PDP context is not for IM CN subsystem-related signalling only */
    /* 1 - UE indicates that the PDP context is for IM CN subsystem-related signalling only */
    TAF_PDP_IM_CN_SIG_FLAG_ENUM_UINT8   enImCnSignalFlg;

    /* 0 - Indicates that this PDP context is to be activated with the value for the low priority indicator
           configured in the MT.
       1 - Indicates that this PDP context is to be activated with the value for the low priority indicator
           set to "MS is not configured for NAS signalling low priority". */
    TAF_PDP_NAS_SIG_PRIO_IND_ENUM_UINT8 enNasSigPrioInd;

    VOS_UINT8                           aucReserved2[1];

}TAF_PDP_PRIM_CONTEXT_EXT_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PDP_PRIM_CONTEXT_EXT_STRU       stPdpContextInfo;
} TAF_PS_SET_PRIM_PDP_CONTEXT_INFO_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_PRIM_PDP_CONTEXT_INFO_CNF_STRU;


typedef struct
{
    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucImsFlag;
    VOS_UINT8                           aucReserved[2];
} TAF_IMS_PDP_CFG_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_IMS_PDP_CFG_STRU                stImsPdpCfg;
} TAF_PS_SET_IMS_PDP_CFG_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_IMS_PDP_CFG_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT8                           ucDormantTimer;
    VOS_UINT8                           aucReserved[3];
}TAF_PS_SET_1X_DORM_TIMER_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_1X_DORM_TIMER_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
}TAF_PS_GET_1X_DORM_TIMER_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT8                           ucSocmDormTiVal;
    VOS_UINT8                           ucUserCfgDormTival;
    VOS_UINT8                           aucReserved[2];
}TAF_PS_GET_1X_DORM_TIMER_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_PRIM_PDP_CONTEXT_INFO_REQ_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_PRI_PDP_QUERY_INFO_STRU         astPdpContextQueryInfo[0]; //lint !e43
} TAF_PS_GET_PRIM_PDP_CONTEXT_INFO_CNF_STRU;

/*****************************************************************************
 ???? : ???????? +CGDSCONT
 ID   : ID_MSG_TAF_PS_SET_SEC_PDP_CONTEXT_INFO_REQ
        ID_MSG_TAF_PS_SET_SEC_PDP_CONTEXT_INFO_CNF
        ID_MSG_TAF_PS_GET_SEC_PDP_CONTEXT_INFO_REQ
        ID_MSG_TAF_PS_GET_SEC_PDP_CONTEXT_INFO_CNF
 REQ  : TAF_PS_SET_SEC_PDP_CONTEXT_INFO_REQ_STRU; TAF_PS_GET_SEC_PDP_CONTEXT_INFO_REQ_STRU
 CNF  : TAF_PS_SET_SEC_PDP_CONTEXT_INFO_CNF_STRU; TAF_PS_GET_SEC_PDP_CONTEXT_INFO_CNF_STRU
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          bitOpLinkdCid       : 1;
    VOS_UINT32                          bitOpPdpDcomp       : 1;
    VOS_UINT32                          bitOpPdpHcomp       : 1;
    VOS_UINT32                          bitOpImCnSignalFlg  : 1;
    VOS_UINT32                          bitOpSpare          : 28;

    VOS_UINT8                           ucDefined;          /* 0:undefined, 1:defined */
    VOS_UINT8                           ucCid;              /* dedicated EPS Bearer context */
    VOS_UINT8                           ucLinkdCid;         /* Default EPS Bearer context */
    TAF_PDP_D_COMP_ENUM_UINT8           enPdpDcomp;         /* no used in LTE */
    TAF_PDP_H_COMP_ENUM_UINT8           enPdpHcomp;         /* no used in LTE */
    /* 0 - UE indicates that the PDP context is not for IM CN subsystem-related signalling only */
    /* 1 - UE indicates that the PDP context is for IM CN subsystem-related signalling only */
    TAF_PDP_IM_CN_SIG_FLAG_ENUM_UINT8   enImCnSignalFlg;
    VOS_UINT8                           aucReserved[2];

} TAF_PDP_SEC_CONTEXT_EXT_STRU;



typedef struct
{
    VOS_UINT8                           ucCid;              /* [1??11] */
    VOS_UINT8                           ucLinkdCid;         /* [1??11] */
    TAF_PDP_D_COMP_ENUM_UINT8           enPdpDcomp;         /*????????????*/
    TAF_PDP_H_COMP_ENUM_UINT8           enPdpHcomp;         /*??????????*/

    TAF_PDP_IM_CN_SIG_FLAG_ENUM_UINT8   enImCnSignalFlg;
    VOS_UINT8                           aucReserved[3];

}TAF_PDP_SEC_CONTEXT_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PDP_SEC_CONTEXT_EXT_STRU        stPdpContextInfo;

} TAF_PS_SET_SEC_PDP_CONTEXT_INFO_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_SEC_PDP_CONTEXT_INFO_CNF_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_SEC_PDP_CONTEXT_INFO_REQ_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_PDP_SEC_CONTEXT_STRU            astPdpContextQueryInfo[0]; //lint !e43
} TAF_PS_GET_SEC_PDP_CONTEXT_INFO_CNF_STRU;



typedef struct
{
    VOS_UINT8                           aucCid[TAF_MAX_CID + 1];
} TAF_CID_LIST_STRU;


typedef struct
{
    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucState;
    TAF_PS_BEARER_TYPE_ENUM_UINT8       enBearerType;
    VOS_UINT8                           aucReserved[1];
} TAF_CID_STATE_STRU;


typedef struct
{
    VOS_UINT8                           ucState;                                /* 0 - deactivated,1 - activated */
    VOS_UINT8                           aucReserved[3];

    VOS_UINT8                           aucCid[TAF_MAX_CID + 1];
} TAF_CID_LIST_STATE_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_CID_LIST_STATE_STRU             stCidListStateInfo;
} TAF_PS_SET_PDP_STATE_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
} TAF_PS_SET_PDP_STATE_CNF_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_PDP_STATE_REQ_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_CID_STATE_STRU                  astCidStateInfo[0]; //lint !e43
} TAF_PS_GET_PDP_STATE_CNF_STRU;


/*****************************************************************************
 ???? : ???????? +CGTFT
 ID   : ID_MSG_L4A_SET_CGTFT_REQ
        ID_MSG_L4A_SET_CGTFT_CNF
        ID_MSG_L4A_READ_CGTFT_REQ
        ID_MSG_L4A_READ_CGTFT_CNF
 REQ  : L4A_SET_CGTFT_REQ_STRU;L4A_READ_CGTFT_REQ_STRU;
 CNF  : L4A_SET_CGTFT_CNF_STRU;L4A_READ_CGTFT_CNF_STRU;
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          bitOpPktFilterId    : 1;    /* ucPacketFilterId*/
    VOS_UINT32                          bitOpPrecedence     : 1;    /* ucPrecedence*/
    VOS_UINT32                          bitOpSrcIp          : 1;    /* aucSourceIpAddr,Mask*/
    VOS_UINT32                          bitOpProtocolId     : 1;    /* ucProtocolId*/
    VOS_UINT32                          bitOpDestPortRange  : 1;    /* destination port range*/
    VOS_UINT32                          bitOpSrcPortRange   : 1;    /* source port range*/
    VOS_UINT32                          bitOpSpi            : 1;    /* ipsec security parameter index*/
    VOS_UINT32                          bitOpTosMask        : 1;    /* type of service*/
    VOS_UINT32                          bitOpFlowLable      : 1;    /* ulFlowLable*/
    VOS_UINT32                          bitOpDirection      : 1;    /* Direction*/
    VOS_UINT32                          bitOpNwPktFilterId  : 1;    /* NWPacketFltId*/
    VOS_UINT32                          bitOpLocalIpv4AddrAndMask      : 1;
    VOS_UINT32                          bitOpLocalIpv6AddrAndMask      : 1;
    VOS_UINT32                          bitOpSpare          : 19;

    VOS_UINT8                           ucCid;

    VOS_UINT8                           ucDefined;

    VOS_UINT8                           ucPacketFilterId;       /* Packet Filter Id,value range from 1 to 16*/

    VOS_UINT8                           ucPrecedence;           /* evaluation precedence index,The value range is from 0 to 255*/

    VOS_UINT8                           ucProtocolId;           /* protocol number,value range from 0 to 255*/

    VOS_UINT8                           aucReserved[3];

    /* source address and subnet mask*/
    TAF_PDP_ADDR_STRU                   stSourceIpaddr;
    TAF_PDP_ADDR_STRU                   stSourceIpMask;

    /* destination port range*/
    VOS_UINT16                          usLowDestPort;                          /* value range from 0 to 65535*/
    VOS_UINT16                          usHighDestPort;                         /* value range from 0 to 65535*/

    /* source port range*/
    VOS_UINT16                          usLowSourcePort;                        /* value range from 0 to 65535*/
    VOS_UINT16                          usHighSourcePort;                       /* value range from 0 to 65535*/

    /* ipsec security parameter index*/
    VOS_UINT32                          ulSecuParaIndex;

    /* only for ipv6*/
    VOS_UINT32                          ulFlowLable;                            /* value range is from 00000 to FFFFF*/

    /* type of service*/
    VOS_UINT8                           ucTypeOfService;                        /* value range from 0 to 255*/
    VOS_UINT8                           ucTypeOfServiceMask;                    /* value range from 0 to 255*/

    /* 0 - Pre-Release 7 TFT filter (see 3GPP TS 24.008 [8], table 10.5.162)*/
    /* 1 - Uplink*/
    /* 2 - Downlink*/
    /* 3 - Birectional (Up & Downlink) (default if omitted)*/
    VOS_UINT8                           ucDirection;

    /* only for CGTFTRDP*/
    VOS_UINT8                           ucNwPktFilterId;                        /* value range from 1 to 16*/

    /* local address and subnet mask*/
    VOS_UINT8                           aucLocalIpv4Addr[TAF_IPV4_ADDR_LEN];
    VOS_UINT8                           aucLocalIpv4Mask[TAF_IPV4_ADDR_LEN];
    VOS_UINT8                           aucLocalIpv6Addr[TAF_IPV6_ADDR_LEN];
    VOS_UINT8                           ucLocalIpv6Prefix;
    VOS_UINT8                           aucReserved2[3];
} TAF_TFT_EXT_STRU;

typedef struct
{
    VOS_UINT32                          ulCid;
    VOS_UINT32                          ulPFNum;
    TAF_TFT_EXT_STRU                    astTftInfo[TAF_MAX_SDF_PF_NUM];
} TAF_PF_TFT_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_TFT_EXT_STRU                    stTftInfo;
} TAF_PS_SET_TFT_INFO_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_TFT_INFO_CNF_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_TFT_INFO_REQ_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_TFT_QUREY_INFO_STRU             astTftQueryInfo[0]; //lint !e43
} TAF_PS_GET_TFT_INFO_CNF_STRU;


/*****************************************************************************
 ???? : ???????? +CGEQREQ
 ID   :



 REQ  :
 CNF  :
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          bitOpTrafficClass       : 1;
    VOS_UINT32                          bitOpDeliverOrder       : 1;
    VOS_UINT32                          bitOpDeliverErrSdu      : 1;
    VOS_UINT32                          bitOpMaxSduSize         : 1;
    VOS_UINT32                          bitOpMaxBitUl           : 1;
    VOS_UINT32                          bitOpMaxBitDl           : 1;
    VOS_UINT32                          bitOpResidualBer        : 1;
    VOS_UINT32                          bitOpSduErrRatio        : 1;
    VOS_UINT32                          bitOpTransDelay         : 1;
    VOS_UINT32                          bitOpTraffHandlePrior   : 1;
    VOS_UINT32                          bitOpGtdBitUl           : 1;
    VOS_UINT32                          bitOpGtdBitDl           : 1;
    VOS_UINT32                          bitOpSrcStatisticsDes   : 1;
    VOS_UINT32                          bitOpSignalIndication   : 1;
    VOS_UINT32                          bitOpSpare              : 18;

    VOS_UINT8                           ucDefined;

    VOS_UINT8                           ucCid;

    VOS_UINT8                           ucTrafficClass;     /* 0 : Conversational class
                                                               1 : Streaming class
                                                               2 : Interactive class
                                                               3 : Background class
                                                               4 : Subscribed value */
    VOS_UINT8                           ucSduErrRatio;      /* 0 : subscribed value
                                                               1 : 1*10-2
                                                               2 : 7*10-3
                                                               3 : 1*10-3
                                                               4 : 1*10-4
                                                               5 : 1*10-5
                                                               6 : 1*10-6
                                                               7 : 1*10-1 */
    VOS_UINT16                          usMaxSduSize;       /* 0 : Subscribed value
                                                               1~1520: 1 ~1520 octets */

    VOS_UINT8                           ucDeliverOrder;     /* 0 : Without delivery order
                                                               1 : With delivery order
                                                               2 : Subscribed value */

    VOS_UINT8                           ucDeliverErrSdu;    /* 0 : Erroneous SDUs are not delivered
                                                               1 : Erroneous SDUs are delivered
                                                               2 : No detect
                                                               3 : subscribed value */

    VOS_UINT32                          ulMaxBitUl;         /* 0 : Subscribed value
                                                               1~256000: 1kbps ~ 256000kbps*/
    VOS_UINT32                          ulMaxBitDl;         /* ??ulMaxBitUl */
    VOS_UINT32                          ulGtdBitUl;         /* ??ulMaxBitUl */
    VOS_UINT32                          ulGtdBitDl;         /* ??ulMaxBitUl */
    VOS_UINT8                           ucResidualBer;      /* 0 : subscribed value
                                                               1 : 5*10-2
                                                               2 : 1*10-2
                                                               3 : 5*10-3
                                                               4 : 4*10-3
                                                               5 : 1*10-3
                                                               6 : 1*10-4
                                                               7 : 1*10-5
                                                               8 : 1*10-6
                                                               9 : 6*10-8 */
    VOS_UINT8                           ucTraffHandlePrior; /* 0 : Subscribed value
                                                               1 : Priority level 1
                                                               2 : Priority level 2
                                                               3 : Priority level 3 */
    VOS_UINT16                          usTransDelay;       /* 0 : Subscribed value
                                                               1~4100 : 1ms~4100ms */

    VOS_UINT8                           ucSrcStatisticsDes; /* 0: Characteristics of SDUs is unknown
                                                               1: Characteristics of SDUs corresponds to a speech source */

    VOS_UINT8                           ucSignalIndication; /* 0: PDP context is not optimized for signalling
                                                               1: PDP context is optimized for signalling */

    VOS_UINT8                           aucReserved[2];

} TAF_UMTS_QOS_EXT_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_UMTS_QOS_EXT_STRU               stUmtsQosInfo;
} TAF_PS_SET_UMTS_QOS_INFO_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_UMTS_QOS_INFO_CNF_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_UMTS_QOS_INFO_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_UMTS_QOS_QUERY_INFO_STRU        astUmtsQosQueryInfo[0]; //lint !e43
} TAF_PS_GET_UMTS_QOS_INFO_CNF_STRU;


/*****************************************************************************
 ???? : ???????? +CGEQMIN
 ID   :



 REQ  :
 CNF  :
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_UMTS_QOS_EXT_STRU               stUmtsQosMinInfo;
} TAF_PS_SET_UMTS_QOS_MIN_INFO_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_UMTS_QOS_MIN_INFO_CNF_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_UMTS_QOS_MIN_INFO_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_UMTS_QOS_QUERY_INFO_STRU        astUmtsQosQueryInfo[0]; //lint !e43
} TAF_PS_GET_UMTS_QOS_MIN_INFO_CNF_STRU;


/*****************************************************************************
 ???? : ???????? +CGEQNEG
 ID   :



 REQ  :
 CNF  :
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_CID_LIST_STRU                   stCidListInfo;
} TAF_PS_GET_DYNAMIC_UMTS_QOS_INFO_REQ_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_UMTS_QOS_QUERY_INFO_STRU        astUmtsQosQueryInfo[0]; //lint !e43
} TAF_PS_GET_DYNAMIC_UMTS_QOS_INFO_CNF_STRU;


/*****************************************************************************
 ???? : ???????? +CGMOD
 ID   :



 REQ  :
 CNF  :
 IND  : -
 ???? : ...
*****************************************************************************/

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_CID_LIST_STRU                   stCidListInfo;
} TAF_PS_CALL_MODIFY_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_CALL_MODIFY_CNF_STRU;


/*****************************************************************************
 ???? : ???????? +CGANS
 ID   : ID_MSG_L4A_SET_CGANS_RSP
        ID_MSG_L4A_SET_CGANS_CNF
        ID_MSG_L4A_CGANS_IND
 RSP  : L4A_SET_CGANS_RSP_STRU
 CNF  : L4A_SET_CGANS_CNF_STRU
 IND  : L4A_CGANS_IND_STRU
 ???? : L4A_CGANS_IND_STRU ??????????????,??????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT8                           ucL2P[20];
    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucAnsExtFlg;                            /* ??????^CGANS????????VOS_TRUE????????VOS_FALSE */
    VOS_UINT8                           aucReserved[2];
} TAF_PS_ANSWER_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_ANSWER_STRU                  stAnsInfo;
} TAF_PS_CALL_ANSWER_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;

    VOS_UINT8                           ucCid;

    VOS_UINT8                           aucReserved[3];
}TAF_PS_CALL_ANSWER_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_CALL_HANGUP_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_CALL_HANGUP_CNF_STRU;


/*****************************************************************************
 ???? : ???????? +CGPADDR
 ID   :


 REQ  :
 CNF  :
 IND  : -
 ???? : ...
*****************************************************************************/
/*****************************************************************************
 ????????   : TAF_PDP_ADDR_STRU
 ????????   :
 ????????   :
*****************************************************************************/

typedef struct
{
    VOS_UINT8                           ucCid;
    VOS_UINT8                           aucReserved[3];

    /* the MT in the address space applicable to the PDP */
    TAF_PDP_ADDR_STRU                   stPdpAddr;
} TAF_PDP_ADDR_QUERY_INFO_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_CID_LIST_STRU                   stCidListInfo;
} TAF_PS_GET_PDP_IP_ADDR_INFO_REQ_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_PDP_ADDR_QUERY_INFO_STRU        astPdpAddrQueryInfo[0]; //lint !e43
} TAF_PS_GET_PDP_IP_ADDR_INFO_CNF_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    VOS_UINT32                          ulCid[TAF_MAX_CID+1];
} TAF_PS_GET_PDP_CONTEXT_INFO_CNF_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_PDP_CONTEXT_INFO_REQ_STRU;

/*****************************************************************************
 ???? : ???????? +CGAUTO
 ID   : ID_MSG_L4A_SET_CGAUTO_REQ
        ID_MSG_L4A_SET_CGAUTO_CNF
        ID_MSG_L4A_READ_CGAUTO_REQ
        ID_MSG_L4A_READ_CGAUTO_CNF
 REQ  : L4A_SET_CGAUTO_REQ_STRU; L4A_READ_CGAUTO_REQ_STRU
 CNF  : L4A_SET_CGAUTO_CNF_STRU; L4A_READ_CGAUTO_CNF_STRU
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT32                          ulAnsMode;
} TAF_PS_SET_ANSWER_MODE_INFO_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_ANSWER_MODE_INFO_CNF_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_ANSWER_MODE_INFO_REQ_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulAnsMode;
} TAF_PS_GET_ANSWER_MODE_INFO_CNF_STRU;


/*****************************************************************************
 ???? : ???????? +CGCONTRDP
 ID   : ID_MSG_L4A_SET_CGCONTRDP_REQ
        ID_MSG_L4A_SET_CGCONTRDP_CNF
 REQ  : L4A_SET_CGCONTRDP_REQ_STRU
 CNF  : L4A_SET_CGCONTRDP_CNF_STRU
 IND  : -
 ???? : ...
******************************************************************************/
typedef struct
{
    VOS_UINT32                          bitOpBearerId       : 1;                /* BearerId*/
    VOS_UINT32                          bitOpApn            : 1;                /* aucApn*/
    VOS_UINT32                          bitOpIpAddr         : 1;                /* aucIpaddr*/
    VOS_UINT32                          bitOpSubMask        : 1;                /* aucSubnetMask*/
    VOS_UINT32                          bitOpGwAddr         : 1;                /* aucGWAddr*/
    VOS_UINT32                          bitOpDNSPrimAddr    : 1;                /* aucDNSPrimAddr*/
    VOS_UINT32                          bitOpDNSSecAddr     : 1;                /* aucDNSSecAddr*/
    VOS_UINT32                          bitOpPCSCFPrimAddr  : 1;                /* aucPCSCFPrimAddr*/
    VOS_UINT32                          bitOpPCSCFSecAddr   : 1;                /* aucPCSCFSecAddr*/
    VOS_UINT32                          bitOpImCnSignalFlg  : 1;
    VOS_UINT32                          bitOpSpare          : 22;

    VOS_UINT8                           ucPrimayCid;                            /* default EPS bearer context*/
    VOS_UINT8                           ucBearerId;                             /* a numeric parameter which identifies the bearer*/

    /* the IM CN subsystem-related signalling flag */
    TAF_PDP_IM_CN_SIG_FLAG_ENUM_UINT8   enImCnSignalFlg;

    VOS_UINT8                           aucReserved[1];

    /* Access Pointer Name*/
    VOS_UINT8                           aucApn[TAF_MAX_APN_LEN + 1];

    /* the IP Address of the MT*/
    TAF_PDP_ADDR_STRU                   stPdpAddr;

    /* the subnet mask for the IP Address of the MT*/
    TAF_PDP_ADDR_STRU                   stSubnetMask;

    /* the Gateway Address of the MT*/
    TAF_PDP_ADDR_STRU                   stGWAddr;

    /* the IP Address of the primary DNS Server*/
    TAF_PDP_ADDR_STRU                   stDNSPrimAddr;

    /* the IP address of the secondary DNS Server*/
    TAF_PDP_ADDR_STRU                   stDNSSecAddr;

    /* the IP Address of the primary P-CSCF Server*/
    TAF_PDP_ADDR_STRU                   stPCSCFPrimAddr;

    /* the IP Address of the secondary P-CSCF Server*/
    TAF_PDP_ADDR_STRU                   stPCSCFSecAddr;

} TAF_PDP_DYNAMIC_PRIM_EXT_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    /* 0xff-if the parameter <cid> is omitted */
    VOS_UINT8                           ucCid;
    VOS_UINT8                           aucReserved[3];
} TAF_PS_GET_DYNAMIC_PRIM_PDP_CONTEXT_INFO_REQ_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_PDP_DYNAMIC_PRIM_EXT_STRU       astPdpContxtInfo[0]; //lint !e43
} TAF_PS_GET_DYNAMIC_PRIM_PDP_CONTEXT_INFO_CNF_STRU;


/*****************************************************************************
 ???? : ???????? +CGSCONTRDP
 ID   : ID_MSG_L4A_SET_CGSCONTRDP_REQ
        ID_MSG_L4A_SET_CGSCONTRDP_CNF
 REQ  : L4A_SET_CGSCONTRDP_REQ_STRU
 CNF  : L4A_SET_CGSCONTRDP_CNF_STRU
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    VOS_UINT8                           ucCid;

    /* default EPS bearer context */
    VOS_UINT8                           ucPrimaryCid;

    /* a numeric parameter which identifies the bearer */
    VOS_UINT8                           ucBearerId;

    VOS_UINT8                           ucReserved[1];
} TAF_PDP_DYNAMIC_SEC_EXT_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    /* 0xff-if the parameter <cid> is omitted */
    VOS_UINT8                           ucCid;
    VOS_UINT8                           aucReserved[3];
} TAF_PS_GET_DYNAMIC_SEC_PDP_CONTEXT_INFO_REQ_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_PDP_DYNAMIC_SEC_EXT_STRU        astPdpContxtInfo[0]; //lint !e43
} TAF_PS_GET_DYNAMIC_SEC_PDP_CONTEXT_INFO_CNF_STRU;


/*****************************************************************************
 ???? : ???????? +CGTFTRDP
 ID   : ID_MSG_L4A_SET_CGTFTRDP_REQ
        ID_MSG_L4A_SET_CGTFTRDP_CNF
 REQ  : L4A_SET_CGTFTRDP_REQ_STRU
 CNF  : L4A_SET_CGTFTRDP_CNF_STRU
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    /* 0xff-if the parameter <cid> is omitted */
    VOS_UINT8                           ucCid;
    VOS_UINT8                           aucReserved[3];
} TAF_PS_GET_DYNAMIC_TFT_INFO_REQ_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_PF_TFT_STRU                     astPfTftInfo[0]; //lint !e43
} TAF_PS_GET_DYNAMIC_TFT_INFO_CNF_STRU;


/*****************************************************************************
 ???? : ???????? +CGEQOS
 ID   : ID_MSG_L4A_SET_CGEQOS_REQ
        ID_MSG_L4A_SET_CGEQOS_CNF
        ID_MSG_L4A_READ_CGEQOS_REQ
        ID_MSG_L4A_READ_CGEQOS_CNF
 REQ  : L4A_SET_CGEQOS_REQ_STRU L4A_READ_CGEQOS_REQ_STRU
 CNF  : L4A_SET_CGEQOS_CNF_STRU L4A_READ_CGEQOS_CNF_STRU
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          bitOpQCI            : 1;                /* QCI*/
    VOS_UINT32                          bitOpDLGBR          : 1;                /* DLGBR*/
    VOS_UINT32                          bitOpULGBR          : 1;                /* ULGBR*/
    VOS_UINT32                          bitOpDLMBR          : 1;                /* DLMBR*/
    VOS_UINT32                          bitOpULMBR          : 1;                /* ULMBR*/
    VOS_UINT32                          bitOpSpare          : 27;

    VOS_UINT8                           ucCid;

    /* 0 QCI is selected by network*/
    /* [1 - 4]value range for guranteed bit rate Traffic Flows*/
    /* [5 - 9]value range for non-guarenteed bit rate Traffic Flows*/
    VOS_UINT8                           ucQCI;

    VOS_UINT8                           ucReserved[2];

    /* DL GBR in case of GBR QCI, The value is in kbit/s*/
    VOS_UINT32                          ulDLGBR;

    /* UL GBR in case of GBR QCI, The value is in kbit/s*/
    VOS_UINT32                          ulULGBR;

    /* DL MBR in case of GBR QCI, The value is in kbit/s*/
    VOS_UINT32                          ulDLMBR;

    /* UL MBR in case of GBR QCI, The value is in kbit/s*/
    VOS_UINT32                          ulULMBR;
}TAF_EPS_QOS_EXT_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_EPS_QOS_EXT_STRU                stEpsQosInfo;
} TAF_PS_SET_EPS_QOS_INFO_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_EPS_QOS_INFO_CNF_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_EPS_QOS_INFO_REQ_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_EPS_QOS_EXT_STRU                astEpsQosInfo[0]; //lint !e43
} TAF_PS_GET_EPS_QOS_INFO_CNF_STRU;


/*****************************************************************************
 ???? : ???????? +CGEQOSRDP
 ID   : ID_MSG_L4A_SET_CGEQOSRDP_REQ
        ID_MSG_L4A_SET_CGEQOSRDP_CNF
 REQ  : L4A_SET_CGEQOSRDP_REQ_STRU
 CNF  : L4A_SET_CGEQOSRDP_CNF_STRU
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    /* 0xff-if the parameter <cid> is omitted */
    VOS_UINT8                           ucCid;
    VOS_UINT8                           aucReserved[3];
} TAF_PS_GET_DYNAMIC_EPS_QOS_INFO_REQ_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_EPS_QOS_EXT_STRU                astEpsQosInfo[0]; //lint !e43
} TAF_PS_GET_DYNAMIC_EPS_QOS_INFO_CNF_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT8                           aucReserve[4];
} TAF_PS_GET_DSFLOW_INFO_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    TAF_DSFLOW_QUERY_INFO_STRU          stQueryInfo;
} TAF_PS_GET_DSFLOW_INFO_CNF_STRU;


/*****************************************************************************
 ???? : ???????? ^DSFLOWCLR
 ID   :

 REQ  :
 CNF  :
 IND  : -
 ???? : ...
*****************************************************************************/
/*****************************************************************************
 ??????    : TAF_DSFLOW_CLEAR_CONFIG_STRU
 ????????  : ????????????
*****************************************************************************/
typedef struct
{
    TAF_DSFLOW_CLEAR_MODE_ENUM_UINT8    enClearMode;
    VOS_UINT8                           ucNsapi;
    VOS_UINT8                           aucReserved[2];
} TAF_DSFLOW_CLEAR_CONFIG_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_DSFLOW_CLEAR_CONFIG_STRU        stClearConfigInfo;
} TAF_PS_CLEAR_DSFLOW_REQ_STRU;


typedef TAF_PS_COMMON_CNF_STRU TAF_PS_CLEAR_DSFLOW_CNF_STRU;


/*****************************************************************************
 ???? : ???????? ^DSFLOWRPT
 ID   :

 REQ  :
 CNF  :
 IND  : -
 ???? : ...
*****************************************************************************/

typedef struct
{
    VOS_UINT32                          ulRptEnabled;       /* ????????????????   */
    VOS_UINT32                          ulTimerLength;      /* ?????????????????? */
} TAF_DSFLOW_REPORT_CONFIG_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_DSFLOW_REPORT_CONFIG_STRU       stReportConfigInfo;
} TAF_PS_CONFIG_DSFLOW_RPT_REQ_STRU;


typedef TAF_PS_COMMON_CNF_STRU TAF_PS_CONFIG_DSFLOW_RPT_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    TAF_DSFLOW_REPORT_STRU              stDsFlowRptInfo;
} TAF_PS_REPORT_DSFLOW_IND_STRU;


typedef struct
{
    VOS_UINT8                           ucRptEnabled;       /*VT ????????????????   */
    VOS_UINT8                           aucReserved[3];
} TAF_VTFLOW_REPORT_CONFIG_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_VTFLOW_REPORT_CONFIG_STRU       stReportConfigInfo;
} TAF_PS_CONFIG_VTFLOW_RPT_REQ_STRU;


typedef TAF_PS_COMMON_CNF_STRU TAF_PS_CONFIG_VTFLOW_RPT_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    TAF_VTFLOW_REPORT_STRU              stDsFlowRptInfo;
} TAF_PS_REPORT_VTFLOW_IND_STRU;


/*****************************************************************************
 ???? : ???????? ^APDSFLOWRPT
 ID   :

 REQ  :
 CNF  :
 IND  : -
 ???? : ...
*****************************************************************************/

typedef struct
{
    VOS_UINT32                          ulRptEnabled;       /* ????????????????   */
    VOS_UINT32                          ulFluxThreshold;    /* ????????????, ????KByte */
} TAF_APDSFLOW_RPT_CFG_STRU;



typedef struct
{
    VOS_UINT32                          ulCurrentTxRate;    /*????????????*/
    VOS_UINT32                          ulCurrentRxRate;    /*????????????*/
    TAF_DSFLOW_INFO_STRU                stCurrentFlowInfo;  /*????????????????*/
    TAF_DSFLOW_INFO_STRU                stTotalFlowInfo;    /*????????????*/
} TAF_APDSFLOW_REPORT_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_APDSFLOW_RPT_CFG_STRU           stRptCfg;
} TAF_PS_SET_APDSFLOW_RPT_CFG_REQ_STRU;



typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_APDSFLOW_RPT_CFG_CNF_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_APDSFLOW_RPT_CFG_REQ_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    TAF_APDSFLOW_RPT_CFG_STRU           stRptCfg;
} TAF_PS_GET_APDSFLOW_RPT_CFG_CNF_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_APDSFLOW_REPORT_STRU            stApDsFlowRptInfo;
} TAF_PS_APDSFLOW_REPORT_IND_STRU;



typedef struct
{
    VOS_UINT8                           ucEnabled;          /* ??????NV????????   */
    VOS_UINT8                           ucInterval;         /* ??????NV????, ????min */
    VOS_UINT8                           aucReserved[2];     /* ???????? */
} TAF_DSFLOW_NV_WRITE_CFG_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_DSFLOW_NV_WRITE_CFG_STRU        stNvWriteCfg;
} TAF_PS_SET_DSFLOW_NV_WRITE_CFG_REQ_STRU;



typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_DSFLOW_NV_WRITE_CFG_CNF_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_DSFLOW_NV_WRITE_CFG_REQ_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    TAF_DSFLOW_NV_WRITE_CFG_STRU        stNvWriteCfg;
} TAF_PS_GET_DSFLOW_NV_WRITE_CFG_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT8                           ucPktCdataInactivityTmrLen;
    VOS_UINT8                           aucReserved[3];
}TAF_PS_SET_CTA_INFO_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

}TAF_PS_GET_CTA_INFO_REQ_STRU;




typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT32                          ulRslt;

}TAF_PS_SET_CTA_INFO_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT32                          ulRslt;

    VOS_UINT8                           ucPktCdataInactivityTmrLen;
    VOS_UINT8                           aucReserved[3];

}TAF_PS_GET_CTA_INFO_CNF_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
}TAF_PS_GET_CGMTU_VALUE_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT32                          ulMtuValue;
}TAF_PS_GET_CGMTU_VALUE_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT32                          ulMtuValue;
}TAF_PS_CGMTU_VALUE_CHG_IND_STRU;


/*****************************************************************************
 ???? : ???????? ^CGAUTH
 ID   :

 REQ  :
 CNF  :
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          bitOpAuth           : 1;
    VOS_UINT32                          bitOpUserName       : 1;
    VOS_UINT32                          bitOpPassword       : 1;
    VOS_UINT32                          bitOpSpare          : 29;

    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucDefined;          /* 0:undefined, 1:defined */
    VOS_UINT8                           ucAuth;             /* ??????????????????????????????????????????????*/
    VOS_UINT8                           aucReserved[1];
    VOS_UINT8                           aucUserName[TAF_MAX_AUTHDATA_USERNAME_LEN + 1];
    VOS_UINT8                           aucPassWord[TAF_MAX_AUTHDATA_PASSWORD_LEN + 1];
} TAF_PDP_AUTH_EXT_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PDP_AUTH_EXT_STRU               stPdpAuthInfo;
} TAF_PS_SET_PDP_AUTH_INFO_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_PDP_AUTH_INFO_CNF_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_PDP_AUTH_INFO_REQ_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_AUTH_QUERY_INFO_STRU            astPdpAuthQueryInfo[0]; //lint !e43
} TAF_PS_GET_PDP_AUTH_INFO_CNF_STRU;


/*****************************************************************************
 ???? : ???????? ^CGDNS
 ID   :

 REQ  :
 CNF  :
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          bitOpPrimDnsAddr    : 1;
    VOS_UINT32                          bitOpSecDnsAddr     : 1;
    VOS_UINT32                          bitOpSpare          : 30;

    VOS_UINT8                           ucCid;              /* [1??11] ????????????????????????????Cid??DNS */
    VOS_UINT8                           ucDefined;          /* 0:undefined, 1:defined */
    VOS_UINT8                           aucReserved[2];
    VOS_UINT8                           aucPrimDnsAddr[TAF_IPV4_ADDR_LEN];
    VOS_UINT8                           aucSecDnsAddr[TAF_IPV4_ADDR_LEN];
} TAF_PDP_DNS_EXT_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PDP_DNS_EXT_STRU                stPdpDnsInfo;
} TAF_PS_SET_PDP_DNS_INFO_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_PDP_DNS_INFO_CNF_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_PDP_DNS_INFO_REQ_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_DNS_QUERY_INFO_STRU             astPdpDnsQueryInfo[0]; //lint !e43
} TAF_PS_GET_PDP_DNS_INFO_CNF_STRU;


/*****************************************************************************
 ???? : ???????? ^TRIG
 ID   :

 REQ  :
 CNF  :
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    VOS_UINT8                           ucMode;
    VOS_UINT8                           ucNsapi;
    VOS_UINT8                           ucTimes;
    VOS_UINT8                           aucReserved[1];
    VOS_UINT32                          ulLength;
    VOS_UINT32                          ulMillisecond;
} TAF_GPRS_DATA_STRU;

typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_GPRS_DATA_STRU                  stGprsDataInfo;
} TAF_PS_TRIG_GPRS_DATA_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_TRIG_GPRS_DATA_CNF_STRU;


/*****************************************************************************
 ???? : ???????? ^DWINS
 ID   :

 REQ  :
 CNF  :
 IND  : -
 ???? : ...
*****************************************************************************/
typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    /* 0:disabled, 1:enabled */
    VOS_UINT32                          ulEnabled;
} TAF_PS_CONFIG_NBNS_FUNCTION_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_CONFIG_NBNS_FUNCTION_CNF_STRU;


/*****************************************************************************
 ????????  : TAF_PS_DIAL_PARA_STRU
 ????????  : ????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          bitOpAuthType       : 1;
    VOS_UINT32                          bitOpApn            : 1;
    VOS_UINT32                          bitOpIpAddr         : 1;
    VOS_UINT32                          bitOpUserName       : 1;
    VOS_UINT32                          bitOpPassWord       : 1;
    VOS_UINT32                          bitOpReqType        : 1;
    VOS_UINT32                          bitOpPdpDcomp       : 1;
    VOS_UINT32                          bitOpPdpHcomp       : 1;
    VOS_UINT32                          bitOpIpv4AddrAlloc  : 1;
    VOS_UINT32                          bitOpEmergencyInd   : 1;
    VOS_UINT32                          bitOpPcscfDiscovery : 1;
    VOS_UINT32                          bitOpImCnSignalFlg  : 1;
    VOS_UINT32                          bitOpDialRatType    : 1;
    VOS_UINT32                          bitOpSpare          : 19;

    /* connect id [1, 20] */
    VOS_UINT8                           ucCid;

    /* 0 - no auth */
    /* 1 - PAP */
    /* 2 - CHAP */
    /* 3 - PAP OR CHAP */
    TAF_PDP_AUTH_TYPE_ENUM_UINT8        enAuthType;

    /* 1 - IPv4 */
    /* 2 - IPv6 */
    /* 3 - IPv4v6 */
    /* 4 - PPP */
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType;

    /* 1 - initial request */
    /* 2 - Handover */
    TAF_PDP_REQUEST_TYPE_ENUM_UINT8     enPdpRequestType;

    /* access point name string with '\0' end */
    VOS_UINT8                           aucApn[TAF_MAX_APN_LEN + 1];

    /* staitc address if needed */
    TAF_PDP_ADDR_STRU                   stPdpAddr;

    /* user name string with '\0' end */
    VOS_UINT8                           aucUserName[TAF_MAX_AUTHDATA_USERNAME_LEN + 1];

    /* user name string with '\0' end */
    VOS_UINT8                           aucPassWord[TAF_MAX_AUTHDATA_PASSWORD_LEN + 1];

    /* 0 - off (default if value is omitted) */
    /* 1 - on (manufacturer preferred compression) */
    /* 2 - V.42bis */
    /* 3 - V.44 */
    TAF_PDP_D_COMP_ENUM_UINT8           enPdpDcomp;

    /* 0 - off (default if value is omitted) */
    /* 1 - on (manufacturer preferred compression) */
    /* 2 - RFC1144 (applicable for SNDCP only) */
    /* 3 - RFC2507 */
    /* 4 - RFC3095 (applicable for PDCP only) */
    TAF_PDP_H_COMP_ENUM_UINT8           enPdpHcomp;

    /* 0 - IPv4 Address Allocation through NAS Signaling (default if omitted) */
    /* 1 - IPv4 Address Allocated through DHCP */
    TAF_PDP_IPV4_ADDR_ALLOC_TYPE_ENUM_UINT8 enIpv4AddrAlloc;

    /* 0 - PDP context is not for emergency bearer services */
    /* 1 - PDP context is for emergency bearer services */
    TAF_PDP_EMC_IND_ENUM_UINT8          enEmergencyInd;

    /* 0 - Preference of P-CSCF address discovery not influenced by +CGDCONT */
    /* 1 - Preference of P-CSCF address discovery through NAS Signalling */
    /* 2 - Preference of P-CSCF address discovery through DHCP */
    TAF_PDP_PCSCF_DISCOVERY_ENUM_UINT8  enPcscfDiscovery;

    /* 0 - UE indicates that the PDP context is not for IM CN subsystem-related signalling only */
    /* 1 - UE indicates that the PDP context is for IM CN subsystem-related signalling only */
    TAF_PDP_IM_CN_SIG_FLAG_ENUM_UINT8   enImCnSignalFlg;

    VOS_UINT8                           ucBitRatType;
    VOS_UINT8                           ucRmnetId;

} TAF_PS_DIAL_PARA_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_DIAL_PARA_STRU               stDialParaInfo;
} TAF_PS_CALL_ORIG_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT8                           ucCid;
    VOS_UINT8                           aucReserved[3];
    TAF_PS_CAUSE_ENUM_UINT32            enCause;
} TAF_PS_CALL_ORIG_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT8                           ucCid;
    TAF_PS_CALL_END_CAUSE_ENUM_UINT8    enCause;
    VOS_UINT8                           aucReserved[2];
} TAF_PS_CALL_END_REQ_STRU;

/*****************************************************************************
 ????????: TAF_PS_CALL_END_CNF_STRU
 ????????: ID_MSG_TAF_PS_CALL_END_CNF????????
           ???????????? - enCause??TAF_PS_CAUSE_SUCCESS
           ???????????? - enCause??TAF_PS_CAUSE_CID_INVALID
                          ??????CID??????????????????????
*****************************************************************************/
typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT8                           ucCid;
    VOS_UINT8                           aucReserved[3];
    TAF_PS_CAUSE_ENUM_UINT32            enCause;

} TAF_PS_CALL_END_CNF_STRU;

/*****************************************************************************
 ???? : ???????? ^AUTHDATA
 ID   : ID_MSG_TAF_PS_SET_AUTHDATA_INFO_REQ
      : ID_MSG_TAF_PS_SET_AUTHDATA_INFO_CNF
      : ID_MSG_TAF_PS_GET_AUTHDATA_INFO_REQ
      : ID_MSG_TAF_PS_GET_AUTHDATA_INFO_CNF
 REQ  : TAF_PS_SET_AUTHDATA_INFO_REQ_STRU; TAF_PS_GET_AUTHDATA_INFO_REQ_STRU
 CNF  : TAF_PS_SET_AUTHDATA_INFO_CNF_STRU; TAF_PS_GET_AUTHDATA_INFO_CNF_STRU
 ???? : ...
*****************************************************************************/

typedef struct
{
    VOS_UINT32                          bitOpAuthType       : 1;
    VOS_UINT32                          bitOpPlmn           : 1;
    VOS_UINT32                          bitOpPassWord       : 1;
    VOS_UINT32                          bitOpUserName       : 1;
    VOS_UINT32                          bitOpSpare          : 28;

    VOS_UINT8                           ucDefined;          /* 0:undefined, 1:defined */
    VOS_UINT8                           ucCid;
    TAF_PDP_AUTH_TYPE_ENUM_UINT8        enAuthType;
    VOS_UINT8                           aucReserved1[1];
    VOS_UINT8                           aucPlmn[TAF_MAX_AUTHDATA_PLMN_LEN + 1];
    VOS_UINT8                           aucReserved2[1];
    VOS_UINT8                           aucPassWord[TAF_MAX_AUTHDATA_USERNAME_LEN + 1];
    VOS_UINT8                           aucUserName[TAF_MAX_AUTHDATA_PASSWORD_LEN + 1];
} TAF_AUTHDATA_EXT_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_AUTHDATA_EXT_STRU               stAuthDataInfo;
} TAF_PS_SET_AUTHDATA_INFO_REQ_STRU;


typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_AUTHDATA_INFO_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_AUTHDATA_INFO_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT32                          ulCidNum;
    TAF_AUTHDATA_QUERY_INFO_STRU        astAuthDataQueryInfo[0]; //lint !e43
} TAF_PS_GET_AUTHDATA_INFO_CNF_STRU;


/*****************************************************************************
 ???? : ???????? D
 ID   : ID_MSG_TAF_PS_GET_D_GPRS_ACTIVE_TYPE_REQ
      : ID_EVT_TAF_PS_GET_D_GPRS_ACTIVE_TYPE_CNF
      :
      :
 REQ  : TAF_PS_GET_D_GPRS_ACTIVE_TYPE_REQ_STRU
 CNF  : TAF_PS_GET_D_GPRS_ACTIVE_TYPE_CNF_STRU
 ???? : ...
*****************************************************************************/


typedef struct
{
    VOS_UINT32                          bitOpL2p            : 1;
    VOS_UINT32                          bitOpSpare          : 31;

    VOS_UINT8                           ucCid;
    TAF_L2P_TYPE_ENUM_UINT8             enL2p;
    VOS_UINT8                           aucReserved[2];
} TAF_ATD_PARA_STRU;


typedef struct
{
    VOS_UINT8                           ucCid;
    TAF_GPRS_ACTIVE_TYPE_UINT8          enActiveType;
    VOS_UINT8                           aucReserved[2];
} TAF_CID_GPRS_ACTIVE_TYPE_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_ATD_PARA_STRU                   stAtdPara;
} TAF_PS_GET_D_GPRS_ACTIVE_TYPE_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    TAF_CID_GPRS_ACTIVE_TYPE_STRU       stCidGprsActiveType;
} TAF_PS_GET_D_GPRS_ACTIVE_TYPE_CNF_STRU;


/*****************************************************************************
 ????????: TAF_PPP_AUTH_PAP_CONTENT_STRU
 ????????:
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usPapReqLen;                            /*request????: 24.008??????[3,253]????*/
    VOS_UINT8                           aucReserve[2];                          /* ???????? */
    VOS_UINT8                           aucPapReqBuf[TAF_PPP_PAP_REQ_MAX_LEN];  /*request*/
} TAF_PPP_AUTH_PAP_CONTENT_STRU;

/*****************************************************************************
 ????????: TAF_PPP_AUTH_CHAP_CONTENT_STRU
 ????????:
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usChapChallengeLen;                     /*challenge????: 24.008??????[3,253]????*/
    VOS_UINT16                          usChapResponseLen;                      /*response????: 24.008??????[3,253]????*/
    VOS_UINT8                           aucChapChallengeBuf[TAF_PPP_CHAP_CHALLENGE_MAX_LEN];    /*challenge,153B*/
    VOS_UINT8                           aucChapResponseBuf[TAF_PPP_CHAP_RESPONSE_MAX_LEN];      /*response,205B*/
    VOS_UINT8                           aucReserve[2];                          /* ???????? */
} TAF_PPP_AUTH_CHAP_CONTENT_STRU;

/*****************************************************************************
 ????????: TAF_PPP_REQ_AUTH_CONFIG_INFO_STRU
 ????????:
*****************************************************************************/
typedef struct
{
    TAF_PDP_AUTH_TYPE_ENUM_UINT8        enAuthType;
    VOS_UINT8                           aucReserve[3];

    union
    {
        TAF_PPP_AUTH_PAP_CONTENT_STRU   stPapContent;
        TAF_PPP_AUTH_CHAP_CONTENT_STRU  stChapContent;
    } enAuthContent;

} TAF_PPP_REQ_AUTH_CONFIG_INFO_STRU;

/*****************************************************************************
 ????????: TAF_PPP_REQ_CONFIG_INFO_STRU
 ????????:
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usIpcpLen;                              /*Ipcp??????*/
    VOS_UINT8                           aucReserve[2];                          /* ???????? */
    VOS_UINT8                           aucIpcp[TAF_PPP_IPCP_FRAME_BUF_MAX_LEN];/*Ipcp??*/
} TAF_PPP_REQ_IPCP_CONFIG_INFO_STRU;

/*****************************************************************************
 ????????: TAF_PPP_REQ_CONFIG_INFO_STRU
 ????????:
*****************************************************************************/
typedef struct
{
    TAF_PPP_REQ_AUTH_CONFIG_INFO_STRU   stAuth;
    TAF_PPP_REQ_IPCP_CONFIG_INFO_STRU   stIPCP;
} TAF_PPP_REQ_CONFIG_INFO_STRU;

/*****************************************************************************
 ???? : ????PPP????
 ID   : ID_MSG_TAF_PS_PPP_DIAL_ORIG_REQ
      : ID_EVT_TAF_PS_PPP_DIAL_ORIG_CNF
      :
      :
 REQ  : TAF_PS_PPP_DIAL_ORIG_REQ_STRU
 CNF  : TAF_PS_PPP_DIAL_ORIG_CNF_STRU
 ???? : ...
*****************************************************************************/

typedef struct
{
    VOS_UINT32                          bitOpPppConfigInfo  : 1;
    VOS_UINT32                          bitOpSpare          : 31;

    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucRmnetId;                              /* ????ID */

    VOS_UINT8                           aucReserved[2];
    TAF_PPP_REQ_CONFIG_INFO_STRU        stPppReqConfigInfo;
} TAF_PPP_DIAL_PARA_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PPP_DIAL_PARA_STRU              stPppDialParaInfo;
} TAF_PS_PPP_DIAL_ORIG_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
} TAF_PS_PPP_DIAL_ORIG_CNF_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_IPV6_INFO_RESULT_ENUM_UINT8  enIpv6Rst;
    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucQfi;
    VOS_UINT8                           ucRabId;
    VOS_UINT8                           ucPduSessionId;
    VOS_UINT8                           aucReserved[3];

    TAF_PDP_IPV6_RA_INFO_STRU           stIpv6RaInfo;

} TAF_PS_IPV6_INFO_IND_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT8                           ucCid;
    VOS_UINT8                           aucReserved[3];
} TAF_PS_GET_NEGOTIATION_DNS_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    TAF_DNS_QUERY_INFO_STRU             stNegotiationDns;
} TAF_PS_GET_NEGOTIATION_DNS_CNF_STRU;


#if (FEATURE_ON == FEATURE_LTE)


typedef struct
{
    VOS_UINT8                           ucSG;
    VOS_UINT8                           ucIMS;
    VOS_UINT8                           ucCSFB;
    VOS_UINT8                           ucVCC;
    VOS_UINT8                           ucVoLGA;
    VOS_UINT8                           aucReserved[3];
}TAF_PH_LTECS_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
}TAF_PS_LTECS_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    TAF_PH_LTECS_STRU                   stLteCs;
}TAF_PS_LTECS_CNF_STRU;



typedef struct
{
    VOS_UINT32                          enCurrentUeMode;                        /*????UE????*/
    VOS_UINT32                          ulSupportModeCnt;                       /*UE????????????????????*/
    VOS_UINT32                          aenSupportModeList[4];                  /*UE??????????????*/
}TAF_PH_CEMODE_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
}TAF_PS_CEMODE_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    TAF_PH_CEMODE_STRU                  stCemode;
}TAF_PS_CEMODE_CNF_STRU;


#endif

/*****************************************************************************
 ????????: TAF_GW_AUTH_STRU
 ????????: ??????????????????
*****************************************************************************/
typedef struct
{
    TAF_PDP_AUTH_TYPE_ENUM_UINT8        enAuthType;
    VOS_UINT8                           ucAccNumLen;
    VOS_UINT8                           aucReserved[2];
    VOS_UINT8                           auAccessNum[TAF_MAX_ACCESS_NUM_LEN];
    VOS_UINT8                           ucUserNameLen;
    VOS_UINT8                           aucUserName[TAF_MAX_AUTHDATA_USERNAME_LEN];
    VOS_UINT8                           ucPwdLen;
    VOS_UINT8                           aucPwd[TAF_MAX_AUTHDATA_PASSWORD_LEN];

} TAF_GW_AUTH_STRU;


/*****************************************************************************
 ????????: TAF_SDF_PARA_STRU
 ????????: SDF????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          bitOpLinkdCid       : 1;
    VOS_UINT32                          bitOpPdnType        : 1;
    VOS_UINT32                          bitOpApn            : 1;
    VOS_UINT32                          bitOpUmtsQos        : 1;
    VOS_UINT32                          bitOpEpsQos         : 1;
    VOS_UINT32                          bitOpGwAuthInfo     : 1;
    VOS_UINT32                          bitOpEmergencyInd   : 1;
    VOS_UINT32                          bitOpIpv4AddrAllocType: 1;
    VOS_UINT32                          bitOpPcscfDiscovery : 1;
    VOS_UINT32                          bitOpImCnSignalFlg  : 1;
    VOS_UINT32                          bitOpImsSuppFlg     : 1;
    VOS_UINT32                          bitOpSpare          : 21;

    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucLinkdCid;
    TAF_PDP_TYPE_ENUM_UINT8             enPdnType;
    TAF_PDP_IPV4_ADDR_ALLOC_TYPE_ENUM_UINT8 enIpv4AddrAllocType;

    TAF_PDP_EMC_IND_ENUM_UINT8          enEmergencyInd;
    TAF_PDP_PCSCF_DISCOVERY_ENUM_UINT8  enPcscfDiscovery;
    TAF_PDP_IM_CN_SIG_FLAG_ENUM_UINT8   enImCnSignalFlg;
    VOS_UINT8                           ucPfNum;
    VOS_UINT8                           ucImsSuppFlg;
    VOS_UINT8                           ucNasSigPrioInd;
    VOS_UINT8                           aucReserved[2];

    TAF_UMTS_QOS_STRU                   stUmtsQosInfo;
    TAF_EPS_QOS_STRU                    stEpsQosInfo;
    TAF_PDP_APN_STRU                    stApnInfo;
    TAF_GW_AUTH_STRU                    stGwAuthInfo;
    TAF_PDP_PF_STRU                     astCntxtTftInfo[TAF_MAX_SDF_PF_NUM];

}TAF_SDF_PARA_STRU;


/*****************************************************************************
 ????????: TAF_SDF_PARA_QUERY_INFO_STRU
 ????????: SDF??????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulSdfNum;
    TAF_SDF_PARA_STRU                   astSdfPara[TAF_MAX_CID_NV];

} TAF_SDF_PARA_QUERY_INFO_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
}TAF_PS_SDF_INFO_REQ_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_SDF_PARA_QUERY_INFO_STRU        stSdfInfo;
}TAF_PS_SDF_INFO_CNF_STRU;



typedef struct
{
    VOS_UINT8                           ucQosFlag;                              /* 0??Qos????????1??Qos?????? */
    VOS_UINT8                           ucMinQosFlag;                           /* 0:????????????????Qos,1:??????????????Qos */
    VOS_UINT8                           aucReserved[2];

    TAF_UMTS_QOS_STRU                   stQos;                                  /* Qos?? */
    TAF_UMTS_QOS_STRU                   stMinQos;                               /* MINQos?? */
}TAF_PS_PDP_QOS_QUERY_PARA_STRU;


typedef struct
{
    TAF_UMTS_QOS_EXT_STRU               stQos;                                  /* Qos?? */
    TAF_UMTS_QOS_EXT_STRU               stMinQos;                               /* MINQos?? */
}TAF_PS_PDP_QOS_SET_PARA_STRU;


#if (FEATURE_ON == FEATURE_IMS)
/*****************************************************************************
 ????????: TAF_SRVCC_CANCEL_NOTIFY_IND_STRU
 ????????: APS->IMSA????SRVCC CANECL
*****************************************************************************/
typedef struct
{
    TAF_CTRL_STRU                           stCtrl;
    TAF_SRVCC_CANCEL_NOTIFY_ENUM_UINT32     enNotificationIndicator;
}TAF_SRVCC_CANCEL_NOTIFY_IND_STRU;
#endif


/* ????TAF_PS_SET_1X_CQOS_PRI_REQ_STRU  ??TAF_PS_SET_CQOS_PRI_CNF_STRU */


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucRabId;
    VOS_UINT8                           aucReserved[2];
}TAF_PS_CALL_DORMANT_IND_STRU;

/** ****************************************************************************
 * Name        : APS_APS_ENTER_DORMANT_IND_STRU
 *
 * Description :
 *******************************************************************************/
typedef struct
{
    MSG_HEADER_STRU                     stMsgHeader;                            /* _H2ASN_Skip */
    VOS_UINT8                           ucPdpId;
    VOS_UINT8                           aucReserved[3];
}TAF_PS_CALL_ENTER_DORMANT_IND_STRU;


/** ****************************************************************************
 * Name        : TAF_PS_HAI_CHANGE_IND_STRU
 *
 * Description :
 *******************************************************************************/
typedef struct
{
    MSG_HEADER_STRU                     stMsgHeader;                            /* _H2ASN_Skip */
    VOS_UINT8                           ucPdpId;
    VOS_UINT8                           aucReserved[3];
}TAF_PS_HAI_CHANGE_IND_STRU;


/** ****************************************************************************
 * Name        : TAF_PS_CDMA_DIAL_MODE_REQ_STRU
 *
 * Description :
 *******************************************************************************/
typedef struct
{
    TAF_CTRL_STRU                          stCtrl;


    TAF_PS_CDATA_DIAL_MODE_ENUM_UINT32    enDialMode;
}TAF_PS_CDATA_DIAL_MODE_REQ_STRU;

typedef TAF_PS_COMMON_CNF_STRU TAF_PS_CDATA_DIAL_MODE_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucNewRabId;
    VOS_UINT8                           ucOldRabId;
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType;

}TAF_PS_CALL_PDP_RABID_CHANGE_IND_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_MIP_MODE_ENUM_UINT8          enMipMode;
    VOS_UINT8                           aucResv[3];
}TAF_PS_SET_MIP_MODE_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    TAF_PS_CAUSE_ENUM_UINT32            enCause;

}TAF_PS_SET_MIP_MODE_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

}TAF_PS_GET_MIP_MODE_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PS_MIP_MODE_ENUM_UINT8          enMipMode;
    VOS_UINT8                           aucResv[3];

}TAF_PS_GET_MIP_MODE_CNF_STRU;

/*****************************************************************************
  H2ASN????????????????
*****************************************************************************/
typedef struct
{
    TAF_PS_MSG_ID_ENUM_UINT32           ulMsgId;                                /*_H2ASN_MsgChoice_Export TAF_PS_MSG_ID_ENUM_UINT32*/
    VOS_UINT8                           aucMsgBlock[4];
    /***************************************************************************
        _H2ASN_MsgChoice_When_Comment          TAF_PS_MSG_ID_ENUM_UINT32
    ****************************************************************************/
}TAF_PS_MSG_REQ;
/*_H2ASN_Length UINT32*/

typedef struct
{
    VOS_MSG_HEADER
    TAF_PS_MSG_REQ                      stMsgReq;
}TafApsApi_MSG;

typedef struct
{
    TAF_PS_EVT_ID_ENUM_UINT32           ulEvtId;                                /*_H2ASN_MsgChoice_Export TAF_PS_EVT_ID_ENUM_UINT32*/
    VOS_UINT8                           aucEvtBlock[4];
    /***************************************************************************
        _H2ASN_MsgChoice_When_Comment          TAF_PS_EVT_ID_ENUM_UINT32
    ****************************************************************************/
}TAF_PS_EVT_CNF;
/*_H2ASN_Length UINT32*/

typedef struct
{
    VOS_MSG_HEADER
    VOS_UINT32                          ulMsgName;
    TAF_PS_EVT_CNF                      stEvtCnf;
}TafApsApi_EVT;


/* ??????????????????????????????????????????????????????????????OK?? */

typedef struct
{
    VOS_UINT32                          bitOpPdpType        : 1;                /* PdpType*/
    VOS_UINT32                          bitOpApn            : 1;                /* aucApn*/
    VOS_UINT32                          bitOpUsername       : 1;                /* AuthUsername*/
    VOS_UINT32                          bitOpPassword       : 1;                /* AuthPassword*/
    VOS_UINT32                          bitOpAuthType       : 1;                /* AuthType*/
    VOS_UINT32                          bitOpSpare          : 27;

    VOS_UINT8                           ucDefined;                              /* 0:undefined, 1:defined */

    VOS_UINT8                           ucCid;

    /* 1 IP Internet Protocol (IETF STD 5)*/
    /* 2 IPV6 Internet Protocol, version 6 (IETF RFC 2460)*/
    /* 3 IPV4V6 Virtual <PDP_type> introduced to handle dual IP stack UE capability. (See 3GPP TS 24.301 [83])*/
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType;

    VOS_UINT8                           aucReserved1[1];

    /* Access Point Name*/
    VOS_UINT8                           aucApn[TAF_MAX_APN_LEN + 1];

    VOS_UINT8                           aucPassWord[TAF_MAX_AUTHDATA_PASSWORD_LEN + 1];
    VOS_UINT8                           aucUserName[TAF_MAX_AUTHDATA_USERNAME_LEN + 1];
    VOS_UINT8                           ucAuthType;
    VOS_UINT8                           aucReserved2[3];

}TAF_PDP_PROFILE_EXT_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;

    TAF_PDP_PROFILE_EXT_STRU            stPdpProfInfo;
} TAF_PS_SET_PROFILE_INFO_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                                           stCtrl;
    TAF_PS_CDATA_1X_QOS_NON_ASSURED_PRI_ENUM_UINT8          enPri;
    VOS_UINT8                                               aucReserved[3];
}TAF_PS_SET_1X_CQOS_PRI_REQ_STRU;


typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_PDP_PROF_INFO_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT32                          ulRslt;
}TAF_PS_SET_CQOS_PRI_CNF_STRU;


typedef struct
{
    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucClass;
    VOS_UINT8                           ucEnable;
    TAF_PDP_TYPE_ENUM_UINT8             enIpType;
    VOS_UINT16                          usInactiveTimer;
    VOS_UINT8                           aucRsv[2];
    TAF_PDP_APN_STRU                    stApn;
}TAF_PS_VZWAPNE_INFO_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT8                           ucIsCustomCmd;                          /* 0:^VZWAPNE????, 1:+VZWAPNE???? */
    VOS_UINT8                           aucRsv[3];
    TAF_PS_VZWAPNE_INFO_STRU            stVzwApneInfo;
}TAF_PS_SET_VZWAPNE_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT8                           ucIsCustomCmd;                          /* 0:^VZWAPNE????, 1:+VZWAPNE???? */
    VOS_UINT8                           aucRsv[3];
}TAF_PS_GET_VZWAPNE_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    TAF_PS_CAUSE_ENUM_UINT32            enCause;
    VOS_UINT8                           ucNum;
    VOS_UINT8                           aucRsv[3];
    TAF_PS_VZWAPNE_INFO_STRU            astVzwApneInfo[TAF_PS_MAX_VZWAPNE_NUM];
}TAF_PS_GET_VZWAPNE_CNF_STRU;


typedef TAF_PS_COMMON_CNF_STRU          TAF_PS_SET_VZWAPNE_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT8                           ucCid;
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType;
    TAF_PS_PDN_OPERATE_TYPE_ENUM_UINT8  enOperateType;
    VOS_UINT8                           aucReserved[1];
    TAF_PS_CUSTOM_PCO_INFO_STRU         stCustomPcoInfo;
}TAF_PS_REPORT_PCO_INFO_IND_STRU;




typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    TAF_PS_REG_RESUL_ENUM_UINT32        enPsRegResult;                          /* PS?????????? */
    TAF_PS_REG_TYPE_ENUM_UINT32         enPsRegType;                            /* PS?????????? */
} TAF_PS_REG_STATUS_IND_STRU;


typedef struct
{
    VOS_UINT8                           ucCauseValue;                           /* ???????????????? */
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType;                              /* ????????????????????????????PDP TYPE */
    VOS_UINT8                           aucReserved[2];
}TAF_PS_PDP_TYPE_CHG_INFO_STRU;


typedef struct
{
    VOS_UINT8                           ucPdpTypeChgEnableFlg;                          /* ????????, 0: ???? 1: ???? */
    VOS_UINT8                           ucRejCauseNum;                                  /* ???????????????????? */
    VOS_UINT8                           aucReserved[2];
    TAF_PS_PDP_TYPE_CHG_INFO_STRU       astPdpTypeChgInfo[TAF_PS_PDP_TYPE_CHG_MAX_NUM];
}TAF_PS_PDP_TYPE_CHG_POLICY_CFG_STRU;


typedef struct
{
    TAF_CTRL_STRU                           stCtrl;
    TAF_PS_PDP_TYPE_CHG_POLICY_CFG_STRU     stPsPdpTypeChgPolicy;
} TAF_PS_PDP_TYPE_CHG_POLICY_IND_STRU;


typedef struct
{
    VOS_UINT8                           ucRoamingNwNotSupportDualStackFlg;
    VOS_UINT8                           ucImsPdnSupportIpType;    /* 1:(IPV4 Only), 2:(IPV6 ONly)*/
    VOS_UINT8                           ucNonImsPdnSupportIpType; /* 1:(IPV4 Only), 2:(IPV6 ONly)*/
    VOS_UINT8                           ucResv;
}TAF_APS_ROAMING_NW_NOT_SUPPORT_DUAL_STACK_CFG_STRU;



typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT8                           ucDataSwitch;
    VOS_UINT8                           ucReserved1;
    VOS_UINT8                           ucReserved2;
    VOS_UINT8                           ucReserved3;
}TAF_PS_SET_DATA_SWITCH_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT8                           ucDataRoamSwitch;
    VOS_UINT8                           ucReserved1;
    VOS_UINT8                           ucReserved2;
    VOS_UINT8                           ucReserved3;
}TAF_PS_SET_DATA_ROAM_SWITCH_REQ_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT8                           ucDataSwitch;
    VOS_UINT8                           ucReserved1;
    VOS_UINT8                           ucReserved2;
    VOS_UINT8                           ucReserved3;
}TAF_PS_GET_DATA_SWITCH_CNF_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    VOS_UINT8                           ucDataRoamSwitch;
    VOS_UINT8                           ucReserved1;
    VOS_UINT8                           ucReserved2;
    VOS_UINT8                           ucReserved3;
}TAF_PS_GET_DATA_ROAM_SWITCH_CNF_STRU;

typedef TAF_PS_COMMON_REQ_STRU TAF_PS_GET_DATA_SWITCH_REQ_STRU;
typedef TAF_PS_COMMON_REQ_STRU TAF_PS_GET_DATA_ROAM_SWITCH_REQ_STRU;
typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_DATA_SWITCH_CNF_STRU;
typedef TAF_PS_COMMON_CNF_STRU TAF_PS_SET_DATA_ROAM_SWITCH_CNF_STRU;


typedef struct
{
    VOS_UINT8                           ucCid;
    VOS_UINT8                           ucApnClassType;
    VOS_UINT8                           aucReserved[2];
    VOS_UINT32                          ulWaitTime;
    VOS_UINT32                          ulPdnMaxConnTime;
    VOS_UINT32                          ulPdnMaxConnCount;
}TAF_PS_APN_THROT_INFO_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    TAF_PS_APN_THROT_INFO_STRU          stApnThrotInfo;
}TAF_PS_SET_APN_THROT_INFO_REQ_STRU;


typedef TAF_PS_COMMON_CNF_STRU          TAF_PS_SET_APN_THROT_INFO_CNF_STRU;


typedef struct
{
    TAF_PS_APN_DATA_SYS_POLICY_ENUM_UINT8   enDataSysPolicy;                    /* APN???????????? */
    /*  bit7 | bit6 | bit5 | bit4 | bit3 | bit2 | bit1 | bit0 |
        RESV | RESV | RESV | RESV | RESV | LTE  | WCDMA| GSM  |
    */
    VOS_UINT8                               ucDataSysSwitchRatPolicy;           /* ?????????????????????????? bit?????????????????? */
    VOS_UINT8                               ucRoamHoSupportFlg;                 /* ??????????????????????????????????WLAN2CELLULAR?????? */
    VOS_UINT8                               ucReserved;
    VOS_UINT16                              usCelluarOutProtectTimeLen;         /* WLAN -> CELLULAR????CELLUAR???????????????????? */
    VOS_UINT16                              usWlanOutProtectTimeLen;            /* CELLULAR -> WLAN????WLAN?????????????????????????? */
} TAF_PS_APN_DATA_SYS_POLICY_STRU;


typedef struct
{
    VOS_UINT8                               aucApn[TAF_MAX_APN_LEN + 1];
    TAF_PS_APN_DATA_SYS_POLICY_STRU         stDataSysPolicy;
} TAF_PS_APN_DATA_SYS_POLICY_INFO_STRU;


typedef struct
{
    VOS_UINT8                               ucProfileNum;
    VOS_UINT8                               aucReserved[7];
    TAF_PS_APN_DATA_SYS_POLICY_INFO_STRU    astApnDataSysInfo[TAF_PS_APN_DATA_SYS_INFO_MAX_NUM];
}TAF_PS_APN_DATA_SYS_POLICY_CONFIG_STRU;


typedef struct
{
    VOS_BOOL                                        bCellularPowerState;        /* CELLULAR???????? */
    VOS_BOOL                                        bCellularRoamingStatus;     /* CELLULAR?????????? */
    TAF_PS_CELLULAR_RAT_TYPE_ENUM_UINT8             enRatType;                  /* ???????????? */
    TAF_PS_CELLULAR_SERVICE_STATUS_ENUM_UINT8       enPsServiceStatus;          /* CELLULAR PS?????????? */
    VOS_UINT8                                       aucReserved1[2];
    VOS_BOOL                                        bWlanPowerState;            /* WLAN???????? */
    TAF_PS_WLAN_SERVICE_STATUS_ENUM_UINT8           enWiFiServiceStatus;        /* WLAN?????????? */
    VOS_UINT8                                       aucReserved2[7];
}TAF_PS_DATA_SYSTEM_STATUS_STRU;


typedef struct
{
    TAF_CTRL_STRU                                   stCtrl;

    VOS_UINT32                                      bitOpBitDataSysCid      : 1;
    VOS_UINT32                                      bitOpApn                : 1;
    VOS_UINT32                                      bitOpSpare              : 30;

    TAF_PS_DATA_SYSTEM_STATUS_STRU                  stDataSystemStatus;
    VOS_UINT32                                      ulBitDataSysSwitchCid;      /* ??????????????PDN??????CID */
    TAF_PDP_APN_STRU                                stApn;
}TAF_PS_DATA_SYSTEM_CHG_NTF_STRU;


typedef struct
{
    TAF_CTRL_STRU                               stCtrl;
    TAF_PS_APN_DATA_SYS_POLICY_CONFIG_STRU      stApnDataSysCfgList;
} TAF_PS_APN_DATA_SYS_POLICY_CFG_IND_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
} TAF_PS_GET_LTE_ATTACH_INFO_REQ_STRU;


typedef struct
{
    /* IPV4:1, IPV6:2, IPV4V6:3, PPP:4 */
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType;         /* IP TYPE*/
    VOS_UINT8                           aucReserved[3];    /* ???? */
    TAF_PDP_APN_STRU                    stApn;             /* APN ????*/
} TAF_LTE_ATTACH_QUERY_INFO_STRU;


typedef struct
{
    TAF_CTRL_STRU                       stCtrl;
    TAF_PS_CAUSE_ENUM_UINT32            enCause;                /* ??????????*/
    TAF_LTE_ATTACH_QUERY_INFO_STRU      stLteAttQueryInfo;      /* LTEAttEsm????????*/
} TAF_PS_GET_LTE_ATTACH_INFO_CNF_STRU;
/*****************************************************************************
  8 UNION????
*****************************************************************************/


/*****************************************************************************
  9 OTHERS????
*****************************************************************************/



/*****************************************************************************
  10 ????????
*****************************************************************************/

/*****************************************************************************
 ?? ?? ??  : TAF_PS_SetPrimPdpContextInfo
 ????????  : ????Primary PDP??????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstPdpContextInfo          - Primary PDP??????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_SetPrimPdpContextInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_PDP_PRIM_CONTEXT_EXT_STRU      *pstPdpContextInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetPrimPdpContextInfo
 ????????  : ????Primary PDP??????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetPrimPdpContextInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetPdpContextInfo
 ????????  : ????PDP??????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetPdpContextInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);
/*****************************************************************************
 ?? ?? ??  : TAF_PS_SetSecPdpContextInfo
 ????????  : ????Secondary PDP??????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstPdpContextInfo          - Secondary PDP??????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_SetSecPdpContextInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_PDP_SEC_CONTEXT_EXT_STRU       *pstPdpContextInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetSecPdpContextInfo
 ????????  : ????Secondary PDP??????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetSecPdpContextInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_SetTftInfo
 ????????  : ????PDP TFT????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstTftInfo                 - TFT????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_SetTftInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_TFT_EXT_STRU                   *pstTftInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetTftInfo
 ????????  : ????PDP TFT????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetTftInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_SetUmtsQosInfo
 ????????  : ????UMTS QOS????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstUmtsQosInfo             - UMTS QOS????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_SetUmtsQosInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_UMTS_QOS_EXT_STRU              *pstUmtsQosInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetUmtsQosInfo
 ????????  : ????UMTS QOS????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetUmtsQosInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_SetUmtsQosMinInfo
 ????????  : ????UMTS MIN QOS????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstUmtsQosMinInfo          - UMTS MIN QOS????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_SetUmtsQosMinInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_UMTS_QOS_EXT_STRU              *pstUmtsQosMinInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetUmtsQosMinInfo
 ????????  : ????UMTS MIN QOS????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetUmtsQosMinInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetDynamicUmtsQosInfo
 ????????  : ????????UMTS QOS????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstCidListInfo             - CID????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetDynamicUmtsQosInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_CID_LIST_STRU                  *pstCidListInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_SetPdpContextState
 ????????  : ????????CID(??)??????PDP??????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstCidListStateInfo        - CID????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_SetPdpContextState(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_CID_LIST_STATE_STRU            *pstCidListStateInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetPdpContextState
 ????????  : ??????????????CID??????PDP??????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetPdpContextState(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_CallModify
 ????????  : ????PS CALL????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             TAF_CID_LIST_STRU          - CID????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_CallModify(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_CID_LIST_STRU                  *pstCidListInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_CallAnswer
 ????????  : ????PS CALL
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstAnsInfo                 - PS CALL????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_CallAnswer(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_PS_ANSWER_STRU                 *pstAnsInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_CallHangup
 ????????  : ????PS CALL
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_CallHangup(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_CallOrig
 ????????  : ????PS CALL
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstDialParaInfo            - PS CALL????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_CallOrig(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_PS_DIAL_PARA_STRU              *pstDialParaInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_CallEnd
 ????????  : ????PS CALL
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             stCidListInfo              - CID????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_CallEnd(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucCid
);


VOS_UINT32 TAF_PS_CallEndEx(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucCid,
    TAF_PS_CALL_END_CAUSE_ENUM_UINT8    enCause
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetPdpIpAddrInfo
 ????????  : ????????CID(??)??PDP IP????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstCidListInfo             - CID????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetPdpIpAddrInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_CID_LIST_STRU                  *pstCidListInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_SetAnsModeInfo
 ????????  : ????PS??????????????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             ulAnsMode                  - ????????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_SetAnsModeInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT32                          ulAnsMode
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetAnsModeInfo
 ????????  : ????PS??????????????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetAnsModeInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetDynamicPrimPdpContextInfo
 ????????  : ????????????????CID??????Primary PDP??????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             ucCid                      - CID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetDynamicPrimPdpContextInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucCid
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetDynamicSecPdpContextInfo
 ????????  : ????????????????CID??????Secondary PDP??????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             ucCid                      - CID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetDynamicSecPdpContextInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucCid
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetDynamicTftInfo
 ????????  : ????????????????CID??????TFT????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             ucCid                      - CID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetDynamicTftInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucCid
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_SetEpsQosInfo
 ????????  : ????????CID??EPS QOS????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstEpsQosInfo              - EPS QOS????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_SetEpsQosInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_EPS_QOS_EXT_STRU               *pstEpsQosInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetEpsQosInfo
 ????????  : ????EPS QOS????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetEpsQosInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetDynamicEpsQosInfo
 ????????  : ????????????????CID??????EPS QOS????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             ucCid                      - CID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetDynamicEpsQosInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucCid
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetDsFlowInfo
 ????????  : ????????????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstQueryConfigInfo         - DSFLOW????????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetDsFlowInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_ClearDsFlowInfo
 ????????  : ????????????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstClearConfigInfo         - ????????????????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_ClearDsFlowInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_DSFLOW_CLEAR_CONFIG_STRU       *pstClearConfigInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_ConfigDsFlowRpt
 ????????  : ????????????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstReportConfigInfo        - ????????????????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_ConfigDsFlowRpt(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_DSFLOW_REPORT_CONFIG_STRU      *pstReportConfigInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_ConfigVTFlowRpt
 ????????  : ????VT????????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstReportConfigInfo        - ????????????????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_ConfigVTFlowRpt(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_VTFLOW_REPORT_CONFIG_STRU      *pstReportConfigInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_SetPdpDnsInfo
 ????????  : ????PDP DNS????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstPdpDnsInfo              - PDP DNS????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_SetPdpDnsInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_PDP_DNS_EXT_STRU               *pstPdpDnsInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetPdpDnsInfo
 ????????  : ????PDP DNS????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetPdpDnsInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_TrigGprsData
 ????????  : ????????GPRS????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstGprsDataInfo            - GPRS????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_TrigGprsData(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_GPRS_DATA_STRU                 *pstGprsDataInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_ConfigNbnsFunction
 ????????  : ????NBNS????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             ulEnabled                  - NBNS????????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_ConfigNbnsFunction(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT32                          ulEnabled
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetNdisStateInfo
 ????????  : ????NDIS????????
 ????????  : ulModuleId                 - ????PID
             usClientId                 - ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetNdisStateInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_SetAuthDataInfo
 ????????  : ????????????????(NDIS)
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstAuthDataInfo            - ????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_SetAuthDataInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_AUTHDATA_EXT_STRU              *pstAuthDataInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetAuthDataInfo
 ????????  : ????????????????(NDIS)
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetAuthDataInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetGprsActiveType
 ????????  : ????D????GPRS????(PPP????)
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstAtdPara                 - D????????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetGprsActiveType(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_ATD_PARA_STRU                  *pstAtdPara
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_PppDialOrig
 ????????  : ????PPP????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             ucCid                      - CID
             pstPppReqConfigInfo        - PPP????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_PppDialOrig(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucCid,
    TAF_PPP_REQ_CONFIG_INFO_STRU       *pstPppReqConfigInfo
);

#if(FEATURE_ON == FEATURE_LTE)
/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetLteCsInfo
 ????????  :
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetLteCsInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetCemodeInfo
 ????????  :
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetCemodeInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

VOS_UINT32 TAF_PS_SetPdpProfInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_PDP_PROFILE_EXT_STRU           *stPdpProfInfo
);
#endif

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetCidSdfParaInfo
 ????????  : ????????NV??????SDF????????, ??????????????????????
             ???????????? --- ????????(??????????C??)
             ???????????? --- ????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : pstSdfQueryInfo            - SDF????????
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetCidSdfParaInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_SDF_PARA_QUERY_INFO_STRU       *pstSdfQueryInfo
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetUnusedCid
 ????????  : ????????????????CID
             ???????????? --- ????????(??????????C??)
             ???????????? --- ????????
 ????????  : ulModuleId                 - ????PID
             usExClientId                 - ??????ID
             ucOpId                     - ??????ID
 ????????  : puCid                      - ??????????CID
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetUnusedCid(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                          *puCid
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetDynamicDnsInfo
 ????????  : ????????CID??DNS????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             ucCid                      - CID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetDynamicDnsInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucCid
);

#if (FEATURE_ON == FEATURE_UE_MODE_CDMA)
VOS_UINT32 TAF_PS_SetCqosPriInfo(
    VOS_UINT32                                      ulModuleId,
    VOS_UINT16                                      usExClientId,
    TAF_PS_CDATA_1X_QOS_NON_ASSURED_PRI_ENUM_UINT8  enPri
);
#endif

/*****************************************************************************
 ?? ?? ??  : TAF_PS_SetApDsFlowRptCfg
 ????????  : ????AP????????????
 ????????  : ulModuleId                 - PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstRptCfg                  - ????????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_SetApDsFlowRptCfg(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_APDSFLOW_RPT_CFG_STRU          *pstRptCfg
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetApDsFlowRptCfg
 ????????  : ????AP????????????
 ????????  : ulModuleId                 - PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetApDsFlowRptCfg(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_SetDsFlowNvWriteCfg
 ????????  : ??????????NV????
 ????????  : ulModuleId                 - PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
             pstNvWriteCfg              - ??????NV????
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_SetDsFlowNvWriteCfg(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_DSFLOW_NV_WRITE_CFG_STRU       *pstNvWriteCfg
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetDsFlowNvWriteCfg
 ????????  : ??????????NV????
 ????????  : ulModuleId                 - PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetDsFlowNvWriteCfg(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

VOS_UINT32 TAF_PS_SetCdataDialModeInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    TAF_PS_CDATA_DIAL_MODE_ENUM_UINT32  enDialMode
);

VOS_UINT32 TAF_PS_SetImsPdpCfg(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_IMS_PDP_CFG_STRU               *pstImsPdpCfg
);

VOS_UINT32 TAF_PS_GetCtaInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

VOS_UINT32 TAF_PS_SetCtaInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucTimeLen
);

VOS_UINT32 TAF_PS_SetCdmaDormantTimer(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucDormantTimer
);

VOS_UINT32 TAF_PS_ProcCdmaDormTimerQryReq(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);


TAF_PS_CDATA_BEAR_STATUS_ENUM_UINT8 TAF_PS_GetCdataBearStatus(
    VOS_UINT8                                               ucPdpId
);

TAF_PS_CDATA_BEAR_STATUS_ENUM_UINT8  TAF_PS_GetPppStatus( VOS_VOID );



VOS_UINT32 TAF_PS_SetMipMode(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_PS_MIP_MODE_ENUM_UINT8          enMipMode
);

VOS_UINT32 TAF_PS_GetMipMode(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

VOS_UINT32 TAF_PS_GetModuleIdByCid(
    VOS_UINT8                           ucCid,
    MODEM_ID_ENUM_UINT16                enModemId
);


VOS_UINT32 TAF_PS_SetVzwApneInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucIsCustomCmd,
    TAF_PS_VZWAPNE_INFO_STRU           *pstVzwapneInfo
);

VOS_UINT32 TAF_PS_GetVzwApneInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucIsCustomCmd
);

VOS_UINT32 TAF_PS_SetApnThrotInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    TAF_PS_APN_THROT_INFO_STRU         *pstApnThrotInfo
);

VOS_UINT8 TAF_PS_FindCidForDial(VOS_UINT32  ulAppPid);

VOS_UINT32 TAF_PS_Set_DataSwitchStatus(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucDataSwitch
);

VOS_UINT32 TAF_PS_Set_DataRoamSwitchStatus(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucDataRoamSwitch
);

VOS_UINT32 TAF_PS_Get_DataSwitchStatus(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

VOS_UINT32 TAF_PS_Get_DataRoamSwitchStatus(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : TAF_PS_GetLteAttchInfo
 ????????  : ????LTE ??????????PDN??????????
 ????????  : ulModuleId                 - ????PID
             usExClientId               - ??????????ID
                                          A?? : ModemID(????bit) + ??????ID
                                          C?? : ??????ID
             ucOpId                     - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK                     - ????
             VOS_ERR                    - ????
*****************************************************************************/
VOS_UINT32 TAF_PS_GetLteAttchInfo(
    VOS_UINT32                          ulModuleId,
    VOS_UINT16                          usExClientId,
    VOS_UINT8                           ucOpId
);

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

#endif

