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
#ifndef  TAF_TYPE_DEF_H
#define  TAF_TYPE_DEF_H

#include "v_typdef.h"


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#pragma pack(4)

/* LOCAL */
#ifdef  LOCAL
#undef  LOCAL
#endif

#ifdef _EXPORT_LOCAL
#define LOCAL
#else
#define LOCAL static
#endif


/* ---------------LogSaver????????????????????----------------------- */
/* 1.1: OM_GreenChannel????????????usPrimId??????*/
#define     TAF_OM_GREEN_CHANNEL_PS     (0xC001)                                /* PS???? */

/* 1.2: OM_GreenChannel??????????????????????????????????????????????????????????????
   ???????????????????? */
enum TAF_OM_GREENCHANNEL_ERR_ENUM
{
    TAF_OM_GREENCHANNEL_PS_CID_NOT_DEFINE = 0,
    TAF_OM_GREENCHANNEL_PS_CREATE_PPP_REQ_ERR,
    TAF_OM_GREENCHANNEL_PS_CREATE_RAW_DATA_PPP_REQ_ERR,
    TAF_OM_GREENCHANNEL_PS_IP_TYPE_DIAL_FAIL,
    TAF_OM_GREENCHANNEL_PS_PPP_TYPE_DIAL_FAIL,
    TAF_OM_GREENCHANNEL_PS_DEACTIVE_PDP_ERR_EVT,
    TAF_OM_GREENCHANNEL_PS_ACTIVE_PDP_REJ,
    TAF_OM_GREENCHANNEL_PS_MODIFY_PDP_REJ,
    TAF_OM_GREENCHANNEL_PS_NET_ORIG_DEACTIVE_IND,

    TAF_OM_GREENCHANNEL_ERR_BUTT
};

/*??????????*/
#define TAF_LITTLE_ENDIAN              1234
#define TAF_BIG_ENDIAN                 4321

#define TAF_BYTE_ORDER                 TAF_LITTLE_ENDIAN

/*OS????*/
#define TAF_WIN32                      1
#define TAF_PSOS                       2
#define TAF_VXWORKS                    3
#define TAF_LINUX                      4
#define TAF_UNIX                       5
#define TAF_SOLARIS                    6
#define TAF_TLINUX                     7
#define TAF_HPUNIX                     8
#define TAF_IBMUNIX                    9
#define TAF_RTT                        10
#define TAF_WINCE                      11
#define TAF_NUCLEUS                    12

#ifndef TAF_OS_VER
#define TAF_OS_VER                     TAF_VXWORKS
#endif

#ifndef CONST
#define CONST const
#endif

#ifndef CONST_T
#define CONST_T   const
#endif

#ifndef STATIC
#if (defined(LLT_OS_VER))
#define STATIC
#else
#define STATIC static
#endif
#endif

#undef PUBLIC
#undef PRIVATE
#undef EXTERN

#define PUBLIC    extern
#define EXTERN extern
#ifdef _EXPORT_PRIVATE
#define PRIVATE
#else
#define PRIVATE   static
#endif

#undef OUT
#undef IN

#define OUT
#define IN


/*TAF API????????*/
typedef int                 TAF_INT;
typedef signed   char       TAF_INT8;
typedef unsigned char       TAF_UINT8;

typedef signed   short      TAF_INT16;
typedef unsigned short      TAF_UINT16;

typedef signed   int        TAF_INT32;
typedef unsigned int        TAF_UINT32;

typedef char                TAF_CHAR;
typedef unsigned char       TAF_UCHAR;
#if (VOS_WIN32 == VOS_OS_VER) && (LLT_OS_VER == LLT_LINUX)
#ifndef TAF_VOID
#define TAF_VOID            void
#endif
#else
typedef void                TAF_VOID;
#endif

typedef unsigned int        TAF_BOOL;
enum
{
    TAF_FALSE = 0,
    TAF_TRUE  = 1
};

typedef TAF_UINT8 MN_CLIENT_TYPE;
enum MN_CLIENT_TYPE_ENUM
{
    TAF_APP_CLIENT,
    TAF_AT_CLIENT,
    TAF_CLIENT_TYPE_BUTT
};

typedef TAF_UINT16          MN_CLIENT_ID_T;     /* APP/AT Client ID type */
typedef TAF_UINT8           MN_OPERATION_ID_T;  /* Async operation ID type */

/* ??????????Client */
#define MN_CLIENT_ALL                                       ((MN_CLIENT_ID_T)(-1))
#define MN_OP_ID_BUTT                                       ((MN_OPERATION_ID_T)(-1))

/* ????CMMCA??client id */
#define CMMCA_CLIENT_ID                                     (0x88)

#define  TAF_NULL_PTR                   0                    /* null pointer */

#define  TAF_MAX_STATUS_TI              1

#define  TAF_ERR_CODE_BASE              (0)                 /* TAF???????????????? */
#define  TAF_ERR_PHONE_BASE             (150)               /* ?????????????? */
#define TAF_ERR_PB_BASE                 (350)               /* ???????????? */
#define TAF_ERR_SAT_BASE                (400)               /* SAT?????? */
#define TAF_ERR_SS_BASE                 (0x400)             /* SS?????? */
#define TAF_ERR_LCS_BASE                (0x500)             /* LCS?????? */
#define TAF_ERR_SS_IMS_BASE             (0x1000)            /* IMS??????SS?????? */
#define TAF_ERR_SS_IMSA_BASE            (0x2000)            /* IMSA??????SS?????? */
#define TAF_ERR_DECODE_BASE             (0x2500)            /* ?????????????? */

enum TAF_ERROR_CODE_ENUM
{
    TAF_ERR_NO_ERROR                                        = (TAF_ERR_CODE_BASE),          /* ???? */
    TAF_ERR_ERROR                                           = (TAF_ERR_CODE_BASE + 1),      /* ???? */
    TAF_ERR_NULL_PTR                                        = (TAF_ERR_CODE_BASE + 2),      /* ?????? */
    TAF_ERR_PARA_ERROR                                      = (TAF_ERR_CODE_BASE + 3),      /* ???????? */
    TAF_ERR_TIME_OUT                                        = (TAF_ERR_CODE_BASE + 4),      /* ?????????? */
    TAF_ERR_TAF_ID_INVALID                                  = (TAF_ERR_CODE_BASE + 5),      /* CallId????OpId????Smi???? */
    TAF_ERR_NUM_VALUE_INVALID                               = (TAF_ERR_CODE_BASE + 6),      /* ????????(????value????) */
    TAF_ERR_NUM_LEN_INVALID                                 = (TAF_ERR_CODE_BASE + 7),      /* ??????????0???????????????? */
    TAF_ERR_CAPABILITY_ERROR                                = (TAF_ERR_CODE_BASE + 8),      /* ?????????????? */
    TAF_ERR_CLIENTID_NO_FREE                                = (TAF_ERR_CODE_BASE + 9),      /* ????????ClientId?????????? */
    TAF_ERR_CALLBACK_FUNC_ERROR                             = (TAF_ERR_CODE_BASE + 10),     /* ???????????? */
    TAF_ERR_MSG_DECODING_FAIL                               = (TAF_ERR_CODE_BASE + 11),     /* ???????????? */
    TAF_ERR_TI_ALLOC_FAIL                                   = (TAF_ERR_CODE_BASE + 12),     /* TI???????? */
    TAF_ERR_TI_GET_FAIL                                     = (TAF_ERR_CODE_BASE + 13),     /* ????Ti???? */
    TAF_ERR_CMD_TYPE_ERROR                                  = (TAF_ERR_CODE_BASE + 14),     /* ???????????? */
    TAF_ERR_MUX_LINK_EST_FAIL                               = (TAF_ERR_CODE_BASE + 15),     /* APP??TAF????MUX???????????? */
    TAF_ERR_USIM_SIM_CARD_NOTEXIST                          = (TAF_ERR_CODE_BASE + 16),     /* USIM???????? */
    TAF_ERR_CLIENTID_NOT_EXIST                              = (TAF_ERR_CODE_BASE + 17),     /* ClientId?????? */
    TAF_ERR_NEED_PIN1                                       = (TAF_ERR_CODE_BASE + 18),     /* ????????PIN1?? */
    TAF_ERR_NEED_PUK1                                       = (TAF_ERR_CODE_BASE + 19),     /* ????????PUK1 */
    TAF_ERR_USIM_SIM_INVALIDATION                           = (TAF_ERR_CODE_BASE + 20),     /* ??????USIM/SIM?? */
    TAF_ERR_SIM_BUSY                                        = (TAF_ERR_CODE_BASE + 21),     /* SIM???? */
    TAF_ERR_SIM_LOCK                                        = (TAF_ERR_CODE_BASE + 22),     /* SIM?????? */
    TAF_ERR_SIM_INCORRECT_PASSWORD                          = (TAF_ERR_CODE_BASE + 23),     /* ???????????? */
    TAF_ERR_SIM_FAIL                                        = (TAF_ERR_CODE_BASE + 24),     /* SIM?????????? */
    TAF_ERR_NOT_READY                                       = (TAF_ERR_CODE_BASE + 25),     /* ????????????????????????????????????FTM???????? */
    TAF_ERR_FILE_NOT_EXIST                                  = (TAF_ERR_CODE_BASE + 26),     /* OPL ?????????? */
    TAF_ERR_NO_NETWORK_SERVICE                              = (TAF_ERR_CODE_BASE + 27),     /* ?????? */
    TAF_ERR_GET_CSQLVL_FAIL                                 = (TAF_ERR_CODE_BASE + 28),     /* ????CSQLVL???????? */
    TAF_ERR_AT_ERROR                                        = (TAF_ERR_CODE_BASE + 29),     /* ????AT_ERROR */
    TAF_ERR_CME_OPT_NOT_SUPPORTED                           = (TAF_ERR_CODE_BASE + 30),     /* ????AT_CME_OPERATION_NOT_SUPPORTED */
    TAF_ERR_AT_CONNECT                                      = (TAF_ERR_CODE_BASE + 31),     /* ????AT_CONNECT */
    TAF_ERR_USIM_SVR_OPLMN_LIST_INAVAILABLE                 = (TAF_ERR_CODE_BASE + 32),     /* ????(U)SIM??USIM_SVR_OPLMN_LIST???????? */
    TAF_ERR_FDN_CHECK_FAILURE                               = (TAF_ERR_CODE_BASE + 33),     /* FDN???????????? */
    TAF_ERR_INTERNAL                                        = (TAF_ERR_CODE_BASE + 34),     /* ???????? */
    TAF_ERR_NET_SEL_MENU_DISABLE                            = (TAF_ERR_CODE_BASE + 36),     /* PLMN SEL????Disable */
    TAF_ERR_SYSCFG_CS_IMS_SERV_EXIST                        = (TAF_ERR_CODE_BASE + 37),     /* ????syscfg????CS/IMS???????? */
    TAF_ERR_NEED_PUK2                                       = (TAF_ERR_CODE_BASE + 38),     /* ????????PUK2 */
    TAF_ERR_USSD_NET_TIMEOUT                                = (TAF_ERR_CODE_BASE + 39),     /* USSD?????????? TAF_ERR_USSD_TIME_OUT => TAF_ERR_USSD_NET_TIMEOUT */
    TAF_ERR_BUSY_ON_USSD                                    = (TAF_ERR_CODE_BASE + 40),     /* ????????USSD???? */
    TAF_ERR_BUSY_ON_SS                                      = (TAF_ERR_CODE_BASE + 41),     /* ????????SS???? */
    TAF_ERR_USSD_USER_TIMEOUT                               = (TAF_ERR_CODE_BASE + 42),     /* USSD????????APP???????? */
    TAF_ERR_SS_NET_TIMEOUT                                  = (TAF_ERR_CODE_BASE + 43),     /* SS???????????????????? */
    TAF_ERR_USSD_TERMINATED_BY_USER                         = (TAF_ERR_CODE_BASE + 44),     /* USSD?????????????? */
    TAF_ERR_NO_SUCH_ELEMENT                                 = (TAF_ERR_CODE_BASE + 45),     /* ???????????????????????????? */
    TAF_ERR_MISSING_RESOURCE                                = (TAF_ERR_CODE_BASE + 46),     /* ?????????????? */
    TAF_ERR_SS_DOMAIN_SELECTION_FAILURE                     = (TAF_ERR_CODE_BASE + 47),     /* ?????????????? */
    TAF_ERR_SS_DOMAIN_SELECTION_TIMER_EXPIRED               = (TAF_ERR_CODE_BASE + 48),     /* ???????????????????????????? */
    TAF_ERR_SS_POWER_OFF                                    = (TAF_ERR_CODE_BASE + 49),     /* ?????????????????????????????? */
    TAF_ERR_PHY_INIT_FAILURE                                = (TAF_ERR_CODE_BASE + 50),     /* ???????????????? */
    TAF_ERR_UNSPECIFIED_ERROR                               = (TAF_ERR_CODE_BASE + 51),     /* ???????????? */
    TAF_ERR_NO_RF                                           = (TAF_ERR_CODE_BASE + 52),     /* NO RF */

    TAF_ERR_IMS_NOT_SUPPORT                                 = (TAF_ERR_CODE_BASE + 53),     /* IMS?????? */
    TAF_ERR_IMS_SERVICE_EXIST                               = (TAF_ERR_CODE_BASE + 54),     /* IMS???????? */
    TAF_ERR_IMS_VOICE_DOMAIN_PS_ONLY                        = (TAF_ERR_CODE_BASE + 55),     /* IMS????????????PS_ONLY */
    TAF_ERR_IMS_STACK_TIMEOUT                               = (TAF_ERR_CODE_BASE + 56),     /* IMS?????????? */

    TAF_ERR_1X_RAT_NOT_SUPPORTED                            = (TAF_ERR_CODE_BASE + 57),     /* ????1X RAT?????? */

    TAF_ERR_NOT_SUPPORT_SRVCC                               = (TAF_ERR_CODE_BASE + 58),     /* USSI??????SRVCC??CALL????SRVCC???????????????? */

    TAF_ERR_SILENT_AES_DEC_PIN_FAIL                         = (TAF_ERR_CODE_BASE + 59),     /* ^SILENTPIN PIN???????????? */

    TAF_ERR_SILENT_VERIFY_PIN_ERR                           = (TAF_ERR_CODE_BASE + 60),     /* ^SILENTPIN PIN?????????? */

    TAF_ERR_SILENT_AES_ENC_PIN_FAIL                         = (TAF_ERR_CODE_BASE + 61),     /* ^SILENTPIN PIN?????????? */

    TAF_ERR_IMS_OPEN_LTE_NOT_SUPPORT                        = (TAF_ERR_CODE_BASE + 62),     /* ????ims??????????????lte */

    TAF_ERR_NOT_FIND_FILE                                   = (TAF_ERR_CODE_BASE + 63),     /* ?????????? */
    TAF_ERR_NOT_FIND_NV                                     = (TAF_ERR_CODE_BASE + 64),     /* NV?????? */
    TAF_ERR_MODEM_ID_ERROR                                  = (TAF_ERR_CODE_BASE + 65),     /* MODEM ID ???????? */
    TAF_ERR_NV_NOT_SUPPORT_ERR                              = (TAF_ERR_CODE_BASE + 66),     /* ??????????*/
    TAF_ERR_WRITE_NV_TIMEOUT                                = (TAF_ERR_CODE_BASE + 67),     /* ??nv???? */

    TAF_ERR_NETWORK_FAILURE                                 = (TAF_ERR_CODE_BASE + 68),     /* ??nv???? */

    TAF_ERR_SCI_ERROR                                       = (TAF_ERR_CODE_BASE + 69),     /* PAM ??????????????????AP???????????????????????? */

    TAF_ERR_PHONE_MSG_UNMATCH                               = (TAF_ERR_PHONE_BASE + 1),     /*??????????????*/
    TAF_ERR_PHONE_ATTACH_FORBIDDEN                          = (TAF_ERR_PHONE_BASE + 2),     /*????ATTACH????*/
    TAF_ERR_PHONE_DETACH_FORBIDDEN                          = (TAF_ERR_PHONE_BASE + 3),     /*????DETACH????*/


    TAF_ERR_PB_NOT_INIT                                     = (TAF_ERR_PB_BASE + 1),        /* PB?????????????? */
    TAF_ERR_PB_MALLOC_FAIL                                  = (TAF_ERR_PB_BASE + 2),        /* ???????????? */
    TAF_ERR_PB_WRONG_INDEX                                  = (TAF_ERR_PB_BASE + 3),        /* ??????index */
    TAF_ERR_PB_WRONG_PARA                                   = (TAF_ERR_PB_BASE + 4),        /* ?????????????? */
    TAF_ERR_PB_STORAGE_FULL                                 = (TAF_ERR_PB_BASE + 5),        /* ???????? */
    TAF_ERR_PB_STORAGE_OP_FAIL                              = (TAF_ERR_PB_BASE + 6),        /* ?????????? */
    TAF_ERR_PB_NOT_FOUND                                    = (TAF_ERR_PB_BASE + 7),        /* ?????????? */
    TAF_ERR_PB_DIAL_STRING_TOO_LONG                         = (TAF_ERR_PB_BASE + 8),        /* ?????????????? */


    TAF_ERR_SAT_MALLOC_FAIL                                 = (TAF_ERR_SAT_BASE + 1),       /* ???????????? */
    TAF_ERR_SAT_WRONG_PARA                                  = (TAF_ERR_SAT_BASE + 2),       /* ?????????????? */
    TAF_ERR_SAT_STORAGE_OP_FAIL                             = (TAF_ERR_SAT_BASE + 3),       /* ?????????? */
    TAF_ERR_SAT_STORAGE_OP_93_SW                            = (TAF_ERR_SAT_BASE + 4),       /* 93???? */
    TAF_ERR_SAT_NO_MAIN_MENU                                = (TAF_ERR_SAT_BASE + 5),       /* ?????????? */

    TAF_ERR_LCS_METHOD_NOT_SUPPORTED                        = (TAF_ERR_LCS_BASE + 0),       /* ?????????????? */
    TAF_ERR_LCS_ADDITIONAL_ASSIS_DATA_REQIRED               = (TAF_ERR_LCS_BASE + 1),       /* ?????????????????? */
    TAF_ERR_LCS_NOT_ENOUGH_SATELLITES                       = (TAF_ERR_LCS_BASE + 2),       /* ?????????????? */
    TAF_ERR_LCS_UE_BUSY                                     = (TAF_ERR_LCS_BASE + 3),       /* ???????? */
    TAF_ERR_LCS_NETWORK_ERROR                               = (TAF_ERR_LCS_BASE + 4),       /* ???????? */
    TAF_ERR_LCS_TOO_MANY_CONNECTIONS                        = (TAF_ERR_LCS_BASE + 5),       /* ?????????????????????????? */
    TAF_ERR_LCS_TOO_MANY_USERS                              = (TAF_ERR_LCS_BASE + 6),       /* ?????????????????????????? */
    TAF_ERR_LCS_FAILURE_DUE_TO_HANDOVER                     = (TAF_ERR_LCS_BASE + 7),       /* ???????????????? */
    TAF_ERR_LCS_INTERNET_CONN_FAILURE                       = (TAF_ERR_LCS_BASE + 8),       /* ???????????? */
    TAF_ERR_LCS_MEMORY_ERROR                                = (TAF_ERR_LCS_BASE + 9),       /* ???????? */
    TAF_ERR_LCS_UNKNOWN_ERROR                               = (TAF_ERR_LCS_BASE + 10),      /* ???????? */

    TAF_DECODE_ERR_NOT_SUPPORT_ENCODING_TYPE                = (TAF_ERR_DECODE_BASE + 0),    /* ???????????????? */
    TAF_DECODE_ERR_UTF8_BEYOND_MAX_BYTE_LIMIT               = (TAF_ERR_DECODE_BASE + 1),    /* UTF8????????????????????????????????????????????????3?????? */
    TAF_DECODE_ERR_UTF8_ABNORMAL_BYTE_HEADER                = (TAF_ERR_DECODE_BASE + 2),    /* UTF8????????????????????????????????????????????????????0,2,3????????1?????? */
    TAF_DECODE_ERR_UTF8_ABNORMAL_BYTE_CONTENT               = (TAF_ERR_DECODE_BASE + 3),    /* UTF8????????????????????????????????????????bit??"10" */
    TAF_DECODE_ERR_BYTE_NUM_ABNORMAL                        = (TAF_ERR_DECODE_BASE + 4),    /* ???????????????????????? */

    TAF_ERR_CODE_BUTT                                       = (0xFFFFFFFF)
};
typedef  VOS_UINT32  TAF_ERROR_CODE_ENUM_UINT32;

#ifndef TAF_SUCCESS
#define TAF_SUCCESS    TAF_ERR_NO_ERROR     /*????????????*/
#endif
#ifndef TAF_FAILURE
#define TAF_FAILURE    TAF_ERR_ERROR        /*????????????*/
#endif

typedef TAF_UINT8 TAF_PARA_TYPE;


#define TAF_PH_MS_CLASS_PARA             91


#define TAF_PH_IMSI_ID_PARA              98    /*+CIMI - ????IMSI*/


#define TAF_PH_NETWORKNAMEFROMUSIM_PARA  105   /*^SPIN, ??USIM????????????????????*/


#define TAF_PH_IDENTIFICATION_INFO_PARA  107
#define TAF_PH_CUR_FREQ                  108
#define TAF_PH_ICC_ID                    110
#define TAF_PH_CELL_RSCP_VALUE_PARA      111
#define TAF_PH_UE_RFPOWER_FREQ_PARA      112
#define TAF_PH_ICC_TYPE_PARA             114
#define TAF_PH_ICC_STATUS_PARA           115
#define TAF_PH_LOAD_DEFAULT              117
#define TAF_PH_PNN_PARA                  120
#define TAF_PH_OPL_PARA                  121


#define TAF_PH_CPNN_PARA                 125
#define TAF_PH_PNN_RANGE_PARA            126
#define TAF_PH_OPL_RANGE_PARA            127


#define TAF_PH_SIMLOCK_VALUE_PARA        (137)                                  /*^SIMLOCK=2???????????????????? */


#define TAF_TELE_PARA_BUTT               (142)



/*????????????????????????*/
#define TAF_MMA_AT_QUERY_PARA_BEGIN (TAF_TELE_PARA_BUTT + 1)/*137*/


/*????????????????*/
#define  TAF_PH_ROAM_STATUS_PARA    (TAF_MMA_AT_QUERY_PARA_BEGIN + 1)/*138*/

/*??????????????????*/
#define  TAF_PH_DOMAIN_PARA         (TAF_PH_ROAM_STATUS_PARA + 1)/*139*/

/*GMR??????????mobile software revision, release date, release time*/
#define  TAF_PH_GMR_PARA            (TAF_PH_DOMAIN_PARA + 1)/*140*/

/*??????????GMM??CGMM????*/
#define  TAF_PH_PRODUCT_NAME_PARA   (TAF_PH_GMR_PARA + 1)/*141*/


/*????????????*/
typedef TAF_UINT8 TAF_PARA_SET_RESULT;
#define TAF_PARA_OK                            0  /*????????????*/
#define TAF_PARA_SET_ERROR                     1  /*????????????*/
#define TAF_PARA_WRITE_NVIM_ERROR              2  /*??NVIM????*/
#define TAF_PARA_TYPE_NOT_SUPPORT              3  /*????????????????*/
#define TAF_PARA_CID_NOT_SUPPORT               4  /*CID????????????????*/
#define TAF_PARA_NOT_INCLUDE_ALL_OP_IE         5  /*??????????????????????????????????*/
#define TAF_PARA_IE_DECODE_ERROR               6  /*????????????*/
#define TAF_PARA_IE_ENCODE_ERROR               7  /*????????????*/
#define TAF_PARA_IE_VALUE_ERROR                8  /*????????????*/
#define TAF_PARA_CMD_NOT_MATCH_PARA            9  /*????????????????????*/
#define TAF_PARA_SIM_IS_BUSY                   10 /*SIM??????*/
#define TAF_PARA_PDP_CONTEXT_NOT_DEFINED       11 /*PDP????????????*/
#define TAF_PARA_SEC_PDP_CONTEXT_NOT_DEFINED   12 /*????PDP????????????*/
#define TAF_PARA_TFT_NOT_DEFINED               13 /*TFT??????*/
#define TAF_PARA_QOS_NOT_DEFINED               14 /*QOS??????*/
#define TAF_PARA_MIN_QOS_NOT_DEFINED           15 /*MIN QOS??????*/
#define TAF_PARA_SPN_NO_EXIST                  16 /*spn??????????*/
#define TAF_PARA_ALLOC_MEM_FAIL                17 /*??????????,????????????*/
#define TAF_PARA_NO_USIM_ERROR                 18 /*????imsi????USIM????*/
#define TAF_PARA_AUTH_NOT_DEFINED              19 /*AUTH??????*/
#define TAF_PARA_MEMORY_FULL                   20
#define TAF_PARA_INVALID_INDEX                 21
#define TAF_PARA_NDIS_AUTHDATA_NOT_DEFINED     22 /*NDIS AUTHDATA??????*/
#define TAF_PARA_EPS_QOS_NOT_DEFINED           23 /* EPS QOS?????? */
#define TAF_PARA_INVALID_PLMNID                24
#define TAF_PARA_DUPLICATE_PLMNINFO            25
#define TAF_PARA_UNSPECIFIED_ERROR             255 /*????????*/



/* ????????????????????????????BCD??????????
   ????????10????????????????????????: 0x51 ????0x15,????10??????15
   ????????????????????15?????????? */
typedef struct{
    VOS_UINT8                       ucYear;
    VOS_UINT8                       ucMonth;
    VOS_UINT8                       ucDay;
    VOS_UINT8                       ucHour;
    VOS_UINT8                       ucMinute;
    VOS_UINT8                       ucSecond;
    VOS_INT8                        cTimeZone;
    VOS_UINT8                       Reserved;
}TIME_ZONE_TIME_STRU;

/* ????MMCMM_INFO_IND???????? */
typedef struct
{
    VOS_UINT8                       ucIeFlg;
    VOS_INT8                        cLocalTimeZone;
    VOS_UINT8                       ucDST;
    VOS_UINT8                       ucLSAID[3];
    VOS_UINT8                       aucReserve[2];
    TIME_ZONE_TIME_STRU             stUniversalTimeandLocalTimeZone;
}NAS_MM_INFO_IND_STRU;


typedef struct
{
    VOS_UINT32                          ulModemId;
    VOS_UINT32                          ulNvItemId;
    VOS_UINT32                          ulNvLength;
    VOS_UINT32                          ulIsNeedCheck;
    VOS_UINT32                          ulOffset;
    VOS_VOID                           *pData;
}TAF_WRITE_ACORE_NV_STRU;


enum TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM
{
    ID_TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_NV_FLUSH,

    ID_TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_NV_UPGRADE_BACKUP,

    ID_TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_NV_BACKUP_FNV,

    ID_TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_NV_FREVERT_FNV,

    ID_TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_BUTT
};
typedef VOS_UINT32  TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_UINT32;


#define TAF_REBOOT_MOD_ID_MEM     0x68000000
#define TAF_REBOOT_MOD_ID_BUTT    0X6FFFFFFF

#if (VOS_OS_VER == VOS_WIN32)
#define TAF_MEM_CPY_S(pDestBuffer, ulDestLen,  pSrcBuffer, ulCount) VOS_MemCpy_s( pDestBuffer, (VOS_UINT32)ulDestLen,  pSrcBuffer, (VOS_UINT32)ulCount)

#define TAF_MEM_SET_S(pDestBuffer, ulDestLen, ucData, ulCount) VOS_MemSet_s( pDestBuffer, (VOS_UINT32)ulDestLen, (VOS_CHAR)(ucData), (VOS_UINT32)ulCount )

#define TAF_MEM_MOVE_S(pDestBuffer, ulDestLen, pucSrcBuffer, ulCount) VOS_MemMove_s( pDestBuffer, ulDestLen, pucSrcBuffer, ulCount )

#define TAF_MEM_CMP( pucDestBuffer, pucSrcBuffer, ulBufferLen ) \
                    memcmp(pucDestBuffer, pucSrcBuffer, ulBufferLen )

#else
#define TAF_MEM_CPY_S(pDestBuffer, ulDestLen,  pSrcBuffer, ulCount) { \
            TAF_STD_MemCpy_s( (pDestBuffer), (VOS_UINT32)(ulDestLen), (pSrcBuffer), (VOS_UINT32)(ulCount), (VOS_INT)((THIS_FILE_ID << 16) | __LINE__) ); \
        }

#define TAF_MEM_SET_S(pDestBuffer, ulDestLen, ucData, ulCount) { \
            TAF_STD_MemSet_s( (pDestBuffer), (VOS_UINT32)(ulDestLen), ((VOS_CHAR)(ucData)), (VOS_UINT32)(ulCount), (VOS_INT)((THIS_FILE_ID << 16) | __LINE__) ); \
        }

#define TAF_MEM_MOVE_S(pDestBuffer, ulDestLen, pucSrcBuffer, ulCount) { \
            TAF_STD_MemMove_s( (pDestBuffer), (ulDestLen), (pucSrcBuffer), (ulCount), (VOS_INT)((THIS_FILE_ID << 16) | __LINE__) ); \
        }

#define TAF_MEM_CMP( pucDestBuffer, pucSrcBuffer, ulBufferLen ) \
                VOS_MemCmp( pucDestBuffer, pucSrcBuffer, ulBufferLen )

#endif


#define TAF_MIN(x, y)\
        (((x)<(y))?(x):(y))

#define TAF_BIT_TO_BYTE_LEN(a) (((a)+7)/8)

#if (OSA_CPU_ACPU == VOS_OSA_CPU)
/* ????AT^NVSTUB???? */
#define TAF_ACORE_NV_READ(modemid, id, item, len)                   mdrv_nv_readex(modemid, id, item, len)

/*  ??????????nv???? */
#define TAF_ACORE_NV_READ_FACTORY(modemid, id, item, len)           mdrv_nv_readex_factory(modemid, id, item, len)


/* ????mdrv_nv_writeex????????C??????NV???????????? */
#define TAF_ACORE_NV_WRITE(ulModemId, ulNvItemId, pData, ulNvLength)  TAF_AGENT_WriteACoreNv(AT_FillACoreNvWriteStru(ulModemId, ulNvItemId, pData, ulNvLength))

/* ????mdrv_nv_write_partex????????C??????NV???????????? */
#define TAF_ACORE_NV_WRITE_PART(ulModemId, ulNvItemId, ulOffset, pData, ulNvLength)  TAF_AGENT_WriteACoreNv(AT_FillACoreNvWritePartStru(ulModemId, ulNvItemId, ulOffset, pData, ulNvLength))

#ifdef FEATURE_AT_NV_WRITE_SUPPORT
/* ????mdrv_nv_writeex??????????AT^NVWR??????C??????????????????????ENG?????????? */
#define TAF_ACORE_NV_WRITE_NO_CHECK(ulModemId, ulNvItemId, pData, ulNvLength)  TAF_AGENT_WriteACoreNv(AT_FillACoreNvWriteNoCheckStru(ulModemId, ulNvItemId, pData, ulNvLength))

/* ????mdrv_nv_write_partex??????????AT^NVWRPART??????C??????????????????????ENG?????????? */
#define TAF_ACORE_NV_WRITE_PART_NO_CHECK(ulModemId, ulNvItemId, ulOffset, pData, ulNvLength)  TAF_AGENT_WriteACoreNv(AT_FillACoreNvWritePartNoCheckStru(ulModemId, ulNvItemId, ulOffset, pData, ulNvLength))
#endif



#ifdef FEATURE_NV_SEC_ON
#define TAF_ACORE_NV_FLUSH()                                        TAF_AGENT_ProcACoreNv(ID_TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_NV_FLUSH)
#define TAF_ACORE_NV_UPGRADE_BACKUP(uloption)                       TAF_AGENT_ProcACoreNv(ID_TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_NV_UPGRADE_BACKUP)
#define TAF_ACORE_NV_BACKUP_FNV()                                   TAF_AGENT_ProcACoreNv(ID_TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_NV_BACKUP_FNV)
#define TAF_ACORE_NV_FREVERT_FNV()                                  TAF_AGENT_ProcACoreNv(ID_TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_NV_FREVERT_FNV)
#else
#define TAF_ACORE_NV_FLUSH()                                        mdrv_nv_flush()
#define TAF_ACORE_NV_UPGRADE_BACKUP(uloption)                       mdrv_nv_backup()
#define TAF_ACORE_NV_BACKUP_FNV()                                   mdrv_nv_backup_factorynv()
#define TAF_ACORE_NV_FREVERT_FNV()                                  mdrv_nv_revert_factorynv()
#endif

#define TAF_ACORE_NV_READ_PART(modemid, id, off, item, len)         mdrv_nv_read_partex(modemid, id, off, item, len)
#define TAF_ACORE_NV_GET_LENGTH(id, len)                            mdrv_nv_get_length(id, len)
#define TAF_ACORE_NV_RESTORE_RESULT()                               mdrv_nv_restore_result()
#define TAF_ACORE_NV_GET_NV_LIST_NUM()                              mdrv_nv_get_nvid_num()
#define TAF_ACORE_NV_GET_NV_ID_LIST(list)                           mdrv_nv_get_nvid_list(list)
#define TAF_ACORE_NV_UPGRADE_RESTORE()                              mdrv_nv_restore()
#define TAF_ACORE_NV_GET_REVERT_NUM(enNvItem)                       mdrv_nv_get_revert_num(enNvItem)
#define TAF_ACORE_NV_GET_REVERT_LIST(enNvItem, pusNvList, ulNvNum)  mdrv_nv_get_revert_list(enNvItem, pusNvList, ulNvNum)
#endif

#if ( VOS_WIN32 == VOS_OS_VER )
#ifdef DMT
#define TAF_ACORE_NV_READ(modemid, id, item, len)                   mdrv_nv_readex(modemid, id, item, len)

#define TAF_ACORE_NV_READ_FACTORY(modemid, id, item, len)           mdrv_nv_readex(modemid, id, item, len)

#define TAF_ACORE_NV_WRITE_OLD(modemid, id, item, len)              mdrv_nv_writeex(modemid, id, item, len)

#define TAF_ACORE_NV_WRITE(ulModemId, ulNvItemId, pData, ulNvLength)  TAF_AGENT_WriteACoreNv(AT_FillACoreNvWriteStru(ulModemId, ulNvItemId, pData, ulNvLength))

#define TAF_ACORE_NV_WRITE_NO_CHECK(ulModemId, ulNvItemId, pData, ulNvLength)  TAF_AGENT_WriteACoreNv(AT_FillACoreNvWriteNoCheckStru(ulModemId, ulNvItemId, pData, ulNvLength))

#define TAF_ACORE_NV_WRITE_PART(ulModemId, ulNvItemId, ulOffset, pData, ulNvLength)  TAF_AGENT_WriteACoreNv(AT_FillACoreNvWritePartStru(ulModemId, ulNvItemId, ulOffset, pData, ulNvLength))

#define TAF_ACORE_NV_WRITE_PART_NO_CHECK(ulModemId, ulNvItemId, ulOffset, pData, ulNvLength)  TAF_AGENT_WriteACoreNv(AT_FillACoreNvWritePartNoCheckStru(ulModemId, ulNvItemId, ulOffset, pData, ulNvLength))

#define TAF_ACORE_NV_FLUSH()                                        TAF_AGENT_ProcACoreNv(ID_TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_NV_FLUSH)
#define TAF_ACORE_NV_UPGRADE_BACKUP(uloption)                       TAF_AGENT_ProcACoreNv(ID_TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_NV_UPGRADE_BACKUP)
#define TAF_ACORE_NV_UPGRADE_RESTORE()                              mdrv_nv_restore()
#define TAF_ACORE_NV_BACKUP_FNV()                                   TAF_AGENT_ProcACoreNv(ID_TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_NV_BACKUP_FNV)
#define TAF_ACORE_NV_FREVERT_FNV()                                  TAF_AGENT_ProcACoreNv(ID_TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_NV_FREVERT_FNV)
#else
#define TAF_ACORE_NV_READ(modemid, id, item, len)                                             mdrv_nv_readex(modemid, id, item, len)

#define TAF_ACORE_NV_WRITE_OLD(modemid, id, item, len)                                        mdrv_nv_writeex(modemid, id, item, len)

#define TAF_ACORE_NV_WRITE(ulModemId, ulNvItemId, pData, ulNvLength)                          mdrv_nv_writeex(ulModemId, ulNvItemId, pData, ulNvLength)

#define TAF_ACORE_NV_WRITE_NO_CHECK(ulModemId, ulNvItemId, pData, ulNvLength)                 mdrv_nv_writeex(ulModemId, ulNvItemId, pData, ulNvLength)

#define TAF_ACORE_NV_WRITE_PART(ulModemId, ulNvItemId, ulOffset, pData, ulNvLength)           mdrv_nv_write_partex(ulModemId, ulNvItemId, ulOffset, pData, ulNvLength)

#define TAF_ACORE_NV_WRITE_PART_NO_CHECK(ulModemId, ulNvItemId, ulOffset, pData, ulNvLength)  mdrv_nv_write_partex(ulModemId, ulNvItemId, ulOffset, pData, ulNvLength)

#define TAF_ACORE_NV_GET_LENGTH(id, len)                            mdrv_nv_get_length(id, len)
#define TAF_ACORE_NV_FLUSH()                                        mdrv_nv_flush()
#define TAF_ACORE_NV_UPGRADE_BACKUP(uloption)                       mdrv_nv_backup()
#define TAF_ACORE_NV_UPGRADE_RESTORE()                              mdrv_nv_restore()
#define TAF_ACORE_NV_BACKUP_FNV()                                   mdrv_nv_backup_factorynv()
#define TAF_ACORE_NV_FREVERT_FNV()                                  mdrv_nv_revert_factorynv()
#endif
#endif

/*lint -save -e752*/
extern VOS_VOID TAF_STD_MemCpy_s(
    VOS_VOID                           *pDestBuffer,
    VOS_UINT32                          ulDestSize,
    const VOS_VOID                     *pSrcBuffer,
    VOS_UINT32                          ulCount,
    VOS_INT32                           lFileIdAndLine
);
/*lint -save -e752*/
extern VOS_VOID TAF_STD_MemSet_s(
    VOS_VOID                           *pDestBuffer,
    VOS_UINT32                          ulDestSize,
    VOS_CHAR                            ucChar,
    VOS_UINT32                          ulCount,
    VOS_INT32                           lFileIdAndLine
);
/*lint -save -e752*/
extern VOS_VOID TAF_STD_MemMove_s(
    VOS_VOID                           *pDestBuffer,
    VOS_UINT32                          ulDestSize,
    const VOS_VOID                     *pSrcBuffer,
    VOS_UINT32                          ulCount,
    VOS_INT32                           lFileIdAndLine
);

extern VOS_UINT32 TAF_AGENT_WriteACoreNv(
    TAF_WRITE_ACORE_NV_STRU            *pstWriteAcoreNv
);
extern VOS_UINT32 TAF_AGENT_ProcACoreNv(
    TAFAGENT_MTA_PROC_ACORE_NV_TPYE_ENUM_UINT32             enProcACoreNvType
);
extern TAF_WRITE_ACORE_NV_STRU * AT_FillACoreNvWriteStru(
    VOS_UINT32                          ulModemId,
    VOS_UINT32                          ulNvItemId,
    VOS_VOID                           *pData,
    VOS_UINT32                          ulNvLength
);
extern TAF_WRITE_ACORE_NV_STRU * AT_FillACoreNvWriteNoCheckStru(
    VOS_UINT32                          ulModemId,
    VOS_UINT32                          ulNvItemId,
    VOS_VOID                           *pData,
    VOS_UINT32                          ulNvLength
);
extern TAF_WRITE_ACORE_NV_STRU * AT_FillACoreNvWritePartStru(
    VOS_UINT32                          ulModemId,
    VOS_UINT32                          ulNvItemId,
    VOS_UINT32                          ulOffset,
    VOS_VOID                           *pData,
    VOS_UINT32                          ulNvLength
);
extern TAF_WRITE_ACORE_NV_STRU * AT_FillACoreNvWritePartNoCheckStru(
    VOS_UINT32                          ulModemId,
    VOS_UINT32                          ulNvItemId,
    VOS_UINT32                          ulOffset,
    VOS_VOID                           *pData,
    VOS_UINT32                          ulNvLength
);

extern MN_CLIENT_ID_T MN_GetRealClientId(
    MN_CLIENT_ID_T                      usClientId,
    VOS_UINT32                          ulPid
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

#endif /* TAF_TYPE_DEF_H */

