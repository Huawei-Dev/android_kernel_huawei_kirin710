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

#ifndef __NAS_ERRLOG_CFG_H__
#define __NAS_ERRLOG_CFG_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#pragma pack(4)

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "vos.h"
#include "product_config.h"

/*****************************************************************************
  2 ??????
*****************************************************************************/

/*****************************************************************************
  3 ????????
*****************************************************************************/


enum NAS_ERR_LOG_ALM_ID_ENUM
{
    NAS_ERR_LOG_ALM_CS_REG_FAIL                             = 0x01,             /* CS?????????? */
    NAS_ERR_LOG_ALM_PS_REG_FAIL                             = 0x02,             /* PS?????????? */
    NAS_ERR_LOG_ALM_OOS_NW_SRCH_PROC_INFO                   = 0x03,             /* ?????????????????????? */
    NAS_ERR_LOG_ALM_CS_CALL_FAIL                            = 0x04,             /* CS?????????????????? */
    NAS_ERR_LOG_ALM_PS_CALL_FAIL                            = 0x05,             /* PS?????????????????? */
    NAS_ERR_LOG_ALM_SMS_FAIL                                = 0x06,             /* ???????? */
    NAS_ERR_LOG_ALM_VC_OPT_FAIL                             = 0x07,             /* VC???????? */
    NAS_ERR_LOG_ALM_CS_PAGING_FAIL                          = 0x08,             /* CS PAGING fail */
    NAS_ERR_LOG_ALM_CS_MT_CALL_FAIL                         = 0x09,             /* CS MT fail */
    NAS_ERR_LOG_ALM_CSFB_MT_CALL_FAIL                       = 0x0a,             /* CSFB MT fail */
    NAS_ERR_LOG_ALM_MNTN                                    = 0x0b,             /* ?????????????????? */
    NAS_ERR_LOG_ALM_NW_DETACH_IND                           = 0x0c,             /* ??????????DETACH???? */

    NAS_ERR_LOG_ALM_PS_SRV_REG_FAIL                         = 0x0d,             /* PS SERVICE???? */
    NAS_ERR_LOG_ALM_CM_SRV_REJ_IND                          = 0x0e,             /* CS SERVICE???? */
    NAS_ERR_LOG_ALM_MO_DETACH_IND                           = 0x0f,             /* ??????????DETACH */
    NAS_ERR_LOG_ALM_RAT_FREQUENTLY_SWITCH                   = 0x10,             /* 4G??2/3G???????? */

    NAS_ERR_LOG_ALM_OOS_BEGIN                               = 0x11,             /* ?????????? */
    NAS_ERR_LOG_ALM_OOS_END                                 = 0x12,             /* ?????????? */

    NAS_ERR_LOG_ALM_PROCESS_INFO_IND                        = 0x13,             /* ???????????? */

    NAS_ERR_LOG_ALM_FFT_SRCH_MCC_INFO                       = 0x14,             /* FFT????MCC?????? */

    NAS_ERR_LOG_ALM_GET_CARD_IMSI_FAIL                      = 0x15,             /* ????????IMSI?????? */

    NAS_ERR_LOG_ALM_SRVCC_FAIL_INFO                         = 0x16,             /* FFT????MCC?????? */

    NAS_ERR_LOG_ALM_LTE_LOST                                = 0x17,             /* ??????????????????LTE?????? */
    NAS_ERR_LOG_ALM_LTE_LOST_DETAIL_INFO                    = 0x18,             /* ????????????????4G???????????????? */

    NAS_ERR_LOG_ALM_MM_CSFB_INFO                            = 0x19,             /* MM??CSFB???? */
    NAS_ERR_LOG_ALM_PROCESS_INFO_MM_RCV_CALL_SRV            = 0x1A,             /* MM???????????????????????? */
    NAS_ERR_LOG_ALM_PROCESS_INFO_MM_AUTH                    = 0x1B,             /* MM?????????????? */
    NAS_ERR_LOG_ALM_PROCESS_INFO_CC_ALERTING                = 0x1C,             /* CC ALERTING?????????? */
    NAS_ERR_LOG_ALM_PROCESS_INFO_CC_PROGRESS_IND            = 0x1D,             /* Progress Indicator?????????? */
    NAS_ERR_LOG_ALM_CC_ABNORNAL_HANGUP                      = 0x1E,             /* CC?????????? */
    NAS_ERR_LOG_ALM_CC_REEST                                = 0x1F,             /* CC???????? */
    NAS_ERR_LOG_ALM_TAF_CALL_INFO_STATS                     = 0x20,             /* TAF CALL?????????????? */

    NAS_ERR_LOG_ALM_MM_PAGING_RSP_RETRY_SUCC                = 0x21,             /* ???????????????????????????? */

    NAS_ERR_LOG_ALM_INTER_SYSTIM_RESUME_TIMER_ABNORMAL      = 0x22,             /* ??????resume???????????? */

    NAS_ERR_LOG_ALM_MM_PAGING_CACHE_RETRY_SUCC              = 0x23,             /* ?????????????????????? */

    NAS_ERR_LOG_ALM_CHECK_SMS_STATUS_TIMEOUT                = 0x24,             /* TAF???????????????????? */

    NAS_ERR_LOG_ALM_OOS_STATS_INFO                          = 0x25,           /* ????????????CHR?????????????? */

    NAS_ERR_LOG_ALM_CC_DECODE_FAIL                          = 0x26,             /* CC???????? */

    NAS_ERR_LOG_ALM_MM_MT_S12_DISCARD_SYSINFO_INFO          = 0x28,             /* ??????S12???????????????????????? */

    NAS_ERR_LOG_ALM_CC_INCOMPATIBLE_INFO                    = 0x29,             /* ???????????? */

    NAS_ERR_LOG_ALM_DOMAIN_CAPABILITY                       = 0x2a,             /* ?????????????? */

    NAS_ERR_LOG_ALM_TIMER_ERR                               = 0x2b,             /* ?????????? */

    NAS_ERR_LOG_ALM_NETWORK_PARA_CLT                        = 0x2c,             /* ???????????? */

    NAS_ERR_LOG_ALM_SIM_INFO_CLT                            = 0x2d,            /* ???????????????????????? */

    NAS_ERR_LOG_ALM_RELATIVE_STILL_MODE_INFO                = 0x2e,            /* ???????????????? */
    /****************************************************************************************************************************
    **********************************    GUNAS ??CNAS CHR????????????    *******************************************************
    ****************************************************************************************************************************/

    NAS_ERR_LOG_ALM_1X_COMMON_INFO                          = 0x40,              /*1x????????*/
    NAS_ERR_LOG_ALM_1X_OOS_REPORT                           = 0x41,              /*1x????????????*/
    NAS_ERR_LOG_ALM_1X_OOS_RECOVERY                         = 0x42,              /*1x????????????????*/
    NAS_ERR_LOG_ALM_1X_OOS_SEARCH                           = 0x43,              /*1x????????????????*/
    NAS_ERR_LOG_ALM_1X_CS_MO_CALL_EXCEPTION                 = 0x44,              /*1x CS????????*/
    NAS_ERR_LOG_ALM_1X_MT_SERVICE_EXCEPTION                 = 0x45,              /*1x????????*/
    NAS_ERR_LOG_ALM_1X_CS_CONVERSATION_EXCEPTION            = 0x46,              /*1x CS????*/
    NAS_ERR_LOG_ALM_1X_CODEC_FAIL                           = 0x47,              /* 1X?????????????????? */
    NAS_ERR_LOG_ALM_1X_QPCH_SUPPORT                         = 0x48,             /* 1x QPCH???????????? */

    NAS_ERR_LOG_ALM_1X_OOS_PROCESS_INFO                     = 0x49,             /* CL????????????????:1x ???????????? */

    NAS_ERR_LOG_ALM_1X_MT_REEST_INFO                        = 0x4a,             /* 1x???????????? */

    NAS_ERR_LOG_ALM_HRPD_COMMON_INFO                        = 0x80,              /*Hrpd????????*/
    NAS_ERR_LOG_ALM_CDMA_PS_CALL_FAIL                       = 0x81,              /*Hrpd PS ????????*/
    NAS_ERR_LOG_ALM_CDMA_PS_DISC_EXCEPTION                  = 0x82,              /*Hrpd PS ????*/
    NAS_ERR_LOG_ALM_HRPD_UATI_FAIL                          = 0x83,              /*Uati????*/
    NAS_ERR_LOG_ALM_HRPD_SESSION_FAIL                       = 0x84,              /*Session????*/
    NAS_ERR_LOG_ALM_HRPD_SESSION_EXCEP_DEACT                = 0x85,              /*Session??????????*/
    NAS_ERR_LOG_ALM_CL_OOS_SEARCH                           = 0x86,              /*CL????????????????*/
    NAS_ERR_LOG_ALM_HRPD_OR_LTE_OOS_REPORT                  = 0x87,             /* CL??????HRPD??LTE???????? */
    NAS_ERR_LOG_ALM_HRPD_OR_LTE_OOS_RECOVERY                = 0x88,              /* CL??????HRPD??LTE???????????? */
    NAS_ERR_LOG_ALM_HRPD_OOS_SEARCH                         = 0x89,              /* HRPD???????????????? */
    NAS_ERR_LOG_ALM_XREG_FAIL_INFO                          = 0x8A,
    NAS_ERR_LOG_ALM_XSMS_SND_FAIL                           = 0x8B,
    NAS_ERR_LOG_ALM_XSMS_RCV_FAIL                           = 0x8C,
    NAS_ERR_LOG_ALM_CL_LTE_COMMON_INFO                      = 0x8D,           /* CL????????LTE???????? */

    NAS_ERR_LOG_ALM_RESERVED                                = 0x8E,              /* ALARMID????????????????????????????CNAS ALARM ID???????????? */

    NAS_ERR_LOG_ALM_CL_LEAVE_LTE_REPORT                     = 0X8F,              /* ??????????LTE???????? */
    NAS_ERR_LOG_ALM_CL_LEAVE_LTE_INFO                       = 0X90,              /* ??????????LTE???? */
    NAS_ERR_LOG_ALM_HRPD_CODEC_FAIL                         = 0x91,            /* HRPD?????????????????? */

    NAS_ERR_LOG_ALM_HRPD_SESSION_CLOSE_PROT_NEG_ERR         = 0x92,            /* HRPD SessionClose????????PROT_NEG_ERR?????? */
    NAS_ERR_LOG_ALM_QUICK_BACK_TO_4G_STATISTIC_INFO         = 0x93,            /* APS??????3G??????4G???????? */

    NAS_ERR_LOG_ALM_CSCALL_IMS_FAIL_1X_REDIAL_INFO          = 0x95,             /* ????VOLTE IMS???????????????????????? */

    NAS_ERR_LOG_ALM_DO_LTE_OOS_PROCESS_INFO                 = 0x96,             /* CL????????????????:DO_LTE ???????????? */

    NAS_ERR_LOG_MODEM_RESTART_ABORT_SERVICE                 = 0x97,               /* Modem??????????????????????chr???? */

    NAS_ERR_LOG_ALM_CL_RAT_MODE_FREQUENTLY_SWITCH_INFO      = 0x98,             /* GUL??CL????????????????CHR???? */

    NAS_ERR_LOG_ALM_CL_GUL_SWITCH_PUNISH_PHASE_INFO         = 0x99,             /* GUL??CL?????????????????????????? */

    NAS_ERR_LOG_ALM_CNAS_KEY_PARAMETER_INFO                 = 0x9a,             /*  CNAS???????????????? */

    NAS_ERR_LOG_ALM_CNAS_1X_RESEL_INFO                      = 0x9b,             /*  CNAS????1x Resel ???????? */
    NAS_ERR_LOG_ALM_CNAS_ENC_VOICE_FAIL_INFO                = 0x9c,             /* ????????????????*/
    NAS_ERR_LOG_ALM_CALL_TYPE_EMC                           = 0x9d,             /* ?????????????????????? EMC */
    NAS_ERR_LOG_ALM_EMC_DOMAIN_SEL_AND_RETRY                = 0x9e,             /* ????AP?????????? EMC?????????????? */

    NAS_ERR_LOG_ALM_CNAS_LOCK_UNLOCK_COUNT                  = 0x9f,             /* ?????????????? */
    NAS_ERR_LOG_ALM_CNAS_UNLOCK_MTMO_COUNT                  = 0xa0,             /* ?????????????????????? */

    NAS_ERR_LOG_ALM_CL_IMS_INFO                             = 0xa1,             /* cl????????????ims????????????????????????????*/

    NAS_ERR_LOG_ALM_EVDO_ATTACH_FAIL_INFO                   = 0xa2,             /* cl????????EHRPD????????????PDN???????????? */
    NAS_ERR_LOG_ALM_ID_BUTT
};
typedef VOS_UINT16  NAS_ERR_LOG_ALM_ID_ENUM_U16;

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
  8 UNION????
*****************************************************************************/

/*****************************************************************************
  9 OTHERS????
*****************************************************************************/

/*****************************************************************************
  10 ????????
*****************************************************************************/

#if ((VOS_OS_VER == VOS_WIN32) || (VOS_OS_VER == VOS_NUCLEUS))
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
