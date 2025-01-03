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


#ifndef __SI_PIH_H__
#define __SI_PIH_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "product_config.h"
#include "vos.h"
#include "siapppih.h"
#include "UsimPsInterface.h"
#include "NVIM_Interface.h"
#if (OSA_CPU_CCPU == VOS_OSA_CPU)
#include "usimmvsimauth.h"
#include "omlist.h"
#endif  /*(OSA_CPU_CCPU == VOS_OSA_CPU)*/
#include "mdrv.h"
#include "msp_diag_comm.h"
#include "omerrorlog.h"

#if (OSA_CPU_ACPU == VOS_OSA_CPU)
#include "SiAcoreApi.h"
#endif

#pragma pack(4)

/*****************************************************************************
  2 ??????
*****************************************************************************/

#define SI_PIH_PIN_CODE_LEN             (8)

#define SI_PIH_PCSC_DATA_CNF            (0xA5)

#define SI_PIH_APDU_HDR_LEN             (USIMM_APDU_HEADLEN)

#define SI_PIH_ATFILE_NAME_MAX          (40)

#define SI_PIH_FILE_START_INDEX         (1)

#define SI_PIH_BCPID_REG_MAX            (20)

#define SI_PIH_VSIM_AES_KEY_LEN         (32)

#define SI_PIH_VSIM_MAX_CALL_BACK_KEY_LEN         (4 * 1024)

#define SI_PIH_SEC_ICC_VSIM_VER         (10000)

#ifdef CBT_ENABLED
#define PIH_USIMM_SCICHG_DEBUG_TIMER_LENTH  (10000)
#define PIH_USIMM_SCICHG_DEBUG_TIMER_NAME   (0xFF)
#endif

#define SI_PIH_POLL_TIMER_START(pTimer,ulPid,ulLength, Name)      VOS_StartRelTimer(pTimer,\
                                                                                ulPid,\
                                                                                ulLength,\
                                                                                Name,\
                                                                                0,\
                                                                                VOS_RELTIMER_NOLOOP,\
                                                                                VOS_TIMER_NO_PRECISION)

#define SI_PIH_POLL_32K_TIMER_START(pTimer,ulPid,ulLength, Name)  VOS_StartDrxTimer(pTimer,\
                                                                                ulPid,\
                                                                                ulLength,\
                                                                                Name,\
                                                                                0)

#define SI_PIH_POLL_32K_TIMER_STOP(pTimer)                  VOS_StopDrxTimer(pTimer)

#define SI_PIH_POLL_REL_32K_TIMER_START(pTimer,ulPid,ulLength, Name)  VOS_StartRelTimer(pTimer,\
                                                                                ulPid,\
                                                                                ulLength,\
                                                                                Name,\
                                                                                0,\
                                                                                VOS_RELTIMER_NOLOOP,\
                                                                                VOS_TIMER_PRECISION_0)

#define SI_PIH_POLL_REL_32K_TIMER_STOP(pTimer)                  VOS_StopRelTimer(pTimer)

#if  ((OSA_CPU_ACPU == VOS_OSA_CPU) || (VOS_OS_VER == VOS_WIN32))
#define PIH_GEN_LOG_MODULE(Level)       (DIAG_GEN_LOG_MODULE(MODEM_ID_0, DIAG_MODE_COMM, Level))

#define PIH_KEY_INFO_LOG(string)            (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_INFO),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "NORMAL:%s", string)
#define PIH_KEY_NORMAL_LOG(string)          (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_NORMAL),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "NORMAL:%s", string)
#define PIH_KEY_WARNING_LOG(string)         (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_WARNING),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "WARNING:%s", string)
#define PIH_KEY_ERROR_LOG(string)           (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_ERROR),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "ERROR:%s", string)

#define PIH_KEY_INFO1_LOG(string, para1)    (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_INFO),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "NORMAL:%s,%d", string, para1)
#define PIH_KEY_NORMAL1_LOG(string, para1)  (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_NORMAL),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "NORMAL:%s,%d", string, para1)
#define PIH_KEY_WARNING1_LOG(string, para1) (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_WARNING),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "WARNING%s,%d", string, para1)
#define PIH_KEY_ERROR1_LOG(string, para1)   (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_ERROR),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "ERROR:%s,%d", string, para1)

#define PIH_INFO_LOG(string)            (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_INFO),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "NORMAL:%s", string)
#define PIH_NORMAL_LOG(string)          (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_NORMAL),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "NORMAL:%s", string)
#define PIH_WARNING_LOG(string)         (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_WARNING),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "WARNING:%s", string)
#define PIH_ERROR_LOG(string)           (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_ERROR),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "ERROR:%s", string)

#define PIH_INFO1_LOG(string, para1)    (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_INFO),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "NORMAL:%s,%d", string, para1)
#define PIH_NORMAL1_LOG(string, para1)  (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_NORMAL),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "NORMAL:%s,%d", string, para1)
#define PIH_WARNING1_LOG(string, para1) (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_WARNING),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "WARNING%s,%d", string, para1)
#define PIH_ERROR1_LOG(string, para1)   (VOS_VOID)DIAG_LogReport(PIH_GEN_LOG_MODULE(PS_LOG_LEVEL_ERROR),I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "ERROR:%s,%d", string, para1)

#elif  (OSA_CPU_CCPU == VOS_OSA_CPU)

#define PIH_KEY_INFO_LOG(string)                USIMM_LogPrint(enSlotId, PS_LOG_LEVEL_INFO, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "Info:%s", string)
#define PIH_KEY_NORMAL_LOG(string)              USIMM_LogPrint(enSlotId, PS_LOG_LEVEL_NORMAL, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "Normal:%s", string)
#define PIH_KEY_WARNING_LOG(string)             USIMM_LogPrint(enSlotId, PS_LOG_LEVEL_WARNING, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "Warning:%s", string)
#define PIH_KEY_ERROR_LOG(string)               USIMM_LogPrint(enSlotId, PS_LOG_LEVEL_ERROR, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "Error:%s", string)

#define PIH_KEY_INFO1_LOG(string, para1)        USIMM_LogPrint1(enSlotId, PS_LOG_LEVEL_INFO, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "Info:%s,%d", string, para1)
#define PIH_KEY_NORMAL1_LOG(string, para1)      USIMM_LogPrint1(enSlotId, PS_LOG_LEVEL_NORMAL, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "Normal:%s,%d", string, para1)
#define PIH_KEY_WARNING1_LOG(string, para1)     USIMM_LogPrint1(enSlotId, PS_LOG_LEVEL_WARNING, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "Warning:%s,%d", string, para1)
#define PIH_KEY_ERROR1_LOG(string, para1)       USIMM_LogPrint1(enSlotId, PS_LOG_LEVEL_ERROR, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "Error:%s,%d", string, para1)

#define PIH_INFO_LOG(string)                    USIMM_LogPrint(enSlotId, PS_LOG_LEVEL_INFO, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "%s", (VOS_CHAR*)__FUNCTION__)
#define PIH_NORMAL_LOG(string)                  USIMM_LogPrint(enSlotId, PS_LOG_LEVEL_NORMAL, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "%s", (VOS_CHAR*)__FUNCTION__)
#define PIH_WARNING_LOG(string)                 USIMM_LogPrint(enSlotId, PS_LOG_LEVEL_WARNING, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "%s", (VOS_CHAR*)__FUNCTION__)
#define PIH_ERROR_LOG(string)                   USIMM_LogPrint(enSlotId, PS_LOG_LEVEL_ERROR, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "%s", (VOS_CHAR*)__FUNCTION__)

#define PIH_INFO1_LOG(string, para1)            USIMM_LogPrint1(enSlotId, PS_LOG_LEVEL_INFO, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "%s: %d", (VOS_CHAR*)__FUNCTION__, para1)
#define PIH_NORMAL1_LOG(string, para1)          USIMM_LogPrint1(enSlotId, PS_LOG_LEVEL_NORMAL, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "%s: %d", (VOS_CHAR*)__FUNCTION__, para1)
#define PIH_WARNING1_LOG(string, para1)         USIMM_LogPrint1(enSlotId, PS_LOG_LEVEL_WARNING, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "%s: %d", (VOS_CHAR*)__FUNCTION__, para1)
#define PIH_ERROR1_LOG(string, para1)           USIMM_LogPrint1(enSlotId, PS_LOG_LEVEL_ERROR, I0_MAPS_PIH_PID, VOS_NULL_PTR, __LINE__, "%s: %d", (VOS_CHAR*)__FUNCTION__, para1)


#endif

#define PIH_BIT_N(num)                  (0x01 << (num))

#define SI_PIH_MNC_TWO_BYTES_LEN        (2)             /* MNC??????2 */
#define SI_PIH_MNC_THREE_BYTES_LEN      (3)             /* MNC??????3 */
#define SI_PIH_AD_MNC_LEN_POS           (3)             /* AD??????MNC???????????????? */

#define SI_PIH_IMSI_MAX_LEN             (8)             /* IMSI?????????????????? */

#define PIH_SET_BIT(Data,BitNo)         (Data |= (VOS_UINT8)(0x1<<BitNo))

#define BIT_ACTIVECARD                  (3)             /*??????????????????*/
#define BIT_HANDLEVSIM                  (2)             /*????????????VSIM??*/
#define BIT_VSIMSTATE                   (1)             /*????VSIM??????????*/
#define BIT_CURCARDOK                   (0)             /*?????????????? */

#define SI_PIH_DH_PARAP_MAX             (128)           /*DH ???? P??????????*/
#define SI_PIH_DH_PARAG_MAX             (1)             /*DH ???? G??????????*/

#define SI_PIH_SMEM_ENDFLAG             (0x5A5A5A5A)

#define SI_PIH_HUK_LEN                  (0x10)
#define SI_PIH_HUK_BITS                 (128)

#define SI_PIH_APNSET_SMEM_ADDR         (g_ulTEEShareAddr)
#define SI_PIH_APNSET_SMEM_LEN          (0x400)         /*????1K*/

#define SI_PIH_DHPARASET_SMEM_ADDR      (SI_PIH_APNSET_SMEM_ADDR+SI_PIH_APNSET_SMEM_LEN)
#define SI_PIH_DHPARASET_SMEM_LEN       (0x400)         /*????1K*/

#define SI_PIH_VSIM_SMEM_ADDR           (SI_PIH_DHPARASET_SMEM_ADDR+SI_PIH_DHPARASET_SMEM_LEN)
#define SI_PIH_VSIM_SMEM_LEN            (0x1000)        /*????4K*/


#define SI_PIH_GETCARDSTATUS_MAX        (200)

#if (VOS_OS_VER != VOS_WIN32)       /* PC Stub */
#define SI_PIH_TASKDELAY_TIMER_LEN      (20)
#else
#define SI_PIH_TASKDELAY_TIMER_LEN      (1)
#endif  /*(VOS_OS_VER != VOS_WIN32)*/

#define SI_PIH_TASKDELAY_SEM_LEN        (1000)

#if (FEATURE_ON == FEATURE_VCOM_EXT)
#define SI_PIH_CTRL_INFO_SIZE           (5)             /* AT??????????????4????+1 */
#else
#define SI_PIH_CTRL_INFO_SIZE           (2)
#endif  /*(FEATURE_ON == FEATURE_VCOM_EXT)*/

/* ??????????????????????SessionID, 0x1f??????USIMM_CHANNEL_NUMBER_MAX?????? */
#define SI_PIH_MAKESESSION_ID(RandNum, ChannelID) \
        ((RandNum & (~0x1f)) | ChannelID)

#define SI_PIH_SCI_ERR_COUNT_MAX_SLICE  (30 * 60 * 32768)   /* Err Log???????????????? */

/*******************************************************************************
  3 ????????
*******************************************************************************/
enum SI_PIH_REQ_ENUM
{
    SI_PIH_NULL_REQ                 = 0,
    SI_PIH_FDN_ENABLE_REQ           = 1,
    SI_PIH_FDN_DISALBE_REQ          = 2,
    SI_PIH_GACCESS_REQ              = 3,
    SI_PIH_BDN_QUERY_REQ            = 4,
    SI_PIH_FDN_QUERY_REQ            = 5,
    SI_PIH_PCSC_DATA_REQ            = 6,
/* Added by h59254 for V7R1C50 ISDB Project,  2012-8-27 begin */
    SI_PIH_ISDB_ACCESS_REQ          = 7,
/* Added by h59254 for V7R1C50 ISDB Project,  2012-8-27 end */
    SI_PIH_HVSST_QUERY_REQ          = 8,
    SI_PIH_HVSST_SET_REQ            = 9,
    SI_PIH_HVSDH_SET_REQ            = 10,
    SI_PIH_HVSDH_QRY_REQ            = 11,
    SI_PIH_HVSCONT_QRY_REQ          = 12,
    SI_PIH_FILE_WRITE_REQ           = 13,
    SI_PIH_CCHO_SET_REQ             = 14,
    SI_PIH_CCHC_SET_REQ             = 15,
    SI_PIH_CGLA_SET_REQ             = 16,
    SI_PIH_CARD_ATR_QRY_REQ         = 17,
    SI_PIH_UICCAUTH_REQ             = 18,
    SI_PIH_URSM_REQ                 = 19,
    SI_PIH_CARDTYPE_QUERY_REQ       = 20,
    SI_PIH_CRSM_SET_REQ             = 21,
    SI_PIH_CRLA_SET_REQ             = 22,
    SI_PIH_SESSION_QRY_REQ          = 23,
    SI_PIH_SCICFG_SET_REQ           = 24,
    SI_PIH_SCICFG_QUERY_REQ         = 25,
    SI_PIH_HVTEE_SET_REQ            = 26,
    SI_PIH_HVCHECKCARD_REQ          = 27,
    SI_PIH_CIMI_QRY_REQ             = 28,
    SI_PIH_CCIMI_QRY_REQ            = 29,

    SI_PIH_CCHP_SET_REQ             = 30,
    SI_PIH_CARDVOLTAGE_QUERY_REQ    = 31,
    SI_PIH_PRIVATECGLA_SET_REQ      = 32,

    SI_PIH_CARDTYPEEX_QUERY_REQ     = 33,

#if (FEATURE_ON == FEATURE_PHONE_SC)
    SI_PIH_SILENT_PIN_SET_REQ       = 34,
    SI_PIH_SILENT_PININFO_SET_REQ   = 35,
#endif

    SI_PIH_REQ_BUTT
};
typedef VOS_UINT32      SI_PIH_REQ_ENUM_UINT32;

enum SI_PIH_LOCK_ENUM
{
    SI_PIH_UNLOCK                   = 0,
    SI_PIH_LOCKED                   = 1,
    SI_PIH_LOCK_BUTT
};
typedef VOS_UINT32  SI_PIH_LOCK_ENUM_UINT32;

enum SI_PIH_CARDSTATE_REPORT_ENUM
{
    SI_PIH_NEED_REPORT              = 0,
    SI_PIH_NO_NEED_REPORT           = 1,
    SI_PIH_REPORT_BUTT
};

enum SI_PIH_PCSC_CMD_ENUM
{
    SI_PIH_PCSC_POWER_ON         = 0,
    SI_PIH_PCSC_POWER_OFF        = 1,
    SI_PIH_PCSC_SIM_QUIRY        = 2,
    SI_PIH_PCSC_APDU_CMD         = 3,
    SI_PIH_PCSC_GET_ATR          = 4,
    SI_PIH_PCSC_GET_PARA         = 5,
    SI_PIH_PCSC_GET_CLKFREQ      = 6,
    SI_PIH_PCSC_GET_BAUDRATE     = 7,
    SI_PIH_PCSC_CMD_BUTT
};
typedef VOS_UINT32      SI_PIH_PCSC_CMD_ENUM_UINT32;

enum SI_PIH_PCSC_SIM_STATUS_ENUM
{
    SI_PIH_PCSC_SIM_ABSENT       = 0,
    SI_PIH_PCSC_SIM_PRESENT      = 1,
    SI_PIH_PCSC_SIM_BUTT
};

typedef VOS_UINT8       SI_PIH_PCSC_SIM_STATUS;

enum SI_PIH_HVSST_HANDLE_STATE_ENUM
{                                               /*OP_ActiveCard OP_HandleVsim   OP_VsimState    OP_CurCardOK*/
    SI_PIH_HVSST_DEACTIVE_RSIM_AGAIN    = 0x00, /*0             0               0               0*/ /*????????*/
    SI_PIH_HVSST_DEACTIVE_RSIM          = 0x01, /*0             0               0               1*/ /*????????*/
    SI_PIH_HVSST_STATE_ERROR2           = 0x02, /*0             0               1               0*/ /*VSIM??????????????????????????*/
    SI_PIH_HVSST_STATE_ERROR3           = 0x03, /*0             0               1               1*/ /*VSIM??????????????????*/
    SI_PIH_HVSST_STATE_ERROR4           = 0x04, /*0             1               0               0*/ /*??????????VSIM??????????????VSIM*/
    SI_PIH_HVSST_STATE_ERROR5           = 0x05, /*0             1               0               1*/ /*????????VSIM??????????????VSIM*/
    SI_PIH_HVSST_DEACTIVE_VSIM_AGAIN    = 0x06, /*0             1               1               0*/ /*????????*/
    SI_PIH_HVSST_DEACTIVE_VSIM          = 0x07, /*0             1               1               1*/ /*????????*/
    SI_PIH_HVSST_ACTIVE_RSIM            = 0x08, /*1             0               0               0*/ /*????????*/
    SI_PIH_HVSST_ACTIVE_RSIM_AGAIN      = 0x09, /*1             0               0               1*/ /*????????????*/
    SI_PIH_HVSST_ACTIVE_RSIM_AGAIN2     = 0x0A, /*1             0               1               0*/ /*VSIM????????,????????*/
    SI_PIH_HVSST_STATE_ERROR11          = 0x0B, /*1             0               1               1*/ /*VSIM????????,????????*/
    SI_PIH_HVSST_ACTIVE_VSIM            = 0x0C, /*1             1               0               0*/ /*????????*/
    SI_PIH_HVSST_ACTIVE_ERROR13         = 0x0D, /*1             1               0               1*/ /*????????????????VSIM*/
    SI_PIH_HVSST_ACTIVE_VSIM_AGAIN      = 0x0E, /*1             1               1               0*/ /*VSIM????????,????VSIM*/
    SI_PIH_HVSST_ACTIVE_VSIM_AGAIN2     = 0x0F, /*1             1               1               1*/ /*????????*/
    SI_PIH_HVSST_HANDLE_STATE_BUTT
};
typedef VOS_UINT8      SI_PIH_HVSST_HANDLE_STATE_ENUM_UINT8;

enum SI_PIH_HVTEE_DATAFLAG_ENUM
{
    SI_PIH_HVTEE_APNSET                 = 0xA5A5A001,
    SI_PIH_HVTEE_DHSET                  = 0xA5A5A002,
    SI_PIH_HVTEE_VSIMDATA               = 0xA5A5A003,
    SI_PIH_HVTEE_DATAFLAG_BUTT
};
typedef VOS_UINT32      SI_PIH_HVTEE_DATAFLAG_ENUM_UINT32;


enum SI_PIH_RACCESS_SRC_TYPE_ENUM
{
    SI_PIH_RACCESS_FROM_PIH      = 0,
    SI_PIH_RACCESS_FROM_AT
};
typedef VOS_UINT8      SI_PIH_RACCESS_SRC_TYPE_ENUM_UINT8;


enum SI_PIH_INFO_LIST_ENUM
{
    SI_PIH_INFO_USED_LIST_ID = 0,
    SI_PIH_INFO_FREE_LIST_ID,
    SI_PIH_INFO_LIST_BUTT
};

typedef VOS_UINT8  SI_PIH_INFO_LIST_ENUM_UINT8;


enum SI_PIH_ERR_LOG_ALM_ID_ENUM
{
    SI_PIH_ERR_LOG_ALM_REQ_RPT_FAIL          = 0x01,             /* ??Errlog????????(????????) */
    SI_PIH_ERR_LOG_ALM_ACTIVE_INIT_ERR_RPT   = 0x02,             /* ?????????????????? */
    SI_PIH_ERR_LOG_ALM_ACTIVE_COUNT_ERR_RPT  = 0x03,             /* ?????????????????????????????? */
    SI_PIH_ERR_LOG_ALM_CARDFETCH_IND_RPT     = 0x04,             /* ????fetch???????????? */

    SI_PIH_ERR_LOG_ALM_ID_BUTT
};
typedef VOS_UINT16 SI_PIH_ERR_LOG_ALM_ID_ENUM_UINT16;

/*****************************************************************************
  4 STRUCT????
*****************************************************************************/


typedef struct
{
    OM_ERR_LOG_HEADER_STRU             stHeader;
    VOS_UINT8                          aucData[4];
}SI_PIH_ERR_LOG_ACTIVE_RPT_STRU;


typedef struct
{
    VOS_UINT32                          ulStartCountSlice;
    VOS_UINT32                          ulCardSciErrCount;
    VOS_UINT32                          ulCardSciUpdateErrCount;
    VOS_UINT32                          ulCardSciReadErrCount;
    VOS_UINT32                          ulCardSciAuthErrCount;
    VOS_UINT32                          ulCardSciRAccessErrCount;
    VOS_UINT32                          ulCardSciEnvelopeErrCount;
    VOS_UINT32                          ulRsv1;
    VOS_UINT32                          ulRsv2;
    VOS_UINT32                          ulEndCountSlice;
}SI_PIH_CARD_SCI_ERR_INFO_STRU;


typedef struct
{
    VOS_UINT32                          ulSlice;
    VOS_UINT32                          ulCardFetchType;
}SI_PIH_CARD_FETCH_INFO_STRU;

typedef struct
{
    VOS_MSG_HEADER
    VOS_UINT32                          ulMsgName;       /* ?????? */
    VOS_UINT16                          usClient;        /* ??????ID */
    VOS_UINT8                           ucOpID;
    VOS_UINT8                           ucRsv;
    SI_PIH_EVENT                        ulEventType;
}SI_PIH_MSG_HEADER_STRU;

typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;
    VOS_UINT8                           aucPIN2[SI_PIH_PIN_CODE_LEN];      /* PIN2????????????????????PIN2????????0 */
} SI_PIH_FDN_ENABLE_REQ_STRU;

typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;
    VOS_UINT8                           aucPIN2[SI_PIH_PIN_CODE_LEN];      /* PIN2????????????????????PIN2????????0 */
} SI_PIH_FDN_DISABLE_REQ_STRU;

typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;
    VOS_UINT32                          ulDataLen;
    VOS_UINT8                           aucData[8];
}SI_PIH_GACCESS_REQ_STRU;


typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;        /* PIH??????    */
    VOS_UINT32                          ulDataLen;          /* PIH????????  */
    VOS_UINT8                           aucData[8];         /* PIH????????  */
}SI_PIH_ISDB_ACCESS_REQ_STRU;

typedef struct
{
    SI_PIH_MSG_HEADER_STRU          stMsgHeader;
    VOS_UINT32                      ulMsgType;
    VOS_UINT32                      ulCmdType;
    VOS_UINT32                      ulCmdLen;
    VOS_UINT8                       aucAPDU[8];
}SI_PIH_PCSC_REQ_STRU;

typedef VOS_VOID (*PUSIMPCSCPROC)(SI_PIH_CARD_SLOT_ENUM_UINT32 enSlotId, SI_PIH_PCSC_REQ_STRU *pstMsg);

typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;        /* PIH?????? */
    SI_PIH_HVSST_SET_STRU               stHvSSTData;
} SI_PIH_HVSST_REQ_STRU;

typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;        /* PIH?????? */
    VOS_UINT8                           ucFileNameLen;
    VOS_UINT8                           aucFileName[SI_PIH_ATFILE_NAME_MAX];
    VOS_UINT8                           ucRef;
    VOS_UINT8                           ucTotalNum;
    VOS_UINT8                           ucIndex;
    VOS_UINT32                          ulFileDataLen;
    VOS_UINT8                           aucFileData[4];
} SI_PIH_FILE_WRITE_REQ_STRU;

typedef struct
{
    SI_PIH_LOCK_ENUM_UINT32             enPIHLock;
    VOS_UINT16                          usClient;
    VOS_UINT8                           ucOpID;
    VOS_UINT8                           ucResv;
    VOS_UINT32                          enCmdType;
    SI_PIH_EVENT                        ulEventType;
}SI_PIH_CTRL_INFO_STRU;

typedef struct
{
    SI_PIH_POLLTIMER_STATE_ENUM_UINT32  enPollState;
    VOS_UINT32                          enPollData;
    VOS_UINT32                          ulTimeLen;
    VOS_UINT32                          ulTimerName;
    HTIMER                              stTimer;
}SI_PIH_POLL_TIME_STRU;

typedef struct
{
    VOS_UINT8                           ucIMSILen;
    VOS_UINT8                           aucIMSI[9];
    VOS_UINT8                           aucRsv[2];
}SI_PIH_IMSI_STRU;

typedef struct
{
    USIMM_FILEPATH_INFO_STRU            stFilePath;
    VOS_UINT16                          usRspLen;
    VOS_UINT8                           aucRspCotent[USIMM_T0_APDU_MAX_LEN];
    VOS_UINT8                           aucRcv[2];
}SI_PIH_CSIM_CTRL_STRU;

typedef struct
{
    VOS_UINT16                     usIndex;
    VOS_UINT16                     usRefNum;
    VOS_UINT16                     usTotalNum;
    VOS_UINT16                     usRsv;
    FILE                           *fpFile;
}SI_PIH_FWRITE_PARA_STRU;

typedef struct
{
    VOS_MSG_HEADER
    VOS_UINT32                      ulMsgName;          /* ???????? */
    VOS_UINT32                      ulResult;           /* PC/SC???????????? */
    VOS_UINT32                      ulCmdType;          /* ???????? */
    VOS_UINT32                      ulRspLen;           /* ?????????????????????? */
    VOS_UINT8                       aucContent[4];      /* ???????? */
}SI_PIH_PCSC_CNF_STRU;

typedef struct
{
    VOS_MSG_HEADER
    VOS_UINT32                      ulMsgName;          /* ???????? */
    VOS_UINT8                       aucContent[4];      /* ???????? */
}SI_PIH_HOOK_MSG_STRU;


typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;                            /* PIH?????? */
    VOS_UINT32                          ulAIDLen;                               /* AID?????? */
    VOS_UINT8                           aucADFName[2*USIMM_AID_LEN_MAX];        /* ????????????????AID????????????????????????1?? */
}SI_PIH_CCHO_SET_REQ_STRU;


typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;                            /* PIH?????? */
    VOS_UINT32                          ulAIDLen;                               /* AID?????? */
    VOS_UINT8                           aucADFName[2*USIMM_AID_LEN_MAX];        /* ????????????????AID????????????????????????1?? */
    VOS_UINT8                           ucAPDUP2;                               /* APDU??????P2???? */
    VOS_UINT8                           ucRsv[3];
}SI_PIH_CCHP_SET_REQ_STRU;


typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;                            /* PIH?????? */
    VOS_UINT32                          ulSessionID;                            /* ?????????? */
}SI_PIH_CCHC_SET_REQ_STRU;


typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;                            /* PIH??????    */
    VOS_UINT32                          ulSessionID;                            /* ?????????? */
    VOS_UINT32                          ulDataLen;                              /* ????????  */
    VOS_UINT8                           aucData[SI_APDU_MAX_LEN + 1];           /* ???????? ,??LE?????????????? */
    VOS_UINT8                           aucRsv[3];
}SI_PIH_CGLA_REQ_STRU;

typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;
    VOS_UINT32                          ulDataLen;
    VOS_UINT8                           aucData[4];
}SI_PIH_HVSDH_SET_REQ_STRU;

typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;
}SI_PIH_HVS_QRY_REQ_STRU;

typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;        /* PIH?????? */
    SI_PIH_UICCAUTH_STRU                stAuthData;
} SI_PIH_UICCAUTH_REQ_STRU;

typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;        /* PIH?????? */
    SI_PIH_ACCESSFILE_STRU              stCmdData;
} SI_PIH_ACCESSFILE_REQ_STRU;

typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;        /* PIH?????? */
    SI_PIH_CARD_SLOT_ENUM_UINT32        enCard0Slot;
    SI_PIH_CARD_SLOT_ENUM_UINT32        enCard1Slot;
    SI_PIH_CARD_SLOT_ENUM_UINT32        enCard2Slot;
} SI_PIH_SCICFG_SET_REQ_STRU;

typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;        /* PIH?????? */
    SI_PIH_HVTEE_SET_STRU               stHvtee;
} SI_PIH_HVTEE_SET_REQ_STRU;

typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;
}SI_PIH_HVCHECKCARD_REQ_STRU;

typedef struct
{
    USIMM_CARDAPP_ENUM_UINT32           enAppType;
    VOS_UINT16                          usEfId;         /* ????ID */
    VOS_UINT8                           ucRecordNum;    /* ????????????????????????0 */
    VOS_UINT8                           ucRsv;          /* ???? */
}SI_PIH_GETFILE_INFO_STRU;

typedef struct
{
    USIMM_CARDAPP_ENUM_UINT32           enAppType;
    VOS_UINT16                          usEfId;         /* ????ID */
    VOS_UINT8                           ucRecordNum;    /* ????????????????????????0 */
    VOS_UINT8                           ucRsv;          /* ???? */
    VOS_UINT32                          ulEfLen ;       /* ???????????? */
    VOS_UINT8                           *pucEfContent;  /* ???????????? */
}SI_PIH_SETFILE_INFO_STRU;


typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;                            /* PIH?????? */
    SI_PIH_CRSM_STRU                    stMsgContent;
}SI_PIH_CRSM_SET_REQ_STRU;


typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;                            /* PIH?????? */
    SI_PIH_CRLA_STRU                    stMsgContent;
}SI_PIH_CRLA_SET_REQ_STRU;

typedef struct
{
    VOS_UINT32                          ulAppType;
    VOS_UINT32                          ulSessionID;
}SI_PIH_CHANNELAPPINFO_STRU;

#if (OSA_CPU_CCPU == VOS_OSA_CPU)

typedef struct
{
    OM_LIST_NODE_STRU                   stListNode;
    VOS_UINT16                          usClient;
    VOS_UINT8                           ucOpID;
    VOS_UINT8                           ucResv;
    VOS_UINT32                          enCmdType;
    SI_PIH_EVENT                        ulEventType;
}SI_PIH_CTRL_INFO_NODE_STRU;
#endif


typedef struct
{
    SI_PIH_FILE_INFO_STRU               stFileInfo;
    VOS_BOOL                            bIsNeedCheck;        /* ???????????????????? */
}SI_PIH_NEED_CHECK_FILE_STRU;

#if (OSA_CPU_CCPU == VOS_OSA_CPU)

typedef struct
{
    SI_PIH_NEED_CHECK_FILE_STRU         stNeedCheckList[SI_PIH_KEYFILE_MAX_NUM];
    VOS_UINT32                          ulReceiverPid;       /* ??????????????????????????PID */
    USIMM_CHECK_KEY_FILE_NV_STRU        stNVCheckFileCfg;    /* NV?????????????? */
    VOS_UINT8                           ucNeedCheckFileNum;  /* ??????????????????(????????????????????????????) */
    VOS_UINT8                           ucCheckFileNum;      /* NAS???????????????? */
    VOS_UINT8                           ucTimerCount;        /* ?????????????? */
    VOS_UINT8                           ucRsv;
}SI_PIH_KEY_FILE_LIST_STRU;
#endif


typedef struct
{
    USIMM_PHYCARD_TYPE_ENUM_UINT32      enPhyCardType;      /*??????????*/
    USIMM_CARDAPP_SERVIC_ENUM_UINT32    enGUTLSvcStatus;
    USIMM_CARD_TYPE_ENUM_UINT32         enGUTLCardType;     /*USIM/SIM*/
    USIMM_CARDAPP_SERVIC_ENUM_UINT32    enCDMASvcStatus;
    USIMM_CARD_TYPE_ENUM_UINT32         enCDMACardType;     /*CSIM/UIM*/
    USIMM_CARDAPP_SERVIC_ENUM_UINT32    enISIMSvcStatus;
    USIMM_CARD_TYPE_ENUM_UINT32         enISIMCardType;     /*ISIM*/
    USIMM_CARDSTATUS_ADDINFO_STRU       stAddInfo;          /*????????????????????????????????*/
}SI_PIH_CARD_STATUS_STRU;


typedef VOS_UINT32 (*PFSIPIHPIDMSGPROC)(SI_PIH_CARD_SLOT_ENUM_UINT32 enSlotId, PS_SI_MSG_STRU *pMsg);


typedef struct
{
    VOS_PID                             ulSenderPid;
    PFSIPIHPIDMSGPROC                   pProcFunc;        /* ???????? */
}SI_PIH_PIDMSGPROC_FUNC;


typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;
    SI_PIH_CRYPTO_PIN_STRU              stCryptoPin;
}SI_PIH_SILENT_PIN_REQ_STRU;


typedef struct
{
    SI_PIH_MSG_HEADER_STRU              stMsgHeader;
    VOS_UINT32                          ulDataLen;
    VOS_UINT8                           aucData[USIMM_PINNUMBER_LEN];
}SI_PIH_SILENT_PININFO_REQ_STRU;

/*****************************************************************************
  5 ????????????
*****************************************************************************/
extern VOS_MSG_HOOK_FUNC            vos_MsgHook;

extern VOS_UINT32                   g_aulPIHUsimBCPid[USIMM_SLOT_SIZE][SI_PIH_BCPID_REG_MAX];

extern VOS_UINT32                   g_aulPIHRefreshBCPid[USIMM_SLOT_SIZE][SI_PIH_BCPID_REG_MAX];

/*****************************************************************************
  6 ????????
*****************************************************************************/
#if (OSA_CPU_CCPU == VOS_OSA_CPU)
extern VOS_VOID SI_PIH_InitTEEShareAddr(SI_PIH_CARD_SLOT_ENUM_UINT32 enSlotId);

extern VOS_UINT32 SI_PIH_Stop32KCheckStatusTimer(SI_PIH_CARD_SLOT_ENUM_UINT32 enSlotId, HTIMER *pstTimer);

extern VOS_UINT32 SI_PIH_Start32KCheckStatusTimer(
    SI_PIH_CARD_SLOT_ENUM_UINT32        enSlotId,
    HTIMER                             *pstTimer,
    VOS_UINT32                          ulTimerLen,
    VOS_UINT32                          ulTimerName);

extern SI_PIH_POLL_TIME_STRU* SI_PIH_GetPollTimerAddr(
    SI_PIH_CARD_SLOT_ENUM_UINT32        enSlotId,
    SI_PIH_TIMER_NAME_ENUM_UINT32       enTimerName);

extern VOS_VOID SI_PIH_PollTimerPro(
    SI_PIH_CARD_SLOT_ENUM_UINT32         enSlotId,
    SI_PIH_POLL_TIME_STRU               *pstPIHTimer);

extern SI_PIH_CARD_STATUS_STRU* SI_PIH_GetCardInfoAddr(SI_PIH_CARD_SLOT_ENUM_UINT32 enSlotId);

extern VOS_UINT32 SI_PIH_CheckGCFTestCard(SI_PIH_CARD_SLOT_ENUM_UINT32 enSlotId);

extern VOS_UINT32 SI_PIH_SendDeactiveReqMsg(
    SI_PIH_CARD_SLOT_ENUM_UINT32        enSlotId,
    VOS_UINT32                          ulSendPara);

#if (FEATURE_ON == FEATURE_PTM)
extern VOS_VOID SI_PIH_ErrLogVarInit(SI_PIH_CARD_SLOT_ENUM_UINT32 enSlotId);
#endif

extern VOS_VOID SI_PIH_MNTNDataHook(
    SI_PIH_CARD_SLOT_ENUM_UINT32        enSlotId,
    VOS_UINT32                          ulHookMsgName,
    VOS_UINT32                          ulHookDataLen,
    VOS_UINT8                          *pucHookData);

#endif

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

