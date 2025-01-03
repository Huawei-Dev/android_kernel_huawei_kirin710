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

#ifndef __ADSCTX_H__
#define __ADSCTX_H__

/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "vos.h"
#include "PsLogdef.h"
#include "PsTypeDef.h"
#include "PsLib.h"
#include "AdsInterface.h"
#include "AdsDeviceInterface.h"
#include "CdsAdsInterface.h"
#include "AdsNdInterface.h"
#include "AdsTimerMgmt.h"
#include "AdsLog.h"
#include "mdrv.h"
#include "NVIM_Interface.h"
#include "acore_nv_stru_gucnas.h"
#include "rnic_dev_def.h"

#if (VOS_OS_VER == VOS_LINUX)
#include <asm/dma-mapping.h>
#include <linux/pm_wakeup.h>
#include <linux/version.h>
#else
#include "Linuxstub.h"
#endif /* VOS_OS_VER == VOS_LINUX */

#if (defined(CONFIG_BALONG_SPE))
#include <linux/spe/spe_interface.h>
#include "mdrv_spe_wport.h"
#endif /* CONFIG_BALONG_SPE */

#include <linux/of_platform.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#pragma pack(4)


/*****************************************************************************
  2 ??????
*****************************************************************************/

/* ADS??????????Modem???????????? */
#define ADS_INSTANCE_MAX_NUM            (MODEM_ID_BUTT)

/* ADS?????????? */
#define ADS_INSTANCE_INDEX_0            (0)
#define ADS_INSTANCE_INDEX_1            (1)
#define ADS_INSTANCE_INDEX_2            (2)

/*???????????????????? */
#define ADS_RAB_NUM_MAX                 (11)

/* ??????????????????5??15, ??????????5???????? */
#define ADS_RAB_ID_OFFSET               (5)

/* Rab Id???????? */
#define ADS_RAB_ID_MIN                  (5)

/* Rab Id???????? */
#define ADS_RAB_ID_MAX                  (15)

/* Rab Id???????? */
#define ADS_RAB_ID_INVALID              (0xFF)

/* ????????????????IPF?????????????????????????????????????? */
#define ADS_UL_SEND_DATA_NUM_THREDHOLD          (g_stAdsCtx.stAdsIpfCtx.ulThredHoldNum)

#define ADS_UL_SET_SEND_DATA_NUM_THREDHOLD(n)   (g_stAdsCtx.stAdsIpfCtx.ulThredHoldNum = (n))

#define ADS_UL_RX_WAKE_LOCK_TMR_LEN     (g_stAdsCtx.stAdsIpfCtx.ulRxWakeLockTmrLen)
#define ADS_DL_TX_WAKE_LOCK_TMR_LEN     (g_stAdsCtx.stAdsIpfCtx.ulTxWakeLockTmrLen)

/* ??????AD????????14????IPF RD????????????14??MAC???????? */
#define ADS_DL_AD_DATA_PTR_OFFSET       (14)

/* ?????????????????? */
#define ADS_UL_DEFAULT_PRI_WEIGHTED_NUM (0x01)

#define ADS_PKT_ERR_RATE_MIN_THRESHOLD      (50)
#define ADS_PKT_ERR_RATE_MAX_THRESHOLD      (100)
#define ADS_PKT_ERR_RATE_DEFAULT_THRESHOLD  (95)

#define ADS_PKT_ERR_DETECT_MIN_DURATION     (1000)
#define ADS_PKT_ERR_DETECT_MAX_DURATION     (10000)
#define ADS_PKT_ERR_DETECT_DEFAULT_DURATION (2000)
#define ADS_PKT_ERR_DETECT_DEFAULT_DELTA    (1000)

#define ADS_IS_PKT_ERR_RATE_THRESHOLD_VALID(val) \
            (((val) >= ADS_PKT_ERR_RATE_MIN_THRESHOLD) \
             && ((val) <= ADS_PKT_ERR_RATE_MAX_THRESHOLD))

#define ADS_IS_PKT_ERR_DETECT_DURATION_VALID(val) \
            (((val) >= ADS_PKT_ERR_DETECT_MIN_DURATION) \
             && ((val) <= ADS_PKT_ERR_DETECT_MAX_DURATION))

#define ADS_CURRENT_TICK                (jiffies)
#define ADS_TIME_AFTER(a,b)             time_after((a),(b))
#define ADS_TIME_AFTER_EQ(a,b)          time_after_eq((a),(b))
#define ADS_TIME_IN_RANGE(a,b,c)        time_in_range((a),(b),(c))

/* ADS ADQ?????? */
#define ADS_DL_ADQ_MAX_NUM              (2)

/*????ADQ????????????????????????????AD??????????????????????????????*/
#define ADS_IPF_DLAD_START_TMR_THRESHOLD (IPF_DLAD0_DESC_SIZE - 6)

/* ADS??????SPE?????? */
#define ADS_IPF_SPE_PORT_0              (SPE_PORT_MAX + 128)
#define ADS_IPF_SPE_PORT_1              (SPE_PORT_MAX + 129)

/* AD???????????? */
#define ADS_IPF_AD0_MEM_BLK_NUM         (IPF_DLAD0_DESC_SIZE * 3)
#define ADS_IPF_AD1_MEM_BLK_NUM         (IPF_DLAD1_DESC_SIZE * 4)
#define ADS_IPF_AD_MEM_RESV_BLK_NUM     (IPF_DLAD1_DESC_SIZE * 2)

/* AD???????????? */
#define ADS_IPF_AD0_MEM_BLK_SIZE        (448)
#define ADS_IPF_AD1_MEM_BLK_SIZE        (1536 + 14)

#define ADS_IPF_RD_BUFF_RECORD_NUM      (IPF_DLRD_DESC_SIZE * 2)
#define ADS_IPF_AD_BUFF_RECORD_NUM      (IPF_DLAD0_DESC_SIZE * 2)

/* ADS_UL_SendPacket??ADS_DL_RegDlDataCallback??rabid????????rabid??
   ??2bit????MODEM ID????6bit????RAB ID????????????RABID????MODEM ID */
#define ADS_GET_MODEMID_FROM_EXRABID(i) ((i >> 6) & 0x03)

#define ADS_GET_RABID_FROM_EXRABID(i)   (i & 0x3F)

#define ADS_BUILD_EXRABID(mid,rabid)    ((VOS_UINT8)((((mid) << 6) & 0xC0) | ((rabid) & 0x3F)))

#define ADS_BIT16_MASK(bit)             ((VOS_UINT16)(1 << (bit)))
#define ADS_BIT16_SET(val,bit)          ((val) | ADS_BIT16_MASK(bit))
#define ADS_BIT16_CLR(val,bit)          ((val) & ~ADS_BIT16_MASK(bit))
#define ADS_BIT16_IS_SET(val,bit)       ((val) & ADS_BIT16_MASK(bit))

/*******************************???????? Begin*******************************/

/* ADS???????????? */
#define ADS_UL_EVENT_BASE               (0x00000000)
#define ADS_UL_EVENT_DATA_PROC          (ADS_UL_EVENT_BASE | 0x0001)

/* ADS???????????? */
#define ADS_DL_EVENT_BASE               (0x00000000)
#define ADS_DL_EVENT_IPF_RD_INT         (ADS_DL_EVENT_BASE | 0x0001)
#define ADS_DL_EVENT_IPF_ADQ_EMPTY_INT  (ADS_DL_EVENT_BASE | 0x0002)
#define ADS_DL_EVENT_IPF_FILTER_DATA_PROC           (ADS_DL_EVENT_BASE | 0x0004)

/*******************************???????? End*******************************/

/*******************************???????? Begin*******************************/
/* ?????????????????? */
#define ADS_GET_DSFLOW_STATS_CTX_PTR()              (&(g_stAdsCtx.stDsFlowStatsCtx))

/* ???????????????? */
#define ADS_SET_CURRENT_UL_RATE(n)                  (g_stAdsCtx.stDsFlowStatsCtx.stULDataStats.ulULCurDataRate = (n))

/* ???????????????? */
#define ADS_SET_CURRENT_DL_RATE(n)                  (g_stAdsCtx.stDsFlowStatsCtx.stDLDataStats.ulDLCurDataRate = (n))

/* ?????????????????????????? */
#define ADS_RECV_UL_PERIOD_PKT_NUM(n)               (g_stAdsCtx.stDsFlowStatsCtx.stULDataStats.ulULPeriodSndBytes += (n))

/* ?????????????????????????? */
#define ADS_RECV_DL_PERIOD_PKT_NUM(n)               (g_stAdsCtx.stDsFlowStatsCtx.stDLDataStats.ulDLPeriodRcvBytes += (n))

/* ?????????????????????????? */
#define ADS_GET_UL_PERIOD_PKT_NUM()                 (g_stAdsCtx.stDsFlowStatsCtx.stULDataStats.ulULPeriodSndBytes)

/* ?????????????????????????? */
#define ADS_GET_DL_PERIOD_PKT_NUM()                 (g_stAdsCtx.stDsFlowStatsCtx.stDLDataStats.ulDLPeriodRcvBytes)

/* ???????????????????????????? */
#define ADS_CLEAR_UL_PERIOD_PKT_NUM()               (g_stAdsCtx.stDsFlowStatsCtx.stULDataStats.ulULPeriodSndBytes = 0)

/* ???????????????????????????? */
#define ADS_CLEAR_DL_PERIOD_PKT_NUM()               (g_stAdsCtx.stDsFlowStatsCtx.stDLDataStats.ulDLPeriodRcvBytes = 0)

/*******************************???????? End*******************************/


/*******************************???? Begin*******************************/
/* ????ADS???????????? */
#define ADS_UL_GET_CTX_PTR(i)                       (&(g_stAdsCtx.astAdsSpecCtx[i].stAdsUlCtx))

/* ???????????????? */
#define ADS_UL_GET_QUEUE_LINK_PTR(i, j)             (g_stAdsCtx.astAdsSpecCtx[i].stAdsUlCtx.astAdsUlQueue[j].pstAdsUlLink)

/* ?????????????? */
#define ADS_UL_GET_QUEUE_LINK_SPINLOCK(i, j)        (&(g_stAdsCtx.astAdsSpecCtx[i].stAdsUlCtx.astAdsUlQueue[j].stSpinLock))

/* ????ADS????BD???????????? */
#define ADS_UL_GET_BD_CFG_PARA_PTR(index)           (&(g_stAdsCtx.stAdsIpfCtx.astIpfUlBdCfgParam[index]))

/* ????ADS????BD???????? */
#define ADS_UL_GET_BD_BUFF_PTR(index)               (&(g_stAdsCtx.stAdsIpfCtx.astIpfUlBdBuff[index]))

/* ????ADS?????????????????????? */
#define ADS_UL_GET_PROTECT_TIMER_LEN()              (g_stAdsCtx.stAdsIpfCtx.ulProtectTmrLen)

/* ???????????????????????????? */
#define ADS_UL_GET_SENDING_FLAG()                   (g_stAdsCtx.stAdsIpfCtx.ucSendingFlg)

/* ???????????????????????????? */
#define ADS_UL_SET_SENDING_FLAG(flg)                (g_stAdsCtx.stAdsIpfCtx.ucSendingFlg = flg)

/* ?????????????????? */
#define ADS_UL_GET_PRIO_QUEUE_INDEX(i, j)           (g_stAdsCtx.astAdsSpecCtx[i].stAdsUlCtx.aulPrioIndex[j])

/* ??????????????????????*/
#define ADS_UL_GET_QUEUE_QCI(i, j)                  (g_stAdsCtx.astAdsSpecCtx[i].stAdsUlCtx.astAdsUlQueue[ADS_UL_GET_PRIO_QUEUE_INDEX(i, j)].enPrio)

/* ???????????????? */
#define ADS_UL_GET_QUEUE_LINK_INFO(i, j)            (g_stAdsCtx.astAdsSpecCtx[i].stAdsUlCtx.astAdsUlQueue[ADS_UL_GET_PRIO_QUEUE_INDEX(i, j)].pstAdsUlLink)

#if (FEATURE_ON == FEATURE_UE_MODE_CDMA)
/* ????IX OR HRPD??????IPF?????????? */
#define ADS_UL_GET_1X_OR_HRPD_UL_IPF_FLAG(i, j)     (g_stAdsCtx.astAdsSpecCtx[i].stAdsUlCtx.astAdsUlQueue[ADS_UL_GET_PRIO_QUEUE_INDEX(i, j)].uc1XorHrpdUlIpfFlag)
#endif

/* ?????????????????????????????????????????? */
#define ADS_UL_GET_RECORD_NUM_IN_WEIGHTED(i, j)     (g_stAdsCtx.astAdsSpecCtx[i].stAdsUlCtx.astAdsUlQueue[ADS_UL_GET_PRIO_QUEUE_INDEX(i, j)].usRecordNum)

/* ?????????????????????????????????????????? */
#define ADS_UL_SET_RECORD_NUM_IN_WEIGHTED(i, j, n)  (g_stAdsCtx.astAdsSpecCtx[i].stAdsUlCtx.astAdsUlQueue[ADS_UL_GET_PRIO_QUEUE_INDEX(i, j)].usRecordNum += n)

/* ?????????????????????????????????????????? */
#define ADS_UL_CLR_RECORD_NUM_IN_WEIGHTED(i, j)     (g_stAdsCtx.astAdsSpecCtx[i].stAdsUlCtx.astAdsUlQueue[ADS_UL_GET_PRIO_QUEUE_INDEX(i, j)].usRecordNum = 0)

/* ?????????????????????????? */
#define ADS_UL_GET_QUEUE_PRI_WEIGHTED_NUM(i, j)     (g_stAdsCtx.astAdsSpecCtx[i].stAdsUlCtx.stQueuePriNv.ausPriWeightedNum[ADS_UL_GET_QUEUE_QCI(i, j)])

/* ????????????????????????*/
#define ADS_UL_GET_QUEUE_PKT_TYPE(InstanceIndex, RabId) \
            (g_stAdsCtx.astAdsSpecCtx[InstanceIndex].stAdsUlCtx.astAdsUlQueue[RabId].enPktType)


/* ????ADS?????????????????????? */
#define ADS_UL_GET_STAT_TIMER_LEN()     \
            (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.stThresholdStatInfo.ulStatTmrLen)

#define ADS_UL_ADD_STAT_PKT_NUM(n)      \
            (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.stThresholdStatInfo.ulStatPktNum += (n))

#define ADS_UL_GET_STAT_PKT_NUM()       \
            (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.stThresholdStatInfo.ulStatPktNum)

#define ADS_UL_CLR_STAT_PKT_NUM()       \
            (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.stThresholdStatInfo.ulStatPktNum = 0)

/* ???????????????????? */
#define ADS_UL_GET_THRESHOLD_ACTIVE_FLAG() \
            (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.ulActiveFlag)

/* ??????????????jiffies?????????? */
#define ADS_UL_GET_JIFFIES_TMR_CNT()     (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.ulProtectTmrCnt)

/* ??????????????jiffies?????????? */
#define ADS_UL_SET_JIFFIES_TMR_CNT(n)     (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.ulProtectTmrCnt += (n))

/* ??????????????jiffies?????????? */
#define ADS_UL_GET_JIFFIES_EXP_TMR_LEN() (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.ulProtectTmrExpCnt)

/* ?????????????????????? */
#define ADS_UL_GET_WATER_LEVEL_ONE()    \
            (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.stWaterMarkLevel.ulWaterLevel1)

#define ADS_UL_GET_WATER_LEVEL_TWO()    \
            (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.stWaterMarkLevel.ulWaterLevel2)

#define ADS_UL_GET_WATER_LEVEL_THREE()  \
            (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.stWaterMarkLevel.ulWaterLevel3)

#define ADS_UL_GET_WATER_LEVEL_FOUR()   \
            (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.stWaterMarkLevel.ulWaterLevel4)

/* ???????????????? */
#define ADS_UL_DATA_THRESHOLD_ONE       \
            (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.stThresholdLevel.ulThreshold1)

#define ADS_UL_DATA_THRESHOLD_TWO       \
            (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.stThresholdLevel.ulThreshold2)

#define ADS_UL_DATA_THRESHOLD_THREE     \
            (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.stThresholdLevel.ulThreshold3)

#define ADS_UL_DATA_THRESHOLD_FOUR      \
            (g_stAdsCtx.stAdsIpfCtx.stUlAssemParmInfo.stThresholdLevel.ulThreshold4)


/*******************************???? End*******************************/

/* ????IPF?????????????????? */
#define ADS_UL_IPF_SRCMEM_FREE_QUE()            (&(g_stAdsCtx.stAdsIpfCtx.stUlSrcMemFreeQue))

/* IPF??????????????QUEUE????????????????IPF BD????????2?? */
#define ADS_UL_IPF_SRCMEM_FREE_QUE_SIZE         (2 * IPF_ULBD_DESC_SIZE)

/* ????????ADS??????????????????A???????????????????????????? */
#if (defined(CONFIG_BALONG_SPE))
#define ADS_UL_MAX_QUEUE_LENGTH                 (448)
#else
#define ADS_UL_MAX_QUEUE_LENGTH                 (500)
#endif

/* ???????????????? */
#define ADS_UL_GET_MAX_QUEUE_LENGTH(i)          (g_stAdsCtx.astAdsSpecCtx[i].stAdsUlCtx.ulUlMaxQueueLength)

/* ????ADS????IPF AD BUFFER???? */
#define ADS_DL_GET_IPF_AD_DESC_PTR(i, j)        (&(g_stAdsCtx.stAdsIpfCtx.astIpfDlAdDesc[i][j]))
#define ADS_DL_GET_IPF_AD_RECORD_PTR(i)         (&(g_stAdsCtx.stAdsIpfCtx.astIpfDlAdRecord[i]))

/*******************************???? Begin*******************************/

/* ????ADS???????????? */
#define ADS_DL_GET_CTX_PTR(i)                   (&(g_stAdsCtx.astAdsSpecCtx[i].stAdsDlCtx))

/* ????ADS????IPF RD BUFFER???? */
#define ADS_DL_GET_IPF_RD_DESC_PTR(index)       (&(g_stAdsCtx.stAdsIpfCtx.astIpfDlRdDesc[index]))
#define ADS_DL_GET_IPF_RD_RECORD_PTR()          (&(g_stAdsCtx.stAdsIpfCtx.stIpfDlRdRecord))

/* ????ADS????RAB INFO???? */
#define ADS_DL_GET_RAB_INFO_PTR(i, rabid)       (&(ADS_DL_GET_CTX_PTR(i)->astAdsDlRabInfo[rabid - ADS_RAB_ID_OFFSET]))

/* ????ADS????RAB???????????????? */
#define ADS_DL_GET_PKT_TYPE(instance, rabid)    (ADS_DL_GET_CTX_PTR(instance)->astAdsDlRabInfo[rabid - ADS_RAB_ID_OFFSET].enPktType)

/* ????ADS???????????????????? */
#define ADS_DL_GET_DATA_CALLBACK_FUNC(i,j)      (ADS_DL_GET_RAB_INFO_PTR(i,j)->pRcvDlDataFunc)
#define ADS_DL_GET_DATA_EXPARAM(i,j)            (ADS_DL_GET_RAB_INFO_PTR(i,j)->ulExParam)

#if (FEATURE_ON == FEATURE_RNIC_NAPI_GRO)
/* ????ADS????RD???????????????????????????? */
#define ADS_DL_GET_RD_LST_DATA_CALLBACK_FUNC(i,j)       (ADS_DL_GET_RAB_INFO_PTR(i,j)->pRcvRdLstDataFunc)
#endif

/* get/set the last data buff ptr */
#define ADS_DL_GET_LST_DATA_PTR(mid,rabid)          (ADS_DL_GET_RAB_INFO_PTR(mid,rabid)->pstLstPkt)
#define ADS_DL_SET_LST_DATA_PTR(mid,rabid, psPara)  (ADS_DL_GET_RAB_INFO_PTR(mid,rabid)->pstLstPkt = (psPara))

#define ADS_DL_GET_FILTER_DATA_CALLBACK_FUNC(ucInstanceIndex, ucRabId) \
            (ADS_DL_GET_RAB_INFO_PTR(ucInstanceIndex, ucRabId)->pRcvDlFilterDataFunc)

/* ????ADS???????????????????? */
#define ADS_DL_GET_FC_ASSEM_INFO_PTR(i)         (&(ADS_DL_GET_CTX_PTR(i)->stFcAssemInfo))

/* ????ADS???????????????????????????????? */
#define ADS_DL_GET_FC_ASSEM_TUNE_FUNC(i)        (ADS_DL_GET_FC_ASSEM_INFO_PTR(i)->pFcAssemTuneFunc)

#define ADS_DL_GET_PKT_ERR_FEEDBACK_CFG_PTR()   (&(g_stAdsCtx.stPktErrFeedbackCfg))
#define ADS_DL_GET_PKT_ERR_STATS_PTR(mid,rabid) (&(g_stAdsCtx.astPktErrStats[mid][rabid - ADS_RAB_ID_OFFSET]))

/* ????ADS????C???????????????????????? */
#define ADS_DL_GET_CCORE_RESET_DELAY_TIMER_LEN()    (g_stAdsCtx.stAdsIpfCtx.ulCCoreResetDelayTmrLen)


/*******************************???? End*******************************/

/*******************************IPF Begin*******************************/
/* ????IPF???????????? */
#define ADS_GET_IPF_CTX_PTR()           (&(g_stAdsCtx.stAdsIpfCtx))

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0))
#define ADS_GET_IPF_DEV()               (&(g_stAdsCtx.stAdsIpfCtx.stDev))
#else
#define ADS_GET_IPF_DEV()               (g_pstDmaDev)
#endif

#define ADS_IMM_MEM_CB(pstImmZc)        ((ADS_IMM_MEM_CB_STRU *)((pstImmZc)->cb))

#if (defined(CONFIG_BALONG_SPE))
#define ADS_GET_IPF_SPE_WPORT()         (g_stAdsCtx.stAdsIpfCtx.lSpeWPort)
#define ADS_GET_IPF_MEM_POOL_CFG_PTR()  (&(g_stAdsCtx.stAdsIpfCtx.stMemPoolCfg))
#define ADS_GET_IPF_MEM_POOL_PTR(id)    (&(g_stAdsCtx.stAdsIpfCtx.astMemPool[id]))
#define ADS_GET_IPF_MEM_QUE(id)         (&(g_stAdsCtx.stAdsIpfCtx.astMemPool[id].stQue))
#define ADS_SPE_MEM_CB(pstImmZc)        ((ADS_SPE_MEM_CB_STRU *)&((pstImmZc)->dma))
#endif

/*lint -emacro({717}, ADS_IPF_SPE_MEM_MAP)*/
#define ADS_IPF_SPE_MEM_MAP(pstImmZc, ulLen)\
            do\
            {\
                if (VOS_TRUE == ADS_IPF_IsSpeMem(pstImmZc))\
                {\
                    ADS_IPF_MemMapByDmaRequset(pstImmZc, ulLen, 0);\
                }\
            } while(0)

/*lint -emacro({717}, ADS_IPF_SPE_MEM_UNMAP)*/
#define ADS_IPF_SPE_MEM_UNMAP(pstImmZc, ulLen)\
            do\
            {\
                if (VOS_TRUE == ADS_IPF_IsSpeMem(pstImmZc))\
                {\
                    ADS_IPF_MemUnmapRequset(pstImmZc, ulLen, 0);\
                }\
            } while(0)

/* ????IPF???? */
#define ADS_GET_IPF_MODE()              (g_stAdsCtx.stAdsIpfCtx.ucIpfMode)

#define ADS_GET_IPF_FILTER_QUE()        (&(g_stAdsCtx.stAdsIpfCtx.stIpfFilterQue))

/*******************************IPF End*******************************/

/* ????MODEMID?????? */
#define ADS_IS_MODEMID_VALID(mid) \
            ((mid) < ADS_INSTANCE_MAX_NUM)

/* ????RABIID?????? */
#define ADS_IS_RABID_VALID(rabid) \
            (((rabid) >= ADS_RAB_ID_MIN) && ((rabid) <= ADS_RAB_ID_MAX))

#define ADS_UL_IS_REACH_THRESHOLD(ulAllUlQueueDataNum, ucSendingFlg) \
            ((0 != ulAllUlQueueDataNum) \
             && (ulAllUlQueueDataNum >= ADS_UL_SEND_DATA_NUM_THREDHOLD) \
             && (VOS_FALSE == ucSendingFlg))

#if !defined(ADS_ARRAY_SIZE)
#define ADS_ARRAY_SIZE(a)               (sizeof((a)) / sizeof((a[0])))
#endif

#if (defined(LLT_OS_VER))
typedef unsigned long         SPINLOCK_STRU;
#else
typedef VOS_SPINLOCK          SPINLOCK_STRU;
#endif

/*****************************************************************************
  3 ????????
*****************************************************************************/

/*****************************************************************************
 ????????  : ADS_IPF_MEM_POOL_ID_ENUM
 ????????  : IPF ????????
*****************************************************************************/
enum ADS_IPF_MEM_POOL_ID_ENUM
{
    ADS_IPF_MEM_POOL_ID_AD0             = 0,
    ADS_IPF_MEM_POOL_ID_AD1,

    ADS_IPF_MEM_POOL_ID_BUTT
};
typedef VOS_UINT32 ADS_IPF_MEM_POOL_ID_ENUM_UINT32;


enum ADS_IPF_MODE_ENUM
{
    ADS_IPF_MODE_INT  = 0x00,                                                   /* ?????????? */
    ADS_IPF_MODE_THRD = 0x01,                                                   /* ?????????? */
    ADS_IPF_MODE_BUTT
};
typedef VOS_UINT8 ADS_IPF_MODE_ENUM_UINT8;

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
 ????????  : ADS_SPE_MEM_CB_STRU
 ????????  : IPF CB????
*****************************************************************************/
typedef struct
{
    dma_addr_t                          ulDmaAddr;

} ADS_SPE_MEM_CB_STRU;

/*****************************************************************************
 ????????  : ADS_IMM_MEM_CB_STRU
 ????????  : IMM CB????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          aulPriv[2];
    dma_addr_t                          ulDmaAddr;

} ADS_IMM_MEM_CB_STRU;

/*****************************************************************************
 ????????  : ADS_IPF_BD_BUFF_STRU
 ????????  : IPF BD Buffer????
*****************************************************************************/
typedef struct
{
    IMM_ZC_STRU                        *pstPkt;

} ADS_IPF_BD_BUFF_STRU;

/*****************************************************************************
 ????????  : ADS_IPF_RD_BUFF_STRU
 ????????  : IPF RD Buffer????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulSlice;
    VOS_UINT16                          usAttr;
    VOS_UINT16                          usPktLen;
    IMM_ZC_STRU                        *pstImmZc;
    VOS_VOID                           *pOutPtr;

} ADS_IPF_RD_BUFF_STRU;

/*****************************************************************************
 ????????  : ADS_IPF_RD_RECORD_STRU
 ????????  : IPF RD ??????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulPos;
    VOS_UINT8                           aucRsv[4];
    ADS_IPF_RD_BUFF_STRU                astRdBuff[ADS_IPF_RD_BUFF_RECORD_NUM];

} ADS_IPF_RD_RECORD_STRU;

/*****************************************************************************
 ????????  : ADS_IPF_AD_BUFF_STRU
 ????????  : IPF AD Buffer????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulSlice;
#ifndef CONFIG_NEW_PLATFORM
    VOS_UINT32                          ulPhyAddr;
#else
    VOS_UINT8                           aucRsv[4];
    VOS_VOID                           *pulPhyAddr;
#endif
    IMM_ZC_STRU                        *pstImmZc;
} ADS_IPF_AD_BUFF_STRU;

/*****************************************************************************
 ????????  : ADS_IPF_AD_RECORD_STRU
 ????????  : IPF AD ??????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulPos;
    VOS_UINT8                           aucRsv[4];
    ADS_IPF_AD_BUFF_STRU                astAdBuff[ADS_IPF_AD_BUFF_RECORD_NUM];
} ADS_IPF_AD_RECORD_STRU;


typedef struct
{
    IMM_ZC_HEAD_STRU                   *pstAdsUlLink;                           /* Rab Id?????????? */
    SPINLOCK_STRU                       stSpinLock;                             /* ?????? */
    VOS_UINT8                           ucIsQueueValid;                         /* ??????????????VOS_TRUE:??????VOS_FALSE:?????? */
    ADS_QCI_TYPE_ENUM_UINT8             enPrio;                                 /* ?????????? */
    VOS_UINT16                          usRecordNum;                            /* ???????????????????????????????????? */
    ADS_CDS_IPF_PKT_TYPE_ENUM_UINT8     enPktType;                              /* ?????????? */
    VOS_UINT8                           uc1XorHrpdUlIpfFlag;                    /* 1X OR HRPD????????IPF?????? */
    VOS_UINT8                           aucRsv[2];

}ADS_UL_QUEUE_STRU;


typedef struct
{
    VOS_UINT32                          ulRabId;                                /* Rab Id */
    VOS_UINT32                          ulExParam;                              /* RMNET???????????????? */
    ADS_CDS_IPF_PKT_TYPE_ENUM_UINT8     enPktType;                              /* ?????????? */
    VOS_UINT8                           aucRsv[7];                              /* ???? */
    RCV_DL_DATA_FUNC                    pRcvDlDataFunc;                         /* ?????????????????? */
    RCV_DL_DATA_FUNC                    pRcvDlFilterDataFunc;                   /* ?????????????????????? */
#if (FEATURE_ON == FEATURE_RNIC_NAPI_GRO)
    RCV_RD_LAST_DATA_FUNC               pRcvRdLstDataFunc;                      /* ????RD?????????????????????? */
#endif
    IMM_ZC_STRU                        *pstLstPkt;

}ADS_DL_RAB_INFO_STRU;


typedef struct
{
    VOS_UINT32              ulEnableMask;
    VOS_UINT32              ulFcActiveFlg;
    unsigned long           ulTmrCnt;
    VOS_UINT32              ulRdCnt;
    VOS_UINT32              ulRateUpLev;
    VOS_UINT32              ulRateDownLev;
    VOS_UINT32              ulExpireTmrLen;
} ADS_DL_FC_ASSEM_STRU;


typedef struct
{
    ADS_DL_RAB_INFO_STRU                astAdsDlRabInfo[ADS_RAB_NUM_MAX];       /*????Rab???? */
    ADS_DL_FC_ASSEM_STRU                stFcAssemInfo;

} ADS_DL_CTX_STRU;


typedef struct
{
    ADS_UL_QUEUE_STRU                   astAdsUlQueue[ADS_RAB_ID_MAX + 1];      /* ??????????????????5-15 */
    ADS_UL_QUEUE_SCHEDULER_PRI_NV_STRU  stQueuePriNv;                           /* ??NV?????????????????????????????????? */
    VOS_UINT32                          aulPrioIndex[ADS_RAB_NUM_MAX];          /* ???????????????????????????????? */
    VOS_UINT32                          ulAdsUlCurIndex;                        /* ?????????????????? */
    VOS_UINT32                          ulUlMaxQueueLength;                     /* ???????????? */
    VOS_UINT32                          ulReserved;
}ADS_UL_CTX_STRU;


typedef struct ADS_UL_DATA_STATS
{
    VOS_UINT32                          ulULCurDataRate;                        /* ??????????????????PDP??????2?????????????????????? */
    VOS_UINT32                          ulULPeriodSndBytes;                     /* ????????????????????????byte?? */
}ADS_UL_DATA_STATS_STRU;


typedef struct ADS_DL_DATA_STATS
{
    VOS_UINT32                          ulDLCurDataRate;                        /* ??????????????????PDP??????2?????????????????????? */
    VOS_UINT32                          ulDLPeriodRcvBytes;                     /* ????????????????????????byte?? */
}ADS_DL_DATA_STATS_STRU;


typedef struct
{
    ADS_UL_DATA_STATS_STRU              stULDataStats;                          /* ADS???????????? */
    ADS_DL_DATA_STATS_STRU              stDLDataStats;                          /* ADS???????????? */
}ADS_STATS_INFO_CTX_STRU;


typedef struct
{
    VOS_UINT32                          ulStatTmrLen;                           /* ?????????????? */
    VOS_UINT32                          ulStatPktNum;                           /* ???????????????????????????? */
}ADS_UL_THRESHOLD_STAT_STRU;


typedef struct
{
    VOS_UINT32                          ulActiveFlag;                           /* ????????: 0??????????,1???????? */
    VOS_UINT32                          ulProtectTmrExpCnt;                     /* ?????????????????? */
    unsigned long                       ulProtectTmrCnt;                        /* ???????????????? */
    ADS_UL_WATER_MARK_LEVEL_STRU        stWaterMarkLevel;                       /* ?????????? */
    ADS_UL_THRESHOLD_LEVEL_STRU         stThresholdLevel;                       /* ?????????????? */
    ADS_UL_THRESHOLD_STAT_STRU          stThresholdStatInfo;                    /* ???????????? */
}ADS_UL_DYNAMIC_ASSEM_INFO_STRU;


typedef struct
{
    VOS_UINT16                          usBlkNum;
    VOS_UINT16                          usBlkSize;
    VOS_UINT8                           ucPort;
    VOS_UINT8                           aucReserved[3];

} ADS_IPF_MEM_CFG_STRU;


typedef struct
{
    VOS_UINT32                          ulEnable;
    VOS_UINT8                           aucReserved[4];
    ADS_IPF_MEM_CFG_STRU                astMemCfg[ADS_IPF_MEM_POOL_ID_BUTT];

} ADS_IPF_MEM_POOL_CFG_STRU;


typedef struct
{
    VOS_UINT16                          usBlkSize;
    VOS_UINT16                          usBlkNum;
    VOS_UINT8                           ucPort;
    VOS_UINT8                           aucReserved[3];
    IMM_ZC_HEAD_STRU                    stQue;

} ADS_IPF_MEM_POOL_STRU;


typedef struct
{
    IPF_CONFIG_ULPARAM_S                astIpfUlBdCfgParam[IPF_ULBD_DESC_SIZE]; /* ????BD DESC */
    IPF_RD_DESC_S                       astIpfDlRdDesc[IPF_DLRD_DESC_SIZE];     /* ????RD DESC */
    ADS_IPF_RD_RECORD_STRU              stIpfDlRdRecord;
    IPF_AD_DESC_S                       astIpfDlAdDesc[ADS_DL_ADQ_MAX_NUM][IPF_DLAD0_DESC_SIZE];   /* ????AD DESC */
    ADS_IPF_AD_RECORD_STRU              astIpfDlAdRecord[ADS_DL_ADQ_MAX_NUM];
    ADS_IPF_BD_BUFF_STRU                astIpfUlBdBuff[IPF_ULBD_DESC_SIZE];     /* ????BD */
    IMM_ZC_HEAD_STRU                    stUlSrcMemFreeQue;                      /* IPF????????????BUFF */
    ADS_UL_DYNAMIC_ASSEM_INFO_STRU      stUlAssemParmInfo;                      /* ???????????????? */
    VOS_UINT32                          ulThredHoldNum;                         /* ?????????????? */
    VOS_UINT32                          ulProtectTmrLen;
    VOS_UINT8                           ucSendingFlg;                           /* ???????????? */
    VOS_UINT8                           ucIpfMode;                              /* IPF????ADS??????????????, 0: ??????????(????)??1???????????? */
    VOS_UINT8                           aucRsv[2];

    VOS_UINT32                          ulWakeLockEnable;                       /* wake lock ???????? */

    struct wakeup_source                stUlBdWakeLock;                         /* wake lock BD */
    struct wakeup_source                stDlRdWakeLock;                         /* wake lock RD */

    struct wakeup_source                stRxWakeLock;                           /* wake lock RX */
    struct wakeup_source                stTxWakeLock;                           /* wake lock TX */

    VOS_UINT32                          ulUlBdWakeLockCnt;                      /* wake lock BD ???? */
    VOS_UINT32                          ulDlRdWakeLockCnt;                      /* wake lock BD ???? */

    VOS_UINT32                          ulRxWakeLockTimeout;                    /* wake lock RX ???????? */
    VOS_UINT32                          ulTxWakeLockTimeout;                    /* wake lock TX ???????? */

    VOS_UINT32                          ulTxWakeLockTmrLen;                     /* wake lock TX ???????? */
    VOS_UINT32                          ulRxWakeLockTmrLen;                     /* wake lock RX ???????? */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0))
    struct device                       stDev;
#endif
#if (defined(CONFIG_BALONG_SPE))
    VOS_INT32                           lSpeWPort;
    VOS_UINT8                           aucReserved[4];
    ADS_IPF_MEM_POOL_CFG_STRU           stMemPoolCfg;
    ADS_IPF_MEM_POOL_STRU               astMemPool[ADS_IPF_MEM_POOL_ID_BUTT];
#endif
    IMM_ZC_HEAD_STRU                    stIpfFilterQue;

    SPINLOCK_STRU                       stAdqSpinLock;                          /* ????AD???????????? */

    VOS_UINT32                          ulCCoreResetDelayTmrLen;
    VOS_UINT8                           aucReserved1[4];

}ADS_IPF_CTX_STRU;


typedef struct
{
    ADS_UL_CTX_STRU                     stAdsUlCtx;                             /* ?????????? */
    ADS_DL_CTX_STRU                     stAdsDlCtx;                             /* ?????????? */

} ADS_SPEC_CTX_STRU;

/*****************************************************************************
 ????????  : ADS_BEARER_PACKET_ERROR_STATS_STRU
 ????????  : ????????????????????
*****************************************************************************/
typedef struct
{
    VOS_ULONG                           ulMinDetectExpires;                     /* ???????????? */
    VOS_ULONG                           ulMaxDetectExpires;                     /* ???????????? */

    VOS_UINT32                          ulErrorPktNum;                          /* ???????? */
    VOS_UINT32                          ulTotalPktNum;                          /* ???????? */

} ADS_BEARER_PACKET_ERROR_STATS_STRU;

/*****************************************************************************
 ????????  : ADS_PACKET_ERROR_FEEDBACK_CFG_STRU
 ????????  : ????????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulEnabled;                              /* ???????? */
    VOS_UINT32                          ulPktErrRateThres;                      /* ????????(??????) */
    VOS_ULONG                           ulMinDetectDuration;                    /* ????????????????(TICK) */
    VOS_ULONG                           ulMaxDetectDuration;                    /* ????????????????(TICK) */

} ADS_PACKET_ERROR_FEEDBACK_CFG_STRU;


typedef struct
{
    ADS_SPEC_CTX_STRU                   astAdsSpecCtx[ADS_INSTANCE_MAX_NUM];    /* ???????????????????? */
    ADS_STATS_INFO_CTX_STRU             stDsFlowStatsCtx;                       /* ???????? */
    ADS_IPF_CTX_STRU                    stAdsIpfCtx;                            /* ??IPF???????????? */
    ADS_TIMER_CTX_STRU                  astAdsTiCtx[ADS_MAX_TIMER_NUM];         /* ???????????? */
    VOS_UINT32                          ulAdsCurInstanceIndex;                  /* ??????????index */
    VOS_UINT8                           ucUlResetFlag;
    VOS_UINT8                           aucRsv[3];
    VOS_SEM                             hULResetSem;                            /* ??????????????????UL????????  */
    VOS_SEM                             hDLResetSem;                            /* ??????????????????DL????????  */

    ADS_PACKET_ERROR_FEEDBACK_CFG_STRU  stPktErrFeedbackCfg;
    ADS_BEARER_PACKET_ERROR_STATS_STRU  astPktErrStats[ADS_INSTANCE_MAX_NUM][ADS_RAB_NUM_MAX];

} ADS_CTX_STRU;


/*****************************************************************************
  8 UNION????
*****************************************************************************/


/*****************************************************************************
  9 OTHERS????
*****************************************************************************/

extern VOS_UINT32                       g_ulAdsULTaskId;
extern VOS_UINT32                       g_ulAdsDLTaskId;
extern VOS_UINT32                       g_ulAdsULTaskReadyFlag;
extern VOS_UINT32                       g_ulAdsDLTaskReadyFlag;
extern ADS_CTX_STRU                     g_stAdsCtx;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0))
extern struct device                   *g_pstDmaDev;
#endif

/*****************************************************************************
  10 ????????
*****************************************************************************/

VOS_UINT32 ADS_UL_IsAllRabNotSndPermitFlg(VOS_VOID);
VOS_UINT32 ADS_UL_GetSpecInstanceSndPermitFlg(VOS_UINT32 ulInstanceIndex);
VOS_VOID ADS_DL_ProcEvent(VOS_UINT32 ulEvent);
VOS_VOID ADS_DL_SndEvent(VOS_UINT32 ulEvent);
ADS_DL_CTX_STRU* ADS_GetDlCtx(VOS_UINT32 ulInstanceIndex);
ADS_TIMER_CTX_STRU* ADS_GetTiCtx(VOS_VOID);
ADS_UL_CTX_STRU* ADS_GetUlCtx(VOS_UINT32 ulInstanceIndex);
VOS_VOID ADS_InitCtx(VOS_VOID);
VOS_VOID ADS_InitDlCtx(VOS_UINT32 ulInstance);
VOS_VOID ADS_InitIpfCtx(VOS_VOID);
VOS_VOID ADS_InitSpecCtx(VOS_VOID);
VOS_VOID ADS_InitStatsInfoCtx(VOS_VOID);
VOS_VOID ADS_InitTiCtx(VOS_VOID);
VOS_VOID ADS_InitUlCtx(VOS_UINT32 ulInstanceIndex);
VOS_UINT32 ADS_UL_CheckAllQueueEmpty(VOS_UINT32 ulInstanceIndex);
VOS_VOID ADS_UL_ClearQueue(
    IMM_ZC_HEAD_STRU                    *pstQueue
);
VOS_UINT32 ADS_UL_CreateQueue(
    VOS_UINT32                           ulInstanceIndex,
    VOS_UINT32                           ulRabId,
    ADS_QCI_TYPE_ENUM_UINT8              enPrio,
    ADS_CDS_IPF_PKT_TYPE_ENUM_UINT8      enPdpType,
    VOS_UINT8                            uc1XorHrpdUlIpfFlag
);
VOS_VOID ADS_UL_DestroyQueue(
    VOS_UINT32                           ulInstanceIndex,
    VOS_UINT32                           ulRabId
);
VOS_UINT32 ADS_UL_GetAllQueueDataNum(VOS_VOID);
VOS_UINT32 ADS_UL_GetInsertIndex(
    VOS_UINT32                           ulInstanceIndex,
    VOS_UINT32                           ulRabId
);
VOS_UINT32 ADS_UL_GetInstanceAllQueueDataNum(VOS_UINT32 ucInstanceIndex);
VOS_UINT32 ADS_UL_InsertQueue(
    VOS_UINT32                          ulInstance,
    IMM_ZC_STRU                        *pstData,
    VOS_UINT32                          ulRabId
);
VOS_UINT32 ADS_UL_IsQueueExistent(
    VOS_UINT32                           ulInstanceIndex,
    VOS_UINT32                           ulRabId
);
VOS_VOID ADS_UL_OrderQueueIndex(
    VOS_UINT32                           ulInstanceIndex,
    VOS_UINT32                           ulIndex
);
VOS_VOID ADS_UL_ProcEvent(VOS_UINT32 ulEvent);
VOS_VOID ADS_UL_SetProtectTmrLen(VOS_UINT32 ulTimerLen);
VOS_VOID ADS_UL_SetQueue(
    VOS_UINT32                          ulInstanceIndex,
    VOS_UINT32                          ulRabId,
    VOS_UINT8                           ucIsQueueValid,
    IMM_ZC_HEAD_STRU                   *pstUlQueue,
    ADS_QCI_TYPE_ENUM_UINT8             enPrio,
    ADS_CDS_IPF_PKT_TYPE_ENUM_UINT8     enPdpType,
    VOS_UINT8                           uc1XorHrpdUlIpfFlag
);
VOS_VOID ADS_UL_SndEvent(VOS_UINT32 ulEvent);
VOS_VOID ADS_UL_UpdateQueueInPdpDeactived(
    VOS_UINT32                           ulInstanceIndex,
    VOS_UINT32                           ulRabId
);
VOS_VOID ADS_UL_UpdateQueueInPdpModified(
           VOS_UINT32                           ulInstanceIndex,
           ADS_QCI_TYPE_ENUM_UINT8              enPrio,
           VOS_UINT32                           ulRabId
);
ADS_CTX_STRU* ADS_GetAllCtx(VOS_VOID);

VOS_UINT32 ADS_UL_EnableRxWakeLockTimeout(VOS_UINT32 ulValue);
VOS_UINT32 ADS_UL_WakeLockTimeout(VOS_VOID);
VOS_UINT32 ADS_UL_WakeLock(VOS_VOID);
VOS_UINT32 ADS_UL_WakeUnLock(VOS_VOID);
VOS_UINT32 ADS_DL_EnableTxWakeLockTimeout(VOS_UINT32 ulValue);
VOS_UINT32 ADS_DL_WakeLockTimeout(VOS_VOID);
VOS_UINT32 ADS_DL_WakeLock(VOS_VOID);
VOS_UINT32 ADS_DL_WakeUnLock(VOS_VOID);

VOS_VOID ADS_DL_InitFcAssemParamInfo(VOS_VOID);
VOS_SEM ADS_GetULResetSem(VOS_VOID);
VOS_SEM ADS_GetDLResetSem(VOS_VOID);
VOS_VOID ADS_DL_ResetFcAssemParamInfo(VOS_VOID);
VOS_VOID ADS_ResetSpecUlCtx(VOS_UINT32 ulInstance);
VOS_VOID ADS_ResetUlCtx(VOS_VOID);
VOS_VOID ADS_ResetSpecDlCtx(VOS_UINT32 ulInstance);
VOS_VOID ADS_ResetDlCtx(VOS_VOID);
VOS_VOID ADS_ResetIpfCtx(VOS_VOID);

VOS_UINT32 ADS_UL_IsAnyQueueExist(VOS_VOID);

VOS_UINT8 ADS_GetUlResetFlag(VOS_VOID);
VOS_VOID  ADS_SetUlResetFlag(VOS_UINT8 ucFlag);

VOS_UINT32 ADS_IPF_IsSpeMem(IMM_ZC_STRU *pstImmZc);
IMM_ZC_STRU* ADS_IPF_AllocMem(VOS_UINT32 ulPoolId, VOS_UINT32 ulLen, VOS_UINT32 ulReserveLen);
dma_addr_t ADS_IPF_GetMemDma(IMM_ZC_STRU *pstImmZc);
VOS_VOID ADS_IPF_SetMemDma(IMM_ZC_STRU *pstImmZc, dma_addr_t ulDmaAddr);
VOS_VOID ADS_IPF_MemMapRequset(IMM_ZC_STRU *pstImmZc, VOS_UINT32 ulLen, VOS_UINT8 ucIsIn);
VOS_VOID ADS_IPF_MemMapByDmaRequset(IMM_ZC_STRU *pstImmZc, VOS_UINT32 ulLen, VOS_UINT8 ucIsIn);
VOS_VOID ADS_IPF_MemUnmapRequset(IMM_ZC_STRU *pstImmZc, VOS_UINT32 ulLen, VOS_UINT8 ucIsIn);

#if (defined(CONFIG_BALONG_SPE))
VOS_VOID ADS_IPF_InitMemPoolCfg(VOS_VOID);
VOS_VOID ADS_IPF_CreateMemPool(VOS_VOID);
#endif

VOS_VOID ADS_DL_ProcIpfFilterQue(VOS_VOID);
VOS_VOID ADS_DL_ProcIpfFilterData(
    IMM_ZC_STRU                        *pstImmZc
);


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0))
VOS_INT32 ADS_PlatDevProbe(struct platform_device *pstDev);
VOS_INT32 ADS_PlatDevRemove(struct platform_device *pstDev);
VOS_INT32 __init ADS_PlatDevInit(void);
VOS_VOID __exit ADS_PlatDevExit(void);
#endif

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


