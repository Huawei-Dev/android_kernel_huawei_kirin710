/*
 *
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses. You may choose this file to be licensed under the terms
 * of the GNU General Public License (GPL) Version 2 or the 2-clause
 * BSD license listed below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#include "product_config.h"
/******************************************************************************
   1 ??????????
******************************************************************************/
#include "PPP/Inc/ppp_public.h"
#include "PPP/Inc/layer.h"
#include "PPP/Inc/ppp_mbuf.h"
#include "PPP/Inc/hdlc.h"
#include "PPP/Inc/throughput.h"
#include "PPP/Inc/proto.h"
#include "PPP/Inc/ppp_fsm.h"
#include "PPP/Inc/lcp.h"
#include "PPP/Inc/async.h"
#include "PPP/Inc/auth.h"
#include "PPP/Inc/ipcp.h"
#include "PPP/Inc/pppid.h"
#include "PPP/Inc/link.h"
#include "PPP/Inc/ppp_init.h"
#include "PPP/Inc/ppp_input.h"

/*****************************************************************************
    ??????????????????????.C??????????
*****************************************************************************/
/*lint -e767  ????????: ??????????????ID???? */
#define    THIS_FILE_ID        PS_FILE_ID_PPP_INPUT_C
/*lint +e767  */

/******************************************************************************
   2 ????????????????
******************************************************************************/
extern VOS_VOID   PPP_ClearDataQ(VOS_VOID);

/******************************************************************************
   3 ????????
******************************************************************************/
#define PPP_ASYNC(PppId)  (PPP_LINK(PppId)->async)

/******************************************
??????????????????????????????????????
????:????????????(u)char *??
*******************************************/
#define PPP_PUTCHAR(c, cp) {     \
	*(cp) = (VOS_UINT8)(c);     \
	(cp) ++;                     \
}

#define PPP_PUTSHORT(s, cp) {    \
    *((VOS_UINT16 *)(cp)) = (s); \
    (cp) += 2;                   \
}

#define PPP_INCPTR(len, cp) {   \
    (cp) += (len);              \
}

#define PPP_LENALIGNTO2BYTE(alignedlen, len){                 \
    (alignedlen) = ((((len) % 2) == 0) ? (len) : (len + 1));\
}

/******************************************************************************
   4 ????????????
******************************************************************************/
/*PPP????????????????,??????????????????????????*/
PPP_DATA_Q_CTRL_ST     g_PppDataQCtrl;

/* RAWDATA???????????????????????? */
VOS_UINT32             g_ulRawDataByPassMode    = PS_FALSE;

/* A?????????????????????? */
VOS_SPINLOCK           g_stPppASpinLock;

/******************************************************************************
   5 ????????
******************************************************************************/

VOS_VOID PPP_InitSpinLock(VOS_VOID)
{
    VOS_SpinLockInit(&g_stPppASpinLock);
}


VOS_UINT32 PPP_GetRawDataByPassMode(VOS_VOID)
{
    return g_ulRawDataByPassMode;
}


VOS_VOID PPP_SetRawDataByPassMode(VOS_UINT32 ulRawDataByPassMode)
{
    g_ulRawDataByPassMode    = ulRawDataByPassMode;

    return;
}


VOS_VOID PPP_INPUT_ResetStatInfo(VOS_VOID)
{
    PSACORE_MEM_SET(&(g_PppDataQCtrl.stStat), sizeof(PPP_DATA_Q_STAT_ST), 0, sizeof(PPP_DATA_Q_STAT_ST));

    return;
} /* PPP_ResetDataQStatInfo */

/******************************************************************************
 Function:       PPP_GetDataCnt
 Description:    ????????????????????????
 Calls:
 Data Accessed:
 Data Updated:
 Input:
 Output:
 Return:

 Others:
******************************************************************************/
VOS_UINT32 PPP_INPUT_GetDataCnt(VOS_VOID)
{
    VOS_UINT32  ulUlDataQCnt;

    ulUlDataQCnt    = PPP_ZC_GET_QUEUE_LEN(&g_PppDataQCtrl.stDataQ);

    return ulUlDataQCnt;
}


VOS_VOID    PPP_INPUT_ShowStatInfo(VOS_VOID)
{
    PS_PRINTF("\n================PPP STAT INFO Begin==========================\n");

    PS_PRINTF("node num                 = %d\n", PPP_ZC_GET_QUEUE_LEN(&g_PppDataQCtrl.stDataQ));

    PS_PRINTF("NotifyMsg                = %d\n", g_PppDataQCtrl.ulNotifyMsg);
    PS_PRINTF("DataNotify SndMsgCnt     = %d\n", g_PppDataQCtrl.stStat.ulSndMsgCnt);
    PS_PRINTF("DataNotify ProcMsgCnt    = %d\n", g_PppDataQCtrl.stStat.ulProcMsgCnt);
    PS_PRINTF("QMaxCnt                  = %d\n", g_PppDataQCtrl.stStat.ulQMaxCnt);
    PS_PRINTF("PPP_ONCE_DEAL_MAX_CNT    = %d\n", PPP_ONCE_DEAL_MAX_CNT);

    PS_PRINTF("MemAllocUplinkCnt        = %d\n", g_PppDataQCtrl.stStat.ulMemAllocUplinkCnt);
    PS_PRINTF("MemAllocUplinkFailCnt    = %d\n", g_PppDataQCtrl.stStat.ulMemAllocUplinkFailCnt);

    PS_PRINTF("MemAllocDownlinkCnt      = %d\n", g_PppDataQCtrl.stStat.ulMemAllocDownlinkCnt);
    PS_PRINTF("MemAllocDownlinkFailCnt  = %d\n", g_PppDataQCtrl.stStat.ulMemAllocDownlinkFailCnt);
    PS_PRINTF("MemFreeCnt               = %d\n", g_PppDataQCtrl.stStat.ulMemFreeCnt);

    PS_PRINTF("UplinkCnt                = %d\n", g_PppDataQCtrl.stStat.ulUplinkCnt);
    PS_PRINTF("UplinkDropCnt            = %d\n", g_PppDataQCtrl.stStat.ulUplinkDropCnt);
    PS_PRINTF("UplinkSndDataCnt         = %d\n", g_PppDataQCtrl.stStat.ulUplinkSndDataCnt);

    PS_PRINTF("DownlinkCnt              = %d\n", g_PppDataQCtrl.stStat.ulDownlinkCnt);
    PS_PRINTF("DownlinkDropCnt          = %d\n", g_PppDataQCtrl.stStat.ulDownlinkDropCnt);
    PS_PRINTF("DownlinkSndDataCnt       = %d\n", g_PppDataQCtrl.stStat.ulDownlinkSndDataCnt);

    PS_PRINTF("DropCnt                  = %d\n", g_PppDataQCtrl.stStat.ulDropCnt);

    PS_PRINTF("================PPP STAT INFO End==========================\n");

    return;
}


VOS_UINT32  PPP_Snd1stDataNotify(VOS_VOID)
{
    if (1 == g_stPppEntInfo.ulPppInitFlag)
    {
        (VOS_VOID)VOS_EventWrite(g_stPppEntInfo.ulPppTaskId, PPP_RCV_DATA_EVENT);
    }

    return PS_SUCC;
} /* PPP_Snd1stDataNotify */



VOS_UINT32  PPP_EnqueueData(PPP_ZC_STRU *pstImmZc, PPP_DATA_TYPE_ENUM_UINT8 enDataType, PPP_ID usPppId)
{
    VOS_ULONG                           ulFlags     = 0UL;
    PPP_ZC_QUEUE_STRU                  *pstDataQ    = &(g_PppDataQCtrl.stDataQ);
    struct link                        *link        = PPP_LINK(usPppId);        /* usPppId???????????????????? */

    if (PPP_ZC_GET_QUEUE_LEN(pstDataQ) > g_stPppEntInfo.usQueneMaxCnt)
    {
        PPP_MemFree(pstImmZc);
        g_PppDataQCtrl.stStat.ulDropCnt++;
    }
    else if ( (PPP_PUSH_PACKET_TYPE == enDataType) && ((ST_STOPPING == link->lcp.fsm.state) || (ST_CLOSING == link->lcp.fsm.state)) )
    {
        PPP_MemFree(pstImmZc);
    }
    else
    {
        /*??????????????????????*/
        PPP_ZC_ENQUEUE_TAIL(pstDataQ, pstImmZc);
    }

    if (PPP_ZC_GET_QUEUE_LEN(pstDataQ) > g_PppDataQCtrl.stStat.ulQMaxCnt)
    {
        g_PppDataQCtrl.stStat.ulQMaxCnt = PPP_ZC_GET_QUEUE_LEN(pstDataQ);
    }

    /*  A??????????????????????????????????????????????????????????????????????
            ????????????????????????PPP????????????????????????????????????????????
            ?????????????????????????????????????????????? */
    VOS_SpinLockIntLock(&g_stPppASpinLock, ulFlags);    /*lint !e571*/

    if ((VOS_NO == g_PppDataQCtrl.ulNotifyMsg) && (0 < PPP_ZC_GET_QUEUE_LEN(pstDataQ)))
    {
        g_PppDataQCtrl.ulNotifyMsg = VOS_YES;
        g_PppDataQCtrl.stStat.ulSndMsgCnt++;

        VOS_SpinUnlockIntUnlock(&g_stPppASpinLock , ulFlags);

        /*??PPP????????????????*/
        if (PS_SUCC != PPP_Snd1stDataNotify())
        {
            /* ?????????????????????????????????? */
            PPP_ClearDataQ();
            return PS_FAIL;
        }

        return PS_SUCC;
    }

    VOS_SpinUnlockIntUnlock(&g_stPppASpinLock , ulFlags);

    return PS_SUCC;
} /* PPP_EnqueueData */



VOS_UINT32 PPP_PullPacketEvent(VOS_UINT16 usPppId, IMM_ZC_STRU *pstImmZc)
{
    if(VOS_NULL_PTR == pstImmZc)
    {
        PPP_MNTN_LOG( PS_PID_APP_PPP, 0, PS_PRINT_WARNING,
                      "PPP_PullPacketEvent, WARNING, pstImmZc is NULL!\r\n" );

        return PS_FAIL;
    }

    g_PppDataQCtrl.stStat.ulUplinkCnt++;

    /* ????V3R1??????????????????PPP ID????????????????????????????????(????PPP ID????????)??
    ????????????PC??????IPCP?????? */
    if((PPP_MAX_ID_NUM < usPppId) || (0 == usPppId))
    {
        g_PppDataQCtrl.stStat.ulUplinkDropCnt++;
        PPP_MNTN_LOG1(PS_PID_APP_PPP, 0, PS_PRINT_NORMAL,
                     "PPP, PPP_PullPacketEvent, NORMAL, usPppId %d Wrong\r\n", usPppId);
        PPP_MemFree(pstImmZc);

        return PS_FAIL;
    }

    /*????pstData??usApp????:??8????usPppId,??8????PPP????????*/
    PPP_ZC_SET_DATA_APP(pstImmZc, (VOS_UINT16)(usPppId << 8) | (VOS_UINT16)PPP_PULL_PACKET_TYPE);

    if ( PS_SUCC != PPP_EnqueueData(pstImmZc, PPP_PULL_PACKET_TYPE, usPppId) )
    {
        if (0 == (g_PppDataQCtrl.stStat.ulUplinkDropCnt & 0x7f))
        {
            PPP_MNTN_LOG( PS_PID_APP_PPP, 0, PS_PRINT_WARNING,
                          "PPP_PullPacketEvent, WARNING, Enqueue Data Fail!\r\n" );
        }

        g_PppDataQCtrl.stStat.ulUplinkDropCnt++;

        return PS_FAIL;
    }

    return PS_SUCC;
} /* PPP_PullPacketEvent */


VOS_UINT32 PPP_PullRawDataEvent(VOS_UINT16 usPppId, IMM_ZC_STRU *pstImmZc)
{
    PPP_ZC_STRU                        *pstMem;

    g_PppDataQCtrl.stStat.ulUplinkCnt++;

    if(VOS_NULL_PTR == pstImmZc)
    {
        PPP_MNTN_LOG( PS_PID_APP_PPP, 0, PS_PRINT_WARNING,
                      "PPP_PullRawDataEvent, WARNING, Alloc TTF mem fail!\r\n" );

        return PS_FAIL;
    }

    if((PPP_MAX_ID_NUM < usPppId)
        || (0 == usPppId))
    {
        g_PppDataQCtrl.stStat.ulUplinkDropCnt++;
        PPP_MNTN_LOG1(PS_PID_APP_PPP, 0, PS_PRINT_WARNING,
                     "PPP, PPP_PullRawDataEvent, WARNING, usPppId %d Wrong\r\n", usPppId);
        PPP_MemFree(pstImmZc);

        return PS_FAIL;
    }

    if (PS_TRUE == PPP_GetRawDataByPassMode())
    {
        pstMem = pstImmZc;
        /* PPP????????????????????ADS????PPP????????????????????0 */
        if (PS_SUCC != PPP_SendPulledData(usPppId, pstMem, 0))
        {
            return PS_FAIL;
        }
    }
    else
    {
        /*????pstData??usApp????:??8????usPppId,??8????PPP????????*/
        PPP_ZC_SET_DATA_APP(pstImmZc, (VOS_UINT16)(usPppId << 8) | (VOS_UINT16)PPP_PULL_RAW_DATA_TYPE);

        if ( PS_SUCC != PPP_EnqueueData(pstImmZc, PPP_PULL_RAW_DATA_TYPE, usPppId) )
        {
            PPP_MNTN_LOG( PS_PID_APP_PPP, 0, PS_PRINT_WARNING,
                          "PPP_PullRawDataEvent, WARNING, Enqueue Data Fail!\r\n" );

            return PS_FAIL;
        }
    }

    return PS_SUCC;
} /* PPP_PullRawEvent */


VOS_INT PPP_DlPacketProc(PPP_ID usPppId, IMM_ZC_STRU *pstImmZc)
{
    
    if(VOS_NULL_PTR == pstImmZc)
    {
        PPP_MNTN_LOG( PS_PID_APP_PPP, 0, PS_PRINT_WARNING,
                      "PPP_PushPacketEvent, WARNING, pstImmZc is NULL!\r\n" );

        return PS_FAIL;
    }

    /*??????????????????????*/
    if((VOS_OK != PppIsIdValid(usPppId))
        || (PPP_LINK(usPppId)->phase != PHASE_NETWORK)
        || (PPP_LINK(usPppId)->ipcp.fsm.state != ST_OPENED))
    {
        /*????????????????????0*/
        g_PppDataQCtrl.stStat.ulDownlinkDropCnt++;
        PPP_MNTN_LOG1(PS_PID_APP_PPP, 0, PS_PRINT_NORMAL,
                      "PPP, PPP_PushPacket, WARNING, packet from GGSN droped, packet num = <1>\r\n",
                      (VOS_INT32)g_PppDataQCtrl.stStat.ulDownlinkDropCnt);

        PPP_MemFree(pstImmZc);

        return PS_FAIL;
    }

    /*????pstData??usApp????:??8????usPppId,??8????PPP????????*/
    PPP_ZC_SET_DATA_APP(pstImmZc, (VOS_UINT16)(usPppId << 8) | (VOS_UINT16)PPP_PUSH_PACKET_TYPE);

    if ( PS_SUCC != PPP_EnqueueData(pstImmZc, PPP_PUSH_PACKET_TYPE, usPppId) )
    {
        if (0 == (g_PppDataQCtrl.stStat.ulDownlinkDropCnt & 0x7f))
        {
            PPP_MNTN_LOG( PS_PID_APP_PPP, 0, PS_PRINT_WARNING,
                          "PPP_PushPacketEvent, WARNING, Enqueue Data Fail!\r\n" );
        }

        g_PppDataQCtrl.stStat.ulDownlinkDropCnt++;

        return PS_FAIL;
    }

    return PS_SUCC;
}


VOS_INT PPP_DlRawDataProc(PPP_ID usPppId, IMM_ZC_STRU *pstImmZc)
{
    
    if(VOS_NULL_PTR == pstImmZc)
    {
        PPP_MNTN_LOG( PS_PID_APP_PPP, 0, PS_PRINT_WARNING,
                      "PPP_PushRawDataEvent, WARNING, pstImmZc is NULL!\r\n" );

        return PS_FAIL;
    }

    if(VOS_OK != PppIsIdValid(usPppId))
    {
        g_PppDataQCtrl.stStat.ulDownlinkDropCnt++;
        PPP_MemFree(pstImmZc);
        PPP_MNTN_LOG(PS_PID_APP_PPP, 0, PS_PRINT_WARNING,
                     "PPP_PushRawData, WARNING, Invalid PPP id, packet from GGSN droped\r\n");

        return PS_FAIL;
    }

    if (PS_TRUE == PPP_GetRawDataByPassMode())
    {
        AT_SendZcDataToModem(usPppId, pstImmZc);
    }
    else
    {
        /*????pstData??usApp????:??8????usPppId,??8????PPP????????*/
        PPP_ZC_SET_DATA_APP(pstImmZc, (VOS_UINT16)(usPppId << 8) | (VOS_UINT16)PPP_PUSH_RAW_DATA_TYPE);

        if ( PS_SUCC != PPP_EnqueueData(pstImmZc, PPP_PUSH_RAW_DATA_TYPE, usPppId) )
        {
            g_PppDataQCtrl.stStat.ulDownlinkDropCnt++;
            PPP_MNTN_LOG( PS_PID_APP_PPP, 0, PS_PRINT_WARNING,
                          "PPP_PushRawDataEvent, WARNING, Enqueue Data Fail!\r\n" );
            return PS_FAIL;
        }
    }

    return PS_SUCC;
}


VOS_INT PPP_PushPacketEvent(VOS_UINT8 ucRabId, IMM_ZC_STRU *pstImmZc, ADS_PKT_TYPE_ENUM_UINT8 enPktType, VOS_UINT32 ulExParam)
{
    PPP_ID                              usPppId = PPP_INVLAID_PPP_ID;

    g_PppDataQCtrl.stStat.ulDownlinkCnt++;

    if ( !PPP_RAB_TO_PPPID(&usPppId, ucRabId) )
    {
        g_PppDataQCtrl.stStat.ulDownlinkDropCnt++;
        PPP_MemFree(pstImmZc);
        PPP_MNTN_LOG1(PS_PID_APP_PPP, 0, PS_PRINT_NORMAL,
                      "PPP, PPP_PushPacketEvent, NORMAL, Can not get PPP Id, RabId <1>", ucRabId);

        return PS_FAIL;
    }

    return PPP_DlPacketProc(usPppId, pstImmZc);
}


VOS_INT PPP_PushRawDataEvent(VOS_UINT8 ucRabId, IMM_ZC_STRU *pstImmZc, ADS_PKT_TYPE_ENUM_UINT8 enPktType, VOS_UINT32 ulExParam)
{
    PPP_ID                              usPppId = PPP_INVLAID_PPP_ID;

    g_PppDataQCtrl.stStat.ulDownlinkCnt++;

    /* ????RabId????????PPP ID???????????? */
    if ( !PPP_RAB_TO_PPPID(&usPppId, ucRabId) )
    {
        PPP_MemFree(pstImmZc);
        PPP_MNTN_LOG1(PS_PID_APP_PPP, 0, PS_PRINT_WARNING,
                      "PPP, PPP_PushRawDataEvent, WARNING, Can not get PPP Id, RabId <1>", ucRabId);

        return PS_FAIL;
    }

    return PPP_DlRawDataProc(usPppId, pstImmZc);
}


PS_BOOL_ENUM_UINT8 PPP_IsContinueProcData
(
    PPP_HDLC_RESULT_TYPE_ENUM_UINT32    enResultType
)
{
    if (0 < PPP_ZC_GET_QUEUE_LEN(&g_PppDataQCtrl.stDataQ))
    {
        return PS_TRUE;
    }

    return PS_FALSE;
}


VOS_VOID  PPP_ProcDataNotify(VOS_VOID)
{
    PPP_ZC_STRU                        *pstMem;
    PPP_ID                              usPppId;
    PPP_HDLC_CONFIG_STRU               *pstHdlcConfig;
    PPP_HDLC_RESULT_TYPE_ENUM_UINT32    ulResult;
    VOS_ULONG                           ulFlags = 0UL;

    g_PppDataQCtrl.stStat.ulProcMsgCnt++;

    pstMem      = (PPP_ZC_STRU *)PPP_ZC_PEEK_QUEUE_HEAD(&g_PppDataQCtrl.stDataQ);

    /* ???????????????????????? */
    if ( VOS_NULL_PTR == pstMem )
    {
        PPP_MNTN_LOG2(PS_PID_APP_PPP, 0, LOG_LEVEL_WARNING,
                      "PPP_ProcDataNotify, WARNING, queue is null!",
                      g_PppDataQCtrl.ulNotifyMsg, PPP_ZC_GET_QUEUE_LEN(&g_PppDataQCtrl.stDataQ));

        VOS_SpinLockIntLock(&g_stPppASpinLock, ulFlags);    /*lint !e571*/
        g_PppDataQCtrl.ulNotifyMsg = VOS_NO;
        VOS_SpinUnlockIntUnlock(&g_stPppASpinLock , ulFlags);

        return;
    }

    /* ??????????(??????????????????????????????????????????????????????) */
    usPppId         = (PPP_ZC_GET_DATA_APP(pstMem) & 0xFF00) >> 8;
    pstHdlcConfig   = PPP_CONFIG(usPppId);

    if (VOS_NULL_PTR == pstHdlcConfig->pFunProcData)
    {
        PPP_ClearDataQ();

        PPP_MNTN_LOG1(PS_PID_APP_PPP, 0, LOG_LEVEL_ERROR,
                      "PPP_ProcDataNotify, ERROR, pstHdlcConfig->pFunProcData is NULL!", g_PppDataQCtrl.ulNotifyMsg);

        VOS_SpinLockIntLock(&g_stPppASpinLock, ulFlags);    /*lint !e571*/
        g_PppDataQCtrl.ulNotifyMsg = VOS_NO;
        VOS_SpinUnlockIntUnlock(&g_stPppASpinLock , ulFlags);

        return;
    }

    ulResult = pstHdlcConfig->pFunProcData(usPppId, PPP_LINK(usPppId), &g_PppDataQCtrl.stDataQ);

    VOS_SpinLockIntLock(&g_stPppASpinLock, ulFlags);    /*lint !e571*/

    if (PS_TRUE == PPP_IsContinueProcData(ulResult))
    {
        g_PppDataQCtrl.ulNotifyMsg = VOS_YES;
        g_PppDataQCtrl.stStat.ulSndMsgCnt++;

        VOS_SpinUnlockIntUnlock(&g_stPppASpinLock , ulFlags);

        PPP_Snd1stDataNotify();

        return;
    }

    g_PppDataQCtrl.ulNotifyMsg = VOS_NO;

    VOS_SpinUnlockIntUnlock(&g_stPppASpinLock , ulFlags);

    return;
} /* PPP_ProcDataNotify */


VOS_VOID PPP_ProcAsFrmDataInd(struct MsgCB * pMsg)
{
    HDLC_PROC_AS_FRM_PACKET_IND_MSG_STRU    *pstHdlcEnable;
    PPP_HDLC_CONFIG_STRU                    *pstHdlcConfig;
    VOS_UINT16                               usPppId;
    VOS_UINT16                               usProtocol;
    PPP_ZC_STRU                             *pstMem;


    pstHdlcEnable = (HDLC_PROC_AS_FRM_PACKET_IND_MSG_STRU*)pMsg;

    usPppId       = pstHdlcEnable->usPppId;
    usProtocol    = pstHdlcEnable->usProtocol;
    pstMem        = pstHdlcEnable->pstMem;

    pstHdlcConfig = PPP_CONFIG(usPppId);

    if (VOS_NULL_PTR == pstHdlcConfig->pFunProcAsFrmData)
    {
        PPP_MemFree(pstMem);
        PPP_MNTN_LOG(PS_PID_APP_PPP, 0, LOG_LEVEL_ERROR,
                      "PPP_ProcHdlcEnable, ERROR, pstHdlcConfig->pFunProcAsFrmData is NULL!");
        return;
    }

    pstHdlcConfig->pFunProcAsFrmData(usPppId, usProtocol, pstMem);

    return;
}

/*****************************************************************************
 Prototype      : PPP_ProcHdlcDisable
 Description    : ????HDLC??????????

 Input          : ---PPP??????????PPP ID
 Output         : ---
 Return Value   : ---VOS_UINT32
 Calls          : ---
 Called By      : ---

 History        : ---
  1.Date        : 2005-11-18
    Author      : ---
    Modification: Created function
*****************************************************************************/
VOS_VOID PPP_ProcHdlcDisable ( PPP_ID usPppId)
{
    PPP_HDLC_CONFIG_STRU               *pstHdlcConfig;

    if ((usPppId == 0) || (PPP_MAX_ID_NUM < usPppId))
    {
        PPP_MNTN_LOG1(PS_PID_APP_PPP, 0, LOG_LEVEL_WARNING,
                      "PPP_ProcHdlcDisable, WARNING, usPppID %d is invalid!", usPppId);
        return;
    }

    pstHdlcConfig = PPP_CONFIG(usPppId);

    if (VOS_NULL_PTR != pstHdlcConfig->pFunDisable)
    {
        PPP_MNTN_LOG(PS_PID_APP_PPP, 0, LOG_LEVEL_INFO,
                      "PPP_ProcHdlcDisable, INFO, Invoke HDLC disable function!");

        pstHdlcConfig->pFunDisable();
    }

    return;
}


VOS_UINT32 PPP_ProcAtCtrlOper(struct MsgCB * pMsg)
{
    PPP_AT_CTRL_OPERATION_MSG *pCtrlOperMsg;

    pCtrlOperMsg = (PPP_AT_CTRL_OPERATION_MSG *)pMsg;

    switch(pCtrlOperMsg->ulCtrlOpType)
    {
        case PPP_AT_CTRL_REL_PPP_REQ:
            Ppp_ReleasePppReq(pCtrlOperMsg->usPppId);
            break;
        case PPP_AT_CTRL_REL_PPP_RAW_REQ:
            Ppp_ReleaseRawDataPppReq(pCtrlOperMsg->usPppId);
            break;
        case PPP_AT_CTRL_HDLC_DISABLE:
            PPP_ProcHdlcDisable(pCtrlOperMsg->usPppId);
            break;
        case PPP_AT_CTRL_CONFIG_INFO_IND:
            Ppp_ProcConfigInfoInd(pCtrlOperMsg->usPppId);
            break;

        default:
            PPP_MNTN_LOG1(PS_PID_APP_PPP, 0, LOG_LEVEL_WARNING,
                          "PPP, PPP_ProcAtCtrlOper, ulCtrlOpType %d is ERROR!",
                          (VOS_INT32)(pCtrlOperMsg->ulCtrlOpType));
            return PS_FAIL;
    }

    return PS_SUCC;
}


/*****************************************************************************
    PPP????????????????????????
    -PPP_Frame_MNTN_Info_STRU    struct
    -PPP_Proto                   2 byte NetWork Order
    -PPP_Frame                   (without PPP Proto)
*****************************************************************************/
VOS_VOID Ppp_MBufFrameMntnInfo
(
    struct ppp_mbuf *bp,
    VOS_UINT16       usProto,
    VOS_UINT32       ulDir
)
{
    VOS_UINT16                ulFrameLen        = 0;
    PPP_FRAME_MNTN_INFO_STRU *ptrPppFrameMntnSt = VOS_NULL;
    VOS_UINT8                *pucBuff           = VOS_NULL;
    VOS_INT32                 ulRet             = VOS_ERR;


    /* PPP ??????*/
    ulFrameLen = (VOS_UINT16)ppp_m_length(bp);

    ptrPppFrameMntnSt = (PPP_FRAME_MNTN_INFO_STRU *)PS_MEM_ALLOC(PS_PID_APP_PPP,
                        ulFrameLen + sizeof(PPP_FRAME_MNTN_INFO_STRU) + sizeof(usProto));
    if (VOS_NULL_PTR == ptrPppFrameMntnSt)
    {
        PPP_MNTN_LOG(PS_PID_APP_PPP, PS_SUBMOD_NULL, PS_PRINT_ERROR,
            "PPP, Ppp_MBufFrameMntnInfo, ERROR, Call VOS_MemAlloc fail!\n");
        return;
    }

    /* ????PPP??????????,??????????????*/
    pucBuff = (VOS_UINT8 *)(ptrPppFrameMntnSt + 1);
    PPP_PUTSHORT(VOS_HTONS(usProto), pucBuff);

    /* ??????????,????????????*/
    ulRet = ppp_mbuf_View(bp, pucBuff, ulFrameLen);
    if (ulFrameLen != ulRet)
    {
        PPP_MNTN_LOG(PS_PID_APP_PPP, PS_SUBMOD_NULL, PS_PRINT_ERROR,
            "PPP, Ppp_MBufFrameMntnInfo, ERROR, ppp_mbuf_View Fail!\n");
        PS_MEM_FREE(PS_PID_APP_PPP, ptrPppFrameMntnSt);
        return ;
    }

    /****************************************************************
       ????????????????
       ????: ????????????????????????????????
             ???????? + 2byte protocol????
    *****************************************************************/
    Ppp_FrameMntnInfo(ptrPppFrameMntnSt, ulDir, ulFrameLen + sizeof(usProto));

    /* ????????*/
    PS_MEM_FREE(PS_PID_APP_PPP, ptrPppFrameMntnSt);
    return;
}


VOS_VOID Ppp_TtfMemFrameMntnInfo
(
    PPP_ZC_STRU *pstMem,
    VOS_UINT16  usProto,
    VOS_UINT32  ulDir
)
{
    VOS_UINT16                ulFrameLen        = 0;
    PPP_FRAME_MNTN_INFO_STRU *ptrPppFrameMntnSt = VOS_NULL;
    VOS_UINT8                *pucBuff           = VOS_NULL;
    VOS_UINT32                ulRet             = PS_FAIL;

    /* PPP ??????*/
    ulFrameLen = (VOS_UINT16)PPP_ZC_GET_DATA_LEN(pstMem);

    ptrPppFrameMntnSt = (PPP_FRAME_MNTN_INFO_STRU *)PS_MEM_ALLOC(PS_PID_APP_PPP,
                        ulFrameLen + sizeof(PPP_FRAME_MNTN_INFO_STRU) + sizeof(usProto));
    if (VOS_NULL_PTR == ptrPppFrameMntnSt)
    {
        PPP_MNTN_LOG(PS_PID_APP_PPP, PS_SUBMOD_NULL, PS_PRINT_ERROR,
            "PPP, Ppp_TtfMemFrameMntnInfo, ERROR, Call VOS_MemAlloc fail!\n");
        return;
    }

    /* ????PPP??????????,??????????*/
    pucBuff = (VOS_UINT8 *)(ptrPppFrameMntnSt + 1);
    PPP_PUTSHORT(VOS_HTONS(usProto), pucBuff);

    /* ??????????,????????????*/
    ulRet = PPP_MemGet(pstMem, 0, pucBuff, ulFrameLen);
    if (PS_SUCC != ulRet)
    {
        PPP_MNTN_LOG(PS_PID_APP_PPP, PS_SUBMOD_NULL, PS_PRINT_ERROR,
                     "PPP, Ppp_frame_MntnInfo, ERROR, TTF_MemGet Fail!\n");
        PS_MEM_FREE(PS_PID_APP_PPP, ptrPppFrameMntnSt);

        return ;
    }

    /****************************************************************
       ????????????????
       ????: ????????????????????????????????
             ???????? + 2byte protocol????
    *****************************************************************/
    Ppp_FrameMntnInfo(ptrPppFrameMntnSt, ulDir, ulFrameLen + sizeof(usProto));

    /* ????????*/
    PS_MEM_FREE(PS_PID_APP_PPP, ptrPppFrameMntnSt);

    return;
}

/*lint -e{429}*/

VOS_VOID Ppp_FrameMntnInfo
(
    PPP_FRAME_MNTN_INFO_STRU *ptrPppMntnSt,
    VOS_UINT32                ulDir,
    VOS_UINT16                ulDataLen
)
{
    ptrPppMntnSt->ulReceiverCpuId = VOS_LOCAL_CPUID;
    ptrPppMntnSt->ulReceiverPid   = PS_PID_APP_PPP;
    ptrPppMntnSt->ulSenderCpuId   = VOS_LOCAL_CPUID;
    ptrPppMntnSt->ulSenderPid     = PS_PID_APP_PPP;
    ptrPppMntnSt->ulLength        = (ulDataLen + sizeof(PPP_FRAME_MNTN_INFO_STRU))
                                        - VOS_MSG_HEAD_LENGTH;
    /* PPP ??????*/
    if (PPP_RECV_IN_PROTOCOL_FRAME == ulDir)
    {
        ptrPppMntnSt->ulMsgname = PPP_RECV_PROTO_PACKET_TYPE;
    }
    if (PPP_SEND_OUT_PROTOCOL_FRAME == ulDir)
    {
        ptrPppMntnSt->ulMsgname = PPP_SEND_PROTO_PACKET_TYPE;
    }

    ptrPppMntnSt->ulPppPhase  = pgPppLink->phase;
    ptrPppMntnSt->ulIpcpState = pgPppLink->ipcp.fsm.state;
    ptrPppMntnSt->ulLcpState  = pgPppLink->lcp.fsm.state;
    ptrPppMntnSt->usPppId     = (VOS_UINT16)(PPP_LINK_TO_ID(pgPppLink));
    ptrPppMntnSt->ulDataLen  = ulDataLen;

    PPP_MNTN_TRACE_MSG(ptrPppMntnSt);

    return;
}


VOS_VOID Ppp_FillEventMntnInfo
(
    PPP_EVENT_MNTN_INFO_STRU  *ptrPppEveMntnSt,
    VOS_UINT16                 usPppID,
    VOS_UINT32                 ulEvent,
    VOS_UINT32                 ulEventLen
)
{
    ptrPppEveMntnSt->ulReceiverCpuId = VOS_LOCAL_CPUID;
    ptrPppEveMntnSt->ulReceiverPid   = PS_PID_APP_PPP;
    ptrPppEveMntnSt->ulSenderCpuId   = VOS_LOCAL_CPUID;
    ptrPppEveMntnSt->ulSenderPid     = PS_PID_APP_PPP;
    ptrPppEveMntnSt->ulLength        = ulEventLen - VOS_MSG_HEAD_LENGTH;

    ptrPppEveMntnSt->ulMsgname      = ulEvent;
    ptrPppEveMntnSt->usPppId        = usPppID;
    ptrPppEveMntnSt->usReserved     = 0;
    ptrPppEveMntnSt->ulPppPhase     = pgPppLink->phase;
    ptrPppEveMntnSt->ulIpcpState    = pgPppLink->ipcp.fsm.state;
    ptrPppEveMntnSt->ulLcpState     = pgPppLink->lcp.fsm.state;
}


VOS_VOID Ppp_EventMntnInfo
(
    VOS_UINT16                usPppID,
    VOS_UINT32                ulEvent
)
{
    PPP_EVENT_MNTN_INFO_STRU    stPppEveMntnSt;

    /*????????????????*/
    Ppp_FillEventMntnInfo(&stPppEveMntnSt, usPppID, ulEvent, sizeof(PPP_EVENT_MNTN_INFO_STRU));

    PPP_MNTN_TRACE_MSG(&stPppEveMntnSt);

    return;
}


/*****************************************************************************
 PPP_ind_config_info????????????????????????????????????
 ????????LEN??2BYTE????
-PPP_Event_MNTN_Info_STRU   struct
-LEN   IP_ADDR_LEN             2 byte
-IP_ADDR                      16 byte(PPP_MAX_IPV4_ADDR_LEN + 1)
-LEN   AUTH_LEN                2 byte
-VALUE ...                  0..x byte
-LEN   IPCP_LEN                2 byte
-VALUE ...                  0..x byte
*****************************************************************************/
/*lint -e{516}*/
VOS_VOID Ppp_RcvConfigInfoIndMntnInfo
(
    VOS_UINT16  usPppID,
    AT_PPP_IND_CONFIG_INFO_STRU *ptrIndConfigInfo
)
{
    VOS_UINT16                          ulDataLen;
    PPP_EVENT_MNTN_INFO_STRU           *ptrPppFrameMntnSt = VOS_NULL;
    VOS_UINT8                          *pucBuff;

    /*************************************************************
    CONFIG info ????????????
    ?????? = aucIpAddr + aucPriDns + aucSecDns + aucGateWay + aucPriNbns + aucSecNbns + 6??????????
    **************************************************************/
    ulDataLen = (IPV4_ADDR_LEN * 6) + (sizeof(VOS_UINT16) * 6) + sizeof(PPP_EVENT_MNTN_INFO_STRU);

    /* ????????,????????+????????????????????*/
    ptrPppFrameMntnSt = (PPP_EVENT_MNTN_INFO_STRU *)PS_MEM_ALLOC(PS_PID_APP_PPP, ulDataLen);

    if (VOS_NULL_PTR == ptrPppFrameMntnSt)
    {
        PPP_MNTN_LOG(PS_PID_APP_PPP, PS_SUBMOD_NULL, PS_PRINT_ERROR,
                     "PPP, Ppp_RcvConfigInfoIndMntnInfo, ERROR, Call VOS_MemAlloc fail!\n");
        return;
    }

    /* ????sizeof(PPP_EVENT_MNTN_INFO_STRU) */
    pucBuff = (VOS_UINT8 *)(ptrPppFrameMntnSt + 1);

    /*lint -e661 -e662 -e669*/
    PPP_PUTSHORT(IPV4_ADDR_LEN, pucBuff);
    PSACORE_MEM_CPY(pucBuff, IPV4_ADDR_LEN, ptrIndConfigInfo->aucIpAddr, IPV4_ADDR_LEN);
    PPP_INCPTR(IPV4_ADDR_LEN, pucBuff);

    /* ???? aucPriDns ??????????*/
    PPP_PUTSHORT(IPV4_ADDR_LEN, pucBuff);
    PSACORE_MEM_CPY(pucBuff, IPV4_ADDR_LEN, ptrIndConfigInfo->stPcoIpv4Item.aucPriDns, IPV4_ADDR_LEN);
    PPP_INCPTR(IPV4_ADDR_LEN, pucBuff);

    /* ???? aucSecDns ??????????*/
    PPP_PUTSHORT(IPV4_ADDR_LEN, pucBuff);
    PSACORE_MEM_CPY(pucBuff, IPV4_ADDR_LEN, ptrIndConfigInfo->stPcoIpv4Item.aucSecDns, IPV4_ADDR_LEN);
    PPP_INCPTR(IPV4_ADDR_LEN, pucBuff);

    /* ???? aucGateWay ??????????*/
    PPP_PUTSHORT(IPV4_ADDR_LEN, pucBuff);
    PSACORE_MEM_CPY(pucBuff, IPV4_ADDR_LEN, ptrIndConfigInfo->stPcoIpv4Item.aucGateWay, IPV4_ADDR_LEN);
    PPP_INCPTR(IPV4_ADDR_LEN, pucBuff);

    /* ???? aucPriNbns ??????????*/
    PPP_PUTSHORT(IPV4_ADDR_LEN, pucBuff);
    PSACORE_MEM_CPY(pucBuff, IPV4_ADDR_LEN, ptrIndConfigInfo->stPcoIpv4Item.aucPriNbns, IPV4_ADDR_LEN);
    PPP_INCPTR(IPV4_ADDR_LEN, pucBuff);

    /* ???? aucSecNbns ??????????*/
    PPP_PUTSHORT(IPV4_ADDR_LEN, pucBuff);
    PSACORE_MEM_CPY(pucBuff, IPV4_ADDR_LEN, ptrIndConfigInfo->stPcoIpv4Item.aucSecNbns, IPV4_ADDR_LEN);
    PPP_INCPTR(IPV4_ADDR_LEN, pucBuff);
    /*lint +e661 +e662 +e669*/

    /* ????????????????*/
    Ppp_FillEventMntnInfo(ptrPppFrameMntnSt, usPppID, AT_PPP_RECV_CONFIG_INFO_IND, ulDataLen);

    PPP_MNTN_TRACE_MSG(ptrPppFrameMntnSt);

    PS_MEM_FREE(PS_PID_APP_PPP, ptrPppFrameMntnSt);

    return;
}


/*****************************************************************************
 PPP_ind_config_info????????????????????????????????????

-PPP_Event_MNTN_Info_STRU   struct
-AUTH_TYPE                     1 byte
-Empty Aligned                 1 byte (1 byte??????????LEN??2byte????)
   (AUTH_TYPE == PAP)
     -LEN      PAP             2 byte
     -VALUE    ...          0..x byte
   (AUTH_TYPE == CHAP)
     -LEN      CHALLENGE       2 byte
     -VALUE    ...          0..x byte
     -LEN      RESPOSNE        2 byte
     -VALUE    ...          0..x byte
   (AUTH_TYPE == OTHER)
     -NULL
-IPCP LEN                      2 byte
-IPCP VAULE ...             0..x byte
*****************************************************************************/
/*lint -e{516}*/
VOS_VOID Ppp_RcvConfigInfoReqMntnInfo(VOS_UINT16  usPppID, PPP_REQ_CONFIG_INFO_STRU *ptrReqConfigInfo)
{
    VOS_UINT16 ulDataLen                       = 0;
    PPP_EVENT_MNTN_INFO_STRU *ptrPppFrameMntnSt = VOS_NULL;
    VOS_UINT8  *pucBuff                         = VOS_NULL;

    VOS_UINT16 usChapChallengeLen               = 0;
    VOS_UINT16 usChapChallengeLenAligned        = 0;

    VOS_UINT16 usChapResponseLen                = 0;
    VOS_UINT16 usChapResponseLenAligned         = 0;

    VOS_UINT16 usPapLen                         = 0;
    VOS_UINT16 usPapLenAligned                  = 0;

    VOS_UINT16 usIpcpLen                        = 0;
    VOS_UINT16 usIpcpLenAligned                 = 0;

    /* ???????????????????? + 1byte ???????? + 1byte ????*/
    ulDataLen += (sizeof(VOS_UINT8)*2);

    /* ????????*/
    if (PPP_PAP_AUTH_TYPE == ptrReqConfigInfo->stAuth.ucAuthType)
    {
        if ((0 != ptrReqConfigInfo->stAuth.AuthContent.PapContent.usPapReqLen)
            && (VOS_NULL == ptrReqConfigInfo->stAuth.AuthContent.PapContent.pPapReq))
        {
            PPP_MNTN_LOG(PS_PID_APP_PPP, PS_SUBMOD_NULL, PS_PRINT_ERROR,
                "PPP, Ppp_RcvConfigInfoReqMntnInfo, ERROR, Param PAP Error!\n");
            return;
        }
        usPapLen = ptrReqConfigInfo->stAuth.AuthContent.PapContent.usPapReqLen;
        PPP_LENALIGNTO2BYTE(usPapLenAligned, usPapLen);

        /* ???????????????????? + 2byte PAP???????? + PAP????*/
        ulDataLen += (usPapLenAligned + sizeof(VOS_UINT16));
    }
    if (PPP_CHAP_AUTH_TYPE == ptrReqConfigInfo->stAuth.ucAuthType)
    {
        if ((0 != ptrReqConfigInfo->stAuth.AuthContent.ChapContent.usChapChallengeLen)
            && (VOS_NULL == ptrReqConfigInfo->stAuth.AuthContent.ChapContent.pChapChallenge))
        {
            PPP_MNTN_LOG(PS_PID_APP_PPP, PS_SUBMOD_NULL, PS_PRINT_ERROR,
                "PPP, Ppp_RcvConfigInfoReqMntnInfo, ERROR, Param CHAP Challenge Error!\n");
            return;
        }
        if ((0 != ptrReqConfigInfo->stAuth.AuthContent.ChapContent.usChapResponseLen)
            && (VOS_NULL == ptrReqConfigInfo->stAuth.AuthContent.ChapContent.pChapResponse))
        {
            PPP_MNTN_LOG(PS_PID_APP_PPP, PS_SUBMOD_NULL, PS_PRINT_ERROR,
                "PPP, Ppp_RcvConfigInfoReqMntnInfo, ERROR, Param CHAP Response Error!\n");
            return;
        }
        usChapChallengeLen = ptrReqConfigInfo->stAuth.AuthContent.ChapContent.usChapChallengeLen;
        PPP_LENALIGNTO2BYTE(usChapChallengeLenAligned, usChapChallengeLen);

        usChapResponseLen  = ptrReqConfigInfo->stAuth.AuthContent.ChapContent.usChapResponseLen;
        PPP_LENALIGNTO2BYTE(usChapResponseLenAligned, usChapResponseLen);

        /* ???????????????????? + 2byte challenge???????? + challenge???? + 2byte response ???????? + response????*/
        ulDataLen += (usChapChallengeLenAligned + usChapResponseLenAligned + (sizeof(VOS_UINT16)*2));
    }

    if ((0 != ptrReqConfigInfo->stIPCP.usIpcpLen) && (VOS_NULL == ptrReqConfigInfo->stIPCP.pIpcp))
    {
        PPP_MNTN_LOG(PS_PID_APP_PPP, PS_SUBMOD_NULL, PS_PRINT_ERROR,
            "PPP, Ppp_RcvConfigInfoReqMntnInfo, ERROR, Param IPCP Error!\n");
        return;
    }
    usIpcpLen = ptrReqConfigInfo->stIPCP.usIpcpLen;
    PPP_LENALIGNTO2BYTE(usIpcpLenAligned, usIpcpLen);

    /* ???????????????????? + 2byte IPCP???????? + IPCP????*/
    ulDataLen += (usIpcpLenAligned + sizeof(VOS_UINT16));

    ptrPppFrameMntnSt = (PPP_EVENT_MNTN_INFO_STRU *)PS_MEM_ALLOC(PS_PID_APP_PPP,
                        ulDataLen + sizeof(PPP_EVENT_MNTN_INFO_STRU));
    if (VOS_NULL_PTR == ptrPppFrameMntnSt)
    {
        PPP_MNTN_LOG(PS_PID_APP_PPP, PS_SUBMOD_NULL, PS_PRINT_ERROR,
            "PPP, Ppp_RcvConfigInfoReqMntnInfo, ERROR, Call VOS_MemAlloc fail!\n");
        return;
    }

    /* ???? ???????? + padding*/
    pucBuff = (VOS_UINT8 *)(ptrPppFrameMntnSt + 1);
    PPP_PUTCHAR(ptrReqConfigInfo->stAuth.ucAuthType, pucBuff);
    PPP_PUTCHAR(0, pucBuff);

    /* ???? pap ???? pap????*/
    if(PPP_PAP_AUTH_TYPE == ptrReqConfigInfo->stAuth.ucAuthType)
    {
        PPP_PUTSHORT(usPapLenAligned, pucBuff);
        if (0 != usPapLenAligned)
        {
            /*lint -e613 */
            PSACORE_MEM_CPY(pucBuff, usPapLen, ptrReqConfigInfo->stAuth.AuthContent.PapContent.pPapReq, usPapLen);
            /*lint +e613 */
            PPP_INCPTR(usPapLenAligned, pucBuff);
        }
    }
    /* ???? chap ???? chap????*/
    if(PPP_CHAP_AUTH_TYPE == ptrReqConfigInfo->stAuth.ucAuthType)
    {
        PPP_PUTSHORT(usChapChallengeLenAligned, pucBuff);
        if (0 != usChapChallengeLenAligned)
        {
            /*lint -e613 */
            PSACORE_MEM_CPY(pucBuff, usChapChallengeLen, ptrReqConfigInfo->stAuth.AuthContent.ChapContent.pChapChallenge, usChapChallengeLen);
            /*lint +e613 */
            PPP_INCPTR(usChapChallengeLenAligned, pucBuff);
        }

        PPP_PUTSHORT(usChapResponseLenAligned, pucBuff);
        if (0 != usChapResponseLenAligned)
        {
            /*lint -e613 */
            PSACORE_MEM_CPY(pucBuff, usChapResponseLen, ptrReqConfigInfo->stAuth.AuthContent.ChapContent.pChapResponse, usChapResponseLen);
            /*lint +e613 */
            PPP_INCPTR(usChapResponseLenAligned, pucBuff);
        }
    }

    /*????IPCP????,????*/
    PPP_PUTSHORT(usIpcpLenAligned, pucBuff);
    if (0 != usIpcpLenAligned)
    {
       PSACORE_MEM_CPY(pucBuff, usIpcpLen, ptrReqConfigInfo->stIPCP.pIpcp, usIpcpLen);
       PPP_INCPTR(usIpcpLenAligned, pucBuff);
    }

    /*????????????????*/
    Ppp_FillEventMntnInfo(ptrPppFrameMntnSt, usPppID, PPP_AT_RECV_CONFIG_INFO_REQ,
                                (ulDataLen + sizeof(PPP_EVENT_MNTN_INFO_STRU)));

    PPP_MNTN_TRACE_MSG(ptrPppFrameMntnSt);

    PS_MEM_FREE(PS_PID_APP_PPP, ptrPppFrameMntnSt);

    return;
}



