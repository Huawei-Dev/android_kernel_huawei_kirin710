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



/******************************************************************************
   2 ????????????????
******************************************************************************/
#include "product_config.h"
/******************************************************************************
   1 ??????????
******************************************************************************/
#include "PPP/Inc/ppp_public.h"
#include "PPP/Inc/pppid.h"
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
#include "PPP/Inc/link.h"
#include "PPP/Inc/pap.h"
#include "PPP/Inc/ppp_init.h"
#include "PPP/Inc/ppp_input.h"
#include "PPP/Inc/ppp_atcmd.h"
#include "NVIM_Interface.h"
#include "acore_nv_id_gucttf.h"
#include "acore_nv_stru_gucttf.h"
#include "nv_stru_gucnas.h"
#include "acore_nv_stru_gucnas.h"



/*****************************************************************************
    ??????????????????????.C??????????
*****************************************************************************/
/*lint -e767  ????????: ??????????????ID???? */
#define    THIS_FILE_ID        PS_FILE_ID_PPP_INIT_C
/*lint +e767  */


/******************************************************************************
   PPP??????????????modem_send??????modem_recv??????
******************************************************************************/
#define PPP_TASK_PRI                                  143

extern VOS_VOID PPP_ProcDataNotify(VOS_VOID);
extern VOS_UINT32  PPP_Snd1stDataNotify(VOS_VOID);
extern VOS_VOID PPP_ProcAsFrmDataInd(struct MsgCB * pMsg);



/******************************************************************************
   3 ????????
******************************************************************************/


/******************************************************************************
   4 ????????????
******************************************************************************/
/* ??????NV??????????WINS??????????*/
VOS_UINT8  g_ucPppConfigWins = WINS_CONFIG_ENABLE;

PPP_ENTITY_INFO_STRU                g_stPppEntInfo;

/* ?????????? */
extern      VOS_SPINLOCK            g_stPppASpinLock;

/******************************************************************************
   5 ????????
******************************************************************************/

VOS_VOID PPP_UpdateWinsConfig(VOS_UINT8 ucWins)
{
    if ((WINS_CONFIG_DISABLE != ucWins) && (WINS_CONFIG_ENABLE != ucWins))
    {
        /* ucWins?????? */
        return;
    }

    /* ????g_ucPppConfigWins */
    g_ucPppConfigWins = ucWins;

    return;
}


VOS_VOID PPP_DataQInit(VOS_VOID)
{
    PPP_ZC_QUEUE_STRU                    *pstDataQ;


    pstDataQ    = &(g_PppDataQCtrl.stDataQ);

    PSACORE_MEM_SET(&g_PppDataQCtrl, sizeof(g_PppDataQCtrl), 0, sizeof(g_PppDataQCtrl));

    PPP_ZC_QUEUE_INIT(pstDataQ);

    return;
}



VOS_VOID PPP_ClearDataQ(VOS_VOID)
{
    PPP_ZC_STRU    *pstMem;

    for(;;)
    {
        if ( 0 == PPP_ZC_GET_QUEUE_LEN(&g_PppDataQCtrl.stDataQ) )
        {
            break;
        }

        pstMem  = (PPP_ZC_STRU *)PPP_ZC_DEQUEUE_HEAD(&g_PppDataQCtrl.stDataQ);

        PPP_MemFree(pstMem);
    }

    PPP_MNTN_LOG(PS_PID_APP_PPP, 0, PS_PRINT_NORMAL,
                                  "PPP, PPP_ClearDataQ, NORMAL, Clear Stat Info\n");

    return;
} /* PPP_ClearDataQ */



VOS_UINT16 PPP_GetMruConfig(VOS_VOID)
{
    VOS_UINT16                      usPppConfigMru  = DEF_MRU;
    VOS_UINT32                      ulRslt;
    PPP_CONFIG_MRU_TYPE_NV_STRU     stPppConfigMruType;


    PSACORE_MEM_SET(&stPppConfigMruType, sizeof(PPP_CONFIG_MRU_TYPE_NV_STRU), 0x00, sizeof(PPP_CONFIG_MRU_TYPE_NV_STRU));

    /* ??????????PPP Default MRU??????NV_Item????????NV??????16bit??????????????????????
       ??????????sizeof(VOS_UINT16) */
    ulRslt = GUCTTF_NV_Read(MODEM_ID_0, en_NV_Item_PPP_CONFIG_MRU_Type, &stPppConfigMruType, sizeof(PPP_CONFIG_MRU_TYPE_NV_STRU));
    usPppConfigMru  = stPppConfigMruType.usPppConfigType;

    if (NV_OK != ulRslt)
    {
        usPppConfigMru = DEF_MRU;
        PPP_MNTN_LOG(PS_PID_APP_PPP, 0, PS_PRINT_WARNING,
                     "Warning: Read en_NV_Item_PPP_DEFAULT_MRU_Type Error!");
    }

    if (usPppConfigMru > MAX_MRU)
    {
        usPppConfigMru = MAX_MRU;
    }

    if (usPppConfigMru < MIN_MRU)
    {
        usPppConfigMru = MIN_MRU;
    }

    PPP_MNTN_LOG1(PS_PID_APP_PPP, 0, PS_PRINT_INFO,
        "[INFO] PPP -- NV config MRU : <1>", (VOS_INT32)usPppConfigMru);

    return usPppConfigMru;
}


VOS_UINT8 PPP_GetWinsConfig(VOS_VOID)
{
    WINS_CONFIG_STRU    stWins;

    /* ?????? */
    PSACORE_MEM_SET(&stWins, sizeof(stWins), 0x0, sizeof(stWins));

    /* ????????,????WINS????????????NV?? */

    /* ??????en_NV_Item_WINS????,??????WINS?????????? */
    if(NV_OK != GUCTTF_NV_Read(MODEM_ID_0, en_NV_Item_WINS_Config, &stWins, sizeof(WINS_CONFIG_STRU)))
    {
        PPP_MNTN_LOG(PS_PID_APP_PPP, 0, PS_PRINT_WARNING, "Warning: Read en_NV_Item_WINS_Config Error!");
        return WINS_CONFIG_ENABLE;
    }

    /* ??en_NV_Item_WINS??????????????WINS?????????? */
    if (0 == stWins.ucStatus)
    {
        return WINS_CONFIG_ENABLE;
    }

    /* ??en_NV_Item_WINS??????????????????WINS?????????? */
    if ((WINS_CONFIG_ENABLE != stWins.ucWins) && (WINS_CONFIG_DISABLE != stWins.ucWins))
    {
        return WINS_CONFIG_ENABLE;
    }

    PPP_MNTN_LOG1(PS_PID_APP_PPP, 0, PS_PRINT_INFO,
                  "PPP_GetWinsConfig,[INFO] PPP -- NV config WINS : %d", (VOS_INT32)stWins.ucWins);

    return stWins.ucWins;
}

/*****************************************************************************
 Prototype      : PPP_StatusPrint()
 Description    :
 Input          : VOS_VOID
 Output         :
 Return Value   : VOID
 Calls          :
 Called By      :
 History        :
  1.Date        : 2007-08-28
    Author      :
    Modification:
*****************************************************************************/
VOS_VOID PPP_StatusPrint(VOS_VOID)
{
    VOS_UINT32  ulIndex;
    struct lcp *lcp;

    PS_PRINTF(" lcp Info \n");
    for(ulIndex = 0; ulIndex < PPP_MAX_ID_NUM; ulIndex++)
    {
        lcp = &((pgPppLink + ulIndex)->lcp);

        /* ??????Shell */
        PS_PRINTF(" %d: %s [%s]\n", ulIndex, lcp->fsm.name, State2Nam(lcp->fsm.state));
        PS_PRINTF(" his side: MRU %d, ACCMAP %x, PROTOCOMP %s, ACFCOMP %s,\n"
                    "           MAGIC %x, MRRU %u, SHORTSEQ %s, REJECT %04x\n",
                    lcp->his_mru, (VOS_UINT32)lcp->his_accmap,
                    lcp->his_protocomp ? "on" : "off",
                    lcp->his_acfcomp ? "on" : "off",
                    (VOS_UINT32)lcp->his_magic, lcp->his_mrru,
                    lcp->his_shortseq ? "on" : "off", lcp->his_reject);
        PS_PRINTF(" my  side: MRU %d, ACCMAP %x, PROTOCOMP %s, ACFCOMP %s,\n"
                    "           MAGIC %x, MRRU %u, SHORTSEQ %s, REJECT %04x\n",
                    lcp->want_mru, (VOS_UINT32)lcp->want_accmap,
                    lcp->want_protocomp ? "on" : "off",
                    lcp->want_acfcomp ? "on" : "off",
                    (VOS_UINT32)lcp->want_magic, lcp->want_mrru,
                    lcp->want_shortseq ? "on" : "off", lcp->my_reject);

        if (lcp->cfg.mru)
            PS_PRINTF("\n Defaults: MRU = %d (max %d), ",
                      lcp->cfg.mru, lcp->cfg.max_mru);
        else
            PS_PRINTF("\n Defaults: MRU = any (max %d), ",
                      lcp->cfg.max_mru);
        if (lcp->cfg.mtu)
            PS_PRINTF("MTU = %d (max %d), ",
                      lcp->cfg.mtu, lcp->cfg.max_mtu);
        else
            PS_PRINTF("MTU = any (max %d), ", lcp->cfg.max_mtu);
        PS_PRINTF("ACCMAP = %x\n", (VOS_UINT32)lcp->cfg.accmap);
        PS_PRINTF("           LQR period = %us, ",
                    lcp->cfg.lqrperiod);
        PS_PRINTF("Open Mode = %s",
                    lcp->cfg.openmode == OPEN_PASSIVE ? "passive" : "active");
        if (lcp->cfg.openmode > 0)
            PS_PRINTF(" (delay %ds)", lcp->cfg.openmode);
        PS_PRINTF("\n           FSM retry = %us, max %u Config"
                    " REQ%s, %u Term REQ%s\n", lcp->cfg.fsm.timeout,
                    lcp->cfg.fsm.maxreq, lcp->cfg.fsm.maxreq == 1 ? "" : "s",
                    lcp->cfg.fsm.maxtrm, lcp->cfg.fsm.maxtrm == 1 ? "" : "s");
        PS_PRINTF("    Ident: %s\n", lcp->cfg.ident);
        PS_PRINTF("\n Negotiation:\n");
        PS_PRINTF("           ACFCOMP =   %s\n",
                    command_ShowNegval(lcp->cfg.acfcomp));
        PS_PRINTF("           CHAP05 =    %s\n",
                    command_ShowNegval(lcp->cfg.chap05));
        PS_PRINTF("           CHAP80 =    %s\n",
                    command_ShowNegval(lcp->cfg.chap80nt));
        PS_PRINTF("           LANMan =    %s\n",
                    command_ShowNegval(lcp->cfg.chap80lm));
        PS_PRINTF("           CHAP81 =    %s\n",
                    command_ShowNegval(lcp->cfg.chap81));
        PS_PRINTF("           LQR =       %s\n",
                    command_ShowNegval(lcp->cfg.lqr));
        PS_PRINTF("           LCP ECHO =  %s\n",
                      lcp->cfg.echo ? "enabled" : "disabled");
        PS_PRINTF("           PAP =       %s\n",
                    command_ShowNegval(lcp->cfg.pap));
        PS_PRINTF("           PROTOCOMP = %s\n",
                    command_ShowNegval(lcp->cfg.protocomp));
    }

    return;
}

/*****************************************************************************
 Prototype      : PppStop
 Description    : TAF PPP????????????????,??????????????????????????????PPP??
                  ??????????????????
 Input          : ---
 Output         : ---
 Return Value   : ---VOS_UINT32
 Calls          : ---
 Called By      : ---

 History        : ---
  1.Date        : 2005-11-18
    Author      : ---
    Modification: Created function
*****************************************************************************/
#define PPP_FREE(point)\
    if(point!=VOS_NULL_PTR)         \
    {                                   \
        /*????????????????????????*/    \
        VOS_MemFree(PS_PID_APP_PPP, point);   \
        point = VOS_NULL_PTR;  \
    }\

VOS_VOID PppStop(VOS_VOID)
{
    VOS_INT32 i;

    /*????????????????throughout????????????????????????*/
    for(i = 0;i < PPP_MAX_ID_NUM; i++)
    {
        throughput_destroy(&((pgPppLink + i)->stats.total));
    }

    PPP_FREE(pgPppLink)
    PPP_FREE(pgPppId)

    return;
}


VOS_VOID PPP_EntInit(VOS_VOID)
{
    VOS_UINT32                  ulRslt;
    NV_TTF_PPP_CONFIG_STRU      stPppConfig;

    PSACORE_MEM_SET(&g_stPppEntInfo, sizeof(PPP_ENTITY_INFO_STRU), 0x0, sizeof(PPP_ENTITY_INFO_STRU));

    PSACORE_MEM_SET(&stPppConfig, sizeof(NV_TTF_PPP_CONFIG_STRU), 0x0, sizeof(NV_TTF_PPP_CONFIG_STRU));

    ulRslt = GUCTTF_NV_Read(MODEM_ID_0, en_NV_Item_PPP_CONFIG, &stPppConfig, (VOS_UINT32)sizeof(NV_TTF_PPP_CONFIG_STRU));
    if (NV_OK != ulRslt)
    {
        g_stPppEntInfo.enChapEnable                 = TTF_ACORE_TRUE;
        g_stPppEntInfo.enPapEnable                  = TTF_ACORE_TRUE;
        g_stPppEntInfo.usLcpEchoMaxLostCnt          = 5;
        g_stPppEntInfo.usQueneMaxCnt                = 1500;

        return;
    }

    g_stPppEntInfo.enChapEnable                 = stPppConfig.enChapEnable;
    g_stPppEntInfo.enPapEnable                  = stPppConfig.enPapEnable;
    g_stPppEntInfo.usLcpEchoMaxLostCnt          = stPppConfig.usLcpEchoMaxLostCnt;
    g_stPppEntInfo.usQueneMaxCnt                = stPppConfig.usQueneMaxCnt;

    return;
}

/******************************************************************************
 Prototype       : PPP_BindToCpu
 Description     : ????Task??????CPU????
 Input           :
 Output          : NONE
 Return Value    : PS_SUCC   --- ????
                   PS_FAIL   --- ????
 History         :
   1.Date        : 2016-06-16
     Author      :
     Modification:
******************************************************************************/
VOS_VOID PPP_BindToCpu(VOS_VOID)
{
    VOS_LONG                ret;
    pid_t                   target_pid;
    VOS_INT                 cpu;

    /* ??????????????Pid */
    target_pid = current->pid;

    /* ??????????????affinity */
    ret = sched_getaffinity(target_pid, &(g_stPppEntInfo.orig_mask));
    if (ret < 0)
    {
        PPP_MNTN_LOG(PS_PID_APP_PPP, 0, PS_PRINT_WARNING, "warning: unable to get cpu affinity\n");
        return;
    }

    PSACORE_MEM_SET(&(g_stPppEntInfo.curr_mask), cpumask_size(), 0, cpumask_size());

    /* ??????????????affinity */
    /*lint -e{713,732} */
    for_each_cpu(cpu, &(g_stPppEntInfo.orig_mask))
    {
        /* ??????CPU0 */
        if ((0 < cpu) && (cpumask_test_cpu(cpu, &(g_stPppEntInfo.orig_mask))))
        {
            cpumask_set_cpu((unsigned int)cpu, &(g_stPppEntInfo.curr_mask));
        }
    }

    if (0 == cpumask_weight(&(g_stPppEntInfo.curr_mask)))
    {
        cpumask_set_cpu(0, &(g_stPppEntInfo.curr_mask));
        return;
    }

    ret = sched_setaffinity(target_pid, &(g_stPppEntInfo.curr_mask));
    if (ret < 0)
    {
        PPP_MNTN_LOG(PS_PID_APP_PPP, 0, PS_PRINT_WARNING, "warning: unable to set cpu affinity\n");
        return;
    }

    return;
}


VOS_VOID PppMsgTimerProc( struct MsgCB * pMsg )
{
    REL_TIMER_MSG  *pPsMsg  = (REL_TIMER_MSG *)pMsg;
    VOS_UINT16      usPppId = (VOS_UINT16)(pPsMsg->ulPara);

    if (TIMER_PPP_LCP_ECHO_MSG == pPsMsg->ulName)
    {
        LcpSendEcho(PPP_LINK(usPppId));
    }
    else if (TIMER_PPP_PHASE_MSG == pPsMsg->ulName)
    {
        /*??????????????????????????*/
        switch(PPP_LINK(usPppId)->phase)
        {
            /*??????LCP????????????????*/
            case PHASE_ESTABLISH:
                FsmTimeout(&(PPP_LINK(usPppId)->lcp.fsm));
                break;

            /*??????????????????????????*/
            case PHASE_TERMINATE:
                FsmTimeout(&(PPP_LINK(usPppId)->lcp.fsm));
                break;

            /*??????????????????????????*/
            case PHASE_AUTHENTICATE:
                AuthTimeout(PPP_LINK(usPppId));
                break;

            /*??????IPCP????????????????*/
            case PHASE_NETWORK:
                FsmTimeout(&(PPP_LINK(usPppId)->ipcp.fsm));
                break;

            default:
                PPP_MNTN_LOG(PS_PID_APP_PPP, 0, PS_PRINT_WARNING,"unknow phase!\r\n");
                break;
        }
    }
    else if (TIMER_PDP_ACT_PENDING == pPsMsg->ulName)
    {
        /*??????IPCP??????PDP????????????,??????????????IPCP??*/
        if (VOS_NULL_PTR != PPP_LINK(usPppId)->ipcp.pstIpcpPendFrame)
        {
            fsm_Input(&(PPP_LINK(usPppId)->ipcp.fsm), PPP_LINK(usPppId)->ipcp.pstIpcpPendFrame);
            PPP_LINK(usPppId)->ipcp.pstIpcpPendFrame = VOS_NULL_PTR;
        }
        PPP_LINK(usPppId)->ipcp.hIpcpPendTimer = VOS_NULL_PTR;
    }
    else if (TIMER_TERMINATE_PENDING == pPsMsg->ulName)
    {
        PPP_LINK(usPppId)->lcp.hLcpCloseTimer = VOS_NULL_PTR;
        PPP_ProcPppDisconnEvent(usPppId);
    }
    else
    {
        PPP_MNTN_LOG1(PS_PID_APP_PPP, 0, PS_PRINT_WARNING,"Unknow Timer!\n", pPsMsg->ulName);
    }

    return;
}


VOS_UINT32    APP_PPP_PidInit(enum VOS_INIT_PHASE_DEFINE InitPhase )
{
    VOS_INT32               i;


    switch( InitPhase )
    {
    case   VOS_IP_LOAD_CONFIG:
            /*????????,????NV??,????????????MRU????WINS????????*/
            /*????NV??,????????????MRU*/
            g_usPppConfigMru = PPP_GetMruConfig();

            /*????NV??,????????????WINS????????*/
            g_ucPppConfigWins = PPP_GetWinsConfig();

            /*????????????????????????????link??????????*/
            /*lint -e433*/
            pgPppLink = (struct link *)VOS_MemAlloc(PS_PID_APP_PPP, STATIC_MEM_PT, sizeof(struct link)*PPP_MAX_ID_NUM);
            /*lint +e433*/
            if (VOS_NULL_PTR == pgPppLink)
            {
                /*????????????*/
                PPP_MNTN_LOG(PS_PID_APP_PPP, 0, PS_PRINT_ERROR,"APP_PPP_PidInit, malloc of  memory fail\r\n");
                return VOS_ERR;
            }

            /*????????????????????????????TAF_PPP_PUBLIC_STRU??????*/
            pgPppId = (PPP_ID *)VOS_MemAlloc(PS_PID_APP_PPP, STATIC_MEM_PT, sizeof(PPP_ID)*PPP_MAX_ID_NUM_ALLOC);
            if (VOS_NULL_PTR == pgPppId)
            {
                /*????????????????????TAF_PPP_PUBLIC_STRU??????*/
                VOS_MemFree(PS_PID_APP_PPP, pgPppLink);
                pgPppLink = VOS_NULL_PTR;


                /*????????????*/
                PPP_MNTN_LOG(PS_PID_APP_PPP, 0, PS_PRINT_ERROR,"APP_PPP_PidInit, malloc of  memory fail\r\n");
                return VOS_ERR;
            }

            /*????????????????????????????????????*/
            for(i = 0;i < PPP_MAX_ID_NUM; i++)
            {
                link_Init((pgPppLink + i));
            }

            PppIdInit();

            /*??????PPP??????????*/
            PPP_DataQInit();

            /* ???????????? */
            PPP_InitSpinLock();

            PPP_EntInit();


            break;

    case   VOS_IP_FARMALLOC:
    case   VOS_IP_INITIAL:
    case   VOS_IP_ENROLLMENT:
    case   VOS_IP_LOAD_DATA:
    case   VOS_IP_FETCH_DATA:
    case   VOS_IP_STARTUP:
    case   VOS_IP_RIVAL:
    case   VOS_IP_KICKOFF:
    case   VOS_IP_STANDBY:
    case   VOS_IP_BROADCAST_STATE:
    case   VOS_IP_RESTART:
    case   VOS_IP_BUTT:
           break;
    }

    return VOS_OK;
}


VOS_VOID APP_PPP_EventProc(VOS_UINT32 ulEvent)
{

    if (ulEvent & PPP_RCV_DATA_EVENT)
    {
        PPP_ProcDataNotify();
    }


    return;
}



VOS_VOID APP_PPP_MsgProc( struct MsgCB * pMsg )
{
    PPP_MSG    *pPsMsg  = (PPP_MSG *)pMsg;

    if(pMsg == VOS_NULL_PTR)
    {
        return;
    }


    /*??????????????????????*/
    if (VOS_PID_TIMER == pMsg->ulSenderPid)
    {
        PppMsgTimerProc(pMsg);


        return ;
    }

    /*??????????????TE??????????????*/
    switch(pPsMsg->ulMsgType)
    {
        case PPP_DATA_PROC_NOTIFY:
            PPP_ProcDataNotify();
            break;

        case PPP_AT_CTRL_OPERATION:
            PPP_ProcAtCtrlOper(pMsg);
            break;

        case PPP_HDLC_PROC_AS_FRM_PACKET_IND:
            PPP_ProcAsFrmDataInd(pMsg);
            break;



        default:
            break;
    }


    return;
}


/*lint -e{838} */
VOS_VOID APP_PPP_FidTask(VOS_UINT32 para1, VOS_UINT32 para2, VOS_UINT32 para3, VOS_UINT32 para4)
{
    MsgBlock                           *pMsg          = VOS_NULL_PTR;
    VOS_UINT32                          ulEvent       = 0;
    VOS_UINT32                          ulTaskID      = 0;
    VOS_UINT32                          ulRtn         = VOS_ERR;
    VOS_UINT32                          ulEventMask   = 0;
    VOS_UINT32                          ulExpectEvent = 0;

    ulTaskID = VOS_GetCurrentTaskID();
    if (PS_NULL_UINT32 == ulTaskID)
    {
        PPP_MNTN_LOG(PS_PID_APP_PPP, 0, PS_PRINT_ERROR, "APP_PPP_FidTask: ERROR, TaskID is invalid.");
        return;
    }

    if (VOS_OK != VOS_CreateEvent(ulTaskID))
    {
        PPP_MNTN_LOG(PS_PID_APP_PPP, 0, PS_PRINT_ERROR, "APP_PPP_FidTask: ERROR, create event fail.");
        return;
    }

    PPP_BindToCpu();

    ulExpectEvent = PPP_RCV_DATA_EVENT | VOS_MSG_SYNC_EVENT;
    ulEventMask   = VOS_EVENT_ANY | VOS_EVENT_WAIT;

    g_stPppEntInfo.ulPppInitFlag    = 1;
    g_stPppEntInfo.ulPppTaskId      = ulTaskID;

    /*lint -e{716} */
    for(;;)
    {
        ulRtn = VOS_EventRead(ulExpectEvent, ulEventMask, 0, &ulEvent);
        if (VOS_OK != ulRtn)
        {
            PPP_MNTN_LOG(PS_PID_APP_PPP, 0, PS_PRINT_ERROR, "APP_PPP_FidTask: ERROR, read event error.");
            continue;
        }

        /* ???????? */
        if (VOS_MSG_SYNC_EVENT != ulEvent)
        {
            APP_PPP_EventProc(ulEvent);
            continue;
        }

        pMsg = (MsgBlock*)VOS_GetMsg(ulTaskID);
        if (VOS_NULL_PTR != pMsg)
        {
            if (PS_PID_APP_PPP == pMsg->ulReceiverPid)
            {
                APP_PPP_MsgProc(pMsg);
            }

            (VOS_VOID)VOS_FreeMsg(PS_PID_APP_PPP, pMsg);
        }
    }
}



VOS_UINT32 APP_PPP_FidInit(enum VOS_INIT_PHASE_DEFINE ip)
{
    VOS_UINT32                          ulRslt;


    switch (ip)
    {
        case VOS_IP_LOAD_CONFIG:
            /* ????PID?????? */
            ulRslt = VOS_RegisterPIDInfo(PS_PID_APP_PPP,
                                (Init_Fun_Type)APP_PPP_PidInit,
                                (Msg_Fun_Type)APP_PPP_MsgProc);
            if (VOS_OK != ulRslt)
            {
                pr_err("[pppa]:APP_PPP_FidInit, register PPP PID fail!\n");
                return VOS_ERR;
            }

            ulRslt = VOS_RegisterMsgTaskEntry(ACPU_FID_PPP, (VOS_VOIDFUNCPTR)APP_PPP_FidTask);
            if (VOS_OK != ulRslt)
            {
                pr_err("[pppa]:APP_PPP_FidInit, VOS_RegisterMsgTaskEntry fail!\n");
                return VOS_ERR;
            }

            /* ?????????? */
            ulRslt = VOS_RegisterTaskPrio(ACPU_FID_PPP, VOS_PRIORITY_P4);
            if( VOS_OK != ulRslt )
            {
                pr_err("[pppa]:APP_PPP_FidInit, register priority fail!\n");
                return VOS_ERR;
            }

            break;

        case VOS_IP_FARMALLOC:
        case VOS_IP_INITIAL:
        case VOS_IP_ENROLLMENT:
        case VOS_IP_LOAD_DATA:
        case VOS_IP_FETCH_DATA:
        case VOS_IP_STARTUP:
        case VOS_IP_RIVAL:
        case VOS_IP_KICKOFF:
        case VOS_IP_STANDBY:
        case VOS_IP_BROADCAST_STATE:
        case VOS_IP_RESTART:
        case VOS_IP_BUTT:
            break;
    }

    return VOS_OK;
}


