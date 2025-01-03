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

#ifndef __PPP_INIT_H__
#define __PPP_INIT_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "PPP/Inc/ppp_public.h"
#include "LinuxInterface.h"

#pragma pack(4)

/*****************************************************************************
  2 ??????
*****************************************************************************/


/*****************************************************************************
  3 ????????
*****************************************************************************/

/*****************************************************************************
  4 STRUCT????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                  ulUplinkCnt;                /* ???????????????? */
    VOS_UINT32                  ulUplinkDropCnt;            /* ?????????? */
    VOS_UINT32                  ulUplinkSndDataCnt;         /* ?????????? */

    VOS_UINT32                  ulDownlinkCnt;              /* ???????????????? */
    VOS_UINT32                  ulDownlinkDropCnt;          /* ?????????? */
    VOS_UINT32                  ulDownlinkSndDataCnt;       /* ?????????? */

    VOS_UINT32                  ulMemAllocDownlinkCnt;      /* ???????????????? */
    VOS_UINT32                  ulMemAllocDownlinkFailCnt;  /* ???????????????????? */
    VOS_UINT32                  ulMemAllocUplinkCnt;        /* ???????????????? */
    VOS_UINT32                  ulMemAllocUplinkFailCnt;    /* ???????????????????? */
    VOS_UINT32                  ulMemFreeCnt;               /* ???????????????? */

    VOS_UINT32                  ulDropCnt;                  /* ???????????? */

    VOS_UINT32                  ulQMaxCnt;                  /* ?????????????????????????? */
    VOS_UINT32                  ulSndMsgCnt;                /* DataNotify?????????? */
    VOS_UINT32                  ulProcMsgCnt;               /* DataNotify?????????? */
} PPP_DATA_Q_STAT_ST;

typedef struct
{
    PPP_ZC_QUEUE_STRU           stDataQ;                    /* PPP???????????????????????????? */
    PPP_DATA_Q_STAT_ST          stStat;                     /* PPP?????????????????? */
    volatile VOS_UINT32         ulNotifyMsg;                /* ????PPP???????? */
}PPP_DATA_Q_CTRL_ST;

typedef struct
{
    struct cpumask              orig_mask;
    struct cpumask              curr_mask;

    VOS_UINT32                  ulPppTaskId;
    VOS_UINT32                  ulPppInitFlag;

    TTF_ACORE_BOOL_ENUM_UINT8   enChapEnable;           /* ????????Chap???? */
    TTF_ACORE_BOOL_ENUM_UINT8   enPapEnable;            /* ????????Pap???? */
    VOS_UINT16                  usLcpEchoMaxLostCnt;    /* ????LcpEchoRequest?????????????????? */

    VOS_UINT16                  usQueneMaxCnt;          /* ???????????????? */
    VOS_UINT8                   aucRsv[2];
} PPP_ENTITY_INFO_STRU;

/*****************************************************************************
  5 ????????????
*****************************************************************************/
extern PPP_ENTITY_INFO_STRU             g_stPppEntInfo;
extern PPP_DATA_Q_CTRL_ST               g_PppDataQCtrl;


#pragma pack()

#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

#endif  /*end of __PPP_INIT_H__*/

