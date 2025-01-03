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

#ifndef __PSLOGFILTERCOMM_H__
#define __PSLOGFILTERCOMM_H__


/******************************************************************************
  1 ??????????????
******************************************************************************/
#include "vos.h"
#include "PsLogFilterInterface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


#pragma pack(4)


/******************************************************************************
  2 ??????
******************************************************************************/


/******************************************************************************
  3 ????????
******************************************************************************/


/******************************************************************************
  4 ????????????
******************************************************************************/


/******************************************************************************
  5 ??????????
******************************************************************************/


/******************************************************************************
  6 ????????
******************************************************************************/


/******************************************************************************
  7 STRUCT????
******************************************************************************/

/*****************************************************************************
 ??????    : PS_OM_PER_PID_REG_CTRL_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????SendPid????????????????, ??????????????SendPid??????
             ??????????????????????????????????????????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                         ulSendPid; /*??????SendPid????????????16??*/
    VOS_UINT16                         usUseCnt;  /*????SendPid??????????????????????*/
    VOS_UINT16                         usMaxCnt;  /*??????????????????????????????????????????????????????????????????*/
    PS_OM_LAYER_MSG_REPLACE_CB        *pafuncFilterEntry; /*??????????????????????????*/
}PS_OM_PER_PID_REG_CTRL_STRU;


/*****************************************************************************
 ??????    : PS_OM_ONE_CPU_LAYER_MSG_FILTER_CTRL_STRU
 ????????  :
 ASN.1???? :
 ????????  : ??????????????????????????????SendPid????????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                           usUseCnt; /* ????????SendPid?????? */
    VOS_UINT16                           usMaxCnt; /* ??????????SendPid???? */
    PS_OM_PER_PID_REG_CTRL_STRU         *pastPerPidMsgFilter;  /* ??????SendPid????????????????????????????????????????usMaxCnt????????????????usUseCnt???? */
}PS_OM_CPU_LAYER_MSG_FILTER_CTRL_STRU;


/*****************************************************************************
 ??????    : PS_OM_LAYER_MSG_REPLACE_CTRL_STRU
 ????????  :
 ASN.1???? :
 ????????  : ??????????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                                      usLocalCpuMaxPidCnt;        /* ??????VOS_PID_BUTT??16??????????????CPU??????PID?????? */
    VOS_UINT8                                       ucLocalCpuId;               /* ??????VOS_CPU_ID_ENUM??????0????C????1????A?? */
    VOS_UINT8                                       aucReserve[1];
    PS_OM_CPU_LAYER_MSG_FILTER_CTRL_STRU            stLocalCpuLayerMsgFilter;   /* ???????????????????????? */
    PS_OM_CPU_LAYER_MSG_FILTER_CTRL_STRU            stDiffCpuLayerMsgFilter;    /* ???????????????????????? */
}PS_OM_LAYER_MSG_REPLACE_CTRL_STRU;


/*****************************************************************************
 ??????    : PS_OM_LAYER_MSG_REPLACE_REG_STATISTIC_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                                      ulRegSuccCnt;
    VOS_UINT32                                      ulRegFailCnt;
    VOS_UINT32                                      ulLocalCpuFilterCnt;
    VOS_UINT32                                      ulDiffCpuFilterCnt;
}PS_OM_LAYER_MSG_REPLACE_STATISTIC_STRU;


/******************************************************************************
  8 UNION????
******************************************************************************/


/******************************************************************************
  9 OTHERS????
*****************************************************************************/

VOS_VOID* PS_OM_CpuLayerMsgCommReplace
(
    VOS_VOID                                    *pMsg,
    PS_OM_LAYER_MSG_REPLACE_CTRL_STRU           *pstLayerMsgReplaceCtrl
);

VOS_UINT32 PS_OM_LayerMsgReplaceCBCommReg
(
    PS_OM_LAYER_MSG_REPLACE_CTRL_STRU          *pstLayerMsgCtrl,
    VOS_UINT32                                  ulSendPid,
    PS_OM_LAYER_MSG_REPLACE_CB                  pFunc
);

VOS_VOID PS_OM_LogFilterCommShow
(
    PS_OM_LAYER_MSG_REPLACE_CTRL_STRU          *pstLayerMsgCtrl
);


#pragma pack()


#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

#endif /* PsLogFilterComm.h */


