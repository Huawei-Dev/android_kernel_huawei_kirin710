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

#ifndef __PCSC_PROC_H__
#define __PCSC_PROC_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  1 ??????????????
*****************************************************************************/

#include "vos.h"
#include "pamappom.h"
#include "UsimPsInterface.h"

/*****************************************************************************
  2 ??????
*****************************************************************************/

#define USIMM_CARDSTATUS_IND                    100
#define SI_PIH_PCSC_DATA_CNF                    0xA5

/*******************************************************************************
  3 ????????
*******************************************************************************/
enum SI_PIH_EVENT_ENUM
{
    SI_PIH_EVENT_PIN_OPER_CNF       = 1,      /* ????PIN??????????        */
    SI_PIH_EVENT_PIN_QUERY_CNF      = 2,      /* ????PIN??????????        */
    SI_PIH_EVENT_PIN_INFO_IND       = 3,      /* ????PIN??????????        */
    SI_PIH_EVENT_SIM_INFO_IND       = 4,      /* SIM??????????            */
    SI_PIH_EVENT_GENERIC_ACCESS_CNF = 5,      /* +CSIM ????               */
    SI_PIH_EVENT_RESTRIC_ACCESS_CNF = 6,      /* +CRSM ????               */
    SI_PIH_EVENT_FDN_CNF            = 7,      /* FDN????                  */
    SI_PIH_EVENT_BDN_CNF            = 8,      /* BDN????                  */
    SI_PIH_EVENT_PERO_LOCK_CNF      = 9,      /* ????????                 */
    SI_PIH_EVENT_BUTT
};
typedef VOS_UINT32  SI_PIH_EVENT;

enum SI_PIH_REQ_ENUM
{
    SI_PIH_NULL_REQ                 = 0,
    SI_PIH_FDN_ENABLE_REQ           = 1,
    SI_PIH_FDN_DISALBE_REQ          = 2,
    SI_PIH_GACCESS_REQ              = 3,
    SI_PIH_BDN_QUERY_REQ            = 4,
    SI_PIH_FDN_QUERY_REQ            = 5,
    SI_PIH_PCSC_DATA_REQ            = 6,
    SI_PIH_REQ_BUTT
};
typedef VOS_UINT32      SI_PIH_REQ_ENUM_UINT32;

/*****************************************************************************
  4 STRUCT????
*****************************************************************************/
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
    SI_PIH_MSG_HEADER_STRU          stMsgHeader;
    VOS_UINT32                      ulMsgType;
    VOS_UINT32                      ulCmdType;
    VOS_UINT32                      ulCmdLen;
    VOS_UINT8                       aucAPDU[8];
}SI_PIH_PCSC_REQ_STRU;

typedef struct
{
    VOS_MSG_HEADER
    VOS_UINT32                      ulMsgName;          /* ???????? */
    VOS_UINT32                      ulResult;           /* PC/SC???????????? */
    VOS_UINT32                      ulCmdType;          /* ???????? */
    VOS_UINT32                      ulRspLen;           /* ?????????????????????? */
    VOS_UINT8                       aucContent[4];      /* ???????? */
}SI_PIH_PCSC_CNF_STRU;

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif
