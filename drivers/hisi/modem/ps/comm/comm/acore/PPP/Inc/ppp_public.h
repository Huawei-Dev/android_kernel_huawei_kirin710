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

#ifndef __PPP_PUBLIC_H__
#define __PPP_PUBLIC_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "vos.h"
#include "AtPppInterface.h"
#include "product_config.h"
#include "TTFUtil.h"
#include "v_IO.h"
#include "TTFComm.h"
#include "ImmInterface.h"
#include "acore_nv_id_gucttf.h"
#include "acore_nv_stru_gucttf.h"
#include "NVIM_Interface.h"

#pragma pack(4)

/*****************************************************************************
  2 ??????
*****************************************************************************/

#ifndef VOS_NTOHL
#if    VOS_BYTE_ORDER==VOS_BIG_ENDIAN
#define    VOS_NTOHL(x)    (x)
#define    VOS_HTONL(x)    (x)
#define    VOS_NTOHS(x)    (x)
#define    VOS_HTONS(x)    (x)
#else
#define VOS_NTOHL(x)    ((((x) & 0x000000ff) << 24) | \
             (((x) & 0x0000ff00) <<  8) | \
             (((x) & 0x00ff0000) >>  8) | \
             (((x) & 0xff000000) >> 24))

#define VOS_HTONL(x)    ((((x) & 0x000000ff) << 24) | \
             (((x) & 0x0000ff00) <<  8) | \
             (((x) & 0x00ff0000) >>  8) | \
             (((x) & 0xff000000) >> 24))

#define VOS_NTOHS(x)    ((((x) & 0x00ff) << 8) | \
             (((x) & 0xff00) >> 8))

#define VOS_HTONS(x)    ((((x) & 0x00ff) << 8) | \
             (((x) & 0xff00) >> 8))

#endif    /* _BYTE_ORDER==_LITTLE_ENDIAN */

#endif

#ifndef INADDR_ANY
#define    INADDR_ANY            (VOS_UINT32)0x00000000L
#endif

#ifndef INADDR_BROADCAST
#define    INADDR_BROADCAST    (VOS_UINT32)0xffffffffL    /* must be masked */
#endif

#ifndef INADDR_NONE
#define    INADDR_NONE            0xffffffffUL        /* -1 return */
#endif


#define NEG_ACCEPTED        (1)
#define NEG_ENABLED         (2)
#define IsAccepted(x)       ((x) & NEG_ACCEPTED)
#define IsEnabled(x)        ((x) & NEG_ENABLED)

#define SCRIPT_LEN          (512)        /* Size of login/dial/hangup scripts */

#if    VOS_BYTE_ORDER==VOS_BIG_ENDIAN
#define ua_htonl(src, tgt) PSACORE_MEM_CPY(tgt,sizeof(VOS_UINT32),src,sizeof(VOS_UINT32))
#define ua_ntohl(src, tgt) PSACORE_MEM_CPY(tgt,sizeof(VOS_UINT32),src,sizeof(VOS_UINT32))
#define ua_htons(src, tgt) PSACORE_MEM_CPY(tgt,sizeof(VOS_UINT16),src,sizeof(VOS_UINT16))
#define ua_ntohs(src, tgt) PSACORE_MEM_CPY(tgt,sizeof(VOS_UINT16),src,sizeof(VOS_UINT16))
#else
#define ua_htonl(src, tgt) \
        *((VOS_CHAR*)(tgt)) = *(((VOS_CHAR*)(src))+3); \
        *(((VOS_CHAR*)(tgt))+1) = *(((VOS_CHAR*)(src))+2); \
        *(((VOS_CHAR*)(tgt))+2) = *(((VOS_CHAR*)(src))+1); \
        *(((VOS_CHAR*)(tgt))+3) = *((VOS_CHAR*)(src));

#define ua_ntohl(src, tgt) \
        *((VOS_CHAR*)tgt) = *(((VOS_CHAR*)src)+3); \
        *(((VOS_CHAR*)tgt)+1) = *(((VOS_CHAR*)src)+2); \
        *(((VOS_CHAR*)tgt)+2) = *(((VOS_CHAR*)src)+1); \
        *(((VOS_CHAR*)tgt)+3) = *((VOS_CHAR*)src);

#define ua_htons(src, tgt) \
        *((VOS_CHAR*)tgt) = *(((VOS_CHAR*)src)+1); \
        *(((VOS_CHAR*)tgt)+1) = *((VOS_CHAR*)src);

#define ua_ntohs(src, tgt) \
        *((VOS_CHAR*)tgt) = *(((VOS_CHAR*)src)+1); \
        *(((VOS_CHAR*)tgt)+1) = *((VOS_CHAR*)src);

#endif
/*??????????????PPP ID????????????????????????
????????????????????????????*/
/*#define PPP_MAX_ID_NUM 1*/
#define PPP_MAX_ID_NUM_ALLOC (PPP_MAX_ID_NUM+1)

/*????????????????????????????????????????????????*/
#define PPP_RECIEVE_RESERVE_FOR_HEAD 4

/*????????????????????????????????????????????????*/
#define PPP_RECIEVE_RESERVE_FOR_TAIL 2

#define PPPoE_RESERVE_HEADER_LEN    20     /*????????????????PPPoE????????????????PPPoE????*/

#define PPP_FEATURE_PPP         0          /*????PPP*/

#define PPP_FEATURE             PPP_FEATURE_PPP   /*????????PPP*/

#define PPP_MAX_DATA_CNT_IN_QUEUE (2000)

#define PPP_RAB_TO_PPPID(pusPppId, ucRabId) \
    ( TAF_SUCCESS == At_PsRab2PppId((ucRabId), pusPppId) )

#define PPP_PPPID_TO_RAB(usPppId, pucRabId) \
    ( TAF_SUCCESS == At_PppId2PsRab((usPppId), pucRabId) )

#define PPP_MNTN_LOG(ModulePID, SubMod, Level, String) \
            ((VOS_VOID)DIAG_LogReport(DIAG_GEN_LOG_MODULE(MODEM_ID_0, DIAG_MODE_COMM, Level), (ModulePID), __FILE__, __LINE__, "\r\n"))
#define PPP_MNTN_LOG1(ModulePID, SubMod, Level, String, Para1) \
            ((VOS_VOID)DIAG_LogReport(DIAG_GEN_LOG_MODULE(MODEM_ID_0, DIAG_MODE_COMM, Level), (ModulePID), __FILE__, __LINE__, "%d \r\n", Para1))
#define PPP_MNTN_LOG2(ModulePID, SubMod, Level, String, Para1, Para2) \
            ((VOS_VOID)DIAG_LogReport(DIAG_GEN_LOG_MODULE(MODEM_ID_0, DIAG_MODE_COMM, Level), (ModulePID), __FILE__, __LINE__, "%d, %d \r\n", Para1, Para2))
#define PPP_MNTN_LOG3(ModulePID, SubMod, Level, String, Para1, Para2, Para3) \
            ((VOS_VOID)DIAG_LogReport(DIAG_GEN_LOG_MODULE(MODEM_ID_0, DIAG_MODE_COMM, Level), (ModulePID), __FILE__, __LINE__, "%d, %d, %d \r\n", Para1, Para2, Para3))
#define PPP_MNTN_LOG4(ModulePID, SubMod, Level, String, Para1, Para2, Para3, Para4) \
            ((VOS_VOID)DIAG_LogReport(DIAG_GEN_LOG_MODULE(MODEM_ID_0, DIAG_MODE_COMM, Level), (ModulePID), __FILE__, __LINE__, "%d, %d, %d, %d \r\n", Para1, Para2, Para3, Para4))

/* --------------????????????????-------------- */
typedef IMM_ZC_STRU      PPP_ZC_STRU;
typedef IMM_ZC_HEAD_STRU PPP_ZC_QUEUE_STRU;

#define PPP_ZC_MAX_DATA_LEN                  (IMM_MAX_ETH_FRAME_LEN)            /* A???????????????????????? */
#define PPP_ZC_UL_RESERVE_LEN                (IMM_MAC_HEADER_RES_LEN)           /* MAC???????????????????????? */
#define PPP_ZC_DL_RESERVE_LEN                (0)                                /* ?????????????????? */

#define PPP_ZC_MEM_ALLOC(ulLen)              (IMM_ZcStaticAlloc(ulLen))
#define PPP_ZC_MEM_FREE(pstMem)              (IMM_ZcFreeAny(pstMem))
#define PPP_ZC_GET_DATA_PTR(pstImmZc)        ((VOS_UINT8 *)IMM_ZcGetDataPtr(pstImmZc))
#define PPP_ZC_GET_DATA_LEN(pstImmZc)        ((VOS_UINT16)IMM_ZcGetUsedLen(pstImmZc))
#define PPP_ZC_GET_DATA_APP(pstImmZc)        ((VOS_UINT16)IMM_ZcGetUserApp(pstImmZc))
#define PPP_ZC_SET_DATA_APP(pstImmZc, ucApp) (IMM_ZcSetUserApp(pstImmZc, ucApp))
#define PPP_ZC_SET_DATA_LEN(pstImmZc, ulLen) (IMM_ZcPut(pstImmZc, ulLen))
#define PPP_ZC_REMOVE_HDR(pstImmZc, ulLen)   (IMM_ZcPull(pstImmZc, ulLen))
#define PPP_ZC_RESERVE(pstMem, usReserveLen) (IMM_ZcReserve(pstMem, usReserveLen))
#define PPP_ZC_GET_RESERVE_ROOM(pstMem)      (pstMem->end - pstMem->tail)

#define PPP_ZC_QUEUE_INIT(pstZcQueue)           (IMM_ZcQueueHeadInit(pstZcQueue))
#define PPP_ZC_ENQUEUE_HEAD(pstZcQueue, pstMem) (IMM_ZcQueueHead(pstZcQueue, pstMem))
#define PPP_ZC_ENQUEUE_TAIL(pstZcQueue, pstMem) (IMM_ZcQueueTail(pstZcQueue, pstMem))
#define PPP_ZC_DEQUEUE_HEAD(pstZcQueue)         (IMM_ZcDequeueHead(pstZcQueue))
#define PPP_ZC_DEQUEUE_TAIL(pstZcQueue)         (IMM_ZcDequeueTail(pstZcQueue))
#define PPP_ZC_PEEK_QUEUE_HEAD(pstZcQueue)      (IMM_ZcQueuePeek(pstZcQueue))
#define PPP_ZC_PEEK_QUEUE_TAIL(pstZcQueue)      (IMM_ZcQueuePeekTail(pstZcQueue))
#define PPP_ZC_GET_QUEUE_LEN(pstZcQueue)        (IMM_ZcQueueLen(pstZcQueue))

/* A?????????????? */
#define PPP_MNTN_TRACE_MSG(pMsg)                DIAG_TraceReport(pMsg)

/*****************************************************************************
  3 ????????
*****************************************************************************/

/*****************************************************************************
  4 STRUCT????
*****************************************************************************/
/* STRUCT???? */
struct link;
struct ppp_mbuf;
struct lcp;

/*IP????*/
struct ppp_in_addr
{
    VOS_UINT32 s_addr;
};

/*****************************************************************************
  5 ????????????
*****************************************************************************/

/*****************************************************************************
  6 ??????????
*****************************************************************************/


/*****************************************************************************
  7 ????????
*****************************************************************************/
/* ?????????? */
#define TIMER_PPP_PHASE_MSG                     (0x0001)
#define TIMER_PPP_LCP_ECHO_MSG                  (0x0002)
#define TIMER_HDLC_FRM_OUTPUT_SPACE_ALLOC_FAIL  (0x0003)
#define TIMER_PDP_ACT_PENDING                   (0x0004)
#define TIMER_TERMINATE_PENDING                 (0x0005)


/*****************************************************************************
  8 UNION????
*****************************************************************************/


/*****************************************************************************
  9 OTHERS????
*****************************************************************************/
/* ????????????????????????????????????????
         C0  C1  C2  C3              C0  C1  C2  C3
    R0 | 0 | 1 | 2 | 3 |        R0 | 3 | 6 | 9 | C |
       -----------------           -----------------
    R1 | 4 | 5 | 6 | 7 |        R1 | 7 | A | D | 0 |
       -----------------   ==>     -----------------
    R2 | 8 | 9 | A | B |        R2 | B | E | 1 | 4 |
       -----------------           -----------------
    R3 | C | D | E | F |        R3 | F | 2 | 5 | 8 |
*/
#define PPP_MATRIX_TRANSFORM(aucDst, aucSrc) \
{                               \
    aucDst[0] = aucSrc[0][3];   \
    aucDst[1] = aucSrc[1][2];   \
    aucDst[2] = aucSrc[2][1];   \
    aucDst[3] = aucSrc[3][0];   \
    aucDst[4] = aucSrc[1][3];   \
    aucDst[5] = aucSrc[2][2];   \
    aucDst[6] = aucSrc[3][1];   \
    aucDst[7] = aucSrc[0][0];   \
    aucDst[8] = aucSrc[2][3];   \
    aucDst[9] = aucSrc[3][2];   \
    aucDst[10] = aucSrc[0][1];  \
    aucDst[11] = aucSrc[1][0];  \
    aucDst[12] = aucSrc[3][3];  \
    aucDst[13] = aucSrc[0][2];  \
    aucDst[14] = aucSrc[1][1];  \
    aucDst[15] = aucSrc[2][0];  \
}

/*****************************************************************************
  10 ????????
*****************************************************************************/
extern PPP_ZC_STRU *PPP_MemAlloc(VOS_UINT16 usLen, VOS_UINT16 usReserveLen);
extern PPP_ZC_STRU *PPP_MemCopyAlloc(VOS_UINT8 *pSrc, VOS_UINT16 usLen, VOS_UINT16 usReserveLen);
extern VOS_VOID     PPP_MemWriteData(PPP_ZC_STRU *pstMem, VOS_UINT16 usDstLen, VOS_UINT8 *pucSrc, VOS_UINT16 usLen);
extern VOS_VOID     PPP_MemFree(PPP_ZC_STRU *pstData);
extern VOS_UINT32   PPP_MemGet(PPP_ZC_STRU *pMemSrc, VOS_UINT16 usOffset, VOS_UINT8 *pDest, VOS_UINT16 usLen);
extern VOS_UINT32   PPP_MemCutTailData(PPP_ZC_STRU **ppMemSrc, VOS_UINT8 *pDest, VOS_UINT16 usLen, VOS_UINT16 usReserveLen);
extern VOS_UINT32   PPP_MemCutHeadData(PPP_ZC_STRU **ppMemSrc, VOS_UINT8 *pDest, VOS_UINT16 usLen);
extern VOS_VOID     PPP_MemSingleCopy(VOS_UINT8 *pucDest, VOS_UINT32 ulDstLen, VOS_UINT8 *pucSrc, VOS_UINT32 ulLen);
extern VOS_VOID     Ppp_ReleasePpp(PPP_ID usPppId);
extern VOS_VOID     PPP_GetSecurityRand
(
    VOS_UINT8                           ucRandByteLen,
    VOS_UINT8                          *pucRand
);

#pragma pack()

#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif


#endif  /*end of __PPP_PUBLIC_H__*/
