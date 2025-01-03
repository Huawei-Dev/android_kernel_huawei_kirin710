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


/*****************************************************************************
  1 ??????????
**************************************************************************** */
#include <product_config.h>
#include <osl_sem.h>
#include <soc_socp_adapter.h>
#include <bsp_socp.h>
#include <securec.h>
#include "OmCommonPpm.h"
#include "scm_common.h"
#include "scm_ind_src.h"
#include "scm_debug.h"
#include "diag_system_debug.h"


#define SOCP_CODER_SRC_PS_IND    SOCP_CODER_SRC_LOM_IND1

/* ****************************************************************************
  2 ????????????
**************************************************************************** */
SCM_CODER_SRC_CFG_STRU      g_astSCMIndCoderSrcCfg =
{
    SCM_CHANNEL_UNINIT,
    SOCP_CODER_SRC_PS_IND,
    SOCP_CODER_DST_OM_IND,
    SOCP_DATA_TYPE_0,
    SOCP_ENCSRC_CHNMODE_CTSPACKET,
    SOCP_CHAN_PRIORITY_2,
    SOCP_TRANS_ID_DIS,
    SOCP_PTR_IMG_DIS,
    SCM_CODER_SRC_BDSIZE,
    SCM_CODER_SRC_RDSIZE,
    NULL,
    NULL,
    NULL,
    NULL,
    0,
    0
};

u32 scm_init_ind_src_buff(void)
{
    u32                          ulRet;



    ulRet = scm_create_ind_src_buff(&g_astSCMIndCoderSrcCfg.pucSrcBuf,
                                &g_astSCMIndCoderSrcCfg.pucSrcPHY,
                                SCM_CODER_SRC_IND_BUFFER_SIZE);
    if(BSP_OK != ulRet)
    {
        g_astSCMIndCoderSrcCfg.enInitState   = SCM_CHANNEL_MEM_FAIL;
        return (u32)BSP_ERROR;
    }
    g_astSCMIndCoderSrcCfg.ulSrcBufLen  = SCM_CODER_SRC_IND_BUFFER_SIZE;
    g_astSCMIndCoderSrcCfg.enInitState  = SCM_CHANNEL_INIT_SUCC;

    return BSP_OK;
}


/* ****************************************************************************
 ?? ?? ??  : scm_create_cnf_src_buff
 ????????  : ??????????buffer????
 ????????  :
**************************************************************************** */
u32 scm_create_ind_src_buff(u8 **pBufVir, u8 **pBufPhy, u32 ulLen)
{
    unsigned long ulRealAddr;

    /*????uncache????????????*/
    *pBufVir = (u8*)scm_UnCacheMemAlloc(ulLen, &ulRealAddr);

    /* ???????????? */
    if (NULL == *pBufVir)
    {
        return (u32)BSP_ERROR;
    }

    /* ????buf?????? */
    *pBufPhy = (u8*)ulRealAddr;

    return BSP_OK;
}


u32 scm_ind_src_chan_init(void)
{

    if (BSP_OK != scm_ind_src_chan_cfg(&g_astSCMIndCoderSrcCfg))
    {
        diag_error("cfg ind src fail\n");
        g_astSCMIndCoderSrcCfg.enInitState = SCM_CHANNEL_CFG_FAIL;  /* ?????????????????????? */

        return (u32)BSP_ERROR;/* ???????? */
    }

    if(BSP_OK != bsp_socp_start(g_astSCMIndCoderSrcCfg.enChannelID))
    {
        diag_error("start ind src fail\n");
        g_astSCMIndCoderSrcCfg.enInitState = SCM_CHANNEL_START_FAIL;  /* ???????????????????? */

        return ERR_MSP_SCM_START_SOCP_FAIL;/* ???????? */
    }

    g_astSCMIndCoderSrcCfg.enInitState = SCM_CHANNEL_INIT_SUCC;     /* ?????????????????????? */

    return BSP_OK;/* ???????? */
}


unsigned long scm_ind_src_phy_to_virt(u8 * phyAddr)
{
    if((phyAddr < g_astSCMIndCoderSrcCfg.pucSrcPHY)
        || (phyAddr >= (g_astSCMIndCoderSrcCfg.pucSrcBuf + g_astSCMIndCoderSrcCfg.ulSrcBufLen)))
    {
        return (unsigned long)NULL;
    }

    return (unsigned long)((phyAddr - g_astSCMIndCoderSrcCfg.pucSrcPHY) + g_astSCMIndCoderSrcCfg.pucSrcBuf);
}


u32 scm_ind_src_chan_cfg(SCM_CODER_SRC_CFG_STRU *pstCfg)
{
    SOCP_CODER_SRC_CHAN_S               stChannel;          /* ?????????????????? */

    stChannel.u32DestChanID = pstCfg->enDstCHID;            /*  ????????ID */
    stChannel.eDataType     = pstCfg->enDataType;           /*  ?????????????????????????????????????????? */
    stChannel.eMode         = pstCfg->enCHMode;             /*  ???????????? */
    stChannel.ePriority     = pstCfg->enCHLevel;            /*  ?????????? */
	stChannel.eTransIdEn    = pstCfg->enTransIdEn;          /*  SOCP Trans Id?????? */
	stChannel.ePtrImgEn     = pstCfg->enPtrImgEn;           /*  SOCP ?????????????? */
    stChannel.u32BypassEn   = SOCP_HDLC_ENABLE;             /*  ????bypass???? */
    stChannel.eDataTypeEn   = SOCP_DATA_TYPE_EN;            /*  ?????????????? */
    stChannel.eDebugEn      = SOCP_ENC_DEBUG_DIS;           /*  ?????????? */

    stChannel.sCoderSetSrcBuf.pucInputStart  = pstCfg->pucSrcPHY;                             /*  ???????????????? */
    stChannel.sCoderSetSrcBuf.pucInputEnd    = (pstCfg->pucSrcPHY + pstCfg->ulSrcBufLen)-1;   /*  ???????????????? */
    stChannel.sCoderSetSrcBuf.pucRDStart     = pstCfg->pucRDPHY;                              /* RD buffer???????? */
    stChannel.sCoderSetSrcBuf.pucRDEnd       = (pstCfg->pucRDPHY + pstCfg->ulRDBufLen)-1;     /*  RD buffer???????? */
    stChannel.sCoderSetSrcBuf.u32RDThreshold = SCM_CODER_SRC_RD_THRESHOLD;                    /* RD buffer???????????? */

    if(pstCfg->enPtrImgEn)
    {
        /* ??????????????8Bytes????????????????????????????????8Bytes??????*/
        pstCfg->pRptrImgVirtAddr = (unsigned long)scm_UnCacheMemAlloc(sizeof(u64), &(pstCfg->pRptrImgPhyAddr));
        if(0 == pstCfg->pRptrImgVirtAddr)
        {
            return ERR_MSP_NOT_FREEE_SPACE;
        }

        stChannel.eRptrImgPhyAddr = pstCfg->pRptrImgPhyAddr;
        stChannel.eRptrImgVirtAddr = pstCfg->pRptrImgVirtAddr;
    }

    if (BSP_OK != bsp_socp_coder_set_src_chan(pstCfg->enChannelID, &stChannel))
    {
        diag_error("Channel ID(0x%x) Error\n", pstCfg->enChannelID);

        return (u32)BSP_ERROR;/* ???????? */
    }



    pstCfg->enInitState = SCM_CHANNEL_INIT_SUCC; /* ?????????????????????? */

    return BSP_OK;/* ???????? */
}





