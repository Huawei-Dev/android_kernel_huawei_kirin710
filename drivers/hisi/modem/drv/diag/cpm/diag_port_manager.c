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
*****************************************************************************/
#include <linux/module.h>
#include <mdrv.h>
#include <mdrv_diag_system.h>
#include <bsp_nvim.h>
#include <bsp_socp.h>
#include <nv_stru_drv.h>
#include <acore_nv_stru_drv.h>
#include "diag_system_debug.h"
#include "diag_port_manager.h"

/*****************************************************************************
  2 ????????????
*****************************************************************************/

CPM_PHY_PORT_CFG_STRU                   g_astCPMPhyPortCfg[CPM_PORT_BUTT - CPM_IND_PORT];
CPM_LOGIC_PORT_CFG_STRU                 g_astCPMLogicPortCfg[CPM_COMM_BUTT];

/* ???????????????? */
DIAG_CHANNLE_PORT_CFG_STRU                g_stPortCfg;

/* ???????????????????? */
CPM_COM_PORT_SND_ERR_INFO_STRU          g_stCPMSndErrInfo = {0};

/* ???????????????????? */
CPM_COM_PORT_RCV_ERR_INFO_STRU          g_stCPMRcvErrInfo = {0};

/*****************************************************************************
  3 ??????????
*****************************************************************************/

/*****************************************************************************
  4 ??????????
*****************************************************************************/

/*****************************************************************************
 ?? ?? ??  : CPM_PhySendReg
 ????????  : ??????????????????????????????????????????????????
 ????????  : enPhyPort??  ????????????????
             pRecvFunc??  ????????????
 ????????  : ??
 ?? ?? ??  : ??

*****************************************************************************/
void CPM_PhySendReg(CPM_PHY_PORT_ENUM_UINT32 enPhyPort, CPM_SEND_FUNC pSendFunc)
{
    if (CPM_PORT_BUTT > enPhyPort)
    {
        CPM_PHY_SEND_FUNC(enPhyPort - CPM_IND_PORT) = pSendFunc;
    }

    return;
}

/*****************************************************************************
 ?? ?? ??  : CPM_LogicRcvReg
 ????????  : ??????????????????????
 ????????  : enLogicPort?? ????????????????
             pRecvFunc??   ????????????
 ????????  : ??
 ?? ?? ??  : ??

*****************************************************************************/
void CPM_LogicRcvReg(CPM_LOGIC_PORT_ENUM_UINT32 enLogicPort, CPM_RCV_FUNC pRcvFunc)
{
    if (CPM_COMM_BUTT > enLogicPort)
    {
        CPM_LOGIC_RCV_FUNC(enLogicPort) = pRcvFunc;
    }

    return;
}

/*****************************************************************************
 ?? ?? ??  : CPM_QueryPhyPort
 ????????  : ??????????????????????????????
 ????????  : enLogicPort??  ??????????
 ????????  : ??
 ?? ?? ??  : ??????????

*****************************************************************************/
CPM_PHY_PORT_ENUM_UINT32 CPM_QueryPhyPort(CPM_LOGIC_PORT_ENUM_UINT32 enLogicPort)
{
    return CPM_LOGIC_PHY_PORT(enLogicPort);
}

/*****************************************************************************
 ?? ?? ??  : CPM_ConnectPorts
 ????????  : ??????????????????????????
 ????????  : enPhyPort??    ??????????
             enLogicPort??  ??????????
 ????????  : ??
 ?? ?? ??  : ??

*****************************************************************************/
void CPM_ConnectPorts(CPM_PHY_PORT_ENUM_UINT32 enPhyPort, CPM_LOGIC_PORT_ENUM_UINT32 enLogicPort)
{
    if ((CPM_PORT_BUTT <= enPhyPort) || (CPM_COMM_BUTT <= enLogicPort))
    {
        return;
    }

    /* ???????????? */
    CPM_LOGIC_SEND_FUNC(enLogicPort)= CPM_PHY_SEND_FUNC(enPhyPort - CPM_IND_PORT);

    /* ???????????? */
    CPM_PHY_RCV_FUNC(enPhyPort - CPM_IND_PORT) = CPM_LOGIC_RCV_FUNC(enLogicPort);

    /* ???????????????????????????? */
    CPM_LOGIC_PHY_PORT(enLogicPort) = enPhyPort;

    return;
}

/*****************************************************************************
 ?? ?? ??  : CPM_DisconnectPorts
 ????????  : ??????????????????????????
 ????????  : enPhyPort??    ??????????
             enLogicPort??  ??????????
 ????????  : ??
 ?? ?? ??  : ??

*****************************************************************************/
void CPM_DisconnectPorts(CPM_PHY_PORT_ENUM_UINT32 enPhyPort, CPM_LOGIC_PORT_ENUM_UINT32 enLogicPort)
{
    if ((CPM_PORT_BUTT <= enPhyPort) || (CPM_COMM_BUTT <= enLogicPort))
    {
        return;
    }

    /* ???????????????????????????????????????????????? */
    if (enPhyPort != CPM_LOGIC_PHY_PORT(enLogicPort))
    {
        return;
    }

    /* ???????????? */
    CPM_PHY_RCV_FUNC(enPhyPort - CPM_IND_PORT) = NULL;

    /* ???????????? */
    CPM_LOGIC_SEND_FUNC(enLogicPort)= NULL;
    CPM_LOGIC_PHY_PORT(enLogicPort) = CPM_PORT_BUTT;

    return;
}


/*****************************************************************************
 ?? ?? ??  : CPM_PortAssociateInit
 ????????  : ??????????????????????????????????
 ????????  : void
 ????????  : ??
 ?? ?? ??  : BSP_OK:????????????????
*****************************************************************************/
int CPM_PortAssociateInit(void)
{
    u32 i;

    for (i = 0; i < CPM_COMM_BUTT; i++)
    {
        g_astCPMLogicPortCfg[i].enPhyPort = CPM_PORT_BUTT;
    }

    /* Modified by h59254 for AP-Modem Personalisation Project, 2012/04/12, begin */
    /* ????????HSIC???????????????????????????????? */
    if (BSP_MODULE_SUPPORT == mdrv_misc_support_check(BSP_MODULE_TYPE_HSIC))
    {
        return BSP_OK;
    }
    /* Modified by h59254 for AP-Modem Personalisation Project, 2012/04/12, end */

    /* ????OM?????????????? */
    if (NV_OK != bsp_nvm_read(NV_ID_DRV_DIAG_PORT, (u8 *)&g_stPortCfg, sizeof(DIAG_CHANNLE_PORT_CFG_STRU)))
    {
        return BSP_ERROR;
    }

    /* ????????*/
    if (CPM_OM_PORT_TYPE_USB == g_stPortCfg.enPortNum)
    {
        CPM_ConnectPorts(CPM_CFG_PORT, CPM_OM_CFG_COMM);
        CPM_ConnectPorts(CPM_IND_PORT, CPM_OM_IND_COMM);
    }
    else if (CPM_OM_PORT_TYPE_VCOM == g_stPortCfg.enPortNum)
    {
        CPM_ConnectPorts(CPM_VCOM_CFG_PORT, CPM_OM_CFG_COMM);
        CPM_ConnectPorts(CPM_VCOM_IND_PORT, CPM_OM_IND_COMM);
    }
    else if (CPM_OM_PORT_TYPE_WIFI == g_stPortCfg.enPortNum)
    {
        CPM_ConnectPorts(CPM_WIFI_AT_PORT,     CPM_AT_COMM);
        CPM_ConnectPorts(CPM_WIFI_OM_IND_PORT, CPM_OM_IND_COMM);
        CPM_ConnectPorts(CPM_WIFI_OM_CFG_PORT, CPM_OM_CFG_COMM);
    }
    /* NV????????????USB???????? */
    else
    {
        CPM_ConnectPorts(CPM_CFG_PORT, CPM_OM_CFG_COMM);
        CPM_ConnectPorts(CPM_IND_PORT, CPM_OM_IND_COMM);

        g_stPortCfg.enPortNum = CPM_OM_PORT_TYPE_USB;
    }

    /*??????????????USB??????????????SOCP????????*/
    if(g_stPortCfg.enPortNum == CPM_OM_PORT_TYPE_USB)
    {
        bsp_socp_set_ind_mode(SOCP_IND_MODE_DIRECT);
    }

    diag_crit("diag port manager init ok\n");
    return BSP_OK;
}
module_init(CPM_PortAssociateInit);
/*****************************************************************************
 ?? ?? ??  : CPM_ComSend
 ????????  : ????????????????????????????????
 ????????  : enLogicPort????????????
             pucVirData:  ????????????
             pucPHYData:  ????????????
             pucData??    ??????????????
             ulLen:       ??????????????

 ????????  : ??
 ?? ?? ??  : BSP_OK:????????????????

*****************************************************************************/
u32 CPM_ComSend(CPM_LOGIC_PORT_ENUM_UINT32 enLogicPort, u8 *pucVirData, u8 *pucPHYData, u32 ulLen)
{
    if(CPM_OM_CFG_COMM == enLogicPort)
    {
        diag_PTR(EN_DIAG_PTR_CPM_COMSEND, 0, 0, 0);
    }

    /* ???????? */
    if (CPM_COMM_BUTT <= enLogicPort)
    {
        g_stCPMSndErrInfo.ulPortErr++;

        return CPM_SEND_PARA_ERR;
    }

    if ((NULL == pucVirData) || (0 == ulLen))
    {
        g_stCPMSndErrInfo.astCPMSndErrInfo[enLogicPort].ulParaErr++;

        return CPM_SEND_PARA_ERR;
    }

    if (NULL == CPM_LOGIC_SEND_FUNC(enLogicPort))
    {
        g_stCPMSndErrInfo.astCPMSndErrInfo[enLogicPort].ulNullPtr++;

        return CPM_SEND_FUNC_NULL;
    }

    return CPM_LOGIC_SEND_FUNC(enLogicPort)(pucVirData, pucPHYData, ulLen);
}

/*****************************************************************************
 ?? ?? ??  : CPM_ComRcv
 ????????  : ????????????????????????????????
 ????????  : enPhyPort??  ??????????
             pucData??    ??????????????
             ulLen:       ??????????????
 ????????  : ??
 ?? ?? ??  : BSP_OK:????????????????

*****************************************************************************/
u32 CPM_ComRcv(CPM_PHY_PORT_ENUM_UINT32 enPhyPort, u8 *pucData, u32 ulLen)
{
    /* ???????? */
    if (CPM_PORT_BUTT <= enPhyPort)
    {
        g_stCPMRcvErrInfo.ulPortErr++;
        diag_PTR(EN_DIAG_PTR_CPM_ERR1, 0, 0, 0);

        return (u32)BSP_ERROR;
    }

    if ((NULL == pucData) || (0 == ulLen))
    {
        g_stCPMRcvErrInfo.astCPMRcvErrInfo[enPhyPort - CPM_IND_PORT].ulParaErr++;
        diag_PTR(EN_DIAG_PTR_CPM_ERR2, 0, 0, 0);

        return (u32)BSP_ERROR;
    }

    if (NULL == CPM_PHY_RCV_FUNC(enPhyPort - CPM_IND_PORT))
    {
        diag_error("CPM_ComRcv The Phy Port %d Rec Func is NULL\n", (s32)enPhyPort);

        g_stCPMRcvErrInfo.astCPMRcvErrInfo[enPhyPort - CPM_IND_PORT].ulNullPtr++;
        diag_PTR(EN_DIAG_PTR_CPM_ERR3, 0, 0, 0);

        return (u32)BSP_ERROR;
    }

    diag_PTR(EN_DIAG_PTR_CPM_COMRCV, 0, 0, 0);

    return CPM_PHY_RCV_FUNC(enPhyPort - CPM_IND_PORT)(pucData, ulLen);
}

/*****************************************************************************
 ?? ?? ??  : CPM_Show
 ????????  : ????????????????????????????????
 ????????  : ??
 ????????  : ??
 ?? ?? ??  : ??

*****************************************************************************/
void CPM_Show(void)
{
    CPM_PHY_PORT_ENUM_UINT32    enPhyPort;
    CPM_LOGIC_PORT_ENUM_UINT32  enLogicPort;

    (void)diag_crit("CPM_Show The Logic and Phy Relation is :");

    for(enLogicPort=CPM_AT_COMM; enLogicPort<CPM_COMM_BUTT; enLogicPort++)
    {
        enPhyPort = CPM_QueryPhyPort(enLogicPort);

        if(CPM_OM_IND_COMM == enLogicPort) 
        {
            diag_crit("The Logic Port %d OM IND is connnect PHY ", enLogicPort);
        }
        else if(CPM_OM_CFG_COMM == enLogicPort) 
        {
            diag_crit("The Logic Port %d OM CFG is connnect PHY ", enLogicPort);
        }
        else
        {
            diag_crit("The Logic Port %d        is connnect PHY ", enLogicPort);
        }
        
        if((CPM_IND_PORT == enPhyPort) || (CPM_CFG_PORT == enPhyPort))
        {
            diag_crit("Port %d(USB Port).", enPhyPort);
        }
        else if((CPM_WIFI_OM_IND_PORT == enPhyPort) || (CPM_WIFI_OM_CFG_PORT == enPhyPort))
        {
            diag_crit("Port %d(socket).", enPhyPort);
        }
        else if((CPM_VCOM_IND_PORT == enPhyPort) || (CPM_VCOM_CFG_PORT == enPhyPort))
        {
            diag_crit("Port %d(netlink).", enPhyPort);
        }
        else
        {
            diag_crit("Port %d.", enPhyPort);
        }
    }

    (void)diag_crit("CPM_Show The Phy Info is :\n");

    for(enPhyPort=0; enPhyPort<(CPM_PORT_BUTT - CPM_IND_PORT); enPhyPort++)
    {
        /* ??????????????????????printk */
        diag_crit("The Phy %d Port's Rec Func is %pS.\n \
                Send Func is %pS.\n", \
                        enPhyPort, \
                        g_astCPMPhyPortCfg[enPhyPort].pRcvFunc, \
                        g_astCPMPhyPortCfg[enPhyPort].pSendFunc);
    }

    for(enLogicPort=0; enLogicPort<CPM_COMM_BUTT; enLogicPort++)
    {
        /* ??????????????????????printk */
        diag_crit("The Logic %d Port's Rec Func is %pS.\n \
                  Send Func is %pS.\n", \
                        enLogicPort, \
                        g_astCPMLogicPortCfg[enLogicPort].pRcvFunc, \
                        g_astCPMLogicPortCfg[enLogicPort].pSendFunc);
    }

    return;
}
EXPORT_SYMBOL(CPM_Show);

/*****************************************************************************
 ?? ?? ??  : CPM_ComErrShow
 ????????  : ????????????????????????????????
 ????????  : ??
 ????????  : ??
 ?? ?? ??  : ??
*****************************************************************************/
void CPM_ComErrShow(void)
{
    CPM_LOGIC_PORT_ENUM_UINT32  enLogicPort;
    CPM_PHY_PORT_ENUM_UINT32    enPhyPort;

    (void)diag_crit("CPM_ComErrShow:");

    (void)diag_crit("Logic Port Err Times: %d", g_stCPMSndErrInfo.ulPortErr);

    for (enLogicPort = 0; enLogicPort < CPM_COMM_BUTT; enLogicPort++)
    {
        diag_crit("Logic %d Port Para Err Times: %d", enLogicPort, g_stCPMSndErrInfo.astCPMSndErrInfo[enLogicPort].ulParaErr);
        diag_crit("Logic %d Port Null Ptr Times: %d", enLogicPort, g_stCPMSndErrInfo.astCPMSndErrInfo[enLogicPort].ulNullPtr);
    }

    diag_crit("Phy Port Err Times: %d", g_stCPMRcvErrInfo.ulPortErr);

    for (enPhyPort = 0; enPhyPort < (CPM_PORT_BUTT - CPM_IND_PORT); enPhyPort++)
    {
        diag_crit("Phy %d Port Para Err Times: %d", enPhyPort, g_stCPMRcvErrInfo.astCPMRcvErrInfo[enPhyPort].ulParaErr);
        diag_crit("Phy %d Port Null Ptr Times: %d", enPhyPort, g_stCPMRcvErrInfo.astCPMRcvErrInfo[enPhyPort].ulNullPtr);
    }

    return;
}
EXPORT_SYMBOL(CPM_ComErrShow);

