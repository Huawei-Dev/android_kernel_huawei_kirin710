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
#include "ATCmdProc.h"

#include "PppInterface.h"
#include "AtUsbComItf.h"
#include "AtInputProc.h"
#include "AtCsdInterface.h"
#include "AtTafAgentInterface.h"
#include "TafAgentInterface.h"
#include "AtCmdMsgProc.h"
#include "AtDataProc.h"
#include "ImmInterface.h"
#include "mdrv.h"
#include "AtMntn.h"
#include "AcpuReset.h"

#include "AtInternalMsg.h"


/*****************************************************************************
    ??????????????????????.C??????????
*****************************************************************************/
#define    THIS_FILE_ID        PS_FILE_ID_AT_INPUTPROC_C

/*****************************************************************************
   2 ????????????
*****************************************************************************/
VOS_UINT32                              g_ulAtUsbDebugFlag = VOS_FALSE;

extern VOS_UINT32 CBTCPM_NotifyChangePort(AT_PHY_PORT_ENUM_UINT32 enPhyPort);


/* AT/DIAG?????????????? */
VOS_UINT8                               gucOmDiagIndex    = AT_MAX_CLIENT_NUM;

/* USB NCM??UDI???? */
UDI_HANDLE                              g_ulAtUdiNdisHdl  = UDI_INVALID_HANDLE;

/* ????????????????USB-MODEM, HSIC-MODEM??HS-UART??????????????????????????PL???? */
UDI_HANDLE                              g_alAtUdiHandle[AT_CLIENT_BUTT] = {UDI_INVALID_HANDLE};

/* AT????????DRV ???????????????? */
AT_UART_FORMAT_PARAM_STRU               g_astAtUartFormatTab[] =
{
    /* auto detect (not support) */

    /* 8 data 2 stop */
    {AT_UART_FORMAT_8DATA_2STOP,            AT_UART_DATA_LEN_8_BIT,
     AT_UART_STOP_LEN_2_BIT,                AT_UART_PARITY_LEN_0_BIT},

    /* 8 data 1 parity 1 stop*/
    {AT_UART_FORMAT_8DATA_1PARITY_1STOP,    AT_UART_DATA_LEN_8_BIT,
     AT_UART_STOP_LEN_1_BIT,                AT_UART_PARITY_LEN_1_BIT},

    /* 8 data 1 stop */
    {AT_UART_FORMAT_8DATA_1STOP,            AT_UART_DATA_LEN_8_BIT,
     AT_UART_STOP_LEN_1_BIT,                AT_UART_PARITY_LEN_0_BIT},

    /* 7 data 2 stop */
    {AT_UART_FORMAT_7DATA_2STOP,            AT_UART_DATA_LEN_7_BIT,
     AT_UART_STOP_LEN_2_BIT,                AT_UART_PARITY_LEN_0_BIT},

    /* 7 data 1 parity 1 stop */
    {AT_UART_FORMAT_7DATA_1PARITY_1STOP,    AT_UART_DATA_LEN_7_BIT,
     AT_UART_STOP_LEN_1_BIT,                AT_UART_PARITY_LEN_1_BIT},

    /* 7 data 1 stop */
    {AT_UART_FORMAT_7DATA_1STOP,            AT_UART_DATA_LEN_7_BIT,
     AT_UART_STOP_LEN_1_BIT,                AT_UART_PARITY_LEN_0_BIT}
};


/*****************************************************************************
   3 ??????????????
*****************************************************************************/

/*****************************************************************************
   4 ????????
*****************************************************************************/


VOS_VOID AT_GetAtMsgStruMsgLength(
    VOS_UINT32                          ulInfoLength,
    VOS_UINT32                         *pulMsgLength
)
{
    if (ulInfoLength > 4)
    {
        *pulMsgLength = (sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH)
                      + (ulInfoLength - 4);
    }
    else
    {
        *pulMsgLength = sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH;
    }

    return;
}


VOS_VOID AT_GetUserTypeFromIndex(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                          *pucUserType
)
{
    if (ucIndex < AT_MAX_CLIENT_NUM)
    {
        *pucUserType    = gastAtClientTab[ucIndex].UserType;
    }
    else
    {
        *pucUserType    = AT_BUTT_USER;
    }

    return;
}


VOS_VOID AT_VcomCmdStreamEcho(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                          *pData,
    VOS_UINT16                          usLen
)
{
    VOS_UINT8                          *pucSystemAppConfig;

    pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

    /* E5???????????? */
    /* AGPS???????????? */
    if ( (SYSTEM_APP_WEBUI != *pucSystemAppConfig)
      && (AT_CLIENT_TAB_APP9_INDEX != ucIndex)
      && (AT_CLIENT_TAB_APP12_INDEX != ucIndex)
      && (AT_CLIENT_TAB_APP24_INDEX != ucIndex)
    )
    {
        APP_VCOM_Send(gastAtClientTab[ucIndex].ucPortNo, pData, usLen);
    }

    return;
}


VOS_VOID AT_SetAts3Value(VOS_UINT8 ucValue)
{
    if (VOS_TRUE == g_ulAtUsbDebugFlag)
    {
        ucAtS3 = ucValue;
    }

    return;
}


VOS_VOID AT_CmdStreamEcho(
    VOS_UINT8                           ucIndex,
    VOS_UINT8*                          pData,
    VOS_UINT16                          usLen
)
{
    VOS_UINT32                          ulMuxUserFlg;
    VOS_UINT32                          ulHsicUserFlg;
    VOS_UINT16                          usEchoLen;

    ulHsicUserFlg = AT_CheckHsicUser(ucIndex);
    ulMuxUserFlg  = AT_CheckMuxUser(ucIndex);

    /* ????pData????????????????<CR><LF>????????????2?????????????????????? */
    if ((usLen > 2) && (ucAtS3 == pData[usLen - 2]) && (ucAtS4 == pData[usLen - 1]))
    {
        /* ??????????<LF>???? */
        usEchoLen = usLen - 1;
    }
    else
    {
        usEchoLen = usLen;
    }

    if(AT_USBCOM_USER == gastAtClientTab[ucIndex].UserType)
    {
        /*??USB COM??????????*/
        DMS_COM_SEND(AT_USB_COM_PORT_NO, pData, usEchoLen);
        AT_MNTN_TraceCmdResult(ucIndex, pData, usEchoLen);
    }
    else if (AT_CTR_USER == gastAtClientTab[ucIndex].UserType)
    {
        DMS_COM_SEND(AT_CTR_PORT_NO, pData, usEchoLen);
        AT_MNTN_TraceCmdResult(ucIndex, pData, usEchoLen);
    }
    else if(AT_PCUI2_USER == gastAtClientTab[ucIndex].UserType)
    {
        /*??PCUI2??????????*/
        DMS_COM_SEND(AT_PCUI2_PORT_NO, pData, usEchoLen);
        AT_MNTN_TraceCmdResult(ucIndex, pData, usEchoLen);
    }
    else if (AT_MODEM_USER == gastAtClientTab[ucIndex].UserType)
    {
        AT_SendDataToModem(ucIndex, pData, usEchoLen);
    }
    else if (AT_APP_USER == gastAtClientTab[ucIndex].UserType)
    {
        /* VCOM AT???????????? */
        AT_VcomCmdStreamEcho(ucIndex, pData, usEchoLen);
    }
    else if (AT_SOCK_USER == gastAtClientTab[ucIndex].UserType)
    {
        if ( BSP_MODULE_SUPPORT == mdrv_misc_support_check(BSP_MODULE_TYPE_WIFI) )
        {
            mdrv_CPM_ComSend(CPM_AT_COMM, pData, VOS_NULL_PTR, usEchoLen);
        }
    }
    else if (AT_NDIS_USER == gastAtClientTab[ucIndex].UserType)
    {
        /* NDIS AT?????????? */
        AT_WARN_LOG("AT_CmdStreamEcho:WARNING: NDIS AT");
    }
    else if (VOS_TRUE == ulHsicUserFlg)
    {
    }
    else if (VOS_TRUE == ulMuxUserFlg)
    {
        /* MUX user */
        AT_MuxCmdStreamEcho(ucIndex, pData, usEchoLen);
    }
    else
    {
        AT_LOG1("AT_CmdStreamEcho:WARNING: Abnormal UserType,ucIndex:",ucIndex);
    }

    return;
}


VOS_UINT32 At_CmdStreamPreProc(VOS_UINT8 ucIndex, VOS_UINT8* pData, VOS_UINT16 usLen)
{
    VOS_UINT8                          *pHead = TAF_NULL_PTR;
    VOS_UINT16                          usCount = 0;
    VOS_UINT16                          usTotal = 0;

    pHead = pData;

    if (VOS_TRUE == g_ulAtUsbDebugFlag)
    {
        PS_PRINTF("At_CmdStreamPreProc: AtEType = %d, UserType = %d, ucAtS3 = %d\r\n",
                   gucAtEType, gastAtClientTab[ucIndex].UserType, ucAtS3);
    }

    /* ???????????? */
    if( AT_E_ECHO_CMD == gucAtEType )
    {
        AT_CmdStreamEcho(ucIndex, pData, usLen);
    }

    /* MAC????????MP????????:AT+CMGS=**<CR><^z><Z>(??AT+CMGW=**<CR><^z><Z>)
       ??????????????????????????????????????????????
       ??????????????????????<^z><Z>???? */
    AT_DiscardInvalidCharForSms(pData, &usLen);

    /* ??????????????????????????????????????AT????????????: <CR>/<ctrl-z>/<ESC> */
    while(usCount++ < usLen)
    {
        if (At_CheckSplitChar((*((pData + usCount) - 1))))
        {
            if(g_aucAtDataBuff[ucIndex].ulBuffLen > 0)
            {
                if((g_aucAtDataBuff[ucIndex].ulBuffLen + usCount) >= AT_COM_BUFF_LEN)
                {
                    g_aucAtDataBuff[ucIndex].ulBuffLen = 0;
                    return AT_FAILURE;
                }
                TAF_MEM_CPY_S(&g_aucAtDataBuff[ucIndex].aucDataBuff[g_aucAtDataBuff[ucIndex].ulBuffLen],
                    AT_COM_BUFF_LEN - g_aucAtDataBuff[ucIndex].ulBuffLen,
                    pHead,
                    usCount);
                At_SendCmdMsg(ucIndex,g_aucAtDataBuff[ucIndex].aucDataBuff, (TAF_UINT16)(g_aucAtDataBuff[ucIndex].ulBuffLen + usCount), AT_NORMAL_TYPE_MSG);
                pHead   = pData + usCount;
                usTotal = usCount;
                g_aucAtDataBuff[ucIndex].ulBuffLen = 0;
            }
            else
            {
                At_SendCmdMsg(ucIndex, pHead, usCount - usTotal, AT_NORMAL_TYPE_MSG);
                pHead   = pData + usCount;
                usTotal = usCount;
            }
        }
    }

    if(usTotal < usLen)
    {
        if((g_aucAtDataBuff[ucIndex].ulBuffLen + (usLen - usTotal)) >= AT_COM_BUFF_LEN)
        {
            g_aucAtDataBuff[ucIndex].ulBuffLen = 0;
            return AT_FAILURE;
        }
        TAF_MEM_CPY_S(&g_aucAtDataBuff[ucIndex].aucDataBuff[g_aucAtDataBuff[ucIndex].ulBuffLen],
            AT_COM_BUFF_LEN - g_aucAtDataBuff[ucIndex].ulBuffLen,
            pHead,
            (TAF_UINT32)(usLen - usTotal));
        g_aucAtDataBuff[ucIndex].ulBuffLen += (VOS_UINT16)((pData - pHead) + usLen);
    }

    return AT_SUCCESS;
}


VOS_VOID AT_StopFlowCtrl(VOS_UINT8 ucIndex)
{
    switch (gastAtClientTab[ucIndex].UserType)
    {
        case AT_MODEM_USER:
            AT_MNTN_TraceStopFlowCtrl(ucIndex, AT_FC_DEVICE_TYPE_MODEM);
            AT_CtrlCTS(ucIndex, AT_IO_LEVEL_HIGH);
            break;

        case AT_HSUART_USER:
            AT_MNTN_TraceStopFlowCtrl(ucIndex, AT_FC_DEVICE_TYPE_HSUART);
            AT_CtrlCTS(ucIndex, AT_IO_LEVEL_HIGH);
            break;

        default:
            break;
    }

    return;
}


VOS_UINT32 At_OmDataProc (
    VOS_UINT8                           ucPortNo,
    VOS_UINT8                          *pData,
    VOS_UINT16                          usLen
)
{
    VOS_UINT32                          ulRst;

    /*OM??????UART PCUI CTRL????????*/
    switch(ucPortNo)
    {
        case AT_UART_PORT_NO:
            if (VOS_NULL_PTR == g_apAtPortDataRcvFuncTab[AT_UART_PORT])
            {
                AT_ERR_LOG("At_OmDataProc: Uart port proc func is NULL!");
                return VOS_ERR;
            }

            ulRst = g_apAtPortDataRcvFuncTab[AT_UART_PORT](pData, usLen);
            break;

        case AT_USB_COM_PORT_NO:
            if (VOS_NULL_PTR == g_apAtPortDataRcvFuncTab[AT_PCUI_PORT])
            {
                AT_ERR_LOG("At_OmDataProc: PCUI proc func is NULL!");
                return VOS_ERR;
            }

            ulRst = g_apAtPortDataRcvFuncTab[AT_PCUI_PORT](pData, usLen);
            break;

        case AT_CTR_PORT_NO:
            if (VOS_NULL_PTR == g_apAtPortDataRcvFuncTab[AT_CTRL_PORT])
            {
                AT_ERR_LOG("At_OmDataProc: CTRL proc func is NULL!");
                return VOS_ERR;
            }

            ulRst = g_apAtPortDataRcvFuncTab[AT_CTRL_PORT](pData, usLen);
            break;

        case AT_PCUI2_PORT_NO:
            if (VOS_NULL_PTR == g_apAtPortDataRcvFuncTab[AT_PCUI2_PORT])
            {
                AT_ERR_LOG("At_OmDataProc: PCUI2 proc func is NULL!");
                return VOS_ERR;
            }

            ulRst = g_apAtPortDataRcvFuncTab[AT_PCUI2_PORT](pData, usLen);
            break;

        case AT_HSUART_PORT_NO:
            if (VOS_NULL_PTR == g_apAtPortDataRcvFuncTab[AT_HSUART_PORT])
            {
                AT_ERR_LOG("At_OmDataProc: HSUART proc func is NULL!");
                return VOS_ERR;
            }

            ulRst = g_apAtPortDataRcvFuncTab[AT_HSUART_PORT](pData, usLen);
            break;

        default:
            AT_WARN_LOG("At_OmDataProc: don't proc data of this port!");
            return VOS_ERR;
    }

    return ulRst;
}


TAF_UINT32 At_DataStreamPreProc (TAF_UINT8 ucIndex,TAF_UINT8 DataMode,TAF_UINT8* pData, TAF_UINT16 usLen)
{

    AT_LOG1("At_DataStreamPreProc ucIndex:",ucIndex);
    AT_LOG1("At_DataStreamPreProc usLen:",usLen);
    AT_LOG1("At_DataStreamPreProc DataMode:",DataMode);

    switch(DataMode)    /* ?????????????????? */
    {
        case AT_CSD_DATA_MODE:
            break;

        /*????OM??????????????????????????????????????????????????????*/
        case AT_DIAG_DATA_MODE:
        case AT_OM_DATA_MODE:
            At_OmDataProc(gastAtClientTab[ucIndex].ucPortNo, pData,usLen);
            break;

        default:
            AT_WARN_LOG("At_DataStreamPreProc DataMode Wrong!");
            break;
    }
    return AT_SUCCESS;
}


VOS_UINT32  AT_CsdDataModeRcvModemMsc(
    VOS_UINT8                           ucIndex
)
{
    TAFAGERNT_MN_CALL_INFO_STRU         astCallInfos[MN_CALL_MAX_NUM];
    VOS_UINT32                          i;
    VOS_UINT8                           ucNumOfCalls;
    VOS_UINT32                          ulRlst;


    TAF_MEM_SET_S(astCallInfos, sizeof(astCallInfos), 0x00, sizeof(astCallInfos));


    /* ??????????????????????????????VIDEO??????????????????????????????????????????????VIDEO??????
       ????????????VIDEO?????????????????????????????? */

    ulRlst          = TAF_AGENT_GetCallInfoReq(ucIndex, &ucNumOfCalls, astCallInfos);

    if(VOS_OK == ulRlst)
    {
        for (i = 0; i < ucNumOfCalls; i++)
        {
            if (MN_CALL_TYPE_VIDEO == astCallInfos[i].enCallType)
            {
                /* ???????????? */
                if (gastAtClientTab[ucIndex].CmdCurrentOpt != AT_CMD_END_SET)
                {
                    TAF_LOG1(WUEPS_PID_AT, 0, PS_LOG_LEVEL_INFO, "At_SetHPara: ulNumOfCalls is ",(TAF_INT32)ucNumOfCalls);

                    if(AT_SUCCESS == MN_CALL_End(gastAtClientTab[ucIndex].usClientId,
                                                 0,
                                                 astCallInfos[i].callId,
                                                 VOS_NULL_PTR))
                    {
                        gastAtClientTab[ucIndex].CmdCurrentOpt = AT_CMD_END_SET;
                        return AT_SUCCESS;
                    }
                    else
                    {
                        return AT_ERROR;
                    }
                }
                else
                {
                    /* ??????????????????????????????????DTR?????????????????????? */
                    return AT_SUCCESS;
                }
            }
        }
    }


    return AT_CME_UNKNOWN;
}


VOS_UINT32  AT_PppDataModeRcvModemMsc(
    VOS_UINT8                           ucIndex,
    AT_DCE_MSC_STRU                     *pMscStru
)
{
    /* 1.????(AT_CMD_PS_DATA_CALL_END_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
         ??????:????????????????????????????PDP DEACTIVE??????????????????DTR????
         ????????????????????
        2.????????????????:????????????????,????????PPP??????????PPP??????????????
          ??????????????DTR????????????????PPP????????
    */
    if (pMscStru->OP_Dtr && (0 == pMscStru->ucDtr))
    {
        if ( (AT_CMD_PS_DATA_CALL_END_SET      == gastAtClientTab[ucIndex].CmdCurrentOpt)
          || (AT_CMD_WAIT_PPP_PROTOCOL_REL_SET == gastAtClientTab[ucIndex].CmdCurrentOpt) )
        {
            return AT_SUCCESS;
        }

        /* ????????????????????PPP????????????????????????UE??????
           UE??????DTR??????????????,????PPP????????????*/
        if (0 == (gastAtClientTab[ucIndex].ModemStatus & IO_CTRL_CTS))
        {
            AT_StopFlowCtrl((TAF_UINT8)ucIndex);
        }

        /*??PPP????????PPP????*/
        PPP_RcvAtCtrlOperEvent(gastAtClientTab[ucIndex].usPppId, PPP_AT_CTRL_REL_PPP_REQ);

        /*??PPP????HDLC??????????*/
        PPP_RcvAtCtrlOperEvent(gastAtClientTab[ucIndex].usPppId, PPP_AT_CTRL_HDLC_DISABLE);

        /* ????Modem????AT??????????AT?????????????????? */
        AT_STOP_TIMER_CMD_READY(ucIndex);

        /*EVENT - RCV Down DTR to Disconnect PPP in Abnormal procedure(PDP type:IP) ;index*/
        AT_EventReport(WUEPS_PID_AT, NAS_OM_EVENT_DTE_DOWN_DTR_RELEASE_PPP_IP_TYPE,
                        &ucIndex, sizeof(ucIndex));

        if ( VOS_OK == TAF_PS_CallEnd(WUEPS_PID_AT,
                                      AT_PS_BuildExClientId(gastAtClientTab[ucIndex].usClientId),
                                      0,
                                      gastAtClientTab[ucIndex].ucCid) )
        {
            /* ???????? */
            if (AT_SUCCESS != At_StartTimer(AT_SET_PARA_TIME, ucIndex))
            {
                AT_ERR_LOG("At_UsbModemStatusPreProc:ERROR:Start Timer");
                return AT_FAILURE;
            }

            /* ???????????????? */
            gastAtClientTab[ucIndex].CmdCurrentOpt = AT_CMD_PS_DATA_CALL_END_SET;
        }
        else
        {
            return AT_FAILURE;
        }
    }

    return AT_SUCCESS;
}


VOS_UINT32  AT_IpDataModeRcvModemMsc(
    VOS_UINT8                           ucIndex,
    AT_DCE_MSC_STRU                     *pMscStru
)
{
    if (pMscStru->OP_Dtr && (0 == pMscStru->ucDtr))
    {
        /*??????????????????????????????*/
        if (0 == (gastAtClientTab[ucIndex].ModemStatus & IO_CTRL_CTS))
        {
            AT_StopFlowCtrl((TAF_UINT8)ucIndex);
        }

        PPP_RcvAtCtrlOperEvent(gastAtClientTab[ucIndex].usPppId, PPP_AT_CTRL_REL_PPP_RAW_REQ);

        /*??PPP????HDLC??????????*/
        PPP_RcvAtCtrlOperEvent(gastAtClientTab[ucIndex].usPppId, PPP_AT_CTRL_HDLC_DISABLE);

        /* ????Modem????AT??????????AT?????????????????? */
        AT_STOP_TIMER_CMD_READY(ucIndex);;

        /*EVENT - RCV Down DTR to Disconnect PPP in Abnormal procedure(PDP type:PPP) ;index*/
        AT_EventReport(WUEPS_PID_AT, NAS_OM_EVENT_DTE_DOWN_DTR_RELEASE_PPP_PPP_TYPE,
                        &ucIndex, sizeof(ucIndex));

        if ( VOS_OK == TAF_PS_CallEnd(WUEPS_PID_AT,
                                      AT_PS_BuildExClientId(gastAtClientTab[ucIndex].usClientId),
                                      0,
                                      gastAtClientTab[ucIndex].ucCid) )
        {
            gastAtClientTab[ucIndex].CmdCurrentOpt = AT_CMD_PS_DATA_CALL_END_SET;
            return AT_SUCCESS;
        }
        else
        {
            return AT_FAILURE;
        }
    }

    return AT_SUCCESS;
}


VOS_VOID AT_MODEM_ProcDtrChange(
    VOS_UINT8                           ucIndex,
    AT_DCE_MSC_STRU                    *pstDceMsc
)
{
    if (1 == pstDceMsc->ucDtr)
    {
        /*????DSR??CTS????*/
        AT_CtrlDSR(ucIndex, AT_IO_LEVEL_HIGH);
        AT_StopFlowCtrl(ucIndex);
    }
    else
    {
        /* ????Q??????DSR??????????????????????????????????????DTR????????DSR??
           ??????PC????????????????????????DTR??????????????????????????????
           ????UE??????DTR???? ??????????????DCD???? */
        if ( (AT_DATA_MODE == gastAtClientTab[ucIndex].Mode)
          && (AT_CSD_DATA_MODE == gastAtClientTab[ucIndex].DataMode) )
        {
            g_ucDtrDownFlag = VOS_TRUE;
        }

        AT_CtrlDCD(ucIndex, AT_IO_LEVEL_LOW);
    }

}


VOS_UINT32 AT_MODEM_WriteMscCmd(
    VOS_UINT8                           ucIndex,
    AT_DCE_MSC_STRU                    *pstDceMsc
)
{
    UDI_HANDLE                          lUdiHandle;
    VOS_INT32                           lResult;

    /* ????UDI?????????? */
    lUdiHandle = g_alAtUdiHandle[ucIndex];
    if (UDI_INVALID_HANDLE == lUdiHandle)
    {
        AT_ERR_LOG("AT_MODEM_WriteMscCmd: Invalid UDI handle!");
        return AT_FAILURE;
    }

    /* ?????????? */
    lResult = mdrv_udi_ioctl(lUdiHandle, ACM_MODEM_IOCTL_MSC_WRITE_CMD, pstDceMsc);
    if (VOS_OK != lResult)
    {
        AT_ERR_LOG("AT_MODEM_WriteMscCmd: Write failed!");
        return AT_FAILURE;
    }

    return AT_SUCCESS;
}


VOS_UINT32 AT_MODEM_StartFlowCtrl(
    VOS_UINT32                          ulParam1,
    VOS_UINT32                          ulParam2
)
{
    VOS_UINT8                           ucIndex;

    for (ucIndex = 0; ucIndex < AT_MAX_CLIENT_NUM; ucIndex++)
    {
        if ( (AT_MODEM_USER == gastAtClientTab[ucIndex].UserType)
          && (AT_DATA_MODE == gastAtClientTab[ucIndex].Mode) )
        {
            if ( (AT_PPP_DATA_MODE == gastAtClientTab[ucIndex].DataMode)
              || (AT_IP_DATA_MODE == gastAtClientTab[ucIndex].DataMode)
              || (AT_CSD_DATA_MODE == gastAtClientTab[ucIndex].DataMode) )
            {
                AT_MNTN_TraceStartFlowCtrl(ucIndex, AT_FC_DEVICE_TYPE_MODEM);
                AT_CtrlCTS(ucIndex, AT_IO_LEVEL_LOW);
            }
        }
    }

    return AT_SUCCESS;
}


VOS_UINT32 AT_MODEM_StopFlowCtrl(
    VOS_UINT32                          ulParam1,
    VOS_UINT32                          ulParam2
)
{
    VOS_UINT8                           ucIndex;

    for(ucIndex = 0; ucIndex < AT_MAX_CLIENT_NUM; ucIndex++)
    {
        if ( (AT_MODEM_USER == gastAtClientTab[ucIndex].UserType)
          && (AT_DATA_MODE == gastAtClientTab[ucIndex].Mode) )
        {
            if ( (AT_PPP_DATA_MODE == gastAtClientTab[ucIndex].DataMode)
                || (AT_IP_DATA_MODE == gastAtClientTab[ucIndex].DataMode)
                || (AT_CSD_DATA_MODE == gastAtClientTab[ucIndex].DataMode) )
            {
                AT_MNTN_TraceStopFlowCtrl(ucIndex, AT_FC_DEVICE_TYPE_MODEM);
                AT_CtrlCTS(ucIndex, AT_IO_LEVEL_HIGH);
            }
        }
    }

    return AT_SUCCESS;
}


VOS_UINT32 AT_ModemStatusPreProc(
    VOS_UINT8                           ucIndex,
    AT_DCE_MSC_STRU                    *pMscStru
)
{

    NAS_OM_EVENT_ID_ENUM_UINT16         enEventId;




    if (VOS_NULL_PTR == pMscStru)
    {
        return AT_FAILURE;
    }

    if (pMscStru->OP_Dtr)
    {
        enEventId = (0 != pMscStru->ucDtr) ?
                    NAS_OM_EVENT_DTE_UP_DTR : NAS_OM_EVENT_DTE_DOWN_DTR;

        AT_EventReport(WUEPS_PID_AT, enEventId, &ucIndex, sizeof(VOS_UINT8));

        if (VOS_TRUE == AT_CheckModemUser(ucIndex))
        {
            AT_MODEM_ProcDtrChange(ucIndex, pMscStru);
        }

    }

    /* ????????????MSC???? */
    if ( (AT_DATA_MODE == gastAtClientTab[ucIndex].Mode)
      || (AT_ONLINE_CMD_MODE == gastAtClientTab[ucIndex].Mode) )
    {
        switch (gastAtClientTab[ucIndex].DataMode)
        {
        case AT_CSD_DATA_MODE:
            if ((pMscStru->OP_Dtr) && (0 == pMscStru->ucDtr))
            {
                AT_CsdDataModeRcvModemMsc(ucIndex);
            }
            return AT_SUCCESS;

        case AT_PPP_DATA_MODE:
            return AT_PppDataModeRcvModemMsc(ucIndex, pMscStru);

        case AT_IP_DATA_MODE:
            return AT_IpDataModeRcvModemMsc(ucIndex, pMscStru);

        default:
            AT_WARN_LOG("At_UsbModemStatusPreProc: DataMode Wrong!");
            break;
        }
    }
    else
    {
         /* ??????????????????????????????????????????????????????????
            ????????????CSD???????????????????? */
         if ((pMscStru->OP_Dtr) && (0 == pMscStru->ucDtr))
         {
             AT_CsdDataModeRcvModemMsc(ucIndex);
         }
    }

    return AT_SUCCESS;
}


VOS_VOID AT_ModemSetCtlStatus(
    VOS_UINT8                           ucIndex,
    AT_DCE_MSC_STRU                    *pMscStru
)
{
    if (TAF_NULL_PTR == pMscStru)
    {
        return;
    }

    /*????dsr????*/
    if ( pMscStru->OP_Dsr )
    {
        if ( 1 == pMscStru->ucDsr )
        {
            gastAtClientTab[ucIndex].ModemStatus |= IO_CTRL_DSR;
        }
        else
        {
            gastAtClientTab[ucIndex].ModemStatus &= ~IO_CTRL_DSR;
        }
    }

    /*????CTS????*/
    if ( pMscStru->OP_Cts )
    {
        if ( 1 == pMscStru->ucCts )
        {
            gastAtClientTab[ucIndex].ModemStatus |= IO_CTRL_CTS;
        }
        else
        {
            gastAtClientTab[ucIndex].ModemStatus &= ~IO_CTRL_CTS;
        }
    }

    /*????RI????*/
    if ( pMscStru->OP_Ri )
    {
        if ( 1 == pMscStru->ucRi )
        {
            gastAtClientTab[ucIndex].ModemStatus |= IO_CTRL_RI;
        }
        else
        {
            gastAtClientTab[ucIndex].ModemStatus &= ~IO_CTRL_RI;
        }
    }

    /*????DCD????*/
    if ( pMscStru->OP_Dcd )
    {
        if ( 1 == pMscStru->ucDcd )
        {
            gastAtClientTab[ucIndex].ModemStatus |= IO_CTRL_DCD;
        }
        else
        {
            gastAtClientTab[ucIndex].ModemStatus &= ~IO_CTRL_DCD;
        }
    }

    /*????FC????*/
    if ( pMscStru->OP_Fc )
    {
        if ( 1 == pMscStru->ucFc )
        {
            gastAtClientTab[ucIndex].ModemStatus |= IO_CTRL_FC;
        }
        else
        {
            gastAtClientTab[ucIndex].ModemStatus &= ~IO_CTRL_FC;
        }
    }

}


VOS_UINT32 AT_SetModemStatus(
    VOS_UINT8                           ucIndex,
    AT_DCE_MSC_STRU                    *pstMsc
)
{
    VOS_UINT32                          ulResult;

    if (VOS_NULL_PTR == pstMsc)
    {
        return AT_FAILURE;
    }

    if (ucIndex >= AT_CLIENT_BUTT)
    {
        return AT_FAILURE;
    }

    /* ????????????????*/
    AT_ModemSetCtlStatus(ucIndex, pstMsc);

    /* ???????????????????? */
    AT_MNTN_TraceOutputMsc(ucIndex, pstMsc);

    /* ???????????????? */
    switch (gastAtClientTab[ucIndex].UserType)
    {
        case AT_MODEM_USER:
            ulResult = AT_MODEM_WriteMscCmd(ucIndex, pstMsc);
            break;


        default:
            ulResult = AT_SUCCESS;
            break;
    }

    return ulResult;
}

/* ????At_SetModemStatusForFC????, ??????At_SetModemStatus???? */


VOS_UINT32 At_ModemEst (
    VOS_UINT8                           ucIndex,
    AT_CLIENT_ID_ENUM_UINT16            usClientId,
    VOS_UINT8                           ucPortNo
)
{

    /* ???????????? */
    TAF_MEM_SET_S(&gastAtClientTab[ucIndex], sizeof(AT_CLIENT_MANAGE_STRU), 0x00, sizeof(AT_CLIENT_MANAGE_STRU));

    /* ???????????? */
    gastAtClientTab[ucIndex].usClientId      = usClientId;
    gastAtClientTab[ucIndex].ucPortType      = ucPortNo;
    gastAtClientTab[ucIndex].ucDlci          = AT_MODEM_USER_DLCI;
    gastAtClientTab[ucIndex].ucPortNo        = ucPortNo;
    gastAtClientTab[ucIndex].UserType        = AT_MODEM_USER;
    gastAtClientTab[ucIndex].ucUsed          = AT_CLIENT_USED;

    /* ??????????????????????PS_MEMSET???????????????????????? */
    gastAtClientTab[ucIndex].Mode            = AT_CMD_MODE;
    gastAtClientTab[ucIndex].IndMode         = AT_IND_MODE;
    gastAtClientTab[ucIndex].DataMode        = AT_DATA_BUTT_MODE;
    gastAtClientTab[ucIndex].DataState       = AT_DATA_STOP_STATE;
    gastAtClientTab[ucIndex].CmdCurrentOpt   = AT_CMD_CURRENT_OPT_BUTT;
    g_stParseContext[ucIndex].ucClientStatus = AT_FW_CLIENT_STATUS_READY;

    AT_LOG1("At_ModemEst ucIndex:",ucIndex);

    return AT_SUCCESS;
}


VOS_UINT32 At_ModemMscInd (
    VOS_UINT8                           ucIndex,
    VOS_UINT8                           ucDlci,
    AT_DCE_MSC_STRU                    *pMscStru
)
{
    AT_PPP_MODEM_MSC_IND_MSG_STRU      *pMsg;
    VOS_UINT32                          ulLength;
    VOS_UINT_PTR                        ulTmpAddr;

    ulLength = (sizeof(AT_PPP_MODEM_MSC_IND_MSG_STRU) - VOS_MSG_HEAD_LENGTH)
               + (sizeof(AT_DCE_MSC_STRU) - 4);
    /*lint -save -e830*/
    pMsg = ( AT_PPP_MODEM_MSC_IND_MSG_STRU * )PS_ALLOC_MSG( PS_PID_APP_PPP, ulLength );
    /*lint -restore */
    if ( VOS_NULL_PTR == pMsg )
    {
        /*????????????---??????????????:*/
        AT_WARN_LOG("At_ModemMscInd: Alloc AT_PPP_MODEM_MSC_IND_MSG_STRU msg fail!");
        return AT_FAILURE;
    }

    /*??????????:*/
    pMsg->MsgHeader.ulSenderCpuId   = VOS_LOCAL_CPUID;
    pMsg->MsgHeader.ulSenderPid     = PS_PID_APP_PPP;
    pMsg->MsgHeader.ulReceiverCpuId = VOS_LOCAL_CPUID;
    pMsg->MsgHeader.ulReceiverPid   = WUEPS_PID_AT;
    pMsg->MsgHeader.ulLength        = ulLength;
    pMsg->MsgHeader.ulMsgName       = AT_PPP_MODEM_MSC_IND_MSG;

    /*??????????*/
    pMsg->ucIndex                   = ucIndex;
    pMsg->ucDlci                    = ucDlci;

    /* ???????????? */
    ulTmpAddr = (VOS_UINT_PTR)(pMsg->aucMscInd);

    TAF_MEM_CPY_S((VOS_VOID *)ulTmpAddr, sizeof(AT_DCE_MSC_STRU), (VOS_UINT8 *)pMscStru, sizeof(AT_DCE_MSC_STRU));

    /* ???????? */
    if ( VOS_OK != PS_SEND_MSG( PS_PID_APP_PPP, pMsg ) )
    {
        /*????????????---????????????:*/
        AT_WARN_LOG( "At_ModemMscInd:WARNING:SEND AT_PPP_MODEM_MSC_IND_MSG_STRU msg FAIL!" );
        return AT_FAILURE;
    }

    return AT_SUCCESS;
}


VOS_UINT32 AT_ModemGetUlDataBuf(
    VOS_UINT8                           ucIndex,
    IMM_ZC_STRU                       **ppstBuf
)
{
    ACM_WR_ASYNC_INFO                   stCtlParam;
    VOS_INT32                           ulResult;


    TAF_MEM_SET_S(&stCtlParam, sizeof(stCtlParam), 0x00, sizeof(stCtlParam));



    /* ????????????????buffer */
    ulResult = mdrv_udi_ioctl(g_alAtUdiHandle[ucIndex], ACM_IOCTL_GET_RD_BUFF, &stCtlParam);

    if ( VOS_OK != ulResult )
    {
        AT_ERR_LOG1("AT_ModemGetUlDataBuf, WARNING, Get modem buffer failed code %d!",
                  ulResult);
        AT_MODEM_DBG_UL_GET_RD_FAIL_NUM(1);
        return AT_FAILURE;
    }

    if (VOS_NULL_PTR == stCtlParam.pVirAddr)
    {
        AT_ERR_LOG("AT_ModemGetUlDataBuf, WARNING, Data buffer error");
        AT_MODEM_DBG_UL_INVALID_RD_NUM(1);
        return AT_FAILURE;
    }

    AT_MODEM_DBG_UL_GET_RD_SUCC_NUM(1);

    *ppstBuf = (IMM_ZC_STRU *)stCtlParam.pVirAddr;

    return AT_SUCCESS;
}


VOS_UINT32 At_ModemDataInd(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                           ucDlci,
    IMM_ZC_STRU                        *pstData
)
{
    AT_DCE_MSC_STRU                     stMscStru;
    VOS_UINT32                          ulRet;
    /* pData?????????????? */
    VOS_UINT8                          *pData;
    /* usLen???????????????? */
    VOS_UINT16                          usLen;

    /* ????index??Dlci???????? */
    if (AT_CLIENT_TAB_MODEM_INDEX != ucIndex)
    {
        /*????????*/
        AT_ModemFreeUlDataBuf(ucIndex, pstData);
        return AT_FAILURE;
    }

    /* ??pstData(IMM_ZC_STRU????)????????????????????????????????pData??usLen?? */
    pData = pstData->data;
    usLen = (VOS_UINT16)pstData->len;

    if ( AT_CMD_MODE == gastAtClientTab[ucIndex].Mode )
    {
        /*??Modem??????????????????????????????????PPP??????????????*/
        if ((usLen > 0) && (0x7e == pData[0]) && (0x7e == pData[usLen - 1]))
        {
            /*????BSP????*/
            AT_ModemFreeUlDataBuf(ucIndex, pstData);
            return AT_SUCCESS;
        }

        ulRet = At_CmdStreamPreProc(ucIndex,pData,usLen);

        /*????BSP????*/
        AT_ModemFreeUlDataBuf(ucIndex, pstData);
        return ulRet;
    }

    /* ????modem????????????????*/
    switch ( gastAtClientTab[ucIndex].DataMode )
    {
        case AT_PPP_DATA_MODE:

            /* (AT2D17549)????MAC 10.6.2????????????????????.????????????????
               ????????????"+++"????????????DTR??????????????
            */
            if (3 == usLen)
            {
                if (('+' == pData[0]) && ('+' == pData[1]) && ('+' == pData[2]))
                {
                    /*????????DTR????*/
                    TAF_MEM_SET_S(&stMscStru, (VOS_SIZE_T)sizeof(stMscStru), 0x00, (VOS_SIZE_T)sizeof(stMscStru));
                    stMscStru.OP_Dtr = 1;
                    stMscStru.ucDtr  = 0;
                    At_ModemMscInd(ucIndex, ucDlci, &stMscStru);
                    break;
                }
            }
            /* PPP???????????????? */
            PPP_PullPacketEvent(gastAtClientTab[ucIndex].usPppId, pstData);
            return AT_SUCCESS;

        case AT_IP_DATA_MODE:
            if (3 == usLen)
            {
                if (('+' == pData[0]) && ('+' == pData[1]) && ('+' == pData[2]))
                {
                    /*????????DTR????*/
                    TAF_MEM_SET_S(&stMscStru, (VOS_SIZE_T)sizeof(stMscStru), 0x00, (VOS_SIZE_T)sizeof(stMscStru));
                    stMscStru.OP_Dtr = 1;
                    stMscStru.ucDtr  = 0;
                    At_ModemMscInd(ucIndex, ucDlci, &stMscStru);
                    break;
                }
            }
            /* PPP???????????????? */
            PPP_PullRawDataEvent(gastAtClientTab[ucIndex].usPppId, pstData);
            return AT_SUCCESS;

        /* Modified by s62952 for AT Project??2011-10-17,  Begin*/
        case AT_CSD_DATA_MODE:
         /* Modified by s62952 for AT Project??2011-10-17,  end*/

        default:
            AT_WARN_LOG("At_ModemDataInd: DataMode Wrong!");
            break;
    }

    /*????????*/
    AT_ModemFreeUlDataBuf(ucIndex, pstData);
    return AT_SUCCESS;
}


VOS_UINT32 AT_ModemInitUlDataBuf(
    VOS_UINT8                           ucIndex,
    VOS_UINT32                          ulEachBuffSize,
    VOS_UINT32                          ulTotalBuffNum
)
{
    ACM_READ_BUFF_INFO                  stReadBuffInfo;
    VOS_INT32                           ulResult;


    /* ?????????????????????? */
    stReadBuffInfo.u32BuffSize = ulEachBuffSize;
    stReadBuffInfo.u32BuffNum  = ulTotalBuffNum;

    ulResult= mdrv_udi_ioctl(g_alAtUdiHandle[ucIndex], ACM_IOCTL_RELLOC_READ_BUFF, &stReadBuffInfo);

    if ( VOS_OK != ulResult )
    {
        AT_ERR_LOG1("AT_ModemInitUlDataBuf, WARNING, Initialize data buffer failed code %d!\r\n",
                  ulResult);

        return AT_FAILURE;
    }

    return AT_SUCCESS;
}


VOS_UINT32 AT_ModemFreeUlDataBuf(
    VOS_UINT8                           ucIndex,
    IMM_ZC_STRU                        *pstBuf
)
{
    ACM_WR_ASYNC_INFO                   stCtlParam;
    VOS_INT32                           ulResult;

    /* ?????????????????????? */
    stCtlParam.pVirAddr = (VOS_CHAR*)pstBuf;
    stCtlParam.pPhyAddr = VOS_NULL_PTR;
    stCtlParam.u32Size  = 0;
    stCtlParam.pDrvPriv = VOS_NULL_PTR;

    ulResult = mdrv_udi_ioctl(g_alAtUdiHandle[ucIndex], ACM_IOCTL_RETURN_BUFF, &stCtlParam);

    if ( VOS_OK != ulResult )
    {
        AT_ERR_LOG1("AT_ModemFreeUlDataBuf, ERROR, Return modem buffer failed, code %d!\r\n",
                  ulResult);
        AT_MODEM_DBG_UL_RETURN_BUFF_FAIL_NUM(1);
        return AT_FAILURE;
    }

    AT_MODEM_DBG_UL_RETURN_BUFF_SUCC_NUM(1);

    return AT_SUCCESS;
}


VOS_VOID AT_ModemFreeDlDataBuf(
    VOS_CHAR                           *pstBuf
)
{
    AT_MODEM_DBG_DL_FREE_BUFF_NUM(1);

    /* ????pstBuf */
    IMM_ZcFree((IMM_ZC_STRU*)pstBuf);
    return;
}


VOS_UINT32 AT_ModemWriteData(
    VOS_UINT8                           ucIndex,
    IMM_ZC_STRU                        *pstBuf
)
{
    ACM_WR_ASYNC_INFO                   stCtlParam;
    VOS_INT32                           ulResult;

    /* ?????????????????? */
    stCtlParam.pVirAddr                 = (VOS_CHAR*)pstBuf;
    stCtlParam.pPhyAddr                 = VOS_NULL_PTR;
    stCtlParam.u32Size                  = 0;
    stCtlParam.pDrvPriv                 = VOS_NULL_PTR;

    if (UDI_INVALID_HANDLE == g_alAtUdiHandle[ucIndex])
    {
        AT_ModemFreeDlDataBuf((VOS_CHAR*)pstBuf);
        return AT_FAILURE;
    }

    /* ??????????????*/
    ulResult = mdrv_udi_ioctl(g_alAtUdiHandle[ucIndex], ACM_IOCTL_WRITE_ASYNC, &stCtlParam);

    if (VOS_OK != ulResult)
    {
        AT_WARN_LOG("AT_ModemWriteData: Write data failed with code!\r\n");
        AT_MODEM_DBG_DL_WRITE_ASYNC_FAIL_NUM(1);
        AT_ModemFreeDlDataBuf((VOS_CHAR*)pstBuf);
        return AT_FAILURE;
    }

    AT_MODEM_DBG_DL_WRITE_ASYNC_SUCC_NUM(1);

    return AT_SUCCESS;
}


VOS_UINT32 AT_SendDataToModem(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                          *pucDataBuf,
    VOS_UINT16                          usLen
)
{
    IMM_ZC_STRU                        *pstData;
    VOS_CHAR                           *pstZcPutData;

    pstData = VOS_NULL_PTR;

    pstData = IMM_ZcStaticAlloc((VOS_UINT16)usLen);

    if (VOS_NULL_PTR == pstData)
    {
        return AT_FAILURE;
    }

    /*????????????????????????????????*/
    pstZcPutData = (VOS_CHAR *)IMM_ZcPut(pstData, usLen);

    TAF_MEM_CPY_S(pstZcPutData, usLen, pucDataBuf, usLen);

    /*??????????MODEM????????????????????????????????*/
    if (AT_SUCCESS != AT_ModemWriteData(ucIndex, pstData))
    {
        return AT_FAILURE;
    }

    return AT_SUCCESS;
}


VOS_UINT32 AT_SendZcDataToModem(
    VOS_UINT16                          usPppId,
    IMM_ZC_STRU                        *pstDataBuf
)
{
    VOS_UINT32                          ulResult;
    VOS_UINT8                           ucIndex;

    ucIndex = gastAtPppIndexTab[usPppId];

    if ( (AT_CMD_MODE        == gastAtClientTab[ucIndex].Mode)
      || (AT_ONLINE_CMD_MODE == gastAtClientTab[ucIndex].Mode) )
    {
        IMM_ZcFree(pstDataBuf);
        return AT_FAILURE;
    }

    switch (gastAtClientTab[ucIndex].UserType)
    {
        case AT_MODEM_USER:
            ulResult = AT_ModemWriteData(ucIndex, pstDataBuf);
            break;


        default:
            IMM_ZcFree(pstDataBuf);
            ulResult = AT_FAILURE;
            break;
    }

    return ulResult;
}


VOS_UINT32 AT_SendCsdZcDataToModem(
    VOS_UINT8                           ucIndex,
    IMM_ZC_STRU                        *pstDataBuf
)
{
    /*??????????MODEM????????????????????????????????*/
    if (AT_SUCCESS != AT_ModemWriteData(ucIndex, pstDataBuf))
    {
        return AT_FAILURE;
    }

    return AT_SUCCESS;
}


VOS_VOID AT_UsbModemEnableCB(VOS_UINT32 ulEnable)
{
    VOS_UINT8                           ucIndex;

    ucIndex = AT_CLIENT_TAB_MODEM_INDEX;

    AT_ModemeEnableCB(ucIndex, ulEnable);

    return;
}


VOS_VOID AT_UsbModemReadDataCB( VOS_VOID )
{
    VOS_UINT8                           ucIndex;
    VOS_UINT8                           ucDlci;
    IMM_ZC_STRU                        *pstBuf;

    pstBuf          = VOS_NULL_PTR;

    /* HSIC MODEM?????? */
    ucIndex     = AT_CLIENT_TAB_MODEM_INDEX;

    AT_MODEM_DBG_UL_DATA_READ_CB_NUM(1);

    if (AT_SUCCESS == AT_ModemGetUlDataBuf(ucIndex, &pstBuf))
    {

        /*MODEM?????? */
        ucDlci      = AT_MODEM_USER_DLCI;

        /* ?????????????????????????????? */
        At_ModemDataInd(ucIndex, ucDlci, pstBuf);
    }

    return;
}


VOS_VOID AT_UsbModemReadMscCB(AT_DCE_MSC_STRU *pstRcvedMsc)
{
    VOS_UINT8                           ucIndex;
    VOS_UINT8                           ucDlci;

    if (VOS_NULL_PTR == pstRcvedMsc)
    {
        AT_WARN_LOG("AT_UsbModemReadMscCB, WARNING, Receive NULL pointer MSC info!");

        return;
    }

    /* MODEM?????? */
    ucIndex     = AT_CLIENT_TAB_MODEM_INDEX;

    /*MODEM?????? */
    ucDlci      = AT_MODEM_USER_DLCI;

     /* ???????????????????? */
    AT_MNTN_TraceInputMsc(ucIndex, pstRcvedMsc);

    At_ModemMscInd(ucIndex, ucDlci, pstRcvedMsc);

    return;
}


VOS_VOID AT_UsbModemInit( VOS_VOID )
{
    UDI_OPEN_PARAM_S                    stParam;
    VOS_UINT8                           ucIndex;

    ucIndex         = AT_CLIENT_TAB_MODEM_INDEX;
    stParam.devid   = UDI_ACM_MODEM_ID;

    /* ????Device??????ID */
    g_alAtUdiHandle[ucIndex] = mdrv_udi_open(&stParam);

    if (UDI_INVALID_HANDLE == g_alAtUdiHandle[ucIndex])
    {
        AT_ERR_LOG("AT_UsbModemInit, ERROR, Open usb modem device failed!");

        return;
    }

    /* ????MODEM???????????????????? */
    if (VOS_OK != mdrv_udi_ioctl (g_alAtUdiHandle[ucIndex], ACM_IOCTL_SET_READ_CB, AT_UsbModemReadDataCB))
    {
        AT_ERR_LOG("AT_UsbModemInit, ERROR, Set data read callback for modem failed!");

        return;
    }

    /* ????MODEM???????????????????? */
    if (VOS_OK != mdrv_udi_ioctl (g_alAtUdiHandle[ucIndex], ACM_IOCTL_SET_FREE_CB, AT_ModemFreeDlDataBuf))
    {
        AT_ERR_LOG("AT_UsbModemInit, ERROR, Set memory free callback for modem failed!");

        return;
    }

    /* ????MODEM?????????????????? */
    if (VOS_OK != mdrv_udi_ioctl (g_alAtUdiHandle[ucIndex], ACM_IOCTL_WRITE_DO_COPY, (void *)0))
    {
        AT_ERR_LOG("AT_UsbModemInit, ERROR, Set not do copy for modem failed!");

        return;
    }

    /* ???????????????????? */
    if (VOS_OK != mdrv_udi_ioctl (g_alAtUdiHandle[ucIndex], ACM_MODEM_IOCTL_SET_MSC_READ_CB, AT_UsbModemReadMscCB))
    {
        AT_ERR_LOG("AT_UsbModemInit, ERROR, Set msc read callback for modem failed!");

        return;
    }

    /* ????MODEM???????????????????????? */
    if (VOS_OK != mdrv_udi_ioctl (g_alAtUdiHandle[ucIndex], ACM_MODEM_IOCTL_SET_REL_IND_CB, AT_UsbModemEnableCB))
    {
        AT_ERR_LOG("AT_UsbModemInit, ERROR, Set enable callback for modem failed!");

        return;
    }

    /* ????MODEM????????????buffer???? */
    AT_ModemInitUlDataBuf(ucIndex, AT_MODEM_UL_DATA_BUFF_SIZE, AT_MODEM_UL_DATA_BUFF_NUM);

    /* ??????MODME???????? */
    AT_InitModemStats();

    /*????client id*/
    At_ModemEst(ucIndex, AT_CLIENT_ID_MODEM, AT_USB_MODEM_PORT_NO);

    AT_ConfigTraceMsg(ucIndex, ID_AT_CMD_MODEM, ID_AT_MNTN_RESULT_MODEM);

    return;
}


VOS_VOID AT_UsbModemClose(VOS_VOID)
{
    AT_CLIENT_TAB_INDEX_UINT8           ucIndex;

    ucIndex = AT_CLIENT_TAB_MODEM_INDEX;

    /* ??????MODEM??????(??TTF??????????????????????????????????)?? */

    AT_DeRegModemPsDataFCPoint(ucIndex, AT_GET_RABID_FROM_EXRABID(gastAtClientTab[ucIndex].ucExPsRabId));

    if (UDI_INVALID_HANDLE != g_alAtUdiHandle[ucIndex])
    {
        mdrv_udi_close(g_alAtUdiHandle[ucIndex]);

        g_alAtUdiHandle[ucIndex] = UDI_INVALID_HANDLE;

        PS_PRINTF("AT_UsbModemClose....\n");
    }

    return;
}


VOS_VOID AT_SetUsbDebugFlag(VOS_UINT32 ulFlag)
{
    g_ulAtUsbDebugFlag = ulFlag;
}



VOS_INT At_RcvFromUsbCom(
    VOS_UINT8                           ucPortNo,
    VOS_UINT8                          *pData,
    VOS_UINT16                          uslength
)
{
    VOS_UINT8                           ucIndex;
    VOS_UINT32                          ulRet;
    VOS_UINT32                          ulMuxUserFlg;
    VOS_UINT32                          ulHsicUserFlg;

    if (VOS_TRUE == g_ulAtUsbDebugFlag)
    {
        PS_PRINTF("At_RcvFromUsbCom: PortNo = %d, length = %d, data = %s\r\n", ucPortNo, uslength, pData);
    }

    if (VOS_NULL_PTR == pData)
    {
        AT_WARN_LOG("At_RcvFromUsbCom: pData is NULL PTR!");
        return AT_DRV_FAILURE;
    }

    if (0 == uslength)
    {
        AT_WARN_LOG("At_RcvFromUsbCom: uslength is 0!");
        return AT_DRV_FAILURE;
    }

    /*PCUI??CTRL????*/
    for (ucIndex = 0; ucIndex < AT_MAX_CLIENT_NUM; ucIndex++)
    {
        ulMuxUserFlg = AT_CheckMuxUser(ucIndex);
        ulHsicUserFlg = AT_CheckHsicUser(ucIndex);

        if ((AT_USBCOM_USER == gastAtClientTab[ucIndex].UserType)
         || (AT_CTR_USER == gastAtClientTab[ucIndex].UserType)
         || (AT_PCUI2_USER == gastAtClientTab[ucIndex].UserType)
         || (AT_UART_USER == gastAtClientTab[ucIndex].UserType)
         || (VOS_TRUE == ulMuxUserFlg)
         || (VOS_TRUE == ulHsicUserFlg))
        {
            if (AT_CLIENT_NULL != gastAtClientTab[ucIndex].ucUsed)
            {
                if (gastAtClientTab[ucIndex].ucPortNo == ucPortNo)
                {
                    break;
                }
            }
        }
    }

    if (VOS_TRUE == g_ulAtUsbDebugFlag)
    {
        PS_PRINTF("At_RcvFromUsbCom: ucIndex = %d\r\n", ucIndex);
    }

    if (ucIndex >= AT_MAX_CLIENT_NUM)
    {
        AT_WARN_LOG("At_RcvFromUsbCom (ucIndex >= AT_MAX_CLIENT_NUM)");
        return AT_DRV_FAILURE;
    }

    if (VOS_TRUE == g_ulAtUsbDebugFlag)
    {
        PS_PRINTF("At_RcvFromUsbCom: CmdMode = %d\r\n", gastAtClientTab[ucIndex].Mode);
    }

    if (AT_CMD_MODE == gastAtClientTab[ucIndex].Mode)
    {
        ulRet = At_CmdStreamPreProc(ucIndex,pData,uslength);
    }
    else
    {
        ulRet = At_DataStreamPreProc(ucIndex,gastAtClientTab[ucIndex].DataMode,pData,uslength);
    }

    if ( AT_SUCCESS == ulRet )
    {
        return AT_DRV_SUCCESS;
    }
    else
    {
        return AT_DRV_FAILURE;
    }
}



VOS_UINT32 At_UsbPcuiEst(VOS_UINT8 ucPortNo)
{
    VOS_UINT8                           ucIndex;

    if (AT_USB_COM_PORT_NO != ucPortNo)
    {
        AT_WARN_LOG("At_UsbPcuiEst the PortNo is error)");
        return VOS_ERR;
    }

    ucIndex = AT_CLIENT_TAB_PCUI_INDEX;

    /* ???????????? */
    TAF_MEM_SET_S(&gastAtClientTab[ucIndex], sizeof(AT_CLIENT_MANAGE_STRU), 0x00, sizeof(AT_CLIENT_MANAGE_STRU));

    AT_ConfigTraceMsg(ucIndex, ID_AT_CMD_PCUI, ID_AT_MNTN_RESULT_PCUI);

    /* ???????????? */
    gastAtClientTab[ucIndex].usClientId      = AT_CLIENT_ID_PCUI;
    gastAtClientTab[ucIndex].ucPortNo        = ucPortNo;
    gastAtClientTab[ucIndex].UserType        = AT_USBCOM_USER;
    gastAtClientTab[ucIndex].ucUsed          = AT_CLIENT_USED;

    /* ??????????????????????PS_MEMSET???????????????????????? */
    gastAtClientTab[ucIndex].Mode            = AT_CMD_MODE;
    gastAtClientTab[ucIndex].IndMode         = AT_IND_MODE;
    gastAtClientTab[ucIndex].DataMode        = AT_DATA_BUTT_MODE;
    gastAtClientTab[ucIndex].DataState       = AT_DATA_STOP_STATE;
    gastAtClientTab[ucIndex].CmdCurrentOpt   = AT_CMD_CURRENT_OPT_BUTT;
    g_stParseContext[ucIndex].ucClientStatus = AT_FW_CLIENT_STATUS_READY;

    /*??DMS??????????????????????????????*/
    (VOS_VOID)DMS_COM_RCV_CALLBACK_REGI(ucPortNo, (pComRecv)At_RcvFromUsbCom);


    AT_LOG1("At_UsbPcuiEst ucIndex:",ucIndex);
    return VOS_OK;
}



VOS_UINT32 At_UsbCtrEst(VOS_UINT8 ucPortNo)
{
    VOS_UINT8                           ucIndex;


    if (AT_CTR_PORT_NO != ucPortNo)
    {
        AT_WARN_LOG("At_UsbCtrEst the PortNo is error)");
        return VOS_ERR;
    }

    ucIndex = AT_CLIENT_TAB_CTRL_INDEX;

    /* ???????????? */
    TAF_MEM_SET_S(&gastAtClientTab[ucIndex], sizeof(AT_CLIENT_MANAGE_STRU), 0x00, sizeof(AT_CLIENT_MANAGE_STRU));

    AT_ConfigTraceMsg(ucIndex, ID_AT_CMD_CTRL, ID_AT_MNTN_RESULT_CTRL);

    /* ???????????? */
    gastAtClientTab[ucIndex].usClientId      = AT_CLIENT_ID_CTRL;
    gastAtClientTab[ucIndex].ucPortNo        = ucPortNo;
    gastAtClientTab[ucIndex].UserType        = AT_CTR_USER;
    gastAtClientTab[ucIndex].ucUsed          = AT_CLIENT_USED;

    /* ??????????????????????PS_MEMSET???????????????????????? */
    gastAtClientTab[ucIndex].Mode            = AT_CMD_MODE;
    gastAtClientTab[ucIndex].IndMode         = AT_IND_MODE;
    gastAtClientTab[ucIndex].DataMode        = AT_DATA_BUTT_MODE;
    gastAtClientTab[ucIndex].DataState       = AT_DATA_STOP_STATE;
    gastAtClientTab[ucIndex].CmdCurrentOpt   = AT_CMD_CURRENT_OPT_BUTT;
    g_stParseContext[ucIndex].ucClientStatus = AT_FW_CLIENT_STATUS_READY;


    /*??????DMS??????????????????????????*/
    (VOS_VOID)DMS_COM_RCV_CALLBACK_REGI(ucPortNo, (pComRecv)At_RcvFromUsbCom);

    return VOS_OK;
}


VOS_UINT32 At_UsbPcui2Est(VOS_UINT8 ucPortNo)
{
    VOS_UINT8                           ucIndex;

    if (AT_PCUI2_PORT_NO != ucPortNo)
    {
        AT_WARN_LOG("At_UsbPcui2Est the PortNo is error)");
        return VOS_ERR;
    }

    ucIndex = AT_CLIENT_TAB_PCUI2_INDEX;

    /* ???????????? */
    TAF_MEM_SET_S(&gastAtClientTab[ucIndex], sizeof(AT_CLIENT_MANAGE_STRU), 0x00, sizeof(AT_CLIENT_MANAGE_STRU));

    AT_ConfigTraceMsg(ucIndex, ID_AT_CMD_PCUI2, ID_AT_MNTN_RESULT_PCUI2);

    /* ???????????? */
    gastAtClientTab[ucIndex].usClientId      = AT_CLIENT_ID_PCUI2;
    gastAtClientTab[ucIndex].ucPortNo        = ucPortNo;
    gastAtClientTab[ucIndex].UserType        = AT_PCUI2_USER;
    gastAtClientTab[ucIndex].ucUsed          = AT_CLIENT_USED;

    /* ??????????????????????PS_MEMSET???????????????????????? */
    gastAtClientTab[ucIndex].Mode            = AT_CMD_MODE;
    gastAtClientTab[ucIndex].IndMode         = AT_IND_MODE;
    gastAtClientTab[ucIndex].DataMode        = AT_DATA_BUTT_MODE;
    gastAtClientTab[ucIndex].DataState       = AT_DATA_STOP_STATE;
    gastAtClientTab[ucIndex].CmdCurrentOpt   = AT_CMD_CURRENT_OPT_BUTT;
    g_stParseContext[ucIndex].ucClientStatus = AT_FW_CLIENT_STATUS_READY;

    /*??????DMS??????????????????????????*/
    (VOS_VOID)DMS_COM_RCV_CALLBACK_REGI(ucPortNo, (pComRecv)At_RcvFromUsbCom);

    return VOS_OK;
}


VOS_UINT32 AT_UART_GetUlDataBuff(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                         **ppucData,
    VOS_UINT32                         *pulLen
)
{
    ACM_WR_ASYNC_INFO                   stCtlParam;
    UDI_HANDLE                          lUdiHandle;
    VOS_INT32                           lResult;

    lUdiHandle = g_alAtUdiHandle[ucIndex];
    if (UDI_INVALID_HANDLE == lUdiHandle)
    {
        AT_ERR_LOG("AT_UART_GetUlDataBuff: Invalid UDI handle!\r\n");
        return AT_FAILURE;
    }

    /* ????????????????BUFFER */
    stCtlParam.pVirAddr = VOS_NULL_PTR;
    stCtlParam.pPhyAddr = VOS_NULL_PTR;
    stCtlParam.u32Size  = 0;
    stCtlParam.pDrvPriv = VOS_NULL_PTR;

    lResult = mdrv_udi_ioctl(lUdiHandle, UART_IOCTL_GET_RD_BUFF, &stCtlParam);
    if (VOS_OK != lResult)
    {
        AT_ERR_LOG("AT_UART_GetUlDataBuff: Get buffer failed!\r\n");
        return AT_FAILURE;
    }

    if ( (VOS_NULL_PTR == stCtlParam.pVirAddr)
      || (AT_INIT_DATA_LEN == stCtlParam.u32Size) )
    {
        AT_ERR_LOG("AT_UART_GetUlDataBuff: Data buffer error!\r\n");
        return AT_FAILURE;
    }

    *ppucData = (VOS_UINT8 *)stCtlParam.pVirAddr;
    *pulLen   = stCtlParam.u32Size;

    return AT_SUCCESS;
}


VOS_UINT32 AT_UART_WriteDataSync(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                          *pucData,
    VOS_UINT32                          ulLen
)
{
    UDI_HANDLE                          lUdiHandle;
    VOS_INT32                           lResult;

    /* ????UDI?????????? */
    lUdiHandle = g_alAtUdiHandle[ucIndex];
    if (UDI_INVALID_HANDLE == lUdiHandle)
    {
        AT_ERR_LOG("AT_UART_WriteDataSync: Invalid UDI handle!\r\n");
        return AT_FAILURE;
    }

    /* ?????????????? */
    if ((VOS_NULL_PTR == pucData) || (0 == ulLen))
    {
        AT_ERR_LOG("AT_UART_WriteDataSync: DATA is invalid!\r\n");
        return AT_FAILURE;
    }

    lResult = mdrv_udi_write(lUdiHandle, pucData, ulLen);
    if (VOS_OK != lResult)
    {
        AT_HSUART_DBG_DL_WRITE_SYNC_FAIL_LEN(ulLen);
        AT_ERR_LOG("AT_UART_WriteDataSync: Write buffer failed!\r\n");
        return AT_FAILURE;
    }

    AT_HSUART_DBG_DL_WRITE_SYNC_SUCC_LEN(ulLen);

    return AT_SUCCESS;
}


VOS_UINT32 AT_UART_SendDlData(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                          *pucData,
    VOS_UINT16                          usLen
)
{
    /* ??????UART????, ???????????? */
    return AT_UART_WriteDataSync(ucIndex, pucData, usLen);
}


VOS_UINT32 AT_UART_SendRawDataFromOm(
    VOS_UINT8                          *pucVirAddr,
    VOS_UINT8                          *pucPhyAddr,
    VOS_UINT32                          ulLen
)
{
    VOS_UINT32                          ulResult;
    VOS_UINT8                           ucIndex;

    ucIndex  = AT_CLIENT_TAB_UART_INDEX;

    ulResult = AT_UART_WriteDataSync(ucIndex, pucVirAddr, (VOS_UINT16)ulLen);
    if (AT_SUCCESS != ulResult)
    {
        return VOS_ERR;
    }

    return VOS_OK;
}


VOS_VOID AT_UART_UlDataReadCB(VOS_VOID)
{
    VOS_UINT8                          *pucData = VOS_NULL_PTR;
    VOS_UINT32                          ulLen;
    VOS_UINT8                           ucIndex;

    ulLen   = 0;
    ucIndex = AT_CLIENT_TAB_UART_INDEX;

    if (AT_SUCCESS == AT_UART_GetUlDataBuff(ucIndex, &pucData, &ulLen))
    {
        /* ?????????????????????????????? */
        At_RcvFromUsbCom(AT_UART_PORT_NO, pucData, (VOS_UINT16)ulLen);
    }

    return;
}


VOS_VOID AT_UART_InitLink(VOS_UINT8 ucIndex)
{
    TAF_AT_NVIM_DEFAULT_LINK_OF_UART_STRU    stDefaultLinkType;


    stDefaultLinkType.enUartLinkType = AT_UART_LINK_TYPE_BUTT;


    /* ???????????? */
    TAF_MEM_SET_S(&gastAtClientTab[ucIndex], sizeof(AT_CLIENT_MANAGE_STRU), 0x00, sizeof(AT_CLIENT_MANAGE_STRU));

    gastAtClientTab[ucIndex].ucPortNo  = AT_UART_PORT_NO;
    gastAtClientTab[ucIndex].UserType  = AT_UART_USER;
    gastAtClientTab[ucIndex].ucUsed    = AT_CLIENT_USED;


    /* ????UART????????????????NV?? */
    if (NV_OK != TAF_ACORE_NV_READ(MODEM_ID_0,
                                   en_NV_Item_DEFAULT_LINK_OF_UART,
                                   &stDefaultLinkType.enUartLinkType,
                                   sizeof(stDefaultLinkType.enUartLinkType)))
    {
        /* NV??????????????UART????????????????????OM???? */
        AT_ERR_LOG("AT_UART_InitLink:Read NV failed!");

        /*????AT/OM??????????????????*/
        gucAtOmIndex = ucIndex;

        /* ??????OM???????? */
        At_SetMode(ucIndex, AT_DATA_MODE, AT_OM_DATA_MODE);
        gastAtClientTab[ucIndex].DataState = AT_DATA_START_STATE;

        AT_AddUsedClientId2Tab(AT_CLIENT_TAB_UART_INDEX);

        /* ????OAM????UART??OM???? */
        CBTCPM_NotifyChangePort(AT_UART_PORT);
    }
    else
    {
        /* NV??????????????UART?????????????????? */
        if (AT_UART_LINK_TYPE_AT != stDefaultLinkType.enUartLinkType)
        {
            AT_NORM_LOG("AT_UART_InitLink:DEFAULT UART LINK TYPE is OM!");

            /*????AT/OM??????????????????*/
            gucAtOmIndex = ucIndex;

            /* ??????OM???????? */
            At_SetMode(ucIndex, AT_DATA_MODE, AT_OM_DATA_MODE);
            gastAtClientTab[ucIndex].DataState = AT_DATA_START_STATE;

            AT_AddUsedClientId2Tab(AT_CLIENT_TAB_UART_INDEX);

            /* ????OAM????UART??OM???? */
            CBTCPM_NotifyChangePort(AT_UART_PORT);
        }
        else
        {
            /* ???????????? */
            gastAtClientTab[ucIndex].usClientId      = AT_CLIENT_ID_UART;

            /* ??????????????????????PS_MEMSET???????????????????????? */
            gastAtClientTab[ucIndex].Mode            = AT_CMD_MODE;
            gastAtClientTab[ucIndex].IndMode         = AT_IND_MODE;
            gastAtClientTab[ucIndex].DataMode        = AT_DATA_BUTT_MODE;
            gastAtClientTab[ucIndex].DataState       = AT_DATA_STOP_STATE;
            gastAtClientTab[ucIndex].CmdCurrentOpt   = AT_CMD_CURRENT_OPT_BUTT;
            g_stParseContext[ucIndex].ucClientStatus = AT_FW_CLIENT_STATUS_READY;
        }
    }

    return;
}


VOS_VOID AT_UART_InitPort(VOS_VOID)
{
    UDI_OPEN_PARAM_S                    stParam;
    UDI_HANDLE                          lUdiHandle;
    VOS_UINT8                           ucIndex;

    stParam.devid = UDI_UART_0_ID;
    ucIndex       = AT_CLIENT_TAB_UART_INDEX;

    AT_ConfigTraceMsg(ucIndex, ID_AT_CMD_UART, ID_AT_MNTN_RESULT_UART);

    lUdiHandle = mdrv_udi_open(&stParam);
    if (UDI_INVALID_HANDLE != lUdiHandle)
    {
        /* ????UART???????????????????? */
        if (VOS_OK != mdrv_udi_ioctl (lUdiHandle, UART_IOCTL_SET_READ_CB, AT_UART_UlDataReadCB))
        {
            AT_ERR_LOG("AT_UART_InitPort: Reg data read callback failed!\r\n");
        }

        /* ??????UART???? */
        AT_UART_InitLink(ucIndex);
        g_alAtUdiHandle[ucIndex] = lUdiHandle;
    }
    else
    {
        AT_ERR_LOG("AT_UART_InitPort: Open UART device failed!\r\n");
        g_alAtUdiHandle[ucIndex] = UDI_INVALID_HANDLE;
    }

    return;
}



VOS_VOID AT_CtrlDCD(
    VOS_UINT8                           ucIndex,
    AT_IO_LEVEL_ENUM_UINT8              enIoLevel
)
{
    AT_DCE_MSC_STRU                     stDceMsc;
    NAS_OM_EVENT_ID_ENUM_UINT16         enEventId;

    TAF_MEM_SET_S(&stDceMsc, sizeof(stDceMsc), 0x00, sizeof(AT_DCE_MSC_STRU));

    stDceMsc.OP_Dcd = VOS_TRUE;
    stDceMsc.ucDcd  = enIoLevel;

    AT_SetModemStatus(ucIndex, &stDceMsc);

    enEventId = (AT_IO_LEVEL_HIGH == enIoLevel) ?
                NAS_OM_EVENT_DCE_UP_DCD : NAS_OM_EVENT_DCE_DOWN_DCD;

    AT_EventReport(WUEPS_PID_AT, enEventId, &ucIndex, sizeof(VOS_UINT8));

    return;
}


VOS_VOID AT_CtrlDSR(
    VOS_UINT8                           ucIndex,
    AT_IO_LEVEL_ENUM_UINT8              enIoLevel
)
{
    AT_DCE_MSC_STRU                     stDceMsc;
    NAS_OM_EVENT_ID_ENUM_UINT16         enEventId;

    TAF_MEM_SET_S(&stDceMsc, sizeof(stDceMsc), 0x00, sizeof(AT_DCE_MSC_STRU));

    stDceMsc.OP_Dsr = VOS_TRUE;
    stDceMsc.ucDsr  = enIoLevel;

    AT_SetModemStatus(ucIndex, &stDceMsc);

    enEventId = (AT_IO_LEVEL_HIGH == enIoLevel) ?
                NAS_OM_EVENT_DCE_UP_DSR: NAS_OM_EVENT_DCE_DOWN_DSR;

    AT_EventReport(WUEPS_PID_AT, enEventId, &ucIndex, sizeof(VOS_UINT8));

    return;
}


VOS_VOID AT_CtrlCTS(
    VOS_UINT8                           ucIndex,
    AT_IO_LEVEL_ENUM_UINT8              enIoLevel
)
{
    AT_DCE_MSC_STRU                     stDceMsc;
    NAS_OM_EVENT_ID_ENUM_UINT16         enEventId;

    TAF_MEM_SET_S(&stDceMsc, sizeof(stDceMsc), 0x00, sizeof(AT_DCE_MSC_STRU));

    stDceMsc.OP_Cts = VOS_TRUE;
    stDceMsc.ucCts  = enIoLevel;

    AT_SetModemStatus(ucIndex, &stDceMsc);

    enEventId = (AT_IO_LEVEL_HIGH == enIoLevel) ?
                NAS_OM_EVENT_DCE_UP_CTS: NAS_OM_EVENT_DCE_DOWN_CTS;

    AT_EventReport(WUEPS_PID_AT, enEventId, &ucIndex, sizeof(VOS_UINT8));

    return;
}


VOS_VOID AT_CtrlRI(
    VOS_UINT8                           ucIndex,
    AT_IO_LEVEL_ENUM_UINT8              enIoLevel
)
{
    AT_DCE_MSC_STRU                     stDceMsc;
    NAS_OM_EVENT_ID_ENUM_UINT16         enEventId;

    TAF_MEM_SET_S(&stDceMsc, sizeof(stDceMsc), 0x00, sizeof(AT_DCE_MSC_STRU));

    stDceMsc.OP_Ri = VOS_TRUE;
    stDceMsc.ucRi  = enIoLevel;

    AT_SetModemStatus(ucIndex, &stDceMsc);

    enEventId = (AT_IO_LEVEL_HIGH == enIoLevel) ?
                NAS_OM_EVENT_DCE_UP_RI: NAS_OM_EVENT_DCE_DOWN_RI;

    AT_EventReport(WUEPS_PID_AT, enEventId, &ucIndex, sizeof(VOS_UINT8));

    return;
}


AT_IO_LEVEL_ENUM_UINT8 AT_GetIoLevel(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                           ucIoCtrl
)
{
    if (0 == (gastAtClientTab[ucIndex].ModemStatus & ucIoCtrl))
    {
        return AT_IO_LEVEL_LOW;
    }

    return AT_IO_LEVEL_HIGH;
}


int  App_VcomRecvCallbackRegister(unsigned char  uPortNo, pComRecv pCallback)
{
    return VOS_OK;
}


VOS_INT AT_RcvFromAppCom(
    VOS_UINT8                           ucVcomId,
    VOS_UINT8                          *pData,
    VOS_UINT32                          ullength
)
{
    VOS_UINT8                           ucIndex;
    VOS_UINT32                          ulRet;

    /* AT????????????????????????VOS_UINT16???????????????????????????????? */
    if (ullength > 0xffff)
    {
        AT_WARN_LOG("AT_RcvFromAppCom: ullength is more than 0xffff!");
        return VOS_ERR;
    }

    if (ucVcomId >= APP_VCOM_DEV_INDEX_BUTT)
    {
        AT_WARN_LOG("AT_RcvFromAppCom: Port No ERR!");
        return VOS_ERR;
    }
    /* APPVCOM????????????AT???? */
    if (ucVcomId >= AT_VCOM_AT_CHANNEL_MAX)
    {
        AT_WARN_LOG("AT_RcvFromAppCom: Port No ERR!");
        return VOS_ERR;
    }
    if (VOS_NULL_PTR == pData)
    {
        AT_WARN_LOG("AT_RcvFromAppCom: pData is NULL PTR!");
        return VOS_ERR;
    }

    if (0 == ullength)
    {
        AT_WARN_LOG("AT_RcvFromAppCom: uslength is 0!");
        return VOS_ERR;
    }

    /* ??????????????Index???? */
    ucIndex = AT_CLIENT_TAB_APP_INDEX + ucVcomId;

    /* ??????????APP???? */
    if ((AT_APP_USER != gastAtClientTab[ucIndex].UserType)
     || (AT_CLIENT_NULL == gastAtClientTab[ucIndex].ucUsed))
    {
        AT_WARN_LOG("AT_RcvFromAppCom: APP client is unused!");
        return VOS_ERR;
    }

    if (AT_CMD_MODE == gastAtClientTab[ucIndex].Mode)
    {
        ulRet = At_CmdStreamPreProc(ucIndex, pData, (VOS_UINT16)ullength);
    }
    else
    {
        ulRet = At_DataStreamPreProc(ucIndex, gastAtClientTab[ucIndex].DataMode, pData, (VOS_UINT16)ullength);
    }

    if ( AT_SUCCESS == ulRet )
    {
        return VOS_OK;
    }
    else
    {
        return VOS_ERR;
    }
}


VOS_INT32 AT_AppComEst(VOS_VOID)
{
    VOS_UINT8                           ucIndex;
    VOS_UINT8                           ucLoop;

    for (ucLoop = 0; ucLoop < AT_VCOM_AT_CHANNEL_MAX; ucLoop++)
    {
        ucIndex = AT_CLIENT_TAB_APP_INDEX + ucLoop;

        /* ???????????? */
        TAF_MEM_SET_S(&gastAtClientTab[ucIndex], sizeof(AT_CLIENT_MANAGE_STRU), 0x00, sizeof(AT_CLIENT_MANAGE_STRU));

        AT_ConfigTraceMsg(ucIndex, (ID_AT_CMD_APP + ucLoop), (ID_AT_MNTN_RESULT_APP + ucLoop));

        gastAtClientTab[ucIndex].usClientId     = AT_CLIENT_ID_APP + ucLoop;

        /* ???????????? */
        gastAtClientTab[ucIndex].ucPortNo        = APP_VCOM_DEV_INDEX_0 + ucLoop;
        gastAtClientTab[ucIndex].UserType        = AT_APP_USER;
        gastAtClientTab[ucIndex].ucUsed          = AT_CLIENT_USED;
        gastAtClientTab[ucIndex].Mode            = AT_CMD_MODE;
        gastAtClientTab[ucIndex].IndMode         = AT_IND_MODE;
        gastAtClientTab[ucIndex].DataMode        = AT_DATA_BUTT_MODE;
        gastAtClientTab[ucIndex].DataState       = AT_DATA_STOP_STATE;
        gastAtClientTab[ucIndex].CmdCurrentOpt   = AT_CMD_CURRENT_OPT_BUTT;
        g_stParseContext[ucIndex].ucClientStatus = AT_FW_CLIENT_STATUS_READY;

        /* ???????????? */
        APP_VCOM_RegDataCallback(gastAtClientTab[ucIndex].ucPortNo, (SEND_UL_AT_FUNC)AT_RcvFromAppCom);

    }

    return VOS_OK;
}


VOS_INT AT_RcvFromSock(
    VOS_UINT8                          *pData,
    VOS_UINT32                         uslength
)
{
    VOS_UINT8                           ucIndex;
    VOS_UINT32                          ulRet;

    ucIndex = AT_CLIENT_TAB_SOCK_INDEX;

    if (VOS_NULL_PTR == pData)
    {
        AT_WARN_LOG("AT_RcvFromSock: pData is NULL PTR!");
        return VOS_ERR;
    }
    if (0 == uslength)
    {
        AT_WARN_LOG("AT_RcvFromSock: uslength is 0!");
        return VOS_ERR;
    }

    if ((AT_SOCK_USER != gastAtClientTab[ucIndex].UserType)
        ||(AT_CLIENT_NULL == gastAtClientTab[ucIndex].ucUsed))
    {
        AT_WARN_LOG("AT_RcvFromSock: SOCK client is unused!");
        return VOS_ERR;
    }

    if (AT_CMD_MODE == gastAtClientTab[ucIndex].Mode)
    {
        ulRet = At_CmdStreamPreProc(ucIndex,pData,(VOS_UINT16)uslength);
    }
    else
    {
        ulRet = At_DataStreamPreProc(ucIndex,gastAtClientTab[ucIndex].DataMode,pData,(VOS_UINT16)uslength);
    }
    if ( AT_SUCCESS == ulRet )
    {
        return VOS_OK;
    }
    else
    {
        return VOS_ERR;
    }
}


VOS_INT32 AT_SockComEst(VOS_UINT8 ucPortNo)
{

    VOS_UINT8                           ucIndex;

    ucIndex = AT_CLIENT_TAB_SOCK_INDEX;

    if (AT_SOCK_PORT_NO != ucPortNo)
    {
        AT_WARN_LOG("At_SockComEst the PortNo is error)");
        return VOS_ERR;
    }

    TAF_MEM_SET_S(&gastAtClientTab[ucIndex], sizeof(AT_CLIENT_MANAGE_STRU), 0x00, sizeof(AT_CLIENT_MANAGE_STRU));

    AT_ConfigTraceMsg(ucIndex, ID_AT_CMD_SOCK, ID_AT_MNTN_RESULT_SOCK);

    gastAtClientTab[ucIndex].usClientId      = AT_CLIENT_ID_SOCK;
    gastAtClientTab[ucIndex].ucPortNo        = ucPortNo;
    gastAtClientTab[ucIndex].UserType        = AT_SOCK_USER;
    gastAtClientTab[ucIndex].ucUsed          = AT_CLIENT_USED;
    gastAtClientTab[ucIndex].Mode            = AT_CMD_MODE;
    gastAtClientTab[ucIndex].IndMode         = AT_IND_MODE;
    gastAtClientTab[ucIndex].DataMode        = AT_DATA_BUTT_MODE;
    gastAtClientTab[ucIndex].DataState       = AT_DATA_STOP_STATE;
    gastAtClientTab[ucIndex].CmdCurrentOpt   = AT_CMD_CURRENT_OPT_BUTT;
    g_stParseContext[ucIndex].ucClientStatus = AT_FW_CLIENT_STATUS_READY;

    /* Modified by s62952 for AT Project??2011-10-17,  Begin*/
    /*??DMS??????????????????????????????*/
    (VOS_VOID)mdrv_CPM_LogicRcvReg(CPM_AT_COMM,(CBTCPM_RCV_FUNC)AT_RcvFromSock);
    /* Modified by s62952 for AT Project??2011-10-17,  end*/

    return VOS_OK;
}


VOS_INT AT_RcvFromAppSock(
    VOS_UINT8                           ucPortNo,
    VOS_UINT8                          *pData,
    VOS_UINT16                          uslength
)
{
    VOS_UINT8                           ucIndex;
    VOS_UINT32                          ulRet;

    ucIndex = AT_CLIENT_TAB_APPSOCK_INDEX;

    if (VOS_NULL_PTR == pData)
    {
        AT_WARN_LOG("AT_RcvFromAppSock: pData is NULL PTR!");
        return VOS_ERR;
    }

    if (0 == uslength)
    {
        AT_WARN_LOG("AT_RcvFromAppSock: uslength is 0!");
        return VOS_ERR;
    }

    if (AT_APP_SOCK_PORT_NO != ucPortNo)
    {
        AT_WARN_LOG("AT_RcvFromAppSock: Port No ERR!");
        return VOS_ERR;
    }

    if ( (AT_APP_SOCK_USER != gastAtClientTab[ucIndex].UserType)
       ||(AT_CLIENT_NULL == gastAtClientTab[ucIndex].ucUsed))
    {
        AT_WARN_LOG("AT_RcvFromAppSock: SOCK client is unused!");
        return VOS_ERR;
    }

    if (AT_CMD_MODE == gastAtClientTab[ucIndex].Mode)
    {
        ulRet = At_CmdStreamPreProc(ucIndex,pData,uslength);
    }
    else
    {
        ulRet = At_DataStreamPreProc(ucIndex,gastAtClientTab[ucIndex].DataMode,pData,uslength);
    }

    if ( AT_SUCCESS == ulRet )
    {
        return VOS_OK;
    }
    else
    {
        return VOS_ERR;
    }
}


VOS_INT32 AT_AppSockComEst(VOS_UINT8 ucPortNo)
{
    VOS_UINT8                           ucIndex;

    ucIndex = AT_CLIENT_TAB_APPSOCK_INDEX;

    if (AT_APP_SOCK_PORT_NO != ucPortNo)
    {
         AT_WARN_LOG("AT_E5SockComEst the PortNo is error)");
        return VOS_ERR;
    }

    AT_ConfigTraceMsg(ucIndex, ID_AT_CMD_APPSOCK, ID_AT_MNTN_RESULT_APPSOCK);

    /* ???????????? */
    TAF_MEM_SET_S(&gastAtClientTab[ucIndex], sizeof(AT_CLIENT_MANAGE_STRU), 0x00, sizeof(AT_CLIENT_MANAGE_STRU));

    /* ???????????? */
    gastAtClientTab[ucIndex].usClientId      = AT_CLIENT_ID_APPSOCK;
    gastAtClientTab[ucIndex].ucPortNo        = ucPortNo;
    gastAtClientTab[ucIndex].UserType        = AT_APP_SOCK_USER;
    gastAtClientTab[ucIndex].ucUsed          = AT_CLIENT_USED;
    gastAtClientTab[ucIndex].Mode            = AT_CMD_MODE;
    gastAtClientTab[ucIndex].IndMode         = AT_IND_MODE;
    gastAtClientTab[ucIndex].DataMode        = AT_DATA_BUTT_MODE;
    gastAtClientTab[ucIndex].DataState       = AT_DATA_STOP_STATE;
    gastAtClientTab[ucIndex].CmdCurrentOpt   = AT_CMD_CURRENT_OPT_BUTT;
    g_stParseContext[ucIndex].ucClientStatus = AT_FW_CLIENT_STATUS_READY;

    /*??DMS??????????????????????????????*/
    (VOS_VOID)App_VcomRecvCallbackRegister(ucPortNo, (pComRecv)AT_RcvFromAppSock);


    return VOS_OK;
}


VOS_UINT32 At_UsbGetWwanMode(VOS_VOID)
{
    return WWAN_WCDMA;
}


VOS_VOID AT_UsbNcmConnStatusChgCB(NCM_IOCTL_CONNECT_STUS_E enStatus, VOS_VOID *pBuffer)
{
    AT_MSG_STRU                        *pstMsg = VOS_NULL_PTR;

    /*
     * ????????????????????, ????????????
     */

    if (NCM_IOCTL_STUS_BREAK == enStatus)
    {
        /* ????OSA???? */
        /*lint -save -e516 */
        pstMsg = (AT_MSG_STRU *)AT_ALLOC_MSG_WITH_HDR(sizeof(AT_MSG_STRU));
        /*lint -restore */
        if (VOS_NULL_PTR == pstMsg)
        {
            AT_ERR_LOG("AT_UsbNcmConnStatusChgCB: Alloc message failed!");
            return;
        }

        /* ???????????? */
        TAF_MEM_SET_S(AT_GET_MSG_ENTITY(pstMsg), AT_GET_MSG_LENGTH(pstMsg), 0x00, AT_GET_MSG_LENGTH(pstMsg));

        /* ?????????? */
        AT_CFG_INTRA_MSG_HDR(pstMsg, ID_AT_NCM_CONN_STATUS_CMD);

        /* ???????????? */
        pstMsg->ucType  = AT_NCM_CONN_STATUS_MSG;
        pstMsg->ucIndex = AT_CLIENT_TAB_NDIS_INDEX;

        /* ???????? */
        AT_SEND_MSG(pstMsg);
    }

    return;
}


VOS_INT AT_RcvFromNdisCom(
    VOS_UINT8                           *pucData,
    VOS_UINT16                          uslength
)
{
    VOS_UINT8                           ucIndex;
    VOS_UINT32                          ulRet;

    /* ???????? */
    if (VOS_NULL_PTR == pucData)
    {
        AT_WARN_LOG("At_RcvFromNdisCom: pData is NULL PTR!");
        return VOS_ERR;
    }

    /* ???????? */
    if (0 == uslength)
    {
        AT_WARN_LOG("At_RcvFromNdisCom: uslength is 0!");
        return VOS_ERR;
    }

    ucIndex = AT_CLIENT_TAB_NDIS_INDEX;

    /* NDIS???????????? */
    if ( (AT_NDIS_USER != gastAtClientTab[ucIndex].UserType)
       ||(AT_CLIENT_NULL == gastAtClientTab[ucIndex].ucUsed))
    {
        AT_WARN_LOG("At_RcvFromNdisCom: NDIS is unused");
        return VOS_ERR;
    }

    /*????NDIS????????????????????*/
    DMS_SetNdisChanStatus(ACM_EVT_DEV_READY);

    if (AT_CMD_MODE == gastAtClientTab[ucIndex].Mode)
    {
        ulRet = At_CmdStreamPreProc(ucIndex,pucData,uslength);
    }
    else
    {
        ulRet = At_DataStreamPreProc(ucIndex,gastAtClientTab[ucIndex].DataMode,pucData,uslength);
    }

    if ( AT_SUCCESS == ulRet )
    {
        return VOS_OK;
    }
    else
    {
        return VOS_ERR;
    }
}


VOS_UINT32 AT_UsbNdisEst(VOS_VOID)
{
    VOS_UINT8                           ucIndex;

    ucIndex = AT_CLIENT_TAB_NDIS_INDEX;

    /* ???????????? */
    TAF_MEM_SET_S(&gastAtClientTab[ucIndex], sizeof(AT_CLIENT_MANAGE_STRU), 0x00, sizeof(AT_CLIENT_MANAGE_STRU));

    AT_ConfigTraceMsg(ucIndex, ID_AT_CMD_NDIS, ID_AT_MNTN_RESULT_NDIS);

    /* ???????????? */
    gastAtClientTab[ucIndex].usClientId      = AT_CLIENT_ID_NDIS;
    gastAtClientTab[ucIndex].ucPortNo        = AT_NDIS_PORT_NO;
    gastAtClientTab[ucIndex].UserType        = AT_NDIS_USER;
    gastAtClientTab[ucIndex].ucUsed          = AT_CLIENT_USED;

    /* ??????????????????????PS_MEMSET???????????????????????? */
    gastAtClientTab[ucIndex].Mode            = AT_CMD_MODE;
    gastAtClientTab[ucIndex].IndMode         = AT_IND_MODE;
    gastAtClientTab[ucIndex].DataMode        = AT_DATA_BUTT_MODE;
    gastAtClientTab[ucIndex].DataState       = AT_DATA_STOP_STATE;
    gastAtClientTab[ucIndex].CmdCurrentOpt   = AT_CMD_CURRENT_OPT_BUTT;
    g_stParseContext[ucIndex].ucClientStatus = AT_FW_CLIENT_STATUS_READY;

    /*??????NDIS ADDR????*/
    TAF_MEM_SET_S(&gstAtNdisAddParam, sizeof(gstAtNdisAddParam), 0x00, sizeof(AT_DIAL_PARAM_STRU));

    return VOS_OK;
}


VOS_VOID AT_OpenUsbNdis(VOS_VOID)
{
    UDI_OPEN_PARAM_S                    stParam;
    VOS_UINT32                          ulRst;

    stParam.devid   = UDI_NCM_NDIS_ID;

    /* ????Device??????ID */
    g_ulAtUdiNdisHdl = mdrv_udi_open(&stParam);

    if (UDI_INVALID_HANDLE == g_ulAtUdiNdisHdl)
    {
        AT_ERR_LOG("AT_OpenUsbNdis, ERROR, Open usb ndis device failed!");

        return;
    }

    /* ????DMS???????????? */
    /*lint -e732   ????????????????????????????????????*/
    ulRst =  DMS_USB_NAS_REGFUNC((USBNdisStusChgFunc)AT_UsbNcmConnStatusChgCB,
                                 (USB_NAS_AT_CMD_RECV)AT_RcvFromNdisCom,
                                 (USB_NAS_GET_WWAN_MODE)At_UsbGetWwanMode);
    if (VOS_OK != ulRst)
    {
        AT_ERR_LOG("AT_OpenUsbNdis, ERROR, Reg NCM failed!");

        return;
    }
    /*lint +e732*/

    return;
}


VOS_VOID AT_CloseUsbNdis(VOS_VOID)
{
    /* ????NDIS???????? */
    AT_UsbNcmConnStatusChgCB(NCM_IOCTL_STUS_BREAK, VOS_NULL_PTR);

    if (UDI_INVALID_HANDLE != g_ulAtUdiNdisHdl)
    {
        mdrv_udi_close(g_ulAtUdiNdisHdl);

        g_ulAtUdiNdisHdl = UDI_INVALID_HANDLE;
    }

    return;
}


VOS_UINT8 AT_GetMuxSupportFlg(VOS_VOID)
{
    return AT_GetCommCtxAddr()->stMuxCtx.ucMuxSupportFlg;
}


VOS_VOID AT_SetMuxSupportFlg(VOS_UINT8 ucMuxSupportFlg)
{
    AT_COMM_CTX_STRU                   *pstCommCtx = VOS_NULL_PTR;

    pstCommCtx = AT_GetCommCtxAddr();

    pstCommCtx->stMuxCtx.ucMuxSupportFlg = ucMuxSupportFlg;
}


VOS_UINT32 AT_CheckMuxDlci(AT_MUX_DLCI_TYPE_ENUM_UINT8 enDlci)
{
    /* ??????????????8????????DLCI??1??8????1-8??????????VOS_OK??????????VOS_ERR */
    if ((enDlci >= AT_MUX_DLCI1_ID)
     && (enDlci < (AT_MUX_DLCI1_ID + AT_MUX_AT_CHANNEL_MAX)))
    {
        return VOS_OK;
    }

    return VOS_ERR;
}


VOS_UINT32 AT_CheckMuxUser(VOS_UINT8 ucIndex)
{
    return VOS_FALSE;
}


VOS_UINT32 AT_IsHsicOrMuxUser(VOS_UINT8 ucIndex)
{
    VOS_UINT32                          ulHsicUserFlg;
    VOS_UINT32                          ulMuxUserFlg;

    ulHsicUserFlg = AT_CheckHsicUser(ucIndex);
    ulMuxUserFlg  = AT_CheckMuxUser(ucIndex);

    /* ??????HSIC????????????MUX???? */
    if ((VOS_FALSE == ulHsicUserFlg)
     && (VOS_FALSE == ulMuxUserFlg))
    {
        return VOS_FALSE;
    }

    return VOS_TRUE;
}


VOS_UINT32 AT_GetMuxDlciFromClientIdx(
    VOS_UINT8                           ucIndex,
    AT_MUX_DLCI_TYPE_ENUM_UINT8        *penDlci
)
{
    VOS_UINT8                           ucLoop;

    for (ucLoop = 0; ucLoop < AT_MUX_AT_CHANNEL_MAX; ucLoop++)
    {
        if (ucIndex == AT_GetCommCtxAddr()->stMuxCtx.astMuxClientTab[ucLoop].enAtClientTabIdx)
        {
            *penDlci = AT_GetCommCtxAddr()->stMuxCtx.astMuxClientTab[ucLoop].enDlci;
            break;
        }
    }

    if (ucLoop >= AT_MUX_AT_CHANNEL_MAX)
    {
        return VOS_FALSE;
    }

    return VOS_TRUE;
}

VOS_UINT32 AT_CheckPcuiCtrlConcurrent(
    VOS_UINT8                           ucIndexOne,
    VOS_UINT8                           ucIndexTwo
)
{
    VOS_UINT32                          ulUserFlg1;
    VOS_UINT32                          ulUserFlg2;

    ulUserFlg1 = AT_CheckUserType(ucIndexOne, AT_USBCOM_USER);
    ulUserFlg1 |= AT_CheckUserType(ucIndexOne, AT_CTR_USER);
    ulUserFlg1 |= AT_CheckUserType(ucIndexOne, AT_PCUI2_USER);

    if (VOS_TRUE != ulUserFlg1)
    {
        return VOS_FALSE;
    }

    ulUserFlg2 = AT_CheckUserType(ucIndexTwo, AT_USBCOM_USER);
    ulUserFlg2 |= AT_CheckUserType(ucIndexTwo, AT_CTR_USER);
    ulUserFlg2 |= AT_CheckUserType(ucIndexTwo, AT_PCUI2_USER);

    if (VOS_TRUE != ulUserFlg2)
    {
        return VOS_FALSE;
    }

    if (gastAtClientTab[ucIndexOne].UserType != gastAtClientTab[ucIndexTwo].UserType)
    {
        return VOS_TRUE;
    }

    return VOS_FALSE;
}


VOS_UINT32 AT_IsConcurrentPorts(
    VOS_UINT8                           ucIndexOne,
    VOS_UINT8                           ucIndexTwo
)
{
    VOS_UINT32                          ulMuxUserFlg1;
    VOS_UINT32                          ulHsicUserFlg1;
    VOS_UINT32                          ulAppUserFlg1;
    VOS_UINT32                          ulMuxUserFlg2;
    VOS_UINT32                          ulHsicUserFlg2;
    VOS_UINT32                          ulAppUserFlg2;

    /* ???????????????????????????????????? */
    ulMuxUserFlg1  = AT_CheckMuxUser(ucIndexOne);
    ulHsicUserFlg1 = AT_CheckHsicUser(ucIndexOne);
    ulAppUserFlg1  = AT_CheckAppUser(ucIndexOne);

    ulMuxUserFlg2  = AT_CheckMuxUser(ucIndexTwo);
    ulHsicUserFlg2 = AT_CheckHsicUser(ucIndexTwo);
    ulAppUserFlg2  = AT_CheckAppUser(ucIndexTwo);

    /* ????1??HSIC??????MUX????,????2????HSIC??????MUX???? */
    if ((VOS_TRUE == ulMuxUserFlg1)
     || (VOS_TRUE == ulHsicUserFlg1))
    {
        if ((VOS_TRUE == ulMuxUserFlg2)
         || (VOS_TRUE == ulHsicUserFlg2))
        {
            return VOS_TRUE;
        }
    }

    /* ????1??APP????,????2????APP???? */
    if (VOS_TRUE == ulAppUserFlg1)
    {
        if (VOS_TRUE == ulAppUserFlg2)
        {
            return VOS_TRUE;
        }
    }

    /* PCUI??CTRL?????????????????????? */
    if (VOS_TRUE == AT_GetPcuiCtrlConcurrentFlag())
    {
        if (VOS_TRUE == AT_CheckPcuiCtrlConcurrent(ucIndexOne, ucIndexTwo))
        {
            return VOS_TRUE;
        }
    }

    return VOS_FALSE;
}


VOS_VOID AT_MuxCmdStreamEcho(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                          *pData,
    VOS_UINT16                          usLen
)
{
    AT_MUX_DLCI_TYPE_ENUM_UINT8         enDlci;
    VOS_UINT32                          ulRslt;

    enDlci = AT_MUX_DLCI_TYPE_BUTT;

    ulRslt = AT_GetMuxDlciFromClientIdx(ucIndex, &enDlci);

    if (VOS_TRUE != ulRslt)
    {
        return;
    }

    MUX_DlciDlDataSend(enDlci, pData, usLen);
    AT_MNTN_TraceCmdResult(ucIndex, pData, usLen);

    return;
}



VOS_UINT32 AT_SendMuxSelResultData(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                          *pData,
    VOS_UINT16                          usLen
)
{
    VOS_UINT8                           ucLoop;
    AT_COMM_CTX_STRU                   *pCommCtx = VOS_NULL_PTR;

    pCommCtx = AT_GetCommCtxAddr();

    /* ??????????MUX??index */
    for (ucLoop = 0; ucLoop < AT_MUX_AT_CHANNEL_MAX; ucLoop++)
    {
        if (ucIndex == pCommCtx->stMuxCtx.astMuxClientTab[ucLoop].enAtClientTabIdx)
        {
            break;
        }
    }

    if (ucLoop >= AT_MUX_AT_CHANNEL_MAX)
    {
        return VOS_ERR;
    }

    /* ????????????????????AT???? */
    if (AT_HSIC_REPORT_OFF == pCommCtx->stMuxCtx.astMuxClientTab[ucLoop].enRptType)
    {
        return VOS_ERR;
    }

    AT_SendMuxResultData(ucIndex, pData, usLen);

    return VOS_OK;
}



VOS_UINT32 AT_SendMuxResultData(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                          *pData,
    VOS_UINT16                          usLen
)
{
    AT_MUX_DLCI_TYPE_ENUM_UINT8         enDlci;
    VOS_UINT32                          ulRslt;

    enDlci = AT_MUX_DLCI_TYPE_BUTT;

    /* MUX???????????????????????????????? */
    if (VOS_TRUE != AT_GetMuxSupportFlg())
    {
        return AT_FAILURE;
    }

    /* ????Dlci */
    ulRslt = AT_GetMuxDlciFromClientIdx(ucIndex, &enDlci);

    if (VOS_TRUE != ulRslt)
    {
        return AT_FAILURE;
    }

    AT_MNTN_TraceCmdResult(ucIndex, pData, usLen);

    /* ??MUX???????? */
    MUX_DlciDlDataSend(enDlci, pData, usLen);

    return AT_SUCCESS;
}



VOS_VOID AT_SndDipcPdpActInd(
    VOS_UINT16                          usClientId,
    VOS_UINT8                           ucCid,
    VOS_UINT8                           ucRabId
)
{
    VOS_UINT32                      ulLength;
    AT_DIPC_PDP_ACT_STRU           *pstAtDipcPdpAct;
    AT_MODEM_PS_CTX_STRU           *pstPsModemCtx = VOS_NULL_PTR;

    ulLength        = sizeof( AT_DIPC_PDP_ACT_STRU ) - VOS_MSG_HEAD_LENGTH;
    pstAtDipcPdpAct = ( AT_DIPC_PDP_ACT_STRU *)PS_ALLOC_MSG( WUEPS_PID_AT, ulLength );

    if ( VOS_NULL_PTR == pstAtDipcPdpAct )
    {
        /*????????????---??????????????:*/
        AT_WARN_LOG( "AT_SndDipcPdpActInd:ERROR:Allocates a message packet for AT_DIPC_PDP_ACT_STRU FAIL!" );
        return;
    }

    pstPsModemCtx = AT_GetModemPsCtxAddrFromClientId(usClientId);

    /*??????????:*/
    pstAtDipcPdpAct->ulSenderCpuId   = VOS_LOCAL_CPUID;
    pstAtDipcPdpAct->ulSenderPid     = WUEPS_PID_AT;
    pstAtDipcPdpAct->ulReceiverCpuId = VOS_LOCAL_CPUID;
    pstAtDipcPdpAct->ulReceiverPid   = PS_PID_APP_DIPC;
    pstAtDipcPdpAct->ulLength        = ulLength;
    /*??????????:*/
    pstAtDipcPdpAct->enMsgType       = ID_AT_DIPC_PDP_ACT_IND;
    pstAtDipcPdpAct->ucRabId         = ucRabId;
    pstAtDipcPdpAct->enUdiDevId      = (UDI_DEVICE_ID_E)pstPsModemCtx->astChannelCfg[ucCid].ulRmNetId;

    /*??????????:*/
    if ( VOS_OK != PS_SEND_MSG( WUEPS_PID_AT, pstAtDipcPdpAct ) )
    {
        /*????????????---????????????:*/
        AT_WARN_LOG( "AT_SndDipcPdpActInd:WARNING:SEND AT_DIPC_PDP_ACT_STRU msg FAIL!" );
    }

    return;
}




VOS_VOID AT_SndDipcPdpDeactInd(
    VOS_UINT8                           ucRabId
)
{
    VOS_UINT32                      ulLength;
    AT_DIPC_PDP_DEACT_STRU         *pstAtDipcPdpDeact;

    ulLength          = sizeof( AT_DIPC_PDP_DEACT_STRU ) - VOS_MSG_HEAD_LENGTH;
    pstAtDipcPdpDeact = ( AT_DIPC_PDP_DEACT_STRU *)PS_ALLOC_MSG( WUEPS_PID_AT, ulLength );

    if ( VOS_NULL_PTR == pstAtDipcPdpDeact )
    {
        /*????????????---??????????????:*/
        AT_WARN_LOG( "AT_SndDipcPdpDeactInd:ERROR:Allocates a message packet for AT_DIPC_PDP_DEACT_STRU FAIL!" );
        return;
    }

    /*??????????:*/
    pstAtDipcPdpDeact->ulSenderCpuId   = VOS_LOCAL_CPUID;
    pstAtDipcPdpDeact->ulSenderPid     = WUEPS_PID_AT;
    pstAtDipcPdpDeact->ulReceiverCpuId = VOS_LOCAL_CPUID;
    pstAtDipcPdpDeact->ulReceiverPid   = PS_PID_APP_DIPC;
    pstAtDipcPdpDeact->ulLength        = ulLength;
    /*??????????:*/
    pstAtDipcPdpDeact->enMsgType       = ID_AT_DIPC_PDP_REL_IND;
    pstAtDipcPdpDeact->ucRabId         = ucRabId;

    /*??????????:*/
    if ( VOS_OK != PS_SEND_MSG( WUEPS_PID_AT, pstAtDipcPdpDeact ) )
    {
        /*????????????---????????????:*/
        AT_WARN_LOG( "AT_SndDipcPdpDeactInd:WARNING:SEND AT_DIPC_PDP_DEACT_STRU msg FAIL!" );
    }

    return;
}



VOS_VOID AT_SetAtChdataCidActStatus(
    VOS_UINT16                          usClientId,
    VOS_UINT8                           ucCid,
    VOS_UINT32                          ulIsCidAct
)
{
    AT_MODEM_PS_CTX_STRU               *pstPsModemCtx = VOS_NULL_PTR;

    /* ????CID?????? */
    if ( ucCid > TAF_MAX_CID_NV)
    {
        AT_ERR_LOG1("AT_SetAtChdataCidActStatus, WARNING, CID error:%d\r\n", ucCid);
        return;
    }

    pstPsModemCtx = AT_GetModemPsCtxAddrFromClientId(usClientId);

    /* ????CID???????????????????? */
    pstPsModemCtx->astChannelCfg[ucCid].ulRmNetActFlg = ulIsCidAct;

    return;
}




VOS_VOID AT_CleanAtChdataCfg(
    VOS_UINT16                          usClientId,
    VOS_UINT8                           ucCid,
    VOS_UINT8                           ucCallId,
    TAF_PS_APN_DATA_SYS_ENUM_UINT8      enDataSys
)
{
    AT_MODEM_PS_CTX_STRU               *pstPsModemCtx = VOS_NULL_PTR;

    /* ????CID?????? */
    if ( ucCid > TAF_MAX_CID_NV)
    {
        AT_ERR_LOG1("AT_CleanAtChdataCfg, WARNING, CID error:%d\r\n", ucCid);
        return;
    }

    pstPsModemCtx = AT_GetModemPsCtxAddrFromClientId(usClientId);

    if (ucCallId < AT_PS_MAX_CALL_NUM)
    {
        if (VOS_FALSE == AT_PS_IsNeedClearCurrCall(usClientId, ucCallId, enDataSys))
        {
            AT_NORM_LOG("AT_PS_FreeCallEntity: not need FreeCallEntity!");
            return;
        }
    }

    /* ????CID???????????????????? */
    pstPsModemCtx->astChannelCfg[ucCid].ulUsed      = VOS_FALSE;
    pstPsModemCtx->astChannelCfg[ucCid].ulRmNetId   = AT_PS_INVALID_RMNET_ID;
    pstPsModemCtx->astChannelCfg[ucCid].ulIfaceld   = AT_PS_INVALID_IFACE_ID;
    /* ??????CID??PDP???????????????????????? */
    pstPsModemCtx->astChannelCfg[ucCid].ulRmNetActFlg = VOS_FALSE;

    return;
}


VOS_UINT32 AT_CheckHsicUser(VOS_UINT8 ucIndex)
{
    return VOS_FALSE;

}


VOS_UINT32 AT_CheckAppUser(VOS_UINT8 ucIndex)
{
    if (AT_APP_USER != gastAtClientTab[ucIndex].UserType)
    {
        return VOS_FALSE;
    }

    return VOS_TRUE;

}


VOS_UINT32 AT_CheckNdisUser(VOS_UINT8 ucIndex)
{
    if (AT_NDIS_USER != gastAtClientTab[ucIndex].UserType)
    {
        return VOS_FALSE;
    }

    return VOS_TRUE;

}


VOS_UINT32 AT_CheckHsUartUser(VOS_UINT8 ucIndex)
{

    return VOS_FALSE;
}


VOS_UINT32 AT_CheckModemUser(VOS_UINT8 ucIndex)
{
    if (AT_MODEM_USER != gastAtClientTab[ucIndex].UserType)
    {
        return VOS_FALSE;
    }

    return VOS_TRUE;
}


VOS_UINT32 AT_CheckUserType(
    VOS_UINT8                               ucIndex,
    AT_USER_TYPE                            enUserType
)
{
    if (enUserType != gastAtClientTab[ucIndex].UserType)
    {
        return VOS_FALSE;
    }

    return VOS_TRUE;
}


VOS_VOID AT_InitFcMap(VOS_VOID)
{
    VOS_UINT8       ucLoop;

    /* ??????g_stFcIdMaptoFcPri */
    for (ucLoop = 0; ucLoop < FC_ID_BUTT; ucLoop++)
    {
        g_stFcIdMaptoFcPri[ucLoop].ulUsed  = VOS_FALSE;
        g_stFcIdMaptoFcPri[ucLoop].enFcPri = FC_PRI_BUTT;
        g_stFcIdMaptoFcPri[ucLoop].ulRabIdMask  = 0;
        g_stFcIdMaptoFcPri[ucLoop].enModemId    = MODEM_ID_BUTT;
    }
}


VOS_UINT32 AT_SendDiagCmdFromOm(
    VOS_UINT8                           ucPortNo,
    VOS_UINT8                           ucType,
    VOS_UINT8                          *pData,
    VOS_UINT16                          uslength
)
{
    return VOS_OK;
}


VOS_UINT32 AT_SendPcuiDataFromOm(
    VOS_UINT8                          *pucVirAddr,
    VOS_UINT8                          *pucPhyAddr,
    VOS_UINT32                          ulLength
)
{
    if (AT_SUCCESS != At_SendData(AT_CLIENT_TAB_PCUI_INDEX,
                                  gastAtClientTab[AT_CLIENT_TAB_PCUI_INDEX].DataMode,
                                  pucVirAddr,
                                  (VOS_UINT16)ulLength))
    {
        return VOS_ERR;
    }
    else
    {
        return VOS_OK;
    }
}


VOS_UINT32 AT_SendCtrlDataFromOm(
    VOS_UINT8                          *pucVirAddr,
    VOS_UINT8                          *pucPhyAddr,
    VOS_UINT32                          ulLength
)
{
    if (AT_SUCCESS != At_SendData(AT_CLIENT_TAB_CTRL_INDEX,
                                  gastAtClientTab[AT_CLIENT_TAB_CTRL_INDEX].DataMode,
                                  pucVirAddr,
                                  (VOS_UINT16)ulLength))
    {
        return VOS_ERR;
    }
    else
    {
        return VOS_OK;
    }
}


VOS_UINT32 AT_SendPcui2DataFromOm(
    VOS_UINT8                          *pucVirAddr,
    VOS_UINT8                          *pucPhyAddr,
    VOS_UINT32                          ulLength
)
{
    if (AT_SUCCESS != At_SendData(AT_CLIENT_TAB_PCUI2_INDEX,
                                  gastAtClientTab[AT_CLIENT_TAB_PCUI2_INDEX].DataMode,
                                  pucVirAddr,
                                  (VOS_UINT16)ulLength))
    {
        return VOS_ERR;
    }
    else
    {
        return VOS_OK;
    }
}



CBTCPM_SEND_FUNC AT_QuerySndFunc(AT_PHY_PORT_ENUM_UINT32 ulPhyPort)
{
    switch(ulPhyPort)
    {
        case AT_UART_PORT:
            return AT_UART_SendRawDataFromOm;

        case AT_PCUI_PORT:
            return AT_SendPcuiDataFromOm;

        case AT_CTRL_PORT:
            return AT_SendCtrlDataFromOm;


        default:
            AT_WARN_LOG("AT_QuerySndFunc: don't proc data of this port!");
            return VOS_NULL_PTR;
    }
}


TAF_UINT32 At_SendCmdMsg (TAF_UINT8 ucIndex,TAF_UINT8* pData, TAF_UINT16 usLen,TAF_UINT8 ucType)
{
    AT_MSG_STRU                        *pMsg = TAF_NULL_PTR;
    AT_CMD_MSG_NUM_CTRL_STRU           *pstMsgNumCtrlCtx = VOS_NULL_PTR;
    VOS_UINT_PTR                        ulTmpAddr;
    VOS_UINT32                          ulLength;
    VOS_ULONG                           ulLockLevel;
    MODEM_ID_ENUM_UINT16                enModemId;
    pstMsgNumCtrlCtx = AT_GetMsgNumCtrlCtxAddr();

    if (VOS_NULL_PTR == pData)
    {
        AT_WARN_LOG("At_SendCmdMsg :pData is null ptr!");
        return AT_FAILURE;
    }

    if (0 == usLen)
    {
        AT_WARN_LOG("At_SendCmdMsg ulLength = 0");
        return AT_FAILURE;
    }

    if (AT_COM_BUFF_LEN < usLen)
    {
        AT_WARN_LOG("At_SendCmdMsg ulLength > AT_COM_BUFF_LEN");
        return AT_FAILURE;
    }

    /* ????????????ITEM????4?????? */
    AT_GetAtMsgStruMsgLength(usLen, &ulLength);
    pMsg = (AT_MSG_STRU *)PS_ALLOC_MSG(WUEPS_PID_AT, ulLength);
    if ( pMsg == TAF_NULL_PTR )
    {
        AT_ERR_LOG("At_SendCmdMsg:ERROR:Alloc Msg");
        return AT_FAILURE;
    }

    if (AT_NORMAL_TYPE_MSG == ucType)
    {
        if (pstMsgNumCtrlCtx->ulMsgCount > AT_MAX_MSG_NUM)
        {
            /*lint -save -e516 */
            /* ?????????????????? */
            PS_FREE_MSG(WUEPS_PID_AT, pMsg);
            /*lint -restore */

            return AT_FAILURE;
        }

        /*lint -e571*/
        VOS_SpinLockIntLock(&(pstMsgNumCtrlCtx->stSpinLock), ulLockLevel);
        /*lint +e571*/

        pstMsgNumCtrlCtx->ulMsgCount++;

        VOS_SpinUnlockIntUnlock(&(pstMsgNumCtrlCtx->stSpinLock), ulLockLevel);
    }

    /* ????????????????????????pMsg->aucValue;*/
    pMsg->ulReceiverCpuId   = VOS_LOCAL_CPUID;
    pMsg->ulSenderPid       = WUEPS_PID_AT;
    pMsg->ulReceiverPid     = WUEPS_PID_AT;

    if (AT_COMBIN_BLOCK_MSG == ucType)
    {
        pMsg->enMsgId = ID_AT_COMBIN_BLOCK_CMD;
    }
    else
    {
        pMsg->enMsgId = AT_GetCmdMsgID(ucIndex);
    }

    pMsg->ucType            = ucType;     /* ???? */
    pMsg->ucIndex           = ucIndex;    /* ???? */
    pMsg->usLen             = usLen;    /* ???? */

    enModemId               = MODEM_ID_0;
    if (VOS_OK != AT_GetModemIdFromClient(ucIndex, &enModemId))
    {
        enModemId = MODEM_ID_0;
    }

    pMsg->enModemId     = (VOS_UINT8)enModemId;
    /* ????????*/
    pMsg->enVersionId   = 0xAA;
    pMsg->ucFilterAtType  = (VOS_UINT8)g_enLogPrivacyAtCmd;

    TAF_MEM_SET_S(pMsg->aucValue, sizeof(pMsg->aucValue), 0x00, sizeof(pMsg->aucValue));
    AT_GetUserTypeFromIndex(ucIndex, &pMsg->ucUserType);


    /* ?????????????? */
    ulTmpAddr = (VOS_UINT_PTR)(pMsg->aucValue);
    TAF_MEM_CPY_S((VOS_VOID*)ulTmpAddr, usLen, pData, usLen);  /* ???? */

    /*??????????AT_PID;*/
    if ( 0 != PS_SEND_MSG( WUEPS_PID_AT, pMsg ) )
    {
        AT_ERR_LOG("At_SendCmdMsg:ERROR:VOS_SendMsg");

        /* ??????????????????????????????????????????????ulMsgCount--???? */

        return AT_FAILURE;
    }
    return AT_SUCCESS;
}


VOS_UINT32 AT_IsApPort(VOS_UINT8 ucIndex)
{
    VOS_UINT32                          ulHsicUserFlg;
    VOS_UINT32                          ulMuxUserFlg;
    VOS_UINT32                          ulVcomUserFlg;
    VOS_UINT8                          *pucSystemAppConfig;

    if (0 == g_stAtDebugInfo.ucUnCheckApPortFlg)
    {
        /* ?????? */
        pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

        ulHsicUserFlg = AT_CheckHsicUser(ucIndex);
        ulMuxUserFlg  = AT_CheckMuxUser(ucIndex);
        ulVcomUserFlg = AT_CheckAppUser(ucIndex);

        if (SYSTEM_APP_ANDROID == *pucSystemAppConfig)
        {
            /* ????????????????????????HSIC??????MUX??????VCOM???? */
            if ((VOS_FALSE == ulHsicUserFlg)
             && (VOS_FALSE == ulMuxUserFlg)
             && (VOS_FALSE == ulVcomUserFlg))
            {
                return VOS_FALSE;
            }
        }
        else
        {
            /* ????????????????????????HSIC??????MUX???? */
            if ((VOS_FALSE == ulHsicUserFlg)
             && (VOS_FALSE == ulMuxUserFlg))
            {
                return VOS_FALSE;
            }
        }
    }

    return VOS_TRUE;
}


VOS_INT AT_ProcCCpuResetBefore(VOS_VOID)
{
    AT_MSG_STRU                        *pstMsg = VOS_NULL_PTR;

    AT_PR_LOGI("enter, %u", VOS_GetSlice());

    /* ???????????????????? */
    AT_SetResetFlag(VOS_TRUE);

    DMS_InitModemStatus();

    /* ????TAFAGENT???????????? */
    TAF_AGENT_ClearAllSem();

    /* ???????? */
    /*lint -save -e516 */
    pstMsg = (AT_MSG_STRU *)PS_ALLOC_MSG_WITH_HEADER_LEN(WUEPS_PID_AT,
                                                         sizeof(AT_MSG_STRU));
    /*lint -restore */
    if (VOS_NULL_PTR == pstMsg)
    {
        AT_PR_LOGE("alloc msg fail, %u", VOS_GetSlice());
        return VOS_ERROR;
    }

    /* ?????????? */
    TAF_MEM_SET_S((VOS_CHAR *)pstMsg + VOS_MSG_HEAD_LENGTH,
               (VOS_SIZE_T)(sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH),
               0x00,
               (VOS_SIZE_T)(sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH));

    /* ?????????? */
    pstMsg->ulReceiverCpuId             = VOS_LOCAL_CPUID;
    pstMsg->ulReceiverPid               = WUEPS_PID_AT;
    pstMsg->ucType                      = ID_CCPU_AT_RESET_START_IND;

    pstMsg->enMsgId                     = ID_AT_COMM_CCPU_RESET_START;

    /* ?????? */
    if (VOS_OK != PS_SEND_MSG(WUEPS_PID_AT, pstMsg))
    {
        AT_PR_LOGE("send msg fail, %u", VOS_GetSlice());
        return VOS_ERROR;
    }

    /* ???????????????????????????????????????????????????????? */
    if (VOS_OK != VOS_SmP(AT_GetResetSem(), AT_RESET_TIMEOUT_LEN))
    {
        AT_PR_LOGE("VOS_SmP fail, %u", VOS_GetSlice());
        AT_DBG_LOCK_BINARY_SEM_FAIL_NUM(1);

        return VOS_ERROR;
    }

    /* ???????????????? */
    AT_DBG_SAVE_CCPU_RESET_BEFORE_NUM(1);

    AT_PR_LOGI("succ, %u", VOS_GetSlice());

    return VOS_OK;
}


VOS_INT AT_ProcCCpuResetAfter(VOS_VOID)
{
    AT_MSG_STRU                        *pstMsg = VOS_NULL_PTR;

    AT_PR_LOGI("enter, %u", VOS_GetSlice());

    /* ???????? */
    /*lint -save -e516 */
    pstMsg = (AT_MSG_STRU *)PS_ALLOC_MSG_WITH_HEADER_LEN(WUEPS_PID_AT,
                                                         sizeof(AT_MSG_STRU));
    /*lint -restore */
    if (VOS_NULL_PTR == pstMsg)
    {
        AT_PR_LOGE("alloc msg fail, %u", VOS_GetSlice());
        return VOS_ERROR;
    }

    /* ?????????? */
    TAF_MEM_SET_S((VOS_CHAR *)pstMsg + VOS_MSG_HEAD_LENGTH,
               (VOS_SIZE_T)(sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH),
               0x00,
               (VOS_SIZE_T)(sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH));

    /* ?????????? */
    pstMsg->ulReceiverCpuId             = VOS_LOCAL_CPUID;
    pstMsg->ulReceiverPid               = WUEPS_PID_AT;
    pstMsg->ucType                      = ID_CCPU_AT_RESET_END_IND;

    pstMsg->enMsgId                     = ID_AT_COMM_CCPU_RESET_END;

    /* ?????? */
    if (VOS_OK != PS_SEND_MSG(WUEPS_PID_AT, pstMsg))
    {
        AT_PR_LOGE("send msg fail, %u", VOS_GetSlice());
        return VOS_ERROR;
    }

    /* ???????????????? */
    AT_DBG_SAVE_CCPU_RESET_AFTER_NUM(1);

    AT_PR_LOGI("succ, %u", VOS_GetSlice());

    return VOS_OK;
}


VOS_INT AT_CCpuResetCallback(
    DRV_RESET_CB_MOMENT_E               enParam,
    VOS_INT                             iUserData
)
{
    /* ?????? */
    if (MDRV_RESET_CB_BEFORE == enParam)
    {
        return AT_ProcCCpuResetBefore();
    }
    /* ?????? */
    else if (MDRV_RESET_CB_AFTER == enParam)
    {
        return AT_ProcCCpuResetAfter();
    }
    else
    {
        return VOS_ERROR;
    }
}


#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4, 9, 0))
VOS_INT AT_HifiResetCallback(
    DRV_RESET_CB_MOMENT_E               enParam,
    VOS_INT                             iUserData
)
{
    AT_MSG_STRU                        *pstMsg = VOS_NULL_PTR;

    /* ??????0?????????????? */
    if (MDRV_RESET_CB_BEFORE == enParam)
    {
        AT_PR_LOGI("before reset enter, %u", VOS_GetSlice());
        /* ???????? */
        /*lint -save -e516 */
        pstMsg = (AT_MSG_STRU *)PS_ALLOC_MSG_WITH_HEADER_LEN(WUEPS_PID_AT,
                                                             sizeof(AT_MSG_STRU));
        /*lint -restore */
        if (VOS_NULL_PTR == pstMsg)
        {
            AT_PR_LOGE("before reset alloc msg fail, %u", VOS_GetSlice());
            return VOS_ERROR;
        }

        /* ?????????? */
        TAF_MEM_SET_S((VOS_CHAR *)pstMsg + VOS_MSG_HEAD_LENGTH,
                   (VOS_SIZE_T)(sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH),
                   0x00,
                   (VOS_SIZE_T)(sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH));

        /* ?????????? */
        pstMsg->ulReceiverCpuId             = VOS_LOCAL_CPUID;
        pstMsg->ulReceiverPid               = WUEPS_PID_AT;
        pstMsg->ucType                      = ID_HIFI_AT_RESET_START_IND;

        pstMsg->enMsgId                     = ID_AT_COMM_HIFI_RESET_START;

        /* ?????? */
        if (VOS_OK != PS_SEND_MSG(WUEPS_PID_AT, pstMsg))
        {
            AT_PR_LOGE("after reset alloc msg fail, %u", VOS_GetSlice());
            return VOS_ERROR;
        }

        return VOS_OK;
    }
    /* ?????? */
    else if (MDRV_RESET_CB_AFTER == enParam)
    {
        AT_PR_LOGI("after reset enter, %u", VOS_GetSlice());
        /* ???????? */
        /*lint -save -e516 */
        pstMsg = (AT_MSG_STRU *)PS_ALLOC_MSG_WITH_HEADER_LEN(WUEPS_PID_AT,
                                                             sizeof(AT_MSG_STRU));
        /*lint -restore */
        if (VOS_NULL_PTR == pstMsg)
        {
            AT_PR_LOGE("after reset alloc msg fail, %u", VOS_GetSlice());
            return VOS_ERROR;
        }

        /* ?????????? */
        TAF_MEM_SET_S((VOS_CHAR *)pstMsg + VOS_MSG_HEAD_LENGTH,
                   (VOS_SIZE_T)(sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH),
                   0x00,
                   (VOS_SIZE_T)(sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH));

        /* ?????????? */
        pstMsg->ulReceiverCpuId             = VOS_LOCAL_CPUID;
        pstMsg->ulReceiverPid               = WUEPS_PID_AT;
        pstMsg->ucType                      = ID_HIFI_AT_RESET_END_IND;

        pstMsg->enMsgId                     = ID_AT_COMM_HIFI_RESET_END;

        /* ?????? */
        if (VOS_OK != PS_SEND_MSG(WUEPS_PID_AT, pstMsg))
        {
            AT_PR_LOGE("after reset send msg fail, %u", VOS_GetSlice());
            return VOS_ERROR;
        }
        return VOS_OK;
    }
    else
    {
        return VOS_ERROR;
    }
}
#else
VOS_INT AT_HifiResetCallback(
    enum DRV_RESET_CALLCBFUN_MOMENT     enParam,
    VOS_INT                             iUserData
)
{
    AT_MSG_STRU                        *pstMsg = VOS_NULL_PTR;

    /* ??????0?????????????? */
    if (DRV_RESET_CALLCBFUN_RESET_BEFORE == enParam)
    {
        AT_PR_LOGI("before reset enter, %u", VOS_GetSlice());
        /* ???????? */
        /*lint -save -e516 */
        pstMsg = (AT_MSG_STRU *)PS_ALLOC_MSG_WITH_HEADER_LEN(WUEPS_PID_AT,
                                                             sizeof(AT_MSG_STRU));
        /*lint -restore */
        if (VOS_NULL_PTR == pstMsg)
        {
            AT_PR_LOGE("before reset alloc msg fail, %u", VOS_GetSlice());
            return VOS_ERROR;
        }

        /* ?????????? */
        TAF_MEM_SET_S((VOS_CHAR *)pstMsg + VOS_MSG_HEAD_LENGTH,
                   (VOS_SIZE_T)(sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH),
                   0x00,
                   (VOS_SIZE_T)(sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH));

        /* ?????????? */
        pstMsg->ulReceiverCpuId             = VOS_LOCAL_CPUID;
        pstMsg->ulReceiverPid               = WUEPS_PID_AT;
        pstMsg->ucType                      = ID_HIFI_AT_RESET_START_IND;

        pstMsg->enMsgId                     = ID_AT_COMM_HIFI_RESET_START;

        /* ?????? */
        if (VOS_OK != PS_SEND_MSG(WUEPS_PID_AT, pstMsg))
        {
            AT_PR_LOGE("after reset alloc msg fail, %u", VOS_GetSlice());
            return VOS_ERROR;
        }

        return VOS_OK;
    }
    /* ?????? */
    else if (DRV_RESET_CALLCBFUN_RESET_AFTER == enParam)
    {
        AT_PR_LOGI("after reset enter, %u", VOS_GetSlice());
        /* ???????? */
        /*lint -save -e516 */
        pstMsg = (AT_MSG_STRU *)PS_ALLOC_MSG_WITH_HEADER_LEN(WUEPS_PID_AT,
                                                             sizeof(AT_MSG_STRU));
        /*lint -restore */
        if (VOS_NULL_PTR == pstMsg)
        {
            AT_PR_LOGE("after reset alloc msg fail, %u", VOS_GetSlice());
            return VOS_ERROR;
        }

        /* ?????????? */
        TAF_MEM_SET_S((VOS_CHAR *)pstMsg + VOS_MSG_HEAD_LENGTH,
                   (VOS_SIZE_T)(sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH),
                   0x00,
                   (VOS_SIZE_T)(sizeof(AT_MSG_STRU) - VOS_MSG_HEAD_LENGTH));

        /* ?????????? */
        pstMsg->ulReceiverCpuId             = VOS_LOCAL_CPUID;
        pstMsg->ulReceiverPid               = WUEPS_PID_AT;
        pstMsg->ucType                      = ID_HIFI_AT_RESET_END_IND;

        pstMsg->enMsgId                     = ID_AT_COMM_HIFI_RESET_END;

        /* ?????? */
        if (VOS_OK != PS_SEND_MSG(WUEPS_PID_AT, pstMsg))
        {
            AT_PR_LOGE("after reset send msg fail, %u", VOS_GetSlice());
            return VOS_ERROR;
        }
        return VOS_OK;
    }
    else
    {
        return VOS_ERROR;
    }
}
#endif


VOS_VOID AT_ModemeEnableCB(
    VOS_UINT8                           ucIndex,
    VOS_UINT32                          ulEnable
)
{
    /* ??????????????????????????????????????????????
    ?? ??????????????????????????????PPP????????????????
       ??????AT??????PDP.
    */
    if (PS_FALSE == ulEnable)
    {
        if (AT_PPP_DATA_MODE == gastAtClientTab[ucIndex].DataMode)
        {
            PPP_RcvAtCtrlOperEvent(gastAtClientTab[ucIndex].usPppId,
                                   PPP_AT_CTRL_REL_PPP_REQ);

            /* ?????????????????????????????? */
            if (0 == (gastAtClientTab[ucIndex].ModemStatus & IO_CTRL_CTS))
            {
                AT_StopFlowCtrl(ucIndex);
            }

            /* ???????? */
            if (VOS_OK != TAF_PS_CallEnd(WUEPS_PID_AT,
                                         AT_PS_BuildExClientId(gastAtClientTab[ucIndex].usClientId),
                                         0,
                                         gastAtClientTab[ucIndex].ucCid))
            {
                AT_ERR_LOG("AT_ModemeEnableCB: TAF_PS_CallEnd failed in <AT_PPP_DATA_MODE>!");
                return;
            }
        }
        else if (AT_IP_DATA_MODE == gastAtClientTab[ucIndex].DataMode)
        {
            PPP_RcvAtCtrlOperEvent(gastAtClientTab[ucIndex].usPppId,
                                   PPP_AT_CTRL_REL_PPP_RAW_REQ);

            /* ?????????????????????????????? */
            if (0 == (gastAtClientTab[ucIndex].ModemStatus & IO_CTRL_CTS))
            {
                AT_StopFlowCtrl(ucIndex);
            }

            /* ???????? */
            if ( VOS_OK != TAF_PS_CallEnd(WUEPS_PID_AT,
                                          AT_PS_BuildExClientId(gastAtClientTab[ucIndex].usClientId),
                                          0,
                                          gastAtClientTab[ucIndex].ucCid) )
            {
                AT_ERR_LOG("AT_ModemeEnableCB: TAF_PS_CallEnd failed in <AT_IP_DATA_MODE>!");
                return;
            }
        }
        else
        {
            /* ????else??????????PCLINT???? */
        }

        /* ??PPP????HDLC?????????? */
        PPP_RcvAtCtrlOperEvent(gastAtClientTab[ucIndex].usPppId,
                               PPP_AT_CTRL_HDLC_DISABLE);

        /* ?????????? */
        AT_StopRelTimer(ucIndex, &gastAtClientTab[ucIndex].hTimer);

        /* ????????????????At_ModemRelInd????????????USB??????????????????
           ????????Modem??always-on????????????????????AT??????????????
           ????????????????:
        */
        gastAtClientTab[ucIndex].Mode            = AT_CMD_MODE;
        gastAtClientTab[ucIndex].IndMode         = AT_IND_MODE;
        gastAtClientTab[ucIndex].DataMode        = AT_DATA_BUTT_MODE;
        gastAtClientTab[ucIndex].DataState       = AT_DATA_STOP_STATE;
        gastAtClientTab[ucIndex].CmdCurrentOpt   = AT_CMD_CURRENT_OPT_BUTT;
        g_stParseContext[ucIndex].ucClientStatus = AT_FW_CLIENT_STATUS_READY;
    }
}





