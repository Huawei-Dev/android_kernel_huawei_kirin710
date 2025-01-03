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
#include "siappstk.h"
#include "PppInterface.h"
#include "AtDataProc.h"
#include "AtEventReport.h"
#include "TafDrvAgent.h"
#include "AtOamInterface.h"
#include "MnCommApi.h"

#include "AtInputProc.h"
#include "FcInterface.h"
#include "AtCmdMsgProc.h"

#include "gen_msg.h"
#include "at_lte_common.h"

#include "TafAppMma.h"

#include "AppVcApi.h"
#include "TafAppRabm.h"
#include "AtCmdSimProc.h"

#include  "product_config.h"

#include "TafStdlib.h"

#include "AtMsgPrint.h"
#include "AtCmdCallProc.h"

#include "AtCmdSupsProc.h"

#include "mnmsgcbencdec.h"


/*****************************************************************************
  2 ????????
*****************************************************************************/
/*****************************************************************************
    ??????????????????????.C??????????
*****************************************************************************/
#define    THIS_FILE_ID        PS_FILE_ID_AT_EVENTREPORT_C

/*****************************************************************************
  3 ????????
*****************************************************************************/


/*****************************************************************************
  4 ????????????
*****************************************************************************/
const AT_SMS_ERROR_CODE_MAP_STRU        g_astAtSmsErrorCodeMap[] =
{
    {TAF_MSG_ERROR_RP_CAUSE_UNASSIGNED_UNALLOCATED_NUMBER,                              AT_CMS_UNASSIGNED_UNALLOCATED_NUMBER},
    {TAF_MSG_ERROR_RP_CAUSE_OPERATOR_DETERMINED_BARRING,                                AT_CMS_OPERATOR_DETERMINED_BARRING},
    {TAF_MSG_ERROR_RP_CAUSE_CALL_BARRED,                                                AT_CMS_CALL_BARRED},
    {TAF_MSG_ERROR_RP_CAUSE_SHORT_MESSAGE_TRANSFER_REJECTED,                            AT_CMS_SHORT_MESSAGE_TRANSFER_REJECTED},
    {TAF_MSG_ERROR_RP_CAUSE_DESTINATION_OUT_OF_ORDER,                                   AT_CMS_DESTINATION_OUT_OF_SERVICE},
    {TAF_MSG_ERROR_RP_CAUSE_UNIDENTIFIED_SUBSCRIBER,                                    AT_CMS_UNIDENTIFIED_SUBSCRIBER},
    {TAF_MSG_ERROR_RP_CAUSE_FACILITY_REJECTED,                                          AT_CMS_FACILITY_REJECTED},
    {TAF_MSG_ERROR_RP_CAUSE_UNKNOWN_SUBSCRIBER,                                         AT_CMS_UNKNOWN_SUBSCRIBER},
    {TAF_MSG_ERROR_RP_CAUSE_NETWORK_OUT_OF_ORDER,                                       AT_CMS_NETWORK_OUT_OF_ORDER},
    {TAF_MSG_ERROR_RP_CAUSE_TEMPORARY_FAILURE,                                          AT_CMS_TEMPORARY_FAILURE},
    {TAF_MSG_ERROR_RP_CAUSE_CONGESTION,                                                 AT_CMS_CONGESTION},
    {TAF_MSG_ERROR_RP_CAUSE_RESOURCES_UNAVAILABLE_UNSPECIFIED,                          AT_CMS_RESOURCES_UNAVAILABLE_UNSPECIFIED},
    {TAF_MSG_ERROR_RP_CAUSE_REQUESTED_FACILITY_NOT_SUBSCRIBED,                          AT_CMS_REQUESTED_FACILITY_NOT_SUBSCRIBED},
    {TAF_MSG_ERROR_RP_CAUSE_REQUESTED_FACILITY_NOT_IMPLEMENTED,                         AT_CMS_REQUESTED_FACILITY_NOT_IMPLEMENTED},
    {TAF_MSG_ERROR_RP_CAUSE_INVALID_SHORT_MESSAGE_TRANSFER_REFERENCE_VALUE,             AT_CMS_INVALID_SHORT_MESSAGE_TRANSFER_REFERENCE_VALUE},
    {TAF_MSG_ERROR_RP_CAUSE_INVALID_MANDATORY_INFORMATION,                              AT_CMS_INVALID_MANDATORY_INFORMATION},
    {TAF_MSG_ERROR_RP_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED,               AT_CMS_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED},
    {TAF_MSG_ERROR_RP_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_SHORT_MESSAGE_PROTOCOL_STATE,   AT_CMS_MESSAGE_NOT_COMPATIBLE_WITH_SHORT_MESSAGE_PROTOCOL_STATE},
    {TAF_MSG_ERROR_RP_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED,        AT_CMS_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED},
    {TAF_MSG_ERROR_RP_CAUSE_PROTOCOL_ERROR_UNSPECIFIED,                                 AT_CMS_PROTOCOL_ERROR_UNSPECIFIED},
    {TAF_MSG_ERROR_RP_CAUSE_INTERWORKING_UNSPECIFIED,                                   AT_CMS_INTERWORKING_UNSPECIFIED},
    {TAF_MSG_ERROR_TP_FCS_TELEMATIC_INTERWORKING_NOT_SUPPORTED,                         AT_CMS_TELEMATIC_INTERWORKING_NOT_SUPPORTED},
    {TAF_MSG_ERROR_TP_FCS_SHORT_MESSAGE_TYPE_0_NOT_SUPPORTED,                           AT_CMS_SHORT_MESSAGE_TYPE_0_NOT_SUPPORTED},
    {TAF_MSG_ERROR_TP_FCS_CANNOT_REPLACE_SHORT_MESSAGE,                                 AT_CMS_CANNOT_REPLACE_SHORT_MESSAGE},
    {TAF_MSG_ERROR_TP_FCS_UNSPECIFIED_TPPID_ERROR,                                      AT_CMS_UNSPECIFIED_TPPID_ERROR},
    {TAF_MSG_ERROR_TP_FCS_DATA_CODING_SCHEME_ALPHABET_NOT_SUPPORTED,                    AT_CMS_DATA_CODING_SCHEME_ALPHABET_NOT_SUPPORTED},
    {TAF_MSG_ERROR_TP_FCS_MESSAGE_CLASS_NOT_SUPPORTED,                                  AT_CMS_MESSAGE_CLASS_NOT_SUPPORTED},
    {TAF_MSG_ERROR_TP_FCS_UNSPECIFIED_TPDCS_ERROR,                                      AT_CMS_UNSPECIFIED_TPDCS_ERROR},
    {TAF_MSG_ERROR_TP_FCS_COMMAND_CANNOT_BE_ACTIONED,                                   AT_CMS_COMMAND_CANNOT_BE_ACTIONED},
    {TAF_MSG_ERROR_TP_FCS_COMMAND_UNSUPPORTED,                                          AT_CMS_COMMAND_UNSUPPORTED},
    {TAF_MSG_ERROR_TP_FCS_UNSPECIFIED_TPCOMMAND_ERROR,                                  AT_CMS_UNSPECIFIED_TPCOMMAND_ERROR},
    {TAF_MSG_ERROR_TP_FCS_TPDU_NOT_SUPPORTED,                                           AT_CMS_TPDU_NOT_SUPPORTED},
    {TAF_MSG_ERROR_TP_FCS_SC_BUSY,                                                      AT_CMS_SC_BUSY},
    {TAF_MSG_ERROR_TP_FCS_NO_SC_SUBSCRIPTION,                                           AT_CMS_NO_SC_SUBSCRIPTION},
    {TAF_MSG_ERROR_TP_FCS_SC_SYSTEM_FAILURE,                                            AT_CMS_SC_SYSTEM_FAILURE},
    {TAF_MSG_ERROR_TP_FCS_INVALID_SME_ADDRESS,                                          AT_CMS_INVALID_SME_ADDRESS},
    {TAF_MSG_ERROR_TP_FCS_DESTINATION_SME_BARRED,                                       AT_CMS_DESTINATION_SME_BARRED},
    {TAF_MSG_ERROR_TP_FCS_SM_REJECTEDDUPLICATE_SM,                                      AT_CMS_SM_REJECTEDDUPLICATE_SM},
    {TAF_MSG_ERROR_TP_FCS_TPVPF_NOT_SUPPORTED,                                          AT_CMS_TPVPF_NOT_SUPPORTED},
    {TAF_MSG_ERROR_TP_FCS_TPVP_NOT_SUPPORTED,                                           AT_CMS_TPVP_NOT_SUPPORTED},
    {TAF_MSG_ERROR_TP_FCS_SIM_SMS_STORAGE_FULL,                                         AT_CMS_SIM_SMS_STORAGE_FULL},
    {TAF_MSG_ERROR_TP_FCS_NO_SMS_STORAGE_CAPABILITY_IN_SIM,                             AT_CMS_NO_SMS_STORAGE_CAPABILITY_IN_SIM},
    {TAF_MSG_ERROR_TP_FCS_ERROR_IN_MS,                                                  AT_CMS_ERROR_IN_MS},
    {TAF_MSG_ERROR_TP_FCS_MEMORY_CAPACITY_EXCEEDED,                                     AT_CMS_MEMORY_CAPACITY_EXCEEDED},
    {TAF_MSG_ERROR_TP_FCS_SIM_APPLICATION_TOOLKIT_BUSY,                                 AT_CMS_SIM_APPLICATION_TOOLKIT_BUSY},
    {TAF_MSG_ERROR_TP_FCS_SIM_DATA_DOWNLOAD_ERROR,                                      AT_CMS_SIM_DATA_DOWNLOAD_ERROR},
    {TAF_MSG_ERROR_TP_FCS_UNSPECIFIED_ERROR_CAUSE,                                      AT_CMS_UNSPECIFIED_ERROR_CAUSE},
    {TAF_MSG_ERROR_STATE_NOT_COMPATIBLE,                                                AT_CMS_ME_FAILURE},
    {TAF_MSG_ERROR_NO_SERVICE,                                                          AT_CMS_NO_NETWORK_SERVICE},
    {TAF_MSG_ERROR_TC1M_TIMEOUT,                                                        AT_CMS_NETWORK_TIMEOUT},
    {TAF_MSG_ERROR_TR1M_TIMEOUT,                                                        AT_CMS_NETWORK_TIMEOUT},
    {TAF_MSG_ERROR_TR2M_TIMEOUT,                                                        AT_CMS_NO_CNMA_ACKNOWLEDGEMENT_EXPECTED},
};


TAF_PS_EVT_ID_ENUM_UINT32 g_astAtBroadcastPsEvtTbl[] =
{
    ID_EVT_TAF_PS_REPORT_DSFLOW_IND,
    ID_EVT_TAF_PS_APDSFLOW_REPORT_IND,
    ID_EVT_TAF_PS_CALL_PDP_DISCONNECT_IND,
    ID_EVT_TAF_PS_CALL_PDP_MANAGE_IND,
    ID_EVT_TAF_PS_CGMTU_VALUE_CHG_IND,
    ID_EVT_TAF_PS_CALL_LIMIT_PDP_ACT_IND,
    ID_EVT_TAF_PS_REPORT_VTFLOW_IND,
    ID_EVT_TAF_PS_PS_REG_STATUS_IND,
    ID_EVT_TAF_PS_PDP_CHG_POLICY_IND,
    ID_EVT_TAF_PS_REPORT_PCO_INFO_IND,
    ID_EVT_TAF_PS_APN_DATA_SYS_POLICY_IND,
    ID_EVT_TAF_PS_DATA_SYSTEM_CHG_NTF,
};

const AT_PS_EVT_FUNC_TBL_STRU           g_astAtPsEvtFuncTbl[] =
{
    /* PS CALL */
    {ID_EVT_TAF_PS_CALL_PDP_ACTIVATE_CNF,
        AT_RcvTafPsCallEvtPdpActivateCnf},
    {ID_EVT_TAF_PS_CALL_PDP_ACTIVATE_REJ,
        AT_RcvTafPsCallEvtPdpActivateRej},
    {ID_EVT_TAF_PS_CALL_PDP_MANAGE_IND,
        AT_RcvTafPsCallEvtPdpManageInd},
    {ID_EVT_TAF_PS_CALL_PDP_ACTIVATE_IND,
        AT_RcvTafPsCallEvtPdpActivateInd},
    {ID_EVT_TAF_PS_CALL_PDP_MODIFY_CNF,
        AT_RcvTafPsCallEvtPdpModifyCnf},
    {ID_EVT_TAF_PS_CALL_PDP_MODIFY_REJ,
        AT_RcvTafPsCallEvtPdpModifyRej},
    {ID_EVT_TAF_PS_CALL_PDP_MODIFY_IND,
        AT_RcvTafPsCallEvtPdpModifiedInd},
    {ID_EVT_TAF_PS_CALL_PDP_DEACTIVATE_CNF,
        AT_RcvTafPsCallEvtPdpDeactivateCnf},
    {ID_EVT_TAF_PS_CALL_PDP_DEACTIVATE_IND,
        AT_RcvTafPsCallEvtPdpDeactivatedInd},

    {ID_EVT_TAF_PS_CALL_ORIG_CNF,
        AT_RcvTafPsCallEvtCallOrigCnf},
    {ID_EVT_TAF_PS_CALL_END_CNF,
        AT_RcvTafPsCallEvtCallEndCnf},
    {ID_EVT_TAF_PS_CALL_MODIFY_CNF,
        AT_RcvTafPsCallEvtCallModifyCnf},
    {ID_EVT_TAF_PS_CALL_ANSWER_CNF,
        AT_RcvTafPsCallEvtCallAnswerCnf},
    {ID_EVT_TAF_PS_CALL_HANGUP_CNF,
        AT_RcvTafPsCallEvtCallHangupCnf},

    /* D */
    {ID_EVT_TAF_PS_GET_D_GPRS_ACTIVE_TYPE_CNF,
        AT_RcvTafPsEvtGetGprsActiveTypeCnf},

    /* PPP */
    {ID_EVT_TAF_PS_PPP_DIAL_ORIG_CNF,
        AT_RcvTafPsEvtPppDialOrigCnf},

    /* +CGDCONT */
    {ID_EVT_TAF_PS_SET_PRIM_PDP_CONTEXT_INFO_CNF,
        AT_RcvTafPsEvtSetPrimPdpContextInfoCnf},
    {ID_EVT_TAF_PS_GET_PRIM_PDP_CONTEXT_INFO_CNF,
        AT_RcvTafPsEvtGetPrimPdpContextInfoCnf},

    /* +CGDSCONT */
    {ID_EVT_TAF_PS_SET_SEC_PDP_CONTEXT_INFO_CNF,
        AT_RcvTafPsEvtSetSecPdpContextInfoCnf},
    {ID_EVT_TAF_PS_GET_SEC_PDP_CONTEXT_INFO_CNF,
        AT_RcvTafPsEvtGetSecPdpContextInfoCnf},

    /* +CGTFT */
    {ID_EVT_TAF_PS_SET_TFT_INFO_CNF,
        AT_RcvTafPsEvtSetTftInfoCnf},
    {ID_EVT_TAF_PS_GET_TFT_INFO_CNF,
        AT_RcvTafPsEvtGetTftInfoCnf},

    /* +CGEQREQ */
    {ID_EVT_TAF_PS_SET_UMTS_QOS_INFO_CNF,
        AT_RcvTafPsEvtSetUmtsQosInfoCnf},
    {ID_EVT_TAF_PS_GET_UMTS_QOS_INFO_CNF,
        AT_RcvTafPsEvtGetUmtsQosInfoCnf},

    /* +CGEQMIN */
    {ID_EVT_TAF_PS_SET_UMTS_QOS_MIN_INFO_CNF,
        AT_RcvTafPsEvtSetUmtsQosMinInfoCnf},
    {ID_EVT_TAF_PS_GET_UMTS_QOS_MIN_INFO_CNF,
        AT_RcvTafPsEvtGetUmtsQosMinInfoCnf},

    /* +CGEQNEG */
    {ID_EVT_TAF_PS_GET_DYNAMIC_UMTS_QOS_INFO_CNF,
        AT_RcvTafPsEvtGetDynamicUmtsQosInfoCnf},

    /* +CGACT */
    {ID_EVT_TAF_PS_SET_PDP_CONTEXT_STATE_CNF,
        AT_RcvTafPsEvtSetPdpStateCnf},
    {ID_EVT_TAF_PS_GET_PDP_CONTEXT_STATE_CNF,
        AT_RcvTafPsEvtGetPdpStateCnf},

    /* +CGPADDR */
    {ID_EVT_TAF_PS_GET_PDP_IP_ADDR_INFO_CNF,
        AT_RcvTafPsEvtGetPdpIpAddrInfoCnf},
    {ID_EVT_TAF_PS_GET_PDP_CONTEXT_INFO_CNF,
        AT_RcvTafPsEvtGetPdpContextInfoCnf},

    /* +CGAUTO */
    {ID_EVT_TAF_PS_SET_ANSWER_MODE_INFO_CNF,
        AT_RcvTafPsEvtSetAnsModeInfoCnf},
    {ID_EVT_TAF_PS_GET_ANSWER_MODE_INFO_CNF,
        AT_RcvTafPsEvtGetAnsModeInfoCnf},

    /* +CGCONTRDP */
    {ID_EVT_TAF_PS_GET_DYNAMIC_PRIM_PDP_CONTEXT_INFO_CNF,
        AT_RcvTafPsEvtGetDynamicPrimPdpContextInfoCnf},
    /* +CGSCONTRDP */
    {ID_EVT_TAF_PS_GET_DYNAMIC_SEC_PDP_CONTEXT_INFO_CNF,
        AT_RcvTafPsEvtGetDynamicSecPdpContextInfoCnf},

    /* +CGTFTRDP */
    {ID_EVT_TAF_PS_GET_DYNAMIC_TFT_INFO_CNF,
        AT_RcvTafPsEvtGetDynamicTftInfoCnf},

    /* +CGEQOS */
    {ID_EVT_TAF_PS_SET_EPS_QOS_INFO_CNF,
        AT_RcvTafPsEvtSetEpsQosInfoCnf},
    {ID_EVT_TAF_PS_GET_EPS_QOS_INFO_CNF,
        AT_RcvTafPsEvtGetEpsQosInfoCnf},

    /* +CGEQOSRDP */
    {ID_EVT_TAF_PS_GET_DYNAMIC_EPS_QOS_INFO_CNF,
        AT_RcvTafPsEvtGetDynamicEpsQosInfoCnf},

    /* ^CDQF/^DSFLOWQRY */
    {ID_EVT_TAF_PS_GET_DSFLOW_INFO_CNF,
        AT_RcvTafPsEvtGetDsFlowInfoCnf},

    /* ^CDCF/^DSFLOWCLR */
    {ID_EVT_TAF_PS_CLEAR_DSFLOW_CNF,
        AT_RcvTafPsEvtClearDsFlowInfoCnf},

    /* ^CDSF/^DSFLOWRPT/^FLOWRPTCTRL */
    {ID_EVT_TAF_PS_CONFIG_DSFLOW_RPT_CNF,
        AT_RcvTafPsEvtConfigDsFlowRptCnf},

    /* ^DSFLOWRPT */
    {ID_EVT_TAF_PS_REPORT_DSFLOW_IND,
        AT_RcvTafPsEvtReportDsFlowInd},

     /* ^VTFLOWRPT */
    {ID_EVT_TAF_PS_REPORT_VTFLOW_IND,
        AT_RcvTafPsEvtReportVTFlowInd},
    {ID_EVT_TAF_PS_CONFIG_VTFLOW_RPT_CNF,
        AT_RcvTafPsEvtConfigVTFlowRptCnf},

    /* ^CGDNS */
    {ID_EVT_TAF_PS_SET_PDP_DNS_INFO_CNF,
        AT_RcvTafPsEvtSetPdpDnsInfoCnf},
    {ID_EVT_TAF_PS_GET_PDP_DNS_INFO_CNF,
        AT_RcvTafPsEvtGetPdpDnsInfoCnf},

    /* ^AUTHDATA */
    {ID_EVT_TAF_PS_SET_AUTHDATA_INFO_CNF,
        AT_RcvTafPsEvtSetAuthDataInfoCnf},
    {ID_EVT_TAF_PS_GET_AUTHDATA_INFO_CNF,
        AT_RcvTafPsEvtGetAuthDataInfoCnf},

    {ID_EVT_TAF_PS_CALL_PDP_IPV6_INFO_IND,
        AT_RcvTafPsEvtReportRaInfo},

    {ID_EVT_TAF_PS_CALL_PDP_DISCONNECT_IND,
        AT_RcvTafPsEvtPdpDisconnectInd},
    {ID_EVT_TAF_PS_GET_NEGOTIATION_DNS_CNF,
        AT_RcvTafPsEvtGetDynamicDnsInfoCnf},

    {ID_EVT_TAF_PS_LTECS_INFO_CNF,
        atReadLtecsCnfProc},
    {ID_EVT_TAF_PS_CEMODE_INFO_CNF,
        atReadCemodeCnfProc},


    {ID_EVT_TAF_PS_GET_CID_SDF_CNF,
        AT_RcvTafPsEvtGetCidSdfInfoCnf},

    {ID_MSG_TAF_PS_GET_LTE_ATTACH_INFO_CNF,
        AT_RcvTafGetLteAttachInfoCnf},

    {ID_EVT_TAF_PS_SET_APDSFLOW_RPT_CFG_CNF,
        AT_RcvTafPsEvtSetApDsFlowRptCfgCnf},
    {ID_EVT_TAF_PS_GET_APDSFLOW_RPT_CFG_CNF,
        AT_RcvTafPsEvtGetApDsFlowRptCfgCnf},
    {ID_EVT_TAF_PS_APDSFLOW_REPORT_IND,
        AT_RcvTafPsEvtApDsFlowReportInd},

    {ID_EVT_TAF_PS_SET_DSFLOW_NV_WRITE_CFG_CNF,
        AT_RcvTafPsEvtSetDsFlowNvWriteCfgCnf},
    {ID_EVT_TAF_PS_GET_DSFLOW_NV_WRITE_CFG_CNF,
        AT_RcvTafPsEvtGetDsFlowNvWriteCfgCnf},

    {ID_EVT_TAF_PS_SET_CTA_INFO_CNF,
        AT_RcvTafPsEvtSetPktCdataInactivityTimeLenCnf},
    {ID_EVT_TAF_PS_GET_CTA_INFO_CNF,
        AT_RcvTafPsEvtGetPktCdataInactivityTimeLenCnf},


    {ID_EVT_TAF_PS_SET_CDMA_DIAL_MODE_CNF,
        At_RcvTafPsEvtSetDialModeCnf},


    {ID_EVT_TAF_PS_CGMTU_VALUE_CHG_IND,
        AT_RcvTafPsEvtCgmtuValueChgInd},

    {ID_EVT_TAF_PS_SET_IMS_PDP_CFG_CNF,
        AT_RcvTafPsEvtSetImsPdpCfgCnf},

    {ID_EVT_TAF_PS_SET_1X_DORM_TIMER_CNF,
        AT_RcvTafPsEvtSet1xDormTimerCnf},

    {ID_EVT_TAF_PS_GET_1X_DORM_TIMER_CNF,
        AT_RcvTafPsEvtGet1xDormTimerCnf},

    /* ????rabid change???? */
    {ID_EVT_TAF_PS_CALL_PDP_RABID_CHANGE_IND,
        AT_RcvTafPsCallEvtPdpRabidChanged},

    /* ????telcel pdp????????????*/
    {ID_EVT_TAF_PS_CALL_LIMIT_PDP_ACT_IND,
        AT_RcvTafPsCallEvtLimitPdpActInd},

    {ID_EVT_TAF_PS_SET_MIP_MODE_CNF,
        AT_RcvTafPsEvtSetMipModeCnf},

    {ID_EVT_TAF_PS_GET_MIP_MODE_CNF,
        AT_RcvTafPsEvtGetMipModeCnf},

    {ID_EVT_TAF_PS_SET_VZWAPNE_CNF,
        AT_RcvTafPsEvtSetVzwApneCnf},

    {ID_EVT_TAF_PS_GET_VZWAPNE_CNF,
        AT_RcvTafPsEvtGetVzwApneCnf},

    {ID_EVT_TAF_PS_PS_REG_STATUS_IND,
        AT_RcvTafPsRegStatusInd},

    {ID_EVT_TAF_PS_PDP_CHG_POLICY_IND,
        AT_RcvTafPdpTypeChgPolicyInd},
    {ID_EVT_TAF_PS_REPORT_PCO_INFO_IND,
        AT_RcvTafPsReportPcoInfoInd},


    {ID_EVT_TAF_PS_SET_DATA_SWITCH_CNF,
        AT_RcvTafPsEvtSetDataSwitchCnf},

    {ID_EVT_TAF_PS_GET_DATA_SWITCH_CNF,
        AT_RcvTafPsEvtGetDataSwitchCnf},

    {ID_EVT_TAF_PS_SET_DATA_ROAM_SWITCH_CNF,
        AT_RcvTafPsEvtSetDataRoamSwitchCnf},

    {ID_EVT_TAF_PS_GET_DATA_ROAM_SWITCH_CNF,
        AT_RcvTafPsEvtGetDataRoamSwitchCnf},

    {ID_EVT_TAF_PS_SET_APN_THROT_INFO_CNF,
        AT_RcvTafPsEvtSetApnThrotInfoCnf},


    {ID_EVT_TAF_PS_APN_DATA_SYS_POLICY_IND,
        AT_RcvTafPsEvtApnDataSysPolicyInd},

    {ID_EVT_TAF_PS_DATA_SYSTEM_CHG_NTF,
        AT_RcvTafPsEvtDataSystemChgNtf},

};

/* ??????????????????Bit???????? */
/* ??????????????Bit0~Bit63 */
AT_RPT_CMD_INDEX_ENUM_UINT8             g_aenAtCurcRptCmdTable[] =
{
    AT_RPT_CMD_MODE,        AT_RPT_CMD_RSSI,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_SRVST,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_SIMST,       AT_RPT_CMD_TIME,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_ANLEVEL,     AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_SMMEMFULL,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_CTZV,
    AT_RPT_CMD_CTZE,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_DSFLOWRPT,   AT_RPT_CMD_BUTT,
    AT_RPT_CMD_ORIG,        AT_RPT_CMD_CONF,        AT_RPT_CMD_CONN,        AT_RPT_CMD_CEND,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_STIN,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_CERSSI,      AT_RPT_CMD_LWCLASH,     AT_RPT_CMD_XLEMA,       AT_RPT_CMD_ACINFO,
    AT_RPT_CMD_PLMN,        AT_RPT_CMD_CALLSTATE,   AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT
};



AT_RPT_CMD_INDEX_ENUM_UINT8             g_aenAtUnsolicitedRptCmdTable[] =
{
    AT_RPT_CMD_MODE,        AT_RPT_CMD_RSSI,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_SRVST,
    AT_RPT_CMD_CREG,        AT_RPT_CMD_SIMST,       AT_RPT_CMD_TIME,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_ANLEVEL,     AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_CTZV,
    AT_RPT_CMD_CTZE,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_DSFLOWRPT,   AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_CUSD,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_CSSI,
    AT_RPT_CMD_CSSU,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_CERSSI,      AT_RPT_CMD_LWURC,       AT_RPT_CMD_BUTT,        AT_RPT_CMD_CUUS1U,
    AT_RPT_CMD_CUUS1I,      AT_RPT_CMD_CGREG,       AT_RPT_CMD_CEREG,       AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,
    AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT,        AT_RPT_CMD_BUTT
};

AT_CME_CALL_ERR_CODE_MAP_STRU           g_astAtCmeCallErrCodeMapTbl[] =
{
    { AT_CME_INCORRECT_PARAMETERS,      TAF_CS_CAUSE_INVALID_PARAMETER              },
    { AT_CME_SIM_FAILURE,               TAF_CS_CAUSE_SIM_NOT_EXIST                  },
    { AT_CME_SIM_PIN_REQUIRED,          TAF_CS_CAUSE_SIM_PIN_NEED                   },
    { AT_CME_UNKNOWN,                   TAF_CS_CAUSE_NO_CALL_ID                     },
    { AT_CME_OPERATION_NOT_ALLOWED,     TAF_CS_CAUSE_NOT_ALLOW                      },
    { AT_CME_INCORRECT_PARAMETERS,      TAF_CS_CAUSE_STATE_ERROR                    },
    { AT_CME_FDN_FAILED,                            TAF_CS_CAUSE_FDN_CHECK_FAILURE              },
    { AT_CME_CALL_CONTROL_BEYOND_CAPABILITY,        TAF_CS_CAUSE_CALL_CTRL_BEYOND_CAPABILITY    },
    { AT_CME_CALL_CONTROL_FAILED,                   TAF_CS_CAUSE_CALL_CTRL_TIMEOUT              },
    { AT_CME_CALL_CONTROL_FAILED,                   TAF_CS_CAUSE_CALL_CTRL_NOT_ALLOWED          },
    { AT_CME_CALL_CONTROL_FAILED,                   TAF_CS_CAUSE_CALL_CTRL_INVALID_PARAMETER    },
    { AT_CME_UNKNOWN,                   TAF_CS_CAUSE_UNKNOWN                        }
};

AT_CMS_SMS_ERR_CODE_MAP_STRU           g_astAtCmsSmsErrCodeMapTbl[] =
{
    { AT_CMS_U_SIM_BUSY,                            MN_ERR_CLASS_SMS_UPDATE_USIM},
    { AT_CMS_U_SIM_NOT_INSERTED,                    MN_ERR_CLASS_SMS_NOUSIM},
    { AT_CMS_INVALID_MEMORY_INDEX,                  MN_ERR_CLASS_SMS_EMPTY_REC},
    { AT_CMS_MEMORY_FULL,                           MN_ERR_CLASS_SMS_STORAGE_FULL},
    { AT_CMS_U_SIM_PIN_REQUIRED,                    MN_ERR_CLASS_SMS_NEED_PIN1},
    { AT_CMS_U_SIM_PUK_REQUIRED,                    MN_ERR_CLASS_SMS_NEED_PUK1},
    { AT_CMS_U_SIM_FAILURE,                         MN_ERR_CLASS_SMS_UNAVAILABLE},
    { AT_CMS_OPERATION_NOT_ALLOWED,                 MN_ERR_CLASS_SMS_FEATURE_INAVAILABLE },
    { AT_CMS_SMSC_ADDRESS_UNKNOWN,                  MN_ERR_CLASS_SMS_INVALID_SCADDR},
    { AT_CMS_INVALID_PDU_MODE_PARAMETER,            MN_ERR_CLASS_SMS_MSGLEN_OVERFLOW},
    { AT_CMS_FDN_DEST_ADDR_FAILED,                  MN_ERR_CLASS_FDN_CHECK_DN_FAILURE},
    { AT_CMS_FDN_SERVICE_CENTER_ADDR_FAILED,        MN_ERR_CLASS_FDN_CHECK_SC_FAILURE},
    { AT_CMS_MO_SMS_CONTROL_FAILED,                 MN_ERR_CLASS_SMS_MO_CTRL_ACTION_NOT_ALLOWED},
    { AT_CMS_MO_SMS_CONTROL_FAILED,                 MN_ERR_CLASS_SMS_MO_CTRL_USIM_PARA_ERROR},
    { AT_CMS_MEMORY_FAILURE,                        MN_ERR_NOMEM}

};


AT_ENCRYPT_VOICE_ERR_CODE_MAP_STRU                  g_astAtEncVoiceErrCodeMapTbl[] =
{
    { AT_ENCRYPT_VOICE_SUCC,                                TAF_CALL_APP_ENCRYPT_VOICE_SUCC},
    { AT_ENCRYPT_VOICE_TIMEOUT,                             TAF_CALL_APP_ENCRYPT_VOICE_TIMEOUT},
    { AT_ENCRYPT_VOICE_TIMEOUT,                             TAF_CALL_APP_ENCRYPT_VOICE_TX01_TIMEOUT},
    { AT_ENCRYPT_VOICE_TIMEOUT,                             TAF_CALL_APP_ENCRYPT_VOICE_TX02_TIMEOUT},
    { AT_ENCRYPT_VOICE_LOCAL_TERMINAL_NO_AUTHORITY,         TAF_CALL_APP_ENCRYPT_VOICE_LOCAL_TERMINAL_NO_AUTHORITY},
    { AT_ENCRYPT_VOICE_REMOTE_TERMINAL_NO_AUTHORITY,        TAF_CALL_APP_ENCRYPT_VOICE_REMOTE_TERMINAL_NO_AUTHORITY},
    { AT_ENCRYPT_VOICE_LOCAL_TERMINAL_ILLEGAL,              TAF_CALL_APP_ENCRYPT_VOICE_LOCAL_TERMINAL_ILLEGAL},
    { AT_ENCRYPT_VOICE_REMOTE_TERMINAL_ILLEGAL,             TAF_CALL_APP_ENCRYPT_VOICE_REMOTE_TERMINAL_ILLEGAL},
    { AT_ENCRYPT_VOICE_UNKNOWN_ERROR,                       TAF_CALL_APP_ENCRYPT_VOICE_UNKNOWN_ERROR },
    { AT_ENCRYPT_VOICE_SIGNTURE_VERIFY_FAILURE,             TAF_CALL_APP_ENCRYPT_VOICE_SIGNTURE_VERIFY_FAILURE},
    { AT_ENCRYPT_VOICE_MT_CALL_NOTIFICATION,                TAF_CALL_APP_ENCRYPT_VOICE_MT_CALL_NOTIFICATION},

    /* Internal err code */
    { AT_ENCRYPT_VOICE_XSMS_SEND_RESULT_FAIL,               TAF_CALL_APP_ENCRYPT_VOICE_XSMS_SEND_RESULT_FAIL},
    { AT_ENCRYPT_VOICE_XSMS_SEND_RESULT_POOL_FULL,          TAF_CALL_APP_ENCRYPT_VOICE_XSMS_SEND_RESULT_POOL_FULL},
    { AT_ENCRYPT_VOICE_XSMS_SEND_RESULT_LINK_ERR,           TAF_CALL_APP_ENCRYPT_VOICE_XSMS_SEND_RESULT_LINK_ERR},
    { AT_ENCRYPT_VOICE_XSMS_SEND_RESULT_NO_TL_ACK,          TAF_CALL_APP_ENCRYPT_VOICE_XSMS_SEND_RESULT_NO_TL_ACK},
    { AT_ENCRYPT_VOICE_XSMS_SEND_RESULT_ENCODE_ERR,         TAF_CALL_APP_ENCRYPT_VOICE_XSMS_SEND_RESULT_ENCODE_ERR},
    { AT_ENCRYPT_VOICE_XSMS_SEND_RESULT_UNKNOWN,            TAF_CALL_APP_ENCRYPT_VOICE_XSMS_SEND_RESULT_UNKNOWN},
    { AT_ENCRYPT_VOICE_SO_NEGO_FAILURE,                     TAF_CALL_APP_ENCRYPT_VOICE_SO_NEGO_FAILURE},
    { AT_ENCRYPT_VOICE_TWO_CALL_ENTITY_EXIST,               TAT_CALL_APP_ENCRYPT_VOICE_TWO_CALL_ENTITY_EXIST},
    { AT_ENCRYPT_VOICE_NO_MO_CALL,                          TAF_CALL_APP_ENCRYPT_VOICE_NO_MO_CALL},
    { AT_ENCRYPT_VOICE_NO_MT_CALL,                          TAF_CALL_APP_ENCRYPT_VOICE_NO_MT_CALL},
    { AT_ENCRYPT_VOICE_NO_CALL_EXIST,                       TAF_CALL_APP_ENCRYPT_VOICE_NO_CALL_EXIST},
    { AT_ENCRYPT_VOICE_CALL_STATE_NOT_ALLOWED,              TAF_CALL_APP_ENCRYPT_VOICE_CALL_STATE_NOT_ALLOWED},
    { AT_ENCRYPT_VOICE_CALL_NUM_MISMATCH,                   TAF_CALL_APP_ENCRYPT_VOICE_CALL_NUM_MISMATCH},
    { AT_ENCRYPT_VOICE_ENC_VOICE_STATE_MISMATCH,            TAF_CALL_APP_ENCRYPT_VOICE_ENC_VOICE_STATE_MISMATCH},
    { AT_ENCRYPT_VOICE_MSG_ENCODE_FAILUE,                   TAF_CALL_APP_ENCRYPT_VOICE_MSG_ENCODE_FAILUE},
    { AT_ENCRYPT_VOICE_MSG_DECODE_FAILUE,                   TAF_CALL_APP_ENCRYPT_VOICE_MSG_DECODE_FAILUE},
    { AT_ENCRYPT_VOICE_GET_TEMP_PUB_PIVA_KEY_FAILURE,       TAF_CALL_APP_ENCRYPT_VOICE_GET_TEMP_PUB_PIVA_KEY_FAILURE},
    { AT_ENCRYPT_VOICE_FILL_CIPHER_TEXT_FAILURE,            TAF_CALL_APP_ENCRYPT_VOICE_FILL_CIPHER_TEXT_FAILURE},
    { AT_ENCRYPT_VOICE_ECC_CAP_NOT_SUPPORTED,               TAF_CALL_APP_ENCRYPT_VOICE_ECC_CAP_NOT_SUPPORTED},
    { AT_ENCRYPT_VOICE_ENC_VOICE_MODE_UNKNOWN,              TAF_CALL_APP_ENCRYPT_VOICE_ENC_VOICE_MODE_UNKNOWN},
    { AT_ENCRYPT_VOICE_ENC_VOICE_MODE_MIMATCH,              TAF_CALL_APP_ENCRYPT_VOICE_ENC_VOICE_MODE_MIMATCH},
    { AT_ENCRYPT_VOICE_CALL_RELEASED,                       TAF_CALL_APP_ENCRYPT_VOICE_CALL_RELEASED},
    { AT_ENCRYPT_VOICE_CALL_ANSWER_REQ_FAILURE,             TAF_CALL_APP_ENCRYPT_VOICE_CALL_ANSWER_REQ_FAILURE},
    { AT_ENCRYPT_VOICE_DECRYPT_KS_FAILURE,                  TAF_CALL_APP_ENCRYPT_VOICE_DECRYPT_KS_FAILURE},
    { AT_ENCRYPT_VOICE_FAILURE_CAUSED_BY_INCOMING_CALL,     TAF_CALL_APP_ENCRYPT_VOICE_FAILURE_CAUSED_BY_INCOMING_CALL},
    { AT_ENCRYPT_VOICE_INIT_VOICE_FUNC_FAILURE,             TAF_CALL_APP_ENCRYPT_VOICE_INIT_VOICE_FUNC_FAILURE},
    { AT_ENCRYPT_VOICE_ERROR_ENUM_BUTT,                     TAF_CALL_APP_ENCRYPT_VOICE_STATUS_ENUM_BUTT}

};

AT_SMS_RSP_PROC_FUN g_aAtSmsMsgProcTable[MN_MSG_EVT_MAX] = {
    /*MN_MSG_EVT_SUBMIT_RPT*/           At_SendSmRspProc,
    /*MN_MSG_EVT_MSG_SENT*/             At_SetCnmaRspProc,
    /*MN_MSG_EVT_MSG_STORED*/           At_SmsRspNop,
    /*MN_MSG_EVT_DELIVER*/              At_SmsDeliverProc,
    /*MN_MSG_EVT_DELIVER_ERR*/          At_SmsDeliverErrProc,
    /*MN_MSG_EVT_SM_STORAGE_LIST*/      At_SmsStorageListProc,                  /*????????????????????????????*/
    /*MN_MSG_EVT_STORAGE_FULL*/         At_SmsRspNop,
    /*MN_MSG_EVT_STORAGE_EXCEED*/       At_SmsStorageExceedProc,
    /*MN_MSG_EVT_READ*/                 At_ReadRspProc,
    /*MN_MSG_EVT_LIST*/                 At_ListRspProc,
    /*MN_MSG_EVT_WRITE*/                At_WriteSmRspProc,
    /*MN_MSG_EVT_DELETE*/               At_DeleteRspProc,
    /*MN_MSG_EVT_DELETE_TEST*/          At_DeleteTestRspProc,
    /*MN_MSG_EVT_MODIFY_STATUS*/        At_SmsModSmStatusRspProc,
    /*MN_MSG_EVT_WRITE_SRV_PARM*/       At_SetCscaCsmpRspProc,
    /*MN_MSG_EVT_READ_SRV_PARM*/        AT_QryCscaRspProc,
    /*MN_MSG_EVT_SRV_PARM_CHANGED*/     At_SmsSrvParmChangeProc,
    /*MN_MSG_EVT_DELETE_SRV_PARM*/      At_SmsRspNop,
    /*MN_MSG_EVT_READ_STARPT*/          At_SmsRspNop,
    /*MN_MSG_EVT_DELETE_STARPT*/        At_SmsRspNop,
    /*MN_MSG_EVT_SET_MEMSTATUS*/        AT_SetMemStatusRspProc,
    /*MN_MSG_EVT_MEMSTATUS_CHANGED*/    At_SmsRspNop,
    /*MN_MSG_EVT_MATCH_MO_STARPT_INFO*/ At_SmsRspNop,
    /*MN_MSG_EVT_SET_RCVMSG_PATH*/      At_SetRcvPathRspProc,
    /*MN_MSG_EVT_GET_RCVMSG_PATH*/      At_SmsRspNop,
    /*MN_MSG_EVT_RCVMSG_PATH_CHANGED*/  At_SmsRcvMsgPathChangeProc,
    /*MN_MSG_EVT_INIT_SMSP_RESULT*/     At_SmsInitSmspResultProc,
    /*MN_MSG_EVT_INIT_RESULT*/          At_SmsInitResultProc,
    /*MN_MSG_EVT_SET_LINK_CTRL_PARAM*/  At_SetCmmsRspProc,
    /*MN_MSG_EVT_GET_LINK_CTRL_PARAM*/  At_GetCmmsRspProc,
    /*MN_MSG_EVT_STUB_RESULT*/          At_SmsStubRspProc,
    /*MN_MSG_EVT_DELIVER_CBM*/          At_SmsDeliverCbmProc,
    /*MN_MSG_EVT_GET_CBTYPE*/           At_GetCbActiveMidsRspProc,
    /*MN_MSG_EVT_ADD_CBMIDS*/           AT_ChangeCbMidsRsp,
    /*MN_MSG_EVT_DELETE_CBMIDS*/        AT_ChangeCbMidsRsp,
    /*MN_MSG_EVT_DELETE_ALL_CBMIDS*/    AT_ChangeCbMidsRsp,

    /*MN_MSG_EVT_DELIVER_ETWS_PRIM_NOTIFY*/  At_ProcDeliverEtwsPrimNotify,

   /*MN_MSG_EVT_SET_SEND_DOMAIN_PARAM*/ At_SetCgsmsRspProc,
   /*MN_MSG_EVT_GET_SEND_DOMAIN_PARAM*/ At_GetCgsmsRspProc,
};

/*??????????????????????????????????*/
AT_QUERY_TYPE_FUNC_STRU     g_aAtQryTypeProcFuncTbl[] =
{
    {TAF_PH_IMSI_ID_PARA,              At_QryParaRspCimiProc},
    {TAF_PH_MS_CLASS_PARA,             At_QryParaRspCgclassProc},


    {TAF_PH_ICC_ID,                    At_QryParaRspIccidProc},
    {TAF_PH_PNN_PARA,                  At_QryParaRspPnnProc},
    {TAF_PH_CPNN_PARA,                 At_QryParaRspCPnnProc},
    {TAF_PH_OPL_PARA,                  At_QryParaRspOplProc},


    {TAF_PH_PNN_RANGE_PARA,            At_QryRspUsimRangeProc},
    {TAF_PH_OPL_RANGE_PARA,            At_QryRspUsimRangeProc},


    {TAF_TELE_PARA_BUTT,               TAF_NULL_PTR}
};

TAF_UINT8                               gaucAtStin[] = "^STIN:";
TAF_UINT8                               gaucAtStmn[] = "^STMN:";
TAF_UINT8                               gaucAtStgi[] = "^STGI:";
TAF_UINT8                               gaucAtStsf[] = "^STSF:";
TAF_UINT8                               gaucAtCsin[] = "^CSIN:";
TAF_UINT8                               gaucAtCstr[] = "^CSTR:";
TAF_UINT8                               gaucAtCsen[] = "^CSEN:";
TAF_UINT8                               gaucAtCsmn[] = "^CSMN:";
TAF_UINT8                               gaucAtCcin[] = "^CCIN:";

static AT_CALL_CUUSU_MSG_STRU g_stCuusuMsgType[] =
{
    {MN_CALL_UUS1_MSG_SETUP             ,   AT_CUUSU_MSG_SETUP              },
    {MN_CALL_UUS1_MSG_DISCONNECT        ,   AT_CUUSU_MSG_DISCONNECT         },
    {MN_CALL_UUS1_MSG_RELEASE_COMPLETE  ,   AT_CUUSU_MSG_RELEASE_COMPLETE   }
};

static AT_CALL_CUUSI_MSG_STRU g_stCuusiMsgType[] =
{
    {MN_CALL_UUS1_MSG_ALERT             ,   AT_CUUSI_MSG_ALERT              },
    {MN_CALL_UUS1_MSG_PROGRESS          ,   AT_CUUSI_MSG_PROGRESS           },
    {MN_CALL_UUS1_MSG_CONNECT           ,   AT_CUUSI_MSG_CONNECT            },
    {MN_CALL_UUS1_MSG_RELEASE           ,   AT_CUUSI_MSG_RELEASE            }
};

/* begin V7R1 PhaseI Modify */
static AT_PH_SYS_MODE_TBL_STRU g_astSysModeTbl[] =
{
    {MN_PH_SYS_MODE_EX_NONE_RAT     ,"NO SERVICE"},
    {MN_PH_SYS_MODE_EX_GSM_RAT      ,"GSM"},
    {MN_PH_SYS_MODE_EX_CDMA_RAT     ,"CDMA"},
    {MN_PH_SYS_MODE_EX_WCDMA_RAT    ,"WCDMA"},
    {MN_PH_SYS_MODE_EX_TDCDMA_RAT   ,"TD-SCDMA"},
    {MN_PH_SYS_MODE_EX_WIMAX_RAT    ,"WIMAX"},
    {MN_PH_SYS_MODE_EX_LTE_RAT      ,"LTE"},
    {MN_PH_SYS_MODE_EX_EVDO_RAT     ,"EVDO"},
    {MN_PH_SYS_MODE_EX_HYBRID_RAT   ,"CDMA1X+EVDO(HYBRID)"},
    {MN_PH_SYS_MODE_EX_SVLTE_RAT    ,"CDMA1X+LTE"}
};

AT_PH_SUB_SYS_MODE_TBL_STRU g_astSubSysModeTbl[] =
{
    {MN_PH_SUB_SYS_MODE_EX_NONE_RAT         ,"NO SERVICE"},
    {MN_PH_SUB_SYS_MODE_EX_GSM_RAT          ,"GSM"},
    {MN_PH_SUB_SYS_MODE_EX_GPRS_RAT         ,"GPRS"},
    {MN_PH_SUB_SYS_MODE_EX_EDGE_RAT         ,"EDGE"},
    {MN_PH_SUB_SYS_MODE_EX_WCDMA_RAT        ,"WCDMA"},
    {MN_PH_SUB_SYS_MODE_EX_HSDPA_RAT        ,"HSDPA"},
    {MN_PH_SUB_SYS_MODE_EX_HSUPA_RAT        ,"HSUPA"},
    {MN_PH_SUB_SYS_MODE_EX_HSPA_RAT         ,"HSPA"},
    {MN_PH_SUB_SYS_MODE_EX_HSPA_PLUS_RAT    ,"HSPA+"},
    {MN_PH_SUB_SYS_MODE_EX_DCHSPA_PLUS_RAT  ,"DC-HSPA+"},
    {MN_PH_SUB_SYS_MODE_EX_TDCDMA_RAT       ,"TD-SCDMA"},
    {MN_PH_SUB_SYS_MODE_EX_TD_HSDPA_RAT     ,"HSDPA"},
    {MN_PH_SUB_SYS_MODE_EX_TD_HSUPA_RAT     ,"HSUPA"},
    {MN_PH_SUB_SYS_MODE_EX_TD_HSPA_RAT      ,"HSPA"},
    {MN_PH_SUB_SYS_MODE_EX_TD_HSPA_PLUS_RAT ,"HSPA+"},

    {MN_PH_SUB_SYS_MODE_EX_LTE_RAT          ,"LTE"},

    {MN_PH_SUB_SYS_MODE_EX_CDMA20001X_RAT   ,"CDMA2000 1X"},

    {MN_PH_SUB_SYS_MODE_EX_EVDOREL0_RAT        ,"EVDO Rel0"},
    {MN_PH_SUB_SYS_MODE_EX_EVDORELA_RAT        ,"EVDO RelA"},
    {MN_PH_SUB_SYS_MODE_EX_HYBIRD_EVDOREL0_RAT ,"HYBRID(EVDO Rel0)"},
    {MN_PH_SUB_SYS_MODE_EX_HYBIRD_EVDORELA_RAT ,"HYBRID(EVDO RelA)"},

    {MN_PH_SUB_SYS_MODE_EX_EHRPD_RAT           ,"EHRPD"},

};
/* end V7R1 PhaseI Modify */

VOS_UINT32  g_ulGuTmodeCnf  = 0;
VOS_UINT32  g_ulLteTmodeCnf = 0;

/* +CLCK????????CLASS??Service Type Code?????????? */
AT_CLCK_CLASS_SERVICE_TBL_STRU          g_astClckClassServiceExtTbl[] = {
    {AT_CLCK_PARA_CLASS_VOICE,                      TAF_SS_TELE_SERVICE,        TAF_ALL_SPEECH_TRANSMISSION_SERVICES_TSCODE},
    {AT_CLCK_PARA_CLASS_VOICE,                      TAF_SS_TELE_SERVICE,        TAF_TELEPHONY_TSCODE},
    {AT_CLCK_PARA_CLASS_VOICE,                      TAF_SS_TELE_SERVICE,        TAF_EMERGENCY_CALLS_TSCODE},
    {AT_CLCK_PARA_CLASS_DATA,                       TAF_SS_BEARER_SERVICE,      TAF_ALL_BEARERSERVICES_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA,                       TAF_SS_TELE_SERVICE,        TAF_ALL_DATA_TELESERVICES_TSCODE},
    {AT_CLCK_PARA_CLASS_FAX,                        TAF_SS_TELE_SERVICE,        TAF_ALL_FACSIMILE_TRANSMISSION_SERVICES_TSCODE},
    {AT_CLCK_PARA_CLASS_FAX,                        TAF_SS_TELE_SERVICE,        TAF_FACSIMILE_GROUP3_AND_ALTER_SPEECH_TSCODE},
    {AT_CLCK_PARA_CLASS_FAX,                        TAF_SS_TELE_SERVICE,        TAF_AUTOMATIC_FACSIMILE_GROUP3_TSCODE},
    {AT_CLCK_PARA_CLASS_FAX,                        TAF_SS_TELE_SERVICE,        TAF_FACSIMILE_GROUP4_TSCODE},
    {AT_CLCK_PARA_CLASS_VOICE_DATA_FAX,             TAF_SS_TELE_SERVICE,        TAF_ALL_TELESERVICES_EXEPTSMS_TSCODE},
    {AT_CLCK_PARA_CLASS_SMS,                        TAF_SS_TELE_SERVICE,        TAF_ALL_SMS_SERVICES_TSCODE},
    {AT_CLCK_PARA_CLASS_SMS,                        TAF_SS_TELE_SERVICE,        TAF_SMS_MT_PP_TSCODE},
    {AT_CLCK_PARA_CLASS_SMS,                        TAF_SS_TELE_SERVICE,        TAF_SMS_MO_PP_TSCODE},
    {AT_CLCK_PARA_CLASS_VOICE_DATA_FAX_SMS,         TAF_SS_TELE_SERVICE,        TAF_ALL_TELESERVICES_TSCODE},
    {AT_CLCK_PARA_CLASS_DATA_SYNC,                  TAF_SS_BEARER_SERVICE,      TAF_ALL_DATA_CIRCUIT_SYNCHRONOUS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_SYNC,                  TAF_SS_BEARER_SERVICE,      TAF_ALL_DATACDS_SERVICES_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_SYNC,                  TAF_SS_BEARER_SERVICE,      TAF_DATACDS_1200BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_SYNC,                  TAF_SS_BEARER_SERVICE,      TAF_DATACDS_2400BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_SYNC,                  TAF_SS_BEARER_SERVICE,      TAF_DATACDS_4800BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_SYNC,                  TAF_SS_BEARER_SERVICE,      TAF_DATACDS_9600BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_SYNC,                  TAF_SS_BEARER_SERVICE,      TAF_ALL_ALTERNATE_SPEECH_DATACDS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_SYNC,                  TAF_SS_BEARER_SERVICE,      TAF_ALL_SPEECH_FOLLOWED_BY_DATACDS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_SYNC,                  TAF_SS_BEARER_SERVICE,      TAF_GENERAL_DATACDS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_ASYNC,                 TAF_SS_BEARER_SERVICE,      TAF_ALL_DATA_CIRCUIT_ASYNCHRONOUS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_ASYNC,                 TAF_SS_BEARER_SERVICE,      TAF_ALL_DATACDA_SERVICES_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_ASYNC,                 TAF_SS_BEARER_SERVICE,      TAF_DATACDA_300BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_ASYNC,                 TAF_SS_BEARER_SERVICE,      TAF_DATACDA_1200BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_ASYNC,                 TAF_SS_BEARER_SERVICE,      TAF_DATACDA_1200_75BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_ASYNC,                 TAF_SS_BEARER_SERVICE,      TAF_DATACDA_2400BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_ASYNC,                 TAF_SS_BEARER_SERVICE,      TAF_DATACDA_4800BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_ASYNC,                 TAF_SS_BEARER_SERVICE,      TAF_DATACDA_9600BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_ASYNC,                 TAF_SS_BEARER_SERVICE,      TAF_ALL_ALTERNATE_SPEECH_DATACDA_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_ASYNC,                 TAF_SS_BEARER_SERVICE,      TAF_ALL_SPEECH_FOLLOWED_BY_DATACDA_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_PKT,                   TAF_SS_BEARER_SERVICE,      TAF_ALL_DATAPDS_SERVICES_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_PKT,                   TAF_SS_BEARER_SERVICE,      TAF_DATAPDS_2400BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_PKT,                   TAF_SS_BEARER_SERVICE,      TAF_DATAPDS_4800BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_PKT,                   TAF_SS_BEARER_SERVICE,      TAF_DATAPDS_9600BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_SYNC_PKT,              TAF_SS_BEARER_SERVICE,      TAF_ALL_SYNCHRONOUS_SERVICES_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_PAD,                   TAF_SS_BEARER_SERVICE,      TAF_ALL_PADACCESSCA_SERVICES_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_PAD,                   TAF_SS_BEARER_SERVICE,      TAF_PADACCESSCA_300BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_PAD,                   TAF_SS_BEARER_SERVICE,      TAF_PADACCESSCA_1200BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_PAD,                   TAF_SS_BEARER_SERVICE,      TAF_PADACCESSCA_1200_75BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_PAD,                   TAF_SS_BEARER_SERVICE,      TAF_PADACCESSCA_2400BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_PAD,                   TAF_SS_BEARER_SERVICE,      TAF_PADACCESSCA_4800BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_PAD,                   TAF_SS_BEARER_SERVICE,      TAF_PADACCESSCA_9600BPS_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_ASYNC_PAD,             TAF_SS_BEARER_SERVICE,      TAF_ALL_ASYNCHRONOUS_SERVICES_BSCODE},
    {AT_CLCK_PARA_CLASS_DATA_SYNC_ASYNC_PKT_PKT,    TAF_SS_BEARER_SERVICE,      TAF_ALL_BEARERSERVICES_BSCODE},
};

AT_CHG_TAF_ERR_CODE_TBL_STRU                g_astAtChgTafErrCodeTbl[] = {
    {TAF_ERR_GET_CSQLVL_FAIL,                       AT_ERROR},
    {TAF_ERR_USIM_SVR_OPLMN_LIST_INAVAILABLE,       AT_ERROR},
    {TAF_ERR_TIME_OUT,                              AT_CME_NETWORK_TIMEOUT},
    {TAF_ERR_USIM_SIM_CARD_NOTEXIST,                AT_CME_SIM_NOT_INSERTED},
    {TAF_ERR_NEED_PIN1,                             AT_CME_SIM_PIN_REQUIRED},
    {TAF_ERR_NEED_PUK1,                             AT_CME_SIM_PUK_REQUIRED},
    {TAF_ERR_SIM_FAIL,                              AT_CME_SIM_FAILURE},
    {TAF_ERR_PB_STORAGE_OP_FAIL,                    AT_CME_SIM_FAILURE},
    {TAF_ERR_UNSPECIFIED_ERROR,                     AT_CME_UNKNOWN},
    {TAF_ERR_PARA_ERROR,                            AT_CME_INCORRECT_PARAMETERS},
    {TAF_ERR_SS_NEGATIVE_PASSWORD_CHECK,            AT_CME_INCORRECT_PASSWORD},
    {TAF_ERR_SIM_BUSY,                              AT_CME_SIM_BUSY},
    {TAF_ERR_SIM_LOCK,                              AT_CME_PH_SIM_PIN_REQUIRED},
    {TAF_ERR_SIM_INCORRECT_PASSWORD,                AT_CME_INCORRECT_PASSWORD},
    {TAF_ERR_PB_NOT_FOUND,                          AT_CME_NOT_FOUND},
    {TAF_ERR_PB_DIAL_STRING_TOO_LONG,               AT_CME_DIAL_STRING_TOO_LONG},
    {TAF_ERR_PB_STORAGE_FULL,                       AT_CME_MEMORY_FULL},
    {TAF_ERR_PB_WRONG_INDEX,                        AT_CME_INVALID_INDEX},
    {TAF_ERR_CMD_TYPE_ERROR,                        AT_CME_OPERATION_NOT_ALLOWED},
    {TAF_ERR_FILE_NOT_EXIST,                        AT_CME_FILE_NOT_EXISTS},
    {TAF_ERR_NO_NETWORK_SERVICE,                    AT_CME_NO_NETWORK_SERVICE},
    {TAF_ERR_AT_ERROR,                              AT_ERROR},
    {TAF_ERR_CME_OPT_NOT_SUPPORTED,                 AT_CME_OPERATION_NOT_SUPPORTED},
    {TAF_ERR_NET_SEL_MENU_DISABLE,                  AT_CME_NET_SEL_MENU_DISABLE},
    {TAF_ERR_SYSCFG_CS_IMS_SERV_EXIST,              AT_CME_CS_IMS_SERV_EXIST},
    {TAF_ERR_NO_RF,                                 AT_CME_NO_RF},
    {TAF_ERR_NEED_PUK2,                             AT_CME_SIM_PUK2_REQUIRED},
    {TAF_ERR_BUSY_ON_USSD,                          AT_CME_OPERATION_NOT_SUPPORTED},
    {TAF_ERR_BUSY_ON_SS,                            AT_CME_OPERATION_NOT_SUPPORTED},
    {TAF_ERR_SS_NET_TIMEOUT,                        AT_CME_NETWORK_TIMEOUT},
    {TAF_ERR_NO_SUCH_ELEMENT,                       AT_CME_NO_SUCH_ELEMENT},
    {TAF_ERR_MISSING_RESOURCE,                      AT_CME_MISSING_RESOURCE},
    {TAF_ERR_IMS_NOT_SUPPORT,                       AT_CME_IMS_NOT_SUPPORT},
    {TAF_ERR_IMS_SERVICE_EXIST,                     AT_CME_IMS_SERVICE_EXIST},
    {TAF_ERR_IMS_VOICE_DOMAIN_PS_ONLY,              AT_CME_IMS_VOICE_DOMAIN_PS_ONLY},
    {TAF_ERR_IMS_STACK_TIMEOUT,                     AT_CME_IMS_STACK_TIMEOUT},
    {TAF_ERR_IMS_OPEN_LTE_NOT_SUPPORT,              AT_CME_IMS_OPEN_LTE_NOT_SUPPORT},
    {TAF_ERR_1X_RAT_NOT_SUPPORTED,                  AT_CME_1X_RAT_NOT_SUPPORTED},
    {TAF_ERR_SILENT_AES_DEC_PIN_FAIL,               AT_CME_SILENT_AES_DEC_PIN_ERROR},
    {TAF_ERR_SILENT_VERIFY_PIN_ERR,                 AT_CME_SILENT_VERIFY_PIN_ERROR},
    {TAF_ERR_SILENT_AES_ENC_PIN_FAIL,               AT_CME_SILENT_AES_ENC_PIN_ERROR},
    {TAF_ERR_NOT_FIND_FILE,                         AT_CME_NOT_FIND_FILE},
    {TAF_ERR_NOT_FIND_NV,                           AT_CME_NOT_FIND_NV},
    {TAF_ERR_MODEM_ID_ERROR,                        AT_CME_MODEM_ID_ERROR},
    {TAF_ERR_NV_NOT_SUPPORT_ERR,                    AT_CME_NV_NOT_SUPPORT_ERR},
    {TAF_ERR_WRITE_NV_TIMEOUT,                      AT_CME_WRITE_NV_TimeOut},
    {TAF_ERR_NETWORK_FAILURE,                       AT_CME_NETWORK_FAILURE},
    {TAF_ERR_SCI_ERROR,                             AT_CME_SCI_ERROR},
};


AT_CHG_MTA_ERR_CODE_TBL_STRU                g_astAtChgMtaErrCodeTbl[] =
{
    {MTA_AT_RESULT_INCORRECT_PARAMETERS,            AT_CME_INCORRECT_PARAMETERS},
    {MTA_AT_RESULT_FUNC_DISABLE,                    AT_CME_FUNC_DISABLE},
};

AT_PIH_RSP_PROC_FUNC_STRU     g_aAtPihRspProcFuncTbl[] =
{
    {SI_PIH_EVENT_FDN_CNF,                  At_ProcPihFndBndCnf},
    {SI_PIH_EVENT_BDN_CNF,                  At_ProcPihFndBndCnf},
    {SI_PIH_EVENT_GENERIC_ACCESS_CNF,       At_ProcPihGenericAccessCnf},
    {SI_PIH_EVENT_ISDB_ACCESS_CNF,          At_ProcPihIsdbAccessCnf},
    {SI_PIH_EVENT_CCHO_SET_CNF,             At_ProcPihCchoSetCnf},
    {SI_PIH_EVENT_CCHP_SET_CNF,             At_ProcPihCchpSetCnf},
    {SI_PIH_EVENT_CCHC_SET_CNF,             At_ProcPihCchcSetCnf},
    {SI_PIH_EVENT_SCICFG_SET_CNF,           At_ProcPihSciCfgSetCnf},
    {SI_PIH_EVENT_HVSST_SET_CNF,            At_ProcPihHvsstSetCnf},
    {SI_PIH_EVENT_CGLA_SET_CNF,             At_ProcPihCglaSetCnf},
    {SI_PIH_EVENT_CARD_ATR_QRY_CNF,         At_ProcPihCardAtrQryCnf},
    {SI_PIH_EVENT_SCICFG_QUERY_CNF,         At_SciCfgQueryCnf},
    {SI_PIH_EVENT_HVSST_QUERY_CNF,          At_HvsstQueryCnf},
    {SI_PIH_EVENT_CARDTYPE_QUERY_CNF,       At_ProcPihCardTypeQryCnf},
    {SI_PIH_EVENT_CARDTYPEEX_QUERY_CNF,     At_ProcPihCardTypeExQryCnf},
    {SI_PIH_EVENT_CARDVOLTAGE_QUERY_CNF,    At_ProcPihCardVoltageQryCnf},
    {SI_PIH_EVENT_PRIVATECGLA_SET_CNF,      At_ProcPihPrivateCglaSetCnf},
    {SI_PIH_EVENT_CRSM_SET_CNF,             At_ProcPihCrsmSetCnf},
    {SI_PIH_EVENT_CRLA_SET_CNF,             At_ProcPihCrlaSetCnf},
    {SI_PIH_EVENT_SESSION_QRY_CNF,          At_ProcPihSessionQryCnf},
    {SI_PIH_EVENT_CIMI_QRY_CNF,             At_ProcPihCimiQryCnf},
    {SI_PIH_EVENT_CCIMI_QRY_CNF,            At_ProcPihCcimiQryCnf},
    {SI_PIH_EVENT_UICCAUTH_CNF,             AT_UiccAuthCnf},
    {SI_PIH_EVENT_URSM_CNF,                 AT_UiccAccessFileCnf},
    {SI_PIH_EVENT_SILENT_PIN_SET_CNF,       At_PrintSilentPinInfo},
    {SI_PIH_EVENT_SILENT_PININFO_SET_CNF,   At_PrintSilentPinInfo},
};

/*****************************************************************************
   5 ??????????????
*****************************************************************************/

extern TAF_UINT8                               gucSTKCmdQualify ;

extern   VOS_UINT32 g_ulGuOnly;
extern   VOS_UINT32 g_ulGuTmodeCnfNum;
extern   VOS_UINT32 g_ulLteIsSend2Dsp;
extern   VOS_UINT32 g_ulTmodeLteMode;

/*****************************************************************************
   6 ????????
*****************************************************************************/

LOCAL VOS_VOID AT_ConvertSysCfgStrToAutoModeStr(
    VOS_UINT8                          *pucAcqOrderBegin,
    VOS_UINT8                          *pucAcqOrder,
    VOS_UINT8                           ucRatNum
);


AT_CLI_VALIDITY_ENUM_UINT8 AT_ConvertCLIValidity(
    MN_CALL_INFO_STRU                  *pstCallInfo
)
{
    AT_CLI_VALIDITY_ENUM_UINT8          enCliVality;
    /* 24008 10.5.4.30 */
    /* Cause of No CLI information element provides the mobile station
       the detailed reason why Calling party BCD nuber is not notified. */

    /* ????????????0???????????????????? */
    if (0 != pstCallInfo->stCallNumber.ucNumLen)
    {
        return AT_CLI_VALIDITY_VALID;
    }

    switch (pstCallInfo->enNoCliCause)
    {
        case MN_CALL_NO_CLI_USR_REJ:
        case MN_CALL_NO_CLI_INTERACT:
        case MN_CALL_NO_CLI_PAYPHONE:
            enCliVality = (AT_CLI_VALIDITY_ENUM_UINT8)pstCallInfo->enNoCliCause;
            break;

        /* ????????????,???????????????? */
        case MN_CALL_NO_CLI_BUTT:
        case MN_CALL_NO_CLI_UNAVAL:
        default:
            enCliVality = AT_CLI_VALIDITY_UNAVAL;
            break;
    }

    return enCliVality;
}

VOS_UINT32 AT_CheckRptCmdStatus(
    VOS_UINT8                          *pucRptCfg,
    AT_CMD_RPT_CTRL_TYPE_ENUM_UINT8     enRptCtrlType,
    AT_RPT_CMD_INDEX_ENUM_UINT8         enRptCmdIndex
)
{
    AT_RPT_CMD_INDEX_ENUM_UINT8        *pulRptCmdTblPtr = VOS_NULL_PTR;
    VOS_UINT32                          ulRptCmdTblSize;
    VOS_UINT8                           ucTableIndex;
    VOS_UINT32                          ulOffset;
    VOS_UINT8                           ucBit;

    /* ?????????????????????????????????? */
    if (enRptCmdIndex >= AT_RPT_CMD_BUTT)
    {
        return VOS_TRUE;
    }

    /* ?????????????????????????????????????? */
    if (AT_CMD_RPT_CTRL_BUTT == enRptCtrlType)
    {
        return VOS_TRUE;
    }

    if (AT_CMD_RPT_CTRL_BY_CURC == enRptCtrlType)
    {
        pulRptCmdTblPtr = AT_GET_CURC_RPT_CTRL_STATUS_MAP_TBL_PTR();
        ulRptCmdTblSize = AT_GET_CURC_RPT_CTRL_STATUS_MAP_TBL_SIZE();
    }
    else
    {
        pulRptCmdTblPtr = AT_GET_UNSOLICITED_RPT_CTRL_STATUS_MAP_TBL_PTR();
        ulRptCmdTblSize = AT_GET_UNSOLICITED_RPT_CTRL_STATUS_MAP_TBL_SIZE();
    }

    for (ucTableIndex = 0; ucTableIndex < ulRptCmdTblSize; ucTableIndex++)
    {
        if (enRptCmdIndex == pulRptCmdTblPtr[ucTableIndex])
        {
            break;
        }
    }

    /* ??????????????Bit?????? */
    if (ulRptCmdTblSize != ucTableIndex)
    {
        /* ??????????????????????Bit????????????, ????????Bit?? */
        ulOffset        = AT_CURC_RPT_CFG_MAX_SIZE - (ucTableIndex / 8) - 1;
        ucBit           = (VOS_UINT8)(ucTableIndex % 8);

        return (VOS_UINT32)((pucRptCfg[ulOffset] >> ucBit) & 0x1);
    }

    return VOS_TRUE;
}


VOS_UINT32 At_ChgMnErrCodeToAt(
    VOS_UINT8                           ucIndex,
    VOS_UINT32                          ulMnErrorCode
)
{
    VOS_UINT32                          ulRtn;
    AT_CMS_SMS_ERR_CODE_MAP_STRU       *pstSmsErrMapTblPtr = VOS_NULL_PTR;
    VOS_UINT32                          ulSmsErrMapTblSize;
    VOS_UINT32                          ulCnt;
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    pstSmsErrMapTblPtr = AT_GET_CMS_SMS_ERR_CODE_MAP_TBL_PTR();
    ulSmsErrMapTblSize = AT_GET_CMS_SMS_ERR_CODE_MAP_TBL_SIZE();

    ulRtn = AT_CMS_UNKNOWN_ERROR;

    for (ulCnt = 0; ulCnt < ulSmsErrMapTblSize; ulCnt++)
    {
        if (pstSmsErrMapTblPtr[ulCnt].ulSmsCause == ulMnErrorCode)
        {
            ulRtn =  pstSmsErrMapTblPtr[ulCnt].ulCmsCode;

            if ((AT_CMGF_MSG_FORMAT_TEXT == pstSmsCtx->enCmgfMsgFormat)
             && (AT_CMS_INVALID_PDU_MODE_PARAMETER == ulRtn))
            {
                ulRtn = AT_CMS_INVALID_TEXT_MODE_PARAMETER;
            }

            break;
        }
    }

    return ulRtn;
}


TAF_UINT32 At_ChgXsmsErrorCodeToAt(
    TAF_UINT32                          ulXsmsError
)
{
    switch(ulXsmsError)
    {
        case TAF_XSMS_APP_SUCCESS:
            return AT_SUCCESS;

        case TAF_XSMS_APP_FAILURE:
            return AT_ERROR;

        case TAF_XSMS_APP_INIT_NOT_FINISH:
            return AT_CME_SIM_BUSY;

        case TAF_XSMS_APP_INVALID_INDEX:
            return AT_CME_INVALID_INDEX;

        case TAF_XSMS_APP_UIM_FAILURE:
            return AT_CME_SIM_FAILURE;

        case TAF_XSMS_APP_STORE_FULL:
            return AT_CMS_SIM_SMS_STORAGE_FULL;

        case TAF_XSMS_APP_NOT_SUPPORT_1X:
            return AT_CME_1X_RAT_NOT_SUPPORTED;

        case TAF_XSMS_APP_NORMAL_VOLTE:
        case TAF_XSMS_APP_UIM_LOCK_LOCKED:
        case TAF_XSMS_APP_ENCODE_ERROR:
        case TAF_XSMS_APP_UIM_MSG_STATUS_WRONG:
        case TAF_XSMS_APP_INSERT_SDND_POOL_FAIL:
        case TAF_XSMS_APP_NOT_INSERT_TO_POOL:
        case TAF_XSMS_APP_NOT_SUPPORT_LTE:
            return AT_ERROR;

        default:
            return AT_ERROR;
    }
}

TAF_UINT32 At_ChgTafErrorCode(TAF_UINT8 ucIndex, TAF_ERROR_CODE_ENUM_UINT32 enTafErrorCode)
{
    TAF_UINT32                          ulRtn  = 0;
    VOS_UINT32                          ulMsgCnt;
    VOS_UINT32                          i;
    VOS_UINT32                          ulFlag = 0;


    /* ???????????? */
    ulMsgCnt = sizeof(g_astAtChgTafErrCodeTbl)/sizeof(AT_CHG_TAF_ERR_CODE_TBL_STRU);

    for (i = 0; i < ulMsgCnt; i++)
    {
        if (g_astAtChgTafErrCodeTbl[i].enTafErrCode == enTafErrorCode)
        {
            ulRtn  = g_astAtChgTafErrCodeTbl[i].enAtReturnCode;
            ulFlag = ulFlag + 1;
            break;
        }
    }

    if(ulFlag == 0)
    {
        if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
        {
            ulRtn = AT_CME_UNKNOWN;
        }
        else if (VOS_NULL_PTR == g_stParseContext[ucIndex].pstCmdElement)
        {
            ulRtn = AT_CME_UNKNOWN;
        }
        else if ((g_stParseContext[ucIndex].pstCmdElement->ulCmdIndex > AT_CMD_SMS_BEGAIN)
              && (g_stParseContext[ucIndex].pstCmdElement->ulCmdIndex < AT_CMD_SMS_END))
        {
            ulRtn = AT_CMS_UNKNOWN_ERROR;
        }
        else
        {
            ulRtn = AT_CME_UNKNOWN;
        }
    }

    return ulRtn;
}


TAF_UINT32 At_SsClass2Print(TAF_UINT8 ucClass)
{
    TAF_UINT32 ulRtn = 0;

    switch(ucClass)
    {
    case TAF_ALL_SPEECH_TRANSMISSION_SERVICES_TSCODE:
        ulRtn = 1;
        break;

    case TAF_ALL_DATA_TELESERVICES_TSCODE:
        ulRtn = 2;
        break;

    case TAF_ALL_FACSIMILE_TRANSMISSION_SERVICES_TSCODE:
        ulRtn = 4;
        break;

    case TAF_ALL_SMS_SERVICES_TSCODE:
        ulRtn = 8;
        break;

    case TAF_ALL_DATA_CIRCUIT_SYNCHRONOUS_BSCODE:
    case TAF_ALL_DATACDS_SERVICES_BSCODE:
        ulRtn = 16;
        break;

    case TAF_ALL_DATA_CIRCUIT_ASYNCHRONOUS_BSCODE:
        ulRtn = 32;
        break;

    default:
        break;
    }

    return ulRtn;
}
/*****************************************************************************
 Prototype      : At_CcClass2Print
 Description    : ??CCA??????CLASS??????????????????????????????
 Input          : ucClass --- CCA??CLASS
 Output         : ---
 Return Value   : ulRtn????????
 Calls          : ---
 Called By      : ---

 History        : ---
  1.Date        : 2005-04-19
    Author      : ---
    Modification: Created function
*****************************************************************************/
TAF_UINT32 At_CcClass2Print(MN_CALL_TYPE_ENUM_U8 enCallType,TAF_UINT8 *pDst)
{
    TAF_UINT16 usLength = 0;

    switch(enCallType)
    {
    case MN_CALL_TYPE_VOICE:
    case MN_CALL_TYPE_PSAP_ECALL:
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pDst,"VOICE");
        break;

    case MN_CALL_TYPE_FAX:
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pDst,"FAX");
        break;

    case MN_CALL_TYPE_VIDEO:
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pDst,"SYNC");
        break;

    case MN_CALL_TYPE_CS_DATA:
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pDst,"DATA");
        break;

    default:
        AT_WARN_LOG("At_CcClass2Print CallType ERROR");
        break;
    }

    return usLength;
}

/* PC??????AT??A??????C??, At_sprintf??????????,?????????????????????? */


TAF_UINT32 At_HexAlpha2AsciiString(TAF_UINT32 MaxLength,TAF_INT8 *headaddr,TAF_UINT8 *pucDst,TAF_UINT8 *pucSrc,TAF_UINT16 usSrcLen)
{
    TAF_UINT16 usLen = 0;
    TAF_UINT16 usChkLen = 0;
    TAF_UINT8 *pWrite = pucDst;
    TAF_UINT8 *pRead = pucSrc;
    TAF_UINT8  ucHigh = 0;
    TAF_UINT8  ucLow = 0;

    if(((TAF_UINT32)(pucDst - (TAF_UINT8 *)headaddr) + (2 * usSrcLen)) >= MaxLength)
    {
        AT_ERR_LOG("At_HexAlpha2AsciiString too long");
        return 0;
    }

    if(0 != usSrcLen)
    {
        /* ???????????? */
        while( usChkLen++ < usSrcLen )
        {
            ucHigh = 0x0F & (*pRead >> 4);
            ucLow = 0x0F & *pRead;

            usLen += 2;    /* ???????? */

            if(0x09 >= ucHigh)   /* 0-9 */
            {
                *pWrite++ = ucHigh + 0x30;
            }
            else if(0x0A <= ucHigh)    /* A-F */
            {
                *pWrite++ = ucHigh + 0x37;
            }
            else
            {

            }

            if(0x09 >= ucLow)   /* 0-9 */
            {
                *pWrite++ = ucLow + 0x30;
            }
            else if(0x0A <= ucLow)    /* A-F */
            {
                *pWrite++ = ucLow + 0x37;
            }
            else
            {

            }

            /* ?????????? */
            pRead++;
        }

    }
    return usLen;
}


TAF_UINT16 At_UnicodeFormatPrint(const TAF_UINT8 *pSrc, TAF_UINT8 *pDest, TAF_UINT32 Dcs)
{
    TAF_UINT8 i, j;
    TAF_UINT16 len;
    TAF_UINT16 base, tmp;

    base = 0;

    if(SI_PB_ALPHATAG_TYPE_UCS2_81 == Dcs)                     /* name decode by 81 */
    {
        base = (TAF_UINT16)((pSrc[1]<<0x07)&0x7F80);           /* get the basepoint value */

        j = 0x02;                                              /* name content offset */
    }
    else if(SI_PB_ALPHATAG_TYPE_UCS2_82 == Dcs)                /* name decode by 82 */
    {
        base = (TAF_UINT16)((pSrc[1]<<0x08)&0xFF00) + pSrc[2];  /* get the basepoint value */

        j = 0x03;                                               /* name content offset */
    }
    else                                                        /* name decode error */
    {
        return 0;
    }

    len = 2 * pSrc[0];                                          /* get the length of name */

    if((len == 0x00)||(len == 0xFF))                            /* length error */
    {
        return 0;
    }

    for( i = 0; i < pSrc[0] ; i++)                              /* decode action begin */
    {
        if((pSrc[j+i]&0x80) == 0x00)
        {
            pDest[i*2] = 0x00;

            pDest[(i*2)+1] = pSrc[j+i];
        }
        else
        {
            tmp = base + (pSrc[j+i]&0x7F);

            pDest[i*2] = (TAF_UINT8)((tmp&0xFF00)>>0x08);

            pDest[(i*2)+1] = (TAF_UINT8)(tmp&0x00FF);
        }
    }

    return len;                                                    /* return the Byte number of the name */
}


VOS_UINT32 AT_Hex2AsciiStrLowHalfFirst(
    VOS_UINT32                          ulMaxLength,
    VOS_INT8                            *pcHeadaddr,
    VOS_UINT8                           *pucDst,
    VOS_UINT8                           *pucSrc,
    VOS_UINT16                          usSrcLen
)
{
    VOS_UINT16                          usLen;
    VOS_UINT16                          usChkLen;
    VOS_UINT8                           *pcWrite;
    VOS_UINT8                           *pcRead;
    VOS_UINT8                           ucHigh;
    VOS_UINT8                           ucLow;

    usLen           = 0;
    usChkLen        = 0;
    pcWrite         = pucDst;
    pcRead          = pucSrc;


    if (((VOS_UINT32)(pucDst - (VOS_UINT8 *)pcHeadaddr) + (2 * usSrcLen)) >= ulMaxLength)
    {
        AT_ERR_LOG("AT_Hex2AsciiStrLowHalfFirst too long");
        return 0;
    }

    if (0 != usSrcLen)
    {
        /* ???????????? */
        while ( usChkLen++ < usSrcLen )
        {
            ucHigh = 0x0F & (*pcRead >> 4);
            ucLow  = 0x0F & *pcRead;

            usLen += 2;    /* ???????? */

            /* ?????????????? */
            if (0x09 >= ucLow)   /* 0-9 */
            {
                *pcWrite++ = ucLow + 0x30;
            }
            else if (0x0A <= ucLow)    /* A-F */
            {
                *pcWrite++ = ucLow + 0x37;
            }
            else
            {

            }

            /* ?????????????? */
            if (0x09 >= ucHigh)   /* 0-9 */
            {
                *pcWrite++ = ucHigh + 0x30;
            }
            else if (0x0A <= ucHigh)    /* A-F */
            {
                *pcWrite++ = ucHigh + 0x37;
            }
            else
            {

            }

            /* ?????????? */
            pcRead++;
        }

    }

    return usLen;
}


/*****************************************************************************
 Prototype      : At_ReadNumTypePara
 Description    : ????ASCII??????????
 Input          : pucDst   --- ????????
                  pucSrc   --- ??????
                  usSrcLen --- ??????????
 Output         :
 Return Value   : AT_XXX  --- ATC??????
 Calls          : ---
 Called By      : ---

 History        : ---
  1.Date        : 2005-04-19
    Author      : ---
    Modification: Created function
*****************************************************************************/
TAF_UINT32 At_ReadNumTypePara(TAF_UINT8 *pucDst,TAF_UINT8 *pucSrc)
{
    TAF_UINT16 usLength = 0;

    if(AT_CSCS_UCS2_CODE == gucAtCscsType)       /* +CSCS:UCS2 */
    {
        TAF_UINT16 usSrcLen = (TAF_UINT16)VOS_StrLen((TAF_CHAR *)pucSrc);

        usLength += (TAF_UINT16)At_Ascii2UnicodePrint(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,pucDst + usLength,pucSrc,usSrcLen);
    }
    else
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pucDst + usLength,"%s",pucSrc);
    }
    return usLength;
}



VOS_BOOL  AT_IsFindVedioModemStatus(
    VOS_UINT8                           ucIndex,
    MN_CALL_TYPE_ENUM_U8                enCallType
)
{
    AT_DCE_MSC_STRU                     stMscStru;
    TAF_UINT32                          ulDelayaCnt;

    if (AT_CLIENT_TAB_MODEM_INDEX != ucIndex)
    {
        return VOS_FALSE;
    }

    /* ??AT_CSD_DATA_MODE??????????????????????DCD??????????????????????????PC??????AT???? */
    if (( AT_MODEM_USER == gastAtClientTab[ucIndex].UserType)
     && (AT_DATA_MODE == gastAtClientTab[ucIndex].Mode)
     && (AT_CSD_DATA_MODE == gastAtClientTab[ucIndex].DataMode)
     && (MN_CALL_TYPE_VIDEO == enCallType))
    {

        /* ???????????? */
        At_SetMode(ucIndex, AT_CMD_MODE, AT_NORMAL_MODE);


        TAF_MEM_SET_S(&stMscStru, sizeof(stMscStru), 0x00, sizeof(stMscStru));

        /* ????DCD???? */
        stMscStru.OP_Dcd = 1;
        stMscStru.ucDcd = 0;
        stMscStru.OP_Dsr = 1;
        stMscStru.ucDsr = 1;
        AT_SetModemStatus(ucIndex, &stMscStru);

        /*EVENT-UE Down DCD*/
        AT_EventReport(WUEPS_PID_AT, NAS_OM_EVENT_DCE_DOWN_DCD,
                         VOS_NULL_PTR, NAS_OM_EVENT_NO_PARA);

        /* ????????????????????????PC????????????????????????  */
        ulDelayaCnt = 1500000;
        while( ulDelayaCnt-- )
        {
            ;
        }

        /* ????DCD???? */
        stMscStru.OP_Dcd = 1;
        stMscStru.ucDcd = 1;
        stMscStru.OP_Dsr = 1;
        stMscStru.ucDsr = 1;
        AT_SetModemStatus(ucIndex, &stMscStru);

        return VOS_TRUE;
    }


    return VOS_FALSE;
}


VOS_VOID  AT_CsRspEvtReleasedProc(
    TAF_UINT8                           ucIndex,
    MN_CALL_EVENT_ENUM_U32              enEvent,
    MN_CALL_INFO_STRU                  *pstCallInfo
)
{
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;
    VOS_BOOL                            bRet;
    VOS_UINT32                          ulTimerName;
    AT_MODEM_CC_CTX_STRU               *pstCcCtx = VOS_NULL_PTR;


    pstCcCtx = AT_GetModemCcCtxAddrFromClientId(ucIndex);

    g_ucDtrDownFlag = VOS_FALSE;




    /* ????cause???????????? */
    AT_UpdateCallErrInfo(ucIndex, pstCallInfo->enCause, &(pstCallInfo->stErrInfoText));

    if ((AT_CMD_CHUP_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
      ||(AT_CMD_H_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
      ||(AT_CMD_CHLD_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
      ||(AT_CMD_CTFR_SET == gastAtClientTab[ucIndex].CmdCurrentOpt))
    {
        if (VOS_TRUE == pstCcCtx->stS0TimeInfo.bTimerStart)
        {
            ulTimerName = pstCcCtx->stS0TimeInfo.ulTimerName;

            AT_StopRelTimer(ulTimerName, &(pstCcCtx->stS0TimeInfo.s0Timer));
            pstCcCtx->stS0TimeInfo.bTimerStart = VOS_FALSE;
            pstCcCtx->stS0TimeInfo.ulTimerName = 0;
        }

        AT_IsFindVedioModemStatus(ucIndex,pstCallInfo->enCallType);

        AT_ReportCendResult(ucIndex, pstCallInfo);

        return;
    }
    else
    {
        /*
        ????????????????????????????????????????????????
        */

        /* gastAtClientTab[ucIndex].ulCause?????????????????????? */

        if (VOS_TRUE == pstCcCtx->stS0TimeInfo.bTimerStart)
        {
            ulTimerName = pstCcCtx->stS0TimeInfo.ulTimerName;

            AT_StopRelTimer(ulTimerName, &(pstCcCtx->stS0TimeInfo.s0Timer));
            pstCcCtx->stS0TimeInfo.bTimerStart = VOS_FALSE;
            pstCcCtx->stS0TimeInfo.ulTimerName = 0;
        }


        /* ????CEND????????????????????^CEND */
        if ((PS_TRUE == At_CheckReportCendCallType(pstCallInfo->enCallType))
         || (AT_EVT_IS_PS_VIDEO_CALL(pstCallInfo->enCallType, pstCallInfo->enVoiceDomain)))
        {
            AT_ReportCendResult(ucIndex, pstCallInfo);

            return;
        }

        ulResult = AT_NO_CARRIER;

        if (AT_EVT_IS_VIDEO_CALL(pstCallInfo->enCallType))
        {
            if (TAF_CS_CAUSE_CC_NW_USER_ALERTING_NO_ANSWER == pstCallInfo->enCause)
            {
                ulResult = AT_NO_ANSWER;
            }

            if (TAF_CS_CAUSE_CC_NW_USER_BUSY == pstCallInfo->enCause)
            {
                ulResult = AT_BUSY;
            }
        }

        /* AT???????????????????????????????????? */
        if (AT_EVT_REL_IS_NEED_CLR_TIMER_STATUS_CMD(gastAtClientTab[ucIndex].CmdCurrentOpt))
        {
            AT_STOP_TIMER_CMD_READY(ucIndex);
        }


        bRet = AT_IsFindVedioModemStatus(ucIndex,pstCallInfo->enCallType);
        if ( VOS_TRUE == bRet )
        {
            return ;
        }
    }

    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);
}



VOS_VOID  AT_CsRspEvtConnectProc(
    VOS_UINT8                           ucIndex,
    MN_CALL_EVENT_ENUM_U32              enEvent,
    MN_CALL_INFO_STRU                   *pstCallInfo
)
{
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;
    TAF_UINT8                           aucAsciiNum[(MN_CALL_MAX_BCD_NUM_LEN*2)+1];
    AT_MODEM_SS_CTX_STRU               *pstSsCtx = VOS_NULL_PTR;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;
    MN_CALL_TYPE_ENUM_U8                enNewCallType;

    enModemId = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("AT_CsRspEvtConnectProc: Get modem id fail.");
        return;
    }

    pstSsCtx = AT_GetModemSsCtxAddrFromModemId(enModemId);


    /* CS????????, ????CS?????????????????? */
    AT_UpdateCallErrInfo(ucIndex, TAF_CS_CAUSE_SUCCESS, &(pstCallInfo->stErrInfoText));

    /* ????????????????????VOICE????DATA */
    if(MN_CALL_DIR_MO == pstCallInfo->enCallDir)
    {
        if(AT_COLP_ENABLE_TYPE == pstSsCtx->ucColpType)
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s+COLP: ",gaucAtCrLf);
            if(0 != pstCallInfo->stConnectNumber.ucNumLen)
            {
                AT_BcdNumberToAscii(pstCallInfo->stConnectNumber.aucBcdNum,
                                    pstCallInfo->stConnectNumber.ucNumLen,
                                    (VOS_CHAR *)aucAsciiNum);
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"%s\",%d,\"\",,\"\"",aucAsciiNum,(pstCallInfo->stConnectNumber.enNumType | AT_NUMBER_TYPE_EXT));
            }
            else
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"\",,\"\",,\"\"");
            }
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
            At_SendResultData(ucIndex,pgucAtSndCodeAddr,usLength);
            usLength = 0;
        }
    }

    /* Video????????At_FormatResultData??????CONNECT */
    if (AT_EVT_IS_VIDEO_CALL(pstCallInfo->enCallType))
    {
        /* IMS Video??????????CONNECT??????^CONN */
        if (TAF_CALL_VOICE_DOMAIN_IMS == pstCallInfo->enVoiceDomain)
        {
            if (VOS_TRUE == AT_CheckRptCmdStatus(pstCallInfo->aucCurcRptCfg, AT_CMD_RPT_CTRL_BY_CURC, AT_RPT_CMD_CONN))
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                   "%s^CONN:%d,%d%s",
                                                   gaucAtCrLf,
                                                   pstCallInfo->callId,
                                                   pstCallInfo->enCallType,
                                                   gaucAtCrLf);

                At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
            }

            return;
        }

        gastAtClientTab[ucIndex].ucCsRabId = pstCallInfo->ucRabId;
        ulResult = AT_CONNECT;

        /* ??????PCUI????????????????????????????????????????????????MODEM????????VP??????????????????  */
        if (AT_MODEM_USER == gastAtClientTab[ucIndex].UserType)
        {

            At_SetMode(ucIndex, AT_DATA_MODE, AT_CSD_DATA_MODE);   /* ???????? */
        }
    }
    else
    {

        enNewCallType = MN_CALL_TYPE_VOICE;
        At_ChangeEcallTypeToCallType(pstCallInfo->enCallType, &enNewCallType);

        if (VOS_TRUE == AT_CheckRptCmdStatus(pstCallInfo->aucCurcRptCfg, AT_CMD_RPT_CTRL_BY_CURC, AT_RPT_CMD_CONN))
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"^CONN:%d",pstCallInfo->callId);
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",enNewCallType);
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
            At_SendResultData(ucIndex,pgucAtSndCodeAddr,usLength);
        }
        return;
    }

    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);

}


VOS_VOID  AT_ProcCsRspEvtOrig(
    TAF_UINT8                           ucIndex,
    MN_CALL_INFO_STRU                  *pstCallInfo
)
{
    AT_MODEM_CC_CTX_STRU               *pstCcCtx = VOS_NULL_PTR;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;
    TAF_UINT16                          usLength;
    VOS_UINT32                          ulCheckRptCmdStatusResult;
    MN_CALL_TYPE_ENUM_U8                enNewCallType;

    usLength  = 0;
    enModemId = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("AT_CsRspEvtOrigProc: Get modem id fail.");
        return;
    }

    pstCcCtx = AT_GetModemCcCtxAddrFromModemId(enModemId);

    /* ??????????????????????????^ORIG ????????????????????????????????????????????^ORIG */
    ulCheckRptCmdStatusResult = AT_CheckRptCmdStatus(pstCallInfo->aucCurcRptCfg, AT_CMD_RPT_CTRL_BY_CURC, AT_RPT_CMD_ORIG);
    enNewCallType = MN_CALL_TYPE_VOICE;
    At_ChangeEcallTypeToCallType(pstCallInfo->enCallType, &enNewCallType);

    if (((PS_TRUE  == At_CheckReportOrigCallType(enNewCallType))
      || (AT_EVT_IS_PS_VIDEO_CALL(pstCallInfo->enCallType, pstCallInfo->enVoiceDomain)))
     && (VOS_TRUE == ulCheckRptCmdStatusResult))
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"^ORIG:%d",pstCallInfo->callId);
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",enNewCallType);
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
    }

    /* ????????????????????OK??????????????????????????????TRUE */
    pstCcCtx->ulCurIsExistCallFlag = VOS_TRUE;

    return;
}


VOS_UINT8 At_GetSsCode(
    MN_CALL_SS_NOTIFY_CODE_ENUM_U8      enCode,
    MN_CALL_STATE_ENUM_U8               enCallState
)
{
    switch (enCode)
    {
        case MN_CALL_SS_NTFY_FORWORDED_CALL:
            return 0;

        case MN_CALL_SS_NTFY_MT_CUG_INFO:
            return 1;

        case MN_CALL_SS_NTFY_ON_HOLD:
            return 2;

        case MN_CALL_SS_NTFY_RETRIEVED:
            return 3;

        case MN_CALL_SS_NTFY_ENTER_MPTY:
            return 4;

        case MN_CALL_SS_NTFY_HOLD_RELEASED:
            return 5;

        case MN_CALL_SS_NTFY_DEFLECTED_CALL:
            return 9;

        case MN_CALL_SS_NTFY_INCALL_FORWARDED:
            return 10;

        case MN_CALL_SS_NTFY_EXPLICIT_CALL_TRANSFER:
            if ( MN_CALL_S_ALERTING == enCallState )
            {
                return 7;
            }
            return 8;

        case MN_CALL_SS_NTFY_CCBS_BE_RECALLED:
            return 0x16;

        default:
            return 0xFF;
    }
}


VOS_UINT8 At_GetCssiForwardCauseCode(MN_CALL_CF_CAUSE_ENUM_UINT8 enCode)
{
    switch (enCode)
    {
        case MN_CALL_CF_CAUSE_ALWAYS:
            return 0;

        case MN_CALL_CF_CAUSE_BUSY:
            return 1;

        case MN_CALL_CF_CAUSE_POWER_OFF:
            return 2;

        case MN_CALL_CF_CAUSE_NO_ANSWER:
            return 3;

        case MN_CALL_CF_CAUSE_SHADOW_ZONE:
            return 4;

        case MN_CALL_CF_CAUSE_DEFLECTION_480:
            return 5;

        case MN_CALL_CF_CAUSE_DEFLECTION_487:
            return 6;

        default:
            AT_ERR_LOG1("At_GetCssiFormardCauseCode: enCode is fail, enCode is ", enCode);
            return 0xFF;
    }
}


VOS_VOID At_ProcCsEvtCssuexNotifiy_Ims(
    const MN_CALL_INFO_STRU            *pstCallInfo,
    VOS_UINT8                           ucCode,
    VOS_UINT16                         *pusLength
)
{
    VOS_CHAR                            aucAsciiNum[(MN_CALL_MAX_BCD_NUM_LEN * 2) + 1];

    TAF_MEM_SET_S(aucAsciiNum, (VOS_UINT32)sizeof(aucAsciiNum), 0, (VOS_UINT32)sizeof(aucAsciiNum));

    /* ^CSSUEX: <code2>,[<index>],<callId>[,<number>,<type>[,<forward_cause>]] */
    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s^CSSUEX: ",
                                         gaucAtCrLf);

    /* <code2>, */
    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%d,", ucCode);

    /* [index], */
    if (MN_CALL_SS_NTFY_MT_CUG_INFO  == pstCallInfo->stSsNotify.enCode)
    {
        /* <index> */
        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                            (VOS_CHAR *)pgucAtSndCodeAddr,
                                            (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                            "%d,", pstCallInfo->stSsNotify.ulCugIndex);
    }
    else
    {
        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                            (VOS_CHAR *)pgucAtSndCodeAddr,
                                            (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                            ",");
    }

    /* <callId> */
    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%d", pstCallInfo->callId);

    if (MN_CALL_SS_NTFY_MT_CUG_INFO  == pstCallInfo->stSsNotify.enCode)
    {
        if (0 != pstCallInfo->stCallNumber.ucNumLen)
        {
            AT_BcdNumberToAscii(pstCallInfo->stCallNumber.aucBcdNum,
                                pstCallInfo->stCallNumber.ucNumLen,
                                aucAsciiNum);

            /* ,<number> */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 ",\"%s\"", aucAsciiNum);

            /* ,<type> */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 ",%d", (pstCallInfo->stCallNumber.enNumType | AT_NUMBER_TYPE_EXT));
        }
    }



    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s", gaucAtCrLf);
}

VOS_VOID At_ProcCsEvtCssuNotifiy_Ims(
    const MN_CALL_INFO_STRU            *pstCallInfo,
    VOS_UINT8                           ucCode,
    VOS_UINT16                         *pusLength
)
{
    VOS_CHAR                            aucAsciiNum[(MN_CALL_MAX_BCD_NUM_LEN * 2) + 1];

    TAF_MEM_SET_S(aucAsciiNum, (VOS_UINT32)sizeof(aucAsciiNum), 0, (VOS_UINT32)sizeof(aucAsciiNum));

    /* ^CSSU: <code2>[,<index>[,<number>,<type>[,<subaddr>,<satype>]]] */
    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s^CSSU: ",
                                         gaucAtCrLf);

    /* <code2> */
    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%d", ucCode);

    if (MN_CALL_SS_NTFY_MT_CUG_INFO == pstCallInfo->stSsNotify.enCode)
    {
        /* ,<index> */
        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                             (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                             ",%d", pstCallInfo->stSsNotify.ulCugIndex);

        if (0 != pstCallInfo->stCallNumber.ucNumLen)
        {
            AT_BcdNumberToAscii(pstCallInfo->stCallNumber.aucBcdNum,
                                pstCallInfo->stCallNumber.ucNumLen,
                                aucAsciiNum);

            /* ,<number> */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 ",\"%s\"", aucAsciiNum);

            /* ,<type> */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 ",%d", (pstCallInfo->stCallNumber.enNumType | AT_NUMBER_TYPE_EXT));
        }
    }

    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s", gaucAtCrLf);

    At_ProcCsEvtCssuexNotifiy_Ims(pstCallInfo,ucCode,pusLength);

}


VOS_VOID At_ProcCsEvtCssiNotifiy_Ims(
    const MN_CALL_INFO_STRU            *pstCallInfo,
    VOS_UINT16                         *pusLength
)
{
    VOS_CHAR                            aucAsciiNum[(MN_CALL_MAX_BCD_NUM_LEN * 2) + 1];
    VOS_UINT8                           ucForwardCauseCode;

    TAF_MEM_SET_S(aucAsciiNum, sizeof(aucAsciiNum), 0x00, sizeof(aucAsciiNum));
    ucForwardCauseCode  = 0xFF;

    /* ^CSSI: <code1>,<index>,<callId>[,<number>,<type>[,<forward_cause>]] */
    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s^CSSI: ",
                                         gaucAtCrLf);

    /* <code1>, */
    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%d,", pstCallInfo->stSsNotify.enCode);

    /* [index], */
    if ((MN_CALL_SS_NTFY_MO_CUG_INFO  == pstCallInfo->stSsNotify.enCode)
     || (MN_CALL_SS_NTFY_BE_FORWORDED == pstCallInfo->stSsNotify.enCode))
    {
        /* ,<index> */
        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                            (VOS_CHAR *)pgucAtSndCodeAddr,
                                            (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                            "%d,", pstCallInfo->stSsNotify.ulCugIndex);
    }
    else
    {
        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                            (VOS_CHAR *)pgucAtSndCodeAddr,
                                            (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                            ",");
    }

    /* <callId> */
    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%d", pstCallInfo->callId);

    if ((MN_CALL_SS_NTFY_MO_CUG_INFO  == pstCallInfo->stSsNotify.enCode)
     || (MN_CALL_SS_NTFY_BE_FORWORDED == pstCallInfo->stSsNotify.enCode))
    {
        /* ???????????? */
        if (0 != pstCallInfo->stConnectNumber.ucNumLen)
        {
            (VOS_VOID)AT_BcdNumberToAscii(pstCallInfo->stConnectNumber.aucBcdNum,
                                          pstCallInfo->stConnectNumber.ucNumLen,
                                          aucAsciiNum);

            /* ,<number> */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 ",\"%s\"", aucAsciiNum);

            /* ,<type> */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 ",%d", (pstCallInfo->stConnectNumber.enNumType | AT_NUMBER_TYPE_EXT));

            /* [,<forward_cause>] */
            ucForwardCauseCode = At_GetCssiForwardCauseCode(pstCallInfo->enCallForwardCause);

            if ( 0xFF != ucForwardCauseCode)
            {
                *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                                     (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                     ",%d", ucForwardCauseCode);
            }
        }
    }

    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s", gaucAtCrLf);

}


VOS_VOID At_ProcCsEvtImsHoldToneNotifiy_Ims(
    const MN_CALL_INFO_STRU            *pstCallInfo,
    VOS_UINT16                         *pusLength
)
{

    /* ^IMSHOLDTONE: <hold_tone> */
    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s%s: ",
                                         gaucAtCrLf,
                                         gastAtStringTab[AT_STRING_IMS_HOLD_TONE].pucText);

    /* <hold_tone> */
    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%d", pstCallInfo->enHoldToneType);


    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s", gaucAtCrLf);

}


VOS_VOID At_ProcCsEvtCssuNotifiy_NonIms(
    const MN_CALL_INFO_STRU            *pstCallInfo,
    VOS_UINT8                           ucCode,
    VOS_UINT16                         *pusLength
)
{
    VOS_CHAR                            aucAsciiNum[(MN_CALL_MAX_BCD_NUM_LEN * 2) + 1];

    TAF_MEM_SET_S(aucAsciiNum, (VOS_UINT32)sizeof(aucAsciiNum), 0, (VOS_UINT32)sizeof(aucAsciiNum));

    /* +CSSU: <code2>[,<index>[,<number>,<type>[,<subaddr>,<satype>]]] */
    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s+CSSU: ",
                                         gaucAtCrLf);

    /* <code2> */
    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%d", ucCode);

    if (MN_CALL_SS_NTFY_MT_CUG_INFO == pstCallInfo->stSsNotify.enCode)
    {
        /* ,<index> */
        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                             (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                             ",%d", pstCallInfo->stSsNotify.ulCugIndex);

        if (0 != pstCallInfo->stCallNumber.ucNumLen)
        {
            AT_BcdNumberToAscii(pstCallInfo->stCallNumber.aucBcdNum,
                                pstCallInfo->stCallNumber.ucNumLen,
                                aucAsciiNum);

            /* ,<number> */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 ",\"%s\"", aucAsciiNum);

            /* ,<type> */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 ",%d", (pstCallInfo->stCallNumber.enNumType | AT_NUMBER_TYPE_EXT));
        }
    }

    if (MN_CALL_SS_NTFY_EXPLICIT_CALL_TRANSFER == pstCallInfo->stSsNotify.enCode)
    {
        /* ,<index> */
        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                             (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                             ",%d", pstCallInfo->stSsNotify.ulCugIndex);

        if (0 != pstCallInfo->stSsNotify.stEctIndicator.rdn.stPresentationAllowedAddr.ucNumLen)
        {
            AT_BcdNumberToAscii(pstCallInfo->stSsNotify.stEctIndicator.rdn.stPresentationAllowedAddr.aucBcdNum,
                                pstCallInfo->stSsNotify.stEctIndicator.rdn.stPresentationAllowedAddr.ucNumLen,
                                aucAsciiNum);

            /* ,<number> */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 ",\"%s\"", aucAsciiNum);

            /* ,<type> */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 ",%d", (pstCallInfo->stSsNotify.stEctIndicator.rdn.stPresentationAllowedAddr.enNumType | AT_NUMBER_TYPE_EXT));
        }
    }

    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s", gaucAtCrLf);

}


VOS_VOID At_ProcCsEvtCssiNotifiy_NonIms(
    const MN_CALL_INFO_STRU            *pstCallInfo,
    VOS_UINT16                         *pusLength
)
{
    /* +CSSI: <code1>[,<index>] */
    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s+CSSI: ",
                                         gaucAtCrLf);

    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%d", pstCallInfo->stSsNotify.enCode);

    if (MN_CALL_SS_NTFY_MO_CUG_INFO  == pstCallInfo->stSsNotify.enCode)
    {
        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                             (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                             ",%d", pstCallInfo->stSsNotify.ulCugIndex);
    }

    if ((MN_CALL_SS_NTFY_CCBS_RECALL == pstCallInfo->stSsNotify.enCode)
     && (MN_CALL_OPTION_EXIST == pstCallInfo->stCcbsFeature.OP_CcbsIndex))
    {
        *pusLength += (VOS_UINT16)At_CcClass2Print(pstCallInfo->enCallType,
                                                   pgucAtSndCodeAddr + *pusLength);

        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                             (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                              "%s",
                                              gaucAtCrLf);

        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                             (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                              ",%d",
                                              pstCallInfo->stCcbsFeature.CcbsIndex);

        if (MN_CALL_OPTION_EXIST == pstCallInfo->stCcbsFeature.OP_BSubscriberNum)
        {
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                  ",%s",
                                                  pstCallInfo->stCcbsFeature.aucBSubscriberNum);
        }

        if (MN_CALL_OPTION_EXIST == pstCallInfo->stCcbsFeature.OP_NumType)
        {
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                  ",%d",
                                                  pstCallInfo->stCcbsFeature.NumType);
        }
    }

    *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s", gaucAtCrLf);

}



VOS_VOID At_ProcCsRspEvtCssuNotifiy(
    VOS_UINT8                           ucIndex,
    MN_CALL_INFO_STRU                  *pstCallInfo,
    VOS_UINT16                         *pusLength
)
{
    VOS_UINT8                           ucCode;
    VOS_UINT16                          usLength;
    VOS_UINT32                          ulCssuRptStatus;

    usLength = *pusLength;

    if (ucIndex >= AT_MAX_CLIENT_NUM)
    {
        return;
    }

    ulCssuRptStatus = AT_CheckRptCmdStatus(pstCallInfo->aucUnsolicitedRptCfg,
                                           AT_CMD_RPT_CTRL_BY_UNSOLICITED,
                                           AT_RPT_CMD_CSSU);

    /* +CSSU: <code2>[,<index>[,<number>,<type>[,<subaddr>,<satype>]]] */
    if (((VOS_TRUE == ulCssuRptStatus)
      && (MN_CALL_SS_NTFY_BE_DEFLECTED < pstCallInfo->stSsNotify.enCode)
      && (MN_CALL_SS_NTFY_CCBS_RECALL  != pstCallInfo->stSsNotify.enCode))
     && ((AT_CMD_D_CS_VOICE_CALL_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
      && (AT_CMD_D_CS_DATA_CALL_SET  != gastAtClientTab[ucIndex].CmdCurrentOpt)
      && (AT_CMD_APDS_SET            != gastAtClientTab[ucIndex].CmdCurrentOpt)))
    {
        ucCode = At_GetSsCode(pstCallInfo->stSsNotify.enCode, pstCallInfo->enCallState);

        if (0xFF == ucCode)
        {
            AT_ERR_LOG("At_ProcCsRspEvtCssuNotifiy: code error.");
            return;
        }

        if (TAF_CALL_VOICE_DOMAIN_IMS == pstCallInfo->enVoiceDomain)
        {
            At_ProcCsEvtCssuNotifiy_Ims(pstCallInfo, ucCode, &usLength);
        }
        else
        {
            At_ProcCsEvtCssuNotifiy_NonIms(pstCallInfo, ucCode, &usLength);
        }
    }

    *pusLength = usLength;

    return;
}


VOS_VOID At_ProcCsRspEvtCssiNotifiy(
    VOS_UINT8                           ucIndex,
    MN_CALL_INFO_STRU                  *pstCallInfo,
    VOS_UINT16                         *pusLength
)
{
    VOS_UINT16                          usLength;
    VOS_UINT32                          ulCssiRptStatus;

    usLength = *pusLength;

    ulCssiRptStatus = AT_CheckRptCmdStatus(pstCallInfo->aucUnsolicitedRptCfg,
                                           AT_CMD_RPT_CTRL_BY_UNSOLICITED,
                                           AT_RPT_CMD_CSSI);

    if ((VOS_TRUE == ulCssiRptStatus)
     && ((MN_CALL_SS_NTFY_BE_DEFLECTED >= pstCallInfo->stSsNotify.enCode)
      || (MN_CALL_SS_NTFY_CCBS_RECALL  == pstCallInfo->stSsNotify.enCode)))
    {
        /* ^CSSI: <code1>[,<index>[,<number>,<type>]] */
        if (TAF_CALL_VOICE_DOMAIN_IMS == pstCallInfo->enVoiceDomain)
        {
            At_ProcCsEvtCssiNotifiy_Ims(pstCallInfo, &usLength);
        }
        else
        /* +CSSI: <code1>[,<index>] */
        {
            At_ProcCsEvtCssiNotifiy_NonIms(pstCallInfo, &usLength);
        }
    }

    *pusLength = usLength;

    return;
}


VOS_VOID  AT_ProcCsRspEvtSsNotify(
    VOS_UINT8                           ucIndex,
    MN_CALL_INFO_STRU                  *pstCallInfo
)
{
    VOS_UINT16                          usLength;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;

    usLength  = 0;

    At_ProcCsRspEvtCssiNotifiy(ucIndex, pstCallInfo, &usLength);

    At_ProcCsRspEvtCssuNotifiy(ucIndex, pstCallInfo, &usLength);

    if (TAF_CALL_VOICE_DOMAIN_IMS == pstCallInfo->enVoiceDomain)
    {
        At_ProcCsEvtImsHoldToneNotifiy_Ims(pstCallInfo, &usLength);
    }

    if ((AT_BROADCAST_CLIENT_INDEX_MODEM_0 != ucIndex)
     && (AT_BROADCAST_CLIENT_INDEX_MODEM_1 != ucIndex)
     && (AT_BROADCAST_CLIENT_INDEX_MODEM_2 != ucIndex))
    {
        enModemId = MODEM_ID_0;

        /* ????client id??????Modem Id */
        ulRslt = AT_GetModemIdFromClient(gastAtClientTab[ucIndex].usClientId, &enModemId);

        if (VOS_OK != ulRslt)
        {
            AT_WARN_LOG("AT_ProcCsRspEvtSsNotify: WARNING:MODEM ID NOT FOUND!");
            return;
        }

        /* CCALLSTATE??????????????????MODEM ID??????????????Index */
        if (MODEM_ID_0 == enModemId)
        {
            ucIndex = AT_BROADCAST_CLIENT_INDEX_MODEM_0;
        }
        else if (MODEM_ID_1 == enModemId)
        {
            ucIndex = AT_BROADCAST_CLIENT_INDEX_MODEM_1;
        }
        else
        {
            ucIndex = AT_BROADCAST_CLIENT_INDEX_MODEM_2;
        }
    }

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return;
}


VOS_VOID  AT_ProcCsRspEvtCallProc(
    TAF_UINT8                           ucIndex,
    MN_CALL_INFO_STRU                  *pstCallInfo
)
{
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;
    TAF_UINT16                          usLength;
    VOS_UINT32                          ulCheckRptCmdStatusResult;

    usLength  = 0;
    enModemId = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("AT_CsRspEvtCallProcProc: Get modem id fail.");
        return;
    }

    /* CS??????????????????????????^CONF ????????????????????????????????????????????^CONF */
    ulCheckRptCmdStatusResult = AT_CheckRptCmdStatus(pstCallInfo->aucCurcRptCfg, AT_CMD_RPT_CTRL_BY_CURC, AT_RPT_CMD_CONF);

    if (((PS_TRUE == At_CheckReportConfCallType(pstCallInfo->enCallType))
      || (AT_EVT_IS_PS_VIDEO_CALL(pstCallInfo->enCallType, pstCallInfo->enVoiceDomain)))
     && (VOS_TRUE == ulCheckRptCmdStatusResult))
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"^CONF:%d",pstCallInfo->callId);
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
    }

    return;
}

TAF_VOID At_CsRspProc(
    TAF_UINT8                           ucIndex,
    MN_CALL_EVENT_ENUM_U32              enEvent,
    MN_CALL_INFO_STRU                   *pstCallInfo
)
{
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;
    AT_MODEM_CC_CTX_STRU               *pstCcCtx = VOS_NULL_PTR;

    pstCcCtx = AT_GetModemCcCtxAddrFromClientId(ucIndex);

    switch( enEvent )            /* ???????????? */
    {



    case MN_CALL_EVT_CONNECT:
        AT_CsRspEvtConnectProc(ucIndex, enEvent, pstCallInfo);
        return;

    case MN_CALL_EVT_ORIG:
        AT_ProcCsRspEvtOrig(ucIndex, pstCallInfo);
        return;

    case MN_CALL_EVT_CALL_PROC:
        AT_ProcCsRspEvtCallProc(ucIndex, pstCallInfo);
        return;


    case MN_CALL_EVT_SS_CMD_RSLT:
        if (AT_CMD_CURRENT_OPT_BUTT == gastAtClientTab[ucIndex].CmdCurrentOpt)
        {
            return;
        }

        if(MN_CALL_SS_RES_SUCCESS == pstCallInfo->enSsResult)
        {
            ulResult = AT_OK;
        }
        else
        {
            ulResult = AT_ERROR;
        }
        AT_STOP_TIMER_CMD_READY(ucIndex);
        break;

    case MN_CALL_EVT_SS_NOTIFY:
    /*case MN_CALL_EVT_ALERTING:alerting ??????????????????????????*/
        AT_ProcCsRspEvtSsNotify(ucIndex, pstCallInfo);
        return;

    case MN_CALL_EVT_RELEASED:
        AT_CsRspEvtReleasedProc(ucIndex, enEvent, pstCallInfo);
        return;

    case MN_CALL_EVT_UUS1_INFO:
        AT_CsUus1InfoEvtIndProc(ucIndex,enEvent,pstCallInfo);
        break;
    case MN_CALL_EVT_GET_CDUR_CNF:
        AT_RcvCdurQryRsp(ucIndex,enEvent,pstCallInfo);
        return;

    case MN_CALL_EVT_ALL_RELEASED:

        /* ??????????????RELEASED??????????????????????????????FALSE */
        pstCcCtx->ulCurIsExistCallFlag = VOS_FALSE;
        break;

    default:
        AT_WARN_LOG("At_CsRspProc CallEvent ERROR");
        return;
    }

    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);
}


TAF_VOID AT_CsSsNotifyEvtIndProc(
    TAF_UINT8                           ucIndex,
    MN_CALL_EVENT_ENUM_U32              enEvent,
    MN_CALL_INFO_STRU                  *pstCallInfo
)
{
    VOS_UINT8                           ucCode;
    VOS_UINT16                          usLength;
    VOS_UINT32                          ulCssiRptStatus;
    VOS_UINT32                          ulCssuRptStatus;

    usLength = 0;
    ulCssiRptStatus = AT_CheckRptCmdStatus(pstCallInfo->aucUnsolicitedRptCfg,
                                           AT_CMD_RPT_CTRL_BY_UNSOLICITED,
                                           AT_RPT_CMD_CSSI);

    if ((VOS_TRUE == ulCssiRptStatus)
     && ((MN_CALL_SS_NTFY_BE_DEFLECTED >= pstCallInfo->stSsNotify.enCode)
      || (MN_CALL_SS_NTFY_CCBS_RECALL  == pstCallInfo->stSsNotify.enCode)))
    {
        /* ^CSSI: <code1>[,<index>[,<number>,<type>]] */
        if (TAF_CALL_VOICE_DOMAIN_IMS == pstCallInfo->enVoiceDomain)
        {
            At_ProcCsEvtCssiNotifiy_Ims(pstCallInfo, &usLength);
        }
        else
        /* +CSSI: <code1>[,<index>] */
        {
            At_ProcCsEvtCssiNotifiy_NonIms(pstCallInfo, &usLength);
        }
    }

    ulCssuRptStatus = AT_CheckRptCmdStatus(pstCallInfo->aucUnsolicitedRptCfg,
                                           AT_CMD_RPT_CTRL_BY_UNSOLICITED,
                                           AT_RPT_CMD_CSSU);

    if ((VOS_TRUE == ulCssuRptStatus)
     && (MN_CALL_SS_NTFY_BE_DEFLECTED < pstCallInfo->stSsNotify.enCode)
     && (MN_CALL_SS_NTFY_CCBS_RECALL  != pstCallInfo->stSsNotify.enCode))
    {
        ucCode = At_GetSsCode(pstCallInfo->stSsNotify.enCode, pstCallInfo->enCallState);

        if (0xFF == ucCode)
        {
            AT_ERR_LOG("AT_CsSsNotifyEvtIndProc: cssu code error.");
            return;
        }

        if (TAF_CALL_VOICE_DOMAIN_IMS == pstCallInfo->enVoiceDomain)
        {
            /* ^CSSU: <code2>[,<index>[,<number>,<type>[,<subaddr>,<satype>]]] */
            At_ProcCsEvtCssuNotifiy_Ims(pstCallInfo, ucCode, &usLength);
        }
        else
        {
            /* +CSSU: <code2>[,<index>[,<number>,<type>[,<subaddr>,<satype>]]] */
            At_ProcCsEvtCssuNotifiy_NonIms(pstCallInfo, ucCode, &usLength);
        }
    }

    if (TAF_CALL_VOICE_DOMAIN_IMS == pstCallInfo->enVoiceDomain)
    {
        At_ProcCsEvtImsHoldToneNotifiy_Ims(pstCallInfo, &usLength);
    }

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return;
}

TAF_VOID At_CsIncomingEvtOfIncomeStateIndProc(
    TAF_UINT8                           ucIndex,
    MN_CALL_EVENT_ENUM_U32              enEvent,
    MN_CALL_INFO_STRU                   *pstCallInfo
)
{
    TAF_UINT16                          usLength;
    TAF_UINT8                           ucCLIValid;
    TAF_UINT32                          ulTimerName;
    TAF_UINT8                           aucAsciiNum[(MN_CALL_MAX_BCD_NUM_LEN*2)+1];
    AT_DCE_MSC_STRU                     stMscStru;
    TAF_UINT16                          usLoop;
    TAF_UINT32                          ulDelayaCnt;
    AT_MODEM_CC_CTX_STRU               *pstCcCtx = VOS_NULL_PTR;
    AT_MODEM_SS_CTX_STRU               *pstSsCtx = VOS_NULL_PTR;

    pstCcCtx = AT_GetModemCcCtxAddrFromClientId(ucIndex);
    pstSsCtx = AT_GetModemSsCtxAddrFromClientId(ucIndex);

    usLength = 0;
    usLoop = 0;
    ulDelayaCnt = 50000;

    if( AT_CRC_ENABLE_TYPE == pstSsCtx->ucCrcType )         /* ?????????????? */
    {
        /* +CRC -- +CRING: <type> */

        if (TAF_CALL_VOICE_DOMAIN_IMS == pstCallInfo->enVoiceDomain)
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                "%sIRING%s",
                                                gaucAtCrLf,
                                                gaucAtCrLf);
        }
        else
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                "%s+CRING: ",
                                                gaucAtCrLf);

            usLength += (TAF_UINT16)At_CcClass2Print(pstCallInfo->enCallType,
                                                     pgucAtSndCodeAddr + usLength);
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                "%s",
                                                gaucAtCrLf);
        }
    }
    else
    {
        if (AT_EVT_IS_CS_VIDEO_CALL(pstCallInfo->enCallType, pstCallInfo->enVoiceDomain))
        {
            /* ????????????????????????????????????MODEM????,??????????????
               ???? */
            for(usLoop = 0; usLoop < AT_MAX_CLIENT_NUM; usLoop++)
            {
                if (AT_MODEM_USER == gastAtClientTab[usLoop].UserType)
                {
                    ucIndex = (VOS_UINT8)usLoop;
                    break;
                }
            }

            /* ????????????????????????????MODEM???????????????? */
            if (AT_MAX_CLIENT_NUM == usLoop)
            {
                return;
            }

            /* ????DSR??RI??????????,????????????????( ??????????????????
               USB???? ) */
            TAF_MEM_SET_S(&stMscStru, sizeof(stMscStru), 0x00, sizeof(AT_DCE_MSC_STRU));
            stMscStru.OP_Dsr = 1;
            stMscStru.ucDsr  = 1;
            stMscStru.OP_Ri = 1;
            stMscStru.ucRi  = 1;
            stMscStru.OP_Dcd = 1;
            stMscStru.ucDcd  = 1;
            AT_SetModemStatus((VOS_UINT8)usLoop,&stMscStru);

            /* ????????????????????????PC????????????????????????  */
            ulDelayaCnt = 50000;
            while( ulDelayaCnt-- )
            {
                ;
            }

            /*EVENT-UE UP DCD*/
            AT_EventReport(WUEPS_PID_AT, NAS_OM_EVENT_DCE_UP_DCD,
                            VOS_NULL_PTR, NAS_OM_EVENT_NO_PARA);
        }

        if (TAF_CALL_VOICE_DOMAIN_IMS == pstCallInfo->enVoiceDomain)
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                "%sIRING%s",
                                                gaucAtCrLf,
                                                gaucAtCrLf);
        }
        else
        {
            /* +CRC -- RING */
            if( AT_V_ENTIRE_TYPE == gucAtVType )
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                    "%sRING%s",
                                                    gaucAtCrLf,
                                                    gaucAtCrLf);
            }
            else
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                    "2\r");
            }

        }

    }

    if( AT_CLIP_ENABLE_TYPE == pstSsCtx->ucClipType )
    {
        /*
        +CLIP: <number>,<type>
        ????????[,<subaddr>,<satype>[,[<alpha>][,<CLI validity>]]]????????
        */
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                            "%s+CLIP: ",
                                            gaucAtCrLf);

        ucCLIValid = AT_ConvertCLIValidity(pstCallInfo);

        if( 0 != pstCallInfo->stCallNumber.ucNumLen )
        {
            AT_BcdNumberToAscii(pstCallInfo->stCallNumber.aucBcdNum,
                                pstCallInfo->stCallNumber.ucNumLen,
                                (VOS_CHAR *)aucAsciiNum);

           /* ??????????????????????????????????????+,?????????????? */
           if (MN_MSG_TON_INTERNATIONAL == ((pstCallInfo->stCallNumber.enNumType >> 4) & 0x07))
           {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                   "\"+%s\",%d,\"\",,\"\",%d",
                                                    aucAsciiNum,
                                                    (pstCallInfo->stCallNumber.enNumType | AT_NUMBER_TYPE_EXT),
                                                    ucCLIValid);
           }
           else
           {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                    "\"%s\",%d,\"\",,\"\",%d",
                                                    aucAsciiNum,
                                                    (pstCallInfo->stCallNumber.enNumType | AT_NUMBER_TYPE_EXT),
                                                    ucCLIValid);
           }
        }
        else
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                "\"\",,\"\",,\"\",%d",
                                                ucCLIValid);
        }
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                            "%s",
                                            gaucAtCrLf);
    }

    if ( AT_SALS_ENABLE_TYPE == pstSsCtx->ucSalsType )
    {
        /*??????????1????????2??????*/
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                          (TAF_CHAR *)pgucAtSndCodeAddr,
                                          (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%s^ALS: ",
                                           gaucAtCrLf);
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                          (TAF_CHAR *)pgucAtSndCodeAddr,
                                          (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%d",
                                           pstCallInfo->enAlsLineNo);
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                          (TAF_CHAR *)pgucAtSndCodeAddr,
                                          (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%s",
                                           gaucAtCrLf);
    }

    At_SendResultData(ucIndex,pgucAtSndCodeAddr,usLength);

    /* ????+CNAP???? */
    AT_ReportCnapInfo(ucIndex, &(pstCallInfo->stNameIndicator));

    /* ??????????????voice???????????????????????????????????????????????? */
    if ((MN_CALL_TYPE_VOICE  == pstCallInfo->enCallType)
     && (0 != pstCcCtx->stS0TimeInfo.ucS0TimerLen))
    {
        /* ????????????????????????????RING?????????? */
        if (TAF_TRUE != pstCcCtx->stS0TimeInfo.bTimerStart)
        {
            ulTimerName = AT_S0_TIMER;
            ulTimerName |= AT_INTERNAL_PROCESS_TYPE;
            ulTimerName |= (ucIndex<<12);

            AT_StartRelTimer(&(pstCcCtx->stS0TimeInfo.s0Timer),
                              (pstCcCtx->stS0TimeInfo.ucS0TimerLen)*1000,
                              ulTimerName,
                              pstCallInfo->callId,
                              VOS_RELTIMER_NOLOOP);
            pstCcCtx->stS0TimeInfo.bTimerStart = TAF_TRUE;
            pstCcCtx->stS0TimeInfo.ulTimerName = ulTimerName;
        }
    }


    if (AT_EVT_IS_CS_VIDEO_CALL(pstCallInfo->enCallType, pstCallInfo->enVoiceDomain))
    {
        /* ????????????????????(??RING??????????)??PC????????????????????????  */
        ulDelayaCnt = 50000;
        while( ulDelayaCnt-- )
        {
            ;
        }

        /* ????RING??????????RI????????????????????DSR??????????,
           ( ??????????????????USB???????????? ) */
        TAF_MEM_SET_S(&stMscStru, sizeof(stMscStru), 0x00, sizeof(AT_DCE_MSC_STRU));
        stMscStru.OP_Ri = 1;
        stMscStru.ucRi  = 0;
        stMscStru.OP_Dcd = 1;
        stMscStru.ucDcd  = 1;
        stMscStru.OP_Dsr = 1;
        stMscStru.ucDsr  = 1;
        AT_SetModemStatus((VOS_UINT8)usLoop,&stMscStru);
    }

    return;

}


TAF_VOID At_CsIncomingEvtOfWaitStateIndProc(
    TAF_UINT8                           ucIndex,
    MN_CALL_EVENT_ENUM_U32              enEvent,
    MN_CALL_INFO_STRU                   *pstCallInfo
)
{
    TAF_UINT16 usLength;
    TAF_UINT8  aucAsciiNum[(MN_CALL_MAX_BCD_NUM_LEN*2)+1];
    AT_MODEM_SS_CTX_STRU               *pstSsCtx = VOS_NULL_PTR;
    AT_CLI_VALIDITY_ENUM_UINT8          enCliValidity;

    usLength = 0;
    pstSsCtx = AT_GetModemSsCtxAddrFromClientId(ucIndex);

    if( AT_CCWA_ENABLE_TYPE == pstSsCtx->ucCcwaType )         /* ?????????????? */
    {
        if (TAF_CALL_VOICE_DOMAIN_IMS == pstCallInfo->enVoiceDomain)
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                "%s^CCWA: ",
                                                gaucAtCrLf);
        }
        else
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                "%s+CCWA: ",
                                                gaucAtCrLf);
        }

        /* ????????TAF??Cause of No CLI??AT??????CLI Validity?????? */
        enCliValidity = AT_ConvertCLIValidity(pstCallInfo);

        /* 27007 7.12
           When CLI is not available, <number> shall be an empty string ("")
           and <type> value will not be significant. TA may return the recommended
           value 128 for <type>. */
        if (AT_CLI_VALIDITY_VALID == enCliValidity)
        {
            AT_BcdNumberToAscii(pstCallInfo->stCallNumber.aucBcdNum,
                                pstCallInfo->stCallNumber.ucNumLen,
                                (VOS_CHAR *)aucAsciiNum);

            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                "\"%s\",%d",
                                                aucAsciiNum,
                                                (pstCallInfo->stCallNumber.enNumType | AT_NUMBER_TYPE_EXT));
        }
        else
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                "\"\",%d",
                                                AT_NUMBER_TYPE_EXT);
        }

        if ((MN_CALL_TYPE_VOICE      == pstCallInfo->enCallType)
         || (MN_CALL_TYPE_PSAP_ECALL == pstCallInfo->enCallType))
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                ",1");
        }
        else if( MN_CALL_TYPE_VIDEO == pstCallInfo->enCallType )
        {
            if (TAF_CALL_VOICE_DOMAIN_IMS == pstCallInfo->enVoiceDomain)
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                    ",2");
            }
            else
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                    ",32");
            }
        }
        else if( MN_CALL_TYPE_FAX == pstCallInfo->enCallType )
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                ",4");
        }
        else if( MN_CALL_TYPE_CS_DATA == pstCallInfo->enCallType )
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                ",2");
        }
        else
        {

        }

        /* <alpha>,<CLI_validity> */
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                        ",,%d",
                                                        enCliValidity);

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                            "%s",
                                            gaucAtCrLf);

        if ( AT_SALS_ENABLE_TYPE == pstSsCtx->ucSalsType)
        {
            /*??????????1????????2??????*/
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                              (TAF_CHAR *)pgucAtSndCodeAddr,
                                              (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                              "%s^ALS: ",
                                              gaucAtCrLf);
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                              (TAF_CHAR *)pgucAtSndCodeAddr,
                                              (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%d",
                                               pstCallInfo->enAlsLineNo);
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                              (TAF_CHAR *)pgucAtSndCodeAddr,
                                              (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%s",
                                               gaucAtCrLf);
        }
    }

    At_SendResultData(ucIndex,pgucAtSndCodeAddr,usLength);
    return;
}


TAF_VOID At_CsIncomingEvtIndProc(
    TAF_UINT8                           ucIndex,
    MN_CALL_EVENT_ENUM_U32              enEvent,
    MN_CALL_INFO_STRU                   *pstCallInfo
)
{
    g_ucDtrDownFlag = VOS_FALSE;

    /*
    ????????????????????????????????????????????????
    */
    /*
    +CRC -- +CRING: <type> || RING
    +CLIP: <number>,<type>[,<subaddr>,<satype>[,[<alpha>][,<CLI validity>]]]
    */
    if ( MN_CALL_S_INCOMING == pstCallInfo->enCallState )
    {
        At_CsIncomingEvtOfIncomeStateIndProc(ucIndex,enEvent,pstCallInfo);
    }
    else if ( MN_CALL_S_WAITING == pstCallInfo->enCallState )
    {
        At_CsIncomingEvtOfWaitStateIndProc(ucIndex,enEvent,pstCallInfo);
    }
    else
    {
        return;
    }


    return;
}


VOS_UINT32 AT_ConCallMsgTypeToCuusiMsgType(
    MN_CALL_UUS1_MSG_TYPE_ENUM_U32      enMsgType,
    AT_CUUSI_MSG_TYPE_ENUM_U32          *penCuusiMsgType

)
{
    VOS_UINT32                          i;

    for ( i = 0 ; i < sizeof(g_stCuusiMsgType)/sizeof(AT_CALL_CUUSI_MSG_STRU) ; i++ )
    {
        if ( enMsgType == g_stCuusiMsgType[i].enCallMsgType)
        {
            *penCuusiMsgType = g_stCuusiMsgType[i].enCuusiMsgType;
            return VOS_OK;
        }
    }

    return VOS_ERR;
}



VOS_UINT32 AT_ConCallMsgTypeToCuusuMsgType(
    MN_CALL_UUS1_MSG_TYPE_ENUM_U32      enMsgType,
    AT_CUUSU_MSG_TYPE_ENUM_U32          *penCuusuMsgType

)
{
    VOS_UINT32                          i;

    for ( i = 0 ; i < sizeof(g_stCuusuMsgType)/sizeof(AT_CALL_CUUSU_MSG_STRU) ; i++ )
    {
        if ( enMsgType == g_stCuusuMsgType[i].enCallMsgType)
        {
            *penCuusuMsgType = g_stCuusuMsgType[i].enCuusuMsgType;
            return VOS_OK;
        }
    }

    return VOS_ERR;
}


VOS_VOID AT_CsUus1InfoEvtIndProc(
    VOS_UINT8                           ucIndex,
    MN_CALL_EVENT_ENUM_U32              enEvent,
    MN_CALL_INFO_STRU                   *pstCallInfo
)
{
    VOS_UINT32                          ulMsgType;
    AT_CUUSI_MSG_TYPE_ENUM_U32          enCuusiMsgType;
    AT_CUUSU_MSG_TYPE_ENUM_U32          enCuusuMsgType;
    VOS_UINT32                          ulRet;
    MN_CALL_DIR_ENUM_U8                 enCallDir;
    VOS_UINT16                          usLength;

    enCallDir = pstCallInfo->enCallDir;
    ulMsgType = AT_CUUSI_MSG_ANY;

    ulRet = AT_ConCallMsgTypeToCuusiMsgType(pstCallInfo->stUusInfo.enMsgType,&enCuusiMsgType);
    if ( VOS_OK == ulRet )
    {
        ulMsgType = enCuusiMsgType;
        enCallDir = MN_CALL_DIR_MO;
    }
    else
    {
        ulRet = AT_ConCallMsgTypeToCuusuMsgType(pstCallInfo->stUusInfo.enMsgType,&enCuusuMsgType);
        if ( VOS_OK == ulRet )
        {
            ulMsgType = enCuusuMsgType;
            enCallDir = MN_CALL_DIR_MT;
        }
    }

    if ( VOS_OK != ulRet)
    {
        if ( MN_CALL_DIR_MO == pstCallInfo->enCallDir)
        {
            ulMsgType = AT_CUUSI_MSG_ANY;
        }
        else
        {
            ulMsgType = AT_CUUSU_MSG_ANY;
        }
    }

    usLength = 0;

    if ( MN_CALL_DIR_MO == enCallDir )
    {
        /* ??????????????????????,???????? */
        if ( VOS_FALSE == AT_CheckRptCmdStatus(pstCallInfo->aucUnsolicitedRptCfg, AT_CMD_RPT_CTRL_BY_UNSOLICITED, AT_RPT_CMD_CUUS1I))
        {
            return;
        }
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                   "%s+CUUS1I:",
                                   gaucAtCrLf);
    }
    else
    {

        /* ??????????????????????,???????? */
        if ( VOS_FALSE == AT_CheckRptCmdStatus(pstCallInfo->aucUnsolicitedRptCfg, AT_CMD_RPT_CTRL_BY_UNSOLICITED, AT_RPT_CMD_CUUS1U) )
        {
            return;
        }
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                   "%s+CUUS1U:",
                                   gaucAtCrLf);
    }

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                    "%d,",
                                    ulMsgType);

    usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,
                                   (TAF_INT8 *)pgucAtSndCodeAddr,
                                   (TAF_UINT8 *)pgucAtSndCodeAddr + usLength,
                                   pstCallInfo->stUusInfo.aucUuie,
                                   (pstCallInfo->stUusInfo.aucUuie[MN_CALL_LEN_POS] + MN_CALL_UUIE_HEADER_LEN));

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s",
                                       gaucAtCrLf);

    At_SendResultData(ucIndex,pgucAtSndCodeAddr,usLength);

}


VOS_VOID At_ProcSetClccResult(
    VOS_UINT8                           ucNumOfCalls,
    MN_CALL_INFO_QRY_CNF_STRU          *pstCallInfos,
    VOS_UINT8                           ucIndex
)
{
    VOS_UINT8                           ucTmp;
    AT_CLCC_MODE_ENUM_U8                enClccMode;
    VOS_UINT8                           aucAsciiNum[MN_CALL_MAX_CALLED_ASCII_NUM_LEN + 1];
    VOS_UINT16                          usLength;

    VOS_UINT8                          ucNumberType;

    ucNumberType = AT_NUMBER_TYPE_UNKOWN;

    usLength = 0;

    if ( (0 != ucNumOfCalls)
        && ( ucNumOfCalls <=  AT_CALL_MAX_NUM))
    {
        for (ucTmp = 0; ucTmp < ucNumOfCalls; ucTmp++)
        {
            /* <CR><LF> */
            if(0 != ucTmp)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                   "%s",
                                                   gaucAtCrLf);
            }

            AT_MapCallTypeModeToClccMode(pstCallInfos->astCallInfos[ucTmp].enCallType, &enClccMode);

            /* +CLCC:  */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr+ usLength,
                                               "%s: %d,%d,%d,%d,%d",
                                               g_stParseContext[ucIndex].pstCmdElement->pszCmdName, /* +CLCC:  */
                                               pstCallInfos->astCallInfos[ucTmp].callId,             /* <id1>, */
                                               pstCallInfos->astCallInfos[ucTmp].enCallDir,          /* <dir>, */
                                               pstCallInfos->astCallInfos[ucTmp].enCallState,        /* <stat>, */
                                               enClccMode,                                          /* <mode>, */
                                               pstCallInfos->astCallInfos[ucTmp].enMptyState         /* <mpty>, */
                                               );

            if (MN_CALL_DIR_MO == pstCallInfos->astCallInfos[ucTmp].enCallDir)
            {
                if (0 != pstCallInfos->astCallInfos[ucTmp].stConnectNumber.ucNumLen)
                {
                    /* <number>, */
                    AT_BcdNumberToAscii(pstCallInfos->astCallInfos[ucTmp].stConnectNumber.aucBcdNum,
                                        pstCallInfos->astCallInfos[ucTmp].stConnectNumber.ucNumLen,
                                        (TAF_CHAR*)aucAsciiNum);

                    /* <type>,????<alpha>,<priority> */
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                       ",\"%s\",%d,\"\",",
                                                       aucAsciiNum,
                                                       (pstCallInfos->astCallInfos[ucTmp].stConnectNumber.enNumType | AT_NUMBER_TYPE_EXT));
                }
                else if (0 != pstCallInfos->astCallInfos[ucTmp].stCalledNumber.ucNumLen)
                {
                    /* <number>, */
                    AT_BcdNumberToAscii(pstCallInfos->astCallInfos[ucTmp].stCalledNumber.aucBcdNum,
                                        pstCallInfos->astCallInfos[ucTmp].stCalledNumber.ucNumLen,
                                        (TAF_CHAR*)aucAsciiNum);

                    /* <type>,????<alpha>,<priority> */
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                       ",\"%s\",%d,\"\",",
                                                       aucAsciiNum,
                                                       (pstCallInfos->astCallInfos[ucTmp].stCalledNumber.enNumType | AT_NUMBER_TYPE_EXT));


                }
                else
                {
                    /* <type>,????<alpha>,<priority> */
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                       ",\"\",%d",ucNumberType);
                }
            }
            else
            {
                if (0 != pstCallInfos->astCallInfos[ucTmp].stCallNumber.ucNumLen)
                {
                    /* <number>, */
                    AT_BcdNumberToAscii(pstCallInfos->astCallInfos[ucTmp].stCallNumber.aucBcdNum,
                                        pstCallInfos->astCallInfos[ucTmp].stCallNumber.ucNumLen,
                                        (VOS_CHAR *)aucAsciiNum);

                    /* <type>,????<alpha>,<priority> */
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                       ",\"%s\",%d,\"\",",
                                                       aucAsciiNum,
                                                       (pstCallInfos->astCallInfos[ucTmp].stCallNumber.enNumType | AT_NUMBER_TYPE_EXT));
                }
                else
                {
                    /* <type>,????<alpha>,<priority> */
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                       ",\"\",%d",ucNumberType);

                }
            }
        }
    }

    gstAtSendData.usBufLen = usLength;

}


VOS_VOID At_ReportClccDisplayName(
    MN_CALL_DISPLAY_NAME_STRU          *pstDisplayName,
    VOS_UINT16                         *pusLength
)
{
    VOS_UINT8                       i;

    /* ,<display name> */
    (*pusLength) += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + (*pusLength),
                                           ",");

    if ( 0 != pstDisplayName->ucNumLen )
    {
        /* ??UTF8????????????????????E4B8ADE59BBD */
        for (i = 0; i < pstDisplayName->ucNumLen; i++)
        {
            (*pusLength) += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr + (*pusLength),
                                                   "%X",
                                                   (VOS_UINT8)pstDisplayName->acDisplayName[i]);
        }
    }

    return;
}


VOS_VOID At_ReportPeerVideoSupport(
    MN_CALL_INFO_PARAM_STRU            *pstCallInfo,
    VOS_UINT16                         *pusLength
)
{
    (*pusLength) += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + (*pusLength),
                                       ",");

    if (VOS_TRUE == pstCallInfo->bitOpPeerVideoSupport)
    {
        /* <terminal video support> */
        (*pusLength) += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + (*pusLength),
                                           "%d",pstCallInfo->enPeerVideoSupport);
    }

    return;
}


VOS_VOID At_ReportClccImsDomain(
    MN_CALL_INFO_PARAM_STRU            *pstCallInfo,
    VOS_UINT16                         *pusLength
)
{
    VOS_UINT8                           ucImsDomain;

    ucImsDomain = 0;

    (*pusLength) += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + (*pusLength),
                                       ",");

    if (TAF_CALL_IMS_DOMAIN_NULL != pstCallInfo->enImsDomain)
    {
        switch (pstCallInfo->enImsDomain)
        {
            case TAF_CALL_IMS_DOMAIN_LTE:
                ucImsDomain = 0;
                break;

            case TAF_CALL_IMS_DOMAIN_WIFI:
                ucImsDomain = 1;
                break;

            default:
                break;
        }

        /* <imsDomain> */
        (*pusLength) += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + (*pusLength),
                                           "%d",ucImsDomain);

    }

    return;
}


VOS_VOID At_ReportClccRttPara(
    MN_CALL_INFO_PARAM_STRU            *pstCallInfo,
    VOS_UINT16                         *pusLength
)
{
    /* ??????????RTT???????????????? <RttFlg>,<RttChannelId>,<cps> ????????  */
    (*pusLength) += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + (*pusLength),
                                           ",%d,%d,%d",
                                           pstCallInfo->enRtt,
                                           pstCallInfo->lRttChannelId,
                                           pstCallInfo->ulCps);

    return;
}



VOS_VOID At_ProcQryClccResult(
    VOS_UINT8                           ucNumOfCalls,
    MN_CALL_INFO_QRY_CNF_STRU          *pstCallInfos,
    VOS_UINT8                           ucIndex
)
{
    VOS_UINT8                           ucTmp;
    VOS_UINT8                           ucNumberType;
    VOS_UINT8                           aucAsciiNum[MN_CALL_MAX_CALLED_ASCII_NUM_LEN + 1];
    VOS_UINT16                          usLength;
    AT_CLCC_MODE_ENUM_U8                enClccMode;
    TAF_CALL_VOICE_DOMAIN_ENUM_UINT8    enVoiceDomain;

    ucNumberType    = AT_NUMBER_TYPE_UNKOWN;
    usLength        = 0;

    if ((0 != ucNumOfCalls)
     && ( ucNumOfCalls <=  AT_CALL_MAX_NUM))
    {
        for (ucTmp = 0; ucTmp < ucNumOfCalls; ucTmp++)
        {
            /* <CR><LF> */
            if(0 != ucTmp)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                   "%s",
                                                   gaucAtCrLf);
            }

            AT_MapCallTypeModeToClccMode(pstCallInfos->astCallInfos[ucTmp].enCallType, &enClccMode);

            if (TAF_CALL_VOICE_DOMAIN_3GPP2 == pstCallInfos->astCallInfos[ucTmp].enVoiceDomain)
            {
                enVoiceDomain = TAF_CALL_VOICE_DOMAIN_3GPP;
            }
            else
            {
                enVoiceDomain = pstCallInfos->astCallInfos[ucTmp].enVoiceDomain;
            }

            /* ^CLCC:  */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr+ usLength,
                                               "%s: %d,%d,%d,%d,%d,%d,%d,%d",
                                               g_stParseContext[ucIndex].pstCmdElement->pszCmdName, /* ^CLCC:  */
                                               pstCallInfos->astCallInfos[ucTmp].callId,            /* <id1>, */
                                               pstCallInfos->astCallInfos[ucTmp].enCallDir,         /* <dir>, */
                                               pstCallInfos->astCallInfos[ucTmp].enCallState,       /* <stat>, */
                                               enClccMode,                                          /* <mode>, */
                                               pstCallInfos->astCallInfos[ucTmp].enMptyState,       /* <mpty>, */
                                               enVoiceDomain,                                       /* <voice_domain> */
                                               pstCallInfos->astCallInfos[ucTmp].enCallType,        /* <call_type> */
                                               pstCallInfos->astCallInfos[ucTmp].ucEConferenceFlag  /* <isEConference> */
                                               );

            if (MN_CALL_DIR_MO == pstCallInfos->astCallInfos[ucTmp].enCallDir)
            {
                if (0 != pstCallInfos->astCallInfos[ucTmp].stConnectNumber.ucNumLen)
                {
                    /* <number>, */
                    AT_BcdNumberToAscii(pstCallInfos->astCallInfos[ucTmp].stConnectNumber.aucBcdNum,
                                        pstCallInfos->astCallInfos[ucTmp].stConnectNumber.ucNumLen,
                                        (TAF_CHAR*)aucAsciiNum);

                    /* <type>,<display name>,????<priority> */
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                       ",\"%s\",%d",
                                                       aucAsciiNum,
                                                       (pstCallInfos->astCallInfos[ucTmp].stConnectNumber.enNumType | AT_NUMBER_TYPE_EXT));
                }
                else if (0 != pstCallInfos->astCallInfos[ucTmp].stCalledNumber.ucNumLen)
                {
                    /* <number>, */
                    AT_BcdNumberToAscii(pstCallInfos->astCallInfos[ucTmp].stCalledNumber.aucBcdNum,
                                        pstCallInfos->astCallInfos[ucTmp].stCalledNumber.ucNumLen,
                                        (TAF_CHAR*)aucAsciiNum);

                    /* <type>,<display name>,????<priority> */
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                       ",\"%s\",%d",
                                                       aucAsciiNum,
                                                       (pstCallInfos->astCallInfos[ucTmp].stCalledNumber.enNumType | AT_NUMBER_TYPE_EXT));
                }
                else
                {
                    /* <type>,<display name>,????<priority> */
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                       ",\"\",%d",ucNumberType);
                }
            }
            else
            {
                if (0 != pstCallInfos->astCallInfos[ucTmp].stCallNumber.ucNumLen)
                {
                    /* <number>, */
                    AT_BcdNumberToAscii(pstCallInfos->astCallInfos[ucTmp].stCallNumber.aucBcdNum,
                                        pstCallInfos->astCallInfos[ucTmp].stCallNumber.ucNumLen,
                                        (VOS_CHAR *)aucAsciiNum);

                    /* <type>,<display name>,????<priority> */
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                       ",\"%s\",%d",
                                                       aucAsciiNum,
                                                       (pstCallInfos->astCallInfos[ucTmp].stCallNumber.enNumType | AT_NUMBER_TYPE_EXT));
                }
                else
                {
                    /* <type>,<display name>,????<priority> */
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                       ",\"\",%d",ucNumberType);
                }
            }

            At_ReportClccDisplayName(&(pstCallInfos->astCallInfos[ucTmp].stDisplayName), &usLength);

            At_ReportPeerVideoSupport(&(pstCallInfos->astCallInfos[ucTmp]), &usLength);

            At_ReportClccImsDomain(&(pstCallInfos->astCallInfos[ucTmp]), &usLength);

            At_ReportClccRttPara(&(pstCallInfos->astCallInfos[ucTmp]), &usLength);
        }
    }

    gstAtSendData.usBufLen = usLength;

}

VOS_UINT32 At_ProcQryClccEconfResult(
    TAF_CALL_ECONF_INFO_QRY_CNF_STRU   *pstCallInfos,
    VOS_UINT8                           ucIndex
)
{
    VOS_UINT16                          usLength;
    VOS_UINT8                           ucTmp;
    VOS_CHAR                            aucAsciiNum[MN_CALL_MAX_CALLED_ASCII_NUM_LEN + 1];

    usLength        = 0;
    TAF_MEM_SET_S(aucAsciiNum, sizeof(aucAsciiNum), 0x00, sizeof(aucAsciiNum));

     /* ^CLCCECONF: Maximum-user-count, n_address */
    usLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                      (VOS_CHAR *)pgucAtSndCodeAddr,
                                      (VOS_CHAR *)pgucAtSndCodeAddr,
                                      "%s: %d,%d",
                                      g_stParseContext[ucIndex].pstCmdElement->pszCmdName,  /* ^CLCCECONF:  */
                                      pstCallInfos->ucNumOfMaxCalls,                        /* Maximum-user-count */
                                      pstCallInfos->ucNumOfCalls);

    if (0 != pstCallInfos->ucNumOfCalls)
    {
        /* n_address */
        for (ucTmp = 0; ucTmp < pstCallInfos->ucNumOfCalls; ucTmp++)
        {
            /* ???????????? */
            if (0 != pstCallInfos->astCallInfo[ucTmp].stCallNumber.ucNumLen)
            {
                /* <number>, */
                AT_BcdNumberToAscii(pstCallInfos->astCallInfo[ucTmp].stCallNumber.aucBcdNum,
                                    pstCallInfos->astCallInfo[ucTmp].stCallNumber.ucNumLen,
                                    aucAsciiNum);
            }

            /* entity, Display-text,Status */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                               ",\"%s\",\"%s\",%d",
                                               aucAsciiNum,                                         /* ???????? */
                                               pstCallInfos->astCallInfo[ucTmp].aucDisplaytext,     /* display-text */
                                               pstCallInfos->astCallInfo[ucTmp].enCallState);       /* Call State */

        }
    }

    gstAtSendData.usBufLen = usLength;

    return AT_OK;

}


VOS_VOID At_CsAllCallInfoEvtCnfProc(
    MN_AT_IND_EVT_STRU                 *pstData,
    VOS_UINT16                          usLen
)
{
    VOS_UINT8                           ucNumOfCalls;
    MN_CALL_INFO_QRY_CNF_STRU          *pstCallInfos;
    VOS_UINT8                           ucIndex;
    VOS_UINT8                           ucTmp;
    AT_CPAS_STATUS_ENUM_U8              enCpas;
    VOS_UINT32                          ulRet;

    /* ?????? */
    ucIndex  = 0;

    /* ????????????????IDLE???????????? */
    pstCallInfos = (MN_CALL_INFO_QRY_CNF_STRU *)pstData->aucContent;
    ucNumOfCalls = pstCallInfos->ucNumOfCalls;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstCallInfos->clientId, &ucIndex))
    {
        AT_WARN_LOG("AT_CsAllCallInfoEvtCnfProc:WARNING:AT INDEX NOT FOUND!");
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_CsAllCallInfoEvtCnfProc: AT_BROADCAST_INDEX.");
        return;
    }

    /* ?????????????? */
    if (AT_CMD_CLCC_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        /* CLCC?????????????? */
        At_ProcSetClccResult(ucNumOfCalls, pstCallInfos, ucIndex);

        ulRet = AT_OK;
    }
    else if (AT_CMD_CLCC_QRY == gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        /* ^CLCC??????????????? */
        At_ProcQryClccResult(ucNumOfCalls, pstCallInfos, ucIndex);

        ulRet = AT_OK;
    }
    else if (AT_CMD_CPAS_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        /* CPAS?????????????? */
        if (ucNumOfCalls > AT_CALL_MAX_NUM)
        {
            At_FormatResultData(ucIndex, AT_CME_UNKNOWN);
            return;
        }

        if (0 == ucNumOfCalls)
        {
            enCpas = AT_CPAS_STATUS_READY;
        }
        else
        {
            enCpas = AT_CPAS_STATUS_CALL_IN_PROGRESS;
            for (ucTmp = 0; ucTmp < ucNumOfCalls; ucTmp++)
            {
                if (MN_CALL_S_INCOMING == pstCallInfos->astCallInfos[ucTmp].enCallState)
                {
                    enCpas = AT_CPAS_STATUS_RING;
                    break;
                }
            }
        }

        gstAtSendData.usBufLen  = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (TAF_CHAR *)pgucAtSndCodeAddr,
                                                        (TAF_CHAR*)pgucAtSndCodeAddr,
                                                        "%s: %d",
                                                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                        enCpas);

        ulRet = AT_OK;

    }
    else
    {
        return;
    }

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, ulRet);

    return;
}


VOS_VOID AT_ProcCsCallConnectInd(
    VOS_UINT8                           ucIndex,
    MN_CALL_INFO_STRU                  *pstCallInfo
)
{
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;
    VOS_UINT16                          usLength;
    MN_CALL_TYPE_ENUM_U8                enNewCallType;

    usLength  = 0;
    enModemId = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("AT_ProcCsCallConnectInd: Get modem id fail.");
        return;
    }


    /* CS????????, ????CS???????? */

    AT_UpdateCallErrInfo(ucIndex, TAF_CS_CAUSE_SUCCESS, &(pstCallInfo->stErrInfoText));


    enNewCallType = MN_CALL_TYPE_VOICE;
    At_ChangeEcallTypeToCallType(pstCallInfo->enCallType, &enNewCallType);

    if (VOS_TRUE == AT_CheckRptCmdStatus(pstCallInfo->aucCurcRptCfg, AT_CMD_RPT_CTRL_BY_CURC, AT_RPT_CMD_CONN))
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                            "%s^CONN:%d,%d%s",
                                            gaucAtCrLf,
                                            pstCallInfo->callId,
                                            enNewCallType,
                                            gaucAtCrLf);
        At_SendResultData(ucIndex,pgucAtSndCodeAddr,usLength);
    }

    return;
}

TAF_VOID At_CsIndProc(
    TAF_UINT8                           ucIndex,
    MN_CALL_EVENT_ENUM_U32              enEvent,
    MN_CALL_INFO_STRU                  *pstCallInfo
)
{
    AT_DCE_MSC_STRU                     stMscStru;
    TAF_UINT16                          usLoop;
    VOS_UINT32                          ulTimerName;
    AT_MODEM_CC_CTX_STRU               *pstCcCtx = VOS_NULL_PTR;


    pstCcCtx = AT_GetModemCcCtxAddrFromClientId(ucIndex);

    switch( enEvent )            /* ???????????? */
    {
        case MN_CALL_EVT_ALL_RELEASED:

            /* ??????????????RELEASED??????????????????????????????FALSE */
            pstCcCtx->ulCurIsExistCallFlag = VOS_FALSE;
            break;
        case MN_CALL_EVT_INCOMING:
            /*????????????????*/
            At_CsIncomingEvtIndProc(ucIndex,enEvent,pstCallInfo);

            /* ????????????????????????????????????TRUE */
            pstCcCtx->ulCurIsExistCallFlag = VOS_TRUE;

            break;

        case MN_CALL_EVT_RELEASED:

            /* ????cause?? */
            AT_UpdateCallErrInfo(ucIndex, pstCallInfo->enCause, &(pstCallInfo->stErrInfoText));

            /* ??????????????????????INCOMING????????????DCD????????????????????DCD?????????? */
            if (AT_EVT_IS_CS_VIDEO_CALL(pstCallInfo->enCallType, pstCallInfo->enVoiceDomain))
            {

                /* ????????????????????????????????????MODEM????,??????????????
                   ???? */
                for(usLoop = 0; usLoop < AT_MAX_CLIENT_NUM; usLoop++)
                {
                    if (AT_MODEM_USER == gastAtClientTab[usLoop].UserType)
                    {
                        ucIndex = (VOS_UINT8)usLoop;
                        break;
                    }
                }

                /* ????????????????????????????MODEM???????????????? */
                if (AT_MAX_CLIENT_NUM == usLoop)
                {
                    return;
                }


                TAF_MEM_SET_S(&stMscStru, sizeof(stMscStru), 0x00, sizeof(stMscStru));
                /* ????DCD???? */
                stMscStru.OP_Dcd = 1;
                stMscStru.ucDcd = 0;
                stMscStru.OP_Dsr = 1;
                stMscStru.ucDsr = 1;
                AT_SetModemStatus(ucIndex,&stMscStru);

                /*EVENT-UE Down DCD*/
                AT_EventReport(WUEPS_PID_AT, NAS_OM_EVENT_DCE_DOWN_DCD,
                                VOS_NULL_PTR, NAS_OM_EVENT_NO_PARA);
                return;
            }

            if (VOS_TRUE == pstCcCtx->stS0TimeInfo.bTimerStart)
            {
                ulTimerName = pstCcCtx->stS0TimeInfo.ulTimerName;

                AT_StopRelTimer(ulTimerName, &(pstCcCtx->stS0TimeInfo.s0Timer));
                pstCcCtx->stS0TimeInfo.bTimerStart = VOS_FALSE;
                pstCcCtx->stS0TimeInfo.ulTimerName = 0;
            }


            AT_ReportCendResult(ucIndex, pstCallInfo);

            break;


        case MN_CALL_EVT_CONNECT:
            AT_ProcCsCallConnectInd(ucIndex, pstCallInfo);
            break;

        case MN_CALL_EVT_SS_NOTIFY:
            AT_CsSsNotifyEvtIndProc(ucIndex,enEvent,pstCallInfo);
            break;

        case MN_CALL_EVT_UUS1_INFO:
            AT_CsUus1InfoEvtIndProc(ucIndex,enEvent,pstCallInfo);
            break;

        default:
            AT_LOG1("At_CsIndProc CallEvent ERROR", enEvent);
            break;
    }
}

TAF_VOID At_CsEventProc(MN_AT_IND_EVT_STRU *pstData,TAF_UINT16 usLen)
{
    TAF_UINT8                           ucIndex     = 0;
    MN_CALL_INFO_STRU                  *pstCallInfo = VOS_NULL_PTR;
    MN_CALL_EVENT_ENUM_U32              enEvent;
    TAF_UINT32                          ulEventLen;

    AT_LOG1("At_CsMsgProc pEvent->ClientId",pstData->clientId);
    AT_LOG1("At_CsMsgProc usMsgName",pstData->usMsgName);

    enEvent    = MN_CALL_EVT_BUTT;
    ulEventLen = sizeof(MN_CALL_EVENT_ENUM_U32);
    TAF_MEM_CPY_S(&enEvent,  sizeof(enEvent), pstData->aucContent, ulEventLen);
    pstCallInfo = (MN_CALL_INFO_STRU *)&pstData->aucContent[ulEventLen];

    if(AT_FAILURE == At_ClientIdToUserId(pstData->clientId, &ucIndex))
    {
        AT_WARN_LOG("At_CsEventProc At_ClientIdToUserId FAILURE");
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        if(AT_FAILURE == At_ClientIdToUserId(pstCallInfo->clientId, &ucIndex))
        {
            AT_NORM_LOG1("At_CsMsgProc: Not AT Client Id, clientid:", pstCallInfo->clientId);
            return;
        }

        if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
        {
            At_CsIndProc(ucIndex, enEvent, pstCallInfo);
        }
        else
        {
            AT_LOG1("At_CsMsgProc ucIndex",ucIndex);
            AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);

            At_CsRspProc(ucIndex, enEvent, pstCallInfo);

        }
    }
    else
    {
        AT_LOG1("At_CsMsgProc ucIndex",ucIndex);
        AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);

        At_CsRspProc(ucIndex, enEvent, pstCallInfo);
    }

}


VOS_VOID At_QryAlsCnf(MN_AT_IND_EVT_STRU *pstData)
{
    MN_CALL_QRY_ALS_CNF_STRU           *pstAlsCnf;
    VOS_UINT8                           ucIndex;
    VOS_UINT32                          ulResult;
    VOS_UINT16                          usLen;
    AT_MODEM_SS_CTX_STRU               *pstModemSsCtx = VOS_NULL_PTR;

    pstAlsCnf = (MN_CALL_QRY_ALS_CNF_STRU *)pstData->aucContent;

    if (AT_SUCCESS != At_ClientIdToUserId(pstAlsCnf->ClientId, &ucIndex))
    {
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_QryAlsCnf : AT_BROADCAST_INDEX.");
        return;
    }

    usLen                  = 0;
    ulResult               = AT_ERROR;
    gstAtSendData.usBufLen = 0;

    AT_STOP_TIMER_CMD_READY(ucIndex);

    pstModemSsCtx = AT_GetModemSsCtxAddrFromClientId(ucIndex);

    if (TAF_ERR_NO_ERROR == pstAlsCnf->ulRet )
    {
        usLen += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                        (VOS_CHAR *)pgucAtSndCodeAddr + usLen,
                                        "%s: %d",
                                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                        pstModemSsCtx->ucSalsType);

        usLen += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                        (VOS_CHAR*)pgucAtSndCodeAddr + usLen,
                                        ",%d",
                                        pstAlsCnf->enAlsLine);

        gstAtSendData.usBufLen = usLen;

        ulResult = AT_OK;
    }

    else
    {
        /* ????????ALS??????????call??????????????AT????error??AT???????????????????? */
        ulResult = AT_ERROR;
    }

    At_FormatResultData(ucIndex,ulResult);

}

VOS_VOID At_QryUus1Cnf(MN_AT_IND_EVT_STRU *pstData)
{
    TAF_PH_QRY_UUS1_INFO_CNF_STRU*      pstUus1Cnf;
    VOS_UINT8                           ucIndex;
    VOS_UINT32                          ulResult;
    VOS_UINT32                          i;
    VOS_UINT16                          usLen;
    VOS_UINT32                          ulUus1IFlg;
    VOS_UINT32                          ulUus1UFlg;

    pstUus1Cnf = (TAF_PH_QRY_UUS1_INFO_CNF_STRU *)pstData->aucContent;

    if (AT_SUCCESS != At_ClientIdToUserId(pstUus1Cnf->ClientId, &ucIndex))
    {
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_QryUus1Cnf : AT_BROADCAST_INDEX.");
        return;
    }

    usLen                  = 0;
    ulResult               = AT_ERROR;
    gstAtSendData.usBufLen = 0;

    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????????????????? */
    ulUus1IFlg  = VOS_TRUE;
    ulUus1UFlg  = VOS_TRUE;

    /* UUS1I???????? */
    if (MN_CALL_CUUS1_DISABLE == pstUus1Cnf->aenSetType[0])
    {
        ulUus1IFlg  = VOS_FALSE;
    }

    /* UUS1U???????? */
    if (MN_CALL_CUUS1_DISABLE == pstUus1Cnf->aenSetType[1])
    {
        ulUus1UFlg  = VOS_FALSE;
    }

    if (TAF_ERR_NO_ERROR == pstUus1Cnf->ulRet )
    {
        usLen +=  (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR*)pgucAtSndCodeAddr,
                                         "%s",
                                         gaucAtCrLf);

        usLen +=  (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR*)pgucAtSndCodeAddr + usLen,
                                         "%s:",
                                         g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

        usLen += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                        (VOS_CHAR *)(pgucAtSndCodeAddr + usLen),
                                        "%d,%d",
                                        ulUus1IFlg,
                                        ulUus1UFlg);

        for ( i = 0 ; i < pstUus1Cnf->ulActNum ; i++ )
        {
            usLen += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                            (VOS_CHAR *)pgucAtSndCodeAddr,
                                            (VOS_CHAR *)(pgucAtSndCodeAddr + usLen),
                                            ",%d,",
                                            pstUus1Cnf->stUus1Info[i].enMsgType);

            usLen += (VOS_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,
                                                         (VOS_INT8 *)pgucAtSndCodeAddr,
                                                         (VOS_UINT8 *)pgucAtSndCodeAddr+usLen,
                                                         pstUus1Cnf->stUus1Info[i].aucUuie,
                                                         pstUus1Cnf->stUus1Info[i].aucUuie[MN_CALL_LEN_POS] + MN_CALL_UUIE_HEADER_LEN);

        }

        gstAtSendData.usBufLen = usLen;

        ulResult = AT_OK;
    }

    At_FormatResultData(ucIndex,ulResult);

}



VOS_VOID At_SetAlsCnf(MN_AT_IND_EVT_STRU *pstData)
{
    MN_CALL_SET_ALS_CNF_STRU      *pstUAlsCnf;
    VOS_UINT8                      ucIndex;
    VOS_UINT32                     ulResult;

    pstUAlsCnf = (MN_CALL_SET_ALS_CNF_STRU *)pstData->aucContent;

    if (AT_FAILURE == At_ClientIdToUserId(pstUAlsCnf->ClientId, &ucIndex))
    {
        AT_WARN_LOG("At_SetAlsCnf: AT INDEX NOT FOUND!");
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_SetAlsCnf : AT_BROADCAST_INDEX.");
        return;
    }

    gstAtSendData.usBufLen = 0;

    AT_STOP_TIMER_CMD_READY(ucIndex);

    if( TAF_ERR_NO_ERROR == pstUAlsCnf->ulRet )
    {
        ulResult = AT_OK;
    }
    else
    {
        ulResult = AT_CME_UNKNOWN;
    }

    At_FormatResultData(ucIndex,ulResult);
}

VOS_VOID At_SetUus1Cnf(MN_AT_IND_EVT_STRU *pstData)
{
    TAF_PH_SET_UUS1_INFO_CNF_STRU* pstUus1Cnf;
    VOS_UINT8                      ucIndex;
    VOS_UINT32                     ulResult;

    pstUus1Cnf = (TAF_PH_SET_UUS1_INFO_CNF_STRU *)pstData->aucContent;

    if (AT_FAILURE == At_ClientIdToUserId(pstUus1Cnf->ClientId, &ucIndex))
    {
        AT_WARN_LOG("At_SetUus1Cnf: AT INDEX NOT FOUND!");
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_SetUus1Cnf : AT_BROADCAST_INDEX.");
        return;
    }

    gstAtSendData.usBufLen = 0;

    AT_STOP_TIMER_CMD_READY(ucIndex);

    if (TAF_ERR_NO_ERROR == pstUus1Cnf->ulRet)
    {
        ulResult = AT_OK;
    }
    else
    {
        ulResult = AT_CME_INCORRECT_PARAMETERS;
    }

    At_FormatResultData(ucIndex,ulResult);

}


TAF_VOID At_CsMsgProc(MN_AT_IND_EVT_STRU *pstData,TAF_UINT16 usLen)
{
    MN_CALL_EVENT_ENUM_U32              enEvent;
    TAF_UINT32                          ulEventLen;

    enEvent = MN_CALL_EVT_BUTT;

    ulEventLen = sizeof(MN_CALL_EVENT_ENUM_U32);
    TAF_MEM_CPY_S(&enEvent,  sizeof(enEvent), pstData->aucContent, ulEventLen);

    /* ??????????????????????MN_CALL_INFO_STRU??????????????????????????????
       ????????????????????????????????????????????,*/
    switch( enEvent )
    {
        case MN_CALL_EVT_CLCC_INFO:
            /* ????MN Call??????????:?????????????????????????????? */
            At_CsAllCallInfoEvtCnfProc(pstData,usLen);
            break;
        case MN_CALL_EVT_SET_ALS_CNF:
            At_SetAlsCnf(pstData);
            break;
        case MN_CALL_EVT_SET_UUS1_INFO_CNF:
            At_SetUus1Cnf(pstData);
            break;
        case MN_CALL_EVT_QRY_UUS1_INFO_CNF:
            At_QryUus1Cnf(pstData);
            break;
        case MN_CALL_EVT_QRY_ALS_CNF:
            At_QryAlsCnf(pstData);
            break;

        case MN_CALL_EVT_ECC_NUM_IND:
            At_RcvMnCallEccNumIndProc(pstData,usLen);
            break;

        case MN_CALL_EVT_CLPR_SET_CNF:
            At_SetClprCnf(pstData);
            break;

        case MN_CALL_EVT_SET_CSSN_CNF:
            At_RcvMnCallSetCssnCnf(pstData);
            break;

        case MN_CALL_EVT_CHANNEL_INFO_IND:
            AT_RcvMnCallChannelInfoInd(pstData->aucContent);
            break;

        case MN_CALL_EVT_XLEMA_CNF:
            At_RcvXlemaQryCnf(pstData, usLen);
            break;

        case MN_CALL_EVT_START_DTMF_CNF:
            AT_RcvTafCallStartDtmfCnf(pstData);
            break;

        case MN_CALL_EVT_STOP_DTMF_CNF:
            AT_RcvTafCallStopDtmfCnf(pstData);
            break;

        case MN_CALL_EVT_START_DTMF_RSLT:
        case MN_CALL_EVT_STOP_DTMF_RSLT:
            /* AT??????????????DTMF???????? */
            break;
        case MN_CALL_EVT_CALL_ORIG_CNF:
            At_RcvTafCallOrigCnf(pstData, usLen);
            break;

        case MN_CALL_EVT_SUPS_CMD_CNF:
            At_RcvTafCallSupsCmdCnf(pstData, usLen);
            break;


        case TAF_CALL_EVT_SEND_FLASH_RSLT:
            AT_RcvTafCallSndFlashRslt(pstData);
            break;

        case TAF_CALL_EVT_SEND_BURST_DTMF_CNF:
            AT_RcvTafCallSndBurstDTMFCnf(pstData);
            break;

        case TAF_CALL_EVT_SEND_BURST_DTMF_RSLT:
            AT_RcvTafCallSndBurstDTMFRslt(pstData);
            break;

        case TAF_CALL_EVT_SEND_CONT_DTMF_CNF:
            AT_RcvTafCallSndContinuousDTMFCnf(pstData);
            break;

        case TAF_CALL_EVT_SEND_CONT_DTMF_RSLT:
            AT_RcvTafCallSndContinuousDTMFRslt(pstData);
            break;

        case TAF_CALL_EVT_RCV_CONT_DTMF_IND:
            AT_RcvTafCallRcvContinuousDtmfInd(pstData);
            break;

        case TAF_CALL_EVT_RCV_BURST_DTMF_IND:
            AT_RcvTafCallRcvBurstDtmfInd(pstData);
            break;

        case TAF_CALL_EVT_CALLED_NUM_INFO_IND:
            AT_RcvTafCallCalledNumInfoInd(pstData);
            break;

        case TAF_CALL_EVT_CALLING_NUM_INFO_IND:
            AT_RcvTafCallCallingNumInfoInd(pstData);
            break;

        case TAF_CALL_EVT_DISPLAY_INFO_IND:
            AT_RcvTafCallDispInfoInd(pstData);
            break;

        case TAF_CALL_EVT_EXT_DISPLAY_INFO_IND:
            AT_RcvTafCallExtDispInfoInd(pstData);
            break;

        case TAF_CALL_EVT_CONN_NUM_INFO_IND:
            AT_RcvTafCallConnNumInfoInd(pstData);
            break;

        case TAF_CALL_EVT_REDIR_NUM_INFO_IND:
            AT_RcvTafCallRedirNumInfoInd(pstData);
            break;

        case TAF_CALL_EVT_SIGNAL_INFO_IND:
            AT_RcvTafCallSignalInfoInd(pstData);
            break;

        case TAF_CALL_EVT_LINE_CTRL_INFO_IND:
            AT_RcvTafCallLineCtrlInfoInd(pstData);
            break;

        case TAF_CALL_EVT_CCWAC_INFO_IND:
            AT_RcvTafCallCCWACInd(pstData);
            break;

        case TAF_CALL_EVT_CCLPR_SET_CNF:
            AT_RcvTafCallCclprCnf(pstData);
            break;

        case TAF_CALL_EVT_CHANNEL_QRY_CNF:
            AT_RcvTafSpmQryCSChannelInfoCnf(pstData);
            break;

        case MN_CALL_EVT_CALL_MODIFY_CNF:
            At_RcvTafCallModifyCnf(pstData, usLen);
            break;
        case MN_CALL_EVT_CALL_ANSWER_REMOTE_MODIFY_CNF:
            At_RcvTafCallAnswerRemoteModifyCnf(pstData, usLen);
            break;
        case MN_CALL_EVT_CALL_MODIFY_STATUS_IND:
            At_RcvTafCallModifyStatusInd(pstData, usLen);
            break;

        case TAF_CALL_EVT_CLCCECONF_INFO:
            AT_RcvTafGetEconfInfoCnf(pstData,usLen);
            break;

        case TAF_CALL_EVT_ECONF_DIAL_CNF:
            AT_RcvTafEconfDialCnf(pstData,usLen);
            break;

        case TAF_CALL_EVT_ECONF_NOTIFY_IND:
            AT_RcvTafEconfNotifyInd(pstData,usLen);
            break;

        case TAF_CALL_EVT_CCWAI_SET_CNF:
            AT_RcvTafCallCcwaiSetCnf(pstData);
            break;

        default:
            At_CsEventProc(pstData,usLen);
            AT_CSCallStateReportProc(pstData);
            break;
    }
}


TAF_UINT32 At_CcfcQryReport (
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU  *pEvent,
    TAF_UINT8                           ucIndex
)
{
    TAF_UINT8  ucTmp    = 0;
    TAF_UINT16 usLength = 0;

    /*
    +CCFC: <status>,<class1>[,<number>,<type>[,<subaddr>,<satype>[,<time>]]]
    */
    if(1 == pEvent->OP_SsStatus)
    {
        /* +CCFC: <status>,<class1> */
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                    (TAF_CHAR *)pgucAtSndCodeAddr,
                    (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                    "%s: ",
                    g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                    (TAF_CHAR *)pgucAtSndCodeAddr,
                    (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                    "%d,%d",
                    (TAF_SS_ACTIVE_STATUS_MASK & pEvent->SsStatus),
                    AT_CC_CALSS_TYPE_INVALID);

        return usLength;
    }

    if (1 == pEvent->OP_FwdFeaturelist)
    {
        for(ucTmp = 0; ucTmp < pEvent->FwdFeaturelist.ucCnt; ucTmp++)
        {
            if(0 != ucTmp)
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                            (TAF_CHAR *)pgucAtSndCodeAddr,
                            (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                            "%s",
                            gaucAtCrLf);
            }

            /* +CCFC:  */
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                        (TAF_CHAR *)pgucAtSndCodeAddr,
                        (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                        "%s: ",
                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

            /* <status> */
            if(1 == pEvent->FwdFeaturelist.astFwdFtr[ucTmp].OP_SsStatus)
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                            (TAF_CHAR *)pgucAtSndCodeAddr,
                            (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                            "%d",
                            (TAF_SS_ACTIVE_STATUS_MASK
                            & (pEvent->FwdFeaturelist.astFwdFtr[ucTmp].SsStatus)));
            }
            else
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                            (TAF_CHAR *)pgucAtSndCodeAddr,
                            (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                            "0");
            }

            /* <class1> */
            if(1 == pEvent->FwdFeaturelist.astFwdFtr[ucTmp].OP_BsService)
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                            (TAF_CHAR *)pgucAtSndCodeAddr,
                            (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                            ",%d",
                            At_GetClckClassFromBsCode(&(pEvent->FwdFeaturelist.astFwdFtr[ucTmp].BsService)));
            }
            else
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                            (TAF_CHAR *)pgucAtSndCodeAddr,
                            (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                            ",%d",
                            AT_CC_CALSS_TYPE_INVALID);
            }

            /* <number> */
            if(1 == pEvent->FwdFeaturelist.astFwdFtr[ucTmp].OP_FwdToNum)
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                            (TAF_CHAR *)pgucAtSndCodeAddr,
                            (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                            ",\"%s\"",
                            pEvent->FwdFeaturelist.astFwdFtr[ucTmp].aucFwdToNum);

                /* <type> */
                if(1 == pEvent->FwdFeaturelist.astFwdFtr[ucTmp].OP_NumType)
                {
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                (TAF_CHAR *)pgucAtSndCodeAddr,
                                (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                ",%d",
                                pEvent->FwdFeaturelist.astFwdFtr[ucTmp].NumType);
                }
                else
                {
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                (TAF_CHAR *)pgucAtSndCodeAddr,
                                (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                ",%d",
                                At_GetCodeType(pEvent->FwdFeaturelist.astFwdFtr[ucTmp].aucFwdToNum[0]));
                }

                /* <subaddr> */
                if (1 == pEvent->FwdFeaturelist.astFwdFtr[ucTmp].OP_FwdToSubAddr)
                {
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                (TAF_CHAR *)pgucAtSndCodeAddr,
                                (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                ",\"%s\"",
                                pEvent->FwdFeaturelist.astFwdFtr[ucTmp].aucFwdToSubAddr);

                    /* <satype> */
                    if(1 == pEvent->FwdFeaturelist.astFwdFtr[ucTmp].OP_SubAddrType)
                    {
                        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                    (TAF_CHAR *)pgucAtSndCodeAddr,
                                    (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                    ",%d",
                                    pEvent->FwdFeaturelist.astFwdFtr[ucTmp].SubAddrType);
                    }
                    else
                    {
                        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                    (TAF_CHAR *)pgucAtSndCodeAddr,
                                    (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                    ",%d",
                                    At_GetCodeType(pEvent->FwdFeaturelist.astFwdFtr[ucTmp].aucFwdToSubAddr[0]));
                    }
                }
                else
                {
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                (TAF_CHAR *)pgucAtSndCodeAddr,
                                (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                ",,");
                }

                /* <time> */
                if(1 == pEvent->FwdFeaturelist.astFwdFtr[ucTmp].OP_NoRepCondTime)
                {
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                (TAF_CHAR *)pgucAtSndCodeAddr,
                                (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                ",%d",
                                pEvent->FwdFeaturelist.astFwdFtr[ucTmp].NoRepCondTime);
                }
                else
                {
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                (TAF_CHAR *)pgucAtSndCodeAddr,
                                (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                ",");
                }
            }


        }

    }

    return usLength;
}


VOS_UINT32 At_ProcReportUssdStr_Nontrans(
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU *pstEvent,
    VOS_UINT16                          usPrintOffSet
)
{
    TAF_SS_USSD_STRING_STRU             stUssdStrBuff;
    MN_MSG_CBDCS_CODE_STRU              stDcsInfo;
    VOS_UINT32                          ulDefAphaLen;
    VOS_UINT32                          ulAsciiStrLen;
    VOS_UINT16                          usOutPrintOffSet;
    VOS_UINT32                          ulRet;

    usOutPrintOffSet = 0;

    TAF_MEM_SET_S(&stDcsInfo, sizeof(stDcsInfo), 0x00, sizeof(stDcsInfo));

    /* USSD??CBS??DCS????????????????CBS??DCS??????????????????????????23038 */
    ulRet = MN_MSG_DecodeCbsDcs(pstEvent->DataCodingScheme,
                                pstEvent->UssdString.aucUssdStr,
                                pstEvent->UssdString.usCnt,
                                &stDcsInfo);

    if (MN_ERR_NO_ERROR != ulRet)
    {
        AT_WARN_LOG("At_ProcReportUssdStr_Nontrans:WARNING: Decode Failure");
        return usOutPrintOffSet;
    }

    /* ??????UCS2???? */
    if (MN_MSG_MSG_CODING_UCS2 == stDcsInfo.enMsgCoding)
    {
        usOutPrintOffSet = (TAF_UINT16)At_Unicode2UnicodePrint(AT_CMD_MAX_LEN,
                                                               (TAF_INT8 *)pgucAtSndCodeAddr,
                                                               pgucAtSndCodeAddr + usPrintOffSet,
                                                               pstEvent->UssdString.aucUssdStr,
                                                               pstEvent->UssdString.usCnt);
    }
    else
    {
        /* 7Bit????????????????????????Ascii???? */
        if (MN_MSG_MSG_CODING_7_BIT == stDcsInfo.enMsgCoding)
        {
            TAF_MEM_SET_S(&stUssdStrBuff,
                          sizeof(TAF_SS_USSD_STRING_STRU),
                          0,
                          sizeof(TAF_SS_USSD_STRING_STRU));

            ulDefAphaLen = pstEvent->UssdString.usCnt * 8 / 7;

            (VOS_VOID)TAF_STD_UnPack7Bit(pstEvent->UssdString.aucUssdStr,
                                         ulDefAphaLen,
                                         0,
                                         stUssdStrBuff.aucUssdStr);

            if (0x0d == (stUssdStrBuff.aucUssdStr[ulDefAphaLen - 1]))
            {
                ulDefAphaLen--;
            }

            ulAsciiStrLen = 0;

            TAF_STD_ConvertDefAlphaToAscii(stUssdStrBuff.aucUssdStr,
                                           ulDefAphaLen,
                                           stUssdStrBuff.aucUssdStr,
                                           &ulAsciiStrLen);

            stUssdStrBuff.usCnt = (VOS_UINT16)ulAsciiStrLen;
        }
        /* ????????:8Bit ???????? */
        else
        {
            TAF_MEM_CPY_S(&stUssdStrBuff,
                          sizeof(TAF_SS_USSD_STRING_STRU),
                          &(pstEvent->UssdString),
                          sizeof(TAF_SS_USSD_STRING_STRU));
        }

        /* ?????????????? */
        if(AT_CSCS_UCS2_CODE == gucAtCscsType)       /* +CSCS:UCS2 */
        {
            usOutPrintOffSet = (TAF_UINT16)At_Ascii2UnicodePrint(AT_CMD_MAX_LEN,
                                                               (TAF_INT8 *)pgucAtSndCodeAddr,
                                                               pgucAtSndCodeAddr + usPrintOffSet,
                                                               stUssdStrBuff.aucUssdStr,
                                                               stUssdStrBuff.usCnt);
        }
        else
        {
            TAF_MEM_CPY_S((TAF_CHAR *)pgucAtSndCodeAddr + usPrintOffSet,
                          stUssdStrBuff.usCnt,
                          stUssdStrBuff.aucUssdStr,
                          stUssdStrBuff.usCnt);
            usOutPrintOffSet = stUssdStrBuff.usCnt;
        }
    }

    return usOutPrintOffSet;
}


VOS_UINT16 AT_PrintUssdStr(
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU *pstEvent,
    VOS_UINT8                           ucIndex,
    VOS_UINT16                          usLength
)
{
    AT_MODEM_SS_CTX_STRU               *pstSsCtx = VOS_NULL_PTR;
    VOS_UINT16                          usPrintOffSet;

    /* ????USSD STRING???????? */
    /* ??????USSD ????????????????DCS?? */
    if (0 == pstEvent->OP_DataCodingScheme)
    {
        AT_WARN_LOG("AT_PrintUssdStr: No DCS.");
        return usLength;
    }

    /* ????????????????????????USSDSting?? */
    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        if (0 == pstEvent->OP_UssdString)
        {
            AT_WARN_LOG("AT_PrintUssdStr: BroadCast,No UssdString.");
            return usLength;
        }

    }
    else
    {
        /* ????????????????????????????USSDSting????????????USSData?? */
        /* ??????29??????????????????????????????????USSData?? */
        if ((0 == pstEvent->OP_UssdString)
         && (0 == pstEvent->OP_USSData))
        {
            AT_WARN_LOG("AT_PrintUssdStr: No UssdSting & UssData.");
            return usLength;
        }

    }

    pstSsCtx = AT_GetModemSsCtxAddrFromClientId(ucIndex);

    usPrintOffSet  = usLength;
    usPrintOffSet += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,
                                      (TAF_CHAR *)pgucAtSndCodeAddr + usPrintOffSet,",\"");

    if (pstEvent->UssdString.usCnt > sizeof(pstEvent->UssdString.aucUssdStr))
    {
        AT_WARN_LOG1("AT_PrintUssdStr: Invalid pstEvent->UssdString.usCnt: ", pstEvent->UssdString.usCnt);
        pstEvent->UssdString.usCnt = sizeof(pstEvent->UssdString.aucUssdStr);
    }

    switch(pstSsCtx->usUssdTransMode)
    {
        case AT_USSD_TRAN_MODE:
            usPrintOffSet += (TAF_UINT16)At_HexString2AsciiNumPrint(AT_CMD_MAX_LEN,
                                                                    (TAF_INT8 *)pgucAtSndCodeAddr,
                                                                    pgucAtSndCodeAddr + usPrintOffSet,
                                                                    pstEvent->UssdString.aucUssdStr,
                                                                    pstEvent->UssdString.usCnt);
            break;

        case AT_USSD_NON_TRAN_MODE:
            /* ??????????????????????7 8Bit UssdString */
            usPrintOffSet += (TAF_UINT16)At_ProcReportUssdStr_Nontrans(pstEvent, usPrintOffSet);
            break;

        default:
            break;
    }

    /* <dcs> */
    usPrintOffSet += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usPrintOffSet,
                                       "\",%d",pstEvent->DataCodingScheme);

    return usPrintOffSet;
}


TAF_VOID At_SsIndProc(TAF_UINT8  ucIndex,TAF_SS_CALL_INDEPENDENT_EVENT_STRU  *pstEvent)
{
    TAF_UINT16                          usLength = 0;
    TAF_UINT8                           ucTmp    = 0;
    VOS_UINT8                          *pucSystemAppConfig = VOS_NULL_PTR;

    pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

    switch(pstEvent->SsEvent)             /* ???????? */
    {
        case TAF_SS_EVT_USS_NOTIFY_IND:                     /* ?????????????????????? */
        case TAF_SS_EVT_USS_REQ_IND:                        /* ?????????????????? */
        case TAF_SS_EVT_USS_RELEASE_COMPLETE_IND:           /* ???????????????? */
        case TAF_SS_EVT_PROCESS_USS_REQ_CNF:
            /* <m> */
            if(TAF_SS_EVT_USS_NOTIFY_IND == pstEvent->SsEvent)
            {
                ucTmp = 0;
            }
            else if(TAF_SS_EVT_USS_REQ_IND == pstEvent->SsEvent)
            {
                ucTmp = 1;
            }
            else
            {

                if (SYSTEM_APP_ANDROID == *pucSystemAppConfig)
                {
                    ucTmp = 2;
                }
                else
                {
                    ucTmp = 0;
                }
            }
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,
                                              (TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s+CUSD: ",gaucAtCrLf);
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%d",ucTmp);
            /* <str> */

            usLength  = AT_PrintUssdStr(pstEvent, ucIndex, usLength);

            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr +
                                               usLength,"%s",gaucAtCrLf);
            At_SendResultData(ucIndex,pgucAtSndCodeAddr,usLength);
            return;



        case TAF_SS_EVT_ERROR:
            if (TAF_ERR_USSD_NET_TIMEOUT == pstEvent->ErrorCode)
            {

                usLength = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   "%s+CUSD: %d%s",
                                                   gaucAtCrLf,
                                                   AT_CUSD_M_NETWORK_TIMEOUT,
                                                   gaucAtCrLf);

                At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

                return;
            }

            if (TAF_ERR_USSD_USER_TIMEOUT == pstEvent->ErrorCode)
            {

                usLength = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   "%s+CUSD: %d%s",
                                                   gaucAtCrLf,
                                                   AT_CUSD_M_NETWORK_CANCEL,
                                                   gaucAtCrLf);

                At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

                return;
            }

            break;

        default:
            return;
    }

}



TAF_UINT8 At_GetClckClassFromBsCode(TAF_SS_BASIC_SERVICE_STRU *pstBs)
{
    VOS_UINT32                          ulLoop;
    VOS_UINT32                          ulItemsNum;

    ulItemsNum = sizeof(g_astClckClassServiceExtTbl) / sizeof(AT_CLCK_CLASS_SERVICE_TBL_STRU);

    /* ??????????????????????????????Class */
    for (ulLoop = 0; ulLoop < ulItemsNum; ulLoop++)
    {
        if ( (g_astClckClassServiceExtTbl[ulLoop].enServiceType == pstBs->BsType)
          && (g_astClckClassServiceExtTbl[ulLoop].enServiceCode == pstBs->BsServiceCode) )
        {
            return g_astClckClassServiceExtTbl[ulLoop].enClass;
        }
    }

    return AT_UNKNOWN_CLCK_CLASS;
}


TAF_UINT32 At_SsRspCusdProc(
    TAF_UINT8                           ucIndex,
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU  *pEvent
)
{
    TAF_UINT32                          ulResult;

    AT_STOP_TIMER_CMD_READY(ucIndex);

    if(TAF_SS_EVT_ERROR == pEvent->SsEvent)
    {
        /* ????????????: ????+CUSD???? */
        ulResult          = At_ChgTafErrorCode(ucIndex,pEvent->ErrorCode);       /* ???????? */
    }
    else
    {
        /* ????OK?????????????? */
        ulResult          = AT_OK;
    }

    At_FormatResultData(ucIndex,ulResult);

    return ulResult;
}


TAF_VOID At_SsRspInterrogateCnfClipProc(
    TAF_UINT8                           ucIndex,
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU  *pEvent,
    TAF_UINT32                          *pulResult,
    TAF_UINT16                          *pusLength
)
{
    TAF_UINT8                           ucTmp    = 0;
    AT_MODEM_SS_CTX_STRU               *pstSsCtx = VOS_NULL_PTR;

    pstSsCtx = AT_GetModemSsCtxAddrFromClientId(ucIndex);

    /* +CLIP: <n>,<m> */
    if(1 == pEvent->OP_SsStatus)    /* ???????? */
    {
        ucTmp = (TAF_SS_PROVISIONED_STATUS_MASK & pEvent->SsStatus) ? 1 : 0;
    }
    else    /* ???????????? */
    {
        ucTmp = 2;
    }

    *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (TAF_CHAR *)pgucAtSndCodeAddr,
                                         (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s: %d,%d",
                                         g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                         pstSsCtx->ucClipType,
                                         ucTmp);

    *pulResult = AT_OK;
}


TAF_VOID At_SsRspInterrogateCnfColpProc(
    TAF_UINT8                           ucIndex,
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU  *pEvent,
    TAF_UINT32                          *pulResult,
    TAF_UINT16                          *pusLength
)
{
    TAF_UINT8                           ucTmp    = 0;
    AT_MODEM_SS_CTX_STRU               *pstSsCtx = VOS_NULL_PTR;

    pstSsCtx = AT_GetModemSsCtxAddrFromClientId(ucIndex);

    if(1 == pEvent->OP_SsStatus)    /* ???????? */
    {
        ucTmp = (TAF_SS_ACTIVE_STATUS_MASK & pEvent->SsStatus);
    }
    else    /* ???????????? */
    {
        ucTmp = 2;
    }

    *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (TAF_CHAR *)pgucAtSndCodeAddr,
                                         (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s: %d,%d",
                                         g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                         pstSsCtx->ucColpType,
                                         ucTmp);

    *pulResult = AT_OK;

}


TAF_VOID At_SsRspInterrogateCnfClirProc(
    TAF_UINT8                           ucIndex,
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU  *pEvent,
    TAF_UINT32                          *pulResult,
    TAF_UINT16                          *pusLength
)
{
    TAF_UINT8                           ucTmp    = 0;
    TAF_SS_CLI_RESTRICION_OPTION        ucClirTmp ;
    TAF_UINT8                           ucCliSsStatus;
    AT_MODEM_SS_CTX_STRU               *pstSsCtx = VOS_NULL_PTR;

    pstSsCtx = AT_GetModemSsCtxAddrFromClientId(ucIndex);

    if (1 == pEvent->OP_GenericServiceInfo) /* ???????? */
    {
        ucCliSsStatus = TAF_SS_ACTIVE_STATUS_MASK &pEvent->GenericServiceInfo.SsStatus;
        if (ucCliSsStatus)
        {
            if ( 1 == pEvent->GenericServiceInfo.OP_CliStrictOp)
            {
               ucClirTmp = pEvent->GenericServiceInfo.CliRestrictionOp;
               if (TAF_SS_CLI_PERMANENT == ucClirTmp)
               {
                 ucTmp = 1;
               }
               else if (TAF_SS_CLI_TMP_DEFAULT_RESTRICTED == ucClirTmp)
               {
                 ucTmp = 3;
               }
               else if (TAF_SS_CLI_TMP_DEFAULT_ALLOWED == ucClirTmp)
               {
                 ucTmp = 4;
               }
               else
               {
                 ucTmp = 2;
               }
            }
            else
            {
               ucTmp = 2;
            }
        }
        else
        {
            ucTmp = 0;
        }
    }
    else if (1 == pEvent->OP_SsStatus)
    {
        ucTmp = 0;
    }
    else /* ???????????? */
    {
        ucTmp = 2;
    }

    *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (TAF_CHAR *)pgucAtSndCodeAddr,
                                         (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                         "%s: %d,%d",
                                         g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                         pstSsCtx->ucClirType,
                                         ucTmp);

    *pulResult = AT_OK;

}


TAF_VOID At_SsRspInterrogateCnfClckProc(
    TAF_UINT8                           ucIndex,
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU  *pEvent,
    TAF_UINT32                          *pulResult,
    TAF_UINT16                          *pusLength
)
{
    TAF_UINT8                           ucTmp    = 0;
    TAF_UINT32                          i;
    VOS_UINT32                          ulCustomizeFlag;
    VOS_UINT32                          ulSuccessFlg;

    /* +CLCK: <status>,<class1> */
    if(1 == pEvent->OP_Error)       /* ?????????????????? */
    {
        *pulResult = At_ChgTafErrorCode(ucIndex,pEvent->ErrorCode);       /* ???????? */
        return;
    }

    if(1 == pEvent->OP_SsStatus)    /* ???????? */
    {
        ucTmp = (TAF_SS_ACTIVE_STATUS_MASK & pEvent->SsStatus);
        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                             (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                             "%s: %d,%d",
                                             g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                             ucTmp,
                                             AT_CLCK_PARA_CLASS_ALL);

        /* ????????IE SS-STATUS???????? */
        ulCustomizeFlag = AT_GetSsCustomizePara(AT_SS_CUSTOMIZE_CLCK_QUERY);
        if (VOS_TRUE == ulCustomizeFlag)
        {
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 ",%d",
                                                 pEvent->SsStatus);
        }
    }
    else if(1 == pEvent->OP_BsServGroupList)
    {
        ulSuccessFlg = VOS_FALSE;
        for (i=0; i<pEvent->BsServGroupList.ucCnt; i++)
        {
            /* ??????ucTmp????class????????status???? */
            ucTmp = At_GetClckClassFromBsCode(&pEvent->BsServGroupList.astBsService[i]);
            if (ucTmp != AT_UNKNOWN_CLCK_CLASS)
            {
                ulSuccessFlg = VOS_TRUE;
                *pusLength  += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: %d,%d%s",g_stParseContext[ucIndex].pstCmdElement->pszCmdName, 1, ucTmp, gaucAtCrLf);
            }
        }

        if (VOS_TRUE == ulSuccessFlg)
        {
            *pusLength -= (TAF_UINT16)VOS_StrLen((VOS_CHAR *)gaucAtCrLf);
            TAF_MEM_SET_S((VOS_UINT8*)pgucAtSndCodeAddr + *pusLength,
                           AT_CMD_MAX_LEN - *pusLength,
                           0x0,
                           AT_CMD_MAX_LEN - *pusLength);
        }

        if (VOS_FALSE == ulSuccessFlg)
        {
            AT_WARN_LOG("+CLCK - Unknown class.");
            *pulResult = AT_ERROR;
            return;
        }

    }
    else    /* ???????????? */
    {
        ucTmp = 0;
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: %d",g_stParseContext[ucIndex].pstCmdElement->pszCmdName,ucTmp);
    }

    *pulResult = AT_OK;

}


TAF_VOID At_SsRspInterrogateCnfCcwaProc(
    TAF_UINT8                           ucIndex,
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU  *pEvent,
    TAF_UINT32                          *pulResult,
    TAF_UINT16                          *pusLength
)
{
    TAF_UINT8                           ucTmp    = 0;
    TAF_UINT32                          i;
    VOS_UINT32                          ulCustomizeFlag;
    VOS_UINT32                          ulSuccessFlg;


    /* +CCWA: <status>,<class1> */
    if(1 == pEvent->OP_Error)       /* ?????????????????? */
    {
        *pulResult = At_ChgTafErrorCode(ucIndex,pEvent->ErrorCode);       /* ???????? */
        return;
    }

    if (1 == pEvent->OP_SsStatus)
    {
        /* ?????????? */
        ucTmp = (TAF_SS_ACTIVE_STATUS_MASK & pEvent->SsStatus);
        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                             (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                             "%s: %d,%d",
                                             g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                             ucTmp,
                                             AT_CLCK_PARA_CLASS_ALL);

        /* ????????IE SS-STATUS???????? */
        ulCustomizeFlag = AT_GetSsCustomizePara(AT_SS_CUSTOMIZE_CCWA_QUERY);
        if (VOS_TRUE == ulCustomizeFlag)
        {
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 ",%d",
                                                 pEvent->SsStatus);
        }
    }
    else if(1 == pEvent->OP_BsServGroupList)
    {
        ulSuccessFlg = VOS_FALSE;
        for (i=0; i<pEvent->BsServGroupList.ucCnt; i++)
        {
            /* ??????ucTmp????class????????status???? */
            ucTmp = At_GetClckClassFromBsCode(&pEvent->BsServGroupList.astBsService[i]);
            if (ucTmp != AT_UNKNOWN_CLCK_CLASS)
            {
                ulSuccessFlg = VOS_TRUE;
                *pusLength  += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: %d,%d%s",g_stParseContext[ucIndex].pstCmdElement->pszCmdName, 1, ucTmp,gaucAtCrLf);
            }
        }

        if (VOS_TRUE == ulSuccessFlg)
        {
            *pusLength -= (TAF_UINT16)VOS_StrLen((VOS_CHAR *)gaucAtCrLf);
            TAF_MEM_SET_S((VOS_UINT8*)pgucAtSndCodeAddr + *pusLength,
                           AT_CMD_MAX_LEN - *pusLength,
                           0x0,
                           AT_CMD_MAX_LEN - *pusLength);
        }

        if (VOS_FALSE == ulSuccessFlg)
        {
             AT_WARN_LOG("+CCWA - Unknown class.");
             *pulResult = AT_ERROR;
             return;
        }
    }
    else    /* ???????????? */
    {
        ucTmp = 0;
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: %d",g_stParseContext[ucIndex].pstCmdElement->pszCmdName,ucTmp);
    }

    *pulResult = AT_OK;

}


TAF_VOID At_SsRspInterrogateCcbsCnfProc(
    TAF_UINT8                           ucIndex,
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU  *pEvent,
    TAF_UINT32                          *pulResult,
    TAF_UINT16                          *pusLength
)
{
    VOS_UINT32                          i = 0;

    if (1 == pEvent->OP_GenericServiceInfo)
    {
        if (TAF_SS_PROVISIONED_STATUS_MASK & pEvent->GenericServiceInfo.SsStatus)
        {
            if (1 == pEvent->GenericServiceInfo.OP_CcbsFeatureList)
            {
                *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"Queue of Ccbs requests is: ");
                for (i = 0; i < pEvent->GenericServiceInfo.CcbsFeatureList.ucCnt; i++)
                {
                    if (VOS_TRUE == pEvent->GenericServiceInfo.CcbsFeatureList.astCcBsFeature[i].OP_CcbsIndex)
                    {
                        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s",gaucAtCrLf);
                        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                      "Index:%d",pEvent->GenericServiceInfo.CcbsFeatureList.astCcBsFeature[i].CcbsIndex);
                    }
                }
            }
            else
            {
                *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"Queue of Ccbs is empty");
            }
        }
        else
        {
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"CCBS not provisioned");
        }
    }
    else if (1 == pEvent->OP_SsStatus)
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"CCBS not provisioned");
    }
    else
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"Unknown");
    }
    *pulResult = AT_OK;

}


TAF_VOID At_SsRspInterrogateCnfCmmiProc(
    TAF_UINT8                           ucIndex,
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU  *pEvent,
    TAF_UINT32                          *pulResult,
    TAF_UINT16                          *pusLength
)
{
    if(1 == pEvent->OP_Error)       /* ?????????????????? */
    {
        *pulResult = At_ChgTafErrorCode(ucIndex,pEvent->ErrorCode);       /* ???????? */
        return;
    }

    if (AT_CMD_CMMI_QUERY_CLIP == gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        if ((1 == pEvent->OP_SsStatus) &&
            (TAF_SS_PROVISIONED_STATUS_MASK & pEvent->SsStatus))
        {
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"CLIP provisioned");
        }
        else if (0 == pEvent->OP_SsStatus)
        {
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"Unknown");
        }
        else
        {
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"CLIP not provisioned");
        }

        *pulResult = AT_OK;
    }
    else if (AT_CMD_CMMI_QUERY_CLIR == gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        if (1 == pEvent->OP_GenericServiceInfo)
        {
            if (TAF_SS_PROVISIONED_STATUS_MASK & pEvent->GenericServiceInfo.SsStatus)
            {
                if (1 == pEvent->GenericServiceInfo.OP_CliStrictOp)
                {
                    switch (pEvent->GenericServiceInfo.CliRestrictionOp)
                    {
                    case TAF_SS_CLI_PERMANENT:
                        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"CLIR provisioned in permanent mode");
                        break;

                    case TAF_SS_CLI_TMP_DEFAULT_RESTRICTED:
                        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"CLIR temporary mode presentation restricted");
                        break;

                    case TAF_SS_CLI_TMP_DEFAULT_ALLOWED:
                        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"CLIR temporary mode presentation allowed");
                        break;

                    default:
                        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"Unknown");
                        break;
                    }
                }
                else
                {
                    *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"Unknown");
                }
            }
            else
            {
                *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"CLIR not provisioned");
            }
        }
        else if (1 == pEvent->OP_SsStatus)
        {
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"CLIR not provisioned");
        }
        else
        {
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"Unknown");
        }
        *pulResult = AT_OK;
    }
    else if ( AT_CMD_SS_INTERROGATE_CCBS == gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        At_SsRspInterrogateCcbsCnfProc(ucIndex,pEvent,pulResult,pusLength);
    }
    else
    {
        *pulResult = AT_ERROR;
    }

}


TAF_VOID At_SsRspInterrogateCnfProc(
    TAF_UINT8                           ucIndex,
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU  *pEvent,
    TAF_UINT32                          *pulResult,
    TAF_UINT16                          *pusLength
)
{
   /* TAF_UINT8                           ucTmp    = 0;*/

    switch(g_stParseContext[ucIndex].pstCmdElement->ulCmdIndex)
    {
    case AT_CMD_CLIP:
        At_SsRspInterrogateCnfClipProc(ucIndex, pEvent, pulResult, pusLength);
        break;

    case AT_CMD_COLP:
        At_SsRspInterrogateCnfColpProc(ucIndex, pEvent, pulResult, pusLength);
        break;

    case AT_CMD_CLIR:
        At_SsRspInterrogateCnfClirProc(ucIndex, pEvent, pulResult, pusLength);
        break;

    case AT_CMD_CLCK:
        At_SsRspInterrogateCnfClckProc(ucIndex, pEvent, pulResult, pusLength);
        break;

    case AT_CMD_CCWA:
        At_SsRspInterrogateCnfCcwaProc(ucIndex, pEvent, pulResult, pusLength);
        break;

    case AT_CMD_CCFC:
        /* +CCFC: <status>,<class1>[,<number>,<type>[,<subaddr>,<satype>[,<time>]]] */
        if(1 == pEvent->OP_Error)       /* ?????????????????? */
        {
            *pulResult = At_ChgTafErrorCode(ucIndex,pEvent->ErrorCode);       /* ???????? */
            break;
        }

        *pusLength = (TAF_UINT16)At_CcfcQryReport(pEvent,ucIndex);
        *pulResult = AT_OK;
        break;

    case AT_CMD_CMMI:
        At_SsRspInterrogateCnfCmmiProc(ucIndex, pEvent, pulResult, pusLength);
        break;

    case AT_CMD_CNAP:
        AT_SsRspInterrogateCnfCnapProc(ucIndex, pEvent, pulResult, pusLength);
        break;

    default:
        break;
    }
}



TAF_VOID At_SsRspUssdProc(
    TAF_UINT8                           ucIndex,
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU  *pEvent,
    TAF_UINT16                          *pusLength
)
{
    TAF_UINT8                           ucTmp    = 0;
    VOS_UINT8                          *pucSystemAppConfig = VOS_NULL_PTR;

    pucSystemAppConfig = AT_GetSystemAppConfigAddr();

    /* <m> */
    if(TAF_SS_EVT_USS_NOTIFY_IND == pEvent->SsEvent)
    {
        ucTmp = 0;
    }
    else if(TAF_SS_EVT_USS_REQ_IND == pEvent->SsEvent)
    {
        ucTmp = 1;
    }
    else
    {

        if (SYSTEM_APP_ANDROID == *pucSystemAppConfig)
        {
            ucTmp = 2;
        }
        else if((0 == pEvent->OP_UssdString) && (0 == pEvent->OP_USSData))
        {
            ucTmp = 2;
        }
        else
        {
            ucTmp = 0;
        }

    }


    /* +CUSD: <m>[,<str>,<dcs>] */
    *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"+CUSD: %d",ucTmp);

    /* <str> */
    /* ???????????????????? */
    if (0 == pEvent->OP_Error)
    {
        *pusLength = AT_PrintUssdStr(pEvent, ucIndex, *pusLength);
    }
}


VOS_UINT32 AT_GetSsEventErrorCode(
    VOS_UINT8                           ucIndex,
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU *pEvent)
{
    if (VOS_TRUE == pEvent->OP_SsStatus)
    {
        if ( 0 == (TAF_SS_PROVISIONED_STATUS_MASK & pEvent->SsStatus) )
        {
            /* ?????????????????????????? */
            return AT_CME_SERVICE_NOT_PROVISIONED;
        }
    }

    return At_ChgTafErrorCode(ucIndex, pEvent->ErrorCode);
}


TAF_VOID At_SsRspProc(TAF_UINT8  ucIndex,TAF_SS_CALL_INDEPENDENT_EVENT_STRU  *pEvent)
{
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;

    /* CLIP CCWA CCFC CLCK CUSD CPWD */
    if (AT_CMD_CUSD_REQ == gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        (VOS_VOID)At_SsRspCusdProc(ucIndex, pEvent);
        return;
    }

    if(TAF_SS_EVT_ERROR == pEvent->SsEvent) /* ??????ERROR?????????????????????? */
    {
        if (TAF_ERR_USSD_NET_TIMEOUT == pEvent->ErrorCode)
        {

            usLength = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               "%s+CUSD: %d%s",
                                               gaucAtCrLf,
                                               AT_CUSD_M_NETWORK_TIMEOUT,
                                               gaucAtCrLf);

            At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

            return;
        }

        if (TAF_ERR_USSD_USER_TIMEOUT == pEvent->ErrorCode)
        {

            usLength = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               "%s+CUSD: %d%s",
                                               gaucAtCrLf,
                                               AT_CUSD_M_NETWORK_CANCEL,
                                               gaucAtCrLf);

            At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

            return;
        }

        if (AT_CMD_CURRENT_OPT_BUTT == gastAtClientTab[ucIndex].CmdCurrentOpt )
        {
            return;
        }

        /* ??SS Event??????????AT???????????? */
        ulResult = AT_GetSsEventErrorCode(ucIndex, pEvent);

        AT_STOP_TIMER_CMD_READY(ucIndex);
    }
    else
    {
        switch(pEvent->SsEvent)             /* ???????? */
        {
        case TAF_SS_EVT_INTERROGATESS_CNF:          /* ???????????? */
            At_SsRspInterrogateCnfProc(ucIndex, pEvent, &ulResult, &usLength);
            AT_STOP_TIMER_CMD_READY(ucIndex);
            break;

        case TAF_SS_EVT_ERASESS_CNF:
        case TAF_SS_EVT_REGISTERSS_CNF:
        case TAF_SS_EVT_ACTIVATESS_CNF:
        case TAF_SS_EVT_DEACTIVATESS_CNF:
        case TAF_SS_EVT_REG_PASSWORD_CNF:
        case TAF_SS_EVT_ERASE_CC_ENTRY_CNF:
            if(0 == pEvent->OP_Error)
            {
                ulResult = AT_OK;
            }
            else
            {
                ulResult = At_ChgTafErrorCode(ucIndex,pEvent->ErrorCode);       /* ???????? */
            }
            AT_STOP_TIMER_CMD_READY(ucIndex);
            break;

        case TAF_SS_EVT_USS_NOTIFY_IND:                     /* ?????????????????????? */
        case TAF_SS_EVT_USS_REQ_IND:                        /* ?????????????????? */
        case TAF_SS_EVT_PROCESS_USS_REQ_CNF:                /* ???????????????? */
        case TAF_SS_EVT_USS_RELEASE_COMPLETE_IND:           /* ???????????????? */
            At_SsRspUssdProc(ucIndex, pEvent, &usLength);
            break;

        /* Delete TAF_SS_EVT_GET_PASSWORD_IND???? */
        default:
            return;
        }
    }

    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);
}

TAF_VOID At_SsMsgProc(TAF_UINT8* pData,TAF_UINT16 usLen)
{
    TAF_SS_CALL_INDEPENDENT_EVENT_STRU *pEvent = TAF_NULL_PTR;
    TAF_UINT8 ucIndex = 0;
    /*lint -save -e830 */
    pEvent = (TAF_SS_CALL_INDEPENDENT_EVENT_STRU *)PS_MEM_ALLOC(WUEPS_PID_AT, sizeof(TAF_SS_CALL_INDEPENDENT_EVENT_STRU));
    /*lint -restore */
    if (TAF_NULL_PTR == pEvent)
    {
        AT_WARN_LOG("At_SsMsgProc Mem Alloc FAILURE");
        return;
    }

    if (usLen > sizeof(TAF_SS_CALL_INDEPENDENT_EVENT_STRU))
    {
        AT_WARN_LOG1("At_SsMsgProc: Invalid Para usLen: ", usLen);
        usLen = sizeof(TAF_SS_CALL_INDEPENDENT_EVENT_STRU);
    }

    TAF_MEM_CPY_S(pEvent, sizeof(TAF_SS_CALL_INDEPENDENT_EVENT_STRU), pData, usLen);

    AT_LOG1("At_SsMsgProc pEvent->ClientId",pEvent->ClientId);
    AT_LOG1("At_SsMsgProc pEvent->SsEvent",pEvent->SsEvent);
    AT_LOG1("At_SsMsgProc pEvent->OP_Error",pEvent->OP_Error);
    AT_LOG1("At_SsMsgProc pEvent->ErrorCode",pEvent->ErrorCode);
    AT_LOG1("At_SsMsgProc pEvent->SsCode",pEvent->SsCode);
    AT_LOG1("At_SsMsgProc pEvent->Cause",pEvent->Cause);

    if(AT_FAILURE == At_ClientIdToUserId(pEvent->ClientId, &ucIndex))
    {
        AT_WARN_LOG("At_SsMsgProc At_ClientIdToUserId FAILURE");
        /*lint -save -e830 */
        PS_MEM_FREE(WUEPS_PID_AT, pEvent);
        /*lint -restore */
        return;
    }

    if(AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        At_SsIndProc(ucIndex, pEvent);
    }
    else
    {
        AT_LOG1("At_SsMsgProc ucIndex",ucIndex);
        AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);

        At_SsRspProc(ucIndex,pEvent);
    }

    PS_MEM_FREE(WUEPS_PID_AT, pEvent);

}


TAF_UINT32 At_PhReadCreg(TAF_PH_REG_STATE_STRU  *pPara,TAF_UINT8 *pDst)
{
    TAF_UINT16 usLength = 0;

    if ((TAF_PH_ACCESS_TECH_CDMA_1X == pPara->ucAct)
        ||(TAF_PH_ACCESS_TECH_EVDO == pPara->ucAct)
        )
    {
        /* lac */
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pDst + usLength,",\"FFFF\"");
        /* ci */
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pDst + usLength,",\"FFFFFFFF\"");

        if((VOS_TRUE == g_usReportCregActParaFlg) && (TAF_PH_ACCESS_TECH_BUTT > pPara->ucAct))
        {
            /* act */
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pDst + usLength,",%d",pPara->ucAct);
        }

        return usLength;
    }

    if(pPara->CellId.ucCellNum > 0)
    {
        /* lac */
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pDst + usLength,",\"%X%X%X%X\"",
                0x000f & (pPara->usLac >> 12),
                0x000f & (pPara->usLac >> 8),
                0x000f & (pPara->usLac >> 4),
                0x000f & (pPara->usLac >> 0));

        /* ci */
        if (CREG_CGREG_CI_RPT_FOUR_BYTE == gucCiRptByte)
        {
            /* VDF????: CREG/CGREG??<CI>????4???????????? */
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pDst + usLength,",\"%X%X%X%X%X%X%X%X\"",
                    0x000f & (pPara->CellId.aulCellId[0] >> 28),
                    0x000f & (pPara->CellId.aulCellId[0] >> 24),
                    0x000f & (pPara->CellId.aulCellId[0] >> 20),
                    0x000f & (pPara->CellId.aulCellId[0] >> 16),
                    0x000f & (pPara->CellId.aulCellId[0] >> 12),
                    0x000f & (pPara->CellId.aulCellId[0] >> 8),
                    0x000f & (pPara->CellId.aulCellId[0] >> 4),
                    0x000f & (pPara->CellId.aulCellId[0] >> 0));
        }
        else
        {
            /* <CI>????2???????????? */
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pDst + usLength,",\"%X%X%X%X\"",
                    0x000f & (pPara->CellId.aulCellId[0] >> 12),
                    0x000f & (pPara->CellId.aulCellId[0] >> 8),
                    0x000f & (pPara->CellId.aulCellId[0] >> 4),
                    0x000f & (pPara->CellId.aulCellId[0] >> 0));
        }

        if((VOS_TRUE == g_usReportCregActParaFlg) && (TAF_PH_ACCESS_TECH_BUTT > pPara->ucAct))
        {
            /* rat */
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pDst + usLength,",%d",pPara->ucAct);
        }
    }

    return usLength;
}


VOS_VOID AT_PhSendPinReady( VOS_UINT16 usModemID )
{
    VOS_UINT32                          i;
    VOS_UINT16                          usLength;

    for(i = 0; i < AT_MAX_CLIENT_NUM; i++)
    {
        if (( usModemID     == g_astAtClientCtx[i].stClientConfiguration.enModemId )
         && ( AT_APP_USER   == gastAtClientTab[i].UserType ))
        {
            break;
        }
    }

    /* ??????E5 User,?????????? */
    if ( i >= AT_MAX_CLIENT_NUM )
    {
        return ;
    }

    usLength = 0;
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                     (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                     "%s",gaucAtCrLf);
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                      (VOS_CHAR *)pgucAtSndCodeAddr,
                                      (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                      "^CPINNTY:READY");
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                     (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                     "%s",gaucAtCrLf);

    At_SendResultData((VOS_UINT8)i,pgucAtSndCodeAddr,usLength);
}


VOS_VOID AT_PhSendNeedPuk( VOS_UINT16 usModemID )
{
    VOS_UINT32                          i;
    VOS_UINT16                          usLength;

    for(i = 0; i < AT_MAX_CLIENT_NUM; i++)
    {
        if (( usModemID     == g_astAtClientCtx[i].stClientConfiguration.enModemId )
         && ( AT_APP_USER   == gastAtClientTab[i].UserType) )
        {
            break;
        }
    }

    /* ??????E5 User,?????????? */
    if ( i >= AT_MAX_CLIENT_NUM )
    {
        return ;
    }

    usLength = 0;
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                     (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                     "%s",gaucAtCrLf);
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                      (VOS_CHAR *)pgucAtSndCodeAddr,
                                      (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                      "^CPINNTY:SIM PUK");

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                     (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                     "%s",gaucAtCrLf);

    At_SendResultData((VOS_UINT8)i,pgucAtSndCodeAddr,usLength);
}



VOS_VOID AT_PhSendSimLocked( VOS_VOID )
{
    VOS_UINT16                          usLength;
    VOS_UINT32                          i;

    for(i = 0; i < AT_MAX_CLIENT_NUM; i++)
    {
        if (AT_APP_USER == gastAtClientTab[i].UserType)
        {
            break;
        }
    }

    /* ??????E5 User,?????????? */
    if ( i >= AT_MAX_CLIENT_NUM )
    {
        return ;
    }

    usLength = 0;
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                     (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                     "%s",gaucAtCrLf);
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                      (VOS_CHAR *)pgucAtSndCodeAddr,
                                      (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                      "^CARDLOCKNTY:SIM LOCKED");

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                     (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                     "%s",gaucAtCrLf);

    At_SendResultData((VOS_UINT8)i,pgucAtSndCodeAddr,usLength);
}


VOS_VOID  AT_PhSendRoaming( VOS_UINT8 ucTmpRoamStatus )
{
    VOS_UINT32                          i;
    VOS_UINT16                          usLength;
    VOS_UINT8                           ucRoamStatus;

    ucRoamStatus = ucTmpRoamStatus;

    for ( i=0 ; i<AT_MAX_CLIENT_NUM; i++ )
    {
        if (AT_APP_USER == gastAtClientTab[i].UserType)
        {
            break;
        }
    }

    /* ??????E5 User,?????????? */
    if ( i >= AT_MAX_CLIENT_NUM )
    {
        return ;
    }

    usLength = 0;
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                     (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                     "%s^APROAMRPT:%d%s",
                                     gaucAtCrLf,
                                     ucRoamStatus,
                                     gaucAtCrLf);

    At_SendResultData((VOS_UINT8)i, pgucAtSndCodeAddr, usLength);

}


VOS_VOID AT_GetOnlyGURatOrder(
    TAF_MMA_MULTIMODE_RAT_CFG_STRU     *pstRatOrder
)
{
    TAF_MMA_MULTIMODE_RAT_CFG_STRU      stRatOrder;
    VOS_UINT32                          i;
    VOS_UINT8                           ucIndex;

    ucIndex = 0;
    TAF_MEM_SET_S(&stRatOrder, (VOS_SIZE_T)sizeof(stRatOrder), 0x00, (VOS_SIZE_T)sizeof(stRatOrder));

    TAF_MEM_CPY_S(&stRatOrder, (VOS_SIZE_T)sizeof(stRatOrder), pstRatOrder, (VOS_SIZE_T)sizeof(stRatOrder));

    /* ????GU?????? */
    for (i = 0; i < stRatOrder.ucRatNum; i++)
    {
        if ((TAF_MMA_RAT_WCDMA == stRatOrder.aenRatOrder[i])
         || (TAF_MMA_RAT_GSM   == stRatOrder.aenRatOrder[i]))
        {
            pstRatOrder->aenRatOrder[ucIndex] = stRatOrder.aenRatOrder[i];
            ucIndex++;
        }
    }

    pstRatOrder->ucRatNum             = ucIndex;
    pstRatOrder->aenRatOrder[ucIndex] = TAF_MMA_RAT_BUTT;


    return;
}



VOS_VOID AT_ReportSysCfgQryCmdResult(
    TAF_MMA_SYS_CFG_PARA_STRU          *pstSysCfg,
    VOS_UINT8                           ucIndex
)
{
    AT_SYSCFG_RAT_TYPE_ENUM_UINT8       enAccessMode;
    AT_SYSCFG_RAT_PRIO_ENUM_UINT8       enAcqorder;
    VOS_UINT16                          usLength;

    usLength = 0;

    /* ??????????????????????GU?????????????????? */
    AT_GetOnlyGURatOrder(&pstSysCfg->stMultiModeRatCfg);

    enAcqorder   = pstSysCfg->enUserPrio;

    /* ????????TAF_MMA_RAT_ORDER_STRU??????????mode??acqorder*/

    switch (pstSysCfg->stMultiModeRatCfg.aenRatOrder[0])
    {
        case TAF_MMA_RAT_GSM:
            if (VOS_TRUE == AT_IsSupportWMode(&pstSysCfg->stMultiModeRatCfg))

            {
                enAccessMode = AT_SYSCFG_RAT_AUTO;
            }
            else
            {
                enAccessMode = AT_SYSCFG_RAT_GSM;
            }
            break;
        case TAF_MMA_RAT_WCDMA:
            if (VOS_TRUE == AT_IsSupportGMode(&pstSysCfg->stMultiModeRatCfg))
            {
                enAccessMode = AT_SYSCFG_RAT_AUTO;
            }
            else
            {
                enAccessMode = AT_SYSCFG_RAT_WCDMA;
            }
            break;

        case TAF_MMA_RAT_1X:
            if (VOS_TRUE == AT_IsSupportHrpdMode(&pstSysCfg->stMultiModeRatCfg))
            {
                enAccessMode = AT_SYSCFG_RAT_1X_AND_HRPD;
            }
            else
            {
                enAccessMode = AT_SYSCFG_RAT_1X;
            }
            break;

        case TAF_MMA_RAT_HRPD:
            if (VOS_TRUE == AT_IsSupport1XMode(&pstSysCfg->stMultiModeRatCfg))
            {
                enAccessMode = AT_SYSCFG_RAT_1X_AND_HRPD;
            }
            else
            {
                enAccessMode = AT_SYSCFG_RAT_HRPD;
            }
            break;

        default:
            /* ??????L????????syscfg?????????????????? */
            enAccessMode    = AT_SYSCFG_RAT_AUTO;

            enAcqorder      = AT_SYSCFG_RAT_PRIO_AUTO;
            break;
    }

    /* ??syscfg????????????^SYSCFG:<mode>,<acqorder>,<band>,<roam>,<srvdomain>*/
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s:",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

    if ( 0 == pstSysCfg->stGuBand.ulBandHigh)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%d,%d,%X,%d,%d",
                                           enAccessMode,
                                           enAcqorder,
                                           pstSysCfg->stGuBand.ulBandLow,
                                           pstSysCfg->enRoam,
                                           pstSysCfg->enSrvDomain);
    }
    else
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%d,%d,%X%08X,%d,%d",
                                           enAccessMode,
                                           enAcqorder,
                                           pstSysCfg->stGuBand.ulBandHigh,
                                           pstSysCfg->stGuBand.ulBandLow,
                                           pstSysCfg->enRoam,
                                           pstSysCfg->enSrvDomain);
    }
    gstAtSendData.usBufLen = usLength;

    return;
}


LOCAL VOS_VOID AT_ConvertSysCfgStrToAutoModeStr(
    VOS_UINT8                          *pucAcqOrderBegin,
    VOS_UINT8                          *pucAcqOrder,
    VOS_UINT8                           ucRatNum
)
{
    
    if ((0 == VOS_StrCmp((VOS_CHAR *)pucAcqOrderBegin, "030201"))
     && (TAF_PH_MAX_GUL_RAT_NUM == ucRatNum))
    {
        /* ????????????????3????????????????L->W->G,acqorder????00 */
        pucAcqOrder = pucAcqOrderBegin;
        VOS_StrCpy_s((VOS_CHAR *)pucAcqOrder, TAF_MMA_RAT_BUTT * 2 + 1, "00");
        pucAcqOrder += AT_SYSCFGEX_RAT_MODE_STR_LEN;
        *pucAcqOrder = '\0';
    }

    return;
}



VOS_VOID AT_ConvertSysCfgRatOrderToStr(
    TAF_MMA_MULTIMODE_RAT_CFG_STRU     *pstRatOrder,
    VOS_UINT8                          *pucAcqOrder
)
{
    VOS_UINT8                          i;
    VOS_UINT8                          *pucAcqOrderBegin = VOS_NULL_PTR;
    VOS_UINT32                          ulLength;

    pucAcqOrderBegin = pucAcqOrder;
    ulLength = TAF_MMA_RAT_BUTT * 2 + 1;

    for (i = 0; i < pstRatOrder->ucRatNum; i++)
    {
        if (TAF_MMA_RAT_WCDMA == pstRatOrder->aenRatOrder[i])
        {
             VOS_StrCpy_s((VOS_CHAR *)pucAcqOrder, ulLength, "02");
             pucAcqOrder += AT_SYSCFGEX_RAT_MODE_STR_LEN;
             ulLength -= AT_SYSCFGEX_RAT_MODE_STR_LEN;
        }
        else if (TAF_MMA_RAT_GSM == pstRatOrder->aenRatOrder[i])
        {
             VOS_StrCpy_s((VOS_CHAR *)pucAcqOrder, ulLength, "01");
             pucAcqOrder += AT_SYSCFGEX_RAT_MODE_STR_LEN;
             ulLength -= AT_SYSCFGEX_RAT_MODE_STR_LEN;
        }
        else if (TAF_MMA_RAT_LTE == pstRatOrder->aenRatOrder[i])
        {
             VOS_StrCpy_s((VOS_CHAR *)pucAcqOrder, ulLength, "03");
             pucAcqOrder += AT_SYSCFGEX_RAT_MODE_STR_LEN;
             ulLength -= AT_SYSCFGEX_RAT_MODE_STR_LEN;
        }
        else if (TAF_MMA_RAT_1X == pstRatOrder->aenRatOrder[i])
        {
             VOS_StrCpy_s((VOS_CHAR *)pucAcqOrder, ulLength, "04");
             pucAcqOrder += AT_SYSCFGEX_RAT_MODE_STR_LEN;
             ulLength -= AT_SYSCFGEX_RAT_MODE_STR_LEN;
        }
        else if (TAF_MMA_RAT_HRPD == pstRatOrder->aenRatOrder[i])
        {
             VOS_StrCpy_s((VOS_CHAR *)pucAcqOrder, ulLength, "07");
             pucAcqOrder += AT_SYSCFGEX_RAT_MODE_STR_LEN;
             ulLength -= AT_SYSCFGEX_RAT_MODE_STR_LEN;
        }

        else
        {
        }
    }

    *pucAcqOrder = '\0';

    AT_ConvertSysCfgStrToAutoModeStr(pucAcqOrderBegin, pucAcqOrder, pstRatOrder->ucRatNum);

    return;
}


VOS_INT8 AT_GetValidLteBandIndex(
    TAF_USER_SET_LTE_PREF_BAND_INFO_STRU                   *pstLBand
)
{
    VOS_INT8                            cValidIndex;

    if (VOS_NULL_PTR == pstLBand)
    {
        return 0;
    }

    for (cValidIndex = TAF_MMA_LTE_BAND_MAX_LENGTH - 1; cValidIndex >= 0; cValidIndex--)
    {
        if (0 != pstLBand->aulBandInfo[cValidIndex])
        {
            return cValidIndex;
        }
    }

    return 0;
}



VOS_VOID AT_ReportSysCfgExQryCmdResult(
    TAF_MMA_SYS_CFG_PARA_STRU          *pstSysCfg,
    VOS_UINT8                           ucIndex
)
{
    VOS_UINT8                           aucAcqorder[TAF_MMA_RAT_BUTT * 2 + 1];
    VOS_UINT8                          *pucAcqOrder = VOS_NULL_PTR;
    VOS_INT8                            cIndex;
    VOS_UINT16                          usLength;

    usLength = 0;
    pucAcqOrder = aucAcqorder;

    /* ????????TAF_MMA_MULTIMODE_RAT_CFG_STRU??????????acqorder??????*/
    AT_ConvertSysCfgRatOrderToStr(&pstSysCfg->stMultiModeRatCfg, pucAcqOrder);


    /* ??syscfgex????????????^SYSCFGEX: <acqorder>,<band>,<roam>,<srvdomain>,<lteband> */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s:",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

    if (0 == pstSysCfg->stGuBand.ulBandHigh)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "\"%s\",%X,%d,%d",
                                           pucAcqOrder,
                                           pstSysCfg->stGuBand.ulBandLow,
                                           pstSysCfg->enRoam,
                                           pstSysCfg->enSrvDomain);
    }
    else
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "\"%s\",%X%08X,%d,%d",
                                           pucAcqOrder,
                                           pstSysCfg->stGuBand.ulBandHigh,
                                           pstSysCfg->stGuBand.ulBandLow,
                                           pstSysCfg->enRoam,
                                           pstSysCfg->enSrvDomain);
    }
    cIndex = AT_GetValidLteBandIndex(&(pstSysCfg->stLBand));

    if (0 == cIndex)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           ",%X",
                                           pstSysCfg->stLBand.aulBandInfo[0]);
    }
    else
    {
         usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           ",%X",
                                           pstSysCfg->stLBand.aulBandInfo[cIndex]);

        cIndex--;

         while (cIndex >= 0)
         {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%08X",
                                           pstSysCfg->stLBand.aulBandInfo[cIndex]);

            cIndex--;
         }
    }
    gstAtSendData.usBufLen = usLength;

    return;
}


VOS_UINT32 AT_ConvertSysCfgRatOrderToWs46No(
    TAF_MMA_MULTIMODE_RAT_CFG_STRU     *pstRatOrder,
    VOS_UINT32                         *pulProctolNo
)
{
    VOS_UINT8                           ucGsmSupportFlag;
    VOS_UINT8                           ucWcdmaSupportFlag;
    VOS_UINT8                           ucLteSupportFlag;
    VOS_UINT32                          i;
    AT_WS46_RAT_TRANSFORM_TBL_STRU      astWs46RatTransFormTab[] =
    {
      /*     G,         U,         L,     Ws46No */
        {VOS_TRUE,  VOS_FALSE, VOS_FALSE, 12},
        {VOS_FALSE, VOS_TRUE,  VOS_FALSE, 22},
        {VOS_TRUE,  VOS_TRUE,  VOS_TRUE,  25},
        {VOS_FALSE, VOS_FALSE, VOS_TRUE,  28},
        {VOS_TRUE,  VOS_TRUE,  VOS_FALSE, 29},
        {VOS_TRUE,  VOS_FALSE, VOS_TRUE,  30},
        {VOS_FALSE, VOS_TRUE,  VOS_TRUE,  31},
    };

    ucGsmSupportFlag   = VOS_FALSE;
    ucWcdmaSupportFlag = VOS_FALSE;
    ucLteSupportFlag   = VOS_FALSE;

    for (i = 0; i < (VOS_UINT32)pstRatOrder->ucRatNum; i++)
    {
        if (TAF_MMA_RAT_GSM == pstRatOrder->aenRatOrder[i])
        {
            ucGsmSupportFlag = VOS_TRUE;
        }
        else if (TAF_MMA_RAT_WCDMA == pstRatOrder->aenRatOrder[i])
        {
            ucWcdmaSupportFlag = VOS_TRUE;
        }
        else if (TAF_MMA_RAT_LTE == pstRatOrder->aenRatOrder[i])
        {
            ucLteSupportFlag = VOS_TRUE;
        }
        else
        {
        }
    }

    for (i = 0; i < sizeof(astWs46RatTransFormTab)/sizeof(astWs46RatTransFormTab[0]); i++)
    {
        if ( (ucGsmSupportFlag == astWs46RatTransFormTab[i].ucGsmSupportFlg)
          && (ucWcdmaSupportFlag == astWs46RatTransFormTab[i].ucWcdmaSupportFlg)
          && (ucLteSupportFlag == astWs46RatTransFormTab[i].ucLteSupportFlg) )
        {
            *pulProctolNo = astWs46RatTransFormTab[i].ucWs46No;

            return VOS_TRUE;
        }
    }

    return VOS_FALSE;
}



VOS_UINT32 AT_ReportWs46QryCmdResult(
    TAF_MMA_SYS_CFG_PARA_STRU          *pstSysCfg,
    VOS_UINT8                           ucIndex
)
{
    VOS_UINT32                          ulWs46No;
    VOS_UINT16                          usLength;

    ulWs46No = 0;
    usLength = 0;

    /* ????????TAF_MMA_MULTIMODE_RAT_CFG_STRU??????????<n> */
    if (VOS_FALSE == AT_ConvertSysCfgRatOrderToWs46No(&pstSysCfg->stMultiModeRatCfg, &ulWs46No))
    {
        return AT_ERROR;
    }

    /* ??+WS46????????????+WS46: <n> */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%d",
                                       ulWs46No);

    gstAtSendData.usBufLen = usLength;

    return AT_OK;
}






VOS_VOID AT_ReportCeregResult(
    VOS_UINT8                           ucIndex,
    TAF_MMA_REG_STATUS_IND_STRU        *pstRegInd,
    VOS_UINT16                         *pusLength
)
{
    VOS_UINT32                          ulRst;
    MODEM_ID_ENUM_UINT16                enModemId;
    AT_MODEM_NET_CTX_STRU              *pstNetCtx = VOS_NULL_PTR;

    enModemId = MODEM_ID_0;

    ulRst = AT_GetModemIdFromClient(ucIndex, &enModemId);
    if (VOS_OK != ulRst)
    {
        AT_ERR_LOG1("AT_ReportCeregResult:Get ModemID From ClientID fail,ClientID:", ucIndex);
        return;
    }

    /* ????????????????LTE*/
    if (VOS_TRUE != AT_IsModemSupportRat(enModemId, TAF_MMA_RAT_LTE))
    {
        return;
    }

    pstNetCtx = AT_GetModemNetCtxAddrFromModemId(enModemId);

    if ((AT_CEREG_RESULT_CODE_BREVITE_TYPE == pstNetCtx->ucCeregType)
     && (VOS_TRUE == pstRegInd->stRegStatus.OP_PsRegState))
    {
        /* +CEREG: <stat> */
        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                             (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                             "%s%s%d%s",
                                             gaucAtCrLf,
                                             gastAtStringTab[AT_STRING_CEREG].pucText,
                                             pstRegInd->stRegStatus.ucPsRegState,
                                             gaucAtCrLf);
    }
    else if ((AT_CEREG_RESULT_CODE_ENTIRE_TYPE == pstNetCtx->ucCeregType)
          && (VOS_TRUE == pstRegInd->stRegStatus.OP_PsRegState))

    {

        if ((TAF_PH_REG_REGISTERED_HOME_NETWORK == pstRegInd->stRegStatus.ucPsRegState)
         || (TAF_PH_REG_REGISTERED_ROAM == pstRegInd->stRegStatus.ucPsRegState))
        {
             /* +CEREG: <stat>[,<lac>,<ci>,[rat]] */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 "%s%s%d", gaucAtCrLf,
                                                 gastAtStringTab[AT_STRING_CEREG].pucText,
                                                 pstRegInd->stRegStatus.ucPsRegState);

            /* ????????????????GU????????+CGREG: <stat> */
            if (TAF_PH_INFO_LTE_RAT == pstRegInd->stRegStatus.ucRatType)
            {
                *pusLength += (VOS_UINT16)At_PhReadCreg(&(pstRegInd->stRegStatus),pgucAtSndCodeAddr + *pusLength);
            }

            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 "%s", gaucAtCrLf);
        }
        else
        {
            /* +CEREG: <stat> */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                                 (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                 "%s%s%d%s", gaucAtCrLf,
                                                 gastAtStringTab[AT_STRING_CEREG].pucText,
                                                 pstRegInd->stRegStatus.ucPsRegState, gaucAtCrLf);
        }
    }
    else
    {

    }

    return;

}




VOS_VOID AT_ReportCgregResult(
    VOS_UINT8                           ucIndex,
    TAF_MMA_REG_STATUS_IND_STRU        *pstRegInd,
    VOS_UINT16                         *pusLength
)
{
    AT_MODEM_NET_CTX_STRU              *pstNetCtx = VOS_NULL_PTR;

    pstNetCtx = AT_GetModemNetCtxAddrFromClientId(ucIndex);


    if ((AT_CGREG_RESULT_CODE_BREVITE_TYPE == pstNetCtx->ucCgregType)
     && (VOS_TRUE == pstRegInd->stRegStatus.OP_PsRegState))
    {
        /* +CGREG: <stat> */
        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                             (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                             "%s%s%d%s",
                                             gaucAtCrLf,
                                             gastAtStringTab[AT_STRING_CGREG].pucText,
                                             pstRegInd->stRegStatus.ucPsRegState,
                                             gaucAtCrLf);
    }
    else if ((AT_CGREG_RESULT_CODE_ENTIRE_TYPE == pstNetCtx->ucCgregType)
          && (VOS_TRUE == pstRegInd->stRegStatus.OP_PsRegState))
    {

        if ((TAF_PH_REG_REGISTERED_HOME_NETWORK == pstRegInd->stRegStatus.ucPsRegState)
         || (TAF_PH_REG_REGISTERED_ROAM == pstRegInd->stRegStatus.ucPsRegState))
        {
          /* +CGREG: <stat>[,<lac>,<ci>,[rat]] */
         *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                              (VOS_CHAR *)pgucAtSndCodeAddr,
                                              (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                              "%s%s%d",
                                              gaucAtCrLf,
                                              gastAtStringTab[AT_STRING_CGREG].pucText,
                                              pstRegInd->stRegStatus.ucPsRegState);

         *pusLength += (VOS_UINT16)At_PhReadCreg(&(pstRegInd->stRegStatus),pgucAtSndCodeAddr + *pusLength);

         *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                              (VOS_CHAR *)pgucAtSndCodeAddr,
                                              (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                              "%s",gaucAtCrLf);
        }
        else
        {
            /* +CGREG: <stat> */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                  (VOS_CHAR *)pgucAtSndCodeAddr,
                                                  (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                  "%s%s%d%s",
                                                  gaucAtCrLf,
                                                  gastAtStringTab[AT_STRING_CGREG].pucText,
                                                  pstRegInd->stRegStatus.ucPsRegState,
                                                  gaucAtCrLf);
        }
    }
    else
    {

    }

    return;
}


VOS_VOID AT_ReportCregResult(
    VOS_UINT8                           ucIndex,
    TAF_MMA_REG_STATUS_IND_STRU        *pstRegInd,
    VOS_UINT16                         *pusLength
)
{
    AT_MODEM_NET_CTX_STRU              *pstNetCtx = VOS_NULL_PTR;

    pstNetCtx = AT_GetModemNetCtxAddrFromClientId(ucIndex);


    if ((AT_CREG_RESULT_CODE_BREVITE_TYPE == pstNetCtx->ucCregType)
     && (VOS_TRUE == pstRegInd->stRegStatus.OP_CsRegState))
    {
        /* +CREG: <stat> */
        *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                             (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                             "%s%s%d%s",
                                             gaucAtCrLf,
                                             gastAtStringTab[AT_STRING_CREG].pucText,
                                             pstRegInd->stRegStatus.RegState,
                                             gaucAtCrLf);
    }
    else if ((AT_CREG_RESULT_CODE_ENTIRE_TYPE == pstNetCtx->ucCregType)
          && (VOS_TRUE == pstRegInd->stRegStatus.OP_CsRegState))
    {
        if ((TAF_PH_REG_REGISTERED_HOME_NETWORK == pstRegInd->stRegStatus.RegState)
        || (TAF_PH_REG_REGISTERED_ROAM == pstRegInd->stRegStatus.RegState))
        {
            /* +CREG: <stat>[,<lac>,<ci>,[rat]] */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                  (VOS_CHAR *)pgucAtSndCodeAddr,
                                                  (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                  "%s%s%d",
                                                  gaucAtCrLf,
                                                  gastAtStringTab[AT_STRING_CREG].pucText,
                                                  pstRegInd->stRegStatus.RegState);

            *pusLength += (VOS_UINT16)At_PhReadCreg(&(pstRegInd->stRegStatus),
                                                     (pgucAtSndCodeAddr + *pusLength));

            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                  (VOS_CHAR *)pgucAtSndCodeAddr,
                                                  (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                                  "%s",gaucAtCrLf);
        }
        else
        {
            /* +CREG: <stat> */
            *pusLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                              (VOS_CHAR *)pgucAtSndCodeAddr,
                                              (VOS_CHAR *)pgucAtSndCodeAddr + *pusLength,
                                              "%s%s%d%s",
                                              gaucAtCrLf,
                                              gastAtStringTab[AT_STRING_CREG].pucText,
                                              pstRegInd->stRegStatus.RegState,
                                              gaucAtCrLf);
        }
    }
    else
    {
    }

    return;
}


VOS_VOID AT_ProcRegStatusInfoInd(
    VOS_UINT8                           ucIndex,
    TAF_MMA_REG_STATUS_IND_STRU        *pstRegInfo
)
{
    VOS_UINT16                          usLength;

    usLength  = 0;

    AT_ReportCregResult(ucIndex, pstRegInfo, &usLength);

    AT_ReportCgregResult(ucIndex, pstRegInfo, &usLength);

    /* ????NV????????????????LTE */
    AT_ReportCeregResult(ucIndex, pstRegInfo, &usLength);

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return;
}



VOS_VOID AT_ProcUsimInfoInd(
    VOS_UINT8                           ucIndex,
    TAF_PHONE_EVENT_INFO_STRU          *pstEvent
)
{
    VOS_UINT16                          usLength;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;

    usLength  = 0;
    enModemId = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("AT_ProcUsimInfoInd: Get modem id fail.");
        return;
    }



    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s^SIMST:%d,%d%s",
                                       gaucAtCrLf,
                                       pstEvent->SimStatus,
                                       pstEvent->MeLockStatus,
                                       gaucAtCrLf);

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return;
}


VOS_VOID At_RcvMmaPsInitResultIndProc(
    TAF_UINT8                           ucIndex,
    TAF_PHONE_EVENT_INFO_STRU          *pEvent
)
{
    VOS_UINT16                          usLength;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;

    usLength       = 0;

    enModemId = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("At_RcvMmaPsInitResultIndProc: Get modem id fail.");
        return;
    }

    if (VOS_FALSE == pEvent->OP_PsInitRslt)
    {
        AT_ERR_LOG("At_RcvMmaPsInitResultIndProc: invalid msg.");
        return;
    }

    /* ????modem???????????????????????????? */
    if (TAF_MMA_PS_INIT_SUCC == pEvent->ulPsInitRslt)
    {
        /* ??GPIO????????AP??MODEM????OK */
        DRV_OS_STATUS_SWITCH(VOS_TRUE);

        /* ????PS INIT?????????????????????????? */
        mdrv_set_modem_state(VOS_TRUE);

        DMS_SetModemStatus(enModemId);
    }
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s^PSINIT: %d%s",
                                       gaucAtCrLf,
                                       pEvent->ulPsInitRslt,
                                       gaucAtCrLf);

    At_SendResultData((VOS_UINT8)ucIndex, pgucAtSndCodeAddr, usLength);
}



/*****************************************************************************
 ?? ?? ??  : AT_RcvMmaUsimMatchFilesInd
 ????????  : ????TAF_PH_EVT_USIM_MATCH_FILES_IND????
 ????????  : VOS_UINT8                           ucIndex
             TAF_PHONE_EVENT_INFO_STRU          *pstEvent
 ????????  : ??
 ?? ?? ??  : VOS_VOID
 ????????  :
 ????????  :

*****************************************************************************/
VOS_VOID AT_RcvMmaUsimMatchFilesInd(
    VOS_UINT8                           ucIndex,
    TAF_PHONE_EVENT_INFO_STRU          *pstEvent
)
{
    VOS_UINT16                          usLength;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;

    usLength  = 0;
    enModemId = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);
    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("AT_RcvMmaUsimMatchFilesInd: Get modem id fail.");
        return;
    }

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s^MATCHFILE: %d,%d,%d,",
                                       gaucAtCrLf,
                                       pstEvent->stUsimMatchFile.ucFileType,
                                       pstEvent->stUsimMatchFile.usTotalLen,
                                       pstEvent->stUsimMatchFile.usCurLen);

    usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,
                                                    (TAF_INT8 *)pgucAtSndCodeAddr,
                                                    (TAF_UINT8 *)pgucAtSndCodeAddr + usLength,
                                                     pstEvent->stUsimMatchFile.aucContent,
                                                     pstEvent->stUsimMatchFile.usCurLen);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s",
                                       gaucAtCrLf);

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
    return;
}


VOS_VOID AT_ProcReportSimSqInfo(
    VOS_UINT8                           ucIndex,
    TAF_MMA_SIMSQ_STATE_ENUM_UINT32     enSimsq
)
{
    VOS_UINT8                           ucSimsqEnable;
    VOS_UINT16                          usLength = 0;

    ucSimsqEnable                       = At_GetSimsqEnable();

    usLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s^SIMSQ: %d,%d%s",
                                       gaucAtCrLf,
                                       ucSimsqEnable,
                                       enSimsq,
                                       gaucAtCrLf);

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
    return;
}


VOS_VOID AT_ProcSimsqInd(
    VOS_UINT8                           ucIndex,
    TAF_PHONE_EVENT_INFO_STRU          *pstEvent)
{
    VOS_UINT8                           ucSimsqEnable;
    MODEM_ID_ENUM_UINT16                enModemId;

    /* ????????????????CC???????? */
    if (VOS_OK != AT_GetModemIdFromClient(ucIndex, &enModemId))
    {
        AT_LOG1("AT_ProcSimsqInd AT_GetModemIdFromClient fail", ucIndex);
        return;
    }

    ucSimsqEnable = At_GetSimsqEnable();

    At_SetSimsqStatus(enModemId,pstEvent->SimStatus);

    if (VOS_FALSE == ucSimsqEnable)
    {
        return;
    }

    AT_ProcReportSimSqInfo(ucIndex, At_GetSimsqStatus(enModemId));

    return;
}


TAF_VOID At_PhIndProc(TAF_UINT8 ucIndex, TAF_PHONE_EVENT_INFO_STRU *pEvent)
{
    switch(pEvent->PhoneEvent)
    {

        case TAF_PH_EVT_USIM_INFO_IND:
            AT_ProcUsimInfoInd(ucIndex, pEvent);
            return;

        case TAF_PH_EVT_SIMSQ_IND:
            AT_ProcSimsqInd(ucIndex, pEvent);
            return;

        case TAF_MMA_EVT_PS_INIT_RESULT_IND:
            At_RcvMmaPsInitResultIndProc(ucIndex, pEvent);
            return;


        case TAF_PH_EVT_OPER_MODE_IND:
            AT_NORM_LOG("At_PhIndProc TAF_PH_EVT_OPER_MODE_IND Do nothing");
            return;



        case MN_PH_EVT_SIMLOCKED_IND:
            AT_PhSendSimLocked();
            break;

        case MN_PH_EVT_ROAMING_IND:
            AT_PhSendRoaming( pEvent->ucRoamStatus );
            break;


        case TAF_PH_EVT_NSM_STATUS_IND:
            AT_RcvMmaNsmStatusInd(ucIndex, pEvent);
            break;

        case TAF_PH_EVT_USIM_MATCH_FILES_IND:
            AT_RcvMmaUsimMatchFilesInd(ucIndex , pEvent);
            break;
        default:
            AT_WARN_LOG("At_PhIndProc Other PhoneEvent");
            return;
    }
}



/* AT_PhnEvtPlmnList */


VOS_VOID AT_PhnEvtSetMtPowerDown(
    VOS_UINT8 ucIndex,
    TAF_PHONE_EVENT_INFO_STRU  *pEvent
)
{
    VOS_UINT32       ulResult = AT_ERROR;

    gstAtSendData.usBufLen = 0;

    /*??????????????????????????TAF_MSG_MMA_MT_POWER_DOWN*/
    if (AT_CMD_MMA_MT_POWER_DOWN == gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);

        if (TAF_ERR_NO_ERROR == pEvent->OP_PhoneError)
        {
            ulResult = AT_OK;
        }
    }

    At_FormatResultData(ucIndex,ulResult);
}


VOS_VOID    At_QryCpinRspProc(
    VOS_UINT8       ucIndex,
    TAF_PH_PIN_TYPE ucPinType,
    VOS_UINT16     *pusLength
)
{
    if(TAF_SIM_PIN == ucPinType)
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"SIM PIN");
    }
    else if(TAF_SIM_PUK == ucPinType)
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"SIM PUK");
    }
    else if(TAF_PHNET_PIN == ucPinType)
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"PH-NET PIN");
    }
    else if(TAF_PHNET_PUK == ucPinType)
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"PH-NET PUK");
    }
    else if(TAF_PHNETSUB_PIN == ucPinType)
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"PH-NETSUB PIN");
    }
    else if(TAF_PHNETSUB_PUK == ucPinType)
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"PH-NETSUB PUK");
    }
    else if(TAF_PHSP_PIN == ucPinType)
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"PH-SP PIN");
    }
    else if(TAF_PHSP_PUK == ucPinType)
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"PH-SP PUK");
    }
    else if(TAF_PHCP_PIN == ucPinType)
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"PH-CP PIN");
    }
    else if(TAF_PHCP_PUK == ucPinType)
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"PH-CP PUK");
    }
    else
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"READY");
    }

    return;
}


TAF_UINT32 AT_ProcOperModeWhenLteOn(VOS_UINT8 ucIndex)
{
    return atSetTmodePara(ucIndex, g_stAtDevCmdCtrl.ucCurrentTMode);
}


TAF_UINT32 At_ProcPinQuery(
    TAF_PHONE_EVENT_INFO_STRU          *pEvent,
    TAF_UINT16                         *pusLength,
    TAF_UINT8                           ucIndex
)
{
    TAF_UINT32                         ulResult;

    ulResult = AT_OK;

    /* AT+CLCK */
    if (AT_CMD_CLCK == g_stParseContext[ucIndex].pstCmdElement->ulCmdIndex)
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "%s: ", g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

        if (TAF_PH_USIMM_ENABLE == pEvent->PinCnf.QueryResult.UsimmEnableFlg)
        {
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "1");
        }
        else
        {
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "0");
        }
    }

    /* AT^CPIN */
    else if (AT_CMD_CPIN_2 == g_stParseContext[ucIndex].pstCmdElement->ulCmdIndex)
    {
        if (TAF_SIM_PIN == pEvent->PinCnf.PinType)
        {
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "%s: ", g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "SIM PIN,%d,%d,%d,%d,%d",\
                                            pEvent->PinCnf.RemainTime.ucPin1RemainTime,\
                                            pEvent->PinCnf.RemainTime.ucPuk1RemainTime,\
                                            pEvent->PinCnf.RemainTime.ucPin1RemainTime,\
                                            pEvent->PinCnf.RemainTime.ucPuk2RemainTime,\
                                            pEvent->PinCnf.RemainTime.ucPin2RemainTime);
        }
        else if (TAF_SIM_PUK == pEvent->PinCnf.PinType)
        {

            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "%s: ", g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "SIM PUK,%d,%d,%d,%d,%d",\
                                                pEvent->PinCnf.RemainTime.ucPuk1RemainTime,\
                                                pEvent->PinCnf.RemainTime.ucPuk1RemainTime,\
                                                pEvent->PinCnf.RemainTime.ucPin1RemainTime,\
                                                pEvent->PinCnf.RemainTime.ucPuk2RemainTime,\
                                                pEvent->PinCnf.RemainTime.ucPin2RemainTime);
        }
        else
        {
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "%s: ", g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "READY,,%d,%d,%d,%d",\
                                                pEvent->PinCnf.RemainTime.ucPuk1RemainTime,\
                                                pEvent->PinCnf.RemainTime.ucPin1RemainTime,\
                                                pEvent->PinCnf.RemainTime.ucPuk2RemainTime,\
                                                pEvent->PinCnf.RemainTime.ucPin2RemainTime);

        }
    }
    /*AT+CPIN*/
    else
    {
        At_QryCpinRspProc(ucIndex, pEvent->PinCnf.PinType, pusLength);
    }

    return ulResult;
}

TAF_UINT32 At_ProcPin2Query(
    TAF_PHONE_EVENT_INFO_STRU          *pEvent,
    TAF_UINT16                         *pusLength,
    TAF_UINT8                           ucIndex
)
{
    TAF_UINT32                         ulResult;

    ulResult = AT_FAILURE;

    /* AT^CPIN2 */
    if (AT_CMD_CPIN2 == g_stParseContext[ucIndex].pstCmdElement->ulCmdIndex)
    {

        if (TAF_SIM_PIN2 == pEvent->PinCnf.PinType)
        {
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "%s: ", g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "SIM PIN2,%d,%d,%d,%d,%d",\
                                            pEvent->PinCnf.RemainTime.ucPin2RemainTime,\
                                            pEvent->PinCnf.RemainTime.ucPuk1RemainTime,\
                                            pEvent->PinCnf.RemainTime.ucPin1RemainTime,\
                                            pEvent->PinCnf.RemainTime.ucPuk2RemainTime,\
                                            pEvent->PinCnf.RemainTime.ucPin2RemainTime);
        }
        else if (TAF_SIM_PUK2 == pEvent->PinCnf.PinType)
        {
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "%s: ", g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "SIM PUK2,%d,%d,%d,%d,%d",\
                                                pEvent->PinCnf.RemainTime.ucPuk2RemainTime,\
                                                pEvent->PinCnf.RemainTime.ucPuk1RemainTime,\
                                                pEvent->PinCnf.RemainTime.ucPin1RemainTime,\
                                                pEvent->PinCnf.RemainTime.ucPuk2RemainTime,\
                                                pEvent->PinCnf.RemainTime.ucPin2RemainTime);
        }
        else
        {
            ulResult = AT_CME_SIM_FAILURE;

            return ulResult;
        }
    }
    else
    {
        ulResult = AT_ERROR;

        return ulResult;
    }

    ulResult = AT_OK;

    return ulResult;

}

TAF_UINT32 At_ProcPinResultPinOk(
    TAF_PHONE_EVENT_INFO_STRU          *pEvent,
    TAF_UINT16                         *pusLength,
    VOS_BOOL                           *pbNeedRptPinReady,
    TAF_UINT8                           ucIndex
)
{
    TAF_UINT32                         ulResult;

    ulResult = AT_FAILURE;

    switch (pEvent->PinCnf.CmdType)
    {
    case TAF_PIN_QUERY:

        ulResult = At_ProcPinQuery(pEvent, pusLength, ucIndex);

        break;

    case TAF_PIN2_QUERY:

        ulResult = At_ProcPin2Query(pEvent, pusLength, ucIndex);

        break;

    case TAF_PIN_VERIFY:
    case TAF_PIN_UNBLOCK:
        if (TAF_SIM_NON == pEvent->PinCnf.PinType)
        {
            ulResult = AT_ERROR;
        }
        else
        {
            ulResult = AT_OK;

            *pbNeedRptPinReady = VOS_TRUE;
        }

        break;

    case TAF_PIN_CHANGE:
    case TAF_PIN_DISABLE:
    case TAF_PIN_ENABLE:

        ulResult = AT_OK;

        break;

    default:

        return AT_RRETURN_CODE_BUTT;
    }

    return ulResult;
}

TAF_UINT32 At_ProcPinResultNotPinOk(
    TAF_PHONE_EVENT_INFO_STRU          *pEvent,
    VOS_BOOL                           *pbNeedRptNeedPuk
)
{
    TAF_UINT32                         ulResult;

    ulResult = AT_FAILURE;

    switch(pEvent->PinCnf.OpPinResult)
    {
     case TAF_PH_OP_PIN_NEED_PIN1:
         ulResult = AT_CME_SIM_PIN_REQUIRED;
         break;

     case TAF_PH_OP_PIN_NEED_PUK1:
         *pbNeedRptNeedPuk = VOS_TRUE;
         ulResult = AT_CME_SIM_PUK_REQUIRED;
         break;

     case TAF_PH_OP_PIN_NEED_PIN2:
         ulResult = AT_CME_SIM_PIN2_REQUIRED;
         break;

     case TAF_PH_OP_PIN_NEED_PUK2:
         ulResult = AT_CME_SIM_PUK2_REQUIRED;
         break;

     case TAF_PH_OP_PIN_INCORRECT_PASSWORD:
         ulResult = AT_CME_INCORRECT_PASSWORD;
         break;

     case TAF_PH_OP_PIN_OPERATION_NOT_ALLOW:
         ulResult = AT_CME_OPERATION_NOT_ALLOWED;
         break;

     case TAF_PH_OP_PIN_SIM_FAIL:
         ulResult = AT_CME_SIM_FAILURE;
         break;

     default:
         ulResult = AT_CME_UNKNOWN;
         break;
    }

    return ulResult;
}

TAF_UINT32 At_ProcPhoneEvtOperPinCnf(
    TAF_PHONE_EVENT_INFO_STRU          *pEvent,
    MODEM_ID_ENUM_UINT16                enModemId,
    TAF_UINT8                           ucIndex
)
{
    TAF_UINT16                         usLength;
    TAF_UINT32                         ulResult;
    VOS_BOOL                           bNeedRptPinReady;
    VOS_BOOL                           bNeedRptNeedPuk;

    ulResult = AT_FAILURE;
    usLength = 0;
    bNeedRptPinReady = VOS_FALSE;
    bNeedRptNeedPuk = VOS_FALSE;

    if (1 == pEvent->OP_PhoneError)  /* MT???????? */
    {
        ulResult = At_ChgTafErrorCode(ucIndex,pEvent->PhoneError);       /* ???????? */

        if ((AT_CME_SIM_PUK_REQUIRED == ulResult)
         && (TAF_PIN_VERIFY == pEvent->PinCnf.CmdType))
        {
            bNeedRptNeedPuk = VOS_TRUE;
        }
    }
    else
    {
        if (TAF_PH_OP_PIN_OK == pEvent->PinCnf.OpPinResult)
        {
            ulResult = At_ProcPinResultPinOk(pEvent, &usLength, &bNeedRptPinReady, ucIndex);

            if (AT_RRETURN_CODE_BUTT == ulResult)
            {
                AT_NORM_LOG("At_ProcPhoneEvtOperPinCnf: return AT_RRETURN_CODE_BUTT");

                return AT_RRETURN_CODE_BUTT;
            }
        }
        else
        {
            ulResult = At_ProcPinResultNotPinOk(pEvent, &bNeedRptNeedPuk);
        }
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    gstAtSendData.usBufLen = usLength;

    At_FormatResultData(ucIndex,ulResult);

    if (VOS_TRUE == bNeedRptPinReady)
    {
        AT_PhSendPinReady(enModemId);
    }

    if (VOS_TRUE == bNeedRptNeedPuk)
    {
        AT_PhSendNeedPuk(enModemId);
    }

    return AT_RRETURN_CODE_BUTT;
}

TAF_UINT32 At_ProcPhoneEvtOperModeCnf(
    TAF_PHONE_EVENT_INFO_STRU          *pEvent,
    TAF_UINT16                         *pusLength,
    MODEM_ID_ENUM_UINT16                enModemId,
    TAF_UINT8                           ucIndex
)
{
    TAF_UINT32                          ulResult;
    VOS_UINT8                           ucSptLteFlag;
    VOS_UINT8                           ucSptUtralTDDFlag;

    ulResult = AT_FAILURE;

    if (1 == pEvent->OP_PhoneError)  /* MT???????? */
    {
        ulResult = At_ChgTafErrorCode(ucIndex,pEvent->PhoneError);       /* ???????? */
    }
    else if (TAF_PH_CMD_QUERY == pEvent->OperMode.CmdType)
    {
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ", g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%d", pEvent->OperMode.PhMode);
        ulResult = AT_OK;
    }
    else
    {
        ulResult = AT_OK;
    }

    /* V7R2 ^PSTANDBY???????????????????? */
    if(AT_CMD_PSTANDBY_SET == (AT_LTE_CMD_CURRENT_OPT_ENUM)gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);

        return AT_RRETURN_CODE_BUTT;
    }

    /* ????GU??????????????????????TL???????????? */
    if (ulResult == AT_OK)
    {
        ucSptLteFlag = AT_IsModemSupportRat(enModemId, TAF_MMA_RAT_LTE);
        ucSptUtralTDDFlag = AT_IsModemSupportUtralTDDRat(enModemId);

        if ((VOS_TRUE == ucSptLteFlag)
         || (VOS_TRUE == ucSptUtralTDDFlag))
        {
            if ((AT_CMD_TMODE_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
             || (AT_CMD_SET_TMODE == gastAtClientTab[ucIndex].CmdCurrentOpt))
            {
                AT_ProcOperModeWhenLteOn(ucIndex);

                return AT_RRETURN_CODE_BUTT;
            }
        }
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    return ulResult;
}

TAF_UINT32 At_ProcMePersonalizationOpRsltOk(
    TAF_PHONE_EVENT_INFO_STRU          *pEvent,
    TAF_UINT16                         *pusLength,
    TAF_UINT8                           ucIndex
)
{
    TAF_UINT32                         ulResult;
    TAF_UINT32                         ulTmp;

    ulResult = AT_FAILURE;
    ulTmp = 0;

    switch(pEvent->MePersonalisation.CmdType)
    {
        case TAF_ME_PERSONALISATION_ACTIVE:
        case TAF_ME_PERSONALISATION_DEACTIVE:
        case TAF_ME_PERSONALISATION_SET:
        case TAF_ME_PERSONALISATION_PWD_CHANGE:
        case TAF_ME_PERSONALISATION_VERIFY:
            ulResult = AT_OK;
            break;

        case TAF_ME_PERSONALISATION_QUERY:
            if ( AT_CMD_CARD_LOCK_READ == gastAtClientTab[ucIndex].CmdCurrentOpt )
            {
                *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
                *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%d,",pEvent->MePersonalisation.unReportContent.OperatorLockInfo.OperatorLockStatus);
                *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%d,",pEvent->MePersonalisation.unReportContent.OperatorLockInfo.RemainTimes);
                if( (pEvent->MePersonalisation.unReportContent.OperatorLockInfo.OperatorLen < TAF_PH_ME_LOCK_OPER_LEN_MIN)
                    ||(pEvent->MePersonalisation.unReportContent.OperatorLockInfo.OperatorLen > TAF_PH_ME_LOCK_OPER_LEN_MAX))
                {
                    *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"0");
                }
                else
                {
                    for (ulTmp = 0;ulTmp< pEvent->MePersonalisation.unReportContent.OperatorLockInfo.OperatorLen;ulTmp++)
                    {
                        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%d",pEvent->MePersonalisation.unReportContent.OperatorLockInfo.Operator[ulTmp]);
                    }
                }
                ulResult = AT_OK;
            }
            else
            {
                *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
                if(TAF_ME_PERSONALISATION_ACTIVE_STATUS == pEvent->MePersonalisation.ActiveStatus)
                {
                    *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"1");
                }
                else
                {
                    *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"0");
                }
                ulResult = AT_OK;
            }
            break;

        case TAF_ME_PERSONALISATION_RETRIEVE:
            *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
            for (ulTmp = 0; ulTmp < pEvent->MePersonalisation.unReportContent.SimPersionalisationStr.DataLen; ulTmp++)
            {
                *(pgucAtSndCodeAddr + *pusLength + ulTmp) = pEvent->MePersonalisation.unReportContent.SimPersionalisationStr.aucSimPersonalisationStr[ulTmp] + 0x30;
            }
            *pusLength += (VOS_UINT16)ulTmp;
            break;

        default:
            ulResult = AT_ERROR;
            break;
    }

    return ulResult;
}


TAF_UINT32 At_ProcPhoneEvtMePersonalizationCnf(
    TAF_PHONE_EVENT_INFO_STRU          *pEvent,
    TAF_UINT16                         *pusLength,
    TAF_UINT8                           ucIndex
)
{
    TAF_UINT32                         ulResult;

    ulResult = AT_FAILURE;

    if (TAF_PH_ME_PERSONALISATION_OK != pEvent->MePersonalisation.OpRslt)
    {
        if (TAF_PH_ME_PERSONALISATION_NO_SIM == pEvent->MePersonalisation.OpRslt)
        {
            ulResult = At_ChgTafErrorCode(ucIndex, TAF_ERR_CMD_TYPE_ERROR);
        }
        else if (TAF_PH_ME_PERSONALISATION_OP_NOT_ALLOW == pEvent->MePersonalisation.OpRslt)
        {
            ulResult = AT_CME_OPERATION_NOT_ALLOWED;
        }
        else if (TAF_PH_ME_PERSONALISATION_WRONG_PWD == pEvent->MePersonalisation.OpRslt)
        {
            ulResult = AT_CME_INCORRECT_PASSWORD;
        }
        else
        {
            ulResult = AT_ERROR;
        }
    }
    else
    {
        ulResult = At_ProcMePersonalizationOpRsltOk(pEvent, pusLength, ucIndex);
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    return ulResult;
}

TAF_UINT32 At_ProcPhoneEvtPlmnListRej(
    TAF_PHONE_EVENT_INFO_STRU          *pEvent,
    TAF_UINT8                           ucIndex
)
{
    TAF_UINT32                          ulResult;

    ulResult = AT_FAILURE;

    if (TAF_ERR_NO_RF == pEvent->PhoneError)
    {
        ulResult = AT_CME_NO_RF;
    }
    else
    {
        ulResult = AT_CME_OPERATION_NOT_ALLOWED;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    return ulResult;
}

TAF_UINT32 At_ProcPhoneEvtUsimResponse(
    TAF_PHONE_EVENT_INFO_STRU          *pEvent,
    TAF_UINT16                         *pusLength,
    TAF_UINT8                           ucIndex
)
{
    TAF_UINT32                          ulResult;

    ulResult = AT_OK;

    /* +CSIM:  */
    *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "%s: ", g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

    if (1 == pEvent->OP_UsimAccessData)
    {
        /* <length>, */
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength,"%d,\"", pEvent->UsimAccessData.ucLen * 2);
        /* <command>, */
        *pusLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN, (TAF_INT8 *)pgucAtSndCodeAddr, (TAF_UINT8 *)pgucAtSndCodeAddr + *pusLength, pEvent->UsimAccessData.aucResponse, pEvent->UsimAccessData.ucLen);
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "\"");
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    return ulResult;
}

TAF_UINT32 At_ProcPhoneEvtRestrictedAccessCnf(
    TAF_PHONE_EVENT_INFO_STRU          *pEvent,
    TAF_UINT16                         *pusLength,
    TAF_UINT8                           ucIndex
)
{
    TAF_UINT32                          ulResult;

    ulResult = AT_OK;

    *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "%s: ", g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

    if(1 == pEvent->OP_UsimRestrictAccess)
    {
        /* <sw1, sw2>, */
        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "%d,%d", pEvent->RestrictedAccess.ucSW1, pEvent->RestrictedAccess.ucSW2);

        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, ",\"");

        if(0 != pEvent->RestrictedAccess.ucLen)
        {
            /* <response> */
            *pusLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN, (TAF_INT8 *)pgucAtSndCodeAddr, (TAF_UINT8 *)pgucAtSndCodeAddr + *pusLength, pEvent->RestrictedAccess.aucContent, pEvent->RestrictedAccess.ucLen);
        }

        *pusLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + *pusLength, "\"");
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    return ulResult;
}


TAF_VOID At_PhRspProc(TAF_UINT8 ucIndex,TAF_PHONE_EVENT_INFO_STRU  *pEvent)
{
    TAF_UINT32                          ulResult;
    TAF_UINT32                          ulRst;
    TAF_UINT16                          usLength;
    MODEM_ID_ENUM_UINT16                enModemId;

    enModemId           = MODEM_ID_0;
    ulResult            = AT_FAILURE;
    usLength            = 0;

    ulRst = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRst)
    {
        AT_ERR_LOG1("At_PhRspProc:Get ModemID From ClientID fail,ClientID:", ucIndex);

        return;
    }

    switch (pEvent->PhoneEvent)
    {
    case TAF_PH_EVT_ERR:

        ulResult = At_ChgTafErrorCode(ucIndex, pEvent->PhoneError);       /* ???????? */

        AT_STOP_TIMER_CMD_READY(ucIndex);

        break;

    case TAF_PH_EVT_PLMN_LIST_REJ:

        ulResult = At_ProcPhoneEvtPlmnListRej(pEvent, ucIndex);

        break;

    case TAF_PH_EVT_OP_PIN_CNF:

        ulResult = At_ProcPhoneEvtOperPinCnf(pEvent, enModemId, ucIndex);

        if (AT_RRETURN_CODE_BUTT == ulResult)
        {
            return;
        }

        break;

    case TAF_PH_EVT_OPER_MODE_CNF:

        ulResult = At_ProcPhoneEvtOperModeCnf(pEvent, &usLength, enModemId, ucIndex);

        if (AT_RRETURN_CODE_BUTT == ulResult)
        {
            return;
        }

        break;

    case TAF_PH_EVT_USIM_RESPONSE:

        ulResult = At_ProcPhoneEvtUsimResponse(pEvent, &usLength, ucIndex);

        break;

    case TAF_PH_EVT_RESTRICTED_ACCESS_CNF:

        ulResult = At_ProcPhoneEvtRestrictedAccessCnf(pEvent, &usLength, ucIndex);

        break;

    case TAF_PH_EVT_OP_PINREMAIN_CNF:

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR *)pgucAtSndCodeAddr, (VOS_CHAR *)pgucAtSndCodeAddr + usLength, "%s: ", g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR *)pgucAtSndCodeAddr, (VOS_CHAR *)pgucAtSndCodeAddr + usLength, "%d,%d,%d,%d ", pEvent->PinRemainCnf.ucPIN1Remain, pEvent->PinRemainCnf.ucPUK1Remain, pEvent->PinRemainCnf.ucPIN2Remain, pEvent->PinRemainCnf.ucPUK2Remain);

        AT_STOP_TIMER_CMD_READY(ucIndex);

        ulResult = AT_OK;

        break;

    case TAF_PH_EVT_ME_PERSONALISATION_CNF:

        ulResult = At_ProcPhoneEvtMePersonalizationCnf(pEvent, &usLength, ucIndex);

        break;

    case TAF_PH_EVT_SETUP_SYSTEM_INFO_RSP:

        AT_NORM_LOG("At_PhRspProc EVT SETUP SYSTEM INFO RSP,Do nothing.");

        return;

    case TAF_PH_EVT_PLMN_LIST_ABORT_CNF:

        /* ????????, ??????????????ABORT??????????????ABORT.
           ??AT??ABORT????????????????, ??????????MMA??ABORT_CNF????????ABORT */
        if (AT_CMD_COPS_ABORT_PLMN_LIST != gastAtClientTab[ucIndex].CmdCurrentOpt)
        {
            AT_WARN_LOG("At_PhRspProc  NOT ABORT PLMN LIST. ");

            return;
        }

        ulResult = AT_ABORT;

        AT_STOP_TIMER_CMD_READY(ucIndex);

        break;

    default:

        AT_WARN_LOG("At_PhRspProc Other PhoneEvent");

        return;
    }

    gstAtSendData.usBufLen = usLength;

    At_FormatResultData(ucIndex,ulResult);
}

TAF_VOID At_PhEventProc(TAF_UINT8* pData,TAF_UINT16 usLen)
{
    TAF_PHONE_EVENT_INFO_STRU *pEvent;
    TAF_UINT8 ucIndex = 0;

    pEvent = (TAF_PHONE_EVENT_INFO_STRU *)pData;

    AT_LOG1("At_PhMsgProc pEvent->ClientId",pEvent->ClientId);
    AT_LOG1("At_PhMsgProc PhoneEvent",pEvent->PhoneEvent);
    AT_LOG1("At_PhMsgProc PhoneError",pEvent->PhoneError);

    if(AT_FAILURE == At_ClientIdToUserId(pEvent->ClientId, &ucIndex))
    {
        AT_WARN_LOG("At_PhRspProc At_ClientIdToUserId FAILURE");
        return;
    }

    if(AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        At_PhIndProc(ucIndex, pEvent);
    }
    else
    {
        AT_LOG1("At_PhMsgProc ucIndex",ucIndex);
        AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);

        At_PhRspProc(ucIndex,pEvent);
    }
}

VOS_VOID AT_ReportCsgListSearchCnfResult(
    TAF_MMA_CSG_LIST_CNF_PARA_STRU     *pstCsgList,
    VOS_UINT16                         *pusLength
)
{
    VOS_UINT16                          usLength;
    VOS_UINT8                           ucHomeNodeBLen;
    VOS_UINT8                           ucCsgTypeLen;
    VOS_UINT32                          i;
    VOS_UINT32                          j;

    usLength   = *pusLength;

    for (i = 0; i < (VOS_UINT32)AT_MIN(pstCsgList->ucPlmnWithCsgIdNum, TAF_MMA_MAX_CSG_ID_LIST_NUM); i++)
    {
        /* ???????????????????????????? */
        if ((0 != i)
         || (0 != pstCsgList->ulCurrIndex))
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",");
        }

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"(");

        /* ?????????? */
        if (( '\0' == pstCsgList->astCsgIdListInfo[i].aucOperatorNameLong[0])
         || ( '\0' == pstCsgList->astCsgIdListInfo[i].aucOperatorNameShort[0] ))
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"\"");
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"\"");
        }
        else
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"%s\"",pstCsgList->astCsgIdListInfo[i].aucOperatorNameLong);
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"%s\"",pstCsgList->astCsgIdListInfo[i].aucOperatorNameShort);
        }

        /* ????????????????????????  */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"%X%X%X",
            (0x0f00 & pstCsgList->astCsgIdListInfo[i].stPlmnId.Mcc) >> AT_OCTET_MOVE_EIGHT_BITS,
            (AT_OCTET_HIGH_FOUR_BITS & pstCsgList->astCsgIdListInfo[i].stPlmnId.Mcc) >> AT_OCTET_MOVE_FOUR_BITS,
            (AT_OCTET_LOW_FOUR_BITS & pstCsgList->astCsgIdListInfo[i].stPlmnId.Mcc));

        if (AT_OCTET_LOW_FOUR_BITS != ((0x0f00 & pstCsgList->astCsgIdListInfo[i].stPlmnId.Mnc) >> AT_OCTET_MOVE_EIGHT_BITS))
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%X",
            (0x0f00 & pstCsgList->astCsgIdListInfo[i].stPlmnId.Mnc) >> AT_OCTET_MOVE_EIGHT_BITS);

        }

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%X%X\"",
            (AT_OCTET_HIGH_FOUR_BITS & pstCsgList->astCsgIdListInfo[i].stPlmnId.Mnc) >> AT_OCTET_MOVE_FOUR_BITS,
            (AT_OCTET_LOW_FOUR_BITS & pstCsgList->astCsgIdListInfo[i].stPlmnId.Mnc));

        /* ????CSG ID */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"%X\"", pstCsgList->astCsgIdListInfo[i].ulCsgId);

        /* ????CSG ID TYPE, 1??CSG ID??Allowed CSG List??; 2??CSG ID??Operator CSG List??????????CSG ID??????;
                            3??CSG ID??Operator CSG List????????????CSG ID??????; 4??CSG ID????Allowed CSG List??Operator CSG List??*/
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d,", pstCsgList->astCsgIdListInfo[i].enPlmnWithCsgIdType);

        /* ????home NodeB Name, ucs2??????????????48???? */
        ucHomeNodeBLen = AT_MIN(pstCsgList->astCsgIdListInfo[i].stCsgIdHomeNodeBName.ucHomeNodeBNameLen, TAF_MMA_MAX_HOME_NODEB_NAME_LEN);

        for (j = 0; j < ucHomeNodeBLen; j++)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%02X",
                                               pstCsgList->astCsgIdListInfo[i].stCsgIdHomeNodeBName.aucHomeNodeBName[j]);
        }

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR *)pgucAtSndCodeAddr, (VOS_CHAR *)pgucAtSndCodeAddr + usLength, ",");

        /* ????CSG????????UCS-2 ????????, ????????12????*/
        ucCsgTypeLen = AT_MIN(pstCsgList->astCsgIdListInfo[i].stCsgType.ucCsgTypeLen, TAF_MMA_MAX_CSG_TYPE_LEN);

        for (j = 0; j < ucCsgTypeLen; j++)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%02X",
                                               pstCsgList->astCsgIdListInfo[i].stCsgType.aucCsgType[j]);
        }

        if (TAF_PH_RA_GSM == pstCsgList->astCsgIdListInfo[i].ucRaMode)  /* GSM */
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",0");
        }
        else if (TAF_PH_RA_WCDMA == pstCsgList->astCsgIdListInfo[i].ucRaMode)     /* W*/
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",2");
        }
        else if(TAF_PH_RA_LTE == pstCsgList->astCsgIdListInfo[i].ucRaMode)   /* LTE */
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",7");
        }
        else
        {
        }

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           ",%d",
                                           pstCsgList->astCsgIdListInfo[i].sSignalValue1);
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           ",%d",
                                           pstCsgList->astCsgIdListInfo[i].sSignalValue2);
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,")");
    }

    *pusLength = usLength;
}



VOS_UINT32 AT_RcvMmaCsgListSearchCnfProc(
    VOS_VOID                           *pMsg
)
{
    TAF_MMA_CSG_LIST_SEARCH_CNF_STRU   *pstCsgListCnf = VOS_NULL_PTR;
    TAF_MMA_CSG_LIST_CNF_PARA_STRU     *pstCsgList    = VOS_NULL_PTR;
    VOS_UINT16                          usLength;
    VOS_UINT8                           ucIndex;
    TAF_MMA_PLMN_LIST_PARA_STRU         stCsgListPara;
    AT_RRETURN_CODE_ENUM_UINT32         enResult;

    usLength       = 0;
    pstCsgListCnf = (TAF_MMA_CSG_LIST_SEARCH_CNF_STRU *)pMsg;
    pstCsgList    = &pstCsgListCnf->stCsgListCnfPara;
    TAF_MEM_SET_S(&stCsgListPara, sizeof(stCsgListPara), 0x00, sizeof(stCsgListPara));

    ucIndex = AT_BROADCAST_CLIENT_INDEX_MODEM_0;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstCsgListCnf->usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvMmaCsgListSearchCnfProc : WARNING:AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvMmaCsgListSearchCnfProc : AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* ????????, ????????????CSG??????ABORT???????????????????????? */
    if ( AT_CMD_CSG_LIST_SEARCH != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        AT_WARN_LOG("AT_RcvMmaCsgListSearchCnfProc, csg LIST CNF when Abort Plmn List or timeout. ");
        return VOS_ERR;
    }


    /* ??????????????,????????ERROR */
    if (VOS_TRUE == pstCsgList->ucOpError)
    {
        enResult = (AT_RRETURN_CODE_ENUM_UINT32)At_ChgTafErrorCode(ucIndex, pstCsgList->enPhoneError);

        AT_STOP_TIMER_CMD_READY(ucIndex);
        gstAtSendData.usBufLen = 0;
        At_FormatResultData(ucIndex, enResult);

        return VOS_OK;
    }

    /* ??????????????????????????^CSGIDSRCH: */
    if (0 == pstCsgList->ulCurrIndex)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "%s",
                                           gaucAtCrLf);

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
    }

    AT_ReportCsgListSearchCnfResult(pstCsgList, &usLength);

    At_BufferorSendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
    usLength = 0;

    /* ??????????????plmn????????????????????????C??????Plmn list???????????????????????????????? */
    if (TAF_MMA_MAX_CSG_ID_LIST_NUM == pstCsgList->ucPlmnWithCsgIdNum)
    {
        stCsgListPara.usQryNum    = TAF_MMA_MAX_CSG_ID_LIST_NUM;
        stCsgListPara.usCurrIndex = (VOS_UINT16)(pstCsgList->ulCurrIndex + pstCsgList->ucPlmnWithCsgIdNum);

        if (VOS_TRUE == TAF_MMA_CsgListSearchReq(WUEPS_PID_AT, gastAtClientTab[ucIndex].usClientId, 0, &stCsgListPara))
        {
            /* ???????????????? */
            gastAtClientTab[ucIndex].CmdCurrentOpt = AT_CMD_CSG_LIST_SEARCH;
            return VOS_OK;
        }

        /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
        AT_STOP_TIMER_CMD_READY(ucIndex);
        gstAtSendData.usBufLen = 0;
        At_FormatResultData(ucIndex, AT_ERROR);
        return VOS_ERR;
    }

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\r\n");

    At_BufferorSendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
    usLength = 0;

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex, AT_OK);
    return VOS_OK;
}



VOS_UINT32 AT_RcvMmaCsgListAbortCnf(
    VOS_VOID                           *pMsg
)
{
    TAF_MMA_CSG_LIST_ABORT_CNF_STRU    *pstPlmnListAbortCnf = VOS_NULL_PTR;
    VOS_UINT8                           ucIndex;
    VOS_UINT32                          ulResult;

    pstPlmnListAbortCnf = (TAF_MMA_CSG_LIST_ABORT_CNF_STRU *)pMsg;

    ucIndex = AT_BROADCAST_CLIENT_INDEX_MODEM_0;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstPlmnListAbortCnf->stCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvMmaCsgListAbortCnf : WARNING:AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvMmaCsgListAbortCnf : AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* ????AT???????????????????? */
    /* ????????, ????????CSG??????ABORT??????????????ABORT.
       ??AT??ABORT????????????????, ??????????MMA??ABORT_CNF????????ABORT */
    if (AT_CMD_ABORT_CSG_LIST_SEARCH != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("AT_RcvMmaCsgListAbortCnf : Current Option is not correct.");
        return VOS_ERR;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    ulResult = AT_ABORT;

    gstAtSendData.usBufLen = 0;

    /* ????At_FormatResultData???????????? */
    At_FormatResultData(ucIndex, ulResult);

    return VOS_OK;
}


VOS_UINT32 AT_RcvMmaCsgSpecSearchCnfProc(
    VOS_VOID                           *pstMsg
)
{
    TAF_MMA_CSG_SPEC_SEARCH_CNF_STRU   *pstPlmnSpecialSelCnf = VOS_NULL_PTR;
    VOS_UINT8                           ucIndex;
    VOS_UINT32                          ulResult;

    pstPlmnSpecialSelCnf = (TAF_MMA_CSG_SPEC_SEARCH_CNF_STRU *)pstMsg;

    ucIndex = AT_BROADCAST_CLIENT_INDEX_MODEM_0;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstPlmnSpecialSelCnf->stCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvMmaCsgSpecSearchCnfProc : WARNING:AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvMmaCsgSpecSearchCnfProc : AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* ????AT???????????????????? */
    if (AT_CMD_CSG_SPEC_SEARCH != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("AT_RcvMmaCsgSpecSearchCnfProc : Current Option is not correct.");
        return VOS_ERR;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    if (TAF_ERR_NO_ERROR == pstPlmnSpecialSelCnf->enErrorCause)
    {
        ulResult = AT_OK;
    }
    else
    {
        ulResult = At_ChgTafErrorCode(ucIndex, pstPlmnSpecialSelCnf->enErrorCause);
    }

    gstAtSendData.usBufLen = 0;

    /* ????At_FormatResultData???????????? */
    At_FormatResultData(ucIndex, ulResult);

    return VOS_OK;
}



VOS_UINT32 AT_RcvMmaQryCampCsgIdInfoCnfProc(
    VOS_VOID                           *pstMsg
)
{
    VOS_UINT16                                    usLength = 0;
    TAF_MMA_QRY_CAMP_CSG_ID_INFO_CNF_STRU        *pstQryCnfMsg = VOS_NULL_PTR;
    VOS_UINT8                                     ucIndex;
    //VOS_UINT8                                     aucCsgIdBuff[9];

    pstQryCnfMsg = (TAF_MMA_QRY_CAMP_CSG_ID_INFO_CNF_STRU*)pstMsg;

    ucIndex = AT_BROADCAST_CLIENT_INDEX_MODEM_0;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstQryCnfMsg->stCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvMmaQryCampCsgIdInfoCnfProc : WARNING:AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    /* ?????????????? */
    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvMmaQryCampCsgIdInfoCnfProc : AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* ???????????????? */
    if (AT_CMD_CSG_ID_INFO_QRY != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("AT_RcvMmaQryCampCsgIdInfoCnfProc: WARNING:Not AT_CMD_CSG_ID_INFO_QRY!");
        return VOS_ERR;
    }

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* <CR><LF>^CSGIDSRCH: [<oper>[,<CSG ID>][,<rat>]]<CR><LF>
       <CR>OK<LF>
     */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s: ",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

    /* ????PLMN ID????????????????????CSG ID????????????????????OK */
    if ((TAF_MMA_INVALID_MCC == pstQryCnfMsg->stPlmnId.Mcc)
     || (TAF_MMA_INVALID_MNC == pstQryCnfMsg->stPlmnId.Mnc)
     || (TAF_MMA_RAT_BUTT <= pstQryCnfMsg->ucRatType))
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                          (VOS_CHAR *)pgucAtSndCodeAddr,
                                          (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                          "\"\",\"\",");
        gstAtSendData.usBufLen = usLength;
        At_FormatResultData(ucIndex, AT_OK);
        return VOS_OK;
    }

    /* BCD????MCC??MNC???????????????????????? */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "\"%X%X%X",
                                       (0x0f00 & pstQryCnfMsg->stPlmnId.Mcc) >> 8,
                                       (0x00f0 & pstQryCnfMsg->stPlmnId.Mcc) >> 4,
                                       (0x000f & pstQryCnfMsg->stPlmnId.Mcc));

    if(0x0F != ((0x0f00 & pstQryCnfMsg->stPlmnId.Mnc) >> 8))
    {
        usLength +=(VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                          (VOS_CHAR *)pgucAtSndCodeAddr,
                                          (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                          "%X",
                                          (0x0f00 & pstQryCnfMsg->stPlmnId.Mnc) >> 8);
    }

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%X%X\"",
                                       (0x00f0 & pstQryCnfMsg->stPlmnId.Mnc) >> 4,
                                       (0x000f & pstQryCnfMsg->stPlmnId.Mnc));


    /* ????CSG ID */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       ",\"%X\"",
                                       pstQryCnfMsg->ulCsgId);

    /* <rat> */
    if (TAF_MMA_RAT_LTE == pstQryCnfMsg->ucRatType)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           ",7");
    }
    if (TAF_PH_RA_GSM == pstQryCnfMsg->ucRatType)  /* GSM */
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           ",0");
    }
    else if (TAF_PH_RA_WCDMA == pstQryCnfMsg->ucRatType)     /* W*/
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           ",2");
    }
    else
    {
    }


    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex, AT_OK);
    return VOS_OK;
}


VOS_UINT32 At_QryParaPlmnListProc(
    VOS_VOID                           *pMsg
)
{
    TAF_MMA_PLMN_LIST_CNF_STRU         *pstPlmnListCnf;
    TAF_MMA_PLMN_LIST_CNF_PARA_STRU    *pstPlmnList;
    VOS_UINT16                          usLength;
    VOS_UINT8                           ucTmp;
    VOS_UINT8                           ucIndex;
    TAF_MMA_PLMN_LIST_PARA_STRU         stPlmnListPara;
    AT_RRETURN_CODE_ENUM_UINT32         enResult;

    usLength       = 0;
    pstPlmnListCnf = (TAF_MMA_PLMN_LIST_CNF_STRU *)pMsg;
    pstPlmnList    = &pstPlmnListCnf->stPlmnListCnfPara;

    ucIndex = AT_BROADCAST_CLIENT_INDEX_MODEM_0;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstPlmnListCnf->usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvMmaDetachCnf : WARNING:AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_PhPlmnListProc : AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* ????????, ??????????????????ABORT???????????????????????? */
    if ( AT_CMD_COPS_TEST != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        AT_WARN_LOG("At_PhPlmnListProc, TAF_PH_EVT_PLMN_LIST_CNF when Abort Plmn List or timeout. ");
        return VOS_ERR;
    }


    /* ??????????????,????????ERROR */
    if (1 == pstPlmnList->ucOpError)
    {
        enResult = (AT_RRETURN_CODE_ENUM_UINT32)At_ChgTafErrorCode(ucIndex, pstPlmnList->enPhoneError);

        AT_STOP_TIMER_CMD_READY(ucIndex);
        gstAtSendData.usBufLen = 0;
        At_FormatResultData(ucIndex, enResult);

        return VOS_OK;
    }
    if (0 == pstPlmnList->ulCurrIndex)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               "%s",
                                               gaucAtCrLf);


        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
    }

    for(ucTmp = 0; ucTmp < pstPlmnList->ulPlmnNum; ucTmp++)
    {
        if((0 != ucTmp)
        || (0 != pstPlmnList->ulCurrIndex))/* ???????????????????????????? */
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",");
        }

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"(%d",pstPlmnList->astPlmnInfo[ucTmp].PlmnStatus);

        if (( '\0' == pstPlmnList->astPlmnName[ucTmp].aucOperatorNameLong[0] )
         || ( '\0' == pstPlmnList->astPlmnName[ucTmp].aucOperatorNameShort[0] ))
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"\"");
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"\"");
        }
        else
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"%s\"",pstPlmnList->astPlmnName[ucTmp].aucOperatorNameLong);
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"%s\"",pstPlmnList->astPlmnName[ucTmp].aucOperatorNameShort);
        }

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"%X%X%X",
            (0x0f00 & pstPlmnList->astPlmnName[ucTmp].PlmnId.Mcc) >> 8,
            (0x00f0 & pstPlmnList->astPlmnName[ucTmp].PlmnId.Mcc) >> 4,
            (0x000f & pstPlmnList->astPlmnName[ucTmp].PlmnId.Mcc)
            );

        if(0x0F != ((0x0f00 & pstPlmnList->astPlmnName[ucTmp].PlmnId.Mnc) >> 8))
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%X",
            (0x0f00 & pstPlmnList->astPlmnName[ucTmp].PlmnId.Mnc) >> 8
            );

        }
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%X%X\"",
            (0x00f0 & pstPlmnList->astPlmnName[ucTmp].PlmnId.Mnc) >> 4,
            (0x000f & pstPlmnList->astPlmnName[ucTmp].PlmnId.Mnc)
            );
        if(TAF_PH_RA_GSM == pstPlmnList->astPlmnInfo[ucTmp].RaMode)  /* GSM */
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",0");
        }
        else if(TAF_PH_RA_WCDMA == pstPlmnList->astPlmnInfo[ucTmp].RaMode)     /* CDMA */
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",2");
        }
        else if(TAF_PH_RA_LTE == pstPlmnList->astPlmnInfo[ucTmp].RaMode)   /* LTE */
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",7");
        }
        else
        {

        }

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,")");
    }

    At_BufferorSendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
    usLength = 0;

    /* ??????????????plmn????????????????????????C??????Plmn list???????????????????????????????? */
    if (TAF_MMA_MAX_PLMN_NAME_LIST_NUM == pstPlmnList->ulPlmnNum)
    {
        stPlmnListPara.usQryNum    = TAF_MMA_MAX_PLMN_NAME_LIST_NUM;
        stPlmnListPara.usCurrIndex = (VOS_UINT16)(pstPlmnList->ulCurrIndex + pstPlmnList->ulPlmnNum);

        if (VOS_TRUE == Taf_PhonePlmnList(WUEPS_PID_AT, gastAtClientTab[ucIndex].usClientId, 0, &stPlmnListPara))
        {
            /* ???????????????? */
            gastAtClientTab[ucIndex].CmdCurrentOpt = AT_CMD_COPS_TEST;
            return VOS_OK;
        }

        /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
        AT_STOP_TIMER_CMD_READY(ucIndex);
        gstAtSendData.usBufLen = 0;
        At_FormatResultData(ucIndex, AT_ERROR);
        return VOS_ERR;
    }

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",,(0,1,2,3,4),(0,1,2)\r\n");

    At_BufferorSendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
    usLength = 0;

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex, AT_OK);
    return VOS_OK;
}


TAF_VOID At_PhMsgProc(TAF_UINT8* pData,TAF_UINT16 usLen)
{


    At_PhEventProc(pData,usLen);
}


TAF_UINT32 At_Unicode2UnicodePrint(TAF_UINT32 MaxLength,TAF_INT8 *headaddr,TAF_UINT8 *pucDst, TAF_UINT8 *pucSrc, TAF_UINT16 usSrcLen)
{
    TAF_UINT16 usLen    = 0;
    TAF_UINT16 usChkLen = 0;
    TAF_UINT8  ucHigh1  = 0;
    TAF_UINT8  ucHigh2  = 0;
    TAF_UINT8  ucLow1   = 0;
    TAF_UINT8  ucLow2   = 0;
    TAF_UINT8 *pWrite   = pucDst;
    TAF_UINT8 *pRead    = pucSrc;

    if(((TAF_UINT32)(pucDst - (TAF_UINT8 *)headaddr) + (2 * usSrcLen)) >= MaxLength)
    {
        AT_ERR_LOG("At_Unicode2UnicodePrint too long");
        return 0;
    }

    /* ???????????? */
    while( usChkLen < usSrcLen )
    {
        /* ?????????? */
        ucHigh1 = 0x0F & (*pRead >> 4);
        ucHigh2 = 0x0F & *pRead;

        if(0x09 >= ucHigh1)   /* 0-9 */
        {
            *pWrite++ = ucHigh1 + 0x30;
        }
        else if(0x0A <= ucHigh1)    /* A-F */
        {
            *pWrite++ = ucHigh1 + 0x37;
        }
        else
        {

        }

        if(0x09 >= ucHigh2)   /* 0-9 */
        {
            *pWrite++ = ucHigh2 + 0x30;
        }
        else if(0x0A <= ucHigh2)    /* A-F */
        {
            *pWrite++ = ucHigh2 + 0x37;
        }
        else
        {

        }

        /* ?????????? */
        usChkLen++;
        pRead++;

        /* ?????????? */
        ucLow1 = 0x0F & (*pRead >> 4);
        ucLow2 = 0x0F & *pRead;


        if(0x09 >= ucLow1)   /* 0-9 */
        {
            *pWrite++ = ucLow1 + 0x30;
        }
        else if(0x0A <= ucLow1)    /* A-F */
        {
            *pWrite++ = ucLow1 + 0x37;
        }
        else
        {

        }

        if(0x09 >= ucLow2)   /* 0-9 */
        {
            *pWrite++ = ucLow2 + 0x30;
        }
        else if(0x0A <= ucLow2)    /* A-F */
        {
            *pWrite++ = ucLow2 + 0x37;
        }
        else
        {

        }

        /* ?????????? */
        usChkLen++;
        pRead++;

        usLen += 4;    /* ???????? */
    }

    return usLen;
}

TAF_UINT32 At_HexString2AsciiNumPrint(TAF_UINT32 MaxLength,TAF_INT8 *headaddr,TAF_UINT8 *pucDst, TAF_UINT8 *pucSrc, TAF_UINT16 usSrcLen)
{
    TAF_UINT16 usLen    = 0;
    TAF_UINT16 usChkLen = 0;
    TAF_UINT8  ucHigh1  = 0;
    TAF_UINT8  ucHigh2  = 0;
    TAF_UINT8 *pWrite   = pucDst;
    TAF_UINT8 *pRead    = pucSrc;

    if(((TAF_UINT32)(pucDst - (TAF_UINT8 *)headaddr) + (2 * usSrcLen)) >= MaxLength)
    {
        AT_ERR_LOG("At_Unicode2UnicodePrint too long");
        return 0;
    }

    /* ???????????? */
    while( usChkLen < usSrcLen )
    {
        /* ?????????? */
        ucHigh1 = 0x0F & (*pRead >> 4);
        ucHigh2 = 0x0F & *pRead;

        if(0x09 >= ucHigh1)   /* 0-9 */
        {
            *pWrite++ = ucHigh1 + 0x30;
        }
        else if(0x0A <= ucHigh1)    /* A-F */
        {
            *pWrite++ = ucHigh1 + 0x37;
        }
        else
        {

        }

        if(0x09 >= ucHigh2)   /* 0-9 */
        {
            *pWrite++ = ucHigh2 + 0x30;
        }
        else if(0x0A <= ucHigh2)    /* A-F */
        {
            *pWrite++ = ucHigh2 + 0x37;
        }
        else
        {

        }

        /* ?????????? */
        usChkLen++;
        pRead++;
        usLen += 2;    /* ???????? */
    }

    return usLen;
}



TAF_UINT32 At_Ascii2UnicodePrint(TAF_UINT32 MaxLength,TAF_INT8 *headaddr,TAF_UINT8 *pucDst, TAF_UINT8 *pucSrc, TAF_UINT16 usSrcLen)
{
    TAF_UINT16 usLen = 0;
    TAF_UINT16 usChkLen = 0;
    TAF_UINT8 *pWrite   = pucDst;
    TAF_UINT8 *pRead    = pucSrc;
    TAF_UINT8  ucHigh = 0;
    TAF_UINT8  ucLow = 0;

    if(((TAF_UINT32)(pucDst - (TAF_UINT8 *)headaddr) + (4 * usSrcLen)) >= MaxLength)
    {
        AT_ERR_LOG("At_Ascii2UnicodePrint too long");
        return 0;
    }

    /* ???????????? */
    while( usChkLen++ < usSrcLen )
    {
        *pWrite++ = '0';
        *pWrite++ = '0';
        ucHigh = 0x0F & (*pRead >> 4);
        ucLow = 0x0F & *pRead;

        usLen += 4;    /* ???????? */

        if(0x09 >= ucHigh)   /* 0-9 */
        {
            *pWrite++ = ucHigh + 0x30;
        }
        else if(0x0A <= ucHigh)    /* A-F */
        {
            *pWrite++ = ucHigh + 0x37;
        }
        else
        {

        }

        if(0x09 >= ucLow)   /* 0-9 */
        {
            *pWrite++ = ucLow + 0x30;
        }
        else if(0x0A <= ucLow)    /* A-F */
        {
            *pWrite++ = ucLow + 0x37;
        }
        else
        {

        }

        /* ?????????? */
        pRead++;
    }

    return usLen;
}

TAF_UINT16 At_PrintReportData(
    TAF_UINT32                          MaxLength,
    TAF_INT8                            *headaddr,
    MN_MSG_MSG_CODING_ENUM_U8           enMsgCoding,
    TAF_UINT8                           *pucDst,
    TAF_UINT8                           *pucSrc,
    TAF_UINT16                          usSrcLen
)
{
    TAF_UINT16                          usLength = 0;
    TAF_UINT32                          ulPrintStrLen;
    TAF_UINT32                          ulMaxMemLength;
    VOS_UINT32                          ulRet;
    VOS_UINT8                           aucPrintUserData[MN_MSG_MAX_8_BIT_LEN];


    ulPrintStrLen = 0;


    /* DCS: UCS2 */
    if (MN_MSG_MSG_CODING_UCS2 == enMsgCoding)
    {
        usLength += (TAF_UINT16)At_Unicode2UnicodePrint(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,pucDst + usLength,pucSrc,usSrcLen);
    }
    /* DCS: 8BIT */
    else if (MN_MSG_MSG_CODING_8_BIT == enMsgCoding)                                   /* DATA:8BIT */
    {
        if (AT_CSCS_GSM_7Bit_CODE == gucAtCscsType)
        {
            TAF_MEM_SET_S(aucPrintUserData, sizeof(aucPrintUserData), 0, MN_MSG_MAX_8_BIT_LEN);

            usSrcLen      = TAF_MIN(usSrcLen, MN_MSG_MAX_8_BIT_LEN);
            ulPrintStrLen = 0;
            ulRet = TAF_STD_ConvertAsciiToDefAlpha(pucSrc,
                                                   usSrcLen,
                                                   aucPrintUserData,
                                                   &ulPrintStrLen,
                                                   usSrcLen);
            if (MN_ERR_NO_ERROR != ulRet)
            {
                AT_NORM_LOG("At_PrintReportData : TAF_STD_ConvertAsciiToDefAlpha fail. ");
                return 0;
            }

            usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,
                                                            (TAF_INT8 *)pgucAtSndCodeAddr,
                                                            pucDst + usLength,
                                                            aucPrintUserData,
                                                            (VOS_UINT16)ulPrintStrLen);
        }
        else
        {
            usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,
                                                            (TAF_INT8 *)pgucAtSndCodeAddr,
                                                            pucDst + usLength,
                                                            pucSrc,
                                                            usSrcLen);
        }
    }
    /* DCS: 7BIT */
    else
    {
        if(AT_CSCS_UCS2_CODE == gucAtCscsType)       /* +CSCS:UCS2 */
        {
            usLength += (TAF_UINT16)At_Ascii2UnicodePrint(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,pucDst + usLength,pucSrc,usSrcLen);
        }
        else
        {
            if(((TAF_UINT32)(pucDst - (TAF_UINT8 *)headaddr) + usSrcLen) >= MaxLength)
            {
                AT_ERR_LOG("At_PrintReportData too long");
                return 0;
            }

            if ((AT_CSCS_IRA_CODE == gucAtCscsType)
             && (MN_MSG_MSG_CODING_7_BIT == enMsgCoding))
            {
                TAF_STD_ConvertDefAlphaToAscii(pucSrc, usSrcLen, (pucDst + usLength), &ulPrintStrLen);
                usLength += (TAF_UINT16)ulPrintStrLen;
            }
            else
            {
                ulMaxMemLength = MaxLength - (TAF_UINT32)(pucDst - (TAF_UINT8*)headaddr);
                TAF_MEM_CPY_S((pucDst + usLength), ulMaxMemLength, pucSrc, usSrcLen);   /* ???????????????? ??usLength ???????????????????? 0??pclink???????????????? */
                usLength += usSrcLen;
            }
        }
    }

    return usLength;
}


TAF_UINT32 At_MsgPduInd(
    MN_MSG_BCD_ADDR_STRU                *pstScAddr,
    MN_MSG_RAW_TS_DATA_STRU             *pstPdu,
    TAF_UINT8                           *pucDst
)
{
    TAF_UINT16                          usLength            = 0;

    /* <alpha> ???? */

    /* <length> */
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)(pucDst + usLength),
                                       ",%d",
                                       pstPdu->ulLen);

    /* <data> ????????????UCS2????????????*/
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pucDst + usLength,
                                           "%s",
                                           gaucAtCrLf);

    /*SCA*/
    if (0 == pstScAddr->ucBcdLen)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pucDst + usLength),
                                           "00");
    }
    else
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pucDst + usLength),
                                           "%X%X%X%X",
                                           (((pstScAddr->ucBcdLen + 1) & 0xf0) >> 4),
                                           ((pstScAddr->ucBcdLen + 1) & 0x0f),
                                           ((pstScAddr->addrType & 0xf0) >> 4),
                                           (pstScAddr->addrType & 0x0f));

        usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,
                                                        (TAF_INT8 *)pgucAtSndCodeAddr,
                                                        pucDst + usLength,
                                                        pstScAddr->aucBcdNum,
                                                        (TAF_UINT16)pstScAddr->ucBcdLen);
    }

    usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,
                                                    (TAF_INT8 *)pgucAtSndCodeAddr,
                                                    pucDst + usLength,
                                                    pstPdu->aucData,
                                                    (TAF_UINT16)pstPdu->ulLen);

    return usLength;
}


VOS_UINT32 At_StaRptPduInd(
    MN_MSG_BCD_ADDR_STRU                *pstScAddr,
    MN_MSG_RAW_TS_DATA_STRU             *pstPdu,
    VOS_UINT8                           *pucDst
)
{
    VOS_UINT16                          usLength            = 0;

    /* <length> */
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)(pucDst + usLength),
                                       "%d",
                                       pstPdu->ulLen);

    /* <data> ????????????UCS2????????????*/
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pucDst + usLength,
                                       "%s",
                                       gaucAtCrLf);

    /*SCA*/
    if (0 == pstScAddr->ucBcdLen)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)(pucDst + usLength),
                                           "00");
    }
    else
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)(pucDst + usLength),
                                           "%X%X%X%X",
                                           (((pstScAddr->ucBcdLen + 1) & 0xf0) >> 4),
                                           ((pstScAddr->ucBcdLen + 1) & 0x0f),
                                           ((pstScAddr->addrType & 0xf0) >> 4),
                                           (pstScAddr->addrType & 0x0f));

        usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,
                                                        (TAF_INT8 *)pgucAtSndCodeAddr,
                                                        pucDst + usLength,
                                                        pstScAddr->aucBcdNum,
                                                        (TAF_UINT16)pstScAddr->ucBcdLen);
    }

    usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,
                                                    (TAF_INT8 *)pgucAtSndCodeAddr,
                                                    pucDst + usLength,
                                                    pstPdu->aucData,
                                                    (TAF_UINT16)pstPdu->ulLen);

    return usLength;
}


VOS_UINT32  AT_IsClientBlock(VOS_VOID)
{
    VOS_UINT32                          ulAtStatus;
    VOS_UINT32                          ulAtMode;
    AT_PORT_BUFF_CFG_ENUM_UINT8         enSmsBuffCfg;

    enSmsBuffCfg    = AT_GetPortBuffCfg();
    if (AT_PORT_BUFF_DISABLE == enSmsBuffCfg)
    {
        return VOS_FALSE;
    }

    ulAtStatus  = AT_IsAnyParseClientPend();
    ulAtMode    = AT_IsAllClientDataMode();

    /* ???????????????????? pend???????????????????? */
    if (VOS_TRUE == ulAtStatus)
    {
        return VOS_TRUE;
    }

    /* ????????????????????data???????????????? */
    if (VOS_TRUE == ulAtMode)
    {
        return VOS_TRUE;
    }

    return VOS_FALSE;

}




TAF_VOID  At_BufferMsgInTa(
    VOS_UINT8                           ucIndex,
    MN_MSG_EVENT_ENUM_U32               enEvent,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    MN_MSG_EVENT_INFO_STRU              *pstEventInfo;
    TAF_UINT8                           *pucUsed;
    AT_MODEM_SMS_CTX_STRU               *pstSmsCtx = VOS_NULL_PTR;

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    pstSmsCtx->stSmtBuffer.ucIndex = pstSmsCtx->stSmtBuffer.ucIndex % AT_BUFFER_SMT_EVENT_MAX;
    pucUsed = &(pstSmsCtx->stSmtBuffer.aucUsed[pstSmsCtx->stSmtBuffer.ucIndex]);
    pstEventInfo = &(pstSmsCtx->stSmtBuffer.astEvent[pstSmsCtx->stSmtBuffer.ucIndex]);
    pstSmsCtx->stSmtBuffer.ucIndex++;


    if (AT_MSG_BUFFER_FREE == *pucUsed)
    {
        *pucUsed = AT_MSG_BUFFER_USED;
    }

    TAF_MEM_CPY_S(pstEventInfo, sizeof(MN_MSG_EVENT_INFO_STRU), pstEvent, sizeof(MN_MSG_EVENT_INFO_STRU));
    return;
}


VOS_UINT16 AT_PrintSmsLength(
    MN_MSG_MSG_CODING_ENUM_U8           enMsgCoding,
    VOS_UINT32                          ulLength,
    VOS_UINT8                          *pDst
)
{
    VOS_UINT16                          usLength;
    VOS_UINT16                          usSmContentLength;

    /* UCS2??????????????????????UCS2??????????????BYTE??????????????????????2 */
    if (MN_MSG_MSG_CODING_UCS2 == enMsgCoding)
    {
        usSmContentLength = (VOS_UINT16)ulLength >> 1;
    }
    else
    {
        usSmContentLength = (VOS_UINT16)ulLength;
    }

    usLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pDst,
                                       ",%d",
                                       usSmContentLength);

    return usLength;
}


TAF_VOID At_ForwardMsgToTeInCmt(
    VOS_UINT8                            ucIndex,
    TAF_UINT16                          *pusSendLength,
    MN_MSG_TS_DATA_INFO_STRU            *pstTsDataInfo,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT16                          usLength = *pusSendLength;
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    /* +CMT */
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "+CMT: ");

    if (AT_CMGF_MSG_FORMAT_TEXT == pstSmsCtx->enCmgfMsgFormat)
    {
        /* +CMT: <oa>,[<alpha>],<scts>[,<tooa>,<fo>,<pid>,<dcs>,<sca>,<tosca>,<length>]<CR><LF><data> */
        /* <oa> */
        usLength += (TAF_UINT16)At_PrintAsciiAddr(&pstTsDataInfo->u.stDeliver.stOrigAddr,
                                                  (pgucAtSndCodeAddr + usLength));
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           ",");

        /* <alpha> ???? */
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           ",");

        /* <scts> */
        usLength += (TAF_UINT16)At_SmsPrintScts(&pstTsDataInfo->u.stDeliver.stTimeStamp,
                                                (pgucAtSndCodeAddr + usLength));
        if (AT_CSDH_SHOW_TYPE == pstSmsCtx->ucCsdhType)
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",");
            /* <tooa> */
            usLength += (TAF_UINT16)At_PrintAddrType(&pstTsDataInfo->u.stDeliver.stOrigAddr,
                                                     (pgucAtSndCodeAddr + usLength));
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",");

            /*<fo>*/
            usLength += (TAF_UINT16)At_PrintMsgFo(pstTsDataInfo, (pgucAtSndCodeAddr + usLength));

            /* <pid> */
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",%d",
                                               pstTsDataInfo->u.stDeliver.enPid);

            /* <dcs> */
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",%d,",
                                               pstTsDataInfo->u.stDeliver.stDcs.ucRawDcsData);

            /* <sca> */
            usLength += (TAF_UINT16)At_PrintBcdAddr(&pstEvent->u.stDeliverInfo.stRcvMsgInfo.stScAddr,
                                                    (pgucAtSndCodeAddr + usLength));

            /* <tosca> */
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",%d",
                                               pstEvent->u.stDeliverInfo.stRcvMsgInfo.stScAddr.addrType);

            /* <length> */
            usLength += AT_PrintSmsLength(pstTsDataInfo->u.stDeliver.stDcs.enMsgCoding,
                                          pstTsDataInfo->u.stDeliver.stUserData.ulLen,
                                          (pgucAtSndCodeAddr + usLength));
        }

        /* <data> ????????????UCS2????????????*/
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "%s",
                                           gaucAtCrLf);

        usLength += (TAF_UINT16)At_PrintReportData(AT_CMD_MAX_LEN,
                                                   (TAF_INT8 *)pgucAtSndCodeAddr,
                                                   pstTsDataInfo->u.stDeliver.stDcs.enMsgCoding,
                                                   (pgucAtSndCodeAddr + usLength),
                                                   pstTsDataInfo->u.stDeliver.stUserData.aucOrgData,
                                                   (TAF_UINT16)pstTsDataInfo->u.stDeliver.stUserData.ulLen);
    }
    else
    {
        /* +CMT: [<alpha>],<length><CR><LF><pdu> */
        usLength += (TAF_UINT16)At_MsgPduInd(&pstEvent->u.stDeliverInfo.stRcvMsgInfo.stScAddr,
                                             &pstEvent->u.stDeliverInfo.stRcvMsgInfo.stTsRawData,
                                             (pgucAtSndCodeAddr + usLength));
    }
    *pusSendLength = usLength;
}


TAF_VOID At_ForwardMsgToTeInBst(
    TAF_UINT8                            ucIndex,
    TAF_UINT16                          *pusSendLength,
    MN_MSG_TS_DATA_INFO_STRU            *pstTsDataInfo,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT16                          usLength = *pusSendLength;
    MN_MSG_BCD_ADDR_STRU               *pstScAddr;
    MN_MSG_RAW_TS_DATA_STRU            *pstPdu;
    TAF_UINT8                           ucBlacklistFlag;

    pstScAddr = &pstEvent->u.stDeliverInfo.stRcvMsgInfo.stScAddr;
    pstPdu    = &pstEvent->u.stDeliverInfo.stRcvMsgInfo.stTsRawData;

    /* ^BST???????????????? */
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "^BST: ");

    /* <length> */
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                       ",%d",
                                       pstPdu->ulLen);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%s",
                                           gaucAtCrLf);

    /*??????????????,??????PDU????????????????????????????????????????????????255*/
    ucBlacklistFlag = 0xFF;
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                       "%X%X",
                                       ((ucBlacklistFlag & 0xf0) >> 4),
                                       (ucBlacklistFlag & 0x0f));

    /*SCA ????????????*/
    if (0 == pstScAddr->ucBcdLen)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "00");
    }
    else
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "%X%X%X%X",
                                           (((pstScAddr->ucBcdLen + 1) & 0xf0) >> 4),
                                           ((pstScAddr->ucBcdLen + 1) & 0x0f),
                                           ((pstScAddr->addrType & 0xf0) >> 4),
                                           (pstScAddr->addrType & 0x0f));

        usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,
                                                        (TAF_INT8 *)pgucAtSndCodeAddr,
                                                        pgucAtSndCodeAddr + usLength,
                                                        pstScAddr->aucBcdNum,
                                                        (TAF_UINT16)pstScAddr->ucBcdLen);
    }

    /*????????*/
    usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,
                                                    (TAF_INT8 *)pgucAtSndCodeAddr,
                                                    pgucAtSndCodeAddr + usLength,
                                                    pstPdu->aucData,
                                                    (TAF_UINT16)pstPdu->ulLen);

    *pusSendLength = usLength;
}



TAF_VOID AT_BlackSmsReport(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU             *pstEvent,
    MN_MSG_TS_DATA_INFO_STRU           *pstTsDataInfo
)
{
    TAF_UINT16                          usLength;

    usLength = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       "%s",
                                       gaucAtCrLf);

    /*bst??????????*/
    At_ForwardMsgToTeInBst(ucIndex, &usLength,pstTsDataInfo,pstEvent);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                   "%s",
                                   gaucAtCrLf);

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
}


TAF_VOID  AT_ForwardDeliverMsgToTe(
    MN_MSG_EVENT_INFO_STRU              *pstEvent,
    MN_MSG_TS_DATA_INFO_STRU            *pstTsDataInfo
)
{
    TAF_BOOL                            bCmtiInd;
    TAF_UINT16                          usLength;
    VOS_UINT8                           ucIndex;
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    ucIndex = AT_BROADCAST_CLIENT_INDEX_MODEM_0;

    /* ????ClientId????ucIndex */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->clientId, &ucIndex))
    {
        AT_WARN_LOG("AT_ForwardDeliverMsgToTe: WARNING:AT INDEX NOT FOUND!");
        return;
    }

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);


    AT_LOG1("AT_ForwardDeliverMsgToTe: current mt is", pstSmsCtx->stCnmiType.CnmiMtType);

    if (AT_CNMI_MT_NO_SEND_TYPE == pstSmsCtx->stCnmiType.CnmiMtType)
    {
        return;
    }

    bCmtiInd = TAF_FALSE;
    if ((MN_MSG_RCVMSG_ACT_STORE == pstEvent->u.stDeliverInfo.enRcvSmAct)
     && (MN_MSG_MEM_STORE_NONE != pstEvent->u.stDeliverInfo.enMemStore))
    {
        if ((AT_CNMI_MT_CMTI_TYPE == pstSmsCtx->stCnmiType.CnmiMtType)
         || (AT_CNMI_MT_CLASS3_TYPE == pstSmsCtx->stCnmiType.CnmiMtType))
        {
            bCmtiInd = TAF_TRUE;
        }

        if (MN_MSG_MSG_CLASS_2 == pstTsDataInfo->u.stDeliver.stDcs.enMsgClass)
        {
            bCmtiInd = TAF_TRUE;
        }
    }

    if ( VOS_TRUE == pstEvent->u.stDeliverInfo.ucBlackRptFlag )
    {
        AT_BlackSmsReport(ucIndex, pstEvent, pstTsDataInfo);
        return;
    }

    usLength = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       "%s",
                                       gaucAtCrLf);

    /*????MT??????????????????CLASS??????????????????????????:
    ????????MT??3??CLASS????????????MT????, ??????????????????????????????????*/
    if (TAF_TRUE == bCmtiInd)
    {
        /* +CMTI: <mem>,<index> */
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "+CMTI: %s,%d",
                                           At_GetStrContent(At_GetSmsArea(pstEvent->u.stDeliverInfo.enMemStore)),
                                           pstEvent->u.stDeliverInfo.ulInex);
    }
    else
    {
        /*CMT??????????*/
        At_ForwardMsgToTeInCmt(ucIndex, &usLength,pstTsDataInfo,pstEvent);
    }

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                   "%s",
                                   gaucAtCrLf);

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return;
}


TAF_VOID  AT_ForwardStatusReportMsgToTe(
    MN_MSG_EVENT_INFO_STRU              *pstEvent,
    MN_MSG_TS_DATA_INFO_STRU            *pstTsDataInfo
)
{
    TAF_UINT16                          usLength;
    VOS_UINT8                           ucIndex;
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    ucIndex = AT_BROADCAST_CLIENT_INDEX_MODEM_0;

    /* ????ClientId????ucIndex */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->clientId, &ucIndex))
    {
        AT_WARN_LOG("AT_ForwardStatusReportMsgToTe: WARNING:AT INDEX NOT FOUND!");
        return;
    }

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    AT_LOG1("AT_ForwardStatusReportMsgToTe: current ds is ", pstSmsCtx->stCnmiType.CnmiDsType);

    if (AT_CNMI_DS_NO_SEND_TYPE == pstSmsCtx->stCnmiType.CnmiDsType)
    {
        return;
    }

    usLength = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       "%s",
                                       gaucAtCrLf);

    if ((MN_MSG_RCVMSG_ACT_STORE == pstEvent->u.stDeliverInfo.enRcvSmAct)
     && (MN_MSG_MEM_STORE_NONE != pstEvent->u.stDeliverInfo.enMemStore))
    {
        /* +CDSI: <mem>,<index> */
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "+CDSI: %s,%d",
                                           At_GetStrContent(At_GetSmsArea(pstEvent->u.stDeliverInfo.enMemStore)),
                                           pstEvent->u.stDeliverInfo.ulInex);
    }
    else
    {
        /* +CDS */
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "+CDS: ");
        if (AT_CMGF_MSG_FORMAT_TEXT == pstSmsCtx->enCmgfMsgFormat)
        {
            /* +CDS: <fo>,<mr>,[<ra>],[<tora>],<scts>,<dt>,<st> */
            /*<fo>*/
            usLength += (TAF_UINT16)At_PrintMsgFo(pstTsDataInfo, (pgucAtSndCodeAddr + usLength));

            /*<mr>*/
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",%d,",
                                               pstTsDataInfo->u.stStaRpt.ucMr);

            /*<ra>*/
            usLength += (TAF_UINT16)At_PrintAsciiAddr(&pstTsDataInfo->u.stStaRpt.stRecipientAddr,
                                                      (pgucAtSndCodeAddr + usLength));
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",");

            /*<tora>*/
            usLength += (TAF_UINT16)At_PrintAddrType(&pstTsDataInfo->u.stStaRpt.stRecipientAddr,
                                                     (pgucAtSndCodeAddr + usLength));
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",");

            /* <scts> */
            usLength += (TAF_UINT16)At_SmsPrintScts(&pstTsDataInfo->u.stStaRpt.stTimeStamp,
                                                    (pgucAtSndCodeAddr + usLength));
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",");

             /* <dt> */
             usLength += (TAF_UINT16)At_SmsPrintScts(&pstTsDataInfo->u.stStaRpt.stDischargeTime,
                                                     (pgucAtSndCodeAddr + usLength));

             /*<st>*/
             usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                (TAF_CHAR *)pgucAtSndCodeAddr,
                                                (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                ",%d",
                                                pstTsDataInfo->u.stStaRpt.enStatus);
        }
        else
        {
            /* +CDS: <length><CR><LF><pdu> */
            usLength += (VOS_UINT16)At_StaRptPduInd(&pstEvent->u.stDeliverInfo.stRcvMsgInfo.stScAddr,
                                                 &pstEvent->u.stDeliverInfo.stRcvMsgInfo.stTsRawData,
                                                 (pgucAtSndCodeAddr + usLength));
        }
    }

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s",
                                       gaucAtCrLf);

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return;
}


TAF_VOID  AT_ForwardPppMsgToTe(
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT32                          ulRet;
    MN_MSG_TS_DATA_INFO_STRU            *pstTsDataInfo;

    pstTsDataInfo = At_GetMsgMem();

    ulRet = MN_MSG_Decode(&pstEvent->u.stDeliverInfo.stRcvMsgInfo.stTsRawData, pstTsDataInfo);
    if (MN_ERR_NO_ERROR != ulRet)
    {
        return;
    }

    if (MN_MSG_TPDU_DELIVER == pstTsDataInfo->enTpduType)
    {
        AT_ForwardDeliverMsgToTe(pstEvent, pstTsDataInfo);
    }
    else if (MN_MSG_TPDU_STARPT == pstTsDataInfo->enTpduType)
    {
        AT_ForwardStatusReportMsgToTe(pstEvent, pstTsDataInfo);
    }
    else
    {
        AT_WARN_LOG("AT_ForwardPppMsgToTe: invalid tpdu type.");
    }

    return;

}


VOS_VOID AT_ForwardCbMsgToTe(
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT32                          ulRet;
    MN_MSG_CBPAGE_STRU                  stCbmPageInfo;
    VOS_UINT16                          usLength;
    VOS_UINT8                           ucIndex;
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    ucIndex = AT_BROADCAST_CLIENT_INDEX_MODEM_0;

    /* ????ClientId????ucIndex */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->clientId, &ucIndex))
    {
        AT_WARN_LOG("AT_ForwardCbMsgToTe: WARNING:AT INDEX NOT FOUND!");
        return;
    }


    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    AT_LOG1("AT_ForwardCbMsgToTe: current bm is ", pstSmsCtx->stCnmiType.CnmiBmType);


    /*????BM??????????????????CLASS??????????????????????????:
    ??????????????BM??3??,CBM??????*/

    ulRet = MN_MSG_DecodeCbmPage(&(pstEvent->u.stCbsDeliverInfo.stCbRawData), &stCbmPageInfo);
    if (MN_ERR_NO_ERROR != ulRet)
    {
        return;
    }

    /*+CBM: <sn>,<mid>,<dcs>,<page>,<pages><CR><LF><data> (text mode enabled)*/
    /*+CBM: <length><CR><LF><pdu> (PDU mode enabled); or*/
    usLength  = 0;
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                       "+CBM: ");

    if (AT_CMGF_MSG_FORMAT_TEXT == pstSmsCtx->enCmgfMsgFormat)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "%d,",
                                           stCbmPageInfo.stSn.usRawSnData);

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "%d,",
                                           stCbmPageInfo.usMid);

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "%d,",
                                           stCbmPageInfo.stDcs.ucRawDcsData);

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "%d,",
                                           stCbmPageInfo.ucPageIndex);

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "%d",
                                           stCbmPageInfo.ucPageNum);

        /* <data> ????????????UCS2????????????*/
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "%s",
                                           gaucAtCrLf);

        usLength += (TAF_UINT16)At_PrintReportData(AT_CMD_MAX_LEN,
                                                   (TAF_INT8 *)pgucAtSndCodeAddr,
                                                   stCbmPageInfo.stDcs.enMsgCoding,
                                                   (pgucAtSndCodeAddr + usLength),
                                                   stCbmPageInfo.stContent.aucContent,
                                                   (TAF_UINT16)stCbmPageInfo.stContent.ulLen);
    }
    else
    {
        /*+CBM: <length><CR><LF><pdu> (PDU mode enabled); or*/
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "%d",
                                           pstEvent->u.stCbsDeliverInfo.stCbRawData.ulLen);

        /* <data> ????????????UCS2????????????*/
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "%s",
                                           gaucAtCrLf);

        usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,
                                                        (TAF_INT8 *)pgucAtSndCodeAddr,
                                                        (pgucAtSndCodeAddr + usLength),
                                                        pstEvent->u.stCbsDeliverInfo.stCbRawData.aucData,
                                                        (TAF_UINT16)pstEvent->u.stCbsDeliverInfo.stCbRawData.ulLen);
    }

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s",
                                       gaucAtCrLf);

    /* ??????????,?????????????????? */
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s",
                                       gaucAtCrLf);


    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
}


TAF_VOID At_ForwardMsgToTe(
    MN_MSG_EVENT_ENUM_U32               enEvent,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{

    AT_LOG1("At_ForwardMsgToTe: current Event is ", enEvent);

    switch (enEvent)
    {
    case MN_MSG_EVT_DELIVER:
        AT_ForwardPppMsgToTe(pstEvent);
        break;

    case MN_MSG_EVT_DELIVER_CBM:
        AT_ForwardCbMsgToTe(pstEvent);
        break;
    default:
        AT_WARN_LOG("At_SendSmtInd: invalid tpdu type.");
        break;
    }
    return;
}


TAF_VOID At_HandleSmtBuffer(
    VOS_UINT8                           ucIndex,
    AT_CNMI_BFR_TYPE                    ucBfrType
)
{
    TAF_UINT8                           ucLoop;
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    if (AT_CNMI_BFR_SEND_TYPE == ucBfrType)
    {
        for (ucLoop = 0; ucLoop < AT_BUFFER_SMT_EVENT_MAX; ucLoop ++)
        {
            if (AT_MSG_BUFFER_USED == pstSmsCtx->stSmtBuffer.aucUsed[ucLoop])
            {
                At_ForwardMsgToTe(MN_MSG_EVT_DELIVER, &(pstSmsCtx->stSmtBuffer.astEvent[ucLoop]));
            }
        }

    }

    TAF_MEM_SET_S(&(pstSmsCtx->stSmtBuffer), sizeof(pstSmsCtx->stSmtBuffer), 0x00, sizeof(pstSmsCtx->stSmtBuffer));

    return;
}


VOS_VOID AT_FlushSmsIndication(VOS_VOID)
{
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;
    AT_PORT_BUFF_CFG_STRU              *pstPortBuffCfg = VOS_NULL_PTR;
    VOS_UINT16                          i;
    VOS_UINT32                          ulClientId;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;
    VOS_UINT8                           aucModemFlag[MODEM_ID_BUTT];
    VOS_UINT32                          j;

    j   = 0;

    pstPortBuffCfg = AT_GetPortBuffCfgInfo();
    TAF_MEM_SET_S(aucModemFlag, sizeof(aucModemFlag), 0x00, sizeof(aucModemFlag));

    if (pstPortBuffCfg->ucNum > AT_MAX_CLIENT_NUM)
    {
        pstPortBuffCfg->ucNum = AT_MAX_CLIENT_NUM;
    }

    /* ????clientId????????flush ????modem id */
    for (i = 0; i < pstPortBuffCfg->ucNum; i++)
    {
        ulClientId = pstPortBuffCfg->ulUsedClientID[i];
        ulRslt = AT_GetModemIdFromClient((VOS_UINT8)ulClientId, &enModemId);
        if (VOS_OK != ulRslt)
        {
            AT_ERR_LOG("AT_FlushSmsIndication: Get modem id fail");
            continue;
        }

        aucModemFlag[enModemId] = VOS_TRUE;
    }

    /* flush SMS */
    for (i = 0; i < MODEM_ID_BUTT; i++)
    {
        if (VOS_TRUE == aucModemFlag[i])
        {
            pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(i);

            for (j = 0; j < AT_BUFFER_SMT_EVENT_MAX; j ++)
            {
                if (AT_MSG_BUFFER_USED == pstSmsCtx->stSmtBuffer.aucUsed[j])
                {
                    At_ForwardMsgToTe(MN_MSG_EVT_DELIVER, &(pstSmsCtx->stSmtBuffer.astEvent[j]));
                }
            }

            TAF_MEM_SET_S(&(pstSmsCtx->stSmtBuffer), sizeof(pstSmsCtx->stSmtBuffer), 0x00, sizeof(pstSmsCtx->stSmtBuffer));
        }
    }

    return;
}



TAF_VOID At_SmsModSmStatusRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    VOS_UINT32                          ulRet;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_SmsModSmStatusRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    if (TAF_TRUE != pstEvent->u.stModifyInfo.bSuccess)
    {
        ulRet = At_ChgMnErrCodeToAt(ucIndex, pstEvent->u.stDeleteInfo.ulFailCause);
    }
    else
    {
        ulRet = AT_OK;
    }

    gstAtSendData.usBufLen = 0;
    At_FormatResultData(ucIndex, ulRet);
    return;
}


TAF_VOID At_SmsInitResultProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pEvent
)
{
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    pstSmsCtx->stCpmsInfo.stUsimStorage.ulTotalRec = pEvent->u.stInitResultInfo.ulTotalSmRec;
    pstSmsCtx->stCpmsInfo.stUsimStorage.ulUsedRec = pEvent->u.stInitResultInfo.ulUsedSmRec;

    return;
}


VOS_VOID At_SmsDeliverErrProc(
    VOS_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    if ((VOS_TRUE == pstSmsCtx->ucLocalStoreFlg)
     && (TAF_MSG_ERROR_TR2M_TIMEOUT == pstEvent->u.stDeliverErrInfo.enErrorCode))
    {
        pstSmsCtx->stCnmiType.CnmiMtType            = AT_CNMI_MT_NO_SEND_TYPE;
        pstSmsCtx->stCnmiType.CnmiDsType            = AT_CNMI_DS_NO_SEND_TYPE;
        AT_WARN_LOG("At_SmsDeliverErrProc: CnmiMtType and CnmiDsType changed!");
    }

    /* ????????????????????????????????????????AT????????????ERROR LOG???????????????????????? */

    return;
}


VOS_VOID At_SmsInitSmspResultProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    VOS_UINT8                           ucDefaultIndex;

    ucDefaultIndex = pstEvent->u.stInitSmspResultInfo.ucDefaultSmspIndex;

    AT_NORM_LOG1("At_SmsInitSmspResultProc: ucDefaultIndex", ucDefaultIndex);

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    if (ucDefaultIndex >= MN_MSG_MAX_USIM_EFSMSP_NUM)
    {
        ucDefaultIndex = AT_CSCA_CSMP_STORAGE_INDEX;
    }

    /* ????defaultSmspIndex, ??csca csmp ?????? */
    pstSmsCtx->stCscaCsmpInfo.ucDefaultSmspIndex = ucDefaultIndex;

    TAF_MEM_CPY_S(&(pstSmsCtx->stCscaCsmpInfo.stParmInUsim),
               sizeof(pstSmsCtx->stCscaCsmpInfo.stParmInUsim),
               &pstEvent->u.stInitSmspResultInfo.astSrvParm[ucDefaultIndex],
               sizeof(pstSmsCtx->stCscaCsmpInfo.stParmInUsim));

    TAF_MEM_CPY_S(&(pstSmsCtx->stCpmsInfo.stRcvPath),
           sizeof(pstSmsCtx->stCpmsInfo.stRcvPath),
           &pstEvent->u.stInitSmspResultInfo.stRcvMsgPath,
           sizeof(pstSmsCtx->stCpmsInfo.stRcvPath));

    g_enClass0Tailor = pstEvent->u.stInitSmspResultInfo.enClass0Tailor;

    return;
}


VOS_VOID At_SmsSrvParmChangeProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    TAF_MEM_CPY_S(&(pstSmsCtx->stCscaCsmpInfo.stParmInUsim),
               sizeof(pstSmsCtx->stCscaCsmpInfo.stParmInUsim),
               &pstEvent->u.stSrvParmChangeInfo.astSrvParm[pstSmsCtx->stCscaCsmpInfo.ucDefaultSmspIndex],
               sizeof(pstSmsCtx->stCscaCsmpInfo.stParmInUsim));

    return;
}


VOS_VOID At_SmsRcvMsgPathChangeProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    pstSmsCtx->stCpmsInfo.stRcvPath.enRcvSmAct = pstEvent->u.stRcvMsgPathInfo.enRcvSmAct;
    pstSmsCtx->stCpmsInfo.stRcvPath.enSmMemStore = pstEvent->u.stRcvMsgPathInfo.enSmMemStore;
    pstSmsCtx->stCpmsInfo.stRcvPath.enRcvStaRptAct = pstEvent->u.stRcvMsgPathInfo.enRcvStaRptAct;
    pstSmsCtx->stCpmsInfo.stRcvPath.enStaRptMemStore = pstEvent->u.stRcvMsgPathInfo.enStaRptMemStore;

    return;
}


VOS_VOID AT_ReportSmMeFull(
    VOS_UINT8                           ucIndex,
    MN_MSG_MEM_STORE_ENUM_U8            enMemStore
)
{
    VOS_UINT16 usLength = 0;

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                       "%s",
                                       gaucAtCrLf);

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                       "^SMMEMFULL: ");

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR*)(pgucAtSndCodeAddr + usLength),
                                       "%s",
                                       At_GetStrContent(At_GetSmsArea(enMemStore)));
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                       "%s",
                                       gaucAtCrLf);

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return;
}

VOS_VOID At_SmsStorageListProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    MN_MSG_STORAGE_LIST_EVT_INFO_STRU  *pstStorageListInfo;
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    MN_MSG_MT_CUSTOMIZE_ENUM_UINT8      enMtCustomize = MN_MSG_MT_CUSTOMIZE_NONE;

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    pstStorageListInfo = &pstEvent->u.stStorageListInfo;
    if (MN_MSG_MEM_STORE_SIM == pstStorageListInfo->enMemStroe)
    {
        TAF_MEM_CPY_S(&(pstSmsCtx->stCpmsInfo.stUsimStorage),
                   sizeof(pstSmsCtx->stCpmsInfo.stUsimStorage),
                   &pstEvent->u.stStorageListInfo,
                   sizeof(pstSmsCtx->stCpmsInfo.stUsimStorage));
    }
    else
    {
        TAF_MEM_CPY_S(&(pstSmsCtx->stCpmsInfo.stNvimStorage),
                   sizeof(pstSmsCtx->stCpmsInfo.stNvimStorage),
                   &pstEvent->u.stStorageListInfo,
                   sizeof(pstSmsCtx->stCpmsInfo.stNvimStorage));
    }

    enMtCustomize = pstSmsCtx->stSmMeFullCustomize.enMtCustomize;
    if ((MN_MSG_MT_CUSTOMIZE_FT == enMtCustomize)
     && (pstEvent->u.stStorageListInfo.ulTotalRec == pstEvent->u.stStorageListInfo.ulUsedRec)
     && (MN_MSG_MEM_STORE_SIM == pstEvent->u.stStorageStateInfo.enMemStroe))
    {
        AT_INFO_LOG("At_SmsStorageListProc: FT memory full.");
        AT_ReportSmMeFull(ucIndex, pstEvent->u.stStorageStateInfo.enMemStroe);
    }

    if (!AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {

        /* ??????NV????????????????????NV??????????????????????????NV?????????? */
        if (MN_MSG_MEM_STORE_NV == pstStorageListInfo->enMemStroe)
        {
            gastAtClientTab[ucIndex].AtSmsData.bWaitForNvStorageStatus = TAF_FALSE;
        }

        /* ??????SIM????????????????????SIM??????????????????????????SIM?????????? */
        if (MN_MSG_MEM_STORE_SIM == pstStorageListInfo->enMemStroe)
        {
            gastAtClientTab[ucIndex].AtSmsData.bWaitForUsimStorageStatus = TAF_FALSE;
        }

        /* CPMS?????????????????????????????????????????????????? */
        if (AT_CMD_CPMS_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
        {
            if ((TAF_FALSE == gastAtClientTab[ucIndex].AtSmsData.bWaitForCpmsSetRsp)
             && (TAF_FALSE == gastAtClientTab[ucIndex].AtSmsData.bWaitForNvStorageStatus)
             && (TAF_FALSE == gastAtClientTab[ucIndex].AtSmsData.bWaitForUsimStorageStatus))
            {
                AT_STOP_TIMER_CMD_READY(ucIndex);
                At_PrintSetCpmsRsp(ucIndex);
            }
        }

        /* CPMS???????????????????????????????????? */
        if (AT_CMD_CPMS_READ == gastAtClientTab[ucIndex].CmdCurrentOpt)
        {
            if ((TAF_FALSE == gastAtClientTab[ucIndex].AtSmsData.bWaitForNvStorageStatus)
             && (TAF_FALSE == gastAtClientTab[ucIndex].AtSmsData.bWaitForUsimStorageStatus))
            {
                AT_STOP_TIMER_CMD_READY(ucIndex);
                At_PrintGetCpmsRsp(ucIndex);
            }
        }
    }

    return;
}


VOS_VOID At_SmsStorageExceedProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;

    /* ?????? */
    enModemId       = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("At_SmsStorageExceedProc: Get modem id fail.");
        return;
    }

    AT_ReportSmMeFull(ucIndex, pstEvent->u.stStorageStateInfo.enMemStroe);

    return;
}


VOS_VOID At_SmsDeliverProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT16                          usLength            = 0;
    TAF_UINT32                          ulRet               = AT_OK;
    MN_MSG_TS_DATA_INFO_STRU            *pstTsDataInfo;
    VOS_UINT8                           ucUserId;
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    ucUserId = AT_BROADCAST_CLIENT_INDEX_MODEM_0;

    /* ????ClientId????ucUserId */
    if ( AT_FAILURE == At_ClientIdToUserId(pstEvent->clientId, &ucUserId) )
    {
        AT_WARN_LOG("AT_SmsDeliverProc: WARNING:AT INDEX NOT FOUND!");
        return;
    }

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucUserId);

    /* ??????????????CLass0????????????
    1:H3G????????TIM Class 0??????????????????????????????????????CLASS 0
    ????????????+CMT??????????????????CNMI????CPMS????????????????????????
    ??????????????CLASS 0??????????????
    CLass0????????????????MT,MODE??????
    */

    pstTsDataInfo = At_GetMsgMem();
    ulRet = MN_MSG_Decode(&pstEvent->u.stDeliverInfo.stRcvMsgInfo.stTsRawData, pstTsDataInfo);
    if (MN_ERR_NO_ERROR != ulRet)
    {
        return;
    }

    AT_StubSaveAutoReplyData(ucUserId, pstEvent, pstTsDataInfo);


    if ( (MN_MSG_TPDU_DELIVER == pstTsDataInfo->enTpduType)
      && (MN_MSG_MSG_CLASS_0 == pstTsDataInfo->u.stDeliver.stDcs.enMsgClass)
      && (MN_MSG_CLASS0_DEF != g_enClass0Tailor))
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s",
                                       gaucAtCrLf);

        if ((MN_MSG_CLASS0_TIM == g_enClass0Tailor)
         || (MN_MSG_CLASS0_VIVO == g_enClass0Tailor))
        {
            /*+CMT???????? */
            At_ForwardMsgToTeInCmt(ucUserId, &usLength,pstTsDataInfo,pstEvent);
        }
        else
        {
            /* +CMTI: <mem>,<index> */
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "+CMTI: %s,%d",
                                               At_GetStrContent(At_GetSmsArea(pstEvent->u.stDeliverInfo.enMemStore)),
                                               pstEvent->u.stDeliverInfo.ulInex);
        }

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%s",
                                           gaucAtCrLf);

        At_SendResultData(ucUserId, pgucAtSndCodeAddr, usLength);

        return;
    }

    if (AT_CNMI_MODE_SEND_OR_DISCARD_TYPE == pstSmsCtx->stCnmiType.CnmiModeType)
    {
        At_ForwardMsgToTe(MN_MSG_EVT_DELIVER, pstEvent);
        return;
    }

    /* ????????0?????? */
    if (AT_CNMI_MODE_BUFFER_TYPE == pstSmsCtx->stCnmiType.CnmiModeType)
    {
        At_BufferMsgInTa(ucIndex, MN_MSG_EVT_DELIVER, pstEvent);
        return;
    }

    /* ????????2?????? */
    if (AT_CNMI_MODE_SEND_OR_BUFFER_TYPE == pstSmsCtx->stCnmiType.CnmiModeType)
    {
        /* ?????????????????????? */
        if (VOS_TRUE == AT_IsClientBlock())
        {
            At_BufferMsgInTa(ucIndex, MN_MSG_EVT_DELIVER, pstEvent);
        }
        else
        {
            At_ForwardMsgToTe(MN_MSG_EVT_DELIVER, pstEvent);
        }
        return;
    }

    /*?????????? AT_CNMI_MODE_EMBED_AND_SEND_TYPE*/

    return;
}


TAF_VOID At_SetRcvPathRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT32                          ulRet;
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_SetRcvPathRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    if (TAF_TRUE != pstEvent->u.stRcvMsgPathInfo.bSuccess)
    {
        ulRet = At_ChgMnErrCodeToAt(ucIndex, pstEvent->u.stSrvParmInfo.ulFailCause);
        AT_STOP_TIMER_CMD_READY(ucIndex);
        At_FormatResultData(ucIndex, ulRet);
        return;
    }

    if (AT_CMD_CPMS_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        /*????????????????????NVIM*/
        pstSmsCtx->stCpmsInfo.stRcvPath.enSmMemStore = pstEvent->u.stRcvMsgPathInfo.enSmMemStore;
        pstSmsCtx->stCpmsInfo.stRcvPath.enStaRptMemStore = pstEvent->u.stRcvMsgPathInfo.enStaRptMemStore;
        pstSmsCtx->stCpmsInfo.enMemReadorDelete = pstSmsCtx->stCpmsInfo.enTmpMemReadorDelete;
        pstSmsCtx->stCpmsInfo.enMemSendorWrite = pstSmsCtx->stCpmsInfo.enTmpMemSendorWrite;

        gastAtClientTab[ucIndex].AtSmsData.bWaitForCpmsSetRsp = TAF_FALSE;

        /* CPMS?????????????????????????????????????????????????? */
        if ((TAF_FALSE == gastAtClientTab[ucIndex].AtSmsData.bWaitForCpmsSetRsp)
         && (TAF_FALSE == gastAtClientTab[ucIndex].AtSmsData.bWaitForNvStorageStatus)
         && (TAF_FALSE == gastAtClientTab[ucIndex].AtSmsData.bWaitForUsimStorageStatus))
        {
            AT_STOP_TIMER_CMD_READY(ucIndex);
            At_PrintSetCpmsRsp(ucIndex);
        }

    }
    else if (AT_CMD_CSMS_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        /* ???????????? */
        pstSmsCtx->enCsmsMsgVersion                      = pstEvent->u.stRcvMsgPathInfo.enSmsServVersion;
        pstSmsCtx->stCpmsInfo.stRcvPath.enSmsServVersion = pstSmsCtx->enCsmsMsgVersion;

        gstAtSendData.usBufLen = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (TAF_CHAR *)pgucAtSndCodeAddr,
                                                        (TAF_CHAR *)(pgucAtSndCodeAddr + gstAtSendData.usBufLen),
                                                        "%s: ",
                                                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        At_PrintCsmsInfo(ucIndex);
        AT_STOP_TIMER_CMD_READY(ucIndex);
        At_FormatResultData(ucIndex, AT_OK);
    }
    else/*AT_CMD_CNMI_SET*/
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);
        gstAtSendData.usBufLen = 0;
        At_FormatResultData(ucIndex, AT_OK);

        pstSmsCtx->stCnmiType.CnmiBfrType = pstSmsCtx->stCnmiType.CnmiTmpBfrType;
        pstSmsCtx->stCnmiType.CnmiDsType = pstSmsCtx->stCnmiType.CnmiTmpDsType;
        pstSmsCtx->stCnmiType.CnmiBmType = pstSmsCtx->stCnmiType.CnmiTmpBmType;
        pstSmsCtx->stCnmiType.CnmiMtType = pstSmsCtx->stCnmiType.CnmiTmpMtType;
        pstSmsCtx->stCnmiType.CnmiModeType = pstSmsCtx->stCnmiType.CnmiTmpModeType;
        pstSmsCtx->stCpmsInfo.stRcvPath.enRcvSmAct = pstEvent->u.stRcvMsgPathInfo.enRcvSmAct;
        pstSmsCtx->stCpmsInfo.stRcvPath.enRcvStaRptAct = pstEvent->u.stRcvMsgPathInfo.enRcvStaRptAct;

        if (0 != pstSmsCtx->stCnmiType.CnmiModeType)
        {
            At_HandleSmtBuffer(ucIndex, pstSmsCtx->stCnmiType.CnmiBfrType);
        }

    }
    return;
}


TAF_VOID At_SetCscaCsmpRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT32                          ulRet;
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_SetCscaCsmpRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    if (TAF_TRUE != pstEvent->u.stSrvParmInfo.bSuccess)
    {
        ulRet = At_ChgMnErrCodeToAt(ucIndex, pstEvent->u.stSrvParmInfo.ulFailCause);
    }
    else
    {
        if (AT_CMD_CSMP_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
        {
            TAF_MEM_CPY_S(&(pstSmsCtx->stCscaCsmpInfo.stVp), sizeof(pstSmsCtx->stCscaCsmpInfo.stVp), &(pstSmsCtx->stCscaCsmpInfo.stTmpVp), sizeof(pstSmsCtx->stCscaCsmpInfo.stVp));
            pstSmsCtx->stCscaCsmpInfo.ucFo = pstSmsCtx->stCscaCsmpInfo.ucTmpFo;
            pstSmsCtx->stCscaCsmpInfo.bFoUsed = TAF_TRUE;
        }
        TAF_MEM_CPY_S(&(pstSmsCtx->stCscaCsmpInfo.stParmInUsim),
                   sizeof(pstSmsCtx->stCscaCsmpInfo.stParmInUsim),
                   &pstEvent->u.stSrvParmInfo.stSrvParm,
                   sizeof(pstSmsCtx->stCscaCsmpInfo.stParmInUsim));
        ulRet = AT_OK;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, ulRet);
    return;
}


TAF_VOID  At_DeleteRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT32                          ulRet;
    MN_MSG_DELETE_PARAM_STRU            stDelete;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_DeleteRspProc : AT_BROADCAST_INDEX.");
        return;
    }


    TAF_MEM_SET_S(&stDelete, sizeof(stDelete), 0x00, sizeof(stDelete));


    if ((AT_CMD_CMGD_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
     && (AT_CMD_CBMGD_SET != gastAtClientTab[ucIndex].CmdCurrentOpt))
    {
        return;
    }

    stDelete.enMemStore = pstEvent->u.stDeleteInfo.enMemStore;
    stDelete.ulIndex = pstEvent->u.stDeleteInfo.ulIndex;
    if (TAF_TRUE != pstEvent->u.stDeleteInfo.bSuccess)
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);
        ulRet = At_ChgMnErrCodeToAt(ucIndex, pstEvent->u.stDeleteInfo.ulFailCause);
        At_FormatResultData(ucIndex, ulRet);
        return;
    }

    if (MN_MSG_DELETE_SINGLE == pstEvent->u.stDeleteInfo.enDeleteType)
    {
        gastAtClientTab[ucIndex].AtSmsData.ucMsgDeleteTypes ^= AT_MSG_DELETE_SINGLE;
    }

    if (MN_MSG_DELETE_ALL == pstEvent->u.stDeleteInfo.enDeleteType)
    {
        gastAtClientTab[ucIndex].AtSmsData.ucMsgDeleteTypes ^= AT_MSG_DELETE_ALL;
    }

    if (MN_MSG_DELETE_READ == pstEvent->u.stDeleteInfo.enDeleteType)
    {
        gastAtClientTab[ucIndex].AtSmsData.ucMsgDeleteTypes ^= AT_MSG_DELETE_READ;
    }

    if (MN_MSG_DELETE_SENT == pstEvent->u.stDeleteInfo.enDeleteType)
    {
        gastAtClientTab[ucIndex].AtSmsData.ucMsgDeleteTypes ^= AT_MSG_DELETE_SENT;
    }

    if (MN_MSG_DELETE_NOT_SENT == pstEvent->u.stDeleteInfo.enDeleteType)
    {
        gastAtClientTab[ucIndex].AtSmsData.ucMsgDeleteTypes ^= AT_MSG_DELETE_UNSENT;
    }

    if (0 == gastAtClientTab[ucIndex].AtSmsData.ucMsgDeleteTypes)
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);
        At_FormatResultData(ucIndex, AT_OK);
    }
    else
    {
        At_MsgDeleteCmdProc(ucIndex,
                            gastAtClientTab[ucIndex].opId,
                            stDelete,
                            gastAtClientTab[ucIndex].AtSmsData.ucMsgDeleteTypes);
    }
    return;
}


VOS_VOID AT_QryCscaRspProc(
    VOS_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU             *pstEvent
)
{
    VOS_UINT16                          usLength;
    VOS_UINT32                          ulRet;
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_QryCscaRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    /* AT??????????CSCA?????????????????????? */
    if (AT_CMD_CSCA_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    if (VOS_TRUE == pstEvent->u.stSrvParmInfo.bSuccess)
    {
        /* ??????????????????AT??????????MSG????????????????????????AT?????????????? */
        TAF_MEM_CPY_S(&(pstSmsCtx->stCscaCsmpInfo.stParmInUsim.stScAddr),
                   sizeof(pstSmsCtx->stCscaCsmpInfo.stParmInUsim.stScAddr),
                   &pstEvent->u.stSrvParmInfo.stSrvParm.stScAddr,
                   sizeof(pstSmsCtx->stCscaCsmpInfo.stParmInUsim.stScAddr));

        /* ????????????AT_OK           ??????????+CSCA: <sca>,<toda>?????????? */
        usLength = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           "%s: ",
                                           g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

        /*????????????????????????????????????????????????0*/
        if ((0 == (pstEvent->u.stSrvParmInfo.stSrvParm.ucParmInd & MN_MSG_SRV_PARM_MASK_SC_ADDR))
         && (0 != pstEvent->u.stSrvParmInfo.stSrvParm.stScAddr.ucBcdLen))
        {
            /*??SCA??????BCD????????ASCII??*/
            usLength += At_PrintBcdAddr(&pstEvent->u.stSrvParmInfo.stSrvParm.stScAddr,
                                        (pgucAtSndCodeAddr + usLength));

            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               ",%d",
                                               pstEvent->u.stSrvParmInfo.stSrvParm.stScAddr.addrType);
        }
        else
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "\"\",128");
        }

        gstAtSendData.usBufLen = usLength;
        ulRet                  = AT_OK;
    }
    else
    {
        /* ????pstEvent->u.stSrvParmInfo.ulFailCause????At_ChgMnErrCodeToAt??????AT???????????? */
        gstAtSendData.usBufLen = 0;
        ulRet                  = At_ChgMnErrCodeToAt(ucIndex, pstEvent->u.stSrvParmInfo.ulFailCause);

    }

    /* ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);

    return;
}


VOS_VOID At_SmsStubRspProc(
    VOS_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU             *pstEvent
)
{
    VOS_UINT32                          ulRet;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_SmsStubRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    /* AT??????????CMSTUB?????????????????? */
    if (AT_CMD_CMSTUB_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    if (MN_ERR_NO_ERROR == pstEvent->u.stResult.ulErrorCode)
    {
        ulRet = AT_OK;
    }
    else
    {
        ulRet = AT_CMS_UNKNOWN_ERROR;
    }

    /* ????At_FormatResultData???????? */
    gstAtSendData.usBufLen = 0;
    At_FormatResultData(ucIndex, ulRet);
    return;
}


VOS_UINT32 AT_GetBitMap(
    VOS_UINT32                         *pulBitMap,
    VOS_UINT32                          ulIndex
)
{
    VOS_UINT8                           ucX;
    VOS_UINT32                          ulY;
    VOS_UINT32                          ulMask;

    ulY = ulIndex/32;
    ucX = (VOS_UINT8)ulIndex%32;
    ulMask = ((VOS_UINT32)1 << ucX);
    if (0 != (pulBitMap[ulY] & ulMask))
    {
        return VOS_TRUE;
    }
    else
    {
        return VOS_FALSE;
    }
}


VOS_VOID AT_SmsListIndex(
    VOS_UINT16                          usLength,
    MN_MSG_DELETE_TEST_EVT_INFO_STRU   *pstPara,
    VOS_UINT16                         *pusPrintOffSet
)
{
    TAF_UINT32                          ulLoop;
    TAF_UINT32                          ulMsgNum;

    ulMsgNum  = 0;

    for (ulLoop = 0; ulLoop < pstPara->ulSmCapacity; ulLoop++)
    {
        if (TAF_TRUE == AT_GetBitMap(pstPara->aulValidLocMap, ulLoop))
        {
            ulMsgNum++;
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%d,", ulLoop);
        }

    }

    /* ????????????"," */
    if (0 != ulMsgNum)
    {
        usLength -= 1;
    }

    *pusPrintOffSet = usLength;

    return;
}


TAF_VOID  At_DeleteTestRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT16                          usLength;
    MN_MSG_DELETE_TEST_EVT_INFO_STRU   *pstPara;
    VOS_UINT32                          ulLoop;
    VOS_BOOL                            bMsgExist;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_DeleteTestRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    pstPara = (MN_MSG_DELETE_TEST_EVT_INFO_STRU *)&pstEvent->u.stDeleteTestInfo;

    if (AT_CMD_CMGD_TEST == gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        usLength = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                          (TAF_CHAR *)pgucAtSndCodeAddr,
                                          (TAF_CHAR *)pgucAtSndCodeAddr,
                                          "%s: (",
                                          g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

        AT_SmsListIndex(usLength, pstPara, &usLength);

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "),(0-4)");
    }
    else
    {
        /* ??????????????????????????: ??????????????????????OK */
        bMsgExist = VOS_FALSE;

        for (ulLoop = 0; ulLoop < MN_MSG_CMGD_PARA_MAX_LEN; ulLoop++)
        {
            if (0 != pstPara->aulValidLocMap[ulLoop])
            {
                bMsgExist = VOS_TRUE;
                break;
            }
        }

        if (VOS_TRUE == bMsgExist)
        {
            usLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                              (TAF_CHAR *)pgucAtSndCodeAddr,
                                              (TAF_CHAR *)pgucAtSndCodeAddr,
                                              "%s: ",
                                              g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

            AT_SmsListIndex(usLength, pstPara, &usLength);
        }
        else
        {
            usLength = 0;
        }
    }

    gstAtSendData.usBufLen = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);

    At_FormatResultData(ucIndex,AT_OK);

    return;
}


TAF_VOID At_ReadRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT16                          usLength            = 0;
    TAF_UINT32                          ulRet               = AT_OK;
    MN_MSG_TS_DATA_INFO_STRU           *pstTsDataInfo;
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_ReadRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    AT_STOP_TIMER_CMD_READY(ucIndex);

    gstAtSendData.usBufLen = 0;

    if (TAF_TRUE != pstEvent->u.stReadInfo.bSuccess)
    {
        ulRet = At_ChgMnErrCodeToAt(ucIndex, pstEvent->u.stReadInfo.ulFailCause);
        At_FormatResultData(ucIndex, ulRet);
        return;
    }

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s: ",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

    usLength += (TAF_UINT16)At_SmsPrintState(pstSmsCtx->enCmgfMsgFormat,
                                             pstEvent->u.stReadInfo.enStatus,
                                             (pgucAtSndCodeAddr + usLength));

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                       ",");

    pstTsDataInfo = At_GetMsgMem();
    ulRet = MN_MSG_Decode(&pstEvent->u.stReadInfo.stMsgInfo.stTsRawData, pstTsDataInfo);
    if (MN_ERR_NO_ERROR != ulRet)
    {
        ulRet = At_ChgMnErrCodeToAt(ucIndex, ulRet);
        At_FormatResultData(ucIndex, ulRet);
        return;
    }

    if (AT_CMGF_MSG_FORMAT_PDU == pstSmsCtx->enCmgfMsgFormat)/*PDU*/
    {
        /* +CMGR: <stat>,[<alpha>],<length><CR><LF><pdu> */
        usLength += (TAF_UINT16)At_MsgPduInd(&pstEvent->u.stReadInfo.stMsgInfo.stScAddr,
                                             &pstEvent->u.stReadInfo.stMsgInfo.stTsRawData,
                                             (pgucAtSndCodeAddr + usLength));

        gstAtSendData.usBufLen = usLength;
        At_FormatResultData(ucIndex, AT_OK);
        return;
    }

    switch (pstEvent->u.stReadInfo.stMsgInfo.stTsRawData.enTpduType)
    {
        case MN_MSG_TPDU_DELIVER:
            /* +CMGR: <stat>,<oa>,[<alpha>],<scts>[,<tooa>,<fo>,<pid>,<dcs>, <sca>,<tosca>,<length>]<CR><LF><data>*/
            /* <oa> */
            usLength += (TAF_UINT16)At_PrintAsciiAddr(&pstTsDataInfo->u.stDeliver.stOrigAddr,
                                                      (pgucAtSndCodeAddr + usLength));
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",");
            /* <alpha> ???? */
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",");

            /* <scts> */
            usLength += (TAF_UINT16)At_SmsPrintScts(&pstTsDataInfo->u.stDeliver.stTimeStamp,
                                                    (pgucAtSndCodeAddr + usLength));

            if (AT_CSDH_SHOW_TYPE == pstSmsCtx->ucCsdhType)
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",");
                /* <tooa> */
                usLength += (TAF_UINT16)At_PrintAddrType(&pstTsDataInfo->u.stDeliver.stOrigAddr,
                                                         (pgucAtSndCodeAddr + usLength));
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",");

                /*<fo>*/
                usLength += (TAF_UINT16)At_PrintMsgFo(pstTsDataInfo, (pgucAtSndCodeAddr + usLength));

                /* <pid> */
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",%d",
                                                   pstTsDataInfo->u.stDeliver.enPid);

                /* <dcs> */
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",%d,",
                                                   pstTsDataInfo->u.stDeliver.stDcs.ucRawDcsData);

                /* <sca> */
                usLength += (TAF_UINT16)At_PrintBcdAddr(&pstEvent->u.stReadInfo.stMsgInfo.stScAddr,
                                                       (pgucAtSndCodeAddr + usLength));

                /* <tosca> */
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                  (TAF_CHAR *)pgucAtSndCodeAddr,
                                                  (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                  ",%d",
                                                  pstEvent->u.stReadInfo.stMsgInfo.stScAddr.addrType);

                /* <length> */
                usLength += AT_PrintSmsLength(pstTsDataInfo->u.stDeliver.stDcs.enMsgCoding,
                                              pstTsDataInfo->u.stDeliver.stUserData.ulLen,
                                              (pgucAtSndCodeAddr + usLength));

            }
            /* <data> ????????????UCS2????????????*/
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               "%s",
                                               gaucAtCrLf);

            usLength += (TAF_UINT16)At_PrintReportData(AT_CMD_MAX_LEN,
                                                      (TAF_INT8 *)pgucAtSndCodeAddr,
                                                       pstTsDataInfo->u.stDeliver.stDcs.enMsgCoding,
                                                       (pgucAtSndCodeAddr + usLength),
                                                       pstTsDataInfo->u.stDeliver.stUserData.aucOrgData,
                                                       (TAF_UINT16)pstTsDataInfo->u.stDeliver.stUserData.ulLen);

            break;
        case MN_MSG_TPDU_SUBMIT:
            /*+CMGR: <stat>,<da>,[<alpha>][,<toda>,<fo>,<pid>,<dcs>,[<vp>], <sca>,<tosca>,<length>]<CR><LF><data>*/
            /* <da> */
            usLength += (TAF_UINT16)At_PrintAsciiAddr(&pstTsDataInfo->u.stSubmit.stDestAddr,
                                                      (pgucAtSndCodeAddr + usLength));
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",");
            /* <alpha> ???? */

            if (AT_CSDH_SHOW_TYPE == pstSmsCtx->ucCsdhType)
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",");

                /* <toda> */
                usLength += (TAF_UINT16)At_PrintAddrType(&pstTsDataInfo->u.stSubmit.stDestAddr,
                                                         (pgucAtSndCodeAddr + usLength));
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",");

                /*<fo>*/
                usLength += (TAF_UINT16)At_PrintMsgFo(pstTsDataInfo, (pgucAtSndCodeAddr + usLength));

                /* <pid> */
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",%d",
                                                   pstTsDataInfo->u.stSubmit.enPid);
                /* <dcs> */
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",%d,",
                                                   pstTsDataInfo->u.stSubmit.stDcs.ucRawDcsData);
                /* <vp>,?????????????? */
                usLength += At_MsgPrintVp(&pstTsDataInfo->u.stSubmit.stValidPeriod,
                                          (pgucAtSndCodeAddr + usLength));
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",");

                /* <sca> */
                usLength += At_PrintBcdAddr(&pstEvent->u.stReadInfo.stMsgInfo.stScAddr,
                                            (pgucAtSndCodeAddr + usLength));

                /* <tosca> */
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",%d",
                                                   pstEvent->u.stReadInfo.stMsgInfo.stScAddr.addrType);

                /* <length> */
                usLength += AT_PrintSmsLength(pstTsDataInfo->u.stSubmit.stDcs.enMsgCoding,
                                              pstTsDataInfo->u.stSubmit.stUserData.ulLen,
                                              (pgucAtSndCodeAddr + usLength));
            }

            /* <data> ????????????UCS2????????????*/
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               "%s",
                                               gaucAtCrLf);

            usLength += (TAF_UINT16)At_PrintReportData(AT_CMD_MAX_LEN,
                                                       (TAF_INT8 *)pgucAtSndCodeAddr,
                                                       pstTsDataInfo->u.stSubmit.stDcs.enMsgCoding,
                                                       (pgucAtSndCodeAddr + usLength),
                                                       pstTsDataInfo->u.stSubmit.stUserData.aucOrgData,
                                                       (TAF_UINT16)pstTsDataInfo->u.stSubmit.stUserData.ulLen);

            break;
        case MN_MSG_TPDU_COMMAND:
            /*+CMGR: <stat>,<fo>,<ct>[,<pid>,[<mn>],[<da>],[<toda>],<length><CR><LF><cdata>]*/
            /*<fo>*/
            usLength += (TAF_UINT16)At_PrintMsgFo(pstTsDataInfo, (pgucAtSndCodeAddr + usLength));
            /* <ct> */
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",%d",
                                               pstTsDataInfo->u.stCommand.enCmdType);

            if (AT_CSDH_SHOW_TYPE == pstSmsCtx->ucCsdhType)
            {
                /* <pid> */
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",%d",
                                                   pstTsDataInfo->u.stCommand.enPid);

                /* <mn>,?????????????? */
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",%d,",
                                                   pstTsDataInfo->u.stCommand.ucMsgNumber);

                /* <da> */
                usLength += (TAF_UINT16)At_PrintAsciiAddr(&pstTsDataInfo->u.stCommand.stDestAddr,
                                                         (pgucAtSndCodeAddr + usLength));
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",");

                /* <toda> */
                usLength += (TAF_UINT16)At_PrintAddrType(&pstTsDataInfo->u.stCommand.stDestAddr,
                                                         (pgucAtSndCodeAddr + usLength));

                /* <length>??0 */
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   ",%d",
                                                   pstTsDataInfo->u.stCommand.ucCommandDataLen);

                /* <data> ????????????UCS2????????????*/
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                   "%s",
                                                   gaucAtCrLf);

                usLength += (TAF_UINT16)At_PrintReportData(AT_CMD_MAX_LEN,
                                                           (TAF_INT8 *)pgucAtSndCodeAddr,
                                                           MN_MSG_MSG_CODING_8_BIT,
                                                           (pgucAtSndCodeAddr + usLength),
                                                           pstTsDataInfo->u.stCommand.aucCmdData,
                                                           pstTsDataInfo->u.stCommand.ucCommandDataLen);

            }
            break;
        case MN_MSG_TPDU_STARPT:
            /*
            +CMGR: <stat>,<fo>,<mr>,[<ra>],[<tora>],<scts>,<dt>,<st>
            */
            /*<fo>*/
            usLength += (TAF_UINT16)At_PrintMsgFo(pstTsDataInfo, (pgucAtSndCodeAddr + usLength));

            /*<mr>*/
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",%d,",
                                               pstTsDataInfo->u.stStaRpt.ucMr);

            /*<ra>*/
            usLength += (TAF_UINT16)At_PrintAsciiAddr(&pstTsDataInfo->u.stStaRpt.stRecipientAddr,
                                                      (pgucAtSndCodeAddr + usLength));
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",");

            /*<tora>*/
            usLength += (TAF_UINT16)At_PrintAddrType(&pstTsDataInfo->u.stStaRpt.stRecipientAddr,
                                                     (pgucAtSndCodeAddr + usLength));
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",");

            /* <scts> */
            usLength += (TAF_UINT16)At_SmsPrintScts(&pstTsDataInfo->u.stStaRpt.stTimeStamp,
                                                    (pgucAtSndCodeAddr + usLength));
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                               ",");

             /* <dt> */
             usLength += (TAF_UINT16)At_SmsPrintScts(&pstTsDataInfo->u.stStaRpt.stDischargeTime,
                                                     (pgucAtSndCodeAddr + usLength));

             /*<st>*/
             usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                (TAF_CHAR *)pgucAtSndCodeAddr,
                                                (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                                ",%d",
                                                pstTsDataInfo->u.stStaRpt.enStatus);
            break;
        default:
            break;
    }

    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex, AT_OK);
    return;
}


TAF_VOID  At_ListRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU             *pstEvent
)
{
    TAF_UINT16                          usLength;
    TAF_UINT32                          ulRet = AT_OK;
    MN_MSG_TS_DATA_INFO_STRU           *pstTsDataInfo = VOS_NULL_PTR;
    TAF_UINT32                          ulLoop;

    MN_MSG_LIST_PARM_STRU               stListParm;

    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_ListRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    TAF_MEM_SET_S(&stListParm, sizeof(stListParm), 0x00, sizeof(MN_MSG_LIST_PARM_STRU));

    if (TAF_TRUE != pstEvent->u.stListInfo.bSuccess)
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);
        ulRet = At_ChgMnErrCodeToAt(ucIndex, pstEvent->u.stListInfo.ulFailCause);
        At_FormatResultData(ucIndex, ulRet);
        return;
    }

    usLength = 0;
    if (VOS_TRUE == pstEvent->u.stListInfo.bFirstListEvt)
    {
        if (AT_V_ENTIRE_TYPE == gucAtVType)
        {
            usLength = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           "%s",
                                           gaucAtCrLf);
        }
    }
    pstTsDataInfo = At_GetMsgMem();

    for (ulLoop = 0; ulLoop < pstEvent->u.stListInfo.ulReportNum; ulLoop++)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "%s: %d,",
                                           g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                           pstEvent->u.stListInfo.astSmInfo[ulLoop].ulIndex);

        usLength += (TAF_UINT16)At_SmsPrintState(pstSmsCtx->enCmgfMsgFormat,
                                                 pstEvent->u.stListInfo.astSmInfo[ulLoop].enStatus,
                                                 (pgucAtSndCodeAddr + usLength));
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           ",");
        /**/
        ulRet = MN_MSG_Decode(&pstEvent->u.stListInfo.astSmInfo[ulLoop].stMsgInfo.stTsRawData, pstTsDataInfo);
        if (MN_ERR_NO_ERROR != ulRet)
        {
            ulRet = At_ChgMnErrCodeToAt(ucIndex, ulRet);
            At_FormatResultData(ucIndex, ulRet);
            return;
        }

        if (AT_CMGF_MSG_FORMAT_PDU == pstSmsCtx->enCmgfMsgFormat)/*PDU*/
        {
            /*
            +CMGL: <index>,<stat>,[<alpha>],<length><CR><LF><pdu>
            [<CR><LF>+CMGL:<index>,<stat>,[<alpha>],<length><CR><LF><pdu>
            [...]]
            */
            usLength += (TAF_UINT16)At_MsgPduInd(&pstEvent->u.stListInfo.astSmInfo[ulLoop].stMsgInfo.stScAddr,/*??*/
                                                 &pstEvent->u.stListInfo.astSmInfo[ulLoop].stMsgInfo.stTsRawData,
                                                 (pgucAtSndCodeAddr + usLength));
        }
        else
        {
            usLength += (TAF_UINT16)At_PrintListMsg(ucIndex, pstEvent, pstTsDataInfo, (pgucAtSndCodeAddr + usLength));
        }

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s",
                                       gaucAtCrLf);

        At_BufferorSendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

        usLength = 0;
    }

    if (TAF_TRUE == pstEvent->u.stListInfo.bLastListEvt)
    {
        gstAtSendData.usBufLen = 0;
        AT_STOP_TIMER_CMD_READY(ucIndex);
        At_FormatResultData(ucIndex, AT_OK);
    }
    else
    {

        /* ?????? */
        TAF_MEM_CPY_S( &stListParm, sizeof(stListParm), &(pstEvent->u.stListInfo.stReceivedListPara), sizeof(stListParm) );

        /* ????SMS???????????????????????? */
        stListParm.ucIsFirstTimeReq = VOS_FALSE;

        /* ???????????? */
        if (MN_ERR_NO_ERROR != MN_MSG_List( gastAtClientTab[ucIndex].usClientId,
                                            gastAtClientTab[ucIndex].opId,
                                            &stListParm) )
        {
            gstAtSendData.usBufLen = 0;
            AT_STOP_TIMER_CMD_READY(ucIndex);
            At_FormatResultData(ucIndex, AT_ERROR);
            return;
        }

    }

    return;
}


TAF_VOID At_WriteSmRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT32                          ulRet               = AT_OK;
    TAF_UINT16                          usLength            = 0;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_WriteSmRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    if (TAF_TRUE != pstEvent->u.stWriteInfo.bSuccess)
    {
        ulRet = At_ChgMnErrCodeToAt(ucIndex, pstEvent->u.stWriteInfo.ulFailCause);
    }
    else
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%s: ",
                                           g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%d",
                                           pstEvent->u.stWriteInfo.ulIndex);

    }

    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex, ulRet);
    return;
}


TAF_VOID At_SetCnmaRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_SetCnmaRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    if ((AT_CMD_CNMA_TEXT_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
     || (AT_CMD_CNMA_PDU_SET == gastAtClientTab[ucIndex].CmdCurrentOpt))
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);
        gstAtSendData.usBufLen = 0;
        At_FormatResultData(ucIndex, AT_OK);
    }
    return;
}



VOS_UINT32 AT_GetSmsRpReportCause(TAF_MSG_ERROR_ENUM_UINT32 enMsgCause)
{
    VOS_UINT32                          i;
    VOS_UINT32                          ulMapLength;

    /* 27005 3.2.5 0...127 3GPP TS 24.011 [6] clause E.2 values */
    /* 27005 3.2.5 128...255 3GPP TS 23.040 [3] clause 9.2.3.22 values.  */
    ulMapLength = sizeof(g_astAtSmsErrorCodeMap) / sizeof(g_astAtSmsErrorCodeMap[0]);

    for (i = 0; i < ulMapLength; i++)
    {
        if (g_astAtSmsErrorCodeMap[i].enMsgErrorCode == enMsgCause)
        {
            return g_astAtSmsErrorCodeMap[i].enAtErrorCode;
        }
    }

    return AT_CMS_UNKNOWN_ERROR;
}


TAF_VOID At_SendSmRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT32                          ulRet               = AT_OK;
    TAF_UINT16                          usLength            = 0;

    AT_INFO_LOG("At_SendSmRspProc: step into function.");

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_SendSmRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    /* ??????????: ??????????????????????AT???????????????????????? */
    if ((AT_CMD_CMGS_TEXT_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
     && (AT_CMD_CMGS_PDU_SET  != gastAtClientTab[ucIndex].CmdCurrentOpt)
     && (AT_CMD_CMGC_TEXT_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
     && (AT_CMD_CMGC_PDU_SET  != gastAtClientTab[ucIndex].CmdCurrentOpt)
     && (AT_CMD_CMSS_SET      != gastAtClientTab[ucIndex].CmdCurrentOpt)
     && (AT_CMD_CMST_SET      != gastAtClientTab[ucIndex].CmdCurrentOpt))
    {
        return;
    }

    gstAtSendData.usBufLen = 0;

    if (TAF_MSG_ERROR_NO_ERROR != pstEvent->u.stSubmitRptInfo.enErrorCode)
    {
        AT_NORM_LOG("At_SendSmRspProc: pstEvent->u.stSubmitRptInfo.enRptStatus is not ok.");

        ulRet = AT_GetSmsRpReportCause(pstEvent->u.stSubmitRptInfo.enErrorCode);
        AT_STOP_TIMER_CMD_READY(ucIndex);
        At_FormatResultData(ucIndex, ulRet);
        return;
    }

    if (gastAtClientTab[ucIndex].AtSmsData.ucMsgSentSmNum < 1)
    {
        AT_WARN_LOG("At_SendSmRspProc: the number of sent message is zero.");
        return;
    }
    gastAtClientTab[ucIndex].AtSmsData.ucMsgSentSmNum--;

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s: ",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%d",
                                       pstEvent->u.stSubmitRptInfo.ucMr);

    if (0 == gastAtClientTab[ucIndex].AtSmsData.ucMsgSentSmNum)
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);
        gstAtSendData.usBufLen = usLength;
        At_FormatResultData(ucIndex, ulRet);
    }
    else
    {
        At_MsgResultCodeFormat(ucIndex, usLength);
    }
    return;
}



VOS_VOID At_SmsDeliverCbmProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    if ((AT_CNMI_MODE_SEND_OR_DISCARD_TYPE == pstSmsCtx->stCnmiType.CnmiModeType)
     || (AT_CNMI_MODE_SEND_OR_BUFFER_TYPE == pstSmsCtx->stCnmiType.CnmiModeType))
    {
        At_ForwardMsgToTe(MN_MSG_EVT_DELIVER_CBM, pstEvent);
        return;
    }

    /* ????CBS?????????? */

    if (AT_CNMI_MODE_EMBED_AND_SEND_TYPE == pstSmsCtx->stCnmiType.CnmiModeType)
    {
        /*??????????*/
    }

    return;
}



VOS_UINT32  AT_CbPrintRange(
    VOS_UINT16                          usLength,
    TAF_CBA_CBMI_RANGE_LIST_STRU       *pstCbMidr
)
{
    TAF_UINT32                          ulLoop;
    TAF_UINT16                          usAddLen;

    usAddLen = usLength;
    for (ulLoop = 0; ulLoop < pstCbMidr->usCbmirNum; ulLoop++)
    {
        if ( pstCbMidr->astCbmiRangeInfo[ulLoop].usMsgIdFrom
            == pstCbMidr->astCbmiRangeInfo[ulLoop].usMsgIdTo)
        {

            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%d",
                                               pstCbMidr->astCbmiRangeInfo[ulLoop].usMsgIdFrom);
        }
        else
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%d-%d",
                                           pstCbMidr->astCbmiRangeInfo[ulLoop].usMsgIdFrom,
                                           pstCbMidr->astCbmiRangeInfo[ulLoop].usMsgIdTo);

        }

        if (ulLoop != (pstCbMidr->usCbmirNum - 1))
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               ",");
        }
    }

    usAddLen = usLength - usAddLen;

    return usAddLen ;
}


VOS_VOID At_GetCbActiveMidsRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT16                          usLength;
    TAF_UINT16                          usAddLength;
    VOS_UINT32                          ulRet;
    AT_MODEM_SMS_CTX_STRU              *pstSmsCtx = VOS_NULL_PTR;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_GetCbActiveMidsRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    pstSmsCtx = AT_GetModemSmsCtxAddrFromClientId(ucIndex);

    /* ?????????? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    if (TAF_TRUE != pstEvent->u.stCbsCbMids.bSuccess)
    {
        ulRet = At_ChgMnErrCodeToAt(ucIndex, pstEvent->u.stCbsCbMids.ulFailCause);
        At_FormatResultData(ucIndex, ulRet);
        return;
    }

    usLength = 0;

    /* ????????????????????,????????????0 */
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s:0,",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "\"");

    /* ??????????MID */
    usAddLength = (VOS_UINT16)AT_CbPrintRange(usLength,&(pstEvent->u.stCbsCbMids.stCbMidr));

    usLength += usAddLength;

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "\",\"");

    /* ????????????MID */
    usAddLength = (VOS_UINT16)AT_CbPrintRange(usLength,&(pstSmsCtx->stCbsDcssInfo));

    usLength += usAddLength;

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "\"");


    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex, AT_OK);
    return;
}



VOS_VOID AT_ChangeCbMidsRsp(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    TAF_UINT32                          ulRet;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_ChangeCbMidsRsp : AT_BROADCAST_INDEX.");
        return;
    }

    if (TAF_TRUE != pstEvent->u.stCbsChangeInfo.bSuccess)
    {
        ulRet = At_ChgMnErrCodeToAt(ucIndex, pstEvent->u.stCbsChangeInfo.ulFailCause);
    }
    else
    {
        ulRet = AT_OK;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, ulRet);

}



VOS_VOID  At_ProcDeliverEtwsPrimNotify(
    VOS_UINT8                                               ucIndex,
    MN_MSG_EVENT_INFO_STRU                                 *pstEvent
)
{
    TAF_CBA_ETWS_PRIM_NTF_EVT_INFO_STRU                    *pstPrimNtf;
    VOS_UINT16                                              usLength;

    pstPrimNtf = &pstEvent->u.stEtwsPrimNtf;

    /* ^ETWSPN: <plmn id>,<warning type>,<msg id>,<sn>,<auth> [,<warning security information>] */
    /* ????: ^ETWSPN: "46000",0180,4352,3000,1 */

    usLength   = 0;
    usLength  += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)(pgucAtSndCodeAddr + usLength),
                                       "%s^ETWSPN: ",
                                       gaucAtCrLf);

    /* <plmn id>
       ulMcc??ulMnc??????????????
       ulMcc????8??    ????bit0--bit7???????? MCC digit 1;
       ulMcc??????8??  ????bit8--bit15???????? MCC digit 2;
       ulMcc????????8??????bit16--bit23???????? MCC digit 3;

       ulMnc????8??    ????bit0--bit7???????? MNC digit 1;
       ulMnc??????8??  ????bit8--bit15???????? MNC digit 2;
       ulMnc????????8??????bit16--bit23???????? MNC digit 3;
    */
    if ( 0x0F0000 == (pstPrimNtf->stPlmn.ulMnc&0xFF0000) )
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "\"%d%d%d%d%d\",",
                                           (pstPrimNtf->stPlmn.ulMcc&0xFF),
                                           (pstPrimNtf->stPlmn.ulMcc&0xFF00)>>8,
                                           (pstPrimNtf->stPlmn.ulMcc&0xFF0000)>>16,
                                           (pstPrimNtf->stPlmn.ulMnc&0xFF),
                                           (pstPrimNtf->stPlmn.ulMnc&0xFF00)>>8);
    }
    else
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)(pgucAtSndCodeAddr + usLength),
                                           "\"%d%d%d%d%d%d\",",
                                           (pstPrimNtf->stPlmn.ulMcc&0xFF),
                                           (pstPrimNtf->stPlmn.ulMcc&0xFF00)>>8,
                                           (pstPrimNtf->stPlmn.ulMcc&0xFF0000)>>16,
                                           (pstPrimNtf->stPlmn.ulMnc&0xFF),
                                           (pstPrimNtf->stPlmn.ulMnc&0xFF00)>>8,
                                           (pstPrimNtf->stPlmn.ulMnc&0xFF0000)>>16);
    }

    /* <warning type> */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)(pgucAtSndCodeAddr + usLength),
                                       "%04X,",
                                       pstPrimNtf->usWarnType);
    /* <msg id> */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)(pgucAtSndCodeAddr + usLength),
                                       "%04X,",
                                       pstPrimNtf->usMsgId);
    /* <sn> */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)(pgucAtSndCodeAddr + usLength),
                                       "%04X,",
                                       pstPrimNtf->usSN);

    /* <auth> */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)(pgucAtSndCodeAddr + usLength),
                                       "%d%s",
                                       pstPrimNtf->enAuthRslt,
                                       gaucAtCrLf);

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

}




TAF_VOID At_SetCmmsRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    AT_RRETURN_CODE_ENUM_UINT32         ulResult = AT_CMS_UNKNOWN_ERROR;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_SetCmmsRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    if (MN_ERR_NO_ERROR == pstEvent->u.stLinkCtrlInfo.ulErrorCode)
    {
        ulResult = AT_OK;
    }

    gstAtSendData.usBufLen = 0;
    At_FormatResultData(ucIndex,ulResult);
    return;
}


TAF_VOID At_GetCmmsRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    AT_RRETURN_CODE_ENUM_UINT32          ulResult = AT_CMS_UNKNOWN_ERROR;
    MN_MSG_LINK_CTRL_EVT_INFO_STRU      *pstLinkCtrlInfo;                     /*event report:MN_MSG_EVT_SET_COMM_PARAM*/

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_GetCmmsRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    gstAtSendData.usBufLen = 0;
    pstLinkCtrlInfo = &pstEvent->u.stLinkCtrlInfo;
    if (MN_ERR_NO_ERROR == pstLinkCtrlInfo->ulErrorCode)
    {
        ulResult = AT_OK;
        gstAtSendData.usBufLen = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (TAF_CHAR *)pgucAtSndCodeAddr,
                                                        (TAF_CHAR *)pgucAtSndCodeAddr,
                                                        "%s: %d",
                                                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                        pstLinkCtrlInfo->enLinkCtrl);
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);
    return;
}


TAF_VOID At_SetCgsmsRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU             *pstEvent
)
{
    AT_RRETURN_CODE_ENUM_UINT32         ulResult;

    ulResult = AT_CMS_UNKNOWN_ERROR;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_SetCgsmsRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    if (MN_ERR_NO_ERROR == pstEvent->u.stSendDomainInfo.ulErrorCode)
    {
        ulResult = AT_OK;
    }

    gstAtSendData.usBufLen = 0;
    At_FormatResultData(ucIndex,ulResult);
    return;
}


TAF_VOID At_GetCgsmsRspProc(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU             *pstEvent
)
{
    AT_RRETURN_CODE_ENUM_UINT32         ulResult;
    MN_MSG_SEND_DOMAIN_EVT_INFO_STRU   *pstSendDomainInfo = VOS_NULL_PTR;                     /*event report:MN_MSG_EVT_SET_COMM_PARAM*/

    ulResult = AT_CMS_UNKNOWN_ERROR;
    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_GetCgsmsRspProc : AT_BROADCAST_INDEX.");
        return;
    }

    gstAtSendData.usBufLen = 0;
    pstSendDomainInfo      = &pstEvent->u.stSendDomainInfo;

    if (MN_ERR_NO_ERROR == pstSendDomainInfo->ulErrorCode)
    {
        ulResult = AT_OK;
        gstAtSendData.usBufLen = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (TAF_CHAR *)pgucAtSndCodeAddr,
                                                        (TAF_CHAR *)pgucAtSndCodeAddr,
                                                        "%s: %d",
                                                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                        pstSendDomainInfo->enSendDomain);
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);
    return;
}


TAF_VOID At_SmsRspNop(
    TAF_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU              *pstEvent
)
{
    AT_INFO_LOG("At_SmsRspNop: no operation need for the event type ");
    return;
}


TAF_VOID At_SmsMsgProc(MN_AT_IND_EVT_STRU *pstData,TAF_UINT16 usLen)
{
    MN_MSG_EVENT_INFO_STRU              *pstEvent;
    MN_MSG_EVENT_ENUM_U32               enEvent;
    TAF_UINT8                           ucIndex;
    TAF_UINT32                          ulEventLen;


    enEvent = MN_MSG_EVT_MAX;


    AT_INFO_LOG("At_SmsMsgProc: Step into function.");
    AT_LOG1("At_SmsMsgProc: pstData->clientId,", pstData->clientId);

    ulEventLen = sizeof(MN_MSG_EVENT_ENUM_U32);
    TAF_MEM_CPY_S(&enEvent,  sizeof(enEvent), pstData->aucContent, ulEventLen);
    pstEvent = (MN_MSG_EVENT_INFO_STRU *)&pstData->aucContent[ulEventLen];

    if (AT_FAILURE == At_ClientIdToUserId(pstData->clientId, &ucIndex))
    {
        AT_WARN_LOG("At_SmsMsgProc At_ClientIdToUserId FAILURE");
        return;
    }

    if (!AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        if (pstEvent->opId != gastAtClientTab[ucIndex].opId)
        {
            AT_LOG1("At_SmsMsgProc: pstEvent->opId,", pstEvent->opId);
            AT_LOG1("At_SmsMsgProc: gastAtClientTab[ucIndex].opId,", gastAtClientTab[ucIndex].opId);
            AT_NORM_LOG("At_SmsMsgProc: invalid operation id.");
            return;
        }

        AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);
    }

    if (enEvent >= MN_MSG_EVT_MAX)
    {
        AT_WARN_LOG("At_SmsRspProc: invalid event type.");
        return;
    }

    AT_LOG1("At_SmsMsgProc enEvent", enEvent);
    g_aAtSmsMsgProcTable[enEvent](ucIndex, pstEvent);
    return;
}


VOS_VOID At_ProcVcSetVoiceMode(
    VOS_UINT8                           ucIndex,
    APP_VC_EVENT_INFO_STRU             *pstVcEvt
)
{
    AT_VMSET_CMD_CTX_STRU               *pstVmSetCmdCtx;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_ProcVcSetVoiceMode : AT_BROADCAST_INDEX.");
        return;
    }

    /* ???????? */
    if (AT_CMD_VMSET_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("At_ProcVcSetVoiceMode : opt error.");
        return;
    }

    pstVmSetCmdCtx = AT_GetCmdVmsetCtxAddr();

    if (VOS_TRUE != pstVcEvt->bSuccess)
    {
        pstVmSetCmdCtx->ulResult = AT_ERROR;
    }
    /* VMSET????????MODEM???????????????? */
    pstVmSetCmdCtx->ulReportedModemNum++;
    if (MULTI_MODEM_NUMBER > pstVmSetCmdCtx->ulReportedModemNum)
    {
        return;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, pstVmSetCmdCtx->ulResult);

    /* ?????????????????????? */
    AT_InitVmSetCtx();
    return;
}


VOS_UINT32 At_ProcVcGetVolumeEvent(
    VOS_UINT8                           ucIndex,
    APP_VC_EVENT_INFO_STRU             *pstVcEvt
)
{
    VOS_UINT8                           aucIntraVolume[] = {AT_CMD_CLVL_LEV_0,AT_CMD_CLVL_LEV_1,
                                                            AT_CMD_CLVL_LEV_2,AT_CMD_CLVL_LEV_3,
                                                            AT_CMD_CLVL_LEV_4,AT_CMD_CLVL_LEV_5};
    VOS_UINT8                           ucVolumnLvl;
    VOS_UINT32                          i;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("APP_VC_AppQryVolumeProc : AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* ????AT???????????????????? */
    if (AT_CMD_CLVL_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    if (VOS_TRUE == pstVcEvt->bSuccess)
    {
        /* ??????AT+CLVL???????? */
        gstAtSendData.usBufLen = 0;

        ucVolumnLvl = 0;
        for (i = 0; i < 6; i++)
        {
            if (aucIntraVolume[i] == pstVcEvt->usVolume)
            {
                ucVolumnLvl = (VOS_UINT8)i;
                break;
            }
        }

        gstAtSendData.usBufLen =
            (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                   (VOS_CHAR *)pgucAtSndCodeAddr,
                                   (VOS_CHAR *)pgucAtSndCodeAddr,
                                   "%s: %d",
                                   g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                   ucVolumnLvl);

        At_FormatResultData(ucIndex, AT_OK);
    }
    else
    {
        At_FormatResultData(ucIndex, AT_ERROR);
    }

    return VOS_OK;
}


VOS_UINT32 At_ProcVcSetMuteStatusEvent(
    VOS_UINT8                           ucIndex,
    APP_VC_EVENT_INFO_STRU             *pstVcEvtInfo
)
{
    VOS_UINT32                          ulRslt;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_ProcVcSetMuteStatusEvent : AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* ????AT???????????????????? */
    if (AT_CMD_CMUT_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    if (VOS_TRUE != pstVcEvtInfo->bSuccess)
    {
        ulRslt = AT_ERROR;
    }
    else
    {
        ulRslt = AT_OK;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, ulRslt);

    return VOS_OK;
}


VOS_UINT32 At_ProcVcGetMuteStatusEvent(
    VOS_UINT8                           ucIndex,
    APP_VC_EVENT_INFO_STRU             *pstVcEvtInfo
)
{
    VOS_UINT32                          ulRslt;
    VOS_UINT16                          usLength = 0;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_ProcVcSetMuteStatusEvent : AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* ????AT???????????????????? */
    if (AT_CMD_CMUT_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    if (VOS_TRUE == pstVcEvtInfo->bSuccess)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%s: %d",
                                           g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                           pstVcEvtInfo->enMuteStatus);

        ulRslt = AT_OK;

        gstAtSendData.usBufLen = usLength;
    }
    else
    {
        ulRslt = AT_ERROR;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, ulRslt);

    return VOS_OK;
}


VOS_VOID At_VcEventProc(
    VOS_UINT8                           ucIndex,
    APP_VC_EVENT_INFO_STRU              *pstVcEvt,
    APP_VC_EVENT_ENUM_U32               enEvent
)
{
    TAF_UINT32                          ulRet;
    switch (enEvent)
    {
        case APP_VC_EVT_SET_VOLUME:
            if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
            {
                AT_WARN_LOG("At_VcEventProc : AT_BROADCAST_INDEX.");
                return;
            }

            if (TAF_TRUE != pstVcEvt->bSuccess)
            {
                ulRet = AT_ERROR;
            }
            else
            {
                ulRet = AT_OK;
            }

            AT_STOP_TIMER_CMD_READY(ucIndex);
            At_FormatResultData(ucIndex, ulRet);
            return;

        case APP_VC_EVT_SET_VOICE_MODE:
            At_ProcVcSetVoiceMode(ucIndex, pstVcEvt);
            return;

        case APP_VC_EVT_GET_VOLUME:
            At_ProcVcGetVolumeEvent(ucIndex, pstVcEvt);
            return;

        case APP_VC_EVT_PARM_CHANGED:
            return;

        case APP_VC_EVT_SET_MUTE_STATUS:
            At_ProcVcSetMuteStatusEvent(ucIndex, pstVcEvt);
            return;

        case APP_VC_EVT_GET_MUTE_STATUS:
            At_ProcVcGetMuteStatusEvent(ucIndex, pstVcEvt);
            return;


        default:
            return;
    }

}


TAF_VOID At_VcMsgProc(MN_AT_IND_EVT_STRU *pstData,TAF_UINT16 usLen)
{
    APP_VC_EVENT_INFO_STRU              *pstEvent;
    APP_VC_EVENT_ENUM_U32               enEvent;
    TAF_UINT8                           ucIndex;
    TAF_UINT32                          ulEventLen;


    enEvent = APP_VC_EVT_BUTT;


    AT_INFO_LOG("At_VcMsgProc: Step into function.");
    AT_LOG1("At_VcMsgProc: pstData->clientId,", pstData->clientId);

    ulEventLen = sizeof(APP_VC_EVENT_ENUM_U32);
    TAF_MEM_CPY_S(&enEvent,  sizeof(enEvent), pstData->aucContent, ulEventLen);
    pstEvent = (APP_VC_EVENT_INFO_STRU *)&pstData->aucContent[ulEventLen];

    if (AT_FAILURE == At_ClientIdToUserId(pstData->clientId, &ucIndex))
    {
        AT_WARN_LOG("At_VcMsgProc At_ClientIdToUserId FAILURE");
        return;
    }

    if (!AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_LOG1("At_VcMsgProc: ucIndex", ucIndex);
        if (ucIndex >= AT_MAX_CLIENT_NUM)
        {
            AT_WARN_LOG("At_VcMsgProc: invalid CLIENT ID or index.");
            return;
        }

        if (pstEvent->opId != gastAtClientTab[ucIndex].opId)
        {
            AT_LOG1("At_VcMsgProc: pstEvent->opId,", pstEvent->opId);
            AT_LOG1("At_VcMsgProc: gastAtClientTab[ucIndex].opId,", gastAtClientTab[ucIndex].opId);
            AT_NORM_LOG("At_VcMsgProc: invalid operation id.");
            return;
        }

        AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);
    }

    if (enEvent >= APP_VC_EVT_BUTT)
    {
        AT_WARN_LOG("At_SmsRspProc: invalid event type.");
        return;
    }

    AT_LOG1("At_VcMsgProc enEvent", enEvent);
    At_VcEventProc(ucIndex,pstEvent,enEvent);


}


TAF_VOID At_SetParaRspProc( TAF_UINT8 ucIndex,
                                      TAF_UINT8 OpId,
                                      TAF_PARA_SET_RESULT Result,
                                      TAF_PARA_TYPE ParaType,
                                      TAF_VOID *pPara)
{
    AT_RRETURN_CODE_ENUM_UINT32         ulResult = AT_FAILURE;
    TAF_UINT16 usLength = 0;

    /* ??????PS???????????? */
    if(gastAtClientTab[ucIndex].usAsyRtnNum > 0)
    {
        gastAtClientTab[ucIndex].usAsyRtnNum--;         /* ??????????1 */
        if(TAF_PARA_OK == Result)
        {
            if(0 != gastAtClientTab[ucIndex].usAsyRtnNum)
            {
                return;                                 /* ????OK???????????????? */
            }
        }
        else
        {
            gastAtClientTab[ucIndex].usAsyRtnNum = 0;   /* ????ERROR?????????????????????? */
        }
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    switch(Result)
    {
    case TAF_PARA_OK:
        ulResult = AT_OK;
        break;

    case TAF_PARA_SIM_IS_BUSY:
        if(g_stParseContext[ucIndex].pstCmdElement->ulCmdIndex > AT_CMD_SMS_BEGAIN)
        {
            ulResult = AT_CMS_U_SIM_BUSY;
        }
        else
        {
            ulResult = AT_CME_SIM_BUSY;
        }
        break;

    default:
        if(g_stParseContext[ucIndex].pstCmdElement->ulCmdIndex > AT_CMD_SMS_BEGAIN)
        {
            ulResult = AT_CMS_UNKNOWN_ERROR;
        }
        else
        {
            ulResult = AT_CME_UNKNOWN;
        }
        break;
    }

    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);
}

TAF_VOID At_SetMsgProc(TAF_UINT8* pData,TAF_UINT16 usLen)
{
    TAF_UINT16 ClientId = 0;
    TAF_UINT8 OpId = 0;
    TAF_PARA_SET_RESULT Result = 0;
    TAF_PARA_TYPE ParaType = 0;
    TAF_VOID *pPara = TAF_NULL_PTR;
    TAF_UINT16 usAddr = 0;
    TAF_UINT16 usParaLen = 0;
    TAF_UINT8 ucIndex  = 0;

    TAF_MEM_CPY_S(&ClientId, sizeof(ClientId), pData, sizeof(ClientId));
    usAddr += sizeof(ClientId);

    TAF_MEM_CPY_S(&OpId, sizeof(OpId), pData+usAddr, sizeof(OpId));
    usAddr += sizeof(OpId);

    TAF_MEM_CPY_S(&Result, sizeof(Result), pData+usAddr, sizeof(Result));
    usAddr += sizeof(Result);

    TAF_MEM_CPY_S(&ParaType, sizeof(ParaType), pData+usAddr, sizeof(ParaType));
    usAddr += sizeof(ParaType);

    TAF_MEM_CPY_S(&usParaLen, sizeof(usParaLen), pData+usAddr, sizeof(usParaLen));
    usAddr += sizeof(usParaLen);

    if(0 != usParaLen)
    {
        pPara = pData+usAddr;
    }

    AT_LOG1("At_SetMsgProc ClientId",ClientId);
    AT_LOG1("At_SetMsgProc Result",Result);
    AT_LOG1("At_SetMsgProc ParaType",ParaType);

    if(AT_BUTT_CLIENT_ID == ClientId)
    {
        AT_WARN_LOG("At_SetMsgProc Error ucIndex");
        return;
    }
    else
    {
        if(AT_FAILURE == At_ClientIdToUserId(ClientId,&ucIndex))
        {
            AT_WARN_LOG("At_SetMsgProc At_ClientIdToUserId FAILURE");
            return;
        }

        if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
        {
            AT_WARN_LOG("At_SetMsgProc : AT_BROADCAST_INDEX.");
            return;
        }

        AT_LOG1("At_SetMsgProc ucIndex",ucIndex);
        AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);

        At_SetParaRspProc(ucIndex,OpId,Result,ParaType,pPara);
    }
}




VOS_UINT16 AT_GetOperNameLengthForCops(
    TAF_CHAR                            *pstr,
    TAF_UINT8                           ucMaxLen
)
{
    VOS_UINT16                          usRsltLen;
    TAF_UINT8                           i;

    usRsltLen = 0;

    for (i = 0; i < ucMaxLen; i++)
    {
        if ('\0' != pstr[i])
        {
            usRsltLen = i+1;
        }
    }

    return usRsltLen;

}

VOS_VOID At_QryParaRspCopsProc(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                           OpId,
    VOS_VOID                           *pPara
)
{
    VOS_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;
    VOS_UINT16                          usNameLength = 0;
    TAF_PH_NETWORKNAME_STRU             stCops;
    AT_MODEM_NET_CTX_STRU              *pstNetCtx = VOS_NULL_PTR;

    pstNetCtx = AT_GetModemNetCtxAddrFromClientId(ucIndex);

    TAF_MEM_SET_S(&stCops, sizeof(stCops), 0x00, sizeof(TAF_PH_NETWORKNAME_STRU));

    TAF_MEM_CPY_S(&stCops, sizeof(stCops), pPara, sizeof(TAF_PH_NETWORKNAME_STRU));

    /* A32D07158
     * +COPS: <mode>[,<format>,<oper>[,<AcT>]], get the PLMN selection mode from msg sent by MMA
     */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s: %d",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                       stCops.PlmnSelMode);

    if (VOS_FALSE == AT_PH_IsPlmnValid(&(stCops.Name.PlmnId)))
    {
        /* ???? PLMNId ?????? sel mode */
        ulResult = AT_OK;
        gstAtSendData.usBufLen = usLength;
        At_FormatResultData(ucIndex,ulResult);
        return;
    }

    /* <format> */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       ",%d",
                                       pstNetCtx->ucCopsFormatType);

    /* <oper> */
    switch (pstNetCtx->ucCopsFormatType)
    {
        /* ?????????????????? */
        case AT_COPS_LONG_ALPH_TYPE:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                               ",\"");

            /*????????SPN??????0x00??????????????,??????????????,At_sprintf??0x00??????????????????PS_MEM_CPY????*/
            usNameLength = AT_GetOperNameLengthForCops(stCops.Name.aucOperatorNameLong, TAF_PH_OPER_NAME_LONG);

            TAF_MEM_CPY_S(pgucAtSndCodeAddr + usLength,
                AT_CMD_MAX_LEN + 20 - 3 - usLength,
                stCops.Name.aucOperatorNameLong,
                usNameLength);

            usLength = usLength + usNameLength;
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "\"");
            break;

       /* ?????????????????? */
        case AT_COPS_SHORT_ALPH_TYPE:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                               ",\"");

            /*????????SPN??????0x00??????????????,??????????????,At_sprintf??0x00??????????????????PS_MEM_CPY????*/
            usNameLength = AT_GetOperNameLengthForCops(stCops.Name.aucOperatorNameShort, TAF_PH_OPER_NAME_SHORT);

            TAF_MEM_CPY_S(pgucAtSndCodeAddr + usLength,
                AT_CMD_MAX_LEN + 20 - 3 - usLength,
                stCops.Name.aucOperatorNameShort,
                usNameLength);

            usLength = usLength + usNameLength;
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "\"");
            break;

        /* BCD????MCC??MNC?????????????????? */
        default:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                               ",\"%X%X%X",
                                               (0x0f00 & stCops.Name.PlmnId.Mcc) >> 8,
                                               (0x00f0 & stCops.Name.PlmnId.Mcc) >> 4,
                                               (0x000f & stCops.Name.PlmnId.Mcc));

            if( 0x0F != ((0x0f00 & stCops.Name.PlmnId.Mnc) >> 8))
            {
                usLength +=(VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                  (VOS_CHAR *)pgucAtSndCodeAddr,
                                                  (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                  "%X",
                                                  (0x0f00 & stCops.Name.PlmnId.Mnc) >> 8);
            }

            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%X%X\"",
                                               (0x00f0 & stCops.Name.PlmnId.Mnc) >> 4,
                                               (0x000f & stCops.Name.PlmnId.Mnc));
            break;
    }

    /* <AcT> */
    if(TAF_PH_RA_GSM == stCops.RaMode)  /* GSM */
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           ",0");
    }
    else if(TAF_PH_RA_WCDMA == stCops.RaMode)   /* CDMA */
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           ",2");
    }
    else if(TAF_PH_RA_LTE == stCops.RaMode)   /* LTE */
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           ",7");
    }
    else
    {

    }

    ulResult = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex, ulResult);

}

TAF_VOID At_QryParaRspCellRoamProc(
    TAF_UINT8                           ucIndex,
    TAF_UINT8                           OpId,
    TAF_VOID                            *pPara
)
{
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;

    TAF_PH_CELLROAM_STRU                stCellRoam;

    TAF_MEM_SET_S(&stCellRoam, sizeof(stCellRoam), 0x00, sizeof(TAF_PH_CELLROAM_STRU));

    TAF_MEM_CPY_S(&stCellRoam, sizeof(stCellRoam), pPara, sizeof(TAF_PH_CELLROAM_STRU));

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,
        "%s:%d,%d",g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                 stCellRoam.RoamMode,
                 stCellRoam.RaMode);

    ulResult = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);

}


TAF_VOID At_QryParaRspSysinfoProc(
    TAF_UINT8                           ucIndex,
    TAF_UINT8                           OpId,
    TAF_VOID                            *pPara
)
{
    VOS_UINT32                          ulResult;
    VOS_UINT16                          usLength;
    TAF_PH_SYSINFO_STRU                 stSysInfo;
    VOS_UINT8                          *pucSystemAppConfig = VOS_NULL_PTR;

    pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

    ulResult                            = AT_FAILURE;
    usLength                            = 0;

    TAF_MEM_SET_S(&stSysInfo, sizeof(stSysInfo), 0x00, sizeof(TAF_PH_SYSINFO_STRU));

    TAF_MEM_CPY_S(&stSysInfo, sizeof(stSysInfo), pPara, sizeof(TAF_PH_SYSINFO_STRU));
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s:%d",g_stParseContext[ucIndex].pstCmdElement->pszCmdName,stSysInfo.ucSrvStatus);
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",stSysInfo.ucSrvDomain);
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",stSysInfo.ucRoamStatus);
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",stSysInfo.ucSysMode);
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",stSysInfo.ucSimStatus);

    if ( SYSTEM_APP_WEBUI == *pucSystemAppConfig)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",stSysInfo.ucSimLockStatus);
    }
    else
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",");
    }

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",stSysInfo.ucSysSubMode);

    ulResult = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);

}


VOS_VOID At_QryMmPlmnInfoRspProc(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                           OpId,
    VOS_VOID                           *pPara
)
{
    TAF_MMA_MM_INFO_PLMN_NAME_STRU     *pstPlmnName = VOS_NULL_PTR;
    VOS_UINT32                          ulResult;
    VOS_UINT16                          usLength;
    VOS_UINT8                           i;

    /* ?????????? */
    pstPlmnName = (TAF_MMA_MM_INFO_PLMN_NAME_STRU *)pPara;
    ulResult    = AT_ERROR;

    /* ????LongName??ShortName */
    if ( pstPlmnName->ucLongNameLen <= TAF_PH_OPER_NAME_LONG
      && pstPlmnName->ucShortNameLen <= TAF_PH_OPER_NAME_SHORT )
    {

        /* ^MMPLMNINFO:<long name>,<short name> */
        usLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                          (VOS_CHAR *)pgucAtSndCodeAddr,
                                          (VOS_CHAR *)pgucAtSndCodeAddr,
                                          "%s:",
                                          g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

        for (i = 0; i < pstPlmnName->ucLongNameLen; i++)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%02X",
                                               pstPlmnName->aucLongName[i]);
        }

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR *)pgucAtSndCodeAddr, (VOS_CHAR *)pgucAtSndCodeAddr + usLength, ",");

        for (i = 0; i < pstPlmnName->ucShortNameLen; i++)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%02X",
                                               pstPlmnName->aucShortName[i]);
        }

        ulResult = AT_OK;
        gstAtSendData.usBufLen = usLength;
    }
    else
    {
        gstAtSendData.usBufLen = 0;
    }

    At_FormatResultData(ucIndex,ulResult);

    return;
}

/*****************************************************************************
 Prototype      : At_QryParaRspCimiProc
 Description    : ????????????Cimi??????????
 Input          : usClientId --- ????ID
                  OpId       --- ????ID
                  QueryType  --- ????????
                  pPara      --- ????
 Output         :
 Return Value   : ---
 Calls          : ---
 Called By      : ---

 History        : ---
  1.Date        : 2005-04-19
    Author      : ---
    Modification: Created function
*****************************************************************************/
TAF_VOID At_QryParaRspCimiProc(
    TAF_UINT8                           ucIndex,
    TAF_UINT8                           OpId,
    TAF_VOID                            *pPara
)
{
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;

    TAF_PH_IMSI_STRU                    stCimi;

    TAF_MEM_CPY_S(&stCimi, sizeof(stCimi), pPara, sizeof(TAF_PH_IMSI_STRU));
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s",stCimi.aucImsi);

    ulResult = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);

}


TAF_VOID At_QryParaRspCgclassProc(
    TAF_UINT8                           ucIndex,
    TAF_UINT8                           OpId,
    TAF_VOID                            *pPara
)
{
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;

    TAF_PH_MS_CLASS_TYPE                stCgclass;

    stCgclass = TAF_PH_MS_CLASS_NULL;

    TAF_MEM_CPY_S(&stCgclass, sizeof(stCgclass), pPara, sizeof(TAF_PH_MS_CLASS_TYPE));
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
    if(TAF_PH_MS_CLASS_A == stCgclass)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"A\"");
    }
    else if(TAF_PH_MS_CLASS_B == stCgclass)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"B\"");
    }
    else if(TAF_PH_MS_CLASS_CG == stCgclass)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"CG\"");
    }
    else
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"CC\"");
    }

    ulResult = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);

}


VOS_VOID At_QryParaRspCregProc(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                           OpId,
    VOS_VOID                           *pPara
)
{
    VOS_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;

    TAF_PH_REG_STATE_STRU               stCreg;
    AT_MODEM_NET_CTX_STRU              *pstNetCtx = VOS_NULL_PTR;

    pstNetCtx = AT_GetModemNetCtxAddrFromClientId(ucIndex);

    TAF_MEM_SET_S(&stCreg, sizeof(stCreg), 0x00, sizeof(TAF_PH_REG_STATE_STRU));

    TAF_MEM_CPY_S(&stCreg, sizeof(stCreg), pPara, sizeof(TAF_PH_REG_STATE_STRU));

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s: %d",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                       (VOS_UINT32)pstNetCtx->ucCregType);

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       ",%d",
                                       stCreg.RegState);

    if ((AT_CREG_RESULT_CODE_ENTIRE_TYPE == pstNetCtx->ucCregType)
     && ((TAF_PH_REG_REGISTERED_HOME_NETWORK == stCreg.RegState)
      || (TAF_PH_REG_REGISTERED_ROAM == stCreg.RegState)))
    {
        usLength += (VOS_UINT16)At_PhReadCreg(&stCreg, pgucAtSndCodeAddr + usLength);
    }

    ulResult = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);

    return;
}


VOS_VOID At_QryParaRspCgregProc(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                           OpId,
    VOS_VOID                           *pPara
)
{
    VOS_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;

    TAF_PH_REG_STATE_STRU               stCgreg;
    AT_MODEM_NET_CTX_STRU              *pstNetCtx = VOS_NULL_PTR;

    pstNetCtx = AT_GetModemNetCtxAddrFromClientId(ucIndex);

    TAF_MEM_SET_S(&stCgreg, sizeof(stCgreg), 0x00, sizeof(TAF_PH_REG_STATE_STRU));

    TAF_MEM_CPY_S(&stCgreg, sizeof(stCgreg), pPara, sizeof(TAF_PH_REG_STATE_STRU));


    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s: %d",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                       (VOS_UINT32)pstNetCtx->ucCgregType);

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       ",%d",
                                       stCgreg.ucPsRegState);

    if ((AT_CGREG_RESULT_CODE_ENTIRE_TYPE == pstNetCtx->ucCgregType)
     && ((TAF_PH_REG_REGISTERED_HOME_NETWORK == stCgreg.ucPsRegState)
      || (TAF_PH_REG_REGISTERED_ROAM == stCgreg.ucPsRegState)))
    {
        usLength += (VOS_UINT16)At_PhReadCreg(&stCgreg, pgucAtSndCodeAddr + usLength);
    }

    ulResult = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);

    return;
}


VOS_VOID AT_QryParaRspCeregProc(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                           ucOpId,
    VOS_VOID                           *pPara
)
{
    VOS_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;

    TAF_PH_REG_STATE_STRU               stCereg;
    AT_MODEM_NET_CTX_STRU              *pstNetCtx = VOS_NULL_PTR;

    pstNetCtx = AT_GetModemNetCtxAddrFromClientId(ucIndex);

    TAF_MEM_SET_S(&stCereg, sizeof(stCereg), 0x00, sizeof(TAF_PH_REG_STATE_STRU));

    TAF_MEM_CPY_S(&stCereg, sizeof(stCereg), pPara, sizeof(TAF_PH_REG_STATE_STRU));

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,"%s: %d",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                       (VOS_UINT32)pstNetCtx->ucCeregType);

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,",%d",
                                       stCereg.ucPsRegState);

    /* ????????????????GU????????????stat */
    if ((AT_CEREG_RESULT_CODE_ENTIRE_TYPE == pstNetCtx->ucCeregType)
     && (TAF_PH_ACCESS_TECH_E_UTRAN == stCereg.ucAct)
     && ((TAF_PH_REG_REGISTERED_HOME_NETWORK == stCereg.ucPsRegState)
      || (TAF_PH_REG_REGISTERED_ROAM == stCereg.ucPsRegState)))
    {

        usLength += (VOS_UINT16)At_PhReadCreg(&stCereg, pgucAtSndCodeAddr + usLength);

    }

    ulResult               = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex, ulResult);

    return;
}




TAF_VOID At_QryParaRspIccidProc(
    TAF_UINT8                           ucIndex,
    TAF_UINT8                           OpId,
    TAF_VOID                           *pPara
)
{
    TAF_UINT32                          ulResult;
    TAF_UINT16                          usLength;
    TAF_PH_ICC_ID_STRU                  stIccId;

    if (AT_CMD_ICCID_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return;
    }

    usLength = 0;
    TAF_MEM_SET_S(&stIccId, sizeof(stIccId), 0x00, sizeof(TAF_PH_ICC_ID_STRU));
    TAF_MEM_CPY_S(&stIccId, sizeof(stIccId), pPara, sizeof(TAF_PH_ICC_ID_STRU));

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s: ",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

    usLength += (VOS_UINT16)AT_Hex2AsciiStrLowHalfFirst(AT_CMD_MAX_LEN,
                                                        (VOS_INT8 *)pgucAtSndCodeAddr,
                                                        (VOS_UINT8 *)pgucAtSndCodeAddr + usLength,
                                                        stIccId.aucIccId,
                                                        stIccId.ucLen);

    ulResult = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex, ulResult);

    return;
}


TAF_VOID At_QryRspUsimRangeProc(
    TAF_UINT8                           ucIndex,
    TAF_UINT8                           OpId,
    TAF_VOID                            *pPara
)
{
    TAF_PH_QRY_USIM_RANGE_INFO_STRU     *pstUsimRangeInfo;
    TAF_UINT16                          usLength = 0;
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT8                           ucSimValue;
    VOS_BOOL                            bUsimInfoPrinted = VOS_FALSE;

    pstUsimRangeInfo = (TAF_PH_QRY_USIM_RANGE_INFO_STRU*)pPara;
    if((pstUsimRangeInfo->stUsimInfo.bFileExist == VOS_TRUE)
    && (TAF_PH_ICC_USIM == pstUsimRangeInfo->stUsimInfo.Icctype))
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s:",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        ucSimValue = 1;
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                          (TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%d,(1,%d),%d",
                                           ucSimValue,
                                           pstUsimRangeInfo->stUsimInfo.ulTotalRecNum,
                                           pstUsimRangeInfo->stUsimInfo.ulRecordLen);
        bUsimInfoPrinted = VOS_TRUE;
    }
    if ((pstUsimRangeInfo->stSimInfo.bFileExist == VOS_TRUE)
     && (TAF_PH_ICC_SIM == pstUsimRangeInfo->stSimInfo.Icctype))
    {
        if (VOS_TRUE == bUsimInfoPrinted)
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        }
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s:",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        ucSimValue = 0;
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                          (TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%d,(1,%d),%d",
                                           ucSimValue,
                                           pstUsimRangeInfo->stSimInfo.ulTotalRecNum,
                                           pstUsimRangeInfo->stSimInfo.ulRecordLen);

    }
    ulResult = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);

}

TAF_VOID At_QryParaRspPnnProc(
    TAF_UINT8                           ucIndex,
    TAF_UINT8                           OpId,
    TAF_VOID                            *pPara
)
{
    TAF_UINT16                          usLength = 0;

    TAF_PH_USIM_PNN_CNF_STRU            *pstPNN;
    TAF_UINT8                           FullNameLen;
    TAF_UINT8                           ShortNameLen;
    TAF_UINT8                           ucTag;
    TAF_UINT8                           ucFirstByte;
    VOS_UINT8                           ucPnnOperNameLen;
    TAF_UINT32                          i;
    TAF_UINT32                          ulRet;
    TAF_PH_QRY_USIM_INFO_STRU           stUsimInfo;

    TAF_MEM_SET_S(&stUsimInfo, sizeof(stUsimInfo), 0x00, sizeof(stUsimInfo));

    pstPNN     = (TAF_PH_USIM_PNN_CNF_STRU*)pPara;


    /* ????PNN???????????????? */
    for (i = 0 ; i < pstPNN->TotalRecordNum; i++)
    {
        FullNameLen = 0;
        ShortNameLen = 0;

        FullNameLen = pstPNN->PNNRecord[i].stOperNameLong.ucLength;

        if (0 == FullNameLen)
        {
            continue;
        }
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s:",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

        /* ????????,????????TAG,?????????????? */
        usLength        += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"");
        ucTag            = FULL_NAME_IEI;
        usLength        += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,&ucTag,1);
        ucPnnOperNameLen = pstPNN->PNNRecord[i].stOperNameLong.ucLength+1;
        usLength        += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,&ucPnnOperNameLen,1);
        ucFirstByte      = (TAF_UINT8)((pstPNN->PNNRecord[i].stOperNameLong.bitExt    << 7)
                                 | (pstPNN->PNNRecord[i].stOperNameLong.bitCoding << 4)
                                 | (pstPNN->PNNRecord[i].stOperNameLong.bitAddCi  << 3)
                                 | (pstPNN->PNNRecord[i].stOperNameLong.bitSpare));
        usLength    += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,&ucFirstByte,1);
        usLength    += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,pstPNN->PNNRecord[i].stOperNameLong.aucOperatorName,FullNameLen);
        usLength    += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"");

        ShortNameLen = pstPNN->PNNRecord[i].stOperNameShort.ucLength;

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",");
        if (0 != ShortNameLen)
        {
            ucTag     = SHORT_NAME_IEI;
            /* ????????,????????TAG,?????????????? */
            usLength        += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"");
            usLength        += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,&ucTag,1);
            ucPnnOperNameLen = pstPNN->PNNRecord[i].stOperNameShort.ucLength + 1;
            usLength        += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,&ucPnnOperNameLen,1);
            ucFirstByte      = (TAF_UINT8)((pstPNN->PNNRecord[i].stOperNameShort.bitExt    << 7)
                                     | (pstPNN->PNNRecord[i].stOperNameShort.bitCoding << 4)
                                     | (pstPNN->PNNRecord[i].stOperNameShort.bitAddCi  << 3)
                                     | (pstPNN->PNNRecord[i].stOperNameShort.bitSpare));
            usLength        += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,&ucFirstByte,1);
            usLength        += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,pstPNN->PNNRecord[i].stOperNameShort.aucOperatorName,ShortNameLen);
            usLength        += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"");
        }
        else
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"\"");
        }

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",");


        if (0 != pstPNN->PNNRecord[i].ucPlmnAdditionalInfoLen)
        {
            /* PNN??????????,????????tag?????? */
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"");
            ucTag     = PLMN_ADDITIONAL_INFO_IEI;
            usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,&ucTag,1);
            usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,&pstPNN->PNNRecord[i].ucPlmnAdditionalInfoLen,1);
            usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,pstPNN->PNNRecord[i].aucPlmnAdditionalInfo,pstPNN->PNNRecord[i].ucPlmnAdditionalInfoLen);
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"");
        }
        else
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"\"");
        }
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);

        At_BufferorSendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
        usLength = 0;

    }

    /* ??????????????PNN????????????????????????C??????PNN???????????????????????????????? */
    if (TAF_MMA_PNN_INFO_MAX_NUM == pstPNN->TotalRecordNum)
    {
        stUsimInfo.ulRecNum                     = 0;
        stUsimInfo.enEfId                       = TAF_PH_PNN_FILE;
        stUsimInfo.Icctype                      = pstPNN->Icctype;
        stUsimInfo.stPnnQryIndex.usPnnNum       = TAF_MMA_PNN_INFO_MAX_NUM;
        stUsimInfo.stPnnQryIndex.usPnnCurrIndex = pstPNN->usPnnCurrIndex + TAF_MMA_PNN_INFO_MAX_NUM;

        ulRet = MN_FillAndSndAppReqMsg(gastAtClientTab[ucIndex].usClientId,
                                       0,
                                       TAF_MSG_MMA_USIM_INFO,
                                       &stUsimInfo,
                                       sizeof(TAF_PH_QRY_USIM_INFO_STRU),
                                       I0_WUEPS_PID_MMA);

        if (TAF_SUCCESS != ulRet)
        {
            /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
            AT_STOP_TIMER_CMD_READY(ucIndex);
            gstAtSendData.usBufLen = 0;
            At_FormatResultData(ucIndex, AT_ERROR);
        }
    }
    else
    {
        /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
        AT_STOP_TIMER_CMD_READY(ucIndex);
        gstAtSendData.usBufLen = 0;
        At_FormatResultData(ucIndex, AT_OK);
    }

}

TAF_VOID At_QryParaRspCPnnProc(
    TAF_UINT8                           ucIndex,
    TAF_UINT8                           OpId,
    TAF_VOID                            *pPara
)
{
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;
    TAF_UINT8                           ucCodingScheme;
    TAF_PH_USIM_PNN_CNF_STRU            *pstPNN;
    TAF_UINT8                           FullNameLen;
    TAF_UINT8                           ShortNameLen;
    TAF_UINT8                           ucTag;

    pstPNN     = (TAF_PH_USIM_PNN_CNF_STRU*)pPara;

    if (0 != pstPNN->TotalRecordNum)
    {
        FullNameLen = 0;
        ShortNameLen = 0;

        FullNameLen = pstPNN->PNNRecord[0].stOperNameLong.ucLength;

        if (0 != FullNameLen)
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s:",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

            /*????????*/
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"");
            ucTag = FULL_NAME_IEI;
            usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,&ucTag,1);
            usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,pstPNN->PNNRecord[0].stOperNameLong.aucOperatorName,FullNameLen);
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"");

            ucCodingScheme = pstPNN->PNNRecord[0].stOperNameLong.bitCoding;
            if (0 != pstPNN->PNNRecord[0].stOperNameLong.bitCoding)
            {
                ucCodingScheme = 1;
            }

            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d,%d",
                                                ucCodingScheme,pstPNN->PNNRecord[0].stOperNameLong.bitAddCi);

            ShortNameLen = pstPNN->PNNRecord[0].stOperNameShort.ucLength;

            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",");

            if (0 != ShortNameLen)
            {
                /*????????*/
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"");
                usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,pstPNN->PNNRecord[0].stOperNameShort.aucOperatorName,ShortNameLen);
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"");

                ucCodingScheme = pstPNN->PNNRecord[0].stOperNameShort.bitCoding;
                if (0 != ucCodingScheme)
                {
                    ucCodingScheme = 1;
                }

                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d,%d",
                                    ucCodingScheme,pstPNN->PNNRecord[0].stOperNameShort.bitAddCi);
            }
            else
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"\"\"");

                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",0,0");

            }

        }

    }

    ulResult = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);

}


TAF_UINT8 At_IsOplRecPrintable(
    TAF_PH_USIM_OPL_RECORD             *pstOplRec,
    VOS_CHAR                            cWildCard
)
{
    TAF_UINT32                          i;

    VOS_UINT8                           ucWildCard;

    ucWildCard = 0x00;

    AT_ConvertCharToHex((VOS_UINT8)cWildCard, &ucWildCard);

    if ( 0xFF == pstOplRec->PNNIndex)
    {
        return VOS_FALSE;
    }

    for ( i=0; i < pstOplRec->PlmnLen; i++)
    {
        if ((0xA <= pstOplRec->PLMN[i])
         && (ucWildCard != pstOplRec->PLMN[i]))
        {
            return VOS_FALSE;
        }
    }


    return VOS_TRUE;

}

/*****************************************************************************
 Prototype      : At_QryParaRspOplProc
 Description    : ????????????Opl??????????
 Input          : usClientId --- ????ID
                  OpId       --- ????ID
                  QueryType  --- ????????
                  pPara      --- ????
 Output         :
 Return Value   : ---
 Calls          : ---
 Called By      : ---

 History        : ---
  1.Date        : 2005-04-19
    Author      : ---
    Modification: Created function
*****************************************************************************/
TAF_VOID At_QryParaRspOplProc(
    TAF_UINT8                           ucIndex,
    TAF_UINT8                           OpId,
    TAF_VOID                            *pPara
)
{
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;
    TAF_UINT32                          i;
    TAF_UINT32                          j;
    TAF_PH_USIM_OPL_CNF_STRU            *pstOPL;
    TAF_UINT32                          ucRecCntPrinted = 0;

    pstOPL     = (TAF_PH_USIM_OPL_CNF_STRU*)pPara;

    /* ????PNN???????????????? */
    for(i = 0 ; i <  pstOPL->TotalRecordNum; i++)
    {
        if ( VOS_FALSE == At_IsOplRecPrintable((pstOPL->OPLRecord+i),pstOPL->cWildCard))
        {
            continue;
        }
        if(0 != ucRecCntPrinted)
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        }

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s:",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        for(j = 0 ; j < pstOPL->OPLRecord[i].PlmnLen; j++)
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%X",pstOPL->OPLRecord[i].PLMN[j]);
        }
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",0x%X-0x%X,%d",pstOPL->OPLRecord[i].LACLow, pstOPL->OPLRecord[i].LACHigh, pstOPL->OPLRecord[i].PNNIndex);

        ++ ucRecCntPrinted;
    }


    ulResult = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);

}


TAF_VOID At_QryParaRspCfplmnProc(
    TAF_UINT8                           ucIndex,
    TAF_UINT8                           OpId,
    TAF_VOID                            *pPara
)
{
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;
    TAF_USER_PLMN_LIST_STRU             *pstUserPlmnList;
    TAF_UINT32                          i;

    pstUserPlmnList = (TAF_USER_PLMN_LIST_STRU*) pPara;

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s: %d",g_stParseContext[ucIndex].pstCmdElement->pszCmdName,pstUserPlmnList->usPlmnNum);
    for ( i = 0 ; i < pstUserPlmnList->usPlmnNum; i++ )
    {

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"%X%X%X",
                     (0x0f00 & pstUserPlmnList->Plmn[i].Mcc) >> 8,
                     (0x00f0 & pstUserPlmnList->Plmn[i].Mcc) >> 4,
                     (0x000f & pstUserPlmnList->Plmn[i].Mcc)
                     );

        if( 0x0f00 == (0x0f00 & pstUserPlmnList->Plmn[i].Mnc))
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%X%X\"",
                     (0x00f0 & pstUserPlmnList->Plmn[i].Mnc) >> 4,
                     (0x000f & pstUserPlmnList->Plmn[i].Mnc)
                     );
        }
        else
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%X%X%X\"",
                     (0x0f00 & pstUserPlmnList->Plmn[i].Mnc) >> 8,
                     (0x00f0 & pstUserPlmnList->Plmn[i].Mnc) >> 4,
                     (0x000f & pstUserPlmnList->Plmn[i].Mnc)
                     );
        }

    }

    ulResult = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);

}






VOS_VOID AT_RcvCdurQryRsp(
    VOS_UINT8                           ucIndex,
    MN_CALL_EVENT_ENUM_U32              enEvent,
    MN_CALL_INFO_STRU                  *pstCallInfo
)
{
    VOS_UINT32                          ulResult;

    /* AT??????????CDUR?????????????????????? */
    if (AT_CMD_CDUR_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return;
    }

    ulResult = AT_OK;

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    if (TAF_CS_CAUSE_SUCCESS == pstCallInfo->enCause)
    {
        /* ????????????: ??????????^CDUR: <CurCallTime>???? */
        gstAtSendData.usBufLen = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (TAF_CHAR *)pgucAtSndCodeAddr,
                                                        (TAF_CHAR *)pgucAtSndCodeAddr,
                                                        "%s:%d,%d",
                                                         g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                         pstCallInfo->callId,
                                                         pstCallInfo->ulCurCallTime);

        ulResult = AT_OK;

    }
    else
    {
        ulResult = AT_ConvertCallError(pstCallInfo->enCause);

        /* ????At_FormatResultData???????? */
        gstAtSendData.usBufLen = 0;
    }

    At_FormatResultData(ucIndex, ulResult);

    return;
}


VOS_UINT32 AT_RcvDrvAgentTseLrfSetRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    VOS_UINT8                           ucIndex;
    DRV_AGENT_TSELRF_SET_CNF_STRU      *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_TSELRF_SET_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentTseLrfSetRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentTseLrfSetRsp : AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????TSELRF?????????????????????? */
    if (AT_CMD_TSELRF_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    gstAtSendData.usBufLen = 0;
    if (DRV_AGENT_TSELRF_SET_NO_ERROR == pstEvent->enResult)
    {
        /* ????????????AT_OK */
        ulRet                            = AT_OK;
        g_stAtDevCmdCtrl.bDspLoadFlag    = VOS_TRUE;
        g_stAtDevCmdCtrl.ucDeviceRatMode = pstEvent->ucDeviceRatMode;
        g_stAtDevCmdCtrl.usFDAC          = 0;

    }
    else
    {
        /* ????????????ERROR?????? */
        ulRet                            = AT_ERROR;
    }

    /* 4. ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);
    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentHkAdcGetRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    VOS_UINT8                           ucIndex;
    DRV_AGENT_HKADC_GET_CNF_STRU      *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_HKADC_GET_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentTseLrfSetRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentTseLrfSetRsp : AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????HKADC?????????????????????????? */
    if (AT_CMD_TBAT_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    gstAtSendData.usBufLen = 0;
    if (DRV_AGENT_HKADC_GET_NO_ERROR == pstEvent->enResult)
    {
        /* ????????????AT_OK */
        gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        "%s:1,%d",
                                                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                        pstEvent->TbatHkadc);

        ulRet                            = AT_OK;

    }
    else
    {
        /* ????????????ERROR?????? */
        ulRet                            = AT_ERROR;
    }

    /* 4. ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);
    return VOS_OK;
}



VOS_UINT32 AT_RcvDrvAgentAppdmverQryRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    VOS_UINT8                           ucIndex;
    DRV_AGENT_APPDMVER_QRY_CNF_STRU    *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_APPDMVER_QRY_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentAppdmverQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentAppdmverQryRsp : AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????APPDMVER?????????????????????? */
    if (AT_CMD_APPDMVER_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    if (DRV_AGENT_APPDMVER_QRY_NO_ERROR == pstEvent->enResult)
    {
        /* ????????????AT_OK           ??????????^APPDMVER:<pdmver>???? */
        ulRet                  = AT_OK;
        gstAtSendData.usBufLen = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (TAF_CHAR *)pgucAtSndCodeAddr,
                                                        (TAF_CHAR*)pgucAtSndCodeAddr,
                                                        "%s:%s",
                                                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                        pstEvent->acPdmver);

    }
    else
    {
        /* ????????????ERROR?????? */
        ulRet                  = AT_ERROR;
        gstAtSendData.usBufLen = 0;
    }

    /* 4. ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);
    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentDloadverQryRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    VOS_UINT8                           ucIndex;
    DRV_AGENT_DLOADVER_QRY_CNF_STRU    *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_DLOADVER_QRY_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentDloadverQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentDloadverQryRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????APPDMVER?????????????????????? */
    if (AT_CMD_DLOADVER_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    if (DRV_AGENT_DLOADVER_QRY_NO_ERROR == pstEvent->enResult)
    {
        /* ????????????AT_OK           ??????????<dloadver>???? */
        ulRet                  = AT_OK;
        gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        "%s",
                                                        pstEvent->aucVersionInfo);
    }
    else
    {
        /* ????????????ERROR?????? */
        ulRet                  = AT_ERROR;
        gstAtSendData.usBufLen = 0;
    }

    /* ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);
    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentAuthVerQryRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    VOS_UINT8                           ucIndex;
    DRV_AGENT_AUTHVER_QRY_CNF_STRU     *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_AUTHVER_QRY_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentAuthVerQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentAuthVerQryRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????AUTHVER?????????????????????? */
    if (AT_CMD_AUTHVER_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    if (DRV_AGENT_AUTHVER_QRY_NO_ERROR == pstEvent->enResult)
    {
        /* ????????????AT_OK           ??????????<CR><LF>^ AUTHVER: <value> <CR><LF>
             <CR><LF>OK<CR><LF>???? */
        ulRet                  = AT_OK;
        gstAtSendData.usBufLen = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (TAF_CHAR *)pgucAtSndCodeAddr,
                                                        (TAF_CHAR*)pgucAtSndCodeAddr,
                                                        "%s:%d",
                                                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                        pstEvent->ulSimLockVersion);

    }
    else
    {
        /* ????????????ERROR?????? */
        ulRet                  = AT_ERROR;
        gstAtSendData.usBufLen = 0;
    }

    /* ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);
    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentFlashInfoQryRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    VOS_UINT8                           ucIndex;
    VOS_UINT16                          usLength;
    DRV_AGENT_FLASHINFO_QRY_CNF_STRU   *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_FLASHINFO_QRY_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentFlashInfoQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentFlashInfoQryRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????^FLASHINFO?????????????????????? */
    if (AT_CMD_FLASHINFO_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    if (DRV_AGENT_FLASHINFO_QRY_NO_ERROR == pstEvent->enResult)
    {
        /* ????????????AT_OK
               ??????????<CR><LF>~~~~~~FLASH INFO~~~~~~:<CR><LF>
                <CR><LF>MMC BLOCK COUNT:<blockcount>,
                     PAGE SIZE:<pagesize>,
                     PAGE COUNT PER BLOCK:<blocksize><CR><LF>
                <CR><LF>OK<CR><LF>???? */
        usLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           "%s%s",
                                           "~~~~~~FLASH INFO~~~~~~:",
                                            gaucAtCrLf);

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "MMC BLOCK COUNT:%d, PAGE SIZE:%d, PAGE COUNT PER BLOCK:%d",
                                            pstEvent->stFlashInfo.ulBlockCount,
                                            pstEvent->stFlashInfo.ulPageSize,
                                            pstEvent->stFlashInfo.ulPgCntPerBlk);

        ulRet     = AT_OK;

    }
    else
    {
        /* ????????????ERROR?????? */
        usLength  = 0;
        ulRet     = AT_ERROR;
    }

    /* ????At_FormatResultData???????? */
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex, ulRet);
    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentDloadInfoQryRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    VOS_UINT8                           ucIndex;
    DRV_AGENT_DLOADINFO_QRY_CNF_STRU   *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_DLOADINFO_QRY_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentDloadInfoQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentDloadInfoQryRsp : AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????DLOADINFO?????????????????????? */
    if (AT_CMD_DLOADINFO_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    if (DRV_AGENT_DLOADINFO_QRY_NO_ERROR == pstEvent->enResult)
    {
        /* ????????????AT_OK
               ??????????^DLOADINFO:<CR><LF>
             <CR><LF>swver:<software version><CR><LF>
             <CR><LF>isover:<iso version><CR><LF>
             <CR><LF>product name:<product name><CR><LF>
             <CR><LF>product name:<WebUiVer><CR><LF>
             <CR><LF>dload type: <dload type><CR><LF>
             <CR><LF>OK<CR><LF>???? */
        ulRet                  = AT_OK;
        gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        (VOS_CHAR*)pgucAtSndCodeAddr,
                                                        "%s",
                                                        pstEvent->aucDlodInfo);

    }
    else
    {
        /* ????????????ERROR?????? */
        ulRet                  = AT_ERROR;
        gstAtSendData.usBufLen = 0;
    }

    /* ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);
    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentHwnatQryRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    VOS_UINT8                           ucIndex;
    DRV_AGENT_HWNATQRY_QRY_CNF_STRU     *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_HWNATQRY_QRY_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentHwnatQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentHwnatQryRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????HWNAT?????????????????????? */
    if (AT_CMD_HWNATQRY_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    if (DRV_AGENT_HWNATQRY_QRY_NO_ERROR == pstEvent->enResult)
    {
        /* ????????????AT_OK
           ??????????^HWNATQRY: <cur_mode> ???? */
        ulRet                  = AT_OK;
        gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (TAF_CHAR *)pgucAtSndCodeAddr,
                                                        (TAF_CHAR *)pgucAtSndCodeAddr,
                                                        "%s:%d",
                                                         g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                         pstEvent->ulNetMode);
    }
    else
    {
        /* ????????????ERROR?????? */
        ulRet                  = AT_ERROR;
        gstAtSendData.usBufLen = 0;
    }

    /* ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);
    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentAuthorityVerQryRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                           ulRet;
    VOS_UINT8                            ucIndex;
    DRV_AGENT_AUTHORITYVER_QRY_CNF_STRU *pstEvent;
    DRV_AGENT_MSG_STRU                  *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_AUTHORITYVER_QRY_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentAuthorityVerQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentAuthorityVerQryRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????AUTHORITYVER?????????????????????? */
    if (AT_CMD_AUTHORITYVER_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? :  */
    if (DRV_AGENT_AUTHORITYVER_QRY_NO_ERROR == pstEvent->enResult)
    {
        /* ????????????AT_OK ??????<CR><LF><Authority Version><CR><LF>
             <CR><LF>OK<CR><LF> */
        gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        "%s",
                                                        pstEvent->aucAuthority);

        ulRet = AT_OK;
    }
    else
    {
        /* ????????????ERROR?????? */
        gstAtSendData.usBufLen = 0;
        ulRet                  = AT_ERROR;
    }

    /* ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);

    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentAuthorityIdQryRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    VOS_UINT8                           ucIndex;
    DRV_AGENT_AUTHORITYID_QRY_CNF_STRU *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_AUTHORITYID_QRY_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentAuthorityIdQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentAuthorityIdQryRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????AUTHORITYID?????????????????????? */
    if (AT_CMD_AUTHORITYID_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? :  */
    if (DRV_AGENT_AUTHORITYID_QRY_NO_ERROR == pstEvent->enResult)
    {
        /* ????????????AT_OK ??????<CR><LF><Authority ID>, <Authority Type><CR><LF>
             <CR><LF>OK<CR><LF> */
        gstAtSendData.usBufLen  = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        "%s",
                                                        pstEvent->aucAuthorityId);

        ulRet                   = AT_OK;
    }
    else
    {
        /* ????????????ERROR?????? */
        ulRet                   = AT_ERROR;
        gstAtSendData.usBufLen  = 0;
    }

    /* ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);
    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentPfverQryRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    VOS_UINT8                           ucIndex;
    DRV_AGENT_PFVER_QRY_CNF_STRU       *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_PFVER_QRY_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentPfverQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentPfverQryRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????PFVER?????????????????????? */
    if (AT_CMD_PFVER_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    if (DRV_AGENT_PFVER_QRY_NO_ERROR == pstEvent->enResult)
    {
        /* ????????????AT_OK           ??????????<CR><LF>^PFVER: <PfVer>,<VerTime> <CR><LF>
             <CR><LF>OK<CR><LF>???? */
        ulRet                  = AT_OK;
        gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                          (VOS_CHAR *)pgucAtSndCodeAddr,
                                          (VOS_CHAR *)pgucAtSndCodeAddr,
                                          "%s:\"%s %s\"",
                                          g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                          pstEvent->stPfverInfo.aucPfVer,
                                          pstEvent->stPfverInfo.acVerTime);

    }
    else
    {
        /* ????????????ERROR?????? */
        ulRet                  = AT_ERROR;
        gstAtSendData.usBufLen = 0;
    }

    /* ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);
    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentSdloadSetRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    VOS_UINT8                           ucIndex;
    DRV_AGENT_SDLOAD_SET_CNF_STRU      *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_SDLOAD_SET_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentSdloadSetRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentSdloadSetRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????SDLOAD?????????????????????? */
    if (AT_CMD_SDLOAD_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????????? :  */
    gstAtSendData.usBufLen = 0;
    if (DRV_AGENT_SDLOAD_SET_NO_ERROR == pstEvent->enResult)
    {
        /* ????????????AT_OK */
        ulRet = AT_OK;
    }
    else
    {
        /* ????????????ERROR?????? */
        ulRet = AT_ERROR;
    }

    /* ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);
    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentCpuloadQryRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                          i;
    VOS_UINT16                          usLength;
    VOS_UINT8                           ucIndex;
    DRV_AGENT_CPULOAD_QRY_CNF_STRU     *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    usLength               = 0;
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_CPULOAD_QRY_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentCpuloadQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentCpuloadQryRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????CPULOAD?????????????????????? */
    if (AT_CMD_CPULOAD_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????????? :  */
    gstAtSendData.usBufLen = 0;

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s: ",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

    for ( i = 0; i < pstEvent->ulCurCpuLoadCnt; i++ )
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%u.%02u",
                                           pstEvent->aulCurCpuLoad[i] / 100,
                                           pstEvent->aulCurCpuLoad[i] % 100);

        if ( (pstEvent->ulCurCpuLoadCnt - 1) == i )
        {
            break;
        }

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           ",");
    }

    /* ????At_FormatResultData???????? */
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex, AT_OK);
    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentMfreelocksizeQryRsp(VOS_VOID *pMsg)
{
    VOS_UINT32                                  ulRet;
    VOS_UINT8                                   ucIndex;
    DRV_AGENT_MFREELOCKSIZE_QRY_CNF_STRU       *pstEvent;
    DRV_AGENT_MSG_STRU                         *pstRcvMsg;
    VOS_UINT32                                  ulACoreMemfreeSize;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_MFREELOCKSIZE_QRY_CNF_STRU *)pstRcvMsg->aucContent;
    ulACoreMemfreeSize     = 0;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentMfreelocksizeQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentMfreelocksizeQryRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????MFREELOCKSIZE?????????????????????? */
    if (AT_CMD_MFREELOCKSIZE_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????????? :  */
    gstAtSendData.usBufLen = 0;
    if (DRV_AGENT_MFREELOCKSIZE_QRY_NO_ERROR == pstEvent->enResult)
    {

        /* ????A???????????????? */
        ulACoreMemfreeSize = FREE_MEM_SIZE_GET();


        /* ????????????????KB?????????? */
        ulACoreMemfreeSize *= AT_KB_TO_BYTES_NUM;

        gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (TAF_CHAR *)pgucAtSndCodeAddr,
                                                        (TAF_CHAR*)pgucAtSndCodeAddr,
                                                        "%s:%d,%d",
                                                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                        pstEvent->lMaxFreeLockSize,
                                                        ulACoreMemfreeSize);


        /* ????????????AT_OK */
        ulRet = AT_OK;
    }
    else
    {
        /* ????????????ERROR?????? */
        gstAtSendData.usBufLen = 0;
        ulRet                  = AT_ERROR;
    }

    /* ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);
    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentImsiChgQryRsp(VOS_VOID *pMsg)
{
    VOS_UINT8                           ucIndex;
    DRV_AGENT_IMSICHG_QRY_CNF_STRU     *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_IMSICHG_QRY_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentImsiChgQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentImsiChgQryRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????IMSICHG?????????????????????? */
    if (AT_CMD_IMSICHG_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????????? :  */
    gstAtSendData.usBufLen = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                (TAF_CHAR *)pgucAtSndCodeAddr,
                                                (TAF_CHAR*)pgucAtSndCodeAddr,
                                                "^IMSICHG: %d,%d",
                                                pstEvent->usDualIMSIEnable,
                                                pstEvent->ulCurImsiSign);

    /* ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, AT_OK);

    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentInfoRbuSetRsp(VOS_VOID *pMsg)
{
    VOS_UINT8                           ucIndex;
    DRV_AGENT_INFORBU_SET_CNF_STRU     *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_INFORBU_SET_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentInfoRbuSetRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentInfoRbuSetRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????INFORBU?????????????????????? */
    if (AT_CMD_INFORBU_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????????? :  */
    if (NV_OK == pstEvent->ulRslt)
    {
        At_FormatResultData(ucIndex, AT_OK);
    }
    else
    {
        At_FormatResultData(ucIndex, AT_ERROR);
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentInfoRrsSetRsp(VOS_VOID *pMsg)
{
    VOS_UINT8                           ucIndex;
    DRV_AGENT_INFORRS_SET_CNF_STRU     *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_INFORRS_SET_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        return VOS_ERR;
    }

    /* AT??????????INFORRU?????????????????????? */
    if (AT_CMD_INFORRS_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????????? :  */
    if (NV_OK == pstEvent->ulRslt)
    {
        At_FormatResultData(ucIndex, AT_OK);
    }
    else
    {
        At_FormatResultData(ucIndex, AT_ERROR);
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentCpnnQryRsp(VOS_VOID *pMsg)
{
    VOS_UINT8                           ucIndex;
    DRV_AGENT_CPNN_QRY_CNF_STRU        *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_CPNN_QRY_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentCpnnQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentCpnnQryRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????CPNN?????????????????????? */
    if (AT_CMD_CPNN_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    if ( VOS_TRUE == pstEvent->bNormalSrvStatus )
    {
        At_FormatResultData(ucIndex, AT_OK);
    }
    else
    {
        At_FormatResultData(ucIndex, AT_ERROR);
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentCpnnTestRsp(VOS_VOID *pMsg)
{
    VOS_UINT8                           ucIndex;
    DRV_AGENT_CPNN_TEST_CNF_STRU       *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_CPNN_TEST_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentCpnnTestRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentCpnnTestRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????CPNN?????????????????????? */
    if (AT_CMD_CPNN_TEST != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    if ( ( PS_USIM_SERVICE_AVAILIABLE == pstEvent->ulOplExistFlg )
      && ( PS_USIM_SERVICE_AVAILIABLE == pstEvent->ulPnnExistFlg )
      && ( VOS_TRUE == pstEvent->bNormalSrvStatus ) )
    {
        gstAtSendData.usBufLen = (TAF_UINT16)VOS_sprintf_s((TAF_CHAR*)pgucAtSndCodeAddr,
                                                         AT_CMD_MAX_LEN + 20 - 3,
                                                         "%s:(0,1)",
                                                         g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        At_FormatResultData(ucIndex, AT_OK);
    }
    else
    {
        At_FormatResultData(ucIndex, AT_ERROR);
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentNvBackupSetRsp(VOS_VOID *pMsg)
{
    VOS_UINT8                           ucIndex;
    DRV_AGENT_NVBACKUP_SET_CNF_STRU    *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_NVBACKUP_SET_CNF_STRU *)pstRcvMsg->aucContent;

    AT_PR_LOGI("Rcv Msg");

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentNvBackupSetRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentNvBackupSetRsp: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????NVBACKUP?????????????????????? */
    if (AT_CMD_NVBACKUP_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    if (NV_OK == pstEvent->ulRslt)
    {
        gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        "%d",
                                                        pstEvent->ulRslt);
        At_FormatResultData(ucIndex, AT_OK);
    }
    else
    {
        At_FormatResultData(ucIndex, AT_ERROR);
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvDrvAgentMemInfoQryRsp(VOS_VOID *pMsg)
{
    DRV_AGENT_MSG_STRU                 *pstRcvMsg            = VOS_NULL_PTR;
    VOS_UINT8                           ucIndex;
    DRV_AGENT_MEMINFO_QRY_RSP_STRU     *pstCCpuMemInfoCnfMsg = VOS_NULL_PTR;
    AT_PID_MEM_INFO_PARA_STRU          *pstPidMemInfo        = VOS_NULL_PTR;
    VOS_UINT32                          ulACpuMemBufSize;
    VOS_UINT32                          ulACpuPidTotal;
    VOS_UINT16                          usAtLength;
    VOS_UINT32                          i;

    /* ?????? */
    pstRcvMsg            = (DRV_AGENT_MSG_STRU *)pMsg;
    pstCCpuMemInfoCnfMsg = (DRV_AGENT_MEMINFO_QRY_RSP_STRU *)pstRcvMsg->aucContent;

    /* ????CCPU??????PID?????????? */
    pstPidMemInfo       = (AT_PID_MEM_INFO_PARA_STRU *)pstCCpuMemInfoCnfMsg->aucData;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstCCpuMemInfoCnfMsg->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_ERR_LOG("AT_RcvDrvAgentMemInfoQryRsp: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    /* Client Id ????????????ERROR */
    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_ERR_LOG("AT_RcvDrvAgentMemInfoQryRsp: AT_BROADCAST_INDEX!");
        return VOS_ERR;
    }

    /* AT??????????MEMINFO?????????????????????? */
    if (AT_CMD_MEMINFO_READ != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_ERR_LOG("AT_RcvDrvAgentMemInfoQryRsp: CmdCurrentOpt Error!");
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);


    /* ?????????????????????????? */
    if ( (VOS_OK != pstCCpuMemInfoCnfMsg->ulResult)
      || ( (AT_MEMQUERY_TTF != pstCCpuMemInfoCnfMsg->ulMemQryType)
        && (AT_MEMQUERY_VOS != pstCCpuMemInfoCnfMsg->ulMemQryType) ) )
    {

        /* ????At_FormatResultData????ERROR?????? */
        gstAtSendData.usBufLen = 0;
        At_FormatResultData(ucIndex, AT_ERROR);
        return VOS_OK;
    }

    /* ?????????????? */
    usAtLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                        "%s:%s",
                                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                        gaucAtCrLf);




    usAtLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                         (VOS_CHAR *)pgucAtSndCodeAddr + usAtLength,
                                         "C CPU Pid:%d%s",
                                         pstCCpuMemInfoCnfMsg->ulPidNum,
                                         gaucAtCrLf);

    /* ????????C CPU????PID?????????? */
    for (i = 0; i < pstCCpuMemInfoCnfMsg->ulPidNum; i++)
    {
        usAtLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                             (VOS_CHAR *)pgucAtSndCodeAddr + usAtLength,
                                             "%d,%d,%d%s",
                                             pstPidMemInfo[i].ulPid,
                                             pstPidMemInfo[i].ulMsgPeakSize,
                                             pstPidMemInfo[i].ulMemPeakSize,
                                             gaucAtCrLf);
    }

    /* ??????????VOS??????????????????A CPU??VOS????????????.
       ????????A CPU??TTF??????????????TTF??????????????C CPU??TTF???????????? */
    if (AT_MEMQUERY_VOS == pstCCpuMemInfoCnfMsg->ulMemQryType)
    {
        ulACpuMemBufSize = AT_PID_MEM_INFO_LEN * sizeof(AT_PID_MEM_INFO_PARA_STRU);

        /* ??????????????A CPU??VOS???????????? */
        /*lint -save -e516 */
        pstPidMemInfo = (AT_PID_MEM_INFO_PARA_STRU *)PS_MEM_ALLOC(WUEPS_PID_AT, ulACpuMemBufSize);
        /*lint -restore */
        if (VOS_NULL_PTR != pstPidMemInfo)
        {
            TAF_MEM_SET_S(pstPidMemInfo, ulACpuMemBufSize, 0x00, ulACpuMemBufSize);


            ulACpuPidTotal = 0;

            if (VOS_ERR != VOS_AnalyzePidMemory(pstPidMemInfo, ulACpuMemBufSize, &ulACpuPidTotal))
            {

                /* ???????? A CPU??????PID?????????????? */
                usAtLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                                     (VOS_CHAR *)pgucAtSndCodeAddr + usAtLength,
                                                     "A CPU Pid:%d%s",
                                                     ulACpuPidTotal,
                                                     gaucAtCrLf);

                for (i = 0; i < ulACpuPidTotal; i++)
                {
                    usAtLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                                         (VOS_CHAR *)pgucAtSndCodeAddr + usAtLength,
                                                         "%d,%d,%d%s",
                                                         pstPidMemInfo[i].ulPid,
                                                         pstPidMemInfo[i].ulMsgPeakSize,
                                                         pstPidMemInfo[i].ulMemPeakSize,
                                                         gaucAtCrLf);
                }

            }

            /* ???????? */
            /*lint -save -e516 */
            PS_MEM_FREE(WUEPS_PID_AT, pstPidMemInfo);
            /*lint -restore */
        }
    }

    gstAtSendData.usBufLen = usAtLength;

    /* ????At_FormatResultData????OK?????? */
    At_FormatResultData(ucIndex, AT_OK);

    return VOS_OK;
}


TAF_VOID At_QryParaRspProc  (
    TAF_UINT8                           ucIndex,
    TAF_UINT8                           OpId,
    TAF_PARA_TYPE                       QueryType,
    TAF_UINT16                          usErrorCode,
    TAF_VOID                            *pPara
)
{

    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;
    TAF_UINT16                          ucTmp;
    TAF_UINT8                           i;

    if(0 != usErrorCode)  /* ???? */
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);

        ulResult = At_ChgTafErrorCode(ucIndex,usErrorCode);       /* ???????? */
        gstAtSendData.usBufLen = usLength;
        At_FormatResultData(ucIndex,ulResult);
        return;
    }

    if(TAF_NULL_PTR == pPara)   /* ???????????? */
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);

        At_FormatResultData(ucIndex,AT_CME_UNKNOWN);

        return;
    }

    ucTmp = (sizeof(g_aAtQryTypeProcFuncTbl) / sizeof(g_aAtQryTypeProcFuncTbl[0]));
    for (i = 0; i != ucTmp; i++ )
    {
        if (QueryType == g_aAtQryTypeProcFuncTbl[i].QueryType)
        {
            if (QueryType != TAF_PH_ICC_ID)
            {
                AT_STOP_TIMER_CMD_READY(ucIndex);
            }

            g_aAtQryTypeProcFuncTbl[i].AtQryParaProcFunc(ucIndex,OpId,pPara);

            return;
        }
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    AT_WARN_LOG("At_QryParaRspProc QueryType FAILURE");
    return;
}

TAF_VOID At_QryMsgProc(TAF_UINT8* pData,TAF_UINT16 usLen)
{
   TAF_UINT16                          usClientId = 0;
    TAF_UINT8                           OpId = 0;
    TAF_PARA_TYPE                       QueryType = 0;
    TAF_UINT16                          usErrorCode = 0;
    TAF_VOID                           *pPara = TAF_NULL_PTR;
    TAF_UINT16                          usAddr = 0;
    TAF_UINT16                          usParaLen = 0;
    TAF_UINT8                           ucIndex  = 0;

    TAF_MEM_CPY_S(&usClientId, sizeof(usClientId), pData, sizeof(usClientId));
    usAddr += sizeof(usClientId);

    TAF_MEM_CPY_S(&OpId, sizeof(OpId), pData+usAddr, sizeof(OpId));
    usAddr += sizeof(OpId);

    TAF_MEM_CPY_S(&QueryType, sizeof(QueryType), pData+usAddr, sizeof(QueryType));
    usAddr += sizeof(QueryType);

    TAF_MEM_CPY_S(&usErrorCode, sizeof(usErrorCode), pData+usAddr, sizeof(usErrorCode));
    usAddr += sizeof(usErrorCode);

    TAF_MEM_CPY_S(&usParaLen, sizeof(usParaLen), pData+usAddr, sizeof(usParaLen));
    usAddr += sizeof(usParaLen);

    if(0 != usParaLen)
    {
        pPara = pData+usAddr;
    }

    AT_LOG1("At_QryMsgProc ClientId",usClientId);
    AT_LOG1("At_QryMsgProc QueryType",QueryType);
    AT_LOG1("At_QryMagProc usErrorCode", usErrorCode);
    if(AT_BUTT_CLIENT_ID == usClientId)
    {
        AT_WARN_LOG("At_QryMsgProc Error ucIndex");
        return;
    }
    else
    {
        if(AT_FAILURE == At_ClientIdToUserId(usClientId,&ucIndex))
        {
            AT_WARN_LOG("At_QryMsgProc At_ClientIdToUserId FAILURE");
            return;
        }

        if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
        {
            AT_WARN_LOG("At_QryMsgProc: AT_BROADCAST_INDEX.");
            return;
        }

        AT_LOG1("At_QryMsgProc ucIndex",ucIndex);
        AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);

        At_QryParaRspProc(ucIndex,OpId,QueryType,usErrorCode,pPara);
    }
}


TAF_UINT32 At_PIHNotBroadIndProc(TAF_UINT8 ucIndex, SI_PIH_EVENT_INFO_STRU *pEvent)
{
    VOS_UINT16                          usLength;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;

    usLength  = 0;
    enModemId = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("At_PIHNotBroadIndProc: Get modem id fail.");
        return VOS_ERR;
    }

    switch(pEvent->EventType)
    {
        case SI_PIH_EVENT_PRIVATECGLA_SET_IND:

            /* ^CGLA??????????????????????IND???????????????????????????????? */
            usLength += At_PrintPrivateCglaResult(ucIndex, pEvent);
            break;

        default:
            AT_WARN_LOG("At_PIHNotBroadIndProc: Abnormal EventType.");
            return VOS_ERR;
    }

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return VOS_OK;
}


TAF_VOID At_PIHIndProc(TAF_UINT8 ucIndex, SI_PIH_EVENT_INFO_STRU *pEvent)
{
    VOS_UINT16                          usLength;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;

    usLength  = 0;
    enModemId = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("At_PIHIndProc: Get modem id fail.");
        return;
    }

    switch(pEvent->EventType)
    {
        case SI_PIH_EVENT_HVRDH_IND:
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%s^HVRDH: %d%s",
                                               gaucAtCrLf,
                                               pEvent->PIHEvent.HvrdhInd.ulReDhFlag,
                                               gaucAtCrLf);
            break;

        case SI_PIH_EVENT_TEETIMEOUT_IND:
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%s^TEETIMEOUT: %d%s",
                                               gaucAtCrLf,
                                               pEvent->PIHEvent.TEETimeOut.ulData,
                                               gaucAtCrLf);
            break;

        case SI_PIH_EVENT_SIM_ERROR_IND:
            usLength += At_CardErrorInfoInd(ucIndex, pEvent);
            break;

        case SI_PIH_EVENT_SIM_ICCID_IND:
            usLength += At_CardIccidInfoInd(ucIndex, pEvent);
            break;
        case SI_PIH_EVENT_SIM_HOTPLUG_IND:
            usLength += At_SimHotPlugStatusInd(ucIndex, pEvent);
            break;

        case SI_PIH_EVENT_SW_CHECK_IND:
            usLength += At_SWCheckStatusInd(pEvent);
            break;

        default:
            AT_WARN_LOG("At_PIHIndProc: Abnormal EventType.");
            return;
    }

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return;
}


VOS_UINT32 At_PrintSilentPinInfo(
    TAF_UINT8                           ucIndex,
    SI_PIH_EVENT_INFO_STRU             *pstEvent,
    VOS_UINT16                         *pusLength
)
{
    VOS_UINT8                          *pucPinIv;
    VOS_UINT32                          i;

    /* ??????????????????????AT_CMD_SILENTPIN_SET/AT_CMD_SILENTPININFO_SET */
    if ( (AT_CMD_SILENTPIN_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
      && (AT_CMD_SILENTPININFO_SET != gastAtClientTab[ucIndex].CmdCurrentOpt))
    {
        AT_WARN_LOG("At_PrintSilentPinInfo : CmdCurrentOpt is not AT_CMD_SILENTPIN_SET/AT_CMD_SILENTPININFO_SET!");
        return AT_ERROR;
    }

    (*pusLength) += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr,
                                       "%s:",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

    for (i = 0; i < DRV_AGENT_PIN_CRYPTO_DATA_LEN; i++)
    {
        (*pusLength) += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + (*pusLength),
                                           "%02X",
                                            pstEvent->PIHEvent.stCryptoPin.aucCryptoPin[i]);
    }

    pucPinIv = (VOS_UINT8*)pstEvent->PIHEvent.stCryptoPin.aulPinIv;

    (*pusLength) += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + (*pusLength), ",");

    for (i = 0; i < (sizeof(VOS_UINT32) * 4); i++)/* IV??????16???? */
    {
        (*pusLength) += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + (*pusLength),
                                           "%02X",
                                           (*(pucPinIv + i)));
    }

    (*pusLength) += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN, (TAF_CHAR *)pgucAtSndCodeAddr, (TAF_CHAR *)pgucAtSndCodeAddr + (*pusLength), ",");

    for (i = 0; i < DRV_AGENT_HMAC_DATA_LEN; i++)
    {
        (*pusLength) += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + (*pusLength),
                                           "%02X",
                                           pstEvent->PIHEvent.stCryptoPin.aucHmacValue[i]);
    }

    return AT_OK;
}


TAF_VOID At_PIHRspProc(TAF_UINT8 ucIndex, SI_PIH_EVENT_INFO_STRU *pEvent)
{
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;
    TAF_UINT32                          ulTmp;
    TAF_UINT32                          i;

    if(TAF_ERR_NO_ERROR != pEvent->PIHError)  /* ???? */
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);

        ulResult = At_ChgTafErrorCode(ucIndex, (TAF_UINT16)(pEvent->PIHError));       /* ???????? */

        gstAtSendData.usBufLen = usLength;

        At_FormatResultData(ucIndex,ulResult);

        return;
    }

    ulTmp = (sizeof(g_aAtPihRspProcFuncTbl) / sizeof(g_aAtPihRspProcFuncTbl[0]));

    for (i = 0; i < ulTmp; i++)
    {
        /* ?????????????????????????????? */
        if (pEvent->EventType == g_aAtPihRspProcFuncTbl[i].ulEventType)
        {

            ulResult = g_aAtPihRspProcFuncTbl[i].pAtPihRspProcFunc(ucIndex, pEvent, &usLength);

            if (AT_ERROR == ulResult)
            {
                AT_WARN_LOG("At_PIHRspProc : pAtPihRspProcFunc is return error!");
                return;
            }

            break;
        }
    }

    /* ???????????????????????? */
    if (i == ulTmp)
    {
        AT_WARN_LOG("At_PIHRspProc : no find AT Proc Func!");
        return;
    }

    ulResult = AT_OK;

    AT_STOP_TIMER_CMD_READY(ucIndex);

    gstAtSendData.usBufLen = usLength;

    At_FormatResultData(ucIndex,ulResult);

    g_enLogPrivacyAtCmd = TAF_LOG_PRIVACY_AT_CMD_BUTT;

    return;
}

/*****************************************************************************
 Prototype      : At_PbIndMsgProc
 Description    : ??????????????????????????
 Input          : pEvent --- ????????
 Output         :
 Return Value   : ---
 Calls          : ---
 Called By      : ---

 History        : h59254
  1.Date        : 2013-05-29
    Author      : ---
    Modification: Created function
*****************************************************************************/
TAF_VOID At_PbIndMsgProc(SI_PB_EVENT_INFO_STRU *pEvent)
{
    if (SI_PB_EVENT_INFO_IND == pEvent->PBEventType)
    {
        /* ??SIM????FDN??????????????????FD */
        if ((0 == pEvent->PBEvent.PBInfoInd.CardType)
         && (SI_PIH_STATE_FDN_BDN_ENABLE == pEvent->PBEvent.PBInfoInd.FdnState))
        {
            gstPBATInfo.usNameMaxLen = pEvent->PBEvent.PBInfoInd.FDNTextLen;
            gstPBATInfo.usNumMaxLen  = pEvent->PBEvent.PBInfoInd.FDNNumberLen;
            gstPBATInfo.usTotal      = pEvent->PBEvent.PBInfoInd.FDNRecordNum;
            gstPBATInfo.usAnrNumLen  = pEvent->PBEvent.PBInfoInd.ANRNumberLen;
            gstPBATInfo.usEmailLen   = pEvent->PBEvent.PBInfoInd.EMAILTextLen;
        }
        else
        {
            gstPBATInfo.usNameMaxLen = pEvent->PBEvent.PBInfoInd.ADNTextLen;
            gstPBATInfo.usNumMaxLen  = pEvent->PBEvent.PBInfoInd.ADNNumberLen;
            gstPBATInfo.usTotal      = pEvent->PBEvent.PBInfoInd.ADNRecordNum;
            gstPBATInfo.usAnrNumLen  = pEvent->PBEvent.PBInfoInd.ANRNumberLen;
            gstPBATInfo.usEmailLen   = pEvent->PBEvent.PBInfoInd.EMAILTextLen;
        }
    }

    return;
}


VOS_VOID AT_PB_ReadContinueProc(VOS_UINT8 ucIndex)
{
    AT_COMM_PB_CTX_STRU                *pstCommPbCntxt = VOS_NULL_PTR;
    AT_UART_CTX_STRU                   *pstUartCtx     = VOS_NULL_PTR;
    VOS_UINT32                          ulResult;

    pstCommPbCntxt = AT_GetCommPbCtxAddr();
    pstUartCtx     = AT_GetUartCtxAddr();
    ulResult       = AT_SUCCESS;

    /* ?????????????????????? */
    pstUartCtx->pWmLowFunc = VOS_NULL_PTR;

    /* ???????????????????????? */
    pstCommPbCntxt->usCurrIdx++;

    if (TAF_SUCCESS == SI_PB_Read(gastAtClientTab[ucIndex].usClientId,
                                  0, SI_PB_STORAGE_UNSPECIFIED,
                                  pstCommPbCntxt->usCurrIdx,
                                  pstCommPbCntxt->usCurrIdx))
    {
        return;
    }
    else
    {
        ulResult = AT_ERROR;
    }

    gstAtSendData.usBufLen = 0;
    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, ulResult);
    return;
}


VOS_VOID AT_PB_ReadRspProc(
    VOS_UINT8                           ucIndex,
    SI_PB_EVENT_INFO_STRU              *pstEvent
)
{
    AT_COMM_PB_CTX_STRU                *pstCommPbCntxt = VOS_NULL_PTR;
    AT_UART_CTX_STRU                   *pstUartCtx     = VOS_NULL_PTR;
    VOS_UINT32                          ulResult;

    pstCommPbCntxt = AT_GetCommPbCtxAddr();
    pstUartCtx     = AT_GetUartCtxAddr();
    ulResult       = AT_SUCCESS;

    /*
     * ????????: ??????????????????
     * ????????: ??????????????????
     */
    if (VOS_TRUE == pstCommPbCntxt->ulSingleReadFlg)
    {
        ulResult = (TAF_ERR_NO_ERROR == pstEvent->PBError) ?
                   AT_OK : At_ChgTafErrorCode(ucIndex, (VOS_UINT16)pstEvent->PBError);
    }
    else if ( (TAF_ERR_NO_ERROR     == pstEvent->PBError)
           || (TAF_ERR_PB_NOT_FOUND == pstEvent->PBError) )
    {
        /* ???????????????????????????????????? */
        if (pstCommPbCntxt->usCurrIdx == pstCommPbCntxt->usLastIdx)
        {
            ulResult = AT_OK;
        }
        else
        {
            ulResult = AT_WAIT_ASYNC_RETURN;
        }
    }
    else
    {
        ulResult = At_ChgTafErrorCode(ucIndex, (VOS_UINT16)pstEvent->PBError);
    }

    /* ????????????, ???????????????? */
    if (AT_WAIT_ASYNC_RETURN == ulResult)
    {
        /*
         * ??????????????????????????:
         * ??????????????, ??????????????????????????????????????????
         */
        if (VOS_TRUE == pstUartCtx->ulTxWmHighFlg)
        {
            pstUartCtx->pWmLowFunc = AT_PB_ReadContinueProc;
            return;
        }

        /* ???????????????????????? */
        pstCommPbCntxt->usCurrIdx++;

        if (TAF_SUCCESS == SI_PB_Read(gastAtClientTab[ucIndex].usClientId,
                                      0, SI_PB_STORAGE_UNSPECIFIED,
                                      pstCommPbCntxt->usCurrIdx,
                                      pstCommPbCntxt->usCurrIdx))
        {
            return;
        }
        else
        {
            ulResult = AT_ERROR;
        }
    }

    gstAtSendData.usBufLen = 0;
    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, ulResult);
    return;
}


TAF_VOID At_PbRspProc(TAF_UINT8 ucIndex,SI_PB_EVENT_INFO_STRU *pEvent)
{
    VOS_UINT32 ulResult = AT_FAILURE;
    TAF_UINT16 usLength = 0;

    if (!( (VOS_TRUE == AT_CheckHsUartUser(ucIndex))
        && ( (AT_CMD_CPBR2_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
          || (AT_CMD_CPBR_SET  == gastAtClientTab[ucIndex].CmdCurrentOpt)) ) )
    {
        if(TAF_ERR_NO_ERROR != pEvent->PBError)  /* ???? */
        {
            ulResult = At_ChgTafErrorCode(ucIndex,(TAF_UINT16)pEvent->PBError);
            gstAtSendData.usBufLen = usLength;
            AT_STOP_TIMER_CMD_READY(ucIndex);
            At_FormatResultData(ucIndex,ulResult);
            return;
        }
    }

    switch(pEvent->PBEventType)
    {
        case SI_PB_EVENT_SET_CNF:
            gstPBATInfo.usNameMaxLen = pEvent->PBEvent.PBSetCnf.TextLen;
            gstPBATInfo.usNumMaxLen  = pEvent->PBEvent.PBSetCnf.NumLen;
            gstPBATInfo.usTotal      = pEvent->PBEvent.PBSetCnf.TotalNum;
            gstPBATInfo.usUsed       = pEvent->PBEvent.PBSetCnf.InUsedNum;
            gstPBATInfo.usAnrNumLen  = pEvent->PBEvent.PBSetCnf.ANRNumberLen;
            gstPBATInfo.usEmailLen   = pEvent->PBEvent.PBSetCnf.EMAILTextLen;

            AT_STOP_TIMER_CMD_READY(ucIndex);

            ulResult = AT_OK;

            break;

        case SI_PB_EVENT_READ_CNF:
        case SI_PB_EVENT_SREAD_CNF:
            if((pEvent->PBError == TAF_ERR_NO_ERROR)&&
                (pEvent->PBEvent.PBReadCnf.PBRecord.ValidFlag == SI_PB_CONTENT_VALID))/*??????????????*/
            {
                if (AT_CMD_D_GET_NUMBER_BEFORE_CALL == gastAtClientTab[ucIndex].CmdCurrentOpt)
                {
                    ulResult = At_DialNumByIndexFromPb(ucIndex,pEvent);
                    if(AT_WAIT_ASYNC_RETURN == ulResult)
                    {
                        g_stParseContext[ucIndex].ucClientStatus = AT_FW_CLIENT_STATUS_PEND;


                        /* ???????? */
                        if(AT_SUCCESS != At_StartTimer(g_stParseContext[ucIndex].pstCmdElement->ulSetTimeOut, ucIndex))
                        {
                            AT_ERR_LOG("At_PbRspProc:ERROR:Start Timer");
                        }
                        ulResult = AT_SUCCESS;

                    }
                    else
                    {
                        ulResult = AT_ERROR;
                    }

                    break;

                }

                if (TAF_FALSE == gulPBPrintTag)
                {
                     usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCrLfAddr,(TAF_CHAR *)pgucAtSndCrLfAddr,"%s","\r\n");
                }

                gulPBPrintTag = TAF_TRUE;

                if(AT_CMD_CPBR_SET == gastAtClientTab[ucIndex].CmdCurrentOpt) /*???? ^CPBR ??????????????*/
                {
                    ulResult = At_PbCPBRCmdPrint(ucIndex,&usLength,pgucAtSndCrLfAddr,pEvent);
                }
                else if(AT_CMD_CPBR2_SET == gastAtClientTab[ucIndex].CmdCurrentOpt) /*???? +CPBR ??????????????*/
                {
                    ulResult = At_PbCPBR2CmdPrint(ucIndex,&usLength,pgucAtSndCrLfAddr,pEvent);
                }
                else if(AT_CMD_SCPBR_SET == gastAtClientTab[ucIndex].CmdCurrentOpt) /*???? ^SCPBR ??????????????*/
                {
                    ulResult = At_PbSCPBRCmdPrint(ucIndex,&usLength,pEvent);
                }
                else if(AT_CMD_CNUM_READ == gastAtClientTab[ucIndex].CmdCurrentOpt) /*???? CNUM ??????????????*/
                {
                    ulResult = At_PbCNUMCmdPrint(ucIndex,&usLength,pgucAtSndCrLfAddr,pEvent);
                }
                else
                {
                    AT_ERR_LOG1("At_PbRspProc: the Cmd Current Opt %d is Unknow", gastAtClientTab[ucIndex].CmdCurrentOpt);

                    return ;
                }

                if(AT_SUCCESS == ulResult)
                {
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCrLfAddr,
                                        (TAF_CHAR *)pgucAtSndCrLfAddr + usLength,
                                        "%s","\r\n");
                }

                At_SendResultData(ucIndex, pgucAtSndCrLfAddr, usLength);

                usLength = 0;
            }

            TAF_MEM_CPY_S((TAF_CHAR *)pgucAtSndCrLfAddr, 2, (TAF_CHAR *)gaucAtCrLf, 2);/*AT????Buffer??????????????????\r\n*/

            if ( (VOS_TRUE == AT_CheckHsUartUser(ucIndex))
              && ( (AT_CMD_CPBR2_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
                || (AT_CMD_CPBR_SET  == gastAtClientTab[ucIndex].CmdCurrentOpt)) )
            {
                AT_PB_ReadRspProc(ucIndex, pEvent);
                return;
            }

            if( (VOS_FALSE == gulPBPrintTag)
             && ( (AT_CMD_CPBR_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
               || (AT_CMD_CPBR2_SET == gastAtClientTab[ucIndex].CmdCurrentOpt) ) )
            {
                pEvent->PBError = TAF_ERR_ERROR;
            }

            if(TAF_ERR_NO_ERROR != pEvent->PBError)  /* ???? */
            {
                ulResult = At_ChgTafErrorCode(ucIndex,(TAF_UINT16)pEvent->PBError);       /* ???????? */

                gstAtSendData.usBufLen = usLength;
            }
            else
            {
                ulResult = AT_OK;
            }

            AT_STOP_TIMER_CMD_READY(ucIndex);
            break;

        case SI_PB_EVENT_SEARCH_CNF:
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,
                                        (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                        "%s","\r");
            AT_STOP_TIMER_CMD_READY(ucIndex);
            ulResult = AT_OK;
            break;

        case SI_PB_EVENT_ADD_CNF:
        case SI_PB_EVENT_SADD_CNF:
        case SI_PB_EVENT_MODIFY_CNF:
        case SI_PB_EVENT_SMODIFY_CNF:
        case SI_PB_EVENT_DELETE_CNF:
            AT_STOP_TIMER_CMD_READY(ucIndex);
            ulResult = AT_OK;
            break;

        case SI_PB_EVENT_QUERY_CNF:

            if(1 == pEvent->OpId)
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s: (\"SM\",\"EN\",\"ON\",\"FD\")",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
                ulResult = AT_OK;
                AT_STOP_TIMER_CMD_READY(ucIndex);
                break;
            }

            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

            gstPBATInfo.usNameMaxLen = pEvent->PBEvent.PBQueryCnf.TextLen;
            gstPBATInfo.usNumMaxLen  = pEvent->PBEvent.PBQueryCnf.NumLen;
            gstPBATInfo.usTotal      = pEvent->PBEvent.PBQueryCnf.TotalNum;
            gstPBATInfo.usUsed       = pEvent->PBEvent.PBQueryCnf.InUsedNum;
            gstPBATInfo.usAnrNumLen  = pEvent->PBEvent.PBQueryCnf.ANRNumberLen;
            gstPBATInfo.usEmailLen   = pEvent->PBEvent.PBQueryCnf.EMAILTextLen;

            switch(g_stParseContext[ucIndex].pstCmdElement->ulCmdIndex)
            {
                case AT_CMD_CPBR:
                case AT_CMD_CPBR2:
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"(1-%d),%d,%d",gstPBATInfo.usTotal,gstPBATInfo.usNumMaxLen,gstPBATInfo.usNameMaxLen);
                    break;
                case AT_CMD_CPBW:
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"(1-%d),%d,(128-255),%d",gstPBATInfo.usTotal,gstPBATInfo.usNumMaxLen,gstPBATInfo.usNameMaxLen);
                    break;
                case AT_CMD_CPBW2:
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"(1-%d),%d,(128-255),%d",gstPBATInfo.usTotal,gstPBATInfo.usNumMaxLen,gstPBATInfo.usNameMaxLen);
                    break;
                case AT_CMD_SCPBR:
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"(1-%d),%d,%d,%d",gstPBATInfo.usTotal,gstPBATInfo.usNumMaxLen,gstPBATInfo.usNameMaxLen,gstPBATInfo.usEmailLen);
                    break;
                case AT_CMD_SCPBW:
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"(1-%d),%d,(128-255),%d,%d",gstPBATInfo.usTotal,gstPBATInfo.usNumMaxLen,gstPBATInfo.usNameMaxLen,gstPBATInfo.usEmailLen);
                    break;
                case AT_CMD_CPBS:
                    if(SI_PB_STORAGE_SM == pEvent->Storage)
                    {
                        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gastAtStringTab[AT_STRING_SM].pucText);
                    }
                    else if(SI_PB_STORAGE_FD == pEvent->Storage)
                    {
                        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gastAtStringTab[AT_STRING_FD].pucText);
                    }
                    else if(SI_PB_STORAGE_ON == pEvent->Storage)
                    {
                        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gastAtStringTab[AT_STRING_ON].pucText);
                    }
                    else if(SI_PB_STORAGE_BD == pEvent->Storage)
                    {
                        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gastAtStringTab[AT_STRING_BD].pucText);
                    }
                    else
                    {
                        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gastAtStringTab[AT_STRING_EN].pucText);
                    }

                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",pEvent->PBEvent.PBQueryCnf.InUsedNum);
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",pEvent->PBEvent.PBQueryCnf.TotalNum);

                    break;
                case AT_CMD_CPBF:
                    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%d,%d",gstPBATInfo.usNumMaxLen,gstPBATInfo.usNameMaxLen);
                    break;

                default:
                    break;
            }

            ulResult = AT_OK;

            AT_STOP_TIMER_CMD_READY(ucIndex);

            break;

        default:
            AT_ERR_LOG1("At_PbRspProc Unknow Event %d", pEvent->PBEventType);
            break;
    }

    gstAtSendData.usBufLen = usLength;

    At_FormatResultData(ucIndex,ulResult);
}


TAF_VOID At_TAFPbMsgProc(TAF_UINT8* pData,TAF_UINT16 usLen)
{
    SI_PB_EVENT_INFO_STRU   *pEvent = TAF_NULL_PTR;
    TAF_UINT8               ucIndex = 0;
    /*lint -save -e516 */
    pEvent = (SI_PB_EVENT_INFO_STRU *)PS_MEM_ALLOC(WUEPS_PID_AT, usLen);
    /*lint -restore */
    if(TAF_NULL_PTR == pEvent)
    {
        return;
    }

    TAF_MEM_CPY_S(pEvent, usLen, pData, usLen);

    AT_LOG1("At_PbMsgProc pEvent->ClientId",pEvent->ClientId);
    AT_LOG1("At_PbMsgProc PBEventType",pEvent->PBEventType);
    AT_LOG1("At_PbMsgProc Event Error",pEvent->PBError);

    if (AT_FAILURE == At_ClientIdToUserId(pEvent->ClientId, &ucIndex))
    {
        /*lint -save -e516 */
        PS_MEM_FREE(WUEPS_PID_AT, pEvent);
        /*lint -restore */
        AT_WARN_LOG("At_TAFPbMsgProc At_ClientIdToUserId FAILURE");
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        /*lint -save -e516 */
        PS_MEM_FREE(WUEPS_PID_AT,pEvent);
        /*lint -restore */
        AT_WARN_LOG("At_TAFPbMsgProc: AT_BROADCAST_INDEX.");
        return;
    }

    AT_LOG1("At_PbMsgProc ucIndex",ucIndex);
    AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);

    At_PbRspProc(ucIndex,pEvent);
    /*lint -save -e516 */
    PS_MEM_FREE(WUEPS_PID_AT,pEvent);
    /*lint -restore */
    return;
}


TAF_VOID At_PbMsgProc(MsgBlock* pMsg)
{
    MN_APP_PB_AT_CNF_STRU   *pstMsg;
    TAF_UINT8               ucIndex = 0;

    pstMsg = (MN_APP_PB_AT_CNF_STRU*)pMsg;

    AT_LOG1("At_PbMsgProc pEvent->ClientId",    pstMsg->stPBAtEvent.ClientId);
    AT_LOG1("At_PbMsgProc PBEventType",         pstMsg->stPBAtEvent.PBEventType);
    AT_LOG1("At_PbMsgProc Event Error",         pstMsg->stPBAtEvent.PBError);

    if (AT_FAILURE == At_ClientIdToUserId(pstMsg->stPBAtEvent.ClientId, &ucIndex))
    {
        AT_ERR_LOG1("At_PbMsgProc At_ClientIdToUserId FAILURE", pstMsg->stPBAtEvent.ClientId);
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_PbMsgProc: AT_BROADCAST_INDEX.");
        At_PbIndMsgProc(&pstMsg->stPBAtEvent);
        return;
    }

    AT_LOG1("At_PbMsgProc ucIndex",ucIndex);
    AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);

    At_PbRspProc(ucIndex,&pstMsg->stPBAtEvent);

    return;
}


TAF_VOID At_PIHMsgProc(MsgBlock* pMsg)
{
    MN_APP_PIH_AT_CNF_STRU  *pstMsg;
    TAF_UINT8               ucIndex = 0;

    pstMsg = (MN_APP_PIH_AT_CNF_STRU*)pMsg;

    if(PIH_AT_EVENT_CNF != pstMsg->ulMsgId)
    {
        AT_ERR_LOG1("At_PIHMsgProc: The Msg Id is Wrong", pstMsg->ulMsgId);
        return;
    }

    AT_LOG1("At_PIHMsgProc pEvent->ClientId",   pstMsg->stPIHAtEvent.ClientId);
    AT_LOG1("At_PIHMsgProc EventType",          pstMsg->stPIHAtEvent.EventType);
    AT_LOG1("At_PIHMsgProc SIM Event Error",    pstMsg->stPIHAtEvent.PIHError);

    if(AT_FAILURE == At_ClientIdToUserId(pstMsg->stPIHAtEvent.ClientId,&ucIndex))
    {
        AT_ERR_LOG("At_PIHMsgProc At_ClientIdToUserId FAILURE");
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        At_PIHIndProc(ucIndex,&pstMsg->stPIHAtEvent);
        AT_WARN_LOG("At_PIHMsgProc : AT_BROADCAST_INDEX.");
        return;
    }

    AT_LOG1("At_PbMsgProc ucIndex",ucIndex);
    AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);

    /* ???????????????? */
    if (VOS_OK == At_PIHNotBroadIndProc(ucIndex,&pstMsg->stPIHAtEvent))
    {
        return;
    }

    At_PIHRspProc(ucIndex,&pstMsg->stPIHAtEvent);

    return;
}

VOS_VOID At_XsmsIndProc(
    VOS_UINT8                           ucIndex,
    TAF_XSMS_APP_MSG_TYPE_ENUM_UINT32   enEventType,
    TAF_XSMS_APP_AT_EVENT_INFO_STRU    *pstEvent)
{
    VOS_UINT16                          usLength;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;

    usLength  = 0;
    enModemId = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("At_XsmsIndProc: Get modem id fail.");
        return;
    }

    switch(enEventType)
    {
        case TAF_XSMS_APP_MSG_TYPE_SEND_SUCC_IND:
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%s^CCMGSS: %d%s",
                                               gaucAtCrLf,
                                               pstEvent->XSmsEvent.stSndSuccInd.ulMr,
                                               gaucAtCrLf);
            break;

        case TAF_XSMS_APP_MSG_TYPE_SEND_FAIL_IND:
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%s^CCMGSF: %d%s",
                                               gaucAtCrLf,
                                               pstEvent->XSmsEvent.stSndFailInd.ulCourseCode,
                                               gaucAtCrLf);
            break;

        case TAF_XSMS_APP_MSG_TYPE_RCV_IND:
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%s^CCMT:",
                                               gaucAtCrLf);
            /* <length>, */
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%d,\"",
                                               2 * sizeof(TAF_XSMS_MESSAGE_STRU)); /*lint !e559 */
            /* <PDU> */
            usLength += (TAF_UINT16)At_HexAlpha2AsciiString(AT_CMD_MAX_LEN,
                                                            (TAF_INT8 *)pgucAtSndCodeAddr,
                                                            (TAF_UINT8 *)pgucAtSndCodeAddr + usLength,
                                                            (TAF_UINT8 *)&pstEvent->XSmsEvent.stRcvInd.stRcvMsg,
                                                            sizeof(TAF_XSMS_MESSAGE_STRU));

            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "\"%s",
                                               gaucAtCrLf);

            break;

        case TAF_XSMS_APP_MSG_TYPE_UIM_FULL_IND:
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%s^CSMMEMFULL: \"SM\"%s",
                                               gaucAtCrLf,
                                               gaucAtCrLf);
            break;

        default:
            AT_WARN_LOG("At_XsmsIndProc: Abnormal EventType.");
            return;
    }

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return;
}


VOS_VOID At_XsmsCnfProc(
    VOS_UINT8                           ucIndex,
    TAF_XSMS_APP_MSG_TYPE_ENUM_UINT32   enEventType,
    TAF_XSMS_APP_AT_EVENT_INFO_STRU    *pstEvent)
{
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;

    if (TAF_ERR_NO_ERROR != pstEvent->ulError)  /* ???? */
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);

        ulResult = At_ChgXsmsErrorCodeToAt(pstEvent->ulError);       /* ???????? */

        gstAtSendData.usBufLen = usLength;

        At_FormatResultData(ucIndex, ulResult);

        return;
    }

    switch (enEventType)
    {
        /* ????????????????????OK */
        case TAF_XSMS_APP_MSG_TYPE_SEND_CNF:
            break;

        case TAF_XSMS_APP_MSG_TYPE_WRITE_CNF:
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "^CCMGW: %d",
                                               pstEvent->XSmsEvent.stWriteCnf.ulIndex - 1);
            break;

        /* ????????????????????OK */
        case TAF_XSMS_APP_MSG_TYPE_DELETE_CNF:

            break;

        /* ????????????????????OK */
        case TAF_XSMS_APP_MSG_TYPE_UIM_MEM_FULL_CNF:

            break;

        default:
            return;
    }

    ulResult = AT_OK;

    AT_STOP_TIMER_CMD_READY(ucIndex);

    gstAtSendData.usBufLen = usLength;

    At_FormatResultData(ucIndex,ulResult);
}


VOS_VOID AT_ProcXsmsMsg(TAF_XSMS_APP_AT_CNF_STRU *pstMsg)
{
    VOS_UINT8                           ucIndex = 0;

    /* ?????????????? */
    if (TAF_XSMS_APP_MSG_TYPE_BUTT <= pstMsg->enEventType)
    {
        AT_ERR_LOG1("AT_ProcXsmsMsg: The Msg Id is Wrong", pstMsg->enEventType);

        return;
    }

    AT_LOG1("AT_ProcXsmsMsg ClientId", pstMsg->stXsmsAtEvent.usClientId);
    AT_LOG1("AT_ProcXsmsMsg OpId",     pstMsg->stXsmsAtEvent.ucOpId);

    if (AT_FAILURE == At_ClientIdToUserId(pstMsg->stXsmsAtEvent.usClientId, &ucIndex))
    {
        AT_ERR_LOG("AT_ProcXsmsMsg At_ClientIdToUserId FAILURE");

        return;
    }

    /* ???????? */
    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        At_XsmsIndProc(ucIndex, pstMsg->enEventType, &pstMsg->stXsmsAtEvent);

        AT_NORM_LOG("At_PIHMsgProc : AT_BROADCAST_INDEX.");

        return;
    }

    AT_LOG1("At_PbMsgProc ucIndex",ucIndex);

    /* AT???????????? */
    At_XsmsCnfProc(ucIndex, pstMsg->enEventType, &pstMsg->stXsmsAtEvent);

    return;
}


/* PC??????AT??A??????C??, At_sprintf??????????,?????????????????????? */
/*****************************************************************************
 Prototype      : At_ChangeSATCMDNo
 Description    : Sat????????????
 Input          :
 Output         :
 Return Value   : ---
 Calls          : ---
 Called By      : ---

 History        : ---

*****************************************************************************/
VOS_UINT32 At_ChangeSTKCmdNo(VOS_UINT32 ulCmdType, VOS_UINT8 *ucCmdNo )
{
    switch(ulCmdType)
    {
        case SI_STK_REFRESH:
            *ucCmdNo = SI_AT_CMD_REFRESH;
            break;
        case SI_STK_DISPLAYTET:
            *ucCmdNo = SI_AT_CMD_DISPLAY_TEXT;
            break;
        case SI_STK_GETINKEY:
            *ucCmdNo = SI_AT_CMD_GET_INKEY;
             break;
        case SI_STK_GETINPUT:
            *ucCmdNo = SI_AT_CMD_GET_INPUT;
            break;
        case SI_STK_PLAYTONE:
            *ucCmdNo = SI_AT_CMD_PLAY_TONE;
            break;
        case SI_STK_SELECTITEM:
            *ucCmdNo = SI_AT_CMD_SELECT_ITEM;
            break;
        case SI_STK_SETUPMENU:
            *ucCmdNo = SI_AT_CMD_SETUP_MENU;
            break;
        case SI_STK_SETUPIDLETEXT:
            *ucCmdNo = SI_AT_CMD_SETUP_IDLE_MODE_TEXT;
            break;
        case SI_STK_LAUNCHBROWSER:
            *ucCmdNo = SI_AT_CMD_LAUNCH_BROWSER;
            break;
        case SI_STK_SENDSS:
            *ucCmdNo = SI_AT_CMD_SEND_SS;
            break;
        case SI_STK_LANGUAGENOTIFICATION:
            *ucCmdNo = SI_AT_CMD_LANGUAGENOTIFICATION;
            break;
        case SI_STK_SETFRAMES:
            *ucCmdNo = SI_AT_CMD_SETFRAMES;
            break;
        case SI_STK_GETFRAMESSTATUS:
            *ucCmdNo = SI_AT_CMD_GETFRAMESSTATUS;
            break;
        default:
            return VOS_ERR;
    }

    return VOS_OK;
}



TAF_UINT32 At_HexText2AsciiStringSimple(TAF_UINT32 MaxLength,TAF_INT8 *headaddr,TAF_UINT8 *pucDst,TAF_UINT32 ulLen,TAF_UINT8 *pucStr)
{
    TAF_UINT16 usLen = 0;
    TAF_UINT16 usChkLen = 0;
    TAF_UINT8 *pWrite = pucDst;
    TAF_UINT8 *pRead = pucStr;
    TAF_UINT8  ucHigh = 0;
    TAF_UINT8  ucLow = 0;

    if(((TAF_UINT32)(pucDst - (TAF_UINT8 *)headaddr) + (2 * ulLen) + 3) >= MaxLength)
    {
        AT_ERR_LOG("At_HexText2AsciiString too long");
        return 0;
    }

    if(0 != ulLen)
    {
        usLen += 1;

        *pWrite++ = '\"';

        /* ???????????? */
        while( usChkLen++ < ulLen )
        {
            ucHigh = 0x0F & (*pRead >> 4);
            ucLow = 0x0F & *pRead;
            usLen += 2;    /* ???????? */

            if(0x09 >= ucHigh)   /* 0-9 */
            {
                *pWrite++ = ucHigh + 0x30;
            }
            else if(0x0A <= ucHigh)    /* A-F */
            {
                *pWrite++ = ucHigh + 0x37;
            }
            else
            {

            }

            if(0x09 >= ucLow)   /* 0-9 */
            {
                *pWrite++ = ucLow + 0x30;
            }
            else if(0x0A <= ucLow)    /* A-F */
            {
                *pWrite++ = ucLow + 0x37;
            }
            else
            {

            }
            /* ?????????? */
            pRead++;
        }

        usLen ++;

        *pWrite++ = '\"';

        *pWrite++ = '\0';
    }

    return usLen;
}


TAF_VOID  At_StkCsinIndPrint(TAF_UINT8 ucIndex,SI_STK_EVENT_INFO_STRU *pEvent)
{
    TAF_UINT16 usLength = 0;

    /* ????????AT???????? */
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s%s",
                                       gaucAtCrLf,
                                       gaucAtCsin);

    /* ?????????????????????????????? */
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%d",
                                       (pEvent->STKCmdStru.SatCmd.SatDataLen*2));

    /* ?????????????????? */
    if (0 != pEvent->STKCmdStru.SatCmd.SatDataLen)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                            ", %d, ",
                                            pEvent->STKCmdStru.SatType);


        /* ??16????????????ASCII???????????????????? */
        usLength += (TAF_UINT16)At_HexText2AsciiStringSimple(AT_CMD_MAX_LEN,
                                                            (TAF_INT8 *)pgucAtSndCodeAddr,
                                                            (TAF_UINT8 *)pgucAtSndCodeAddr + usLength,
                                                            pEvent->STKCmdStru.SatCmd.SatDataLen,
                                                            pEvent->STKCmdStru.SatCmd.SatCmdData);
    }

    /* ???????????? */
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                        "%s",
                                        gaucAtCrLf);

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
}

/*****************************************************************************
 Prototype      : At_STKCMDDataPrintSimple
 Description    : Sat????????????
 Input          :
 Output         :
 Return Value   : ---
 Calls          : ---
 Called By      : ---

 History        : ---
  1.Date        : 2009-07-04
    Author      : zhuli
    Modification: Created function
*****************************************************************************/
TAF_VOID At_STKCMDDataPrintSimple(TAF_UINT8 ucIndex,SI_STK_EVENT_INFO_STRU *pEvent)
{
    TAF_UINT16 usLength = 0;

    if(SI_STK_CMD_IND_EVENT == pEvent->STKCBEvent)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                        "%s",gaucAtCsin);
    }
    else
    {
        if(SI_STK_SETUPMENU != pEvent->STKCmdStru.SatType)
        {
            return;
        }

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                        "%s",gaucAtCsmn);
    }

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                    "%d, %d, ",(pEvent->STKCmdStru.SatCmd.SatDataLen*2), pEvent->STKCmdStru.SatType);

    usLength += (TAF_UINT16)At_HexText2AsciiStringSimple(AT_CMD_MAX_LEN,(TAF_INT8 *)pgucAtSndCodeAddr,(TAF_UINT8 *)pgucAtSndCodeAddr + usLength,
                                    pEvent->STKCmdStru.SatCmd.SatDataLen, pEvent->STKCmdStru.SatCmd.SatCmdData);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                    "%s",gaucAtCrLf);

    At_SendResultData(ucIndex,pgucAtSndCrLfAddr,usLength+2);

    return ;
}

/*****************************************************************************
 Prototype      : At_SatCallBackFunc
 Description    : Sat????????????
 Input          :
 Output         :
 Return Value   : ---
 Calls          : ---
 Called By      : ---

 History        : ---
  1.Date        : 2009-07-04
    Author      : zhuli
    Modification: Created function
*****************************************************************************/
TAF_VOID At_STKCMDSWPrintSimple(TAF_UINT8 ucIndex,STK_CALLBACK_EVENT STKCBEvent,SI_STK_SW_INFO_STRU *pSw)
{
    TAF_UINT16 usLength = 0;
    VOS_UINT8  *pucSystemAppConfig;

    /* ????????????????????: MP/WEBUI/ANDROID */
    pucSystemAppConfig = AT_GetSystemAppConfigAddr();

    if (SYSTEM_APP_ANDROID != *pucSystemAppConfig)
    {
        return ;
    }

    if(SI_STK_TERMINAL_RSP_EVENT == STKCBEvent)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                        "%s",gaucAtCstr);
    }
    else
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                        "%s",gaucAtCsen);
    }

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                        "%d, %d%s",pSw->SW1, pSw->SW2,gaucAtCrLf);

    At_SendResultData(ucIndex,pgucAtSndCrLfAddr,usLength+2);

    return ;
}


VOS_VOID AT_SendSTKCMDTypeResultData(
    VOS_UINT8                           ucIndex,
    VOS_UINT16                          usLength
)
{
    if (AT_V_ENTIRE_TYPE == gucAtVType)
    {
        /* Code??????\r\n */
        TAF_MEM_CPY_S((TAF_CHAR *)pgucAtSndCrLfAddr, 2, (TAF_CHAR *)gaucAtCrLf, 2);
        At_SendResultData(ucIndex, pgucAtSndCrLfAddr, usLength + 2);
    }
    else
    {
        At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
    }

    return;
}


VOS_UINT32 At_STKCMDTypePrint(TAF_UINT8 ucIndex,TAF_UINT32 SatType, TAF_UINT32 EventType)
{
    VOS_UINT8                          *pucSystemAppConfig;
    TAF_UINT16                          usLength = 0;
    TAF_UINT8                           ucCmdType = 0;
    TAF_UINT32                          ulResult = AT_SUCCESS;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;

    /* ?????? */
    enModemId       = MODEM_ID_0;

    pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("At_STKCMDTypePrint: Get modem id fail.");
        return AT_FAILURE;
    }

    /* ????AP?????????? */
    if (SYSTEM_APP_ANDROID != *pucSystemAppConfig)
    {
        if(SI_STK_CMD_END_EVENT != EventType)
        {
            ulResult = At_ChangeSTKCmdNo(SatType, &ucCmdType);
        }

        if(AT_FAILURE == ulResult)
        {
            return AT_FAILURE;
        }
    }

    if(TAF_FALSE == g_ulSTKFunctionFlag)
    {
        return AT_FAILURE;
    }

    switch (EventType)
    {
        case SI_STK_CMD_QUERY_RSP_EVENT:
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%s %d, 0%s",
                                               gaucAtStgi,
                                               ucCmdType,
                                               gaucAtCrLf);
            break;
        case SI_STK_CMD_IND_EVENT:
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%s %d, 0, 0%s",
                                               gaucAtStin,
                                               ucCmdType,
                                               gaucAtCrLf);
            break;
        case SI_STK_CMD_END_EVENT:
            if (SYSTEM_APP_ANDROID == *pucSystemAppConfig)
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                   "%s 0, 0%s",
                                                   gaucAtCsin,
                                                   gaucAtCrLf);
            }
            else
            {
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                   "%s 99, 0, 0%s",
                                                   gaucAtStin,
                                                   gaucAtCrLf);
            }
            break;
        default:
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (TAF_CHAR *)pgucAtSndCodeAddr,
                                               (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                                "%s %d, 0, 1%s",
                                                gaucAtStin,
                                                ucCmdType,
                                                gaucAtCrLf);
            break;
    }

    AT_SendSTKCMDTypeResultData(ucIndex, usLength);

    return AT_SUCCESS;
}


TAF_VOID AT_STKCnfMsgProc(MN_APP_STK_AT_CNF_STRU *pstSTKCnfMsg)
{
    TAF_UINT8                           ucIndex;
    TAF_UINT32                          ulResult;
    VOS_UINT8                          *pucSystemAppConfig;

    ucIndex                             = 0;
    ulResult                            = AT_OK;
    pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

    AT_LOG1("AT_STKCnfMsgProc pEvent->ClientId",   pstSTKCnfMsg->stSTKAtCnf.ClientId);
    AT_LOG1("AT_STKCnfMsgProc EventType",          pstSTKCnfMsg->stSTKAtCnf.STKCBEvent);
    AT_LOG1("AT_STKCnfMsgProc SIM Event Error",    pstSTKCnfMsg->stSTKAtCnf.STKErrorNo);

    gstAtSendData.usBufLen = 0;

    if(AT_FAILURE == At_ClientIdToUserId(pstSTKCnfMsg->stSTKAtCnf.ClientId,&ucIndex))
    {
        AT_ERR_LOG("AT_STKCnfMsgProc At_ClientIdToUserId FAILURE");
        return;
    }

    /* ?????????????????????????????? */
    if((SI_STK_CMD_IND_EVENT != pstSTKCnfMsg->stSTKAtCnf.STKCBEvent)
        &&(SI_STK_CMD_TIMEOUT_IND_EVENT != pstSTKCnfMsg->stSTKAtCnf.STKCBEvent)
        &&(SI_STK_CMD_END_EVENT != pstSTKCnfMsg->stSTKAtCnf.STKCBEvent)
        &&(SI_STK_CC_RESULT_IND_EVENT != pstSTKCnfMsg->stSTKAtCnf.STKCBEvent)

        &&(SI_STK_SMSCTRL_RESULT_IND_EVENT != pstSTKCnfMsg->stSTKAtCnf.STKCBEvent))
    {
        if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
        {
            AT_WARN_LOG("AT_STKCnfMsgProc: AT_BROADCAST_INDEX.");
            return;
        }

        AT_STOP_TIMER_CMD_READY(ucIndex);

        AT_LOG1("AT_STKCnfMsgProc ucIndex",            ucIndex);
        AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);
    }

    if(AT_SUCCESS != pstSTKCnfMsg->stSTKAtCnf.STKErrorNo)
    {
        ulResult = At_ChgTafErrorCode(ucIndex,(TAF_UINT16)pstSTKCnfMsg->stSTKAtCnf.STKErrorNo);       /* ???????? */

        At_FormatResultData(ucIndex,ulResult);
    }
    else
    {
        switch(pstSTKCnfMsg->stSTKAtCnf.STKCBEvent)
        {
            case SI_STK_CMD_IND_EVENT:
                if (SYSTEM_APP_ANDROID == *pucSystemAppConfig)
                {
                    At_StkCsinIndPrint(ucIndex,&(pstSTKCnfMsg->stSTKAtCnf));
                }
                else
                {
                    At_STKCMDTypePrint(ucIndex,pstSTKCnfMsg->stSTKAtCnf.STKCmdStru.SatType,pstSTKCnfMsg->stSTKAtCnf.STKCBEvent);
                }

                break;
            case SI_STK_CMD_END_EVENT:
            case SI_STK_CMD_TIMEOUT_IND_EVENT:
                At_STKCMDTypePrint(ucIndex,pstSTKCnfMsg->stSTKAtCnf.STKCmdStru.SatType,pstSTKCnfMsg->stSTKAtCnf.STKCBEvent);
                break;

            case SI_STK_CMD_QUERY_RSP_EVENT:
                At_STKCMDTypePrint(ucIndex,pstSTKCnfMsg->stSTKAtCnf.STKCmdStru.SatType,pstSTKCnfMsg->stSTKAtCnf.STKCBEvent);
                At_FormatResultData(ucIndex,ulResult);
                break;

            case SI_STK_GET_CMD_RSP_EVENT:
                if (SYSTEM_APP_ANDROID == *pucSystemAppConfig)
                {
                    At_StkCsinIndPrint(ucIndex, &(pstSTKCnfMsg->stSTKAtCnf));
                }
                else
                {
                    At_STKCMDDataPrintSimple(ucIndex, &(pstSTKCnfMsg->stSTKAtCnf));
                }

                At_FormatResultData(ucIndex,ulResult);
                break;

            case SI_STK_ENVELPOE_RSP_EVENT:
            case SI_STK_TERMINAL_RSP_EVENT:
                At_STKCMDSWPrintSimple(ucIndex,pstSTKCnfMsg->stSTKAtCnf.STKCBEvent,&pstSTKCnfMsg->stSTKAtCnf.STKSwStru);
                At_FormatResultData(ucIndex,ulResult);
                break;

            case SI_STK_CC_RESULT_IND_EVENT:
            case SI_STK_SMSCTRL_RESULT_IND_EVENT:
                At_StkCcinIndPrint(ucIndex, &(pstSTKCnfMsg->stSTKAtCnf));
                break;

            default:
                At_FormatResultData(ucIndex,ulResult);
                break;
        }
    }

    return;
}


TAF_VOID AT_STKPrintMsgProc(MN_APP_STK_AT_DATAPRINT_STRU *pstSTKPrintMsg)
{
    TAF_UINT8                       ucIndex = 0;

    if(AT_FAILURE == At_ClientIdToUserId(pstSTKPrintMsg->stSTKAtPrint.ClientId,&ucIndex))
    {
        AT_ERR_LOG("AT_STKPrintMsgProc At_ClientIdToUserId FAILURE");
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_STKPrintMsgProc: AT_BROADCAST_INDEX.");
        return;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    AT_LOG1("At_STKMsgProc pEvent->ClientId",   pstSTKPrintMsg->stSTKAtPrint.ClientId);
    AT_LOG1("At_STKMsgProc ucIndex",            ucIndex);
    AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);

    gucSTKCmdQualify = pstSTKPrintMsg->stSTKAtPrint.CmdQualify;

    TAF_MEM_CPY_S(pgucAtSndCodeAddr, AT_CMD_MAX_LEN + 20 - 3, pstSTKPrintMsg->stSTKAtPrint.aucData, pstSTKPrintMsg->stSTKAtPrint.DataLen);

    At_SendResultData(ucIndex,pgucAtSndCrLfAddr,(VOS_UINT16)pstSTKPrintMsg->stSTKAtPrint.DataLen+2);

    At_FormatResultData(ucIndex,AT_OK);

    return;
}


TAF_VOID At_STKMsgProc(MsgBlock* pMsg)
{
    MN_APP_STK_AT_DATAPRINT_STRU    *pstSTKPrintMsg;
    MN_APP_STK_AT_CNF_STRU          *pstSTKCnfMsg;

    pstSTKCnfMsg    = (MN_APP_STK_AT_CNF_STRU*)pMsg;
    pstSTKPrintMsg  = (MN_APP_STK_AT_DATAPRINT_STRU*)pMsg;

    if(STK_AT_DATAPRINT_CNF == pstSTKCnfMsg->ulMsgId)
    {
        AT_STKPrintMsgProc(pstSTKPrintMsg);
    }
    else if(STK_AT_EVENT_CNF == pstSTKCnfMsg->ulMsgId)
    {
        AT_STKCnfMsgProc(pstSTKCnfMsg);
    }
    else
    {
        AT_ERR_LOG1("At_STKMsgProc:Msg ID Error",pstSTKPrintMsg->ulMsgId);
    }

    return;
}



TAF_VOID At_DataStatusIndProc(TAF_UINT16  ClientId,
                                  TAF_UINT8      ucDomain,
                                  TAF_UINT8      ucRabId,
                                  TAF_UINT8      ucStatus,
                                  TAF_UINT8      ucCause )
{
    AT_RRETURN_CODE_ENUM_UINT32         ulResult = AT_FAILURE;
    TAF_UINT8 ucIndex = 0;
    TAF_UINT16 usLength = 0;

    AT_LOG1("At_DataStatusIndProc ClientId",ClientId);
    AT_LOG1("At_DataStatusIndProc ucDomain",ucDomain);
    AT_LOG1("At_DataStatusIndProc ucRabId",ucRabId);
    AT_LOG1("At_DataStatusIndProc ucStatus",ucStatus);
    AT_LOG1("At_DataStatusIndProc ucRabId",ucCause);
    if(AT_FAILURE == At_ClientIdToUserId(ClientId,&ucIndex))
    {
        AT_WARN_LOG("At_DataStatusIndProc At_ClientIdToUserId FAILURE");
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_DataStatusIndProc: AT_BROADCAST_INDEX.");
        return;
    }

    AT_LOG1("At_DataStatusIndProc ucIndex",ucIndex);
    AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);

    switch(ucStatus)
    {
    case TAF_RABM_STOP_DATA:
    case TAF_DATA_STOP:
        break;

      default:
        break;
    }

    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);
}

TAF_VOID At_DataStatusMsgProc(TAF_UINT8* pData,TAF_UINT16 usLen)
{
    TAF_UINT16  ClientId = 0;
    TAF_UINT8      ucDomain = 0;
    TAF_UINT8      ucRabId = 0;
    TAF_UINT8      ucStatus = 0;
    TAF_UINT8      ucCause = 0;
    TAF_UINT16 usAddr = 0;

    TAF_MEM_CPY_S(&ClientId, sizeof(ClientId), pData, sizeof(ClientId));
    usAddr += sizeof(ClientId);

    TAF_MEM_CPY_S(&ucDomain, sizeof(ucDomain), pData+usAddr, sizeof(ucDomain));
    usAddr += sizeof(ucDomain);

    TAF_MEM_CPY_S(&ucRabId, sizeof(ucRabId), pData+usAddr, sizeof(ucRabId));
    usAddr += sizeof(ucRabId);

    TAF_MEM_CPY_S(&ucStatus, sizeof(ucStatus), pData+usAddr, sizeof(ucStatus));
    usAddr += sizeof(ucStatus);

    TAF_MEM_CPY_S(&ucCause, sizeof(ucCause), pData+usAddr, sizeof(ucCause));
    /* usAddr += sizeof(ucCause); */

    At_DataStatusIndProc(ClientId,ucDomain,ucRabId,ucStatus,ucCause);
}


VOS_UINT32 AT_ConvertCallError(TAF_CS_CAUSE_ENUM_UINT32 enCause)
{
    AT_CME_CALL_ERR_CODE_MAP_STRU      *pstCallErrMapTblPtr = VOS_NULL_PTR;
    VOS_UINT32                          ulCallErrMapTblSize;
    VOS_UINT32                          ulCnt;

    pstCallErrMapTblPtr = AT_GET_CME_CALL_ERR_CODE_MAP_TBL_PTR();
    ulCallErrMapTblSize = AT_GET_CME_CALL_ERR_CODE_MAP_TBL_SIZE();

    for (ulCnt = 0; ulCnt < ulCallErrMapTblSize; ulCnt++)
    {
        if (pstCallErrMapTblPtr[ulCnt].enCsCause == enCause)
        {
            return pstCallErrMapTblPtr[ulCnt].ulCmeCode;
        }
    }

    return AT_CME_UNKNOWN;
}


AT_ENCRYPT_VOICE_ERROR_ENUM_UINT32  AT_MapEncVoiceErr(
    TAF_CALL_APP_ENCRYPT_VOICE_STATUS_ENUM_UINT32           enTafEncVoiceErr
)
{
    VOS_UINT32                          i;
    AT_ENCRYPT_VOICE_ERR_CODE_MAP_STRU *pstAtEncVoiceErrMapTbl;
    VOS_UINT32                          ulAtEncVoiceErrMapSize;

    pstAtEncVoiceErrMapTbl = AT_GET_ENC_VOICE_ERR_CODE_MAP_TBL_PTR();
    ulAtEncVoiceErrMapSize = AT_GET_ENC_VOICE_ERR_CODE_MAP_TBL_SIZE();

    for (i = 0; i < ulAtEncVoiceErrMapSize; i++)
    {
        if (pstAtEncVoiceErrMapTbl[i].enTafEncErr == enTafEncVoiceErr)
        {
            return pstAtEncVoiceErrMapTbl[i].enAtEncErr;
        }
    }
    return AT_ENCRYPT_VOICE_ERROR_ENUM_BUTT;
}


TAF_UINT32 At_CmdCmgdMsgProc(
    TAF_UINT8                                               ucIndex,
    TAF_UINT32                                              ulErrorCode
)
{
    VOS_UINT8                       *pucSystemAppConfig = VOS_NULL_PTR;
    TAF_UINT32                       ulResult           = AT_FAILURE;

    pucSystemAppConfig              = AT_GetSystemAppConfigAddr();

    if ((MN_ERR_CLASS_SMS_EMPTY_REC == ulErrorCode)
     && (SYSTEM_APP_ANDROID != *pucSystemAppConfig))
    {
        ulResult = AT_OK;
        AT_STOP_TIMER_CMD_READY(ucIndex);
    }
    else
    {
        ulResult = At_ChgMnErrCodeToAt(ucIndex,ulErrorCode);                     /* ???????? */
        AT_STOP_TIMER_CMD_READY(ucIndex);
    }

    return ulResult;
}



TAF_VOID At_CmdCnfMsgProc(TAF_UINT8* pData,TAF_UINT16 usLen)
{
    AT_CMD_CNF_EVENT                    *pstCmdCnf;
    MN_CLIENT_ID_T                      clientId;
    TAF_UINT32                          ulErrorCode;
    TAF_UINT8                           ucIndex;
    TAF_UINT32                          ulResult = AT_FAILURE;
    TAF_UINT16                          usLength = 0;

    pstCmdCnf = (AT_CMD_CNF_EVENT *)pData;

    clientId    = pstCmdCnf->clientId;
    ulErrorCode = pstCmdCnf->ulErrorCode;

    if(AT_FAILURE == At_ClientIdToUserId(clientId,&ucIndex))
    {
        AT_WARN_LOG("At_CmdCnfMsgProc At_ClientIdToUserId FAILURE");
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_CmdCnfMsgProc: AT_BROADCAST_INDEX.");
        return;
    }

    if (AT_FW_CLIENT_STATUS_READY == g_stParseContext[ucIndex].ucClientStatus)
    {
        AT_WARN_LOG("At_CmdCnfMsgProc : AT command entity is released.");
        return;
    }

    /*
        call????????????TAF_CS_CAUSE_SUCCESS????????????????????MN_ERR_NO_ERROR,
        ????????????????0
    */
    if (MN_ERR_NO_ERROR == ulErrorCode)
    {
        /* ??????????????????C??????????????????????????????MN_ERR_NO_ERROR
           AT??????????????????AT_OK */
        if (AT_CMD_H_SET == gastAtClientTab[ucIndex].CmdCurrentOpt
         || AT_CMD_CHUP_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
        {
            AT_STOP_TIMER_CMD_READY(ucIndex);
            At_FormatResultData(ucIndex,AT_OK);
        }

        AT_NORM_LOG("At_CmdCnfMsgProc Rsp No Err");
        return;
    }

    AT_LOG1("At_CmdCnfMsgProc ucIndex",ucIndex);
    AT_LOG1("gastAtClientTab[ucIndex].CmdCurrentOpt",gastAtClientTab[ucIndex].CmdCurrentOpt);

    switch(gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
    case AT_CMD_CDUR_READ:
    /* CCWA???????? */
    case AT_CMD_CCWA_DISABLE:
    case AT_CMD_CCWA_ENABLE:
    case AT_CMD_CCWA_QUERY:

    /* CCFC???? */
    case AT_CMD_CCFC_DISABLE:
    case AT_CMD_CCFC_ENABLE:
    case AT_CMD_CCFC_QUERY:
    case AT_CMD_CCFC_REGISTRATION:
    case AT_CMD_CCFC_ERASURE:

    /* CUSD???????? */
    case AT_CMD_CUSD_REQ:

    /* CLCK???????? */
    case AT_CMD_CLCK_UNLOCK:
    case AT_CMD_CLCK_LOCK:
    case AT_CMD_CLCK_QUERY:

    /* CLOP???? */
    case AT_CMD_COLP_READ:

    /* CLIR???? */
    case AT_CMD_CLIR_READ:

    /* CLIP???? */
    case AT_CMD_CLIP_READ:
    /* CPWD???? */
    case AT_CMD_CPWD_SET:

    case AT_CMD_CNAP_QRY:
        ulResult = AT_ConvertCallError(ulErrorCode);
        AT_STOP_TIMER_CMD_READY(ucIndex);
        break;
    case AT_CMD_CSCA_READ:
        ulResult = At_ChgMnErrCodeToAt(ucIndex, ulErrorCode);
        AT_STOP_TIMER_CMD_READY(ucIndex);
        break;
    case AT_CMD_CPMS_SET:
    case AT_CMD_CPMS_READ:
        ulResult = AT_CMS_UNKNOWN_ERROR;
        AT_STOP_TIMER_CMD_READY(ucIndex);
        break;


    /*
        ????ulErrorCode????TAF_CS_CAUSE_NO_CALL_ID????AT_CMD_D_CS_VOICE_CALL_SET
        ??AT_CMD_D_CS_DATA_CALL_SET????????????AT_NO_CARRIER??????
    */

    case AT_CMD_D_CS_VOICE_CALL_SET:
    case AT_CMD_APDS_SET:
        if (TAF_CS_CAUSE_NO_CALL_ID == ulErrorCode)
        {
            ulResult = AT_ERROR;
            AT_STOP_TIMER_CMD_READY(ucIndex);
            break;
        }

    case AT_CMD_D_CS_DATA_CALL_SET:
         ulResult = AT_NO_CARRIER;
         AT_STOP_TIMER_CMD_READY(ucIndex);
         break;

    case AT_CMD_CHLD_SET:
    case AT_CMD_CHUP_SET:
    case AT_CMD_A_SET:
    case AT_CMD_CHLD_EX_SET:
    case AT_CMD_H_SET:
        ulResult = AT_ConvertCallError(ulErrorCode);                            /* ???????? */
        AT_STOP_TIMER_CMD_READY(ucIndex);
        break;
    case AT_CMD_CMGR_SET:
    case AT_CMD_CMGD_SET:
        ulResult = At_CmdCmgdMsgProc(ucIndex, ulErrorCode);
        break;
        /* fall through */
    case AT_CMD_CSMS_SET:
    case AT_CMD_CMMS_SET:
    case AT_CMD_CGSMS_SET:
    case AT_CMD_CGSMS_READ:
    case AT_CMD_CMMS_READ:
    case AT_CMD_CSMP_READ:    /*del*/
    case AT_CMD_CMGS_TEXT_SET:
    case AT_CMD_CMGS_PDU_SET:
    case AT_CMD_CMGC_TEXT_SET:
    case AT_CMD_CMGC_PDU_SET:
    case AT_CMD_CMSS_SET:
    case AT_CMD_CMST_SET:
    case AT_CMD_CNMA_TEXT_SET:
    case AT_CMD_CNMA_PDU_SET:
    case AT_CMD_CMGW_PDU_SET:
    case AT_CMD_CMGW_TEXT_SET:
    case AT_CMD_CMGL_SET:
    case AT_CMD_CMGD_TEST:
    case AT_CMD_CSMP_SET:
    case AT_CMD_CSCA_SET:
    case AT_CMD_CSCB_SET:
    case AT_CMD_CSCB_READ:
        ulResult = At_ChgMnErrCodeToAt(ucIndex,ulErrorCode);                     /* ???????? */
        AT_STOP_TIMER_CMD_READY(ucIndex);
        break;
    default:
        /*????????????????????????????????????????*/
        ulResult = AT_CME_UNKNOWN;
        AT_STOP_TIMER_CMD_READY(ucIndex);
        break;
    }

    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);

}


TAF_UINT32 At_PrintTimeZoneInfo(
    NAS_MM_INFO_IND_STRU                *pstMmInfo,
    VOS_UINT8                           *pucDst
)
{
    VOS_INT8                            cTimeZone;
    VOS_UINT8                           ucTimeZoneValue;
    VOS_UINT16                          usLength;

    usLength  = 0;
    cTimeZone = AT_INVALID_TZ_VALUE;

    /* ?????????????????????? */
    if (NAS_MM_INFO_IE_UTLTZ == (pstMmInfo->ucIeFlg & NAS_MM_INFO_IE_UTLTZ))
    {
        cTimeZone   = pstMmInfo->stUniversalTimeandLocalTimeZone.cTimeZone;
    }

    if (NAS_MM_INFO_IE_LTZ == (pstMmInfo->ucIeFlg & NAS_MM_INFO_IE_LTZ))
    {
        cTimeZone   = pstMmInfo->cLocalTimeZone;
    }

    if (cTimeZone < 0)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           "-");

        ucTimeZoneValue = (VOS_UINT8)(cTimeZone * (-1));
    }
    else
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           "+");

        ucTimeZoneValue = (VOS_UINT8)cTimeZone;
    }

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pucDst + usLength,
                                       "%02d",
                                       ucTimeZoneValue);

    /* ???? */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pucDst + usLength,
                                        "\"%s",
                                       gaucAtCrLf);
    return usLength;
}


VOS_UINT32 AT_PrintTimeZoneInfoNoAdjustment(
    TAF_AT_COMM_TIME_STRU              *pstMmInfo,
    VOS_UINT8                          *pucDst
)
{
    VOS_INT8                            cTimeZone;
    VOS_UINT8                           ucTimeZoneValue;
    VOS_UINT16                          usLength;

    usLength  = 0;
    cTimeZone = AT_INVALID_TZ_VALUE;

    /* ???????? */
    if (NAS_MM_INFO_IE_UTLTZ == (pstMmInfo->ucIeFlg & NAS_MM_INFO_IE_UTLTZ))
    {
        cTimeZone   = pstMmInfo->stUniversalTimeandLocalTimeZone.cTimeZone;
    }


    if (cTimeZone < 0)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           "-");

        ucTimeZoneValue = (VOS_UINT8)(cTimeZone * (-1));
    }
    else
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           "+");

        ucTimeZoneValue = (VOS_UINT8)cTimeZone;
    }

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pucDst + usLength,
                                       "%d",
                                       ucTimeZoneValue);


    /* ?????????????????????? */
    if ( (NAS_MM_INFO_IE_DST == (pstMmInfo->ucIeFlg & NAS_MM_INFO_IE_DST))
      && (pstMmInfo->ucDST > 0))
    {
        /* ??????: DST????????, ????????0??*/
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           ",%02d\"%s",
                                           pstMmInfo->ucDST,
                                           gaucAtCrLf);
    }
    else
    {
        /* ?????? */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           ",00\"%s",
                                           gaucAtCrLf);
    }

    return usLength;
}


VOS_UINT32 AT_PrintTimeZoneInfoWithCtzeType(
    TAF_AT_COMM_TIME_STRU               *pstMmInfo,
    VOS_UINT8                           *pucDst
)
{
    VOS_INT8                            cTimeZone;
    VOS_UINT8                           ucTimeZoneValue;
    VOS_UINT16                          usLength;

    usLength  = 0;
    cTimeZone = AT_INVALID_TZ_VALUE;

    /* ?????????????????????? */
    if (NAS_MM_INFO_IE_UTLTZ == (pstMmInfo->ucIeFlg & NAS_MM_INFO_IE_UTLTZ))
    {
        cTimeZone   = pstMmInfo->stUniversalTimeandLocalTimeZone.cTimeZone;
    }

    if (NAS_MM_INFO_IE_LTZ == (pstMmInfo->ucIeFlg & NAS_MM_INFO_IE_LTZ))
    {
        cTimeZone   = pstMmInfo->cLocalTimeZone;
    }

    if (cTimeZone < 0)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           "-");

        ucTimeZoneValue = (VOS_UINT8)(cTimeZone * (-1));
    }
    else
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           "+");

        ucTimeZoneValue = (VOS_UINT8)cTimeZone;
    }

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pucDst + usLength,
                                       "%02d",
                                       ucTimeZoneValue);

    /* ?????????????????????? */
    if ((NAS_MM_INFO_IE_DST == (pstMmInfo->ucIeFlg & NAS_MM_INFO_IE_DST))
      && (pstMmInfo->ucDST > 0))
    {
        /* ??????: DST????????, ????????0??*/
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           ",%01d",
                                           pstMmInfo->ucDST);
    }
    else
    {
        /* ?????? */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           ",0");
    }

    /* ???????????? */
    if (NAS_MM_INFO_IE_UTLTZ == (pstMmInfo->ucIeFlg & NAS_MM_INFO_IE_UTLTZ))
    {
        /* YY */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           ",%d%d/",
                                           pstMmInfo->stUniversalTimeandLocalTimeZone.usYear / 10,
                                           pstMmInfo->stUniversalTimeandLocalTimeZone.usYear % 10);
        /* MM */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           "%d%d/",
                                           pstMmInfo->stUniversalTimeandLocalTimeZone.ucMonth / 10,
                                           pstMmInfo->stUniversalTimeandLocalTimeZone.ucMonth % 10);
        /* dd */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           "%d%d,",
                                           pstMmInfo->stUniversalTimeandLocalTimeZone.ucDay / 10,
                                           pstMmInfo->stUniversalTimeandLocalTimeZone.ucDay % 10);

        /* hh */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           "%d%d:",
                                           pstMmInfo->stUniversalTimeandLocalTimeZone.ucHour / 10,
                                           pstMmInfo->stUniversalTimeandLocalTimeZone.ucHour % 10);

        /* mm */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           "%d%d:",
                                           pstMmInfo->stUniversalTimeandLocalTimeZone.ucMinute / 10,
                                           pstMmInfo->stUniversalTimeandLocalTimeZone.ucMinute % 10);

        /* ss */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                           "%d%d",
                                           pstMmInfo->stUniversalTimeandLocalTimeZone.ucSecond / 10,
                                           pstMmInfo->stUniversalTimeandLocalTimeZone.ucSecond % 10);

    }

    /* ???? */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pucDst + usLength,
                                            "\"%s",
                                           gaucAtCrLf);
    return usLength;
}


VOS_UINT8 At_GetDaysForEachMonth(
    VOS_UINT8                               ucYear,
    VOS_UINT8                               ucMonth
)
{
    VOS_UINT16   usAdjustYear;

    /* ??????year??????????????????2000?????????? */
    usAdjustYear = 2000 + ucYear;

    if ((1 == ucMonth) || (3 == ucMonth) || (5 == ucMonth) || (7 == ucMonth)
     || (8 == ucMonth) || (10 == ucMonth) || (12 == ucMonth) )
    {
        /* 1,3,5,7,8,10,12????31?? */
        return 31;
    }
    else if ((4 == ucMonth) || (6 == ucMonth) || (9 == ucMonth) || (11 == ucMonth))
    {
        /* 4,6,9,11????30?? */
        return 30;
    }
    else
    {
        /* 2??????????????????????29??????????28?? */
        if ( ((0 == (usAdjustYear % 4)) && (0 != (usAdjustYear % 100))) || (0 == (usAdjustYear % 400)))
        {
            /* ???? */
            return 29;
        }
        else
        {
            /* ?????? */
            return 28;
        }
    }
}


VOS_VOID At_AdjustLocalDate(
    TIME_ZONE_TIME_STRU                 *pstUinversalTime,
    VOS_INT8                            cAdjustValue,
    TIME_ZONE_TIME_STRU                 *pstLocalTime
)
{
    VOS_UINT8    ucDay;

    /* ???????? */
    ucDay = (VOS_UINT8)(pstUinversalTime->ucDay + cAdjustValue);

    if (0 == ucDay)
    {
        /* ???????? */
        if ( 1 == pstUinversalTime->ucMonth )
        {
            /* ??????????????12????,???????? */
            pstLocalTime->ucMonth = 12;

            if (0 == pstUinversalTime->ucYear)
            {
                /* ??????2000??????????1999?? */
                pstLocalTime->ucYear = 99;
            }
            else
            {
                pstLocalTime->ucYear = pstUinversalTime->ucYear - 1;
            }
        }
        else
        {
            pstLocalTime->ucMonth = pstUinversalTime->ucMonth - 1;
            pstLocalTime->ucYear  = pstUinversalTime->ucYear;
        }

        /* ??????????????????????????, */
        pstLocalTime->ucDay = At_GetDaysForEachMonth(pstLocalTime->ucYear, pstLocalTime->ucMonth);
    }
    else if (ucDay > At_GetDaysForEachMonth(pstUinversalTime->ucYear, pstUinversalTime->ucMonth))
    {
        /*???????????????????? */
        pstLocalTime->ucDay = 1;

        /* ???????? */
        if ( 12 == pstUinversalTime->ucMonth )
        {
            /* ??????????????1????,???????? */
            pstLocalTime->ucMonth = 1;
            pstLocalTime->ucYear = pstUinversalTime->ucYear + 1;
        }
        else
        {
            pstLocalTime->ucMonth = pstUinversalTime->ucMonth + 1;
            pstLocalTime->ucYear = pstUinversalTime->ucYear;
        }
    }
    else
    {
        pstLocalTime->ucDay   = ucDay;
        pstLocalTime->ucMonth = pstUinversalTime->ucMonth;
        pstLocalTime->ucYear  = pstUinversalTime->ucYear;
    }
}


VOS_VOID At_UniversalTime2LocalTime(
    TIME_ZONE_TIME_STRU                 *pstUinversalTime,
    TIME_ZONE_TIME_STRU                 *pstLocalTime
)
{
    VOS_INT8    cTemp;
    VOS_INT8    cAdjustValue;

    pstLocalTime->cTimeZone = pstUinversalTime->cTimeZone;

    /* ????????????????????????????????????????????????????15?????????? */

    /* ?????????? */
    pstLocalTime->ucSecond  = pstUinversalTime->ucSecond;

    /* ?????????? */
    cTemp = (VOS_INT8)(((pstUinversalTime->cTimeZone % 4) * 15) + pstUinversalTime->ucMinute);
    if (cTemp >= 60)
    {
        /*??????????????????????60?????????????? 1 */
        pstLocalTime->ucMinute  = (VOS_UINT8)(cTemp - 60);
        cAdjustValue = 1;
    }
    else if (cTemp < 0)
    {
        /*??????????????????????0?????????????? 1 */
        pstLocalTime->ucMinute  = (VOS_UINT8)(cTemp + 60);
        cAdjustValue = -1;
    }
    else
    {
        pstLocalTime->ucMinute = (VOS_UINT8)cTemp;
        cAdjustValue = 0;
    }

    /* ?????????? */
    cTemp = (VOS_INT8)((pstUinversalTime->cTimeZone / 4) + pstUinversalTime->ucHour + cAdjustValue);

    if (cTemp >= 24)
    {
        /*????????????????????24???????????? 1 */
        pstLocalTime->ucHour = (VOS_UINT8)(cTemp - 24);
        cAdjustValue = 1;
    }
    else if (cTemp < 0)
    {
        /*????????????????????0???????? 1 */
        pstLocalTime->ucHour = (VOS_UINT8)(cTemp + 24);
        cAdjustValue = -1;
    }
    else
    {
        pstLocalTime->ucHour = (VOS_UINT8)cTemp;
        cAdjustValue = 0;
    }

    /* ???????????? */
    At_AdjustLocalDate(pstUinversalTime, cAdjustValue, pstLocalTime);

    return;
}


TAF_UINT32 At_PrintMmTimeInfo(
    VOS_UINT8                           ucIndex,
    TAF_AT_COMM_TIME_STRU              *pstMmTimeInfo,
    TAF_UINT8                          *pDst
)
{
    TAF_UINT16                          usLength;
    TAF_INT8                            cTimeZone;
    AT_MODEM_NET_CTX_STRU              *pstNetCtx = VOS_NULL_PTR;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;
    VOS_UINT32                          ulChkTimeFlg;
    VOS_UINT32                          ulChkCtzvFlg;
    VOS_UINT32                          ulChkCtzeFlg;

    usLength = 0;

    enModemId = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("At_PrintMmTimeInfo: Get modem id fail.");
        return usLength;
    }

    pstNetCtx = AT_GetModemNetCtxAddrFromModemId(enModemId);

    if (NAS_MM_INFO_IE_UTLTZ == (pstMmTimeInfo->ucIeFlg & NAS_MM_INFO_IE_UTLTZ))
    {
        /* ?????????????????????????????????????????????? */
        pstNetCtx->stTimeInfo.ucIeFlg |= NAS_MM_INFO_IE_UTLTZ;

        pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucYear   = pstMmTimeInfo->stUniversalTimeandLocalTimeZone.usYear % 100;
        pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucMonth  = pstMmTimeInfo->stUniversalTimeandLocalTimeZone.ucMonth;
        pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucDay    = pstMmTimeInfo->stUniversalTimeandLocalTimeZone.ucDay;
        pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucHour   = pstMmTimeInfo->stUniversalTimeandLocalTimeZone.ucHour;
        pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucMinute = pstMmTimeInfo->stUniversalTimeandLocalTimeZone.ucMinute;
        pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucSecond = pstMmTimeInfo->stUniversalTimeandLocalTimeZone.ucSecond;
        pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.Reserved = 0x00;
        pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.cTimeZone = pstMmTimeInfo->stUniversalTimeandLocalTimeZone.cTimeZone;
        pstNetCtx->ulNwSecond                                           = AT_GetSeconds();
    }

    /* ????DST???? */
    if (NAS_MM_INFO_IE_DST == (pstMmTimeInfo->ucIeFlg & NAS_MM_INFO_IE_DST))
    {
        /* ?????????????????????? */
        pstNetCtx->stTimeInfo.ucIeFlg |= NAS_MM_INFO_IE_DST;
        pstNetCtx->stTimeInfo.ucDST = pstMmTimeInfo->ucDST;
    }
    else
    {
        pstNetCtx->stTimeInfo.ucIeFlg &= ~NAS_MM_INFO_IE_DST;
    }

    ulChkCtzvFlg    = AT_CheckRptCmdStatus(pstMmTimeInfo->aucUnsolicitedRptCfg, AT_CMD_RPT_CTRL_BY_UNSOLICITED, AT_RPT_CMD_CTZV);
    ulChkTimeFlg    = AT_CheckRptCmdStatus(pstMmTimeInfo->aucUnsolicitedRptCfg, AT_CMD_RPT_CTRL_BY_UNSOLICITED, AT_RPT_CMD_TIME);
    ulChkCtzeFlg    = AT_CheckRptCmdStatus(pstMmTimeInfo->aucUnsolicitedRptCfg, AT_CMD_RPT_CTRL_BY_UNSOLICITED, AT_RPT_CMD_CTZE);

    /*????????????: +CTZV: "GMT??tz, Summer(Winter) Time" */
    if ((VOS_TRUE == AT_CheckRptCmdStatus(pstMmTimeInfo->aucCurcRptCfg, AT_CMD_RPT_CTRL_BY_CURC, AT_RPT_CMD_CTZV))
     && (VOS_TRUE == ulChkCtzvFlg))

    {
        if (NAS_MM_INFO_IE_UTLTZ == (pstMmTimeInfo->ucIeFlg & NAS_MM_INFO_IE_UTLTZ))
        {
            cTimeZone = pstMmTimeInfo->stUniversalTimeandLocalTimeZone.cTimeZone;
        }
        else
        {
            cTimeZone = pstMmTimeInfo->cLocalTimeZone;
        }

        if (cTimeZone != pstNetCtx->stTimeInfo.cLocalTimeZone)
        {
            /* ?????????????????????? */
            pstNetCtx->stTimeInfo.ucIeFlg |= NAS_MM_INFO_IE_LTZ;
            pstNetCtx->stTimeInfo.cLocalTimeZone = cTimeZone;
            pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.cTimeZone = cTimeZone;

            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pDst + usLength,
                                               "%s%s\"",gaucAtCrLf,
                                               gastAtStringTab[AT_STRING_CTZV].pucText);

            usLength += (VOS_UINT16)At_PrintTimeZoneInfo(&(pstNetCtx->stTimeInfo),
                                                         pDst + usLength);
        }

    }

    /* ????????????:+CTZE: "(+/-)tz,dst,yyyy/mm/dd,hh:mm:ss" */
    if ((VOS_TRUE == AT_CheckRptCmdStatus(pstMmTimeInfo->aucCurcRptCfg, AT_CMD_RPT_CTRL_BY_CURC, AT_RPT_CMD_CTZE))
     && (VOS_TRUE == ulChkCtzeFlg))
    {

        if (NAS_MM_INFO_IE_UTLTZ == (pstMmTimeInfo->ucIeFlg & NAS_MM_INFO_IE_UTLTZ))
        {
            cTimeZone = pstMmTimeInfo->stUniversalTimeandLocalTimeZone.cTimeZone;
        }
        else
        {
            cTimeZone = pstMmTimeInfo->cLocalTimeZone;
        }

        if (cTimeZone != pstNetCtx->stTimeInfo.cLocalTimeZone)
        {
            /* ?????????????????????? */
            pstNetCtx->stTimeInfo.ucIeFlg |= NAS_MM_INFO_IE_LTZ;
            pstNetCtx->stTimeInfo.cLocalTimeZone = cTimeZone;
            pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.cTimeZone = cTimeZone;
        }

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pDst + usLength,
                                       "%s%s\"",gaucAtCrLf,
                                       gastAtStringTab[AT_STRING_CTZE].pucText);

        usLength += (VOS_UINT16)AT_PrintTimeZoneInfoWithCtzeType(pstMmTimeInfo,
                                                 pDst + usLength);



    }
    /*????????????: ^TIME: "yy/mm/dd,hh:mm:ss(+/-)tz,dst" */
    if ((VOS_TRUE == AT_CheckRptCmdStatus(pstMmTimeInfo->aucCurcRptCfg, AT_CMD_RPT_CTRL_BY_CURC, AT_RPT_CMD_TIME))
     && (VOS_TRUE == ulChkTimeFlg)
     && (NAS_MM_INFO_IE_UTLTZ == (pstMmTimeInfo->ucIeFlg & NAS_MM_INFO_IE_UTLTZ)))
    {
        /* "^TIME: */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pDst + usLength,
                                           "%s%s",gaucAtCrLf,
                                           gastAtStringTab[AT_STRING_TIME].pucText);

        /* YY */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pDst + usLength,
                                           "\"%d%d/",
                                           pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucYear / 10,
                                           pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucYear % 10);
        /* MM */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pDst + usLength,
                                           "%d%d/",
                                           pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucMonth / 10,
                                           pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucMonth % 10);
        /* dd */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pDst + usLength,
                                           "%d%d,",
                                           pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucDay / 10,
                                           pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucDay % 10);

        /* hh */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pDst + usLength,
                                           "%d%d:",
                                           pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucHour / 10,
                                           pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucHour % 10);

        /* mm */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pDst + usLength,
                                           "%d%d:",
                                           pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucMinute / 10,
                                           pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucMinute % 10);

        /* ss */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pDst + usLength,
                                           "%d%d",
                                           pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucSecond / 10,
                                           pstNetCtx->stTimeInfo.stUniversalTimeandLocalTimeZone.ucSecond % 10);

        /* GMT??tz, Summer(Winter) Time" */
        usLength += (VOS_UINT16)AT_PrintTimeZoneInfoNoAdjustment(pstMmTimeInfo,
                                                                 pDst + usLength);
    }

    return usLength;
}

/* begin V7R1 PhaseI Modify */

VOS_UINT32  AT_GetSysModeName(
    MN_PH_SYS_MODE_EX_ENUM_U8           enSysMode,
    VOS_CHAR                           *pucSysModeName,
    VOS_UINT32                          ulMaxMemLength
)
{
    VOS_UINT32                          i;

    for ( i = 0 ; i < sizeof(g_astSysModeTbl)/sizeof(AT_PH_SYS_MODE_TBL_STRU) ; i++ )
    {
        if ( g_astSysModeTbl[i].enSysMode == enSysMode)
        {
            VOS_StrNCpy_s(pucSysModeName, ulMaxMemLength,
                        g_astSysModeTbl[i].pcStrSysModeName,
                        VOS_StrLen(g_astSysModeTbl[i].pcStrSysModeName));

            return VOS_OK;
        }
    }

    return VOS_ERR;
}


VOS_UINT32  AT_GetSubSysModeName(
    MN_PH_SUB_SYS_MODE_EX_ENUM_U8       enSubSysMode,
    VOS_CHAR                           *pucSubSysModeName,
    VOS_UINT32                          ulMaxMemLength
)
{
    VOS_UINT32                          i;

    for ( i = 0 ; i < sizeof(g_astSubSysModeTbl)/sizeof(AT_PH_SUB_SYS_MODE_TBL_STRU) ; i++ )
    {
        if ( g_astSubSysModeTbl[i].enSubSysMode == enSubSysMode)
        {
            VOS_StrNCpy_s(pucSubSysModeName, ulMaxMemLength,
                        g_astSubSysModeTbl[i].pcStrSubSysModeName,
                        VOS_StrLen(g_astSubSysModeTbl[i].pcStrSubSysModeName));

            return VOS_OK;
        }
    }

    return VOS_ERR;
}


VOS_VOID  AT_QryParaRspSysinfoExProc(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                           OpId,
    VOS_VOID                           *pPara
)
{
    VOS_UINT32                          ulResult;
    VOS_UINT16                          usLength;
    VOS_CHAR                            aucSysModeName[255];
    VOS_CHAR                            aucSubSysModeName[255];
    TAF_PH_SYSINFO_STRU                 stSysInfo;
    VOS_UINT8                          *pucSystemAppConfig = VOS_NULL_PTR;

    pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

    TAF_MEM_SET_S(&stSysInfo, sizeof(stSysInfo), 0x00, sizeof(TAF_PH_SYSINFO_STRU));

    TAF_MEM_CPY_S(&stSysInfo, sizeof(stSysInfo), pPara, sizeof(TAF_PH_SYSINFO_STRU));

    usLength  = 0;
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s:%d",g_stParseContext[ucIndex].pstCmdElement->pszCmdName,stSysInfo.ucSrvStatus);
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",stSysInfo.ucSrvDomain);
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",stSysInfo.ucRoamStatus);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",stSysInfo.ucSimStatus);

    if ( SYSTEM_APP_WEBUI == *pucSystemAppConfig)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",stSysInfo.ucSimLockStatus);
    }
    else
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",");
    }

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",stSysInfo.ucSysMode);

    TAF_MEM_SET_S(aucSysModeName, sizeof(aucSysModeName), 0x00, sizeof(aucSysModeName));
    TAF_MEM_SET_S(aucSubSysModeName, sizeof(aucSubSysModeName), 0x00, sizeof(aucSubSysModeName));

    /* ????SysMode?????? */
    AT_GetSysModeName(stSysInfo.ucSysMode, aucSysModeName, (TAF_UINT32)sizeof(aucSysModeName));

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"%s\"",aucSysModeName);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",stSysInfo.ucSysSubMode);

    /* ????SubSysMode?????? */
    AT_GetSubSysModeName(stSysInfo.ucSysSubMode, aucSubSysModeName, (TAF_UINT32)sizeof(aucSubSysModeName));

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"%s\"",aucSubSysModeName);
    ulResult = AT_OK;
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);
}
/* end V7R1 PhaseI Modify */


VOS_VOID  AT_QryParaAnQueryProc(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                           OpId,
    VOS_VOID                           *pPara
)
{
    VOS_UINT32                          ulResult;
    MN_MMA_ANQUERY_PARA_STRU            stAnqueryPara;
    AT_CMD_ANTENNA_LEVEL_ENUM_UINT8     enCurAntennaLevel;
    AT_MODEM_NET_CTX_STRU              *pstNetCtx = VOS_NULL_PTR;
    VOS_UINT8                          *pucSystemAppConfig = VOS_NULL_PTR;
    VOS_INT16                           sRsrp;
    VOS_INT16                           sRsrq;
    VOS_UINT8                           ucLevel;
    VOS_INT16                           sRssi;

    /* ?????? */
    ulResult   = AT_OK;
    TAF_MEM_SET_S(&stAnqueryPara, sizeof(stAnqueryPara), 0x00, sizeof(MN_MMA_ANQUERY_PARA_STRU));

    TAF_MEM_CPY_S(&stAnqueryPara, sizeof(stAnqueryPara), pPara, sizeof(MN_MMA_ANQUERY_PARA_STRU));

    if((TAF_MMA_RAT_GSM  == stAnqueryPara.enServiceSysMode)
    || (TAF_MMA_RAT_WCDMA == stAnqueryPara.enServiceSysMode))
    {
        pstNetCtx = AT_GetModemNetCtxAddrFromClientId(ucIndex);


        /* ????????????:?? Rscp??Ecio????????????????Rscp??Ecio??-145??-32??????rssi??99??
           ????????0 */
        if ( ((0 == stAnqueryPara.u.st2G3GCellSignInfo.sCpichRscp) && (0 == stAnqueryPara.u.st2G3GCellSignInfo.sCpichEcNo))
          || (99 == stAnqueryPara.u.st2G3GCellSignInfo.ucRssi) )
        {
            /* ????????0, ?????????????? */
            enCurAntennaLevel       = AT_CMD_ANTENNA_LEVEL_0;
        }
        else
        {
            /* ????????AT_CalculateAntennaLevel??????D25?????????????????? */
            enCurAntennaLevel = AT_CalculateAntennaLevel(stAnqueryPara.u.st2G3GCellSignInfo.sCpichRscp,
                                                         stAnqueryPara.u.st2G3GCellSignInfo.sCpichEcNo);
        }

        /* ???????????? */
        AT_GetSmoothAntennaLevel(ucIndex, enCurAntennaLevel );

        stAnqueryPara.u.st2G3GCellSignInfo.sCpichRscp     = -stAnqueryPara.u.st2G3GCellSignInfo.sCpichRscp;
        stAnqueryPara.u.st2G3GCellSignInfo.sCpichEcNo     = -stAnqueryPara.u.st2G3GCellSignInfo.sCpichEcNo;

        pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

        if ( SYSTEM_APP_WEBUI == *pucSystemAppConfig)
        {
            gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        "%s:%d,%d,%d,%d,0,0",
                                                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                        (VOS_INT32)stAnqueryPara.u.st2G3GCellSignInfo.sCpichRscp,
                                                        (VOS_INT32)stAnqueryPara.u.st2G3GCellSignInfo.sCpichEcNo,
                                                        (VOS_INT32)stAnqueryPara.u.st2G3GCellSignInfo.ucRssi,
                                                        (VOS_INT32)pstNetCtx->enCalculateAntennaLevel);


            /* ???????????????? */
            At_FormatResultData(ucIndex,ulResult);

            return;
        }
        gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                                       "%s:%d,%d,%d,%d,0x%X",
                                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                       (VOS_INT32)stAnqueryPara.u.st2G3GCellSignInfo.sCpichRscp,
                                                       (VOS_INT32)stAnqueryPara.u.st2G3GCellSignInfo.sCpichEcNo,
                                                       (VOS_INT32)stAnqueryPara.u.st2G3GCellSignInfo.ucRssi,
                                                       (VOS_INT32)pstNetCtx->enCalculateAntennaLevel,
                                                       (VOS_INT32)stAnqueryPara.u.st2G3GCellSignInfo.ulCellId);

        /* ???????????????? */
        At_FormatResultData(ucIndex,ulResult);

        return;
    }
    else if(TAF_MMA_RAT_LTE == stAnqueryPara.enServiceSysMode)
    {
            sRsrp   = stAnqueryPara.u.st4GCellSignInfo.sRsrp;
            sRsrq   = stAnqueryPara.u.st4GCellSignInfo.sRsrq;
            sRssi   = stAnqueryPara.u.st4GCellSignInfo.sRssi;
            ucLevel = 0;

            AT_CalculateLTESignalValue(&sRssi,&ucLevel,&sRsrp,&sRsrq);

            gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        "%s:0,99,%d,%d,%d,%d",
                                                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                        (VOS_INT32)sRssi,
                                                        (VOS_INT32)ucLevel,
                                                        (VOS_INT32)sRsrp,
                                                        (VOS_INT32)sRsrq);


            /* ???????????????? */
            At_FormatResultData(ucIndex,ulResult);

            return;
    }
    else
    {
        AT_WARN_LOG("AT_QryParaAnQueryProc:WARNING: THE RAT IS INVALID!");
        return;
    }

}



VOS_VOID  AT_QryParaHomePlmnProc(
    VOS_UINT8                           ucIndex,
    VOS_UINT8                           OpId,
    VOS_VOID                           *pPara
)
{
    VOS_UINT32                          ulResult;
    VOS_UINT16                          usLength;

    TAF_MMA_HPLMN_WITH_MNC_LEN_STRU     stHplmn;

    /* ?????? */
    ulResult   = AT_OK;
    usLength   = 0;

    TAF_MEM_SET_S(&stHplmn, sizeof(stHplmn), 0x00, sizeof(TAF_MMA_HPLMN_WITH_MNC_LEN_STRU));

    TAF_MEM_CPY_S(&stHplmn, sizeof(stHplmn), pPara, sizeof(TAF_MMA_HPLMN_WITH_MNC_LEN_STRU));

    /* ????MCC??MNC */
    usLength  = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       "%s:",
                                       (VOS_INT8*)g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%X%X%X",
                                       (VOS_INT32)(0x0f & stHplmn.stHplmn.Mcc) ,
                                       (VOS_INT32)(0x0f00 & stHplmn.stHplmn.Mcc) >> 8,
                                       (VOS_INT32)(0x0f0000 & stHplmn.stHplmn.Mcc) >> 16);

    if (2 == stHplmn.ucHplmnMncLen)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%X%X",
                                           (VOS_INT32)(0x0f & stHplmn.stHplmn.Mnc) ,
                                           (VOS_INT32)(0x0f00 & stHplmn.stHplmn.Mnc) >> 8);
    }
    else if (3 == stHplmn.ucHplmnMncLen)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%X%X%X",
                                           (VOS_INT32)(0x0f & stHplmn.stHplmn.Mnc) ,
                                           (VOS_INT32)(0x0f00 & stHplmn.stHplmn.Mnc) >> 8,
                                           (VOS_INT32)(0x0f0000 & stHplmn.stHplmn.Mnc) >> 16);
    }
    else
    {
        AT_WARN_LOG("AT_QryParaHomePlmnProc HPLMN MNC LEN INVAILID");
    }

    gstAtSendData.usBufLen = usLength;

    /* ???????????????? */
    At_FormatResultData(ucIndex,ulResult);

    return;
}





VOS_VOID AT_PrcoPsEvtErrCode(
    VOS_UINT8                           ucIndex,
    TAF_PS_CAUSE_ENUM_UINT32            enCuase
)
{
    VOS_UINT32                          ulResult;

    /* ?????????????? */
    if ( TAF_PS_CAUSE_SUCCESS != enCuase )
    {
        ulResult    = AT_ERROR;
    }
    else
    {
        ulResult    = AT_OK;
    }

    /* ????AT??????, ???????????? */
    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, ulResult);
}


VOS_VOID AT_LogPrintMsgProc(TAF_MNTN_LOG_PRINT_STRU *pstMsg)
{
    AT_PR_LOGI("[MDOEM:%d]%s", pstMsg->enModemId, pstMsg->acLog);
    return;
}



VOS_UINT32 AT_IsBroadcastPsEvt(
    TAF_PS_EVT_ID_ENUM_UINT32           enEvtId
)
{
    VOS_UINT32                          i;

    for ( i = 0; i < AT_ARRAY_SIZE(g_astAtBroadcastPsEvtTbl); i++ )
    {
        if (enEvtId == g_astAtBroadcastPsEvtTbl[i])
        {
            return VOS_TRUE;
        }
    }

    return VOS_FALSE;
}


VOS_VOID AT_RcvTafPsEvt(
    TAF_PS_EVT_STRU                     *pstEvt
)
{
    VOS_UINT32                          i;
    VOS_UINT32                          ulResult;
    VOS_UINT8                           ucIndex;
    MN_PS_EVT_FUNC                      pEvtFunc;
    TAF_CTRL_STRU                      *pstCtrl;

    /* ?????? */
    ulResult    = VOS_OK;
    pEvtFunc    = VOS_NULL_PTR;
    pstCtrl     = (TAF_CTRL_STRU*)(pstEvt->aucContent);

    if ( AT_FAILURE == At_ClientIdToUserId(pstCtrl->usClientId,
                                           &ucIndex) )
    {
        AT_WARN_LOG("AT_RcvTafPsEvt: At_ClientIdToUserId FAILURE");
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        /* ????IDNEX????????????????????????????????????????????????????????????????????
           ????????????????/NW ACT/NW DISCONNET?????????????????????????????????????????????? */
        if (VOS_FALSE == AT_IsBroadcastPsEvt(pstEvt->ulEvtId))
        {
            AT_WARN_LOG("AT_RcvTafPsEvt: AT_BROADCAST_INDEX,but not Broadcast Event.");
            return;
        }
    }

    /* ?????????????????????????? */
    for ( i = 0; i < AT_ARRAY_SIZE(g_astAtPsEvtFuncTbl); i++ )
    {
        if ( pstEvt->ulEvtId == g_astAtPsEvtFuncTbl[i].ulEvtId )
        {
            /* ????ID???? */
            pEvtFunc = g_astAtPsEvtFuncTbl[i].pEvtFunc;
            break;
        }
    }

    /* ?????????????????????? */
    if ( VOS_NULL_PTR != pEvtFunc )
    {
        ulResult = pEvtFunc(ucIndex, pstEvt->aucContent);
    }
    else
    {
        AT_ERR_LOG1("AT_RcvTafPsEvt: Unexpected event received! <EvtId>",
            pstEvt->ulEvtId);
        ulResult    = VOS_ERR;
    }

    /* ??????????????????????, ????????????AT????????????????: ???????????? */
    if ( VOS_OK != ulResult )
    {
        AT_ERR_LOG1("AT_RcvTafPsEvt: Can not handle this message! <MsgId>",
            pstEvt->ulEvtId);
    }

    return;
}


VOS_UINT32 AT_RcvTafPsCallEvtPdpActivateCnf_App(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pstEvtInfo
)
{
    TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU  *pstEvent;
    VOS_UINT8                          *pucSystemAppConfig;

    /* ?????? */
    pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

    pstEvent  = (TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU*)pstEvtInfo;

    if (SYSTEM_APP_WEBUI == *pucSystemAppConfig)
    {
        /* ?????????? */
        AT_AppPsRspEvtPdpActCnfProc(ucIndex, pstEvent);
    }
    else
    {
        /* ???????? */
        if (AT_CMD_CGACT_ORG_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
        {
            /* AT+CGACT???? */
            AT_STOP_TIMER_CMD_READY(ucIndex);
            At_FormatResultData(ucIndex, AT_OK);
        }
        else
        {
            /* AT^NDISDUP???? */
            AT_PS_ProcCallConnectedEvent(pstEvent);
        }
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtPdpActivateCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult;
    TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU  *pstEvent;
    MODEM_ID_ENUM_UINT16                usModemId;

    /* ?????? */
    ulResult  = AT_FAILURE;
    pstEvent  = (TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU*)pEvtInfo;

    /* ????<CID> */
    gastAtClientTab[ucIndex].ucCid      = pstEvent->ucCid;

    /* ????<RabId> */
    usModemId = MODEM_ID_0;

    if (VOS_OK != AT_GetModemIdFromClient(ucIndex, &usModemId))
    {
        AT_ERR_LOG("AT_RcvTafPsCallEvtPdpActivateCnf: Get modem id fail.");
        return AT_ERROR;
    }

    /* ??????????RABID = modemId + rabId */
    gastAtClientTab[ucIndex].ucExPsRabId  = AT_BUILD_EXRABID(usModemId, pstEvent->ucRabId);

    /* ????ADS???????? */
    /* AT_NotifyAdsWhenPdpAvtivated(pstEvent); */

    /* ????PS???????????? */
    AT_PS_SetPsCallErrCause(ucIndex, TAF_PS_CAUSE_SUCCESS);

    AT_PS_AddIpAddrRabIdMap(ucIndex, pstEvent);

    switch ( gastAtClientTab[ucIndex].UserType )
    {
        /* NDIS???????? */
        case AT_NDIS_USER:
            AT_NdisPsRspPdpActEvtCnfProc(ucIndex, pstEvent);
            return VOS_OK;


        /* E5???????????????? */
        case AT_APP_USER:
            return AT_RcvTafPsCallEvtPdpActivateCnf_App(ucIndex, pEvtInfo);

        /* ????AP_MODEM????????HISC?????????????? */
        case AT_HSIC1_USER:
        case AT_HSIC2_USER:
        case AT_HSIC3_USER:
        case AT_HSIC4_USER:
            if (AT_CMD_CGACT_ORG_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
            {
                AT_HsicPsRspEvtPdpActCnfProc(pstEvent);
                AT_STOP_TIMER_CMD_READY(ucIndex);
                At_FormatResultData(ucIndex, AT_OK);
            }
            else
            {
                AT_PS_ProcCallConnectedEvent(pstEvent);
            }

            return VOS_OK;

        case AT_USBCOM_USER:
            AT_CtrlConnIndProc(pstEvent, AT_USBCOM_USER);
            break;

        default:
            break;
    }

    /* ???????????? */
    switch(gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        case AT_CMD_CGACT_ORG_SET:
            ulResult    = AT_OK;
            AT_STOP_TIMER_CMD_READY(ucIndex);
            At_FormatResultData(ucIndex,ulResult);
            break;

        case AT_CMD_CGANS_ANS_SET:
            ulResult    = AT_OK;
            AT_STOP_TIMER_CMD_READY(ucIndex);
            At_FormatResultData(ucIndex,ulResult);
            break;

        case AT_CMD_CGDATA_SET:
            ulResult    = AT_CONNECT;
            AT_STOP_TIMER_CMD_READY(ucIndex);
            At_SetMode(ucIndex, AT_DATA_MODE, AT_IP_DATA_MODE);
            At_FormatResultData(ucIndex, ulResult);
            break;

        case AT_CMD_CGANS_ANS_EXT_SET:
            AT_AnswerPdpActInd(ucIndex, pstEvent);
            break;

        case AT_CMD_D_IP_CALL_SET:
        case AT_CMD_PPP_ORG_SET:
            /* Modem??????PDP??????????
               AT_CMD_D_IP_CALL_SET??PPP????
               AT_CMD_PPP_ORG_SET??IP????
            */
            AT_ModemPsRspPdpActEvtCnfProc(ucIndex, pstEvent);
            break;

        default:
            break;
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtPdpActivateRej(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_PDP_ACTIVATE_REJ_STRU  *pstEvent;
    VOS_UINT8                          *pucSystemAppConfig;

    /* ?????? */
    pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

    pstEvent  = (TAF_PS_CALL_PDP_ACTIVATE_REJ_STRU*)pEvtInfo;

    /* gastAtClientTab[ucIndex].ulCause?????????????????????? */


    /* ????PS???????????? */
    AT_PS_SetPsCallErrCause(ucIndex, pstEvent->enCause);

    /* ?????????????????? */
    switch (gastAtClientTab[ucIndex].UserType)
    {
        /* MODEM???????? */
        case AT_HSUART_USER:
        case AT_MODEM_USER:
            AT_ModemPsRspPdpActEvtRejProc(ucIndex, pstEvent);
            return VOS_OK;

        /* NDIS???????? */
        case AT_NDIS_USER:
            AT_NdisPsRspPdpActEvtRejProc(ucIndex, pstEvent);
            break;

        /* E5???????????????????????? */
        case AT_APP_USER:
            if (SYSTEM_APP_WEBUI == *pucSystemAppConfig)
            {
                /* ?????????? */
                AT_AppPsRspEvtPdpActRejProc(ucIndex, pstEvent);
            }
            else
            {
                if (AT_CMD_CGACT_ORG_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
                {
                    /* AT+CGACT???? */
                    AT_STOP_TIMER_CMD_READY(ucIndex);
                    At_FormatResultData(ucIndex, AT_ERROR);
                }
                else
                {
                    /* AT^NDISDUP???? */
                    AT_PS_ProcCallRejectEvent(pstEvent);
                }
            }
            return VOS_OK;

        case AT_HSIC1_USER:
        case AT_HSIC2_USER:
        case AT_HSIC3_USER:
        case AT_HSIC4_USER:
            if (AT_CMD_CGACT_ORG_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
            {
                /* ????CID???????????????????? */
                AT_CleanAtChdataCfg(pstEvent->stCtrl.usClientId, pstEvent->ucCid, AT_PS_MAX_CALL_NUM, TAF_PS_APN_DATA_SYS_CELLULAR);
                AT_STOP_TIMER_CMD_READY(ucIndex);
                At_FormatResultData(ucIndex, AT_ERROR);
            }
            else
            {
                AT_PS_ProcCallRejectEvent(pstEvent);
            }
            return VOS_OK;

        /* ????????????????ERROR */
        case AT_USBCOM_USER:
        default:
            AT_STOP_TIMER_CMD_READY(ucIndex);
            At_FormatResultData(ucIndex, AT_ERROR);
            break;
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtPdpManageInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT16                          usLength;
    TAF_PS_CALL_PDP_MANAGE_IND_STRU    *pstEvent;
    AT_MODEM_SS_CTX_STRU               *pstModemSsCtx = VOS_NULL_PTR;

    VOS_UINT8                           aucTempValue[TAF_MAX_APN_LEN + 1];

    /* ?????? */
    usLength  = 0;
    pstEvent  = (TAF_PS_CALL_PDP_MANAGE_IND_STRU*)pEvtInfo;

    /* ?????????????? */
    pstModemSsCtx   = AT_GetModemSsCtxAddrFromClientId(ucIndex);

    if(AT_CRC_ENABLE_TYPE == pstModemSsCtx->ucCrcType)
    {
        /* +CRC -- +CRING: GPRS <PDP_type>, <PDP_addr>[,[<L2P>][,<APN>]] */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR*)pgucAtSndCodeAddr,
                                           (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                           "%s+CRING: GPRS ",gaucAtCrLf);

        /* <PDP_type> */
        if (TAF_PDP_IPV4 == pstEvent->stPdpAddr.enPdpType)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR*)pgucAtSndCodeAddr,
                                               (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                               "%s",gastAtStringTab[AT_STRING_IP].pucText);
        }
        else if (TAF_PDP_IPV6 == pstEvent->stPdpAddr.enPdpType)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR*)pgucAtSndCodeAddr,
                                               (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                               "%s", gastAtStringTab[AT_STRING_IPV6].pucText);
        }
        else if (TAF_PDP_IPV4V6 == pstEvent->stPdpAddr.enPdpType)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR*)pgucAtSndCodeAddr,
                                               (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                               "%s", gastAtStringTab[AT_STRING_IPV4V6].pucText);
        }
        else
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR*)pgucAtSndCodeAddr,
                                               (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                               "%s",gastAtStringTab[AT_STRING_PPP].pucText);
        }

        /* <PDP_addr> */
        TAF_MEM_SET_S(aucTempValue, sizeof(aucTempValue), 0x00, (TAF_MAX_APN_LEN + 1));
        AT_Ipv4Addr2Str((VOS_CHAR *)aucTempValue, pstEvent->stPdpAddr.aucIpv4Addr);
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR*)pgucAtSndCodeAddr,
                                           (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                           ",\"%s\"",aucTempValue);

        /* <L2P>??????<APN> */
        TAF_MEM_SET_S(aucTempValue, sizeof(aucTempValue), 0x00, (TAF_MAX_APN_LEN + 1));

        if (pstEvent->stApn.ucLength > sizeof(pstEvent->stApn.aucValue))
        {
            AT_WARN_LOG1("AT_RcvTafPsCallEvtPdpManageInd: Invalid pstEvent->stApn.ucLength: ", pstEvent->stApn.ucLength);
            pstEvent->stApn.ucLength = sizeof(pstEvent->stApn.aucValue);
        }

        TAF_MEM_CPY_S(aucTempValue, sizeof(aucTempValue), pstEvent->stApn.aucValue, pstEvent->stApn.ucLength);
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR*)pgucAtSndCodeAddr,
                                           (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                           ",,\"%s\"%s",aucTempValue,gaucAtCrLf);
    }
    else
    {
        /* +CRC -- RING */
        if(AT_V_ENTIRE_TYPE == gucAtVType)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR*)pgucAtSndCodeAddr,
                                               (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                               "%sRING%s",gaucAtCrLf,gaucAtCrLf);
        }
        else
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR*)pgucAtSndCodeAddr,
                                               (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                               "2\r");
        }
    }

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtPdpActivateInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    /* ?????? */
    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtPdpModifyCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_PDP_MODIFY_CNF_STRU    *pstEvent;
    AT_MODEM_PS_CTX_STRU               *pstPsModemCtx = VOS_NULL_PTR;

    /* ?????????????????????? */
    if ( AT_CMD_CGCMOD_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    pstEvent = (TAF_PS_CALL_PDP_MODIFY_CNF_STRU*)pEvtInfo;

    /* ????ADS???????? */
    /*AT_NotifyAdsWhenPdpModify(pstEvent);*/

    pstPsModemCtx = AT_GetModemPsCtxAddrFromClientId(ucIndex);

    switch ( gastAtClientTab[ucIndex].UserType )
    {
        case AT_HSUART_USER:
        case AT_MODEM_USER:
            /* ??FC?????????????? */
            AT_NotifyFcWhenPdpModify(pstEvent, FC_ID_MODEM);
            break;

        case AT_NDIS_USER:
            /* ??FC?????????????? */
            AT_NotifyFcWhenPdpModify(pstEvent, FC_ID_NIC_1);
            break;

        case AT_APP_USER:
            AT_PS_ProcCallModifyEvent(ucIndex, pstEvent);
            break;

        case AT_HSIC1_USER:
        case AT_HSIC2_USER:
        case AT_HSIC3_USER:
        case AT_HSIC4_USER:
            switch ( pstPsModemCtx->astChannelCfg[pstEvent->ucCid].ulRmNetId)
            {
                case UDI_ACM_HSIC_ACM1_ID:
                case UDI_NCM_HSIC_NCM0_ID:
                    /* ??FC?????????????? */
                    AT_NotifyFcWhenPdpModify(pstEvent, FC_ID_DIPC_1);
                    break;
                case UDI_ACM_HSIC_ACM3_ID:
                case UDI_NCM_HSIC_NCM1_ID:
                    /* ??FC?????????????? */
                    AT_NotifyFcWhenPdpModify(pstEvent, FC_ID_DIPC_2);
                    break;
                case UDI_ACM_HSIC_ACM5_ID:
                case UDI_NCM_HSIC_NCM2_ID:
                    /* ??FC?????????????? */
                    AT_NotifyFcWhenPdpModify(pstEvent, FC_ID_DIPC_3);
                    break;
                default:
                    break;
            }
            break;

        default:
            break;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, AT_OK);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtPdpModifyRej(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    /* ?????????????????????? */
    if ( AT_CMD_CGCMOD_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, AT_ERROR);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtPdpModifiedInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_PDP_MODIFY_IND_STRU    *pstEvent;
    AT_MODEM_PS_CTX_STRU               *pstPsModemCtx = VOS_NULL_PTR;

    pstEvent = (TAF_PS_CALL_PDP_MODIFY_IND_STRU*)pEvtInfo;

    /* ????ADS???????? */
    /*AT_NotifyAdsWhenPdpModify(pstEvent);*/

    pstPsModemCtx = AT_GetModemPsCtxAddrFromClientId(ucIndex);

    switch ( gastAtClientTab[ucIndex].UserType )
    {
        case AT_HSUART_USER:
        case AT_MODEM_USER:
            /* ??FC?????????????? */
            AT_NotifyFcWhenPdpModify(pstEvent, FC_ID_MODEM);
            break;

        case AT_NDIS_USER:
            /* ??FC?????????????? */
            AT_NotifyFcWhenPdpModify(pstEvent, FC_ID_NIC_1);
            break;

        case AT_APP_USER:
            AT_PS_ProcCallModifyEvent(ucIndex, pstEvent);
            break;

        case AT_HSIC1_USER:
        case AT_HSIC2_USER:
        case AT_HSIC3_USER:
        case AT_HSIC4_USER:
            switch ( pstPsModemCtx->astChannelCfg[pstEvent->ucCid].ulRmNetId)
            {
                case UDI_ACM_HSIC_ACM1_ID:
                case UDI_NCM_HSIC_NCM0_ID:
                    /* ??FC?????????????? */
                    AT_NotifyFcWhenPdpModify(pstEvent, FC_ID_DIPC_1);
                    break;
                case UDI_ACM_HSIC_ACM3_ID:
                case UDI_NCM_HSIC_NCM1_ID:
                    /* ??FC?????????????? */
                    AT_NotifyFcWhenPdpModify(pstEvent, FC_ID_DIPC_2);
                    break;
                case UDI_ACM_HSIC_ACM5_ID:
                case UDI_NCM_HSIC_NCM2_ID:
                    /* ??FC?????????????? */
                    AT_NotifyFcWhenPdpModify(pstEvent, FC_ID_DIPC_3);
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtPdpDeactivateCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_PDP_DEACTIVATE_CNF_STRU *pstEvent;
    VOS_UINT8                           *pucSystemAppConfig;

    /* ?????? */
    pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

    pstEvent  = (TAF_PS_CALL_PDP_DEACTIVATE_CNF_STRU*)pEvtInfo;

    /* gastAtClientTab[ucIndex].ulCause?????????????????????? */

    /* ????ADS?????????? */
    /*AT_NotifyAdsWhenPdpDeactivated(pstEvent);*/

    AT_PS_DeleteIpAddrRabIdMap(ucIndex, pstEvent);

    /* NDIS???????? */
    if (AT_NDIS_USER == gastAtClientTab[ucIndex].UserType)
    {
        AT_NdisPsRspPdpDeactEvtCnfProc(ucIndex, pstEvent);
        return VOS_OK;
    }

    /* E5???????????????? */
    if (AT_APP_USER == gastAtClientTab[ucIndex].UserType)
    {
        if (SYSTEM_APP_WEBUI == *pucSystemAppConfig)
        {
            /* ?????????? */
            AT_AppPsRspEvtPdpDeactCnfProc(ucIndex, pstEvent);
        }
        else
        {
            /* ???????? */
            if (AT_CMD_CGACT_END_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
            {
                /* AT+CGACT???? */
                AT_STOP_TIMER_CMD_READY(ucIndex);
                At_SetMode(ucIndex, AT_CMD_MODE, AT_NORMAL_MODE);
                At_FormatResultData(ucIndex, AT_OK);
            }
            else
            {
                /* AT^NDISDUP???? */
                AT_PS_ProcCallEndedEvent(pstEvent);
            }
        }

        return VOS_OK;
    }

    if (VOS_TRUE == AT_CheckHsicUser(ucIndex))
    {
        if (AT_CMD_CGACT_END_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
        {
            AT_HsicPsRspEvtPdpDeactCnfProc(pstEvent);
            AT_STOP_TIMER_CMD_READY(ucIndex);
            At_SetMode(ucIndex, AT_CMD_MODE, AT_NORMAL_MODE);
            At_FormatResultData(ucIndex, AT_OK);
        }
        else
        {
            AT_PS_ProcCallEndedEvent(pstEvent);
        }

        return VOS_OK;
    }

    /* ???????????????????????????????????????? */
    switch(gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        case AT_CMD_CGACT_END_SET:

            AT_STOP_TIMER_CMD_READY(ucIndex);

            /* ???????????? */
            At_SetMode(ucIndex, AT_CMD_MODE, AT_NORMAL_MODE);

            At_FormatResultData(ucIndex,AT_OK);
            break;

        case AT_CMD_H_PS_SET:
        case AT_CMD_PS_DATA_CALL_END_SET:
                AT_ModemPsRspPdpDeactEvtCnfProc(ucIndex, pstEvent);
            break;

        default:
            break;
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtPdpDeactivatedInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_PDP_DEACTIVATE_IND_STRU *pstEvent;
    VOS_UINT8                           *pucSystemAppConfig;
    VOS_UINT8                           ucCallId;

    pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

    pstEvent    = (TAF_PS_CALL_PDP_DEACTIVATE_IND_STRU*)pEvtInfo;

    /* gastAtClientTab[ucIndex].ulCause?????????????????????? */

    /* ????PS???????????? */
    AT_PS_SetPsCallErrCause(ucIndex, pstEvent->enCause);

    AT_PS_DeleteIpAddrRabIdMap(ucIndex, pstEvent);

    switch (gastAtClientTab[ucIndex].UserType)
    {
        case AT_HSUART_USER:
        case AT_USBCOM_USER:
        case AT_MODEM_USER:
        case AT_CTR_USER:
            AT_ModemPsRspPdpDeactivatedEvtProc(ucIndex, pstEvent);
            break;

        case AT_NDIS_USER:
            /* ????????????????, ???????????? */
            if (AT_CMD_NDISCONN_SET == AT_NDIS_GET_CURR_CMD_OPT())
            {
                /* ???????????????? */
                AT_STOP_TIMER_CMD_READY(AT_NDIS_GET_USR_PORT_INDEX());

                /* ???????????????? */
                At_FormatResultData(AT_NDIS_GET_USR_PORT_INDEX(), AT_OK);
            }

            AT_NdisPsRspPdpDeactivatedEvtProc(ucIndex, pstEvent);
            break;

        case AT_APP_USER:
            /* ????????????????, ???????????? */
            if (AT_CMD_NDISCONN_SET == AT_APP_GET_CURR_CMD_OPT())
            {
                /* ???????????????? */
                AT_STOP_TIMER_CMD_READY(AT_APP_GET_USR_PORT_INDEX());

                /* ???????????????? */
                At_FormatResultData(AT_APP_GET_USR_PORT_INDEX(), AT_OK);
            }

            if (SYSTEM_APP_WEBUI == *pucSystemAppConfig)
            {
                AT_AppPsRspEvtPdpDeactivatedProc(ucIndex, pstEvent);
            }
            else
            {
                ucCallId = AT_PS_TransCidToCallId(ucIndex, pstEvent->ucCid);
                if (AT_PS_IsCallIdValid(ucIndex, ucCallId))
                {
                    /* AT^NDISDUP??????????????PDP?????? */
                    AT_PS_ProcCallEndedEvent(pstEvent);
                }
            }
            break;

        case AT_HSIC1_USER:
        case AT_HSIC2_USER:
        case AT_HSIC3_USER:
        case AT_HSIC4_USER:
            /* AT+CGACT ????????AT_HsicPsRspEvtPdpDeactivatedProc
               AT^NDISDUP ???????? AT_PS_ProcCallEndedEvent*/
            ucCallId = AT_PS_TransCidToCallId(ucIndex, pstEvent->ucCid);
            if (!AT_PS_IsCallIdValid(ucIndex, ucCallId))
            {
                AT_HsicPsRspEvtPdpDeactivatedProc(ucIndex, pstEvent);
            }
            else
            {
                AT_PS_ProcCallEndedEvent(pstEvent);
            }
            break;

        default:
            break;
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtCallOrigCnf_Ndis(
    VOS_UINT8                           ucIndex,
    TAF_PS_CALL_ORIG_CNF_STRU          *pstCallOrigCnf
)
{
    VOS_UINT32                          ulResult;

    ulResult = AT_FAILURE;

    if (TAF_PS_CAUSE_SUCCESS != pstCallOrigCnf->enCause)
    {
        /* ??????PDP?????????? */
        AT_NdisSetState(g_enAtNdisActPdpType, AT_PDP_STATE_IDLE);

        /* ????NDIS???????? */
        TAF_MEM_SET_S(&gstAtNdisAddParam, sizeof(gstAtNdisAddParam), 0x00, sizeof(AT_DIAL_PARAM_STRU));

        if (TAF_PS_CAUSE_PDP_ACTIVATE_LIMIT == pstCallOrigCnf->enCause)
        {
            ulResult = AT_CME_PDP_ACT_LIMIT;
        }
        else
        {
            ulResult = AT_ERROR;
        }

    }
    else
    {
        ulResult = AT_OK;
    }

    /* ???????????????? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    At_FormatResultData(ucIndex, ulResult);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtCallOrigCnf_App(
    TAF_PS_CALL_ORIG_CNF_STRU          *pstCallOrigCnf
)
{
    VOS_UINT32                          ulResult;
    VOS_UINT8                          *pucSystemAppConfig;

    /* ?????? */
    pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

    if (SYSTEM_APP_WEBUI == *pucSystemAppConfig)
    {
        if (AT_CMD_NDISCONN_SET == AT_APP_GET_CURR_CMD_OPT())
        {
            ulResult = AT_FAILURE;

            if (TAF_PS_CAUSE_SUCCESS != pstCallOrigCnf->enCause)
            {
                /* ??????PDP?????????? */
                AT_AppSetPdpState(AT_APP_GetActPdpType(), AT_PDP_STATE_IDLE);

                /* ????APP???????? */
                TAF_MEM_SET_S(AT_APP_GetDailParaAddr(), sizeof(AT_DIAL_PARAM_STRU), 0x00, sizeof(AT_DIAL_PARAM_STRU));

                if (TAF_PS_CAUSE_PDP_ACTIVATE_LIMIT == pstCallOrigCnf->enCause)
                {
                    ulResult = AT_CME_PDP_ACT_LIMIT;
                }
                else
                {
                    ulResult = AT_ERROR;
                }
            }
            else
            {
                ulResult = AT_OK;
            }

            /* ???????????????? */
            AT_STOP_TIMER_CMD_READY(AT_APP_GET_USR_PORT_INDEX());

            At_FormatResultData(AT_APP_GET_USR_PORT_INDEX(), ulResult);
        }

        return VOS_OK;
    }
    else
    {
        AT_PS_ProcCallOrigCnfEvent(pstCallOrigCnf);
        return VOS_OK;
    }
}



VOS_UINT32 AT_RcvTafPsCallEvtCallOrigCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_ORIG_CNF_STRU          *pstCallOrigCnf;

    pstCallOrigCnf  = (TAF_PS_CALL_ORIG_CNF_STRU*)pEvtInfo;

    /* ????PS???????????? */
    if (TAF_PS_CAUSE_SUCCESS != pstCallOrigCnf->enCause)
    {
        AT_PS_SetPsCallErrCause(ucIndex, pstCallOrigCnf->enCause);
    }

    if ( (VOS_TRUE == AT_CheckNdisUser(ucIndex))
      && (AT_CMD_NDISCONN_SET == AT_NDIS_GET_CURR_CMD_OPT()) )
    {
        return AT_RcvTafPsCallEvtCallOrigCnf_Ndis(AT_NDIS_GET_USR_PORT_INDEX(), pstCallOrigCnf);
    }

    if (VOS_TRUE == AT_CheckAppUser(ucIndex))
    {
        return AT_RcvTafPsCallEvtCallOrigCnf_App(pstCallOrigCnf);
    }

    if (VOS_TRUE == AT_CheckHsicUser(ucIndex))
    {
        AT_PS_ProcCallOrigCnfEvent(pstCallOrigCnf);
        return VOS_OK;
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtCallEndCnf_App(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pstEvtInfo
)
{
    VOS_UINT32                          ulResult;
    TAF_PS_CALL_END_CNF_STRU           *pstCallEndCnf;
    VOS_UINT8                          *pucSystemAppConfig;

    /* ?????? */
    pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

    ulResult        = AT_FAILURE;
    pstCallEndCnf   = (TAF_PS_CALL_END_CNF_STRU*)pstEvtInfo;

    if (SYSTEM_APP_WEBUI == *pucSystemAppConfig)
    {
        if (AT_CMD_NDISCONN_SET == AT_APP_GET_CURR_CMD_OPT())
        {
            if ( TAF_ERR_NO_ERROR != pstCallEndCnf->enCause)
            {
                ulResult = AT_ERROR;
            }
            else
            {
                ulResult = AT_OK;
            }

            /* ???????????????? */
            AT_STOP_TIMER_CMD_READY(AT_APP_GET_USR_PORT_INDEX());

            /* ???????????????? */
            At_FormatResultData(AT_APP_GET_USR_PORT_INDEX(), ulResult);
        }

        return VOS_OK;
    }
    else
    {
        AT_PS_ProcCallEndCnfEvent(pstCallEndCnf);
        return VOS_OK;
    }
}


VOS_UINT32 AT_RcvTafPsCallEvtCallEndCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult;
    TAF_PS_CALL_END_CNF_STRU           *pstCallEndCnf;

    /* ?????? */
    ulResult        = AT_FAILURE;
    pstCallEndCnf   = (TAF_PS_CALL_END_CNF_STRU*)pEvtInfo;

    if ( (AT_MODEM_USER == gastAtClientTab[ucIndex].UserType)
      || (AT_HSUART_USER == gastAtClientTab[ucIndex].UserType) )
    {
        AT_MODEM_ProcCallEndCnfEvent(ucIndex, pstCallEndCnf);
        return VOS_OK;
    }

    if ( (VOS_TRUE == AT_CheckNdisUser(ucIndex))
      && (AT_CMD_NDISCONN_SET == AT_NDIS_GET_CURR_CMD_OPT()) )
    {
        if ( TAF_ERR_NO_ERROR != pstCallEndCnf->enCause)
        {
            ulResult = AT_ERROR;
        }
        else
        {
            ulResult = AT_OK;
        }

        /* ???????????????? */
        AT_STOP_TIMER_CMD_READY(AT_NDIS_GET_USR_PORT_INDEX());

        /* ???????????????? */
        At_FormatResultData(AT_NDIS_GET_USR_PORT_INDEX(), ulResult);

        return VOS_OK;
    }

    if (VOS_TRUE == AT_CheckAppUser(ucIndex))
    {
        return AT_RcvTafPsCallEvtCallEndCnf_App(ucIndex, pEvtInfo);
    }

    if (VOS_TRUE == AT_CheckHsicUser(ucIndex))
    {
        AT_PS_ProcCallEndCnfEvent(pstCallEndCnf);
        return VOS_OK;
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtCallModifyCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_MODIFY_CNF_STRU        *pstCallModifyCnf;

    /* ?????? */
    pstCallModifyCnf = (TAF_PS_CALL_MODIFY_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGCMOD_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /*----------------------------------------------------------
       (1)??????????????, ??????PDP????, ????????ERROR
       (2)??????????, ????PDP????, ????PDP????????????????
    ----------------------------------------------------------*/
    if ( TAF_PS_CAUSE_SUCCESS != pstCallModifyCnf->enCause )
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);
        At_FormatResultData(ucIndex, AT_ERROR);
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtCallAnswerCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_ANSWER_CNF_STRU        *pstCallAnswerCnf;
    VOS_UINT32                          ulResult;

    /* ?????? */
    pstCallAnswerCnf = (TAF_PS_CALL_ANSWER_CNF_STRU*)pEvtInfo;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvTafPsCallEvtCallAnswerCnf : AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* ?????????????????????? */
    if ((AT_CMD_CGANS_ANS_SET     != gastAtClientTab[ucIndex].CmdCurrentOpt)
     && (AT_CMD_CGANS_ANS_EXT_SET != gastAtClientTab[ucIndex].CmdCurrentOpt))
    {
        return VOS_ERR;
    }

    /*----------------------------------------------------------
       (1)??????????????, ??????PDP????, ????????ERROR
       (2)??????????, ????PDP????, ????PDP????????????????
    ----------------------------------------------------------*/

    /* IP??????????????????????????CONNECT */
    if (TAF_ERR_AT_CONNECT == pstCallAnswerCnf->enCause)
    {
        ulResult = At_SetDialGprsPara(ucIndex,
                                      pstCallAnswerCnf->ucCid,
                                      TAF_IP_ACTIVE_TE_PPP_MT_PPP_TYPE);

        /* ??????connect??CmdCurrentOpt??????At_RcvTeConfigInfoReq?????? */
        if (AT_ERROR == ulResult)
        {
            gastAtClientTab[ucIndex].CmdCurrentOpt = AT_CMD_CURRENT_OPT_BUTT;
        }

        AT_StopRelTimer(ucIndex, &gastAtClientTab[ucIndex].hTimer);
        g_stParseContext[ucIndex].ucClientStatus = AT_FW_CLIENT_STATUS_READY;
        gastAtClientTab[ucIndex].opId = 0;
        At_FormatResultData(ucIndex, ulResult);

        return VOS_OK;
    }

    /* ??????????????????ERROR */
    if (TAF_ERR_NO_ERROR != pstCallAnswerCnf->enCause)
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);
        At_FormatResultData(ucIndex, AT_ERROR);
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsCallEvtCallHangupCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult;
    TAF_PS_CALL_HANGUP_CNF_STRU        *pstCallHangUpCnf;

    pstCallHangUpCnf  = (TAF_PS_CALL_HANGUP_CNF_STRU*)pEvtInfo;

    if (TAF_ERR_NO_ERROR == pstCallHangUpCnf->enCause)
    {
        ulResult = AT_OK;
    }
    else
    {
        ulResult = AT_ERROR;
    }

    /* ???????????? */
    switch(gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        case AT_CMD_CGANS_ANS_SET:
            AT_STOP_TIMER_CMD_READY(ucIndex);
            At_FormatResultData(ucIndex,ulResult);
            break;

        default:
            break;
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSetPrimPdpContextInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_PRIM_PDP_CONTEXT_INFO_CNF_STRU  *pstSetPdpCtxInfoCnf;

    pstSetPdpCtxInfoCnf = (TAF_PS_SET_PRIM_PDP_CONTEXT_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGDCONT_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetPdpCtxInfoCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetPrimPdpContextInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;
    VOS_UINT8                           ucTmp = 0;
    TAF_PRI_PDP_QUERY_INFO_STRU         stCgdcont;
    TAF_PS_GET_PRIM_PDP_CONTEXT_INFO_CNF_STRU *pstGetPrimPdpCtxInfoCnf = VOS_NULL_PTR;

    VOS_UINT8                           aucStr[TAF_MAX_APN_LEN + 1];

    TAF_MEM_SET_S(&stCgdcont, sizeof(stCgdcont), 0x00, sizeof(TAF_PRI_PDP_QUERY_INFO_STRU));
    pstGetPrimPdpCtxInfoCnf = (TAF_PS_GET_PRIM_PDP_CONTEXT_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGDCONT_READ != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    for(ucTmp = 0; ucTmp < pstGetPrimPdpCtxInfoCnf->ulCidNum; ucTmp++)
    {
        if(0 != ucTmp)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        }

        TAF_MEM_CPY_S(&stCgdcont, sizeof(stCgdcont), &pstGetPrimPdpCtxInfoCnf->astPdpContextQueryInfo[ucTmp], sizeof(TAF_PRI_PDP_QUERY_INFO_STRU));

        /* +CGDCONT:  */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        /* <cid> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",stCgdcont.ucCid);
        /* <PDP_type> */
        if (TAF_PDP_IPV4 == stCgdcont.stPriPdpInfo.stPdpAddr.enPdpType)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_IP].pucText);
        }
        else if (TAF_PDP_IPV6 == stCgdcont.stPriPdpInfo.stPdpAddr.enPdpType)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",%s", gastAtStringTab[AT_STRING_IPV6].pucText);
        }
        else if (TAF_PDP_IPV4V6 == stCgdcont.stPriPdpInfo.stPdpAddr.enPdpType)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",%s", gastAtStringTab[AT_STRING_IPV4V6].pucText);
        }
        else
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_PPP].pucText);
        }
        /* <APN> */
        TAF_MEM_SET_S(aucStr, sizeof(aucStr), 0x00, sizeof(aucStr));

        if (stCgdcont.stPriPdpInfo.stApn.ucLength > sizeof(stCgdcont.stPriPdpInfo.stApn.aucValue))
        {
            AT_WARN_LOG1("AT_RcvTafPsEvtGetPrimPdpContextInfoCnf: stCgdcont.stPriPdpInfo.stApn.ucLength: ",
                stCgdcont.stPriPdpInfo.stApn.ucLength);
            stCgdcont.stPriPdpInfo.stApn.ucLength = sizeof(stCgdcont.stPriPdpInfo.stApn.aucValue);
        }

        TAF_MEM_CPY_S(aucStr, sizeof(aucStr), stCgdcont.stPriPdpInfo.stApn.aucValue, stCgdcont.stPriPdpInfo.stApn.ucLength);
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"", aucStr);
        /* <PDP_addr> */
        TAF_MEM_SET_S(aucStr, sizeof(aucStr), 0x00, sizeof(aucStr));
        AT_Ipv4Addr2Str((VOS_CHAR *)aucStr, stCgdcont.stPriPdpInfo.stPdpAddr.aucIpv4Addr);
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"", aucStr);
        /* <d_comp> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgdcont.stPriPdpInfo.enPdpDcomp);
        /* <h_comp> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgdcont.stPriPdpInfo.enPdpHcomp);


        /* <IPv4AddrAlloc>  */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgdcont.stPriPdpInfo.enIpv4AddrAlloc);
        /* <Emergency Indication> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgdcont.stPriPdpInfo.enEmergencyInd);
        /* <P-CSCF_discovery> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgdcont.stPriPdpInfo.enPcscfDiscovery);
        /* <IM_CN_Signalling_Flag_Ind> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgdcont.stPriPdpInfo.enImCnSignalFlg);
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgdcont.stPriPdpInfo.enNasSigPrioInd);

    }

    ulResult                = AT_OK;
    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetPdpContextInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                              ulResult;
    VOS_UINT16                              usLength ;
    VOS_UINT8                               ucTmp ;
    TAF_PS_GET_PDP_CONTEXT_INFO_CNF_STRU   *pstGetPdpCtxInfoCnf;

    ulResult            = AT_FAILURE;
    usLength            = 0;
    ucTmp               = 0;
    pstGetPdpCtxInfoCnf = (TAF_PS_GET_PDP_CONTEXT_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGPADDR_TEST != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* +CGPADDR:  */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"(");

    for(ucTmp = 0; ucTmp < pstGetPdpCtxInfoCnf->ulCidNum; ucTmp++)
    {
        /* <cid> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",pstGetPdpCtxInfoCnf->ulCid[ucTmp]);

        if (((VOS_UINT32)ucTmp + 1) >= pstGetPdpCtxInfoCnf->ulCidNum)
        {
            break;
        }

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
    }
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,")");

    ulResult                = AT_OK;
    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSetSecPdpContextInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_SEC_PDP_CONTEXT_INFO_CNF_STRU   *pstSetPdpCtxInfoCnf;

    pstSetPdpCtxInfoCnf = (TAF_PS_SET_SEC_PDP_CONTEXT_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGDSCONT_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetPdpCtxInfoCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetSecPdpContextInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;
    VOS_UINT8                           ucTmp = 0;
    TAF_PDP_SEC_CONTEXT_STRU            stSecPdpInfo;
    TAF_PS_GET_SEC_PDP_CONTEXT_INFO_CNF_STRU *pstGetSecPdpCtxInfoCnf = VOS_NULL_PTR;

    TAF_MEM_SET_S(&stSecPdpInfo, sizeof(stSecPdpInfo), 0x00, sizeof(TAF_PDP_SEC_CONTEXT_STRU));

    pstGetSecPdpCtxInfoCnf = (TAF_PS_GET_SEC_PDP_CONTEXT_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGDSCONT_READ != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    for (ucTmp = 0; ucTmp < pstGetSecPdpCtxInfoCnf->ulCidNum; ucTmp++)
    {
        if (0 != ucTmp)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        }

        TAF_MEM_CPY_S(&stSecPdpInfo, sizeof(stSecPdpInfo), &pstGetSecPdpCtxInfoCnf->astPdpContextQueryInfo[ucTmp], sizeof(TAF_PDP_SEC_CONTEXT_STRU));
        /* +CGDSCONT:  */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        /* <cid> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",stSecPdpInfo.ucCid);
        /* <p_cid> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stSecPdpInfo.ucLinkdCid);
        /* <d_comp> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stSecPdpInfo.enPdpDcomp);
        /* <h_comp> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stSecPdpInfo.enPdpHcomp);
        /* <IM_CN_Signalling_Flag_Ind> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stSecPdpInfo.enImCnSignalFlg);

    }

    ulResult                = AT_OK;
    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}



VOS_UINT32 AT_RcvTafPsEvtSetTftInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_TFT_INFO_CNF_STRU       *pstSetTftInfoCnf;

    pstSetTftInfoCnf = (TAF_PS_SET_TFT_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGTFT_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetTftInfoCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetTftInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;
    VOS_UINT8                           ucTmp1 = 0;
    VOS_UINT8                           ucTmp2 = 0;
    VOS_CHAR                            acIpv4StrTmp[TAF_MAX_IPV4_ADDR_STR_LEN];
    VOS_CHAR                            acIpv6StrTmp[AT_IPV6_ADDR_MASK_FORMAT_STR_LEN];
    VOS_CHAR                            aucLocalIpv4StrTmp[TAF_MAX_IPV4_ADDR_STR_LEN];
    VOS_UINT8                           aucLocalIpv6Mask[APP_MAX_IPV6_ADDR_LEN];
    TAF_TFT_QUREY_INFO_STRU            *pstCgtft;
    TAF_PS_GET_TFT_INFO_CNF_STRU       *pstGetTftInfoCnf;

    TAF_MEM_SET_S(acIpv4StrTmp, sizeof(acIpv4StrTmp), 0x00, sizeof(acIpv4StrTmp));
    TAF_MEM_SET_S(acIpv6StrTmp, sizeof(acIpv6StrTmp), 0x00, sizeof(acIpv6StrTmp));
    TAF_MEM_SET_S(aucLocalIpv4StrTmp, sizeof(aucLocalIpv4StrTmp), 0x00, sizeof(aucLocalIpv4StrTmp));
    TAF_MEM_SET_S(aucLocalIpv6Mask, sizeof(aucLocalIpv6Mask), 0x00, sizeof(aucLocalIpv6Mask));

    pstGetTftInfoCnf = (TAF_PS_GET_TFT_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGTFT_READ != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ???????????? */
    pstCgtft = (TAF_TFT_QUREY_INFO_STRU *)PS_MEM_ALLOC(WUEPS_PID_AT,
                                                       sizeof(TAF_TFT_QUREY_INFO_STRU));
    if (VOS_NULL_PTR == pstCgtft)
    {
        return VOS_ERR;
    }

    for (ucTmp1 = 0; ucTmp1 < pstGetTftInfoCnf->ulCidNum; ucTmp1++)
    {

        TAF_MEM_CPY_S(pstCgtft, sizeof(TAF_TFT_QUREY_INFO_STRU), &pstGetTftInfoCnf->astTftQueryInfo[ucTmp1], sizeof(TAF_TFT_QUREY_INFO_STRU));

        for (ucTmp2= 0; ucTmp2 < pstCgtft->ucPfNum; ucTmp2++)
        {
            if (!(0 == ucTmp1 && 0 == ucTmp2))
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength, "%s",gaucAtCrLf);
            }
            /* +CGTFT:  */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ", g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
            /* <cid> */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, "%d", pstCgtft->ucCid);
            /* <packet filter identifier> */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",%d", pstCgtft->astPfInfo[ucTmp2].ucPacketFilterId);
            /* <evaluation precedence index> */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",%d", pstCgtft->astPfInfo[ucTmp2].ucPrecedence);
            /* <source address and subnet mask> */
            if (VOS_TRUE == pstCgtft->astPfInfo[ucTmp2].bitOpRmtIpv4AddrAndMask)
            {
                AT_Ipv4AddrItoa(acIpv4StrTmp, pstCgtft->astPfInfo[ucTmp2].aucRmtIpv4Address);
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%s", acIpv4StrTmp);
                AT_Ipv4AddrItoa(acIpv4StrTmp, pstCgtft->astPfInfo[ucTmp2].aucRmtIpv4Mask);
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ".%s\"", acIpv4StrTmp);
            }
            else if (VOS_TRUE == pstCgtft->astPfInfo[ucTmp2].bitOpRmtIpv6AddrAndMask)
            {
                (VOS_VOID)AT_Ipv6AddrMask2FormatString(acIpv6StrTmp,
                                                       pstCgtft->astPfInfo[ucTmp2].aucRmtIpv6Address,
                                                       pstCgtft->astPfInfo[ucTmp2].aucRmtIpv6Mask);
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%s\"", acIpv6StrTmp);
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",");
            }
            /* <protocol number (ipv4) / next header (ipv6)> */
            if (VOS_TRUE == pstCgtft->astPfInfo[ucTmp2].bitOpProtocolId)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",%d", pstCgtft->astPfInfo[ucTmp2].ucProtocolId);
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",");
            }
            /* <destination port range> */
            if (VOS_TRUE == pstCgtft->astPfInfo[ucTmp2].bitOpSingleLocalPort)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",%d", pstCgtft->astPfInfo[ucTmp2].usLcPortLowLimit);
            }
            else if (VOS_TRUE == pstCgtft->astPfInfo[ucTmp2].bitOpLocalPortRange)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%d", pstCgtft->astPfInfo[ucTmp2].usLcPortLowLimit);
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ".%d\"", pstCgtft->astPfInfo[ucTmp2].usLcPortHighLimit);
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",");
            }
            /* <source port range> */
            if (VOS_TRUE == pstCgtft->astPfInfo[ucTmp2].bitOpSingleRemotePort)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",%d", pstCgtft->astPfInfo[ucTmp2].usRmtPortLowLimit);
            }
            else if (VOS_TRUE == pstCgtft->astPfInfo[ucTmp2].bitOpRemotePortRange)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%d", pstCgtft->astPfInfo[ucTmp2].usRmtPortLowLimit);
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ".%d\"", pstCgtft->astPfInfo[ucTmp2].usRmtPortHighLimit);
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",");
            }
            /* <ipsec security parameter index (spi)> */
            if (1 == pstCgtft->astPfInfo[ucTmp2].bitOpSecuParaIndex)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%X\"", pstCgtft->astPfInfo[ucTmp2].ulSecuParaIndex);
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",");
            }
            /* <type of service (tos) (ipv4) and mask / traffic class (ipv6) and mask> */
            if (VOS_TRUE == pstCgtft->astPfInfo[ucTmp2].bitOpTypeOfService)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%d", pstCgtft->astPfInfo[ucTmp2].ucTypeOfService);
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ".%d\"", pstCgtft->astPfInfo[ucTmp2].ucTypeOfServiceMask);
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",");
            }
            /* <flow label (ipv6)> */
            if (VOS_TRUE == pstCgtft->astPfInfo[ucTmp2].bitOpFlowLabelType)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",%X", pstCgtft->astPfInfo[ucTmp2].ulFlowLabelType);
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",");
            }
            /* <direction> */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",%d", pstCgtft->astPfInfo[ucTmp2].enDirection);

            if (AT_IsSupportReleaseRst(AT_ACCESS_STRATUM_REL11))
            {
                /* <local address and subnet mask> */
                if ( VOS_TRUE == pstCgtft->astPfInfo[ucTmp2].bitOpLocalIpv4AddrAndMask )
                {
                    AT_Ipv4AddrItoa(aucLocalIpv4StrTmp, pstCgtft->astPfInfo[ucTmp2].aucLocalIpv4Addr);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s",aucLocalIpv4StrTmp);

                    AT_Ipv4AddrItoa(aucLocalIpv4StrTmp, pstCgtft->astPfInfo[ucTmp2].aucLocalIpv4Mask);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,".%s\"",aucLocalIpv4StrTmp);
                }
                else if ( VOS_TRUE == pstCgtft->astPfInfo[ucTmp2].bitOpLocalIpv6AddrAndMask )
                {
                    AT_GetIpv6MaskByPrefixLength(pstCgtft->astPfInfo[ucTmp2].ucLocalIpv6Prefix, aucLocalIpv6Mask);
                    (VOS_VOID)AT_Ipv6AddrMask2FormatString(acIpv6StrTmp,
                                                           pstCgtft->astPfInfo[ucTmp2].aucLocalIpv6Addr,
                                                           aucLocalIpv6Mask);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%s\"", acIpv6StrTmp);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",");
                }
            }
        }
    }

    /* ?????????????????? */
    /*lint -save -e516 */
    PS_MEM_FREE(WUEPS_PID_AT, pstCgtft);
    /*lint -restore */
    ulResult                = AT_OK;
    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    /* ?????????? */
    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSetUmtsQosInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_UMTS_QOS_INFO_CNF_STRU  *pstSetUmtsQosInfoCnf;

    pstSetUmtsQosInfoCnf = (TAF_PS_SET_UMTS_QOS_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGEQREQ_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetUmtsQosInfoCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetUmtsQosInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;
    TAF_UINT8                           ucTmp = 0;
    TAF_PS_GET_UMTS_QOS_INFO_CNF_STRU  *pstUmtsQosInfo = VOS_NULL_PTR;
    TAF_UMTS_QOS_QUERY_INFO_STRU        stCgeq;

    TAF_MEM_SET_S(&stCgeq, sizeof(stCgeq), 0x00, sizeof(TAF_UMTS_QOS_QUERY_INFO_STRU));

    pstUmtsQosInfo = (TAF_PS_GET_UMTS_QOS_INFO_CNF_STRU *)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGEQREQ_READ != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    for(ucTmp = 0; ucTmp < pstUmtsQosInfo->ulCidNum; ucTmp++)
    {
        if(0 != ucTmp)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        }

        TAF_MEM_CPY_S(&stCgeq, sizeof(stCgeq), &pstUmtsQosInfo->astUmtsQosQueryInfo[ucTmp], sizeof(TAF_UMTS_QOS_QUERY_INFO_STRU));
        /* +CGEQREQ:+CGEQMIN   */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        /* <cid> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",stCgeq.ucCid);
        /* <Traffic class> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucTrafficClass);
        /* <Maximum bitrate UL> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ulMaxBitUl);
        /* <Maximum bitrate DL> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ulMaxBitDl);
        /* <Guaranteed bitrate UL> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ulGuarantBitUl);
        /* <Guaranteed bitrate DL> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ulGuarantBitDl);
        /* <Delivery order> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucDeliverOrder);
        /* <Maximum SDU size> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.usMaxSduSize);
        /* <SDU error ratio> */
        switch(stCgeq.stQosInfo.ucSduErrRatio)
        {
        case 0:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_0E0].pucText);
            break;

        case 1:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E2].pucText);
            break;

        case 2:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_7E3].pucText);
            break;

        case 3:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E3].pucText);
            break;

        case 4:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E4].pucText);
            break;

        case 5:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E5].pucText);
            break;

        case 6:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E6].pucText);
            break;

        case 7:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E1].pucText);
            break;

        default:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            break;
        }
        /* <Residual bit error ratio> */
        switch(stCgeq.stQosInfo.ucResidualBer)
        {
        case 0:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_0E0].pucText);
            break;

        case 1:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_5E2].pucText);
            break;

        case 2:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E2].pucText);
            break;

        case 3:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_5E3].pucText);
            break;

        case 4:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_4E3].pucText);
            break;

        case 5:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E3].pucText);
            break;

        case 6:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E4].pucText);
            break;

        case 7:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E5].pucText);
            break;

        case 8:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E6].pucText);
            break;

        case 9:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_6E8].pucText);
            break;

        default:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            break;
        }
        /* <Delivery of erroneous SDUs> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucDeliverErrSdu);
        /* <Transfer delay> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.usTransDelay);
        /* <Traffic handling priority> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucTraffHandlePrior);

        /* <Source Statistics Descriptor> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucSrcStatisticsDescriptor);
        /* <Signalling Indication> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucSignallingIndication);
    }

    ulResult                = AT_OK;
    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSetUmtsQosMinInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_UMTS_QOS_MIN_INFO_CNF_STRU  *pstSetUmtsQosMinInfoCnf;

    pstSetUmtsQosMinInfoCnf = (TAF_PS_SET_UMTS_QOS_MIN_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGEQMIN_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetUmtsQosMinInfoCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetUmtsQosMinInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_UINT32                              ulResult = AT_FAILURE;
    TAF_UINT16                              usLength = 0;
    TAF_UINT8                               ucTmp = 0;
    TAF_PS_GET_UMTS_QOS_MIN_INFO_CNF_STRU  *pstUmtsQosMinInfo = VOS_NULL_PTR;
    TAF_UMTS_QOS_QUERY_INFO_STRU            stCgeq;

    TAF_MEM_SET_S(&stCgeq, sizeof(stCgeq), 0x00, sizeof(TAF_UMTS_QOS_QUERY_INFO_STRU));

    pstUmtsQosMinInfo = (TAF_PS_GET_UMTS_QOS_MIN_INFO_CNF_STRU *)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGEQMIN_READ != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    for(ucTmp = 0; ucTmp < pstUmtsQosMinInfo->ulCidNum; ucTmp++)
    {
        if(0 != ucTmp)
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        }

        TAF_MEM_CPY_S(&stCgeq, sizeof(stCgeq), &pstUmtsQosMinInfo->astUmtsQosQueryInfo[ucTmp], sizeof(TAF_UMTS_QOS_QUERY_INFO_STRU));
        /* +CGEQREQ:+CGEQMIN   */
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        /* <cid> */
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%d",stCgeq.ucCid);
        /* <Traffic class> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucTrafficClass);
        /* <Maximum bitrate UL> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ulMaxBitUl);
        /* <Maximum bitrate DL> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ulMaxBitDl);
        /* <Guaranteed bitrate UL> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ulGuarantBitUl);
        /* <Guaranteed bitrate DL> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ulGuarantBitDl);
        /* <Delivery order> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucDeliverOrder);
        /* <Maximum SDU size> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.usMaxSduSize);
        /* <SDU error ratio> */
        switch(stCgeq.stQosInfo.ucSduErrRatio)
        {
        case 0:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_0E0].pucText);
            break;

        case 1:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E2].pucText);
            break;

        case 2:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_7E3].pucText);
            break;

        case 3:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E3].pucText);
            break;

        case 4:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E4].pucText);
            break;

        case 5:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E5].pucText);
            break;

        case 6:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E6].pucText);
            break;

        case 7:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E1].pucText);
            break;

        default:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            break;
        }
        /* <Residual bit error ratio> */
        switch(stCgeq.stQosInfo.ucResidualBer)
        {
        case 0:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_0E0].pucText);
            break;

        case 1:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_5E2].pucText);
            break;

        case 2:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E2].pucText);
            break;

        case 3:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_5E3].pucText);
            break;

        case 4:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_4E3].pucText);
            break;

        case 5:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E3].pucText);
            break;

        case 6:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E4].pucText);
            break;

        case 7:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E5].pucText);
            break;

        case 8:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E6].pucText);
            break;

        case 9:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_6E8].pucText);
            break;

        default:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            break;
        }
        /* <Delivery of erroneous SDUs> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucDeliverErrSdu);
        /* <Transfer delay> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.usTransDelay);
        /* <Traffic handling priority> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucTraffHandlePrior);

        /* <Source Statistics Descriptor> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucSrcStatisticsDescriptor);
        /* <Signalling Indication> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucSignallingIndication);
    }

    ulResult                = AT_OK;
    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetDynamicUmtsQosInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                                  ulResult = AT_FAILURE;
    VOS_UINT16                                  usLength = 0;
    VOS_UINT8                                   ucTmp = 0;
    TAF_PS_GET_DYNAMIC_UMTS_QOS_INFO_CNF_STRU  *pstDynUmtsQosMinInfo = VOS_NULL_PTR;
    TAF_UMTS_QOS_QUERY_INFO_STRU                stCgeq;

    TAF_MEM_SET_S(&stCgeq, sizeof(stCgeq), 0x00, sizeof(TAF_UMTS_QOS_QUERY_INFO_STRU));

    pstDynUmtsQosMinInfo = (TAF_PS_GET_DYNAMIC_UMTS_QOS_INFO_CNF_STRU *)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGEQNEG_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    for(ucTmp = 0; ucTmp < pstDynUmtsQosMinInfo->ulCidNum; ucTmp++)
    {
        if(0 != ucTmp)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        }

        TAF_MEM_CPY_S(&stCgeq, sizeof(stCgeq), &pstDynUmtsQosMinInfo->astUmtsQosQueryInfo[ucTmp], sizeof(TAF_UMTS_QOS_QUERY_INFO_STRU));
        /* +CGEQREQ:+CGEQMIN   */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        /* <cid> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",stCgeq.ucCid);
        /* <Traffic class> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucTrafficClass);
        /* <Maximum bitrate UL> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ulMaxBitUl);
        /* <Maximum bitrate DL> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ulMaxBitDl);
        /* <Guaranteed bitrate UL> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ulGuarantBitUl);
        /* <Guaranteed bitrate DL> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ulGuarantBitDl);
        /* <Delivery order> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucDeliverOrder);
        /* <Maximum SDU size> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.usMaxSduSize);
        /* <SDU error ratio> */
        switch(stCgeq.stQosInfo.ucSduErrRatio)
        {
        case 0:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_0E0].pucText);
            break;

        case 1:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E2].pucText);
            break;

        case 2:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_7E3].pucText);
            break;

        case 3:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E3].pucText);
            break;

        case 4:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E4].pucText);
            break;

        case 5:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E5].pucText);
            break;

        case 6:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E6].pucText);
            break;

        case 7:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E1].pucText);
            break;

        default:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            break;
        }
        /* <Residual bit error ratio> */
        switch(stCgeq.stQosInfo.ucResidualBer)
        {
        case 0:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_0E0].pucText);
            break;

        case 1:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_5E2].pucText);
            break;

        case 2:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E2].pucText);
            break;

        case 3:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_5E3].pucText);
            break;

        case 4:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_4E3].pucText);
            break;

        case 5:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E3].pucText);
            break;

        case 6:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E4].pucText);
            break;

        case 7:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E5].pucText);
            break;

        case 8:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_1E6].pucText);
            break;

        case 9:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%s",gastAtStringTab[AT_STRING_6E8].pucText);
            break;

        default:
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            break;
        }
        /* <Delivery of erroneous SDUs> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucDeliverErrSdu);
        /* <Transfer delay> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.usTransDelay);
        /* <Traffic handling priority> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeq.stQosInfo.ucTraffHandlePrior);
    }

    ulResult                = AT_OK;
    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSetPdpStateCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_PDP_STATE_CNF_STRU      *pstSetPdpStateCnf;

    pstSetPdpStateCnf = (TAF_PS_SET_PDP_STATE_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( (AT_CMD_CGACT_ORG_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
      && (AT_CMD_CGACT_END_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
      && (AT_CMD_CGDATA_SET    != gastAtClientTab[ucIndex].CmdCurrentOpt) )
    {
        return VOS_ERR;
    }

    /*----------------------------------------------------------
       (1)??????????????, ??????PDP????, ????????ERROR
       (2)??????????, ????PDP????, ????PDP????????????????
    ----------------------------------------------------------*/

    if (TAF_PS_CAUSE_SUCCESS != pstSetPdpStateCnf->enCause)
    {
        /* ????PS???????????? */
        AT_PS_SetPsCallErrCause(ucIndex, pstSetPdpStateCnf->enCause);

        AT_STOP_TIMER_CMD_READY(ucIndex);

        if (TAF_PS_CAUSE_PDP_ACTIVATE_LIMIT == pstSetPdpStateCnf->enCause)
        {
            At_FormatResultData(ucIndex, AT_CME_PDP_ACT_LIMIT);
        }
        else
        {
            At_FormatResultData(ucIndex, AT_ERROR);
        }
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtCgactQryCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT16                          usLength = 0;
    VOS_UINT8                           ucTmp = 0;
    TAF_CID_STATE_STRU                  stCgact;
    TAF_PS_GET_PDP_STATE_CNF_STRU      *pstPdpState = VOS_NULL_PTR;

    pstPdpState = (TAF_PS_GET_PDP_STATE_CNF_STRU *)pEvtInfo;

    TAF_MEM_SET_S(&stCgact, sizeof(stCgact), 0x00, sizeof(TAF_CID_STATE_STRU));

    /* ?????????????????????? */
    for (ucTmp = 0; ucTmp < pstPdpState->ulCidNum; ucTmp++)
    {
        if (0 != ucTmp)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        }

        TAF_MEM_CPY_S(&stCgact, sizeof(stCgact), &pstPdpState->astCidStateInfo[ucTmp], sizeof(TAF_CID_STATE_STRU));
        /* +CGACT:  */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        /* <cid> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",stCgact.ucCid);
        /* <state> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgact.ucState);
    }

    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, AT_OK);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtCgeqnegTestCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT16                          usLength;
    VOS_UINT32                          ulQosnegNum;
    VOS_UINT32                          ulTmp;
    TAF_CID_STATE_STRU                  stCgact;
    TAF_PS_GET_PDP_STATE_CNF_STRU      *pstPdpState = VOS_NULL_PTR;

    usLength    = 0;
    ulQosnegNum = 0;
    pstPdpState = (TAF_PS_GET_PDP_STATE_CNF_STRU *)pEvtInfo;

    TAF_MEM_SET_S(&stCgact, sizeof(stCgact), 0x00, sizeof(TAF_CID_STATE_STRU));

    /* CGEQNEG?????????? */

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s", "(");

    for(ulTmp = 0; ulTmp < pstPdpState->ulCidNum; ulTmp++)
    {
        TAF_MEM_CPY_S(&stCgact, sizeof(stCgact), &pstPdpState->astCidStateInfo[ulTmp], sizeof(TAF_CID_STATE_STRU));

        if (TAF_PDP_ACTIVE == stCgact.ucState)
        {   /*??????CID????????,????????CID????????????????;??????????CID*/
            if (0 == ulQosnegNum )
            {   /*????????????CID????CID????????????*/
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%d",stCgact.ucCid);
            }
            else
            {   /*??????????????CID????CID??????????*/
                usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",%d",stCgact.ucCid);
            }

            ulQosnegNum ++;
        }
    }

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,"%s", ")");

    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, AT_OK);

    return VOS_OK;
}



VOS_UINT32 AT_RcvTafPsEvtGetPdpStateCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{

    /* ?????????????????????? */
    if (AT_CMD_CGACT_READ == gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return AT_RcvTafPsEvtCgactQryCnf(ucIndex, pEvtInfo);
    }
    else if (AT_CMD_CGEQNEG_TEST == gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return AT_RcvTafPsEvtCgeqnegTestCnf(ucIndex, pEvtInfo);

    }
    else
    {
        return VOS_ERR;
    }


}


VOS_UINT32 AT_RcvTafPsEvtGetPdpIpAddrInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT16                            usLength = 0;
    VOS_UINT8                             ucTmp = 0;
    VOS_CHAR                              aStrTmp[TAF_MAX_IPV4_ADDR_STR_LEN];
    VOS_CHAR                              acIPv6Str[TAF_MAX_IPV6_ADDR_DOT_STR_LEN];
    TAF_PDP_ADDR_QUERY_INFO_STRU          stPdpAddrQuery;
    TAF_PS_GET_PDP_IP_ADDR_INFO_CNF_STRU *pstPdpIpAddr = VOS_NULL_PTR;

    /* ?????? */
    pstPdpIpAddr = (TAF_PS_GET_PDP_IP_ADDR_INFO_CNF_STRU *)pEvtInfo;
    TAF_MEM_SET_S(aStrTmp, sizeof(aStrTmp), 0x00, sizeof(aStrTmp));

    TAF_MEM_SET_S(acIPv6Str, sizeof(acIPv6Str), 0x00, sizeof(acIPv6Str));
    TAF_MEM_SET_S(&stPdpAddrQuery, sizeof(stPdpAddrQuery), 0x00, sizeof(TAF_PDP_ADDR_QUERY_INFO_STRU));

    /* ?????????????????????? */
    if ( AT_CMD_CGPADDR_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    for (ucTmp = 0; ucTmp < pstPdpIpAddr->ulCidNum; ucTmp++)
    {
        if(0 != ucTmp)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, "%s", gaucAtCrLf);
        }

        TAF_MEM_CPY_S(&stPdpAddrQuery, sizeof(stPdpAddrQuery), &pstPdpIpAddr->astPdpAddrQueryInfo[ucTmp], sizeof(TAF_PDP_ADDR_QUERY_INFO_STRU));


        /* +CGPADDR:  */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, "%s: ", g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

        /* <cid> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, "%d", stPdpAddrQuery.ucCid);

        /* <PDP_addr> */
        if ( (TAF_PDP_IPV4 == stPdpAddrQuery.stPdpAddr.enPdpType)
          || (TAF_PDP_PPP == stPdpAddrQuery.stPdpAddr.enPdpType) )
        {
            AT_Ipv4AddrItoa(aStrTmp, stPdpAddrQuery.stPdpAddr.aucIpv4Addr);
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"%s\"", aStrTmp);
        }
        else if (TAF_PDP_IPV6 == stPdpAddrQuery.stPdpAddr.enPdpType)
        {
            (VOS_VOID)AT_Ipv6AddrMask2FormatString(acIPv6Str,
                                                   stPdpAddrQuery.stPdpAddr.aucIpv6Addr,
                                                   VOS_NULL_PTR);
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%s\"", acIPv6Str);
        }
        else if (TAF_PDP_IPV4V6 == stPdpAddrQuery.stPdpAddr.enPdpType)
        {
            AT_Ipv4AddrItoa(aStrTmp, stPdpAddrQuery.stPdpAddr.aucIpv4Addr);
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,(TAF_CHAR *)pgucAtSndCodeAddr,(TAF_CHAR *)pgucAtSndCodeAddr + usLength,",\"%s\"", aStrTmp);

            (VOS_VOID)AT_Ipv6AddrMask2FormatString(acIPv6Str,
                                                   stPdpAddrQuery.stPdpAddr.aucIpv6Addr,
                                                   VOS_NULL_PTR);
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%s\"", acIPv6Str);
        }
        else
        {
            /* TAF_PDP_TYPE_BUTT */
            return VOS_ERR;
        }
    }

    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, AT_OK);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSetAnsModeInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_ANSWER_MODE_INFO_CNF_STRU   *pstSetAnsModeInfoCnf;

    pstSetAnsModeInfoCnf = (TAF_PS_SET_ANSWER_MODE_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGAUTO_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetAnsModeInfoCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetAnsModeInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT16                              usLength;
    TAF_PS_GET_ANSWER_MODE_INFO_CNF_STRU   *pstCallAns;

    /* ?????? */
    usLength    = 0;
    pstCallAns  = (TAF_PS_GET_ANSWER_MODE_INFO_CNF_STRU *)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGAUTO_READ != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* +CGAUTO */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",pstCallAns->ulAnsMode);

    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, AT_OK);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetDynamicPrimPdpContextInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;
    VOS_UINT8                           ucTmp = 0;
    VOS_CHAR                            acIpv4StrTmp[TAF_MAX_IPV4_ADDR_STR_LEN];
    VOS_CHAR                            acIpv6StrTmp[AT_IPV6_ADDR_MASK_FORMAT_STR_LEN];

    VOS_UINT8                           aucStr[TAF_MAX_APN_LEN + 1];

    TAF_PDP_DYNAMIC_PRIM_EXT_STRU       stCgdcont;
    TAF_PS_GET_DYNAMIC_PRIM_PDP_CONTEXT_INFO_CNF_STRU  *pstGetDynamicPdpCtxInfoCnf = VOS_NULL_PTR;

    TAF_MEM_SET_S(acIpv4StrTmp,  sizeof(acIpv4StrTmp), 0x00, TAF_MAX_IPV4_ADDR_STR_LEN);
    TAF_MEM_SET_S(acIpv6StrTmp, sizeof(acIpv6StrTmp), 0x00, AT_IPV6_ADDR_MASK_FORMAT_STR_LEN);
    TAF_MEM_SET_S(&stCgdcont,    sizeof(stCgdcont), 0x00, sizeof(TAF_PDP_DYNAMIC_PRIM_EXT_STRU));
    pstGetDynamicPdpCtxInfoCnf = (TAF_PS_GET_DYNAMIC_PRIM_PDP_CONTEXT_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGCONTRDP_SET!= gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    if( VOS_OK == pstGetDynamicPdpCtxInfoCnf->enCause )
    {
        for(ucTmp = 0; ucTmp < pstGetDynamicPdpCtxInfoCnf->ulCidNum; ucTmp++)
        {
            if(0 != ucTmp)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
            }

            TAF_MEM_CPY_S(&stCgdcont, sizeof(stCgdcont), &pstGetDynamicPdpCtxInfoCnf->astPdpContxtInfo[ucTmp], sizeof(TAF_PDP_DYNAMIC_PRIM_EXT_STRU));

            /* +CGCONTRDP:  */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
            /* <p_cid> */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",stCgdcont.ucPrimayCid);
            /* <bearer_id> */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgdcont.ucBearerId);
            /* <APN> */
            if(1 == stCgdcont.bitOpApn)
            {
                TAF_MEM_SET_S(aucStr, sizeof(aucStr), 0x00, sizeof(aucStr));
                TAF_MEM_CPY_S(aucStr, sizeof(aucStr), stCgdcont.aucApn, TAF_MAX_APN_LEN);
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"",stCgdcont.aucApn);
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            }

            /* <ip_addr> */
            if((VOS_TRUE == stCgdcont.bitOpIpAddr) && (VOS_TRUE == stCgdcont.bitOpSubMask))
            {
                if (TAF_PDP_IPV4 == stCgdcont.stPdpAddr.enPdpType)
                {
                    AT_Ipv4AddrItoa(acIpv4StrTmp, stCgdcont.stPdpAddr.aucIpv4Addr);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s",acIpv4StrTmp);

                    AT_Ipv4AddrItoa(acIpv4StrTmp, stCgdcont.stSubnetMask.aucIpv4Addr);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,".%s\"",acIpv4StrTmp);
                }
                else if(TAF_PDP_IPV6 == stCgdcont.stPdpAddr.enPdpType)
                {
                    (VOS_VOID)AT_Ipv6AddrMask2FormatString(acIpv6StrTmp,
                                                           stCgdcont.stPdpAddr.aucIpv6Addr,
                                                           stCgdcont.stSubnetMask.aucIpv6Addr);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%s\"", acIpv6StrTmp);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            }

            /* <gw_addr> */
            if(VOS_TRUE == stCgdcont.bitOpGwAddr)
            {
                if ( (TAF_PDP_IPV4 == stCgdcont.stGWAddr.enPdpType)
                  || (TAF_PDP_PPP == stCgdcont.stGWAddr.enPdpType) )
                {
                    AT_Ipv4AddrItoa(acIpv4StrTmp, stCgdcont.stGWAddr.aucIpv4Addr);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"",acIpv4StrTmp);
                }
                else if(TAF_PDP_IPV6 == stCgdcont.stGWAddr.enPdpType)
                {
                    (VOS_VOID)AT_Ipv6AddrMask2FormatString(acIpv6StrTmp,
                                                           stCgdcont.stGWAddr.aucIpv6Addr,
                                                           VOS_NULL_PTR);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%s\"", acIpv6StrTmp);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            }

            /* <NDS_prim_addr> */
            if(VOS_TRUE == stCgdcont.bitOpDNSPrimAddr)
            {
                if ( (TAF_PDP_IPV4 == stCgdcont.stDNSPrimAddr.enPdpType)
                  || (TAF_PDP_PPP == stCgdcont.stDNSPrimAddr.enPdpType) )
                {
                    AT_Ipv4AddrItoa(acIpv4StrTmp, stCgdcont.stDNSPrimAddr.aucIpv4Addr);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"",acIpv4StrTmp);
                }
                else if(TAF_PDP_IPV6 == stCgdcont.stDNSPrimAddr.enPdpType)
                {
                    (VOS_VOID)AT_Ipv6AddrMask2FormatString(acIpv6StrTmp,
                                                           stCgdcont.stDNSPrimAddr.aucIpv6Addr,
                                                           VOS_NULL_PTR);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%s\"", acIpv6StrTmp);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            }

            /* <DNS_sec_addr> */
            if(VOS_TRUE == stCgdcont.bitOpDNSSecAddr)
            {
                if ( (TAF_PDP_IPV4 == stCgdcont.stDNSSecAddr.enPdpType)
                  || (TAF_PDP_PPP == stCgdcont.stDNSSecAddr.enPdpType) )
                {
                    AT_Ipv4AddrItoa(acIpv4StrTmp, stCgdcont.stDNSSecAddr.aucIpv4Addr);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"",acIpv4StrTmp);
                }
                else if(TAF_PDP_IPV6 == stCgdcont.stDNSSecAddr.enPdpType)
                {
                    (VOS_VOID)AT_Ipv6AddrMask2FormatString(acIpv6StrTmp,
                                                           stCgdcont.stDNSSecAddr.aucIpv6Addr,
                                                           VOS_NULL_PTR);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%s\"", acIpv6StrTmp);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            }

            /* <P-CSCF_prim_addr> */
            if(VOS_TRUE == stCgdcont.bitOpPCSCFPrimAddr)
            {
                if ( (TAF_PDP_IPV4 == stCgdcont.stPCSCFPrimAddr.enPdpType)
                  || (TAF_PDP_PPP == stCgdcont.stPCSCFPrimAddr.enPdpType) )
                {
                    AT_Ipv4AddrItoa(acIpv4StrTmp, stCgdcont.stPCSCFPrimAddr.aucIpv4Addr);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"",acIpv4StrTmp);
                }
                else if(TAF_PDP_IPV6 == stCgdcont.stPCSCFPrimAddr.enPdpType)
                {
                    (VOS_VOID)AT_Ipv6AddrMask2FormatString(acIpv6StrTmp,
                                                           stCgdcont.stPCSCFPrimAddr.aucIpv6Addr,
                                                           VOS_NULL_PTR);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%s\"", acIpv6StrTmp);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            }

            /* <P-CSCF_sec_addr> */
            if(VOS_TRUE == stCgdcont.bitOpPCSCFSecAddr)
            {
                if ( (TAF_PDP_IPV4 == stCgdcont.stPCSCFSecAddr.enPdpType)
                  || (TAF_PDP_PPP == stCgdcont.stPCSCFSecAddr.enPdpType))
                {
                    AT_Ipv4AddrItoa(acIpv4StrTmp, stCgdcont.stPCSCFSecAddr.aucIpv4Addr);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"",acIpv4StrTmp);
                }
                else if(TAF_PDP_IPV6 == stCgdcont.stPCSCFSecAddr.enPdpType)
                {
                    (VOS_VOID)AT_Ipv6AddrMask2FormatString(acIpv6StrTmp,
                                                           stCgdcont.stPCSCFSecAddr.aucIpv6Addr,
                                                           VOS_NULL_PTR);
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%s\"", acIpv6StrTmp);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            }

            if (VOS_TRUE == stCgdcont.bitOpImCnSignalFlg)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgdcont.enImCnSignalFlg);
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            }
        }
        ulResult                = AT_OK;
        gstAtSendData.usBufLen  = usLength;

    }
    else
    {
        ulResult                = AT_ERROR;
        gstAtSendData.usBufLen  = 0;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetDynamicSecPdpContextInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;
    VOS_UINT8                           ucTmp = 0;

    TAF_PDP_DYNAMIC_SEC_EXT_STRU       stCgdscont;
    TAF_PS_GET_DYNAMIC_SEC_PDP_CONTEXT_INFO_CNF_STRU  *pstGetDynamicPdpCtxInfoCnf = VOS_NULL_PTR;

    TAF_MEM_SET_S(&stCgdscont, sizeof(stCgdscont), 0x00, sizeof(TAF_PDP_DYNAMIC_SEC_EXT_STRU));
    pstGetDynamicPdpCtxInfoCnf = (TAF_PS_GET_DYNAMIC_SEC_PDP_CONTEXT_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGSCONTRDP_SET!= gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    if( VOS_OK == pstGetDynamicPdpCtxInfoCnf->enCause )
    {
        for(ucTmp = 0; ucTmp < pstGetDynamicPdpCtxInfoCnf->ulCidNum; ucTmp++)
        {
            if(0 != ucTmp)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
            }

            TAF_MEM_CPY_S(&stCgdscont, sizeof(stCgdscont), &pstGetDynamicPdpCtxInfoCnf->astPdpContxtInfo[ucTmp], sizeof(TAF_PDP_DYNAMIC_SEC_EXT_STRU));

            /* +CGSCONTRDP:  */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
            /* <cid> */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",stCgdscont.ucCid);
            /* <p_cid> */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgdscont.ucPrimaryCid);
            /* <bearer_id> */
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgdscont.ucBearerId);
        }

        ulResult                = AT_OK;
        gstAtSendData.usBufLen  = usLength;
    }
    else
    {
        ulResult                = AT_ERROR;
        gstAtSendData.usBufLen  = 0;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetDynamicTftInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;
    VOS_UINT8                           ucIndex1 = 0;
    VOS_UINT8                           ucIndex2 = 0;
    VOS_CHAR                            acIpv4StrTmp[TAF_MAX_IPV4_ADDR_STR_LEN];
    VOS_CHAR                            acIpv6StrTmp[AT_IPV6_ADDR_MASK_FORMAT_STR_LEN];
    VOS_CHAR                            aucLocalIpv4StrTmp[TAF_MAX_IPV4_ADDR_STR_LEN];
    VOS_UINT8                           aucLocalIpv6Mask[APP_MAX_IPV6_ADDR_LEN];

    TAF_PF_TFT_STRU                       *pstCgtft                 = VOS_NULL_PTR;
    TAF_PS_GET_DYNAMIC_TFT_INFO_CNF_STRU  *pstGetDynamicTftInfoCnf  = VOS_NULL_PTR;

    TAF_MEM_SET_S(acIpv4StrTmp, sizeof(acIpv4StrTmp), 0x00, sizeof(acIpv4StrTmp));
    TAF_MEM_SET_S(acIpv6StrTmp, sizeof(acIpv6StrTmp), 0x00, sizeof(acIpv6StrTmp));
    TAF_MEM_SET_S(aucLocalIpv4StrTmp, sizeof(aucLocalIpv4StrTmp), 0x00, sizeof(aucLocalIpv4StrTmp));
    TAF_MEM_SET_S(aucLocalIpv6Mask, sizeof(aucLocalIpv6Mask), 0x00, sizeof(aucLocalIpv6Mask));

    pstGetDynamicTftInfoCnf = (TAF_PS_GET_DYNAMIC_TFT_INFO_CNF_STRU*)pEvtInfo;

    pstCgtft = (TAF_PF_TFT_STRU *)PS_MEM_ALLOC(WUEPS_PID_AT, sizeof(TAF_PF_TFT_STRU));
    if (VOS_NULL_PTR == pstCgtft)
    {
        return VOS_ERR;
    }
    TAF_MEM_SET_S(pstCgtft, sizeof(TAF_PF_TFT_STRU), 0x00, sizeof(TAF_PF_TFT_STRU));

    /* ?????????????????????? */
    if ( AT_CMD_CGTFTRDP_SET!= gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        /*lint -save -e516 */
        PS_MEM_FREE(WUEPS_PID_AT, pstCgtft);
        /*lint -restore */
        return VOS_ERR;
    }

    if ( VOS_OK == pstGetDynamicTftInfoCnf->enCause)
    {
        for (ucIndex1 = 0; ucIndex1 < pstGetDynamicTftInfoCnf->ulCidNum; ucIndex1++)
        {
            for (ucIndex2 = 0; ucIndex2 < pstGetDynamicTftInfoCnf->astPfTftInfo[ucIndex1].ulPFNum; ucIndex2++)
            {
                if (!(0 == ucIndex1 && 0 == ucIndex2))
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
                }

                TAF_MEM_CPY_S(pstCgtft, sizeof(TAF_PF_TFT_STRU), &pstGetDynamicTftInfoCnf->astPfTftInfo[ucIndex1], sizeof(TAF_PF_TFT_STRU));

                /* +CGTFTRDP:  */
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
                /* <cid> */
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",pstCgtft->ulCid);
                /* <packet filter identifier> */
                if(1 == pstCgtft->astTftInfo[ucIndex2].bitOpPktFilterId)
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",pstCgtft->astTftInfo[ucIndex2].ucPacketFilterId);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }

                /* <evaluation precedence index> */
                if(1 == pstCgtft->astTftInfo[ucIndex2].bitOpPrecedence)
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",pstCgtft->astTftInfo[ucIndex2].ucPrecedence);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }

                /* <source address and subnet> */
                if(1 == pstCgtft->astTftInfo[ucIndex2].bitOpSrcIp)
                {
                    if ( (TAF_PDP_IPV4 == pstCgtft->astTftInfo[ucIndex2].stSourceIpaddr.enPdpType)
                      || (TAF_PDP_PPP == pstCgtft->astTftInfo[ucIndex2].stSourceIpaddr.enPdpType) )
                    {
                        AT_Ipv4AddrItoa(acIpv4StrTmp, pstCgtft->astTftInfo[ucIndex2].stSourceIpaddr.aucIpv4Addr);
                        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s",acIpv4StrTmp);

                        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,".");

                        AT_Ipv4AddrItoa(acIpv4StrTmp, pstCgtft->astTftInfo[ucIndex2].stSourceIpMask.aucIpv4Addr);
                        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s\"",acIpv4StrTmp);
                    }
                    else if(TAF_PDP_IPV6 == pstCgtft->astTftInfo[ucIndex2].stSourceIpaddr.enPdpType)
                    {
                        (VOS_VOID)AT_Ipv6AddrMask2FormatString(acIpv6StrTmp,
                                                               pstCgtft->astTftInfo[ucIndex2].stSourceIpaddr.aucIpv6Addr,
                                                               pstCgtft->astTftInfo[ucIndex2].stSourceIpMask.aucIpv6Addr);
                        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%s\"", acIpv6StrTmp);
                    }
                    else
                    {
                        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                    }
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }

                /* <protocal number(ipv4)/next header ipv6> */
                if(1 == pstCgtft->astTftInfo[ucIndex2].bitOpProtocolId)
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",pstCgtft->astTftInfo[ucIndex2].ucProtocolId);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }
                /* <destination port range> */
                if(1 == pstCgtft->astTftInfo[ucIndex2].bitOpDestPortRange)
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%d.%d\"",pstCgtft->astTftInfo[ucIndex2].usLowDestPort,pstCgtft->astTftInfo[ucIndex2].usHighDestPort);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }
                /* <source port range> */
                if(1 == pstCgtft->astTftInfo[ucIndex2].bitOpSrcPortRange)
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%d.%d\"",pstCgtft->astTftInfo[ucIndex2].usLowSourcePort,pstCgtft->astTftInfo[ucIndex2].usHighSourcePort);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }

                /* <ipsec security parameter index(spi)> */
                if(1 == pstCgtft->astTftInfo[ucIndex2].bitOpSpi)
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%X",pstCgtft->astTftInfo[ucIndex2].ulSecuParaIndex);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }
                /* <type os service(tos) (ipv4) and mask> */
                if(1 == pstCgtft->astTftInfo[ucIndex2].bitOpTosMask)
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%d.%d\"",pstCgtft->astTftInfo[ucIndex2].ucTypeOfService,pstCgtft->astTftInfo[ucIndex2].ucTypeOfServiceMask);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }
                /* <traffic class (ipv6) and mask> */

                /* <flow lable (ipv6)> */
                if(1 == pstCgtft->astTftInfo[ucIndex2].bitOpFlowLable)
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%X",pstCgtft->astTftInfo[ucIndex2].ulFlowLable);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }
                /* <direction> */
                if(1 == pstCgtft->astTftInfo[ucIndex2].bitOpDirection)
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",pstCgtft->astTftInfo[ucIndex2].ucDirection);
                }
                else
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                }

                /* <NW packet filter Identifier> */
                if(1 == pstCgtft->astTftInfo[ucIndex2].bitOpNwPktFilterId)
                {
                    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",pstCgtft->astTftInfo[ucIndex2].ucNwPktFilterId);
                }
                else
                {
                    if (AT_IsSupportReleaseRst(AT_ACCESS_STRATUM_REL11))
                    {
                        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
                    }
                }

                if (AT_IsSupportReleaseRst(AT_ACCESS_STRATUM_REL11))
                {
                    /* <local address and subnet> */
                    if ( 1 == pstCgtft->astTftInfo[ucIndex2].bitOpLocalIpv4AddrAndMask )
                    {
                        AT_Ipv4AddrItoa(aucLocalIpv4StrTmp, pstCgtft->astTftInfo[ucIndex2].aucLocalIpv4Addr);
                        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s",aucLocalIpv4StrTmp);

                        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,".");

                        AT_Ipv4AddrItoa(aucLocalIpv4StrTmp, pstCgtft->astTftInfo[ucIndex2].aucLocalIpv4Mask);
                        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s\"",aucLocalIpv4StrTmp);
                    }
                    else if ( 1 == pstCgtft->astTftInfo[ucIndex2].bitOpLocalIpv6AddrAndMask )
                    {
                        AT_GetIpv6MaskByPrefixLength(pstCgtft->astTftInfo[ucIndex2].ucLocalIpv6Prefix, aucLocalIpv6Mask);
                        (VOS_VOID)AT_Ipv6AddrMask2FormatString(acIpv6StrTmp,
                                                               pstCgtft->astTftInfo[ucIndex2].aucLocalIpv6Addr,
                                                               aucLocalIpv6Mask);
                        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN, (VOS_CHAR*)pgucAtSndCodeAddr, (VOS_CHAR*)pgucAtSndCodeAddr + usLength, ",\"%s\"", acIpv6StrTmp);
                    }
                    else
                    {
                        /* empty proc */
                    }
                }
            }

            /* <3,0,0,"192.168.0.2.255.255.255.0">,0,"0.65535","0.65535",0,"0.0",0,0 */
        }

        ulResult                = AT_OK;
        gstAtSendData.usBufLen  = usLength;
    }
    else
    {
        ulResult                = AT_ERROR;
       gstAtSendData.usBufLen   = 0;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);
    /*lint -save -e516 */
    PS_MEM_FREE(WUEPS_PID_AT, pstCgtft);
    /*lint -restore */
    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSetEpsQosInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{

    TAF_PS_SET_EPS_QOS_INFO_CNF_STRU  *pstSetEpsqosInfoCnf;

    pstSetEpsqosInfoCnf = (TAF_PS_SET_PRIM_PDP_CONTEXT_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGEQOS_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetEpsqosInfoCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetEpsQosInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;
    VOS_UINT8                           ucTmp = 0;

    TAF_EPS_QOS_EXT_STRU                stCgeqos;
    TAF_PS_GET_EPS_QOS_INFO_CNF_STRU   *pstGetEpsQosInfoCnf = VOS_NULL_PTR;

    TAF_MEM_SET_S(&stCgeqos, sizeof(stCgeqos), 0x00, sizeof(TAF_EPS_QOS_EXT_STRU));

    pstGetEpsQosInfoCnf = (TAF_PS_GET_EPS_QOS_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGEQOS_READ!= gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    for(ucTmp = 0; ucTmp < pstGetEpsQosInfoCnf->ulCidNum; ucTmp++)
    {
        if(0 != ucTmp)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        }

        TAF_MEM_CPY_S(&stCgeqos, sizeof(stCgeqos), &pstGetEpsQosInfoCnf->astEpsQosInfo[ucTmp], sizeof(TAF_EPS_QOS_EXT_STRU));

        /* +CGEQOS:  */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        /* <cid> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",stCgeqos.ucCid);
        /* <QCI> */
        if(1 == stCgeqos.bitOpQCI)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeqos.ucQCI);
        }
        else
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
        }
        /* <DL GBR> */
        if(1 == stCgeqos.bitOpDLGBR)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeqos.ulDLGBR);
        }
        else
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
        }
        /* <UL GBR> */
        if(1 == stCgeqos.bitOpULGBR)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeqos.ulULGBR);
        }
        else
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
        }
        /* <DL MBR> */
        if(1 == stCgeqos.bitOpDLMBR)
        {
           usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeqos.ulDLMBR);
        }
        else
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
        }
        /* <UL MBR> */
        if(1 == stCgeqos.bitOpULMBR)
        {
           usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeqos.ulULMBR);
        }
    }

    ulResult                = AT_OK;
    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}

VOS_VOID AT_PrintDynamicEpsQosInfo(
    TAF_PS_GET_DYNAMIC_EPS_QOS_INFO_CNF_STRU  *pstGetDynamicEpsQosInfoCnf,
    VOS_UINT8                                  ucIndex
)
{
    TAF_EPS_QOS_EXT_STRU                stCgeqos;
    VOS_UINT16                          usLength = 0;
    VOS_UINT8                           ucTmp    = 0;

    TAF_MEM_SET_S(&stCgeqos, sizeof(stCgeqos), 0x00, sizeof(TAF_EPS_QOS_EXT_STRU));

    for(ucTmp = 0; ucTmp < pstGetDynamicEpsQosInfoCnf->ulCidNum; ucTmp++)
    {
        if(0 != ucTmp)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        }

        TAF_MEM_CPY_S(&stCgeqos, sizeof(stCgeqos), &pstGetDynamicEpsQosInfoCnf->astEpsQosInfo[ucTmp], sizeof(TAF_EPS_QOS_EXT_STRU));

        /* +CGEQOSRDP:  */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        /* <cid> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",stCgeqos.ucCid);
        /* <QCI> */
        if(1 == stCgeqos.bitOpQCI)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeqos.ucQCI);
        }
        else
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
        }
        if (4 >= stCgeqos.ucQCI)
        {
            /* <DL GBR> */
            if(1 == stCgeqos.bitOpDLGBR)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeqos.ulDLGBR);
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            }
            /* <UL GBR> */
            if(1 == stCgeqos.bitOpULGBR)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeqos.ulULGBR);
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            }
            /* <DL MBR> */
            if(1 == stCgeqos.bitOpDLMBR)
            {
               usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeqos.ulDLMBR);
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
            }
            /* <UL MBR> */
            if(1 == stCgeqos.bitOpULMBR)
            {
               usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stCgeqos.ulULMBR);
            }
        }
    }

    gstAtSendData.usBufLen  = usLength;

    return;
}

VOS_UINT32 AT_RcvTafPsEvtGetDynamicEpsQosInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_GET_DYNAMIC_EPS_QOS_INFO_CNF_STRU  *pstGetDynamicEpsQosInfoCnf = VOS_NULL_PTR;
    VOS_UINT32                                 ulResult                   = AT_FAILURE;

    pstGetDynamicEpsQosInfoCnf = (TAF_PS_GET_DYNAMIC_EPS_QOS_INFO_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CGEQOSRDP_SET!= gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    if(VOS_OK == pstGetDynamicEpsQosInfoCnf->enCause)
    {
        AT_PrintDynamicEpsQosInfo(pstGetDynamicEpsQosInfoCnf, ucIndex);
        ulResult                = AT_OK;
    }
    else
    {
        ulResult                = AT_ERROR;
        gstAtSendData.usBufLen  = 0;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetDsFlowInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT16                              usLength;
    TAF_DSFLOW_QUERY_INFO_STRU             *pstAccumulatedFlowInfo;
    TAF_PS_GET_DSFLOW_INFO_CNF_STRU        *pstGetDsFlowInfoCnf;

    /* ?????? */
    usLength               = 0;
    pstGetDsFlowInfoCnf    = (TAF_PS_GET_DSFLOW_INFO_CNF_STRU*)pEvtInfo;
    pstAccumulatedFlowInfo = &pstGetDsFlowInfoCnf->stQueryInfo;



    /* ????????AT???????? */
    if ( AT_CMD_DSFLOWQRY_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ???????????????? */

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s:",
                                       g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%08X",
                                       pstAccumulatedFlowInfo->stCurrentFlowInfo.ulDSLinkTime);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       ",%08X%08X",
                                       pstAccumulatedFlowInfo->stCurrentFlowInfo.ulDSSendFluxHigh,
                                       pstAccumulatedFlowInfo->stCurrentFlowInfo.ulDSSendFluxLow);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       ",%08X%08X",
                                       pstAccumulatedFlowInfo->stCurrentFlowInfo.ulDSReceiveFluxHigh,
                                       pstAccumulatedFlowInfo->stCurrentFlowInfo.ulDSReceiveFluxLow);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       ",%08X",
                                       pstAccumulatedFlowInfo->stTotalFlowInfo.ulDSLinkTime);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       ",%08X%08X",
                                       pstAccumulatedFlowInfo->stTotalFlowInfo.ulDSSendFluxHigh,
                                       pstAccumulatedFlowInfo->stTotalFlowInfo.ulDSSendFluxLow);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       ",%08X%08X",
                                       pstAccumulatedFlowInfo->stTotalFlowInfo.ulDSReceiveFluxHigh,
                                       pstAccumulatedFlowInfo->stTotalFlowInfo.ulDSReceiveFluxLow);


    gstAtSendData.usBufLen = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, AT_OK);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtClearDsFlowInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CLEAR_DSFLOW_CNF_STRU       *pstClearDsFlowCnf;

    pstClearDsFlowCnf = (TAF_PS_CLEAR_DSFLOW_CNF_STRU*)pEvtInfo;


    /* ????????AT???????? */
    if (AT_CMD_DSFLOWCLR_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }


    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstClearDsFlowCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtConfigDsFlowRptCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CONFIG_DSFLOW_RPT_CNF_STRU  *pstConfigDsFlowRptCnf;

    pstConfigDsFlowRptCnf = (TAF_PS_CONFIG_DSFLOW_RPT_CNF_STRU*)pEvtInfo;


    /* ????????AT???????? */
    if (AT_CMD_DSFLOWRPT_SET   != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }


    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstConfigDsFlowRptCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtConfigVTFlowRptCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CONFIG_VTFLOW_RPT_CNF_STRU  *pstConfigVTFlowRptCnf;

    pstConfigVTFlowRptCnf = (TAF_PS_CONFIG_VTFLOW_RPT_CNF_STRU*)pEvtInfo;

    /* ????????AT???????? */
    if (AT_CMD_VTFLOWRPT_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstConfigVTFlowRptCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtReportDsFlowInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT16                          usLength;
    TAF_PS_REPORT_DSFLOW_IND_STRU      *pstDSFlowReport;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;

    /* ?????? */
    usLength        = 0;
    pstDSFlowReport = (TAF_PS_REPORT_DSFLOW_IND_STRU*)pEvtInfo;
    enModemId       = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("AT_RcvTafPsEvtReportDsFlowInd: Get modem id fail.");
        return VOS_ERR;
    }


    /* ?????????????????????????????????????????????? */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                        (VOS_CHAR*)pgucAtSndCodeAddr,
                        (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                        "%s^DSFLOWRPT:%08X,%08X,%08X,%08X%08X,%08X%08X,%08X,%08X%s",
                        gaucAtCrLf,
                        pstDSFlowReport->stDsFlowRptInfo.stCurrentFlowInfo.ulDSLinkTime,
                        pstDSFlowReport->stDsFlowRptInfo.ulCurrentSendRate,
                        pstDSFlowReport->stDsFlowRptInfo.ulCurrentReceiveRate,
                        pstDSFlowReport->stDsFlowRptInfo.stCurrentFlowInfo.ulDSSendFluxHigh,
                        pstDSFlowReport->stDsFlowRptInfo.stCurrentFlowInfo.ulDSSendFluxLow,
                        pstDSFlowReport->stDsFlowRptInfo.stCurrentFlowInfo.ulDSReceiveFluxHigh,
                        pstDSFlowReport->stDsFlowRptInfo.stCurrentFlowInfo.ulDSReceiveFluxLow,
                        pstDSFlowReport->stDsFlowRptInfo.ulQosSendRate,
                        pstDSFlowReport->stDsFlowRptInfo.ulQosReceiveRate,
                        gaucAtCrLf);

    At_SendResultData(ucIndex,pgucAtSndCodeAddr,usLength);


    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtReportVTFlowInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT16                          usLength;
    TAF_PS_REPORT_VTFLOW_IND_STRU      *pstVTFlowReport;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;

    /* ?????? */
    usLength        = 0;
    pstVTFlowReport = (TAF_PS_REPORT_VTFLOW_IND_STRU*)pEvtInfo;
    enModemId       = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("AT_RcvTafPsEvtReportVTFlowInd: Get modem id fail.");
        return VOS_ERR;
    }

    /* ?????????????????????????????????????????????? */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                        (VOS_CHAR*)pgucAtSndCodeAddr,
                        (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                        "%s%s%08X,%08X%08X,%08X%08X%s",
                        gaucAtCrLf,
                        gastAtStringTab[AT_STRING_VT_FLOW_RPT].pucText,
                        pstVTFlowReport->stDsFlowRptInfo.ulDSLinkTime,
                        pstVTFlowReport->stDsFlowRptInfo.ulDSSendFluxHigh,
                        pstVTFlowReport->stDsFlowRptInfo.ulDSSendFluxLow,
                        pstVTFlowReport->stDsFlowRptInfo.ulDSReceiveFluxHigh,
                        pstVTFlowReport->stDsFlowRptInfo.ulDSReceiveFluxLow,
                        gaucAtCrLf);

    At_SendResultData(ucIndex,pgucAtSndCodeAddr,usLength);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSetApDsFlowRptCfgCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_APDSFLOW_RPT_CFG_CNF_STRU   *pstSetRptCfgCnf;

    pstSetRptCfgCnf = (TAF_PS_SET_APDSFLOW_RPT_CFG_CNF_STRU *)pEvtInfo;

    /* ????????AT???????? */
    if (AT_CMD_APDSFLOWRPTCFG_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetRptCfgCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetApDsFlowRptCfgCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_GET_APDSFLOW_RPT_CFG_CNF_STRU   *pstGetRptCfgCnf;
    VOS_UINT16                              usLength;

    pstGetRptCfgCnf = (TAF_PS_GET_APDSFLOW_RPT_CFG_CNF_STRU *)pEvtInfo;
    usLength         = 0;

    /* ????????AT???????? */
    if (AT_CMD_APDSFLOWRPTCFG_QRY != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ?????????? */
    if (TAF_PS_CAUSE_SUCCESS != pstGetRptCfgCnf->enCause)
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);
        At_FormatResultData(ucIndex, AT_ERROR);
        return VOS_ERR;
    }

    /* ???????????? */
    usLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                      (VOS_CHAR *)pgucAtSndCodeAddr,
                                      (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                      "%s: %d,%u",
                                      g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                      pstGetRptCfgCnf->stRptCfg.ulRptEnabled,
                                      pstGetRptCfgCnf->stRptCfg.ulFluxThreshold);

    gstAtSendData.usBufLen = usLength;
    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, AT_OK);
    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtApDsFlowReportInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_APDSFLOW_REPORT_IND_STRU    *pstApDsFlowRptInd;
    VOS_UINT16                          usLength;
    MODEM_ID_ENUM_UINT16                enModemId;

    pstApDsFlowRptInd = (TAF_PS_APDSFLOW_REPORT_IND_STRU *)pEvtInfo;
    usLength          = 0;
    enModemId         = MODEM_ID_0;

    if (VOS_OK != AT_GetModemIdFromClient(ucIndex, &enModemId))
    {
        AT_ERR_LOG("AT_RcvTafPsEvtApDsFlowReportInd: Get modem id fail.");
        return VOS_ERR;
    }

    /* ^APDSFLOWRPT: <curr_ds_time>,<tx_rate>,<rx_rate>,<curr_tx_flow>,<curr_rx_flow>,<total_tx_flow>,<total_rx_flow> */
    usLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                      (VOS_CHAR*)pgucAtSndCodeAddr,
                                      (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                      "%s^APDSFLOWRPT: %08X,%08X,%08X,%08X%08X,%08X%08X,%08X%08X,%08X%08X%s",
                                      gaucAtCrLf,
                                      pstApDsFlowRptInd->stApDsFlowRptInfo.stCurrentFlowInfo.ulDSLinkTime,
                                      pstApDsFlowRptInd->stApDsFlowRptInfo.ulCurrentTxRate,
                                      pstApDsFlowRptInd->stApDsFlowRptInfo.ulCurrentRxRate,
                                      pstApDsFlowRptInd->stApDsFlowRptInfo.stCurrentFlowInfo.ulDSSendFluxHigh,
                                      pstApDsFlowRptInd->stApDsFlowRptInfo.stCurrentFlowInfo.ulDSSendFluxLow,
                                      pstApDsFlowRptInd->stApDsFlowRptInfo.stCurrentFlowInfo.ulDSReceiveFluxHigh,
                                      pstApDsFlowRptInd->stApDsFlowRptInfo.stCurrentFlowInfo.ulDSReceiveFluxLow,
                                      pstApDsFlowRptInd->stApDsFlowRptInfo.stTotalFlowInfo.ulDSSendFluxHigh,
                                      pstApDsFlowRptInd->stApDsFlowRptInfo.stTotalFlowInfo.ulDSSendFluxLow,
                                      pstApDsFlowRptInd->stApDsFlowRptInfo.stTotalFlowInfo.ulDSReceiveFluxHigh,
                                      pstApDsFlowRptInd->stApDsFlowRptInfo.stTotalFlowInfo.ulDSReceiveFluxLow,
                                      gaucAtCrLf);

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSetDsFlowNvWriteCfgCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_DSFLOW_NV_WRITE_CFG_CNF_STRU    *pstSetNvWriteCfgCnf;

    pstSetNvWriteCfgCnf = (TAF_PS_SET_DSFLOW_NV_WRITE_CFG_CNF_STRU *)pEvtInfo;

    /* ????????AT???????? */
    if (AT_CMD_DSFLOWNVWRCFG_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetNvWriteCfgCnf->enCause);
    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetDsFlowNvWriteCfgCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_GET_DSFLOW_NV_WRITE_CFG_CNF_STRU    *pstGetNvWriteCfgCnf;
    VOS_UINT16                                  usLength;

    pstGetNvWriteCfgCnf = (TAF_PS_GET_DSFLOW_NV_WRITE_CFG_CNF_STRU *)pEvtInfo;
    usLength            = 0;

    /* ????????AT???????? */
    if (AT_CMD_DSFLOWNVWRCFG_QRY != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ?????????? */
    if (TAF_PS_CAUSE_SUCCESS != pstGetNvWriteCfgCnf->enCause)
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);
        At_FormatResultData(ucIndex, AT_ERROR);
        return VOS_ERR;
    }

    /* ???????????? */
    usLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                      (VOS_CHAR *)pgucAtSndCodeAddr,
                                      (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                      "%s: %d,%d",
                                      g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                      pstGetNvWriteCfgCnf->stNvWriteCfg.ucEnabled,
                                      pstGetNvWriteCfgCnf->stNvWriteCfg.ucInterval);

    gstAtSendData.usBufLen = usLength;
    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, AT_OK);
    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSetPktCdataInactivityTimeLenCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_CTA_INFO_CNF_STRU       *pstSetPktCdataInactivityTimeLenCnf = VOS_NULL_PTR;

    pstSetPktCdataInactivityTimeLenCnf = (TAF_PS_SET_CTA_INFO_CNF_STRU *)pEvtInfo;

    /* ????????AT???????? */
    if (AT_CMD_CTA_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetPktCdataInactivityTimeLenCnf->ulRslt);
    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetPktCdataInactivityTimeLenCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT16                          usLength;
    TAF_PS_GET_CTA_INFO_CNF_STRU       *pstGetPktCdataInactivityTimeLenCnf = VOS_NULL_PTR;

    pstGetPktCdataInactivityTimeLenCnf = (TAF_PS_GET_CTA_INFO_CNF_STRU *)pEvtInfo;
    usLength                           = 0;

    /* ????????AT???????? */
    if (AT_CMD_CTA_QRY != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ?????????? */
    if (TAF_PS_CAUSE_SUCCESS != pstGetPktCdataInactivityTimeLenCnf->ulRslt)
    {
        AT_STOP_TIMER_CMD_READY(ucIndex);
        At_FormatResultData(ucIndex, AT_ERROR);
        return VOS_ERR;
    }

    /* ???????????? */
    usLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                      (VOS_CHAR *)pgucAtSndCodeAddr,
                                      (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                      "%s: %d",
                                      g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                      pstGetPktCdataInactivityTimeLenCnf->ucPktCdataInactivityTmrLen);

    gstAtSendData.usBufLen = usLength;
    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, AT_OK);
    return VOS_OK;

}


VOS_UINT32 AT_RcvTafPsEvtCgmtuValueChgInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CGMTU_VALUE_CHG_IND_STRU    *pstCgmtuChgInd;
    VOS_UINT16                          usLength;
    MODEM_ID_ENUM_UINT16                enModemId;

    pstCgmtuChgInd = (TAF_PS_CGMTU_VALUE_CHG_IND_STRU *)pEvtInfo;
    usLength       = 0;
    enModemId      = MODEM_ID_0;

    if (VOS_OK != AT_GetModemIdFromClient(ucIndex, &enModemId))
    {
        AT_ERR_LOG("AT_RcvTafPsEvtCgmtuValueChgInd: Get modem id fail.");
        return VOS_ERR;
    }

    /* ^CGMTU: <curr_mtu_value> */
    usLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                      (VOS_CHAR*)pgucAtSndCodeAddr,
                                      (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                      "%s^CGMTU: %d%s",
                                      gaucAtCrLf,
                                      pstCgmtuChgInd->ulMtuValue,
                                      gaucAtCrLf);

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSetPdpDnsInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_PDP_DNS_INFO_CNF_STRU   *pstSetPdpDnsInfoCnf;

    pstSetPdpDnsInfoCnf = (TAF_PS_SET_PDP_DNS_INFO_CNF_STRU*)pEvtInfo;

    if ( AT_CMD_CGDNS_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetPdpDnsInfoCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetPdpDnsInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    /* ????At_QryParaRspCgdnsProc?????????? */
    VOS_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;
    VOS_UINT8                           ucTmp = 0;
    TAF_DNS_QUERY_INFO_STRU             stPdpDns;
    TAF_PS_GET_PDP_DNS_INFO_CNF_STRU   *pstPdpDnsInfo = VOS_NULL_PTR;
    VOS_INT8                            acDnsAddr[TAF_MAX_IPV4_ADDR_STR_LEN];

    TAF_MEM_SET_S(&stPdpDns, sizeof(stPdpDns), 0x00, sizeof(TAF_DNS_QUERY_INFO_STRU));
    TAF_MEM_SET_S(acDnsAddr, sizeof(acDnsAddr), 0x00, TAF_MAX_IPV4_ADDR_STR_LEN);
    pstPdpDnsInfo = (TAF_PS_GET_PDP_DNS_INFO_CNF_STRU *)pEvtInfo;

    if ( AT_CMD_CGDNS_READ != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    for(ucTmp = 0; ucTmp < pstPdpDnsInfo->ulCidNum; ucTmp++)
    {
        if(0 != ucTmp)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        }

        TAF_MEM_CPY_S(&stPdpDns, sizeof(stPdpDns), &pstPdpDnsInfo->astPdpDnsQueryInfo[ucTmp],sizeof(TAF_DNS_QUERY_INFO_STRU));
        /* +CGDNS:  */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        /* <cid> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",stPdpDns.ucCid);
        /* <PriDns> */
        if(1 == stPdpDns.stDnsInfo.bitOpPrimDnsAddr)
        {
            AT_Ipv4Addr2Str(acDnsAddr, stPdpDns.stDnsInfo.aucPrimDnsAddr);
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"",acDnsAddr);
        }
        else
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
        }
        /* <SecDns> */
        if(1 == stPdpDns.stDnsInfo.bitOpSecDnsAddr)
        {
             AT_Ipv4Addr2Str(acDnsAddr, stPdpDns.stDnsInfo.aucSecDnsAddr);
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"",acDnsAddr);
        }
        else
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",");
        }
    }


    ulResult                = AT_OK;
    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSetAuthDataInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_AUTHDATA_INFO_CNF_STRU  *pstSetAuthDataInfoCnf;

    /* ?????? */
    pstSetAuthDataInfoCnf = (TAF_PS_SET_AUTHDATA_INFO_CNF_STRU*)pEvtInfo;

    /* ????????AT???????? */
    if ( AT_CMD_AUTHDATA_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetAuthDataInfoCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetAuthDataInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult = AT_FAILURE;
    VOS_UINT16                          usLength = 0;
    VOS_UINT8                           ucTmp = 0;
    TAF_AUTHDATA_QUERY_INFO_STRU        stPdpAuthData;
    TAF_PS_GET_AUTHDATA_INFO_CNF_STRU  *pstPdpAuthData = VOS_NULL_PTR;

    TAF_MEM_SET_S(&stPdpAuthData, sizeof(stPdpAuthData), 0x00, sizeof(TAF_AUTHDATA_QUERY_INFO_STRU));

    pstPdpAuthData = (TAF_PS_GET_AUTHDATA_INFO_CNF_STRU *)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_AUTHDATA_READ != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    for(ucTmp = 0; ucTmp < pstPdpAuthData->ulCidNum; ucTmp++)
    {
        if(0 != ucTmp)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s",gaucAtCrLf);
        }

        TAF_MEM_CPY_S(&stPdpAuthData, sizeof(stPdpAuthData), &pstPdpAuthData->astAuthDataQueryInfo[ucTmp], sizeof(TAF_AUTHDATA_QUERY_INFO_STRU));
        /* ^AUTHDATA:  */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        /* <cid> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",stPdpAuthData.ucCid);

        /* <Auth_type> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",%d",stPdpAuthData.stAuthDataInfo.enAuthType);

        /* <passwd> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"",stPdpAuthData.stAuthDataInfo.aucPassword);

        /* <username> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"",stPdpAuthData.stAuthDataInfo.aucUsername);

        /* <PLMN> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR*)pgucAtSndCodeAddr,(VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"",stPdpAuthData.stAuthDataInfo.aucPlmn);
    }


    ulResult                = AT_OK;
    gstAtSendData.usBufLen  = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetGprsActiveTypeCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                              ulResult;
    TAF_PS_GET_D_GPRS_ACTIVE_TYPE_CNF_STRU *pstGetGprsActiveTypeCnf;

    /* ?????? */
    ulResult                = AT_FAILURE;
    pstGetGprsActiveTypeCnf = (TAF_PS_GET_D_GPRS_ACTIVE_TYPE_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_D_GPRS_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ?????????????? */
    if ( TAF_PARA_OK == pstGetGprsActiveTypeCnf->enCause )
    {
        ulResult = At_SetDialGprsPara(ucIndex,
                        pstGetGprsActiveTypeCnf->stCidGprsActiveType.ucCid,
                        pstGetGprsActiveTypeCnf->stCidGprsActiveType.enActiveType);
    }
    else
    {
        ulResult = AT_ERROR;
    }

    if ( AT_WAIT_ASYNC_RETURN != ulResult )
    {
        if ( AT_ERROR == ulResult )
        {
            gastAtClientTab[ucIndex].CmdCurrentOpt = AT_CMD_CURRENT_OPT_BUTT;
        }

        AT_StopRelTimer(ucIndex, &gastAtClientTab[ucIndex].hTimer);
        g_stParseContext[ucIndex].ucClientStatus = AT_FW_CLIENT_STATUS_READY;
        gastAtClientTab[ucIndex].opId = 0;

        At_FormatResultData(ucIndex, ulResult);
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtPppDialOrigCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult;

    TAF_PS_PPP_DIAL_ORIG_CNF_STRU      *pstPppDialOrigCnf;

    /* ?????? */
    ulResult          = AT_FAILURE;
    pstPppDialOrigCnf = (TAF_PS_PPP_DIAL_ORIG_CNF_STRU*)pEvtInfo;

    /* MODEM???????????? */
    if ( (AT_MODEM_USER == gastAtClientTab[ucIndex].UserType)
      || (AT_HSUART_USER  == gastAtClientTab[ucIndex].UserType))
    {
        if (TAF_PS_CAUSE_SUCCESS != pstPppDialOrigCnf->enCause)
        {
            /* ????PS???????????? */
            AT_PS_SetPsCallErrCause(ucIndex, pstPppDialOrigCnf->enCause);

            if ((AT_CMD_D_PPP_CALL_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
             || (AT_CMD_PPP_ORG_SET    == gastAtClientTab[ucIndex].CmdCurrentOpt))
            {
                ulResult = AT_NO_CARRIER;

                PPP_RcvAtCtrlOperEvent(gastAtClientTab[ucIndex].usPppId, PPP_AT_CTRL_REL_PPP_REQ);

                /* ??PPP????HDLC?????????? */
                PPP_RcvAtCtrlOperEvent(gastAtClientTab[ucIndex].usPppId, PPP_AT_CTRL_HDLC_DISABLE);

                /* ???????????? */
                At_SetMode(ucIndex, AT_CMD_MODE, AT_NORMAL_MODE);

            }
            else if (AT_CMD_D_IP_CALL_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
            {
                if (TAF_PS_CAUSE_PDP_ACTIVATE_LIMIT == pstPppDialOrigCnf->enCause)
                {
                    ulResult = AT_CME_PDP_ACT_LIMIT;
                }
                else
                {
                    ulResult = AT_ERROR;
                }

                PPP_RcvAtCtrlOperEvent(gastAtClientTab[ucIndex].usPppId, PPP_AT_CTRL_REL_PPP_RAW_REQ);

                /*??PPP????HDLC??????????*/
                PPP_RcvAtCtrlOperEvent(gastAtClientTab[ucIndex].usPppId, PPP_AT_CTRL_HDLC_DISABLE);



            }
            else
            {
                ;
            }

            AT_STOP_TIMER_CMD_READY(ucIndex);
            At_FormatResultData(ucIndex, ulResult);
        }
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetCidSdfInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    return VOS_OK;
}


VOS_BOOL AT_PH_IsPlmnValid(TAF_PLMN_ID_STRU *pstPlmnId)
{
    VOS_UINT32                          i;

    for (i=0; i<3; i++)
    {
        if ((((pstPlmnId->Mcc >> (i*4)) & 0x0F) > 9)
         || ((((pstPlmnId->Mnc >> (i*4)) & 0x0F) > 9) && (i != 2 ))
         || ((((pstPlmnId->Mnc >> (i*4)) & 0x0F) > 9) && (((pstPlmnId->Mnc >> (i*4)) & 0x0F) != 0x0F)))
        {
            /* PLMN ID???? */
            return VOS_FALSE;
        }
    }
    return VOS_TRUE;
}


VOS_UINT32 AT_RcvTafPsEvtReportRaInfo(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_IPV6_INFO_IND_STRU *pstRaInfoNotifyInd;
    AT_PDP_ENTITY_STRU                  *pstPdpEntity;
    MODEM_ID_ENUM_UINT16                 enModemId;
    VOS_UINT32                           ulRet;
    VOS_UINT8                           *pucSystemAppConfig;

    /* ?????? */
    pucSystemAppConfig                  = AT_GetSystemAppConfigAddr();

    pstRaInfoNotifyInd = (TAF_PS_IPV6_INFO_IND_STRU *)pEvtInfo;

    enModemId          = MODEM_ID_0;

    ulRet = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRet)
    {
        AT_ERR_LOG("AT_RcvTafPsEvtReportRaInfo:Get Modem Id fail");
        return VOS_ERR;
    }

    if (AT_NDIS_USER == gastAtClientTab[ucIndex].UserType)
    {
        pstPdpEntity = AT_NDIS_GetPdpEntInfoAddr();

        /* ????IPv6????????????, ????????????????NDIS */
        if ( (AT_PDP_STATE_ACTED == pstPdpEntity->enIpv6State)
          || (AT_PDP_STATE_ACTED == pstPdpEntity->enIpv4v6State) )
        {
            /* ??NDIS????????IPV6 PDN???? */
            AT_SendNdisIPv6PdnInfoCfgReq(enModemId, pstRaInfoNotifyInd);
        }
    }

    if (AT_APP_USER == gastAtClientTab[ucIndex].UserType)
    {
        if (SYSTEM_APP_WEBUI == *pucSystemAppConfig)
        {
            pstPdpEntity = AT_APP_GetPdpEntInfoAddr();

            /* ????IPv6????????????, ????????????????RA???????? */
            if ( (AT_PDP_STATE_ACTED == pstPdpEntity->enIpv6State)
              || (AT_PDP_STATE_ACTED == pstPdpEntity->enIpv4v6State) )
            {
                AT_AppProcIpv6RaInfo(pstRaInfoNotifyInd);
            }
        }
        else
        {
            AT_PS_ProcIpv6RaInfo(pstRaInfoNotifyInd);
        }
    }

    if (VOS_TRUE == AT_CheckHsicUser(ucIndex))
    {
        AT_PS_ProcIpv6RaInfo(pstRaInfoNotifyInd);
    }

    return VOS_OK;
}



VOS_UINT32 AT_RcvTafPsEvtPdpDisconnectInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult;

    VOS_UINT16                          usLength;

    usLength = 0;

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        /* ????????????????????NO CARRIER*/
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                   (TAF_CHAR *)pgucAtSndCodeAddr,
                                   (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                    "%s",gaucAtCrLf);

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                        "%s","NO CARRIER");

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                        "%s",gaucAtCrLf);

        At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

        return VOS_OK;
    }

    /* IP????????????^CGANS??????????????ID_EVT_TAF_PS_CALL_PDP_DISCONNECT_IND */
    if (AT_CMD_PPP_ORG_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        ulResult = AT_NO_CARRIER;

        PPP_RcvAtCtrlOperEvent(gastAtClientTab[ucIndex].usPppId, PPP_AT_CTRL_REL_PPP_REQ);

        /* ??PPP????HDLC?????????? */
        PPP_RcvAtCtrlOperEvent(gastAtClientTab[ucIndex].usPppId, PPP_AT_CTRL_HDLC_DISABLE);

        /* ???????????? */
        At_SetMode(ucIndex, AT_CMD_MODE, AT_NORMAL_MODE);




    }
    else if ((AT_CMD_CGANS_ANS_EXT_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
          || (AT_CMD_CGANS_ANS_SET == gastAtClientTab[ucIndex].CmdCurrentOpt))
    {
        /*
        1.PPP????????????^CGANS??????????????ID_EVT_TAF_PS_CALL_PDP_DISCONNECT_IND
        2.+CGANS????
        ??????????????????????????????????????ERROR
        */
        ulResult = AT_ERROR;
    }
    else
    {
        ulResult = AT_ERROR;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex, ulResult);

    return VOS_OK;
}



VOS_VOID AT_SetMemStatusRspProc(
    VOS_UINT8                           ucIndex,
    MN_MSG_EVENT_INFO_STRU             *pstEvent
)
{
    VOS_UINT32                          ulResult;

    /* ?????????????? */
    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_SetMemStatusRspProc: AT_BROADCAST_INDEX.");
        return;
    }

    /* ??????????????????????AT_CMD_CSASM_SET */
    if ( AT_CMD_CSASM_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return;
    }

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????????????? */
    if ( VOS_TRUE == pstEvent->u.stMemStatusInfo.bSuccess)
    {
        ulResult    = AT_OK;
    }
    else
    {
        ulResult    = AT_ERROR;
    }

    gstAtSendData.usBufLen = 0;
    /* ????AT_FormATResultDATa???????????? */
    At_FormatResultData(ucIndex, ulResult);

    return;
}


VOS_UINT32 AT_RcvTafPsEvtGetDynamicDnsInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult    = AT_ERROR;
    VOS_UINT16                          usLength    = 0;
    TAF_PS_GET_NEGOTIATION_DNS_CNF_STRU *pstNegoDnsCnf;
    VOS_INT8                            acDnsAddr[TAF_MAX_IPV4_ADDR_STR_LEN];

    TAF_MEM_SET_S(acDnsAddr, sizeof(acDnsAddr), 0x00, TAF_MAX_IPV4_ADDR_STR_LEN);

    pstNegoDnsCnf = (TAF_PS_GET_NEGOTIATION_DNS_CNF_STRU *)pEvtInfo;

    /* ?????????????? */
    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvTafPsEvtGetDynamicDnsInfoCnf: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    if ( AT_CMD_DNSQUERY_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    if (TAF_PARA_OK != pstNegoDnsCnf->enCause)
    {
        ulResult = AT_ERROR;
    }
    else
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%s: ",
                                           g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

        /* <PriDns> */
        if(VOS_TRUE == pstNegoDnsCnf->stNegotiationDns.stDnsInfo.bitOpPrimDnsAddr)
        {
            AT_Ipv4Addr2Str(acDnsAddr, pstNegoDnsCnf->stNegotiationDns.stDnsInfo.aucPrimDnsAddr);
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                               "\"%s\"",
                                               acDnsAddr);
        }
        /* <SecDns> */
        if(VOS_TRUE == pstNegoDnsCnf->stNegotiationDns.stDnsInfo.bitOpSecDnsAddr)
        {
            AT_Ipv4Addr2Str(acDnsAddr, pstNegoDnsCnf->stNegotiationDns.stDnsInfo.aucSecDnsAddr);
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                               ",\"%s\"",
                                               acDnsAddr);
        }
        else
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                               ",");
        }
        ulResult = AT_OK;
    }

    gstAtSendData.usBufLen  = usLength;
    /* ????AT_FormATResultDATa???????????? */
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}



VOS_UINT32 At_RcvTafPsEvtSetDialModeCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult;
    TAF_PS_CDATA_DIAL_MODE_CNF_STRU    *pstDialMode;

    /* ?????? */
    ulResult     = AT_OK;
    pstDialMode  = (TAF_PS_CDATA_DIAL_MODE_CNF_STRU *)pEvtInfo;

    /* ????AT???????????????????? */
    if (AT_CMD_CRM_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("At_RcvTafPsEvtSetDialModeCnf : Current Option is not AT_CMD_CRM_SET.");
        return VOS_OK;
    }

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ?????????????? */
    gstAtSendData.usBufLen = 0;

    if (TAF_PS_CAUSE_SUCCESS != pstDialMode->enCause)
    {
        ulResult = AT_ERROR;
    }

    /* ???????? */
    At_FormatResultData(ucIndex, ulResult);

    return VOS_OK;
}




VOS_UINT32 atReadLtecsCnfProc(VOS_UINT8   ucIndex,VOS_VOID    *pEvtInfo)
{
    TAF_PS_LTECS_CNF_STRU *pLtecsReadCnf = NULL;
    VOS_UINT16 usLength = 0;
    VOS_UINT32 ulResult;

    pLtecsReadCnf = (TAF_PS_LTECS_CNF_STRU *)pEvtInfo;

    if(pLtecsReadCnf->enCause == VOS_OK)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR *)pgucAtSndCodeAddr,(VOS_CHAR *)pgucAtSndCodeAddr + usLength,
        "^LTECS:");
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR *)pgucAtSndCodeAddr,(VOS_CHAR *)pgucAtSndCodeAddr + usLength,
        "%d,%d",pLtecsReadCnf->stLteCs.ucSG,pLtecsReadCnf->stLteCs.ucIMS);
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR *)pgucAtSndCodeAddr,(VOS_CHAR *)pgucAtSndCodeAddr + usLength,
         ",%d,%d",pLtecsReadCnf->stLteCs.ucCSFB,pLtecsReadCnf->stLteCs.ucVCC);
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR *)pgucAtSndCodeAddr,(VOS_CHAR *)pgucAtSndCodeAddr + usLength,
        ",%d",pLtecsReadCnf->stLteCs.ucVoLGA);

         ulResult                = AT_OK;
        gstAtSendData.usBufLen  = usLength;
    }
    else
    {
         ulResult                = AT_ERROR;
        gstAtSendData.usBufLen  = 0;
    }


    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);
    return VOS_OK;
}

VOS_UINT32 atReadCemodeCnfProc(VOS_UINT8   ucIndex,VOS_VOID    *pEvtInfo)
{
    TAF_PS_CEMODE_CNF_STRU *pCemodeReadCnf = NULL;
    VOS_UINT16 usLength = 0;
    VOS_UINT32 ulResult;




    pCemodeReadCnf = (TAF_PS_CEMODE_CNF_STRU *)pEvtInfo;

    if(pCemodeReadCnf->enCause == VOS_OK)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR *)pgucAtSndCodeAddr,(VOS_CHAR *)pgucAtSndCodeAddr + usLength,
        "+CEMODE:");
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,(VOS_CHAR *)pgucAtSndCodeAddr,(VOS_CHAR *)pgucAtSndCodeAddr + usLength,
        "%d",pCemodeReadCnf->stCemode.enCurrentUeMode);

         ulResult                = AT_OK;
        gstAtSendData.usBufLen  = usLength;
    }
    else
    {
         ulResult                = AT_ERROR;
        gstAtSendData.usBufLen  = 0;
    }


    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);
    return VOS_OK;
}




/*****************************************************************************
 ?? ?? ??  : AT_RcvTafGetLteAttachInfoCnf
 ????????  : ID_MSG_TAF_PS_GET_LTE_ATTACH_INFO_CNF????????????
 ????????  : VOS_UINT8                  ucIndex,
             VOS_VOID                  *pEvtInfo       - ????????, MN_PS_EVT_STRU????EvtId
 ????????  : ??
 ?? ?? ??  : VOS_UINT32

*****************************************************************************/
VOS_UINT32 AT_RcvTafGetLteAttachInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_GET_LTE_ATTACH_INFO_CNF_STRU          *pstGetLteAttachInfoCnf      = VOS_NULL_PTR;
    VOS_UINT16                                    usLength                    = 0;
    VOS_UINT32                                    ulResult                    = AT_ERROR;
    VOS_UINT8                                     aucStr[TAF_MAX_APN_LEN + 1] = {0};

    pstGetLteAttachInfoCnf            = (TAF_PS_GET_LTE_ATTACH_INFO_CNF_STRU *)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_LTEATTACHINFO_QRY != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        AT_WARN_LOG("AT_RcvTafGetLteAttachInfoCnf : Current Option is not AT_CMD_LTEATTACHINFO_QRY.");
        return VOS_ERR;
    }

    /*??????????????????????*/
    if (TAF_PS_CAUSE_SUCCESS == pstGetLteAttachInfoCnf->enCause)
    {
        /* ^LTEATTACHINFO:  */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                    (VOS_CHAR*)pgucAtSndCodeAddr,
                                    (VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%s: ",
                                    g_stParseContext[ucIndex].pstCmdElement->pszCmdName);

        /* <PDP_type> */
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                    (VOS_CHAR*)pgucAtSndCodeAddr,
                                    (VOS_CHAR*)pgucAtSndCodeAddr + usLength,"%d",
                                    pstGetLteAttachInfoCnf->stLteAttQueryInfo.enPdpType);

        /* <APN> */
        pstGetLteAttachInfoCnf->stLteAttQueryInfo.stApn.ucLength = TAF_MIN(pstGetLteAttachInfoCnf->stLteAttQueryInfo.stApn.ucLength,
                                                                            sizeof(pstGetLteAttachInfoCnf->stLteAttQueryInfo.stApn.aucValue));

        TAF_MEM_CPY_S(aucStr, sizeof(aucStr),
            pstGetLteAttachInfoCnf->stLteAttQueryInfo.stApn.aucValue,
            pstGetLteAttachInfoCnf->stLteAttQueryInfo.stApn.ucLength);

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                    (VOS_CHAR*)pgucAtSndCodeAddr,
                                    (VOS_CHAR*)pgucAtSndCodeAddr + usLength,",\"%s\"", aucStr);

        ulResult                    = AT_OK;
    }

    gstAtSendData.usBufLen          = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex,ulResult);

    return VOS_OK;
}



VOS_VOID AT_ConvertNasMncToBcdType(
    VOS_UINT32                          ulNasMnc,
    VOS_UINT32                         *pulMnc
)
{
    VOS_UINT32                          i;
    VOS_UINT8                           aucTmp[4];

    *pulMnc = 0;

    for (i = 0 ; i < 3 ; i++ )
    {
        aucTmp[i] = ulNasMnc & 0x0f;
        ulNasMnc         >>=  8;
    }

    if(0xf == aucTmp[2])
    {
        *pulMnc = ((VOS_UINT32)aucTmp[0] << 4)
                        |((VOS_UINT32)aucTmp[1] )
                        |0xf00;
    }
    else
    {
        *pulMnc = ((VOS_UINT32)aucTmp[0] << 8)
                    |((VOS_UINT32)aucTmp[1] << 4)
                    | aucTmp[2];
    }

}




VOS_VOID AT_ConvertNasMccToBcdType(
    VOS_UINT32                          ulNasMcc,
    VOS_UINT32                         *pulMcc
)
{
    VOS_UINT32                          i;
    VOS_UINT8                           aucTmp[4];

    *pulMcc = 0;

    for (i = 0; i < 3 ; i++ )
    {
        aucTmp[i]   = ulNasMcc & 0x0f;
        ulNasMcc  >>=  8;
    }

    *pulMcc = ((VOS_UINT32)aucTmp[0] << 8)
             |((VOS_UINT32)aucTmp[1] << 4)
             | aucTmp[2];

}


VOS_VOID At_RcvMnCallEccNumIndProc(
    MN_AT_IND_EVT_STRU                 *pstData,
    VOS_UINT16                          usLen
)
{
    MN_CALL_ECC_NUM_INFO_STRU          *pstEccNumInfo = VOS_NULL_PTR;
    VOS_UINT8                           aucAsciiNum[(MN_CALL_MAX_BCD_NUM_LEN*2)+1];
    VOS_UINT8                           ucIndex;
    VOS_UINT32                          i;
    VOS_UINT16                          usLength;
    VOS_UINT32                          ulMcc;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;

    enModemId = MODEM_ID_0;

    TAF_MEM_SET_S(aucAsciiNum, sizeof(aucAsciiNum), 0x00, sizeof(aucAsciiNum));


    /* ???????????????????????? */
    pstEccNumInfo = (MN_CALL_ECC_NUM_INFO_STRU *)pstData->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEccNumInfo->usClientId, &ucIndex))
    {
        AT_WARN_LOG("At_RcvMnCallEccNumIndProc:WARNING:AT INDEX NOT FOUND!");
        return;
    }

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("At_RcvMnCallEccNumIndProc: Get modem id fail.");
        return;
    }


    /* ??APP?????????????????? */
    for (i = 0; i < pstEccNumInfo->ulEccNumCount; i++)
    {
        /* ??BCD????????ASCII?? */
        AT_BcdNumberToAscii(pstEccNumInfo->astCustomEccNumList[i].aucEccNum,
                            pstEccNumInfo->astCustomEccNumList[i].ucEccNumLen,
                            (VOS_CHAR*)aucAsciiNum);

        /* ??NAS??????MCC??????BCD???? */
        AT_ConvertNasMccToBcdType(pstEccNumInfo->astCustomEccNumList[i].ulMcc, &ulMcc);

        usLength = 0;
        usLength = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr +
                                           usLength,
                                           "%s^XLEMA:",
                                           gaucAtCrLf);

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr +
                                           usLength,
                                           "%d,%d,%s,%d,%d,",
                                           (i+1),
                                           pstEccNumInfo->ulEccNumCount,
                                           aucAsciiNum,
                                           pstEccNumInfo->astCustomEccNumList[i].ucCategory,
                                           pstEccNumInfo->astCustomEccNumList[i].ucValidSimPresent);

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr +
                                           usLength,
                                           "%x%x%x",
                                           (ulMcc & 0x0f00)>>8,
                                           (ulMcc & 0xf0)>>4,
                                           (ulMcc & 0x0f));

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr +
                                           usLength,
                                           ",%d%s",
                                           pstEccNumInfo->astCustomEccNumList[i].ucAbnormalServiceFlg,
                                           gaucAtCrLf);

        At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

        TAF_MEM_SET_S(aucAsciiNum, sizeof(aucAsciiNum), 0x00, sizeof(aucAsciiNum));

    }

    return;
}




VOS_VOID AT_RcvMmaNsmStatusInd(
    TAF_UINT8                           ucIndex,
    TAF_PHONE_EVENT_INFO_STRU          *pEvent
)
{
    VOS_UINT16                          usLength;

    usLength = 0;
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                     (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                     "%s+PACSP",gaucAtCrLf);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                      (VOS_CHAR *)pgucAtSndCodeAddr,
                                      (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                      "%d",pEvent->ucPlmnMode);

    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                     (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                     "%s",gaucAtCrLf);

    At_SendResultData(ucIndex, pgucAtSndCodeAddr,usLength);

    return;
}


VOS_VOID AT_RcvMmaRssiChangeInd(
    TAF_UINT8                           ucIndex,
    TAF_MMA_RSSI_INFO_IND_STRU         *pstRssiInfoInd
)
{
    VOS_UINT16                          usLength;
    VOS_UINT32                          ulRptCmdRssi;
    VOS_UINT32                          ulRptCmdCerssi;
    VOS_UINT32                          ulRptCmdAnlevel;
    VOS_INT16                           sRsrp;
    VOS_INT16                           sRsrq;
    VOS_UINT8                           ucLevel;
    VOS_INT16                           sRssi;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;
    VOS_UINT8                          *pucSystemAppConfig;

    usLength       = 0;

    enModemId = MODEM_ID_0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("AT_RcvMmaRssiChangeInd: Get modem id fail.");
        return;
    }

    ulRptCmdRssi   = AT_CheckRptCmdStatus(pstRssiInfoInd->aucCurcRptCfg, AT_CMD_RPT_CTRL_BY_CURC, AT_RPT_CMD_RSSI);
    ulRptCmdCerssi = AT_CheckRptCmdStatus(pstRssiInfoInd->aucCurcRptCfg, AT_CMD_RPT_CTRL_BY_CURC, AT_RPT_CMD_CERSSI);
    ulRptCmdAnlevel = AT_CheckRptCmdStatus(pstRssiInfoInd->aucCurcRptCfg, AT_CMD_RPT_CTRL_BY_CURC, AT_RPT_CMD_ANLEVEL);

    if ((VOS_TRUE == AT_CheckRptCmdStatus(pstRssiInfoInd->aucUnsolicitedRptCfg, AT_CMD_RPT_CTRL_BY_UNSOLICITED, AT_RPT_CMD_RSSI))
     && (VOS_TRUE == ulRptCmdRssi))
    {

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%s%s%d%s",
                                           gaucAtCrLf,
                                           gastAtStringTab[AT_STRING_RSSI].pucText,
                                           pstRssiInfoInd->stRssiInfo.aRssi[0].ucRssiValue,
                                           gaucAtCrLf);

        At_SendResultData(ucIndex, pgucAtSndCodeAddr,usLength);
    }

    usLength = 0;

    if ((VOS_TRUE == AT_CheckRptCmdStatus(pstRssiInfoInd->aucUnsolicitedRptCfg, AT_CMD_RPT_CTRL_BY_UNSOLICITED, AT_RPT_CMD_CERSSI))
     && (VOS_TRUE == ulRptCmdCerssi))
    {
        if (TAF_MMA_RAT_GSM == pstRssiInfoInd->stRssiInfo.enRatType)
        {
            usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                               (VOS_CHAR *)pgucAtSndCodeAddr,
                                               (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                               "%s%s%d,%d,%d,%d,%d,%d,%d%s",
                                               gaucAtCrLf,
                                               gastAtStringTab[AT_STRING_CERSSI].pucText,
                                               pstRssiInfoInd->stRssiInfo.aRssi[0].u.stGCellSignInfo.sRssiValue,
                                               0,
                                               255,
                                               0,
                                               0,
                                               0,
                                               0,
                                               gaucAtCrLf);

            At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
            return;
        }

        if (TAF_MMA_RAT_WCDMA == pstRssiInfoInd->stRssiInfo.enRatType)
        {
            if ( TAF_UTRANCTRL_UTRAN_MODE_FDD == pstRssiInfoInd->stRssiInfo.ucCurrentUtranMode)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                   "%s%s%d,%d,%d,%d,%d,%d,%d%s",
                                                   gaucAtCrLf,
                                                   gastAtStringTab[AT_STRING_CERSSI].pucText,
                                                   0,      /* rssi */
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stWCellSignInfo.sRscpValue,
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stWCellSignInfo.sEcioValue,
                                                   0,
                                                   0,
                                                   0,
                                                   0,
                                                   gaucAtCrLf);
            }
            else
            {
                /* ??fdd 3g ??????ecio??????????255 */
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                   "%s%s%d,%d,%d,%d,%d,%d,%d%s",
                                                   gaucAtCrLf,
                                                   gastAtStringTab[AT_STRING_CERSSI].pucText,
                                                   0,      /* rssi */
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stWCellSignInfo.sRscpValue,
                                                   255,
                                                   0,
                                                   0,
                                                   0,
                                                   0,
                                                   gaucAtCrLf);

            }
            At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

            return;
        }
        /* ????LTE ??CERSSI */
        if (TAF_MMA_RAT_LTE == pstRssiInfoInd->stRssiInfo.enRatType)
        {
            pucSystemAppConfig = AT_GetSystemAppConfigAddr();
            if (SYSTEM_APP_ANDROID != *pucSystemAppConfig)
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                   "%s%s0,0,255,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s",
                                                   gaucAtCrLf,
                                                   gastAtStringTab[AT_STRING_CERSSI].pucText,
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.sRsrp,
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.sRsrq,
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.lSINR,
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stCQI.usRI,
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stCQI.ausCQI[0],
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stCQI.ausCQI[1],
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stRxAntInfo.ucRxANTNum,
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stRxAntInfo.asRsrpRx[0],
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stRxAntInfo.asRsrpRx[1],
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stRxAntInfo.asRsrpRx[2],
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stRxAntInfo.asRsrpRx[3],
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stRxAntInfo.alSINRRx[0],
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stRxAntInfo.alSINRRx[1],
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stRxAntInfo.alSINRRx[2],
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stRxAntInfo.alSINRRx[3],
                                                   gaucAtCrLf);
            }
            else
            {
                usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr,
                                                   (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                                   "%s%s0,0,255,%d,%d,%d,%d,%d,%d,%s",
                                                   gaucAtCrLf,
                                                   gastAtStringTab[AT_STRING_CERSSI].pucText,
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.sRsrp,
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.sRsrq,
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.lSINR,
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stCQI.usRI,
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stCQI.ausCQI[0],
                                                   pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.stCQI.ausCQI[1],
                                                   gaucAtCrLf);
            }

            At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);
        }
    }

    /*????ANLEVEL */

    usLength = 0;
    if (VOS_TRUE == ulRptCmdAnlevel)
    {


        sRsrp = pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.sRsrp;
        sRsrq = pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.sRsrq;
        sRssi = pstRssiInfoInd->stRssiInfo.aRssi[0].u.stLCellSignInfo.sRssi;

        AT_CalculateLTESignalValue(&sRssi,&ucLevel,&sRsrp,&sRsrq);

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%s%s0,99,%d,%d,%d,%d%s",
                                           gaucAtCrLf,
                                           "^ANLEVEL:",
                                           sRssi,
                                           ucLevel,
                                           sRsrp,
                                           sRsrq,
                                           gaucAtCrLf);

        At_SendResultData(ucIndex, pgucAtSndCodeAddr,usLength);
    }

    return;
}



VOS_VOID At_StkNumPrint(
    VOS_UINT16                         *pusLength,
    VOS_UINT8                          *pucData,
    VOS_UINT16                          usDataLen,
    VOS_UINT8                           ucNumType
)
{
    VOS_UINT16                          usLength = *pusLength;
    /* ???????? */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                   (VOS_CHAR *)pgucAtSndCodeAddr,
                                   (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                   ",\"");

    TAF_MEM_CPY_S(pgucAtSndCodeAddr + usLength,  usDataLen, pucData, usDataLen);

    usLength += usDataLen;

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                   (VOS_CHAR *)pgucAtSndCodeAddr,
                                   (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                   "\"");

    /* ???????? */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           ",%d",
                                           ucNumType);

    *pusLength = usLength;

    return;
}


VOS_VOID AT_BcdHalfByteToAscii(
    VOS_UINT8                           ucBcdHalfByte,
    VOS_UINT8                          *pucAsciiNum
)
{
    if(ucBcdHalfByte <= 9)  /*????????*/
    {
        *pucAsciiNum = ucBcdHalfByte + 0x30;
    }
    else if(0x0A == ucBcdHalfByte)   /*????*????*/
    {
        *pucAsciiNum = 0x2a;
    }
    else if(0x0B == ucBcdHalfByte)   /*????#????*/
    {
        *pucAsciiNum = 0x23;
    }
    else if(0x0C == ucBcdHalfByte)   /*????'P'????*/
    {
        *pucAsciiNum = 0x50;
    }
    else if(0x0D == ucBcdHalfByte)   /*????'?'????*/
    {
        *pucAsciiNum = 0x3F;
    }
    else                                    /*????????*/
    {
        *pucAsciiNum = ucBcdHalfByte + 0x57;
    }

    return;
}


VOS_VOID AT_BcdToAscii(
    VOS_UINT8                           ucBcdNumLen,
    VOS_UINT8                          *pucBcdNum,
    VOS_UINT8                          *pucAsciiNum,
    VOS_UINT8                           ucAsciiNumBufflen,
    VOS_UINT8                          *pucLen
)
{
    VOS_UINT8       ucTmp;
    VOS_UINT8       ucLen = 0;
    VOS_UINT8       ucFirstNumber;
    VOS_UINT8       ucSecondNumber;

    for (ucTmp = 0; ucTmp < ucBcdNumLen; ucTmp++)
    {
        if(0xFF == pucBcdNum[ucTmp])
        {
            break;
        }

        ucFirstNumber  = (VOS_UINT8)(pucBcdNum[ucTmp] & 0x0F); /*????????????*/

        ucSecondNumber = (VOS_UINT8)((pucBcdNum[ucTmp] >> 4) & 0x0F);/*????????????*/

        /* ?????????????????????????????? */
        if (ucAsciiNumBufflen <= ucLen)
        {
            ucLen = 0;
            break;
        }

        AT_BcdHalfByteToAscii(ucFirstNumber, pucAsciiNum);

        pucAsciiNum++;

        ucLen++;

        if(0x0F == ucSecondNumber)
        {
            break;
        }

        /* ?????????????????????????????? */
        if (ucAsciiNumBufflen <= ucLen)
        {
            ucLen = 0;
            break;
        }

        AT_BcdHalfByteToAscii(ucSecondNumber, pucAsciiNum);

        pucAsciiNum++;

        ucLen++;
    }

    *pucLen = ucLen;

    return;
}



VOS_VOID  At_StkCcinIndPrint(
    VOS_UINT8                           ucIndex,
    SI_STK_EVENT_INFO_STRU             *pstEvent
)
{
    VOS_UINT16                          usLength = 0;
    VOS_UINT8                           aucAscii[250] = {0};
    VOS_UINT8                           ucAsciiLen = 0;
    /* ????????AT???????? */
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s",
                                       gaucAtCcin);

    /* ????call/sms control ???? */
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%d",
                                       (pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.ucType));

    /* ????Call/SMS Control?????? */
    usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       ",%d",
                                       (pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.ucResult));

    /* ????ALPHAID???? */
    if (0 != pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.stAlphaIdInfo.ulAlphaLen)
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       ",\"%s",
                                       (pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.stAlphaIdInfo.aucAlphaId));

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "\"");
     }
     else
     {
         usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                            (TAF_CHAR *)pgucAtSndCodeAddr,
                                            (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                            ",\"\"");

     }

    if (SI_STK_SMS_CTRL == pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.ucType)
    {
        /* ????????????BCD????????acsii */
        AT_BcdToAscii(pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.uInfo.stMoSmsCtrlInfo.stDstAddrInfo.ucAddrLen,
                      pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.uInfo.stMoSmsCtrlInfo.stDstAddrInfo.aucAddr,
                      aucAscii,
                      sizeof(aucAscii),
                      &ucAsciiLen);

        /* ?????????????????? */
        At_StkNumPrint(&usLength,
                       aucAscii,
                       ucAsciiLen,
                       pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.uInfo.stMoSmsCtrlInfo.stDstAddrInfo.ucNumType);

        /* ????????????????BCD????????acsii */
        AT_BcdToAscii(pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.uInfo.stMoSmsCtrlInfo.stSerCenterAddrInfo.ucAddrLen,
                      pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.uInfo.stMoSmsCtrlInfo.stSerCenterAddrInfo.aucAddr,
                      aucAscii,
                      sizeof(aucAscii),
                      &ucAsciiLen);

        /* ?????????????????????? */
        At_StkNumPrint(&usLength,
                       aucAscii,
                       ucAsciiLen,
                       pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.uInfo.stMoSmsCtrlInfo.stSerCenterAddrInfo.ucNumType);

    }
    else if (SI_STK_USSD_CALL_CTRL == pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.ucType)
    {

        /* ????dcs??????data???? */
        At_StkNumPrint(&usLength,
                     pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.uInfo.stCtrlDataInfo.aucData,
                     pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.uInfo.stCtrlDataInfo.usDataLen,
                     pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.uInfo.stCtrlDataInfo.ucDataType);
    }
    else
    {

        /* ????????????BCD????????acsii */
        AT_BcdToAscii((VOS_UINT8)pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.uInfo.stCtrlDataInfo.usDataLen,
                      pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.uInfo.stCtrlDataInfo.aucData,
                      aucAscii,
                      sizeof(aucAscii),
                      &ucAsciiLen);

        /* ?????????????????? */
        At_StkNumPrint(&usLength,
                       aucAscii,
                       ucAsciiLen,
                       pstEvent->STKCmdStru.CmdStru.STKCcIndInfo.uInfo.stCtrlDataInfo.ucDataType);
    }

    /* ???????????? */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                        "%s",
                                        gaucAtCrLf);

    At_SendResultData(ucIndex, pgucAtSndCrLfAddr, usLength + 2);

    return;
}


VOS_VOID AT_ReportCCallstateResult(
    VOS_UINT16                          usClientId,
    VOS_UINT8                           ucCallId,
    VOS_UINT8                          *pucRptCfg,
    AT_CS_CALL_STATE_ENUM_UINT8         enCallState,
    TAF_CALL_VOICE_DOMAIN_ENUM_UINT8    enVoiceDomain
)
{
    VOS_UINT16                          usLength = 0;
    VOS_UINT8                           ucIndex;

    /* ????client id??????Modem Id */
    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_ReportCCallstateResult:WARNING:AT INDEX NOT FOUND!");
        return;
    }

    if (VOS_TRUE == AT_CheckRptCmdStatus(pucRptCfg, AT_CMD_RPT_CTRL_BY_CURC, AT_RPT_CMD_CALLSTATE))
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%s%s: %d,%d,%d%s",
                                           gaucAtCrLf,
                                           gastAtStringTab[AT_STRING_CCALLSTATE].pucText,
                                           ucCallId,
                                           enCallState,
                                           enVoiceDomain,
                                           gaucAtCrLf);

    }

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return;
}


VOS_VOID AT_ReportCCallstateHoldList(
    MN_CALL_EVT_HOLD_STRU              *pstHoldEvt,
    AT_CS_CALL_STATE_ENUM_UINT8         enCallState
)
{
    VOS_UINT8                           ucLoop;

    for (ucLoop = 0; ucLoop < (pstHoldEvt->ucCallNum); ucLoop++)
    {
        AT_ReportCCallstateResult(pstHoldEvt->usClientId,
                                  pstHoldEvt->aucCallId[ucLoop],
                                  pstHoldEvt->aucCurcRptCfg,
                                  enCallState,
                                  pstHoldEvt->enVoiceDomain);
    }

    return;
}


VOS_VOID AT_ReportCCallstateRetrieveList(
    MN_CALL_EVT_RETRIEVE_STRU          *pstRetrieveEvt,
    AT_CS_CALL_STATE_ENUM_UINT8         enCallState
)
{
    VOS_UINT8                           ucLoop;

    for (ucLoop = 0; ucLoop < (pstRetrieveEvt->ucCallNum); ucLoop++)
    {
        AT_ReportCCallstateResult(pstRetrieveEvt->usClientId,
                                  pstRetrieveEvt->aucCallId[ucLoop],
                                  pstRetrieveEvt->aucCurcRptCfg,
                                  enCallState,
                                  pstRetrieveEvt->enVoiceDomain);
    }

    return;
}


VOS_VOID AT_CSCallStateReportProc(
    MN_AT_IND_EVT_STRU                 *pstData
)
{
    MN_CALL_EVENT_ENUM_U32              enEvent;
    TAF_UINT32                          ulEventLen;
    MN_CALL_INFO_STRU                  *pstCallInfo     = VOS_NULL_PTR;
    MN_CALL_EVT_HOLD_STRU              *pstHoldEvt      = VOS_NULL_PTR;
    MN_CALL_EVT_RETRIEVE_STRU          *pstRetrieveEvt  = VOS_NULL_PTR;

    enEvent = MN_CALL_EVT_BUTT;

    ulEventLen      = sizeof(MN_CALL_EVENT_ENUM_U32);
    TAF_MEM_CPY_S(&enEvent,  sizeof(enEvent), pstData->aucContent, ulEventLen);
    pstCallInfo     = (MN_CALL_INFO_STRU *)&pstData->aucContent[ulEventLen];

    switch(enEvent)
    {
        case MN_CALL_EVT_ORIG:
            AT_ReportCCallstateResult(pstData->clientId, pstCallInfo->callId, pstCallInfo->aucCurcRptCfg, AT_CS_CALL_STATE_ORIG, pstCallInfo->enVoiceDomain);
            return;
        case MN_CALL_EVT_CALL_PROC:
            AT_ReportCCallstateResult(pstData->clientId, pstCallInfo->callId, pstCallInfo->aucCurcRptCfg, AT_CS_CALL_STATE_CALL_PROC, pstCallInfo->enVoiceDomain);
            return;
        case MN_CALL_EVT_ALERTING:
            AT_ReportCCallstateResult(pstData->clientId, pstCallInfo->callId, pstCallInfo->aucCurcRptCfg, AT_CS_CALL_STATE_ALERTING, pstCallInfo->enVoiceDomain);
            return;
        case MN_CALL_EVT_CONNECT:
            AT_ReportCCallstateResult(pstData->clientId, pstCallInfo->callId, pstCallInfo->aucCurcRptCfg, AT_CS_CALL_STATE_CONNECT, pstCallInfo->enVoiceDomain);
            return;
        case MN_CALL_EVT_RELEASED:
            AT_ReportCCallstateResult(pstData->clientId, pstCallInfo->callId, pstCallInfo->aucCurcRptCfg, AT_CS_CALL_STATE_RELEASED, pstCallInfo->enVoiceDomain);
            return;
        case MN_CALL_EVT_INCOMING:
            if ( MN_CALL_S_INCOMING == pstCallInfo->enCallState )
            {
                AT_ReportCCallstateResult(pstData->clientId, pstCallInfo->callId, pstCallInfo->aucCurcRptCfg, AT_CS_CALL_STATE_INCOMMING, pstCallInfo->enVoiceDomain);
            }
            else if ( MN_CALL_S_WAITING == pstCallInfo->enCallState )
            {
                AT_ReportCCallstateResult(pstData->clientId, pstCallInfo->callId, pstCallInfo->aucCurcRptCfg, AT_CS_CALL_STATE_WAITING, pstCallInfo->enVoiceDomain);
            }
            else
            {
                ;
            }
            return;
        case MN_CALL_EVT_HOLD:
            pstHoldEvt      = (MN_CALL_EVT_HOLD_STRU *)(pstData->aucContent);
            AT_ReportCCallstateHoldList(pstHoldEvt,
                                    AT_CS_CALL_STATE_HOLD);
            return;
        case MN_CALL_EVT_RETRIEVE:
            pstRetrieveEvt  = (MN_CALL_EVT_RETRIEVE_STRU *)(pstData->aucContent);
            AT_ReportCCallstateRetrieveList(pstRetrieveEvt,
                                    AT_CS_CALL_STATE_RETRIEVE);
            return;
        default:
            break;
    }

    return;
}


VOS_VOID AT_ReportCendResult(
    VOS_UINT8                           ucIndex,
    MN_CALL_INFO_STRU                  *pstCallInfo
)
{
    VOS_UINT16                          usLength;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT32                          ulRslt;

    enModemId = MODEM_ID_0;

    usLength  = 0;

    ulRslt = AT_GetModemIdFromClient(ucIndex, &enModemId);

    if (VOS_OK != ulRslt)
    {
        AT_ERR_LOG("AT_ReportCendResult: Get modem id fail.");
        return;
    }

    if (VOS_TRUE == AT_CheckRptCmdStatus(pstCallInfo->aucCurcRptCfg, AT_CMD_RPT_CTRL_BY_CURC, AT_RPT_CMD_CEND))
    {
        usLength    += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                              (VOS_CHAR *)pgucAtSndCodeAddr,
                                              (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                              "%s^CEND:%d,%d,%d,%d%s",
                                              gaucAtCrLf,
                                              pstCallInfo->callId,
                                              pstCallInfo->ulPreCallTime,
                                              pstCallInfo->enNoCliCause,
                                              pstCallInfo->enCause,
                                              gaucAtCrLf);
        At_SendResultData(ucIndex,pgucAtSndCodeAddr,usLength);
    }

    return;
}


VOS_UINT16 At_PrintClprInfo(
        VOS_UINT8                           ucIndex,
        MN_CALL_CLPR_GET_CNF_STRU          *pstClprGetCnf)
{
    VOS_UINT16                          usLength;
    VOS_UINT8                           ucType;
    VOS_CHAR                            aucAsciiNum[(MN_CALL_MAX_BCD_NUM_LEN*2) + 1];
    VOS_UINT32                          ulAsiciiLen;

    /* ?????? */
    usLength = 0;
    TAF_MEM_SET_S(aucAsciiNum, sizeof(aucAsciiNum), 0x00, sizeof(aucAsciiNum));

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                             (VOS_CHAR *)pgucAtSndCodeAddr,
                             (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                             "%s: ",
                             g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
    /* ????<RedirectNumPI>???? */
    if (VOS_TRUE == pstClprGetCnf->stClprInfo.bitOpCallingNumPI)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                 (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                 "%d,",
                                 pstClprGetCnf->stClprInfo.enCallingNumPI);

    }
    else
    {
         usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                 (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                 ",");
    }

    /* ????<no_CLI_cause>???? */
    if (VOS_TRUE == pstClprGetCnf->stClprInfo.bitOpNoCLICause)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                 (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                 "%d,",
                                 pstClprGetCnf->stClprInfo.enNoCLICause);

    }
    else
    {
         usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                 (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                 ",");
    }

    /* ????<redirect_num>??<num_type>???? */
    if (VOS_TRUE == pstClprGetCnf->stClprInfo.stRedirectInfo.bitOpRedirectNum)
    {
        AT_BcdNumberToAscii(pstClprGetCnf->stClprInfo.stRedirectInfo.stRedirectNum.aucBcdNum,
                            pstClprGetCnf->stClprInfo.stRedirectInfo.stRedirectNum.ucNumLen,
                            aucAsciiNum);

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                 (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                 "\"%s\",%d,",
                                 aucAsciiNum,
                                 (pstClprGetCnf->stClprInfo.stRedirectInfo.stRedirectNum.enNumType| AT_NUMBER_TYPE_EXT));

    }
    else
    {
         usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                 (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                 "\"\",,");
    }

    /* ????<redirect_subaddr>??<num_type>???? */
    ucType = (MN_CALL_IS_EXIT | (MN_CALL_SUBADDR_NSAP << 4));
    if ((VOS_TRUE == pstClprGetCnf->stClprInfo.stRedirectInfo.bitOpRedirectSubaddr)
     && (ucType == pstClprGetCnf->stClprInfo.stRedirectInfo.stRedirectSubaddr.Octet3))
    {
        if (pstClprGetCnf->stClprInfo.stRedirectInfo.stRedirectSubaddr.LastOctOffset < sizeof(pstClprGetCnf->stClprInfo.stRedirectInfo.stRedirectSubaddr.Octet3))
        {
            AT_WARN_LOG1("At_PrintClprInfo: pstClprGetCnf->stRedirectInfo.stRedirectSubaddr.LastOctOffset: ",
                pstClprGetCnf->stClprInfo.stRedirectInfo.stRedirectSubaddr.LastOctOffset);
            pstClprGetCnf->stClprInfo.stRedirectInfo.stRedirectSubaddr.LastOctOffset = sizeof(pstClprGetCnf->stClprInfo.stRedirectInfo.stRedirectSubaddr.Octet3);
        }

        ulAsiciiLen = pstClprGetCnf->stClprInfo.stRedirectInfo.stRedirectSubaddr.LastOctOffset
                    - sizeof(pstClprGetCnf->stClprInfo.stRedirectInfo.stRedirectSubaddr.Octet3);

        TAF_MEM_CPY_S(aucAsciiNum,
                   sizeof(aucAsciiNum),
                   pstClprGetCnf->stClprInfo.stRedirectInfo.stRedirectSubaddr.SubAddrInfo,
                   ulAsiciiLen);

        aucAsciiNum[ulAsiciiLen] = '\0';

        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                 (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                 "\"%s\",%d,",
                                 aucAsciiNum,
                                 pstClprGetCnf->stClprInfo.stRedirectInfo.stRedirectSubaddr.Octet3);
    }
    else
    {
         usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                 (VOS_CHAR *)pgucAtSndCodeAddr,
                                 (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                 "\"\",,");
    }

    /* ????<CallingNumPI>???? */
    if (VOS_TRUE == pstClprGetCnf->stClprInfo.stRedirectInfo.bitOpRedirectNumPI)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
            (VOS_CHAR *)pgucAtSndCodeAddr,
            (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
            "%d",
            pstClprGetCnf->stClprInfo.stRedirectInfo.enRedirectNumPI);

    }

    return usLength;
}

VOS_VOID At_SetClprCnf(MN_AT_IND_EVT_STRU *pstData)
{
    MN_CALL_CLPR_GET_CNF_STRU          *pstClprGetCnf;
    VOS_UINT16                          usLength;
    VOS_UINT8                           ucIndex;


    ucIndex = 0;

    /* ?????? */
    pstClprGetCnf = (MN_CALL_CLPR_GET_CNF_STRU *)pstData->aucContent;

    /* ????ClientId????ucIndex */
    if ( AT_FAILURE == At_ClientIdToUserId(pstClprGetCnf->stAppCtrl.usClientId, &ucIndex) )
    {
        AT_WARN_LOG("At_SetClprCnf: WARNING:AT INDEX NOT FOUND!");
        return;
    }

    /* ??????????????????????AT_ERROR */
    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_SetClprCnf: WARNING:AT_BROADCAST_INDEX!");
        return;
    }

    /* ??????????????????????AT_CMD_CLPR_GET */
    if (AT_CMD_CLPR_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        AT_WARN_LOG("At_SetClprCnf: WARNING:Not AT_CMD_CLPR_GET!");
        return;
    }

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????????????? */
    if (TAF_ERR_NO_ERROR != pstClprGetCnf->ulRet)
    {
        At_FormatResultData(ucIndex, AT_ERROR);
        return;
    }

    usLength = At_PrintClprInfo(ucIndex, pstClprGetCnf);

    /* ???????? */
    gstAtSendData.usBufLen  = usLength;
    At_FormatResultData(ucIndex, AT_OK);

    return;

}


VOS_VOID AT_PhNetScanReportSuccess(
    VOS_UINT8                           ucIndex,
    TAF_MMA_NET_SCAN_CNF_STRU          *pstNetScanCnf
)
{
    VOS_UINT16                          usLength;
    VOS_UINT32                          i;
    VOS_UINT32                          ulMcc;
    VOS_UINT32                          ulMnc;

    usLength       = 0;

    /* ???????????????????? */
    for ( i = 0; i < pstNetScanCnf->ucFreqNum; i++ )
    {
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s",
                                       gastAtStringTab[AT_STRING_NETSCAN].pucText);

        ulMcc = pstNetScanCnf->astNetScanInfo[i].ulMcc;
        ulMnc = pstNetScanCnf->astNetScanInfo[i].ulMnc;
        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%u,,,%x,%x%x%x,%x%x",
                                       pstNetScanCnf->astNetScanInfo[i].ulArfcn,
                                       pstNetScanCnf->astNetScanInfo[i].usLac,
                                      (ulMcc & 0x0f),
                                      (ulMcc & 0x0f00) >> 8,
                                      (ulMcc & 0x0f0000) >> 16,
                                      (ulMnc & 0x0f),
                                      (ulMnc & 0x0f00) >> 8);

        /* ????????????????F???????????? */
        if ( 0x0f != ((ulMnc & 0x0f0000) >> 16) )
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%x",
                                       (ulMnc & 0x0f0000) >> 16);
        }

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       ",%d,%d,%x,",
                                       pstNetScanCnf->astNetScanInfo[i].usBsic,
                                       pstNetScanCnf->astNetScanInfo[i].sRxlev,
                                       pstNetScanCnf->astNetScanInfo[i].ulCellId);

        /* ???????????????????????????? */
        if ( 0 == pstNetScanCnf->astNetScanInfo[i].stBand.ulBandHigh )
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%X",
                                       pstNetScanCnf->astNetScanInfo[i].stBand.ulBandLow);
        }
        else
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (TAF_CHAR *)pgucAtSndCodeAddr,
                                       (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%X%08X",
                                       pstNetScanCnf->astNetScanInfo[i].stBand.ulBandHigh,
                                       pstNetScanCnf->astNetScanInfo[i].stBand.ulBandLow);
        }

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr + usLength,
                                           ",%d,%u",
                                           pstNetScanCnf->astNetScanInfo[i].usPSC,
                                           pstNetScanCnf->astNetScanInfo[i].ulPhyId);

        if ( i != (pstNetScanCnf->ucFreqNum - 1) )
        {
            usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s",
                                       gaucAtCrLf);
        }
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ????FREQNUM ==0??????????OK */
    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex, AT_OK);

    return;
}


VOS_VOID AT_PhNetScanReportFailure(
    VOS_UINT8                           ucIndex,
    TAF_MMA_NET_SCAN_CAUSE_ENUM_UINT8   enNetScanCause
)
{
    VOS_UINT32                          ulResult;

    /* ????NetScan??????????????????AT???????????? */
    switch ( enNetScanCause )
    {
        case TAF_MMA_NET_SCAN_CAUSE_SIGNAL_EXIST :
            ulResult = AT_ERROR;
            break;

        case TAF_MMA_NET_SCAN_CAUSE_STATE_NOT_ALLOWED :
            ulResult = AT_CME_OPERATION_NOT_ALLOWED;
            break;

        case TAF_MMA_NET_SCAN_CAUSE_FREQ_LOCK :
            ulResult = AT_CME_OPERATION_NOT_ALLOWED;
            break;

        case TAF_MMA_NET_SCAN_CAUSE_PARA_ERROR :
            ulResult = AT_CME_INCORRECT_PARAMETERS;
            break;

        case TAF_MMA_NET_SCAN_CAUSE_CONFLICT :
            ulResult = AT_CME_OPERATION_NOT_ALLOWED;
            break;

        case TAF_MMA_NET_SCAN_CAUSE_SERVICE_EXIST :
            ulResult = AT_CME_OPERATION_NOT_ALLOWED;
            break;

        case TAF_MMA_NET_SCAN_CAUSE_NOT_CAMPED :
            ulResult = AT_CME_OPERATION_NOT_ALLOWED;
            break;

        case TAF_MMA_NET_SCAN_CAUSE_TIMER_EXPIRED :
            ulResult = AT_ERROR;
            break;

        case TAF_MMA_NET_SCAN_CAUSE_RAT_TYPE_ERROR :
            ulResult = AT_CME_OPERATION_NOT_ALLOWED;
            break;

        case TAF_MMA_NET_SCAN_CAUSE_MMA_STATE_DISABLE :
            ulResult = AT_ERROR;
            break;

        default:
            ulResult = AT_ERROR;
            break;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, ulResult);

    return;
}




VOS_UINT32 AT_RcvDrvAgentSwverSetCnf(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    VOS_UINT8                           ucIndex;
    DRV_AGENT_SWVER_SET_CNF_STRU       *pstEvent;
    DRV_AGENT_MSG_STRU                 *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_SWVER_SET_CNF_STRU *)pstRcvMsg->aucContent;

    AT_PR_LOGI("Rcv Msg");

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentSwverSetCnf: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvDrvAgentSwverSetCnf: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????SWVER?????????????????????? */
    if (AT_CMD_SWVER_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("AT_RcvDrvAgentSwverSetCnf: WARNING:Not AT_CMD_SWVER_SET!");
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    if (DRV_AGENT_NO_ERROR == pstEvent->enResult)
    {
        /* ????????????AT_OK           ??????????<CR><LF>^SWVER: <SwVer>_(<VerTime>)<CR><LF>
             <CR><LF>OK<CR><LF>???? */
        ulRet                  = AT_OK;

        gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                          (VOS_CHAR *)pgucAtSndCodeAddr,
                                          (VOS_CHAR *)pgucAtSndCodeAddr,
                                          "%s: %s_(%s)",
                                          g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                          pstEvent->stSwverInfo.aucSWVer,
                                          pstEvent->stSwverInfo.acVerTime);

    }
    else
    {
        /* ????????????ERROR?????? */
        ulRet                  = AT_ERROR;
        gstAtSendData.usBufLen = 0;
    }

    /* ????At_FormatResultData???????? */
    At_FormatResultData(ucIndex, ulRet);
    return VOS_OK;
}


VOS_VOID At_RcvMnCallSetCssnCnf(MN_AT_IND_EVT_STRU *pstData)
{
    MN_CALL_SET_CSSN_CNF_STRU      *pstCssnCnf;
    VOS_UINT8                       ucIndex;
    VOS_UINT32                      ulResult;

    pstCssnCnf = (MN_CALL_SET_CSSN_CNF_STRU *)pstData->aucContent;

    if (AT_FAILURE == At_ClientIdToUserId(pstCssnCnf->ClientId, &ucIndex))
    {
        AT_WARN_LOG("At_RcvMnCallSetCssnCnf: AT INDEX NOT FOUND!");
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_RcvMnCallSetCssnCnf : AT_BROADCAST_INDEX.");
        return;
    }

    /* AT???????????????????????????????????? */
    if (AT_CMD_CSSN_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("At_RcvMnCallSetCssnCnf: WARNING:Not AT_CMD_APP_SET_CSSN_REQ!");
        return;
    }

    gstAtSendData.usBufLen = 0;

    AT_STOP_TIMER_CMD_READY(ucIndex);

    if (TAF_ERR_NO_ERROR == pstCssnCnf->ulRet)
    {
        ulResult = AT_OK;
    }
    else
    {
        ulResult = AT_CME_INCORRECT_PARAMETERS;
    }

    At_FormatResultData(ucIndex,ulResult);

}


TAF_CALL_CHANNEL_TYPE_ENUM_UINT8 AT_ConvertCodecTypeToChannelType(
    VOS_UINT8                           ucIsLocalAlertingFlag,
    MN_CALL_CODEC_TYPE_ENUM_U8          enCodecType
)
{
    TAF_CALL_CHANNEL_TYPE_ENUM_UINT8    enChannelType;

    enChannelType = TAF_CALL_CHANNEL_TYPE_NONE;

    if (VOS_TRUE == ucIsLocalAlertingFlag)
    {
        /* ????????,???????????? */
        enChannelType = TAF_CALL_CHANNEL_TYPE_NONE;
    }
    else
    {
        /* ??????????????????channel type */
        /* ???????????????????????? */
        enChannelType = TAF_CALL_CHANNEL_TYPE_NARROW;

        if ((MN_CALL_CODEC_TYPE_AMRWB == enCodecType)
         || (MN_CALL_CODEC_TYPE_EVS == enCodecType))
        {
            /* ???????????????????? */
            enChannelType = TAF_CALL_CHANNEL_TYPE_WIDE;
        }

        if (MN_CALL_CODEC_TYPE_EVS_NB == enCodecType)
        {
            enChannelType = TAF_CALL_CHANNEL_TYPE_EVS_NB;
        }

        if (MN_CALL_CODEC_TYPE_EVS_WB == enCodecType)
        {
            enChannelType = TAF_CALL_CHANNEL_TYPE_EVS_WB;
        }

        if (MN_CALL_CODEC_TYPE_EVS_SWB == enCodecType)
        {
            enChannelType = TAF_CALL_CHANNEL_TYPE_EVS_SWB;
        }
    }

    return enChannelType;
}


VOS_VOID AT_RcvMnCallChannelInfoInd(VOS_VOID *pEvtInfo)
{
    MN_CALL_EVT_CHANNEL_INFO_STRU      *pstChannelInfoInd;
    VOS_UINT16                          usLength;
    VOS_UINT8                           ucIndex;
    TAF_CALL_CHANNEL_TYPE_ENUM_UINT8    enChannelType;

    usLength          = 0;
    pstChannelInfoInd = (MN_CALL_EVT_CHANNEL_INFO_STRU *)pEvtInfo;

    if ((pstChannelInfoInd->enCodecType == MN_CALL_CODEC_TYPE_BUTT)
     && (VOS_FALSE == pstChannelInfoInd->ucIsLocalAlertingFlag))
    {
        AT_WARN_LOG("AT_RcvMnCallChannelInfoInd: WARNING: CodecType BUTT!");
        return;
    }

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstChannelInfoInd->usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvMnCallChannelInfoInd:WARNING:AT INDEX NOT FOUND!");
        return;
    }

    enChannelType = AT_ConvertCodecTypeToChannelType(pstChannelInfoInd->ucIsLocalAlertingFlag, pstChannelInfoInd->enCodecType);

    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s%s %d,%d%s",
                                       gaucAtCrLf,
                                       gastAtStringTab[AT_STRING_CS_CHANNEL_INFO].pucText,
                                       enChannelType,
                                       pstChannelInfoInd->enVoiceDomain,
                                       gaucAtCrLf);

    gstAtSendData.usBufLen = usLength;

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return;
}



VOS_VOID At_RcvXlemaQryCnf(
    MN_AT_IND_EVT_STRU                 *pstData,
    VOS_UINT16                          usLen
)
{
    MN_CALL_ECC_NUM_INFO_STRU          *pstEccNumInfo = VOS_NULL_PTR;
    VOS_UINT8                           aucAsciiNum[(MN_CALL_MAX_BCD_NUM_LEN*2)+1];
    VOS_UINT8                           ucIndex;
    VOS_UINT32                          i;
    VOS_UINT16                          usLength;
    VOS_UINT32                          ulMcc;

    ucIndex = 0;
    ulMcc   = 0;
    TAF_MEM_SET_S(aucAsciiNum, sizeof(aucAsciiNum), 0x00, sizeof(aucAsciiNum));

    /* ???????????????????????? */
    pstEccNumInfo = (MN_CALL_ECC_NUM_INFO_STRU *)pstData->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEccNumInfo->usClientId, &ucIndex))
    {
        AT_WARN_LOG("At_RcvXlemaQryCnf:WARNING:AT INDEX NOT FOUND!");
        return;
    }

    /* ?????????????????????? */
    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_RcvXlemaQryCnf: WARNING:AT_BROADCAST_INDEX!");
        return;
    }

    /* ??????????????????????AT_CMD_XLEMA_QRY */
    if (AT_CMD_XLEMA_QRY != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        AT_WARN_LOG("At_RcvXlemaQryCnf: WARNING:Not AT_CMD_XLEMA_QRY!");
        return;
    }

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ??APP?????????????????? */
    for (i = 0; i < pstEccNumInfo->ulEccNumCount; i++)
    {
        /* ??BCD????????ASCII?? */
        AT_BcdNumberToAscii(pstEccNumInfo->astCustomEccNumList[i].aucEccNum,
                            pstEccNumInfo->astCustomEccNumList[i].ucEccNumLen,
                            (VOS_CHAR*)aucAsciiNum);

        /* ??NAS??????MCC??????BCD???? */
        AT_ConvertNasMccToBcdType(pstEccNumInfo->astCustomEccNumList[i].ulMcc, &ulMcc);

        usLength = 0;
        usLength = (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr +
                                           usLength,
                                           "%s^XLEMA: ",
                                           gaucAtCrLf);

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr +
                                           usLength,
                                           "%d,%d,%s,%d,%d,",
                                           (i+1),
                                           pstEccNumInfo->ulEccNumCount,
                                           aucAsciiNum,
                                           pstEccNumInfo->astCustomEccNumList[i].ucCategory,
                                           pstEccNumInfo->astCustomEccNumList[i].ucValidSimPresent);

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr +
                                           usLength,
                                           "%x%x%x",
                                           (ulMcc & 0x0f00)>>8,
                                           (ulMcc & 0xf0)>>4,
                                           (ulMcc & 0x0f));

        usLength += (TAF_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (TAF_CHAR *)pgucAtSndCodeAddr,
                                           (TAF_CHAR *)pgucAtSndCodeAddr +
                                           usLength,
                                           ",%d%s",
                                           pstEccNumInfo->astCustomEccNumList[i].ucAbnormalServiceFlg,
                                           gaucAtCrLf);

        At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

        TAF_MEM_SET_S(aucAsciiNum, sizeof(aucAsciiNum), 0x00, sizeof(aucAsciiNum));
    }

    At_FormatResultData(ucIndex, AT_OK);

    return;
}





VOS_VOID AT_RcvTafCallStartDtmfCnf(
    MN_AT_IND_EVT_STRU                 *pstData
)
{
    VOS_UINT8                           ucIndex;
    TAF_CALL_EVT_DTMF_CNF_STRU         *pstDtmfCNf;

    /* ????ClientID???????????? */
    if(AT_FAILURE == At_ClientIdToUserId(pstData->clientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvTafCallStartDtmfCnf: Get Index Fail!");
        return;
    }

    /* AT??????????^DTMF????/+VTS?????????????????????? */
    if ( (AT_CMD_DTMF_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
      && (AT_CMD_VTS_SET != gastAtClientTab[ucIndex].CmdCurrentOpt) )
    {
        AT_WARN_LOG("AT_RcvTafCallStartDtmfCnf: Error Option!");
        return;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ?????????????????????????????????? */
    pstDtmfCNf = (TAF_CALL_EVT_DTMF_CNF_STRU *)(pstData->aucContent
                                              + sizeof(MN_CALL_EVENT_ENUM_U32));
    if (TAF_CS_CAUSE_SUCCESS != pstDtmfCNf->enCause)
    {
        At_FormatResultData(ucIndex, AT_ERROR);
    }
    else
    {
        At_FormatResultData(ucIndex, AT_OK);
    }

    return;
}


VOS_VOID AT_RcvTafCallStopDtmfCnf(
    MN_AT_IND_EVT_STRU                 *pstData
)
{
    VOS_UINT8                           ucIndex;
    TAF_CALL_EVT_DTMF_CNF_STRU         *pstDtmfCNf;

    /* ????ClientID???????????? */
    if(AT_FAILURE == At_ClientIdToUserId(pstData->clientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvTafCallStopDtmfCnf: Get Index Fail!");
        return;
    }

    /* AT??????????^DTMF?????????????????????? */
    if (AT_CMD_DTMF_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("AT_RcvTafCallStopDtmfCnf: Error Option!");
        return;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ?????????????????????????????????? */
    pstDtmfCNf = (TAF_CALL_EVT_DTMF_CNF_STRU *)(pstData->aucContent
                                              + sizeof(MN_CALL_EVENT_ENUM_U32));
    if (TAF_CS_CAUSE_SUCCESS != pstDtmfCNf->enCause)
    {
        At_FormatResultData(ucIndex, AT_ERROR);
    }
    else
    {
        At_FormatResultData(ucIndex, AT_OK);
    }

    return;
}



VOS_VOID At_RcvTafCallOrigCnf(
    MN_AT_IND_EVT_STRU                 *pstData,
    TAF_UINT16                          usLen
)
{
    TAF_UINT8                           ucIndex;
    MN_CALL_INFO_STRU                  *pstCallInfo         = VOS_NULL_PTR;
    MN_CALL_EVENT_ENUM_U32              enEvent;
    TAF_UINT32                          ulEventLen;
    TAF_UINT32                          ulResult;
    TAF_UINT16                          usLength;

    ulResult = AT_FAILURE;
    usLength = 0;
    ucIndex  = 0;

    AT_LOG1("At_RcvTafCallOrigCnf pEvent->ClientId",pstData->clientId);
    AT_LOG1("At_RcvTafCallOrigCnf usMsgName",pstData->usMsgName);

    ulEventLen = sizeof(MN_CALL_EVENT_ENUM_U32);
    TAF_MEM_CPY_S(&enEvent,  sizeof(enEvent), pstData->aucContent, ulEventLen);
    pstCallInfo = (MN_CALL_INFO_STRU *)&pstData->aucContent[ulEventLen];

    if (AT_FAILURE == At_ClientIdToUserId(pstCallInfo->clientId, &ucIndex))
    {
        AT_WARN_LOG("At_CsEventProc At_ClientIdToUserId FAILURE");
        return;
    }

    /* ????????????OK??????????????NO CARRIER */
    if (TAF_CS_CAUSE_SUCCESS == pstCallInfo->enCause)
    {
        /* ??????????????????????????OK????????????????????????????????????????????OK??AT???????????????????????????????? */
        if (PS_TRUE == At_CheckOrigCnfCallType(pstCallInfo, ucIndex))
        {
            ulResult = AT_OK;
        }
        else
        {
            if (MN_CALL_TYPE_VIDEO == pstCallInfo->enCallType)
            {
                AT_STOP_TIMER_CMD_READY(ucIndex);
            }
            return;
        }

    }
    else
    {
        if (TAF_CS_CAUSE_NO_CALL_ID == pstCallInfo->enCause)
        {
            ulResult = AT_ERROR;
        }
        else
        {
            ulResult = AT_NO_CARRIER;
        }

        AT_UpdateCallErrInfo(ucIndex, pstCallInfo->enCause, &(pstCallInfo->stErrInfoText));
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    gstAtSendData.usBufLen = usLength;
    At_FormatResultData(ucIndex,ulResult);


}


PS_BOOL_ENUM_UINT8 AT_CheckCurrentOptType_SupsCmdSuccess(
    MN_CALL_INFO_STRU                  *pstCallInfo,
    TAF_UINT8                           ucIndex
)
{
    switch (gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        case AT_CMD_H_SET :
        case AT_CMD_CHUP_SET:
        case AT_CMD_REJCALL_SET:
            return PS_TRUE;
        case AT_CMD_A_SET:
        case AT_CMD_CHLD_SET:
        case AT_CMD_CHLD_EX_SET:
            if (VOS_TRUE == pstCallInfo->ucAtaReportOkAsyncFlag)
            {
                return PS_TRUE;
            }

            return PS_FALSE;
        default:
            return PS_FALSE;
    }
}


PS_BOOL_ENUM_UINT8 AT_CheckCurrentOptType_SupsCmdOthers(
    TAF_UINT8                           ucIndex
)
{
    switch(gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        case AT_CMD_CHLD_SET:
        case AT_CMD_CHUP_SET:
        case AT_CMD_A_SET:
        case AT_CMD_CHLD_EX_SET:
        case AT_CMD_H_SET:
        case AT_CMD_REJCALL_SET:
            return PS_TRUE;

        default:
            return PS_FALSE;
    }
}


VOS_VOID At_RcvTafCallSupsCmdCnf(
    MN_AT_IND_EVT_STRU                 *pstData,
    TAF_UINT16                          usLen
)
{
    TAF_UINT8                           ucIndex;
    MN_CALL_INFO_STRU                  *pstCallInfo         = VOS_NULL_PTR;
    MN_CALL_EVENT_ENUM_U32              enEvent;
    TAF_UINT32                          ulEventLen;
    TAF_UINT32                          ulResult;
    TAF_UINT16                          usLength;

    ulResult    = AT_FAILURE;
    usLength    = 0;
    ucIndex     = 0;

    AT_LOG1("At_RcvTafCallOrigCnf pEvent->ClientId",pstData->clientId);
    AT_LOG1("At_RcvTafCallOrigCnf usMsgName",pstData->usMsgName);

    ulEventLen = sizeof(MN_CALL_EVENT_ENUM_U32);
    TAF_MEM_CPY_S(&enEvent, sizeof(enEvent), pstData->aucContent, ulEventLen);
    pstCallInfo = (MN_CALL_INFO_STRU *)&pstData->aucContent[ulEventLen];

    if(AT_FAILURE == At_ClientIdToUserId(pstCallInfo->clientId, &ucIndex))
    {
        AT_WARN_LOG("At_RcvTafCallSupsCmdCnf At_ClientIdToUserId FAILURE");
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_RcvTafCallSupsCmdCnf: AT_BROADCAST_INDEX.");
        return;
    }

    /* AT?????????? */
    if (AT_FW_CLIENT_STATUS_READY == g_stParseContext[ucIndex].ucClientStatus)
    {
        AT_WARN_LOG("At_RcvTafCallSupsCmdCnf : AT command entity is released.");
        return;
    }

    /* ??????????????????OK */
    if (TAF_CS_CAUSE_SUCCESS == pstCallInfo->enCause)
    {
        if (PS_TRUE == AT_CheckCurrentOptType_SupsCmdSuccess(pstCallInfo, ucIndex))
        {
            ulResult = AT_OK;
        }
        else
        {
            return;
        }
    }
    else
    {
        if (PS_TRUE == AT_CheckCurrentOptType_SupsCmdOthers(ucIndex))
        {
            ulResult = AT_ConvertCallError(pstCallInfo->enCause);
        }
        else
        {
            ulResult = AT_CME_UNKNOWN;
        }
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    gstAtSendData.usBufLen = usLength;

    At_FormatResultData(ucIndex,ulResult);

}



VOS_VOID AT_PhEOPlmnQueryCnfProc(TAF_UINT8 *pData)
{
    VOS_UINT16                                              usLen;
    VOS_UINT8                                               ucIndex;
    VOS_UINT32                                              ulRslt;
    TAF_PHONE_EVENT_EOPLMN_QRY_CNF_STRU                    *pstEOPlmnQryCnf = VOS_NULL_PTR;

    usLen            = 0;
    pstEOPlmnQryCnf  = (TAF_PHONE_EVENT_EOPLMN_QRY_CNF_STRU *)pData;

    /* ????ClientId????ucIndex */
    if (AT_FAILURE == At_ClientIdToUserId(pstEOPlmnQryCnf->ClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_PhEOPlmnQueryCnfProc At_ClientIdToUserId FAILURE");
        return;
    }

    /* ??????????????????????AT_CMD_EOPLMN_QRY */
    if (AT_CMD_EOPLMN_QRY != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        AT_WARN_LOG("AT_PhEOPlmnQueryCnfProc: WARNING:Not AT_CMD_EOPLMN_QRY!");
        return;
    }

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    if (TAF_ERR_NO_ERROR == pstEOPlmnQryCnf->ulResult)
    {
        usLen += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                        (VOS_CHAR *)pgucAtSndCodeAddr + usLen,
                                        "%s: \"%s\",%d,",
                                        g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                        pstEOPlmnQryCnf->aucVersion,
                                        pstEOPlmnQryCnf->usOPlmnNum * TAF_AT_PLMN_WITH_RAT_LEN);


        /* ??16????????????ASCII???????????????????? */
        usLen += (TAF_UINT16)At_HexText2AsciiStringSimple(AT_CMD_MAX_LEN,
                                                            (TAF_INT8 *)pgucAtSndCodeAddr,
                                                            (TAF_UINT8 *)pgucAtSndCodeAddr + usLen,
                                                            pstEOPlmnQryCnf->usOPlmnNum * TAF_SIM_PLMN_WITH_RAT_LEN,
                                                            pstEOPlmnQryCnf->aucOPlmnList);

        gstAtSendData.usBufLen = usLen;

        ulRslt = AT_OK;
    }
    else
    {
        gstAtSendData.usBufLen = 0;
        ulRslt = AT_ERROR;
    }

    At_FormatResultData(ucIndex, ulRslt);

    return;
}


VOS_UINT32 AT_RcvNvManufactureExtSetCnf(VOS_VOID *pMsg)
{
    VOS_UINT8                                       ucIndex;
    DRV_AGENT_NVMANUFACTUREEXT_SET_CNF_STRU        *pstEvent;
    DRV_AGENT_MSG_STRU                             *pstRcvMsg;

    /* ?????? */
    pstRcvMsg              = (DRV_AGENT_MSG_STRU *)pMsg;
    pstEvent               = (DRV_AGENT_NVMANUFACTUREEXT_SET_CNF_STRU *)pstRcvMsg->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstEvent->stAtAppCtrl.usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvNvManufactureExtSetCnf: AT INDEX NOT FOUND!");
        return VOS_ERR;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvNvManufactureExtSetCnf: AT_BROADCAST_INDEX.");
        return VOS_ERR;
    }

    /* AT??????????NvManufactureExt?????????????????????? */
    if (AT_CMD_NVMANUFACTUREEXT_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("AT_RcvNvManufactureExtSetCnf: WARNING:Not AT_CMD_NVMANUFACTUREEXT_SET!");
        return VOS_ERR;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    if (NV_OK == pstEvent->ulRslt)
    {
        gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        (VOS_CHAR *)pgucAtSndCodeAddr,
                                                        "%d",
                                                        pstEvent->ulRslt);
        At_FormatResultData(ucIndex, AT_OK);
    }
    else
    {
        At_FormatResultData(ucIndex, AT_ERROR);
    }

    return VOS_OK;
}


VOS_VOID At_ChangeEcallTypeToCallType(
    MN_CALL_TYPE_ENUM_U8                enEcallType,
    MN_CALL_TYPE_ENUM_U8               *enCallType
)
{
    switch (enEcallType)
    {
        case MN_CALL_TYPE_TEST :
        case MN_CALL_TYPE_RECFGURATION :
        case MN_CALL_TYPE_PSAP_ECALL :
            *enCallType = MN_CALL_TYPE_VOICE;
            break;

        case MN_CALL_TYPE_MIEC :
        case MN_CALL_TYPE_AIEC :
            *enCallType = MN_CALL_TYPE_EMERGENCY;
            break;

        default:
            *enCallType = enEcallType;
            break;
    }

}


VOS_UINT32 At_IsCmdCurrentOptSendedOrigReq(AT_CMD_CURRENT_OPT_ENUM CmdCurrentOpt)
{
    switch (CmdCurrentOpt)
    {
        case AT_CMD_APDS_SET :
        case AT_CMD_D_CS_VOICE_CALL_SET :
        case AT_CMD_CECALL_SET:
        case AT_CMD_ECLSTART_SET:
        case AT_CMD_CACMIMS_SET:
        case AT_CMD_CUSTOMDIAL_SET:
             return VOS_TRUE;

        default:
             return VOS_FALSE;
    }
}


PS_BOOL_ENUM_UINT8 At_CheckOrigCnfCallType(
    MN_CALL_INFO_STRU                  *pstCallInfo,
    VOS_UINT8                           ucIndex
)
{
    switch (pstCallInfo->enCallType)
    {
        case MN_CALL_TYPE_VOICE :
        case MN_CALL_TYPE_EMERGENCY :
        case MN_CALL_TYPE_VIDEO_RX:
        case MN_CALL_TYPE_VIDEO_TX:
        case MN_CALL_TYPE_MIEC :
        case MN_CALL_TYPE_AIEC :
        case MN_CALL_TYPE_TEST :
        case MN_CALL_TYPE_RECFGURATION :
            if (VOS_TRUE == At_IsCmdCurrentOptSendedOrigReq(gastAtClientTab[ucIndex].CmdCurrentOpt))
            {
                return PS_TRUE;
            }

            return PS_FALSE;
        case MN_CALL_TYPE_VIDEO:
            if (AT_CMD_APDS_SET == gastAtClientTab[ucIndex].CmdCurrentOpt)
            {
                return PS_TRUE;
            }
            else
            {
                return PS_FALSE;
            }
        default:
            return PS_FALSE;
    }

}


PS_BOOL_ENUM_UINT8 At_CheckReportCendCallType(
    MN_CALL_TYPE_ENUM_U8                enCallType
)
{
    switch (enCallType)
    {
        case MN_CALL_TYPE_VOICE :
        case MN_CALL_TYPE_EMERGENCY :
        case MN_CALL_TYPE_MIEC :
        case MN_CALL_TYPE_AIEC :
        case MN_CALL_TYPE_TEST :
        case MN_CALL_TYPE_RECFGURATION :
        case MN_CALL_TYPE_PSAP_ECALL :
            return PS_TRUE;
        default:
            return PS_FALSE;
    }

}


PS_BOOL_ENUM_UINT8 At_CheckReportOrigCallType(
    MN_CALL_TYPE_ENUM_U8                enCallType
)
{
    switch (enCallType)
    {
        case MN_CALL_TYPE_VOICE :
        case MN_CALL_TYPE_EMERGENCY :
            return PS_TRUE;

        default:
            return PS_FALSE;
    }

}


PS_BOOL_ENUM_UINT8 At_CheckReportConfCallType(
    MN_CALL_TYPE_ENUM_U8                enCallType
)
{
    switch (enCallType)
    {
        case MN_CALL_TYPE_VOICE :
        case MN_CALL_TYPE_EMERGENCY :
        case MN_CALL_TYPE_MIEC :
        case MN_CALL_TYPE_AIEC :
        case MN_CALL_TYPE_TEST :
        case MN_CALL_TYPE_RECFGURATION :
        case MN_CALL_TYPE_PSAP_ECALL :
            return PS_TRUE;
        default:
            return PS_FALSE;
    }

}


PS_BOOL_ENUM_UINT8 At_CheckUartRingTeCallType(
    MN_CALL_TYPE_ENUM_U8                enCallType
)
{
    switch (enCallType)
    {
        case MN_CALL_TYPE_VOICE :
        case MN_CALL_TYPE_EMERGENCY :
        case MN_CALL_TYPE_MIEC :
        case MN_CALL_TYPE_AIEC :
        case MN_CALL_TYPE_TEST :
        case MN_CALL_TYPE_RECFGURATION :
        case MN_CALL_TYPE_PSAP_ECALL :
            return PS_TRUE;
        default:
            return PS_FALSE;
    }

}




VOS_VOID At_RcvTafCallModifyCnf(
    MN_AT_IND_EVT_STRU                 *pstData,
    VOS_UINT16                          usLen
)
{
    MN_CALL_MODIFY_CNF_STRU            *pstModifyCnf;
    VOS_UINT8                           ucIndex;

    ucIndex = 0;

    pstModifyCnf = (MN_CALL_MODIFY_CNF_STRU *)pstData->aucContent;

    /* ????ClientId????ucIndex */
    if ( AT_FAILURE == At_ClientIdToUserId(pstModifyCnf->usClientId, &ucIndex) )
    {
        AT_WARN_LOG("At_RcvTafCallModifyCnf: WARNING:AT INDEX NOT FOUND!");
        return;
    }

    /* ?????????????? */
    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_RcvTafCallModifyCnf: WARNING:AT_BROADCAST_INDEX!");
        return;
    }

    /* ??????????????????????AT_CMD_CALL_MODIFY_INIT_SET */
    if (AT_CMD_CALL_MODIFY_INIT_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        AT_WARN_LOG("At_RcvTafCallModifyCnf: WARNING:Not AT_CMD_CALL_MODIFY_INIT_SET!");
        return;
    }

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????????? */
    if (TAF_CS_CAUSE_SUCCESS != pstModifyCnf->enCause)
    {
        At_FormatResultData(ucIndex, AT_ERROR);
    }
    else
    {
        At_FormatResultData(ucIndex, AT_OK);
    }

    return;
}


VOS_VOID At_RcvTafCallAnswerRemoteModifyCnf(
    MN_AT_IND_EVT_STRU                 *pstData,
    VOS_UINT16                          usLen
)
{
    MN_CALL_MODIFY_CNF_STRU            *pstModifyCnf;
    VOS_UINT8                           ucIndex;

    ucIndex = 0;

    pstModifyCnf = (MN_CALL_MODIFY_CNF_STRU *)pstData->aucContent;

    /* ????ClientId????ucIndex */
    if ( AT_FAILURE == At_ClientIdToUserId(pstModifyCnf->usClientId, &ucIndex) )
    {
        AT_WARN_LOG("At_RcvTafCallAnswerRemoteModifyCnf: WARNING:AT INDEX NOT FOUND!");
        return;
    }

    /* ?????????????? */
    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("At_RcvTafCallAnswerRemoteModifyCnf: WARNING:AT_BROADCAST_INDEX!");
        return;
    }

    /* ??????????????????????AT_CMD_CALL_MODIFY_ANS_SET */
    if (AT_CMD_CALL_MODIFY_ANS_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        AT_WARN_LOG("At_RcvTafCallAnswerRemoteModifyCnf: WARNING:Not AT_CMD_CALL_MODIFY_CNF_SET!");
        return;
    }

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????????? */
    if (TAF_CS_CAUSE_SUCCESS != pstModifyCnf->enCause)
    {
        At_FormatResultData(ucIndex, AT_ERROR);
    }
    else
    {
        At_FormatResultData(ucIndex, AT_OK);
    }

    return;
}


VOS_VOID At_RcvTafCallModifyStatusInd(
    MN_AT_IND_EVT_STRU                 *pstData,
    VOS_UINT16                          usLen
)
{
    MN_CALL_EVT_MODIFY_STATUS_IND_STRU *pstStatusInd;
    VOS_UINT16                          usLength;
    VOS_UINT8                           ucIndex;

    usLength          = 0;
    pstStatusInd      = (MN_CALL_EVT_MODIFY_STATUS_IND_STRU *)pstData->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstStatusInd->usClientId, &ucIndex))
    {
        AT_WARN_LOG("At_RcvTafCallModifyStatusInd:WARNING:AT INDEX NOT FOUND!");
        return;
    }


    if (MN_CALL_MODIFY_REMOTE_USER_REQUIRE_TO_MODIFY == pstStatusInd->enModifyStatus)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%s%s %d,%d,%d,%d,%d,%d%s",
                                           gaucAtCrLf,
                                           gastAtStringTab[AT_STRING_CALL_MODIFY_IND].pucText,
                                           pstStatusInd->ucCallId,
                                           pstStatusInd->enCurrCallType,
                                           pstStatusInd->enVoiceDomain,
                                           pstStatusInd->enExpectCallType,
                                           pstStatusInd->enVoiceDomain,
                                           pstStatusInd->enModifyReason,
                                           gaucAtCrLf);
    }
    else if (MN_CALL_MODIFY_PROC_BEGIN == pstStatusInd->enModifyStatus)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%s%s %d,%d%s",
                                           gaucAtCrLf,
                                           gastAtStringTab[AT_STRING_CALL_MODIFY_BEG].pucText,
                                           pstStatusInd->ucCallId,
                                           pstStatusInd->enVoiceDomain,
                                           gaucAtCrLf);
    }
    else if (MN_CALL_MODIFY_PROC_END == pstStatusInd->enModifyStatus)
    {
        usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                           (VOS_CHAR *)pgucAtSndCodeAddr,
                                           (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                           "%s%s %d,%d,%d%s",
                                           gaucAtCrLf,
                                           gastAtStringTab[AT_STRING_CALL_MODIFY_END].pucText,
                                           pstStatusInd->ucCallId,
                                           pstStatusInd->enVoiceDomain,
                                           pstStatusInd->enCause,
                                           gaucAtCrLf);
    }
    else
    {
        return;
    }

    gstAtSendData.usBufLen = usLength;

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return;
}


VOS_VOID AT_RcvTafGetEconfInfoCnf(
    MN_AT_IND_EVT_STRU                 *pstData,
    VOS_UINT16                          usLen
)
{
    TAF_CALL_ECONF_INFO_QRY_CNF_STRU   *pstCallInfos;
    VOS_UINT32                          ulRet;
    VOS_UINT8                           ucIndex;

    /* ?????? */
    ucIndex = 0;
    ulRet   = VOS_ERR;

    /* ???????????? */
    pstCallInfos = (TAF_CALL_ECONF_INFO_QRY_CNF_STRU *)pstData->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstCallInfos->usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvTafGetEconfInfoCnf: WARNING: AT INDEX NOT FOUND!");
        return;
    }


    if (AT_CMD_CLCCECONF_QRY != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("AT_RcvTafGetEconfInfoCnf: WARNING: CmdCurrentOpt != AT_CMD_CLCCECONF_QRY!");
        return;
    }

    /* ^CLCCECONF??????????????? */
    ulRet = At_ProcQryClccEconfResult(pstCallInfos, ucIndex);

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, ulRet);

    return;
}


VOS_VOID AT_RcvTafEconfDialCnf(
    MN_AT_IND_EVT_STRU                 *pstData,
    VOS_UINT16                          usLen
)
{
    TAF_CALL_ECONF_DIAL_CNF_STRU       *pstEconfDialCnf;
    VOS_UINT8                           ucIndex;

    ucIndex = 0;

    pstEconfDialCnf = (TAF_CALL_ECONF_DIAL_CNF_STRU *)pstData->aucContent;

    /* ????ClientId????ucIndex */
    if ( AT_FAILURE == At_ClientIdToUserId(pstEconfDialCnf->usClientId, &ucIndex) )
    {
        AT_WARN_LOG("AT_RcvTafEconfDialCnf: WARNING:AT INDEX NOT FOUND!");
        return;
    }

    /* ?????????????? */
    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvTafEconfDialCnf: WARNING:AT_BROADCAST_INDEX!");
        return;
    }

    /* ???????????????? */
    if ((AT_CMD_ECONF_DIAL_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
     && (AT_CMD_CACMIMS_SET    != gastAtClientTab[ucIndex].CmdCurrentOpt))
    {
        AT_WARN_LOG("AT_RcvTafEconfDialCnf: WARNING:Not AT_CMD_ECONF_DIAL_SET or AT_CMD_CACMIMS_SET!");
        return;
    }

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????????? */
    if (TAF_CS_CAUSE_SUCCESS != pstEconfDialCnf->enCause)
    {
        At_FormatResultData(ucIndex, AT_ERROR);
    }
    else
    {
        At_FormatResultData(ucIndex, AT_OK);
    }

    return;
}


VOS_VOID AT_RcvTafEconfNotifyInd(
    MN_AT_IND_EVT_STRU                 *pstData,
    VOS_UINT16                          usLen
)
{
    VOS_UINT8                           ucIndex;
    VOS_UINT16                          usLength;
    TAF_CALL_EVT_ECONF_NOTIFY_IND_STRU *pstNotifyInd = VOS_NULL_PTR;
    AT_MODEM_CC_CTX_STRU               *pstCcCtx = VOS_NULL_PTR;

    usLength     = 0;
    pstNotifyInd = (TAF_CALL_EVT_ECONF_NOTIFY_IND_STRU *)pstData->aucContent;

    /* ????clientid????index */
    if (AT_FAILURE == At_ClientIdToUserId(pstNotifyInd->usClientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvTafEconfNotifyInd:WARNING:AT INDEX NOT FOUND!");
        return;
    }

    pstCcCtx = AT_GetModemCcCtxAddrFromClientId(pstNotifyInd->usClientId);

    if (pstNotifyInd->ucNumOfCalls > TAF_CALL_MAX_ECONF_CALLED_NUM)
    {
        pstCcCtx->stEconfInfo.ucNumOfCalls   = TAF_CALL_MAX_ECONF_CALLED_NUM;
    }
    else
    {
        pstCcCtx->stEconfInfo.ucNumOfCalls   = pstNotifyInd->ucNumOfCalls;
    }

    TAF_MEM_CPY_S(pstCcCtx->stEconfInfo.astCallInfo,
               sizeof(pstCcCtx->stEconfInfo.astCallInfo),
               pstNotifyInd->astCallInfo,
               (sizeof(TAF_CALL_ECONF_INFO_PARAM_STRU) * pstCcCtx->stEconfInfo.ucNumOfCalls));

    /* call_num??pstNotifyInd->ucNumOfCalls????????pstCcCtx->stEconfInfo.ucNumOfCalls?????????????????? */
    usLength += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                       (VOS_CHAR *)pgucAtSndCodeAddr,
                                       (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                       "%s%s %d%s",
                                       gaucAtCrLf,
                                       gastAtStringTab[AT_STRING_ECONFSTATE].pucText,
                                       pstNotifyInd->ucNumOfCalls,
                                       gaucAtCrLf);

    gstAtSendData.usBufLen = usLength;

    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return;
}


VOS_VOID AT_RcvTafCallCcwaiSetCnf(
    MN_AT_IND_EVT_STRU                 *pstData
)
{
    VOS_UINT8                           ucIndex;
    TAF_CALL_EVT_CCWAI_CNF_STRU        *pstCcwaiCnf;
    VOS_UINT32                          ulResult;

    /* ????ClientID???????????? */
    if(AT_FAILURE == At_ClientIdToUserId(pstData->clientId, &ucIndex))
    {
        AT_WARN_LOG("AT_RcvTafCallCcwaiSetCnf: WARNING:AT INDEX NOT FOUND!");
        return;
    }

    if (AT_IS_BROADCAST_CLIENT_INDEX(ucIndex))
    {
        AT_WARN_LOG("AT_RcvTafCallCcwaiSetCnf: WARNING:AT_BROADCAST_INDEX!");
        return;
    }

    /* AT??????????^CCWAI?????????????????????? */
    if (AT_CMD_CCWAI_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("AT_RcvTafCallCcwaiSetCnf: WARNING:Not AT_CMD_CCWAI_SET!");
        return;
    }

    /* ????AT_STOP_TIMER_CMD_READY????AT??????????????READY???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    pstCcwaiCnf = (TAF_CALL_EVT_CCWAI_CNF_STRU *)(pstData->aucContent
                                              + sizeof(MN_CALL_EVENT_ENUM_U32));

    /* ???????????????????? */
    if (VOS_OK == pstCcwaiCnf->ulResult)
    {
        ulResult = AT_OK;
    }
    else
    {
        ulResult = AT_ERROR;
    }

    gstAtSendData.usBufLen = 0;

    /* ????At_FormatResultData???????????? */
    At_FormatResultData(ucIndex, ulResult);

    return;
}


VOS_UINT32 AT_RcvTafPsEvtSetImsPdpCfgCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_IMS_PDP_CFG_CNF_STRU  *pstSetImsPdpCfgCnf;

    pstSetImsPdpCfgCnf = (TAF_PS_SET_IMS_PDP_CFG_CNF_STRU*)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_IMSPDPCFG_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetImsPdpCfgCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSet1xDormTimerCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_1X_DORM_TIMER_CNF_STRU  *pstSet1xDormTimerCnf;

    pstSet1xDormTimerCnf = (TAF_PS_SET_1X_DORM_TIMER_CNF_STRU* )pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_DORMTIMER_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSet1xDormTimerCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGet1xDormTimerCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_GET_1X_DORM_TIMER_CNF_STRU  *pstGet1xDormTiCnf = VOS_NULL_PTR;
    VOS_UINT16                          usLength;

    pstGet1xDormTiCnf = (TAF_PS_GET_1X_DORM_TIMER_CNF_STRU *)pEvtInfo;
    usLength         = 0;

    /* ????????AT???????? */
    if (AT_CMD_DORMTIMER_QRY != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ???????????? */
    usLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                      (VOS_CHAR *)pgucAtSndCodeAddr,
                                      (VOS_CHAR *)pgucAtSndCodeAddr + usLength,
                                      "%s: %d,%d",
                                      g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                      pstGet1xDormTiCnf->ucSocmDormTiVal,
                                      pstGet1xDormTiCnf->ucUserCfgDormTival);

    gstAtSendData.usBufLen = usLength;

    AT_STOP_TIMER_CMD_READY(ucIndex);
    At_FormatResultData(ucIndex, AT_OK);

    return VOS_OK;
}



VOS_UINT32 AT_RcvTafPsCallEvtPdpRabidChanged(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_PDP_RABID_CHANGE_IND_STRU  *pstEvent;
    MODEM_ID_ENUM_UINT16                    usModemId;

    /* ?????? */
    pstEvent  = (TAF_PS_CALL_PDP_RABID_CHANGE_IND_STRU *)pEvtInfo;
    usModemId = MODEM_ID_0;

    if (VOS_OK != AT_GetModemIdFromClient(ucIndex, &usModemId))
    {
        AT_ERR_LOG("AT_RcvTafPsCallEvtPdpRabidChanged: Get modem id fail.");
        return AT_ERROR;
    }

    /* ??????????RABID = modemId + rabId */
    gastAtClientTab[ucIndex].ucExPsRabId  = AT_BUILD_EXRABID(usModemId, pstEvent->ucNewRabId);

    switch ( gastAtClientTab[ucIndex].UserType )
    {
        /* ?????????????? */
        case AT_APP_USER:
            AT_PS_ProcRabidChangedEvent(pstEvent);
            break;

        default:
            break;
    }

    return VOS_OK;
}



VOS_UINT32 AT_RcvTafPsCallEvtLimitPdpActInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_LIMIT_PDP_ACT_IND_STRU *pstLimitPdpActInd = VOS_NULL_PTR;
    MODEM_ID_ENUM_UINT16                usModemId;
    VOS_UINT16                          usLength;

    usLength                = 0;
    usModemId               = MODEM_ID_0;
    pstLimitPdpActInd       = (TAF_PS_CALL_LIMIT_PDP_ACT_IND_STRU *)pEvtInfo;

    if (VOS_OK != AT_GetModemIdFromClient(ucIndex, &usModemId))
    {
        AT_ERR_LOG("AT_RcvTafPsCallEvtLimitPdpActInd: Get modem id fail.");
        return VOS_ERR;
    }

    /* ^LIMITPDPACT: <FLG>,<CAUSE><CR><LF> */
    usLength = (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                      (VOS_CHAR*)pgucAtSndCodeAddr,
                                      (VOS_CHAR*)pgucAtSndCodeAddr + usLength,
                                      "%s%s: %d,%d%s",
                                      gaucAtCrLf,
                                      gastAtStringTab[AT_STRING_LIMITPDPACT].pucText,
                                      pstLimitPdpActInd->ucLimitFlg,
                                      pstLimitPdpActInd->enCause,
                                      gaucAtCrLf);

    gstAtSendData.usBufLen = usLength;

    /* ????At_SendResultData???????????? */
    At_SendResultData(ucIndex, pgucAtSndCodeAddr, usLength);

    return VOS_OK;

}



VOS_UINT32 AT_RcvTafPsEvtSetMipModeCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_MIP_MODE_CNF_STRU       *pstSetMipModeCnf = VOS_NULL_PTR;

    pstSetMipModeCnf = (TAF_PS_SET_MIP_MODE_CNF_STRU *)pEvtInfo;

    /* ?????????????????????? */
    if ( AT_CMD_CMIP_SET != gastAtClientTab[ucIndex].CmdCurrentOpt )
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetMipModeCnf->enCause);

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtGetMipModeCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_GET_MIP_MODE_CNF_STRU       *pstGetMipModeCnf = VOS_NULL_PTR;

    pstGetMipModeCnf = (TAF_PS_GET_MIP_MODE_CNF_STRU *)pEvtInfo;

    /* ????????AT???????? */
    if (AT_CMD_CMIP_QRY != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf( AT_CMD_MAX_LEN,
                                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                                     "%s: %d",
                                                     g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                     pstGetMipModeCnf->enMipMode);

    At_FormatResultData(ucIndex, AT_OK);

    return VOS_OK;
}



VOS_UINT32 AT_RcvTafPsEvtSetVzwApneCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_VZWAPNE_CNF_STRU        *pstSetVzwApneCnf = VOS_NULL_PTR;

    pstSetVzwApneCnf = (TAF_PS_SET_VZWAPNE_CNF_STRU *)pEvtInfo;

    /* ?????????????????????? */
    if (AT_CMD_VZWAPNE_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("AT_RcvTafPsEvtSetVzwApneCnf: WARNING:NOT VZWAPNE_SET OPTION!");
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetVzwApneCnf->enCause);

    return VOS_OK;
}


VOS_CHAR *AT_GetPdpTypeStr(
    TAF_PDP_TYPE_ENUM_UINT8             enPdpType
)
{
    switch (enPdpType)
    {
        case TAF_PDP_IPV4:
            return (VOS_CHAR *)gastAtStringTab[AT_STRING_IPv4].pucText;
        case TAF_PDP_IPV6:
            return (VOS_CHAR *)gastAtStringTab[AT_STRING_IPv6].pucText;
        case TAF_PDP_IPV4V6:
            return (VOS_CHAR *)gastAtStringTab[AT_STRING_IPv4v6].pucText;
        default:
            AT_WARN_LOG1("AT_GetPdpTypeStr: Invalid PDP Type!", enPdpType);
            break;
    }

    return (VOS_CHAR *)gastAtStringTab[AT_STRING_IP].pucText;
}


VOS_VOID AT_PrintVzwApneResult(
    VOS_UINT8                           ucIndex,
    TAF_PS_GET_VZWAPNE_CNF_STRU        *pstGetVzwApneCnf
)
{
    VOS_UINT32                          ulLoop;
    VOS_CHAR                           *pcSplitStr  = VOS_NULL_PTR;
    VOS_CHAR                           *pcIPTypeStr = VOS_NULL_PTR;
    VOS_CHAR                           *pcApnebStr  = VOS_NULL_PTR;
    VOS_CHAR                            acApnStr[TAF_MAX_APN_LEN + 1];
    VOS_UINT8                           ucApnStrLen;
    VOS_UINT8                           ucMaxNum;
    VOS_UINT8                           ucIsCustomCmd;

    gstAtSendData.usBufLen = 0;

    /* ???????????? */
    if (TAF_PS_CAUSE_SUCCESS != pstGetVzwApneCnf->enCause)
    {
        At_FormatResultData(ucIndex, AT_ERROR);
        return;
    }

    ucMaxNum            = (pstGetVzwApneCnf->ucNum > TAF_PS_MAX_VZWAPNE_NUM) ?
                                TAF_PS_MAX_VZWAPNE_NUM : pstGetVzwApneCnf->ucNum;

    /* +VZWAPNE???????? */
    if (AT_CMD_VZWAPNE == g_stParseContext[ucIndex].pstCmdElement->ulCmdIndex)
    {
        ucIsCustomCmd   = VOS_TRUE;
        pcSplitStr      = ",";
    }
    else
    {
        ucIsCustomCmd   = VOS_FALSE;
        pcSplitStr      = (VOS_CHAR*)gaucAtCrLf;
    }

    for (ulLoop = 0; ulLoop < ucMaxNum; ulLoop++)
    {
        /* ????+VZWAPNE: /^VZWAPNE: */
        if ((0 == ulLoop) || (VOS_FALSE == ucIsCustomCmd))
        {
            gstAtSendData.usBufLen += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                                             (VOS_CHAR *)pgucAtSndCodeAddr + gstAtSendData.usBufLen,
                                                             "%s: ",
                                                             g_stParseContext[ucIndex].pstCmdElement->pszCmdName);
        }

        /* ????<cid> */
        if (VOS_FALSE == ucIsCustomCmd)
        {
            gstAtSendData.usBufLen += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                                             (VOS_CHAR *)pgucAtSndCodeAddr + gstAtSendData.usBufLen,
                                                             "%d,",
                                                             pstGetVzwApneCnf->astVzwApneInfo[ulLoop].ucCid);
        }

        /* ????<apncl>,<apnni>,<apntype>,<apnb>,<apned>,<apntime> */
        ucApnStrLen = (pstGetVzwApneCnf->astVzwApneInfo[ulLoop].stApn.ucLength > TAF_MAX_APN_LEN) ?
                        TAF_MAX_APN_LEN : pstGetVzwApneCnf->astVzwApneInfo[ulLoop].stApn.ucLength;

        TAF_MEM_SET_S(acApnStr, sizeof(acApnStr), 0, sizeof(acApnStr));
        TAF_MEM_CPY_S(acApnStr, sizeof(acApnStr), pstGetVzwApneCnf->astVzwApneInfo[ulLoop].stApn.aucValue, ucApnStrLen);

        pcIPTypeStr = AT_GetPdpTypeStr(pstGetVzwApneCnf->astVzwApneInfo[ulLoop].enIpType);
        pcApnebStr  = (VOS_TRUE == pstGetVzwApneCnf->astVzwApneInfo[ulLoop].ucEnable) ? "Enabled" : "Disabled";

        gstAtSendData.usBufLen += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                         (VOS_CHAR *)pgucAtSndCodeAddr,
                                                         (VOS_CHAR *)pgucAtSndCodeAddr + gstAtSendData.usBufLen,
                                                         "%d,\"%s\",%s,\"LTE\",\"%s\",%d",
                                                         pstGetVzwApneCnf->astVzwApneInfo[ulLoop].ucClass,
                                                         acApnStr,
                                                         pcIPTypeStr,
                                                         pcApnebStr,
                                                         pstGetVzwApneCnf->astVzwApneInfo[ulLoop].usInactiveTimer);

        /* ?????????? */
        if (ulLoop + 1 < ucMaxNum)
        {
            gstAtSendData.usBufLen += (VOS_UINT16)At_sprintf(AT_CMD_MAX_LEN,
                                                             (VOS_CHAR *)pgucAtSndCodeAddr,
                                                             (VOS_CHAR *)pgucAtSndCodeAddr + gstAtSendData.usBufLen,
                                                             "%s",
                                                             pcSplitStr);
        }

    }

    /* ??????AT???? */
    At_FormatResultData(ucIndex, AT_OK);

    return;

}


VOS_UINT32 AT_RcvTafPsEvtGetVzwApneCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_GET_VZWAPNE_CNF_STRU        *pstGetVzwApneCnf = VOS_NULL_PTR;

    pstGetVzwApneCnf    = (TAF_PS_GET_VZWAPNE_CNF_STRU *)pEvtInfo;

    /* ?????????????????????? */
    if (AT_CMD_VZWAPNE_QRY != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("AT_RcvTafPsEvtGetVzwApneCnf: WARNING:NOT VZWAPNE_QRY OPTION!");
        return VOS_ERR;
    }

    /* ????AT???? */
    AT_STOP_TIMER_CMD_READY(ucIndex);

    AT_PrintVzwApneResult(ucIndex, pstGetVzwApneCnf);

    return VOS_OK;
}



VOS_UINT32 AT_RcvTafPsRegStatusInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_REG_STATUS_IND_STRU         *pstPsRegStatusInd = VOS_NULL_PTR;
    AT_COMM_PS_CTX_STRU                *pstCommPsCtx    = VOS_NULL_PTR;
    MODEM_ID_ENUM_UINT16                usModemId;


    usModemId          = MODEM_ID_0;
    pstPsRegStatusInd  = (TAF_PS_REG_STATUS_IND_STRU *)pEvtInfo;
    pstCommPsCtx       = AT_GetCommPsCtxAddr();


    if (VOS_OK != AT_GetModemIdFromClient(ucIndex, &usModemId))
    {
        AT_ERR_LOG("AT_RcvTafPsEvtRefreshPdpTypeInd: Get modem id fail.");

        return VOS_ERR;
    }

    /* ????AT PDP????  */
    if ( (VOS_TRUE == pstCommPsCtx->astPdpTypeChgPolicyCfg[usModemId].ucPdpTypeChgEnableFlg)
      && (TAF_PS_REG_RESULT_SUCCESS == pstPsRegStatusInd->enPsRegResult)
      && (TAF_PS_REG_TYPE_ATTACH == pstPsRegStatusInd->enPsRegType) )
    {
        AT_InitPsPdpTypeChgMgrInfoByModemId(usModemId);
    }

    return VOS_OK;

}

VOS_UINT32 AT_RcvTafPdpTypeChgPolicyInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_PDP_TYPE_CHG_POLICY_IND_STRU      *pstPsPdpTypeChgPolicyInd = VOS_NULL_PTR;
    AT_COMM_PS_CTX_STRU                      *pstCommPsCtx             = VOS_NULL_PTR;
    MODEM_ID_ENUM_UINT16                      usModemId;

    pstPsPdpTypeChgPolicyInd  = (TAF_PS_PDP_TYPE_CHG_POLICY_IND_STRU *)pEvtInfo;

    pstCommPsCtx = AT_GetCommPsCtxAddr();

    if (VOS_OK != AT_GetModemIdFromClient(ucIndex, &usModemId))
    {
        AT_ERR_LOG("AT_RcvTafPdpTypeChgPolicyInd: Get modem id fail.");

        return VOS_ERR;
    }

    TAF_MEM_SET_S(&(pstCommPsCtx->astPdpTypeChgPolicyCfg[usModemId]),
                  sizeof(TAF_PS_PDP_TYPE_CHG_POLICY_CFG_STRU),
                  0x00,
                  sizeof(TAF_PS_PDP_TYPE_CHG_POLICY_CFG_STRU));

    /* ????NV???? */
    if ( VOS_TRUE == pstPsPdpTypeChgPolicyInd->stPsPdpTypeChgPolicy.ucPdpTypeChgEnableFlg)
    {
        TAF_MEM_CPY_S(&(pstCommPsCtx->astPdpTypeChgPolicyCfg[usModemId]),
                      sizeof(TAF_PS_PDP_TYPE_CHG_POLICY_CFG_STRU),
                      &(pstPsPdpTypeChgPolicyInd->stPsPdpTypeChgPolicy),
                      sizeof(TAF_PS_PDP_TYPE_CHG_POLICY_CFG_STRU));
    }

    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsReportPcoInfoInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_REPORT_PCO_INFO_IND_STRU    *pstPcoInfoInd = VOS_NULL_PTR;

    pstPcoInfoInd  = (TAF_PS_REPORT_PCO_INFO_IND_STRU *)pEvtInfo;

    if (pstPcoInfoInd->stCustomPcoInfo.ulContainerNum > 0)
    {
        AT_PS_ReportCustomPcoInfo(&pstPcoInfoInd->stCustomPcoInfo,
                                  pstPcoInfoInd->enOperateType,
                                  pstPcoInfoInd->ucCid,
                                  pstPcoInfoInd->enPdpType,
                                  ucIndex);
    }

    return VOS_OK;
}





VOS_UINT32 AT_RcvTafPsEvtSetDataSwitchCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{

    TAF_PS_SET_DATA_SWITCH_CNF_STRU*       pstSetDataSwitchCnf = VOS_NULL_PTR;
    pstSetDataSwitchCnf = (TAF_PS_SET_DATA_SWITCH_CNF_STRU *)pEvtInfo;

    /* ????????AT???????? */
    if (AT_CMD_DATASWITCH_SET!= gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetDataSwitchCnf->enCause);

    return VOS_OK;
}



VOS_UINT32 AT_RcvTafPsEvtGetDataSwitchCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{

    TAF_PS_GET_DATA_SWITCH_CNF_STRU*       pstGetDataSwitchCnf = VOS_NULL_PTR;
    pstGetDataSwitchCnf = (TAF_PS_GET_DATA_SWITCH_CNF_STRU *)pEvtInfo;

    /* ????????AT???????? */
    if (AT_CMD_DATASWITCH_QRY != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf( AT_CMD_MAX_LEN,
                                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                                     "%s: %d",
                                                     g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                     pstGetDataSwitchCnf->ucDataSwitch);

    At_FormatResultData(ucIndex, AT_OK);
    return VOS_OK;
}

VOS_UINT32 AT_RcvTafPsEvtSetDataRoamSwitchCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{

    TAF_PS_SET_DATA_ROAM_SWITCH_CNF_STRU*       pstSetDataRoamSwitchCnf = VOS_NULL_PTR;
    pstSetDataRoamSwitchCnf = (TAF_PS_SET_DATA_ROAM_SWITCH_CNF_STRU *)pEvtInfo;

    /* ????????AT???????? */
    if (AT_CMD_DATAROAMSWITCH_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    /* ?????????? */
    AT_PrcoPsEvtErrCode(ucIndex, pstSetDataRoamSwitchCnf->enCause);
    return VOS_OK;
}



VOS_UINT32 AT_RcvTafPsEvtGetDataRoamSwitchCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{

    TAF_PS_GET_DATA_ROAM_SWITCH_CNF_STRU*       pstGetDataSwitchCnf = VOS_NULL_PTR;
    pstGetDataSwitchCnf = (TAF_PS_GET_DATA_ROAM_SWITCH_CNF_STRU *)pEvtInfo;

    /* ????????AT???????? */
    if (AT_CMD_DATAROAMSWITCH_QRY != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        return VOS_ERR;
    }

    AT_STOP_TIMER_CMD_READY(ucIndex);

    /* ???????????? */
    gstAtSendData.usBufLen = (VOS_UINT16)At_sprintf( AT_CMD_MAX_LEN,
                                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                                     (VOS_CHAR *)pgucAtSndCodeAddr,
                                                     "%s: %d",
                                                     g_stParseContext[ucIndex].pstCmdElement->pszCmdName,
                                                     pstGetDataSwitchCnf->ucDataRoamSwitch);

    At_FormatResultData(ucIndex, AT_OK);
    return VOS_OK;
}


VOS_UINT32 AT_RcvTafPsEvtSetApnThrotInfoCnf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_SET_APN_THROT_INFO_CNF_STRU       *pstSetApnThrotInfoCnf = VOS_NULL_PTR;

    pstSetApnThrotInfoCnf = (TAF_PS_SET_APN_THROT_INFO_CNF_STRU*)pEvtInfo;

    /* ????????AT???????? */
    if (AT_CMD_APN_THROT_INFO_SET != gastAtClientTab[ucIndex].CmdCurrentOpt)
    {
        AT_WARN_LOG("AT_RcvTafPsEvtSetApnThrotInfoCnf: WARNING: CmdCurrentOpt != AT_CMD_APN_THROT_INFO_SET!");

        return VOS_ERR;
    }

    /* ?????????? ????????*/
    AT_PrcoPsEvtErrCode(ucIndex, pstSetApnThrotInfoCnf->enCause);

    return VOS_OK;
}



VOS_UINT32 AT_RcvTafPsEvtApnDataSysPolicyInd(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_APN_DATA_SYS_POLICY_CFG_IND_STRU  *pstApnDataSysPolicyCfgInd = VOS_NULL_PTR;
    AT_COMM_PS_CTX_STRU                      *pstCommPsCtx              = VOS_NULL_PTR;
    MODEM_ID_ENUM_UINT16                      usModemId;

    pstApnDataSysPolicyCfgInd  = (TAF_PS_APN_DATA_SYS_POLICY_CFG_IND_STRU *)pEvtInfo;

    pstCommPsCtx = AT_GetCommPsCtxAddr();

    if (VOS_OK != AT_GetModemIdFromClient(ucIndex, &usModemId))
    {
        AT_ERR_LOG("AT_RcvTafApnDataSysPolicyInd: Get modem id fail.");

        return VOS_ERR;
    }

    TAF_MEM_SET_S(&(pstCommPsCtx->astApnDataSysCfgList[usModemId]),
                  sizeof(TAF_PS_APN_DATA_SYS_POLICY_CONFIG_STRU),
                  0x00,
                  sizeof(TAF_PS_APN_DATA_SYS_POLICY_CONFIG_STRU));

    /* ????NV???? */
    TAF_MEM_CPY_S(&(pstCommPsCtx->astApnDataSysCfgList[usModemId]),
                  sizeof(TAF_PS_APN_DATA_SYS_POLICY_CONFIG_STRU),
                  &(pstApnDataSysPolicyCfgInd->stApnDataSysCfgList),
                  sizeof(TAF_PS_APN_DATA_SYS_POLICY_CONFIG_STRU));

    return VOS_OK;
}

VOS_UINT32 AT_RcvTafPsEvtDataSystemChgNtf(
    VOS_UINT8                           ucIndex,
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_DATA_SYSTEM_CHG_NTF_STRU          *pstDataSystemChgNtf   = VOS_NULL_PTR;
    AT_COMM_PS_CTX_STRU                      *pstCommPsCtx          = VOS_NULL_PTR;
    AT_MODEM_PS_CTX_STRU                     *pstPsModemCtx         = VOS_NULL_PTR;
    VOS_UINT32                                ulBitDataSysSwitchCid;
    VOS_UINT32                                i;
    MODEM_ID_ENUM_UINT16                      usModemId;

    pstDataSystemChgNtf  = (TAF_PS_DATA_SYSTEM_CHG_NTF_STRU *)pEvtInfo;

    pstCommPsCtx                = AT_GetCommPsCtxAddr();
    pstPsModemCtx               = AT_GetModemPsCtxAddrFromClientId(ucIndex);
    ulBitDataSysSwitchCid       = 0;
    usModemId                   = MODEM_ID_0;

    if (VOS_OK != AT_GetModemIdFromClient(ucIndex, &usModemId))
    {
        AT_ERR_LOG("AT_RcvTafPsEvtDataSystemChgNtf: Get modem id fail.");
        return VOS_ERR;
    }

    TAF_MEM_SET_S(&(pstCommPsCtx->astDataSystemStatus[usModemId]),
                  sizeof(TAF_PS_DATA_SYSTEM_STATUS_STRU),
                  0x00,
                  sizeof(TAF_PS_DATA_SYSTEM_STATUS_STRU));

    /* ???????????? */
    TAF_MEM_CPY_S(&(pstCommPsCtx->astDataSystemStatus[usModemId]),
                  sizeof(TAF_PS_DATA_SYSTEM_STATUS_STRU),
                  &(pstDataSystemChgNtf->stDataSystemStatus),
                  sizeof(TAF_PS_DATA_SYSTEM_STATUS_STRU));

    /* ?????????????? */
    if (VOS_TRUE == pstDataSystemChgNtf->bitOpBitDataSysCid)
    {
        ulBitDataSysSwitchCid = pstDataSystemChgNtf->ulBitDataSysSwitchCid;
    }
    else if (VOS_TRUE == pstDataSystemChgNtf->bitOpApn)
    {
        for (i = 0; i < AT_PS_MAX_CALL_NUM; i++)
        {
            if ( (pstPsModemCtx->astCallEntity[i].stUsrDialParam.ucAPNLen == pstDataSystemChgNtf->stApn.ucLength)
              && (0 == VOS_StrNiCmp((VOS_CHAR *)(pstDataSystemChgNtf->stApn.aucValue),
                                  (VOS_CHAR *)(pstPsModemCtx->astCallEntity[i].stUsrDialParam.aucAPN),
                                  pstPsModemCtx->astCallEntity[i].stUsrDialParam.ucAPNLen)))
            {
                ulBitDataSysSwitchCid = 0x01 << pstPsModemCtx->astCallEntity[i].stUsrDialParam.ucCid;
                break;
            }
        }
    }
    else
    {
        AT_ERR_LOG("AT_RcvTafPsEvtDataSystemChgNtf: bitOpBitDomainCid and bitOpApn both error .");
        return VOS_ERR;
    }

    AT_PS_PreProcPsCallDataSysChgNtf(ucIndex, ulBitDataSysSwitchCid);

    /* ????wlan???? */
    if (VOS_FALSE == pstCommPsCtx->astDataSystemStatus[usModemId].bWlanPowerState)
    {
        AT_PS_ProcWlanPowerOff(ucIndex);
    }

    return VOS_OK;
}




