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
#ifndef _ATDEVICECMD_H_
#define _ATDEVICECMD_H_

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "v_typdef.h"
#include "ATCmdProc.h"


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


#pragma pack(4)

/*****************************************************************************
  2 ??????
*****************************************************************************/
/*??????????????????*/

/* WIFI KEY??????????????NVIM????Ipcom_parameters_handle.h?????? NV_WLKEY_LEN ???????? */
#define AT_NV_WLKEY_LEN                 (27)

/* ??????????????????????NVIM????Ipcom_parameters_handle.h?????? NV_WLAUTHMODE_LEN ???????? */
#define AT_NV_WLAUTHMODE_LEN            (16)

/* ??????????????????????NVIM????Ipcom_parameters_handle.h?????? NV_ENCRYPTIONMODES_LEN ???????? */
#define AT_NV_ENCRYPTIONMODES_LEN       (5)

/* WPA????????????????????NVIM????Ipcom_parameters_handle.h?????? NV_WLWPAPSK_LEN ???????? */
#define AT_NV_WLWPAPSK_LEN              (65)

/* NV??50012??????????nv_wifisec_type WIFI KEY?????????????? */
#define AT_NV_WIFISEC_OTHERDATA_LEN     (72)

/* ????????????WIFI KEY???? */
#define AT_WIWEP_CARD_WIFI_KEY_TOTAL    (4)

/* ????????????WIFI KEY???? */
#define AT_WIWEP_TOOLS_WIFI_KEY_TOTAL   (16)

/* PHYNUM??????????????MAC???????????? */
#define AT_PHYNUM_MAC_LEN               (12)

/* PHYNUM??????????????MAC??????????^WIFIGLOBAL?????????????????????????? */
#define AT_PHYNUM_MAC_COLON_NUM         (5)

#define AT_TSELRF_PATH_TOTAL            (4)

#define AT_WIFIGLOBAL_MAC_LEN_BETWEEN_COLONS   (2)                             /* MAC????????????????????????*/


#if(FEATURE_ON == FEATURE_UE_MODE_TDS)
#define AT_TDS_SCALIB_STR (VOS_UINT8 *)"(\"CACHE\",\"USE\",\"SAVE\",\"GET\",\"READ\",\"INI\",\"BEGIN\",\"END\",\"SET\",\"\"),(\"APCOFFSETFLAG\",\"APCOFFSET\",\"APC\",\"APCFREQ\",\"AGC\",\"AGCFREQ\",\"\"),(1,5,6),(@pram)"
#define AT_TDS_SCALIB_TEST_STR "(CACHE,USE,SAVE,GET,READ,INI,BEGIN,END,SET),(APCOFFSETFLAG,APCOFFSET,APC,APCFREQ,AGC,AGCFREQ),(1,5,6),(DATA)"
#endif

#define BAND_WIDTH_NUMS 6

#define UIMID_DATA_LEN                              (4)

/*****************************************************************************
  3 ????????
*****************************************************************************/

enum AT_TBAT_OPERATION_TYPE_ENUM
{
    AT_TBAT_BATTERY_ANALOG_VOLTAGE      = 0,
    AT_TBAT_BATTERY_DIGITAL_VOLTAGE     = 1,
    AT_TBAT_BATTERY_VOLUME              = 2,
    AT_TBAT_OPERATION_TYPE_BUTT
};
typedef VOS_UINT32  AT_TBAT_OPERATION_TYPE_ENUM_UINT32;


enum AT_TBAT_OPERATION_DIRECTION_ENUM
{
    AT_TBAT_READ_FROM_UUT,
    AT_TBAT_SET_TO_UUT,
    AT_TBAT_OPERATION_DIRECTION_BUTT
};
typedef VOS_UINT32  AT_TBAT_OPERATION_DIRECTION_ENUM_UINT32;


enum AT_TSELRF_PATH_ENUM
{
    AT_TSELRF_PATH_GSM                  = 1,
    AT_TSELRF_PATH_WCDMA_PRI            = 2,
    AT_TSELRF_PATH_WCDMA_DIV            = 3,
    AT_TSELRF_PATH_TD					= 6,
    AT_TSELRF_PATH_WIFI                 = 7,
    AT_TSELRF_PATH_BUTT
};
typedef VOS_UINT32  AT_TSELRF_PATH_ENUM_UINT32;



enum AT_KEY_TYPE_ENUM
{
    AT_KEY_TYPE_DIEID      = 1,
    AT_KEY_TYPE_TBOX_SMS   = 2,
    AT_KEY_TYPE_SOCID      = 3,
    AT_KEY_TYPE_AUTHKEY    = 4,
    AT_KEY_TYPE_BUTT
};

enum AT_SECURE_STATE_ENUM
{
    AT_NOT_SET_STATE            = 0,     /*????????????????????*/
    AT_NO_DX_SECU_DISABLE_STATE = 0,     /*??DX????????????????????????*/
    AT_NO_DX_SECU_ENABLE_STATE  = 1,     /*??DX??????????????????????*/
    AT_DX_RMA_STATE             = 2,     /*????DX????????????????????????*/
    AT_DX_SECURE_STATE          = 3,     /*????DX??????????????????????*/
    AT_SECURE_STATE_BUTT
};

enum AT_DRV_RETURN_STATE_ENUM
{
    AT_DRV_NOT_SETTED_STATE = 0,         /*??????????????*/
    AT_DRV_STATE_SECURE     = 1,         /*????????*/
    AT_DRV_STATE_RMA        = 2,         /*??????????*/
    AT_DRV_STATE_BUTT
};

enum AT_SET_STATE_ENUM
{
    AT_SET_SECURE_STATE = 1,             /*??????????????*/
    AT_SET_RMA_STATE    = 2,             /*????????????????*/
    AT_SET_STATE_BUTT
};


enum AT_SET_SLT_TEST_TYPE_ENUM
{
    AT_SET_SGMII_TEST                   = 1,    /* SGMII???????????????? */
    AT_SET_RGMII_TEST                   = 2,    /* RGMII???????????????? */
    AT_SET_PCIE_TEST                    = 3,    /* PCIe????PHY???????????? */
    AT_SET_SPI_TEST                     = 4,    /* SPI master??slave???????????? */
    AT_SET_SDCARD_TEST                  = 5,    /* MMC0??????SD?????????? */
    AT_SET_L2CACHE_TEST                 = 6,    /* L2CACHE???? */
    AT_SET_HIFI_TEST                    = 7,    /* HIFI????*/
    AT_SET_SLT_TEST_BUTT
};
typedef VOS_UINT8  AT_SET_SLT_TEST_TYPE_ENUM_UINT8;

#define SLT_SUCCESS                     (0)
#define SLT_ERROR                       (1)


#define AT_AUTHKEY_LEN                  (8)     /* 64 Bits??AUTH KEY ????????*/
#define AT_KCE_LEN                      (16)    /* 128bit KCE??????key?????? */
#define AT_SOCID_LEN                    (32)    /* 256Bits??SOCID???????? */
#define AT_KEY_HASH_LEN                 (32)    /* SOCID????AUTHKEY??hash?????? */
#define AT_KEYBUFF_LEN                  (32)
#ifdef MBB_SLT
#define AT_BSN_LEN                      (16)    /* BSN????????*/
#endif

#define AT_SECUREDEBUG_VALUE            (3)     /* ????????DEBUG??????????????????*/
#define AT_SECDBGRESET_VALUE            (1)     /* ????????????Coresight ????????????????SecEngine*/
#define AT_CSRESET_VALUE                (1)     /* ????????????Coresight ????????????????SecEngine*/
#define AT_DFTSEL_VALUE                 (1)     /* ????????????????????????????DFT????*/

/*****************************************************************************
  4 ????????????
*****************************************************************************/

/* ???? g_stATDislogPwd ???? DIAG??????????????????NV????; ??????????????
   ???? g_stATDislogPwd ????????????, ???????????? DIAG ??????;
   ????????NV??????????????  */
extern VOS_INT8                         g_acATOpwordPwd[AT_OPWORD_PWD_LEN+1];


/*****************************************************************************
  5 ??????????
*****************************************************************************/


/*****************************************************************************
  6 ????????
*****************************************************************************/


/*****************************************************************************
  7 STRUCT????
*****************************************************************************/


typedef struct
{
    VOS_UINT8                           aucwlKeys[AT_NV_WLKEY_LEN];
}AT_WIFISEC_WIWEP_INFO_STRU;

/*****************************************************************************
  8 UNION????
*****************************************************************************/


/*****************************************************************************
  9 OTHERS????
*****************************************************************************/


/*****************************************************************************
  10 ????????
*****************************************************************************/
VOS_UINT32 At_SetSecuBootPara(VOS_UINT8 ucIndex);
VOS_UINT32 At_QrySecuBootPara(VOS_UINT8 ucIndex);
VOS_UINT32 At_QrySecuBootFeaturePara( VOS_UINT8 ucIndex );
#if (FEATURE_ON == FEATURE_PHONE_ENG_AT_CMD)
VOS_UINT32 At_SetKeyPara(VOS_UINT8 ucIndex);
VOS_UINT32 At_GetKeyInfoPara(VOS_UINT8 ucIndex);
#endif
VOS_UINT32 AT_SetTbatPara(VOS_UINT8 ucIndex);

VOS_UINT32 AT_QryTbatPara(VOS_UINT8 ucIndex);

VOS_UINT32 AT_SetPstandbyPara(VOS_UINT8 ucIndex);

VOS_UINT32 AT_SetWiwepPara(VOS_UINT8 ucIndex);

VOS_UINT32 AT_QryWiwepPara(VOS_UINT8 ucIndex);

VOS_UINT32 AT_TestWiwepPara(VOS_UINT8 ucIndex);
VOS_UINT32 AT_SetCmdlenPara(VOS_UINT8 ucIndex);

VOS_UINT32 AT_QryCmdlenPara(VOS_UINT8 ucIndex);

VOS_UINT32 AT_UpdateMacPara(
    VOS_UINT8                           aucMac[],
    VOS_UINT16                          usMacLength
);

VOS_UINT32 AT_SetTmodeAutoPowerOff(VOS_UINT8 ucIndex);

#if (FEATURE_ON == FEATURE_PHONE_ENG_AT_CMD)
VOS_UINT32 AT_SetTseLrfPara(VOS_UINT8 ucIndex);

VOS_UINT32 AT_QryTseLrfPara(VOS_UINT8 ucIndex);
#endif

VOS_UINT32 AT_GetPhynumMac(VOS_UINT8 aucMac[]);

VOS_UINT32 AT_ExistSpecificPort(VOS_UINT8 ucPortType);

VOS_UINT32 AT_OpenDiagPort(VOS_VOID);
VOS_UINT32 AT_CloseDiagPort(VOS_VOID);
VOS_UINT32 AT_CheckSetPortRight(
    VOS_UINT8                           aucOldRewindPortStyle[],
    VOS_UINT8                           aucNewRewindPortStyle[]
);

VOS_UINT32 AT_TestHsicCmdPara(VOS_UINT8 ucIndex);

#if(FEATURE_ON == FEATURE_UE_MODE_TDS)
VOS_UINT32 At_TestTdsScalibPara(VOS_UINT8 ucIndex);
#endif

VOS_UINT32 AT_TestSimlockUnlockPara( VOS_UINT8 ucIndex );

VOS_UINT32 AT_SetNVReadPara(VOS_UINT8 ucClientId);
#ifdef FEATURE_AT_NV_WRITE_SUPPORT
VOS_UINT32 AT_SetNVWritePara(VOS_UINT8 ucClientId);
#endif

VOS_UINT32 AT_QryFPllStatusPara(VOS_UINT8 ucIndex);
VOS_VOID At_RfPllStatusCnfProc(PHY_AT_RF_PLL_STATUS_CNF_STRU *pstMsg);

VOS_UINT32 AT_QryFpowdetTPara(VOS_UINT8 ucIndex);
VOS_VOID At_RfFpowdetTCnfProc(PHY_AT_POWER_DET_CNF_STRU *pstMsg);

VOS_UINT32 AT_NVWRGetParaInfo( AT_PARSE_PARA_TYPE_STRU * pstPara, VOS_UINT8 * pu8Data, VOS_UINT32 * pulLen);


#ifdef FEATURE_AT_NV_WRITE_SUPPORT
VOS_UINT32 AT_SetNvwrSecCtrlPara(VOS_UINT8 ucIndex);
VOS_UINT32 AT_RcvMtaNvwrSecCtrlSetCnf( VOS_VOID *pMsg );
VOS_UINT32 AT_QryNvwrSecCtrlPara(VOS_UINT8 ucIndex);
#endif
VOS_BOOL AT_IsNVWRAllowedNvId(VOS_UINT16 usNvId);

extern VOS_UINT32 AT_AsciiToHex(
    VOS_UINT8                          *pucSrc,
    VOS_UINT8                          *pucDst
);

extern VOS_UINT32 AT_AsciiToHexCode_Revers(
    VOS_UINT8                          *pucSrc,
    VOS_UINT16                          usDataLen,
    VOS_UINT8                          *pucDst
);

extern VOS_UINT32 AT_Hex2Ascii_Revers(
    VOS_UINT8                           aucHex[],
    VOS_UINT32                          ulLength,
    VOS_UINT8                           aucAscii[]
);

#if (FEATURE_ON == FEATURE_UE_MODE_CDMA)
extern VOS_UINT32 AT_SetMeidPara(VOS_UINT8 ucIndex);

extern VOS_UINT32 AT_QryMeidPara(VOS_UINT8 ucIndex);
#endif

#if (FEATURE_ON == FEATURE_PHONE_ENG_AT_CMD)
extern VOS_UINT32 AT_SetMipiWrPara(VOS_UINT8 ucIndex);
#endif
extern VOS_UINT32 AT_SetMipiRdPara(VOS_UINT8 ucIndex);
#if (FEATURE_ON == FEATURE_PHONE_ENG_AT_CMD)
extern VOS_UINT32 AT_SetSSIWrPara(VOS_UINT8 ucIndex);
extern VOS_UINT32 AT_SetSSIRdPara(VOS_UINT8 ucIndex);
#endif

#if (FEATURE_ON == FEATURE_PHONE_ENG_AT_CMD)
VOS_UINT32 AT_SetSlavePara(VOS_UINT8 ucIndex);
VOS_UINT32 AT_RcvMtaSetSlaveCnf( VOS_VOID *pMsg );
#endif

VOS_UINT32 AT_QryRficDieIDPara(VOS_UINT8 ucIndex);
VOS_UINT32 AT_RcvMtaRficDieIDQryCnf( VOS_VOID *pMsg );
VOS_UINT16 AT_RficDieIDOut(
    VOS_UINT8                          *pMsg,
    VOS_UINT32                          RficNum,
    VOS_UINT16                          usLength,
    VOS_UINT8                           ucIndex
);

VOS_UINT32 AT_QryPmuDieSNPara(VOS_UINT8 ucIndex);
VOS_UINT32 AT_RcvMtaPmuDieSNQryCnf( VOS_VOID *pMsg );

VOS_UINT32 AT_SetTasTestCfg(VOS_UINT8 ucIndex);
VOS_UINT32 AT_RcvMtaTasTestCfgCnf( VOS_VOID *pMsg );
#if (FEATURE_ON == FEATURE_PHONE_ENG_AT_CMD)
VOS_UINT32 AT_QryTasTestCfgPara(VOS_UINT8 ucIndex);
#endif
VOS_UINT16 AT_TasTestOut(
    MTA_AT_TAS_TEST_QRY_CNF_STRU       *pstMtaAtTasTestReqCnf
);
VOS_UINT32 AT_RcvMtaTasTestQryCnf( VOS_VOID *pMsg );
#if (FEATURE_ON == FEATURE_UE_MODE_CDMA)
VOS_UINT32 AT_SetCdmaAttDiversitySwitch(VOS_UINT8 ucIndex);
#endif
VOS_UINT32 AT_RcvMtaPowerDetQryCnf(VOS_VOID *pMsg);

#if (FEATURE_ON == FEATURE_PHONE_ENG_AT_CMD)
VOS_UINT32 AT_SetMipiReadPara(VOS_UINT8 ucIndex);
#endif
VOS_UINT32 AT_RcvMtaSetMipiReadCnf(VOS_VOID *pstMsg);

VOS_UINT32  At_SetCltPara(VOS_UINT8 ucIndex);

VOS_UINT32 AT_SetDcxotempcompPara(VOS_UINT8 ucIndex);
VOS_UINT32  AT_QryDcxotempcompPara(VOS_UINT8 ucIndex );
#ifdef MBB_SLT
VOS_UINT32 AT_SetBsnExPara(VOS_UINT8 ucIndex);
VOS_UINT32 AT_QryBsnExPara(VOS_UINT8 ucIndex);
VOS_UINT32 AT_SetUsbTestPara(VOS_UINT8 ucIndex);
VOS_UINT32 AT_SetSltTestPara(VOS_UINT8 ucIndex);
#endif


#if (VOS_OS_VER == VOS_WIN32)
#pragma pack()
#else
#pragma pack(0)
#endif




#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

#endif /* end of AtDeviceCmd.h */
