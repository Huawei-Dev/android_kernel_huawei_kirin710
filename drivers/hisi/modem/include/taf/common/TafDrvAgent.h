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

#ifndef __ATAGENT_H__
#define __ATAGENT_H__

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "vos.h"

#include "AtMnInterface.h"
#include "TafAppMma.h"
#include "mdrv.h"

#include "AtPhyInterface.h"

#include "v_typdef.h"

#ifdef MBB_COMMON
#include "MbbTafFactoryAtComm.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifdef WIN32
#pragma warning(disable:4200) /* zero-sized array in struct/union */
#endif

#pragma pack(4)

/*****************************************************************************
  2 ??????
*****************************************************************************/

#define AT_MAX_VERSION_LEN              (128)                 /* ???????????????? */


#define AT_MAX_PDM_VER_LEN              (16)                                    /* PDM???????????????? */

#define TAF_DLOAD_INFO_LEN              (1024)

#define TAF_AUTH_ID_LEN                 (50)

#define AT_DLOAD_TASK_DELAY_TIME        (500)

#define TAF_MAX_VER_INFO_LEN            (6)

#define TAF_MAX_PROPLAT_LEN             (63)                                    /*????????????????????*/

#define TAF_AUTHORITY_LEN               (50)                                    /* AUTHORITYVER???????????????? */

#define AT_AGENT_DRV_VERSION_TIME_LEN   (32)                                    /* ????????DRV_GET_VERSION_TIME?????????????????????? */


#define TAF_MAX_FLAFH_INFO_LEN          (255)

#define TAF_MAX_GPIO_INFO_LEN           (32)

/*??????????????????*/
#define DRV_AGENT_MAX_MODEL_ID_LEN      (31)
#define DRV_AGENT_MAX_REVISION_ID_LEN   (31)

/* MS?????????????????????? */
#define DRV_AGENT_MS_SUPPORT_RX_DIV_2100           (0x0001)
#define DRV_AGENT_MS_SUPPORT_RX_DIV_1900           (0x0002)
#define DRV_AGENT_MS_SUPPORT_RX_DIV_1800           (0x0004)
#define DRV_AGENT_MS_SUPPORT_RX_DIV_AWS_1700       (0x0008)
#define DRV_AGENT_MS_SUPPORT_RX_DIV_850            (0x0010)
#define DRV_AGENT_MS_SUPPORT_RX_DIV_800            (0x0020)
#define DRV_AGENT_MS_SUPPORT_RX_DIV_2600           (0x0040)
#define DRV_AGENT_MS_SUPPORT_RX_DIV_900            (0x0080)
#define DRV_AGENT_MS_SUPPORT_RX_DIV_IX_1700        (0x0100)

#define DRV_AGENT_DSP_RF_SWITCH_ON      (1)

#define DRV_AGENT_SIMLOCK_MAX_ERROR_TIMES  (3)  /* Simlock???????????????? */

#define  AT_PID_MEM_INFO_LEN                        (150) /* VOS????????????????????PID???? */

#define  AT_KB_TO_BYTES_NUM                         (1024) /* KB??????????????1024 */



#if (FEATURE_ON == FEATURE_SECURITY_SHELL)
/* ????SHELL?????????????????? */
#ifndef MBB_COMMON
#define AT_SHELL_PWD_LEN                (8)
#endif
#endif

/* ??????????????100????????PAD ??NAND??256MB??????block size??128kB????????2048????
   ????????????????5%????????????FLASH????2048*5%=102.4????100??????????????????
   ????????????????100??????????????100??????????????????????????????????
   ????????<totalNum>??????????????????????
 */
#define DRV_AGENT_NAND_BADBLOCK_MAX_NUM (100)

#define DRV_AGENT_CHIP_TEMP_ERR         (65535)

#define DRV_AGENT_HUK_LEN                       (16)        /* HUK??128Bits??????, ??????16Bytes */
#define DRV_AGENT_PUBKEY_LEN                    (1032)                          /* ????????????, ??????1032Bytes */
#define DRV_AGENT_RSA_CIPHERTEXT_LEN            (256)                           /* RSA????????, ??????256Bytes */
#define DRV_AGENT_SIMLOCKDATAWRITE_STRU_LEN     (516)                           /* ?????????????????????????????? */
#define DRV_AGENT_PUBKEY_SIGNATURE_LEN          (32)        /* ????????SSK???????? */

#define DRV_AGENT_SUPPORT_CATEGORY_NUM          (4)         /* ??????????????CATEGORY??????????????????????:network/network subset/SP/CP */

#define DRV_AGENT_PH_LOCK_CODE_GROUP_NUM        (20)        /* ???????????????? */

#define DRV_AGENT_SUPPORT_CATEGORY_NUM_EXTERED  (4)         /* ????????????????????????????CATEGORY??????????????????????:network/network subset/SP/CP */
#define DRV_AGENT_PH_LOCK_CODE_GROUP_NUM_EXTERED   (10)     /* ???????????????????????????????????????? */
#define DRV_AGENT_PH_LOCK_CODE_LEN_EXTERNED     (6)         /* ???????????????? */

#define DRV_AGENT_PH_LOCK_CODE_LEN              (4)         /* ???????????????? */

#define DRV_AGENT_PH_PHYNUM_LEN                 (16)        /* ?????????? */
#define DRV_AGENT_PH_PHYNUM_IMEI_LEN            (15)        /* IMEI?????? */
#define DRV_AGENT_PH_PHYNUM_IMEI_NV_LEN         (16)        /* IMEI??NV?????? */
#define DRV_AGENT_PH_PHYNUM_SN_LEN              (16)        /* SN???? */
#define DRV_AGENT_PH_PHYNUM_SN_NV_LEN           (DRV_AGENT_PH_PHYNUM_SN_LEN+4)  /* SN??NV?????? */
#define DRV_AGENT_PORT_PASSWORD_LEN             (16)        /* ?????????????????????? */

#define DRV_AGENT_DH_PUBLICKEY_LEN              (128)       /* DH??????????????????????Modem?????????? */
#define DRV_AGENT_DH_PRIVATEKEY_LEN             (48)        /* DH??????????Modem?????????? */

#define DRV_AGENT_HMAC_DATA_LEN                 (32)        /* HMAC?????????? */

#if (FEATURE_ON == FEATURE_PHONE_SC)
#define DRV_AGENT_PIN_CRYPTO_DATA_LEN           (16)        /* PIN?????????????? */
#define DRV_AGENT_PIN_CRYPTO_IV_LEN             (16)        /* PIN IV?????????? */
#endif

#define TAF_MAX_CPU_CNT                         (4)
#define TAF_SRE_ERROR_CODE                      (0xffffffff)

/*****************************************************************************
  3 ????????
*****************************************************************************/

/*****************************************************************************
 ??????    : DRV_AGENT_TSELRF_SET_ERROR_ENUM
 ????????  : ^TSELRF ??????????????????????????
             0: DRV_AGENT_TSELRF_SET_ERROR_NO_ERROR ??????????????
             1: DRV_AGENT_TSELRF_SET_ERROR_LOADDSP  ??????????????
*****************************************************************************/
enum DRV_AGENT_TSELRF_SET_ERROR_ENUM
{
    DRV_AGENT_TSELRF_SET_NO_ERROR      = 0,
    DRV_AGENT_TSELRF_SET_LOADDSP_FAIL,

    DRV_AGENT_TSELRF_SET_BUTT
};
typedef VOS_UINT32 DRV_AGENT_TSELRF_SET_ERROR_ENUM_UINT32;


/*****************************************************************************
 ??????    : DRV_AGENT_HKADC_GET_ERROR_ENUM
 ????????  : ????HKADC??????????????????????
             0: DRV_AGENT_HKADC_GET_NO_ERROR??????????
             1: DRV_AGENT_HKADC_GET_FAIL         ??????????
*****************************************************************************/
enum DRV_AGENT_HKADC_GET_ERROR_ENUM
{
    DRV_AGENT_HKADC_GET_NO_ERROR      = 0,
    DRV_AGENT_HKADC_GET_FAIL,

    DRV_AGENT_HKADC_GET_BUTT
};
typedef VOS_UINT32 DRV_AGENT_HKADC_GET_ERROR_ENUM_UINT32;

/*****************************************************************************
 ??????    : DRV_AGENT_USIMWRITESTUB_SET_ERROR_ENUM
 ????????  : USIMWRITESTUB ??????????????????????????
             0: ??????????????
             1: ??????????????
*****************************************************************************/
enum DRV_AGENT_ERROR_ENUM
{
    DRV_AGENT_NO_ERROR      = 0,
    DRV_AGENT_ERROR,
    DRV_AGENT_PARAM_ERROR,
    DRV_AGENT_CME_ERROR,
    DRV_AGENT_CME_RX_DIV_OTHER_ERR,
    DRV_AGENT_CME_RX_DIV_NOT_SUPPORTED,
    DRV_AGENT_CME_RX_DIV_BAND_ERR,

    DRV_AGENT_BUTT
};
typedef VOS_UINT32 DRV_AGENT_ERROR_ENUM_UINT32;



enum DRV_AGENT_MSID_QRY_ERROR_ENUM
{
    DRV_AGENT_MSID_QRY_NO_ERROR                  = 0,
    DRV_AGENT_MSID_QRY_READ_PRODUCT_ID_ERROR     = 1,
    DRV_AGENT_MSID_QRY_READ_SOFT_VER_ERROR       = 2,
    DRV_AGENT_MSID_QRY_BUTT
};
typedef VOS_UINT32  DRV_AGENT_MSID_QRY_ERROR_ENUM_UINT32;


enum DRV_AGENT_APPDMVER_QRY_ERROR_ENUM
{
    DRV_AGENT_APPDMVER_QRY_NO_ERROR      = 0,
    DRV_AGENT_APPDMVER_QRY_ERROR         = 1,

    DRV_AGENT_APPDMVER_QRY_BUTT
};
typedef VOS_UINT32 DRV_AGENT_APPDMVER_QRY_ERROR_ENUM_UINT32;


enum DRV_AGENT_DLOADINFO_QRY_ERROR_ENUM
{
    DRV_AGENT_DLOADINFO_QRY_NO_ERROR      = 0,
    DRV_AGENT_DLOADINFO_QRY_ERROR         = 1,

    DRV_AGENT_DLOADINFO_QRY_BUTT
};
typedef VOS_UINT32 DRV_AGENT_DLOADINFO_QRY_ERROR_ENUM_UINT32;


enum DRV_AGENT_AUTHORITYVER_QRY_ERROR_ENUM
{
    DRV_AGENT_AUTHORITYVER_QRY_NO_ERROR      = 0,
    DRV_AGENT_AUTHORITYVER_QRY_ERROR         = 1,

    DRV_AGENT_AUTHORITYVER_QRY_BUTT
};
typedef VOS_UINT32 DRV_AGENT_AUTHORITYVER_QRY_ERROR_ENUM_UINT32;


enum DRV_AGENT_AUTHORITYID_QRY_ERROR_ENUM
{
    DRV_AGENT_AUTHORITYID_QRY_NO_ERROR      = 0,
    DRV_AGENT_AUTHORITYID_QRY_ERROR         = 1,

    DRV_AGENT_AUTHORITYID_QRY_BUTT
};
typedef VOS_UINT32 DRV_AGENT_AUTHORITYID_QRY_ERROR_ENUM_UINT32;


enum DRV_AGENT_GODLOAD_SET_ERROR_ENUM
{
    DRV_AGENT_GODLOAD_SET_NO_ERROR      = 0,
    DRV_AGENT_GODLOAD_SET_ERROR         = 1,

    DRV_AGENT_GODLOAD_SET_BUTT
};
typedef VOS_UINT32 DRV_AGENT_GODLOAD_SET_ERROR_ENUM_UINT32;


enum DRV_AGENT_SDLOAD_SET_ERROR_ENUM
{
    DRV_AGENT_SDLOAD_SET_NO_ERROR      = 0,
    DRV_AGENT_SDLOAD_SET_ERROR         = 1,

    DRV_AGENT_SDLOAD_SET_BUTT
};
typedef VOS_UINT32 DRV_AGENT_SDLOAD_SET_ERROR_ENUM_UINT32;


enum DRV_AGENT_HWNATQRY_QRY_ERROR_ENUM
{
    DRV_AGENT_HWNATQRY_QRY_NO_ERROR      = 0,
    DRV_AGENT_HWNATQRY_QRY_ERROR         = 1,

    DRV_AGENT_HWNATQRY_QRY_BUTT
};
typedef VOS_UINT32 DRV_AGENT_HWNATQRY_QRY_ERROR_ENUM_UINT32;


enum DRV_AGENT_CPULOAD_QRY_ERROR_ENUM
{
    DRV_AGENT_CPULOAD_QRY_NO_ERROR      = 0,
    DRV_AGENT_CPULOAD_QRY_ERROR         = 1,

    DRV_AGENT_CPULOAD_QRY_BUTT
};
typedef VOS_UINT32 DRV_AGENT_CPULOAD_QRY_ERROR_ENUM_UINT32;


enum DRV_AGENT_MFREELOCKSIZE_QRY_ERROR_ENUM
{
    DRV_AGENT_MFREELOCKSIZE_QRY_NO_ERROR      = 0,
    DRV_AGENT_MFREELOCKSIZE_QRY_ERROR         = 1,

    DRV_AGENT_MFREELOCKSIZE_QRY_BUTT
};
typedef VOS_UINT32 DRV_AGENT_MFREELOCKSIZE_QRY_ERROR_ENUM_UINT32;



enum DRV_AGENT_AUTHVER_QRY_ERROR_ENUM
{
    DRV_AGENT_AUTHVER_QRY_NO_ERROR      = 0,
    DRV_AGENT_AUTHVER_QRY_ERROR         = 1,

    DRV_AGENT_AUTHVER_QRY_BUTT
};
typedef VOS_UINT32 DRV_AGENT_AUTHVER_QRY_ERROR_ENUM_UINT32;


enum DRV_AGENT_FLASHINFO_QRY_ERROR_ENUM
{
    DRV_AGENT_FLASHINFO_QRY_NO_ERROR      = 0,
    DRV_AGENT_FLASHINFO_QRY_ERROR         = 1,

    DRV_AGENT_FLASHINFO_QRY_BUTT
};
typedef VOS_UINT32 DRV_AGENT_FLASHINFO_QRY_ERROR_ENUM_UINT32;


enum DRV_AGENT_PFVER_QRY_ERROR_ENUM
{
    DRV_AGENT_PFVER_QRY_NO_ERROR                 = 0,
    DRV_AGENT_PFVER_QRY_ERROR_GET_VERSION_TIME   = 1,
    DRV_AGENT_PFVER_QRY_ERROR_GET_VERSION        = 2,
    DRV_AGENT_PFVER_QRY_ERROR_ALLOC_MEM          = 3,

    DRV_AGENT_PFVER_QRY_BUTT
};
typedef VOS_UINT32 DRV_AGENT_PFVER_QRY_ERROR_ENUM_UINT32;

/*****************************************************************************
 ??????    : DRV_AGENT_DLOADVER_QRY_ERROR_ENUM
 ????????  : DLOADVER ??????????????????????????
             0: ??????????????
             1: ??????????????
*****************************************************************************/
enum DRV_AGENT_DLOADVER_QRY_ERROR_ENUM
{
    DRV_AGENT_DLOADVER_QRY_NO_ERROR      = 0,
    DRV_AGENT_DLOADVER_QRY_ERROR         = 1,

    DRV_AGENT_DLOADVER_QRY_BUTT
};
typedef VOS_UINT32 DRV_AGENT_DLOADVER_QRY_ERROR_ENUM_UINT32;



enum DRV_AGENT_PERSONALIZATION_ERR_ENUM
{
    DRV_AGENT_PERSONALIZATION_NO_ERROR         = 0,             /* ???????? */
    DRV_AGENT_PERSONALIZATION_IDENTIFY_FAIL,                    /* ???????????? */
    DRV_AGENT_PERSONALIZATION_SIGNATURE_FAIL,                   /* ???????????? */
    DRV_AGENT_PERSONALIZATION_DK_INCORRECT,                     /* ???????????? */
    DRV_AGENT_PERSONALIZATION_PH_PHYNUM_LEN_ERROR,              /* ?????????????? */
    DRV_AGENT_PERSONALIZATION_PH_PHYNUM_VALUE_ERROR,            /* ???????????? */
    DRV_AGENT_PERSONALIZATION_PH_PHYNUM_TYPE_ERROR,             /* ?????????????? */
    DRV_AGENT_PERSONALIZATION_RSA_ENCRYPT_FAIL,                 /* RSA???????? */
    DRV_AGENT_PERSONALIZATION_RSA_DECRYPT_FAIL,                 /* RSA???????? */
    DRV_AGENT_PERSONALIZATION_GET_RAND_NUMBER_FAIL,             /* ??????????????(crypto_rand) */
    DRV_AGENT_PERSONALIZATION_WRITE_HUK_FAIL,                   /* HUK???????? */
    DRV_AGENT_PERSONALIZATION_FLASH_ERROR,                      /* Flash???? */
    DRV_AGENT_PERSONALIZATION_OTHER_ERROR,                      /* ???????? */

    DRV_AGENT_PERSONALIZATION_ERR_BUTT
};
typedef VOS_UINT32 DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32;


enum DRV_AGENT_PERSONALIZATION_CATEGORY_ENUM
{
    DRV_AGENT_PERSONALIZATION_CATEGORY_NETWORK                 = 0x00,          /* category:???? */
    DRV_AGENT_PERSONALIZATION_CATEGORY_NETWORK_SUBSET          = 0x01,          /* category:?????? */
    DRV_AGENT_PERSONALIZATION_CATEGORY_SERVICE_PROVIDER        = 0x02,          /* category:??SP */
    DRV_AGENT_PERSONALIZATION_CATEGORY_CORPORATE               = 0x03,          /* category:?????? */
    DRV_AGENT_PERSONALIZATION_CATEGORY_SIM_USIM                = 0x04,          /* category:??(U)SIM?? */

    DRV_AGENT_PERSONALIZATION_CATEGORY_BUTT
};
typedef VOS_UINT8 DRV_AGENT_PERSONALIZATION_CATEGORY_ENUM_UINT8;


enum DRV_AGENT_PERSONALIZATION_INDICATOR_ENUM
{
    DRV_AGENT_PERSONALIZATION_INDICATOR_INACTIVE               = 0x00,          /* ?????? */
    DRV_AGENT_PERSONALIZATION_INDICATOR_ACTIVE                 = 0x01,          /* ?????? */

    DRV_AGENT_PERSONALIZATION_INDICATOR_BUTT
};
typedef VOS_UINT8 DRV_AGENT_PERSONALIZATION_INDICATOR_ENUM_UINT8;


enum DRV_AGENT_PERSONALIZATION_STATUS_ENUM
{
    DRV_AGENT_PERSONALIZATION_STATUS_READY      = 0x00,                         /* ???????? */
    DRV_AGENT_PERSONALIZATION_STATUS_PIN        = 0x01,                         /* ???????????????????????? */
    DRV_AGENT_PERSONALIZATION_STATUS_PUK        = 0x02,                         /* Block????????????UnBlock?? */

    DRV_AGENT_PERSONALIZATION_STATUS_BUTT
};
typedef VOS_UINT8 DRV_AGENT_PERSONALIZATION_STATUS_ENUM_UINT8;


enum DRV_AGENT_PH_PHYNUM_TYPE_ENUM
{
    DRV_AGENT_PH_PHYNUM_IMEI            = 0x00,          /* IMEI */
    DRV_AGENT_PH_PHYNUM_SN              = 0x01,          /* SN */

    DRV_AGENT_PH_PHYNUM_BUTT
};
typedef VOS_UINT8 DRV_AGENT_PH_PHYNUM_TYPE_ENUM_UINT8;


enum DRV_AGENT_PORT_STATUS_ENUM
{
    DRV_AGENT_PORT_STATUS_OFF              = 0,         /* ???????? */
    DRV_AGENT_PORT_STATUS_ON               = 1,         /* ???????? */

    DRV_AGENT_PORT_STATUS_BUTT
};
typedef VOS_UINT32 DRV_AGENT_PORT_STATUS_ENUM_UINT32;


enum DRV_AGENT_USIM_OPERATE_ENUM
{
    DRV_AGENT_USIM_OPERATE_DEACT                = 0,         /* ??????USIM */
    DRV_AGENT_USIM_OPERATE_ACT                  = 1,         /* ????USIM */

    DRV_AGENT_USIM_OPERATE_BUTT
};
typedef VOS_UINT32 DRV_AGENT_USIM_OPERATE_ENUM_UINT32;


enum DRV_AGENT_MSG_TYPE_ENUM
{
    /* ???????? */                      /*????ID*/      /* ???? */
    /* AT????DRV AGENT?????? */
    DRV_AGENT_MSID_QRY_REQ               = 0x0000,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */
    DRV_AGENT_GCF_IND                    = 0x0002,

    DRV_AGENT_GPIOPL_SET_REQ             = 0x000E,
    DRV_AGENT_GPIOPL_QRY_REQ             = 0x0010,
    DRV_AGENT_DATALOCK_SET_REQ           = 0x0012,
    DRV_AGENT_TBATVOLT_QRY_REQ           = 0x0014,
    DRV_AGENT_VERTIME_QRY_REQ            = 0x0016,
    DRV_AGENT_YJCX_SET_REQ               = 0x0020,
    DRV_AGENT_YJCX_QRY_REQ               = 0x0022,
    DRV_AGENT_APPDMVER_QRY_REQ           = 0x0024,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/
    DRV_AGENT_DLOADINFO_QRY_REQ          = 0x0028,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/
    DRV_AGENT_FLASHINFO_QRY_REQ          = 0x002A,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/
    DRV_AGENT_AUTHVER_QRY_REQ            = 0x002C,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/
    DRV_AGENT_AUTHORITYVER_QRY_REQ       = 0x0030,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/
    DRV_AGENT_AUTHORITYID_QRY_REQ        = 0x0032,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/
    DRV_AGENT_GODLOAD_SET_REQ            = 0x0034,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/
    DRV_AGENT_HWNATQRY_QRY_REQ           = 0x0036,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/
    DRV_AGENT_CPULOAD_QRY_REQ            = 0x0038,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/
    DRV_AGENT_MFREELOCKSIZE_QRY_REQ      = 0x003A,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/

    DRV_AGENT_MEMINFO_QRY_REQ            = 0x003B,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/

    DRV_AGENT_HARDWARE_QRY               = 0x003E, /*??????????????*/
    DRV_AGENT_FULL_HARDWARE_QRY          = 0x0040, /*????????????????????*/
    DRV_AGENT_TMODE_SET_REQ              = 0x0046,
    DRV_AGENT_VERSION_QRY_REQ            = 0x0048,
    DRV_AGENT_SECUBOOT_QRY_REQ           = 0x004A,
    DRV_AGENT_SECUBOOTFEATURE_QRY_REQ    = 0x004C,
    DRV_AGENT_PFVER_QRY_REQ              = 0x004E,
    DRV_AGENT_FCHAN_SET_REQ              = 0x0052,
    DRV_AGENT_SDLOAD_SET_REQ             = 0x0056,
    DRV_AGENT_SFEATURE_QRY_REQ           = 0x0058,
    DRV_AGENT_PRODTYPE_QRY_REQ           = 0x0060,
    DRV_AGENT_SDREBOOT_REQ               = 0x0062,
    DRV_AGENT_RXDIV_SET_REQ              = 0x0064,
    DRV_AGENT_DLOADVER_QRY_REQ           = 0x0066,

    DRV_AGENT_RXDIV_QRY_REQ              = 0x006A,
    DRV_AGENT_SIMLOCK_SET_REQ            = 0x006C,
    DRV_AGENT_IMSICHG_QRY_REQ            = 0x0072,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */
    DRV_AGENT_NVRESTORE_SET_REQ          = 0x0074,                              /* _H2ASN_MsgChoice DRV_AGENT_NVRESTORE_RST_STRU */
    DRV_AGENT_INFORBU_SET_REQ            = 0x0076,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */
    DRV_AGENT_NVRSTSTTS_QRY_REQ          = 0x0078,                              /* _H2ASN_MsgChoice DRV_AGENT_NVRESTORE_RST_STRU */
    DRV_AGENT_CPNN_TEST_REQ              = 0x007A,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */
    DRV_AGENT_NVBACKUP_SET_REQ           = 0x007C,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */
    DRV_AGENT_CPNN_QRY_REQ               = 0x007E,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */
    DRV_AGENT_NVRESTORE_MANU_DEFAULT_REQ = 0x0080,                              /* _H2ASN_MsgChoice DRV_AGENT_NVRESTORE_RST_STRU */
    DRV_AGENT_ADC_SET_REQ                = 0x0082,                              /* _H2ASN_MsgChoice SPY_TEMP_THRESHOLD_PARA_STRU */
    DRV_AGENT_TSELRF_SET_REQ             = 0x0084,                              /* _H2ASN_MsgChoice DRV_AGENT_TSELRF_SET_REQ_STRU */
    DRV_AGENT_HKADC_GET_REQ              = 0x0086,                              /* _H2ASN_MsgChoice  */
    DRV_AGENT_TBAT_QRY_REQ               = 0x0088,
    /* Added by f62575 for B050 Project, 2012-2-3, Begin   */
    DRV_AGENT_SECUBOOT_SET_REQ           = 0x008A,

    DRV_AGENT_SIMLOCK_NV_SET_REQ         = 0x008c,

    DRV_AGENT_SPWORD_SET_REQ             = 0x008e,

    DRV_AGENT_PSTANDBY_SET_REQ           = 0x0090,

    DRV_AGENT_NVBACKUPSTAT_QRY_REQ       = 0x0092,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */
    DRV_AGENT_NANDBBC_QRY_REQ            = 0x0094,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */
    DRV_AGENT_NANDVER_QRY_REQ            = 0x0096,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */
    DRV_AGENT_CHIPTEMP_QRY_REQ           = 0x0098,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */


    DRV_AGENT_HUK_SET_REQ                = 0x009A,                              /* _H2ASN_MsgChoice DRV_AGENT_HUK_SET_REQ_STRU */
    DRV_AGENT_FACAUTHPUBKEY_SET_REQ      = 0x009C,                              /* _H2ASN_MsgChoice DRV_AGENT_FACAUTHPUBKEY_SET_REQ_STRU */
    DRV_AGENT_IDENTIFYSTART_SET_REQ      = 0x009E,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */
    DRV_AGENT_IDENTIFYEND_SET_REQ        = 0x00A0,                              /* _H2ASN_MsgChoice DRV_AGENT_IDENTIFYEND_SET_REQ_STRU */
    DRV_AGENT_PHONESIMLOCKINFO_QRY_REQ   = 0x00A4,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */
    DRV_AGENT_SIMLOCKDATAREAD_QRY_REQ    = 0x00A6,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */
    DRV_AGENT_PHONEPHYNUM_SET_REQ        = 0x00A8,                              /* _H2ASN_MsgChoice DRV_AGENT_PHONEPHYNUM_SET_REQ_STRU */
    DRV_AGENT_PHONEPHYNUM_QRY_REQ        = 0x00AA,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */
    DRV_AGENT_SARREDUCTION_SET_REQ       = 0x00B4,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */

    DRV_AGENT_INFORRS_SET_REQ            = 0x0100,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU */

    DRV_AGENT_MAX_LOCK_TIMES_SET_REQ     = 0x0102,

    DRV_AGENT_AP_SIMST_SET_REQ           = 0x0104,                              /* _H2ASN_MsgChoice DRV_AGENT_AP_SIMST_SET_REQ_STRU */

    DRV_AGENT_SWVER_SET_REQ              = 0x0106,                              /* _H2ASN_MsgChoice DRV_AGENT_SWVER_INFO_STRU */
    DRV_AGENT_QRY_CCPU_MEM_INFO_REQ      = 0x0108,

    DRV_AGENT_HVPDH_REQ                  = 0x010A,

    DRV_AGENT_NVMANUFACTUREEXT_SET_REQ   = 0x010C,


    DRV_AGENT_SIMLOCKWRITEEX_SET_REQ     = 0x0112,
    DRV_AGENT_SIMLOCKDATAREADEX_READ_REQ = 0x0114,

    /* DRV AGENT????AT?????? */
    DRV_AGENT_MSID_QRY_CNF               = 0x0001,                              /* _H2ASN_MsgChoice DRV_AGENT_MSID_QRY_CNF_STRU */

    DRV_AGENT_GPIOPL_SET_CNF             = 0x000D,
    DRV_AGENT_GPIOPL_QRY_CNF             = 0x000F,
    DRV_AGENT_DATALOCK_SET_CNF           = 0x0011,
    DRV_AGENT_TBATVOLT_QRY_CNF           = 0x0013,
    DRV_AGENT_VERTIME_QRY_CNF            = 0x0015,
    DRV_AGENT_YJCX_SET_CNF               = 0x001F,
    DRV_AGENT_YJCX_QRY_CNF               = 0x0021,
    DRV_AGENT_APPDMVER_QRY_CNF           = 0x0023,                              /* _H2ASN_MsgChoice DRV_AGENT_APPDMVER_QRY_CNF_STRU */
    DRV_AGENT_DLOADINFO_QRY_CNF          = 0x0027,                              /* _H2ASN_MsgChoice DRV_AGENT_DLOADINFO_QRY_CNF_STRU */
    DRV_AGENT_FLASHINFO_QRY_CNF          = 0x0029,                              /* _H2ASN_MsgChoice DRV_AGENT_FLASHINFO_QRY_CNF_STRU*/
    DRV_AGENT_AUTHVER_QRY_CNF            = 0x002B,                              /* _H2ASN_MsgChoice DRV_AGENT_AUTHVER_QRY_CNF_STRU*/
    DRV_AGENT_AUTHORITYVER_QRY_CNF       = 0x002F,                              /* _H2ASN_MsgChoice DRV_AGENT_AUTHORITYVER_QRY_CNF_STRU*/
    DRV_AGENT_AUTHORITYID_QRY_CNF        = 0x0031,                              /* _H2ASN_MsgChoice DRV_AGENT_AUTHORITYID_QRY_CNF_STRU*/
    DRV_AGENT_GODLOAD_SET_CNF            = 0x0033,                              /* _H2ASN_MsgChoice DRV_AGENT_GODLOAD_SET_CNF_STRU*/
    DRV_AGENT_HWNATQRY_QRY_CNF           = 0x0035,                              /* _H2ASN_MsgChoice DRV_AGENT_HWNATQRY_QRY_CNF_STRU*/
    /* Added by ??????/f62575 for CPULOAD&MFREELOCKSIZE????????????C??, 2011/11/15, begin */
    DRV_AGENT_CPULOAD_QRY_CNF            = 0x0037,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/
    DRV_AGENT_MFREELOCKSIZE_QRY_CNF      = 0x0039,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/
    /* Added by ??????/f62575 for CPULOAD&MFREELOCKSIZE????????????C??, 2011/11/15, end */

    DRV_AGENT_MEMINFO_QRY_CNF            = 0x003A,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/

    DRV_AGENT_HARDWARE_QRY_RSP           = 0x003D, /*??????????????*/
    DRV_AGENT_FULL_HARDWARE_QRY_RSP      = 0x003F, /*????????????????????*/
    DRV_AGENT_VERSION_QRY_CNF            = 0x0047,
    DRV_AGENT_SECUBOOT_QRY_CNF           = 0x0049,
    DRV_AGENT_SECUBOOTFEATURE_QRY_CNF    = 0x004B,
    DRV_AGENT_PFVER_QRY_CNF              = 0x004D,                              /* _H2ASN_MsgChoice DRV_AGENT_PFVER_QRY_CNF_STRU */
    DRV_AGENT_FCHAN_SET_CNF              = 0x0053,
    DRV_AGENT_SDLOAD_SET_CNF             = 0x0057,
    DRV_AGENT_SFEATURE_QRY_CNF           = 0x0059,
    DRV_AGENT_PRODTYPE_QRY_CNF           = 0x0061,
    DRV_AGENT_RXDIV_SET_CNF              = 0x0063,
    DRV_AGENT_DLOADVER_QRY_CNF           = 0x0065,
    DRV_AGENT_RXDIV_QRY_CNF              = 0x0069,
    DRV_AGENT_SIMLOCK_SET_CNF            = 0x006B,
    DRV_AGENT_IMSICHG_QRY_CNF            = 0x0071,                              /* _H2ASN_MsgChoice DRV_AGENT_IMSICHG_QRY_CNF_STRU */
    DRV_AGENT_NVRESTORE_SET_CNF          = 0x0073,                              /* _H2ASN_MsgChoice DRV_AGENT_NVRESTORE_RST_STRU */
    DRV_AGENT_INFORBU_SET_CNF            = 0x0075,                              /* _H2ASN_MsgChoice DRV_AGENT_INFORBU_SET_CNF_STRU */
    DRV_AGENT_NVRSTSTTS_QRY_CNF          = 0x0077,                              /* _H2ASN_MsgChoice DRV_AGENT_NVRESTORE_RST_STRU */
    DRV_AGENT_CPNN_TEST_CNF              = 0x0079,                              /* _H2ASN_MsgChoice DRV_AGENT_CPNN_TEST_CNF_STRU */
    DRV_AGENT_NVBACKUP_SET_CNF           = 0x007B,                              /* _H2ASN_MsgChoice DRV_AGENT_NVBACKUP_SET_CNF_STRU */
    DRV_AGENT_CPNN_QRY_CNF               = 0x007D,                              /* _H2ASN_MsgChoice DRV_AGENT_CPNN_QRY_CNF_STRU */
    DRV_AGENT_NVRESTORE_MANU_DEFAULT_CNF = 0x007F,                              /* _H2ASN_MsgChoice DRV_AGENT_NVRESTORE_RST_STRU */
    DRV_AGENT_ADC_SET_CNF                = 0x0081,
    DRV_AGENT_TSELRF_SET_CNF             = 0x0083,                              /* _H2ASN_MsgChoice DRV_AGENT_TSELRF_SET_CNF_STRU */
    DRV_AGENT_HKADC_GET_CNF              = 0x0085,                              /* _H2ASN_MsgChoice DRV_AGENT_HKADC_GET_CNF_STRU */
    DRV_AGENT_TBAT_QRY_CNF               = 0x0087,
    DRV_AGENT_SECUBOOT_SET_CNF           = 0x0089,                              /* _H2ASN_MsgChoice DRV_AGENT_SECUBOOT_SET_CNF_STRU */
    DRV_AGENT_SPWORD_SET_CNF             = 0x008B,

    DRV_AGENT_NVBACKUPSTAT_QRY_CNF       = 0x008D,                              /* _H2ASN_MsgChoice DRV_AGENT_NVBACKUPSTAT_QRY_CNF_STRU */
    DRV_AGENT_NANDBBC_QRY_CNF            = 0x008F,                              /* _H2ASN_MsgChoice DRV_AGENT_NANDBBC_QRY_CNF_STRU */
    DRV_AGENT_NANDVER_QRY_CNF            = 0x0091,                              /* _H2ASN_MsgChoice DRV_AGENT_NANDVER_QRY_CNF_STRU */
    DRV_AGENT_CHIPTEMP_QRY_CNF           = 0x0093,                              /* _H2ASN_MsgChoice DRV_AGENT_CHIPTEMP_QRY_CNF_STRU */


    DRV_AGENT_HUK_SET_CNF                = 0x0095,                              /* _H2ASN_MsgChoice DRV_AGENT_HUK_SET_CNF_STRU */
    DRV_AGENT_FACAUTHPUBKEY_SET_CNF      = 0x0097,                              /* _H2ASN_MsgChoice DRV_AGENT_FACAUTHPUBKEY_SET_CNF_STRU */
    DRV_AGENT_IDENTIFYSTART_SET_CNF      = 0x0099,                              /* _H2ASN_MsgChoice DRV_AGENT_IDENTIFYSTART_SET_CNF_STRU */
    DRV_AGENT_IDENTIFYEND_SET_CNF        = 0x009B,                              /* _H2ASN_MsgChoice DRV_AGENT_IDENTIFYEND_SET_CNF_STRU */
    DRV_AGENT_SIMLOCKDATAWRITE_SET_CNF   = 0x009D,                              /* _H2ASN_MsgChoice DRV_AGENT_SIMLOCKDATAWRITE_SET_CNF_STRU */
    DRV_AGENT_PHONESIMLOCKINFO_QRY_CNF   = 0x009F,                              /* _H2ASN_MsgChoice DRV_AGENT_PHONESIMLOCKINFO_QRY_CNF_STRU */
    DRV_AGENT_SIMLOCKDATAREAD_QRY_CNF    = 0x00A1,                              /* _H2ASN_MsgChoice DRV_AGENT_SIMLOCKDATAREAD_QRY_CNF_STRU */
    DRV_AGENT_PHONEPHYNUM_SET_CNF        = 0x00A3,                              /* _H2ASN_MsgChoice DRV_AGENT_PHONEPHYNUM_SET_CNF_STRU */
    DRV_AGENT_PHONEPHYNUM_QRY_CNF        = 0x00A5,                              /* _H2ASN_MsgChoice DRV_AGENT_PHONEPHYNUM_QRY_CNF_STRU */
    DRV_AGENT_PORTCTRLTMP_SET_CNF        = 0x00A7,                              /* _H2ASN_MsgChoice DRV_AGENT_PORTCTRLTMP_SET_CNF_STRU */
    DRV_AGENT_PORTATTRIBSET_SET_CNF      = 0x00A9,                              /* _H2ASN_MsgChoice DRV_AGENT_PORTATTRIBSET_SET_CNF_STRU */
    DRV_AGENT_PORTATTRIBSET_QRY_CNF      = 0x00AB,                              /* _H2ASN_MsgChoice DRV_AGENT_PORTATTRIBSET_QRY_CNF_STRU */
    DRV_AGENT_OPWORD_SET_CNF             = 0x00AD,                              /* _H2ASN_MsgChoice DRV_AGENT_OPWORD_SET_CNF_STRU */
    DRV_AGENT_ANTSTATE_QRY_IND           = 0x00AF,                              /* _H2ASN_MsgChoice AT_APPCTRL_STRU*/
    DRV_AGENT_INFORRS_SET_CNF            = 0x0101,                              /* _H2ASN_MsgChoice DRV_AGENT_INFORRS_SET_CNF_STRU */


    DRV_AGENT_MAX_LOCK_TIMES_SET_CNF     = 0x0103,                              /* _H2ASN_MsgChoice DRV_AGENT_MAX_LOCK_TMS_SET_CNF_STRU */

    DRV_AGENT_AP_SIMST_SET_CNF           = 0x0105,                              /* _H2ASN_MsgChoice DRV_AGENT_AP_SIMST_SET_CNF_STRU */

    DRV_AGENT_SWVER_SET_CNF              = 0x0107,                              /* _H2ASN_MsgChoice DRV_AGENT_SWVER_SET_CNF_STRU */

    DRV_AGENT_HVPDH_CNF                  = 0x0109,

    DRV_AGENT_NVMANUFACTUREEXT_SET_CNF   = 0x010B,


    DRV_AGENT_QRY_CCPU_MEM_INFO_CNF      = 0x0111,

    DRV_AGENT_SIMLOCKWRITEEX_SET_CNF     = 0x0113,
    DRV_AGENT_SIMLOCKDATAREADEX_SET_CNF  = 0x0115,
    DRV_AGENT_PHONESIMLOCKINFO_QRY_NEW_CNF = 0x0117,

    DRV_AGENT_MSG_TYPE_BUTT              = 0xFFFF
};
typedef VOS_UINT32 DRV_AGENT_MSG_TYPE_ENUM_UINT32;


enum AT_DEVICE_CMD_RAT_MODE_ENUM
{
    AT_RAT_MODE_WCDMA = 0,
    AT_RAT_MODE_CDMA,
    AT_RAT_MODE_TDSCDMA,
    AT_RAT_MODE_GSM,
    AT_RAT_MODE_EDGE,
    AT_RAT_MODE_AWS,
    AT_RAT_MODE_FDD_LTE,
    AT_RAT_MODE_TDD_LTE,
    AT_RAT_MODE_WIFI,
    AT_RAT_MODE_BUTT
};
typedef VOS_UINT8 AT_DEVICE_CMD_RAT_MODE_ENUM_UINT8;


/* ????????????????????  */
enum AT_MEMQUERY_PARA_ENUM
{
    AT_MEMQUERY_VOS = 0,  /* ????VOS?????????????????????????? */
    AT_MEMQUERY_TTF,      /* ????TTF?????????????????????????? */
    AT_MEMQUERY_BUTT
};
typedef VOS_UINT32  AT_MEMQUERY_PARA_ENUM_UINT32;



enum DRV_AGENT_DH_KEY_TYPE_ENUM
{
    DRV_AGENT_DH_KEY_SERVER_PUBLIC_KEY  = 0x00,          /* ?????????? */
    DRV_AGENT_DH_KEY_MODEM_PUBLIC_KEY   = 0x01,          /* MODEM?????? */
    DRV_AGENT_DH_KEY_MODEM_PRIVATE_KEY  = 0x02,          /* MODEM?????? */

    DRV_AGENT_DH_KEY_BUTT
};
typedef VOS_UINT32 DRV_AGENT_DH_KEY_TYPE_ENUM_UINT32;


enum DRV_AGENT_HVPDH_ERR_ENUM
{
    DRV_AGENT_HVPDH_NO_ERROR            = 0x00,          /* ???????? */
    DRV_AGENT_HVPDH_AUTH_UNDO           = 0x01,          /* ?????????????????????? */
    DRV_AGENT_HVPDH_NV_READ_FAIL        = 0x02,          /* NV???????? */
    DRV_AGENT_HVPDH_NV_WRITE_FAIL       = 0x03,          /* NV???????? */
    DRV_AGENT_HVPDH_OTHER_ERROR         = 0x04,          /* ???????? */

    DRV_AGENT_HVPDH_ERR_BUTT
};
typedef VOS_UINT32 DRV_AGENT_HVPDH_ERR_ENUM_UINT32;




/*****************************************************************************
  4 ????????????
*****************************************************************************/


/*****************************************************************************
  5 ??????????
*****************************************************************************/


/*****************************************************************************
  6 ????????
*****************************************************************************/



typedef struct
{
    VOS_UINT32                          ulStandbyTime;                          /* ????????????????????????????(??????ms),???????? 0~65535,??????5000?? */
    VOS_UINT32                          ulSwitchTime;                           /* ????????PC??????????????????????????????????????????????????ms?????????????? 0~65535????????500?? */
} DRV_AGENT_PSTANDBY_REQ_STRU;



typedef struct
{
    VOS_MSG_HEADER
    VOS_UINT32                          ulMsgId;
    VOS_UINT8                           aucContent[4];
} DRV_AGENT_MSG_STRU;


/*****************************************************************************
  7 STRUCT????
*****************************************************************************/



enum GAS_AT_CMD_ENUM
{
    GAS_AT_CMD_GAS_STA              =   0,  /* GAS???? */
    GAS_AT_CMD_NCELL                =   1,  /* ???????? */
    GAS_AT_CMD_SCELL                =   2,  /* ???????????? */
    GAS_AT_CMD_MEASURE_DOWN         =   3,  /* ???????? */
    GAS_AT_CMD_MEASURE_UP           =   4,  /* ???????? */
    GAS_AT_CMD_FREQ_LOCK            =   5,  /* ???????????????????? */
    GAS_AT_CMD_FREQ_UNLOCK          =   6,  /* ???? */
    GAS_AT_CMD_FREQ_SPEC_SEARCH     =   7,  /* ???????????? */
    GAS_AT_CMD_ADD_FORB_CELL        =   8,  /* ???????????? */
    GAS_AT_CMD_DEL_FORB_CELL        =   9,  /* ???????????? */
    GAS_AT_CMD_DEL_HISTORY_SI_DATA  =   10, /* ???????????? */
    GAS_AT_CMD_BUTT
};

typedef VOS_UINT8 GAS_AT_CMD_ENUM_U8;


typedef struct
{
    GAS_AT_CMD_ENUM_U8                  ucCmd;
    VOS_UINT8                           ucParaNum;
    VOS_UINT16                          usReserve;
    VOS_UINT32                          aulPara[10];
}GAS_AT_CMD_STRU;


typedef struct
{
    AT_APPCTRL_STRU                      stAtAppCtrl;                                   /* AT???????????? */
    DRV_AGENT_MSID_QRY_ERROR_ENUM_UINT32 ulResult;                                      /* ???????????? */
    VOS_INT8                             acModelId[TAF_MAX_MODEL_ID_LEN + 1];           /* ???????? */
    VOS_INT8                             acSoftwareVerId[TAF_MAX_REVISION_ID_LEN + 1];  /* ???????????? */
    VOS_UINT8                            aucImei[TAF_PH_IMEI_LEN];
} DRV_AGENT_MSID_QRY_CNF_STRU;


typedef struct
{
    VOS_UINT8                           ucLoadDspMode;
    VOS_UINT8                           ucDeviceRatMode;
} DRV_AGENT_TSELRF_SET_REQ_STRU;


typedef struct
{
    AT_APPCTRL_STRU                          stAtAppCtrl;
    DRV_AGENT_APPDMVER_QRY_ERROR_ENUM_UINT32 enResult;
    VOS_INT8                                 acPdmver[AT_MAX_PDM_VER_LEN + 1];
    VOS_UINT8                                aucReserved1[3];
} DRV_AGENT_APPDMVER_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                           stAtAppCtrl;
    DRV_AGENT_DLOADINFO_QRY_ERROR_ENUM_UINT32 enResult;
    VOS_UCHAR                                 aucDlodInfo[TAF_DLOAD_INFO_LEN];
} DRV_AGENT_DLOADINFO_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                              stAtAppCtrl;
    DRV_AGENT_AUTHORITYVER_QRY_ERROR_ENUM_UINT32 enResult;
    VOS_UINT8                                    aucAuthority[TAF_AUTHORITY_LEN + 1];
    VOS_UINT8                                    aucReserved1[1];
} DRV_AGENT_AUTHORITYVER_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                             stAtAppCtrl;
    DRV_AGENT_AUTHORITYID_QRY_ERROR_ENUM_UINT32 enResult;
    VOS_UINT8                                   aucAuthorityId[TAF_AUTH_ID_LEN + 1];
    VOS_UINT8                                   aucReserved1[1];
} DRV_AGENT_AUTHORITYID_QRY_CNF_STRU;


typedef struct
{
    VOS_UINT8                           aucPfVer[TAF_MAX_PROPLAT_LEN + 1];
    VOS_CHAR                            acVerTime[AT_AGENT_DRV_VERSION_TIME_LEN];
}DRV_AGENT_PFVER_INFO_STRU;


typedef struct
{
    AT_APPCTRL_STRU                       stAtAppCtrl;
    DRV_AGENT_PFVER_QRY_ERROR_ENUM_UINT32 enResult;
    DRV_AGENT_PFVER_INFO_STRU             stPfverInfo;
} DRV_AGENT_PFVER_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                               stAtAppCtrl;
    DRV_AGENT_SDLOAD_SET_ERROR_ENUM_UINT32        enResult;
} DRV_AGENT_SDLOAD_SET_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                               stAtAppCtrl;
    DRV_AGENT_DLOADVER_QRY_ERROR_ENUM_UINT32      enResult;
    VOS_CHAR                                      aucVersionInfo[TAF_MAX_VER_INFO_LEN + 1];
    VOS_UINT8                                     ucReserved1;
} DRV_AGENT_DLOADVER_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                          stAtAppCtrl;
    DRV_AGENT_GODLOAD_SET_ERROR_ENUM_UINT32  enResult;
} DRV_AGENT_GODLOAD_SET_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                          stAtAppCtrl;
    DRV_AGENT_HWNATQRY_QRY_ERROR_ENUM_UINT32 enResult;
    VOS_UINT                                 ulNetMode;
} DRV_AGENT_HWNATQRY_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                          stAtAppCtrl;
    VOS_UINT32                               ulCurCpuLoadCnt;
    VOS_UINT32                               aulCurCpuLoad[TAF_MAX_CPU_CNT];
} DRV_AGENT_CPULOAD_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;
    DRV_AGENT_MFREELOCKSIZE_QRY_ERROR_ENUM_UINT32   enResult;
    VOS_INT32                                       lMaxFreeLockSize;
}DRV_AGENT_MFREELOCKSIZE_QRY_CNF_STRU;
/* Added by ??????/f62575 for CPULOAD&MFREELOCKSIZE????????????C??, 2011/11/15, end */


typedef struct
{
    VOS_UINT32                              ulBlockCount;                       /*Block????*/
    VOS_UINT32                              ulPageSize;                         /*page??????*/
    VOS_UINT32                              ulPgCntPerBlk;                      /*????Block????page????*/
}DRV_AGENT_DLOAD_FLASH_STRU;


typedef struct
{
    AT_APPCTRL_STRU                           stAtAppCtrl;
    DRV_AGENT_FLASHINFO_QRY_ERROR_ENUM_UINT32 enResult;
    DRV_AGENT_DLOAD_FLASH_STRU                stFlashInfo;
} DRV_AGENT_FLASHINFO_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                           stAtAppCtrl;
    DRV_AGENT_AUTHVER_QRY_ERROR_ENUM_UINT32   enResult;
    VOS_UINT32                                ulSimLockVersion;
} DRV_AGENT_AUTHVER_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                          stAtAppCtrl;
    DRV_AGENT_APPDMVER_QRY_ERROR_ENUM_UINT32 enResult;
} DRV_AGENT_SDLOAD_QRY_CNF_STRU;


typedef struct
{
    VOS_UINT8                           ucType;                                 /* ????????: COMP_TYPE_I */
    VOS_UINT8                           ucMode;
    VOS_UINT8                           aucReserved[1];                         /* ???????? */
    VOS_UINT8                           ucLen;                                  /* ???????? */
    VOS_CHAR                            aucData[AT_MAX_VERSION_LEN];
} DRV_AGENT_VERSION_CTRL_STRU;




typedef struct
{
    VOS_UINT16                          usDspBand;       /*DSP????????????*/
    VOS_UINT8                           ucRxOnOff;       /* Rx on off??*/
    VOS_UINT8                           ucReserve;       /*??????*/
    VOS_UINT32                          ulSetLowBands;   /*????????????????????????*/
    VOS_UINT32                          ulSetHighBands;  /*????????????????????????*/
} AT_DRV_AGENT_RXDIV_SET_STRU;

typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;        /*??????*/
    VOS_UINT32                          ulResult;           /*????????*/
    VOS_UINT8                           ucRxOnOff;          /*RX????????????*/
    VOS_UINT8                           ucReserve;          /*??????*/
    VOS_UINT16                          usSetDivBands;      /*????????BAND*/
} DRV_AGENT_AT_RXDIV_CNF_STRU;

typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;        /*??????*/
    VOS_UINT32                          ulResult;           /*????????*/
    VOS_UINT16                          usDrvDivBands;      /*??????BAND*/
    VOS_UINT16                          usCurBandSwitch;    /*??????????BAND*/
} DRV_AGENT_QRY_RXDIV_CNF_STRU;


typedef struct
{
    VOS_UINT32                          ulPwdLen;
    VOS_UINT8                           aucPwd[TAF_PH_ME_PERSONALISATION_PWD_LEN_MAX +4];
}DRV_AGENT_SIMLOCK_SET_REQ_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;                            /*??????*/
    VOS_UINT32                          ulResult;                               /*????????*/
}DRV_AGENT_SET_SIMLOCK_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;                            /*??????*/
    VOS_UINT32                          ulResult;                               /*????????*/
    VOS_UINT8                           aucHwVer[DRV_AGENT_MAX_HARDWARE_LEN+1]; /*??????????*/
} DRV_AGENT_HARDWARE_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;                                        /*??????*/
    VOS_UINT32                          ulResult;                                           /*????????*/
    VOS_UINT8                           aucModelId[DRV_AGENT_MAX_MODEL_ID_LEN + 1];         /*MODE ID??*/
    VOS_UINT8                           aucRevisionId[DRV_AGENT_MAX_REVISION_ID_LEN + 1];   /*??????????*/
    VOS_UINT8                           aucHwVer[DRV_AGENT_MAX_HARDWARE_LEN+1];             /*??????????*/
} DRV_AGENT_FULL_HARDWARE_QRY_CNF_STRU;



typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;                            /*??????*/
    VOS_UINT32                          ulResult;                               /*????????*/
} DRV_AGENT_NVRESTORE_RST_STRU;


#define AT_SD_DATA_UNIT_LEN             (512)
#define AT_GPIOPL_MAX_LEN               (20)



typedef struct
{
    VOS_UINT32                          enGpioOper;
    VOS_UINT8                           aucGpiopl[AT_GPIOPL_MAX_LEN];

}DRV_AGENT_GPIOPL_SET_REQ_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_BOOL                            bFail;

}DRV_AGENT_GPIOPL_SET_CNF_STRU;



typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_BOOL                            bFail;
    VOS_UINT8                           aucGpiopl[AT_GPIOPL_MAX_LEN];

}DRV_AGENT_GPIOPL_QRY_CNF_STRU;


typedef struct
{
    VOS_UINT8                           aucPwd[TAF_PH_ME_PERSONALISATION_PWD_LEN_MAX +1];

}DRV_AGENT_DATALOCK_SET_REQ_STRU;



typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_BOOL                            bFail;           /* DATALOCK???????????? */

}DRV_AGENT_DATALOCK_SET_CNF_STRU;


typedef struct
{

    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_BOOL                            bFail;
    VOS_INT32                           lBatVol;

}DRV_AGENT_TBATVOLT_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_BOOL                            bFail;

}DRV_AGENT_TMODE_SET_CNF_STRU;


enum DRV_AGENT_VERSION_QRY_ERROR_ENUM
{
    DRV_AGENT_VERSION_QRY_NO_ERROR              = 0,
    DRV_AGENT_VERSION_QRY_VERTIME_ERROR         = 1,

    DRV_AGENT_VERSION_QRY_BUTT
};
typedef VOS_UINT32 DRV_AGENT_VERSION_QRY_ERROR_ENUM_UINT32;



typedef struct
{
    AT_APPCTRL_STRU                          stAtAppCtrl;
    TAF_PH_REVISION_ID_STRU                  stSoftVersion;                                 /*??????????*/
    TAF_PH_HW_VER_STRU                       stFullHwVer;                                   /*??????????????*/
    TAF_PH_HW_VER_STRU                       stInterHwVer;                                  /*??????????????*/
    TAF_PH_MODEL_ID_STRU                     stModelId;                                     /*????????ID */
    TAF_PH_MODEL_ID_STRU                     stInterModelId;                                /*????????ID */
    TAF_PH_CDROM_VER_STRU                    stIsoVer;                                      /*??????????????*/
    DRV_AGENT_VERSION_QRY_ERROR_ENUM_UINT32  enResult;                                      /*?????????? */
    VOS_CHAR                                 acVerTime[AT_AGENT_DRV_VERSION_TIME_LEN];      /*????????*/

}DRV_AGENT_VERSION_QRY_CNF_STRU;


typedef struct
{
    VOS_UINT32                          BandWCDMA_I_2100      :1;
    VOS_UINT32                          BandWCDMA_II_1900     :1;
    VOS_UINT32                          BandWCDMA_III_1800    :1;
    VOS_UINT32                          BandWCDMA_IV_1700     :1;
    VOS_UINT32                          BandWCDMA_V_850       :1;
    VOS_UINT32                          BandWCDMA_VI_800      :1;
    VOS_UINT32                          BandWCDMA_VII_2600    :1;
    VOS_UINT32                          BandWCDMA_VIII_900    :1;
    VOS_UINT32                          BandWCDMA_IX_J1700    :1;
    VOS_UINT32                          BandSpare1            :1;
    VOS_UINT32                          BandWCDMA_XI_1500     :1;
    VOS_UINT32                          BandSpare7            :7;
    VOS_UINT32                          BandWCDMA_XIX_850     :1;
    VOS_UINT32                          BandSpare13           :13;
}AT_WCDMA_PREF_BAND_STRU;


typedef struct
{
    VOS_UINT32                          BandGsm450      :1;
    VOS_UINT32                          BandGsm480      :1;
    VOS_UINT32                          BandGsm850      :1;
    VOS_UINT32                          BandGsmP900     :1;
    VOS_UINT32                          BandGsmR900     :1;
    VOS_UINT32                          BandGsmE900     :1;
    VOS_UINT32                          BandGsm1800     :1;
    VOS_UINT32                          BandGsm1900     :1;
    VOS_UINT32                          BandGsm700      :1;
    VOS_UINT32                          BandSpare7      :23;

}AT_GSM_PREF_BAND_STRU;


typedef union
{
    VOS_UINT32                          ulBand;
    AT_WCDMA_PREF_BAND_STRU             BitBand;
}AT_WCDMA_BAND_SET_UN;


typedef union
{
    VOS_UINT32                          ulBand;
    AT_GSM_PREF_BAND_STRU               BitBand;
}AT_GSM_BAND_SET_UN;



typedef struct
{
    VOS_UINT32                          ulUeGSptBand;
    VOS_UINT32                          ulUeWSptBand;
    VOS_UINT32                          ulAllUeBand;
    AT_WCDMA_BAND_SET_UN                unWRFSptBand;
    AT_GSM_BAND_SET_UN                  unGRFSptBand;
}AT_UE_BAND_CAPA_ST;

#ifndef MBB_COMMON

enum AT_FEATURE_DRV_TYPE_ENUM
{
    AT_FEATURE_LTE = 0,
    AT_FEATURE_HSPAPLUS,
    AT_FEATURE_HSDPA,
    AT_FEATURE_HSUPA,
    AT_FEATURE_DIVERSITY,
    AT_FEATURE_UMTS,
    AT_FEATURE_EVDO,
    AT_FEATURE_EDGE,
    AT_FEATURE_GPRS,
    AT_FEATURE_GSM,
    AT_FEATURE_CDMA,
    AT_FEATURE_WIMAX,
    AT_FEATURE_WIFI,
    AT_FEATURE_GPS,
    AT_FEATURE_TDSCDMA
};
typedef VOS_UINT32  AT_FEATURE_DRV_TYPE_ENUM_UINT32;

#define AT_FEATURE_NAME_LEN_MAX       (16)
#endif

#define AT_FEATURE_CONTENT_LEN_MAX    (56)



typedef struct
{
    VOS_UINT8        ucFeatureFlag;
    VOS_UINT8        aucFeatureName[AT_FEATURE_NAME_LEN_MAX];
    VOS_UINT8        aucContent[AT_FEATURE_CONTENT_LEN_MAX];
}AT_FEATURE_SUPPORT_ST;


typedef struct
{
    VOS_UINT8                           ucPowerClass;       /* UE????????                      */
    VOS_UINT8                           enTxRxFreqSeparate; /* Tx/Rx ????????                  */
    VOS_UINT8                           aucReserve1[2];     /* 4??????????????                 */
} AT_RF_CAPA_STRU;



typedef struct
{
    VOS_UINT32                          ulHspaStatus;       /* 0??????????,????DPA??UPA??????;1????????           */
    VOS_UINT8                           ucMacEhsSupport;
    VOS_UINT8                           ucHSDSCHPhyCat;
    VOS_UINT8                           aucReserve1[2];     /* ??????????????ulHspaStatus???????????????????????? */
    AT_RF_CAPA_STRU                     stRfCapa;           /* RF ????????  */
    VOS_UINT8                           enDlSimulHsDschCfg; /* ENUMERATED  OPTIONAL  */
    VOS_UINT8                           enAsRelIndicator;   /* Access Stratum Release Indicator  */
    VOS_UINT8                           ucHSDSCHPhyCategory; /* ????HS-DSCH???????????????? */
    VOS_UINT8                           enEDCHSupport;       /* ????????EDCH?????? */
    VOS_UINT8                           ucEDCHPhyCategory;   /* ????UPA?????? */
    VOS_UINT8                           enFDPCHSupport;      /* ????????FDPCH??????  */
    VOS_UINT8                           ucV690Container;     /* V690Container???? */
    VOS_UINT8                           enHSDSCHSupport;     /* ????????enHSDSCHSupport??????  */
} AT_UE_CAPA_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    AT_UE_BAND_CAPA_ST                  stBandFeature;

}DRV_AGENT_SFEATURE_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_BOOL                            bFail;
}DRV_AGENT_SECUBOOT_SET_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_BOOL                            bFail;
    VOS_UINT8                           ucSecuBootEnable;
    VOS_UINT8                           aucReserve1[3];                          /* 4?????????????? */
}DRV_AGENT_SECUBOOT_QRY_CNF_STRU;



typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_BOOL                            bFail;
    VOS_UINT8                           ucSecuBootFeature;
    VOS_UINT8                           aucReserve1[7];                          /* 4?????????????? */
}DRV_AGENT_SECUBOOTFEATURE_QRY_CNF_STRU;


enum AT_DEVICE_CMD_BAND_ENUM
{
    AT_BAND_2100M = 0,
    AT_BAND_1900M,
    AT_BAND_1800M,
    AT_BAND_1700M,
    AT_BAND_1600M,
    AT_BAND_1500M,
    AT_BAND_900M,
    AT_BAND_850M,
    AT_BAND_800M,
    AT_BAND_450M,
    AT_BAND_2600M,
    AT_BAND_1X_BC0,
    AT_BAND_WIFI = 15,
    AT_BAND_BUTT
};
typedef VOS_UINT8 AT_DEVICE_CMD_BAND_ENUM_UINT8;


typedef struct
{
    VOS_UINT16                          usUlArfcn;  /*??????Channel No*/
    VOS_UINT16                          usDlArfcn;  /*??????Channel No*/
    VOS_UINT16                          usDspBand;  /*DSP????????????*/
    VOS_UINT8                           aucReserved[2];
}AT_DSP_BAND_ARFCN_STRU;


typedef struct
{
    VOS_UINT16             usArfcnMin;
    VOS_UINT16             usArfcnMax;
}AT_ARFCN_RANGE_STRU;


enum AT_TMODE_ENUM
{
    AT_TMODE_NORMAL = 0,   /*????????,????????????*/
    AT_TMODE_FTM ,         /*??????????,????????*/
    AT_TMODE_UPGRADE ,     /*????????,?????????????? */
    AT_TMODE_RESET,        /* ????????  */
    AT_TMODE_POWEROFF,
    AT_TMODE_SIGNALING = 11,
    AT_TMODE_OFFLINE,
#if((FEATURE_ON == FEATURE_LTE) || (FEATURE_ON == FEATURE_UE_MODE_TDS))
    AT_TMODE_F_NONESIGNAL   = 13,
    AT_TMODE_SYN_NONESIGNAL = 14,
    AT_TMODE_SET_SLAVE      = 15,
    AT_TMODE_GU_BT          = 16,
    AT_TMODE_TDS_FAST_CT    = 17,
    AT_TMODE_TDS_BT         = 18,
    AT_TMODE_COMM_CT        = 19,
#endif
    AT_TMODE_BUTT
};
typedef VOS_UINT8  TAF_PH_TMODE_ENUM_UINT8;


typedef struct
{
    VOS_UINT8                           ucLoadDspMode;
    VOS_UINT8                           ucCurrentDspMode;
    VOS_UINT16                          usChannelNo;
    AT_DEVICE_CMD_RAT_MODE_ENUM_UINT8   ucDeviceRatMode;
    AT_DEVICE_CMD_BAND_ENUM_UINT8       ucDeviceAtBand;
    VOS_UINT8                           aucReserved[2];
    VOS_BOOL                            bDspLoadFlag;
    AT_DSP_BAND_ARFCN_STRU              stDspBandArfcn;
}DRV_AGENT_FCHAN_SET_REQ_STRU;



enum DRV_AGENT_FCHAN_SET_ERROR_ENUM
{
    DRV_AGENT_FCHAN_SET_NO_ERROR                            = 0,
    DRV_AGENT_FCHAN_BAND_NOT_MATCH                          = 1,
    DRV_AGENT_FCHAN_BAND_CHANNEL_NOT_MATCH                  = 2,
    DRV_AGENT_FCHAN_OTHER_ERR                               = 3,

    DRV_AGENT_FCHAN_SET_BUTT
};
typedef VOS_UINT32 DRV_AGENT_FCHAN_SET_ERROR_ENUM_UINT32;



typedef struct
{
    AT_APPCTRL_STRU                       stAtAppCtrl;
    DRV_AGENT_FCHAN_SET_REQ_STRU          stFchanSetReq;
    DRV_AGENT_FCHAN_SET_ERROR_ENUM_UINT32 enResult;

}DRV_AGENT_FCHAN_SET_CNF_STRU;



#define AT_MS_SUPPORT_RX_DIV_2100           0x0001
#define AT_MS_SUPPORT_RX_DIV_1900           0x0002
#define AT_MS_SUPPORT_RX_DIV_1800           0x0004
#define AT_MS_SUPPORT_RX_DIV_AWS_1700       0x0008
#define AT_MS_SUPPORT_RX_DIV_850            0x0010
#define AT_MS_SUPPORT_RX_DIV_800            0x0020
#define AT_MS_SUPPORT_RX_DIV_2600           0x0040
#define AT_MS_SUPPORT_RX_DIV_900            0x0080
#define AT_MS_SUPPORT_RX_DIV_IX_1700        0x0100



enum AT_DSP_RF_ON_OFF_ENUM
{
    AT_DSP_RF_SWITCH_OFF = 0,
    AT_DSP_RF_SWITCH_ON,
    AT_DSP_RF_SWITCH_BUTT
};
typedef VOS_UINT8 AT_DSP_RF_ON_OFF_ENUM_UINT8;


enum AT_DSP_CLT_ENABLE_ENUM
{
    AT_DSP_CLT_DISABLE = 0,
    AT_DSP_CLT_ENABLE,

    AT_DSP_CLT_BUTT
};
typedef VOS_UINT8 AT_DSP_CLT_ENABLE_ENUM_UINT8;


enum AT_DCXOTEMPCOMP_ENABLE_ENUM
{
    AT_DCXOTEMPCOMP_DISABLE = 0,
    AT_DCXOTEMPCOMP_ENABLE,

    AT_DCXOTEMPCOMP_BUTT
};
typedef VOS_UINT8 AT_DCXOTEMPCOMP_ENABLE_ENUM_UINT8;

typedef struct
{
    VOS_PID                             ulPid;
    VOS_UINT32                          ulMsgPeakSize;
    VOS_UINT32                          ulMemPeakSize;
}AT_PID_MEM_INFO_PARA_STRU;


typedef struct
{
    VOS_UINT32                          ulSetLowBands;
    VOS_UINT32                          ulSetHighBands;
    AT_DSP_BAND_ARFCN_STRU              stDspBandArfcn;
}DRV_AGENT_RXPRI_SET_REQ_STRU;



typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    DRV_AGENT_ERROR_ENUM_UINT32         enResult;
    DRV_AGENT_RXPRI_SET_REQ_STRU        stRxpriSetReq;
    VOS_UINT16                          usWPriBands;
    VOS_UINT16                          usGPriBands;
    VOS_UINT16                          usSetPriBands;
    VOS_UINT8                           aucReserved[2];
}DRV_AGENT_RXPRI_SET_CNF_STRU;



typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT32                          ulProdType;

}DRV_AGENT_PRODTYPE_QRY_CNF_STRU;



typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT32                          ulTbatType;

}DRV_AGENT_TBAT_QRY_CNF_STRU;



typedef struct
{
    AT_APPCTRL_STRU                      stAtAppCtrl;
    VOS_UINT16                           usWDrvPriBands;
    VOS_UINT16                           usGDrvPriBands;
    VOS_BOOL                             bFail;
}DRV_AGENT_RXPRI_QRY_CNF_STRU;


typedef struct
{
    VOS_UINT32                  ulIsEnable;           /*????????????????????, 0????????1??????*/
    VOS_INT32                   lCloseAdcThreshold;   /*????????????????????????*/
    VOS_INT32                   lAlarmAdcThreshold;   /*??????????????????????????*/
    VOS_INT32                   lResumeAdcThreshold;  /*????????????????????????*/
}SPY_TEMP_THRESHOLD_PARA_STRU;


typedef struct
{
    AT_APPCTRL_STRU                        stAtAppCtrl;
    VOS_BOOL                               bFail;

}DRV_AGENT_ADC_SET_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT8                           ucLen;
    VOS_UINT8                           aucReserved[2];
    VOS_CHAR                            aucData[AT_AGENT_DRV_VERSION_TIME_LEN+1];
} DRV_AGENT_VERSION_TIME_STRU;

/*****************************************************************************
 ??????    : DRV_AGENT_YJCX_SET_CNF_STRU
 ????????  : AT??AT AGENT AT^YJCX????????????????
*****************************************************************************/
typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT32                          ulResult;
    VOS_UCHAR                           aucflashInfo[TAF_MAX_FLAFH_INFO_LEN + 1];
} DRV_AGENT_YJCX_SET_CNF_STRU;

/*****************************************************************************
 ??????    : DRV_AGENT_YJCX_QRY_CNF_STRU
 ????????  : AT??AT AGENT AT^YJCX????????????????
*****************************************************************************/
typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT32                          ulResult;
    VOS_UCHAR                           aucgpioInfo[TAF_MAX_GPIO_INFO_LEN + 1];
    VOS_UINT8                           aucReserved[3];
} DRV_AGENT_YJCX_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT32                          ulCurImsiSign;
    VOS_UINT16                          usDualIMSIEnable;
    VOS_UINT8                           aucReserved[2];
}DRV_AGENT_IMSICHG_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT32                          ulRslt;
}DRV_AGENT_INFORBU_SET_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT32                          ulRslt;
}DRV_AGENT_INFORRS_SET_CNF_STRU;



typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_BOOL                            bNormalSrvStatus;
    VOS_UINT32                          ulPnnExistFlg;
    VOS_UINT32                          ulOplExistFlg;

}DRV_AGENT_CPNN_TEST_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT32                          ulRslt;
}DRV_AGENT_NVBACKUP_SET_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_BOOL                            bNormalSrvStatus;
}DRV_AGENT_CPNN_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                         stAtAppCtrl;
    VOS_UINT32                              ulResult;
    AT_MEMQUERY_PARA_ENUM_UINT32            ulMemQryType;                       /* ????????????0:VOS????, 1: TTF???? */
    VOS_UINT32                              ulPidNum;                           /* PID?????? */
    VOS_UINT8                               aucData[4];                         /* ????PID?????????????? */
}DRV_AGENT_MEMINFO_QRY_RSP_STRU;


typedef struct
{
    AT_APPCTRL_STRU                         stAtAppCtrl;
    DRV_AGENT_TSELRF_SET_ERROR_ENUM_UINT32  enResult;
    VOS_UINT8                               ucDeviceRatMode;
    VOS_UINT8                               aucReserved[3];
}DRV_AGENT_TSELRF_SET_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                             stAtAppCtrl;
    DRV_AGENT_HKADC_GET_ERROR_ENUM_UINT32  enResult;
    VOS_INT32                                                   TbatHkadc;
}DRV_AGENT_HKADC_GET_CNF_STRU;



#if (FEATURE_ON == FEATURE_SECURITY_SHELL)

typedef struct
{
    VOS_CHAR                            acShellPwd[AT_SHELL_PWD_LEN];
}DRV_AGENT_SPWORD_SET_REQ_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT32                          ulResult;
}DRV_AGENT_SPWORD_SET_CNF_STRU;
#endif


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;                            /* ?????? */
    VOS_UINT32                          ulResult;                               /* ???????? */
    VOS_UINT32                          ulNvBackupStat;                         /* NV???????? */
}DRV_AGENT_NVBACKUPSTAT_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;                            /* ?????? */
    VOS_UINT32                          ulResult;                               /* ???????? */
    VOS_UINT32                          ulBadBlockNum;                          /* ???????? */
    VOS_UINT32                          aulBadBlockIndex[0]; //lint !e43                 /* ?????????? */
} DRV_AGENT_NANDBBC_QRY_CNF_STRU;



#define DRV_AGENT_NAND_MFU_NAME_MAX_LEN     16                                  /* ???????????????? */
#define DRV_AGENT_NAND_DEV_SPEC_MAX_LEN     32                                  /* ???????????????? */

typedef struct
{
    VOS_UINT32      ulMufId;                                                    /* ????ID */
    VOS_UINT8       aucMufName[DRV_AGENT_NAND_MFU_NAME_MAX_LEN];                /* ?????????????? */
    VOS_UINT32      ulDevId;                                                    /* ????ID */
    VOS_UINT8       aucDevSpec[DRV_AGENT_NAND_DEV_SPEC_MAX_LEN];                /* ?????????????? */
} DRV_AGENT_NAND_DEV_INFO_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;                 /* ?????? */
    VOS_UINT32                          ulResult;                    /* ???????? */
    DRV_AGENT_NAND_DEV_INFO_STRU        stNandDevInfo;               /* ???????? */
} DRV_AGENT_NANDVER_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;                 /* ?????? */
    VOS_UINT32                          ulResult;                    /* ???????? */
    VOS_INT                             lGpaTemp;                    /* G PA???? */
    VOS_INT                             lWpaTemp;                    /* W PA???? */
    VOS_INT                             lLpaTemp;                    /* L PA???? */
    VOS_INT                             lSimTemp;                    /* SIM?????? */
    VOS_INT                             lBatTemp;                    /* ???????? */
} DRV_AGENT_CHIPTEMP_QRY_CNF_STRU;






typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;                 /* ?????? */
    VOS_UINT16                          usAntState;
    VOS_UINT8                           aucRsv[2];
} DRV_AGENT_ANT_STATE_IND_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT32                          ulResult;
}DRV_AGENT_MAX_LOCK_TMS_SET_CNF_STRU;


typedef struct
{
    VOS_UINT32                          ulUsimState;
}DRV_AGENT_AP_SIMST_SET_REQ_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT32                          ulResult;
}DRV_AGENT_AP_SIMST_SET_CNF_STRU;



typedef struct
{
    VOS_UINT8                           aucHUK[DRV_AGENT_HUK_LEN];  /* HUK???? 128Bits */
}DRV_AGENT_HUK_SET_REQ_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
}DRV_AGENT_HUK_SET_CNF_STRU;



typedef struct
{
    /* ???????????? */
    VOS_UINT8                           aucPubKey[DRV_AGENT_PUBKEY_LEN];
    /* ????????SSK???????? */
    VOS_UINT8                           aucPubKeySign[DRV_AGENT_PUBKEY_SIGNATURE_LEN];
}DRV_AGENT_FACAUTHPUBKEY_SET_REQ_STRU;


typedef struct
{
    VOS_UINT8                           ucNetWorkFlg;                       /* 1: ???????? 0: ???????? */
    VOS_UINT8                           ucLayer;
    VOS_UINT8                           aucReserve[2];
    VOS_UINT32                          ulTotal;                                /* ?????????????? */
    VOS_UINT32                          ulHmacLen;
    VOS_UINT32                          ulSimlockDataLen;
    VOS_UINT8                           aucHmac[DRV_AGENT_HMAC_DATA_LEN];
    VOS_UINT8                           aucSimlockData[4];
}DRV_AGENT_SIMLOCKWRITEEX_SET_REQ_STRU;


typedef struct
{
    VOS_UINT32                                      ulTotal;                    /* ?????????? */
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
}DRV_AGENT_SIMLOCKWRITEEX_SET_CNF_STRU;


typedef struct
{
    VOS_UINT8                           ucLayer;        /* ?????????? */
    VOS_UINT8                           ucIndex;        /* ?????????? */
}DRV_AGENT_SIMLOCKDATAREADEX_READ_REQ_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;                /* ?????? */
    VOS_UINT32                          ulResult;
    VOS_UINT8                           ucLayer;        /* ?????????? */
    VOS_UINT8                           ucIndex;        /* ?????????? */
    VOS_UINT8                           ucTotal;        /* ???????????? */
    VOS_UINT8                           ucReserve;
    VOS_UINT32                          ulDataLen;      /* ???????????? */
    VOS_UINT8                           aucData[4];     /* ???? */
}DRV_AGENT_SIMLOCKDATAREADEX_READ_CNF_STRU;



typedef struct
{
    VOS_UINT8                           aucPara[DRV_AGENT_PUBKEY_LEN];
}DRV_AGENT_FACAUTHPUBKEYEX_SET_REQ_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
}DRV_AGENT_FACAUTHPUBKEY_SET_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
    /* ????????????RSA???????????? */
    VOS_UINT8                                       aucRsaText[DRV_AGENT_RSA_CIPHERTEXT_LEN];
}DRV_AGENT_IDENTIFYSTART_SET_CNF_STRU;


typedef struct
{
    /* ????????????RSA???????????? */
    VOS_UINT8                           aucRsaText[DRV_AGENT_RSA_CIPHERTEXT_LEN];
}DRV_AGENT_IDENTIFYEND_SET_REQ_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
}DRV_AGENT_IDENTIFYEND_SET_CNF_STRU;




typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
}DRV_AGENT_SIMLOCKDATAWRITE_SET_CNF_STRU;


typedef struct
{
   VOS_UINT8        aucPhLockCodeBegin[DRV_AGENT_PH_LOCK_CODE_LEN_EXTERNED];
   VOS_UINT8        aucPhLockCodeEnd[DRV_AGENT_PH_LOCK_CODE_LEN_EXTERNED];
}DRV_AGENT_PH_LOCK_CODE_NEW_STRU;


typedef struct
{
   VOS_UINT8        aucPhLockCodeBegin[DRV_AGENT_PH_LOCK_CODE_LEN];
   VOS_UINT8        aucPhLockCodeEnd[DRV_AGENT_PH_LOCK_CODE_LEN];
}DRV_AGENT_PH_LOCK_CODE_STRU;


typedef struct
{
    DRV_AGENT_PERSONALIZATION_CATEGORY_ENUM_UINT8           enCategory;             /* ??????????category???? */
    DRV_AGENT_PERSONALIZATION_INDICATOR_ENUM_UINT8          enIndicator;            /* ?????????????????? */
    DRV_AGENT_PERSONALIZATION_STATUS_ENUM_UINT8             enStatus;
    VOS_UINT8                                               ucMaxUnlockTimes;       /* ?????????????????????? */
    VOS_UINT8                                               ucRemainUnlockTimes;    /* ?????????????????????? */
    VOS_UINT8                                               aucRsv[3];              /* ???????????????????????? */
}DRV_AGENT_SIMLOCK_DATA_CATEGORY_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
    VOS_UINT8                                       ucSupportCategoryNum;       /* ????category???? */
    VOS_UINT8                                       aucRsv[3];              /* ???????????????????????? */

    /* ????????3??category????????????????network->network subset->SP?????????? */
    DRV_AGENT_SIMLOCK_DATA_CATEGORY_STRU            astCategoryData[DRV_AGENT_SUPPORT_CATEGORY_NUM];
}DRV_AGENT_SIMLOCKDATAREAD_QRY_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
    /* ????????4??category????????????????network->network subset->SP->CP?????????? */
    DRV_AGENT_SIMLOCK_DATA_CATEGORY_STRU            astCategoryData[DRV_AGENT_SUPPORT_CATEGORY_NUM];
}DRV_AGENT_SIMLOCKDATAREAD_QRY_CNF_EX_STRU;


typedef struct
{
    DRV_AGENT_PERSONALIZATION_CATEGORY_ENUM_UINT8           enCategory;             /* ??????????category???? */
    DRV_AGENT_PERSONALIZATION_INDICATOR_ENUM_UINT8          enIndicator;            /* ?????????????????? */
    VOS_UINT8                                               ucFlag;                 /* 0: ?????? 1: ?????? */
    VOS_UINT8                                               ucRsv;                  /* 4????????, ?????? */
    VOS_UINT32                                              ulGroupNum;             /* ??????????????begin/end?????????? */
    DRV_AGENT_PH_LOCK_CODE_NEW_STRU                         astLockCode[DRV_AGENT_PH_LOCK_CODE_GROUP_NUM_EXTERED];      /* ??????????????????*/
}DRV_AGENT_SIMLOCK_INFO_CATEGORY_NEW_STRU;


typedef struct
{
    DRV_AGENT_PERSONALIZATION_CATEGORY_ENUM_UINT8           enCategory;             /* ??????????category???? */
    DRV_AGENT_PERSONALIZATION_INDICATOR_ENUM_UINT8          enIndicator;            /* ?????????????????? */
    VOS_UINT8                                               ucGroupNum;             /* ??????????????begin/end?????????? */
    VOS_UINT8                                               ucRsv;                  /* 4????????, ?????? */
    /* ??????????????????*/
    DRV_AGENT_PH_LOCK_CODE_STRU                             astLockCode[DRV_AGENT_PH_LOCK_CODE_GROUP_NUM];
}DRV_AGENT_SIMLOCK_INFO_CATEGORY_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
    VOS_UINT8                                       ucSupportCategoryNum;       /* ????category???? */
    VOS_UINT8                                       aucReserve[3];
    DRV_AGENT_SIMLOCK_INFO_CATEGORY_NEW_STRU        astCategoryInfo[DRV_AGENT_SUPPORT_CATEGORY_NUM_EXTERED];
}DRV_AGENT_PHONESIMLOCKINFO_QRY_CNF_NEW_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */

    /* ????????3??category????????????????network->network subset->SP?????????? */
    DRV_AGENT_SIMLOCK_INFO_CATEGORY_STRU            astCategoryInfo[DRV_AGENT_SUPPORT_CATEGORY_NUM];
}DRV_AGENT_PHONESIMLOCKINFO_QRY_CNF_STRU;


typedef struct
{
    DRV_AGENT_PH_PHYNUM_TYPE_ENUM_UINT8 enPhynumType;                                   /* ?????????? */
    VOS_UINT8                           aucReserve[3];
    VOS_UINT8                           aucPhynumValue[DRV_AGENT_RSA_CIPHERTEXT_LEN];   /* ??????RSA???????? */
    VOS_UINT32                          ulRsaIMEILen;                                   /* Rsa???????????????? */
    VOS_UINT8                           aucHmacData[DRV_AGENT_HMAC_DATA_LEN];           /* hmac???? */
    VOS_UINT32                          ulHmacLen;                                      /* hmac???????? */
}DRV_AGENT_PHONEPHYNUM_SET_REQ_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
}DRV_AGENT_PHONEPHYNUM_SET_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
    VOS_UINT8                                       aucImeiRsa[DRV_AGENT_RSA_CIPHERTEXT_LEN];
    VOS_UINT8                                       aucSnRsa[DRV_AGENT_RSA_CIPHERTEXT_LEN];
}DRV_AGENT_PHONEPHYNUM_QRY_CNF_STRU;




typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
}DRV_AGENT_PORTCTRLTMP_SET_CNF_STRU;




typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
}DRV_AGENT_PORTATTRIBSET_SET_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
    DRV_AGENT_PORT_STATUS_ENUM_UINT32               enPortStatus;               /* ???????????? */
}DRV_AGENT_PORTATTRIBSET_QRY_CNF_STRU;



typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32       enResult;                   /* ???????????? */
}DRV_AGENT_OPWORD_SET_CNF_STRU;



typedef struct
{
    DRV_AGENT_DH_KEY_TYPE_ENUM_UINT32   enKeyType;                              /* DH???????? */
    VOS_UINT32                          ulKeyLen;                               /* DH???????? */
    VOS_UINT8                           aucKey[DRV_AGENT_DH_PUBLICKEY_LEN];     /* DH?????????????????????????????????????????????????? */
}DRV_AGENT_HVPDH_REQ_STRU;


typedef struct
{
    AT_APPCTRL_STRU                                 stAtAppCtrl;                /* ?????? */
    DRV_AGENT_HVPDH_ERR_ENUM_UINT32                 enResult;                   /* ???????????? */
}DRV_AGENT_HVPDH_CNF_STRU;
/* Added by L47619 for V9R1 vSIM Project, 2013-8-27, end */


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT32                          ulRslt;
}DRV_AGENT_NVMANUFACTUREEXT_SET_CNF_STRU;


typedef struct
{
    AT_APPCTRL_STRU                     stAtAppCtrl;
    VOS_UINT32                          ulChkPoolLeakRslt;
    VOS_UINT32                          ulChkNodeLeakRslt;
    VOS_UINT32                          ulChkRrmNodeLeakRslt;
}DRV_AGENT_QRY_CCPU_MEM_INFO_CNF_STRU;

/*****************************************************************************
  8 UNION????
*****************************************************************************/


/*****************************************************************************
  9 OTHERS????
*****************************************************************************/
/*****************************************************************************
  H2ASN????????????????
*****************************************************************************/
typedef struct
{
    DRV_AGENT_MSG_TYPE_ENUM_UINT32      ulMsgId;   /*_H2ASN_MsgChoice_Export DRV_AGENT_MSG_TYPE_ENUM_UINT32*/
    VOS_UINT8                           aucMsgBlock[4];
    /***************************************************************************
        _H2ASN_MsgChoice_When_Comment          DRV_AGENT_MSG_TYPE_ENUM_UINT32
    ****************************************************************************/
}DRV_AGENT_MSG_DATA;
/*_H2ASN_Length UINT32*/

typedef struct
{
    VOS_MSG_HEADER
    DRV_AGENT_MSG_DATA                  stMsgData;
}TafDrvAgent_MSG;



typedef struct
{
    VOS_UINT8                           aucSWVer[TAF_MAX_REVISION_ID_LEN + 1];
    VOS_CHAR                            acVerTime[AT_AGENT_DRV_VERSION_TIME_LEN];
}DRV_AGENT_SWVER_INFO_STRU;



typedef struct
{
    AT_APPCTRL_STRU                       stAtAppCtrl;
    DRV_AGENT_ERROR_ENUM_UINT32           enResult;
    DRV_AGENT_SWVER_INFO_STRU             stSwverInfo;
} DRV_AGENT_SWVER_SET_CNF_STRU;


typedef struct
{
    VOS_UINT16                         *pusDrvAgentUsimTempTable;           /* SIM hkadc?????? */
    VOS_UINT16                         *pusDrvAgentBatTempTable;            /* Battery hkadc?????? */
    VOS_UINT16                         *pusDrvAgentAdcTable;                /* PA hkadc?????? */
    VOS_UINT8                           ucDrvAgentSystemAppConfigAddr;      /* DrvAgent???????????????? */
    VOS_UINT8                           ucGcfInd;                           /* ??????????????GCF???? */
    VOS_UINT8                           ucSimLockErrTimes;                  /* ????SIMLOCK?????????????????? */
    VOS_UINT8                           aucReserve[5];                      /* PCLINT-64 ????8???????? */
} DRV_AGENT_CONTEXT_STRU;

/*****************************************************************************
  10 ????????
*****************************************************************************/

extern DRV_AGENT_CONTEXT_STRU* DRVAGENT_GetCtxAddr(VOS_VOID);

extern VOS_VOID MMA_GetProductionVersion(VOS_CHAR *pcDest);
extern VOS_UINT32 AT_GetWcdmaBandStr(VOS_UINT8 *pucGsmBandstr, AT_UE_BAND_CAPA_ST *pstBandCapa);
extern VOS_UINT32 AT_GetGsmBandStr(VOS_UINT8 *pucGsmBandstr , AT_UE_BAND_CAPA_ST *pstBandCapa);
extern VOS_UINT32 At_SendRfCfgAntSelToHPA(
    VOS_UINT8                           ucDivOrPriOn,
    VOS_UINT8                           ucIndex
);
extern VOS_UINT32 At_DelCtlAndBlankCharWithEndPadding(VOS_UINT8 *pucData, VOS_UINT16  *pusCmdLen);
extern VOS_UINT32 Spy_SetTempPara(SPY_TEMP_THRESHOLD_PARA_STRU *stTempPara);

#if (FEATURE_ON == FEATURE_LTE)
extern VOS_VOID L_ExtSarPowerReductionPRI(MODEM_ID_ENUM_UINT16 enModemId, VOS_UINT32 para);
#endif

#if (VOS_RTOSCK == VOS_OS_VER)
//extern VOS_UINT32 SRE_GetMaxNumberOfCores(VOS_VOID);
extern VOS_UINT32 SRE_CpuUsageGet(VOS_UINT32 uwCoreId);
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

#endif /* end of TafDrvAgent.h */
