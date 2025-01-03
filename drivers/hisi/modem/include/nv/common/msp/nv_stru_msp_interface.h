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


#ifndef __MSP_NV_DEF_INTE_H__
#define __MSP_NV_DEF_INTE_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#include "vos.h"

/****************guc_phy??????????????????tf AT???? star**********************/
typedef enum{
    /*guc_phy??????????????????tf AT???? star*/
    en_NV_Item_WG_RF_MAIN_BAND           = 10000,  //NAS_NVIM_WG_RF_MAIN_BAND_STRU
    en_NV_Item_W_RF_DIV_BAND             = 10001,  //UCOM_NV_W_RF_DIV_BAND_STRU
    en_NV_Item_DCXO_C_TRIM               = 10023,  //dcxo for ap nv same as ccore_nv_id_guc_phy.h
    en_NV_Item_RF_SAR_BACKOFF_TESTMODE   = 10029,  //UCOM_NV_SAR_BACKOFF_TEST_MODE_STRU
    en_NV_Item_DCXO_C2_FIX               = 10071,  //dcxo for ap nv same as ccore_nv_id_guc_phy.h
    en_NV_Item_TRI_MODE_ENABLE           = 10073,  //UCOM_NV_TRI_MODE_ENABLE_STRU
    en_NV_Item_TRI_MODE_FEM_PROFILE_ID   = 10074,  //UCOM_NV_TRI_MODE_FEM_PROFILE_ID_STRU
    /*guc_phy??????????????????tf AT???? end*/
}NV_ID_MSP_TAF_ENUM;

typedef struct
{
    VOS_UINT32                                     ulWBand;
    VOS_UINT32                                     ulWbandExtRsv;
    VOS_UINT32                                     ulGeBand;
}NV_WG_RF_MAIN_BAND_STRU;

/*****************************************************************************
 ??????    : UCOM_NV_W_RF_DIV_BAND_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32          uwWBand;
    VOS_UINT32          uwWbandExtRsv;
}UCOM_NV_W_RF_DIV_BAND_STRU;

/*****************************************************************************
 ??????    : UCOM_NV_SAR_BACKOFF_TEST_MODE_STRU
 ????????  :
 ASN.1???? :
 ????????  : ??SAR????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          uhwSarBackoffTestModeFlg;               /* ??SAR???????? */
}UCOM_NV_SAR_BACKOFF_TEST_MODE_STRU;

/*****************************************************************************
 ??????    : UCOM_NV_TRI_MODE_ENABLE_STRU
 ????????  :
 ASN.1???? :
 ????????  : ??????????????????(0:???? 1:????)
*****************************************************************************/
typedef struct
{
    VOS_UINT16                              uhwEnable;                          /* ?????????????? */
    VOS_UINT16                              uhwReserved;
}UCOM_NV_TRI_MODE_ENABLE_STRU;

/*****************************************************************************
 ??????    : UCOM_NV_TRI_MODE_FEM_PROFILE_ID_STRU
 ????????  :
 ASN.1???? :
 ????????  : ??????????????????Profile Id??NV??
*****************************************************************************/
typedef struct
{
    VOS_UINT32                              uwProfileId;                        /* ????????????????????????????????????ABB??TCXO??RF??????RF????????????
                                                                                   ??AT??????????????????????0??????????0-7?? */
    VOS_UINT32                              auwReserved[3];                     /* ?????????????????? */
}UCOM_NV_TRI_MODE_FEM_PROFILE_ID_STRU;

/****************guc_phy??????????????????tf AT???? end**********************/

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif

