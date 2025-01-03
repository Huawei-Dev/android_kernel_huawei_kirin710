/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2012-2018. All rights reserved.
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

#ifndef __APPRRCINTERFACE_H__
#define __APPRRCINTERFACE_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


/*****************************************************************************
  1 Include Headfile
*****************************************************************************/
#include  "vos.h"
#include  "PsTypeDef.h"
#include  "LPSCommon.h"



#if (VOS_OS_VER != VOS_WIN32)
#pragma pack(4)
#else
#pragma pack(push, 4)
#endif

/*****************************************************************************
  2 macro
*****************************************************************************/
#define RRC_APP_CELL_MAX_COUNT           (32)
#define RRC_APP_MAX_NUM_OF_MCC           (3)

/*typedef DT_CMD_ENUM_UINT8 APP_CMD_ENUM_UINT8;*/
/*typedef DT_RESULT_ENUM_UINT32 APP_RESULT_ENUM_UINT32;*/

/* RRC??????????????MAC????rar */
#define PS_OM_EST_PTL_SND_MACRA_TO_RCV_RAR_TIME      (11)           /* 11ms T4-T1 */
/* ??mac????rar??????????3???? */
#define PS_OM_EST_PTL_RCV_RAR_TO_SND_MSG3_TIME       (3)            /* 2.5ms T5-T4*/
/* ????????3??????setup???? */
#define PS_OM_EST_PTL_SND_MSG3_TO_RCV_SETUP_TIME     (73)           /* 28.5ms+2*Ts1c  T6-T5*/
/* ????setup???????????? */
#define PS_OM_EST_PTL_SETUP_TO_CMPL_TIME             (3)             /* 3ms T7-T6*/
/* ??????????????????setup cmpl???????? */
#define PS_OM_EST_PTL_RRC_SND_MACRA_TO_CMPL_TIME     (92)            /* 47.5ms+2*Ts1c--(50.5~92.5ms) T7-T1*/
/* ???????????????????? */
#define PS_OM_EST_PTL_USER_PLANE_TIME                (106)            /* 61ms+2*Ts1c+Ts1u--66~106ms T13-T1*/

/* ???????????????? */
#define PS_OM_REEST_PTL_SEARCH_CELL_TIME             (100)            /* <100ms */
/* ???????????????????? */
#define PS_OM_REEST_PTL_RCV_SI_TIME                  (1280)           /* <1280ms */
/* ?????????????????????????????????????????????? */
#define PS_OM_REEST_PTL_RCV_REEST_IND_TO_MACRA       (1500)           /* <1500ms */

/*  ???????????????????????????? */
#define PS_OM_HO_PTL_HO_REQ_TO_CNF                   (1)              /* <1ms T6-T5*/

/* ??????????????????Cnf?????????? */
#define PS_OM_HO_PTL_RRC_MACRA_REQ_TO_MACRA_CNF      (11)             /* 2.5 + 1+ 7.5ms T8-T7*/

/* ?????????????????????????????????????? */
#define PS_OM_HO_PTL_SND_CMPL_TO_CMPL_CNF            (13)             /* 13ms T10-T9*/

/* ?????????????????????????????????????? */
#define PS_OM_HO_PTL_RCV_RBCFG_TO_MACRA_REQ          (50)             /* 50ms T7-T4*/

/* ?????????????????????????????????????????????? */
#define PS_OM_HO_PTL_USER_PLANE_TIME                 (100)            /* 100ms T11-T4*/

/* add for AT&T LRRC DAM begin */
/* ?????????????????????????? */
#define RRC_APP_MAX_LIMITED_ITEM_COUNT         (32)
/* add for AT&T LRRC DAM end */
/* ??????????????????????????????*/
#define LRRC_LCSEL_INTRA_CELL_REPORT_NUM 4
#define LRRC_LCSEL_INTER_CELL_REPORT_NUM 4
#define LRRC_LCSEL_UTRAN_CELL_REPORT_NUM 4
#define LRRC_LCSEL_INTER_FREQ_REPORT_NUM 9

#define LRRC_SCELL_MAX_NUM 4
#define LRRC_INTRA_CELL_MAX_NUM 16
#define LRRC_INTER_CELL_MAX_NUM 16
#define LRRC_UTRAN_CELL_MAX_NUM 16
#define LRRC_GERAN_CELL_MAX_NUM 16

/*  ??????????????????????????????????*/
#define LRRC_ECELL_QRY_CELL_REPORT_NUM 9
#define LRRC_ECELL_QRY_NBRCELL_NUM 8
#define LRRC_ECELL_QRY_SELL_REPORT_NUM 4
#define RRC_ECELL_QRY_INVALID_UINT8        0XFF
#define RRC_ECELL_QRY_INVALID_UINT16       0XFFFF
#define RRC_ECELL_QRY_INVALID_UINT32       0XFFFFFFFF

/* UE??????UTRAN?????????????????? */
#define LRRC_TRRC_PHY_MAX_SUPPORT_CARRIER_NUM               9

#define LRRC_GURRC_GERAN_ARFCN_MAX_NUM                      32

/* begin: add for at&t ue cap display  */
/* ????BAND?????????????? */
#define LRRC_APP_MAX_BAND_IND_ARRAY_NUM                     (8)
/* end:   add for at&t ue cap display  */

#define LRRC_APP_LWCLASH_MAX_SCELL_NUM                      (4)


/*****************************************************************************
  3 Massage Declare
*****************************************************************************/
/*****************************************************************************
 ??????    : APP_RRC_MSG_ID_ENUM
 ????????  :
 ASN.1???? :
 ????????  : RRC <-> APP ????????ID
*****************************************************************************/
enum APP_RRC_MSG_ID_ENUM
{
    /* RRC????APP?????? */
    ID_APP_RRC_TRANSPARENT_CMD_REQ      = (PS_MSG_ID_APP_TO_RRC_BASE + 0x00),   /* _H2ASN_MsgChoice APP_RRC_TRANSPARENT_CMD_REQ_STRU */
    ID_APP_RRC_CELL_MEAS_RPT_REQ        = (PS_MSG_ID_APP_TO_RRC_BASE + 0x01),   /* _H2ASN_MsgChoice APP_RRC_CELL_MEAS_RPT_REQ_STRU */
    ID_APP_RRC_TIME_DELAY_RPT_REQ       = (PS_MSG_ID_APP_TO_RRC_BASE + 0x02),   /* _H2ASN_MsgChoice APP_RRC_TIME_DELAY_RPT_REQ_STRU */
    ID_APP_RRC_INQ_CAMP_CELL_INFO_REQ   = (PS_MSG_ID_APP_TO_RRC_BASE + 0x03),   /* _H2ASN_MsgChoice APP_RRC_INQ_CAMP_CELL_INFO_REQ_STRU */
    ID_APP_RRC_LOCK_WORK_INFO_REQ       = (PS_MSG_ID_APP_TO_RRC_BASE + 0x04),   /* _H2ASN_MsgChoice APP_RRC_LOCK_WORK_INFO_REQ_STRU */
    ID_APP_RRC_CSQ_REQ                  = (PS_MSG_ID_APP_TO_RRC_BASE + 0x05),   /* _H2ASN_MsgChoice APP_RRC_CSQ_REQ_STRU */
    ID_APP_RRC_PTL_STATE_QUERY_REQ      = (PS_MSG_ID_APP_TO_RRC_BASE + 0x06),   /* _H2ASN_MsgChoice APP_RRC_PTL_STATE_QUERY_REQ_STRU */
    ID_APP_RRC_CELL_INFO_QUERY_REQ      = (PS_MSG_ID_APP_TO_RRC_BASE + 0x07),   /* _H2ASN_MsgChoice APP_RRC_CELL_INFO_QUERY_REQ_STRU */
    ID_APP_RRC_LWCLASH_REQ              = (PS_MSG_ID_APP_TO_RRC_BASE + 0x08),   /* _H2ASN_MsgChoice APP_RRC_PTL_LWCLASH_REQ_STRU */
    /*  DT begin */
    ID_APP_RRC_SERVING_CELL_INFO_QUERY_REQ   = (PS_MSG_ID_APP_TO_RRC_BASE + 0x09),   /* _H2ASN_MsgChoice APP_RRC_CELL_INFO_QUERY_REQ_STRU */
    ID_APP_RRC_CSEL_INFO_QUERY_REQ           = (PS_MSG_ID_APP_TO_RRC_BASE + 0x0a),   /* _H2ASN_MsgChoice APP_RRC_CELL_INFO_QUERY_REQ_STRU */
    ID_APP_RRC_UE_CAP_INFO_QUERY_REQ         = (PS_MSG_ID_APP_TO_RRC_BASE + 0x0b),   /* _H2ASN_MsgChoice APP_RRC_CELL_INFO_QUERY_REQ_STRU */
    ID_APP_RRC_AC_BARRING_INFO_QUERY_REQ     = (PS_MSG_ID_APP_TO_RRC_BASE + 0x0c),   /* _H2ASN_MsgChoice APP_RRC_CELL_INFO_QUERY_REQ_STRU */
    ID_APP_RRC_DRX_INFO_QUERY_REQ            = (PS_MSG_ID_APP_TO_RRC_BASE + 0x0d),   /* _H2ASN_MsgChoice APP_RRC_CELL_INFO_QUERY_REQ_STRU */

    /*  DT end */
    ID_APP_RRC_NMR_REQ                  = (PS_MSG_ID_APP_TO_RRC_BASE + 0x0e),   /* _H2ASN_MsgChoice APP_RRC_NMR_REQ_STRU */
    ID_APP_RRC_CELLID_REQ               = (PS_MSG_ID_APP_TO_RRC_BASE + 0x0f),   /* _H2ASN_MsgChoice APP_RRC_CELLID_REQ_STRU */

    ID_APP_LRRC_RESEL_OFFSET_CFG_NTF         = (PS_MSG_ID_APP_TO_RRC_BASE + 0x10),   /* _H2ASN_MsgChoice APP_LRRC_RESEL_OFFSET_CFG_NTF_STRU  */
    ID_APP_LRRC_CON_TO_IDLE_NTF          = (PS_MSG_ID_APP_TO_RRC_BASE + 0x11),   /* _H2ASN_MsgChoice APP_LRRC_CON_TO_IDLE_NTF_STRU  */
    ID_APP_LRRC_FAST_DORM_CFG_NTF          = (PS_MSG_ID_APP_TO_RRC_BASE + 0x12),   /* _H2ASN_MsgChoice APP_LRRC_FAST_DORM_CFG_NTF_STRU  */
    ID_APP_LRRC_GET_NCELL_INFO_REQ      = (PS_MSG_ID_APP_TO_RRC_BASE + 0x13),   /* _H2ASN_MsgChoice APP_LRRC_GET_NCELL_INFO_REQ_STRU  */

    /* begin:V7R2-DT ??????????????????????????????????????????, 2014/3/26 */
    /*  Prob Begin */
    ID_APP_LRRC_INQ_TCFG_TXPOWER_REQ    = (PS_MSG_ID_APP_TO_RRC_BASE + 0x14),   /* _H2ASN_MsgChoice APP_RRC_INQ_TCFG_TXPOWER_REQ_STRU */
    /*  Prob End */
    ID_APP_RRC_FORCE_HOANDCSEL_REQ        = (PS_MSG_ID_APP_TO_RRC_BASE + 0x15),/*_H2ASN_MsgChoice APP_RRC_FORCE_HOANDCSEL_REQ_STRU*/
    ID_APP_RRC_BARCELL_ACCESS_REQ        = (PS_MSG_ID_APP_TO_RRC_BASE + 0x16),/*_H2ASN_MsgChoice APP_RRC_BARCELL_ACCESS_REQ_STRU*/
    /* end:V7R2-DT ??????????????????????????????????????????, 2014/3/26 */
    ID_APP_LRRC_SET_UE_REL_VERSION_REQ      = (PS_MSG_ID_APP_TO_RRC_BASE + 0x17), /* _H2ASN_MsgChoice APP_LRRC_SET_UE_REL_VERSION_REQ_STRU  */

    /* begin:add for ???????? */
    ID_DT_LRRC_MEAS_REPORT_REQ         = (PS_MSG_ID_APP_TO_RRC_BASE + 0x18),
    ID_DT_LRRC_SYNC_REPORT_REQ         = (PS_MSG_ID_APP_TO_RRC_BASE + 0x19),
    /* end:add for ???????? */

    /* begin: add for at&t ue cap display  */
    ID_APP_LRRC_GET_UE_CAP_INFO_REQ    = (PS_MSG_ID_APP_TO_RRC_BASE + 0x1a),   /* _H2ASN_MsgChoice APP_LRRC_GET_UE_CAP_INFO_REQ_STRU */
    /* end:   add for at&t ue cap display  */

    /* begin: added  for SCell Info Qry */
    ID_APP_RRC_SCELL_INFO_REQ    = (PS_MSG_ID_APP_TO_RRC_BASE + 0x1b),   /* _H2ASN_MsgChoice APP_RRC_SCELL_INFO_REQ_STRU */
    /* end: added  for SCell Info Qry */

    /* begin: add for cell info display,  -d9c-d51 */
    ID_APP_RRC_QUERY_ECELL_INFO_REQ    = (PS_MSG_ID_APP_TO_RRC_BASE + 0x1c),  /* _H2ASN_MsgChoice APP_RRC_QUERY_ECELL_INFO_REQ_STRU */
    ID_APP_RRC_QUERY_SCELL_INFO_REQ   = (PS_MSG_ID_APP_TO_RRC_BASE + 0x1d),   /* _H2ASN_MsgChoice APP_RRC_QUERY_SCELL_INFO_REQ_STRU */
    /* end: add for cell info display,   */

    ID_APP_LRRC_SET_TLPS_PRINT2LAYER_REQ    = (PS_MSG_ID_RRC_TO_APP_BASE + 0x18),

    /* APP????RRC?????? */
    ID_RRC_APP_TRANSPARENT_CMD_CNF      = (PS_MSG_ID_RRC_TO_APP_BASE + 0x00),   /* _H2ASN_MsgChoice RRC_APP_TRANSPARENT_CMD_CNF_STRU */
    ID_RRC_APP_TRANSPARENT_CMD_IND      = (PS_MSG_ID_RRC_TO_APP_BASE + 0x01),   /* _H2ASN_MsgChoice NULL */
    ID_RRC_APP_CELL_MEAS_RPT_CNF        = (PS_MSG_ID_RRC_TO_APP_BASE + 0x02),   /* _H2ASN_MsgChoice RRC_APP_CELL_MEAS_RPT_CNF_STRU */
    ID_RRC_APP_CELL_MEAS_RPT_IND        = (PS_MSG_ID_RRC_TO_APP_BASE + 0x03),   /* _H2ASN_MsgChoice RRC_APP_CELL_MEAS_REPORT_IND_STRU */
    ID_RRC_APP_TIME_DELAY_RPT_CNF       = (PS_MSG_ID_RRC_TO_APP_BASE + 0x04),   /* _H2ASN_MsgChoice RRC_APP_TIME_DELAY_RPT_CNF_STRU */
    ID_RRC_APP_TIME_DELAY_RPT_IND       = (PS_MSG_ID_RRC_TO_APP_BASE + 0x05),   /* _H2ASN_MsgChoice RRC_APP_TIME_DELAY_RPT_IND_STRU */
    ID_RRC_APP_INQ_CAMP_CELL_INFO_CNF   = (PS_MSG_ID_RRC_TO_APP_BASE + 0x06),   /* _H2ASN_MsgChoice RRC_APP_INQ_CAMP_CELL_INFO_CNF_STRU */
    ID_RRC_APP_INQ_CAMP_CELL_INFO_IND   = (PS_MSG_ID_RRC_TO_APP_BASE + 0x07),   /* _H2ASN_MsgChoice RRC_APP_INQ_CAMP_CELL_INFO_IND_STRU */
    ID_RRC_APP_LOCK_WORK_INFO_CNF       = (PS_MSG_ID_RRC_TO_APP_BASE + 0x08),   /* _H2ASN_MsgChoice RRC_APP_LOCK_WORK_INFO_CNF_STRU */
    ID_RRC_APP_RPT_DBG_INFO_IND         = (PS_MSG_ID_RRC_TO_APP_BASE + 0x09),   /* _H2ASN_MsgChoice RRC_APP_DEBUG_INFO_STRU */
    ID_RRC_APP_CSQ_CNF                  = (PS_MSG_ID_RRC_TO_APP_BASE + 0x0a),   /* _H2ASN_MsgChoice RRC_APP_CSQ_CNF_STRU */
    ID_RRC_APP_CSQ_IND                  = (PS_MSG_ID_RRC_TO_APP_BASE + 0x0b),   /* _H2ASN_MsgChoice RRC_APP_CSQ_IND_STRU */
    ID_RRC_APP_PTL_STATE_QUERY_CNF      = (PS_MSG_ID_RRC_TO_APP_BASE + 0x0c),     /* _H2ASN_MsgChoice RRC_APP_PTL_STATE_QUERY_CNF_STRU */
    ID_RRC_APP_PTL_STATE_CHANGE_IND     = (PS_MSG_ID_RRC_TO_APP_BASE + 0x0d),     /* _H2ASN_MsgChoice RRC_APP_PTL_STATE_CHANGE_IND_STRU */
    ID_RRC_APP_CELL_INFO_QUERY_CNF      = (PS_MSG_ID_RRC_TO_APP_BASE + 0x0e),   /* _H2ASN_MsgChoice RRC_APP_CELL_INFO_QUERY_CNF_STRU */
    ID_RRC_APP_LWCLASH_CNF              = (PS_MSG_ID_RRC_TO_APP_BASE + 0x0f),   /* _H2ASN_MsgChoice RRC_APP_PTL_LWCLASH_IND_STRU */
    ID_RRC_APP_LWCLASH_IND              = (PS_MSG_ID_RRC_TO_APP_BASE + 0x10),   /* _H2ASN_MsgChoice RRC_APP_PTL_LWCLASH_CNF_STRU */
    /* DT begin */
    ID_RRC_APP_SERVING_CELL_INFO_QUERY_CNF    = (PS_MSG_ID_RRC_TO_APP_BASE + 0x11),   /* _H2ASN_MsgChoice RRC_APP_CELL_INFO_QUERY_CNF_STRU */
    ID_RRC_APP_SERVING_CELL_INFO_IND    = (PS_MSG_ID_RRC_TO_APP_BASE + 0x12),   /* _H2ASN_MsgChoice RRC_APP_CELL_INFO_QUERY_CNF_STRU */
    ID_RRC_APP_CSEL_INFO_QUERY_CNF      = (PS_MSG_ID_RRC_TO_APP_BASE + 0x13),   /* _H2ASN_MsgChoice RRC_APP_CELL_INFO_QUERY_CNF_STRU */
    ID_RRC_APP_LTE_CSEL_INFO_IND        = (PS_MSG_ID_RRC_TO_APP_BASE + 0x14),   /* _H2ASN_MsgChoice RRC_APP_CELL_INFO_QUERY_CNF_STRU */

    ID_RRC_APP_UE_CAP_INFO_QUERY_CNF      = (PS_MSG_ID_RRC_TO_APP_BASE + 0x15),   /* _H2ASN_MsgChoice RRC_APP_CELL_INFO_QUERY_CNF_STRU */
    ID_RRC_APP_UE_CAP_INFO_IND            = (PS_MSG_ID_RRC_TO_APP_BASE + 0x16),   /* _H2ASN_MsgChoice RRC_APP_CELL_INFO_QUERY_CNF_STRU */
    ID_RRC_APP_AC_BARRING_INFO_QUERY_CNF  = (PS_MSG_ID_RRC_TO_APP_BASE + 0x17),   /* _H2ASN_MsgChoice RRC_APP_CELL_INFO_QUERY_CNF_STRU */
    ID_RRC_APP_AC_BARRING_INFO_IND        = (PS_MSG_ID_RRC_TO_APP_BASE + 0x18),   /* _H2ASN_MsgChoice RRC_APP_CELL_INFO_QUERY_CNF_STRU */

    ID_RRC_APP_UTRA_CSEL_INFO_IND         = (PS_MSG_ID_RRC_TO_APP_BASE + 0x19),   /* _H2ASN_MsgChoice RRC_APP_CELL_INFO_QUERY_CNF_STRU */
    ID_RRC_APP_GERAN_CSEL_INFO_IND        = (PS_MSG_ID_RRC_TO_APP_BASE + 0x1a),   /* _H2ASN_MsgChoice RRC_APP_CELL_INFO_QUERY_CNF_STRU */
    ID_RRC_APP_DRX_INFO_QUERY_CNF         = (PS_MSG_ID_RRC_TO_APP_BASE + 0x1b),   /* _H2ASN_MsgChoice RRC_APP_CELL_INFO_QUERY_CNF_STRU */
    ID_RRC_APP_DRX_INFO_IND               = (PS_MSG_ID_RRC_TO_APP_BASE + 0x1c),   /* _H2ASN_MsgChoice RRC_APP_CELL_INFO_QUERY_CNF_STRU */
    /* DT end */
    ID_RRC_APP_NMR_CNF                    = (PS_MSG_ID_RRC_TO_APP_BASE + 0x1d),   /* _H2ASN_MsgChoice RRC_APP_NMR_CNF_STRU */
    ID_RRC_APP_CELLID_CNF                 = (PS_MSG_ID_RRC_TO_APP_BASE + 0x1e),   /* _H2ASN_MsgChoice RRC_APP_CELLID_CNF_STRU */
    ID_RRC_APP_GET_NCELL_INFO_CNF       = (PS_MSG_ID_RRC_TO_APP_BASE + 0x1f), /*_H2ASN_MsgChoice LRRC_APP_GET_NCELL_INFO_CNF_STRU*/

    ID_LRRC_APP_SET_UE_REL_VERSION_CNF      = (PS_MSG_ID_RRC_TO_APP_BASE + 0x40),/* _H2ASN_MsgChoice LRRC_APP_SET_UE_REL_VERSION_CNF_STRU  */
   /* begin:V7R2-DT add dt cnf msg, 2014/5/21 */
    ID_APP_RRC_FORCE_HOANDCSEL_CNF        = (PS_MSG_ID_RRC_TO_APP_BASE + 0x41),/* _H2ASN_MsgChoice RRC_APP_FORCE_HOANDCSEL_CNF_STRU */
    ID_APP_RRC_BARCELL_ACCESS_CNF        = (PS_MSG_ID_RRC_TO_APP_BASE + 0x42),/* _H2ASN_MsgChoice RRC_APP_BARCELL_ACCESS_CNF_STRU */
    /* end:V7R2-DT add dt cnf msg, 2014/5/21 */

    /*Print2Layer  */
    ID_LRRC_APP_SET_TLPS_PRINT2LAYER_CNF = (PS_MSG_ID_RRC_TO_APP_BASE + 0x47),

    /* begin:add for ???????? */
    ID_LRRC_DT_MEAS_REPORT_CNF   = (PS_MSG_ID_RRC_TO_APP_BASE + 0x48),
    ID_LRRC_DT_SYNC_REPORT_CNF   = (PS_MSG_ID_RRC_TO_APP_BASE + 0x49),
    ID_LRRC_DT_MEAS_INFO_IND     = (0x988),/* ??????????????????????Ind????id??0x988??????id_lrrc_lphy_conn_meas_ind */
    ID_LRRC_DT_SYNC_INFO_IND     = (0x904),/* ??????????????????????Ind????id??0x904??????id_lrrc_lphy_sync_info_ind */
    ID_LRRC_DT_OUT_OF_SYNC_INFO_IND = (0x90f),/* ??????????????????????Ind????id??0x90f??????id_lrrc_lphy_out_of_sync_info_ind */
    /* end:add for ???????? */

    /* V7R2-DT, report pcell and scell basic information,   2014-3-25 begin*/
    ID_RRC_APP_SERVING_CELL_CA_INFO_IND          = (PS_MSG_ID_RRC_TO_DT_BASE + 0x12),
    /* V7R2-DT, report pcell and scell basic information,   2014-3-25 begin*/

    /* begin: add for at&t ue cap display  */
    ID_LRRC_APP_GET_UE_CAP_INFO_CNF       = (PS_MSG_ID_RRC_TO_APP_BASE + 0x4a), /* _H2ASN_MsgChoice LRRC_APP_GET_UE_CAP_INFO_CNF_STRU */
    /* end:   add for at&t ue cap display  */

    /* begin: add for fgi spilt display  */
    ID_LRRC_APP_FGI_INFO_IND              = (PS_MSG_ID_RRC_TO_APP_BASE + 0x4b), /* _H2ASN_MsgChoice LRRC_APP_FGI_INFO_IND_STRU */
    /* end:   add for fgi spilt display  */
    /* Begin Debug Info report  */
    ID_RRC_APP_DBG_SYSINFO_IND           = (PS_MSG_ID_RRC_TO_APP_BASE + 0x4c),  /* _H2ASN_MsgChoice  LRRC_APP_DBG_SYSINFO_IND_STRU */
    /* End Debug Info report  */

    /* add for lrrc debug stub cmd  beign */
    ID_APP_RRC_DEBUG_STUB_SET_3HOUR_REQ       = (PS_MSG_ID_APP_TO_RRC_BASE + 0x20),   /* _H2ASN_MsgChoice APP_RRC_DEBUG_STUB_SET_3HOUR_REQ_STRU */
    ID_APP_RRC_DEBUG_STUB_HO_FAIL_REQ         = (PS_MSG_ID_APP_TO_RRC_BASE + 0x21),   /* _H2ASN_MsgChoice APP_RRC_DEBUG_STUB_HO_FAIL_REQ_STRU */
    ID_APP_RRC_DEBUG_STUB_REL_ALL_REQ         = (PS_MSG_ID_APP_TO_RRC_BASE + 0x22),   /* _H2ASN_MsgChoice APP_RRC_DEBUG_STUB_REL_ALL_REQ_STRU */

    ID_RRC_APP_DEBUG_STUB_CMD_CNF             = (PS_MSG_ID_RRC_TO_APP_BASE + 0x4d),   /* _H2ASN_MsgChoice RRC_APP_DEBUG_STUB_CMD_CNF_STRU */
    /* add for lrrc debug stub cmd  end */

    /* begin: added  for SCell Info Qry */
    ID_RRC_APP_SCELL_INFO_CNF              = (PS_MSG_ID_RRC_TO_APP_BASE + 0x4e), /* _H2ASN_MsgChoice RRC_APP_SCELL_INFO_CNF_STRU */
    /* end: added  for SCell Info Qry */

    ID_RRC_CLOUD_CA_INFO_IND               = (PS_MSG_ID_RRC_TO_APP_BASE + 0x4f),

    /* begin: added by   Sell Info Qry -D51*/
    ID_RRC_APP_QUERY_ECELL_INFO_CNF         = (PS_MSG_ID_RRC_TO_APP_BASE + 0x51), /* _H2ASN_MsgChoice RRC_APP_QUERY_ECELL_INFO_CNF_STRU */
    ID_RRC_APP_QUERY_SCELL_INFO_CNF         = (PS_MSG_ID_RRC_TO_APP_BASE + 0x52), /* _H2ASN_MsgChoice RRC_APP_QUERY_SCELL_INFO_CNF_STRU */
    /* end: added by   for SCell Info Qry */

    /* begin: add&mod for Plmn Feature, 2018_05_23 */
    ID_RRC_PLMN_FEATURE_INFO_IND               = (PS_MSG_ID_RRC_TO_APP_BASE + 0x53),
    /* end: add&mod for Plmn Feature, 2018_05_23 */

    /* added by  for badcell ,begin */
    ID_APP_RRC_DEBUG_STUB_ADD_BAD_CELL_REQ     = (PS_MSG_ID_APP_TO_RRC_BASE + 0x23),
    /* added by  for  badcell ,end   */
    ID_APP_RRC_MSG_ID_BUTT
};
typedef VOS_UINT32    APP_RRC_MSG_ID_ENUM_UINT32;

/*****************************************************************************
  4 Enum
*****************************************************************************/
/*****************************************************************************
 ??????    : DT_CMD_ENUM
 ????????  : DT????????
*****************************************************************************/
enum DT_CMD_ENUM
{
    DT_CMD_STOP,        /*????*/
    DT_CMD_START,       /*????*/
    DT_CMD_BUTT
};
typedef VOS_UINT8 DT_CMD_ENUM_UINT8;

/*****************************************************************************
 ??????    : DT_RESULT_ENUM
 ????????  : DT????????????
*****************************************************************************/
enum DT_RESULT_ENUM
{
    DT_RESULT_SUCC = 0,
    DT_RESULT_FAIL,
    DT_RESULT_NOT_SUPPORT_MEASURE,                /*????????????????*/

    /**********??????????????????????????????????********/
    /*RRC????????????????Begin*/
    DT_RESULT_RRC_BEGIN = 0x1000,

    /*RRC????????????????End*/

    /*NAS????????????????Begin*/
    DT_RESULT_NAS_BEGIN                 = 0x2000,
    DT_RESULT_NAS_PLMN_LOCK             = 0x2001,
    DT_RESULT_NAS_PLMN_UNLOCK           = 0x2002,

    /*NAS????????????????End*/

    /*L2????????????????Begin*/
   DT_RESULT_L2_BEGIN = 0x3000,

    /*L2????????????????End*/

   /*RRU????????????????Begin*/
   DT_RESULT_RRU_BEGIN = 0x4000,

   /*RRU????????????????End*/

    DT_RESULT_BUTT
};
typedef VOS_UINT32 DT_RESULT_ENUM_UINT32;

typedef DT_CMD_ENUM_UINT8       APP_CMD_ENUM_UINT8;
typedef DT_RESULT_ENUM_UINT32   APP_RESULT_ENUM_UINT32;
/*****************************************************************************
 ??????    : APP_RRC_CELL_RPT_PERIOD_ENUM
 ????????  :
*****************************************************************************/
enum APP_RRC_CELL_RPT_PERIOD_ENUM
{
    APP_RRC_CELL_REPORT_PERIOD_300MS = 0,
    APP_RRC_CELL_REPORT_PERIOD_600MS,
    APP_RRC_CELL_REPORT_PERIOD_900MS,
    APP_RRC_CELL_REPORT_PERIOD_1200MS,
    APP_RRC_CELL_REPORT_PERIOD_BUTT
};
typedef VOS_UINT8 APP_RRC_CELL_RPT_PERIOD_ENUM_UINT8;

/*****************************************************************************
 ??????    : APP_LATENCY_TYPE_ENUM
 ????????  :
*****************************************************************************/
enum APP_LATENCY_TYPE_ENUM
{
    APP_LATENCY_EST =0,               /*????????????*/
    APP_LATENCY_HO,                   /*????????*/
    APP_LATENCY_REEST,                /*????????*/
    APP_LATENCY_BUTT
};
typedef VOS_UINT8 APP_LATENCY_TYPE_ENUM_UINT8;

/*****************************************************************************
 ??????    : APP_RRC_LOCK_WORK_INFO_TYPE_ENUM
 ????????  : ??????????
*****************************************************************************/
enum APP_RRC_LOCK_WORK_INFO_TYPE_ENUM
{
    RRC_APP_LOCK_FREQPOINT,              /* ???????? */
    RRC_APP_LOCK_FREQANDCELL,            /* ?????????????????? */
    RRC_APP_LOCK_FREQBAND,               /* ???????? */
    RRC_APP_LOCK_BUTT
};
typedef VOS_UINT8 APP_RRC_LOCK_WORK_INFO_TYPE_ENUM_UINT8;
/*****************************************************************************
 ??????    : APP_DELAY_TYPE_ENUM
 ????????  :
*****************************************************************************/
enum APP_DELAY_TYPE_ENUM
{
    APP_DELAY_CONTROL_PLANE =0,     /*??????????*/
    APP_DELAY_USER_PLANE,           /*??????????*/
    APP_DELAY_HO,                   /*????????*/
    APP_DELAY_BUTT
};
typedef VOS_UINT8 APP_DELAY_TYPE_ENUM_UINT8;
/*****************************************************************************
 ??????    : APP_CAMPED_FLAG_ENUM
 ????????  :
*****************************************************************************/
enum APP_CAMPED_FLAG_ENUM
{
    APP_CAMPED,                 /* ?????? */
    APP_NOT_CAMPED,             /* ?????? */
    APP_CAMPED_BUTT
};
typedef VOS_UINT8 APP_CAMPED_FLAG_ENUM_UINT8;
/*****************************************************************************
 ??????    : APP_DELAY_TYPE_ENUM
 ????????  :
*****************************************************************************/
enum APP_STATE_FLAG_ENUM
{
    APP_STATE_NOT_IN_RANGE,                 /* ??????????????,????2 */
    APP_STATE_IN_RANGE,                     /* ????????????,????1*/
    APP_STATE_BUTT
};
typedef VOS_UINT8 APP_STATE_FLAG_ENUM_UINT8;

/* begin: add for at&t ue cap display  */
/*****************************************************************************
 ??????    : LRRC_CA_CC_NUM_ENUM
 ????????  :
*****************************************************************************/
enum LRRC_CA_CC_NUM_ENUM
{
    LRRC_CA_CC_NUM_2,                             /* ????????????CA CC????2CC */
    LRRC_CA_CC_NUM_3,                             /* ????????????CA CC????3CC */
    LRRC_CA_CC_NUM_4,                             /* ????????????CA CC????4CC */
    LRRC_CA_CC_NUM_BUTT
};
typedef VOS_UINT8 LRRC_CA_CC_NUM_ENUM_UINT8;
/* end:   add for at&t ue cap display  */

/*****************************************************************************
   5 STRUCT
*****************************************************************************/
/*****************************************************************************
 ??????    : APP_OM_MSG_STRU
 ????????  : APP(????????)??OM????????????
*****************************************************************************/
typedef struct
{
     VOS_MSG_HEADER                     /*VOS??
 */
     VOS_UINT32          ulMsgId;
     APP_MSG_HEADER                     /*APP??
 */
     VOS_UINT8           aucPara[4];    /* ???????? */
}APP_OM_MSG_STRU;

/*****************************************************************************
 ??????    : APP_PLMN_ID_STRU
 ????????  :
    MCC, Mobile country code (aucPlmnId[0], aucPlmnId[1] bits 1 to 4)
    MNC, Mobile network code (aucPlmnId[2], aucPlmnId[1] bits 5 to 8).

    The coding of this field is the responsibility of each administration but BCD
    coding shall be used. The MNC shall consist of 2 or 3 digits. For PCS 1900 for NA,
    Federal regulation mandates that a 3-digit MNC shall be used. However a network
    operator may decide to use only two digits in the MNC over the radio interface.
    In this case, bits 5 to 8 of octet 4 shall be coded as "1111". Mobile equipment
    shall accept MNC coded in such a way.

    ---------------------------------------------------------------------------
                 ||(BIT8)|(BIT7)|(BIT6)|(BIT5)|(BIT4)|(BIT3)|(BIT2)|(BIT1)
    ---------------------------------------------------------------------------
    aucPlmnId[0] ||    MCC digit 2            |           MCC digit 1
    ---------------------------------------------------------------------------
    aucPlmnId[1] ||    MNC digit 3            |           MCC digit 3
    ---------------------------------------------------------------------------
    aucPlmnId[2] ||    MNC digit 2            |           MNC digit 1
    ---------------------------------------------------------------------------

    AT??????
    at+cops=1,2,"mcc digit 1, mcc digit 2, mcc digit 3, mnc digit 1, mnc digit 2, mnc

digit 3",2 :

    e.g.
    at+cops=1,2,"789456",2 :
    --------------------------------------------------------------------------------
    (mcc digit 1)|(mcc digit 2)|(mcc digit 3)|(mnc digit 1)|(mnc digit 2)|(mnc digit 3)
    --------------------------------------------------------------------------------
       7         |     8       |      9      |     4       |      5      |     6
    --------------------------------------------------------------------------------

    ??aucPlmnId[3]????????????:
    ---------------------------------------------------------------------------
                 ||(BIT8)|(BIT7)|(BIT6)|(BIT5)|(BIT4)|(BIT3)|(BIT2)|(BIT1)
    ---------------------------------------------------------------------------
    aucPlmnId[0] ||    MCC digit 2 = 8        |           MCC digit 1 = 7
    ---------------------------------------------------------------------------
    aucPlmnId[1] ||    MNC digit 3 = 6        |           MCC digit 3 = 9
    ---------------------------------------------------------------------------
    aucPlmnId[2] ||    MNC digit 2 = 5        |           MNC digit 1 = 4
    ---------------------------------------------------------------------------

*****************************************************************************/
typedef struct
{
    VOS_UINT8                           aucPlmnId[3];
    VOS_UINT8                           ucRsv;
} APP_PLMN_ID_STRU;

/*****************************************************************************
 ??????    : APP_RRC_CELL_MEAS_RPT_REQ_STRU
 ????????  :
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgID;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_CMD_ENUM_UINT8                  enCommand;
    APP_RRC_CELL_RPT_PERIOD_ENUM_UINT8  enPeriod;
    VOS_UINT8                           aucReserved[2];
}APP_RRC_CELL_MEAS_RPT_REQ_STRU;

/*****************************************************************************
 ??????    : RRC_APP_CELL_MEAS_RPT_CNF_STRU
 ????????  :
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_RESULT_ENUM_UINT32              enResult;
}RRC_APP_CELL_MEAS_RPT_CNF_STRU;

/*****************************************************************************
 ??????    :RRC_APP_CELL_MEAS_RSLT_STRU
 ????????  :????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16 usCellId;
    VOS_INT16  sRSRP;
    VOS_INT16  sRSRQ;
    VOS_INT16  sRSSI;
}RRC_APP_CELL_MEAS_RSLT_STRU;

/*****************************************************************************
 ??????    :RRC_APP_CELL_MEAS_REPORT_IND_STRU
 ????????  :RRC??????????????????????????????????????
            ????????????????????RRC????????????????????????????????????????
            ??????????????????????????????????????????????????????RRC??????????OM??????????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    VOS_UINT8                           ucCellCnt;                              /* ???????? */
    VOS_UINT8                           aucReserved[3];
    RRC_APP_CELL_MEAS_RSLT_STRU         astCellMeasInd[RRC_APP_CELL_MAX_COUNT];
}RRC_APP_CELL_MEAS_REPORT_IND_STRU;

/*****************************************************************************
 ??????    : APP_RRC_TIME_DELAY_RPT_REQ_STRU
 ????????  : ????????????????????????????????????RB????????????????????????????????????RB1????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_CMD_ENUM_UINT8                  enCommand;
    APP_DELAY_TYPE_ENUM_UINT8           enDelayType;
    VOS_UINT8                           aucReserved[2];
}APP_RRC_TIME_DELAY_RPT_REQ_STRU;

/*****************************************************************************
 ??????    :RRC_APP_TIME_DELAY_RPT_CNF_STRU
 ????????  :??????APP_RRC_TIME_DELAY_RPT_REQ_STRU??????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_DELAY_TYPE_ENUM_UINT8           enDelayType;
    VOS_UINT8                           aucReserved[3];
    APP_RESULT_ENUM_UINT32              enResult;
}RRC_APP_TIME_DELAY_RPT_CNF_STRU;

/*****************************************************************************
 ??????    :APP_RRC_INQ_CAMP_CELL_INFO_REQ_STRU
 ????????  :??????????????????ID????????????????????????????????????????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_CMD_ENUM_UINT8                  enCommand;
    VOS_UINT8                           aucReserved[3];
}APP_RRC_INQ_CAMP_CELL_INFO_REQ_STRU;

/*****************************************************************************
 ??????    :RRC_APP_INQ_CAMP_CELL_INFO_CNF_STRU
 ????????  :??????APP_RRC_INQ_CAMP_CELL_INFO_REQ_STRU??????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_RESULT_ENUM_UINT32              enResult;
}RRC_APP_INQ_CAMP_CELL_INFO_CNF_STRU;

/*****************************************************************************
 ??????    :RRC_APP_INQ_CAMP_CELL_INFO_IND_STRU
 ????????  :????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    PS_BOOL_ENUM_UINT8                  enValueFlag;
    VOS_UINT8                           aucReserved[3];
    VOS_UINT16                          usCellId;
    VOS_UINT16                          usFreqInfo;
}RRC_APP_INQ_CAMP_CELL_INFO_IND_STRU;

/*****************************************************************************
 ??????    :APP_RRC_FREQ_BAND_STRU
 ????????  :????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usLowBand;                              /* ???????? */
    VOS_UINT16                          usHighBand;                             /* ???????? */
}APP_RRC_FREQ_BAND_STRU;

/*****************************************************************************
 ??????    :APP_RRC_CELL_INFO_STRU
 ????????  :????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usCellId;                               /* ????ID */
    VOS_UINT16                          usFreqPoint;                            /* ???????? */
}APP_RRC_CELL_INFO_STRU;

/*****************************************************************************
 ??????    :APP_RRC_LOCK_INFO_STRU
 ????????  :??????????????
*****************************************************************************/
typedef struct
{
    APP_RRC_LOCK_WORK_INFO_TYPE_ENUM_UINT8  enLockType;                         /* ???????? */
    VOS_UINT8                               ucBandInd;
    union
    {
        VOS_UINT16                      usFreqPoint;                            /* ?????????? */
        APP_RRC_CELL_INFO_STRU          stFreqAndCell;                          /* ??????????ID?????? */
        APP_RRC_FREQ_BAND_STRU          stFreqBand;                             /* ???????????????? */
    }u;
}APP_RRC_LOCK_INFO_STRU;

/*****************************************************************************
 ??????    :APP_RRC_LOCK_WORK_INFO_REQ_STRU
 ????????  :??????????????????????????
*****************************************************************************/
/*lint -save -e959*/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32 ulMsgID;                                     /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_CMD_ENUM_UINT8                  enCommand;                              /* ???????????? */
    VOS_UINT8                           aucReserved[3];                         /* ????, ??????2, ???????????????????? */
    APP_RRC_LOCK_INFO_STRU              stLockInfo;
}APP_RRC_LOCK_WORK_INFO_REQ_STRU;
/*lint -restore*/

/*****************************************************************************
 ??????    :RRC_APP_LOCK_WORK_INFO_CNF_STRU
 ????????  :
 ASN.1???? :
 ????????  :??????APP_RRC_LOCK_WORK_INFO_REQ????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_RESULT_ENUM_UINT32              enResult;
}RRC_APP_LOCK_WORK_INFO_CNF_STRU;

/* begin: add for at&t ue cap display  */
/*****************************************************************************
 ??????    :APP_LRRC_GET_UE_CAP_INFO_REQ_STRU
 ????????  :HIDS??????????????UE????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgID;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    VOS_UINT8                           aucReserved[128];                         /* ???? */
}APP_LRRC_GET_UE_CAP_INFO_REQ_STRU;

/*****************************************************************************
 ??????    : LRRC_APP_UE_CAP_INFO_STRU
 ????????  : LRRC??APP??????????UE????????????
*****************************************************************************/
typedef struct
{
    /* ulFGI01To32: APP??????bit??????: short DRX:FGI4, C-DRX:FGI5, L-W,PSHO:FGI8,
       L-G,PSHO:FGI9, CSFB w/measurements(REL9):FGI22, TTI Bundling:FGI28, SPS:FGI29 */
    VOS_UINT32                          ulFGI01To32;                            /* fgi bit??????????????????????FGI1??FGI32 */
    VOS_UINT32                          ulFGI33To64;                            /* fgi bit??????????????????????FGI33??FGI64 */
    VOS_UINT32                          ulFGI101To132;                          /* fgi bit??????????????????????FGI101??FGI132 */
    VOS_UINT32                          ulFGIReserved;                          /* fgi bit????????????32bit?????????????? */

    /* ??????bit????????????profile0x0001,??????????????????1????????????0????
       ??????;????????profile0x0001,profile0x0002,profile0x0003,profile0x0004,
       profile0x0006,profile0x0101,profile0x0103,profile0x0104 */
    VOS_UINT16                          usROHC;

    VOS_UINT8                           ucCategory;
    LRRC_CA_CC_NUM_ENUM_UINT8           enCaCCNum;                              /* ??????????CA CC?? */


    VOS_UINT32                          ulBandNum;   /* usBandNum ????????[1,256] */
    VOS_UINT32                          aulBandInd[LRRC_APP_MAX_BAND_IND_ARRAY_NUM]; /* aulBandInd,????BIT??1:??????????0????????????
                                                                                ulBandInd[0]????????BIT????BAND1,????????; */
    VOS_UINT32                          aul256Qam[LRRC_APP_MAX_BAND_IND_ARRAY_NUM]; /* aul256Qam,????BIT??1:??????????0????????????
                                                                                aul256Qam[0]????????BIT??????????; */
    PS_BOOL_ENUM_UINT8                  enUlMimo4Layer;                           /* ????????????4?? */
    PS_BOOL_ENUM_UINT8                  enDlMimo4Layer;                           /* ????????????4?? */
    VOS_UINT8                           aucReserved[2];
}LRRC_APP_UE_CAP_INFO_STRU;

/*****************************************************************************
 ??????    :LRRC_APP_GET_UE_CAP_INFO_CNF_STRU
 ????????  :
 ASN.1???? :
 ????????  :??????APP_LRRC_GET_UE_CAP_INFO_REQ_STRU????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_RESULT_ENUM_UINT32              enResult;
    LRRC_APP_UE_CAP_INFO_STRU           stUeCapInfo;

    VOS_UINT8                           aucReserved[32];                       /* ??????????????????Ind????
                                                                                   ??????????????????CA??????????
                                                                                   CA???????????????? */
}LRRC_APP_GET_UE_CAP_INFO_CNF_STRU;
/* end:   add for at&t ue cap display  */

/*****************************************************************************
 ??????    : APP_RRC_TRANSPARENT_CMD_REQ
 ????????  :
 ASN.1???? :
 ????????  :??????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32 ulMsgId;                                     /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    VOS_UINT16 usTransCmdNum;
    VOS_UINT16 usParaSize;
    VOS_UINT8  aucPara[4];
}APP_RRC_TRANSPARENT_CMD_REQ_STRU;


/*****************************************************************************
 ??????    : RRC_APP_TRANSPARENT_CMD_CNF_STRU
 ????????  : PS->OMT??????????????????????????(
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32          ulMsgId;                            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    VOS_UINT8           aucTransCmdCnf[4];  /*??????????????????????*/
}RRC_APP_TRANSPARENT_CMD_CNF_STRU;

/*****************************************************************************
 ??????    :PS_APP_HO_LATENCY_DETAIL_STRU
 ????????  :????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          T4_ulRrcRcvHoRecfg;
    VOS_UINT32                          ulRrcRcvNasRabmRsp;
    VOS_UINT32                          ulRrcRcvCmmHoCnf;
    VOS_UINT32                          ulRrcRcvStopPdcpCnf;
    VOS_UINT32                          T5_ulRrcSndDspHoReq;
    VOS_UINT32                          T6_ulRrcRcvDspHoCnf;
    VOS_UINT32                          T7_ulRrcSndMacRaReq;
    VOS_UINT32                          T12_ulMacSndPhyAccessReq;
    VOS_UINT32                          T13_ulMacRcvRar;
    VOS_UINT32                          T8_ulRrcRcvMacRaCnf;
    VOS_UINT32                          ulRrcSndSmcSecuCfg;
    VOS_UINT32                          T9_ulRrcSndRecfgCmp;
    VOS_UINT32                          T10_ulRrcRcvAmDataCnf;
    VOS_UINT32                          ulRrcRcvCqiSrsCnf;
    VOS_UINT32                          ulRrcRcvPdcpContineCnf;
    VOS_UINT32                          T11_ulRrcRcvRabmStatusRsp;
}PS_APP_HO_LATENCY_DETAIL_STRU;
/*****************************************************************************
 ??????    :PS_APP_HO_COMP_DETAIL_STRU
 ????????  :??????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulRealTestT6T5;
    VOS_UINT32                          ulPtlT6T5;          /* 1ms */
    VOS_UINT32                          ulRealTestT8T7;
    VOS_UINT32                          ulPtlT8T7;          /* 2.5 + 1+ 7.5ms */
    VOS_UINT32                          ulRealTestT10T9;
    VOS_UINT32                          ulPtlT10T9;         /* 13ms */
    VOS_UINT32                          ulRealTestT7T4;
    VOS_UINT32                          ulPtlT7T4;          /* 50ms */
    VOS_UINT32                          ulRealTestT11T4;
    VOS_UINT32                          ulPtlT11T4;         /* 100ms */
}PS_APP_HO_COMP_DETAIL_STRU;
/*****************************************************************************
 ??????    :PS_APP_EST_LATENCY_DETAIL_STRU
 ????????  :????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          T1_ulRrcSndMacRaReq;
    VOS_UINT32                          T2_ulMacSndPhyAccessReq;
    VOS_UINT32                          T4_ulMacRcvRar;
    VOS_UINT32                          ulRrcRcvMacRaCnf;
    VOS_UINT32                          T5_ulMacSndMsg3;
    VOS_UINT32                          T6_ulRrcRcvSetUp;
    VOS_UINT32                          T7_ulRrcSndEstCmp;
    VOS_UINT32                          ulRrcRcvSecCmd;
    VOS_UINT32                          ulRrcSndSecCmdCmp;
    VOS_UINT32                          ulRrcRcvCapEnq;
    VOS_UINT32                          ulRrcSndCapInfo;
    VOS_UINT32                          ulRrcRcvRecfg;
    VOS_UINT32                          T13_ulRrcSndRecfgCmp;
}PS_APP_EST_LATENCY_DETAIL_STRU;
/*****************************************************************************
 ??????    :PS_APP_EST_COMP_STRU
 ????????  :??????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulRealTestT4T1;
    VOS_UINT32                          ulPtlT4T1;              /* 5s + 6ms */
    VOS_UINT32                          ulRealTestT5T4;
    VOS_UINT32                          ulPtlT5T4;              /* 2.5ms */
    VOS_UINT32                          ulTestRealT6T5;
    VOS_UINT32                          ulPtlT6T5;              /* 28.5ms+2*Ts1c */
    VOS_UINT32                          ulRealTestT7T6;
    VOS_UINT32                          ulPtlT7T6;              /* 3ms */
    VOS_UINT32                          ulReaTestlT7T1;
    VOS_UINT32                          ulPtlT7T1;              /* 47.5ms+2*Ts1c */
    VOS_UINT32                          ulReaTestlT13T1;
    VOS_UINT32                          ulPtlT13T1;             /* 61ms+2*Ts1c+Ts1u */
}PS_APP_EST_COMP_DETAIL_STRU;
/*****************************************************************************
 ??????    :PS_APP_REEST_LATENCY_DETAIL_STRU
 ????????  :????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          T2_ulRrcRcvReestInd;
    VOS_UINT32                          T3_ulRrcSndCellSearchReq;
    VOS_UINT32                          T4_ulRrcRcvCellSearchInd;
    VOS_UINT32                          T5_ulRrcRcvSi;
    VOS_UINT32                          T6_ulRrcSndCampReq;
    VOS_UINT32                          T7_ulRrcRcvCampCnf;
    VOS_UINT32                          T10_ulRrcSndMacRaReq;
    VOS_UINT32                          ulMacSndPhyAccessReq;
    VOS_UINT32                          ulMacRcvRar;
    VOS_UINT32                          ulRrcRcvMacRaCnf;
    VOS_UINT32                          ulMacSndMsg3;
    VOS_UINT32                          ulRrcRcvReest;
    VOS_UINT32                          ulRrcSndReestCmpl;
}PS_APP_REEST_LATENCY_DETAIL_STRU;

/*****************************************************************************
 ??????    :PS_APP_REEST_COMP_DETAIL_STRU
 ????????  :??????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulRealTestT4T3;
    VOS_UINT32                          ulPtlT4T3;              /* 100ms */
    VOS_UINT32                          ulRealTestT5T4;
    VOS_UINT32                          ulPtlT5T4;              /* 1280ms */
    VOS_UINT32                          ulRealTestT10T2;
    VOS_UINT32                          ulPtlT10T2;             /* 1500ms */

}PS_APP_REEST_COMP_DETAIL_STRU;
/*****************************************************************************
 ??????    :RRC_APP_TIME_LATENCY_RPT_IND_STRU
 ????????  :??????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                                  T7T4_ulHoCPlaneRealLatency;
    VOS_UINT32                                  ulHoCPlanePtlLatency;
    VOS_UINT32                                  T11T4_ulHoUPlaneRealLatency;
    VOS_UINT32                                  ulHoUPlanePtlLatency;
    PS_APP_HO_LATENCY_DETAIL_STRU               stHoLatencyDetail;
    PS_APP_HO_COMP_DETAIL_STRU                  stHoCompDetail;
}PS_APP_HO_LATENCY_STRU;

/*****************************************************************************
 ??????    :PS_APP_REEST_LATENCY_STRU
 ????????  :??????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                                  T10T2_ulReestRealLatency;
    VOS_UINT32                                  ulReestPtlLatency;
    PS_APP_REEST_LATENCY_DETAIL_STRU            stReestLatencyDetail;
    PS_APP_REEST_COMP_DETAIL_STRU               stReestCompDetail;
}PS_APP_REEST_LATENCY_STRU;

/*****************************************************************************
 ??????    :PS_APP_EST_LATENCY_STRU
 ????????  :??????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                                  T13T1_ulEstUPlaneRealLatency;
    VOS_UINT32                                  ulEstUPlanePtlLatency;
    VOS_UINT32                                  T7T1_ulEstCPlaneRealLatency;
    VOS_UINT32                                  ulEstCPlanePtlLatency;
    PS_APP_EST_LATENCY_DETAIL_STRU              stEstLatencyDetail;
    PS_APP_EST_COMP_DETAIL_STRU                 stEstCompDetail;
}PS_APP_EST_LATENCY_STRU;

/*****************************************************************************
 ??????    :RRC_APP_TIME_LATENCY_RPT_IND_STRU
 ????????  :??????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;

    APP_LATENCY_TYPE_ENUM_UINT8         enLatencyType;
    VOS_UINT8                           aucReserved[3];
union
    {
        PS_APP_HO_LATENCY_STRU             stHoElapse;
        PS_APP_REEST_LATENCY_STRU          stReestElapse;
        PS_APP_EST_LATENCY_STRU            stEstElapse;
    }u;
} RRC_APP_TIME_DELAY_RPT_IND_STRU;

/*****************************************************************************
 ??????    :APP_RRC_CSQ_REQ_STRU
 ????????  :CSQ????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    VOS_UINT16                          usSwt;              /* 0: ???????????? 1: ????RSSI????????IND????  2: ????????????RSSI */
    VOS_UINT16                          usPeriod;
    VOS_UINT16                          usNdb;              /* ???? 0-5 dbm*/
    VOS_UINT16                          usMs;               /* ???? 1-20 s*/
}APP_RRC_CSQ_REQ_STRU;

/*****************************************************************************
 ??????    :RRC_APP_CSQ_CNF_STRU
 ????????  :CSQ????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usRI;                /*RI??*/
    VOS_UINT16                          ausCQI[2];           /* CQI???????? */
    VOS_UINT8                           aucRes[2];

}APP_RRC_CQI_INFO_STRU;

/*****************************************************************************
 ??????    :RRC_APP_CSQ_CNF_STRU
 ????????  :CSQ????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_RESULT_ENUM_UINT32              enResult;
    VOS_INT16                           sRsrp;              /* RSRP????????????(-141,-44) */
    VOS_INT16                           sRsrq;              /* RSRQ????????????(-40, -6) */
    VOS_INT16                           sRssi;              /* RSSI?????? */
    VOS_UINT16                          usBer;              /* ?????? */
    VOS_INT32                           lSINR;              /* SINR  RS_SNR */
    APP_RRC_CQI_INFO_STRU               stCQI;              /* CQI???????? */
}RRC_APP_CSQ_CNF_STRU;

/*****************************************************************************
 ??????    :RRC_APP_CSQ_IND_STRU
 ????????  :RRC??????APP??????CSQ????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_INT16                           sRsrp;              /* RSRP????????????(-141,-44) */
    VOS_INT16                           sRsrq;              /* RSRQ????????????(-40, -6) */
    VOS_INT16                           sRssi;              /* RSSI?????? */
    VOS_UINT16                          usBer;              /* ?????? */
    VOS_INT32                           lSINR;              /* SINR  RS_SNR */
    APP_RRC_CQI_INFO_STRU               stCQI;              /* CQI???????? */
}RRC_APP_CSQ_IND_STRU;

/*****************************************************************************
 ??????    :APP_RRC_PTL_STATE_QUERY_REQ_STRU
 ????????  :????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_CMD_ENUM_UINT8                  enCommand;
    APP_RRC_CELL_RPT_PERIOD_ENUM_UINT8  enPeriod;
    VOS_UINT8                           aucReserved[2];

}APP_RRC_PTL_STATE_QUERY_REQ_STRU;

/*****************************************************************************
 ??????    : RRC_APP_PTL_STATE_QUERY_CNF_STRU
 ????????  :
 ASN.1???? :
 ????????  : RRC??????????????
*****************************************************************************/
/*V7R2-DT , 2014/4/25, begin*/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;             /* MSP????????ID????CmdID????Prob */
    APP_RESULT_ENUM_UINT32              enResult;
    //VOS_UINT32                          ulCurrentState;     /* RRC????????, 0:????IDLE?? 1:????CONNECTED 2:???????????????? */
}RRC_APP_PTL_STATE_QUERY_CNF_STRU;
/*V7R2-DT , 2014/4/25, end*/

/*****************************************************************************
 ??????    : RRC_APP_PTL_STATE_CHANGE_IND_STRU
 ????????  :
 ASN.1???? :
 ????????  : RRC??????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    VOS_UINT32                          ulCurrentState;     /* RRC????????, 0:????IDLE?? 1:????CONNECTED 2:???????????????? */
}RRC_APP_PTL_STATE_CHANGE_IND_STRU;
/* DT begin */
/*****************************************************************************
 ??????    : RRC_APP_PTL_STATE_CHANGE_IND_STRU
 ????????  :
 ASN.1???? :
 ????????  : RRC??????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    VOS_UINT32                          ulCurrentState;     /* RRC????????, 0:????IDLE?? 1:????CONNECTED 2:???????????????? */
}RRC_APP_DT_PTL_STATE_IND_STRU;

/* DT end */

/*****************************************************************************
 ??????    :APP_RRC_PTL_STATE_QUERY_REQ_STRU
 ????????  :????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
}APP_RRC_CELL_INFO_QUERY_REQ_STRU;

/*****************************************************************************
 ??????    : RRC_APP_PTL_STATE_QUERY_CNF_STRU
 ????????  : RRC??????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    VOS_UINT16                          usFreq;             /* 0xFFFF??????,??????100KHz */
    VOS_UINT16                          usPci;              /* 0xFFFF??????,??????(0,503) */
    VOS_UINT8                           ucDlBandWidth;      /* 0xff??????,????:(0,5): (0 : 1.4M , 1 : 3M , 2 : 5M ,3 : 10M , 4 : 15M, 5 : 20M) */
    VOS_UINT8                           aucReserved[3];
}RRC_APP_CELL_INFO_QUERY_CNF_STRU;

/*  DT begin */
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgID;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_CMD_ENUM_UINT8                  enCommand;
    APP_RRC_CELL_RPT_PERIOD_ENUM_UINT8  enPeriod;
    VOS_UINT8                           aucReserved[2];
}APP_RRC_INQ_CMD_REQ_STRU;

typedef APP_RRC_INQ_CMD_REQ_STRU APP_RRC_INQ_SERVING_CELL_INFO_REQ_STRU;

typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgID;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_RESULT_ENUM_UINT32              enResult;
}APP_RRC_INQ_CMD_CNF_HEADER_STRU;
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgID;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
}APP_RRC_INQ_CMD_IND_HEADER_STRU;

/*  DT end */

/* begin:V7R2-DT ??????????????????????????????????????????,2014/3/26 */
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_RESULT_ENUM_UINT32              enResult;
}RRC_APP_FORCE_HOANDCSEL_CNF_STRU;
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32 ulMsgID;                                     /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    DT_CMD_ENUM_UINT8                   enCmd;              /* FORCE HO/CSEL FLAG */
    VOS_UINT8                           ucRsv[3];
    VOS_UINT32                          ulPci;              /* PHY Cell ID */
}APP_RRC_FORCE_HOANDCSEL_REQ_STRU;
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_RESULT_ENUM_UINT32              enResult;
}RRC_APP_BARCELL_ACCESS_CNF_STRU;
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32 ulMsgID;                                     /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    DT_CMD_ENUM_UINT8                   enCmd;              /* Bar Cell Access FLAG */
    VOS_UINT8                           ucRsv[3];
}APP_RRC_BARCELL_ACCESS_REQ_STRU;

/* end:V7R2-DT ??????????????????????????????????????????, 2014/3/26 */

/*****************************************************************************
 ??????    : APP_RRC_MSG_DATA
 ????????  :
 ASN.1???? :
 ????????  : APP_RRC_MSG_DATA????????,??????RRC????
*****************************************************************************/
typedef struct
{
    APP_RRC_MSG_ID_ENUM_UINT32          enMsgID;        /*_H2ASN_MsgChoice_Export APP_RRC_MSG_ID_ENUM_UINT32*/
    VOS_UINT8                           aucMsg[4];
    /***************************************************************************
        _H2ASN_MsgChoice_When_Comment          APP_RRC_MSG_ID_ENUM_UINT32
    ****************************************************************************/
}APP_RRC_MSG_DATA;

/*_H2ASN_Length UINT32*/

/*****************************************************************************
 ??????    : AppRrcInterface_MSG
 ????????  :
 ASN.1???? :
 ????????  : AppRrcInterface_MSG????????,??????RRC????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    APP_RRC_MSG_DATA                    stMsgData;
}AppRrcInterface_MSG;
/*********************************************************
 ??????    : LRRC_LPHY_LTE_BAND_WIDTH_ENUM
 ????????  :
 ASN.1???? :
 ????????  :
**********************************************************/
enum RRC_APP_BAND_WIDTH_ENUM
{
    RRC_APP_LTE_BAND_WIDTH_1D4M = 0,
    RRC_APP_LTE_BAND_WIDTH_3M,
    RRC_APP_LTE_BAND_WIDTH_5M,
    RRC_APP_LTE_BAND_WIDTH_10M,
    RRC_APP_LTE_BAND_WIDTH_15M,
    RRC_APP_LTE_BAND_WIDTH_20M,
    RRC_APP_LTE_BAND_WIDTH_BUTT
};
typedef VOS_UINT16 RRC_APP_BAND_WIDTH_ENUM_UINT16;

/*****************************************************************************
 ??????    : APP_RRC_LWCLASH_REQ_STRU
 ????????  :????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                      /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;        /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
} APP_RRC_LWCLASH_REQ_STRU;
/* begin:add&mod  for 4G+ display,  */
/*********************************************************
 ??????    : APP_RRC_ANTENNA_MAX_LAYERS_MIMO_ENUM
 ????????  :
 ASN.1???? :
 ????????  :
**********************************************************/
enum APP_RRC_ANTENNA_MAX_LAYERS_MIMO_ENUM
{
    APP_RRC_ANTENNA_TWO_LAYERS      = 0,      /* UE MIMO????2?? */
    APP_RRC_ANTENNA_FOUR_LAYERS,              /* UE MIMO????4?? */
    APP_RRC_ANTENNA_EIGHT_LAYERS,             /* UE MIMO????8?? */
};
typedef VOS_UINT8    APP_RRC_ANTENNA_MAX_LAYERS_MIMO_ENUM_UINT8;
/* end:add&mod  for 4G+ display,  */
/*****************************************************************************
 ??????    : RRC_APP_LWCLASH_PARA_STRU
????????  : RRC??????????
*****************************************************************************/
typedef struct
{
    /* Modified  for LTE Band66 2017-4-24 begin */
    VOS_UINT32                              ulUlFreq;          /*???????????? ????:100Khz*/
    VOS_UINT32                              ulDlFreq;          /*???????????? ????:100Khz*/
    /* Modified  for LTE Band66 2017-4-24 end */
    RRC_APP_BAND_WIDTH_ENUM_UINT16          usUlBandwidth;     /*???????? */
    RRC_APP_BAND_WIDTH_ENUM_UINT16          usDlBandwidth;     /*???????? */
    APP_CAMPED_FLAG_ENUM_UINT8              enCamped;          /*???????? */
    APP_STATE_FLAG_ENUM_UINT8               enState;           /*?????????????? */
    VOS_UINT8                               usBand;            /*???????? */
    /* begin:add&mod  for 4G+ display */
    APP_RRC_ANTENNA_MAX_LAYERS_MIMO_ENUM_UINT8   enDlMimo;
    /* end:add&mod  for 4G+ display */
} RRC_APP_LWCLASH_PARA_STRU;

/*****************************************************************************
 ??????    : RRC_APP_SCELL_INFO_STRU
 ????????  :
 ASN.1???? :
 ????????  :
*****************************************************************************/
typedef struct
{
    VOS_UINT32                              ulUlFreq;           /*???????????? ????:100Khz*/
    VOS_UINT32                              ulDlFreq;           /*???????????? ????:100Khz*/
    RRC_APP_BAND_WIDTH_ENUM_UINT16          usUlBandwidth;      /*???????? */
    RRC_APP_BAND_WIDTH_ENUM_UINT16          usDlBandwidth;      /*???????? */
    /* begin:add&mod  for 4G+ display */
    APP_RRC_ANTENNA_MAX_LAYERS_MIMO_ENUM_UINT8   enDlMimo;
    VOS_UINT8                               aucResv[3];
    /* end:add&mod  for 4G+ display */
}RRC_APP_SCELL_INFO_STRU;


/*****************************************************************************
 ??????    : RRC_APP_LWCLASH_CNF_STRU
 ????????  :
 ASN.1???? :
 ????????  :
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                      /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;        /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;         /* MSP????????ID????CmdID????Prob */
    RRC_APP_LWCLASH_PARA_STRU           stLWClashPara;
    VOS_UINT32                          ulScellNum;
    RRC_APP_SCELL_INFO_STRU             stScellInfo[LRRC_APP_LWCLASH_MAX_SCELL_NUM];
} RRC_APP_LWCLASH_CNF_STRU;
/*****************************************************************************
 ??????    : RRC_APP_LWCLASH_IND_STRU
????????  : RRC??????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                      /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;        /*_H2ASN_Skip*/
    RRC_APP_LWCLASH_PARA_STRU           stLWClashPara;
    VOS_UINT32                          ulScellNum;
    RRC_APP_SCELL_INFO_STRU             stScellInfo[LRRC_APP_LWCLASH_MAX_SCELL_NUM];
} RRC_APP_LWCLASH_IND_STRU;

/*****************************************************************************
 ??????    :APP_RRC_NMR_REQ_STRU
 ????????  :NMR????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
}APP_RRC_NMR_REQ_STRU;

/*****************************************************************************
 ??????    :RRC_APP_NMR_CGI_STRU
 ????????  :NMR??????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usMncNum;           /*???? MNC ????*/
    VOS_UINT16                          usMcc;
    VOS_UINT16                          usMnc;
    VOS_UINT8                           aucRes[2];
} RRC_APP_PLMN_ID_STRU;

/*****************************************************************************
 ??????    :RRC_APP_NMR_CGI_STRU
 ????????  :NMR??????????
*****************************************************************************/
typedef struct
{
    RRC_APP_PLMN_ID_STRU                stPlmnId;
    VOS_UINT32                          sCellId;            /* ??????(0,503) */
} RRC_APP_CELL_GLOBAL_ID_STRU;

/*****************************************************************************
 ??????    :RRC_APP_NMR_CGI_STRU
 ????????  :NMR??????????
*****************************************************************************/
typedef struct
{
    RRC_APP_CELL_GLOBAL_ID_STRU         stCellGloId;        /* CellGlobalId */
    VOS_UINT16                          usTAC;
    VOS_UINT16                          usPci;              /* 0xFFFF??????,??????(0,503) */
    VOS_INT16                           sRsrp;              /* RSRP????????????(-141,-44) */
    VOS_INT16                           sRsrq;              /* RSRQ????????????(-40, -6) */
    VOS_UINT16                          usTa;               /* TA??*/
    VOS_UINT8                           aucRes[2];
} RRC_APP_LTE_CELL_INFO_STRU;

/*****************************************************************************
 ??????    :RRC_APP_NMR_CNF_STRU
 ????????  :NMR????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_RESULT_ENUM_UINT32              enResult;
    RRC_APP_LTE_CELL_INFO_STRU          stLteCelInfo;
}RRC_APP_NMR_CNF_STRU;

/*****************************************************************************
 ??????    :APP_RRC_CELLID_REQ_STRU
 ????????  :????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
}APP_RRC_CELLID_REQ_STRU;

/*****************************************************************************
 ??????    : RRC_APP_CELLID_CNF_STRU
 ????????  : RRC??????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_RESULT_ENUM_UINT32              enResult;
    APP_PLMN_ID_STRU                    stPlmnId;
    VOS_UINT32                          ulCi;               /* 0xFFFF??????, */
    VOS_UINT16                          usPci;              /* 0xFFFF??????,??????(0,503) */
    VOS_UINT16                          usTAC;             /* TAC */
}RRC_APP_CELLID_CNF_STRU;

/*****************************************************************************
  6 UNION
*****************************************************************************/


/*****************************************************************************
  7 Extern Global Variable
*****************************************************************************/
/*****************************************************************************
 ??????    : APP_LPS_MSG_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulMsgId;      /*????ID*/
    VOS_UINT32                          ulSize;       /*????????????*/
    VOS_UINT8                           aucValue[4];  /*????????????????????*/
}APP_LPS_MSG_STRU;

/* BEGIN DTS_DCM_IDLE_RESELECTION_CFG   2012-12-08 Add*/
/*****************************************************************************
 ??????    : APP_LRRC_RESEL_OFFSET_CFG_NTF_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                         /*_H2ASN_Skip*/
    VOS_UINT32             ulMsgId;        /*_H2ASN_Skip*/

    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    /*BEGIN DTS_IDLE_RESELECTION_CFG_2   Modify*/
    VOS_UINT32                           ulFlag;
    /*END DTS_IDLE_RESELECTION_CFG_2   Modify*/
}APP_LRRC_RESEL_OFFSET_CFG_NTF_STRU;

/*****************************************************************************
 ??????    : APP_LRRC_CON_TO_IDLE_NTF_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                         /*_H2ASN_Skip*/
    VOS_UINT32             ulMsgId;        /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;

    VOS_INT32              ulReserv;
}APP_LRRC_CON_TO_IDLE_NTF_STRU;


/*****************************************************************************
 ??????    : LRRC_LPDCP_FAST_DORMANCY_CMD_ENUM
 ????????  :
 ASN.1???? :
 ????????  : ????PDCP??????????FAST_DORMANCY
*****************************************************************************/
enum APP_LRRC_FAST_DORM_ENUM
{
    APP_LRRC_FAST_DORMANCY_STOP         = 0,                                  /* ????FAST_DORMANCY */
    APP_LRRC_FAST_DORMANCY_START,                                             /* ????FAST_DORMANCY */
    APP_LRRC_FAST_DORMANCY_BUTT
};
typedef VOS_UINT32 APP_LRRC_FAST_DORM_ENUM_UINT32;

/*****************************************************************************
 ??????    : APP_LRRC_FAST_DORM_CFG_NTF_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                         /*_H2ASN_Skip*/
    VOS_UINT32             ulMsgId;        /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;

    APP_LRRC_FAST_DORM_ENUM_UINT32      ulFlag;
    VOS_UINT32            ulTimerLen;   /* unite: s */
}APP_LRRC_FAST_DORM_CFG_NTF_STRU;



/*****************************************************************************
 ??????    : ID_APP_LRRC_SET_UE_REL_VERSION_REQ
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                         /*_H2ASN_Skip*/
    VOS_UINT32             ulMsgId;        /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    VOS_UINT32              ulMode;     /* 2:LTE , 1:TDS */
    VOS_UINT32              ulVersion;  /* 9 - 14 */
}APP_LRRC_SET_UE_REL_VERSION_REQ_STRU;

/*****************************************************************************
 ??????    : ID_LRRC_APP_SET_UE_REL_VERSION_CNF
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                      /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;        /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;         /* MSP????????ID????CmdID????Prob */
    APP_RESULT_ENUM_UINT32              enResult;
} LRRC_APP_SET_UE_REL_VERSION_CNF_STRU;

/* begin : added  for SCell Info Qry */
/*****************************************************************************
 ??????    :APP_RRC_SCELL_INFO_REQ_STRU
 ????????  :AT??????????SCELL????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgID;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    VOS_UINT8                           aucReserved[4];                         /* ???? */
}APP_RRC_SCELL_INFO_REQ_STRU;


typedef struct
{
    VOS_UINT32  ulPhyCellId;          /* scell??????????id */
    VOS_UINT32  ulScellUlFreq;        /* scell???????? */
    VOS_UINT32  ulScellDlFreq;        /* scell???????? */
    VOS_UINT32  ulScellUlFreqPoint;     /* scell????????*/
    VOS_UINT32  ulScellDlFreqPoint;     /* scell????????*/
    VOS_UINT8    usScellUlBandWidth;   /* scell????????*/
    VOS_UINT8    usScellDlBandWidth;   /* scell????????*/
    VOS_UINT8    ucFreqBandIndicator;   /* scell ????*/
    VOS_UINT8    ucRsv;   /* ???? */
    VOS_INT16    sRssi;
    VOS_INT16    sRsrp;
    VOS_INT16    sRsrq;
    VOS_UINT16  usScellIndex;
}RRC_SCELL_INFO_STRU;

/*****************************************************************************
 ??????    :RRC_APP_SCELL_INFO_CNF_STRU
 ????????  :
 ASN.1???? :
 ????????  :??????APP_RRC_SCELL_INFO_REQ_STRU????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                            ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                            ulOpId;
    APP_RESULT_ENUM_UINT32      enResult;
    VOS_UINT32                            ulSCellCnt;
    RRC_SCELL_INFO_STRU           astSCellInfo[LRRC_SCELL_MAX_NUM];
}RRC_APP_SCELL_INFO_CNF_STRU;
/* end : added  for SCell Info Qry */

/*****************************************************************************
 ??????    : LRRC_DAM_BAR_LIST_ITEM_STRU
 ????????  :
 ASN.1???? :
 ????????  :
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usFreqInfo;
    VOS_UINT16                          usCellId;
    VOS_UINT8                           ucBandInd;
    VOS_UINT8                           aucReserved[3];
    VOS_UINT32                          ulTimeOutTimeInMs;
    VOS_UINT32                          ulRemainTimeOutInMs;
}LRRC_DAM_BAR_LIST_ITEM_STRU;

/*****************************************************************************
 ??????    : LRRC_APP_DAM_BAR_LIST_DBG_INFO_IND_STRU
 ????????  :
 ASN.1???? :
 ????????  :
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    VOS_UINT16                          usItemCount; /* Bar List?????????? */
    VOS_UINT16                          usRev;  /* ???? */
    LRRC_DAM_BAR_LIST_ITEM_STRU         astDamBarListItem[RRC_APP_MAX_LIMITED_ITEM_COUNT];
}LRRC_APP_DAM_BAR_LIST_DBG_INFO_IND_STRU;
/* add for AT&T LRRC DAM end */
/*****************************************************************************
 ??????    : LRRC_APP_IDLE_SERVE_INFO_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          enCurrReselPrior;    /* ?????????????????????????????????????? */
    VOS_UINT16                          enBandInd;           /* ???????? */
    VOS_UINT16                          usFreqInfo;          /* ???????????? */
    VOS_UINT16                          usCellId;            /* ????????ID */
    VOS_INT16                           sRsrp;               /* RSRP?????? */
    VOS_INT16                           sRsrq;               /* RSRQ?????? */
    VOS_INT16                           sRssi;               /* RSSI?????? */
    VOS_INT16                           sSValue;             /*??????????SP??*/
    VOS_INT16                           sSqual;              /*??????????SQ??*/
    VOS_INT16                           sQRxLevMin;          /*????RSRP????????*/
    VOS_INT16                           sPCompensation;      /* ???? P-Max ?? UE Max Tx power ?????????? PCompensation */
    VOS_INT16                           sQqualMin;           /* S????RSRQ???????? */
    VOS_INT16                           sSIntraSearchP;      /* ??????????????rsrp???????? */
    VOS_INT16                           sSIntraSearchQ;      /* ??????????????rsrq???????? */
    VOS_INT16                           sSNonIntraSearchP;   /* ????????????????????????????????rsrp???????? */
    VOS_INT16                           sSNonIntraSearchQ;   /* ????????????????????????????????rsrq???????? */
    VOS_INT16                           sThreshServingLowP;  /* ?????????????????????????????????????? */
    VOS_INT16                           sThreshServingLowQ;  /* ??????????????R9???? */
} LRRC_APP_IDLE_SERVE_INFO_STRU;


/*****************************************************************************
 ??????    : LRRC_APP_IDLE_INTRA_INFO_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usCellId;
    VOS_INT16                           sSValue;            /*??????????SP??*/
    VOS_INT16                           sSqual;             /*??????????SQ??*/
    VOS_INT16                           sRsrp;              /* RSRP?????? */
    VOS_INT16                           sRsrq;              /* RSRQ?????? */
    VOS_INT16                           sRssi;              /* RSSI?????? */
}LRRC_APP_IDLE_CELL_MEAS_RESULT_STRU;

typedef struct
{
    VOS_UINT16                          enCurrReselPrior;    /* ?????????????????????????????????????? */
    VOS_UINT16                          enBandInd;           /* ???????? */
    VOS_UINT16                          usFreqInfo;          /*????*/
    VOS_UINT16                          usTotalCellNum;      /*????????*/
    VOS_UINT16                          usDetectedCellNum;   /*????????????????*/
    VOS_INT16                           sQRxLevMin;          /*????SP????????????????????*/
    VOS_INT16                           sPCompensation;      /* ???? P-Max ?? UE Max Tx power ?????????? PCompensation */
    VOS_INT16                           sQqualMin;           /* S????RSRQ???????? */
    VOS_INT16                           sSIntraSearchP;      /* ??????????????rsrp???????? */
    VOS_INT16                           sSIntraSearchQ;      /* ??????????????rsrq???????? */
    LRRC_APP_IDLE_CELL_MEAS_RESULT_STRU astIntraCellMesRslt[LRRC_LCSEL_INTRA_CELL_REPORT_NUM];
}LRRC_APP_IDLE_INTRA_INFO_STRU;



/*****************************************************************************
 ??????    : LRRC_APP_IDLE_INTER_INFO_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                              enCurrReselPrior;    /* ?????????????????????????????????????? */
    VOS_UINT16                              usFreqInfo;
    VOS_UINT16                              enBandInd;           /* ???????? */
    VOS_INT16                               sThreshLowP;         /* ?????????????????????????????????????? */
    VOS_INT16                               sThreshLowQ;         /* ??????????????R9???? */
    VOS_INT16                               sThreshHighP;        /* ?????????????????????????????????????? */
    VOS_INT16                               sThreshHighQ;        /* ??????????????R9???? */
    VOS_UINT16                              usTotalCellNum;      /*????????*/
    VOS_UINT16                              usDetectedCellNum;   /*????????????????*/
    LRRC_APP_IDLE_CELL_MEAS_RESULT_STRU     astInterCellMesRslt[LRRC_LCSEL_INTER_CELL_REPORT_NUM];/* SCELL???????????????? */
}LRRC_APP_IDLE_SINGLE_FREQ_MEAS_RESULT_STRU;

typedef struct
{
    VOS_UINT16                                   usInterFreqNum;
    VOS_INT16                                    sSNonIntraSearchP;   /* ????????????????????????????????rsrp???????? */
    VOS_INT16                                    sSNonIntraSearchQ;   /* ????????????????????????????????rsrq???????? */
    VOS_INT16                                    sServValue;          /*??????????SP??*/
    VOS_INT16                                    sServqual;           /*??????????SQ??*/
    VOS_INT16                                    sThreshServingLowP;  /* ?????????????????????????????????????? */
    VOS_INT16                                    sThreshServingLowQ;  /* ??????????????R9???? */
    LRRC_APP_IDLE_SINGLE_FREQ_MEAS_RESULT_STRU   astInterFreqMesRslt[LRRC_LCSEL_INTER_FREQ_REPORT_NUM];
}LRRC_APP_IDLE_INTER_INFO_STRU;

/*****************************************************************************
 ??????    : LRRC_APP_IDLE_UTRAN_INFO_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                              usPrimaryCode;
    VOS_INT16                               sRscp;               /* ????1/8 */
    VOS_INT16                               sEcN0;               /* ????1/8 */
    VOS_INT16                               sSValue;             /*??????????SP??*/
    VOS_INT16                               sSqual;              /*??????????SQ??*/
}LRRC_APP_UTRAN_CELL_MEAS_RESULT_STRU;

typedef struct
{
    VOS_UINT16                              enCurrReselPrior;    /* ?????????????????????????????????????? */
    VOS_UINT16                              usArfcn;
    VOS_INT16                               sRssi;               /* ????1/8 */
    VOS_INT16                               sQRxLevMin;          /*????SP????????????????????*/
    VOS_INT16                               sPCompensation;      /* ???? P-Max ?? UE Max Tx power ?????????? PCompensation */
    VOS_INT16                               sQqualMin;           /* S????RSRQ???????? */
    VOS_INT16                               sThreshLowP;         /* ?????????????????????????????????????? */
    VOS_INT16                               sThreshLowQ;         /* ??????????????R9???? */
    VOS_INT16                               sThreshHighP;        /* ?????????????????????????????????????? */
    VOS_INT16                               sThreshHighQ;        /* ??????????????R9???? */
    VOS_UINT16                              usCellNum;
    LRRC_APP_UTRAN_CELL_MEAS_RESULT_STRU    astUtranCellMesRslt[LRRC_LCSEL_UTRAN_CELL_REPORT_NUM];
}LRRC_APP_UTRAN_SIGNLE_FREQ_MEAS_RESULT_STRU;

typedef struct
{
    VOS_UINT16                                      usArfcnNum;
    VOS_INT16                                       sSNonIntraSearchP;   /* ????????????????????????????????rsrp???????? */
    VOS_INT16                                       sSNonIntraSearchQ;   /* ????????????????????????????????rsrq???????? */
    VOS_INT16                                       sServValue;          /*??????????SP??*/
    VOS_INT16                                       sServqual;           /*??????????SQ??*/
    VOS_INT16                                       sThreshServingLowP;  /* ?????????????????????????????????????? */
    VOS_INT16                                       sThreshServingLowQ;  /* ???????????S???R9???? */
    LRRC_APP_UTRAN_SIGNLE_FREQ_MEAS_RESULT_STRU     astUtranFreqMesRslt[LRRC_TRRC_PHY_MAX_SUPPORT_CARRIER_NUM];
}LRRC_APP_IDLE_UTRAN_INFO_STRU;

/*****************************************************************************
 ??????    : LRRC_APP_IDLE_UTRAN_INFO_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                              enCurrReselPrior;   /* ?????????????????????????????????????? */
    VOS_UINT16                              usArfcn;
    VOS_UINT16                              enBandInd;          /* ???????? */
    VOS_INT16                               sRssi;              /* ????1/8 */
    VOS_UINT16                              usNcc;
    VOS_UINT16                              usBcc;
    VOS_INT16                               sSValue;             /*??????????SP??*/
    VOS_INT16                               sQRxLevMin;          /*????SP????????????????????*/
    VOS_INT16                               sPCompensation;      /* ???? P-Max ?? UE Max Tx power ?????????? PCompensation */
    VOS_INT16                               sThreshLowP;         /* ?????????????????????????????????????? */
    VOS_INT16                               sThreshHighP;        /* ?????????????????????????????????????? */
}LRRC_APP_GERAN_SIGNLE_FREQ_MEAS_RESULT_STRU;

typedef struct
{
    VOS_UINT16                                    usArfcnNum;
    VOS_INT16                                     sSNonIntraSearchP;   /* ????????????????????????????????rsrp???????? */
    VOS_INT16                                     sSNonIntraSearchQ;   /* ????????????????????????????????rsrq???????? */
    VOS_INT16                                     sServValue;          /*??????????SP??*/
    VOS_INT16                                     sServqual;           /*??????????SQ??*/
    VOS_INT16                                     sThreshServingLowP;  /* ?????????????????????????????????????? */
    VOS_INT16                                     sThreshServingLowQ;  /* ??????????????R9???? */
    LRRC_APP_GERAN_SIGNLE_FREQ_MEAS_RESULT_STRU   astGeranFreqMesRslt[LRRC_GURRC_GERAN_ARFCN_MAX_NUM];
}LRRC_APP_IDLE_GERAN_INFO_STRU;

/*begin: measurement report 2015-08-18  */
/*****************************************************************************
 ??????    : LRRC_APP_CELL_MEAS_RSLT_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usCellId;
    VOS_UINT16                          usFreqInfo;
    VOS_INT16                           sRsrp;              /* RSRP?????? */
    VOS_INT16                           sRsrq;              /* RSRQ?????? */
    VOS_INT16                           sRssi;              /* RSSI?????? */
} LRRC_APP_CELL_MEAS_RSLT_STRU;

/*****************************************************************************
 ??????    : LRRC_APP_UTRAN_MEAS_RSLT_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usArfcn;
    VOS_UINT16                          usPrimaryCode;
    VOS_INT16                           sRscp;               /* ????1/8 */
    VOS_INT16                           sEcN0;               /* ????1/8 */
    VOS_INT16                           sRssi;               /* ????1/8 */
    VOS_UINT16                          UtranType;
} LRRC_APP_UTRAN_CELL_RSLT_STRU;
/*****************************************************************************
 ??????     :LRRC_GRR_BANDINDICATOR_ENUM
 ????????  :
 ASN.1????   :
 ???????? : 2G????????????
*****************************************************************************/
enum LRRC_APP_GERAN_BANDIND_ENUM
{
    DCS1800                          = 0,
    PCS1900                          = 1,

    LRRC_APP_GERAN_BANDIND_BUTT      = 0x7FFF
};
typedef VOS_UINT16    LRRC_APP_GERAN_BANDIND_ENUM_UINT16;

/*****************************************************************************
 ??????    : RRC_APP_PROTOCOL_STATE
 ????????  :
 ASN.1???? :
 ????????  : RRC????????????
*****************************************************************************/
enum RRC_APP_PROTOCOL_STATE_ENUM
{
    RRC_MEAS_PROTOCOL_STATE_IDLE            = 0 ,
    RRC_MEAS_PROTOCOL_STATE_CONNECTED,
    RRC_MEAS_PROTOCOL_STATE_BUTT            = 0x7FFF
};
typedef VOS_UINT16 RRC_APP_PROTOCOL_STATE_ENUM_UINT16;

/*****************************************************************************
 ??????     :LRRC_GRR_BANDINDICATOR_ENUM
 ????????  :
 ASN.1????   :
 ???????? : 2G????????????
*****************************************************************************/
enum LRRC_GRR_BANDINDICATOR_ENUM
{
    LRRC_GRR_BANDINDICATOR_DCS1800                          = 0,
    LRRC_GRR_BANDINDICATOR_PCS1900                             ,

    LRRC_GRR_BANDINDICATOR_BUTT
};
typedef VOS_UINT16    LRRC_GRR_BANDINDICATOR_ENUM_UINT16;

/*****************************************************************************
 ??????    : LRRC_APP_UTRAN_MEAS_RSLT_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usArfcn;
    LRRC_APP_GERAN_BANDIND_ENUM_UINT16  enBandInd;          /* ???????? */
    VOS_INT16                           sRssi;              /* ????1/8 */
} LRRC_APP_GERAN_CELL_RSLT_STRU;

/*****************************************************************************
 ??????    : LRRC_APP_SERV_MEAS_RSLT_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    RRC_APP_PROTOCOL_STATE_ENUM_UINT16 enState;             /* ???????????? */
    LRRC_APP_CELL_MEAS_RSLT_STRU       stServCellRslt;      /* ???????????????? */
} LRRC_APP_SERV_MEAS_RSLT_STRU;

/*****************************************************************************
 ??????    : LRRC_APP_SCELL_MEAS_RSLT_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    LRRC_APP_CELL_MEAS_RSLT_STRU       astSCellRslt[LRRC_SCELL_MAX_NUM];          /* SCell???????? */
} LRRC_APP_SCELL_MEAS_RSLT_STRU;

/*****************************************************************************
 ??????    : LRRC_APP_INTRA_MEAS_RSLT_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    LRRC_APP_CELL_MEAS_RSLT_STRU       astIntraCellRslt[LRRC_INTRA_CELL_MAX_NUM]; /* ???????????????? */
} LRRC_APP_INTRA_MEAS_RSLT_STRU;

/*****************************************************************************
 ??????    : LRRC_APP_INTER_MEAS_RSLT_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    LRRC_APP_CELL_MEAS_RSLT_STRU       astInterCellRslt[LRRC_INTER_CELL_MAX_NUM]; /* ???????????????? */
} LRRC_APP_INTER_MEAS_RSLT_STRU;
/*****************************************************************************
 ??????    : LRRC_APP_INTER_MEAS_RSLT_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    LRRC_APP_UTRAN_CELL_RSLT_STRU       astUtranCellRslt[LRRC_UTRAN_CELL_MAX_NUM]; /* ???????????????? */
} LRRC_APP_UTRAN_MEAS_RSLT_STRU;
/*****************************************************************************
 ??????    : LRRC_APP_INTER_MEAS_RSLT_STRU
 ????????  :
 ASN.1???? :
 ????????  : ????????APP????????????????????
*****************************************************************************/
typedef struct
{
    LRRC_APP_GERAN_CELL_RSLT_STRU       astGeranCellRslt[LRRC_GERAN_CELL_MAX_NUM]; /* ???????????????? */
} LRRC_APP_GERAN_MEAS_RSLT_STRU;
/*end: measurement report 2015-08-18  */

/* add for Conn Meas Filter Optimize begin */
/*****************************************************************************
 ??????    : LRRC_CONN_MEAS_FILTER_INFO_IND_TYPE_ENUM
 ????????  : LRRC??????????????????
*****************************************************************************/
enum LRRC_CONN_MEAS_FILTER_INFO_IND_TYPE_ENUM
{
    LRRC_CONN_MEAS_FILTER_EUTRA_INFO,    /* _H2ASN_MsgChoice LRRC_CONN_MEAS_FILTER_EUTRA_INFO_STRU */
    LRRC_CONN_MEAS_FILTER_GERA_INFO,    /* _H2ASN_MsgChoice LRRC_CONN_MEAS_FILTER_GERA_INFO_STRU */
    LRRC_CONN_MEAS_FILTER_UTRA_INFO,    /* _H2ASN_MsgChoice LRRC_CONN_MEAS_FILTER_UTRA_INFO_STRU */
    LRRC_CONN_MEAS_FILTER_INFO_IND_TYPE_BUTT
};
typedef VOS_UINT32 LRRC_CONN_MEAS_FILTER_INFO_IND_TYPE_ENUM_UNIT32;

/*****************************************************************************
 ??????    : LRRC_CONN_MEAS_FILTER_EUTRA_INFO_STRU
 ????????  :
 ASN.1???? :
 ????????  : LRRC EUTRA????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16    usCellId;    /* ????id */
    VOS_INT16     sRsrp;       /* ????????RSRP?????? */
    VOS_INT16     sRsrq;       /* ????????RSRQ?????? */
    VOS_INT16     sRssi;       /* ????????RSSI?????? */
    VOS_UINT32    ulMeasTimeInterval;    /* ???????????????? */
}LRRC_CONN_MEAS_FILTER_EUTRA_INFO_STRU;


/*****************************************************************************
 ??????    :LRRC_GRR_BSIC_INFO_STRU
 ????????  :
 ASN.1???? :
 ????????  :CELL BAIC Info??????36331 6.3.4
            usNcc(GSM Network Colour Code)  ????????:(0..7), 8 ??????????
            usBcc(GSM Base Station Colour Code)  ????????:(0..7) , 8 ??????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                                              usNcc;
    VOS_UINT16                                              usBcc;
}LRRC_GRR_BSIC_INFO_STRU;

/*****************************************************************************
 ??????    : LRRC_CONN_MEAS_FILTER_GERA_INFO_STRU
 ????????  :
 ASN.1???? :
 ????????  : LRRC GERAN????????????????????
*****************************************************************************/
typedef struct
{
    PS_BOOL_ENUM_UINT8        enBsicVaild;    /* BSIC???????? */
    VOS_UINT8                 ucResv;         /* ?????? */
    VOS_INT16                 sRssi;          /* ????????Rssi */
    VOS_UINT16                usArfcn;            /* ???? */
    LRRC_GRR_BANDINDICATOR_ENUM_UINT16     enBandInd;          /* ???????? */
    LRRC_GRR_BSIC_INFO_STRU   stBsic;         /* BSIC????????????BSIC???? */
    VOS_UINT32                ulMeasTimeInterval;    /* ???????????????? */
}LRRC_CONN_MEAS_FILTER_GERA_INFO_STRU;

/*****************************************************************************
 ??????    : LRRC_CONN_MEAS_UTRA_TYPE_ENUM
 ????????  : LRRC??????????????????
*****************************************************************************/
enum LRRC_CONN_MEAS_UTRA_TYPE_ENUM
{
    LRRC_CONN_MEAS_FILTER_UTRA_FDD,    /*_H2ASN_Skip*/
    LRRC_CONN_MEAS_FILTER_UTRA_TDD,    /*_H2ASN_Skip*/
    LRRC_CONN_MEAS_FILTER_UTRA_TYPE_BUTT
};
typedef VOS_UINT8 LRRC_CONN_MEAS_UTRA_TYPE_ENUM_UINT8;

/*****************************************************************************
 ??????    : LRRC_CONN_MEAS_FILTER_UTRA_INFO_STRU
 ????????  :
 ASN.1???? :
 ????????  : LRRC FDD UTRA????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                usCellId;       /* ????id */
    LRRC_CONN_MEAS_UTRA_TYPE_ENUM_UINT8    enUtraType;    /* Utra?????? */
    VOS_UINT8                 ucResv;     /* ?????? */
    VOS_INT16                 sRscp;          /* ????????Rscp */
    VOS_INT16                 sEcN0;          /* ????????EcN0 */
    VOS_UINT32                ulMeasTimeInterval;    /* ???????????????? */
}LRRC_CONN_MEAS_FILTER_UTRA_INFO_STRU;

/*****************************************************************************
 ??????    : LRRC_CONN_MEAS_FILTER_INFO_IND_STRU
 ????????  :
 ASN.1???? :
 ????????  : LRRC????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    LRRC_CONN_MEAS_FILTER_INFO_IND_TYPE_ENUM_UNIT32       enUnionStructSelChoice;/*_H2ASN_Skip*/
    union  /* _H2ASN_Skip */
    {      /* _H2ASN_Skip */
        LRRC_CONN_MEAS_FILTER_EUTRA_INFO_STRU        stEutraConnMeasFilterInfo;   /* _H2ASN_Skip */
        LRRC_CONN_MEAS_FILTER_GERA_INFO_STRU        stGeraConnMeasFilterInfo;   /* _H2ASN_Skip */
        LRRC_CONN_MEAS_FILTER_UTRA_INFO_STRU        stUtraConnMeasFilterInfo;   /* _H2ASN_Skip */
    }u;  /* _H2ASN_Skip */
}LRRC_CONN_MEAS_FILTER_INFO_IND_STRU;
/* add for Conn Meas Filter Optimize end */

/*****************************************************************************
 ??????    : APP_OM_MSG_REDF_STRU
 ????????  : APP(????????)??OM????????????(??APP_OM_MSG_STRU????)
*****************************************************************************/
typedef struct
{
     VOS_MSG_HEADER                     /*VOS??*/
     VOS_UINT32          ulMsgId;
     APP_MSG_HEADER                     /*APP??*/
     VOS_UINT8           aucPara[4];    /* ???????? */
}APP_OM_MSG_REDF_STRU;

/* add for lrrc debug stub cmd  beign */

/*****************************************************************************
 ??????    :APP_RRC_DEBUG_STUB_SET_3HOUR_REQ_STRU
 ????????  :????3??????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                      ulMsgId;                /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                      ulOpId;
    VOS_UINT32                      ulTimerLength;         /* 3?????????????? */
}APP_RRC_DEBUG_STUB_SET_3HOUR_REQ_STRU;
/*****************************************************************************
 ??????    :APP_RRC_DEBUG_STUB_HO_FAIL_REQ_STRU
 ????????  :??????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                      ulMsgId;                /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                      ulOpId;
    VOS_UINT32                      ulHoFailFlag;         /* 1??????????????0???????? */
}APP_RRC_DEBUG_STUB_HO_FAIL_REQ_STRU;
/*****************************************************************************
 ??????    :APP_RRC_DEBUG_STUB_REL_ALL_REQ_STRU
 ????????  :????REL ALL
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                      ulMsgId;                /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                      ulOpId;
    VOS_UINT32                      ulRelAllCmd;            /* 1??????REL_ALL??0???????? */
}APP_RRC_DEBUG_STUB_REL_ALL_REQ_STRU;
/*****************************************************************************
 ??????    :RRC_APP_DEBUG_STUB_CMD_CNF_STRU
 ????????  :
 ASN.1???? :
 ????????  :
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgId;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                          ulOpId;
    APP_RESULT_ENUM_UINT32              enResult;
}RRC_APP_DEBUG_STUB_CMD_CNF_STRU;

/* add for lrrc debug stub cmd  end */
/* add for lrrc debug badcell  begin */
/*****************************************************************************
 ??????    :APP_RRC_DEBUG_STUB_ADD_BAD_CELL_REQ_STRU
 ????????  :??????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                          /*_H2ASN_Skip*/
    VOS_UINT32                      ulMsgId;                /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                      ulOpId;
    VOS_UINT32                      ulAddBadCellFlag;         /* 1??????????0???????????? */
    VOS_UINT16                      usBand;
    VOS_UINT16                      usFreq;
    VOS_UINT16                      usPhyCellId;
    VOS_UINT16                      usCause;
    VOS_UINT32                      enExitFLow;
    VOS_UINT32                      ulRsv;
    VOS_UINT8                       ucRsv0;
    VOS_UINT8                       ucRsv1;
    VOS_UINT8                       ucRsv2;
    VOS_UINT8                       ucRsv3;
    VOS_INT16                       sRsrp;
    VOS_INT16                       sRsrq;    /* ?????????????????? */
    VOS_UINT16                      usRsv2;
    VOS_UINT16                      usRsv3;
}APP_RRC_DEBUG_STUB_ADD_BAD_CELL_REQ_STRU;

/* add for lrrc debug badcell  end */

/* add for lrrc observe   begin */
/*****************************************************************************
 ??????    :LTE_CA_STATE_INFO_STRU
 ????????  :
 ASN.1???? :
 ????????  :??????????????????????????
****************************************************************************/
typedef struct
{
    VOS_UINT32    ulMcc;         //??????0xFFFFFFFF
    VOS_UINT32    ulMnc;         //MCC-MNC????????0xFFFFFFFF
    VOS_UINT16    usArfcn;       //????
    VOS_UINT16    usBand;        //????
    VOS_UINT32    ulPCI;         //PCI
    VOS_UINT32    ulCGI;         //CGI????????0xFFFFFFFF
    VOS_UINT16    usTAC;         //TAC????????0xFFFF
    VOS_UINT16    usBW;          //BW????????0xFFFF
    VOS_INT16     sRsrp;
    VOS_INT16     sRssi;
    VOS_INT16     sRsrq;
    VOS_UINT8     ucReserved[6];
} PS_LTE_CELL_INFO_STRU;

/*****************************************************************************
 ??????    :LTE_CA_STATE_INFO_STRU
 ????????  :
 ASN.1???? :
 ????????  :????????????????????????????????????????????????8??????
****************************************************************************/
typedef struct
{
    VOS_UINT32    ulFlag;           //????????????????????????????1
    VOS_UINT16    usLength;         //????????????????????????????????????????
    VOS_UINT8     ucUeState;        /*????*,????????0xFF*/
    VOS_UINT8     ucReserved[5];    //????
    VOS_UINT32    ulActiveCount;    //????????????
    VOS_UINT32    ulNbrCount;       //????????
    PS_LTE_CELL_INFO_STRU     astCellInfo[LRRC_ECELL_QRY_CELL_REPORT_NUM];
} PS_LTE_ECELL_INFO_STRU;

/*****************************************************************************
 ??????    :CA_STATE_INFO
 ????????  :
 ASN.1???? :
 ????????  :Scell????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32    ulCellId;    //????ID
    VOS_UINT32    ulArfcn;     //??????????????????????
} CA_STATE_INFO;

/*****************************************************************************
 ??????    :LTE_CA_STATE_INFO_STRU
 ????????  :
 ASN.1???? :
 ????????  :CA????????
****************************************************************************/
typedef struct
{
    VOS_UINT32        ulFlag;        //??????1
    VOS_UINT16        usLength;      //????
    VOS_UINT8         ucReserved[2];
    VOS_UINT32        ulCount;       //CA??????????
    CA_STATE_INFO     stCAInfo[LRRC_ECELL_QRY_CELL_REPORT_NUM];      //CA????????
} LTE_CA_STATE_INFO_STRU;

/*****************************************************************************
 ??????    :RRC_APP_SCELL_INFO_CNF_STRU
 ????????  :
 ASN.1???? :
 ????????  :??????????????????????????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                         /*_H2ASN_Skip*/
    VOS_UINT32         ulMsgID;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32         ulOpId;
    VOS_UINT8          aucReserved[4];     /* ???? */
}APP_RRC_QUERY_ECELL_INFO_REQ_STRU;

/*****************************************************************************
 ??????    :RRC_APP_SCELL_INFO_CNF_STRU
 ????????  :
 ASN.1???? :
 ????????  :??????APP_RRC_SCELL_INFO_REQ_STRU????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                         /*_H2ASN_Skip*/
    VOS_UINT32         ulMsgID;            /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32         ulOpId;
    VOS_UINT8          aucReserved[4];     /* ???? */
}APP_RRC_QUERY_SCELL_INFO_REQ_STRU;

/*****************************************************************************
 ??????    :RRC_APP_SCELL_INFO_CNF_STRU
 ????????  :
 ASN.1???? :
 ????????  :??????APP_RRC_ECELL_INFO_REQ_STRU????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                               /*_H2ASN_Skip*/
    VOS_UINT32                 ulMsgId;          /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                 ulOpId;
    PS_LTE_ECELL_INFO_STRU     stECellInfo;   /*??????????????????????????*/
}RRC_APP_QUERY_ECELL_INFO_CNF_STRU;

/*****************************************************************************
 ??????    :RRC_APP_SCELL_INFO_CNF_STRU
 ????????  :
 ASN.1???? :
 ????????  :??????APP_RRC_SCELL_INFO_REQ_STRU????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                               /*_H2ASN_Skip*/
    VOS_UINT32                 ulMsgId;          /*_H2ASN_Skip*/
    APP_MSG_HEADER
    VOS_UINT32                 ulOpId;
    LTE_CA_STATE_INFO_STRU     stSCellInfo;      /*CA????????*/
}RRC_APP_QUERY_SCELL_INFO_CNF_STRU;
/* add for lrrc observe   end */


extern PS_BOOL_ENUM_UINT8  LRRC_COMM_LoadDspAlready( MODEM_ID_ENUM_UINT16 enModemId);

extern VOS_UINT32 LHPA_InitDsp( VOS_VOID );
extern VOS_VOID LHPA_DbgSendSetWorkMode_toMaterMode(MODEM_ID_ENUM_UINT16 enModemId);
extern VOS_VOID LHPA_DbgSendSetWorkMode_toSlaveMode(MODEM_ID_ENUM_UINT16 enModemId);

extern VOS_VOID * LAPP_MemAlloc( MODEM_ID_ENUM_UINT16 enModemId,VOS_UINT32 ulSize );
extern VOS_UINT32  LApp_MemFree(MODEM_ID_ENUM_UINT16 usModemId,VOS_VOID *pAddr );
extern VOS_UINT32  LAppSndMsgToLPs(MODEM_ID_ENUM_UINT16 enModemId,APP_LPS_MSG_STRU  *pstAppToPsMsg );
/* Modified  for common CT, 2013-08-10, begin */
extern 	VOS_UINT32 LHPA_InitDsp_ForAT( VOS_VOID );
extern VOS_UINT32 LHPA_InitDspNvForLteTdsCBT(MODEM_ID_ENUM_UINT16 enModemId);
extern VOS_UINT32 LHPA_LoadDspForLteCBT(MODEM_ID_ENUM_UINT16 enModemId);
extern VOS_VOID   LHPA_DbgSetSlaveModeThenMasterMode(MODEM_ID_ENUM_UINT16 enModemId);
/* Modified  for common CT, 2013-08-10, end */

/*****************************************************************************
  8 Fuction Extern
*****************************************************************************/


/*****************************************************************************
  9 OTHERS
*****************************************************************************/










#if (VOS_OS_VER != VOS_WIN32)
#pragma pack()
#else
#pragma pack(pop)
#endif




#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

#endif /* end of AppRrcInterface.h */
