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

#ifndef  CSS_AT_INTERFACE_H
#define  CSS_AT_INTERFACE_H

/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "vos.h"


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


#pragma pack(4)

/*****************************************************************************
  2 ??????
*****************************************************************************/
#define MCC_INFO_VERSION_LEN                 (9)
#define AT_CSS_MAX_MCC_ID_NUM                (17)
#define AT_CSS_BLACK_CELL_LIST_VERSION_LEN   (9)
#define AT_CSS_CLOUD_LINE_VERSION_LEN        (9)                 /* ???????????????????????????????? */
#define AT_CSS_PLMN_MAX_LINE_NUM             (64)                /* ????????????????????PLMN???????????????????? */
#define AT_CSS_TACLAC_MAX_LINE_NUM           (10)                /* ????????????????????TAC/LAC???????????????????? */

#define AT_CSS_MRU_MAX_NUM                   (10)                /* MRU?????????????????? */

/*****************************************************************************
  3 ????????
*****************************************************************************/

enum CSS_AT_MSG_TYPE_ENUM
{
    /* AT->CSS */
    ID_AT_CSS_MCC_INFO_SET_REQ                = 0x0001,                           /* _H2ASN_MsgChoice AT_CSS_MCC_INFO_SET_REQ_STRU */
    ID_AT_CSS_MCC_VERSION_INFO_REQ            = 0x0002,                           /* _H2ASN_MsgChoice AT_CSS_MCC_VERSION_INFO_REQ_STRU */
    ID_AT_CSS_BLACK_CELL_LIST_SET_REQ         = 0x0003,                           /* _H2ASN_MsgChoice AT_CSS_BLACK_CELL_LIST_SET_REQ_STRU */
    ID_AT_CSS_BLACK_CELL_LIST_QUERY_REQ       = 0x0004,                           /* _H2ASN_MsgChoice AT_CSS_BLACK_CELL_LIST_QUERY_REQ_STRU */
    ID_AT_CSS_LINE_INDEX_LIST_SET_REQ         = 0x0005,                           /* _H2ASN_MsgChoice AT_CSS_LINE_INDEX_LIST_SET_REQ_STRU */
    ID_AT_CSS_LINE_DETAIL_SET_REQ             = 0x0006,                           /* _H2ASN_MsgChoice AT_CSS_LINE_DETAIL_SET_REQ_STRU */
    ID_AT_CSS_LINE_INDEX_LIST_QUERY_REQ       = 0x0007,                           /* _H2ASN_MsgChoice AT_CSS_LINE_INDEX_LIST_QUERY_REQ_STRU */
    ID_AT_CSS_VZWMRUC_SET_REQ                 = 0x0008,                           /* _H2ASN_MsgChoice AT_CSS_VZWMRUC_SET_REQ_STRU */
    ID_AT_CSS_VZWMRUE_SET_REQ                 = 0x0009,                           /* _H2ASN_MsgChoice AT_CSS_VZWMRUE_SET_REQ_STRU */
    ID_AT_CSS_VZWMRUE_QUERY_REQ               = 0x000a,                           /* _H2ASN_MsgChoice AT_CSS_VZWMRUE_QUERY_REQ_STRU */

    /* CSS->AT */
    ID_CSS_AT_MCC_INFO_SET_CNF                = 0x1001,                           /* _H2ASN_MsgChoice CSS_AT_MCC_INFO_SET_CNF_STRU */
    ID_CSS_AT_MCC_VERSION_INFO_CNF            = 0x1002,                           /* _H2ASN_MsgChoice CSS_AT_MCC_VERSION_INFO_CNF_STRU */
    ID_CSS_AT_QUERY_MCC_INFO_NOTIFY           = 0x1003,                           /* _H2ASN_MsgChoice CSS_AT_QUERY_MCC_INFO_NOTIFY_STRU */
    ID_CSS_AT_BLACK_CELL_LIST_SET_CNF         = 0x1004,                           /* _H2ASN_MsgChoice CSS_AT_BLACK_CELL_LIST_SET_CNF_STRU */
    ID_CSS_AT_BLACK_CELL_LIST_QUERY_CNF       = 0x1005,                           /* _H2ASN_MsgChoice CSS_AT_BLACK_CELL_LIST_QUERY_CNF_STRU */
    ID_CSS_AT_BLACK_CELL_MCC_NOTIFY           = 0x1006,                           /* _H2ASN_MsgChoice CSS_AT_BLACK_CELL_MCC_NOTIFY_STRU */
    ID_CSS_AT_LINE_INDEX_LIST_SET_CNF         = 0x1007,                           /* _H2ASN_MsgChoice CSS_AT_LINE_INDEX_LIST_SET_CNF_STRU */
    ID_CSS_AT_LINE_DETAIL_SET_CNF             = 0x1008,                           /* _H2ASN_MsgChoice CSS_AT_LINE_DETAIL_SET_CNF_STRU */
    ID_CSS_AT_LINE_INDEX_LIST_QUERY_CNF       = 0x1009,                           /* _H2ASN_MsgChoice CSS_AT_LINE_INDEX_LIST_QUERY_CNF_STRU */
    ID_CSS_AT_LINE_PLMN_NOTIFY                = 0x100a,                           /* _H2ASN_MsgChoice CSS_AT_LINE_PLMN_NOTIFY_STRU */
    ID_CSS_AT_LINE_INDEX_NOTIFY               = 0x100b,                           /* _H2ASN_MsgChoice CSS_AT_LINE_INDEX_NOTIFY_STRU */

    ID_CSS_AT_VZWMRUC_SET_CNF                 = 0x100c,                           /* _H2ASN_MsgChoice CSS_AT_VZWMRUC_SET_CNF_STRU */
    ID_CSS_AT_VZWMRUE_SET_CNF                 = 0x100d,                           /* _H2ASN_MsgChoice CSS_AT_VZWMRUE_SET_CNF_STRU */
    ID_CSS_AT_VZWMRUE_QUERY_CNF               = 0x100e,                           /* _H2ASN_MsgChoice CSS_AT_VZWMRUE_QUERY_CNF_STRU */


    ID_CSS_AT_MSG_BUTT
};
typedef  VOS_UINT32  CSS_AT_MSG_TYPE_ENUM_UINT32;


enum AT_CSS_RAT_ENUM
{
    AT_CSS_RAT_TYPE_GSM = 0,                           /* GSM???????? */
    AT_CSS_RAT_TYPE_WCDMA,                             /* WCDMA???????? */
    AT_CSS_RAT_TYPE_LTE,                               /* LTE???????? */

    AT_CSS_RAT_TYPE_BUTT
};
typedef  VOS_UINT8  AT_CSS_RAT_ENUM_UINT8;

enum AT_CSS_SET_MCC_OPERATE_TYPE_ENUM
{
    AT_CSS_SET_MCC_TYPE_ADD_MCC = 0,                   /* ????MCC */
    AT_CSS_SET_MCC_TYPE_DELETE_ALL_MCC,                /* ????????MCC???? */
    AT_CSS_SET_MCC_TYPE_DELETE_ONE_MCC,                /* ????????MCC???? */

    AT_CSS_SET_MCC_TYPE_BUTT
};
typedef  VOS_UINT8  AT_CSS_SET_MCC_OPERATE_TYPE_ENUM_UINT8;


enum AT_CSS_BLACK_CELL_LIST_OPERATE_TYPE_ENUM
{
    AT_CSS_BLACK_CELL_LIST_ADD_ONE      = 0,           /* ?????????????????? */
    AT_CSS_BLACK_CELL_LIST_DELETE_ALL,                 /* ?????????????????? */

    AT_CSS_BLACK_CELL_LIST_TYPE_BUTT
};
typedef  VOS_UINT8  AT_CSS_BLACK_CELL_LIST_OPERATE_TYPE_ENUM_UINT8;

/*****************************************************************************
??????    : AT_CSS_LINE_INDEX_LIST_OPERATE_TYPE_ENUM
????????  : ??????????????????

*****************************************************************************/
enum AT_CSS_LINE_INDEX_LIST_OPERATE_TYPE_ENUM
{
    AT_CSS_LINE_INDEX_LIST_ADD          = 0,           /* ???????????????? */
    AT_CSS_LINE_INDEX_LIST_DELETE_ALL,                 /* ???????????????? */

    AT_CSS_LINE_INDEX_LIST_TYPE_BUTT
};
typedef  VOS_UINT8  AT_CSS_LINE_INDEX_LIST_OPERATE_TYPE_ENUM_UINT8;

/*****************************************************************************
??????    : AT_CSS_LINE_DETAIL_OPERATE_TYPE_ENUM
????????  : ??????????????????????????

*****************************************************************************/
enum AT_CSS_LINE_DETAIL_OPERATE_TYPE_ENUM
{
    AT_CSS_LINE_DETAIL_ADD              = 0,           /* ???????????????????? */
    AT_CSS_LINE_DETAIL_DELETE_ALL,                     /* ???????????????????? */

    AT_CSS_LINE_DETAIL_TYPE_BUTT
};
typedef  VOS_UINT8  AT_CSS_LINE_DETAIL_OPERATE_TYPE_ENUM_UINT8;

/*****************************************************************************
??????    : AT_CSS_LINE_DETAIL_INFO_TYPE_ENUM
????????  : ??????????????????????

*****************************************************************************/
enum AT_CSS_LINE_DETAIL_INFO_TYPE_ENUM
{
    AT_CSS_LINE_DETAIL_INFO_TACLAC_PAIR     = 0,           /* TACLAC?? */
    AT_CSS_LINE_DETAIL_INFO_HO_PATH,                       /* HO???????? */
    AT_CSS_LINE_DETAIL_INFO_HO_BAR,                        /* HO????Bar???? */
    AT_CSS_LINE_DETAIL_INFO_LTE_HO_PATH,                   /* LTE???????? */
    AT_CSS_LINE_DETAIL_INFO_NO_INFO         = 0xFF         /* ?????????????????????????? */
};
typedef  VOS_UINT8  AT_CSS_LINE_DETAIL_INFO_TYPE_ENUM_UINT8;

/*****************************************************************************
  4 ????????
*****************************************************************************/

typedef struct
{
    /*MCC??aucMcc[2]????????????,mcc??460:
    ---------------------------------------------------------------------------
                 ||(BIT8)|(BIT7)|(BIT6)|(BIT5)|(BIT4)|(BIT3)|(BIT2)|(BIT1)
    ---------------------------------------------------------------------------
    aucMcc[0]    ||    MCC digit 2 = 6        |           MCC digit 1 = 4
    ---------------------------------------------------------------------------
    aucMcc[1]    ||    ????                   |           MCC digit 3 = 0
    ---------------------------------------------------------------------------*/
    VOS_UINT8                           aucMcc[2];                              /* MCC ID */
    VOS_UINT8                           aucRsv[2];
} AT_CSS_MCC_ID_STRU;


typedef struct
{
    VOS_UINT32                          ulMcc;
    VOS_UINT32                          ulMnc;
}CSS_AT_PLMN_ID_STRU;

typedef struct
{
    VOS_UINT32                          ulFreqHigh;
    VOS_UINT32                          ulFreqLow;
} AT_CSS_FREQ_RANGE_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                              /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                                /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           aucRsv[2];
} AT_CSS_MCC_VERSION_INFO_REQ_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                              /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                                /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           aucRsv[1];
    VOS_UINT8                           aucVersionId[MCC_INFO_VERSION_LEN];     /* ??????????????xx.xx.xxx */
} CSS_AT_MCC_VERSION_INFO_CNF_STRU;



typedef struct
{
    VOS_MSG_HEADER                                                                        /* _H2ASN_Skip */
    VOS_UINT32                                    ulMsgId;                                /* _H2ASN_Skip */
    MODEM_ID_ENUM_UINT16                          usModemId;

    VOS_UINT16                                    usClientId;
    VOS_UINT8                                     ucSeq;                                  /* ?????? */
    AT_CSS_SET_MCC_OPERATE_TYPE_ENUM_UINT8        ucOperateType;                          /* ???????? */
    VOS_UINT8                                     aucVersionId[MCC_INFO_VERSION_LEN];     /* ??????????????xx.xx.xxx */

    VOS_UINT8                                     aucRsv[1];

    /*
        1)aucMccINfoBuff??????????MCC??????????????????????????ulMccInfoBuffLen????????????????
        2)aucMccINfoBuff??????????AT_CSS_MCC_INFO_STRU????????????????MNC????,
          BAND??????????????????????????????????????????????

        typedef struct
        {
            VOS_UINT8                           ucSupportFlag;    // 1:????????GSM 2:????????WCDMA 4:????????LTE??????????????????
            AT_CSS_FREQ_RANGE_STRU              stFreqRange;
        } AT_CSS_FREQ_RANGE_WITH_RAT_STRU;

        typedef struct
        {
            VOS_UINT8                                   ucBandInd;
            VOS_UINT8                                   ucFreqRangNum;
            //????????????ucFreqRangNum??AT_CSS_FREQ_RANGE_WITH_RAT_STRU????
              ??FreqRange??????????????FreqRange??????????ucFreqRangNum????0
            AT_CSS_FREQ_RANGE_WITH_RAT_STRU             astFreqRangeArray[ucFreqRangNum];

            VOS_UINT8                                   ucPreConfigFreqNum;
            //????????????ucPreConfigFreqNum??AT_CSS_FREQ_RANGE_WITH_RAT_STRU????
              ??PreConfigFreq??????????????PreConfigFreq??????????ucPreConfigFreqNum????0
            AT_CSS_FREQ_RANGE_WITH_RAT_STRU             astPreConfigFreqArray[ucPreConfigFreqNum];      //????????????
        }AT_CSS_BAND_INFO_STRU;


        typedef struct
        {
            MNC??aucMnc[2]??????????????mnc??01:
            ---------------------------------------------------------------------------
                         ||(BIT8)|(BIT7)|(BIT6)|(BIT5)|(BIT4)|(BIT3)|(BIT2)|(BIT1)
            ---------------------------------------------------------------------------
            aucMnc[0]    ||    MNC digit 3 = f        |           ????
            ---------------------------------------------------------------------------
            aucMnc[1]    ||    MNC digit 2 = 1        |           MNC digit 1 = 0
            ---------------------------------------------------------------------------
            VOS_UINT8                           aucMnc[2];
            VOS_UINT8                           ucBandCount;// BAND??????
            //????????????ucBandCount??band????????????????BAND??????????ucBandCount????0
            AT_CSS_BAND_INFO_STRU               astBandArray[ucBandCount];
        }AT_CSS_MNC_INFO_STRU;


        typedef struct
        {
            MCC??aucMcc[2]????????????,mcc??460:
            ---------------------------------------------------------------------------
                         ||(BIT8)|(BIT7)|(BIT6)|(BIT5)|(BIT4)|(BIT3)|(BIT2)|(BIT1)
            ---------------------------------------------------------------------------
            aucMcc[0]    ||    MCC digit 2 = 6        |           MCC digit 1 = 4
            ---------------------------------------------------------------------------
            aucMcc[1]    ||    ????                   |           MCC digit 3 = 0
            ---------------------------------------------------------------------------
            VOS_UINT8                           aucMcc[2];
            VOS_UINT8                           ucMncCount;// MNC??????
            //????????????ucMncCount??AT_CSS_MNC_INFO_STRU??????mnc??????????????mnc??????????ucMncCount????0
            AT_CSS_MNC_INFO_STRU                astMncAarry[ucMncCount];
        }AT_CSS_MCC_INFO_STRU;


        3)aucMccINfoBuff????????????????AP??CSS??????????AT??????????????AP??????????????????
          ??????????????????????AT??AT????????????????????????????????????CSS??
          ????AP????????????????0x22??????????????????'22'??AT????????????0x22;
        4)aucMccINfoBuff????????????????
        5)ulMccInfoBuffLen????????1.6K??
    */
    VOS_UINT32                          ulMccInfoBuffLen;
    VOS_UINT8                           aucMccInfoBuff[4];
} AT_CSS_MCC_INFO_SET_REQ_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                                                              /* _H2ASN_Skip */
    VOS_UINT32                                              ulMsgId;                                            /* _H2ASN_Skip */
    VOS_UINT16                                              usClientId;
    VOS_UINT8                                               ucSeq;                                              /* ?????? */
    AT_CSS_BLACK_CELL_LIST_OPERATE_TYPE_ENUM_UINT8          enOperateType;                                      /* ???????? */
    VOS_UINT8                                               aucVersionId[AT_CSS_BLACK_CELL_LIST_VERSION_LEN];   /* ??????????????xx.xx.xxx */
    AT_CSS_RAT_ENUM_UINT8                                   enRatType;                                          /* ???????? */
    VOS_UINT8                                               aucRsv[2];

    /*
        1)aucBlackCellListBuff??????????????????????????????????????????ulBlackCellListBuffLen????????????????
        2)aucBlackCellListBuff??????????AT_CSS_GSM_CLOUD_BLACKCELL_STRU??????????

        ????????BS1,BS2??BS3????????????????????AT_CSS_GSM_CLOUD_BLACKCELL_STRU????????????????
        ????ucPairCount??astBlackListArray??????????
        typedef struct
        {
            CSS_PLMN_ID_STRU    stPlmn;
            VOS_UNIT8           ucPairCount;
            //????????????ucPairCount??AT_CSS_GSM_CLOUD_BLACKCELL_PAIR_STRU??????pair??????
              ??????????????mcc????????????????AP????????????MCC????????Modem??????MCC????????????????
              ????????????????^REPORTBLACKCELLMCC????????????
            AT_CSS_GSM_CLOUD_BLACKCELL_PAIR_STRU astBlackListPairArray[ucPairCount];
        }AT_CSS_GSM_CLOUD_BLACKCELL_STRU;

        typedef struct
        {
            VOS_UNIT32  ulMcc; //Modem????plmn????;????460---0x00000604
            VOS_UNIT32  ulMnc; //Modem????plmn????;???? 01---0x000F0100
        }CSS_PLMN_ID_STRU;

        typedef struct
        {
            VOS_UNIT16  usSourceCellLai;
            VOS_UNIT16  usSourceCellId;
            VOS_UNIT16  usBlackCellArfcn; //??????GSM????????????????0x1029????GSM900????,41????
            VOS_UNIT8   ucBlackCellBsic;  //????ncc,bcc;????0x14????<2,4>
            VOS_UNIT8   ucBlackCellReduceVal;//??????????????????????????db??
        }AT_CSS_GSM_CLOUD_BLACKCELL_PAIR_STRU;
    */

    VOS_UINT32                                              ulBlackCellListBuffLen;
    VOS_UINT8                                               aucBlackCellListBuff[4];
} AT_CSS_BLACK_CELL_LIST_SET_REQ_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                              /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                                /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           aucRsv[2];
} AT_CSS_BLACK_CELL_LIST_QUERY_REQ_STRU;

typedef struct
{
    VOS_MSG_HEADER                                                              /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                                /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           ucSeq;                                  /* ?????? */
    VOS_UINT8                           aucRsv[1];

    VOS_UINT32                          ulResult;                               /*0??????????1????????*/
} CSS_AT_MCC_INFO_SET_CNF_STRU;

typedef struct
{
    VOS_MSG_HEADER                                                              /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                                /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           aucRsv[1];
    VOS_UINT8                           aucVersionId[MCC_INFO_VERSION_LEN];     /* ??????????????xx.xx.xxx */
    VOS_UINT32                          ulMccNum;                               /* MCC ???? */
    AT_CSS_MCC_ID_STRU                  astMccId[AT_CSS_MAX_MCC_ID_NUM];        /* MCC ID???? */
} CSS_AT_QUERY_MCC_INFO_NOTIFY_STRU;


typedef struct
{
    VOS_UINT32                          ulMccNum;                                               /* MCC ???? */
    VOS_UINT32                          aulMcc[AT_CSS_MAX_MCC_ID_NUM];                          /* MCC ????,Modem????plmn????;????460---0x00000604 */
} CSS_AT_BLACK_CELL_MCC_INFO_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                          /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                            /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           ucSeq;                              /* ?????? */
    VOS_UINT8                           ucReserved;
    VOS_UINT32                          ulResult;                           /* VOS_OK??????????VOS_ERR???????? */
} CSS_AT_BLACK_CELL_LIST_SET_CNF_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                                              /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                                                /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           ucReserved;
    VOS_UINT8                           aucVersionId[AT_CSS_BLACK_CELL_LIST_VERSION_LEN];       /* ??????????????xx.xx.xxx */
    CSS_AT_BLACK_CELL_MCC_INFO_STRU     stMccInfo;                                              /* ??????MCC???? */
} CSS_AT_BLACK_CELL_LIST_QUERY_CNF_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                                              /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                                                /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           ucReserved;
    VOS_UINT8                           aucVersionId[AT_CSS_BLACK_CELL_LIST_VERSION_LEN];       /* ??????????????xx.xx.xxx */
    CSS_AT_BLACK_CELL_MCC_INFO_STRU     stMccInfo;                                              /* ??????MCC???? */
} CSS_AT_BLACK_CELL_MCC_NOTIFY_STRU;



typedef struct
{
    VOS_MSG_HEADER                                                                                              /* _H2ASN_Skip */
    VOS_UINT32                                              ulMsgId;                                            /* _H2ASN_Skip */
    VOS_UINT16                                              usClientId;
    MODEM_ID_ENUM_UINT16                                    usModemId;
    VOS_UINT8                                               ucSeq;                                              /* ?????? */
    AT_CSS_LINE_INDEX_LIST_OPERATE_TYPE_ENUM_UINT8          enOperateType;                                      /* ???????? */
    VOS_UINT8                                               aucVersionId[AT_CSS_CLOUD_LINE_VERSION_LEN];        /* ??????????????xx.xx.xxx */
    VOS_UINT8                                               ucRsv;

    /*
        1)aucLineIndexListBuff????????????????????????????????????????????????ulLineIndexListBuffLen????????????????
        2)aucLineIndexListBuff??????????AT_CSS_CLOUD_LINE_INDEX_LIST_INFO_STRU??????????
        ??LineIndex??0xFFFF????????PLMN????????????????????

        typedef struct
        {
            CSS_PLMN_ID_STRU stPlmn;
            VOS_UNIT16          usLineIndex;
            VOS_UINT8           ucTacNum;
            VOS_UINT8           ucLacNum;
            //????????????ucTacNum??VOS_UINT16??TAC??????????
            VOS_UINT16          ausTacList[ucTacNum];
            //????????????ucLacNum??VOS_UINT16??LAC??????????
            VOS_UINT16          ausLacList[ucLacNum];
        }AT_CSS_CLOUD_LINE_INDEX_INFO_STRU;

    */
    VOS_UINT32                                              ulLineIndexListBuffLen;
    VOS_UINT8                                               aucLineIndexListBuff[4];
}AT_CSS_LINE_INDEX_LIST_SET_REQ_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                          /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                            /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           ucSeq;                              /* ?????? */
    VOS_UINT8                           ucRsv;
    VOS_UINT32                          ulResult;                           /* VOS_OK??????????VOS_ERR???????? */
} CSS_AT_LINE_INDEX_LIST_SET_CNF_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                                                              /* _H2ASN_Skip */
    VOS_UINT32                                              ulMsgId;                                            /* _H2ASN_Skip */
    VOS_UINT16                                              usClientId;
    MODEM_ID_ENUM_UINT16                                    usModemId;
    VOS_UINT8                                               ucSeq;                                              /* ?????? */
    AT_CSS_LINE_DETAIL_OPERATE_TYPE_ENUM_UINT8              enOperateType;                                      /* ???????? */
    VOS_UINT8                                               aucVersionId[AT_CSS_CLOUD_LINE_VERSION_LEN];   /* ??????????????xx.xx.xxx */
    VOS_UINT8                                               ucRsv;

    /*
        1)aucLineDetailBuff????????????????????????????????????????????????ulLineDetailBuffLen????????????????

        2)aucLineDetailBuff??????????AT_CSS_LINE_DETAIL_INFO_STRU??????????:
        typedef struct
        {
            CSS_PLMN_ID_STRU                             stPlmn;
            VOS_UNIT16                                      usLineIndex;
            AT_CSS_LINE_DETAIL_INFO_TYPE_ENUM_UINT8         enInfoType;
            VOS_UINT8                                       aucLeftBuff[ulLineDetailBuffLen-11];
        }AT_CSS_LINE_DETAIL_INFO_STRU;

        3)AT_CSS_LINE_DETAIL_INFO_STRU????????aucLeftBuff????enInfoType????????????????
          i.??enInfoType??AT_CSS_LINE_DETAIL_INFO_TACLAC_PAIR??aucLeftBuff??????????AT_CSS_CLOUD_LINE_TACLAC_MAP_INFO_STRU????????????
            typedef struct
            {
                VOS_UITN16                                       usTac;
                VOS_UINT16                                       usLac;
            }AT_CSS_CLOUD_LINE_TACLAC_PAIR_INFO_STRU;
            typedef struct
            {
                VOS_UINT8                                        ucPairNum;
                //????????????ucPairNum??AT_CSS_CLOUD_LINE_TACLAC_PAIR_INFO_STRU????????
                AT_CSS_CLOUD_LINE_TACLAC_PAIR_INFO_STRU          astCloudTacLacPairInfoList[ucPairNum];
            }AT_CSS_CLOUD_LINE_TACLAC_MAP_INFO_STRU;

          ii.??enInfoType??AT_CSS_LINE_DETAIL_INFO_HO_PATH??aucLeftBuff??????????AT_CSS_CLOUD_LINE_HO_PATH_INFO_STRU????????????
            typedef struct
            {
                VOS_UINT32                                       usSrcCellId;
                VOS_UINT16                                       usSrcArfcn;
                VOS_UINT16                                       usSrcBsic;
                VOS_UINT16                                       usDstArfcn;
                VOS_UINT16                                       usDstBsic;
                VOS_UINT16                                       usRxlevA;
                VOS_UINT16                                       usRxlevB;
            }AT_CSS_CLOUD_LINE_HO_PATH_CELL_INFO_STRU;
            typedef struct
            {
                VOS_UITN16                                       usLac;
                VOS_UINT8                                        ucCellNum;
                //????????????ucCellNum??AT_CSS_CLOUD_LINE_HO_PATH_CELL_INFO_STRU????????
                AT_CSS_CLOUD_LINE_HO_PATH_CELL_INFO_STRU         astCellInfoList[ucCellNum];
            }AT_CSS_CLOUD_LINE_HO_PATH_LAC_INFO_STRU;
            typedef struct
            {
                VOS_UINT8                                        ucRat;
                VOS_UINT8                                        ucDirection;
                VOS_UINT8                                        ucLacNum;
                //????????????ucLacNum??AT_CSS_CLOUD_LINE_HO_PATH_LAC_INFO_STRU????????
                AT_CSS_CLOUD_LINE_HO_PATH_LAC_INFO_STRU          astLacInfoList[ucLacNum];
            }AT_CSS_CLOUD_LINE_HO_PATH_INFO_STRU;
          iii.??enInfoType??AT_CSS_LINE_DETAIL_INFO_HO_BAR??aucLeftBuff??????????AT_CSS_CLOUD_LINE_HO_BAR_INFO_STRU????????????
            typedef struct
            {
                VOS_UINT16                                       usLac;
                VOS_UINT32                                       usSrcCellId;
                VOS_UINT16                                       usSrcArfcn;
                VOS_UINT16                                       usSrcBsic;
                VOS_UINT16                                       usDstArfcn;
                VOS_UINT16                                       usDstBsic;
            }AT_CSS_CLOUD_LINE_HO_BAR_CELL_INFO_STRU;
            typedef struct
            {
                VOS_UINT8                                        ucRat;
                VOS_UINT8                                        ucCellNum;
                //????????????ucCellNum??AT_CSS_CLOUD_LINE_HO_BAR_CELL_INFO_STRU????????
                AT_CSS_CLOUD_LINE_HO_BAR_CELL_INFO_STRU          astCellInfoList[ucCellNum];
            }AT_CSS_CLOUD_LINE_HO_BAR_INFO_STRU;
          iiii.??enInfoType??AT_CSS_LINE_DETAIL_INFO_NO_INFO????????PLMN/??????????????????????????????modem??????ap??????PLMN/??????????????
          iiiii.??enInfoType????????????????????????????????????????????????????
    */
    VOS_UINT32                                              ulLineDetailBuffLen;
    VOS_UINT8                                               aucLineDetailBuff[4];
} AT_CSS_LINE_DETAIL_SET_REQ_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                          /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                            /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           ucSeq;                              /* ?????? */
    VOS_UINT8                           ucRsv;
    VOS_UINT32                          ulResult;                           /* VOS_OK??????????VOS_ERR???????? */
}CSS_AT_LINE_DETAIL_SET_CNF_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                          /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                            /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    MODEM_ID_ENUM_UINT16                usModemId;
}AT_CSS_LINE_INDEX_LIST_QUERY_REQ_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                          /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                            /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           aucVersionId[AT_CSS_CLOUD_LINE_VERSION_LEN];   /* ?????? */
    VOS_UINT8                           ucRsv;
    CSS_AT_PLMN_ID_STRU                 stRplmnInfo;                        /* rplmn???? */
    VOS_UINT32                          ulResult;                           /* ???????????????? */
}CSS_AT_LINE_INDEX_LIST_QUERY_CNF_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                          /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                            /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           aucRsv[2];
    CSS_AT_PLMN_ID_STRU                 stRplmnInfo;                        /* rplmn???? */
} CSS_AT_LINE_PLMN_NOTIFY_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                          /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                            /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;                         /* _H2ASN_Skip */
    VOS_UINT16                          usLineNum;                          /* ???????? */
    VOS_UINT16                          ausLineIndexList[AT_CSS_TACLAC_MAX_LINE_NUM]; /* ???????? */
    CSS_AT_PLMN_ID_STRU                 stPlmnId;                           /* plmn id */
} CSS_AT_LINE_INDEX_NOTIFY_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                          /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                            /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    MODEM_ID_ENUM_UINT16                usModemId;
} AT_CSS_VZWMRUC_SET_REQ_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                              /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                                /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           aucRsv[2];
    VOS_UINT32                          ulResult;                               /* VOS_OK??????????VOS_ERR???????? */
} CSS_AT_VZWMRUC_SET_CNF_STRU;


typedef struct
{
    VOS_UINT8                           ucEntry;
    AT_CSS_RAT_ENUM_UINT8               enRat;
    VOS_UINT16                          usBandId;
    CSS_AT_PLMN_ID_STRU                 stPlmnId;
}AT_CSS_MRU_STRU;



typedef struct
{
    VOS_MSG_HEADER                                                          /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                            /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    MODEM_ID_ENUM_UINT16                usModemId;
    AT_CSS_MRU_STRU                     stMru;
} AT_CSS_VZWMRUE_SET_REQ_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                              /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                                /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           aucRsv[2];
    VOS_UINT32                          ulResult;                               /* VOS_OK??????????VOS_ERR???????? */
} CSS_AT_VZWMRUE_SET_CNF_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                          /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                            /* _H2ASN_Skip */
    VOS_UINT16                          usClientId;
    MODEM_ID_ENUM_UINT16                usModemId;
} AT_CSS_VZWMRUE_QUERY_REQ_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                              /* _H2ASN_Skip */
    VOS_UINT32                          ulMsgId;                                /* _H2ASN_Skip */
    VOS_UINT32                          ulResult;                               /* VOS_OK??????????VOS_ERR???????? */
    VOS_UINT16                          usClientId;
    VOS_UINT8                           ucRsv;
    VOS_UINT8                           ucMruNum;
    AT_CSS_MRU_STRU                     astMru[AT_CSS_MRU_MAX_NUM];
} CSS_AT_VZWMRUE_QUERY_CNF_STRU;


/*****************************************************************************
  5 ????????????
*****************************************************************************/


/*****************************************************************************
  6 ????????????
*****************************************************************************/

/*****************************************************************************
  7 OTHERS????
*****************************************************************************/

/* ASN???????? */
typedef struct
{
    VOS_UINT32                          ulMsgId;                                /*_H2ASN_MsgChoice_Export CSS_AT_MSG_TYPE_ENUM_UINT32 */
    VOS_UINT8                           aucMsg[4];
    /***************************************************************************
        _H2ASN_MsgChoice_When_Comment          CSS_AT_MSG_TYPE_ENUM_UINT32
    ****************************************************************************/
}CSS_AT_INTERFACE_MSG_DATA;
/*_H2ASN_Length UINT32*/

typedef struct
{
    VOS_MSG_HEADER
    CSS_AT_INTERFACE_MSG_DATA           stMsgData;
} CssAtInterface_MSG;


#if ((VOS_OS_VER == VOS_WIN32) || (VOS_OS_VER == VOS_NUCLEUS))
#pragma pack()
#else
#pragma pack(0)
#endif


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif


