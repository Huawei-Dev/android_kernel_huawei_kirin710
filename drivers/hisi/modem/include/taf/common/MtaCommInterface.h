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

#ifndef __MTACOMMINTERFACE_H__
#define __MTACOMMINTERFACE_H__

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include  "vos.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#pragma pack(4)

/*****************************************************************************
  2 ?????? 
*****************************************************************************/
/*network monitor GSM???? ???????????? */
#define NETMON_MAX_GSM_NCELL_NUM                (6)

/*network monitor UTRAN ???? ???????????? */
#define NETMON_MAX_UTRAN_NCELL_NUM              (16)

/*network monitor LTE ???? ???????????? */
#define NETMON_MAX_LTE_NCELL_NUM                (16)

#define MTA_LRRC_MSG_TYPE_BASE                  (0x1000)            /* MTA??????LTE?????????????? */
#define MTA_COMM_MSG_TYPE_BASE                  (0x2000)            /* MTA?????????????????????????? */

/*****************************************************************************
  3 ????????
*****************************************************************************/

enum MTA_RRC_GSM_BAND_ENUM
{
    MTA_RRC_GSM_BAND_850  = 0x00,
    MTA_RRC_GSM_BAND_900,
    MTA_RRC_GSM_BAND_1800,
    MTA_RRC_GSM_BAND_1900,

    MTA_RRC_GSM_BAND_BUTT
};
typedef VOS_UINT16 MTA_RRC_GSM_BAND_ENUM_UINT16;


enum MTA_NETMON_CELL_TYPE_ENUM
{
    MTA_NETMON_SCELL_TYPE               = 0,
    MTA_NETMON_NCELL_TYPE               = 1,
    MTA_NETMON_CELL_TYPE_BUTT
};

typedef VOS_UINT32 MTA_NETMON_CELL_TYPE_ENUM_UINT32;


enum MTA_NETMON_UTRAN_TYPE_ENUM
{
    MTA_NETMON_UTRAN_FDD_TYPE           = 0,
    MTA_NETMON_UTRAN_TDD_TYPE           = 1,
    MTA_NETMON_UTRAN_TYPE_BUTT
};
typedef VOS_UINT32 MTA_NETMON_UTRAN_TYPE_ENUM_UINT32;


enum MTA_NETMON_RESULT_ENUM
{
    MTA_NETMON_RESULT_NO_ERR            = 0,
    MTA_NETMON_RESULT_ERR               = 1,
    MTA_NETMON_RESULT_BUTT
};
typedef VOS_UINT32 MTA_NETMON_RESULT_ENUM_UINT32;

/*****************************************************************************
 ??????    : MTA_NETMON_CELL_QRY_MODULE_ENUM
 ????????  :
 ASN.1???? :
 ????????  : ????????????????????????????????
*****************************************************************************/
enum MTA_NETMON_CELL_QRY_MODULE_ENUM
{
    MTA_NETMON_CELL_QRY_MODULE_AT    = 0x00,    /* AT??????????????????????????AT^MONSC/AT^MONNC???? */
    MTA_NETMON_CELL_QRY_MODULE_MTC   = 0x01,    /* MTC???????????????????????? */
    MTA_NETMON_CELL_QRY_MODULE_BUTT
};
typedef VOS_UINT32 MTA_NETMON_CELL_QRY_MODULE_ENUM_UINT32;

/*****************************************************************************
 ??????    : MTA_NV_REFRESH_REASON_ENUM
 ????????  :
 ASN.1???? :
 ????????  : NV REFRESH??????
*****************************************************************************/
enum MTA_NV_REFRESH_REASON_ENUM
{
    MTA_NV_REFRESH_REASON_USIM_DEPENDENT                    = 0x00,             /* ???????? */
    MTA_NV_REFRESH_REASON_BUTT
};
typedef VOS_UINT8 MTA_NV_REFRESH_REASON_ENUM_UINT8;

/*****************************************************************************
  4 ????????????
*****************************************************************************/

/*****************************************************************************
  5 ??????????
*****************************************************************************/

/*****************************************************************************
  6 ????????
*****************************************************************************/
enum MTA_COMM_MSG_TYPE_ENUM
{
    ID_MTA_NV_REFRESH_IND               = MTA_COMM_MSG_TYPE_BASE + 0x01,        /* _H2ASN_MsgChoice MTA_NV_REFRESH_IND_STRU */

    ID_MTA_NV_REFRESH_RSP               = MTA_COMM_MSG_TYPE_BASE + 0x02,        /* _H2ASN_MsgChoice MTA_NV_REFRESH_RSP_STRU */

    ID_MTA_COMM_MSG_TYPE_BUTT

};
typedef VOS_UINT32 MTA_COMM_MSG_TYPE_ENUM_UINT32;



/*****************************************************************************
  7 STRUCT????
*****************************************************************************/

/* ========??????????????MTA????????????????======== */

/**************************network monitor??????????????????????**********************************************************/

/* MTA??????????????????????????????2G/3G/????????/???? */

typedef struct
{
    VOS_MSG_HEADER                                     /* ??????*/              /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgName;     /*????????*/             /*_H2ASN_Skip*/
    MTA_NETMON_CELL_TYPE_ENUM_UINT32    enCelltype;    /*0:??????????????1:????????*/
    VOS_UINT32                          ulQryModule;   /* ?????????????????? */
}MTA_RRC_NETMON_CELL_QRY_REQ_STRU;

/*GSM ????????*/

typedef struct
{
    VOS_UINT32                          bitOpBsic     : 1;
    VOS_UINT32                          bitOpCellID   : 1;
    VOS_UINT32                          bitOpLAC      : 1;
    VOS_UINT32                          bitOpSpare    : 29;
    VOS_UINT32                          ulCellID;       /*????ID*/
    VOS_UINT16                          usLAC;          /*????????*/
    VOS_UINT16                          usAfrcn;        /*????*/
    VOS_INT16                           sRSSI;          /* ??????RSSI */
    MTA_RRC_GSM_BAND_ENUM_UINT16        enBand;         /* band 0-3 */
    VOS_UINT8                           ucBsic;         /*??????????*/
    VOS_UINT8                           aucReserved[3];
}MTA_NETMON_GSM_NCELL_INFO_STRU;


/*LTE ????????,????????????????????????????????????*/

typedef struct
{
    VOS_UINT32                          ulPID;            /*????????ID*/
    VOS_UINT32                          ulArfcn;          /*????*/
    VOS_INT16                           sRSRP;            /* RSRP????????????????*/
    VOS_INT16                           sRSRQ;            /* RSRQ????????????????*/
    VOS_INT16                           sRSSI;            /* Receiving signal strength in dbm */
    VOS_UINT8                           aucReserved[2];
}MTA_NETMON_LTE_NCELL_INFO_STRU;


/*WCDMA ????????*/

typedef struct
{
    VOS_UINT16                          usArfcn;          /*????*/
    VOS_UINT16                          usPSC;            /*??????*/
    VOS_INT16                           sECN0;            /*ECN0*/
    VOS_INT16                           sRSCP;            /*RSCP*/
}MTA_NETMON_UTRAN_NCELL_INFO_FDD_STRU;


/*TD_SCDMA ????????,??????????????????????????????*/

typedef struct
{
    VOS_UINT16                          usArfcn;          /*????*/
    VOS_UINT16                          usSC;             /*????*/
    VOS_UINT16                          usSyncID;         /*??????????*/
    VOS_INT16                           sRSCP;            /*RSCP*/
}MTA_NETMON_UTRAN_NCELL_INFO_TDD_STRU;


/*????????????*/

typedef struct
{
    VOS_UINT8                                ucGsmNCellCnt;      /*GSM ????????*/
    VOS_UINT8                                ucUtranNCellCnt;    /*WCDMA ????????*/
    VOS_UINT8                                ucLteNCellCnt;      /*LTE ????????*/
    VOS_UINT8                                ucReserved;
    MTA_NETMON_GSM_NCELL_INFO_STRU           astGsmNCellInfo[NETMON_MAX_GSM_NCELL_NUM];          /*GSM ????????????*/
    MTA_NETMON_UTRAN_TYPE_ENUM_UINT32        enCellMeasTypeChoice;     /* NETMON????????????:FDD,TDD */
    union
    {
        MTA_NETMON_UTRAN_NCELL_INFO_FDD_STRU astFddNCellInfo[NETMON_MAX_UTRAN_NCELL_NUM];         /* FDD???????????? */
        MTA_NETMON_UTRAN_NCELL_INFO_TDD_STRU astTddNCellInfo[NETMON_MAX_UTRAN_NCELL_NUM];         /*  TDD???????????? */
    }u;
    MTA_NETMON_LTE_NCELL_INFO_STRU           astLteNCellInfo[NETMON_MAX_LTE_NCELL_NUM];      /*LTE ????????????*/
}RRC_MTA_NETMON_NCELL_INFO_STRU;


/*********************network monitor????GSM ????????????************************************************/

typedef struct
{
    VOS_MSG_HEADER                                     /* ?????? */             /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgName;     /* ???????? */           /*_H2ASN_Skip*/
}MTA_GRR_NETMON_TA_QRY_REQ_STRU;


typedef struct
{
    VOS_MSG_HEADER                                          /* ?????? */        /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgName;          /* ???????? */      /*_H2ASN_Skip*/
    MTA_NETMON_RESULT_ENUM_UINT32       enResult;           /* ???????? */
    VOS_UINT16                          usTa;               /* ??????TA?? */
    VOS_UINT8                           aucReserved[2];     /* ?????????????????? */
}GRR_MTA_NETMON_TA_QRY_CNF_STRU;


typedef struct
{
    VOS_UINT32                          ulMcc;              /* ?????????? */
    VOS_UINT32                          ulMnc;              /* ?????????? */
    VOS_UINT32                          ulCellID;           /* ????ID */
    VOS_UINT16                          usLac;              /* ???????? */
    VOS_UINT16                          usArfcn;            /* ?????????? */
    VOS_INT16                           sRssi;              /* Receiving signal strength in dbm */
    MTA_RRC_GSM_BAND_ENUM_UINT16        enBand;             /* GSM????(0-3) */
    VOS_UINT8                           ucBsic;             /* ?????????? */
    VOS_UINT8                           ucRxQuality;        /* IDLE????????PS????????????,????????????????????????????[0,7] ,??????99*/
    VOS_UINT8                           aucReserved[2];     /* ?????????????????? */
}GRR_MTA_NETMON_SCELL_INFO_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                              /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgName;      /* ???????? */          /*_H2ASN_Skip*/
    MTA_NETMON_RESULT_ENUM_UINT32       enResult;
    MTA_NETMON_CELL_TYPE_ENUM_UINT32    enCelltype;     /* 0:??????????????1:???????? */
    VOS_UINT32                          ulQryModule;    /* ?????????????????? */
    union
    {
        GRR_MTA_NETMON_SCELL_INFO_STRU  stSCellinfo;    /* GSM???????????????? */
        RRC_MTA_NETMON_NCELL_INFO_STRU  stNCellinfo;    /* GSM???????????? */
    }u;
}GRR_MTA_NETMON_CELL_QRY_CNF_STRU;

/******************************network monitor????UTRAN ????????????****************************************************/


/*FDD ????????????????*/

typedef struct
{
    VOS_UINT32                          bitOpDRX      : 1;
    VOS_UINT32                          bitOpURA      : 1;
    VOS_UINT32                          bitOpSpare    : 30;
    VOS_UINT32                          ulDrx;          /* Discontinuous reception cycle length */
    VOS_INT16                           sECN0;          /*ECN0*/
    VOS_INT16                           sRSSI;          /* Receiving signal strength in dbm */
    VOS_INT16                           sRSCP;          /*Received Signal Code Power in dBm????????????????*/
    VOS_UINT16                          usPSC;          /*??????*/
    VOS_UINT16                          usURA;          /* UTRAN Registration Area Identity */
    VOS_UINT8                           aucReserved[2];

} MTA_NETMON_UTRAN_SCELL_INFO_FDD_STRU;


/*TDD ??????????????????????????????????*/

typedef struct
{
    VOS_UINT32                          ulDrx;              /* Discontinuous reception cycle length */
    VOS_UINT16                          usSC;               /*????*/
    VOS_UINT16                          usSyncID;           /*??????????*/
    VOS_UINT16                          usRac;              /*RAC*/
    VOS_INT16                           sRSCP;              /*RSCP*/
} MTA_NETMON_UTRAN_SCELL_INFO_TDD_STRU;



 /*UTRAN ????????????*/
 
typedef struct
{
    VOS_UINT32                                  bitOpCellID  : 1;
    VOS_UINT32                                  bitOpLAC     : 1;
    VOS_UINT32                                  bitOpSpare   : 30;
    VOS_UINT32                                  ulMcc;                  /*??????????*/
    VOS_UINT32                                  ulMnc;                  /*??????????*/
    VOS_UINT32                                  ulCellID;               /*????ID*/
    VOS_UINT16                                  usArfcn;                /*????*/
    VOS_UINT16                                  usLAC;                  /*????????*/
    MTA_NETMON_UTRAN_TYPE_ENUM_UINT32           enCellMeasTypeChoice;   /* NETMON????????????:FDD,TDD */
    union
    {
        MTA_NETMON_UTRAN_SCELL_INFO_FDD_STRU    stCellMeasResultsFDD;    /* FDD */
        MTA_NETMON_UTRAN_SCELL_INFO_TDD_STRU    stCellMeasResultsTDD;    /*  TDD */
    }u;
}RRC_MTA_NETMON_UTRAN_SCELL_INFO_STRU;



typedef struct
{
    VOS_MSG_HEADER                                              /* ??????*/     /*_H2ASN_Skip*/
    VOS_UINT32                                ulMsgName;        /*????????*/    /*_H2ASN_Skip*/
    MTA_NETMON_RESULT_ENUM_UINT32             enResult;
    MTA_NETMON_CELL_TYPE_ENUM_UINT32          enCelltype;       /*0:??????????????1:????????*/
    VOS_UINT32                                ulQryModule;      /* ?????????????????? */
    union
    {
        RRC_MTA_NETMON_UTRAN_SCELL_INFO_STRU  stSCellinfo;      /* UTRAN???????????????? */
        RRC_MTA_NETMON_NCELL_INFO_STRU        stNCellinfo;      /* UTRAN???????????? */
    }u;
}RRC_MTA_NETMON_CELL_INFO_QRY_CNF_STRU;

/*LTE ????????????*/

typedef struct
{
    VOS_UINT32                                  ulMcc;                  /*??????????*/
    VOS_UINT32                                  ulMnc;                  /*??????????*/
    VOS_UINT32                                  ulCellID;               /*????ID*/
    VOS_UINT32                                  ulPID;                  /*????????ID*/
    VOS_UINT32                                  ulArfcn;                /*????*/
    VOS_UINT16                                  usTAC;
    VOS_INT16                                   sRSRP;
    VOS_INT16                                   sRSRQ;
    VOS_INT16                                   sRSSI;
} MTA_NETMON_EUTRAN_SCELL_INFO_STRU;


typedef struct
{
    VOS_MSG_HEADER                                  /* ?????? */                /*_H2ASN_Skip*/
    VOS_UINT32                          ulMsgName;   /* ???????? */             /*_H2ASN_Skip*/
    MTA_NETMON_CELL_TYPE_ENUM_UINT32    enCelltype;  /* 0????????????????1?????????? */
    VOS_UINT32                          ulQryModule; /* ?????????????????? */
}MTA_LRRC_NETMON_CELL_QRY_REQ_STRU;


typedef struct
{
    VOS_MSG_HEADER                                              /* ??????*/     /*_H2ASN_Skip*/
    VOS_UINT32                                ulMsgName;        /*????????*/    /*_H2ASN_Skip*/
    MTA_NETMON_RESULT_ENUM_UINT32             enResult;
    MTA_NETMON_CELL_TYPE_ENUM_UINT32          enCelltype;       /*0:??????????????1:????????*/
    VOS_UINT32                                ulQryModule;      /* ?????????????????? */
    union
    {
        MTA_NETMON_EUTRAN_SCELL_INFO_STRU     stSCellinfo;      /* LTE???????????????? */
        RRC_MTA_NETMON_NCELL_INFO_STRU        stNCellinfo;      /* LTE???????????? */
    }u;
}LRRC_MTA_NETMON_CELL_INFO_QRY_CNF_STRU;



typedef struct
{
    VOS_MSG_HEADER                                                              /*_H2ASN_Skip*/
    VOS_UINT32                                              ulMsgName;          /*_H2ASN_Skip*/
    MTA_NV_REFRESH_REASON_ENUM_UINT8                        enReason;           /* NV REFRESH???? */
    VOS_UINT8                                               aucRsv[3];
}MTA_NV_REFRESH_IND_STRU;


typedef struct
{
    VOS_MSG_HEADER                                                              /*_H2ASN_Skip*/
    VOS_UINT32                                              ulMsgName;          /*_H2ASN_Skip*/
    VOS_UINT32                                              ulRslt;             /* VOS_OK:??????????:???? */
}MTA_NV_REFRESH_RSP_STRU;

/*****************************************************************************
  10 ????????
*****************************************************************************/
VOS_UINT32 NAS_RegNvRefreshIndMsg(
    MODEM_ID_ENUM_UINT16                enModemId,
    VOS_UINT32                          ulRegPid
);

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

#endif /* end of MtaCommInterface.h */
