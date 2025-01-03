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

#ifndef __CBTRL_H__
#define __CBTRL_H__

/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "vos.h"
#if (OSA_CPU_CCPU == VOS_OSA_CPU)
#include "msp_diag_comm.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif

/*****************************************************************************
  2 ??????
*****************************************************************************/
/*OM<->APP : NON SIGALING Transparent Message.*/
#define APP_OM_NON_SIG_BT_TRAN_REQ      (0x1601)
#define OM_APP_NON_SIG_BT_TRAN_CNF      (0x1602)

/*OM<->APP : Get the WCDMA SYNC Status.*/
#define APP_OM_W_SYNC_STATUS_REQ        (0x1603)
#define OM_APP_W_SYNC_STATUS_CNF        (0x1604)

/*OM<->APP : Get the GMSK/EDGE DownLink Status.*/
#define APP_OM_GE_DL_STATUS_REQ         (0x1605)
#define OM_APP_GE_DL_STATUS_CNF         (0x1606)

/*OM<->APP : Get the EDGE BLER.*/
#define APP_OM_EDGE_BLER_REQ            (0x1607)
#define OM_APP_EDGE_BLER_CNF            (0x1608)

/*OM<->APP : Get the EDGE BLER.*/
#define APP_OM_W_BER_DATA_REQ           (0x1609)
#define OM_APP_W_BER_DATA_CNF           (0x160a)
#define OM_APP_W_BER_DATA_IND           (0x160b)

#define APP_OM_LISTMODE_BT_GETMSG_REQ   (0x1611)
#define OM_APP_LISTMODE_BT_GETMSG_CNF   (0x1612)

#define APP_OM_LISTMODE_BT_TRAN_REQ     (0x1613)
#define OM_APP_LISTMODE_BT_TRAN_CNF     (0x1614)

#define APP_OM_LISTMODE_BT_TEST_REQ     (0x1615)
#define OM_APP_LISTMODE_BT_TEST_CNF     (0x1616)
#define OM_APP_LISTMODE_BT_BER_IND      (0x1617)

#define OM_APP_LISTMODE_BT_RSSI_IND     (0x1618)

#define APP_OM_BT_W_TX_SET_POWER_REQ    (0x1619)
#define OM_APP_BT_W_TX_SET_POWER_CNF    (0x1620)

#define APP_OM_BT_WG_RSSI_REQ           (0x1621)
#define OM_APP_BT_WG_RSSI_CNF           (0x1622)

#define APP_OM_G_BER_DATA_REQ           (0x1624)
#define OM_APP_G_BER_DATA_CNF           (0x1625)
#define OM_APP_G_BER_DATA_IND           (0x1626)

#define APP_OM_NON_SIG_BT_C_SYNC_REQ    (0x1701)
#define OM_APP_NON_SIG_BT_C_SYNC_CNF    (0x1702)
#define APP_OM_NON_SIG_BT_C_FER_REQ     (0x1703)
#define OM_APP_NON_SIG_BT_C_FER_CNF     (0x1704)

#define APP_OM_BT_C_TX_SET_POWER_REQ        (0x1705)
#define OM_APP_BT_C_TX_SET_POWER_CNF        (0x1706)

#define APP_OM_SWITCH_RF_ANT_REQ         0x0068
#define OM_APP_SWITCH_RF_ANT_CNF         0x0068


#define CBT_STATE_IDLE                          0 /*IDLE??????????????????????????*/
#define CBT_STATE_ACTIVE                        1 /*ACTIVE????????????????*/

#define CBT_MSG_ID_COMP_LENGTH                  (4U)

#define CBT_MSG_HEADER_LENGTH                   (16U)
#define CBT_MSG_IDLEN_LENGTH                    (8U)
#define CBT_MSG_HEAD_EX_LENGTH                  ((CBT_MSG_HEADER_LENGTH) + (CBT_MSG_IDLEN_LENGTH))

#define CBT_MSG_SEGMENT_LEN                     (4U*1024U)
#define CBT_MSG_CONTEXT_MAX_LENGTH              (CBT_MSG_SEGMENT_LEN - CBT_MSG_HEADER_LENGTH)

#define CBT_CCPU_TO_ACPU_SEND_DATA_REQ          (0x030d)

#define CBT_GET_COMPMODE_COMPID(COMPMODE)       ((COMPMODE>>12)& 0xF)
#define CBT_GET_COMPMODE_MODE(COMPMODE)         ((COMPMODE>>8) & 0xF)

#define CBT_MODEM_SSID_COMBINE(modem, ssid)     (((modem) & 0x0F) | ((ssid<<4) & 0xF0))

#define CBT_POWER_10TH_UNIT                             (10)
#define CBT_RSSI_8TH_UNIT                               (8)
#define CBT_POWER_10DBM_THRESHOLD                       (100)
#define CBT_GSM_BAND_CHAN_COMPOSE(usBand, usChan)       (((usBand) << 12) | (0xFFF & (usChan)))
#define CBT_RSSI_TO_POWER(x)                            (((x) * CBT_POWER_10TH_UNIT) / CBT_RSSI_8TH_UNIT)
#define CBT_CALL_GSM_RX_LEVEL_PARA                      (316)
#define CBT_WCDMA_FREQ_MEASURE_PARA                     (65535)

#define CBT_WRITE_NV_HEAD_SIZE                  (8)
#define CBT_WRITE_NV_FLASH_HEAD_SIZE            (8)

#define OM_BER_DATA_MAX_SIZE                    (1024)
#define CBT_NV_TO_FLASH_HEAD_SIZE               (4)
#define OM_STATE_IDLE                               0 /*IDLE????OM??????????????????????*/
#define OM_STATE_ACTIVE                             1 /*ACTIVE????OM????????????*/

/*OM<->APP : Just for LMT.*/
#define APP_OM_WRITE_NV_REQ                       0x8023
#define OM_APP_WRITE_NV_CNF                       0x8024

/*OM<->APP : Just for LMT.*/
#define APP_OM_HANDLE_LMT_REQ                     0x80a1
#define OM_APP_HANDLE_LMT_CNF                     0x80a2

/*OM<->APP : Just for LMT.*/
#define APP_OM_ACTIVE_PHY_REQ                     0x80a3
#define OM_APP_ACTIVE_PHY_CNF                     0x80a4

/*OM<->APP :????PA??????*/
#define APP_OM_PA_ATTRIBUTE_REQ                   0x80c1
#define OM_APP_PA_ATTRIBUTE_IND                   0x80c2

/*OM<->APP :????????????????PA??????*/
#define APP_OM_PA_TEMP_PHY_CHAN_REQ               0x80c7
#define OM_APP_PA_TEMP_PHY_CHAN_IND               0x80c8

/*??????????????????????????*/
#define APP_OM_SET_FTM_REQ                        0x80e5
#define OM_APP_SET_FTM_CNF                        0x80e6

/* OM<->APP :LMT????DSDA???????? */
#define APP_OM_QUERY_MODEM_NUM_REQ                0x8211
#define OM_APP_QUERY_MODEM_NUM_CNF                0x8212

#define APP_OM_AT_TMODE_REQ                       0x0065
#define OM_APP_AT_TMODE_CNF                       0x0065

#define APP_OM_AT_BANDSW_REQ                      0x0066
#define OM_APP_AT_BANDSW_CNF                      0x0066

#define APP_OM_AT_FCHAN_REQ                       0x0067
#define OM_APP_AT_FCHAN_CNF                       0x0067

/*OM<->APP : Restablish link*/
#define APP_OM_ESTABLISH_REQ                      0x80b1
#define OM_APP_ESTABLISH_CNF                      0x80b2

/*OM<->APP : Release link*/
#define APP_OM_RELEASE_REQ                        0x80b3
#define OM_APP_RELEASE_CNF                        0x80b4

#define OM_TRANS_PRIMID                           0x5001

/* OM<->APP :????C??NV??????Flash*/
#define APP_OM_NV_TO_FLASH_REQ                    0x802B
#define OM_APP_NV_TO_FLASH_CNF                    0x802C

/* OM<->APP :????C??????????NV????Flash*/
#define APP_OM_NV_WRITE_FLASH_REQ                 0x802D
#define OM_APP_NV_WRITE_FLASH_CNF                 0x802E

/* GUCCBT->NRNOSIG????IND??NR?????????????????? */
#define ID_GUCCBT_NRNOSIG_IND                     0x0F0F
/*****************************************************************************
  6 STRUCT????
*****************************************************************************/
enum OM_W_SNYC_STATUS
{
    OM_W_SYNC_STATUS_SYNC = 0,
    OM_W_SYNC_STATUS_OUT_OF_SYNC,
    OM_W_SYNC_STATUS_UNKNOWN,
    OM_W_SYNC_STATUS_BUTT
};

typedef VOS_UINT16 OM_W_SNYC_STATUS_ENUM_UINT16;

enum OM_GE_SNYC_STATUS
{
    OM_GE_SYNC_STATUS_NORMAL,
    OM_GE_SYNC_STATUS_DISNORMAL,
    OM_GE_SYNC_STATUS_UNKNOWN,
    OM_GE_SYNC_STATUS_BUTT
};

enum CBT_C_SYNC_STATUS
{
    CBT_C_SYNC_STATUS_SYNC = 0,
    CBT_C_SYNC_STATUS_OUT_OF_SYNC,
    CBT_C_SYNC_STATUS_UNKNOWN,
    CBT_C_SYNC_STATUS_BUTT
};

enum LMT_RAT_MODE
{
    LMT_RAT_WCDMA = 0,
    LMT_RAT_GSM,
    LMT_RAT_CDMA,
    LMT_RAT_TDS,
    LMT_RAT_LTE,
    LMT_RAT_NR,
    LMT_RAT_BUTT
};

/* ComponentType???? */
typedef enum
{
    CBT_MODE_LTE = 0,
    CBT_MODE_TDS,
    CBT_MODE_GSM,
    CBT_MODE_UMTS,
    CBT_MODE_CDMA,
    CBT_MODE_NR,
    CBT_MODE_COMM = 0xf,
    CBT_MODE_BUTT

} CBT_COMPONENT_MODE_ENUM;

typedef enum
{
    CBT_MT_REQ = 1,
    CBT_MT_CNF,
    CBT_MT_IND,
    CBT_MT_BUTT

} CBT_MSG_TYPE_ENUM;

typedef enum
{
    CBT_SSID_NOAPPOINT = 0,
    CBT_SSID_APP_CPU,
    CBT_SSID_MODEM_CPU,
    CBT_SSID_LTE_DSP,
    CBT_SSID_LTE_BBP,
    CBT_SSID_GU_DSP,
    CBT_SSID_HIFI,
    CBT_SSID_TDS_DSP,
    CBT_SSID_TDS_BBP,
    CBT_SSID_MCU,
    CBT_SSID_GPU,
    CBT_SSID_GU_BBP,
    CBT_SSID_IOM3,
    CBT_SSID_ISP,
    CBT_SSID_X_DSP,
    CBT_SSID_RESERVE,
    CBT_SSID_BUTT
} CBT_SSID_ENUM;

typedef enum
{
    CBT_COMP_FUNC = 1,
    CBT_COMP_NOSIG,
    CBT_COMP_PHY,
    CBT_COMP_PS,
    CBT_COMP_TRANS,
    CBT_COMP_BBIC,
    CBT_COMP_BUTT
} CBT_COMPONET_ID_ENUM;

typedef enum
{
    CBT_TEST_MODE_INVALID   = 0xFFFFFFFF,
    CBT_TEST_MODE_CT        = 0,
    CBT_TEST_MODE_BT        = 1,
    CBT_TEST_MODE_BUTT
}CBT_TEST_MODE_ENUM;

/*****************************************************************************
??????    : MODEM_SSID_STRU
????????  : ????????modem??ssid??????????
*****************************************************************************/
typedef struct
{
    VOS_UINT8 ucModem  : 3;  /*modem0: 0  modem1: 1*/
    VOS_UINT8 ucResv   : 1;
    VOS_UINT8 ucSsid   : 4;  /**/
} CBT_MODEM_SSID_STRU;

/*****************************************************************************
??????    : FRAGMENT_INFO_STRU
????????  : ????????????????????????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT8 ucMsgType    : 2; /*??????????REQ: 1   CNF: 2   IND: 3*/
    VOS_UINT8 ucFragIndex  : 4; /*??????????????????*/
    VOS_UINT8 ucEof        : 1; /*??????????????0????????????1????????*/
    VOS_UINT8 ucFragFlag   : 1; /*??????????????0????????1????*/
} CBT_FRAGMENT_INFO_STRU;

/*****************************************************************************
??????    : TIME_STAMP_STRU
????????  : ????????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32 ulTimestampL;
    VOS_UINT16 usTimestampH;
    VOS_UINT16 usRsv;
} CBT_TIME_STAMP_STRU;

/*****************************************************************************
??????    : COMPONENT_MODE_STRU
????????  : ??????????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT8 ucRsv;
    VOS_UINT8 ucMode     : 4;  /*????GUTLC??*/
    VOS_UINT8 ucCompID   : 4;
} CBT_COMPONENT_MODE_STRU;

/*****************************************************************************
??????    : CBT_MSG_HEAD_STRU
????????  : ????OM????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT8               ucSid;              /* ?????? 7*/
    CBT_MODEM_SSID_STRU     stModemSsid;
    VOS_UINT8               ucSessionID;        /*?????? 1*/
    CBT_FRAGMENT_INFO_STRU  stMsgSegment;
    VOS_UINT32              ulTransId;
    CBT_TIME_STAMP_STRU     stTimeStamp;        /*??????????*/
} CBT_MSG_HEAD_STRU;

/*****************************************************************************
??????    : CBT_UNIFORM_MSG_STRU
????????  : ??????????????????????
*****************************************************************************/
typedef struct
{
    CBT_MSG_HEAD_STRU               stMsgHeader;
    VOS_UINT16                      usMsgId;      /* ????ID */
    CBT_COMPONENT_MODE_STRU         stCompMode;
    VOS_UINT32                      ulMsgLength;
    VOS_UINT8                       aucPara[4];   /* ???????? */
} CBT_UNIFORM_MSG_STRU;

/*****************************************************************************
??????    : CBT_UNIFORM_MSG_STRU
????????  : ??????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    CBT_UNIFORM_MSG_STRU            stPcMsgData;
} CBT_UNIFORM_MSG_WITH_HEADER_STRU;

/*****************************************************************************
??????    : CBT_TRANS_MSG_STRU
????????  : ??????????????????????
*****************************************************************************/
typedef struct
{
    CBT_MSG_HEAD_STRU               stMsgHeader;
    VOS_UINT16                      usMsgId;      /* ????ID */
    VOS_UINT16                      usCompMode;
    VOS_UINT32                      ulMsgLength;
    VOS_UINT32                      ulReceiverPid; /* ??????????????PID */
    VOS_UINT8                       aucPara[4];    /* ???????? */
} CBT_TRANS_MSG_STRU;
/*****************************************************************************
??????    : CBT_HOOK_MSG_STRU
????????  : ??????CBT??????????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usPrimId;
    VOS_UINT16                          usReserve;
    VOS_UINT8                           aucPara[4];   /* ???????? */
} CBT_HOOK_MSG_STRU;
/*****************************************************************************
??????    : CBT_RCV_TRANS_MSG_STRU
????????  : ??????CBT????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usTransPrimId;
    VOS_UINT16                          usRsv;
    VOS_UINT16                          usMsgId;     /* ???????????????? */
    VOS_UINT16                          usCompMode;
    VOS_UINT8                           aucPara[4];   /* ???????? */
}CBT_RCV_TRANS_MSG_STRU;

/*****************************************************************************
??????    : CBT_SEND_COMM_MSG_STRU
????????  : PHY??????Agent????????????CBT????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    VOS_UINT16                          usMsgId;     /* ???????????????? */
    VOS_UINT16                          usCompMode;
    VOS_UINT8                           aucPara[4];   /* ???????? */
}CBT_SEND_COMM_MSG_STRU;
/*****************************************************************************
??????    : PS_TO_CBT_MSG_STRU
????????  : PHY??????Agent????????????CBT????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usMsgId;     /* ???????????????? */
    VOS_UINT16                          usCompMode;     /* ?????????? */
    VOS_UINT8                           aucPara[4];   /* ???????? */
}PS_TO_CBT_MSG_STRU;
/*****************************************************************************
??????    : CBT_CTOA_MSG_STRU
????????  : ??????????????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    VOS_UINT16                      usPrimId;            /* ????ID */
    VOS_UINT16                      usLen;
    VOS_UINT8                       aucData[4];
}CBT_CTOA_MSG_STRU;

/*****************************************************************************
??????    : CBT_WRITE_NV_REQ_STRU
????????  : ??NV????
*****************************************************************************/
typedef struct
{
    VOS_UINT32 ulCount;             /*????????NV??????*/
    VOS_UINT16 ausNvItemData[2];    /*????NVID????NVID????????????NVID??????*/
}CBT_WRITE_NV_REQ_STRU;

/*****************************************************************************
??????    : CBT_WRITE_NV_CNF_STRU
????????  : ??NV????
*****************************************************************************/
typedef struct
{
    CBT_MSG_HEAD_STRU           stMsgHead;
    VOS_UINT16                  usMsgId;      /* ????ID */
    CBT_COMPONENT_MODE_STRU     stCompMode;
    VOS_UINT32                  ulMsgLength;
    VOS_UINT32                  ulErrorCode;        /*????????????*/
    VOS_UINT32                  ulErrNvId;          /*??????????????NVID*/
}CBT_WRITE_NV_CNF_STRU;

/*****************************************************************************
??????    : CBT_WRITE_NV_FLASH_REQ_STRU
????????  : ??NV??flash????
*****************************************************************************/
typedef struct
{
    VOS_UINT32 ulCount;             /*????????NV??????*/
    VOS_UINT16 ausNvItemData[2];    /*????NVID????NVID????????????NVID??????*/
}CBT_WRITE_NV_FLASH_REQ_STRU;

/*****************************************************************************
??????    : CBT_WRITE_NV_FLASH_CNF_STRU
????????  : ??NV??flash????
*****************************************************************************/
typedef struct
{
    CBT_MSG_HEAD_STRU           stMsgHead;
    VOS_UINT16                  usMsgId;            /* ????ID */
    CBT_COMPONENT_MODE_STRU     stCompMode;
    VOS_UINT32                  ulMsgLength;
    VOS_UINT32                  ulErrorCode;        /*????????????*/
    VOS_UINT32                  ulErrNvId;          /*??????????????NVID*/
}CBT_WRITE_NV_FLASH_CNF_STRU;

/*****************************************************************************
??????    : CBT_NV_TO_FLASH_CNF_STRU
????????  : ????NV??FLASH??????????????
*****************************************************************************/
typedef struct
{
    CBT_MSG_HEAD_STRU           stMsgHead;
    VOS_UINT16                  usMsgId;      /* ????ID */
    CBT_COMPONENT_MODE_STRU     stCompMode;
    VOS_UINT32                  ulMsgLength;
    VOS_UINT32                  ulErrorCode;        /*????????????*/
}CBT_NV_TO_FLASH_CNF_STRU;

typedef VOS_UINT32 (*CBT_FUN)(CBT_UNIFORM_MSG_STRU *pstCbtMsg, VOS_UINT16 usReturnPrimId);

typedef struct
{
    CBT_FUN     pfCbtFun;           /*Reserves the pointer of function handles current msg.*/
    VOS_UINT32  ulPrimId;           /*Indicates current msg type.*/
    VOS_UINT32  ulReturnPrimId;     /*Indicates return msg type.*/
} CBT_MSG_FUN_STRU;
/*****************************************************************************
 ??????    : CBT_LISI_MODE_CTRL_STRU
 ????????  :
 ????????  : Listmode??????????????
*****************************************************************************/
typedef struct
{
    CBT_MODEM_SSID_STRU         stModemSsid;            /* Modem */
    VOS_UINT8                   ucReserve;              /* ?????? */
    CBT_COMPONENT_MODE_STRU     stCompMode;             /* ????ID */

    VOS_UINT32                  ulBand;
    VOS_UINT16                  usTxChan;
    VOS_UINT16                  usRxChan;
    VOS_UINT16                  usPcl;
    VOS_UINT16                  usRsv1;

    VOS_UINT16                  usWSyncStatus;
    VOS_UINT16                  usCSyncStatus;
    VOS_UINT16                  usCReportFlag;
    VOS_UINT16                  usGeReportFlag;

    VOS_UINT16                  usRecvPrimId;
    VOS_UINT16                  usEnableReport;
    VOS_UINT16                  usListModeSegIndex;             /* list mode segment index, start by 1 */
    VOS_UINT16                  usRsv2;
    VOS_UINT32                  ulHandOverStartTime;            /* Handover ????????: ms */
    VOS_UINT16                  usEnableRssiReport;             /* RSSI???????? */
    VOS_UINT16                  usOffSetFrames;                 /* Handover??????????dsp????????RSSI??????: Frames */
    VOS_UINT16                  usRssiReportFrames;             /* RSSI???????? */
    VOS_UINT16                  usTrigRssiTimer;                /* ????dsp????????RSSI???????? */
    VOS_BOOL                    bCbtCallSuc;                    /*CBT listmode call ????*/
    VOS_UINT32                  ulCbtCallSucStartTime;          /* CBT call ?????????????????? */
    VOS_UINT32                  ulCbtCallTimeOut;               /* ????????CBT call ??????????????ms ??0 ????????*/
    VOS_INT16                   sCbtCallRxLevel;                /* CBT call ??????????????????????0.1dBm */
    VOS_INT16                   sCbtCallTxPower;                /* CBT call ??????????????????????0.1dBm */

    VOS_UINT16                  usTotalFrameNum;        /* ?????? */
    VOS_UINT16                  usCurFrameNum;          /* ??????BER???????? */
    VOS_UINT16                  usReportFrameNum;       /* ??????BER?????? */
    VOS_UINT16                  usCurReportFrameNum;    /* ??????BER?????? */
    VOS_UINT32                  ulFrameStatistic;       /* listmode ?????????? */
    VOS_UINT32                  ulListmodeFrameTotal;   /* listmode ?????????? */

    VOS_UINT16                  usTxTotalFrameNum;      /* ??????BER?????? */
    VOS_UINT16                  usTxCurFrameNum;        /* ??????BER???????? */

    VOS_SEM                     ulCbtTotalFrameSem;
    VOS_SEM                     ulCbtTxSegmentFrameSem;
    VOS_SEM                     ulCbtSyncSem;
    VOS_SEM                     ulCbtGeDlQualitySem;

#if ( FEATURE_ON == FEATURE_GSM_WHOLE_SDR )
    VOS_SEM                     ulCbtEdgeBlerSem;
#endif
}CBT_LISI_MODE_CTRL_STRU;
/*****************************************************************************
 ??????    : CBT_GE_DL_STATUS_STRU
 ????????  :
 ????????  : GSM????????????????????
*****************************************************************************/
typedef struct
{
    CBT_MSG_HEAD_STRU      stHeader;
    VOS_UINT16             usPrimId;   /*Indicates current msg type.*/
    VOS_UINT16             usToolId;   /*Not used now.*/
    VOS_UINT32             ulMsgLength;
    VOS_UINT16             usBerValue[2];
}CBT_GE_DL_STATUS_STRU;
/*****************************************************************************
 ??????    : CBT_LIST_MODE_BER_IND_STRU
 ????????  :
 ????????  : Ber????????????
*****************************************************************************/
typedef struct
{
    CBT_MSG_HEAD_STRU       stHeader;
    VOS_UINT16              usPrimId;            /*Indicates current msg type.*/
    VOS_UINT16              usToolId;            /*Not used now.*/
    VOS_UINT32              ulMsgLength;

    VOS_UINT16              usTotalFrameNum;
    VOS_UINT16              usCurFrameNum;
    VOS_UINT16              usBand;
    VOS_UINT16              usRxChan;
    VOS_UINT16              usCrcData;
    VOS_UINT16              usListModeSegIndex;  /* list mode segment index, start by 1 */
    VOS_UINT32              ulDataLen;           /* ????????,????:????,??????????4????????,????[0..WTTFPHY_MAX_PHY_DATA_REQ_LEN-1] */
    VOS_UINT8               aucData[OM_BER_DATA_MAX_SIZE]; /* ?????????? */
}CBT_LIST_MODE_BER_IND_STRU;
/*****************************************************************************
 ??????    : CBT_C_FER_DATA_CNF_STRU
 ????????  :
 ????????  : C?? Fer????????????
*****************************************************************************/
typedef struct
{
    CBT_MSG_HEAD_STRU       stHeader;
    VOS_UINT16              usPrimId;            /*Indicates current msg type.*/
    VOS_UINT16              usToolId;            /*Not used now.*/
    VOS_UINT32              ulMsgLength;

    VOS_UINT32              ulErrorCode;
    VOS_UINT16              usTotalFrameNum;
    VOS_UINT16              usBadFrameNum;
    VOS_UINT32              ulTotalBitsNum;
    VOS_UINT32              ulErrorBitsNum;
}CBT_C_FER_DATA_CNF_STRU;

/*****************************************************************************
 ??????    : CBT_G_BER_DATA_IND_STRU
 ????????  :
 ????????  : G?? Ber????????????
*****************************************************************************/
typedef struct
{
    CBT_MSG_HEAD_STRU       stHeader;
    VOS_UINT16              usPrimId;            /*Indicates current msg type.*/
    VOS_UINT16              usToolId;            /*Not used now.*/
    VOS_UINT32              ulMsgLength;

    VOS_UINT16              usTotalFrameNum;
    VOS_UINT16              usCurFrameNum;
    VOS_UINT16              usCrcData;
    VOS_UINT16              usDataLen;           /* ????????,????:????,??????????4????????,????[0..WTTFPHY_MAX_PHY_DATA_REQ_LEN-1] */
    VOS_UINT8               aucData[OM_BER_DATA_MAX_SIZE]; /* ?????????? */
}CBT_G_BER_DATA_IND_STRU;

/*****************************************************************************
 ??????    : CBT_LT_SWITCH_RF_ANT_STRU
 ????????  :
 ????????  : Ber????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16  usGpioNo;
    VOS_UINT16  usGpioLevel;
} CBT_LT_SWITCH_RF_ANT_STRU;

/*****************************************************************************
 ??????    : CBT_LIST_MODE_RSSI_IND_STRU
 ????????  :
 ????????  : listmode Rssi????????????
*****************************************************************************/
typedef struct
{
    CBT_MSG_HEAD_STRU       stHeader;
    VOS_UINT16              usPrimId;            /*Indicates current msg type.*/
    VOS_UINT16              usToolId;            /*Not used now.*/
    VOS_UINT32              ulMsgLength;

    VOS_UINT16              usBand;
    VOS_UINT16              usRxChan;
    VOS_UINT16              usListModeSegIndex; /* list mode segment index, start by 1 */
    VOS_UINT16              usRsv;
    VOS_INT32               lRxLevel;           /* ??????RX level 0.125dBm */
    VOS_INT32               lRscp;                /* ??????Rscp 0.125dBm */
}CBT_LIST_MODE_RSSI_IND_STRU;

/*****************************************************************************
 ??????    : CBT_NO_SIG_BT_RSSI_IND_STRU
 ????????  :
 ????????  : ????????Rssi????????????
*****************************************************************************/
typedef struct
{
    CBT_MSG_HEAD_STRU       stHeader;
    VOS_UINT16              usPrimId;            /*Indicates current msg type.*/
    VOS_UINT16              usToolId;            /*Not used now.*/
    VOS_UINT32              ulMsgLength;

    VOS_UINT32              ulErrorCode;
    VOS_INT32               lRxLevel;           /* ??????RX level 0.125dBm */
}CBT_NO_SIG_BT_RSSI_CNF_STRU;

/*****************************************************************************
??????    : CBT_RTT_AGENT_MSG_STRU
????????  : CBT??????????RTT??????????
*****************************************************************************/
typedef struct
{
    CBT_MSG_HEAD_STRU               stMsgHeader;
    VOS_UINT16                      usMsgId;      /* ????ID */
    CBT_COMPONENT_MODE_STRU         stCompMode;
    VOS_UINT32                      ulMsgLength;
    VOS_UINT16                      usTMode;      /* TMode */
    VOS_UINT16                      usRsv;
} CBT_RTT_AGENT_MSG_STRU;

/*****************************************************************************
??????    : CBT_LMT_MSG_INFO
????????  : ????LMT??????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32              enModem;
    VOS_UINT16              usSysMode;
    VOS_BOOL                bMasterMode;
    VOS_RATMODE_ENUM_UINT32 enMsgMode;
    VOS_UINT32              ulReceiverPid;
}CBT_LMT_MSG_INFO;

typedef VOS_UINT32 (* RTTAgentFunc)(VOS_VOID *pMsg);

/*****************************************************************************
??????    : GUCCBT_NRNOSIG_IND_MSG_STRU
????????  : NR????BT????????usBusiness????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    VOS_UINT16              usMsgId;
    VOS_UINT16              usBusiness;
}GUCCBT_NRNOSIG_IND_MSG_STRU;

typedef struct
{
    VOS_UINT8               ucRsv;
    VOS_UINT8               ucComponentType    : 4;   //??ucComponentType??OM/MSP,?????? 0x0: LTE, 0x1: TDS,0x2: GSM, 0x3: UMTS,0x4: X, 0xF: ????????
    VOS_UINT8               ucComponentID      : 4;   // OM/MSP:0x1, nosig:0x2, PHY:0x3
}CBT_COMPONENT_ID_STRU;

/*****************************************************************************
??????    : NRNOSIG_GUCCBT_MSG_STRU
????????  : NrNosig??GUCCBT????????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    VOS_UINT16              usMsgId;      /* ???????????????? */
    CBT_COMPONENT_ID_STRU   stComponentId;
    VOS_UINT32              ulResult;
}NRNOSIG_GUCCBT_MSG_STRU;

/*****************************************************************************
  ????????
*****************************************************************************/
#if (OSA_CPU_CCPU == VOS_OSA_CPU)

VOS_VOID CBT_SendContentChannel(CBT_MODEM_SSID_STRU stModemSsid, CBT_COMPONENT_MODE_STRU stCompMode,
                                       VOS_UINT16 usReturnPrimId, CBT_UNIFORM_MSG_STRU * pstCbtToPcMsg);

VOS_VOID CBT_SendResultChannel(CBT_MODEM_SSID_STRU stModemSsid, CBT_COMPONENT_MODE_STRU stCompMode,
                                VOS_UINT16 usReturnPrimId, VOS_UINT32 ulResult);

VOS_VOID OM_NoSigCtrlInit(VOS_UINT8 ucModemId);

VOS_VOID CBT_ListModeCtrlInit(VOS_UINT8 ucModemId);

VOS_VOID CBT_ResetMsgHead(CBT_UNIFORM_MSG_STRU * pstCbtToPcMsg);

VOS_UINT32 CBT_SendData(CBT_UNIFORM_MSG_STRU * pucMsg, VOS_UINT16 usMsgLen);

VOS_UINT32 CBT_GreenChannel(CBT_MODEM_SSID_STRU stModemSsid, CBT_COMPONENT_MODE_STRU stCompMode, VOS_UINT16 usPrimId,
                            VOS_UINT8 * pucData, VOS_UINT16 usLen);

#endif


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
