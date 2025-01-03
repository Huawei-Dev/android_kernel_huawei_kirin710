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
#ifndef  APP_VC_API_H
#define  APP_VC_API_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "TafTypeDef.h"
#include "vos.h"

/*****************************************************************************
  2 ????????
*****************************************************************************/
#define APP_VC_MSD_DATA_LEN             (140)                                   /* ????:btye */



/*****************************************************************************
  3????????
*****************************************************************************/
/* ??????????0 ??????1 ??????????2 ??????????3 ??????4 ??????7 ??????????8 ???????? */
enum VC_PHY_DEVICE_MODE_ENUM
{
    VC_PHY_DEVICE_MODE_HANDSET,                                                 /* ???? */
    VC_PHY_DEVICE_MODE_HANDS_FREE,                                              /* ???????? */
    VC_PHY_DEVICE_MODE_CAR_FREE,                                                /* ???????? */
    VC_PHY_DEVICE_MODE_EARPHONE,                                                /* ???? */
    VC_PHY_DEVICE_MODE_BLUETOOTH,                                               /* ???? */
    VC_PHY_DEVICE_MODE_PCVOICE,                                                 /* PC???????? */
    VC_PHY_DEVICE_MODE_HEADPHONE,                                               /* ????????MIC?????????? */
    VC_PHY_DEVICE_MODE_SUPER_HANDFREE,                                              /* ???????? */
    VC_PHY_DEVICE_MODE_SMART_TALK,                                              /* ???????? */
    VC_PHY_DEVICE_MODEM_USBVOICE,                                               /* USB???? */
    VC_PHY_DEVICE_MODE_BUTT                                                     /* invalid value */
};
typedef VOS_UINT16  VC_PHY_DEVICE_MODE_ENUM_U16;

/*****************************************************************************
 ??????    : APP_VC_VOICE_MODE_ENUM
 ????????  : STICK????????????????^CVOICE??????????????????????????
*****************************************************************************/
enum APP_VC_VOICE_MODE_ENUM
{
    APP_VC_VOICE_MODE_PCVOICE           = 0,
    APP_VC_VOICE_MODE_EARPHONE          = 1,
    APP_VC_VOICE_MODE_HANDSET           = 2,
    APP_VC_VOICE_MODE_HANDS_FREE        = 3,
    APP_VC_VOICE_MODE_BUTT
};
typedef VOS_UINT16 APP_VC_VOICE_MODE_ENUM_U16;

/*****************************************************************************
 ??????    : APP_VC_VOICE_PORT_ENUM
 ????????  : ????????????????
*****************************************************************************/
enum APP_VC_VOICE_PORT_ENUM
{
    APP_VC_VOICE_PORT_MODEM             = 1,
    APP_VC_VOICE_PORT_DIAG              = 2,
    APP_VC_VOICE_PORT_PCUI              = 3,
    APP_VC_VOICE_PORT_PCVOICE           = 4,
    APP_VC_VOICE_PORT_PCSC              = 5,
    APP_VC_VOICE_PORT_BUTT
};
typedef VOS_UINT8 APP_VC_VOICE_PORT_ENUM_U8;

enum APP_VC_EVENT_ENUM
{
    APP_VC_EVT_PARM_CHANGED,                                                /*service para changed*/
    APP_VC_EVT_SET_VOLUME,
    APP_VC_EVT_SET_VOICE_MODE,
    APP_VC_EVT_GET_VOLUME,
    APP_VC_EVT_SET_MUTE_STATUS,
    APP_VC_EVT_GET_MUTE_STATUS,

    APP_VC_EVT_SET_ECALL_CFG,
    APP_VC_EVT_ECALL_TRANS_STATUS,
    APP_VC_EVT_BUTT
};
typedef VOS_UINT32 APP_VC_EVENT_ENUM_U32;

enum APP_VC_MUTE_STATUS_ENUM
{
    APP_VC_MUTE_STATUS_UNMUTED          = 0,
    APP_VC_MUTE_STATUS_MUTED            = 1,
    APP_VC_MUTE_STATUS_BUTT
};
typedef VOS_UINT8 APP_VC_MUTE_STATUS_ENUM_UINT8;


enum TAF_VC_TTYMODE_ENUM
{
    TAF_VC_TTY_OFF                      = 0,
    TAF_VC_TTY_FULL                     = 1,
    TAF_VC_TTY_VCO                      = 2,
    TAF_VC_TTY_HCO                      = 3,
    TAF_VC_TTYMODE_BUTT
};
typedef VOS_UINT8 TAF_VC_TTYMODE_ENUM_UINT8;


enum APP_VC_MSG_ENUM
{
    APP_VC_MSG_REQ_SET_VOLUME   = 0,                                            /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ???????????????? */
    APP_VC_MSG_REQ_SET_MODE,                                                    /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ???????????????????? */

    APP_VC_MSG_REQ_QRY_MODE,                                                    /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ???????????????????? */
    APP_VC_MSG_CNF_QRY_MODE,                                                    /* _H2ASN_MsgChoice APP_VC_EVENT_INFO_STRU *//* ???????????????????? */

    APP_VC_MSG_REQ_SET_PORT,                                                    /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ???????????????????? */
    APP_VC_MSG_CNF_SET_PORT,                                                    /* _H2ASN_MsgChoice APP_VC_EVENT_INFO_STRU *//* ???????????????????? */

    APP_VC_MSG_REQ_QRY_PORT,                                                    /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ???????????????????? */
    APP_VC_MSG_CNF_QRY_PORT,                                                    /* _H2ASN_MsgChoice APP_VC_EVENT_INFO_STRU *//* ???????????????????? */

    APP_VC_MSG_REQ_QRY_VOLUME,                                                  /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU */
    APP_VC_MSG_CNF_QRY_VOLUME,

    APP_VC_MSG_SET_MUTE_STATUS_REQ,                                             /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ???????????????????? */
    APP_VC_MSG_GET_MUTE_STATUS_REQ,                                             /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ???????????????????? */

    APP_VC_MSG_SET_FOREGROUND_REQ,                                              /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ???????????????????? */
    APP_VC_MSG_SET_FOREGROUND_CNF,                                              /* _H2ASN_MsgChoice APP_VC_MSG_CNF_ASN_STRU *//* ???????????????????? */

    APP_VC_MSG_SET_BACKGROUND_REQ,                                              /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ???????????????????? */
    APP_VC_MSG_SET_BACKGROUND_CNF,                                              /* _H2ASN_MsgChoice APP_VC_MSG_CNF_ASN_STRU *//* ???????????????????? */

    APP_VC_MSG_FOREGROUND_QRY,                                                  /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ???????????????? */
    APP_VC_MSG_FOREGROUND_RSP,                                                  /* _H2ASN_MsgChoice APP_VC_QRY_GROUNG_RSP_STRU *//* ???????????????? */

    APP_VC_MSG_SET_MODEMLOOP_REQ,                                               /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ???????????????????? */

    APP_VC_MSG_SET_MSD_REQ,                                                     /* _H2ASN_MsgChoice APP_VC_MSG_SET_MSD_REQ_STRU *//* ????MSD???????? */
    APP_VC_MSG_SET_MSD_CNF,                                                     /* _H2ASN_MsgChoice APP_VC_MSG_CNF_ASN_STRU *//* ????MSD???????? */

    APP_VC_MSG_QRY_MSD_REQ,                                                     /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ????MSD???????? */
    APP_VC_MSG_QRY_MSD_CNF,                                                     /* _H2ASN_MsgChoice APP_VC_MSG_QRY_MSD_CNF_STRU *//* ????MSD???????? */

    APP_VC_MSG_SET_ECALL_CFG_REQ,                                               /* _H2ASN_MsgChoice APP_VC_MSG_SET_ECALL_CFG_REQ_STRU *//* ????ecall???????? */

    APP_VC_MSG_QRY_ECALL_CFG_REQ,                                               /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ????ecall???????????? */
    APP_VC_MSG_QRY_ECALL_CFG_CNF,                                               /* _H2ASN_MsgChoice APP_VC_MSG_QRY_ECALL_CFG_CNF_STRU *//* ????ecall???????????? */

    APP_VC_MSG_DTMF_DECODER_IND,                                                /* _H2ASN_MsgChoice APP_VC_DTMF_DECODER_IND_STRU *//* DTMF Decoder Ind???????? */

    APP_VC_MSG_SET_TTYMODE_REQ,                                                 /* _H2ASN_MsgChoice APP_VC_SET_TTYMODE_REQ_STRU *//* ????TTY???????????? */
    APP_VC_MSG_SET_TTYMODE_CNF,                                                 /* _H2ASN_MsgChoice APP_VC_MSG_CNF_ASN_STRU *//* ????TTY???????????? */
    APP_VC_MSG_QRY_TTYMODE_REQ,                                                 /* _H2ASN_MsgChoice APP_VC_REQ_MSG_ASN_STRU *//* ????TTY???????????? */
    APP_VC_MSG_QRY_TTYMODE_CNF,                                                 /* _H2ASN_MsgChoice APP_VC_QRY_TTYMODE_CNF_STRU *//* ????TTY???????????? */

    APP_VC_MSG_HIFI_RESET_NTF,

    APP_VC_MSG_BUTT
};
typedef VOS_UINT16  APP_VC_MSG_ENUM_U16;


enum APP_VC_QRY_GROUND_ENUM
{
    APP_VC_FOREGROUND                   = 0,
    APP_VC_BACKGROUND                   = 1,
    APP_VC_GROUND_INVALID               = 2,
    APP_VC_GROUND_BUTT
};
typedef VOS_UINT16 APP_VC_QRY_GROUND_ENUM_U16;


enum APP_VC_START_HIFI_ORIG_ENUM
{
    APP_VC_START_HIFI_ORIG_CALL                   = 0,
    APP_VC_START_HIFI_ORIG_IMSA                   = 1,
    APP_VC_START_HIFI_ORIG_BUTT
};
typedef VOS_UINT8 APP_VC_START_HIFI_ORIG_ENUM_UINT8;


enum APP_VC_ECALL_TRANS_STATUS_ENUM
{
    APP_VC_ECALL_MSD_TRANSMITTING_START     = 0,                                /* ????MSD???????????????? */
    APP_VC_ECALL_MSD_TRANSMITTING_SUCCESS,                                      /* ????MSD???????????????? */
    APP_VC_ECALL_MSD_TRANSMITTING_FAIL,                                         /* ????MSD???????????????? */
    APP_VC_ECALL_PSAP_MSD_REQUIRETRANSMITTING,                                  /* PSAP????????MSD???? */
    APP_VC_ECALL_TRANS_STATUS_BUTT
};
typedef VOS_UINT8  APP_VC_ECALL_TRANS_STATUS_ENUM_UINT8;


enum APP_VC_ECALL_TRANS_FAIL_CAUSE_ENUM
{
    APP_VC_ECALL_CAUSE_WAIT_PSAP_TIME_OUT   = 0,                                /* ????PSAP?????????????? */
    APP_VC_ECALL_CAUSE_MSD_TRANSMITTING_TIME_OUT,                               /* MSD???????????? */
    APP_VC_ECALL_CAUSE_WAIT_AL_ACK_TIME_OUT,                                    /* ???????????????????? */
    APP_VC_ECALL_CAUSE_UNSPECIFIC_ERROR,                                        /* ???????????? */
    APP_VC_ECALL_CAUSE_BUTT
};
typedef VOS_UINT8  APP_VC_ECALL_TRANS_FAIL_CAUSE_ENUM_UINT8;


enum APP_VC_ECALL_MSD_MODE_ENUM
{
    APP_VC_ECALL_MSD_MODE_TRANSPARENT   = 0,                                    /* ???????? */
    APP_VC_ECALL_MSD_MODE_BUTT
};
typedef VOS_UINT16  APP_VC_ECALL_MSD_MODE_ENUM_UINT16;


enum APP_VC_ECALL_VOC_CONFIG_ENUM
{
    APP_VC_ECALL_VOC_CONFIG_NOT_ABANDON = 0,                                    /* MSD??????????????????*/
    APP_VC_ECALL_VOC_CONFIG_ABANDON,                                            /* MSD????????????????????*/
    APP_VC_ECALL_VOC_CONFIG_BUTT
};
typedef VOS_UINT16  APP_VC_ECALL_VOC_CONFIG_ENUM_UINT16;



typedef struct
{
    VOS_MSG_HEADER                                                              /* _H2ASN_Skip */
    APP_VC_MSG_ENUM_U16                 enMsgName;                              /* _H2ASN_Skip *//* ?????? */
    VOS_UINT8                           aucReserve1[2];                         /* ???? */
    MN_CLIENT_ID_T                      clientId;                               /* Client ID */
    MN_OPERATION_ID_T                   opId;                                   /* Operation ID */
    VOS_UINT8                           aucReserve2;                            /* ???? */
    VOS_UINT8                           aucContent[4];                          /* ???????? */
} APP_VC_REQ_MSG_STRU;



typedef struct
{
    VOS_BOOL                            bSuccess;                               /*set(get) success or failure */
    VOS_UINT32                          ulErrCode;
    MN_CLIENT_ID_T                      clientId;
    MN_OPERATION_ID_T                   opId;
    APP_VC_VOICE_PORT_ENUM_U8           enVoicePort;
    VC_PHY_DEVICE_MODE_ENUM_U16         enDevMode;
    VOS_UINT16                          usVolume;
    APP_VC_MUTE_STATUS_ENUM_UINT8       enMuteStatus;
    VOS_UINT8                           aucRsv[2];

    APP_VC_ECALL_TRANS_STATUS_ENUM_UINT8 enEcallState;
    VOS_UINT32                          ulEcallDescription;
}APP_VC_EVENT_INFO_STRU;


typedef struct
{
    VOS_UINT8                           ucQryRslt;                              /* ???? success or failure */
    VOS_UINT8                           aucReserved;
    APP_VC_QRY_GROUND_ENUM_U16          enGround;                               /* ???????? */
}APP_VC_QRY_GROUNG_RSP_STRU;


typedef struct
{
    VOS_UINT8                           aucMsdData[APP_VC_MSD_DATA_LEN];        /* MSD???????? */
}APP_VC_MSG_SET_MSD_REQ_STRU;


typedef struct
{
    VOS_UINT8                           ucQryRslt;                              /* ???????? */
    VOS_UINT8                           aucReserved[3];
    VOS_UINT8                           aucMsdData[APP_VC_MSD_DATA_LEN];        /* MSD???????? */
}APP_VC_MSG_QRY_MSD_CNF_STRU;


typedef struct
{
    APP_VC_ECALL_MSD_MODE_ENUM_UINT16   enMode;                                 /* ???????????? */
    APP_VC_ECALL_VOC_CONFIG_ENUM_UINT16 enVocConfig;                            /* ???????????????????????? */
}APP_VC_MSG_SET_ECALL_CFG_REQ_STRU;



typedef struct
{
    VOS_UINT8                           ucQryRslt;                              /* ???????? */
    VOS_UINT8                           aucReserved[3];
    APP_VC_ECALL_MSD_MODE_ENUM_UINT16   enMode;                                 /* MSD???????????? */
    APP_VC_ECALL_VOC_CONFIG_ENUM_UINT16 enVocConfig;                            /* ???????????????????????? */
}APP_VC_MSG_QRY_ECALL_CFG_CNF_STRU;


typedef struct
{
    VOS_UINT8                           ucRslt;                                  /* ???? */
    VOS_UINT8                           aucReserved[3];
}APP_VC_SET_MSD_CNF_STRU;


typedef struct
{
    VOS_UINT8                           ucQryRslt;                              /* ???? success or failure */
    TAF_VC_TTYMODE_ENUM_UINT8           enTTYMode;                              /* ???????? */
    VOS_UINT8                           aucReserved[2];
}APP_VC_QRY_TTYMODE_CNF_STRU;


typedef struct
{
    TAF_VC_TTYMODE_ENUM_UINT8           enTTYMode;                              /* ????TTY MODE*/
    VOS_UINT8                           aucReserved[3];
}APP_VC_SET_TTYMODE_REQ_STRU;


typedef struct
{
    VOS_UINT8                           ucRslt;
    VOS_UINT8                           aucReserved[3];
}APP_VC_MSG_CNF_ASN_STRU;


typedef struct
{
    VOS_UINT8                           aucContent[4];
}APP_VC_REQ_MSG_ASN_STRU;


/*****************************************************************************
  4 ??????
*****************************************************************************/


/*****************************************************************************
  5 ????????????
*****************************************************************************/


/*****************************************************************************
  6 ????????????
*****************************************************************************/


VOS_UINT32  APP_VC_SetVoiceVolume(
    MN_CLIENT_ID_T                      ClientId,
    MN_OPERATION_ID_T                   OpId,
    VOS_UINT8                           ucVoiceVolume
);


VOS_UINT32  APP_VC_SetVoiceMode(
    MN_CLIENT_ID_T                      ClientId,
    MN_OPERATION_ID_T                   OpId,
    VOS_UINT8                           ucVoiceMode,
    VOS_UINT32                          ulRcvPid
);


VOS_UINT32 APP_VC_SetVoicePort(
    MN_CLIENT_ID_T                      ClientId,
    MN_OPERATION_ID_T                   OpId,
    APP_VC_VOICE_PORT_ENUM_U8           ucVoicePort
);


VOS_UINT32 APP_VC_GetVoicePort(
    MN_CLIENT_ID_T                      ClientId,
    MN_OPERATION_ID_T                   OpId
);


VOS_UINT32 APP_VC_GetVoiceMode(
    MN_CLIENT_ID_T                      ClientId,
    MN_OPERATION_ID_T                   OpId
);


extern  VC_PHY_DEVICE_MODE_ENUM_U16  APP_VC_AppVcVoiceMode2VcPhyVoiceMode(
    APP_VC_VOICE_MODE_ENUM_U16          usVoiceMode
);


extern  APP_VC_VOICE_MODE_ENUM_U16  APP_VC_VcPhyVoiceMode2AppVcVoiceMode(
    VC_PHY_DEVICE_MODE_ENUM_U16         usVoiceMode
);

extern VOS_UINT32  APP_VC_GetVoiceVolume(
    MN_CLIENT_ID_T                      ClientId,
    MN_OPERATION_ID_T                   OpId
);

/*****************************************************************************
 ?? ?? ??  : APP_VC_SetMuteStatus
 ????????  : ????????????
 ????????  : usClientId   - ??????ID
             ucOpId       - ??????ID
             enMuteStatus - ????????
 ????????  : ??
 ?? ?? ??  : VOS_OK       - ????
             VOS_ERR      - ????
 ????????  :
 ????????  :
*****************************************************************************/
VOS_UINT32  APP_VC_SetMuteStatus(
    VOS_UINT16                          usClientId,
    VOS_UINT8                           ucOpId,
    APP_VC_MUTE_STATUS_ENUM_UINT8       enMuteStatus
);


/*****************************************************************************
 ?? ?? ??  : APP_VC_GetMuteStatus
 ????????  : ????????????
 ????????  : usClientId   - ??????ID
             ucOpId       - ??????ID
 ????????  : ??
 ?? ?? ??  : VOS_OK       - ????
             VOS_ERR      - ????
 ????????  :
 ????????  :
*****************************************************************************/
VOS_UINT32 APP_VC_GetMuteStatus(
    VOS_UINT16                          usClientId,
    VOS_UINT8                           ucOpId
);

/*****************************************************************************
 ?? ?? ??  : APP_VC_SetModemLoop
 ????????  : ??????????????????????
 ????????  : usClientId   - ??????ID
             ucOpId       - ??????ID
             ucModemLoop  - ??????????????????????
 ????????  : ??
 ?? ?? ??  : VOS_OK       - ????
             VOS_ERR      - ????
 ????????  :
 ????????  :
*****************************************************************************/
VOS_UINT32 APP_VC_SetModemLoop(
    VOS_UINT16                          usClientId,
    VOS_UINT8                           ucOpId,
    VOS_UINT8                           ucModemLoop
);

VOS_UINT32 APP_VC_SendVcHifiResetNtf(
    VOS_UINT32                          ulRcvPid
);


typedef struct
{
    VOS_CHAR                            ucDtmfCode;
    VOS_UINT8                           ucReserved;
    VOS_UINT16                          usOntime;
}APP_VC_DTMF_DECODER_IND_STRU;



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

#endif /* APP_VC_API_H */

