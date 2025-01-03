
#ifndef __BASTETINTERFACE_H__
#define __BASTETINTERFACE_H__

/*****************************************************************************
 * 1 ??????????????                                                          *
*****************************************************************************/
#include "vos.h"

#ifdef __cplusplus
#if __cplusplus
    extern "C" {
#endif
#endif

#pragma pack(4)

/*****************************************************************************
 * 2 ??????                                                                  *
*****************************************************************************/
/* Bastet???????????????? */
#define BST_ASPEN_INFO_PKT_DROP             0xc0000001
/* ??????A?????????????? */
#define BST_ASPEN_PKT_DROP_SIZE             (128u)

/* ???????????????? */
#define BASTET_ASPEN_PKT_DROP_TYPE_CDS      0x10
#define BASTET_ASPEN_PKT_DROP_TYPE_PDCP     0x20
#define BASTET_ASPEN_PKT_DROP_TYPE_WRLC     0x40

#define BASTET_ASPEN_PKT_DROP_TYPE_MASK     (0xF0)

/*****************************************************************************
 * 3 Massage Declare                                                         *
*****************************************************************************/

/*****************************************************************************
 * 4 ????????                                                                *
*****************************************************************************/
enum BST_ACORE_CORE_MSG_TYPE_ENUM
{
    BST_ACORE_CORE_MSG_TYPE_DSPP,
    BST_ACORE_CORE_MSG_TYPE_ASPEN,
    BST_ACORE_CORE_MSG_TYPE_EMCOM_SUPPORT,
    BST_ACORE_CORE_MSG_TYPE_EMCOM_KEY_PSINFO,
    BST_ACORE_CORE_MSG_TYPE_RESET_INFO,
    BST_ACORE_CORE_MSG_TYPE_BUTT
};
typedef VOS_UINT32 BST_ACORE_CORE_MSG_TYPE_ENUM_UINT32;

enum BST_ACORE_CORE_KEY_PSSTATE_ENUM
{
    BST_ACORE_CORE_KEY_PS_STOP,
    BST_ACORE_CORE_KEY_PS_START,
    BST_ACORE_CORE_KEY_PS_BUTT
};
typedef VOS_UINT32 BST_ACORE_CORE_KEY_PSSTATE_ENUM_UINT32;

enum BST_EMCOM_SUPPORT_ENUM
{
    BST_CCORE_EMCOM_NOT_SUPPORT,
    BST_CCORE_EMCOM_SUPPORT,
    BST_CCORE_EMCOM_BUTT
};
typedef VOS_UINT8 BST_EMCOM_SUPPORT_ENUM_UINT8;


/*****************************************************************************
 * 5 ??/????????                                                             *
*****************************************************************************/
typedef struct
{
    BST_ACORE_CORE_MSG_TYPE_ENUM_UINT32 enMsgType;
    const VOS_UINT8                    *pucData;
} BST_ACOM_DATA_STRU;

typedef struct
{
    VOS_MSG_HEADER
    BST_ACORE_CORE_MSG_TYPE_ENUM_UINT32 enMsgType;
    VOS_UINT32                          ulLen;
    VOS_UINT8                           aucValue[4];
} BST_ACOM_MSG_STRU;

typedef struct
{
    VOS_UINT32                          ulTcpSeq;
    VOS_UINT16                          usSrcPort;
    VOS_UINT16                          usDropType;
} BST_ASPEN_TCP_INFO_STRU;

typedef struct
{
    VOS_MSG_HEADER
    BST_ACORE_CORE_MSG_TYPE_ENUM_UINT32    enMsgType;
    BST_ACORE_CORE_KEY_PSSTATE_ENUM_UINT32 enState;
} BST_KEY_PSINFO_STRU;

typedef struct
{
    VOS_MSG_HEADER
    BST_ACORE_CORE_MSG_TYPE_ENUM_UINT32 enMsgType;
    BST_EMCOM_SUPPORT_ENUM_UINT8        enState;
    VOS_UINT8                           aucReverse[3];
} BST_EMCOM_SUPPORT_STRU;

typedef struct
{
    VOS_UINT32                          ulAspenInfoType;
    VOS_UINT32                          ulPktNum;                           /* ???????? */
    BST_ASPEN_TCP_INFO_STRU             stPkt[BST_ASPEN_PKT_DROP_SIZE];     /* ????????(????????????128??????????) */
} BST_ASPEN_PKT_DROP_STRU;

/*****************************************************************************
 * 6 UNION????                                                               *
*****************************************************************************/

/*****************************************************************************
 * 7 ????????????                                                            *
*****************************************************************************/

/*****************************************************************************
 * 8 ????????                                                             *
*****************************************************************************/

/*****************************************************************************
 * 9 OTHERS????                                                              *
*****************************************************************************/

#pragma pack()

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif /* __BASTETINTERFACE_H__ */
