
#ifndef __NV_ID_PAM_H__
#define __NV_ID_PAM_H__

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "vos.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#if (VOS_OS_VER != VOS_WIN32)
#pragma pack(4)
#else
#pragma pack(push, 4)
#endif
/*****************************************************************************
  2 ??????
*****************************************************************************/

/*****************************************************************************
  3 ????????
*****************************************************************************/
/*****************************************************************************
 ??????    : PAM_NV_ID_ENUM
 ????????  : PAM????????NV??ID????
*****************************************************************************/
enum PAM_NV_ID_ENUM
{
/* 40  */        en_NV_Item_USIM_TEMP_PROTECT_NEW =     40,
/* 45  */        en_NV_Item_Om_Port_Type =    45,

/* 4001 */       en_NV_Item_Usim_App_Priority_Cfg = 4001,

/* 4008 */       en_NV_Item_NV_SC_PERS_CTRL_CFG = 4008,

/* 4011 */       en_NV_Item_Usim_Uicc_App_Priority_Cfg = 4011,

/* 4043 */       en_NV_Item_Usim_Debug_Mode_Set = 4043,

/* 8244  */      en_NV_Item_Usim_PB_Ctrl_Info = 8244,
/* 8261  */      en_NV_Item_TerminalProfile_Set = 8261,

/* 50041  */     en_NV_Item_NV_HUAWEI_DOUBLE_IMSI_CFG_I   = 50041,
#if (FEATURE_ON == FEATURE_UE_MODE_CDMA)
/* 9283 */       en_NV_Item_ESN_MEID = 9283,
#endif
};

/*****************************************************************************
  4 ????????????
*****************************************************************************/

/*****************************************************************************
  5 ??????????
*****************************************************************************/

/*****************************************************************************
  6 ????????
*****************************************************************************/


/*****************************************************************************
  7 STRUCT????
*****************************************************************************/

/*****************************************************************************
  8 UNION????
*****************************************************************************/


/*****************************************************************************
  9 OTHERS????
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

#endif
