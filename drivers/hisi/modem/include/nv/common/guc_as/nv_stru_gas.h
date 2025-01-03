
#ifndef __NV_STRU_GAS_H__
#define __NV_STRU_GAS_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  1 Include Headfile
*****************************************************************************/

#if (VOS_OS_VER != VOS_WIN32)
#pragma pack(2)
#else
#pragma pack(push, 2)
#endif

#include "vos.h"
#include "nv_id_guas.h"

/*****************************************************************************
  2 Macro
*****************************************************************************/
#define NVIM_TDS_MAX_SUPPORT_BANDS_NUM                      (8)


/*****************************************************************************
  3 Massage Declare
*****************************************************************************/

/*****************************************************************************
  4 Enum
*****************************************************************************/
enum NVIM_TDS_FREQ_BAND_LIST_ENUM
{
    ID_NVIM_TDS_FREQ_BAND_A         = 0x01,         /* ????????: 9504~9596  10054~10121 */
    ID_NVIM_TDS_FREQ_BAND_B         = 0x02,         /* ????????: 9254~9546  9654~9946 */
    ID_NVIM_TDS_FREQ_BAND_C         = 0x04,         /* ????????: 9554~9646 */
    ID_NVIM_TDS_FREQ_BAND_D         = 0x08,         /* ????????: 12854~13096 */
    ID_NVIM_TDS_FREQ_BAND_E         = 0x10,         /* ????????: 11504~11996 */
    ID_NVIM_TDS_FREQ_BAND_F         = 0x20,         /* ????????: 9404~9596 */
    ID_NVIM_TDS_FREQ_BAND_BUTT
};
typedef VOS_UINT8  NVIM_TDS_FREQ_BAND_LIST_ENUM_UINT8;


/*****************************************************************************
  5 Struct
*****************************************************************************/

/*****************************************************************************
 ??????    : NVIM_EGPRS_MULTI_SLOT_CLASS_STRU
 ????????  : en_NV_Item_Egprs_Multi_Slot_Class ????
 DESCRIPTION:  ????MS??EGPRS??????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usEgprsMultiSlotClass;                  /* Range: [0,12]
                                                                                   0x0:MS????????????????0xC
                                                                                   0x1~0xC:????MS?????????????? */
    VOS_UINT8                           aucReserve[2];
}NVIM_EGPRS_MULTI_SLOT_CLASS_STRU;

/*****************************************************************************
 ??????    : NVIM_EGPRS_FLAG_STRU
 ????????  : en_NV_Item_Egprs_Flag ????
 DESCRIPTION:  MS????????EGPRS????NV????????????Modem????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usEgprsFlag;                            /* 0x0000:??????EGPRS
                                                                                   0x0001:????EGPRS */
    VOS_UINT8                           aucReserve[2];
}NVIM_EGPRS_FLAG_STRU;

/*****************************************************************************
 ??????    : NVIM_GPRS_ACTIVE_TIMER_LENGTH_STRU
 ????????  : en_NV_Item_GPRS_ActiveTimerLength ????
 DESCRIPTION: GPRS Active Timer????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                          ulGprsActiveTimerLength;                /* 0x0000:100ms;
                                                                                   0x0001:100ms;
                                                                                   0x0002:200ms;???????? */
}NVIM_GPRS_ACTIVE_TIMER_LENGTH_STRU;

/*****************************************************************************
 ??????    : NVIM_GPRS_MULTI_SLOT_CLASS_STRU
 ????????  : en_Nv_Item_Gprs_Multi_Slot_Class ????
 DESCRIPTION: ????MS??GPRS??????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT16                          usGprsMultiSlotClass;                   /* Range: [0,12]
                                                                                   0x0:MS????????????????0xC
                                                                                   0x1~0xC:????MS?????????????? */
    VOS_UINT8                           aucReserve[2];
}NVIM_GPRS_MULTI_SLOT_CLASS_STRU;

/*****************************************************************************
 ??????    : NVIM_GAS_HIGH_MULTISLOT_CLASS_STRU
 ????????  : en_NV_Item_GAS_High_Multislot_Class ????
 DESCRIPTION: MS????????Multi class33
*****************************************************************************/
typedef struct
{
    VOS_UINT16                              usHighMultislotClassFlg;            /* Range: [0,1],0x0:????,0x1:???? */
    VOS_UINT16                              usHighMultislotClass;               /* ??????????????????NV?????? */
}NVIM_GAS_HIGH_MULTISLOT_CLASS_STRU;

/*****************************************************************************
 ??????    : NVIM_UE_TDS_SUPPORT_FREQ_BAND_LIST_STRU
 ????????  : en_NV_Item_UTRAN_TDD_FREQ_BAND ????
 DESCRIPTION: TDS??????????????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT8                               ucBandCnt;                          /* ??????TDS????????,????????????3??????(A/E/F),Range: [0,6] */
    VOS_UINT8                               aucReserved[3];
    VOS_UINT8                               aucBandNo[NVIM_TDS_MAX_SUPPORT_BANDS_NUM];  /* aucBandNo[x]??????????TDS?????? */
}NVIM_UE_TDS_SUPPORT_FREQ_BAND_LIST_STRU;


/*****************************************************************************
  6 UNION
*****************************************************************************/


/*****************************************************************************
  7 Extern Global Variable
*****************************************************************************/


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

#endif

/* end of nv_stru_gas.h */

