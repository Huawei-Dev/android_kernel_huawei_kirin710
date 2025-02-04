

#ifndef __NV_STRU_CAS_H__
#define __NV_STRU_CAS_H__


/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "PsTypeDef.h"
#include "nv_id_cas.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#pragma pack(4)

/*****************************************************************************
  2 ??????
*****************************************************************************/


/*****************************************************************************
  3 ????????
*****************************************************************************/


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
 ??????    : CPROC_1X_NVIM_DM_THRESHOLD_STRU
 ????????  :
 ASN.1???? :
 ????????  : Threshold for DM. 3570
*****************************************************************************/
typedef struct
{
    VOS_UINT8                           ucDiversitySwitch;          /* ???????? */
    VOS_UINT8                           ucIdleCrcInitCounter;       /* CRC?????????????????????? */
    VOS_UINT16                          usSimCardTemperature;       /* SIM?????????? */
    VOS_INT16                           shwIdleMeasRscpOn;          /* ????????RSCP???? */
    VOS_INT16                           shwIdleMeasRscpOff;         /* ????????RSCP???? */
    VOS_INT16                           shwIdleMeasEcN0On;          /* ????????EcN0???? */
    VOS_INT16                           shwIdleMeasEcN0Off;         /* ????????EcN0???? */
    VOS_UINT8                           ucTchCSFerOnCounter;        /* CS????????????FER???? */
    VOS_UINT8                           ucTchCSFerOffCounter;       /* CS????????????FER???? */
    VOS_UINT8                           ucTchCSFerOnWinSize;        /* CS????????????FER?????? */
    VOS_UINT8                           ucTchCSFerOffWinSize;       /* CS????????????FER?????? */
}CPROC_1X_NVIM_DM_THRESHOLD_STRU;


/*****************************************************************************
  8 UNION????
*****************************************************************************/


/*****************************************************************************
  9 OTHERS????
*****************************************************************************/


/*****************************************************************************
  10 ????????
*****************************************************************************/


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

#endif

/* end of nv_stru_cas.h */

