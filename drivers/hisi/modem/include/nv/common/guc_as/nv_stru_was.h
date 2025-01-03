

#ifndef __NV_STRU_WAS_H__
#define __NV_STRU_WAS_H__


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


/*****************************************************************************
  1 Include Headfile
*****************************************************************************/
#if (VOS_OS_VER != VOS_WIN32)
#pragma pack(4)
#else
#pragma pack(push, 4)
#endif

#include "PsTypeDef.h"
#include "nv_id_guas.h"

/*****************************************************************************
  2 Macro
*****************************************************************************/
#define WAS_NV_PTL_VER_R3                       (0)                             /* WAS_PTL_VER_R3 */
#define WAS_NV_PTL_VER_R4                       (1)                             /* WAS_PTL_VER_R4 */
#define WAS_NV_PTL_VER_R5                       (2)                             /* WAS_PTL_VER_R5 */
#define WAS_NV_PTL_VER_R6                       (3)                             /* WAS_PTL_VER_R6 */
#define WAS_NV_PTL_VER_R7                       (4)                             /* WAS_PTL_VER_R7 */
#define WAS_NV_PTL_VER_R8                       (5)                             /* WAS_PTL_VER_R8 */
#define WAS_NV_PTL_VER_R9                       (6)                             /* WAS_PTL_VER_R9 */


/*****************************************************************************
  3 Massage Declare
*****************************************************************************/

/*****************************************************************************
  4 Enum
*****************************************************************************/
/*****************************************************************************
 ??????    : WAS_TX_RX_FREQ_SEPARAT_ENUM_UINT8
 ????????  :
 ASN.1???? :
 ????????  :
*****************************************************************************/
enum WAS_TX_RX_FREQ_SEPARAT_ENUM
{
    WAS_TX_RX_FREQ_SEPARAT_DEFAULT_TX_RX_SEPARATION = 0,
    WAS_TX_RX_FREQ_SEPARAT_SPARE2,
    WAS_TX_RX_FREQ_SEPARAT_SPARE1,
    WAS_TX_RX_FREQ_SEPARAT_BUTT
} ;
typedef VOS_UINT8 WAS_TX_RX_FREQ_SEPARAT_ENUM_UINT8;

/*****************************************************************************
 ??????    : WAS_DL_SIMUL_HS_DSCH_CFG_ENUM_UINT8
 ????????  :
 ASN.1???? :
 ????????  :
*****************************************************************************/
enum  WAS_DL_SIMUL_HS_DSCH_CFG_ENUM
{
    WAS_DL_SIMUL_HS_DSCH_CFG_KBPS32 = 0,
    WAS_DL_SIMUL_HS_DSCH_CFG_KBPS64,
    WAS_DL_SIMUL_HS_DSCH_CFG_KBPS128,
    WAS_DL_SIMUL_HS_DSCH_CFG_KBPS384,
    WAS_DL_SIMUL_HS_DSCH_CFG_BUTT
};
typedef VOS_UINT8 WAS_DL_SIMUL_HS_DSCH_CFG_ENUM_UINT8;

/*****************************************************************************
 ??????    : WAS_PTL_VER_TYPE_ENUM_UINT8
 ????????  : 10.2.39    RRC CONNECTION REQUEST
 ASN.1???? : AccessStratumReleaseIndicator
 ????????  : ????????
             Absence of the IE implies R3.
             The IE also indicates the release of the RRC transfer syntax
             supported by the UE 13 spare values are needed
*****************************************************************************/
enum WAS_PTL_VER_TYPE_ENUM
{
    WAS_PTL_VER_ENUM_R3                 = WAS_NV_PTL_VER_R3,                    /* _H2ASN_Replace  WAS_NV_PTL_VER_R3 = 0 */
    WAS_PTL_VER_ENUM_R4                 = WAS_NV_PTL_VER_R4,                    /* _H2ASN_Replace  WAS_NV_PTL_VER_R4 = 1 */
    WAS_PTL_VER_ENUM_R5                 = WAS_NV_PTL_VER_R5,                    /* _H2ASN_Replace  WAS_NV_PTL_VER_R5 = 2 */
    WAS_PTL_VER_ENUM_R6                 = WAS_NV_PTL_VER_R6,                    /* _H2ASN_Replace  WAS_NV_PTL_VER_R6 = 3 */
    WAS_PTL_VER_ENUM_R7                 = WAS_NV_PTL_VER_R7,                    /* _H2ASN_Replace  WAS_NV_PTL_VER_R7 = 4 */
    WAS_PTL_VER_ENUM_R8                 = WAS_NV_PTL_VER_R8,                    /* _H2ASN_Replace  WAS_NV_PTL_VER_R8 = 5 */
    WAS_PTL_VER_ENUM_R9                 = WAS_NV_PTL_VER_R9,                    /* _H2ASN_Replace  WAS_NV_PTL_VER_R9 = 6 */
    WAS_PTL_VER_ENUM_BUTT
};
typedef VOS_UINT8 WAS_PTL_VER_TYPE_ENUM_UINT8;

/*****************************************************************************
  5 STRUCT
*****************************************************************************/

/*****************************************************************************
 ??????    : WAS_RF_CAPA_STRU
 ????????  : 10.3.3.33 RF capability FDD
 ASN.1???? :
 ????????  : RF????????
 DESCRIPTION: RF????????
*****************************************************************************/
typedef struct
{
    VOS_UINT8                               ucPowerClass;                       /* UE????????                               */
    WAS_TX_RX_FREQ_SEPARAT_ENUM_UINT8       enTxRxFreqSeparate;                 /* Tx/Rx ????????                           */
    VOS_UINT8                               aucReserve1[2];                     /* 4?????????????? */
}WAS_RF_CAPA_STRU;

/*****************************************************************************
 ??????    : WAS_NVIM_UE_CAPA_CUSTOMED_STRU
 ????????  : ????????????????NVIM????UE????????,??????BOSTON????????????   ID:9008 en_NV_Item_WAS_RadioAccess_Capa_New
 DESCRIPTION: ????????????????NVIM????UE????????,??????BOSTON????????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                              ulHspaStatus;                       /* 0??????????,????DPA??UPA??????;1???????? */

    WAS_RF_CAPA_STRU                        stRfCapa;                           /* RF ????????                                  */

    PS_BOOL_ENUM_UINT8                      enSupportPwrBoosting;               /* 16QAM??????????????????E-DPCCH Power Boosting*/
    PS_BOOL_ENUM_UINT8                      enReserve1;                         /* ????enSf4Support????????????reserved */

    WAS_DL_SIMUL_HS_DSCH_CFG_ENUM_UINT8     enDlSimulHsDschCfg;                 /* ENUMERATED  OPTIONAL                         */
    WAS_PTL_VER_TYPE_ENUM_UINT8             enAsRelIndicator;                   /* Access Stratum Release Indicator             */

    PS_BOOL_ENUM_UINT8                      enHSDSCHSupport;                    /* ????????enHSDSCHSupport??????                */
    VOS_UINT8                               ucHSDSCHPhyCategory;                /* ????HS-DSCH????????????????                  */

    PS_BOOL_ENUM_UINT8                      enMacEhsSupport;
    VOS_UINT8                               ucHSDSCHPhyCategoryExt;
    PS_BOOL_ENUM_UINT8                      enMultiCellSupport;                 /* ???????? Multi cell support,????????MultiCell,Ex2???? */
    VOS_UINT8                               ucHSDSCHPhyCategoryExt2;            /* HS-DSCH physical layer category extension 2 */

    PS_BOOL_ENUM_UINT8                      enCellSpecTxDiversityForDc;         /*  This IE is optionally present if Dual-Cell HSDPA is supported. Otherwise it is not needed.
                                                                                    The IE is not needed in the INTER RAT HANDOVER INFO message. Otherwise, it is optional*/
    PS_BOOL_ENUM_UINT8                      enReserve2;                         /* ????enEFDPCHSupport????????????reserved */
    PS_BOOL_ENUM_UINT8                      enEDCHSupport;                      /* ????????EDCH??????                           */
    VOS_UINT8                               ucEDCHPhyCategory;                  /* ????UPA??????                                */
    PS_BOOL_ENUM_UINT8                      enSuppUl16QAM;                      /* ????????????16QAM??????????ucEDCHPhyCategoryExt?????? */
    VOS_UINT8                               ucEDCHPhyCategoryExt;               /* ??????????????16QAM????????7 */
    PS_BOOL_ENUM_UINT8                      enSuppEDpdchInterpolationFormula;   /* 16QAM??????????????????E-DPDCH power interpolation formula */
    PS_BOOL_ENUM_UINT8                      enReserve3;                         /* ????enSuppHsdpaInFach????????????reserved */
    PS_BOOL_ENUM_UINT8                      enReserve4;                         /* ????enSuppHsdpaInPch????????????reserved */

    PS_BOOL_ENUM_UINT8                      enMacIsSupport;                     /* ????????MAC_I/MAC_Is */

    PS_BOOL_ENUM_UINT8                      enReserve5;                         /* ????enFDPCHSupport????????????reserved */

    PS_BOOL_ENUM_UINT8                      enReserve6;                         /* ????enHsscchLessSupport????????????reserved */
    PS_BOOL_ENUM_UINT8                      enReserve7;                         /* ????enUlDpcchDtxSupport????????????reserved */

    PS_BOOL_ENUM_UINT8                      enAdjFreqMeasWithoutCmprMode;       /* ???????? Adjacent Frequency measurements without compressed mode */

    PS_BOOL_ENUM_UINT8                      enMimoSingleStreamStrict;           /* ????????????????????MIMO */
    PS_BOOL_ENUM_UINT8                      enMimoWithDlTxDiversity;            /* R9????????MIMO???????????????????????????????????? */

    /* V7r1 ????????NV?? LTE???? */
    PS_BOOL_ENUM_UINT8                      enSptAbsPriBasedReselInUtra;        /* ????UTRA??????????????????????0??1????????0???????? */

    VOS_UINT8                               ucHSDSCHPhyCategoryExt3;            /* HS-DSCH physical layer category extension 3 */
    PS_BOOL_ENUM_UINT8                      enDcMimoSupport;                    /* ????????DC+MIMO */
    PS_BOOL_ENUM_UINT8                      enSuppCommEDCH;                     /* E-RACH???????? */

    PS_BOOL_ENUM_UINT8                      enDcUpaSupport;                     /* ????????DC UPA?????? */
    VOS_UINT8                               ucEDCHPhyCategoryExt2;              /* EDCH  category extension 2*/
    PS_BOOL_ENUM_UINT8                      enEdpdchGainFactorFlg;              /* E-DPDCH?????????????????????? */
    PS_BOOL_ENUM_UINT8                      enReserve8;                         /* ????enHo2EutranUnSupportFlg????????????reserved */
    PS_BOOL_ENUM_UINT8                      enReserve9;                         /* ????enEutranMeasUnSupportFlg????????????reserved */
    VOS_UINT8                               aucReserve2[5];
}WAS_NVIM_UE_CAPA_CUSTOMED_STRU;


/*****************************************************************************
 ??????    : WAS_NVIM_UE_CAPA_STRU
 ????????  : ??????NVIM????UE????????               ID:9008 en_NV_Item_WAS_RadioAccess_Capa_New
 DESCRIPTION: ??????NVIM????UE????????
*****************************************************************************/
typedef struct
{
    VOS_UINT32                              ulHspaStatus;                       /* 0??????????,????DPA??UPA??????;1???????? */

    WAS_RF_CAPA_STRU                        stRfCapa;                           /* RF ????????                                  */

    PS_BOOL_ENUM_UINT8                      enSupportPwrBoosting;               /* 16QAM??????????????????E-DPCCH Power Boosting*/
    PS_BOOL_ENUM_UINT8                      enSf4Support;                       /* ????????ul dpcch ???? slotFormat4 */

    WAS_DL_SIMUL_HS_DSCH_CFG_ENUM_UINT8     enDlSimulHsDschCfg;                 /* ENUMERATED  OPTIONAL                         */
    WAS_PTL_VER_TYPE_ENUM_UINT8             enAsRelIndicator;                   /* Access Stratum Release Indicator             */

    PS_BOOL_ENUM_UINT8                      enHSDSCHSupport;                    /* ????????enHSDSCHSupport??????                */
    VOS_UINT8                               ucHSDSCHPhyCategory;                /* ????HS-DSCH????????????????                  */

    PS_BOOL_ENUM_UINT8                      enMacEhsSupport;
    VOS_UINT8                               ucHSDSCHPhyCategoryExt;
    PS_BOOL_ENUM_UINT8                      enMultiCellSupport;                 /* ???????? Multi cell support,????????MultiCell,Ex2???? */
    VOS_UINT8                               ucHSDSCHPhyCategoryExt2;            /* HS-DSCH physical layer category extension 2 */

    PS_BOOL_ENUM_UINT8                      enCellSpecTxDiversityForDc;         /*  This IE is optionally present if Dual-Cell HSDPA is supported. Otherwise it is not needed.
                                                                                    The IE is not needed in the INTER RAT HANDOVER INFO message. Otherwise, it is optional*/
    PS_BOOL_ENUM_UINT8                      enEFDPCHSupport;                    /* ????????E-FDPCH??????,FDPCH????????NV?????? */
    PS_BOOL_ENUM_UINT8                      enEDCHSupport;                      /* ????????EDCH??????                           */
    VOS_UINT8                               ucEDCHPhyCategory;                  /* ????UPA??????                                */
    PS_BOOL_ENUM_UINT8                      enSuppUl16QAM;                      /* ????????????16QAM??????????ucEDCHPhyCategoryExt?????? */
    VOS_UINT8                               ucEDCHPhyCategoryExt;               /* ??????????????16QAM????????7 */
    PS_BOOL_ENUM_UINT8                      enSuppEDpdchInterpolationFormula;   /* 16QAM??????????????????E-DPDCH power interpolation formula */
    PS_BOOL_ENUM_UINT8                      enSuppHsdpaInFach;                  /* ????CELL_FACH??HS-DSCH?????? */
    PS_BOOL_ENUM_UINT8                      enSuppHsdpaInPch;                   /* ????CELL_PCH??URA_PCH??HS-DSCH?????? */

    PS_BOOL_ENUM_UINT8                      enMacIsSupport;                     /* ????????MAC_I/MAC_Is */

    PS_BOOL_ENUM_UINT8                      enFDPCHSupport;                     /* ????????FDPCH??????                          */

    PS_BOOL_ENUM_UINT8                      enHsscchLessSupport;                /* ???????? hsscchlessHsdschOperation           */
    PS_BOOL_ENUM_UINT8                      enUlDpcchDtxSupport;                /* ???????? discontinuousDpcchTransmission      */

    PS_BOOL_ENUM_UINT8                      enAdjFreqMeasWithoutCmprMode;       /* ???????? Adjacent Frequency measurements without compressed mode */

    PS_BOOL_ENUM_UINT8                      enMimoSingleStreamStrict;           /* ????????????????????MIMO */
    PS_BOOL_ENUM_UINT8                      enMimoWithDlTxDiversity;            /* R9????????MIMO???????????????????????????????????? */

    /* V7r1 ????????NV?? LTE???? */
    PS_BOOL_ENUM_UINT8                      enSptAbsPriBasedReselInUtra;        /* ????UTRA??????????????????????0??1????????0???????? */

    VOS_UINT8                               ucHSDSCHPhyCategoryExt3;            /* HS-DSCH physical layer category extension 3 */
    PS_BOOL_ENUM_UINT8                      enDcMimoSupport;                    /* ????????DC+MIMO */
    PS_BOOL_ENUM_UINT8                      enSuppCommEDCH;                     /* E-RACH???????? */

    PS_BOOL_ENUM_UINT8                      enDcUpaSupport;                     /* ????????DC UPA?????? */
    VOS_UINT8                               ucEDCHPhyCategoryExt2;              /* EDCH  category extension 2*/
    PS_BOOL_ENUM_UINT8                      enEdpdchGainFactorFlg;              /* E-DPDCH?????????????????????? */
    PS_BOOL_ENUM_UINT8                      enHo2EutranUnSupportFlg;            /* ????????????L??HO */
    PS_BOOL_ENUM_UINT8                      enEutranMeasUnSupportFlg;           /* ??????????????????L?????? */
    VOS_UINT8                               aucReserve2[5];
}WAS_NVIM_UE_CAPA_STRU;


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

/* end of nv_stru_was.h */

