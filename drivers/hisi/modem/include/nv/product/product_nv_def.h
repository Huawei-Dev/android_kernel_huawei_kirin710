/******************************************************************************

    Copyright(C)2008,Hisilicon Co. LTD.

 ******************************************************************************
  File Name       :   product_nv_def.h
  Description     :   ????NV ??????????
  History         :
******************************************************************************/

#ifndef __PRODUCT_NV_DEF_H__
#define __PRODUCT_NV_DEF_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define MAX_SINGLE_GUC_BAND_CHECK_NUM       28
#define MAX_SINGLE_TL_BAND_CHECK_NUM        12
#define MAX_NV_GUC_CHECK_ITEM_NUM           32
#define MAX_NV_TL_CHECK_ITEM_NUM            64

#include <asm-generic/int-ll64.h>

/*????????????????*/
typedef struct
{
    int reserved;  /*note */
}PRODUCT_MODULE_STRU;

typedef struct
{
    u32 uwGucCrcResult;                     		/* GUc????NV?????????? */
    u32 uwTlCrcResult;                      		/* TL????NV?????????? */
    u32 uwGucM2CrcResult;                   		/* GUC????NV?????????? */
}NV_CRC_CHECK_RESULT_STRU;

typedef struct
{
    u16 uhwTransmitMode;                       		/* ?????????????????? */
    u16 uhwBand;                              		/* ??????????BAND?? */
    u16 uhwEnable;                              	/* ???????????? */
    u16 uhwValidCount;                              	/* ?????????????????? */
    u16 auhwNeedCheckID[MAX_SINGLE_GUC_BAND_CHECK_NUM]; /* ??????????????NV_ID?? */
}SINGLE_GUC_BAND_NV_ID_STRU;

typedef struct
{
    u16 uhwTransmitMode;                       		/* ?????????????????? */
    u16 uhwBand;                              		/* ??????????BAND?? */
    u16 uhwEnable;                              	/* ???????????? */
    u16 uhwValidCount;                              	/* ?????????????????? */
    u16 auhwNeedCheckID[MAX_SINGLE_TL_BAND_CHECK_NUM]; 	/* ??????????????NV_ID?? */
}SINGLE_TL_BAND_NV_ID_STRU;

typedef struct
{
    SINGLE_GUC_BAND_NV_ID_STRU astNVIDCheckItem[MAX_NV_GUC_CHECK_ITEM_NUM];  	/* ??????????????NV_ID?? */
}NV_GUC_CHECK_ITEM_STRU;

typedef struct
{
    SINGLE_TL_BAND_NV_ID_STRU astNVIDCheckItem[MAX_NV_TL_CHECK_ITEM_NUM];   	/* ??????????????NV_ID?? */
}NV_TL_CHECK_ITEM_STRU;

typedef struct
{
    u16 uhwWorkStationNum;
    u16 auhwNV50001InsertPoint[5];
    u16 auhwNV50002InsertPoint[5];
    u16 auhwNV50003InsertPoint[5];
    u32 rsv;
}NV_WORKSTATION_INFO_STRU;

/*****************************************************************************
 ??????    : CHG_BATTERY_LOW_TEMP_PROTECT_NV
 ????????  : CHG_BATTERY_LOW_TEMP_PROTECT_NV???? ID=52005
*****************************************************************************/
typedef struct
{
    u32  ulIsEnable;
    s32  lCloseAdcThreshold;
    u32  ulTempLowCount;
}CHG_BATTERY_LOW_TEMP_PROTECT_NV;


typedef struct
{
    u32                          ulIsEnable;
    s32                           lCloseADCHold;
    u32                          ulTempOverMax;
}OM_BATTREY_TEMP_CFG_STRU;

/*****************************************************************************
 ??????    : nvi_cust_pid_type
 ????????  : nvi_cust_pid_type????
*****************************************************************************/
typedef struct
{
    u32  nv_status;
    u16  cust_first_pid;
    u16  cust_rewind_pid;
}nvi_cust_pid_type;

/*****************************************************************************
 ??????    : NV_WEBNAS_SD_WORKMODE_STRU
 ????????  : NV_WEBNAS_SD_WORKMODE????
*****************************************************************************/
typedef struct
{
    u32 ulSDWorkMode;
}NV_WEBNAS_SD_WORKMODE_STRU;

/*****************************************************************************
 ??????    : NV_OLED_TEMP_ADC_STRU
 ????????  : NV_OLED_TEMP_ADC????
*****************************************************************************/
typedef struct
{
    s16       sTemp;
    s16       sADC;
}NV_OLED_TEMP_ADC_STRU;

/*****************************************************************************
 ??????    : NV_OLED_TEMP_ADC_STRU_ARRAY
 ????????  : NV_OLED_TEMP_ADC_STRU_ARRAY????  ID=49
*****************************************************************************/
typedef struct
{
    NV_OLED_TEMP_ADC_STRU          stNV_OLED_TEMP_ADC[28];
}NV_OLED_TEMP_ADC_STRU_ARRAY;

/*****************************************************************************
 ??????    : TEMP_ADC_STRU
 ????????  : TEMP_ADC????
*****************************************************************************/
typedef struct
{
    s16    sTemp;
    u16    usADC;
}TEMP_ADC_STRU;

/*****************************************************************************
 ??????    : TEMP_ADC_STRU_ARRAY
 ????????  : TEMP_ADC_STRU_ARRAY????
*****************************************************************************/
typedef struct
{
    TEMP_ADC_STRU    stTempAdc[28];
}TEMP_ADC_STRU_ARRAY;

/*****************************************************************************
 ??????    : USB_SN_NV_INFO_STRU
 ????????  : USB_SN_NV_INFO????
*****************************************************************************/
typedef struct
{
    u32    usbSnNvStatus;
    u32    usbSnNvSucFlag;
    u32    usbSnReserved1;
    /*u32    usbSnReserved2;*/
}USB_SN_NV_INFO_STRU;

/*****************************************************************************
 ??????    : LIVE_TIME_STRU
 ????????  : LIVE_TIME????
*****************************************************************************/
typedef struct
{
    u32    ulLiveTime;
}LIVE_TIME_STRU;

/*****************************************************************************
 ??????    : LIVE_TIME_CONTROL_STRU
 ????????  : LIVE_TIME_CONTROL????
*****************************************************************************/
typedef struct
{
    u32    ulEnable;
    u32    ulCycle;
} LIVE_TIME_CONTROL_STRU;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif


