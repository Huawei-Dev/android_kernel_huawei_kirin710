#include <vos.h>
#include  "omerrorlog.h"
#include  "acore_nv_stru_msp.h"
/*****************************************************************************
   ????????????
*****************************************************************************/

#define    ERRLOG_IDLE         0
#define    ERRLOG_BUSY         1


#define                                 OM_MSG_RECEIVE_FLAG               (1) 
#define                                 OM_MSG_NO_RECEIVE_FLAG            (0)


/* Error Log ?????????? */
#define OM_ERRLOG_TIMER_LENTH               (5000)
#define OM_ERRORLOG_TIMER_NAME              (0x00001001)
#define OM_ERRORLOG_TIMER_PARA              (0x0000EFFE)

/* Clt INFO timer */
#define OM_CLTINFO_TIMER_LENTH               (5000)
#define OM_CLTINFO_TIMER_NAME         (0x00002002)
#define OM_CLTINFO_TIMER_PARA         (0x0000DFFD)

/* Send Log Tool MSG Type*/
#define OM_ERRLOG_SEND_MSG                  (0x0000DDDD)
#define OM_ERRLOG_RCV_MSG                   (0x0000EEEE)
#define OM_APP_ERRLOG_HOOK_IND              (0xBBFF)

#define OM_CLTINFO_CNF_NEED_PROCESS          0
#define OM_CLTINFO_CNF_NOT_NEED_PROCESS      1
#define OM_CLTINFO_INVALID_PID               0x5a5abeef

#define     OM_PID_NULL                     (0)          /* OM PID???? */
#define     OM_AP_NO_MSG_SEND               (0)          /* OM??????????AP?????????? */
#define     OM_AP_SEND_MSG_FINISH           (0)          /* OM??????AP???????? */



/* ????????Error Log????????????Ap?????? */
typedef struct
{
    VOS_UINT32                          ulErrLogSendNum;
    VOS_UINT32                          ulErrLogSendLen;
}OM_ERR_LOG_DEBUG_INFO;

/* OM????AP???????????????????????? */
typedef struct
{
    VOS_UINT16                          usFaultId;          /* ??????????faultid */
    VOS_UINT16                          usModemId;          /* ??????????modemid */
    VOS_UINT32                          ulFaultNv;          /* ????????faultid??????nvid */
    VOS_UINT32                          ulAlarmIdNum;       /* ??????????alarm???????? */
    VOS_UINT32                          ulErrLogReportSend; /* ????????????alarm??????????????????????pid???????????????? */
    VOS_UINT32                          ulErrLogState;      /* ???????????? */
    VOS_UINT32                          ulMsgSN;
    VOS_UINT32                          ulErrSendFlag[4];   /* ???????????? */
    VOS_UINT32                          ulErrRptFlag[4];    /* ???????????? */
    NV_ID_CHR_FAULTID_CONFIG_STRU       stFaultCfg;         /* ??????NV???? */
    
}OM_APP_MSG_RECORD_STRU;

/* ????????Error Log????????????Ap?????? */
typedef struct
{
    VOS_MSG_HEADER
    VOS_UINT32      ulMsgName;
    VOS_UINT32      ulMsgLen;
    VOS_UINT8       aucData[0];
    
}CHR_APP_REQ_STRU;
/*????????????*/

#define OM_ACPU_ERRLOG_SEND               (0x01 << (6))
#define OM_ACPU_ERRLOG_RCV                (0x01 << (7))



#define OM_ACPU_CHR_DEBUG_TRACE(pucData, ulDataLen, ulSwitch) \
        if(VOS_FALSE != (g_ulChrOmAcpuDbgFlag&ulSwitch)) \
        { \
            VOS_UINT32 ulChrOmDbgIndex; \
            (VOS_VOID)chr_print("Data Len = %d\n", ulDataLen); \
            for (ulChrOmDbgIndex = 0 ; ulChrOmDbgIndex < ulDataLen; ulChrOmDbgIndex++) \
            { \
                (VOS_VOID)mdrv_print(MDRV_P_ERR, "%02x ", *((VOS_UINT8*)pucData + ulChrOmDbgIndex)); \
            } \
            (VOS_VOID)chr_print("\r\n"); \
        }


/*OM??????????????????????????????????????????*/

typedef struct
{
    OM_RCV_DATA_HEADER_STRU             stChrRcvOmHeader;
    //????????????????????????UINT32??ulMsgType
    //????????????????????????????usMsgType ?? usFaultId
    union{
        VOS_UINT32                          ulMsgType;
        struct {
            VOS_UINT16                          usMsgType;
            VOS_UINT16                          usFaultId;
        }stComChrType;
    }unComChrType;
    //VOS_UINT32                          ulMsgType;
    VOS_UINT32                          ulMsgSN;
    VOS_UINT32                          ulRptLen;
}OM_RCV_REPORT_STRU;


extern VOS_VOID OM_AcpuSendVComData(VOS_UINT8 *pData, VOS_UINT32 uslength);
extern VOS_INT  OM_AcpuReadVComData(VOS_UINT8 ucDevIndex, VOS_UINT8 *pucData, VOS_UINT32 ulength);
extern VOS_VOID OM_AcpuErrLogMsgProc(MsgBlock* pMsg);
extern VOS_VOID OM_AcpuErrLogReqMsgProc(MsgBlock* pMsg);
extern VOS_VOID OM_AcpuErrLogTimeoutProc(VOS_VOID);


