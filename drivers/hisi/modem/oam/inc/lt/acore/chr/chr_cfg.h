
#include "product_config.h"
#include "omerrorlog.h"
#include "blist.h"
#include "mdrv_sysboot.h"
#include "mdrv.h"

/*??????????????????*/
#define   PRIORITY_PACKET_START            (0)
#define   PRIORITY_PACKET_END              (0x7F)



/*????????????????????*/
#define   PERIOD_PACKET_START            (0)
#define   PERIOD_PACKET_END              (0x7F)

#define   PERIOD_CHK_FAIL            (3)
#define   PERIOD_CHK_COMPLETE        (0)
#define   PERIOD_CHK_CONTINUE        (1)
#define   PERIOD_CHK_RESTART         (2)

/*a??CHR ??????????????ID??*/
enum CHR_ID_REQ_MSG_ENUM
{ 
    CHR_ID_RESET_CCORE        = 0x1001,
    CHR_ID_ERR_LOG_REQ        = 0x1002,
    CHR_ID_BLACKLIST_REQ      = 0x1003,
    CHR_ID_PRIORITY_REQ       = 0x1004,
    CHR_ID_PERIOD_REQ         = 0x1005,
    
    CHR_ID_REQ_BUTT 
   
};

//#define chr_print(fmt, ...)    (printk(KERN_ERR "[chr]:<%s> line = %d, "fmt, __FUNCTION__, __LINE__ ,##__VA_ARGS__))
#define chr_print(fmt, ...)    (mdrv_err("<%s>"fmt, __FUNCTION__, ##__VA_ARGS__))

/*??????????????????*/
typedef struct
{
    VOS_UINT32          ulBlackListPacketLen;
    CHR_LIST_INFO_S    *pstChrBlackList;
    
}CHR_ACPU_BLACK_SAVE_STRU;


/*OM a??????c??????????????*/
typedef struct
{   
    VOS_MSG_HEADER 
    VOS_UINT32                   ulMsgName;
    VOS_UINT32                   ulPacketLen;
    CHR_LIST_INFO_S              stOmAcpuBlackList[0];        
}OM_ACPU_BLACK_LIST_STRU;


/*??????????0????????*/
typedef struct
{
    VOS_UINT32                  ulPiorityLen;
    CHR_PRIORITY_INFO_S         PriorityCfg[0];
}CHR_ACPU_PRIORITY_SAVE_STRU;


/*OM a??????c????????0??????????????*/
typedef struct
{   
    VOS_MSG_HEADER 
    VOS_UINT32                     ulMsgName;
    VOS_UINT32                     ulPacketLen;
    CHR_PRIORITY_INFO_S            PriorityCfg[0];        
}OM_ACPU_PRIORITY_CFG_STRU;


/*????????????????????*/
typedef struct
{
    VOS_UINT32                      ulperiod; /*ap??????period??8bit*/
    VOS_UINT32                      ulPacketLen;
    CHR_PERIOD_CFG_STRU             PeriodCfg[0];
}CHR_ACPU_PERIOD_SAVE_STRU;



/*????????????????*/
typedef struct
{
    LIST_S                     PriorityList;
    VOS_UINT32                 ulPacketLen;
    CHR_PRIORITY_INFO_S        pstPriorityCfg[0];
}OM_PRIORITY_NODE_STRU;

typedef struct
{
    VOS_UINT32              ulSN;
    VOS_UINT32              ulPrioPacketLen;
    OM_PRIORITY_NODE_STRU   List;
}OM_PRIORITY_LIST_STRU;

/*??????????????????*/

typedef struct
{  
    LIST_S                  PeriodList;
    VOS_UINT32              ulperiod;
    VOS_UINT32              ulPacketLen;
    CHR_PERIOD_CFG_STRU     pstPeriodCfg[0];
}OM_PERIOD_NODE_STRU;

typedef struct
{
    VOS_UINT32              ulSN;
    VOS_UINT32              ulPeriodPacketLen;
    OM_PERIOD_NODE_STRU     List;
}OM_PERIOD_LIST_STRU;


/*OM a??????c??????????????*/
typedef struct
{   
    VOS_MSG_HEADER
    VOS_UINT32                    ulMsgName;
    VOS_UINT32                    ulperiod;
    VOS_UINT32                    ulPacketLen;      
    CHR_PERIOD_CFG_STRU           stOmAcpuPeriodCfg[0];  
    
}OM_ACPU_PERIOD_CFG_STRU;

VOS_UINT32 OM_AcpuBlackListProc(VOS_UINT8 *pucData, VOS_UINT32 ulLen);
VOS_UINT32 OM_AcpuPriorityCfgProc(VOS_UINT8 *pucData, VOS_UINT32 ulLen);
VOS_UINT32 OM_AcpuPeriodCfgProc(VOS_UINT8 *pucData, VOS_UINT32 ulLen);
VOS_INT    chr_ResetCcoreCB(DRV_RESET_CB_MOMENT_E enParam, int userdata);
VOS_UINT32 OM_AcpuResetProc(VOS_VOID);

VOS_UINT32 CHR_Cfg_Init(VOS_VOID);
VOS_VOID OM_AcpuSendAppcfgResult(VOS_UINT32 ulRest);

