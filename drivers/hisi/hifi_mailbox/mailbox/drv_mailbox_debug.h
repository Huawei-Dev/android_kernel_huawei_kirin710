
#ifndef _DRV_MAILBOX_DEBUG_H_
#define _DRV_MAILBOX_DEBUG_H_

/*****************************************************************************
1 ??????????
*****************************************************************************/
#include "drv_mailbox_platform.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif



/*****************************************************************************
  2 ??????
*****************************************************************************/
/*??????????????????????????*/
#define MAILBOX_MAIL_TRANS_TIME_LIMIT				(3000)		 /* ????????????????????????(value/32 ms) */
#define MAILBOX_MAIL_DEAL_TIME_LIMIT				(2000)		 /* ????????????????????????????(value/32 ms) */
#define MAILBOX_MAIL_SCHE_TIME_LIMIT				(2000)		 /* ????????????????????????????????(value/32 ms) */

/*????????????????????????*/
#define MAILBOX_ERRO_ARRAY_NUM						(5)

#define MAILBOX_LOG_NONE				(-1)
#define MAILBOX_LOG_CRITICAL			(0)
#define MAILBOX_LOG_ERROR				(1)
#define MAILBOX_LOG_WARNING 			(2)
#define MAILBOX_LOG_INFO				(3)

#define MAILBOX_SHOW_ALL				(0x001) /*????????????????????*/
#define MAILBOX_SHOW_CLEAR				(0x010) /*??????????????????????*/

/*????????????????????????*/
#define MAILBOX_QUEUE_LEFT_INVALID					(0xffffffff)

/*????????????????slice*/
#define MAILBOX_MAX_SLICE							(0xffffffff)
#define mailbox_get_slice_diff(s,e) 				(((e) >= (s))?((e) - (s)) : ((MAILBOX_MAX_SLICE - (s)) + (e)))

/*????????????????*/
#if (MAILBOX_LOG_LEVEL == MAILBOX_LOG_NONE)
#define mailbox_logerro_p0(ErrorId)                 (unsigned int)(ErrorId)

#define mailbox_logerro_p1(ErrorId, Param)          (unsigned int)(ErrorId)

#define mailbox_logerro_p2(ErrorId, Param1,Param2)  (unsigned int)(ErrorId)

#else
#define mailbox_logerro_p0(ErrorId)                 mailbox_log_erro((unsigned int)ErrorId, (unsigned int)0,(unsigned int)0,\
                                                    (unsigned int)_MAILBOX_LINE_, (char*)_MAILBOX_FILE_)

#define mailbox_logerro_p1(ErrorId, Param)          mailbox_log_erro((unsigned int)ErrorId, (unsigned long)Param,(unsigned long)0, \
                                                    (unsigned int)_MAILBOX_LINE_, (char*)_MAILBOX_FILE_)

#define mailbox_logerro_p2(ErrorId, Param1,Param2)  mailbox_log_erro((unsigned int)ErrorId, (unsigned long)Param1,Param2, \
                                                    (unsigned int)_MAILBOX_LINE_, (char*)_MAILBOX_FILE_)
#endif

/*????????????*/ /*??????????????????:????????????*/
#define    MAILBOX_CRIT_RET_START								0x80000001
#define    MAILBOX_CRIT_GUT_INVALID_USER_MAIL_HANDLE			0x80000002
#define    MAILBOX_CRIT_GUT_INIT_CHANNEL_POOL_TOO_SMALL 		0x80000003
#define    MAILBOX_CRIT_GUT_INIT_USER_POOL_TOO_SMALL			0x80000004
#define    MAILBOX_CRIT_GUT_MUTEX_LOCK_FAILED					0x80000005
#define    MAILBOX_CRIT_GUT_MUTEX_UNLOCK_FAILED 				0x80000006
#define    MAILBOX_CRIT_GUT_MSG_CHECK_FAIL						0x80000007
#define    MAILBOX_CRIT_GUT_RECEIVE_MAIL						0x80000008
#define    MAILBOX_CRIT_GUT_READ_MAIL							0x80000009
#define    MAILBOX_CRIT_GUT_MEMORY_CONFIG						0x8000000a
#define    MAILBOX_CRIT_PORT_CONFIG 							0x80000010 /*????????????????????*/
#define    MAILBOX_CRIT_RET_END 								0x800000ff /*????????????*/


/*****************************************************************************
  ??????????????
*****************************************************************************/
/*??????????????*/ /*????????????????????:????????????????????*/
#define    MAILBOX_ERR_RET_START								0x80000100
#define    MAILBOX_ERR_GUT_INVALID_CPU_LINK 					0x80000101
#define    MAILBOX_ERR_GUT_INVALID_SRC_CPU						0x80000102
#define    MAILBOX_ERR_GUT_INVALID_TARGET_CPU					0x80000103
#define    MAILBOX_ERR_GUT_INVALID_CHANNEL_ID					0x80000104
#define    MAILBOX_ERR_GUT_INVALID_CARRIER_ID					0x80000105
#define    MAILBOX_ERR_GUT_REQUEST_CHANNEL						0x80000106
#define    MAILBOX_ERR_GUT_RELEASE_CHANNEL						0x80000107
#define    MAILBOX_ERR_GUT_TIMESTAMP_CHECK_FAIL 				0x80000108
#define    MAILBOX_ERR_GUT_WRITE_EXCEED_MAX_SIZE				0x80000109
#define    MAILBOX_ERR_GUT_ALREADY_INIT 						0x8000010a
#define    MAILBOX_ERR_GUT_SEND_MAIL_IN_INT_CONTEXT 			0x8000010b
#define    MAILBOX_ERR_GUT_USER_BUFFER_SIZE_TOO_SMALL			0x8000010c
#define    MAILBOX_ERR_GUT_INPUT_PARAMETER						0x8000010d
#define    MAILBOX_ERR_GUT_NOT_INIT 							0x8000010e
#define    MAILBOX_ERR_GUT_MAILBOX_SEQNUM_CHECK_FAIL			0x8000010f
#define    MAILBOX_ERR_GUT_MAILBOX_RECEIVE_FULL 				0x80000110
#define    MAILBOX_ERR_GUT_INIT_PLATFORM						0x80000112
#define    MAILBOX_ERR_GUT_MAILBOX_NULL_PARAM					0x80000113
#define    MAILBOX_ERR_GUT_CREATE_BOX							0x80000114
#define    MAILBOX_ERR_GUT_MUTEX_CREATE_FAILED					0x80000115
#define    MAILBOX_ERR_GUT_READ_CALLBACK_NOT_FIND				0x80000116
#define    MAILBOX_ERR_GUT_INVALID_USER_ID						0x80000117
#define    MAILBOX_ERR_GUT_INIT_CHANNEL_POOL_TOO_LARGE			0x80000118
#define    MAILBOX_ERR_GUT_INIT_USER_POOL_TOO_LARGE 			0x80000119
#define    MAILBOX_ERR_GUT_CALCULATE_SPACE						0x8000011a
#define    MAILBOX_ERR_GUT_INIT_CORESHARE_MEM					0x8000011b

#define    MAILBOX_ERR_VXWORKS_TASK_CREATE						0x80000140
#define    MAILBOX_ERR_VXWORKS_CALLBACK_NOT_FIND				0x80000141
#define    MAILBOX_ERR_VXWORKS_CALLBACK_ERRO					0x80000142
#define    MAILBOX_ERR_VXWORKS_MAIL_TASK_NOT_FIND				0x80000143
#define    MAILBOX_ERR_VXWORKS_MAIL_INT_NOT_FIND				0x80000144
#define    MAILBOX_ERR_VXWORKS_CHANNEL_NOT_FIND 				0x80000145
#define    MAILBOX_ERR_VXWORKS_ALLOC_MEMORY 					0x80000146

#define    MAILBOX_ERR_MCU_CHANNEL_NOT_FIND 					0x80000160
#define    MAILBOX_ERR_MCU_ZOS_MSG_ALLOC_FAIL					0x80000161
#define    MAILBOX_ERR_MCU_ZOS_MSG_SEND_FAIL					0x80000162
#define    MAILBOX_ERR_MCU_ZOS_PID_NOT_FIND 					0x80000163
#define    MAILBOX_ERR_MCU_ZOS_CBFUNC_NULL						0x80000164

#define    MAILBOX_ERR_LINUX_TASK_CREATE						0x80000180
#define    MAILBOX_ERR_LINUX_CALLBACK_NOT_FIND					0x80000181
#define    MAILBOX_ERR_LINUX_CALLBACK_ERRO						0x80000182
#define    MAILBOX_ERR_LINUX_MAIL_TASK_NOT_FIND 				0x80000183
#define    MAILBOX_ERR_LINUX_MAIL_INT_NOT_FIND					0x80000184
#define    MAILBOX_ERR_LINUX_CHANNEL_NOT_FIND					0x80000185
#define    MAILBOX_ERR_LINUX_ALLOC_MEMORY						0x80000186

#define    MAILBOX_ERR_RET_END									0x800001ff /*??????????????*/

/*????????????*/
#define    MAILBOX_WARNING_RET_START							0x80000200
#define    MAILBOX_WARNING_USER_CALLBACK_ALREADY_EXIST			0x80000201
#define    MAILBOX_WARNING_TRANSPORT_TIME_OUT					0x80000202
#define    MAILBOX_WARNING_RECEIVE_TIME_OUT 					0x80000203
#define    MAILBOX_WARNING_SCHE_TIME_OUT						0x80000204
#define    MAILBOX_WARNING_RET_END								0x800002ff /*????????????*/

/*????????????*/
#define    MAILBOX_INFO_RET_START								0x80000300
#define    MAILBOX_INFO_RECEIVE_FIRST_MAIL						0x80000301
#define    MAILBOX_INFO_SEND_FIRST_MAIL 						0x80000302
#define    MAILBOX_INFO_RET_END 								0x800003ff /*????????????*/

/*??????????????????????*/
#define MAILBOX_BOARDST_USER_PROTECT1				(0x18273645)

#define MAILBOX_MCU_TEST_BUFF_SIZE					256

/*****************************************************************************
  3 ????????
*****************************************************************************/

/*****************************************************************************
  4 ??????????
*****************************************************************************/


/*****************************************************************************
 ?? ?? ??  : tm_mb_cb
 ????????  : ????????????????????????????
*****************************************************************************/
struct  mb_st_msg
{
    unsigned int protect;                       /*?????????? MAILBOX_BOARDST_USER_PROTECT1*/
    unsigned int length;                        /*??????????????*/
    unsigned int back_code;              /*????????????????????????*/
    unsigned int test_id;                        /*??????????????: TM_MAILBOX_TEST_ID_E????*/
};

/*****************************************************************************
  5 ????????
*****************************************************************************/

/*****************************************************************************
 ?? ?? ??  : MAILBOX_BOARDST_TEST_ID_E
 ????????  : ??????????????????????ID
*****************************************************************************/
enum MAILBOX_BOARDST_TEST_ID_E 
{
    MAILBOX_BOARDST_ID_LOOP_SEND,                /*??????????????*/
    MAILBOX_BOARDST_ID_LOOP_BACK,                /*????????????????????????*/
    MAILBOX_BOARDST_ID_LOOP_FINISH               /*????????????*/
};

/*****************************************************************************
  6 STRUCT????
*****************************************************************************/

/*****************************************************************************
 ?? ?? ??  : struct mb_log
 ????????  : ????????????????
*****************************************************************************/
struct mb_log
{
    unsigned int erro_num;
    unsigned long param1;
    unsigned long param2;
    unsigned int line;
    const char*   file;
};

/****************************************************************************
  ????????????use id ????????????
****************************************************************************/
typedef struct
{
    unsigned int               send_slice;         /*????????????*/
    unsigned int               recv_slice;         /*????????????*/
    unsigned long               mail_addr;         /*????????????*/
    unsigned short              use_id;
    unsigned short              reserved;
}MAILBOX_TRACK_STRU;

/*****************************************************************************
  ????????????????????????
*****************************************************************************/
struct mb_slice
{
    unsigned int               total;       /*????????????????,??????????????????????????????????????*/
    unsigned int               start;       /*????????????????????????*/
    unsigned int               max;         /*????????????????????????????????????????????????????????**/
    unsigned int               code;       /*??????????????????*/
    unsigned int               overflow;    /*??????????????????????*/
};

struct mb_mntn
{
    unsigned int               peak_traffic_left;       /*??????????????????????????????????????????*/

    struct mb_slice             trans;                   /*??????????????????????????????????????????????????????*/   
    struct mb_slice             deal;                    /*????????????????????????????????????????*/   
    struct mb_slice             sche;                    /*????????????????????????????????????????????????????*/   
  
    /*??????????????(????)????????*/
    unsigned int               track_prob;             /*????TrackArray????????????*/
    MAILBOX_TRACK_STRU          track_array[MAILBOX_RECORD_USEID_NUM];/*??????????????MAILBOX_LATEST_USEID_NUM??use id ????????*/
    struct mb_buff             *mbuff;                  
};

/*****************************************************************************
  7 UNION????
*****************************************************************************/

/*****************************************************************************
  8 OTHERS????
*****************************************************************************/

/*****************************************************************************
  9 ????????????
*****************************************************************************/

/*****************************************************************************
  10 ????????
*****************************************************************************/
extern MAILBOX_EXTERN int mailbox_log_erro(
                unsigned int   err_no,
                unsigned long   param1,
                unsigned long   param2,
                unsigned int   line_no,
                char*           file_name);

MAILBOX_EXTERN void mailbox_record_send(
                struct mb_mntn* mntn,                
                unsigned int mailcode, 
                unsigned int time_stamp,
                unsigned long mail_addr);


MAILBOX_EXTERN void mailbox_record_transport(
                struct mb_mntn* mntn, 
                unsigned int mailcode, 
                unsigned int write_slice,
                unsigned int read_slice,
                unsigned long mail_addr);


MAILBOX_EXTERN void mailbox_record_receive(
                struct mb_mntn* mntn,                
                unsigned int mailcode, 
                unsigned int slice_start);

MAILBOX_EXTERN int mailbox_show(
                unsigned int    channel,
                unsigned int    show_all);

MAILBOX_EXTERN void mailbox_record_sche_send(void *priv);

MAILBOX_EXTERN void mailbox_record_sche_recv(void *priv);

MAILBOX_EXTERN void mailbox_usb_suspend(bool is_suspend);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif	/*_DRV_MAILBOX_DEBUG_H_*/

