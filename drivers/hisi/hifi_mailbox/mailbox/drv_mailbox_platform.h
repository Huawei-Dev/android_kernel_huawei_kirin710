
#ifndef _DRV_MAILBOX_PLATFORM_H_
#define _DRV_MAILBOX_PLATFORM_H_

/*****************************************************************************
1 ??????????
*****************************************************************************/
#if defined(BSP_CORE_MODEM) /*C??????????????????*/
#include "drv_mailbox_port_vxworks.h"

#elif defined (BSP_CORE_APP) /*A??????????????????*/
#include "drv_mailbox_port_linux.h"

#elif defined (BSP_CORE_CM3)  /*M??????????????????*/
#include "drv_mailbox_port_mcu.h"

#endif
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ??????
*****************************************************************************/

#ifndef MAILBOX_TRUE
#define MAILBOX_TRUE								(1)
#endif

#ifndef MAILBOX_FALSE
#define MAILBOX_FALSE								(0)
#endif

#ifndef MAILBOX_NULL
#define MAILBOX_NULL								(void*)(0)
#endif

/*????????????????*/
#ifdef _DRV_LLT_
#define MAILBOX_LOCAL											/*????????????????(PC????)*/
#else
#ifndef MAILBOX_LOCAL
#define MAILBOX_LOCAL								static		/*????????????????(????)*/
#endif
#endif

#ifndef MAILBOX_EXTERN
#define MAILBOX_EXTERN											/*????????????????*/
#endif

#ifndef MAILBOX_GLOBAL
#define MAILBOX_GLOBAL											/*??????????????????????????*/
#endif

/*??????????????????????????*/
#define MIALBOX_DIRECTION_INVALID					(0) 			/*????????????????*/
#define MIALBOX_DIRECTION_SEND						(1) 			/*????????????????????????????*/
#define MIALBOX_DIRECTION_RECEIVE					(2) 			/*????????????????????????????*/

/*??????????*/
#define  MAILBOX_MAILCODE_INVALID					(unsigned long)(0xffffffff)

/*****************************************************************************
  3 ????????
*****************************************************************************/

/*****************************************************************************
 ?? ?? ??  : MAILBOX_DELAY_SCENE_E
 ????????  : ??????????????????????????????
*****************************************************************************/
enum MAILBOX_DELAY_SCENE_E
{
	MAILBOX_DELAY_SCENE_MSG_FULL ,			/*????msg??????????????????????????????*/
	MAILBOX_DELAY_SCENE_IFC_FULL			/*????ifc??????????????????????????????*/
};

/*****************************************************************************
  4 ??????????
*****************************************************************************/

/*****************************************************************************
  5 ????????
*****************************************************************************/

/*****************************************************************************
  6 STRUCT????
*****************************************************************************/

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
/*??????????????????????????*/
extern MAILBOX_EXTERN void  mailbox_assert(unsigned int ErroNo);

extern MAILBOX_EXTERN int mailbox_mutex_lock(void * const *mutexId);

extern MAILBOX_EXTERN void mailbox_mutex_unlock(void * const *mutexId);

extern MAILBOX_EXTERN int mailbox_int_context(void);

extern MAILBOX_EXTERN int mailbox_get_timestamp(void);

extern MAILBOX_EXTERN int mailbox_process_register(
                unsigned int channel_id, 
                 int (*cb)(unsigned int channel_id),
                 void *priv);

extern MAILBOX_EXTERN int mailbox_channel_register(
                unsigned int ChannelID, 
                unsigned int IntNum,
                unsigned int DstID,
                unsigned int Direct,
                void   **mutex);

extern MAILBOX_EXTERN void *mailbox_memcpy(void *dst, const void *src, unsigned int size);

extern MAILBOX_EXTERN void *mailbox_memset(void * m, int c, unsigned int size);

extern MAILBOX_EXTERN int mailbox_delivery(unsigned int channel_id);

extern MAILBOX_EXTERN int mailbox_init_platform(void);

extern MAILBOX_EXTERN int mailbox_scene_delay(
                unsigned int scene_id,
                int *try_times);

extern MAILBOX_EXTERN void *mailbox_init_completion(void);

extern MAILBOX_EXTERN int mailbox_wait_completion(void **mutexId, unsigned int timeout);

extern MAILBOX_EXTERN void mailbox_complete(void **wait_id);

extern MAILBOX_EXTERN void mailbox_del_completion(void * const *wait);
extern void mailbox_ifc_test_init(void);

#if defined (BSP_CORE_CM3)
extern void mailbox_dpm_device_get(void);
extern void mailbox_dpm_device_put(void);
#else
#define mailbox_dpm_device_get()
#define mailbox_dpm_device_put()
#endif
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif	/*_DRV_MAILBOX_PLATFORM_H_*/

