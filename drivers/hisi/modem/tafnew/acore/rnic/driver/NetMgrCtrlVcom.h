/*
* Copyright (C) Huawei Technologies Co., Ltd. 2012-2015. All rights reserved.
* foss@huawei.com
*
* If distributed as part of the Linux kernel, the following license terms
* apply:
*
* * This program is free software; you can redistribute it and/or modify
* * it under the terms of the GNU General Public License version 2 and
* * only version 2 as published by the Free Software Foundation.
* *
* * This program is distributed in the hope that it will be useful,
* * but WITHOUT ANY WARRANTY; without even the implied warranty of
* * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* * GNU General Public License for more details.
* *
* * You should have received a copy of the GNU General Public License
* * along with this program; if not, write to the Free Software
* * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
*
* Otherwise, the following license terms apply:
*
* * Redistribution and use in source and binary forms, with or without
* * modification, are permitted provided that the following conditions
* * are met:
* * 1) Redistributions of source code must retain the above copyright
* *    notice, this list of conditions and the following disclaimer.
* * 2) Redistributions in binary form must reproduce the above copyright
* *    notice, this list of conditions and the following disclaimer in the
* *    documentation and/or other materials provided with the distribution.
* * 3) Neither the name of Huawei nor the names of its contributors may
* *    be used to endorse or promote products derived from this software
* *    without specific prior written permission.
*
* * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
*/

#ifndef _NET_MGR_CTRL_VCOM_H_
#define _NET_MGR_CTRL_VCOM_H_

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "v_typdef.h"
#include "PsTypeDef.h"
#include "product_config.h"
#include "TafTypeDef.h"
#include "NetMgrPrivate.h"

#if (VOS_OS_VER == VOS_LINUX)
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#else
#include "Linuxstub.h"
#endif


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifdef WIN32
#pragma warning(disable:4200) /* zero-sized array in struct/union */
#endif

#pragma pack(4)

/*****************************************************************************
  2 ??????
*****************************************************************************/

#define NM_CTRL_DEVICE_NAME             "nmctrlvcom"

#define NM_PROC_FILE_BIND_PID			"bind_pid"
#define NM_BIND_PID_LEN                 (16)
#define NM_ISDIGIT(c)                   (((c) >= '0') && ((c) <= '9'))

#define NM_CTRL_GET_MAJOR_NUM()         (g_stNmCtrlCtx.ulMajorNum)
#define NM_CTRL_SET_MAJOR_NUM(major)    (g_stNmCtrlCtx.ulMajorNum = (major))

#define NM_CTRL_GET_DATA_FLG()          (g_stNmCtrlCtx.ulDataFlg)
#define NM_CTRL_SET_DATA_FLG(flg)       (g_stNmCtrlCtx.ulDataFlg = (flg))


typedef struct list_head                LIST_HEAD_STRU;


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
typedef struct
 {
    LIST_HEAD_STRU                      stMsgList;
    unsigned int                        ulLen;
    unsigned int                        ulReserv;
    unsigned char                       aucData[0];
}NM_CTRL_CDEV_DATA_STRU;

typedef struct
{
    struct cdev                        *pstNmCtrlDev;            /* cdev?????????????????????? */
    wait_queue_head_t                   stReadInq;
    struct mutex                        stListLock;             /* ????????????????????????????,?????????????????? */
    LIST_HEAD_STRU                      stListHead;
    LIST_HEAD_STRU                      stLowPriListHead;
    unsigned int                        ulMajorNum;
    unsigned int                        ulDataFlg;
}NM_CTRL_CTX_STRU;

/*****************************************************************************
  8 UNION????
*****************************************************************************/


/*****************************************************************************
  9 OTHERS????
*****************************************************************************/


/*****************************************************************************
  10 ????????
*****************************************************************************/

extern int __init NM_CTRL_Init(VOS_VOID);
extern int NM_CTRL_Open(struct inode *node, struct file *filp);
extern unsigned int NM_CTRL_Poll(struct file* filp, poll_table *wait);
extern ssize_t NM_CTRL_Read(struct file *filp, char __user *buf, size_t size, loff_t *ppos);
extern int NM_CTRL_Release(struct inode *node, struct file *filp);
extern void NM_CTRL_SendMsg(void* pDataBuffer, unsigned int len);
extern void NM_CTRL_Setup(struct cdev * dev);



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

#endif /* _NET_MGR_CTRL_VCOM_H_ */