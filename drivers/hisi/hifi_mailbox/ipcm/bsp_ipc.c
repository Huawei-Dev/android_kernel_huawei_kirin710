
#include <linux/module.h>
#include <asm/io.h>
#include <asm/string.h>
#include <linux/semaphore.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/notifier.h>
#include <linux/delay.h>

#include <linux/slab.h>
#include <linux/hisi/hisi_mailbox.h>
#include <linux/hisi/hisi_rproc.h>


#include "bsp_drv_ipc.h"
#include "soc_acpu_baseaddr_interface.h"


//#define USE_HIFI_IPC
/*lint -e750*/
BSP_IPC_ENTRY   stIpcIntTable[INTSRC_NUM];
static IPC_DEV_S    g_stIpcDev = {0};
BSP_U32         g_CoreNum;

struct semaphore    g_semIpcTask[INTSRC_NUM];
IPC_DEBUG_E     g_stIpc_debug = {0};

/* base address of ipc registers */
void __iomem *ipc_base = NULL;
spinlock_t g_ipc_int_lock = __SPIN_LOCK_UNLOCKED("ipc");

#define USE_HISI_MAILBOX

/*************************************k3 ipc******************************************/
#define BIT_ENABLE(n)                           (1 << (n))
#define BYTE_REF(address) (* ((unsigned char volatile *) (address)))
#define HALFWORD_REF(address) (* ((unsigned short volatile *) (address)))
#define WORD_REF(address) (* ((unsigned int volatile *) (address)))
#define WORD_PTR(address) (* ((unsigned int volatile **) (address)))
#define BYTE(address)   volatile unsigned char __attribute__((section(".ARM.__at_"address)))
#define HALFWORD(address)   volatile unsigned short __attribute__((section(".ARM.__at_"address)))
#define WORD(address)   volatile unsigned int __attribute__((section(".ARM.__at_"address)))

#define K3_IPC_MODE_ACK                         (7)
#define K3_IPC_MODE_IDLE                        (4)
#define K3_IPC_MODE_AUTOACK                 (0)

/*************************************hifi????ipc******************************************/
#define K3_SYS_IPC_BASE_ADDR_S      (unsigned long)(SOC_ACPU_IPC_BASE_ADDR)
#define K3_SYS_IPC_BASE_ADDR_NS     (unsigned long)(SOC_ACPU_IPC_NS_BASE_ADDR)
#define K3_SYS_IPC_REG_SIZE     (0xA00)

#define K3_IPC_LOCK(base)                          WORD_REF(base + 0xA00)
#define K3_IPC_SOURCE(base, box)           WORD_REF(base + ((box) * 64))
#define K3_IPC_DEST(base, box)             WORD_REF(base + ((box) * 64) + 0x04)
#define K3_IPC_DCLR(base, box)             WORD_REF(base + ((box) * 64) + 0x08)
#define K3_IPC_DSTATUS(base, box)          WORD_REF(base + ((box) * 64) + 0x0c)
#define K3_IPC_MODE(base, box)          WORD_REF(base + ((box) * 64) + 0x10)
#define K3_IPC_IMASK(base, box)        WORD_REF(base + ((box) * 64) + 0x14)
#define K3_IPC_ICLR(base, box)             WORD_REF(base + ((box) * 64) + 0x18)
#define K3_IPC_SEND(base, box)                WORD_REF(base + ((box) * 64) + 0x1c)
#define K3_IPC_DATA(base, box, num)       WORD_REF(base + ((box) * 64) + 0x20 + ((num) *4))
#define K3_IPC_CPUIMST(base, core)         WORD_REF(base + 0x800 + ((core) * 8))
#define K3_IPC_CPUIRST(base, core)         WORD_REF(base + 0x804 + ((core) * 8))

#define K3_SYS_IPC_CORE_LIT                        (0)
#define K3_SYS_IPC_CORE_BIG                          (1)
#define K3_SYS_IPC_CORE_IOM3                      (2)
#define K3_SYS_IPC_CORE_LPM3                      (3)
#define K3_SYS_IPC_CORE_HIFI                        (4)

	/*************************************hifi????ipc******************************************/
#define K3_HIFI_IPC_BASE_ADDR      (unsigned long)(0xE804C000)
#define K3_HIFI_IPC_REG_SIZE        (0x1000)

#define K3_ASP_CFG_CTRLDIS(base)                       WORD_REF(base + 0x04)
#define K3_ASP_CFG_GATE_EN(base)                       WORD_REF(base + 0x0c)

enum {
    /*hifi??????ipc??????ap??lpm3??iom3????????????0????*/
    K3_HIFI_IPC_CORE_AP_LPM3_IOM3 = 0,
    K3_HIFI_IPC_CORE_MODEM_A9 = 1,
    K3_HIFI_IPC_CORE_MODEM_BBE = 2,
    K3_HIFI_IPC_CORE_HIFI = 3,
    K3_HIFI_IPC_CORE_IOM3 = 5,
    K3_HIFI_IPC_CORE_AP = 6,
    K3_HIFI_IPC_CORE_LPM3 = 8,
};

typedef enum {
    K3_SEC_SYS_IPC = 0,
    K3_UNSEC_SYS_IPC,
    K3_HIFI_IPC,
} K3_IPC;

typedef struct {
	/*????????ipc????audio ipc*/
	K3_IPC ipcMode;
	/*????????ipc????*/
	void __iomem *ipcBase;
	/*??????*/
	int mailBoxNum;
	/*??????*/
	int intNum;
	/*????????*/
	int sourceCore;
	/*??????????*/
	int destCore;
} K3_IPC_CONFIG;

enum {
    K3_IPC_CORE_IS_SEND = 0,
    K3_IPC_CORE_IS_RECEIVE,
    K3_IPC_CORE_IS_UNKNOEN,
};

/*??????????????????????????????????*/
static K3_IPC_CONFIG k3IpcConfig[K3_IPC_CORE_IS_UNKNOEN] = {
	/*????????send ipc??*/
	{
		K3_UNSEC_SYS_IPC,
		NULL,
		18,
		220,
		K3_SYS_IPC_CORE_LIT,
		K3_SYS_IPC_CORE_HIFI
	},

/*????????rec ipc??*/
	/*????????rec ipc??*/
	{
		K3_UNSEC_SYS_IPC,
		NULL,
		2,
		227,
		K3_SYS_IPC_CORE_HIFI,
		K3_SYS_IPC_CORE_BIG
	}
};


static int DRV_k3IpcIntHandler_ipc(struct notifier_block *nb, unsigned long len, void *msg);
struct hisi_mbox *hifi_tx_mbox;
struct notifier_block rx_nb;

#ifdef USE_HISI_MAILBOX
#define MAX_SEND_IPC_TRY    3


static int hisi_hifi_mbox_init(void)
{
	int ret = 0;
	rproc_id_t rproc_id;

	rx_nb.next = NULL;
	rx_nb.notifier_call = DRV_k3IpcIntHandler_ipc;
	rproc_id = HISI_RPROC_HIFI_MBX2;
    	/* register the rx notify callback */
	ret = RPROC_MONITOR_REGISTER(rproc_id, &rx_nb);
	if (ret)
		pr_info("%s:RPROC_MONITOR_REGISTER failed", __func__);

	return ret;
}

/*
static void hisi_hifi_mbox_exit(void)
{
    if (hifi_mbox)
        hisi_mbox_put(&hifi_mbox);
}
*/
#else
static irqreturn_t DRV_k3IpcIntHandler_ack(int irq, void *dev_id)
{
	BSP_S32 retval = IRQ_HANDLED;
	BSP_U32 u32IntStat = 0;

	int myRole = K3_IPC_CORE_IS_SEND;
	BSP_U32 mailBoxNum = k3IpcConfig[myRole].mailBoxNum;
	BSP_U32 source = k3IpcConfig[myRole].sourceCore;
	void __iomem *ipcBase = k3IpcConfig[myRole].ipcBase;

	/*????A15??????????*/
	u32IntStat = K3_IPC_CPUIMST(ipcBase, source);

	/*??????????????A15????hifi??????18??????*/
	if (u32IntStat & BIT_ENABLE(mailBoxNum)) {
		/*????????????????????????????????*/
		if (K3_IPC_MODE(ipcBase, mailBoxNum) & BIT_ENABLE(K3_IPC_MODE_ACK)) {
			printk("func:%s: Receive ack int\n", __func__);

			K3_IPC_SOURCE(ipcBase, mailBoxNum) = BIT_ENABLE(source);
		}
		/*??????*/
		K3_IPC_DCLR(ipcBase, mailBoxNum) = BIT_ENABLE(mailBoxNum);
	}

	return (irqreturn_t)IRQ_RETVAL(retval);
}

#endif

static void drv_ipc_int_deinit(void)
{
	int i = 0;

	for (i = 0; i < K3_IPC_CORE_IS_UNKNOEN; i++) {
		if (k3IpcConfig[i].ipcBase) {
			iounmap(k3IpcConfig[i].ipcBase);
			k3IpcConfig[i].ipcBase = NULL;
		}
	}
}

/*****************************************************************************
* ?? ?? ??  : DRV_IPCIntInit
*
* ????????  : IPC??????????
*
* ????????  : ??
* ????????  : ??
*
* ?? ?? ??  : ??
*
* ????????  : 2009??3??5??   wangjing  creat
*****************************************************************************/
BSP_S32 DRV_IPCIntInit(void)
{

	int myRole = 0;

	printk(KERN_ERR "DRV_IPCIntInit begin.\n");

	if (BSP_TRUE == g_stIpcDev.bInit) {
		return BSP_OK;
	}

	printk(KERN_ERR "DRV_IPCIntInit line = %d\n", __LINE__);

	g_CoreNum = IPC_CORE_ACPU;

	memset((void*)stIpcIntTable, 0x0, (INTSRC_NUM * sizeof(BSP_IPC_ENTRY) ));

	/************************************??????****************************************/
	myRole = K3_IPC_CORE_IS_SEND;
	if (K3_UNSEC_SYS_IPC == k3IpcConfig[myRole].ipcMode) {
		k3IpcConfig[myRole].ipcBase = ioremap(K3_SYS_IPC_BASE_ADDR_NS, K3_SYS_IPC_REG_SIZE);
		if (!k3IpcConfig[myRole].ipcBase) {
			printk(KERN_ERR "line %d :k3 unsec sys ipc ioremap error.\n", __LINE__);
			return -1;
		}
	} else if (K3_SEC_SYS_IPC == k3IpcConfig[myRole].ipcMode) {
		k3IpcConfig[myRole].ipcBase = ioremap(K3_SYS_IPC_BASE_ADDR_S, K3_SYS_IPC_REG_SIZE);
		if (!k3IpcConfig[myRole].ipcBase) {
			printk(KERN_ERR "line %d :k3 sec sys ipc ioremap error.\n", __LINE__);
			return -1;
		}
	} else {
		k3IpcConfig[myRole].ipcBase = ioremap(K3_HIFI_IPC_BASE_ADDR, K3_HIFI_IPC_REG_SIZE);
		if (!k3IpcConfig[myRole].ipcBase) {
			printk(KERN_ERR "line %d :k3 hifi ipc ioremap error.\n", __LINE__);
			return -1;
		}
	}

	/*??????????*/
	K3_IPC_LOCK(k3IpcConfig[myRole].ipcBase) = 0x1ACCE551;
	/************************************end****************************************/

	/************************************??????****************************************/
	myRole = K3_IPC_CORE_IS_RECEIVE;
	if (K3_UNSEC_SYS_IPC == k3IpcConfig[myRole].ipcMode) {
		k3IpcConfig[myRole].ipcBase = ioremap(K3_SYS_IPC_BASE_ADDR_NS, K3_SYS_IPC_REG_SIZE);
		if (!k3IpcConfig[myRole].ipcBase) {
			printk(KERN_ERR "line %d :k3 unsec sys ipc ioremap error.\n", __LINE__);
			goto err1;
		}
	} else if(K3_SEC_SYS_IPC == k3IpcConfig[myRole].ipcMode) {
		k3IpcConfig[myRole].ipcBase = ioremap(K3_SYS_IPC_BASE_ADDR_S, K3_SYS_IPC_REG_SIZE);
		if (!k3IpcConfig[myRole].ipcBase) {
			printk(KERN_ERR "line %d :k3 sec sys ipc ioremap error.\n", __LINE__);
			goto err1;
		}
	} else {
		k3IpcConfig[myRole].ipcBase = ioremap(K3_HIFI_IPC_BASE_ADDR, K3_HIFI_IPC_REG_SIZE);
		if (!k3IpcConfig[myRole].ipcBase) {
			printk(KERN_ERR "line %d :k3 hifi ipc ioremap error.\n", __LINE__);
			goto err1;
		}
	}
	/*??????????*/
	K3_IPC_LOCK(k3IpcConfig[myRole].ipcBase) = 0x1ACCE551;
	/************************************end****************************************/
#ifdef USE_HISI_MAILBOX
	hisi_hifi_mbox_init();
#else
	ret = request_irq(k3IpcConfig[K3_IPC_CORE_IS_SEND].intNum,
	                  DRV_k3IpcIntHandler_ack, 0, "k3IpcIntHandler_ack", NULL);
	if (ret) {
		printk(KERN_ERR "BSP_DRV_IPCIntInit: Unable to register ipc irq ret=%d.\n", ret);
		goto err2;
	}
	printk(KERN_ERR "BSP_DRV_IPCIntInit line = %d\n", __LINE__);
#endif

	/*??????????????????????????*/
	g_stIpcDev.bInit = BSP_TRUE;

	printk(KERN_ERR "BSP_DRV_IPCIntInit end.\n");

	return BSP_OK;

#ifndef USE_HISI_MAILBOX
err2:
#endif

err1:
	drv_ipc_int_deinit();

	return BSP_ERROR;
}

/*****************************************************************************
* ?? ?? ??  : IPC_IntEnable
*
* ????????  : ????????????
*
* ????????  :   IPC_INT_CORE_E enCoreNum ????????????core
                BSP_U32 ulLvl ????????????????????????0??31
* ????????  : ??
*
* ?? ?? ??  : OK&ERROR
*
* ????????  : 2011??4??11?? wangjing creat
*****************************************************************************/
BSP_S32 IPC_IntEnable (IPC_INT_LEV_E ulLvl)
{
	/*????????*/
	IPC_CHECK_PARA(ulLvl);

	return BSP_OK;
}


/*****************************************************************************
 * ?? ?? ??  : BSP_INT_Disable
 *
 * ????????  : ??????????????
 *
 * ????????  : IPC_INT_CORE_E enCoreNum ????????????core
                BSP_U32 ulLvl ????????????????????????0??31
 * ????????  : ??
 *
 * ?? ?? ??  : OK&ERROR
 *
 * ????????  : 2011??4??11?? wangjing creat
 *****************************************************************************/
BSP_S32 IPC_IntDisable (IPC_INT_LEV_E ulLvl)
{
	/*????????*/
	IPC_CHECK_PARA(ulLvl);

	return BSP_OK;
}

/*****************************************************************************
 * ?? ?? ??  : IPC_IntConnect
 *
 * ????????  : ????????????
 *
 * ????????  : IPC_INT_CORE_E enCoreNum ????????????core
               BSP_U32 ulLvl ????????????????????????0??31
               VOIDFUNCPTR routine ????????????
 *             BSP_U32 parameter      ????????????????
 * ????????  : ??
 *
 * ?? ?? ??  : OK&ERROR
 *
 * ????????  : 2011??4??11?? wangjing creat
 *****************************************************************************/
BSP_S32 IPC_IntConnect  (IPC_INT_LEV_E ulLvl, VOIDFUNCPTR routine, BSP_U32 parameter)
{

	unsigned long flag = 0;

	/*????????*/
	IPC_CHECK_PARA(ulLvl);

	spin_lock_irqsave(&g_ipc_int_lock, flag);
	stIpcIntTable[ulLvl].routine = routine;
	stIpcIntTable[ulLvl].arg = parameter;
	spin_unlock_irqrestore(&g_ipc_int_lock, flag);

	return BSP_OK;
}

/*****************************************************************************
 * ?? ?? ??  : IPC_IntDisonnect
 *
 * ????????  : ????????????????
 *
 * ????????  :
 *              BSP_U32 ulLvl ????????????????????????0??31
 *              VOIDFUNCPTR routine ????????????
 *             BSP_U32 parameter      ????????????????
 * ????????  : ??
 *
 * ?? ?? ??  : OK&ERROR
 *
 * ????????  : 2011??4??11?? wangjing creat
 *****************************************************************************/
 BSP_S32 IPC_IntDisonnect  (IPC_INT_LEV_E ulLvl,VOIDFUNCPTR routine, BSP_U32 parameter)
 {
	unsigned long flag = 0;

	/*????????*/
	IPC_CHECK_PARA(ulLvl);

	spin_lock_irqsave(&g_ipc_int_lock, flag);
	stIpcIntTable[ulLvl].routine = NULL;
	stIpcIntTable[ulLvl].arg = 0;
	spin_unlock_irqrestore(&g_ipc_int_lock, flag);

	return BSP_OK;
}

/*****************************************************************************
* ?? ?? ??  : BSP_DRV_k3IpcIntHandler_S
*
* ????????  : k3??IPC??????????????????????
*
* ????????  : ??
* ????????  : ??
*
* ?? ?? ??  : ??
*
* ????????  : 2011??4??11?? wangjing creat
*****************************************************************************/
static int DRV_k3IpcIntHandler_ipc(struct notifier_block *nb, unsigned long len, void *msg)
{
	BSP_U32 newLevel = 0;
	mbox_msg_t *_msg = (mbox_msg_t *)msg;

	newLevel = _msg[0];

	/*??????????????????????*/
	if (newLevel < INTSRC_NUM) {
		g_stIpc_debug.u32IntHandleTimes[newLevel]++;

		if (NULL != stIpcIntTable[newLevel].routine) {
			stIpcIntTable[newLevel].routine(stIpcIntTable[newLevel].arg);
		}
	}

	return 0;
}

/*****************************************************************************
* ?? ?? ??  : IPC_IntSend
*
* ????????  : ????????
*
* ????????  :
                IPC_INT_CORE_E enDstore ????????????core
                BSP_U32 ulLvl ????????????????????????0??31
* ????????  : ??
*
* ?? ?? ??  : OK&ERROR
*
* ????????  : 2011??4??11?? wangjing creat
*****************************************************************************/
BSP_S32 IPC_IntSend(IPC_INT_CORE_E enDstCore, IPC_INT_LEV_E ulLvl)
{
	int myRole = K3_IPC_CORE_IS_SEND;
	BSP_U32 source = k3IpcConfig[myRole].sourceCore;

#ifdef USE_HISI_MAILBOX
	BSP_U32 ipcMsg[2];
	int ret = 0;
	rproc_id_t rproc_id;
#else
	BSP_U32 mailBoxNum = k3IpcConfig[myRole].mailBoxNum;
	BSP_U32 dest = k3IpcConfig[myRole].destCore;
	void __iomem *ipcBase = k3IpcConfig[myRole].ipcBase;
#endif

	/*????????*/
	IPC_CHECK_PARA(ulLvl);

	/*????????hifi??????????k3??????sys ipc??ulLvl??????????????????*/
	if (IPC_CORE_HiFi == enDstCore) {
#ifdef USE_HISI_MAILBOX
		ipcMsg[0] = (source << 24) | (ulLvl << 8);

	rproc_id = HISI_RPROC_HIFI_MBX18;
		ret = RPROC_ASYNC_SEND(rproc_id, (mbox_msg_t *)ipcMsg, 2);
		if(ret)
		  {
		        printk(" %s , line %d, send error\n", __func__, __LINE__);
		  }
#else
		/*????????????????*/
		while(0 == (K3_IPC_MODE(ipcBase, mailBoxNum) & BIT_ENABLE(K3_IPC_MODE_IDLE))) {
			printk("func:%s: mailbox is busy mode = 0x%x\n", __func__, K3_IPC_MODE(ipcBase, mailBoxNum));
		}

		K3_IPC_SOURCE(ipcBase, mailBoxNum) = BIT_ENABLE(source);
		K3_IPC_DEST(ipcBase, mailBoxNum) = BIT_ENABLE(dest);

		/*??????????????hifi??????????*/

		/*????????*/
		K3_IPC_IMASK(ipcBase, mailBoxNum) = ~(BIT_ENABLE(source)|BIT_ENABLE(dest));

		/*????????*/
		K3_IPC_MODE(ipcBase, mailBoxNum) = BIT_ENABLE(K3_IPC_MODE_AUTOACK);

		/*??????????????*/
		K3_IPC_DATA(ipcBase, mailBoxNum, 0) = source;
		K3_IPC_DATA(ipcBase, mailBoxNum, 1) = ulLvl;

		/*??????????????*/
		K3_IPC_SEND(ipcBase, mailBoxNum) = BIT_ENABLE(source);

#endif
	} else {
		/*????????????????,????????*/
		BSP_RegWr(BSP_IPC_CPU_RAW_INT(enDstCore), 1 << ulLvl);
	}

	g_stIpc_debug.u32RecvIntCore = enDstCore;
	g_stIpc_debug.u32IntSendTimes[ulLvl]++;

	return BSP_OK;
}


/*****************************************************************************
* ?? ?? ??  : BSP_IPC_SpinLock
*
* ????????  : ??????????????????
*
* ????????  : ??
* ????????  : ??
*
* ?? ?? ??  : ??
*
* ????????  : 2011??4??11?? wangjing creat
*****************************************************************************/
void BSP_IPC_SpinLock (unsigned int u32SignalNum)
{
	unsigned int u32HsCtrl;

	if(u32SignalNum >= INTSRC_NUM)
	{
		printk("BSP_IPC_SpinLock  Parameter error, line:%d\n", __LINE__);
		return;
	}
	for(;;)
	{
		u32HsCtrl = BSP_RegRd(BSP_IPC_HS_CTRL(g_CoreNum, u32SignalNum));
		if (0 == u32HsCtrl)
		{
			break;
		}
	}
}

/*****************************************************************************
* ?? ?? ??  : BSP_IPC_SpinUnLock
*
* ????????  : ??????????
*
* ????????  : ??
* ????????  : ??
*
* ?? ?? ??  : ??
*
* ????????  : 2011??4??11?? wangjing creat
*****************************************************************************/
void BSP_IPC_SpinUnLock (unsigned int u32SignalNum)
{
	if(u32SignalNum >= INTSRC_NUM)
	{
		printk("BSP_IPC_SpinUnLock  Parameter error, line:%d\n", __LINE__);
		return;
	}
	/*????????????????????0*/
	BSP_RegWr(BSP_IPC_HS_CTRL(g_CoreNum, u32SignalNum), 0);
}

EXPORT_SYMBOL(IPC_IntEnable);
EXPORT_SYMBOL(IPC_IntDisable);
EXPORT_SYMBOL(IPC_IntConnect);
EXPORT_SYMBOL(IPC_IntSend);


