#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/udp.h>
#include <net/sock.h>
#include "../emcom_netlink.h"
#include "../emcom_utils.h"
#include <huawei_platform/emcom/smartcare/smartcare.h>

void smartcare_event_process(int32_t event, uint8_t *pdata, uint16_t len)
{
	switch (event)
	{
		default:
			EMCOM_LOGE(" : smartcare received unsupported message");
			break;
	}
}

void smartcare_init(void)
{
	return;
}


void smartcare_deinit(void)
{
	return;
}

EXPORT_SYMBOL(smartcare_event_process);
EXPORT_SYMBOL(smartcare_init);
EXPORT_SYMBOL(smartcare_deinit);
