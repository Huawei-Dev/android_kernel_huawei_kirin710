#include "hisi_gpio.h"
#include <linux/device.h>
#include <linux/gpio.h>
#include <linux/version.h>
#include <linux/hisi/hisi_log.h>

#define HISI_LOG_TAG HISI_GPIO_TAG

/* Parse gpio base from DT */
int pl061_parse_gpio_base(struct device *dev)
{
	struct device_node *np = dev->of_node;
	int ret = -EINVAL;

	if (of_property_read_u32(np, "linux,gpio-base", (u32 *)&ret))
		return -ENOENT;
	if (ret >= 0)
		return ret;
	return -EINVAL;
}

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
int pl061_check_security_status(struct pl061 *chip)
#else
int pl061_check_security_status(struct pl061_gpio *chip)
#endif
{
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0))
	WARN(chip->sec_status, "%s controller is busy", dev_name(chip->gc.parent));
#else
	WARN(chip->sec_status, "%s controller is busy", dev_name(chip->gc.dev));
#endif
	return chip->sec_status;
}
