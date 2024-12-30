#ifndef _HIFI_USB_DEBUGFS_H
#define _HIFI_USB_DEBUGFS_H

#include "hifi-usb.h"

static inline int hifi_usb_debugfs_init(struct hifi_usb_proxy *hifi_usb)
{
	return 0;
}
static inline void hifi_usb_debugfs_exit(struct hifi_usb_proxy *hifi_usb)
{
}
static inline void hifi_usb_handle_test_mesg(struct hifi_usb_proxy *hifi_usb,
		struct hifi_usb_test_msg *mesg){}

#endif /* _HIFI_USB_DEBUGFS_H */
