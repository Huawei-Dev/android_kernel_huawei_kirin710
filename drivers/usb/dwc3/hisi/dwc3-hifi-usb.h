#ifndef _DWC3_HIFI_USB_H_
#define _DWC3_HIFI_USB_H_

static inline int ap_start_use_hifiusb(void) {return -ENODEV;}
static inline void ap_stop_use_hifiusb(void) {}
static inline void ap_use_hifi_usb_msg_receiver(void *msg_buf) {}

#endif /* _DWC3_HIFI_USB_H_ */

