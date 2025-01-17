

#ifndef __OAM_LINUX_NETLINK_H__
#define __OAM_LINUX_NETLINK_H__

/* ?????????????? */
#include "oal_ext_if.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_OAM_LINUX_NETLINK_H

/* ?????? */
#if (_PRE_CONFIG_TARGET_PRODUCT == _PRE_TARGET_PRODUCT_TYPE_WS835DMB)
#define OAM_NETLINK_ID 29  // 1151honor835 ??????29??????????????????ko????????????????????????netlink????????
#elif (_PRE_CONFIG_TARGET_PRODUCT == _PRE_TARGET_PRODUCT_TYPE_E5) || \
      (_PRE_CONFIG_TARGET_PRODUCT == _PRE_TARGET_PRODUCT_TYPE_CPE)
#define OAM_NETLINK_ID 26  // E5 ??????26
#elif (_PRE_CONFIG_TARGET_PRODUCT == _PRE_TARGET_PRODUCT_TYPE_5630HERA)
#define OAM_NETLINK_ID 26  // HERA ??????26
#else
#define OAM_NETLINK_ID 25
#endif

/* STRUCT???? */
typedef struct {
    oal_sock_stru *pst_nlsk;
    oal_uint32 ul_pid;
} oam_netlink_stru;

typedef struct {
    oal_uint32 (*p_oam_sdt_func)(oal_uint8 *puc_data, oal_uint32 ul_len);
    oal_uint32 (*p_oam_hut_func)(oal_uint8 *puc_data, oal_uint32 ul_len);
    oal_uint32 (*p_oam_alg_func)(oal_uint8 *puc_data, oal_uint32 ul_len);
    oal_uint32 (*p_oam_daq_func)(oal_uint8 *puc_data, oal_uint32 ul_len);
    oal_uint32 (*p_oam_reg_func)(oal_uint8 *puc_data, oal_uint32 ul_len);
    oal_uint32 (*p_oam_acs_func)(oal_uint8 *puc_data, oal_uint32 ul_len);
    oal_uint32 (*p_oam_psta_func)(oal_uint8 *puc_data, oal_uint32 ul_len);
} oam_netlink_proto_ops;

/* ???????????? */
extern oam_netlink_stru g_netlink;
extern oam_netlink_proto_ops g_netlink_ops;

/* ???????? */
extern oal_uint32 oam_netlink_kernel_create(oal_void);
extern oal_void oam_netlink_kernel_release(oal_void);

#endif /* end of oam_linux_netlink.h */
