
#ifndef __MAC_RESOURCE_H__
#define __MAC_RESOURCE_H__

/*****************************************************************************
  1 ??????????????
*****************************************************************************/
#include "oal_ext_if.h"
#include "oal_queue.h"
#include "mac_device.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_MAC_RESOURCE_H

/*****************************************************************************
  2 ??????
*****************************************************************************/
/* mac_vap_stru, hmac_vap_stru????????, dmac_vap_stru?????????????? */
#ifdef _PRE_WLAN_FEATURE_CUSTOM_SECURITY
#define MAC_RES_VAP_SIZE 4232  // (2600 + 1232)     /* lm: hmac vap?????????????????????????????????????????????????????????? */
#else
#define MAC_RES_VAP_SIZE 2532
#endif

/* mac_user_stru, hmac_user_stru????????, dmac_user_stru?????????????????????????????? */
#define FEATURE_TX_CLASSIFY_LAN_TO_WLAN_RES_SIZE 1700 /* ????????????????????hmac_user_stru????????????????????????????????????1700 */

#define MAC_RES_USER_SIZE (3724 + FEATURE_TX_CLASSIFY_LAN_TO_WLAN_RES_SIZE + 240) /* ??????3560,????????????????????3640,????60????????51????????dmac?????????????????? */

/* ????dev???? */
#define MAC_RES_MAX_DEV_NUM (WLAN_CHIP_MAX_NUM_PER_BOARD * WLAN_DEVICE_MAX_NUM_PER_CHIP)

/* ????????????(????????+????????) */
/*
1102????????:P2P_dev/CL??STA??????????P2P_GO??AP??????????????????(????+????????)????9??
    1)AP ????:  1?????????? + 8??????????
    2)STA+P2P CL ????????:  2?????????? + 2??????????
    3)STA+P2P GO ????????:  3?????????? + 5??????????
    4)STA+Proxy STA????????:  1102????proxy sta????
 */
#define MAC_RES_MAX_USER_NUM (WLAN_USER_MAX_USER_LIMIT)
extern oal_uint16 g_us_max_asoc_user;

typedef struct {
    mac_device_stru ast_dev_info[MAC_RES_MAX_DEV_NUM];
    oal_queue_stru st_queue;
    oal_uint aul_idx[MAC_RES_MAX_DEV_NUM];
    oal_uint8 auc_user_cnt[MAC_RES_MAX_DEV_NUM];
    oal_uint8 auc_resv[2];
} mac_res_device_stru;

typedef struct {
    oal_void *past_vap_info[WLAN_VAP_SUPPORT_MAX_NUM_LIMIT];
    oal_queue_stru st_queue;
    oal_uint aul_idx[WLAN_VAP_SUPPORT_MAX_NUM_LIMIT];
    oal_uint16 us_hmac_priv_size;
    oal_uint8 auc_user_cnt[WLAN_VAP_SUPPORT_MAX_NUM_LIMIT];
    oal_uint8 auc_resv[2];
} mac_res_vap_stru;

typedef struct {
    oal_void *past_user_info[MAC_RES_MAX_USER_NUM];
    oal_queue_stru st_queue;
    oal_uint *pul_idx;
    oal_uint16 us_hmac_priv_size;
    oal_uint8 auc_resv[2];
    oal_uint8 *puc_user_cnt;
} mac_res_user_stru;

typedef struct {
    mac_res_device_stru st_dev_res;
    mac_res_vap_stru st_vap_res;
    mac_res_user_stru st_user_res;
} mac_res_stru;
extern mac_res_stru g_st_mac_res;

/*****************************************************************************
  10 ????????
*****************************************************************************/
extern oal_uint32 mac_res_alloc_dmac_dev(oal_uint8 *puc_dev_idx);
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
extern oal_uint32 mac_res_alloc_hmac_dev(oal_uint8 *puc_dev_idx);
#else
extern oal_uint32 mac_res_alloc_hmac_dev(oal_uint32 ul_dev_idx);
#endif
extern oal_uint32 mac_res_free_dev(oal_uint32 ul_dev_idx);
extern oal_uint32 mac_res_free_mac_user(oal_uint16 us_idx);
extern oal_uint32 mac_res_free_mac_vap(oal_uint32 ul_idx);


OAL_STATIC OAL_INLINE oal_uint32 mac_res_alloc_hmac_vap(oal_uint8 *puc_idx, oal_uint16 us_hmac_priv_size)
{
    oal_uint ul_idx_temp;

    if (oal_unlikely(puc_idx == OAL_PTR_NULL)) {
        return OAL_FAIL;
    }

    ul_idx_temp = (oal_uint)(uintptr_t)oal_queue_dequeue(&(g_st_mac_res.st_vap_res.st_queue));
    /* 0???????? */
    if (ul_idx_temp == 0) {
        return OAL_FAIL;
    }

    *puc_idx = (oal_uint8)(ul_idx_temp - 1);

    g_st_mac_res.st_vap_res.us_hmac_priv_size = us_hmac_priv_size;

    (g_st_mac_res.st_vap_res.auc_user_cnt[ul_idx_temp - 1])++;

    return OAL_SUCC;
}


OAL_STATIC OAL_INLINE oal_uint32 mac_res_alloc_dmac_vap(oal_uint8 uc_idx)
{
    if (oal_unlikely(uc_idx >= WLAN_VAP_SUPPORT_MAX_NUM_LIMIT)) {
        return OAL_FAIL;
    }

    (g_st_mac_res.st_vap_res.auc_user_cnt[uc_idx])++;

    return OAL_SUCC;
}


OAL_STATIC OAL_INLINE oal_uint32 mac_res_alloc_dmac_user(oal_uint16 us_idx)
{
    if (oal_unlikely((us_idx) >= MAC_RES_MAX_USER_NUM)) {
        return OAL_FAIL;
    }

    /* DMAC???????????????????? */
    (g_st_mac_res.st_user_res.puc_user_cnt[us_idx])++;

    return OAL_SUCC;
}


OAL_STATIC OAL_INLINE mac_device_stru *mac_res_get_dev(oal_uint32 ul_dev_idx)
{
    if (oal_unlikely(ul_dev_idx >= MAC_RES_MAX_DEV_NUM)) {
        return OAL_PTR_NULL;
    }

    return &(g_st_mac_res.st_dev_res.ast_dev_info[ul_dev_idx]);
}


OAL_STATIC OAL_INLINE oal_void *mac_res_get_hmac_vap(oal_uint32 ul_idx)
{
    if (oal_unlikely(ul_idx >= WLAN_VAP_SUPPORT_MAX_NUM_LIMIT)) {
        return OAL_PTR_NULL;
    }

    return (oal_void *)(g_st_mac_res.st_vap_res.past_vap_info[ul_idx]);
}


OAL_STATIC OAL_INLINE oal_void *mac_res_get_mac_vap(oal_uint8 uc_idx)
{
    if (oal_unlikely(uc_idx >= WLAN_VAP_SUPPORT_MAX_NUM_LIMIT)) {
        return OAL_PTR_NULL;
    }

    /* ???????????????????? */
    return (oal_void *)((oal_uint8 *)(g_st_mac_res.st_vap_res.past_vap_info[uc_idx])
                        + g_st_mac_res.st_vap_res.us_hmac_priv_size);
}


OAL_STATIC OAL_INLINE oal_void *mac_res_get_dmac_vap(oal_uint8 uc_idx)
{
    return mac_res_get_mac_vap(uc_idx);
}


OAL_STATIC OAL_INLINE oal_uint32 mac_res_alloc_hmac_user(oal_uint16 *pus_idx, oal_uint16 us_hmac_priv_size)
{
    oal_uint ul_idx_temp;

    if (oal_unlikely(pus_idx == OAL_PTR_NULL)) {
        return OAL_FAIL;
    }

    ul_idx_temp = (oal_uint)(uintptr_t)oal_queue_dequeue(&(g_st_mac_res.st_user_res.st_queue));
    /* 0???????? */
    if (ul_idx_temp == 0) {
        return OAL_FAIL;
    }

    *pus_idx = (oal_uint16)(ul_idx_temp - 1);

    g_st_mac_res.st_user_res.us_hmac_priv_size = us_hmac_priv_size;

    (g_st_mac_res.st_user_res.puc_user_cnt[ul_idx_temp - 1])++;

    return OAL_SUCC;
}


OAL_STATIC OAL_INLINE oal_void *_mac_res_get_hmac_user(oal_uint16 us_idx)
{
    if (oal_unlikely(us_idx >= MAC_RES_MAX_USER_NUM)) {
        return OAL_PTR_NULL;
    }

    return (oal_void *)(g_st_mac_res.st_user_res.past_user_info[us_idx]);
}


OAL_STATIC OAL_INLINE oal_void *_mac_res_get_mac_user(oal_uint16 us_idx)
{
    if (oal_unlikely(us_idx >= MAC_RES_MAX_USER_NUM)) {
        return OAL_PTR_NULL;
    }

    /* ???????????????? */
    return (oal_void *)((oal_uint8 *)(g_st_mac_res.st_user_res.past_user_info[us_idx])
                        + g_st_mac_res.st_user_res.us_hmac_priv_size);
}


OAL_STATIC OAL_INLINE oal_uint16 mac_res_get_max_user_id(void)
{
    return (oal_uint16)(g_us_max_asoc_user * MAC_RES_MAX_DEV_NUM + WLAN_SERVICE_VAP_MAX_NUM_PER_DEVICE *
            MAC_RES_MAX_DEV_NUM);
}

extern oal_uint32 mac_res_init(oal_void);
extern oal_uint32 mac_res_exit(void);
extern oal_uint16 mac_res_get_max_asoc_user(oal_void);
extern oal_uint32 mac_res_set_max_asoc_user(oal_uint16 us_num);
extern wlan_mib_ieee802dot11_stru *mac_res_get_mib_info(oal_uint8 uc_vap_id);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of mac_resource.h */
