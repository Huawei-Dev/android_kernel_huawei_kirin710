

/* ?????????? */
#define HISI_NVRAM_SUPPORT

#include "plat_cali.h"
#include "plat_firmware.h"
#include "plat_debug.h"
#include "securec.h"
#include "hisi_ini.h"

/* ?????? */
#define RF_CALI_DATA_BUF_LEN (sizeof(oal_cali_param_stru))

/* ???????????? */
/* ??????????????buf */
OAL_STATIC oal_uint8 *g_cali_data_buf = NULL;
oal_uint8 g_uc_netdev_is_open = OAL_FALSE;
/* ????????????????dfr?????????? */
oal_uint32 g_cali_excp_dfr_count   = 0;

/* add for hi1102a bfgx */
OAL_STATIC oal_uint8 *g_bfgx_cali_data_buf_hi1102a = NULL;

/* ????????????BFGX_BT_CUST_INI_SIZE/4 (128) */
OAL_STATIC bfgx_ini_cmd g_bfgx_ini_config_cmd_hi1102a[BFGX_BT_CUST_INI_SIZE / 4] = {
    { "bt_maxpower",                   0x0505 },
    { "bt_edrpow_offset",              0 },
    { "bt_blepow_offset",              0 },
    { "bt_fem_control",                0 },
    { "bt_cali_swtich_all",            0 },
    { "bt_ant_num_bt",                 0 },
    { "bt_frame_end_detection_switch", 0 },
    { "bt_reserved1",                  0 },
    { "bt_reserved2",                  0 },
    { "bt_reserved3",                  0 },
    { "bt_reserved4",                  0 },
    { "bt_reserved5",                  0 },
    { "bt_reserved6",                  0 },
    { "bt_reserved7",                  0 },
    { "bt_reserved8",                  0 },
    { "bt_reserved9",                  0 },
    { "bt_reserved10",                 0 },

    { NULL, 0 }
};

/* ????????????BFGX_BT_CUST_INI_SIZE/4 (128) */
OAL_STATIC int32 g_bfgx_cust_ini_data_hi1102a[BFGX_BT_CUST_INI_SIZE / 4] = {0};

/*
 * ?? ?? ??  : get_cali_count
 * ????????  : ????????????????????????????????0??????????
 * ????????  : uint32 *count:??????????????????????????
 * ????????  : count:??????????????????????????
 * ?? ?? ??  : 0??????????-1????????
 */
oal_int32 get_cali_count(oal_uint32 *count)
{
    oal_cali_param_stru *pst_cali_data = NULL;
    oal_uint16 cali_count;
    oal_uint32 cali_parm;

    if (count == NULL) {
        ps_print_err("count is NULL\n");
        return -EFAIL;
    }

    if (g_cali_data_buf == NULL) {
        ps_print_err("g_cali_data_buf is NULL\n");
        return -EFAIL;
    }

    pst_cali_data = (oal_cali_param_stru *)g_cali_data_buf;
    cali_count = pst_cali_data->st_cali_update_info.ul_cali_time;
    cali_parm = *(oal_uint32 *)&(pst_cali_data->st_cali_update_info);

    ps_print_warning("cali count is [%d], cali update info is [%d]\n", cali_count, cali_parm);

    *count = cali_parm;

    return SUCC;
}

/*
 * ?? ?? ??  : get_bfgx_cali_data
 * ????????  : ????????bfgx????????????????????????????
 * ????????  : uint8  *buf:????????????bfgx????????????????
 *             uint32 *len:????????????bfgx??????????????????????
 *             uint32 buf_len:buf??????
 * ?? ?? ??  : 0??????????-1????????
 */
int32 get_bfgx_cali_data(oal_uint8 *buf, oal_uint32 *len, oal_uint32 buf_len)
{
    oal_cali_param_stru *pst_cali_data = NULL;
    oal_uint32 bfgx_cali_data_len;
    oal_int32 ret;

    ps_print_info("%s\n", __func__);

    if (unlikely(buf == NULL)) {
        ps_print_err("buf is NULL\n");
        return -EFAIL;
    }

    if (unlikely(len == NULL)) {
        ps_print_err("len is NULL\n");
        return -EFAIL;
    }

    if (unlikely(g_bfgx_cali_data_buf_hi1102a == NULL)) {
        ps_print_err("g_bfgx_cali_data_buf_hi1102a is NULL\n");
        return -EFAIL;
    }

    if (g_cali_data_buf == NULL) {
        ps_print_err("g_cali_data_buf is NULL\n");
        return -EFAIL;
    }

    bfgx_cali_data_len = sizeof(oal_bfgn_cali_param_stru);
    if (bfgx_cali_data_len > BFGX_BT_CALI_DATA_SIZE) {
        ps_print_err("bfgx data buffer[%d] is smaller than struct size[%d]\n",
                     BFGX_BT_CALI_DATA_SIZE, bfgx_cali_data_len);
        return -EFAIL;
    }

    pst_cali_data = (oal_cali_param_stru *)g_cali_data_buf;
    ret = memcpy_s(g_bfgx_cali_data_buf_hi1102a, BFGX_CALI_DATA_BUF_LEN,
                   (oal_uint8 *)&(pst_cali_data->st_bfgn_cali_data), bfgx_cali_data_len);
    if (ret != EOK) {
        ps_print_err("get_bfgx_cali_data: memcpy_s failed,ret = %d\n", ret);
        return -EFAIL;
    }

#ifdef HISI_NVRAM_SUPPORT
    if (bfgx_nv_data_init() != OAL_SUCC) {
        ps_print_err("bfgx nv data init fail!\n");
    }
#endif

    bfgx_cali_data_len = sizeof(bfgx_cali_data_stru);
    ret = memcpy_s(buf, buf_len, g_bfgx_cali_data_buf_hi1102a, bfgx_cali_data_len);
    if (ret != EOK) {
        ps_print_err("cali buf len[%d] is smaller than struct size[%d] ret=%d\n", buf_len, bfgx_cali_data_len, ret);
        return -EFAIL;
    }
    *len = bfgx_cali_data_len;

    return SUCC;
}

/*
 * ?? ?? ??  : get_cali_data_buf_addr
 * ????????  : ??????????????????????????
 * ?? ?? ??  : g_cali_data_buf????????????????NULL
 */
void *get_cali_data_buf_addr(void)
{
    return g_cali_data_buf;
}

/*
 * ?? ?? ??  : bfgx_get_cust_ini_data_buf
 * ????????  : ????????bfgx ini????????????????????
 * ????????  : pul_len : bfgx ini??????????buf??????
 * ?? ?? ??  : bfgx ini????buf????????????????NULL
 */
void *bfgx_get_cust_ini_data_buf(uint32 *pul_len)
{
    bfgx_cali_data_stru *pst_bfgx_cali_data_buf = NULL;

    if (g_bfgx_cali_data_buf_hi1102a == NULL) {
        return NULL;
    }

    pst_bfgx_cali_data_buf = (bfgx_cali_data_stru *)g_bfgx_cali_data_buf_hi1102a;

    *pul_len = sizeof(pst_bfgx_cali_data_buf->auc_bt_cust_ini_data);

    ps_print_info("bfgx cust ini buf size is %d\n", *pul_len);

    return pst_bfgx_cali_data_buf->auc_bt_cust_ini_data;
}

/*
 * ?? ?? ??  : bfgx_get_nv_data_buf
 * ????????  : ????????bfgx nv??????????????
 * ????????  : nv buf??????
 * ?? ?? ??  : bfgx nv????buf????????????????NULL
 */
void *bfgx_get_nv_data_buf(uint32 *pul_len)
{
    bfgx_cali_data_stru *pst_bfgx_cali_data_buf = NULL;

    if (g_bfgx_cali_data_buf_hi1102a == NULL) {
        return NULL;
    }

    pst_bfgx_cali_data_buf = (bfgx_cali_data_stru *)g_bfgx_cali_data_buf_hi1102a;

    *pul_len = sizeof(pst_bfgx_cali_data_buf->auc_nv_data);

    ps_print_info("bfgx nv buf size is %d\n", *pul_len);

    return pst_bfgx_cali_data_buf->auc_nv_data;
}

EXPORT_SYMBOL(get_cali_data_buf_addr);
EXPORT_SYMBOL(g_uc_netdev_is_open);

/*
 * ?? ?? ??  : plat_bfgx_cali_data_test
 * ????????  : test
 */
void plat_bfgx_cali_data_test(void)
{
    oal_cali_param_stru *pst_cali_data = NULL;
    oal_uint32 *p_test = NULL;
    oal_uint32 count;
    oal_uint32 i;

    pst_cali_data = (oal_cali_param_stru *)get_cali_data_buf_addr();
    if (pst_cali_data == NULL) {
        ps_print_err("get_cali_data_buf_addr failed\n");
        return;
    }

    p_test = (oal_uint32 *)&(pst_cali_data->st_bfgn_cali_data);
    count = sizeof(oal_bfgn_cali_param_stru) / sizeof(oal_uint32);

    for (i = 0; i < count; i++) {
        p_test[i] = i;
    }

    return;
}

/*
 * ?? ?? ??  : cali_data_buf_malloc
 * ????????  : ??????????????????????
 * ?? ?? ??  : 0??????????????-1????????????
 */
oal_int32 cali_data_buf_malloc(void)
{
    g_cali_data_buf = os_kzalloc_gfp(RF_CALI_DATA_BUF_LEN);
    if (g_cali_data_buf == NULL) {
        ps_print_err("malloc for g_cali_data_buf fail\n");
        return -EFAIL;
    }

    g_bfgx_cali_data_buf_hi1102a = (oal_uint8 *)os_kzalloc_gfp(BFGX_CALI_DATA_BUF_LEN);
    if (g_bfgx_cali_data_buf_hi1102a == NULL) {
        os_mem_kfree(g_cali_data_buf);
        g_cali_data_buf = NULL;
        ps_print_err("malloc for g_bfgx_cali_data_buf_hi1102a fail\n");
        return -EFAIL;
    }

    return SUCC;
}

/*
 * ?? ?? ??  : cali_data_buf_free
 * ????????  : ??????????????????????
 */
void cali_data_buf_free(void)
{
    if (g_cali_data_buf != NULL) {
        os_mem_kfree(g_cali_data_buf);
    }
    g_cali_data_buf = NULL;

    if (g_bfgx_cali_data_buf_hi1102a != NULL) {
        os_mem_kfree(g_bfgx_cali_data_buf_hi1102a);
    }
    g_bfgx_cali_data_buf_hi1102a = NULL;
}

/*
 * ?? ?? ??  : bfgx_cust_ini_init
 * ????????  : bt??????????????????
 * ?? ?? ??  : 0??????????-1????????
 */
int32 bfgx_cust_ini_init(void)
{
    int32 i;
    int32 l_ret = INI_FAILED;
    int32 l_cfg_value;
    int32 l_ori_val;
    int8 *pst_buf = NULL;
    uint32 ul_len;

    for (i = 0; i < BFGX_CFG_INI_BUTT; i++) {
        l_ori_val = g_bfgx_ini_config_cmd_hi1102a[i].init_value;

        /* ????ini???????? */
        l_ret = get_cust_conf_int32(INI_MODU_DEV_BT, g_bfgx_ini_config_cmd_hi1102a[i].name, &l_cfg_value);
        if (l_ret == INI_FAILED) {
            g_bfgx_cust_ini_data_hi1102a[i] = l_ori_val;
            ps_print_warning("bfgx read ini file failed cfg_id[%d],default value[%d]!", i, l_ori_val);
            continue;
        }

        g_bfgx_cust_ini_data_hi1102a[i] = l_cfg_value;

        ps_print_info("bfgx ini init [id:%d] [%s] changed from [%d]to[%d]",
                      i, g_bfgx_ini_config_cmd_hi1102a[i].name, l_ori_val, l_cfg_value);
    }

    pst_buf = bfgx_get_cust_ini_data_buf(&ul_len);
    if (pst_buf == NULL) {
        ps_print_err("get cust ini buf fail!");
        return INI_FAILED;
    }

    l_ret = memcpy_s(pst_buf, ul_len, g_bfgx_cust_ini_data_hi1102a, ul_len);
    if (l_ret != EOK) {
        ps_print_err("bfgx_cust_ini_init: memcpy_s failed, ret=%d\n!", l_ret);
        return INI_FAILED;
    }

    return INI_SUCC;
}

#ifdef HISI_NVRAM_SUPPORT
/*
 * ?? ?? ??  : bfgx_nv_data_init
 * ????????  : bt ????NV????
 */
oal_int32 bfgx_nv_data_init(void)
{
    int32 l_ret;
    int8 *pst_buf = NULL;
    uint32 ul_len;

    oal_uint8 bt_cal_nvram_tmp[OAL_BT_NVRAM_DATA_LENGTH];

    l_ret = read_conf_from_nvram(bt_cal_nvram_tmp, OAL_BT_NVRAM_DATA_LENGTH,
                                 OAL_BT_NVRAM_NUMBER, OAL_BT_NVRAM_NAME);
    if (l_ret != INI_SUCC) {
        ps_print_err("bfgx_nv_data_init::BT read NV error!");
        // last byte of NV ram is used to mark if NV ram is failed to read.
        bt_cal_nvram_tmp[OAL_BT_NVRAM_DATA_LENGTH - 1] = OAL_TRUE;
    } else {
        // last byte of NV ram is used to mark if NV ram is failed to read.
        bt_cal_nvram_tmp[OAL_BT_NVRAM_DATA_LENGTH - 1] = OAL_FALSE;
    }

    pst_buf = bfgx_get_nv_data_buf(&ul_len);
    if (pst_buf == NULL) {
        ps_print_err("get bfgx nv buf fail!");
        return INI_FAILED;
    }

    l_ret = memcpy_s(pst_buf, ul_len, bt_cal_nvram_tmp, OAL_BT_NVRAM_DATA_LENGTH);
    if (l_ret != EOK) {
        ps_print_err("bfgx_nv_data_init: memcpy_s failed, ret=%d\n!", l_ret);
        return INI_FAILED;
    }
    ps_print_info("bfgx_nv_data_init SUCCESS");
    return INI_SUCC;
}
#endif

/*
 * ?? ?? ??  : bfgx_customize_init
 * ????????  : bfgx????????????????????ini??????????????nv????
 * ?? ?? ??  : 0??????????-1????????
 */
int32 bfgx_customize_init(void)
{
    int32 ret;

    /* ??????????????????????buffer */
    ret = cali_data_buf_malloc();
    if (ret != OAL_SUCC) {
        ps_print_err("alloc cali data buf fail\n");
        return INI_FAILED;
    }

    ret = bfgx_cust_ini_init();
    if (ret != OAL_SUCC) {
        ps_print_err("bfgx ini init fail!\n");
        cali_data_buf_free();
        return INI_FAILED;
    }

#ifdef HISI_NVRAM_SUPPORT
    ret = bfgx_nv_data_init();
    if (ret != OAL_SUCC) {
        ps_print_err("bfgx nv data init fail!\n");
        cali_data_buf_free();
        return INI_FAILED;
    }
#endif

    return INI_SUCC;
}

