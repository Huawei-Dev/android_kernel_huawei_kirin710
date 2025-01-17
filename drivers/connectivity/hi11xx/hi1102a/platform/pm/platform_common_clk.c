

/* ?????????? */
#include "platform_common_clk.h"

#ifdef CONFIG_ARCH_PLATFORM
#include <linux/mtd/nve_ap_kernel_interface.h>
#else
#include <linux/mtd/hisi_nve_interface.h>
#endif

#include "hisi_ini.h"
#include "plat_debug.h"
#include "chr_user.h"
#include "plat_firmware.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_PLATFORM_COMMON_CLK_C

typedef struct {
    int8 *pc_name;         // ini ????????????????
    int8 c_index;          // ??????????????????a0?????????? a1,??????...
    oal_int32 l_type;      // ??????????/????????index
    oal_int32 l_prot_min;  // ????????????????
    oal_int32 l_prot_max;  // ????????????????
    oal_int32 l_def_val;   // ??????????????????
} ini_file_str;

typedef struct {
    oal_int32 part_id;     // nv??
    oal_int32 total_size;  // nv??????
    oal_int32 read_size;   // ??????????????????????
    char *name;
    oal_int32 (*process_cali)(oal_uint8 *pc_buffer, dcxo_dl_para_stru *pst_dl_para);  // ????????
} nv_part_str;

/* ???????? */
oal_int32 process_plat_cali(oal_uint8 *pc_buffer, dcxo_dl_para_stru *pst_dl_para);
oal_int32 process_factory_cali(oal_uint8 *pc_buffer, dcxo_dl_para_stru *pst_dl_para);
oal_int32 process_gnss_self_study(oal_uint8 *pc_buffer, dcxo_dl_para_stru *pst_dl_para);

/* ???????????? */
oal_uint8 *g_dcxo_data_buf = NULL;  // ??????NV??????????????????????cfg????????????????????GNSS????????????????????????
dcxo_manage_stru g_dcxo_info = {0};
dcxo_nv_info_stru g_factory = {0};

oal_int32 g_default_coeff[COEFF_NUM] = {
    DEFAULT_A0,
    DEFAULT_A1,
    DEFAULT_A2,
    DEFAULT_A3,
    DEFAULT_T0
};

dcxo_pmu_addr_stru g_st_pmu_addr[PMU_TYPE_BUFF] = {

    {   PMU_6555V300_CALI_END, PMU_6555V300_CALI_AVE0, PMU_6555V300_CALI_AVE1,
        PMU_6555V300_CALI_AVE2, PMU_6555V300_CALI_AVE3, PMU_6555V300_ANA_EN,
        PMU_6555V300_STATE, PMU_6555V300_LOW_BYTE, PMU_6555V300_HIGH_BYTE,
        PMU_HI655V300
    },

    {   PMU_6421V700_CALI_END, PMU_6421V700_CALI_AVE0, PMU_6421V700_CALI_AVE1,
        PMU_6421V700_CALI_AVE2, PMU_6421V700_CALI_AVE3, PMU_6421V700_ANA_EN,
        PMU_6421V700_STATE, PMU_6421V700_LOW_BYTE, PMU_6421V700_HIGH_BYTE,
        PMU_HI6421V700
    },
    {
        PMU_6555V200_CALI_END, PMU_6555V200_CALI_AVE0, PMU_6555V200_CALI_AVE1,
        PMU_6555V200_CALI_AVE2, PMU_6555V200_CALI_AVE3, PMU_6555V200_ANA_EN,
        PMU_6555V200_STATE, PMU_6555V200_LOW_BYTE, PMU_6555V200_HIGH_BYTE,
        PMU_HI6555V200
    }
};

/* ??????????????????????????????nv????????????????nv???????????? */
nv_part_str g_gst_dcxo_nv_part[] = {
    {   PLAT_DEF_ID, OAL_SIZEOF(g_default_coeff), OAL_SIZEOF(g_default_coeff),
        PLAT_DEF_NAME, process_plat_cali
    },

    {   NV_FAC_ID, NV_FAC_SIZE, OAL_SIZEOF(dcxo_nv_info_stru),
        NV_FAC_NAME, process_factory_cali
    },
    /* GNSS ??????????????????valid?????? + a0~t0???????? */
    {   NV_GNSS_ID, NV_GNSS_SIZE, OAL_SIZEOF(oal_int32) + OAL_SIZEOF(oal_uint32)*COEFF_NUM,
        NV_GNSS_NAME, process_gnss_self_study
    }
};

/* ????????????????ini?????? ??????????????????????????deal_min_max_val ??????????1 */
ini_file_str g_gst_dcxo_ini_para[] = {
    { "a0_min", COEFF_A0, INIT_TYPE_MIN, A0_EXCEP_PROT_MIN, A0_EXCEP_PROT_MAX, DEF_A0_MIN },
    { "a0_max", COEFF_A0, INIT_TYPE_MAX, A0_EXCEP_PROT_MIN, A0_EXCEP_PROT_MAX, DEF_A0_MAX },
    { "a1_min", COEFF_A1, INIT_TYPE_MIN, A1_EXCEP_PROT_MIN, A1_EXCEP_PROT_MAX, DEF_A1_MIN },
    { "a1_max", COEFF_A1, INIT_TYPE_MAX, A1_EXCEP_PROT_MIN, A1_EXCEP_PROT_MAX, DEF_A1_MAX },
    { "a2_min", COEFF_A2, INIT_TYPE_MIN, A2_EXCEP_PROT_MIN, A2_EXCEP_PROT_MAX, DEF_A2_MIN },
    { "a2_max", COEFF_A2, INIT_TYPE_MAX, A2_EXCEP_PROT_MIN, A2_EXCEP_PROT_MAX, DEF_A2_MAX },
    { "a3_min", COEFF_A3, INIT_TYPE_MIN, A3_EXCEP_PROT_MIN, A3_EXCEP_PROT_MAX, DEF_A3_MIN },
    { "a3_max", COEFF_A3, INIT_TYPE_MAX, A3_EXCEP_PROT_MIN, A3_EXCEP_PROT_MAX, DEF_A3_MAX },
    { "t0_min", COEFF_T0, INIT_TYPE_MIN, T0_EXCEP_PROT_MIN, T0_EXCEP_PROT_MAX, DEF_T0_MIN },
    { "t0_max", COEFF_T0, INIT_TYPE_MAX, T0_EXCEP_PROT_MIN, T0_EXCEP_PROT_MAX, DEF_T0_MAX }
};

/* ???????? */
oal_int32 dcxo_data_buf_malloc(oal_void)
{
    oal_uint8 *buffer = NULL;

    buffer = os_kzalloc_gfp(DCXO_CALI_DATA_BUF_LEN);
    if (buffer == NULL) {
        return -EFAIL;
    }
    g_dcxo_data_buf = buffer;

    return SUCC;
}

void dcxo_data_buf_free(void)
{
    if (g_dcxo_data_buf != NULL) {
        os_mem_kfree(g_dcxo_data_buf);
        g_dcxo_data_buf = NULL;
    }
}

oal_void *get_dcxo_data_buf_addr(oal_void)
{
    return g_dcxo_data_buf;
}

nv_part_str *get_nv_part_from_id(oal_int32 part_id)
{
    oal_int32 loop;
    for (loop = 0; loop < oal_array_size(g_gst_dcxo_nv_part); loop++) {
        if (g_gst_dcxo_nv_part[loop].part_id == part_id) {
            return &(g_gst_dcxo_nv_part[loop]);
        }
    }

    return NULL;
}

/*
 * ?? ?? ??  : deal_min_max_val
 * ????????  : ??????ini??????????????????????????????????????g_st_dcxo_info.check_value??
 *             ??????????????????????:
 *             1 ??ini????????max ????????min??????????t0_max????t0_min??????????t0_min, t0_max??????????????
 *             2 ??ini????????????????????????????????????????????????????????????????????
 *
 *             ??????????????:
 *             ????????????????????????
 *
 *             ??????????????????????????????????????1????????????????????????????????
 *             ??????????????:
 *             ????gst_dcxo_ini_para????????????????????????????????min????????max????????????????check_value??????
 *             ??????t0????:
 *             ????t0_min????????????????????????????check_value[0][INIT_TYPE_MIN](??????0????????????T0),??????
 *             t0????????????????check_value[0][INIT_TYPE_MAX]
 *
 *             ????t0_max??, ??????????????????check_value[0][INIT_TYPE_MIN],????????????????????????
 *             ????check_value[0][INIT_TYPE_MAX]????????t0_min????????????????INIT_TYPE_MAX????????t0_max??????
 *             ???????? ??INIT_TYPE_MAX????????????ini????????????
 * ????????  : c_para_pos??????gst_dcxo_ini_para????????????????index
 *             l_val   ??ini??????????????
 * ?? ?? ??  : ??????????????????INI_SUCC??????????INI_FAILED
 */
oal_int32 deal_min_max_val(oal_int8 c_para_pos, oal_int32 l_val)
{
    oal_int8 c_chk_arr_pos;
    oal_int32 l_pair_pos;
    oal_int32 *al_check_coeff;

    c_chk_arr_pos = g_gst_dcxo_ini_para[c_para_pos].c_index;
    l_pair_pos = g_gst_dcxo_ini_para[c_para_pos].l_type;
    al_check_coeff = g_dcxo_info.check_value[c_chk_arr_pos];

    ps_print_info("[dcxo] read ini file [index,pos] [%d,%d] value %d\n", c_chk_arr_pos, l_pair_pos, l_val);
    // ??min????????????min??????????????check_value[INIT_TYPE_MAX]????
    if (l_pair_pos == INIT_TYPE_MIN) {
        al_check_coeff[INIT_TYPE_MIN] = l_val;
        al_check_coeff[INIT_TYPE_MAX] = g_gst_dcxo_ini_para[c_para_pos].l_def_val;
    }

    // ??????????????max????????????min < max, ??????check_value??min????????????????????
    if ((l_pair_pos == INIT_TYPE_MAX) && (l_val <= al_check_coeff[INIT_TYPE_MIN])) {
        al_check_coeff[INIT_TYPE_MIN] = al_check_coeff[INIT_TYPE_MAX];
        al_check_coeff[INIT_TYPE_MAX] = g_gst_dcxo_ini_para[c_para_pos].l_def_val;
        ps_print_err("[dcxo][ini] get par array id [%d] val[%d] min >= max \n", c_para_pos, l_val);
        return INI_FAILED;
    }

    // min max??????????????
    if ((l_val > g_gst_dcxo_ini_para[c_para_pos].l_prot_max) || (l_val < g_gst_dcxo_ini_para[c_para_pos].l_prot_min)) {
        ps_print_err("[dcxo][ini] get id [%d] val[%d], not limit between [%d]<->[%d]\n",
                     c_para_pos, l_val, g_gst_dcxo_ini_para[c_para_pos].l_prot_min,
                     g_gst_dcxo_ini_para[c_para_pos].l_prot_max);

        al_check_coeff[l_pair_pos] = g_gst_dcxo_ini_para[c_para_pos].l_def_val;
        return INI_FAILED;
    }

    al_check_coeff[l_pair_pos] = l_val;

    return INI_SUCC;
}

/*
 * ?? ?? ??  : read_tcxo_dcxo_mode_from_ini_file
 * ????????  : ??ini?????????? tcxo or dcxo??????
 * ?? ?? ??  : ??????????????
 */
oal_int32 read_tcxo_dcxo_mode_from_ini_file(void)
{
    int8 ac_mode_buff[INI_BUF_SIZE] = {0};
    oal_int32 l_mode;

    // ??ini?????????? "tcxo_dcxo_mode" label
    if (get_cust_conf_string(INI_MODU_PLAT, TCXO_DCXO_MODE, ac_mode_buff, OAL_SIZEOF(ac_mode_buff)) != INI_SUCC) {
        ps_print_err("[dcxo] read dcxo_tcxo_mode from ini file failed, use default tcxo mode\n");
        g_dcxo_info.dcxo_tcxo_mode = INI_TCXO_MODE;
        return INI_TCXO_MODE;
    }

    if (OAL_STRNCMP(INI_DCXO_STR, ac_mode_buff, OAL_STRLEN(INI_DCXO_STR)) == 0) {
        l_mode = INI_DCXO_MODE;
    } else {
        l_mode = INI_TCXO_MODE;
    }

    g_dcxo_info.dcxo_tcxo_mode = l_mode;

    return l_mode;
}

/*
 * ?? ?? ??  : read_min_max_val_from_ini_file
 * ????????  : ??ini?????????? min/max????????
 */
void read_min_max_val_from_ini_file(void)
{
    oal_int8 loop;
    oal_int8 c_index;
    oal_int32 l_val;
    oal_int32 l_type;

    for (loop = 0; loop < oal_array_size(g_gst_dcxo_ini_para); loop++) {
        if (get_cust_conf_int32(INI_MODU_PLAT, g_gst_dcxo_ini_para[loop].pc_name, &l_val) != INI_SUCC) {
            // ????????ini????????, ????????????
            c_index = g_gst_dcxo_ini_para[loop].c_index;
            l_type = g_gst_dcxo_ini_para[loop].l_type;
            g_dcxo_info.check_value[c_index][l_type] = g_gst_dcxo_ini_para[loop].l_def_val;
            ps_print_err("[dcxo] [index,pos][%d,%d] read from ini failed, use default value %d\n",
                         c_index, l_type, g_gst_dcxo_ini_para[loop].l_def_val);
            continue;
        }

        if (deal_min_max_val(loop, l_val) == INI_FAILED) {
            ps_print_err("[dcxo] deal para arry id[%d], min-max error\n", loop);
        }
    }
}

void read_pmu_type_from_ini_file(void)
{
    int8 ac_type_buff[INI_BUF_SIZE] = {0};
    g_dcxo_info.pmu_chip_type = PMU_HI655V300;

    if (get_cust_conf_string(INI_MODU_PLAT, INI_PMU_CHIP_TYPE, ac_type_buff, OAL_SIZEOF(ac_type_buff)) != INI_SUCC) {
        ps_print_err("[dcxo] read pmu type from ini failed, use default HI655V300\n");
        return;
    }

    if (OAL_STRNCMP(INI_6555V300_STR, ac_type_buff, OAL_STRLEN(INI_6555V300_STR)) == 0) {
        g_dcxo_info.pmu_chip_type = PMU_HI655V300;
        ps_print_info("[dcxo] use pmu %s", INI_6555V300_STR);
    } else if (OAL_STRNCMP(INI_6421V700_STR, ac_type_buff, OAL_STRLEN(INI_6421V700_STR)) == 0) {
        g_dcxo_info.pmu_chip_type = PMU_HI6421V700;
        ps_print_info("[dcxo] use pmu %s", INI_6421V700_STR);
    } else if (OAL_STRNCMP(INI_6555V200_STR, ac_type_buff, OAL_STRLEN(INI_6555V200_STR)) == 0) {
        g_dcxo_info.pmu_chip_type = PMU_HI6555V200;
        ps_print_info("[dcxo] use pmu %s", INI_6555V200_STR);
    } else {
        ps_print_err("[dcxo] read pmu info %s not vld, use default HI655V300\n", ac_type_buff);
    }
}

void read_tcxo_dcxo_ini_file(void)
{
    oal_int32 l_ret;

    // ????????????tcxo ????????????????min-max????
    l_ret = read_tcxo_dcxo_mode_from_ini_file();
    if (l_ret == INI_TCXO_MODE) {
        return;
    }

    read_min_max_val_from_ini_file();
    read_pmu_type_from_ini_file();
}

int32 get_tcxo_dcxo_mode(void)
{
    return g_dcxo_info.dcxo_tcxo_mode;
}

/*
 * ?? ?? ??  : report_chr_err
 * ????????  : ????CHR????
 * ????????  : chr_errno ??????????id,
 *             chr_ptr ??????????????????
 *             chr_len ??????????????
 */
void report_chr_err(oal_int32 chr_errno, oal_uint8 *chr_ptr, oal_uint16 chr_len)
{
    switch (chr_errno) {
        case PLAT_CHR_ERRNO_DCXO_NV_RD:
            if (chr_len != OAL_SIZEOF(plat_chr_nv_rd_excep_stru)) {
                ps_print_err("[dcxo] [chr] id [%d] input len [%d] not match [%ld]\n",
                             chr_errno, chr_len, OAL_SIZEOF(plat_chr_nv_rd_excep_stru));

                return;
            }

            if (g_dcxo_info.chr_nv_read_err > PLAT_MAX_REPORT_CNT) {
                ps_print_err("[dcxo] [chr] id [%d] exceed max report\n", chr_errno);
                return;
            }

            g_dcxo_info.chr_nv_read_err++;

            chr_exception_p(chr_errno, chr_ptr, chr_len);
            break;

        default:
            ps_print_err("[dcxo] [chr] id [%d] not support\n", chr_errno);
            return;
    }

    ps_print_info("[dcxo] [chr] id [%d] repot, report cnt %d\n", chr_errno, g_dcxo_info.chr_nv_read_err);
}

oal_int32 read_coeff_from_nvram(oal_uint8 *pc_out, nv_part_str *nv_para)
{
#ifdef CONFIG_ARCH_PLATFORM
    struct opt_nve_info_user info;
#else
    struct hisi_nve_info_user info;
#endif
    oal_int32 ret = INI_FAILED;

    if (nv_para->part_id < 0) {  // ????????0??nv id????????????????????????dcxo??????
        ret = memcpy_s(pc_out, MALLOC_LEN, g_default_coeff, nv_para->read_size);
        if (ret != EOK) {
            ps_print_err("read_coeff_from_nvram: memcpy_s failed, ret = %d", ret);
            return INI_FAILED;
        }
        return INI_SUCC;
    } else {
        memset_s(&info, OAL_SIZEOF(info), 0, OAL_SIZEOF(info));
        ret = memcpy_s(info.nv_name, sizeof(info.nv_name), nv_para->name, OAL_STRLEN(nv_para->name));
        if (ret != EOK) {
            ps_print_err("read_coeff_from_nvram: memcpy_s failed, ret = %d", ret);
            return INI_FAILED;
        }
        info.nv_operation = NVRAM_READ;
        info.valid_size = nv_para->total_size;
        info.nv_number = nv_para->part_id;

#ifdef CONFIG_ARCH_PLATFORM
        ret = nve_direct_access_interface(&info);
#else
        ret = hisi_nve_direct_access(&info);
#endif
        if (ret == INI_SUCC) {
            ret = memcpy_s(pc_out, MALLOC_LEN, info.nv_data, nv_para->read_size);
            if (ret != EOK) {
                ps_print_err("read_coeff_from_nvram: memcpy_s failed, ret = %d", ret);
                return INI_FAILED;
            }
            ps_print_info("[dcxo] read_conf_from_nvram::nvram id[%d], nv name[%s], size[%d]\r\n!",
                          info.nv_number, info.nv_name, info.valid_size);
        } else {
            ps_print_err("[dcxo] read nvm [%d] %s failed", info.nv_number, info.nv_name);
            return INI_FAILED;
        }
    }

    return INI_SUCC;
}

oal_int32 nv_coeff_vld(oal_int32 *pl_coeff, oal_uint32 size, char *nv_name)
{
    oal_int32 loop;
    oal_int32 l_invld_cnt = 0;
    for (loop = 0; loop < size; loop++) {
        if ((*pl_coeff < g_dcxo_info.check_value[loop][INIT_TYPE_MIN]) ||
            (*pl_coeff > g_dcxo_info.check_value[loop][INIT_TYPE_MAX])) {
            ps_print_err("[dcxo] get nv[%s] coeff [%d], value %d, check exceed min[%d] <-> max[%d] scope \n",
                         nv_name, loop, *pl_coeff, g_dcxo_info.check_value[loop][INIT_TYPE_MIN],
                         g_dcxo_info.check_value[loop][INIT_TYPE_MAX]);

            l_invld_cnt++;
        }

        ps_print_info("[dcxo] read nv[%s] nv a[%d] = Dec(%d) Hex(0x%x)\n", nv_name, loop, *pl_coeff, *pl_coeff);

        pl_coeff++;
    }

    if (l_invld_cnt > 0) {
        return INI_FAILED;
    }

    return INI_SUCC;
}


/*
 * ?? ?? ??  : update_dcxo_coeff
 * ????????  : ????????????????????????????????????????a0~a3
 * ????????  : ??????????????????buffer????
 */
oal_void update_dcxo_coeff(oal_int32 *coeff, oal_uint32 coeff_cnt)
{
    dcxo_dl_para_stru *pst_para = NULL;
    oal_int32 ret;

    if (coeff == NULL) {
        return;
    }

    pst_para = get_dcxo_data_buf_addr();
    if (pst_para == NULL) {
        ps_print_err("[dcxo] update coeff input pst_para is NULL\n");
        return;
    }

    if (nv_coeff_vld(coeff, COEFF_NUM, "update_dcxo_coeff") != INI_SUCC) {
        ps_print_err("[dcxo] update coeff invlid\n");
        return;
    }

    ret = memcpy_s(pst_para->coeff_para, sizeof(pst_para->coeff_para), coeff, coeff_cnt);
    if (ret != EOK) {
        ps_print_err("[dcxo] memcpy_s failed, ret = %d\n", ret);
        return;
    }
}

oal_int32 process_plat_cali(oal_uint8 *pc_buffer, dcxo_dl_para_stru *pst_dl_para)
{
    oal_int32 *pl_para;
    oal_uint32 pmu_type;
    oal_int32 ret;

    pst_dl_para->check_data = DCXO_CHECK_MAGIC;
    pst_dl_para->tcxo_dcxo_flag = INI_DCXO_MODE;

    // ????????????????????????
    pl_para = pst_dl_para->coeff_para;
    ret = memcpy_s(pl_para, sizeof(pst_dl_para->coeff_para), pc_buffer, sizeof(g_default_coeff));
    if (ret != EOK) {
        ps_print_err("[dcxo] process_plat_cali, memcpy_s failed, ret = %d \n", ret);
        return INI_FAILED;
    }

    // ????ini????????????PMU ????????
    pmu_type = g_dcxo_info.pmu_chip_type;
    ret = memcpy_s(&(pst_dl_para->pmu_addr), sizeof(dcxo_pmu_addr_stru),
                   &g_st_pmu_addr[pmu_type], sizeof(dcxo_pmu_addr_stru));
    if (ret != EOK) {
        ps_print_err("[dcxo] process_plat_cali, memcpy_s failed, ret = %d \n", ret);
        return INI_FAILED;
    }

    return INI_SUCC;
}

oal_int32 process_factory_cali(oal_uint8 *pc_buffer, dcxo_dl_para_stru *pst_dl_para)
{
    oal_int32 *pl_coeff = NULL;
    plat_chr_nv_rd_excep_stru chr_nv_rd;
    oal_int32 ret;
    oal_uint16 crc_relt;

    ret = memcpy_s(&g_factory, OAL_SIZEOF(dcxo_nv_info_stru), pc_buffer, OAL_SIZEOF(dcxo_nv_info_stru));
    if (ret != EOK) {
        ps_print_err("[dcxo] process_factory_cali: memcpy_s faild, ret = %d\n", ret);
        return INI_FAILED;
    }

    pl_coeff = g_factory.coeff_para;

    if (g_factory.valid != DCXO_NV_CHK_OK) {
        ps_print_err("[dcxo] factory nv check not valid\n");
        goto report_chr;
    }

    // ??????????????????t0????????10??????????????16??
    if (g_factory.t0_bit_width_fix == T0_BIT_WIDTH_10) {
        pl_coeff[COEFF_T0] *= T0_WIDTH10_TO_WIDTH16;
    }

    /* ????????????????????????????????????min-max???? */
    if (nv_coeff_vld(pl_coeff, COEFF_NUM, NV_FAC_NAME) == INI_FAILED) {
        ps_print_err("[dcxo] factory coeff data check failed\n");
        goto report_chr;
    }

    // dcxo_nv_info_stru??????????????4????????crc????????????????????????????
    crc_relt = cal_crc_16((oal_uint8 *)&g_factory, sizeof(dcxo_nv_info_stru) - sizeof(oal_int32));
    if (crc_relt != (g_factory.crc_relt & FAC_NV_CRC_MASK)) {
        ps_print_err("[dcxo] crc calc failed, calc %d, read %d\n",
                     crc_relt, g_factory.crc_relt);

        // ????????nv??????????????crc????, ????????????????????chr
        if ((g_factory.crc_relt == 0) && (pl_coeff[COEFF_T0] == DCXO_PARA_T0_30)) {
            ps_print_info("[dcxo] old nv version don't report chr");
            return INI_FAILED;
        }

        goto report_chr;
    }

    ps_print_info("[dcxo] prcess_factory crc calc succ, calc 0x%x, read 0x%x\n",
                  crc_relt, g_factory.crc_relt);

    ret = memcpy_s(pst_dl_para->coeff_para, sizeof(pst_dl_para->coeff_para),
                   pl_coeff, COEFF_NUM * sizeof(oal_int32));
    if (ret != EOK) {
        ps_print_err("[dcxo] process_factory_cali: memcpy_s faild, ret = %d", ret);
        goto report_chr;
    }

    return INI_SUCC;

report_chr:
    chr_nv_rd.l_struct_len = OAL_SIZEOF(plat_chr_nv_rd_excep_stru);
    ret = memcpy_s(chr_nv_rd.l_para, sizeof(chr_nv_rd.l_para), pl_coeff, COEFF_NUM * sizeof(oal_int32));
    if (ret == EOK) {
        report_chr_err(PLAT_CHR_ERRNO_DCXO_NV_RD, (oal_uint8 *)&chr_nv_rd, OAL_SIZEOF(chr_nv_rd));
    }
    return INI_FAILED;
}

oal_int32 process_gnss_self_study(oal_uint8 *pc_buffer, dcxo_dl_para_stru *pst_dl_para)
{
    oal_int32 *pl_coeff;
    dcxo_nv_info_stru *pst_info;
    plat_chr_nv_rd_excep_stru chr_nv_rd;
    oal_int32 ret;

    pst_info = (dcxo_nv_info_stru *)pc_buffer;
    pl_coeff = pst_info->coeff_para;

    if (pst_info->valid != DCXO_NV_CHK_OK) {
        ps_print_err("[dcxo] gnss nv check not valid \n");
        goto report_chr;
    }

    /* ????gnss??????????????????????????????????min-max???? */
    if (nv_coeff_vld(pl_coeff, COEFF_NUM, NV_GNSS_NAME) == INI_FAILED) {
        ps_print_err("[dcxo] factory coeff data check failed\n");
        goto report_chr;
    }

    ret = memcpy_s(pst_dl_para->coeff_para, sizeof(pst_dl_para->coeff_para),
                   pl_coeff, COEFF_NUM * OAL_SIZEOF(oal_int32));
    if (ret != EOK) {
        ps_print_err("[dcxo] process_gnss_self_study, memcpy_s failed, ret = %d\n", ret);
        goto report_chr;
    }

    return INI_SUCC;

report_chr:
    memset_s(&chr_nv_rd, OAL_SIZEOF(plat_chr_nv_rd_excep_stru), 0, OAL_SIZEOF(plat_chr_nv_rd_excep_stru));
    chr_nv_rd.l_struct_len = OAL_SIZEOF(plat_chr_nv_rd_excep_stru);
    ret = memcpy_s(chr_nv_rd.l_para, sizeof(chr_nv_rd.l_para), pl_coeff,
                   COEFF_NUM * OAL_SIZEOF(oal_int32));
    if (ret == EOK) {
        report_chr_err(PLAT_CHR_ERRNO_DCXO_NV_RD, (oal_uint8 *)&chr_nv_rd, OAL_SIZEOF(chr_nv_rd));
    }
    return INI_FAILED;
}

oal_int32 get_dcxo_coeff(dcxo_dl_para_stru *pst_dl_para)
{
    oal_uint8 *buffer = NULL;
    oal_int32 ret = INI_FAILED;
    oal_int32 loop;
    oal_int32 nv_size;

    if (pst_dl_para == NULL) {
        ps_print_err("[dcxo] pst_dl_para input is NULL \n");
        return INI_FAILED;
    }

    buffer = os_kzalloc_gfp(MALLOC_LEN);
    if (buffer == NULL) {
        ps_print_err("[dcxo] alloc coeff mem failed \n");
        return INI_FAILED;
    }

    nv_size = oal_array_size(g_gst_dcxo_nv_part);
   // ????????????????????????????????????????????nv??????????????
    for (loop = 0; loop < nv_size; loop++) {
        // ??????????????buffer??????????????
        if (g_gst_dcxo_nv_part[loop].read_size > MALLOC_LEN) {
            ps_print_err("[dcxo] read nv %s size exceed malloc len\n",
                         g_gst_dcxo_nv_part[loop].name);
            ret = INI_FAILED;
            continue;
        }

        // ????nv????????
        ret = read_coeff_from_nvram(buffer, &g_gst_dcxo_nv_part[loop]);
        if (ret == INI_FAILED) {
            memset_s(buffer, MALLOC_LEN, 0, MALLOC_LEN);
            continue;
        }

        // ??nv??????????????
        if (g_gst_dcxo_nv_part[loop].process_cali != NULL) {
            ret = g_gst_dcxo_nv_part[loop].process_cali(buffer, pst_dl_para);
            if (ret != INI_SUCC) {
                memset_s(buffer, MALLOC_LEN, 0, MALLOC_LEN);
                continue;
            }

            // ??????????????????buffer????nv??
            g_dcxo_info.use_part_id = g_gst_dcxo_nv_part[loop].part_id;
        }

        memset_s(buffer, MALLOC_LEN, 0, MALLOC_LEN);
    }

    os_mem_kfree(buffer);
    return ret;
}

oal_void show_dcxo_conf_info(dcxo_dl_para_stru *pst_dl_para)
{
    oal_int32 loop;
    nv_part_str *nv_part;
    dcxo_pmu_addr_stru *pmu_addr = NULL;

    nv_part = get_nv_part_from_id(g_dcxo_info.use_part_id);

    ps_print_info("[dcxo] check data = 0x%x use dcxo mode, nv id = %d, name = %s cali buffer len %ld\n",
                  pst_dl_para->check_data, g_dcxo_info.use_part_id, (nv_part == NULL) ? NULL : nv_part->name,
                  DCXO_CALI_DATA_BUF_LEN);

    for (loop = 0; loop < COEFF_NUM; loop++) {
        ps_print_info("[dcxo] a[%d] = 0x%x \n", loop, pst_dl_para->coeff_para[loop]);
    }

    pmu_addr = &(pst_dl_para->pmu_addr);
    ps_print_info("[dcxo] pmu info  cali 0x%x, av0 0x%x av1 0x%x av2 0x%x av3 0x%x\n",
                  pmu_addr->cali_end, pmu_addr->auto_cali_ave0, pmu_addr->auto_cali_ave1,
                  pmu_addr->auto_cali_ave2, pmu_addr->auto_cali_ave3);

    ps_print_info("[dcxo] pmu info  ana 0x%x, state 0x%x low byte 0x%x high bytpe 0x%x type %d\n",
                  pmu_addr->wifi_ana_en, pmu_addr->xoadc_state, pmu_addr->reg_addr_low,
                  pmu_addr->reg_addr_high, pmu_addr->pmu_type);
}

oal_int32 read_dcxo_cali_data(oal_void)
{
    dcxo_dl_para_stru *pst_dl_para;

    pst_dl_para = get_dcxo_data_buf_addr();
    if (pst_dl_para == NULL) {
        ps_print_err("[dcxo][read_dcxo_cali_data] pst_para is NULL\n");
        return INI_FAILED;
    }

    if (get_tcxo_dcxo_mode() == INI_TCXO_MODE) {
        ps_print_info("[dcxo] use tcxo mode\n");
        return INI_SUCC;
    }

    if (get_dcxo_coeff(pst_dl_para) == INI_FAILED) {
        ps_print_err("[dcxo] not read coeff from gnss part\n");
    }

    show_dcxo_conf_info(pst_dl_para);

    return INI_SUCC;
}
