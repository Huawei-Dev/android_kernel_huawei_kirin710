

/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "mac_board.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_MAC_BOARD_C

/*****************************************************************************
  2 ????????????
*****************************************************************************/
/* HOST CRX???? */
DRAM_RAM_B frw_event_sub_table_item_stru g_dmac_host_crx_table[HMAC_TO_DMAC_SYN_BUTT];

/* DMAC??????HOST_DRX???????????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_dmac_tx_host_drx[DMAC_TX_HOST_DRX_BUTT];

/* DMAC??????WLAN_DTX???????????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_dmac_tx_wlan_dtx[DMAC_TX_WLAN_DTX_BUTT];

/* DMAC??????WLAN_CTX???????????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_dmac_wlan_ctx_event_sub_table[DMAC_WLAN_CTX_EVENT_SUB_TYPE_BUTT];

/* DMAC????,WLAN_DRX???????????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_dmac_wlan_drx_event_sub_table[HAL_WLAN_DRX_EVENT_SUB_TYPE_BUTT];

/* DMAC??????ERROR_IRQ?????????????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_dmac_high_prio_event_sub_table[HAL_EVENT_ERROR_IRQ_SUB_TYPE_BUTT];

/* DMAC????,WLAN_CRX???????????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_dmac_wlan_crx_event_sub_table[HAL_WLAN_CRX_EVENT_SUB_TYPE_BUTT];

/* DMAC??????TX_COMP???????????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_dmac_tx_comp_event_sub_table[HAL_TX_COMP_SUB_TYPE_BUTT];

/* DMAC????, TBTT?????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_dmac_tbtt_event_sub_table[HAL_EVENT_TBTT_SUB_TYPE_BUTT];

/* DMAC????, MISC?????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_dmac_misc_event_sub_table[HAL_EVENT_DMAC_MISC_SUB_TYPE_BUTT];

/* WLAN_DTX ???????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_ast_hmac_wlan_dtx_event_sub_table[DMAC_TX_WLAN_DTX_BUTT];

/* HMAC???? WLAN_DRX???????????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_ast_hmac_wlan_drx_event_sub_table[DMAC_WLAN_DRX_EVENT_SUB_TYPE_BUTT];

/* HMAC???? WLAN_CRX???????????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_EVENT_SUB_TYPE_BUTT];

/* HMAC???? TBTT???????????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_ast_hmac_tbtt_event_sub_table[DMAC_TBTT_EVENT_SUB_TYPE_BUTT];

/* HMAC???? ????HOST???????????????????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_ast_hmac_wlan_ctx_event_sub_table[DMAC_TO_HMAC_SYN_BUTT];

/* HMAC???? MISC???????????????????????????? */
DRAM_RAM_B frw_event_sub_table_item_stru g_ast_hmac_wlan_misc_event_sub_table[DMAC_MISC_SUB_TYPE_BUTT];

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
DRAM_RAM_B frw_event_sub_table_item_stru g_ast_hmac_hcc_rx_event_sub_table[DMAC_HCC_RX_EVENT_SUB_TYPE_BUTT];
#endif

frw_event_sub_table_item_stru *g_past_dmac_host_crx_table = g_dmac_host_crx_table;
frw_event_sub_table_item_stru *g_past_dmac_tx_host_drx = g_dmac_tx_host_drx;
frw_event_sub_table_item_stru *g_past_dmac_tx_wlan_dtx = g_dmac_tx_wlan_dtx;
frw_event_sub_table_item_stru *g_past_dmac_wlan_ctx_event_sub_table = g_dmac_wlan_ctx_event_sub_table;
frw_event_sub_table_item_stru *g_past_dmac_wlan_drx_event_sub_table = g_dmac_wlan_drx_event_sub_table;
frw_event_sub_table_item_stru *g_past_dmac_high_prio_event_sub_table = g_dmac_high_prio_event_sub_table;
frw_event_sub_table_item_stru *g_past_dmac_wlan_crx_event_sub_table = g_dmac_wlan_crx_event_sub_table;
frw_event_sub_table_item_stru *g_past_dmac_tx_comp_event_sub_table = g_dmac_tx_comp_event_sub_table;
frw_event_sub_table_item_stru *g_past_dmac_tbtt_event_sub_table = g_dmac_tbtt_event_sub_table;
frw_event_sub_table_item_stru *g_past_dmac_misc_event_sub_table = g_dmac_misc_event_sub_table;
frw_event_sub_table_item_stru *g_past_hmac_wlan_dtx_event_sub_table = g_ast_hmac_wlan_dtx_event_sub_table;
frw_event_sub_table_item_stru *g_past_hmac_wlan_drx_event_sub_table = g_ast_hmac_wlan_drx_event_sub_table;
frw_event_sub_table_item_stru *g_past_hmac_wlan_crx_event_sub_table = g_ast_hmac_wlan_crx_event_sub_table;
frw_event_sub_table_item_stru *g_past_hmac_tbtt_event_sub_table = g_ast_hmac_tbtt_event_sub_table;
frw_event_sub_table_item_stru *g_past_hmac_wlan_ctx_event_sub_table = g_ast_hmac_wlan_ctx_event_sub_table;
frw_event_sub_table_item_stru *g_past_hmac_wlan_misc_event_sub_table = g_ast_hmac_wlan_misc_event_sub_table;

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
frw_event_sub_table_item_stru *g_past_hmac_hcc_rx_event_sub_table = g_ast_hmac_hcc_rx_event_sub_table;
#endif

oal_uint16 g_us_dmac_high_prio_event_sub_table_size = OAL_SIZEOF(g_dmac_high_prio_event_sub_table);
oal_uint16 g_us_dmac_wlan_drx_event_sub_table_size = OAL_SIZEOF(g_dmac_wlan_drx_event_sub_table);
oal_uint16 g_us_dmac_wlan_crx_event_sub_table_size = OAL_SIZEOF(g_dmac_wlan_crx_event_sub_table);
oal_uint16 g_us_dmac_wlan_ctx_event_sub_table_size = OAL_SIZEOF(g_dmac_wlan_ctx_event_sub_table);
oal_uint16 g_us_dmac_tx_comp_event_sub_table_size = OAL_SIZEOF(g_dmac_tx_comp_event_sub_table);
oal_uint16 g_us_dmac_tbtt_event_sub_table_size = OAL_SIZEOF(g_dmac_tbtt_event_sub_table);
oal_uint16 g_us_dmac_misc_event_sub_table_size = OAL_SIZEOF(g_dmac_misc_event_sub_table);
oal_uint16 g_us_dmac_tx_host_drx_table_size = OAL_SIZEOF(g_dmac_tx_host_drx);
oal_uint16 g_us_dmac_host_crx_table_size = OAL_SIZEOF(g_dmac_host_crx_table);
oal_uint16 g_us_dmac_tx_wlan_dtx_table_size = OAL_SIZEOF(g_dmac_tx_wlan_dtx);

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
oal_uint16 g_us_hmac_wlan_hcc_rx_event_sub_table_size = OAL_SIZEOF(g_ast_hmac_hcc_rx_event_sub_table);
#endif
oal_uint16 g_us_hmac_wlan_misc_event_sub_table_size = OAL_SIZEOF(g_ast_hmac_wlan_misc_event_sub_table);
oal_uint16 g_us_hmac_wlan_dtx_event_sub_table_size = OAL_SIZEOF(g_ast_hmac_wlan_dtx_event_sub_table);
oal_uint16 g_us_hmac_wlan_drx_event_sub_table_size = OAL_SIZEOF(g_ast_hmac_wlan_drx_event_sub_table);
oal_uint16 g_us_hmac_wlan_crx_event_sub_table_size = OAL_SIZEOF(g_ast_hmac_wlan_crx_event_sub_table);
oal_uint16 g_us_hmac_wlan_ctx_event_sub_table_size = OAL_SIZEOF(g_ast_hmac_wlan_ctx_event_sub_table);
oal_uint16 g_us_hmac_tbtt_event_sub_table_size = OAL_SIZEOF(g_ast_hmac_tbtt_event_sub_table);

oal_uint16 g_us_hal_event_dmac_misc_sub_type_butt = HAL_EVENT_DMAC_MISC_SUB_TYPE_BUTT;

/*****************************************************************************
DFX????????????????
*****************************************************************************/
#ifdef _PRE_WLAN_DFT_STAT
dfx_performance_log_switch_enum_uint8 g_auc_dfx_performance_log_switch[DFX_PERFORMANCE_LOG_BUTT] = { 0 };
#endif

/*****************************************************************************
  3 ????????
*****************************************************************************/

#if defined(_PRE_PRODUCT_ID_HI110X_DEV)
oal_void event_fsm_table_register(oal_void)
{
    /* Part1: ??????Dmac???????? */
    /* ????DMAC????HOST_CRX???? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_HOST_CRX, FRW_EVENT_PIPELINE_STAGE_1, g_past_dmac_host_crx_table);

    /* ????DMAC????HOST_DRX?????????????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_HOST_DRX, FRW_EVENT_PIPELINE_STAGE_1, g_past_dmac_tx_host_drx);

    /* ????DMAC????WLAN_DTX?????????????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_WLAN_DTX, FRW_EVENT_PIPELINE_STAGE_1, g_past_dmac_tx_wlan_dtx);

    /* ????DMAC????WLAN_CTX?????????????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_WLAN_CTX, FRW_EVENT_PIPELINE_STAGE_1,
                                 g_past_dmac_wlan_ctx_event_sub_table);

    /* ????DMAC????WLAN_DRX???????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_WLAN_DRX, FRW_EVENT_PIPELINE_STAGE_0,
                                 g_past_dmac_wlan_drx_event_sub_table);

    /* ????DMAC????WLAN_CRX????pipeline 0???? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_WLAN_CRX, FRW_EVENT_PIPELINE_STAGE_0,
                                 g_past_dmac_wlan_crx_event_sub_table);

    /* ????DMAC????TX_COMP???????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_WLAN_TX_COMP, FRW_EVENT_PIPELINE_STAGE_0,
                                 g_past_dmac_tx_comp_event_sub_table);

    /* ????DMAC????TBTT???????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_TBTT, FRW_EVENT_PIPELINE_STAGE_0, g_past_dmac_tbtt_event_sub_table);

    /* ????DMAC????ERR???????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_HIGH_PRIO, FRW_EVENT_PIPELINE_STAGE_0,
                                 g_past_dmac_high_prio_event_sub_table);

    /* ????DMAC????MISC???????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_DMAC_MISC, FRW_EVENT_PIPELINE_STAGE_0,
                                 g_past_dmac_misc_event_sub_table);

    /* Part2: ??????Hmac???????? */
    /* ????WLAN_DTX???????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_WLAN_DTX, FRW_EVENT_PIPELINE_STAGE_0,
                                 g_past_hmac_wlan_dtx_event_sub_table);

    /* ????WLAN_DRX???????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_WLAN_DRX, FRW_EVENT_PIPELINE_STAGE_1,
                                 g_past_hmac_wlan_drx_event_sub_table);

    /* ????HMAC????WLAN_CRX???????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_WLAN_CRX, FRW_EVENT_PIPELINE_STAGE_1,
                                 g_past_hmac_wlan_crx_event_sub_table);

    /* ????DMAC????MISC???????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_DMAC_MISC, FRW_EVENT_PIPELINE_STAGE_1,
                                 g_past_hmac_wlan_misc_event_sub_table);

    /* ????TBTT???????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_TBTT, FRW_EVENT_PIPELINE_STAGE_1, g_past_hmac_tbtt_event_sub_table);

    /* ???????????????????????? */
    frw_event_table_register_etc(FRW_EVENT_TYPE_HOST_SDT_REG, FRW_EVENT_PIPELINE_STAGE_1,
                                 g_past_hmac_wlan_ctx_event_sub_table);
}
#else
oal_void event_fsm_table_register(oal_void)
{
    /* Part1: ??????Dmac???????? */
    /* ????DMAC????HOST_CRX???? */
    frw_event_table_register(FRW_EVENT_TYPE_HOST_CRX, FRW_EVENT_PIPELINE_STAGE_1, g_past_dmac_host_crx_table);

    /* ????DMAC????HOST_DRX?????????????? */
    frw_event_table_register(FRW_EVENT_TYPE_HOST_DRX, FRW_EVENT_PIPELINE_STAGE_1, g_past_dmac_tx_host_drx);

    /* ????DMAC????WLAN_DTX?????????????? */
    frw_event_table_register(FRW_EVENT_TYPE_WLAN_DTX, FRW_EVENT_PIPELINE_STAGE_1, g_past_dmac_tx_wlan_dtx);

    /* ????DMAC????WLAN_CTX?????????????? */
    frw_event_table_register(FRW_EVENT_TYPE_WLAN_CTX, FRW_EVENT_PIPELINE_STAGE_1, g_past_dmac_wlan_ctx_event_sub_table);

    /* ????DMAC????WLAN_DRX???????? */
    frw_event_table_register(FRW_EVENT_TYPE_WLAN_DRX, FRW_EVENT_PIPELINE_STAGE_0, g_past_dmac_wlan_drx_event_sub_table);

    /* ????DMAC????WLAN_CRX????pipeline 0???? */
    frw_event_table_register(FRW_EVENT_TYPE_WLAN_CRX, FRW_EVENT_PIPELINE_STAGE_0, g_past_dmac_wlan_crx_event_sub_table);

    /* ????DMAC????TX_COMP???????? */
    frw_event_table_register(FRW_EVENT_TYPE_WLAN_TX_COMP, FRW_EVENT_PIPELINE_STAGE_0,
                             g_past_dmac_tx_comp_event_sub_table);

    /* ????DMAC????TBTT???????? */
    frw_event_table_register(FRW_EVENT_TYPE_TBTT, FRW_EVENT_PIPELINE_STAGE_0, g_past_dmac_tbtt_event_sub_table);

    /* ????DMAC????ERR???????? */
    frw_event_table_register(FRW_EVENT_TYPE_HIGH_PRIO, FRW_EVENT_PIPELINE_STAGE_0,
                             g_past_dmac_high_prio_event_sub_table);

    /* ????DMAC????MISC???????? */
    frw_event_table_register(FRW_EVENT_TYPE_DMAC_MISC, FRW_EVENT_PIPELINE_STAGE_0, g_past_dmac_misc_event_sub_table);

    /* Part2: ??????Hmac???????? */
    /* ????WLAN_DTX???????? */
    frw_event_table_register(FRW_EVENT_TYPE_WLAN_DTX, FRW_EVENT_PIPELINE_STAGE_0, g_past_hmac_wlan_dtx_event_sub_table);

    /* ????WLAN_DRX???????? */
    frw_event_table_register(FRW_EVENT_TYPE_WLAN_DRX, FRW_EVENT_PIPELINE_STAGE_1, g_past_hmac_wlan_drx_event_sub_table);

    /* ????HMAC????WLAN_CRX???????? */
    frw_event_table_register(FRW_EVENT_TYPE_WLAN_CRX, FRW_EVENT_PIPELINE_STAGE_1, g_past_hmac_wlan_crx_event_sub_table);

    /* ????DMAC????MISC???????? */
    frw_event_table_register(FRW_EVENT_TYPE_DMAC_MISC, FRW_EVENT_PIPELINE_STAGE_1,
                             g_past_hmac_wlan_misc_event_sub_table);

    /* ????TBTT???????? */
    frw_event_table_register(FRW_EVENT_TYPE_TBTT, FRW_EVENT_PIPELINE_STAGE_1, g_past_hmac_tbtt_event_sub_table);

    /* ???????????????????????? */
    frw_event_table_register(FRW_EVENT_TYPE_HOST_SDT_REG, FRW_EVENT_PIPELINE_STAGE_1,
                             g_past_hmac_wlan_ctx_event_sub_table);
}
#endif

oal_void event_fsm_unregister(oal_void)
{
    /* Part1: ??????Dmac???????? */
    /* ??????DMAC????HOST_CRX???? */
    memset_s(g_past_dmac_host_crx_table, g_us_dmac_host_crx_table_size, 0, g_us_dmac_host_crx_table_size);

    /* ??????DMAC????HOST_DRX?????????????? */
    memset_s(g_past_dmac_tx_host_drx, g_us_dmac_tx_host_drx_table_size, 0, g_us_dmac_tx_host_drx_table_size);

    /* ??????DMAC????WLAN_DTX?????????????? */
    memset_s(g_past_dmac_tx_wlan_dtx, g_us_dmac_tx_wlan_dtx_table_size, 0, g_us_dmac_tx_wlan_dtx_table_size);

    /* ??????DMAC????WLAN_DRX???????? */
    memset_s(g_past_dmac_wlan_drx_event_sub_table, g_us_dmac_wlan_drx_event_sub_table_size,
        0, g_us_dmac_wlan_drx_event_sub_table_size);

    /* ??????DMAC????WLAN_CRX???????? */
    memset_s(g_past_dmac_wlan_crx_event_sub_table, g_us_dmac_wlan_crx_event_sub_table_size,
        0, g_us_dmac_wlan_crx_event_sub_table_size);

    /* ??????DMAC????TX_COMP???????? */
    memset_s(g_past_dmac_tx_comp_event_sub_table, g_us_dmac_tx_comp_event_sub_table_size,
        0, g_us_dmac_tx_comp_event_sub_table_size);

    /* ??????DMAC????TBTT???????? */
    memset_s(g_past_dmac_tbtt_event_sub_table, g_us_dmac_tbtt_event_sub_table_size,
        0, g_us_dmac_tbtt_event_sub_table_size);

    /* ??????DMAC????MAC_ERROR???????? */
    memset_s(g_past_dmac_high_prio_event_sub_table, g_us_dmac_high_prio_event_sub_table_size,
        0, g_us_dmac_high_prio_event_sub_table_size);

    /* ??????DMAC????MAC_ERROR???????? */
    memset_s(g_past_dmac_misc_event_sub_table, g_us_dmac_misc_event_sub_table_size,
        0, g_us_dmac_misc_event_sub_table_size);

    /* Part2: ??????Hmac???????? */
    memset_s(g_past_hmac_wlan_dtx_event_sub_table, g_us_hmac_wlan_dtx_event_sub_table_size,
        0, g_us_hmac_wlan_dtx_event_sub_table_size);

    memset_s(g_past_hmac_wlan_drx_event_sub_table, g_us_hmac_wlan_drx_event_sub_table_size,
        0, g_us_hmac_wlan_drx_event_sub_table_size);

    memset_s(g_past_hmac_wlan_crx_event_sub_table, g_us_hmac_wlan_crx_event_sub_table_size,
        0, g_us_hmac_wlan_crx_event_sub_table_size);

    memset_s(g_past_hmac_tbtt_event_sub_table, g_us_hmac_tbtt_event_sub_table_size,
        0, g_us_hmac_tbtt_event_sub_table_size);

    memset_s(g_past_hmac_wlan_ctx_event_sub_table, g_us_hmac_wlan_ctx_event_sub_table_size,
        0, g_us_hmac_wlan_ctx_event_sub_table_size);

    memset_s(g_past_hmac_wlan_misc_event_sub_table, g_us_hmac_wlan_misc_event_sub_table_size,
        0, g_us_hmac_wlan_misc_event_sub_table_size);
}
/*lint -e19*/
oal_module_symbol(g_past_dmac_host_crx_table);
oal_module_symbol(g_past_dmac_tx_host_drx);
oal_module_symbol(g_past_dmac_tx_wlan_dtx);
oal_module_symbol(g_past_dmac_wlan_ctx_event_sub_table);
oal_module_symbol(g_past_dmac_wlan_drx_event_sub_table);
oal_module_symbol(g_past_dmac_high_prio_event_sub_table);
oal_module_symbol(g_past_dmac_wlan_crx_event_sub_table);
oal_module_symbol(g_past_dmac_tx_comp_event_sub_table);
oal_module_symbol(g_past_dmac_tbtt_event_sub_table);
oal_module_symbol(g_past_dmac_misc_event_sub_table);

oal_module_symbol(g_past_hmac_wlan_dtx_event_sub_table);
oal_module_symbol(g_past_hmac_wlan_drx_event_sub_table);
oal_module_symbol(g_past_hmac_wlan_crx_event_sub_table);
oal_module_symbol(g_past_hmac_tbtt_event_sub_table);
oal_module_symbol(g_past_hmac_wlan_ctx_event_sub_table);
oal_module_symbol(g_past_hmac_wlan_misc_event_sub_table);
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
oal_module_symbol(g_past_hmac_hcc_rx_event_sub_table);
#endif

oal_module_symbol(event_fsm_table_register);

oal_module_symbol(event_fsm_unregister);
/*lint +e19*/
/*****************************************************************************
DFX????????????
*****************************************************************************/
#ifdef _PRE_WLAN_DFT_STAT

oal_uint32 dfx_get_performance_log_switch_enable(dfx_performance_log_switch_enum_uint8 uc_performance_log_switch_type)
{
    return g_auc_dfx_performance_log_switch[uc_performance_log_switch_type];
}


oal_void dfx_set_performance_log_switch_enable(
    dfx_performance_log_switch_enum_uint8 uc_performance_log_switch_type, oal_uint8 uc_value)
{
    if (uc_performance_log_switch_type >= DFX_PERFORMANCE_LOG_BUTT) {
        OAM_WARNING_LOG1(0, OAM_SF_ANY, "dfx_set_performance_log_switch_enable::log_switch type:%d.",
                         uc_performance_log_switch_type);
        return;
    }
    g_auc_dfx_performance_log_switch[uc_performance_log_switch_type] = uc_value;
}
#endif


