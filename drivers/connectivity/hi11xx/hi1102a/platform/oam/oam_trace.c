

/* ?????????? */
#include "oam_trace.h"
#include "oam_main.h"
#include "oam_trace.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_OAM_TRACE_C

/* ???????????? */
#ifdef _PRE_PROFILING_MODE
/* 2.1 profiling???????????? */
/* ????tx profiling?????????????? */
oam_profiling_tx_statistic_stru g_oam_profiling_statistic_tx;

/* ????rx profiling?????????????? */
oam_profiling_rx_statistic_stru g_oam_profiling_statistic_rx;

/* ????tx profiling?????????????? */
oam_profiling_alg_statistic_stru g_oam_profiling_statistic_alg;

/* ????????start time???????? */
oam_profiling_starttime_statistic_stru g_oam_profiling_statistic_starttime;

/* ???????????????????????? */
oam_profiling_chswitch_statistic_stru g_oam_profiling_statistic_chswitch;

/* ????profiling test?????????? */
oam_profiling_statistic_debug_stru g_oam_profiling_statistic_debug;

#endif

#ifdef _PRE_PROFILING_MODE
/*
 * ?? ?? ??  : oam_profiling_switch_test_process
 * ????????  : proc??????????????????
 */
oal_void oam_profiling_switch_test_process(oal_uint8 uc_config_type, oal_uint8 uc_config_value)
{
    switch (uc_config_type) {
        case OAM_PROFILING_SWITCH_DEBUG_CONFIG: {
            if (OAM_PROFILING_STATISTIC_TX_DEBUG & uc_config_value) {
                g_oam_profiling_statistic_debug.i_profiling_tx_debuging_enable = OAL_TRUE;
            } else {
                g_oam_profiling_statistic_debug.i_profiling_tx_debuging_enable = OAL_FALSE;
            }

            if (OAM_PROFILING_STATISTIC_RX_DEBUG & uc_config_value) {
                g_oam_profiling_statistic_debug.i_profiling_rx_debuging_enable = OAL_TRUE;
            } else {
                g_oam_profiling_statistic_debug.i_profiling_rx_debuging_enable = OAL_FALSE;
            }
            if (OAM_PROFILING_STATISTIC_ALG_DEBUG & uc_config_value) {
                g_oam_profiling_statistic_debug.i_profiling_alg_debuging_enable = OAL_TRUE;
            } else {
                g_oam_profiling_statistic_debug.i_profiling_alg_debuging_enable = OAL_FALSE;
            }
        }
        break;

        default:

            break;
    }
}

/*
 * ?? ?? ??  : oam_profiling_compute_time_offset
 * ????????  : ????????????????????????
 * ????????  : (1)????????
 *             (2)????????
 * ????????  : ????????????????
 */
oal_uint32 oam_profiling_compute_time_offset(oal_time_us_stru st_time_first,
                                             oal_time_us_stru st_time_second,
                                             oal_time_us_stru *pst_time_offset)
{
    if (oal_unlikely(pst_time_offset == NULL)) {
        oal_warn_on(1);
        return OAL_FAIL;
    }
    /* ??????1sec */
    if (st_time_first.i_sec == st_time_second.i_sec) {
        pst_time_offset->i_sec = 0;
        pst_time_offset->i_usec = st_time_second.i_usec - st_time_first.i_usec;
    } else { /* ????1sec */
        pst_time_offset->i_sec = 0;
        pst_time_offset->i_usec = MSEC_PER_SEC * (st_time_second.i_sec - st_time_first.i_sec) -
                                  st_time_first.i_usec + st_time_second.i_usec;
    }

    return OAL_SUCC;
}

/*
 * ?? ?? ??  : oam_profiling_packet_add
 * ????????  : ????????packet idx ??1
 */
oal_void oam_profiling_packet_add(oam_profiling_enum_uint8 en_profiling_type)
{
    switch (en_profiling_type) {
        /* ???????? */
        case OAM_PROFILING_RX:
            g_oam_profiling_statistic_rx.uc_skb_id_idx++;
            break;
        /* ???????? */
        case OAM_PROFILING_TX:
            g_oam_profiling_statistic_tx.uc_skb_id_idx++;
            break;
        default:
            break;
    }
}

/*
 * ?? ?? ??  : oam_profiling_rx_init
 * ????????  : ????????????????????????????
 */
oal_void oam_profiling_rx_init(oal_void)
{
    oal_uint32 ul_packet_idx;
    oal_uint32 ul_func_idx;

    g_oam_profiling_statistic_rx.uc_skb_id_idx = 0;

    for (ul_packet_idx = 0; ul_packet_idx < OAM_PROFILING_RX_PACKET_MAX_COUNT; ul_packet_idx++) {
        g_oam_profiling_statistic_rx.aus_rx_skb_id_list[ul_packet_idx] = 0;

        for (ul_func_idx = 0; ul_func_idx < OAM_PROFILING_RX_FUNC_BUTT; ul_func_idx++) {
            g_oam_profiling_statistic_rx.ast_rx_func_stand_time[ul_packet_idx][ul_func_idx] = 0;
        }
    }
}

/*
 * ?? ?? ??  : oam_profiling_rx_save_data
 * ????????  : ??????????skb id????????,????????,??????????????????skb_run_time_offset
 */
oal_void oam_profiling_rx_save_data(oam_profiling_rx_func_enum_uint8 en_func_index)
{
    /* ???????? */
    if (g_oam_profiling_statistic_debug.i_profiling_rx_debuging_enable == OAM_PROFILING_SWITCH_OFF) {
        return;
    }

    if (g_oam_profiling_statistic_rx.ast_rx_func_stand_time[g_oam_profiling_statistic_rx.uc_skb_id_idx][en_func_index] == 0) {
        g_oam_profiling_statistic_rx.ast_rx_func_stand_time[g_oam_profiling_statistic_rx.uc_skb_id_idx][en_func_index] = oal_5115timer_get_10ns();
    }
}

/*
 * ?? ?? ??  : oam_profiling_judge_data
 * ????????  : ??????????????????????????????????????
 * ????????  : uc_packet_idx : ??????packet index
 *             past_profiling_data : rx tx?????????????????????????????? ????????
 */
oal_bool_enum_uint8 oam_profiling_judge_data(oal_uint8 uc_packet_idx,
                                             oal_uint32 past_profiling_data[][OAM_PROFILING_MAX_POINT_NUM])
{
    oal_uint8 uc_rx_profiling_point_idx;
    oal_uint8 uc_rx_profiling_point_idx_start;
    oal_uint8 uc_rx_profiling_point_idx_next;

    for (uc_rx_profiling_point_idx = 0; uc_rx_profiling_point_idx < (OAM_PROFILING_RX_FUNC_BUTT - 1);
         uc_rx_profiling_point_idx++) {
        if (past_profiling_data[uc_packet_idx][uc_rx_profiling_point_idx] == 0) {
            continue;
        }
        uc_rx_profiling_point_idx_start = uc_rx_profiling_point_idx;
        // ??????????????0????????
        uc_rx_profiling_point_idx++;
        while (past_profiling_data[uc_packet_idx][uc_rx_profiling_point_idx] == 0) {
            uc_rx_profiling_point_idx++;
        }
        uc_rx_profiling_point_idx_next = uc_rx_profiling_point_idx;
        uc_rx_profiling_point_idx--;

        if (past_profiling_data[uc_packet_idx][uc_rx_profiling_point_idx_start] <
            past_profiling_data[uc_packet_idx][uc_rx_profiling_point_idx_next]) {
            return OAL_FALSE;
        }
    }

    return OAL_TRUE;
}

/*
 * ?? ?? ??  : oam_profiling_print_all_point
 * ????????  : ??????????????????????????????????????
 * ????????  : uc_show_level : profiling log level
 *             uc_packet_num : ??????????????????100
 *             en_offset_max_num : rx ??tx ??????????????
 *             past_profiling_data : rx??tx????????????????????????????????
 *                                   ????g_oam_profiling_statistic_rx.ast_rx_func_stand_time
 */
oal_void oam_profiling_print_all_point(oal_uint8 uc_show_level, oal_uint8 uc_packet_num,
                                       oam_profiling_rx_func_enum en_offset_max_num,
                                       oal_uint32 past_profiling_data[][OAM_PROFILING_MAX_POINT_NUM])
{
    oal_uint8 uc_rx_profiling_point_idx;
    oal_uint32 ul_rx_packet_idx_offset_time_tmp = 0;
    oal_uint8 uc_packet_idx;
    oal_bool_enum_uint8 en_ret = OAL_FALSE;

    for (uc_packet_idx = 0; uc_packet_idx < uc_packet_num; uc_packet_idx++) {
        // ????????????????
        en_ret = oam_profiling_judge_data(uc_packet_idx, g_oam_profiling_statistic_rx.ast_rx_func_stand_time);
        if (en_ret == OAL_FALSE) {
            // log level??2????????????????packet????????
            if (uc_show_level != OAM_PROFILING_LOG_LEVEL_2) {
                continue;
            }
        }

        OAL_IO_PRINT("packet_idx:%d\t", uc_packet_idx);

        // ??????ok?? ??????????????
        for (uc_rx_profiling_point_idx = 0; uc_rx_profiling_point_idx < en_offset_max_num;
             uc_rx_profiling_point_idx++) {
            ul_rx_packet_idx_offset_time_tmp = past_profiling_data[uc_packet_idx][uc_rx_profiling_point_idx];
            OAL_IO_PRINT("%10u\t", ul_rx_packet_idx_offset_time_tmp);
        }
        OAL_IO_PRINT("\n");
    }
}

/*
 * ?? ?? ??  : oam_profiling_print_offset_section_point
 * ????????  : ????rx ??tx ????????offset????????rx????3????????????3????offset??
 * ????????  : uc_packet_num : ??????????????????100
 *             uc_offset_count : rx ??tx ??????????rx 3 tx 6
 *             ast_profiling_offset_section : rx??tx??????????????????????
 *             past_profiling_data : rx??tx????????????????????????????????
 *                                   ????g_oam_profiling_statistic_rx.ast_rx_func_stand_time
 *             past_profiling_packet_total_time_list : ??????????toal offset ??????????????
 *
 */
oal_void oam_profiling_print_offset_section_point(oam_profiling_log_level_enum_uint8 uc_show_level,
                                                  oal_uint8 uc_packet_num, oal_uint8 uc_offset_count,
                                                  oal_uint8 ast_profiling_offset_section[][OAM_PROFILING_RX_MSG_COUNT],
                                                  oal_uint32 past_profiling_data[][OAM_PROFILING_MAX_POINT_NUM],
                                                  oal_uint16 *past_profiling_packet_total_time_list)
{
    oal_uint8 uc_offset_count_idx;
    oal_uint8 uc_start_index;
    oal_uint8 uc_end_index;
    oal_uint8 uc_packet_idx;
    oal_uint8 uc_good_data_num = 0;
    oal_uint32 ul_average = 0;
    oal_uint32 ul_rx_packet_idx_offset_time_tmp = 0;
    oal_uint32 ul_rx_packet_idx_offset_time_tmp_total = 0;
    oal_bool_enum_uint8 en_ret = OAL_FALSE;

    for (uc_packet_idx = 0; uc_packet_idx < uc_packet_num; uc_packet_idx++) {
        // ????????????????
        en_ret = oam_profiling_judge_data(uc_packet_idx, past_profiling_data);
        if (en_ret == OAL_FALSE) {
            // log level??2????????????????packet????????
            if (uc_show_level != OAM_PROFILING_LOG_LEVEL_2) {
                continue;
            }
        }

        uc_good_data_num++;
        ul_rx_packet_idx_offset_time_tmp_total = 0;

        OAL_IO_PRINT("packet_idx:%d\t", uc_packet_idx);

        for (uc_offset_count_idx = 0; uc_offset_count_idx < uc_offset_count; uc_offset_count_idx++) {
            uc_start_index = ast_profiling_offset_section[uc_offset_count_idx][0];
            uc_end_index = ast_profiling_offset_section[uc_offset_count_idx][1];
            ul_rx_packet_idx_offset_time_tmp = past_profiling_data[uc_packet_idx][uc_start_index] -
                                               past_profiling_data[uc_packet_idx][uc_end_index];
            OAL_IO_PRINT("%10u\t", ul_rx_packet_idx_offset_time_tmp);
            ul_rx_packet_idx_offset_time_tmp_total += ul_rx_packet_idx_offset_time_tmp;
        }
        // ??????offset ??????????????????aus_rx_skb_id_list????
        past_profiling_packet_total_time_list[uc_packet_idx] = ul_rx_packet_idx_offset_time_tmp_total;
        OAL_IO_PRINT("\t%10u\n", past_profiling_packet_total_time_list[uc_packet_idx]);
        ul_average += past_profiling_packet_total_time_list[uc_packet_idx];
    }

    OAL_IO_PRINT("Average=%5u\n", ul_average / uc_good_data_num);
}

/*
 * ?? ?? ??  : oam_profiling_rx_show_offset
 * ????????  : ??????????????????????????????
 */
oal_void oam_profiling_rx_show_offset(oal_uint8 uc_show_level)
{
    oal_uint8 uc_packet_num;
    oal_uint8 uc_rx_profiling_point_idx;
    oal_uint8 ast_rx_profiling_offset_section[OAM_PROFILING_RX_OFFSET_COUNT][OAM_PROFILING_RX_MSG_COUNT] = {
        { OAM_PROFILING_FUNC_RX_COMP_START, OAM_PROFILING_FUNC_RX_COMP_IRQ_END },
        { OAM_PROFILING_FUNC_RX_DMAC_START, OAM_PROFILING_FUNC_RX_DMAC_HANDLE_PREPARE_EVENT },
        { OAM_PROFILING_FUNC_RX_HMAC_START, OAM_PROFILING_FUNC_RX_DMAC_END }
    };

    uc_packet_num = (g_oam_profiling_statistic_rx.uc_skb_id_idx < OAM_PROFILING_RX_PACKET_MAX_COUNT ?
                                                                g_oam_profiling_statistic_rx.uc_skb_id_idx :
                                                                OAM_PROFILING_TX_PACKET_MAX_COUNT);

    OAL_IO_PRINT("RX:\n");
    // ??????????????
    OAL_IO_PRINT("\n");
    for (uc_rx_profiling_point_idx = 0; uc_rx_profiling_point_idx < OAM_PROFILING_RX_OFFSET_COUNT;
         uc_rx_profiling_point_idx++) {
        OAL_IO_PRINT("%d-%d ",
                     ast_rx_profiling_offset_section[uc_rx_profiling_point_idx][0],
                     ast_rx_profiling_offset_section[uc_rx_profiling_point_idx][1]);
        switch (ast_rx_profiling_offset_section[uc_rx_profiling_point_idx][0]) {
            case OAM_PROFILING_FUNC_RX_COMP_START:
                OAL_IO_PRINT("irq\t");
                break;
            case OAM_PROFILING_FUNC_RX_DMAC_START:
                OAL_IO_PRINT("dmac\t");
                break;
            case OAM_PROFILING_FUNC_RX_HMAC_START:
                OAL_IO_PRINT("hmac\t");
                break;
            default:
                break;
        }
    }
    OAL_IO_PRINT("\toffset_total_time");
    OAL_IO_PRINT("\n");

    oam_profiling_print_offset_section_point(uc_show_level, uc_packet_num, OAM_PROFILING_RX_OFFSET_COUNT,
                                             ast_rx_profiling_offset_section,
                                             g_oam_profiling_statistic_rx.ast_rx_func_stand_time,
                                             g_oam_profiling_statistic_rx.aus_rx_skb_id_list);

    if (uc_show_level == OAM_PROFILING_LOG_LEVEL_0) {
        return;
    }

    // ??????????????????
    OAL_IO_PRINT("\n");
    for (uc_rx_profiling_point_idx = OAM_PROFILING_FUNC_RX_COMP_START;
         uc_rx_profiling_point_idx < OAM_PROFILING_RX_FUNC_BUTT; uc_rx_profiling_point_idx++) {
        OAL_IO_PRINT("%d\t", uc_rx_profiling_point_idx);
    }
    OAL_IO_PRINT("\n");

    oam_profiling_print_all_point(uc_show_level, uc_packet_num, OAM_PROFILING_RX_FUNC_BUTT,
                                  g_oam_profiling_statistic_rx.ast_rx_func_stand_time);
}

/*
 * ?? ?? ??  : oam_profiling_tx_init
 * ????????  : ????????????????????????????
 */
oal_void oam_profiling_tx_init(oal_void)
{
    oal_uint32 ul_packet_idx;
    oal_uint32 ul_func_idx;

    g_oam_profiling_statistic_tx.uc_skb_id_idx = 0;

    for (ul_packet_idx = 0; ul_packet_idx < OAM_PROFILING_TX_PACKET_MAX_COUNT; ul_packet_idx++) {
        g_oam_profiling_statistic_tx.aus_tx_skb_id_list[ul_packet_idx] = 0;
        for (ul_func_idx = 0; ul_func_idx < OAM_PROFILING_TX_FUNC_BUTT; ul_func_idx++) {
            g_oam_profiling_statistic_tx.ast_tx_func_stand_time[ul_packet_idx][ul_func_idx] = 0;
        }
    }
}

/*
 * ?? ?? ??  : oam_profiling_tx_save_data
 * ????????  : ??????????skb id????????,????????,??????????????????skb_run_time_offset
 * ????????  : (1)????????????netbuf
 *             (2)????????
 */
oal_void oam_profiling_tx_save_data(oal_void *pst_netbuf,
                                    oam_profiling_tx_func_enum_uint8 en_func_index)
{
    /* ???????? */
    if (g_oam_profiling_statistic_debug.i_profiling_tx_debuging_enable == OAM_PROFILING_SWITCH_OFF) {
        return;
    }

    if (g_oam_profiling_statistic_tx.ast_tx_func_stand_time[g_oam_profiling_statistic_tx.uc_skb_id_idx][en_func_index] == 0) {
        g_oam_profiling_statistic_tx.ast_tx_func_stand_time[g_oam_profiling_statistic_tx.uc_skb_id_idx][en_func_index] = oal_5115timer_get_10ns();
    }
}

/*
 * ?? ?? ??  : oam_profiling_tx_show_offset
 * ????????  : ??????????????????????????????
 */
oal_void oam_profiling_tx_show_offset(oal_uint8 uc_show_level)
{
    oal_uint8 uc_packet_num;
    oal_uint8 uc_tx_profiling_point_idx;
    oal_uint8 ast_tx_profiling_offset_section[OAM_PROFILING_TX_OFFSET_COUNT][OAM_PROFILING_TX_MSG_COUNT] = {
        { OAM_PROFILING_FUNC_CONFIG_XMIT_START, OAM_PROFILING_FUNC_TX_EVENT_TO_DMAC },
        { OAM_PROFILING_FUNC_DMAC_TX_START,      OAM_PROFILING_FUNC_TID_ENQUEUE },
        { OAM_PROFILING_FUNC_SCHEDULE_START,     OAM_PROFILING_FUNC_SCHEDULE_END },
        { OAM_PROFILING_FUNC_TX_COMP_IRQ_START,  OAM_PROFILING_FUNC_TX_COMP_IRQ_END },
        { OAM_PROFILING_FUNC_TX_COMP_DMAC_START, OAM_PROFILING_FUNC_TX_COMP_DMAC_END }
    };

    uc_packet_num = (g_oam_profiling_statistic_tx.uc_skb_id_idx < OAM_PROFILING_TX_PACKET_MAX_COUNT ?
                                                                g_oam_profiling_statistic_tx.uc_skb_id_idx :
                                                                OAM_PROFILING_TX_PACKET_MAX_COUNT);

    OAL_IO_PRINT("TX:\n");

    // ??????????????
    OAL_IO_PRINT("\n");
    for (uc_tx_profiling_point_idx = 0; uc_tx_profiling_point_idx < OAM_PROFILING_TX_OFFSET_COUNT;
         uc_tx_profiling_point_idx++) {
        OAL_IO_PRINT("%d-%d ",
                     ast_tx_profiling_offset_section[uc_tx_profiling_point_idx][0],
                     ast_tx_profiling_offset_section[uc_tx_profiling_point_idx][1]);
        switch (ast_tx_profiling_offset_section[uc_tx_profiling_point_idx][0]) {
            case OAM_PROFILING_FUNC_CONFIG_XMIT_START:
                OAL_IO_PRINT("wal hmac\t");
                break;
            case OAM_PROFILING_FUNC_DMAC_TX_START:
                OAL_IO_PRINT("dmac tid\t");
                break;
            case OAM_PROFILING_FUNC_SCHEDULE_START:
                OAL_IO_PRINT("schedule\t");
                break;
            case OAM_PROFILING_FUNC_TX_COMP_IRQ_START:
                OAL_IO_PRINT("irq up\t");
                break;
            case OAM_PROFILING_FUNC_TX_COMP_DMAC_START:
                OAL_IO_PRINT("irq down\t");
                break;
            default:
                break;
        }
    }
    OAL_IO_PRINT("\toffset_total_time");
    OAL_IO_PRINT("\n");

    oam_profiling_print_offset_section_point(uc_show_level, uc_packet_num, OAM_PROFILING_TX_OFFSET_COUNT,
                                             ast_tx_profiling_offset_section,
                                             g_oam_profiling_statistic_tx.ast_tx_func_stand_time,
                                             g_oam_profiling_statistic_tx.aus_tx_skb_id_list);

    if (uc_show_level == OAM_PROFILING_LOG_LEVEL_0) {
        return;
    }

    // ??????????????????
    OAL_IO_PRINT("\n");
    for (uc_tx_profiling_point_idx = OAM_PROFILING_FUNC_CONFIG_XMIT_START;
         uc_tx_profiling_point_idx < OAM_PROFILING_TX_FUNC_BUTT; uc_tx_profiling_point_idx++) {
        OAL_IO_PRINT("%d\t", uc_tx_profiling_point_idx);
    }
    OAL_IO_PRINT("\n");

    oam_profiling_print_all_point(uc_show_level, uc_packet_num, OAM_PROFILING_TX_FUNC_BUTT,
                                  g_oam_profiling_statistic_tx.ast_tx_func_stand_time);
}

/*
 * ?? ?? ??  : oam_profiling_alg_init
 * ????????  : ????????????????????????????
 */
oal_void oam_profiling_alg_init(oal_void)
{
    oal_uint32 ul_packet_idx;
    oal_uint32 ul_func_idx;

    for (ul_packet_idx = 0; ul_packet_idx < OAM_PROFILING_ALG_PACKET_MAX_COUNT; ul_packet_idx++) {
        /* ??????netbuf????????SKB_ID????????0?????????? */
        g_oam_profiling_statistic_alg.aus_alg_skb_id_list[ul_packet_idx] = OAM_PROFILING_PACKET_INVALID_VALUE;
        g_oam_profiling_statistic_alg.uc_skb_id_idx = 0;
        g_oam_profiling_statistic_alg.uc_idx_for_array = 0;
        g_oam_profiling_statistic_alg.us_abnormal_index = 0;

        for (ul_func_idx = 0; ul_func_idx < OAM_PROFILING_ALG_FUNC_BUTT; ul_func_idx++) {
            g_oam_profiling_statistic_alg.ast_alg_func_stand_time[ul_packet_idx][ul_func_idx] = 0;
            g_oam_profiling_statistic_alg.ast_alg_func_time_offset[ul_packet_idx][ul_func_idx] = 0;
            g_oam_profiling_statistic_alg.aus_alg_pass_count[ul_packet_idx][ul_func_idx] = 0;
        }
    }
}

/*
 * ?? ?? ??  : oam_profiling_alg_save_data
 * ????????  : ??????????skb id????????,????????,??????????????????skb_run_time_offset
 */
oal_void oam_profiling_alg_save_data(oam_profiling_alg_func_enum_uint8 en_func_index)
{
    /* ????????0???????? ???????????????????????? */
    if (g_oam_profiling_statistic_alg.ast_alg_func_stand_time[g_oam_profiling_statistic_alg.uc_skb_id_idx][en_func_index] == 0) {
        g_oam_profiling_statistic_alg.ast_alg_func_stand_time[g_oam_profiling_statistic_alg.uc_skb_id_idx][en_func_index] = oal_5115timer_get_10ns();
    }
}

/*
 * ?? ?? ??  : oam_profiling_alg_show_offset
 * ????????  : ??????????????????????????????
 */
oal_uint32 oam_profiling_alg_show_offset(oal_void)
{
    oal_uint32 ul_packet_idx;
    oal_uint32 ul_func_idx;
    oal_uint32 ul_time_offset = 0;

    for (ul_packet_idx = 0; ul_packet_idx < 1 /* OAM_PROFILING_ALG_PACKET_MAX_COUNT */; ul_packet_idx++) {
        OAL_IO_PRINT("ALG time show:\n");
        /* ????XX?????? */
        OAL_IO_PRINT("      arrive_time      offset  ");
        for (ul_func_idx = OAM_PROFILING_ALG_START; ul_func_idx <= OAM_PROFILING_ALG_END; ul_func_idx++) {
            OAL_IO_PRINT("\nNo%3d ", ul_func_idx);
            OAL_IO_PRINT("%10u  ", g_oam_profiling_statistic_alg.ast_alg_func_stand_time[ul_packet_idx][ul_func_idx]);

            if (ul_func_idx != OAM_PROFILING_ALG_START) {
                ul_time_offset = g_oam_profiling_statistic_alg.ast_alg_func_stand_time[ul_packet_idx][ul_func_idx - 1] -
                                 g_oam_profiling_statistic_alg.ast_alg_func_stand_time[ul_packet_idx][ul_func_idx];
                OAL_IO_PRINT("%10u ", ul_time_offset);
            }
        }

        ul_time_offset = g_oam_profiling_statistic_alg.ast_alg_func_stand_time[ul_packet_idx][OAM_PROFILING_ALG_START] -
                         g_oam_profiling_statistic_alg.ast_alg_func_stand_time[ul_packet_idx][OAM_PROFILING_ALG_END];
        OAL_IO_PRINT("\nALG stage 1 total time is: %d (10ns)   \n\n", ul_time_offset);
    }

    ul_time_offset = g_oam_profiling_statistic_alg.ast_alg_func_stand_time[0][OAM_PROFILING_ALG_START] -
                     g_oam_profiling_statistic_alg.ast_alg_func_stand_time[0][OAM_PROFILING_ALG_END];

    OAL_IO_PRINT("ALG total time is: %d (10ns)     \n", ul_time_offset);

    /* ???? */
    oam_profiling_alg_init();

    return OAL_SUCC;
}

oal_void oam_profiling_statistic_init(oal_void)
{
    memset_s(&g_oam_profiling_statistic_starttime, OAL_SIZEOF(g_oam_profiling_statistic_starttime),
             0, OAL_SIZEOF(g_oam_profiling_statistic_starttime));

    memset_s(&g_oam_profiling_statistic_chswitch, OAL_SIZEOF(g_oam_profiling_statistic_chswitch), 0,
             OAL_SIZEOF(g_oam_profiling_statistic_chswitch));
}

/*
 * ?? ?? ??  : oam_profiling_starttime_save_timestamp
 * ????????  : ????????????????????????
 * ????????  : en_func_idx: ????????????????
 */
oal_void oam_profiling_starttime_save_timestamp(oam_profiling_starttime_func_enum_uint8 en_func_idx)
{
    g_oam_profiling_statistic_starttime.aul_timestamp[en_func_idx] = oal_5115timer_get_10ns();
}

/*
 * ?? ?? ??  : oam_profiling_starttime_show_offset
 * ????????  : ??????????????????????
 */
oal_void oam_profiling_starttime_show_offset(oal_void)
{
    oal_uint32 ul_idx;

    /* ???????????????????? */
    OAL_IO_PRINT("Print all chip start timestamps: \n");
    for (ul_idx = 0; ul_idx < OAM_PROFILING_STARTTIME_FUNC_BUTT; ul_idx++) {
        OAL_IO_PRINT("%-16u \n", g_oam_profiling_statistic_starttime.aul_timestamp[ul_idx]);
    }

    OAL_IO_PRINT("Print chip start timestamp offset: \n");
    /* ????????????????????????????????????????????????????start??????end??????????????2 */
    for (ul_idx = 0; ul_idx < OAM_PROFILING_STARTTIME_FUNC_BUTT; ul_idx += 2) {
        OAL_IO_PRINT("%-16u \n",
                     g_oam_profiling_statistic_starttime.aul_timestamp[ul_idx] -
                     g_oam_profiling_statistic_starttime.aul_timestamp[ul_idx + 1]);
    }

    return;
}

/*
 * ?? ?? ??  : oam_profiling_chswitch_save_timestamp
 * ????????  : ????????????????????????
 * ????????  : en_func_idx: ????????????????
 */
oal_void oam_profiling_chswitch_save_timestamp(oam_profiling_chswitch_func_enum_uint8 en_func_idx)
{
    g_oam_profiling_statistic_chswitch.aul_timestamp[en_func_idx] = oal_5115timer_get_10ns();

    return;
}

/*
 * ?? ?? ??  : oam_profiling_chswitch_show_offset
 * ????????  : ????????????????
 */
oal_void oam_profiling_chswitch_show_offset(oal_void)
{
    oal_uint32 ul_idx;

    /* ???????????????????? */
    OAL_IO_PRINT("Print all chswitch timestamps: \n");
    for (ul_idx = 0; ul_idx < OAM_PROFILING_CHSWITCH_FUNC_BUTT; ul_idx++) {
        OAL_IO_PRINT("%-16u \n", g_oam_profiling_statistic_chswitch.aul_timestamp[ul_idx]);
    }

    OAL_IO_PRINT("Print chswitch timestamp offset: \n");
    /* ????????????????????????????????????????????????????start??????end??????????????2 */
    for (ul_idx = 0; ul_idx < OAM_PROFILING_CHSWITCH_FUNC_BUTT; ul_idx += 2) {
        OAL_IO_PRINT("%-16u \n",
                     g_oam_profiling_statistic_chswitch.aul_timestamp[ul_idx] -
                     g_oam_profiling_statistic_chswitch.aul_timestamp[ul_idx + 1]);
    }

    return;
}

/*
 * ?? ?? ??  : oam_profiling_set_switch
 * ????????  : ????profiling??????????
 */
oal_uint32 oam_profiling_set_switch(oam_profiling_enum_uint8 en_profiling_type,
                                    oam_profiling_swith_enum_uint8 en_profiling_switch)
{
    if ((en_profiling_switch >= OAL_SWITCH_BUTT) || (en_profiling_type >= OAM_PROFILING_BUTT)) {
        return OAL_ERR_CODE_INVALID_CONFIG;
    }
    switch (en_profiling_type) {
        /* ???????? */
        case OAM_PROFILING_RX:
            g_oam_profiling_statistic_debug.i_profiling_rx_debuging_enable = en_profiling_switch;
            oam_profiling_rx_init();

            break;

        /* ???????? */
        case OAM_PROFILING_TX:
            g_oam_profiling_statistic_debug.i_profiling_tx_debuging_enable = en_profiling_switch;
            oam_profiling_tx_init();

            break;

        /* ALG???? */
        case OAM_PROFILING_ALG:
            g_oam_profiling_statistic_debug.i_profiling_alg_debuging_enable = en_profiling_switch;

            break;

        default:

            break;
    }

    return OAL_SUCC;
}

oal_void oam_profiling_init(oal_void)
{
    /* ???????????? */
    oal_5115timer_init();

    /* ??????????????profiling???? */
    oam_profiling_rx_init();

    /* ??????????????profiling???? */
    oam_profiling_tx_init();

    /* ??????????????profiling???? */
    oam_profiling_alg_init();

    /* ??????????????profiling???? */
    oam_profiling_statistic_init();

    /* profiling??????:?????????? */
    oam_profiling_set_switch(OAM_PROFILING_RX, OAM_PROFILING_SWITCH_OFF);
    oam_profiling_set_switch(OAM_PROFILING_TX, OAM_PROFILING_SWITCH_OFF);
    oam_profiling_set_switch(OAM_PROFILING_ALG, OAM_PROFILING_SWITCH_OFF);
}
#endif

#ifdef _PRE_PROFILING_MODE
oal_module_symbol(g_oam_profiling_statistic_tx);
oal_module_symbol(g_oam_profiling_statistic_rx);
oal_module_symbol(oam_profiling_set_switch);
oal_module_symbol(oam_profiling_packet_add);

oal_module_symbol(oam_profiling_rx_save_data);
oal_module_symbol(oam_profiling_rx_show_offset);
oal_module_symbol(oam_profiling_tx_save_data);
oal_module_symbol(oam_profiling_tx_show_offset);
oal_module_symbol(oam_profiling_alg_save_data);
oal_module_symbol(oam_profiling_alg_show_offset);

oal_module_symbol(oam_profiling_starttime_save_timestamp);
oal_module_symbol(oam_profiling_starttime_show_offset);

oal_module_symbol(oam_profiling_chswitch_save_timestamp);
oal_module_symbol(oam_profiling_chswitch_show_offset);
#endif
