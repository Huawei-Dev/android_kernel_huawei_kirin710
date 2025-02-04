


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


/*****************************************************************************
  1 ??????????
*****************************************************************************/
#include "platform_spec.h"
#include "oal_mem.h"
#include "oal_main.h"

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
#include "oam_ext_if.h"
#endif


#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
#undef  THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_OAL_MEM_C
#else
#undef  THIS_FILE_ID
#define THIS_FILE_ID 0
#endif

/*****************************************************************************
  2 ??????
*****************************************************************************/


/*****************************************************************************
  2 ??????????
*****************************************************************************/
/*****************************************************************************
  ??????  : oal_mem_subpool_stat
  ????????: ????????????????????????????
*****************************************************************************/
typedef struct
{
    oal_uint16   us_free_cnt;    /* ?????????????????????? */
    oal_uint16   us_total_cnt;   /* ???????????????????? */
}oal_mem_subpool_stat;

/*****************************************************************************
  ??????  : oal_mem_pool_stat
  ????????: ??????????????????????????????
*****************************************************************************/
typedef struct
{
    oal_uint16             us_mem_used_cnt;    /* ?????????????????? */
    oal_uint16             us_mem_total_cnt;   /* ???????????????????????? */

    oal_mem_subpool_stat   ast_subpool_stat[WLAN_MEM_MAX_SUBPOOL_NUM];
}oal_mem_pool_stat;

/*****************************************************************************
  ??????  : oal_mem_stat
  ????????: ??????????????????????????
*****************************************************************************/
typedef struct
{
    oal_mem_pool_stat ast_mem_start_stat[OAL_MEM_POOL_ID_BUTT];   /* ???????????? */
    oal_mem_pool_stat ast_mem_end_stat[OAL_MEM_POOL_ID_BUTT];     /* ???????????? */
}oal_mem_stat;


/*****************************************************************************
  3 ????????????
*****************************************************************************/
/* ?????????????????????????????????????? */
#ifdef _PRE_WLAN_CACHE_COHERENT_SUPPORT
oal_uint32 gul_dscr_fstvirt_addr = 0;
oal_uint32 gul_dscr_fstphy_addr = 0;
#endif

/******************************************************************************
    ????????????????????????????????
*******************************************************************************/
OAL_STATIC oal_mem_stat g_st_mem_stat;
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
oal_mempool_info_to_sdt_stru    g_st_mempool_info = {
    .p_mempool_info_func  = NULL,
    .p_memblock_info_func = NULL
};
#else
oal_mempool_info_to_sdt_stru    g_st_mempool_info = {NULL, NULL};
#endif
#ifdef _PRE_DEBUG_MODE
OAL_STATIC oal_mempool_tx_dscr_addr    g_st_tx_dscr_addr;
#endif
/******************************************************************************
    ????????????????????????????????
*******************************************************************************/
OAL_STATIC  oal_mem_subpool_cfg_stru g_ast_shared_dscr_cfg_table[] =
{
    {WLAN_MEM_SHARED_RX_DSCR_SIZE  + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE,  WLAN_MEM_SHARED_RX_DSCR_CNT},   /* ???????????????????? */
    {WLAN_MEM_SHARED_TX_DSCR_SIZE1 + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE, WLAN_MEM_SHARED_TX_DSCR_CNT1},  /* ???????????????????? */
    {WLAN_MEM_SHARED_TX_DSCR_SIZE2 + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE, WLAN_MEM_SHARED_TX_DSCR_CNT2},  /* ???????????????????? */
};

/******************************************************************************
    ????????????????????????????????
*******************************************************************************/
OAL_STATIC  oal_mem_subpool_cfg_stru g_ast_shared_mgmt_cfg_table[] =
{
    {WLAN_MEM_SHARED_MGMT_PKT_SIZE1 + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE, WLAN_MEM_SHARED_MGMT_PKT_CNT1},   /* beacon??Probe Response??Auth Seq3???????????? */
};

/******************************************************************************
    ????????????????????????????????
*******************************************************************************/
OAL_STATIC  oal_mem_subpool_cfg_stru g_ast_shared_data_cfg_table[] =
{
    {WLAN_MEM_SHARED_DATA_PKT_SIZE + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE, WLAN_MEM_SHARED_DATA_PKT_CNT}  /* 802.11MAC????+SNAP??+Ethernet???????? */
};

/******************************************************************************
    ??????????????????????????????
*******************************************************************************/
#define TOTAL_WLAN_MEM_LOCAL_SIZE1  (WLAN_MEM_LOCAL_SIZE1 + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE)
#define TOTAL_WLAN_MEM_LOCAL_SIZE2  (WLAN_MEM_LOCAL_SIZE2 + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE)
#define TOTAL_WLAN_MEM_LOCAL_SIZE3  (WLAN_MEM_LOCAL_SIZE3 + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE)
#define TOTAL_WLAN_MEM_LOCAL_SIZE4  (WLAN_MEM_LOCAL_SIZE4 + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE)
#define TOTAL_WLAN_MEM_LOCAL_SIZE5  (WLAN_MEM_LOCAL_SIZE5 + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE)
#define TOTAL_WLAN_MEM_LOCAL_SIZE6  (WLAN_MEM_LOCAL_SIZE6 + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE)
#define TOTAL_WLAN_MEM_LOCAL_SIZE   (TOTAL_WLAN_MEM_LOCAL_SIZE1*WLAN_MEM_LOCAL_CNT1 \
                                    + TOTAL_WLAN_MEM_LOCAL_SIZE2*WLAN_MEM_LOCAL_CNT2 \
                                    + TOTAL_WLAN_MEM_LOCAL_SIZE3*WLAN_MEM_LOCAL_CNT3 \
                                    + TOTAL_WLAN_MEM_LOCAL_SIZE4*WLAN_MEM_LOCAL_CNT4 \
                                    + TOTAL_WLAN_MEM_LOCAL_SIZE5*WLAN_MEM_LOCAL_CNT5 \
                                    + TOTAL_WLAN_MEM_LOCAL_SIZE6*WLAN_MEM_LOCAL_CNT6)
OAL_STATIC  oal_mem_subpool_cfg_stru g_ast_local_cfg_table[] =
{
    {TOTAL_WLAN_MEM_LOCAL_SIZE1, WLAN_MEM_LOCAL_CNT1},  /* ???????????????? */
    {TOTAL_WLAN_MEM_LOCAL_SIZE2, WLAN_MEM_LOCAL_CNT2},   /* ???????????????? */
    {TOTAL_WLAN_MEM_LOCAL_SIZE3, WLAN_MEM_LOCAL_CNT3},
    {TOTAL_WLAN_MEM_LOCAL_SIZE4, WLAN_MEM_LOCAL_CNT4},
    {TOTAL_WLAN_MEM_LOCAL_SIZE5, WLAN_MEM_LOCAL_CNT5},
    {TOTAL_WLAN_MEM_LOCAL_SIZE6, WLAN_MEM_LOCAL_CNT6},
};

/*????????????????????*/
#if (TOTAL_WLAN_MEM_LOCAL_SIZE1 % OAL_MEM_INFO_SIZE)
#error alignment fault error
#endif
#if (TOTAL_WLAN_MEM_LOCAL_SIZE2 % OAL_MEM_INFO_SIZE)
#error alignment fault error
#endif
#if (TOTAL_WLAN_MEM_LOCAL_SIZE3 % OAL_MEM_INFO_SIZE)
#error alignment fault error
#endif
#if (TOTAL_WLAN_MEM_LOCAL_SIZE4 % OAL_MEM_INFO_SIZE)
#error alignment fault error
#endif
#if (TOTAL_WLAN_MEM_LOCAL_SIZE5 % OAL_MEM_INFO_SIZE)
#error alignment fault error
#endif
#if (TOTAL_WLAN_MEM_LOCAL_SIZE6 % OAL_MEM_INFO_SIZE)
#error alignment fault error
#endif

/******************************************************************************
    ??????????????????????????
*******************************************************************************/
#define TOTAL_WLAN_MEM_EVENT_SIZE1 (WLAN_MEM_EVENT_SIZE1 + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE)
#define TOTAL_WLAN_MEM_EVENT_SIZE2 (WLAN_MEM_EVENT_SIZE2 + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE)
#define TOTAL_WLAN_MEM_EVENT_SIZE  (TOTAL_WLAN_MEM_EVENT_SIZE1*WLAN_MEM_EVENT_CNT1 \
                                   + TOTAL_WLAN_MEM_EVENT_SIZE2*WLAN_MEM_EVENT_CNT2)
OAL_STATIC  oal_mem_subpool_cfg_stru g_ast_event_cfg_table[] =
{
    {TOTAL_WLAN_MEM_EVENT_SIZE1, WLAN_MEM_EVENT_CNT1},
    {TOTAL_WLAN_MEM_EVENT_SIZE2, WLAN_MEM_EVENT_CNT2},
};

#if (TOTAL_WLAN_MEM_EVENT_SIZE1 % OAL_MEM_INFO_SIZE)
#error alignment fault error
#endif
#if (TOTAL_WLAN_MEM_EVENT_SIZE2 % OAL_MEM_INFO_SIZE)
#error alignment fault error
#endif

/******************************************************************************
    MIB??????????????????????
*******************************************************************************/
#define TOTAL_WLAN_MEM_MIB_SIZE1    (WLAN_MEM_MIB_SIZE1 + OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE)
#define TOTAL_WLAN_MEM_MIB_SIZE     (TOTAL_WLAN_MEM_MIB_SIZE1*WLAN_MEM_MIB_CNT1)

OAL_STATIC  oal_mem_subpool_cfg_stru g_ast_mib_cfg_table[] =
{
    {TOTAL_WLAN_MEM_MIB_SIZE1, WLAN_MEM_MIB_CNT1},
};

#if (TOTAL_WLAN_MEM_MIB_SIZE1 % OAL_MEM_INFO_SIZE)
#error alignment fault error
#endif

/******************************************************************************
    netbuf??????????????????????
*******************************************************************************/
#define TOTAL_WLAN_MEM_NETBUF_SIZE1 (WLAN_MEM_NETBUF_SIZE1 + OAL_NETBUF_MAINTAINS_SIZE + OAL_DOG_TAG_SIZE)
#define TOTAL_WLAN_MEM_NETBUF_SIZE2 (WLAN_MEM_NETBUF_SIZE2 + OAL_NETBUF_MAINTAINS_SIZE + OAL_DOG_TAG_SIZE)
#define TOTAL_WLAN_MEM_NETBUF_SIZE3 (WLAN_MEM_NETBUF_SIZE3 + OAL_NETBUF_MAINTAINS_SIZE + OAL_DOG_TAG_SIZE)

 oal_mem_subpool_cfg_stru g_ast_netbuf_cfg_table[] =
{
    {TOTAL_WLAN_MEM_NETBUF_SIZE1, WLAN_MEM_NETBUF_CNT1},      /* ??????netbuf */
    {TOTAL_WLAN_MEM_NETBUF_SIZE2, WLAN_MEM_NETBUF_CNT2},
    {TOTAL_WLAN_MEM_NETBUF_SIZE3, WLAN_MEM_NETBUF_CNT3}
};

/******************************************************************************
    sdt netbuf??????????????????????
*******************************************************************************/
#define TOTAL_WLAN_MEM_SDT_NETBUF_SIZE1 (WLAN_MEM_SDT_NETBUF_SIZE1 + OAL_MEM_INFO_SIZE)
#define TOTAL_WLAN_MEM_SDT_NETBUF_SIZE2 (WLAN_MEM_SDT_NETBUF_SIZE2 + OAL_MEM_INFO_SIZE)
#define TOTAL_WLAN_MEM_SDT_NETBUF_SIZE3 (WLAN_MEM_SDT_NETBUF_SIZE3 + OAL_MEM_INFO_SIZE)
#define TOTAL_WLAN_MEM_SDT_NETBUF_SIZE4 (WLAN_MEM_SDT_NETBUF_SIZE4 + OAL_MEM_INFO_SIZE)
OAL_STATIC  oal_mem_subpool_cfg_stru g_ast_sdt_netbuf_cfg_table[] =
{
    {TOTAL_WLAN_MEM_SDT_NETBUF_SIZE1, WLAN_MEM_SDT_NETBUF_SIZE1_CNT},
    {TOTAL_WLAN_MEM_SDT_NETBUF_SIZE2, WLAN_MEM_SDT_NETBUF_SIZE2_CNT},
    {TOTAL_WLAN_MEM_SDT_NETBUF_SIZE3, WLAN_MEM_SDT_NETBUF_SIZE3_CNT},
    {TOTAL_WLAN_MEM_SDT_NETBUF_SIZE4, WLAN_MEM_SDT_NETBUF_SIZE4_CNT},
};

/******************************************************************************
    ??????????????????????????
*******************************************************************************/
OAL_STATIC  oal_mem_pool_cfg_stru g_ast_mem_pool_cfg_table[] =
{
    /*       ??????ID                           ??????????????????               ??????????      ?????????????? */
    {OAL_MEM_POOL_ID_EVENT,           OAL_ARRAY_SIZE(g_ast_event_cfg_table),       {0, 0}, g_ast_event_cfg_table},
    {OAL_MEM_POOL_ID_SHARED_DATA_PKT, OAL_ARRAY_SIZE(g_ast_shared_data_cfg_table), {0, 0}, g_ast_shared_data_cfg_table},
    {OAL_MEM_POOL_ID_SHARED_MGMT_PKT, OAL_ARRAY_SIZE(g_ast_shared_mgmt_cfg_table), {0, 0}, g_ast_shared_mgmt_cfg_table},
    {OAL_MEM_POOL_ID_LOCAL,           OAL_ARRAY_SIZE(g_ast_local_cfg_table),       {0, 0}, g_ast_local_cfg_table},
    {OAL_MEM_POOL_ID_MIB,             OAL_ARRAY_SIZE(g_ast_mib_cfg_table),         {0, 0}, g_ast_mib_cfg_table},
    {OAL_MEM_POOL_ID_SHARED_DSCR,     OAL_ARRAY_SIZE(g_ast_shared_dscr_cfg_table), {0, 0}, g_ast_shared_dscr_cfg_table},
    {OAL_MEM_POOL_ID_SDT_NETBUF,      OAL_ARRAY_SIZE(g_ast_sdt_netbuf_cfg_table),  {0, 0}, g_ast_sdt_netbuf_cfg_table}
};

#ifdef WIN32
OAL_STATIC oal_uint8 *g_pauc_mem_pool[OAL_MEM_POOL_ID_BUTT] = {0};
OAL_STATIC oal_uint8 g_auc_mem_pool_event[TOTAL_WLAN_MEM_EVENT_SIZE];
OAL_STATIC oal_uint8 g_auc_mem_pool_shared_data_pkt[TOTAL_WLAN_MEM_SHARED_DATA_PKT_SIZE];
OAL_STATIC oal_uint8 g_auc_mem_pool_shared_mgmt_pkt[TOTAL_WLAN_MEM_SHARED_MGMT_PKT_SIZE];
OAL_STATIC oal_uint8 g_auc_mem_pool_local[TOTAL_WLAN_MEM_LOCAL_SIZE];
OAL_STATIC oal_uint8 g_auc_mem_pool_mib[TOTAL_WLAN_MEM_MIB_SIZE];
OAL_STATIC oal_uint8 g_auc_mem_pool_shared_dscr[TOTAL_WLAN_MEM_SHARED_DSCR_SIZE];
#else
OAL_STATIC oal_uint8 *g_pauc_mem_pool[OAL_MEM_POOL_ID_BUTT] = {0};
OAL_STATIC oal_uint8 g_auc_mem_pool_event[TOTAL_WLAN_MEM_EVENT_SIZE] __attribute__((aligned(8)));
OAL_STATIC oal_uint8 g_auc_mem_pool_shared_data_pkt[TOTAL_WLAN_MEM_SHARED_DATA_PKT_SIZE] __attribute__((aligned(8)));
OAL_STATIC oal_uint8 g_auc_mem_pool_shared_mgmt_pkt[TOTAL_WLAN_MEM_SHARED_MGMT_PKT_SIZE] __attribute__((aligned(8)));
OAL_STATIC oal_uint8 g_auc_mem_pool_local[TOTAL_WLAN_MEM_LOCAL_SIZE] __attribute__((aligned(8)));
OAL_STATIC oal_uint8 g_auc_mem_pool_mib[TOTAL_WLAN_MEM_MIB_SIZE] __attribute__((aligned(8)));
OAL_STATIC oal_uint8 g_auc_mem_pool_shared_dscr[TOTAL_WLAN_MEM_SHARED_DSCR_SIZE] __attribute__((aligned(8)));
#endif
/******************************************************************************
    ????????netbuf??????????????ID??????????
*******************************************************************************/
OAL_STATIC oal_uint32 g_ul_truesize_to_pool_id[OAL_ARRAY_SIZE(g_ast_netbuf_cfg_table)] = {0};

/******************************************************************************
    ????????sdt netbuf??????????????ID??????????
*******************************************************************************/
OAL_STATIC oal_uint32 g_ul_truesize_to_pool_id_sdt[OAL_ARRAY_SIZE(g_ast_sdt_netbuf_cfg_table)] = {0};

/******************************************************************************
    netbuf??????data??????????head??????????
*******************************************************************************/
//OAL_STATIC oal_uint32 g_ul_netbuf_def_data_offset[OAL_ARRAY_SIZE(g_ast_netbuf_cfg_table)] = {0};

/******************************************************************************
    netbuf??????data??????????head??????????
*******************************************************************************/
oal_uint32 g_ul_sdt_netbuf_def_data_offset[OAL_ARRAY_SIZE(g_ast_sdt_netbuf_cfg_table)] = {0};


/******************************************************************************
    ????????????????????????????????????????????????????
    ??????????????????????????????????????????
*******************************************************************************/
OAL_STATIC oal_mem_pool_stru g_ast_mem_pool[OAL_MEM_POOL_ID_BUTT];

/******************************************************************************
    malloc????????????
*******************************************************************************/
OAL_STATIC oal_uint8 *g_pauc_pool_base_addr[OAL_MEM_POOL_ID_BUTT] = {OAL_PTR_NULL};

/******************************************************************************
    netbuf??????????????
*******************************************************************************/
//OAL_STATIC oal_netbuf_stru **g_ppst_netbuf_stack_mem;

/******************************************************************************
    sdt netbuf??????????????
*******************************************************************************/
OAL_STATIC oal_netbuf_stru **g_ppst_sdt_netbuf_stack_mem;

/* ???????????? */
#define OAL_MEM_BLK_TOTAL_CNT   (WLAN_MEM_SHARED_RX_DSCR_CNT + WLAN_MEM_SHARED_TX_DSCR_CNT1 + WLAN_MEM_SHARED_TX_DSCR_CNT2 +\
                                 WLAN_MEM_SHARED_MGMT_PKT_CNT1 + \
                                 WLAN_MEM_SHARED_DATA_PKT_CNT + \
                                 WLAN_MEM_LOCAL_CNT1 + WLAN_MEM_LOCAL_CNT2 + WLAN_MEM_LOCAL_CNT3 + WLAN_MEM_LOCAL_CNT4 + WLAN_MEM_LOCAL_CNT5 +\
                                 WLAN_MEM_LOCAL_CNT6 + \
                                 WLAN_MEM_EVENT_CNT1 + \
                                 WLAN_MEM_EVENT_CNT2 + \
                                 WLAN_MEM_MIB_CNT1)

/* ?????????????????? + ???????????? */
#define OAL_MEM_CTRL_BLK_SIZE   (OAL_SIZEOF(oal_mem_stru *) + OAL_SIZEOF(oal_mem_stru))

/* netbuf?????????? */
#define OAL_MEM_NETBUF_BLK_TOTAL_CNT    (WLAN_MEM_NETBUF_CNT1 + WLAN_MEM_NETBUF_CNT2 + WLAN_MEM_NETBUF_CNT3)

/* sdt netbuf?????????? */
#define OAL_MEM_SDT_NETBUF_BLK_TOTAL_CNT    (WLAN_MEM_SDT_NETBUF_SIZE1_CNT + WLAN_MEM_SDT_NETBUF_SIZE2_CNT +\
                                             WLAN_MEM_SDT_NETBUF_SIZE3_CNT + WLAN_MEM_SDT_NETBUF_SIZE4_CNT)

/* netbuf???????????? * 2 */
#define OAL_MEM_NETBUF_CTRL_BLK_SIZE    (OAL_SIZEOF(oal_netbuf_stru *) * 2)


/* ???????????????????? */
#define OAL_MEM_CTRL_BLK_TOTAL_SIZE  (OAL_MEM_BLK_TOTAL_CNT * OAL_MEM_CTRL_BLK_SIZE + \
                                      OAL_MEM_NETBUF_BLK_TOTAL_CNT * OAL_MEM_NETBUF_CTRL_BLK_SIZE + \
                                      OAL_MEM_SDT_NETBUF_BLK_TOTAL_CNT * OAL_MEM_NETBUF_CTRL_BLK_SIZE)


OAL_STATIC oal_netbuf_stru *g_pst_netbuf_base_addr[OAL_MEM_NETBUF_BLK_TOTAL_CNT] = {OAL_PTR_NULL};

OAL_STATIC oal_netbuf_stru *g_pst_sdt_netbuf_base_addr[OAL_MEM_SDT_NETBUF_BLK_TOTAL_CNT] = {OAL_PTR_NULL};

/*****************************************************************************
  ??????  : oal_mem_ctrl_blk_stru
  ????????: ????????????????????????????????
*****************************************************************************/
typedef struct
{
    oal_uint8  auc_base_addr[OAL_MEM_CTRL_BLK_TOTAL_SIZE];
    oal_uint32 ul_idx;
}oal_mem_ctrl_blk_stru;

/******************************************************************************
    ??????????????????????????????????????????????????????????????
    ??????oal_mem_ctrl_blk_alloc????
*******************************************************************************/
OAL_STATIC oal_mem_ctrl_blk_stru g_st_ctrl_blk;

/*****************************************************************************
  4 ??????
*****************************************************************************/
/* ?????????????????? */
#define OAL_MEM_MAX_WORD_ALIGNMENT_BUFFER         3

/* ????enhanced????????????????????????????????????????????????4???????????? */
/* ????????????????????????oal_mem_struc????????????????????????????         */
/*                                                                           */
/* +-------------------+---------------------------------------------------+ */
/* | oal_mem_stru addr |                    payload                        | */
/* +-------------------+---------------------------------------------------+ */
/* |      4 byte       |                                                   | */
/* +-------------------+---------------------------------------------------+ */
/* #define OAL_MEM_INFO_SIZE    4                                            */

/* ?????????? */
#define OAL_MEM_SPIN_LOCK_BH(_st_spinlock)  \
    {                                       \
        oal_spin_lock_bh(&_st_spinlock);    \
    }

/* ?????????? */
#define OAL_MEM_SPIN_UNLOCK_BH(_st_spinlock)   \
    {                                          \
        oal_spin_unlock_bh(&_st_spinlock);     \
    }

/* ??????????(??????) */
#define OAL_MEM_SPIN_LOCK_IRQSAVE(_st_spinlock, _ul_flag)   \
    {                                                       \
        oal_spin_lock_irq_save(&_st_spinlock, &_ul_flag);   \
    }

/* ??????????(??????) */
#define OAL_MEM_SPIN_UNLOCK_IRQRESTORE(_st_spinlock, _ul_flag)  \
    {                                                           \
        oal_spin_unlock_irq_restore(&_st_spinlock, &_ul_flag);  \
    }

/*****************************************************************************
  5 ????????
*****************************************************************************/


OAL_STATIC oal_void  oal_mem_init_ctrl_blk(oal_void)
{
    g_st_ctrl_blk.ul_idx = 0;
}


OAL_STATIC oal_uint8* oal_mem_ctrl_blk_alloc(oal_uint32 ul_size)
{
    oal_uint8 *puc_alloc;

    ul_size = OAL_GET_4BYTE_ALIGN_VALUE(ul_size);

    if ((g_st_ctrl_blk.ul_idx + ul_size) > OAL_MEM_CTRL_BLK_TOTAL_SIZE)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_ctrl_blk_alloc, not_enough memory!\n",
                     __FILE__, __LINE__);
        return OAL_PTR_NULL;
    }

    puc_alloc = g_st_ctrl_blk.auc_base_addr + g_st_ctrl_blk.ul_idx;
    g_st_ctrl_blk.ul_idx += ul_size;

    return puc_alloc;
}


oal_mem_pool_stru* oal_mem_get_pool(oal_mem_pool_id_enum_uint8 en_pool_id)
{
    if (OAL_UNLIKELY(en_pool_id >= OAL_MEM_POOL_ID_BUTT))
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_get_pool, array overflow!\n",
                     __FILE__, __LINE__);
        return OAL_PTR_NULL;
    }

    return &g_ast_mem_pool[en_pool_id];
}

#ifdef _PRE_DEBUG_MODE

oal_mempool_tx_dscr_addr* oal_mem_get_tx_dscr_addr(oal_void)
{
    return &g_st_tx_dscr_addr;
}

oal_void oal_mem_stop_rcd_rls(oal_void)
{
    if (0 == g_st_tx_dscr_addr.us_rcd_rls_stop_flag)
    {
        g_st_tx_dscr_addr.us_rcd_rls_stop_flag = 1;
    }
}

oal_uint16 oal_mem_get_stop_flag(oal_void)
{
    return (g_st_tx_dscr_addr.us_rcd_rls_stop_flag >= OAL_TX_DSCR_RCD_TAIL_CNT);
}
#endif

oal_mem_pool_cfg_stru* oal_mem_get_pool_cfg_table(oal_mem_pool_id_enum_uint8 en_pool_id)
{
    if (OAL_UNLIKELY(en_pool_id >= OAL_MEM_POOL_ID_BUTT))
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_get_pool_cfg_table, array overflow!\n",
                     __FILE__, __LINE__);
        return OAL_PTR_NULL;
    }

    return &g_ast_mem_pool_cfg_table[en_pool_id];
}


OAL_STATIC oal_netbuf_stru* oal_mem_find_available_netbuf(oal_mem_subpool_stru *pst_mem_subpool, oal_mem_pool_id_enum en_netbuf_id)
{
    oal_netbuf_stru   *pst_netbuf = OAL_PTR_NULL;
    oal_uint16         us_top;
    oal_uint16         us_loop;
    oal_uint16         us_has_popped_netbuf = 0;
    oal_netbuf_stru  **ppst_netbuf_stack_mem;

    us_top = pst_mem_subpool->us_free_cnt;

    if (OAL_MEM_POOL_ID_SDT_NETBUF == en_netbuf_id)
    {
        ppst_netbuf_stack_mem = g_ppst_sdt_netbuf_stack_mem;
    }
    else
    {
        return OAL_PTR_NULL;
    }

    while (0 != us_top)
    {
        us_top--;
        pst_netbuf = (oal_netbuf_stru *)pst_mem_subpool->ppst_free_stack[us_top];
        if (1 == oal_netbuf_read_user(pst_netbuf))
        {
            break;
        }

        /* ????netbuf??????????????1??????????????netbuf?????????????? */
        ppst_netbuf_stack_mem[us_has_popped_netbuf++] = pst_netbuf;
    }

    /* ??????????netbuf???????????????????? */
    for (us_loop = us_has_popped_netbuf; us_loop > 0; us_loop--)
    {
        pst_mem_subpool->ppst_free_stack[us_top++] = (oal_netbuf_stru *)ppst_netbuf_stack_mem[us_loop - 1];
    }

    /* ??????????netbuf????????????????????????????????????????????????????????????????????????(????Qdisc??????) */
    if (us_has_popped_netbuf == pst_mem_subpool->us_free_cnt)
    {
        return OAL_PTR_NULL;
    }

    /* ???????????????????????? */
    pst_mem_subpool->us_free_cnt--;

    return pst_netbuf;
}


oal_uint32  oal_mem_get_total_bytes_in_pool(
                oal_mem_pool_id_enum_uint8    en_pool_id,
                oal_uint32                   *pul_total_bytes)
{
    oal_uint16                       us_subpool_idx;
    oal_uint16                       us_size;
    oal_uint16                       us_cnt;
    oal_uint32                       ul_total_bytes;         /* ???????????????? */
    OAL_CONST oal_mem_pool_cfg_stru *pst_mem_pool_cfg;

    pst_mem_pool_cfg = oal_mem_get_pool_cfg_table(en_pool_id);
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mem_pool_cfg))
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_get_total_bytes_in_pool, pointer is NULL!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_GET_CFG_TBL_FAIL;
    }

    ul_total_bytes = 0;
    for (us_subpool_idx = 0; us_subpool_idx < pst_mem_pool_cfg->uc_subpool_cnt; us_subpool_idx++)
    {
        us_size = pst_mem_pool_cfg->pst_subpool_cfg_info[us_subpool_idx].us_size;
        us_cnt  = pst_mem_pool_cfg->pst_subpool_cfg_info[us_subpool_idx].us_cnt;

        ul_total_bytes += us_size * us_cnt;
    }

    *pul_total_bytes = ul_total_bytes;

    return OAL_SUCC;
}


OAL_STATIC oal_void  oal_mem_release(oal_void)
{
    oal_uint32  ul_pool_id;

#ifdef _PRE_WLAN_CACHE_COHERENT_SUPPORT
    oal_uint32    ul_ret;
    oal_uint32    ul_total_bytes  = 0;         /* ???????????????? */
#endif

    for (ul_pool_id = 0; ul_pool_id < OAL_MEM_POOL_ID_BUTT; ul_pool_id++)
    {
        if (OAL_PTR_NULL != g_pauc_pool_base_addr[ul_pool_id])
        {
#if 0
#ifdef _PRE_WLAN_CACHE_COHERENT_SUPPORT
            if(ul_pool_id == OAL_MEM_POOL_ID_SHARED_DSCR)
            {
                ul_ret = oal_mem_get_total_bytes_in_pool(OAL_MEM_POOL_ID_SHARED_DSCR, &ul_total_bytes);
                if (OAL_SUCC != ul_ret)
                {
                    OAL_IO_PRINT("[file = %s, line = %d], oal_mem_release, oal_mem_get_total_bytes_in_pool failed!\n",
                                 __FILE__, __LINE__);
                }
                /* free????????????????????????????????????????????????dma handler */
                oal_mem_uncache_free(ul_total_bytes, (oal_void*)gul_dscr_fstvirt_addr, gul_dscr_fstphy_addr);
            }
            else
#endif
            {
                oal_free((void *)g_pauc_pool_base_addr[ul_pool_id]);
            }
#endif
            g_pauc_pool_base_addr[ul_pool_id] = OAL_PTR_NULL;
        }
    }
}


OAL_STATIC oal_void  oal_mem_netbuf_release(oal_void)
{
    oal_uint32    ul_loop;

    for (ul_loop = 0; ul_loop < OAL_MEM_NETBUF_BLK_TOTAL_CNT; ul_loop++)
    {
        if (OAL_PTR_NULL == g_pst_netbuf_base_addr[ul_loop])
        {
            continue;
        }

        /* ????netbuf??????????????????????????????1 */
        oal_netbuf_set_user(g_pst_netbuf_base_addr[ul_loop], 1);

        oal_netbuf_free(g_pst_netbuf_base_addr[ul_loop]);

        g_pst_netbuf_base_addr[ul_loop] = OAL_PTR_NULL;
    }
}


OAL_STATIC oal_void  oal_mem_sdt_netbuf_release(oal_void)
{
    oal_uint32    ul_loop;

    for (ul_loop = 0; ul_loop < OAL_MEM_SDT_NETBUF_BLK_TOTAL_CNT; ul_loop++)
    {
        if (OAL_PTR_NULL == g_pst_sdt_netbuf_base_addr[ul_loop])
        {
            continue;
        }

        /* ????netbuf??????????????????????????????1 */
        oal_netbuf_set_user(g_pst_sdt_netbuf_base_addr[ul_loop], 1);

        oal_netbuf_free(g_pst_sdt_netbuf_base_addr[ul_loop]);

        g_pst_sdt_netbuf_base_addr[ul_loop] = OAL_PTR_NULL;
    }
}


oal_netbuf_stru* oal_netbuf_duplicate(oal_netbuf_stru* pst_src_netbuf,
											oal_uint8 uc_out_subpool_id,
											oal_uint32 ul_add_head_room,
											oal_uint32 ul_add_tail_room)
{
    oal_uint32 ul_dup_len = 0;
    oal_netbuf_stru* pst_dup_netbuf;

    OAL_BUG_ON(NULL == pst_src_netbuf);

    ul_dup_len += oal_netbuf_headroom(pst_src_netbuf);
    ul_dup_len += OAL_NETBUF_LEN(pst_src_netbuf);
    ul_dup_len += oal_netbuf_tailroom(pst_src_netbuf);
    ul_dup_len += ul_add_head_room;
    ul_dup_len += ul_add_tail_room;

    pst_dup_netbuf = OAL_MEM_NETBUF_ALLOC(uc_out_subpool_id, ul_dup_len,OAL_NETBUF_PRIORITY_MID);

    if(NULL == pst_dup_netbuf)
        return NULL;

    /*duplicate cb*/
    oal_memcopy((oal_void*)oal_netbuf_cb(pst_dup_netbuf),(oal_void*)oal_netbuf_cb(pst_src_netbuf),OAL_NETBUF_CB_SIZE());

    skb_reserve(pst_dup_netbuf,(oal_int32)oal_netbuf_headroom(pst_src_netbuf));
    oal_netbuf_put(pst_dup_netbuf, OAL_NETBUF_LEN(pst_src_netbuf));

    oal_memcopy((oal_void*)oal_netbuf_data(pst_dup_netbuf), (oal_void*)oal_netbuf_data(pst_src_netbuf), OAL_NETBUF_LEN(pst_src_netbuf));

    return pst_dup_netbuf;
}



OAL_STATIC oal_uint32  oal_mem_create_subpool(oal_mem_pool_id_enum_uint8 en_pool_id, oal_uint8 *puc_base_addr)
{
    oal_mem_pool_stru      *pst_mem_pool;
    oal_mem_subpool_stru   *pst_mem_subpool;
    oal_mem_stru           *pst_mem;
    oal_mem_stru          **ppst_stack_mem;
    oal_uint8               uc_subpool_id;
    oal_uint32              ul_blk_id;


    if (OAL_PTR_NULL == puc_base_addr)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_subpool, pointer is NULL!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_mem_pool = oal_mem_get_pool(en_pool_id);
    if (OAL_PTR_NULL == pst_mem_pool)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_subpool, pointer is NULL!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_GET_POOL_FAIL;
    }

    /* ?????????????????????????????????????????????????????????????????????? */
    ppst_stack_mem = (oal_mem_stru **)oal_mem_ctrl_blk_alloc(sizeof(oal_mem_stru *) * pst_mem_pool->us_mem_total_cnt);

    /* ?????????????????????????????????????????? */
    if (OAL_PTR_NULL == ppst_stack_mem)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_subpool, pointer is NULL!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_ALLOC_CTRL_BLK_FAIL;
    }

    /* ????oal_mem_stru?????????????????????????????????????????????????????? */
    pst_mem = (oal_mem_stru *)oal_mem_ctrl_blk_alloc(sizeof(oal_mem_stru) * pst_mem_pool->us_mem_total_cnt);

    /* ?????????????????????????????????????????? */
    if (OAL_PTR_NULL == pst_mem)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_subpool, pointer is NULL!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_ALLOC_CTRL_BLK_FAIL;
    }

    OAL_MEMZERO(ppst_stack_mem, sizeof(oal_mem_stru *) * pst_mem_pool->us_mem_total_cnt);
    OAL_MEMZERO((void *)pst_mem, sizeof(oal_mem_stru) * pst_mem_pool->us_mem_total_cnt);

    /* ????????????????oal_mem_stru?????????????????????????????? */
    pst_mem_pool->pst_mem_start_addr = pst_mem;

    /* ??????????????????????????????????????????????payload?????? */
    for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
    {
        /* ?????????????????????? */
        pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);

        /* ???????????????????????????????????????? */
        pst_mem_subpool->ppst_free_stack = (void **)ppst_stack_mem;

        for (ul_blk_id = 0; ul_blk_id < pst_mem_subpool->us_total_cnt; ul_blk_id++)
        {
            pst_mem->en_pool_id        = en_pool_id;
            pst_mem->uc_subpool_id     = uc_subpool_id;
            pst_mem->us_len            = pst_mem_subpool->us_len;
            pst_mem->en_mem_state_flag = OAL_MEM_STATE_FREE;
            pst_mem->uc_user_cnt       = 0;
            pst_mem->puc_origin_data   = puc_base_addr;       /* ????oal_mem_st??????payload?????? */
            pst_mem->puc_data          = pst_mem->puc_origin_data;

        #ifdef _PRE_DEBUG_MODE
            if ((uc_subpool_id > 0) && (OAL_MEM_POOL_ID_SHARED_DSCR == en_pool_id))
            {
                g_st_tx_dscr_addr.ul_tx_dscr_addr[g_st_tx_dscr_addr.us_tx_dscr_cnt++] = (oal_uint)(pst_mem->puc_data + OAL_MEM_INFO_SIZE);
            }

            OAL_MEMZERO(pst_mem->ul_alloc_core_id,    OAL_SIZEOF(oal_uint32) * WLAN_MEM_MAX_USERS_NUM);
            OAL_MEMZERO(pst_mem->ul_alloc_file_id,    OAL_SIZEOF(oal_uint32) * WLAN_MEM_MAX_USERS_NUM);
            OAL_MEMZERO(pst_mem->ul_alloc_line_num,   OAL_SIZEOF(oal_uint32) * WLAN_MEM_MAX_USERS_NUM);
            OAL_MEMZERO(pst_mem->ul_alloc_time_stamp, OAL_SIZEOF(oal_uint32) * WLAN_MEM_MAX_USERS_NUM);
            pst_mem->ul_trace_file_id    = 0;
            pst_mem->ul_trace_line_num   = 0;
            pst_mem->ul_trace_time_stamp = 0;
            /* ???????? */
            *((oal_uint32 *)(pst_mem->puc_origin_data + pst_mem->us_len - OAL_DOG_TAG_SIZE)) = (oal_uint32)OAL_DOG_TAG;
        #endif

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
            pst_mem->ul_return_addr  = 0;
#endif

           *ppst_stack_mem = pst_mem;
            ppst_stack_mem++;
            pst_mem++;

            puc_base_addr += pst_mem_subpool->us_len;
        }
    }

    return OAL_SUCC;
}

#if 0

OAL_STATIC oal_uint32  oal_mem_create_netbuf_subpool(oal_mem_pool_id_enum_uint8 en_pool_id)
{
    oal_mem_pool_stru      *pst_mem_pool;
    oal_mem_subpool_stru   *pst_mem_subpool;
    oal_netbuf_stru       **ppst_stack_mem;
    oal_netbuf_stru        *pst_netbuf;
    oal_uint8               uc_subpool_id;
    oal_uint32              ul_blk_id;
    oal_uint32              ul_mem_total_cnt;

    pst_mem_pool = oal_mem_get_pool(en_pool_id);
    if (OAL_PTR_NULL == pst_mem_pool)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_netbuf_subpool, pointer is NULL!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_GET_POOL_FAIL;
    }

    if(0 == pst_mem_pool->us_mem_total_cnt)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_netbuf_subpool, us_mem_total_cnt is zero,use kernel skb!\n",
                     __FILE__, __LINE__);
        return OAL_SUCC;
    }

    /* ?????????????????????????????????????????????????????????????????????? */
    ppst_stack_mem = (oal_netbuf_stru **)oal_mem_ctrl_blk_alloc(sizeof(oal_netbuf_stru *) * pst_mem_pool->us_mem_total_cnt);

    /* ?????????????????????????????????????????? */
    if (OAL_PTR_NULL == ppst_stack_mem)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_netbuf_subpool, pointer is NULL!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_ALLOC_CTRL_BLK_FAIL;
    }

    /* ?????????????????????????????????????????????? */
    g_ppst_netbuf_stack_mem = (oal_netbuf_stru **)oal_mem_ctrl_blk_alloc(sizeof(oal_netbuf_stru *) * pst_mem_pool->us_mem_total_cnt);
    if (OAL_PTR_NULL == g_ppst_netbuf_stack_mem)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_netbuf_subpool, pointer is NULL!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_ALLOC_CTRL_BLK_FAIL;
    }
    OAL_MEMZERO(g_ppst_netbuf_stack_mem, sizeof(oal_mem_stru *) * pst_mem_pool->us_mem_total_cnt);
    OAL_MEMZERO(ppst_stack_mem, sizeof(oal_mem_stru *) * pst_mem_pool->us_mem_total_cnt);

    ul_mem_total_cnt = 0;
    for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
    {
        /* ?????????????????????? */
        pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);

        /* ???????????????????????????????????????? */
        pst_mem_subpool->ppst_free_stack = (void **)ppst_stack_mem;

        for (ul_blk_id = 0; ul_blk_id < pst_mem_subpool->us_total_cnt; ul_blk_id++)
        {

            pst_netbuf = oal_netbuf_alloc(pst_mem_subpool->us_len + OAL_NETBUF_DEFAULT_HEADROOM, OAL_NETBUF_DEFAULT_HEADROOM, WLAN_MEM_NETBUF_ALIGN);
            if (OAL_UNLIKELY(OAL_PTR_NULL == pst_netbuf))
            {
                oal_mem_netbuf_release();
                OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_netbuf_subpool, pointer is NULL!\n",
                             __FILE__, __LINE__);
                return OAL_ERR_CODE_ALLOC_MEM_FAIL;
            }

        #ifdef _PRE_DEBUG_MODE
            /* ???????? */
            *((oal_uint32 *)(oal_netbuf_end(pst_netbuf) - OAL_NETBUF_MAINTAINS_SIZE - OAL_DOG_TAG_SIZE)) = (oal_uint32)OAL_DOG_TAG;
        #endif

            if (0 == ul_blk_id)
            {
                g_ul_truesize_to_pool_id[uc_subpool_id] = pst_netbuf->truesize;

                g_ul_netbuf_def_data_offset[uc_subpool_id] =
                                ((oal_uint32)pst_netbuf->data > (oal_uint32)pst_netbuf->head) ?
                                (oal_uint32)(pst_netbuf->data - pst_netbuf->head) : 0;
            }

            g_pst_netbuf_base_addr[ul_mem_total_cnt + ul_blk_id] = pst_netbuf;

            *ppst_stack_mem = pst_netbuf;
            ppst_stack_mem++;
        }

        ul_mem_total_cnt += pst_mem_subpool->us_total_cnt;
    }

    return OAL_SUCC;
}
#endif


OAL_STATIC oal_uint32  oal_mem_create_sdt_netbuf_subpool(oal_mem_pool_id_enum_uint8 en_pool_id)
{
    oal_mem_pool_stru      *pst_mem_pool;
    oal_mem_subpool_stru   *pst_mem_subpool;
    oal_netbuf_stru       **ppst_stack_mem;
    oal_netbuf_stru        *pst_netbuf;
    oal_uint8               uc_subpool_id;
    oal_uint32              ul_blk_id;
    oal_uint32              ul_mem_total_cnt;

    pst_mem_pool = oal_mem_get_pool(en_pool_id);
    if (OAL_PTR_NULL == pst_mem_pool)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_sdt_netbuf_subpool, pointer is NULL!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_GET_POOL_FAIL;
    }

    /* ?????????????????????????????????????????????????????????????????????? */
    ppst_stack_mem = (oal_netbuf_stru **)oal_mem_ctrl_blk_alloc(sizeof(oal_netbuf_stru *) * pst_mem_pool->us_mem_total_cnt);

    /* ?????????????????????????????????????????? */
    if (OAL_PTR_NULL == ppst_stack_mem)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_sdt_netbuf_subpool, pointer is NULL!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_ALLOC_CTRL_BLK_FAIL;
    }

    /* ?????????????????????????????????????????????? */
    g_ppst_sdt_netbuf_stack_mem = (oal_netbuf_stru **)oal_mem_ctrl_blk_alloc(sizeof(oal_netbuf_stru *) * pst_mem_pool->us_mem_total_cnt);
    if (OAL_PTR_NULL == g_ppst_sdt_netbuf_stack_mem)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_sdt_netbuf_subpool, pointer is NULL!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_ALLOC_CTRL_BLK_FAIL;
    }
    OAL_MEMZERO(g_ppst_sdt_netbuf_stack_mem, sizeof(oal_mem_stru *) * pst_mem_pool->us_mem_total_cnt);
    OAL_MEMZERO(ppst_stack_mem, sizeof(oal_mem_stru *) * pst_mem_pool->us_mem_total_cnt);

    ul_mem_total_cnt = 0;
    for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
    {
        /* ?????????????????????? */
        pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);

        /* ???????????????????????????????????????? */
        pst_mem_subpool->ppst_free_stack = (void **)ppst_stack_mem;

        for (ul_blk_id = 0; ul_blk_id < pst_mem_subpool->us_total_cnt; ul_blk_id++)
        {
            //pst_netbuf = oal_netbuf_alloc(pst_mem_subpool->us_len, 0, WLAN_MEM_NETBUF_ALIGN);
            pst_netbuf = OAL_MEM_NETBUF_ALLOC(OAL_NORMAL_NETBUF, pst_mem_subpool->us_len, OAL_NETBUF_PRIORITY_MID);
            if (OAL_UNLIKELY(OAL_PTR_NULL == pst_netbuf))
            {
                oal_mem_sdt_netbuf_release();
                OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_sdt_netbuf_subpool, alloc %u bytes, pointer is NULL!\n",
                             __FILE__, __LINE__, pst_mem_subpool->us_len);
                return OAL_ERR_CODE_ALLOC_MEM_FAIL;
            }

            if (0 == ul_blk_id)
            {
                g_ul_truesize_to_pool_id_sdt[uc_subpool_id] = pst_netbuf->truesize;

                g_ul_sdt_netbuf_def_data_offset[uc_subpool_id] =
                                ((oal_uint)pst_netbuf->data > (oal_uint)pst_netbuf->head) ?
                                (oal_uint)(pst_netbuf->data - pst_netbuf->head) : 0;
            }

            g_pst_sdt_netbuf_base_addr[ul_mem_total_cnt + ul_blk_id] = pst_netbuf;

            *ppst_stack_mem = pst_netbuf;
            ppst_stack_mem++;
        }

        ul_mem_total_cnt += pst_mem_subpool->us_total_cnt;
    }

    return OAL_SUCC;
}


OAL_STATIC oal_uint32  oal_mem_create_pool(oal_mem_pool_id_enum_uint8 en_pool_id, oal_uint8 *puc_base_addr)
{
    oal_uint8                           uc_subpool_id = 0;
    oal_uint8                           uc_subpool_cnt  = 0;
    oal_mem_pool_stru                  *pst_mem_pool;
    oal_mem_subpool_stru               *pst_mem_subpool;
    oal_uint32                          ul_ret;
    OAL_CONST oal_mem_pool_cfg_stru    *pst_mem_pool_cfg;
    OAL_CONST oal_mem_subpool_cfg_stru *pst_mem_subpool_cfg;

    /* ???????? */
    if (en_pool_id >= OAL_MEM_POOL_ID_BUTT)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_pool, array overflow!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_ARRAY_OVERFLOW;
    }

    pst_mem_pool = oal_mem_get_pool(en_pool_id);
    if (OAL_PTR_NULL == pst_mem_pool)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_pool, pointer is NULL!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_GET_POOL_FAIL;
    }

    pst_mem_pool_cfg = oal_mem_get_pool_cfg_table(en_pool_id);
    if (OAL_PTR_NULL == pst_mem_pool_cfg)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_pool, pointer is NULL!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_GET_CFG_TBL_FAIL;
    }

    /* ?????????????????????? */
    uc_subpool_cnt = pst_mem_pool_cfg->uc_subpool_cnt;

    pst_mem_pool->uc_subpool_cnt  = uc_subpool_cnt;
    pst_mem_pool->us_mem_used_cnt = 0;

    pst_mem_pool->us_max_byte_len = pst_mem_pool_cfg->pst_subpool_cfg_info[uc_subpool_cnt-1].us_size;
    if (pst_mem_pool->us_max_byte_len >= WLAN_MEM_MAX_BYTE_LEN)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_pool, exceeds the max length!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_EXCEED_MAX_LEN;
    }

    if (pst_mem_pool->uc_subpool_cnt > WLAN_MEM_MAX_SUBPOOL_NUM)
    {
        OAL_IO_PRINT("[file = %s, line = %d], oal_mem_create_pool, exceeds the max subpool number!\n",
                     __FILE__, __LINE__);
        return OAL_ERR_CODE_OAL_MEM_EXCEED_SUBPOOL_CNT;
    }

    /* ?????????????????? */
    OAL_MEMZERO((void *)pst_mem_pool->ast_subpool_table, sizeof(pst_mem_pool->ast_subpool_table));

    /* ?????????????????? */
    for (uc_subpool_id = 0; uc_subpool_id < uc_subpool_cnt; uc_subpool_id++)
    {
        pst_mem_subpool_cfg           = pst_mem_pool_cfg->pst_subpool_cfg_info + uc_subpool_id;
        pst_mem_subpool               = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);

        pst_mem_subpool->us_free_cnt  = pst_mem_subpool_cfg->us_cnt;
        pst_mem_subpool->us_total_cnt = pst_mem_subpool_cfg->us_cnt;
        pst_mem_subpool->us_len       = pst_mem_subpool_cfg->us_size;

        oal_spin_lock_init(&pst_mem_subpool->st_spinlock);

        pst_mem_pool->us_mem_total_cnt += pst_mem_subpool_cfg->us_cnt;   /* ?????????????? */
    }

    if (OAL_MEM_POOL_ID_SDT_NETBUF == en_pool_id)
    {
        /* ????sdt netbuf?????? */
        ul_ret = oal_mem_create_sdt_netbuf_subpool(en_pool_id);
    }
    else
    {
        /* ?????????????? */
        ul_ret = oal_mem_create_subpool(en_pool_id, puc_base_addr);
    }

    return ul_ret;
}


oal_void oal_mem_init_static_mem_map(oal_void)
{
    //????host ??????
    //OAL_MEM_POOL_ID_EVENT = 0,              /* ?????????? */
    //OAL_MEM_POOL_ID_SHARED_DATA_PKT,        /* ???????????????? */
    //OAL_MEM_POOL_ID_SHARED_MGMT_PKT,        /* ???????????????? */
    //OAL_MEM_POOL_ID_LOCAL,                  /* ??????????????  */
    //OAL_MEM_POOL_ID_MIB,                    /* MIB?????? */
    //OAL_MEM_POOL_ID_SHARED_DSCR,            /* ???????????????? */
    //OAL_MEM_POOL_ID_SDT_NETBUF,             /* SDT netbuf?????? */

    OAL_MEMZERO(g_auc_mem_pool_event, OAL_SIZEOF(g_auc_mem_pool_event));
    OAL_MEMZERO(g_auc_mem_pool_shared_data_pkt, OAL_SIZEOF(g_auc_mem_pool_shared_data_pkt));
    OAL_MEMZERO(g_auc_mem_pool_shared_mgmt_pkt, OAL_SIZEOF(g_auc_mem_pool_shared_mgmt_pkt));
    OAL_MEMZERO(g_auc_mem_pool_local, OAL_SIZEOF(g_auc_mem_pool_local));
    OAL_MEMZERO(g_auc_mem_pool_mib, OAL_SIZEOF(g_auc_mem_pool_mib));
    OAL_MEMZERO(g_auc_mem_pool_shared_dscr, OAL_SIZEOF(g_auc_mem_pool_shared_dscr));

    g_pauc_mem_pool[OAL_MEM_POOL_ID_EVENT]              = g_auc_mem_pool_event;
    g_pauc_mem_pool[OAL_MEM_POOL_ID_SHARED_DATA_PKT]    = g_auc_mem_pool_shared_data_pkt;
    g_pauc_mem_pool[OAL_MEM_POOL_ID_SHARED_MGMT_PKT]    = g_auc_mem_pool_shared_mgmt_pkt;
    g_pauc_mem_pool[OAL_MEM_POOL_ID_LOCAL]              = g_auc_mem_pool_local;
    g_pauc_mem_pool[OAL_MEM_POOL_ID_MIB]                = g_auc_mem_pool_mib;
    g_pauc_mem_pool[OAL_MEM_POOL_ID_SHARED_DSCR]        = g_auc_mem_pool_shared_dscr;
}


oal_uint32  oal_mem_init_pool(oal_void)
{
    oal_uint32    ul_total_bytes  = 0;         /* ???????????????? */
    oal_uint32    ul_pool_id      = 0;         /* ?????????????????? */
    oal_uint32    ul_ret;
    oal_uint8    *puc_base_addr;               /* ????malloc???????????????? */

    OAL_MEMZERO((oal_void *)g_ast_mem_pool, OAL_SIZEOF(g_ast_mem_pool));
    OAL_MEMZERO((oal_void *)g_pauc_pool_base_addr, OAL_SIZEOF(g_pauc_pool_base_addr));
#ifdef _PRE_DEBUG_MODE
    OAL_MEMZERO(&g_st_tx_dscr_addr, OAL_SIZEOF(g_st_tx_dscr_addr));
#endif

    /* ???????????????? */
    oal_mem_init_ctrl_blk();

    /* ?????????????????????? */
    oal_mem_init_static_mem_map();

    for (ul_pool_id = 0; ul_pool_id < OAL_MEM_POOL_ID_SDT_NETBUF; ul_pool_id++)
    {
#if 0
        ul_ret = oal_mem_get_total_bytes_in_pool((oal_uint8)ul_pool_id, &ul_total_bytes);
        if (OAL_SUCC != ul_ret)
        {
            OAL_IO_PRINT("[file = %s, line = %d], oal_mem_init_pool, oal_mem_get_total_bytes_in_pool failed!\n",
                         __FILE__, __LINE__);
            return ul_ret;
        }

#ifdef _PRE_WLAN_CACHE_COHERENT_SUPPORT
        if(ul_pool_id == OAL_MEM_POOL_ID_SHARED_DSCR)
        {
            puc_base_addr = (oal_uint8 *)oal_mem_uncache_alloc(ul_total_bytes + OAL_MEM_MAX_WORD_ALIGNMENT_BUFFER, &gul_dscr_fstphy_addr);
            gul_dscr_fstvirt_addr = (oal_uint32)puc_base_addr;
        }
        else
#endif
        {
            puc_base_addr = (oal_uint8 *)oal_memalloc(ul_total_bytes + OAL_MEM_MAX_WORD_ALIGNMENT_BUFFER);
        }
#else
        puc_base_addr = g_pauc_mem_pool[ul_pool_id];
#endif

        if (OAL_PTR_NULL == puc_base_addr)
        {
            oal_mem_release();
            OAL_IO_PRINT("[file = %s, line = %d], oal_mem_init_pool, memory allocation %u bytes fail!\n",
                         __FILE__, __LINE__, ul_total_bytes + OAL_MEM_MAX_WORD_ALIGNMENT_BUFFER);
            return OAL_ERR_CODE_ALLOC_MEM_FAIL;
        }

        /* ??????????????oal_malloc?????????? */
        g_pauc_pool_base_addr[ul_pool_id] = puc_base_addr;

        puc_base_addr = (oal_uint8 *)OAL_GET_4BYTE_ALIGN_VALUE((oal_uint)puc_base_addr);

        ul_ret = oal_mem_create_pool((oal_uint8)ul_pool_id, puc_base_addr);
        if (OAL_SUCC != ul_ret)
        {
            oal_mem_release();
            OAL_IO_PRINT("[file = %s, line = %d], oal_mem_init_pool, oal_mem_create_pool failed!\n",
                         __FILE__, __LINE__);
            return ul_ret;
        }
    }

    /* ????sdt netbuf?????? */
    return oal_mem_create_pool(OAL_MEM_POOL_ID_SDT_NETBUF, OAL_PTR_NULL);
}


oal_mem_stru* oal_mem_alloc_enhanced(
                oal_uint32                    ul_file_id,
                oal_uint32                    ul_line_num,
                oal_mem_pool_id_enum_uint8    en_pool_id,
                oal_uint16                    us_len,
                oal_uint8                     uc_lock)
{
    oal_mem_pool_stru    *pst_mem_pool;
    oal_mem_subpool_stru *pst_mem_subpool;
    oal_mem_stru         *pst_mem;
    oal_uint8             uc_subpool_id;
    oal_uint              ul_irq_flag = 0;

    /* ?????????? */
    pst_mem_pool = &g_ast_mem_pool[en_pool_id];

    us_len += OAL_DOG_TAG_SIZE;

    /* ????: ??????????????????????  */
    if (OAL_UNLIKELY(us_len > pst_mem_pool->us_max_byte_len))
    {
        return OAL_PTR_NULL;
    }

    pst_mem = OAL_PTR_NULL;

    for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
    {
        pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);

        OAL_MEM_SPIN_LOCK_IRQSAVE(pst_mem_subpool->st_spinlock, ul_irq_flag)
        if ((pst_mem_subpool->us_len < us_len) || (0 == pst_mem_subpool->us_free_cnt))
        {
            OAL_MEM_SPIN_UNLOCK_IRQRESTORE(pst_mem_subpool->st_spinlock, ul_irq_flag)
            continue;
        }

        /* ??????????????????oal_mem_stru???? */
        pst_mem_subpool->us_free_cnt--;
        pst_mem = (oal_mem_stru *)pst_mem_subpool->ppst_free_stack[pst_mem_subpool->us_free_cnt];

        pst_mem->puc_data          = pst_mem->puc_origin_data;
        pst_mem->uc_user_cnt       = 1;
        pst_mem->en_mem_state_flag = OAL_MEM_STATE_ALLOC;

        pst_mem_pool->us_mem_used_cnt++;

    #ifdef _PRE_DEBUG_MODE
        pst_mem->ul_alloc_core_id[pst_mem->uc_user_cnt - 1]    = OAL_GET_CORE_ID();
        pst_mem->ul_alloc_file_id[pst_mem->uc_user_cnt - 1]    = ul_file_id;
        pst_mem->ul_alloc_line_num[pst_mem->uc_user_cnt - 1]   = ul_line_num;
        pst_mem->ul_alloc_time_stamp[pst_mem->uc_user_cnt - 1] = (oal_uint32)OAL_TIME_GET_STAMP_MS();
    #endif

        OAL_MEM_SPIN_UNLOCK_IRQRESTORE(pst_mem_subpool->st_spinlock, ul_irq_flag)
        break;
    }

#ifdef _PRE_DEBUG_MODE
    if (OAL_PTR_NULL == pst_mem)
    {
        //oal_mem_info(en_pool_id);
        //oal_mem_leak(en_pool_id);
        //oal_dump_stack();
    }
#endif

    return pst_mem;
}


oal_uint32  oal_mem_free_enhanced(
                oal_uint32      ul_file_id,
                oal_uint32      ul_line_num,
                oal_mem_stru   *pst_mem,
                oal_uint8       uc_lock)
{
    oal_mem_pool_stru      *pst_mem_pool;
    oal_mem_subpool_stru   *pst_mem_subpool;
#ifdef _PRE_DEBUG_MODE
    oal_uint32              ul_dog_tag = 0;
#endif

    oal_uint              ul_irq_flag = 0;
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mem))
    {
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_mem_pool = &g_ast_mem_pool[pst_mem->en_pool_id];

    pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[pst_mem->uc_subpool_id]);

#ifdef _PRE_DEBUG_MODE
    if ((OAL_MEM_POOL_ID_SHARED_DSCR == pst_mem->en_pool_id) && (pst_mem->uc_subpool_id > 0) && (0 == oal_mem_get_stop_flag()))
    {
       g_st_tx_dscr_addr.us_released_tx_dscr_cnt %= OAL_TX_DSCR_ITEM_NUM;
       g_st_tx_dscr_addr.ast_tx_dscr_info[g_st_tx_dscr_addr.us_released_tx_dscr_cnt].ul_released_addr = (oal_uint)(pst_mem->puc_data);
       g_st_tx_dscr_addr.ast_tx_dscr_info[g_st_tx_dscr_addr.us_released_tx_dscr_cnt].ul_release_file_id = ul_file_id;
       g_st_tx_dscr_addr.ast_tx_dscr_info[g_st_tx_dscr_addr.us_released_tx_dscr_cnt].ul_release_line_num = ul_line_num;
       g_st_tx_dscr_addr.ast_tx_dscr_info[g_st_tx_dscr_addr.us_released_tx_dscr_cnt++].ul_release_ts = (oal_uint32)OAL_TIME_GET_STAMP_MS();
    }
#endif

    OAL_MEM_SPIN_LOCK_IRQSAVE(pst_mem_subpool->st_spinlock, ul_irq_flag)

    /* ????: ?????????? */
#ifdef _PRE_DEBUG_MODE
    ul_dog_tag = (*((oal_uint32 *)(pst_mem->puc_origin_data + pst_mem->us_len - OAL_DOG_TAG_SIZE)));
    if (OAL_DOG_TAG != ul_dog_tag)
    {
        /* ???????????? */
        /* *((oal_uint32 *)(pst_mem->puc_origin_data + pst_mem->us_len - OAL_DOG_TAG_SIZE)) = (oal_uint32)OAL_DOG_TAG; */
        OAL_MEM_SPIN_UNLOCK_IRQRESTORE(pst_mem_subpool->st_spinlock, ul_irq_flag)
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
        OAL_BUG_ON(1);
#endif
        return OAL_ERR_CODE_OAL_MEM_DOG_TAG;
    }
#endif

    /* ????: ???????????????????????? */
    if (OAL_UNLIKELY(OAL_MEM_STATE_FREE == pst_mem->en_mem_state_flag))
    {
        OAL_MEM_SPIN_UNLOCK_IRQRESTORE(pst_mem_subpool->st_spinlock, ul_irq_flag)
        return OAL_ERR_CODE_OAL_MEM_ALREADY_FREE;
    }

    /* ????: ??????????????????0?????? */
    if (OAL_UNLIKELY(0 == pst_mem->uc_user_cnt))
    {
        OAL_MEM_SPIN_UNLOCK_IRQRESTORE(pst_mem_subpool->st_spinlock, ul_irq_flag)
        return OAL_ERR_CODE_OAL_MEM_USER_CNT_ERR;
    }

#ifdef _PRE_DEBUG_MODE
    pst_mem->ul_alloc_core_id[pst_mem->uc_user_cnt - 1]    = 0;
    pst_mem->ul_alloc_file_id[pst_mem->uc_user_cnt - 1]    = ul_file_id;
    pst_mem->ul_alloc_line_num[pst_mem->uc_user_cnt - 1]   = ul_line_num;
    pst_mem->ul_alloc_time_stamp[pst_mem->uc_user_cnt - 1] = 0;
#endif

    pst_mem->uc_user_cnt--;

    /* ???????????????????????????????????????? */
    if (0 != pst_mem->uc_user_cnt)
    {
        OAL_MEM_SPIN_UNLOCK_IRQRESTORE(pst_mem_subpool->st_spinlock, ul_irq_flag)

        return OAL_SUCC;
    }

    /* ????: ?????????????????????????????????????????????????? */
    if (OAL_UNLIKELY(pst_mem_subpool->us_free_cnt >= pst_mem_subpool->us_total_cnt))
    {
        OAL_MEM_SPIN_UNLOCK_IRQRESTORE(pst_mem_subpool->st_spinlock, ul_irq_flag)

        return OAL_ERR_CODE_OAL_MEM_EXCEED_TOTAL_CNT;
    }

#ifdef _PRE_DEBUG_MODE
    pst_mem->ul_trace_file_id    = 0;
    pst_mem->ul_trace_line_num   = 0;
    pst_mem->ul_trace_time_stamp = 0;
#endif

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    pst_mem->ul_return_addr  = 0;
#endif


    pst_mem->en_mem_state_flag = OAL_MEM_STATE_FREE;

    pst_mem_subpool->ppst_free_stack[pst_mem_subpool->us_free_cnt] = (void *)pst_mem;
    pst_mem_subpool->us_free_cnt++;

    pst_mem_pool->us_mem_used_cnt--;

    OAL_MEM_SPIN_UNLOCK_IRQRESTORE(pst_mem_subpool->st_spinlock, ul_irq_flag)

    return OAL_SUCC;
}


OAL_INLINE oal_uint32  oal_mem_free_enhanced_array(
                oal_uint32      ul_file_id,
                oal_uint32      ul_line_num,
                oal_void       *p_data,
                oal_uint8       uc_mem_num)
{
    oal_mem_pool_stru    *pst_mem_pool    = OAL_PTR_NULL;
    oal_mem_subpool_stru *pst_mem_subpool = OAL_PTR_NULL;
    oal_mem_stru         *pst_mem         = OAL_PTR_NULL;
    oal_uint8   uc_index;
    oal_uint *past_mem;

    past_mem = (oal_uint *)p_data;

    for(uc_index = 0; uc_index < uc_mem_num; uc_index++)
    {
        pst_mem = (oal_mem_stru *)(*((oal_uint *)((oal_uint8 *)past_mem[uc_index] - OAL_MEM_INFO_SIZE)));
        if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mem))
        {
            continue;
        }

        /*pool????????????????*/
        if (OAL_PTR_NULL == pst_mem_pool)
        {
            pst_mem_pool = &g_ast_mem_pool[pst_mem->en_pool_id];
            pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[pst_mem->uc_subpool_id]);
        }

        /* ????: ???????????????????????? */
        if (OAL_UNLIKELY(OAL_MEM_STATE_FREE == pst_mem->en_mem_state_flag))
        {
            continue;
        }

#ifdef _PRE_DEBUG_MODE
        /* ????: ??????????????????0?????? */
        if (OAL_UNLIKELY(0 == pst_mem->uc_user_cnt))
        {
            continue;
        }

        pst_mem->ul_alloc_core_id[pst_mem->uc_user_cnt - 1]  = 0;
        pst_mem->ul_alloc_file_id[pst_mem->uc_user_cnt - 1]  = 0;
        pst_mem->ul_alloc_line_num[pst_mem->uc_user_cnt - 1] = 0;
#endif

		pst_mem->uc_user_cnt--;

#ifdef _PRE_DEBUG_MODE
        /* ???????????????????????????????????????? */
        if (OAL_UNLIKELY(0 != pst_mem->uc_user_cnt))
        {
            continue;
        }

        /*lint -e613*/
        /* ????: ?????????????????????????????????????????????????? */
        if (OAL_UNLIKELY(pst_mem_subpool->us_free_cnt >= pst_mem_subpool->us_total_cnt))   /* [false alarm]:fortify????  pst_mem_subpool??????NULL ????????????????????????????????*/
        {
            continue;
        }
        /*lint +e613*/
#endif

        pst_mem->en_mem_state_flag = OAL_MEM_STATE_FREE;
        /*lint -e613*/
        pst_mem_subpool->ppst_free_stack[pst_mem_subpool->us_free_cnt] = (void *)pst_mem;
        pst_mem_subpool->us_free_cnt++;
        /*lint +e613*/
        pst_mem_pool->us_mem_used_cnt--;

    }

    return OAL_SUCC;
}


oal_uint32  oal_mem_incr_user(
                oal_uint32      ul_file_id,
                oal_uint32      ul_line_num,
                oal_mem_stru   *pst_mem,
                oal_uint8       uc_lock)
{
    oal_mem_pool_stru      *pst_mem_pool;
    oal_mem_subpool_stru   *pst_mem_subpool;

    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mem))
    {
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_mem_pool = &g_ast_mem_pool[pst_mem->en_pool_id];

    pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[pst_mem->uc_subpool_id]);

    OAL_MEM_SPIN_LOCK_BH(pst_mem_subpool->st_spinlock)

    /* ????: ???????????????? */
    if (OAL_UNLIKELY(OAL_MEM_STATE_FREE == pst_mem->en_mem_state_flag))
    {
        OAL_MEM_SPIN_UNLOCK_BH(pst_mem_subpool->st_spinlock)

        return OAL_ERR_CODE_OAL_MEM_ALREADY_FREE;
    }

#ifdef _PRE_DEBUG_MODE
    /* ????: ???????????????????????????????? */
    if (OAL_UNLIKELY((oal_uint16)(pst_mem->uc_user_cnt + 1) > WLAN_MEM_MAX_USERS_NUM))
    {
        OAL_MEM_SPIN_UNLOCK_BH(pst_mem_subpool->st_spinlock)

        return OAL_ERR_CODE_OAL_MEM_USER_CNT_ERR;
    }
#endif

    pst_mem->uc_user_cnt++;

#ifdef _PRE_DEBUG_MODE
    pst_mem->ul_alloc_core_id[pst_mem->uc_user_cnt - 1]    = OAL_GET_CORE_ID();
    pst_mem->ul_alloc_file_id[pst_mem->uc_user_cnt - 1]    = ul_file_id;
    pst_mem->ul_alloc_line_num[pst_mem->uc_user_cnt - 1]   = ul_line_num;
    pst_mem->ul_alloc_time_stamp[pst_mem->uc_user_cnt - 1] = (oal_uint32)OAL_TIME_GET_STAMP_MS();
#endif

    OAL_MEM_SPIN_UNLOCK_BH(pst_mem_subpool->st_spinlock)

    return OAL_SUCC;
}


oal_void* oal_mem_alloc(
                oal_uint32                    ul_file_id,
                oal_uint32                    ul_line_num,
                oal_mem_pool_id_enum_uint8    en_pool_id,
                oal_uint16                    us_len,
                oal_uint8                     uc_lock)
{
    oal_mem_stru *pst_mem;

    /* ????: ???????????? */
    if (OAL_UNLIKELY(0 == us_len))
    {
        return OAL_PTR_NULL;
    }

    us_len += OAL_MEM_INFO_SIZE;

    pst_mem = oal_mem_alloc_enhanced(ul_file_id, ul_line_num, en_pool_id, us_len, uc_lock);
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mem))
    {
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
        if(OAL_MEM_POOL_ID_SHARED_DSCR > en_pool_id)
        {
            oal_mem_print_normal_pool_info(en_pool_id);
        }
#endif

        return OAL_PTR_NULL;
    }

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
     pst_mem->ul_return_addr  = oal_get_func_return_address();
#endif

    pst_mem->puc_data = pst_mem->puc_origin_data + OAL_MEM_INFO_SIZE;

    *((oal_uint *)(pst_mem->puc_data - OAL_MEM_INFO_SIZE)) = (oal_uint)pst_mem;

    return (oal_void *)pst_mem->puc_data;
}


oal_uint32  oal_mem_free(
                oal_uint32    ul_file_id,
                oal_uint32    ul_line_num,
                oal_void     *p_data,
                oal_uint8     uc_lock)
{
    oal_mem_stru   *pst_mem;
    oal_uint32      ul_data;
    oal_uint32      ul_ret;

    if (OAL_UNLIKELY(OAL_PTR_NULL == p_data))
    {
        return OAL_ERR_CODE_PTR_NULL;
    }


    pst_mem = (oal_mem_stru *)(*((oal_uint *)((oal_uint8 *)p_data - OAL_MEM_INFO_SIZE)));
    if (((oal_uint)pst_mem) < 0xfff)
    {
        ul_data = (*((oal_uint *)((oal_uint8 *)p_data - OAL_MEM_INFO_SIZE - OAL_DOG_TAG_SIZE)));
        OAL_IO_PRINT("oal_mem_free mem covered 0x%x \n", ul_data);
        return OAL_FAIL;
    }

    ul_ret = oal_mem_free_enhanced(ul_file_id, ul_line_num, pst_mem, uc_lock);
    if (OAL_UNLIKELY(ul_ret != OAL_SUCC))
    {
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        OAM_ERROR_LOG1(0, OAM_SF_ANY, "oal_mem_free failed, ul_ret %d", ul_ret);
#ifdef _PRE_DEBUG_MODE
        OAM_ERROR_LOG4(0, OAM_SF_ANY, "oal_mem_free failed, last free file_id %d, line_num %d, current free file_id %d, line_num %d",
                            pst_mem->ul_alloc_file_id[0], pst_mem->ul_alloc_line_num[0], ul_file_id, ul_line_num);
#endif
#endif
    }

    return ul_ret;
}



OAL_INLINE oal_uint32  oal_mem_free_array(
                oal_uint32    ul_file_id,
                oal_uint32    ul_line_num,
                oal_void     *p_data,
                oal_uint8     uc_mem_num)

{
    return oal_mem_free_enhanced_array(ul_file_id, ul_line_num, p_data, uc_mem_num);
}

#if 0

oal_netbuf_stru* oal_mem_netbuf_alloc(oal_uint32    ul_file_id,
                                      oal_uint32    ul_line_num,
                                      oal_uint16    us_len,
                                      oal_uint8     uc_lock)
{

    oal_mem_pool_stru          *pst_mem_pool;
    oal_mem_subpool_stru       *pst_mem_subpool;
    oal_netbuf_stru            *pst_netbuf;
    oal_uint8                   uc_subpool_id;
#ifdef _PRE_DEBUG_MODE
    oal_mem_netbuf_info_stru   *pst_info;
#endif

    /* ?????????? */
    pst_mem_pool = &g_ast_mem_pool[OAL_MEM_POOL_ID_NETBUF];

    us_len += OAL_NETBUF_MAINTAINS_SIZE + OAL_DOG_TAG_SIZE;

    /* ????: ??????????????????????  */
    if (OAL_UNLIKELY(us_len > pst_mem_pool->us_max_byte_len))
    {
        return OAL_PTR_NULL;
    }

    pst_netbuf = OAL_PTR_NULL;

    for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
    {
        pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);

        OAL_MEM_SPIN_LOCK_BH(pst_mem_subpool->st_spinlock)

        /* ????????????????????????????0?????????????????????????????????????????? */
        if ((pst_mem_subpool->us_len < us_len) || (0 == pst_mem_subpool->us_free_cnt))
        {
            OAL_MEM_SPIN_UNLOCK_BH(pst_mem_subpool->st_spinlock)

            continue;
        }

        /* ??????????????????????????????????(??????????1??????)?????????????????????????? */
        pst_netbuf = oal_mem_find_available_netbuf(pst_mem_subpool, OAL_MEM_POOL_ID_NETBUF);
        if (OAL_PTR_NULL == pst_netbuf)
        {
            OAL_MEM_SPIN_UNLOCK_BH(pst_mem_subpool->st_spinlock)

            continue;
        }

        /* ??????????1 */
        oal_netbuf_increase_user(pst_netbuf);

        pst_mem_pool->us_mem_used_cnt++;

        /* netbuf??data???????? */
        oal_netbuf_reset(pst_netbuf, g_ul_netbuf_def_data_offset[uc_subpool_id]);

    #ifdef _PRE_DEBUG_MODE
        pst_info = (oal_mem_netbuf_info_stru *)(oal_netbuf_end(pst_netbuf) - OAL_NETBUF_MAINTAINS_SIZE - OAL_DOG_TAG_SIZE);
        pst_info->ul_alloc_file_id    = ul_file_id;
        pst_info->ul_alloc_line_num   = ul_line_num;
        pst_info->ul_alloc_time_stamp = (oal_uint32)OAL_TIME_GET_STAMP_MS();
        pst_info->ul_trace_file_id    = 0;
        pst_info->ul_trace_line_num   = 0;
        pst_info->ul_trace_time_stamp = 0;
    #endif

        OAL_MEM_SPIN_UNLOCK_BH(pst_mem_subpool->st_spinlock)

        break;
    }

#ifdef _PRE_DEBUG_MODE
    if (OAL_PTR_NULL == pst_netbuf)
    {
        oal_mem_info(OAL_MEM_POOL_ID_NETBUF);
        oal_mem_leak(OAL_MEM_POOL_ID_NETBUF);
        oal_dump_stack();
    }
#endif

    return pst_netbuf;

}
#endif


oal_netbuf_stru* oal_mem_sdt_netbuf_alloc(oal_uint16 us_len, oal_uint8 uc_lock)
{
    oal_mem_pool_stru      *pst_mem_pool;
    oal_mem_subpool_stru   *pst_mem_subpool;
    oal_netbuf_stru        *pst_netbuf = OAL_PTR_NULL;
    oal_uint8               uc_subpool_id;
    oal_uint                ul_irq_flag = 0;
	oal_uint32				ul_headroom;

    /* ?????????? */
    pst_mem_pool = &g_ast_mem_pool[OAL_MEM_POOL_ID_SDT_NETBUF];

    /* ????: ??????????????????????  */
    if (OAL_UNLIKELY(us_len > pst_mem_pool->us_max_byte_len))
    {
        return OAL_PTR_NULL;
    }

    for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
    {
        pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);

        OAL_MEM_SPIN_LOCK_IRQSAVE(pst_mem_subpool->st_spinlock, ul_irq_flag)

        /* ????????????????????????????0?????????????????????????????????????????? */
        if ((pst_mem_subpool->us_len < us_len) || (0 == pst_mem_subpool->us_free_cnt))
        {
            OAL_MEM_SPIN_UNLOCK_IRQRESTORE(pst_mem_subpool->st_spinlock, ul_irq_flag)
            continue;
        }

        /* ??????????????????????????????????(??????????1??????)?????????????????????????? */
        pst_netbuf = oal_mem_find_available_netbuf(pst_mem_subpool, OAL_MEM_POOL_ID_SDT_NETBUF);
        if (OAL_PTR_NULL == pst_netbuf)
        {
            OAL_MEM_SPIN_UNLOCK_IRQRESTORE(pst_mem_subpool->st_spinlock, ul_irq_flag)
            continue;
        }

        /* ??????????1 */
        oal_netbuf_increase_user(pst_netbuf);

        pst_mem_pool->us_mem_used_cnt++;

        /* netbuf??data???????? */
    #if (_PRE_OS_VERSION_WIN32 == _PRE_OS_VERSION)
		ul_headroom = OAL_NETBUF_DEFAULT_DATA_OFFSET;
    #else
		ul_headroom = g_ul_sdt_netbuf_def_data_offset[uc_subpool_id];
    #endif
        if(oal_netbuf_headroom(pst_netbuf) > ul_headroom)
        {
            oal_netbuf_push(pst_netbuf,oal_netbuf_headroom(pst_netbuf) - ul_headroom);
        }
        else
        {
            oal_netbuf_pull(pst_netbuf, ul_headroom - oal_netbuf_headroom(pst_netbuf));
        }

        OAL_BUG_ON(oal_netbuf_headroom(pst_netbuf) != ul_headroom);

        oal_netbuf_trim(pst_netbuf, pst_netbuf->len);

        OAL_BUG_ON(pst_netbuf->len);

        OAL_MEM_SPIN_UNLOCK_IRQRESTORE(pst_mem_subpool->st_spinlock, ul_irq_flag)

        break;
    }

    return pst_netbuf;
}

OAL_STATIC OAL_INLINE oal_uint32 oal_mem_find_netbuf_subpool_id(oal_netbuf_stru   *pst_netbuf,
                                                                oal_mem_pool_stru *pst_mem_pool,
                                                                oal_uint8         *puc_subpool_id)
{
    oal_uint8 uc_subpool_id;

    for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
    {
        if (g_ul_truesize_to_pool_id[uc_subpool_id] == pst_netbuf->truesize)
        {
            *puc_subpool_id = uc_subpool_id;

            return OAL_SUCC;
        }
    }

    return OAL_FAIL;
}



OAL_STATIC OAL_INLINE oal_uint32 oal_mem_find_sdt_netbuf_subpool_id(oal_netbuf_stru   *pst_netbuf,
                                                                oal_mem_pool_stru *pst_mem_pool,
                                                                oal_uint8         *puc_subpool_id)
{
    oal_uint8 uc_subpool_id;

    for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
    {
        if (g_ul_truesize_to_pool_id_sdt[uc_subpool_id] == pst_netbuf->truesize)
        {
            *puc_subpool_id = uc_subpool_id;

            return OAL_SUCC;
        }
    }

    return OAL_FAIL;
}

#if 0

oal_uint32  oal_mem_netbuf_free(oal_uint32         ul_file_id,
                                oal_uint32         ul_line_num,
                                oal_netbuf_stru   *pst_netbuf,
                                oal_uint8          uc_lock)
{

    oal_uint8                   uc_subpool_id;
    oal_mem_pool_stru          *pst_mem_pool;
    oal_mem_subpool_stru       *pst_mem_subpool;
    oal_uint32                  ul_ret;
#ifdef _PRE_DEBUG_MODE
    oal_mem_netbuf_info_stru   *pst_info;
#endif

    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_netbuf))
    {
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_mem_pool = &g_ast_mem_pool[OAL_MEM_POOL_ID_NETBUF];

    /* ??????netbuf??????????????????ID */
    ul_ret = oal_mem_find_netbuf_subpool_id(pst_netbuf, pst_mem_pool, &uc_subpool_id);
    if (OAL_UNLIKELY(OAL_SUCC != ul_ret))
    {
        return OAL_ERR_CODE_OAL_MEM_SKB_SUBPOOL_ID_ERR;
    }

    pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);

    OAL_MEM_SPIN_LOCK_BH(pst_mem_subpool->st_spinlock)

    /* ????: ?????????? */
#ifdef _PRE_DEBUG_MODE
    pst_info = (oal_mem_netbuf_info_stru *)(oal_netbuf_end(pst_netbuf) - OAL_NETBUF_MAINTAINS_SIZE - OAL_DOG_TAG_SIZE);
    if (OAL_DOG_TAG != pst_info->ul_dog_tag)
    {
        /* ???????????? */
        /* pst_info->ul_dog_tag = OAL_DOG_TAG; */
        OAL_MEM_SPIN_UNLOCK_BH(pst_mem_subpool->st_spinlock)

        return OAL_ERR_CODE_OAL_MEM_DOG_TAG;
    }
#endif

    /* ????: ?????????????????????????????????????????????????? */
    if (OAL_UNLIKELY(pst_mem_subpool->us_free_cnt >= pst_mem_subpool->us_total_cnt))
    {
        OAL_MEM_SPIN_UNLOCK_BH(pst_mem_subpool->st_spinlock)

        return OAL_ERR_CODE_OAL_MEM_EXCEED_TOTAL_CNT;
    }

    /* ????netbuf???????????????????????? */
    pst_mem_subpool->ppst_free_stack[pst_mem_subpool->us_free_cnt] = (void *)pst_netbuf;
    pst_mem_subpool->us_free_cnt++;

    pst_mem_pool->us_mem_used_cnt--;

    OAL_MEM_SPIN_UNLOCK_BH(pst_mem_subpool->st_spinlock);

    return OAL_SUCC;

}
#endif


oal_uint32  oal_mem_sdt_netbuf_free(oal_netbuf_stru *pst_netbuf, oal_uint8 uc_lock)
{
    oal_uint8               uc_subpool_id;
    oal_mem_pool_stru      *pst_mem_pool;
    oal_mem_subpool_stru   *pst_mem_subpool;
    oal_uint32              ul_ret;
    oal_uint                ul_irq_flag = 0;

    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_netbuf))
    {
        /*oal_netbuf_free(pst_netbuf);*/
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_mem_pool = &g_ast_mem_pool[OAL_MEM_POOL_ID_SDT_NETBUF];

    /* ??????netbuf??????????????????ID */
    ul_ret = oal_mem_find_sdt_netbuf_subpool_id(pst_netbuf, pst_mem_pool, &uc_subpool_id);
    if (OAL_UNLIKELY(OAL_SUCC != ul_ret))
    {
        oal_netbuf_free(pst_netbuf);
        return OAL_ERR_CODE_OAL_MEM_SKB_SUBPOOL_ID_ERR;
    }

    pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);

    OAL_MEM_SPIN_LOCK_IRQSAVE(pst_mem_subpool->st_spinlock, ul_irq_flag)

    /* ????: ?????????????????????????????????????????????????? */
    if (OAL_UNLIKELY(pst_mem_subpool->us_free_cnt >= pst_mem_subpool->us_total_cnt))
    {
        OAL_MEM_SPIN_UNLOCK_IRQRESTORE(pst_mem_subpool->st_spinlock, ul_irq_flag)

        return OAL_ERR_CODE_OAL_MEM_EXCEED_TOTAL_CNT;
    }

    /* ????netbuf???????????????????????? */
    pst_mem_subpool->ppst_free_stack[pst_mem_subpool->us_free_cnt] = (void *)pst_netbuf;
    pst_mem_subpool->us_free_cnt++;

    pst_mem_pool->us_mem_used_cnt--;
    oal_netbuf_free(pst_netbuf);
    OAL_MEM_SPIN_UNLOCK_IRQRESTORE(pst_mem_subpool->st_spinlock, ul_irq_flag)

    return OAL_SUCC;
}


oal_uint32  oal_mempool_info_to_sdt_register(oal_stats_info_up_to_sdt  p_up_mempool_info,
                                                     oal_memblock_info_up_to_sdt p_up_memblock_info)
{
    g_st_mempool_info.p_mempool_info_func = p_up_mempool_info;
    g_st_mempool_info.p_memblock_info_func = p_up_memblock_info;

    return OAL_SUCC;
}


oal_void  oal_mem_info(oal_mem_pool_id_enum_uint8 en_pool_id)
{
    oal_mem_pool_stru      *pst_mem_pool;
    oal_mem_subpool_stru   *pst_mem_subpool;
    oal_uint8               uc_subpool_id;

    pst_mem_pool = oal_mem_get_pool(en_pool_id);
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mem_pool))
    {
        return;
    }

    for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
    {
        pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);

        /* ??????????????oal_mem_leak???????????????????????????? */
        if (OAL_PTR_NULL != g_st_mempool_info.p_mempool_info_func)
        {
            g_st_mempool_info.p_mempool_info_func(en_pool_id,
                                              pst_mem_pool->us_mem_total_cnt,
                                              pst_mem_pool->us_mem_used_cnt,
                                              uc_subpool_id,
                                              pst_mem_subpool->us_total_cnt,
                                              pst_mem_subpool->us_free_cnt);
        }

    }
}

#if 0

OAL_STATIC oal_void  oal_mem_netbuf_leak(oal_void)
{
    oal_mem_pool_stru          *pst_mem_pool;
    oal_mem_subpool_stru       *pst_mem_subpool;
    oal_netbuf_stru            *pst_netbuf;
    oal_mem_netbuf_info_stru   *pst_info;
    oal_uint8                   uc_subpool_id;
    oal_bool_enum_uint8         en_flag = OAL_TRUE;
    oal_uint16                  us_loop;

    pst_mem_pool = oal_mem_get_pool(OAL_MEM_POOL_ID_NETBUF);
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mem_pool))
    {
        return;
    }

    if (pst_mem_pool->us_mem_used_cnt != 0)
    {
        OAL_IO_PRINT("netbuf memory leak, used cnt = %d!\n", pst_mem_pool->us_mem_used_cnt);
    }

    for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
    {
        pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);
        if (pst_mem_subpool->us_free_cnt != pst_mem_subpool->us_total_cnt)
        {
            OAL_IO_PRINT("netbuf memory leak, subpool id = %d, subpool free cnt = %d, subpool total cnt = %d!\n",
                         uc_subpool_id, pst_mem_subpool->us_free_cnt, pst_mem_subpool->us_total_cnt);
        }
    }

    for (us_loop = 0; us_loop < OAL_MEM_NETBUF_BLK_TOTAL_CNT; us_loop++)
    {
        if (OAL_PTR_NULL == g_pst_netbuf_base_addr[us_loop])
        {
            continue;
        }

        if (1 == oal_atomic_read(&g_pst_netbuf_base_addr[us_loop]->users))
        {
            continue;
        }

        /* ?????????????? */
        if (OAL_TRUE == en_flag)
        {
            OAL_IO_PRINT("[netbuf memory leak] current time stamp: %u.\n", (oal_uint32)OAL_TIME_GET_STAMP_MS());
            en_flag = OAL_FALSE;
        }

        pst_netbuf = g_pst_netbuf_base_addr[us_loop];
        pst_info = (oal_mem_netbuf_info_stru *)(oal_netbuf_end(pst_netbuf) - OAL_NETBUF_MAINTAINS_SIZE - OAL_DOG_TAG_SIZE);
        OAL_IO_PRINT("users: %d, "
                     "alloc_file_id: %u, alloc_line_num: %u, alloc_time_stamp: %u, "
                     "trace_file_id: %u, trace_line_num: %u, trace_time_stamp: %u.\n",
                      oal_atomic_read(&pst_netbuf->users),
                      pst_info->ul_alloc_file_id, pst_info->ul_alloc_line_num, pst_info->ul_alloc_time_stamp,
                      pst_info->ul_trace_file_id, pst_info->ul_trace_line_num, pst_info->ul_trace_time_stamp);
    }
}
#endif


#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)

oal_uint8 oal_get_func_name(oal_uint8 *buff, oal_ulong call_func_ddr)
{
    oal_uint8 buf_cnt = 0;

#if (_PRE_OS_VERSION == _PRE_OS_VERSION_LINUX)
    buf_cnt = sprint_symbol(buff, call_func_ddr);
#else
    buf_cnt = 0;
   *buff = '\0';
#endif

    return buf_cnt;
}


oal_ulong oal_get_func_return_address(oal_void)
{
    oal_ulong ul_ret_addr = 0;

#if (_PRE_OS_VERSION == _PRE_OS_VERSION_LINUX)
    ul_ret_addr = (oal_ulong)__builtin_return_address(0);
#else
    ul_ret_addr = 0;
#endif

    return ul_ret_addr;
}
oal_module_symbol(oal_get_func_return_address);


oal_void oal_mem_print_funcname(oal_ulong func_addr)
{
    oal_uint8              ac_buff[OAL_MEM_SPRINT_SYMBOL_SIZE] = {0};
    oal_uint8              ac_buff_head[100] = {0};
    oal_uint8              uc_size;

    uc_size = oal_get_func_name(ac_buff, func_addr);
    /* OTA???????????? */
    OAL_SPRINTF(ac_buff_head, sizeof(ac_buff_head), "Func: ");
    oal_strncat(ac_buff_head, ac_buff, uc_size);
    oam_print(ac_buff_head);
}
oal_module_symbol(oal_mem_print_funcname);


oal_uint32 oal_mem_return_addr_count(oal_mem_subpool_stru *pst_mem_subpool, oal_mem_stru *pst_mem_base, oal_ulong call_func_addr)
{
    oal_uint16             us_loop;
    oal_mem_stru          *pst_mem;
    oal_uint32             us_count = 0;

    pst_mem = pst_mem_base;

    for (us_loop = 0; us_loop < pst_mem_subpool->us_total_cnt; us_loop++)
    {
        if ((OAL_MEM_STATE_ALLOC == pst_mem->en_mem_state_flag) && (call_func_addr == pst_mem->ul_return_addr))
        {
            us_count++;
        }
        pst_mem++;
     }

     return us_count;
}


oal_uint8 oal_mem_func_addr_is_registerd(oal_ulong* ua_func_addr, oal_uint8 uc_func_size, oal_uint8* p_func_loop, oal_ulong call_func_addr)
{
    oal_uint8 uc_loop = 0;

    /* ?????????????????????????? */
    while(ua_func_addr[uc_loop])
    {
        /* ??????????????true */
        if(ua_func_addr[uc_loop] == call_func_addr)
        {
            return OAL_TRUE;
        }

        uc_loop++;
        if(uc_func_size == uc_loop)
        {
            break;
        }
    }

    if(uc_func_size == uc_loop)
    {
        uc_loop = 0;
    }

    /* ???????????????????????? */
    *p_func_loop = uc_loop;

    return OAL_FALSE;

}


oal_void oal_mem_print_normal_pool_info(oal_mem_pool_id_enum_uint8 en_pool_id)
{
    oal_mem_pool_stru     *pst_mem_pool;
    oal_mem_subpool_stru  *pst_mem_subpool;
    oal_mem_stru          *pst_mem;
    oal_mem_stru          *pst_mem_base;
    oal_uint16             us_loop;
    oal_uint8              uc_subpool_id = 0;
    oal_ulong              ua_func_addr[50] = {0};
    oal_uint8              uc_func_size = 50;
    oal_uint8              us_func_loop = 0;
    oal_uint32             us_ret_count = 0;
    oal_uint8              ac_buff[OAL_MEM_SPRINT_SYMBOL_SIZE] = {0};
    oal_uint8              ac_buff_head[200] = {0};
    oal_uint8              uc_size;

    pst_mem_pool = oal_mem_get_pool(en_pool_id);
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mem_pool))
    {
        return;
    }

    OAM_WARNING_LOG4(0, OAM_SF_CFG, "{host memory info: pool id=%d, subpool cnt=%d, mem block total cnt=%d, used cnt=%d.}",
                 en_pool_id, pst_mem_pool->uc_subpool_cnt, pst_mem_pool->us_mem_total_cnt, pst_mem_pool->us_mem_used_cnt);

    pst_mem = pst_mem_pool->pst_mem_start_addr;

    OAL_REFERENCE(pst_mem_subpool);
    /* ?????????????? */
    for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
    {
        /* ?????????????????????? */
        pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);

        OAM_WARNING_LOG4(0, OAM_SF_CFG, "{host subpool id[%d] info: len =%d, mem block total cnt=%d, free cnt=%d.}",
                              uc_subpool_id, pst_mem_subpool->us_len, pst_mem_subpool->us_total_cnt, pst_mem_subpool->us_free_cnt);

        /* ???????????????? */
        pst_mem_base = pst_mem;

        /* ????????????????????mem block */
        for (us_loop = 0; us_loop < pst_mem_subpool->us_total_cnt; us_loop++)
        {
            if ((0 == pst_mem->ul_return_addr) && (OAL_MEM_STATE_ALLOC == pst_mem->en_mem_state_flag))
            {
                OAM_WARNING_LOG2(0, OAM_SF_CFG, "{oal_mem_print_normal_pool_info:: subpool id[%d] mem block[%d] has no call func addr.}",
                                       uc_subpool_id, us_loop);

                /* ???????????????? */
                pst_mem++;
            }
            else if (OAL_MEM_STATE_ALLOC == pst_mem->en_mem_state_flag)
            {
                if(OAL_FALSE == oal_mem_func_addr_is_registerd(ua_func_addr, uc_func_size, &us_func_loop, pst_mem->ul_return_addr))
                {
                    ua_func_addr[us_func_loop] = pst_mem->ul_return_addr;

                    us_ret_count = oal_mem_return_addr_count(pst_mem_subpool, pst_mem_base, pst_mem->ul_return_addr);

                    uc_size = oal_get_func_name(ac_buff, pst_mem->ul_return_addr);
                    /* OTA???????????? */
                    OAL_SPRINTF(ac_buff_head, sizeof(ac_buff_head), "[%d] mem blocks occupied by ", us_ret_count);
                    oal_strncat(ac_buff_head, ac_buff, uc_size);
                    oam_print(ac_buff_head);
                }
                /* ?????????????????????????? */
                pst_mem++;
            }
            else
            {
                pst_mem++;
            }
        }
        /* ???????????????????????? */
        OAL_MEMZERO(ua_func_addr, uc_func_size);
    }

}
oal_module_symbol(oal_mem_print_normal_pool_info);


oal_void oal_mem_print_pool_info(oal_void)
{
    oal_uint8 uc_loop;

    for(uc_loop = 0; uc_loop <= OAL_MEM_POOL_ID_SHARED_DSCR; uc_loop++)
    {
        oal_mem_print_normal_pool_info(uc_loop);
    }
}
oal_module_symbol(oal_mem_print_pool_info);

#endif


oal_void  oal_mem_leak(oal_mem_pool_id_enum_uint8 en_pool_id)
{
#ifdef _PRE_DEBUG_MODE
    oal_mem_pool_stru     *pst_mem_pool;
    oal_mem_stru          *pst_mem;
    oal_bool_enum_uint8    en_flag = OAL_TRUE;
    oal_uint16             us_loop;


    pst_mem_pool = oal_mem_get_pool(en_pool_id);
    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mem_pool))
    {
        return;
    }

    pst_mem = pst_mem_pool->pst_mem_start_addr;

    for (us_loop = 0; us_loop < pst_mem_pool->us_mem_total_cnt; us_loop++)
    {
        /* ???????? != 0????????????????????????(??????????0??????????) */
        if (0 != pst_mem->ul_alloc_line_num[0])
        {
            /* ?????????????? */
            if (OAL_TRUE == en_flag)
            {
                OAL_IO_PRINT("[memory leak] current time stamp: %u.\n", (oal_uint32)OAL_TIME_GET_STAMP_MS());
                en_flag = OAL_FALSE;
            }

            OAL_IO_PRINT("[memory leak] user_cnt: %u, pool_id: %u, subpool_id: %u, len: %u, "
                         "alloc_core_id = %u, alloc_file_id: %u, alloc_line_num: %u, alloc_time_stamp: %u, "
                         "trace_file_id: %u, trace_line_num: %u, trace_time_stamp: %u.\n",
                         pst_mem->uc_user_cnt,
                         pst_mem->en_pool_id,
                         pst_mem->uc_subpool_id,
                         pst_mem->us_len,
                         pst_mem->ul_alloc_core_id[0],
                         pst_mem->ul_alloc_file_id[0],
                         pst_mem->ul_alloc_line_num[0],
                         pst_mem->ul_alloc_time_stamp[0],
                         pst_mem->ul_trace_file_id,
                         pst_mem->ul_trace_line_num,
                         pst_mem->ul_trace_time_stamp);
        }

        /* ????????????????????oal_mem_info?????????????????????? zouhongliang SDT*/
        if (OAL_PTR_NULL != g_st_mempool_info.p_memblock_info_func)
        {
            g_st_mempool_info.p_memblock_info_func(pst_mem->puc_origin_data,
                                               pst_mem->uc_user_cnt,
                                               pst_mem->en_pool_id,
                                               pst_mem->uc_subpool_id,
                                               pst_mem->us_len,
                                               pst_mem->ul_alloc_file_id[0],
                                               pst_mem->ul_alloc_line_num[0]);
        }

        pst_mem++;
    }
#endif
}


OAL_STATIC oal_void  oal_mem_statistics(oal_mem_pool_stat *past_mem_pool_stat)
{
    oal_mem_pool_id_enum_uint8    en_pool_id;
    oal_uint8                     uc_subpool_id;
    oal_mem_pool_stru            *pst_mem_pool;
    oal_mem_subpool_stru         *pst_mem_subpool;

    for (en_pool_id = 0; en_pool_id < OAL_MEM_POOL_ID_BUTT; en_pool_id++)
    {
        pst_mem_pool = &g_ast_mem_pool[en_pool_id];

        /* ???????????????????? */
        past_mem_pool_stat[en_pool_id].us_mem_used_cnt  = pst_mem_pool->us_mem_used_cnt;
        past_mem_pool_stat[en_pool_id].us_mem_total_cnt = pst_mem_pool->us_mem_total_cnt;

        /* ?????????????????? */
        for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
        {
            pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);

            past_mem_pool_stat[en_pool_id].ast_subpool_stat[uc_subpool_id].us_free_cnt  = pst_mem_subpool->us_free_cnt;
            past_mem_pool_stat[en_pool_id].ast_subpool_stat[uc_subpool_id].us_total_cnt = pst_mem_subpool->us_total_cnt;
        }
    }
}


OAL_STATIC oal_uint32  oal_mem_check(oal_mem_pool_stat *past_stat_start, oal_mem_pool_stat *past_stat_end)
{
    oal_uint8                     uc_bitmap = 0;
    oal_mem_pool_id_enum_uint8    en_pool_id;
    oal_uint8                     uc_subpool_id;
    oal_mem_pool_stru            *pst_mem_pool;

    for (en_pool_id = 0; en_pool_id < OAL_MEM_POOL_ID_BUTT; en_pool_id++)
    {
        /* ????????????????(????????????????????) */
        if ((past_stat_start[en_pool_id].us_mem_used_cnt != past_stat_end[en_pool_id].us_mem_used_cnt) ||
            (past_stat_start[en_pool_id].us_mem_total_cnt != past_stat_end[en_pool_id].us_mem_total_cnt))
        {
            uc_bitmap |= (oal_uint8)(1 << en_pool_id);
            continue;
        }

        pst_mem_pool = &g_ast_mem_pool[en_pool_id];

        /* ??????????????????????(????????????????????) */
        for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
        {
            if ((past_stat_start[en_pool_id].ast_subpool_stat[uc_subpool_id].us_free_cnt !=
                 past_stat_end[en_pool_id].ast_subpool_stat[uc_subpool_id].us_free_cnt)       ||
                (past_stat_start[en_pool_id].ast_subpool_stat[uc_subpool_id].us_total_cnt !=
                 past_stat_end[en_pool_id].ast_subpool_stat[uc_subpool_id].us_total_cnt))
            {
                uc_bitmap |= (oal_uint8)(1 << en_pool_id);
                continue;
            }
        }
    }

    /* ????????????????(????????????)?????? */
    if (0 == uc_bitmap)
    {
        OAL_IO_PRINT("no memory leak!\n");
        return OAL_FALSE;
    }

    /* ??????????????????(??????????)?????????????????????????????? */
    OAL_IO_PRINT("memory leak!\n");
    for (en_pool_id = 0; en_pool_id < OAL_MEM_POOL_ID_BUTT; en_pool_id++)
    {
        if (!(uc_bitmap & (1 << en_pool_id)))
        {
            continue;
        }

        pst_mem_pool = &g_ast_mem_pool[en_pool_id];

        OAL_IO_PRINT("                      Start\t\tEnd\t\n");
        OAL_IO_PRINT("pool(%d) used cnt:     %d\t\t%d\t\n", en_pool_id, past_stat_start[en_pool_id].us_mem_used_cnt, past_stat_end[en_pool_id].us_mem_used_cnt);
        OAL_IO_PRINT("pool(%d) total cnt:    %d\t\t%d\t\n", en_pool_id, past_stat_start[en_pool_id].us_mem_total_cnt, past_stat_end[en_pool_id].us_mem_total_cnt);

        for (uc_subpool_id = 0; uc_subpool_id < pst_mem_pool->uc_subpool_cnt; uc_subpool_id++)
        {
        OAL_IO_PRINT("subpool(%d) free cnt:  %d\t\t%d\t\n", uc_subpool_id, past_stat_start[en_pool_id].ast_subpool_stat[uc_subpool_id].us_free_cnt, past_stat_end[en_pool_id].ast_subpool_stat[uc_subpool_id].us_free_cnt);
        OAL_IO_PRINT("subpool(%d) total cnt: %d\t\t%d\t\n", uc_subpool_id, past_stat_start[en_pool_id].ast_subpool_stat[uc_subpool_id].us_total_cnt, past_stat_end[en_pool_id].ast_subpool_stat[uc_subpool_id].us_total_cnt);
        }

        OAL_IO_PRINT("\n");
    }

    return OAL_TRUE;
}


oal_void  oal_mem_start_stat(oal_void)
{
    OAL_MEMZERO(&g_st_mem_stat, OAL_SIZEOF(g_st_mem_stat));

    /* ???????????????????? */
    oal_mem_statistics(g_st_mem_stat.ast_mem_start_stat);
}


oal_uint32  oal_mem_end_stat(oal_void)
{
    oal_mem_statistics(g_st_mem_stat.ast_mem_end_stat);

    /* ???????????????????? */
    return oal_mem_check(g_st_mem_stat.ast_mem_start_stat, g_st_mem_stat.ast_mem_end_stat);
}


oal_uint32  oal_mem_trace_enhanced(oal_uint32      ul_file_id,
                                   oal_uint32      ul_line_num,
                                   oal_mem_stru   *pst_mem,
                                   oal_uint8       uc_lock)
{
    oal_mem_pool_stru      *pst_mem_pool;
    oal_mem_subpool_stru   *pst_mem_subpool;

    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mem))
    {
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_mem_pool = &g_ast_mem_pool[pst_mem->en_pool_id];

    pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[pst_mem->uc_subpool_id]);

#ifdef _PRE_DEBUG_MODE
    OAL_MEM_SPIN_LOCK_BH(pst_mem_subpool->st_spinlock)

    pst_mem->ul_trace_file_id    = ul_file_id;
    pst_mem->ul_trace_line_num   = ul_line_num;
    pst_mem->ul_trace_time_stamp = (oal_uint32)OAL_TIME_GET_STAMP_MS();

    OAL_MEM_SPIN_UNLOCK_BH(pst_mem_subpool->st_spinlock)
#endif

    return OAL_SUCC;
}


oal_uint32  oal_mem_trace(oal_uint32    ul_file_id,
                          oal_uint32    ul_line_num,
                          oal_void     *p_data,
                          oal_uint8     uc_lock)
{
    oal_mem_stru   *pst_mem;

    if (OAL_UNLIKELY(OAL_PTR_NULL == p_data))
    {
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_mem = (oal_mem_stru *)(*((oal_uint *)((oal_uint8 *)p_data - OAL_MEM_INFO_SIZE)));

    return oal_mem_trace_enhanced(ul_file_id, ul_line_num, pst_mem, uc_lock);
}

#if 0

oal_uint32  oal_mem_netbuf_trace(oal_uint32       ul_file_id,
                                 oal_uint32       ul_line_num,
                                 oal_netbuf_stru *pst_netbuf,
                                 oal_uint8        uc_lock)
{
    oal_uint8                   uc_subpool_id;
    oal_mem_pool_stru          *pst_mem_pool;
    oal_mem_subpool_stru       *pst_mem_subpool;
    oal_mem_netbuf_info_stru   *pst_info;
    oal_uint32                  ul_ret;

    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_netbuf))
    {
        return OAL_ERR_CODE_PTR_NULL;
    }

    pst_mem_pool = &g_ast_mem_pool[OAL_MEM_POOL_ID_NETBUF];

    /* ??????netbuf??????????????????ID */
    ul_ret = oal_mem_find_netbuf_subpool_id(pst_netbuf, pst_mem_pool, &uc_subpool_id);
    if (OAL_UNLIKELY(OAL_SUCC != ul_ret))
    {
        return OAL_SUCC;
    }

    pst_mem_subpool = &(pst_mem_pool->ast_subpool_table[uc_subpool_id]);

    OAL_MEM_SPIN_LOCK_BH(pst_mem_subpool->st_spinlock)

    pst_info = (oal_mem_netbuf_info_stru *)(oal_netbuf_end(pst_netbuf) - OAL_NETBUF_MAINTAINS_SIZE - OAL_DOG_TAG_SIZE);
    pst_info->ul_trace_file_id = ul_file_id;
    pst_info->ul_trace_line_num = ul_line_num;
    pst_info->ul_trace_time_stamp = (oal_uint32)OAL_TIME_GET_STAMP_MS();

    OAL_MEM_SPIN_UNLOCK_BH(pst_mem_subpool->st_spinlock);

    return OAL_SUCC;
}
#endif


oal_uint32  oal_mem_exit(oal_void)
{
    /* ?????????????? */
    oal_mem_release();

    /* ????netbuf?????? */
    oal_mem_netbuf_release();

    oal_mem_sdt_netbuf_release();

    OAL_MEMZERO(g_ast_mem_pool, OAL_SIZEOF(g_ast_mem_pool));

    return OAL_SUCC;
}


/*lint -e19*/
oal_module_symbol(oal_mem_free);
oal_module_symbol(oal_mem_free_array);

oal_module_symbol(oal_mem_alloc);

/*lint -e19*/
oal_module_symbol(oal_netbuf_duplicate);
oal_module_symbol(oal_mem_alloc_enhanced);
oal_module_symbol(oal_mem_free_enhanced);
oal_module_symbol(oal_mem_incr_user);
oal_module_symbol(oal_mem_sdt_netbuf_alloc);
oal_module_symbol(oal_mem_sdt_netbuf_free);
oal_module_symbol(oal_mem_leak);
oal_module_symbol(oal_mem_info);
oal_module_symbol(oal_mem_trace_enhanced);
oal_module_symbol(oal_mem_trace);
oal_module_symbol(oal_mempool_info_to_sdt_register);
oal_module_symbol(g_pst_netbuf_base_addr);
oal_module_symbol(g_pst_sdt_netbuf_base_addr);
#ifdef _PRE_WLAN_CACHE_COHERENT_SUPPORT
oal_module_symbol(gul_dscr_fstvirt_addr);
oal_module_symbol(gul_dscr_fstphy_addr);
#endif
#ifdef _PRE_DEBUG_MODE
oal_module_symbol(g_st_tx_dscr_addr);
oal_module_symbol(oal_mem_get_tx_dscr_addr);
oal_module_symbol(oal_mem_stop_rcd_rls);
oal_module_symbol(oal_mem_get_stop_flag);
#endif

#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

