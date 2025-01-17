

#ifdef _PRE_MEM_TRACE

#include "mem_trace.h"

#include "oal_list.h"
#include "oal_schedule.h"

// note: ??????????????????????????????????????????????????????????????????
/*
 * @brief ??????????????????????????????????????????????????????????????
 *        ????????????????????????????????????2??N??????(N>=5)
 */
#define MEM_TRACE_TBL_SIZE 8192  // ????????????????????????????

/* @brief ???????????????????????????????????????????????????????????????????? */
#define MEM_TRACE_OWNER_TBL_SIZE 64
/*
 * ???????????????????? = 44*MEM_TRACE_TBL_SIZE
 *                        + 20
 *                        + 20*MEM_TRACE_OWNER_TBL_SIZE
 *                        + 8*(MEM_TRACE_TBL_SIZE>>5)
 *                        + sizeof(oal_spin_lock) = 178K
 */
// ????????????????????????
typedef struct {
    oal_ulong ul_addr;                // ??????????
    oal_uint32 ul_time;               // ??????????????
    oal_uint32 ul_fileid;             // ??????????????????ID
    oal_uint32 ul_linenum;            // ??????????????????????
    oal_uint32 ul_last_trace_fileid;  // ????????????????????????
    oal_uint32 ul_last_trace_line;    // ????????????????????????
    oal_uint32 ul_last_trace_time;    // ????????????????????????????
    oal_dlist_head_stru st_list_entry;
    oal_dlist_head_stru st_hash_list_entry;
    oal_dlist_head_stru st_owner_list_entry;
} mem_trace_node;

// ????????????????
typedef struct _mem_node_owner {
    oal_uint32 ul_fileid;   // ??????????????????ID
    oal_uint32 ul_linenum;  // ??????????????????????
    oal_dlist_head_stru st_owner_list_head;
    oal_uint32 ul_cnt;
} mem_node_owner;

#define MEM_TRACE_HASH_TBL_SIZE      (MEM_TRACE_TBL_SIZE >> 5)
#define MEM_TRACE_HASH_TBL_SIZE_MASK (MEM_TRACE_HASH_TBL_SIZE - 1)

// ??????????????????
typedef struct {
    mem_trace_node ast_mem_trace_tbl[MEM_TRACE_TBL_SIZE];
    oal_dlist_head_stru st_free_list_head;
    oal_dlist_head_stru st_used_list_head;
    oal_dlist_head_stru ast_hast_table[MEM_TRACE_HASH_TBL_SIZE];  // ??????????????????
    mem_node_owner ast_owner[MEM_TRACE_OWNER_TBL_SIZE];
    oal_spin_lock_stru st_spin_lock;
    oal_uint32 ul_cnt;
    oal_uint32 ul_node_shortage;  // ??????node????????????
} mem_trace_mgmt;

OAL_STATIC mem_trace_mgmt g_mem_trace_mgmt;

/*
 * ?? ?? ??  : mem_trace_get_mgr
 * ????????  : ????????????????????????????????????????????????
 */
OAL_STATIC OAL_INLINE mem_trace_mgmt *mem_trace_get_mgr(oal_void)
{
    return &g_mem_trace_mgmt;
}

/*
 * ?? ?? ??  : mem_trace_init
 * ????????  : ??????mem_trace????
 */
oal_void mem_trace_init(oal_void)
{
    oal_uint32 i;
    mem_trace_mgmt *pst_mgr = mem_trace_get_mgr();

    memset_s((oal_void *)pst_mgr, OAL_SIZEOF(mem_trace_mgmt), 0, OAL_SIZEOF(mem_trace_mgmt));
    oal_spin_lock_init(&pst_mgr->st_spin_lock);
    oal_dlist_init_head(&pst_mgr->st_free_list_head);
    oal_dlist_init_head(&pst_mgr->st_used_list_head);
    pst_mgr->ul_cnt = 0;

    for (i = 0; i < MEM_TRACE_HASH_TBL_SIZE; i++) {
        oal_dlist_init_head(&pst_mgr->ast_hast_table[i]);
    }

    // ????????????????????????free????
    for (i = 0; i < MEM_TRACE_TBL_SIZE; i++) {
        oal_dlist_add_tail(&pst_mgr->ast_mem_trace_tbl[i].st_list_entry, &pst_mgr->st_free_list_head);
    }

    for (i = 0; i < MEM_TRACE_OWNER_TBL_SIZE; i++) {
        pst_mgr->ast_owner[i].ul_cnt = 0;
        pst_mgr->ast_owner[i].ul_fileid = ~0;
        pst_mgr->ast_owner[i].ul_linenum = 0;
        oal_dlist_init_head(&pst_mgr->ast_owner[i].st_owner_list_head);
    }

    OAL_IO_PRINT("mem_trace_init done!\r\n");
}

/*
 * ?? ?? ??  : mem_trace_exit
 * ????????  : ????mem_trace????
 */
oal_void mem_trace_exit(oal_void)
{
    // nothing todo
}

/*
 * ?? ?? ??  : mem_trace_owner_search
 * ????????  : ????????????????????????????????????????????????????????????owner????????
 */
OAL_STATIC mem_node_owner *mem_trace_owner_search(oal_uint32 ul_fileid, oal_uint32 ul_linenum)
{
    mem_trace_mgmt *pst_mgr = mem_trace_get_mgr();
    mem_node_owner *pst_owner;

    for (pst_owner = pst_mgr->ast_owner + 0; pst_owner < pst_mgr->ast_owner + MEM_TRACE_OWNER_TBL_SIZE; pst_owner++) {
        // ????????owner??????????owner
        if (((pst_owner->ul_fileid == 0xffffffff) && (pst_owner->ul_linenum == 0)) ||
            ((pst_owner->ul_fileid == ul_fileid) && (pst_owner->ul_linenum == ul_linenum))) {
            return pst_owner;
        }
    }

    return OAL_PTR_NULL;
}

/*
 * ?? ?? ??  : __mem_trace_add_node
 * ????????  : ??????????????????????????????(??????????????skb??????????????????????)
 */
oal_void __mem_trace_add_node(oal_ulong ul_addr,
                              oal_uint32 ul_fileid,
                              oal_uint32 ul_linenum)
{
    mem_trace_node *pst_mem_trace_node = NULL;
    oal_dlist_head_stru *pst_entry = NULL;
    oal_uint ul_irq_save;
    mem_node_owner *pst_owner = NULL;
    mem_trace_mgmt *pst_mgr = mem_trace_get_mgr();

    oal_spin_lock_irq_save(&pst_mgr->st_spin_lock, &ul_irq_save);
    if (oal_dlist_is_empty(&pst_mgr->st_free_list_head)) {
        OAL_IO_PRINT("mem trace mod not initialized or the trace space not enough!!!\n");
        pst_mgr->ul_node_shortage = OAL_TRUE;
        oal_spin_unlock_irq_restore(&pst_mgr->st_spin_lock, &ul_irq_save);
        return;
    }
    // ??free??????????????free????????????????????free????????????????
    pst_entry = oal_dlist_delete_head(&(pst_mgr->st_free_list_head));
    oal_dlist_add_tail(pst_entry, &(pst_mgr->st_used_list_head));

    pst_mem_trace_node = oal_dlist_get_entry(pst_entry, mem_trace_node, st_list_entry);
    pst_mem_trace_node->ul_addr = ul_addr;
    pst_mem_trace_node->ul_time = (oal_uint32)OAL_TIME_JIFFY;
    pst_mem_trace_node->ul_last_trace_time = pst_mem_trace_node->ul_time;
    pst_mem_trace_node->ul_fileid = ul_fileid;
    pst_mem_trace_node->ul_linenum = ul_linenum;
    pst_mem_trace_node->ul_last_trace_fileid = ul_fileid;
    pst_mem_trace_node->ul_last_trace_line = ul_linenum;

    oal_dlist_add_tail(&(pst_mem_trace_node->st_hash_list_entry),
                       &(pst_mgr->ast_hast_table[ul_addr & MEM_TRACE_HASH_TBL_SIZE_MASK]));
    pst_mgr->ul_cnt++;
    pst_owner = mem_trace_owner_search(ul_fileid, ul_linenum);
    if (pst_owner != NULL) {
        pst_owner->ul_fileid = ul_fileid;
        pst_owner->ul_linenum = ul_linenum;
        pst_owner->ul_cnt++;
        oal_dlist_add_tail(&(pst_mem_trace_node->st_owner_list_entry), &pst_owner->st_owner_list_head);
    } else {
        oal_warn_on(1);
    }

    oal_spin_unlock_irq_restore(&pst_mgr->st_spin_lock, &ul_irq_save);
}

/*
 * ?? ?? ??  : __mem_trace_delete_node
 * ????????  : ??????????????????????(??????????????skb??????????????????????)
 */
oal_void __mem_trace_delete_node(oal_ulong ul_addr,
                                 oal_uint32 ul_fileid,
                                 oal_uint32 ul_linenum)
{
    oal_dlist_head_stru *pst_entry = NULL;
    oal_dlist_head_stru *pst_entry_tmp = NULL;
    mem_trace_node *pst_mem_trace_node = NULL;
    oal_bool_enum_uint8 en_match_flag = OAL_FALSE;
    oal_uint ul_irq_save;
    mem_node_owner *pst_owner = NULL;
    mem_trace_mgmt *pst_mgr = mem_trace_get_mgr();

    oal_spin_lock_irq_save(&pst_mgr->st_spin_lock, &ul_irq_save);

    oal_dlist_search_for_each_safe(pst_entry, pst_entry_tmp,
                                   &(pst_mgr->ast_hast_table[ul_addr & MEM_TRACE_HASH_TBL_SIZE_MASK]))
    {
        pst_mem_trace_node = oal_dlist_get_entry(pst_entry, mem_trace_node, st_hash_list_entry);
        if (pst_mem_trace_node->ul_addr == ul_addr) {
            oal_dlist_delete_entry(pst_entry);  // ??hash????????
            pst_mem_trace_node->ul_last_trace_time = (oal_uint32)OAL_TIME_JIFFY;
            pst_mem_trace_node->ul_last_trace_fileid = ul_fileid;
            pst_mem_trace_node->ul_last_trace_line = ul_linenum;
            en_match_flag = OAL_TRUE;
            break;
        }
    }

    if (en_match_flag) {
        pst_mgr->ul_cnt--;
        oal_dlist_delete_entry(&(pst_mem_trace_node->st_list_entry));                           // ??used ????????
        oal_dlist_add_tail(&(pst_mem_trace_node->st_list_entry), &pst_mgr->st_free_list_head);  // ??????free????
        pst_owner = mem_trace_owner_search(pst_mem_trace_node->ul_fileid, pst_mem_trace_node->ul_linenum);
        if (pst_owner != NULL) {
            oal_dlist_delete_entry(&(pst_mem_trace_node->st_owner_list_entry));  // ??owner????????
            pst_owner->ul_cnt--;
        } else {
            OAL_IO_PRINT("%s error:pst_owner is null\n", __FUNCTION__);
        }
    } else if (!pst_mgr->ul_node_shortage) {
        // ??????????????????????
        oal_bool_enum_uint8 en_ever_del = OAL_FALSE;
        oal_dlist_search_for_each(pst_entry, &pst_mgr->st_free_list_head)
        {
            pst_mem_trace_node = oal_dlist_get_entry(pst_entry, mem_trace_node, st_list_entry);
            if (pst_mem_trace_node->ul_addr == ul_addr) {
                OAL_IO_PRINT("0x%lx add@[%d:%d:%u] del@[%d:%d:%u]\n",
                             ul_addr,
                             pst_mem_trace_node->ul_fileid, pst_mem_trace_node->ul_linenum,
                             pst_mem_trace_node->ul_time,
                             pst_mem_trace_node->ul_last_trace_fileid,
                             pst_mem_trace_node->ul_last_trace_line,
                             pst_mem_trace_node->ul_last_trace_time);
                en_ever_del = OAL_TRUE;
            }
        }

        if (en_ever_del) {
            OAL_IO_PRINT("maybe double-free 0x%lx@[%d:%d] time=%u, see last above\n---cut---\n",
                         ul_addr, ul_fileid, ul_linenum, (oal_uint32)OAL_TIME_JIFFY);
        } else {
            OAL_IO_PRINT("delete node not registered, addr=0x%lx)\n", ul_addr);
            oal_warn_on(1);
        }
    }

    oal_spin_unlock_irq_restore(&pst_mgr->st_spin_lock, &ul_irq_save);
}

/*
 * ?? ?? ??  : __mem_trace_probe
 * ????????  : ????????????????????????????????
 */
oal_void __mem_trace_probe(oal_ulong ul_addr,
                           oal_uint32 ul_probe_fileid,
                           oal_uint32 ul_probe_line)
{
    oal_dlist_head_stru *pst_entry = NULL;
    mem_trace_node *pst_mem_trace_node = NULL;
    oal_bool_enum_uint8 en_match_flag = OAL_FALSE;
    oal_uint ul_irq_save;
    mem_trace_mgmt *pst_mgr = mem_trace_get_mgr();

    oal_spin_lock_irq_save(&pst_mgr->st_spin_lock, &ul_irq_save);

    oal_dlist_search_for_each(pst_entry, &(pst_mgr->ast_hast_table[ul_addr & MEM_TRACE_HASH_TBL_SIZE_MASK]))
    {
        pst_mem_trace_node = oal_dlist_get_entry(pst_entry, mem_trace_node, st_hash_list_entry);
        if (pst_mem_trace_node->ul_addr == ul_addr) {
            pst_mem_trace_node->ul_last_trace_fileid = ul_probe_fileid;
            pst_mem_trace_node->ul_last_trace_line = ul_probe_line;
            pst_mem_trace_node->ul_last_trace_time = (oal_uint32)OAL_TIME_JIFFY;
            en_match_flag = OAL_TRUE;
            break;
        }
    }

    oal_spin_unlock_irq_restore(&pst_mgr->st_spin_lock, &ul_irq_save);

    if (!en_match_flag) {
        if (!pst_mgr->ul_node_shortage) {
            // ??????????????
            OAL_IO_PRINT("the node(0x%p) maybe not register!\n", (void *)ul_addr);
            mem_trace_info_show(MEM_TRACE_INFO_MODE2, 0, 0);
            mem_trace_info_show(MEM_TRACE_INFO_MODE1, 0, 0);
            oal_warn_on(1);
        }
    }
}

/*
 * ?? ?? ??  : mem_trace_info_show
 * ????????  : ????????????
 */
oal_void mem_trace_info_show(oal_uint32 ul_mode, oal_uint32 ul_fileid, oal_uint32 ul_line)
{
    oal_dlist_head_stru *pst_entry = NULL;
    mem_trace_node *pst_mem_trace_node = NULL;
    oal_uint32 i;
    oal_uint ul_irq_save;
    mem_node_owner *pst_owner = NULL;
    mem_trace_mgmt *pst_mgr = mem_trace_get_mgr();

    oal_spin_lock_irq_save(&pst_mgr->st_spin_lock, &ul_irq_save);

    OAL_IO_PRINT("==============show mem trace info(mode=%d) shortage=%d:==================\r\n",
                 ul_mode, pst_mgr->ul_node_shortage);

    if (ul_mode == MEM_TRACE_INFO_MODE0) {
        OAL_IO_PRINT("    Addr    | File_id | Line |    Time    | trace_file | trace_line | Last_time\r\n");
        pst_owner = mem_trace_owner_search(ul_fileid, ul_line);
        if (pst_owner != NULL) {
            if (pst_owner->ul_fileid != ul_fileid) {
                OAL_IO_PRINT("no mem trace owner find!\r\n");
            } else {
                oal_dlist_search_for_each(pst_entry, &(pst_owner->st_owner_list_head))
                {
                    pst_mem_trace_node = oal_dlist_get_entry(pst_entry, mem_trace_node, st_owner_list_entry);
                    OAL_IO_PRINT("0x%p |%8u | %4u | %10u | %10u | %10u | %10u\r\n",
                                 (oal_void *)pst_mem_trace_node->ul_addr,
                                 pst_mem_trace_node->ul_fileid,
                                 pst_mem_trace_node->ul_linenum,
                                 pst_mem_trace_node->ul_time,
                                 pst_mem_trace_node->ul_last_trace_fileid,
                                 pst_mem_trace_node->ul_last_trace_line,
                                 pst_mem_trace_node->ul_last_trace_time);
                }
            }
        } else {
            OAL_IO_PRINT("%s error:pst_owner is null\n", __FUNCTION__);
        }
    } else if (ul_mode == MEM_TRACE_INFO_MODE1) {
        OAL_IO_PRINT(" File_id | Line | Cnt \r\n");

        for (i = 0; i < MEM_TRACE_OWNER_TBL_SIZE; i++) {
            if ((pst_mgr->ast_owner[i].ul_fileid == 0xffffffff)
                && (pst_mgr->ast_owner[i].ul_linenum == 0)) {
                break;
            } else {
                OAL_IO_PRINT("%8u | %4u | %4u\r\n",
                             pst_mgr->ast_owner[i].ul_fileid,
                             pst_mgr->ast_owner[i].ul_linenum,
                             pst_mgr->ast_owner[i].ul_cnt);
            }
        }
    } else if (ul_mode == MEM_TRACE_INFO_MODE2) {
        OAL_IO_PRINT(" current mem trace cnt:%d\r\n", pst_mgr->ul_cnt);
    }
    oal_spin_unlock_irq_restore(&pst_mgr->st_spin_lock, &ul_irq_save);

    OAL_IO_PRINT("========================End=====================\r\n");
}

oal_module_symbol(__mem_trace_add_node);
oal_module_symbol(__mem_trace_delete_node);
oal_module_symbol(__mem_trace_probe);
oal_module_symbol(mem_trace_info_show);

#endif /* #ifdef _PRE_MEM_TRACE */
