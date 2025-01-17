

/* ?????????? */
#include "oal_ext_if.h"
#include "oam_ext_if.h"
#include "securec.h"

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_OAL_FSM_C

/*
 * ?? ?? ??  : oal_fsm_create
 * ????????  : ??????????????
 * ????????  : p_oshandle: ??????owner????????????????????????????VAP????
 *             p_name    : ????????????
 *             p_ctx     : ??????context,????pm_handler
 *             uc_init_state:????????
 *             p_state_info:??????????????
 *             uc_num_states:??????????????
 *             pp_event_names:????????????????????????????
 *             us_num_event_names:????????
 */
oal_uint32 oal_fsm_create(oal_void *p_oshandle, /* ??????owner????????????????????????????VAP???? */
                          const oal_uint8 *p_name,                    /* ???????????? */
                          oal_void *p_ctx,                            /* ??????context */
                          oal_fsm_stru *pst_oal_fsm,                  /* oal?????????? */
                          oal_uint8 uc_init_state,                    /* ???????? */
                          const oal_fsm_state_info *p_state_info,     /* ?????????????? */
                          oal_uint8 uc_num_states)                    /* ?????????????????? */
{
    oal_uint32 ul_loop;

    if (pst_oal_fsm == OAL_PTR_NULL) {
        OAL_IO_PRINT("{oal_fsm_create:pst_oal_fsm is NULL }");
        return OAL_ERR_CODE_PTR_NULL;
    }

    if (uc_num_states > OAL_FSM_MAX_STATES) {
        OAL_IO_PRINT("{oal_fsm_create:state number [%d] too big. }", uc_num_states);
        return OAL_FAIL;
    }

    /* ?????????????????????????????????? */
    for (ul_loop = 0; ul_loop < uc_num_states; ul_loop++) {
        if ((p_state_info[ul_loop].state >= OAL_FSM_MAX_STATES) || (p_state_info[ul_loop].state != ul_loop)) {
            /* OAM??????????????%s */
            OAL_IO_PRINT("oal_fsm_create::entry %d has invalid state %d }", ul_loop, p_state_info[ul_loop].state);
            return OAL_FAIL;
        }
    }

    memset_s(pst_oal_fsm, OAL_SIZEOF(oal_fsm_stru), 0, OAL_SIZEOF(oal_fsm_stru));
    pst_oal_fsm->uc_cur_state = uc_init_state;
    pst_oal_fsm->uc_prev_state = uc_init_state;
    pst_oal_fsm->p_state_info = p_state_info;
    pst_oal_fsm->uc_num_states = uc_num_states;
    pst_oal_fsm->p_oshandler = p_oshandle;
    pst_oal_fsm->p_ctx = p_ctx;
    pst_oal_fsm->us_last_event = OAL_FSM_EVENT_NONE;

    /* strncpy fsm name */
    ul_loop = 0;
    while ((ul_loop < OAL_FSM_MAX_NAME - 1) && (p_name[ul_loop] != '\0')) {
        pst_oal_fsm->uc_name[ul_loop] = p_name[ul_loop];
        ul_loop++;
    }
    if (ul_loop < OAL_FSM_MAX_NAME) {
        pst_oal_fsm->uc_name[ul_loop] = '\0';
    }

    /* ?????????? */
    if (pst_oal_fsm->p_state_info[pst_oal_fsm->uc_cur_state].oal_fsm_entry) {
        pst_oal_fsm->p_state_info[pst_oal_fsm->uc_cur_state].oal_fsm_entry(pst_oal_fsm->p_ctx);
    }

    return OAL_SUCC;
}

/*
 * ?? ?? ??  : oal_fsm_trans_to_state
 * ????????  : ????????destroy????
 * ????????  : p_fsm:??????????
 */
oal_uint32 oal_fsm_trans_to_state(oal_fsm_stru *p_fsm, oal_uint8 uc_state)
{
    oal_uint8 uc_cur_state = p_fsm->uc_cur_state;

    if ((uc_state == OAL_FSM_STATE_NONE) || (uc_state >= OAL_FSM_MAX_STATES) || (uc_state >= p_fsm->uc_num_states)) {
        OAL_IO_PRINT("oal_fsm_trans_to_state::trans to state %d needs to be a valid state cur_state=%d",
                     uc_state, uc_cur_state);
        return OAL_FAIL;
    }

    if (uc_state == uc_cur_state) {
        OAL_IO_PRINT("oal_fsm_trans_to_state::trans to state %d needs to be a valid state cur_state=%d",
                     uc_state, uc_cur_state);
        return OAL_SUCC;
    }

    /* ?????????????????????? */
    if (p_fsm->p_state_info[p_fsm->uc_cur_state].oal_fsm_exit) {
        p_fsm->p_state_info[p_fsm->uc_cur_state].oal_fsm_exit(p_fsm->p_ctx);
    }

    /* ???????????????????? */
    if (p_fsm->p_state_info[uc_state].oal_fsm_entry) {
        p_fsm->p_state_info[uc_state].oal_fsm_entry(p_fsm->p_ctx);
    }

    p_fsm->uc_prev_state = uc_cur_state;
    p_fsm->uc_cur_state = uc_state;

    return OAL_SUCC;
}

/*
 * ?? ?? ??  : oal_fsm_event_dispatch
 * ????????  : ????????????????????
 * ????????  : p_fsm:??????????
 */
oal_uint32 oal_fsm_event_dispatch(oal_fsm_stru *p_fsm, oal_uint16 us_event,
                                  oal_uint16 us_event_data_len, oal_void *p_event_data)
{
    oal_uint32 ul_event_handled = OAL_FAIL;

    if (p_fsm == OAL_PTR_NULL) {
        OAL_IO_PRINT("oal_fsm_event_dispatch:p_fsm = OAL_PTR_NULL");
        return OAL_ERR_CODE_PTR_NULL;
    }

    if ((p_fsm->uc_cur_state != OAL_FSM_STATE_NONE) && (p_fsm->uc_cur_state < p_fsm->uc_num_states)) {
        p_fsm->us_last_event = us_event;
        ul_event_handled = (*p_fsm->p_state_info[p_fsm->uc_cur_state].oal_fsm_event)(p_fsm->p_ctx, us_event,
                                                                                     us_event_data_len,
                                                                                     p_event_data);
    }
    if (ul_event_handled == OAL_FAIL) {
        OAL_IO_PRINT("oal_fsm_event_dispatch:event[%d] did not handled in state %d",
                     us_event, p_fsm->p_state_info[p_fsm->uc_cur_state].state);
        return OAL_FAIL;
    }

    return OAL_SUCC;
}
/*lint -e19*/
oal_module_symbol(oal_fsm_create);
oal_module_symbol(oal_fsm_trans_to_state);
oal_module_symbol(oal_fsm_event_dispatch);
/*lint +e19*/
