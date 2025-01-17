

/* ?????????? */
#include "oam_linux_netlink.h"
#include "oam_ext_if.h"

#include "securec.h"
#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_OAM_LINUX_NETLINK_C

/* ???????????? */
oam_netlink_stru g_netlink;

oam_netlink_proto_ops g_netlink_ops;

/* ????????app???????? */
typedef struct {
    oal_uint32 ul_daq_addr; /* ?????????????? */
    oal_uint32 ul_data_len; /* ???????????????? */
    oal_uint32 ul_unit_len; /* ??????????????????:??????(daq_unit_head)?????? */
} oam_data_acq_info_stru;

/* ???????????????? */
typedef struct {
    oal_uint8 en_send_type; /* ?????????????????? */
    oal_uint8 uc_resv[3];
    oal_uint32 ul_msg_sn;   /* ?????????????????? */
    oal_uint32 ul_data_len; /* ???????????? */
} oam_data_acq_data_head_stru;


/*
 * ?? ?? ??  : oam_netlink_ops_register
 * ????????  : WAL????????????????????????netlink????????????(????????)
 */
oal_void oam_netlink_ops_register(oam_nl_cmd_enum_uint8 en_type,
    oal_uint32 (*p_func)(oal_uint8 *puc_data, oal_uint32 ul_len))
{
    if (oal_unlikely(p_func == OAL_PTR_NULL)) {
        OAL_IO_PRINT("oam_netlink_ops_register, p_func is null ptr.");
        return;
    }

    switch (en_type) {
        case OAM_NL_CMD_SDT:
            g_netlink_ops.p_oam_sdt_func = p_func;
            break;

        case OAM_NL_CMD_HUT:
            g_netlink_ops.p_oam_hut_func = p_func;
            break;

        case OAM_NL_CMD_ALG:
            g_netlink_ops.p_oam_alg_func = p_func;
            break;

        case OAM_NL_CMD_DAQ:
            g_netlink_ops.p_oam_daq_func = p_func;
            break;

        case OAM_NL_CMD_REG:
            g_netlink_ops.p_oam_reg_func = p_func;
            break;

        case OAM_NL_CMD_ACS:
            g_netlink_ops.p_oam_acs_func = p_func;
            break;

        case OAM_NL_CMD_PSTA:
            g_netlink_ops.p_oam_psta_func = p_func;
            break;

        default:
            OAL_IO_PRINT("oam_netlink_ops_register, err type = %d.", en_type);
            break;
    }
}

/*
 * ?? ?? ??  : oam_netlink_ops_unregister
 * ????????  : OAM????????????????????????netlink????????????(????????)
 */
oal_void oam_netlink_ops_unregister(oam_nl_cmd_enum_uint8 en_type)
{
    switch (en_type) {
        case OAM_NL_CMD_SDT:
            g_netlink_ops.p_oam_sdt_func = OAL_PTR_NULL;
            break;

        case OAM_NL_CMD_HUT:
            g_netlink_ops.p_oam_hut_func = OAL_PTR_NULL;
            break;

        case OAM_NL_CMD_ALG:
            g_netlink_ops.p_oam_alg_func = OAL_PTR_NULL;
            break;

        case OAM_NL_CMD_DAQ:
            g_netlink_ops.p_oam_daq_func = OAL_PTR_NULL;
            break;

        case OAM_NL_CMD_REG:
            g_netlink_ops.p_oam_reg_func = OAL_PTR_NULL;
            break;

        case OAM_NL_CMD_ACS:
            g_netlink_ops.p_oam_acs_func = OAL_PTR_NULL;
            break;

        case OAM_NL_CMD_PSTA:
            g_netlink_ops.p_oam_psta_func = OAL_PTR_NULL;
            break;

        default:
            OAL_IO_PRINT("oam_netlink_ops_unregister::err type = %d.", en_type);
            break;
    }
}

/*
 * ?? ?? ??  : oam_netlink_kernel_recv
 * ????????  : netlink????????????(????: host app -> ????)
 */
oal_void oam_netlink_kernel_recv(oal_netbuf_stru *pst_buf)
{
    oal_netbuf_stru *pst_netbuf = NULL;
    oal_nlmsghdr_stru *pst_nlmsghdr = NULL;

    if (pst_buf == OAL_PTR_NULL) {
        OAL_IO_PRINT("oam_netlink_kernel_recv, pst_buf is null.");
        return;
    }

    pst_netbuf = pst_buf;

    while (oal_netbuf_len(pst_netbuf) >= oal_nlmsg_space(0)) {
        pst_nlmsghdr = oal_nlmsg_hdr(pst_netbuf);

        g_netlink.ul_pid = pst_nlmsghdr->nlmsg_pid;

        switch (pst_nlmsghdr->nlmsg_type) {
            case OAM_NL_CMD_SDT:
                if (g_netlink_ops.p_oam_sdt_func != OAL_PTR_NULL) {
                    g_netlink_ops.p_oam_sdt_func(oal_nlmsg_data(pst_nlmsghdr), oal_nlmsg_payload(pst_nlmsghdr, 0));
                }
                break;

            case OAM_NL_CMD_HUT:
                if (g_netlink_ops.p_oam_hut_func != OAL_PTR_NULL) {
                    g_netlink_ops.p_oam_hut_func(oal_nlmsg_data(pst_nlmsghdr), oal_nlmsg_payload(pst_nlmsghdr, 0));
                }
                break;

            case OAM_NL_CMD_ALG:
                if (g_netlink_ops.p_oam_alg_func != OAL_PTR_NULL) {
                    g_netlink_ops.p_oam_alg_func(oal_nlmsg_data(pst_nlmsghdr), oal_nlmsg_payload(pst_nlmsghdr, 0));
                }
                break;
            case OAM_NL_CMD_DAQ:
                if (g_netlink_ops.p_oam_daq_func != OAL_PTR_NULL) {
                    g_netlink_ops.p_oam_daq_func(oal_nlmsg_data(pst_nlmsghdr), oal_nlmsg_payload(pst_nlmsghdr, 0));
                }
                break;
            case OAM_NL_CMD_REG:
                if (g_netlink_ops.p_oam_reg_func != OAL_PTR_NULL) {
                    g_netlink_ops.p_oam_reg_func(oal_nlmsg_data(pst_nlmsghdr), oal_nlmsg_payload(pst_nlmsghdr, 0));
                }
                break;
            case OAM_NL_CMD_ACS:
                if (g_netlink_ops.p_oam_acs_func != OAL_PTR_NULL) {
                    g_netlink_ops.p_oam_acs_func(oal_nlmsg_data(pst_nlmsghdr), oal_nlmsg_payload(pst_nlmsghdr, 0));
                }
                break;
            case OAM_NL_CMD_PSTA:
                if (g_netlink_ops.p_oam_psta_func != OAL_PTR_NULL) {
                    g_netlink_ops.p_oam_psta_func(oal_nlmsg_data(pst_nlmsghdr), oal_nlmsg_payload(pst_nlmsghdr, 0));
                }
                break;
            default:
                break;
        }

        oal_netbuf_pull(pst_netbuf, oal_nlmsg_align(pst_nlmsghdr->nlmsg_len));
    }
}

/*
 * ?? ?? ??  : oam_netlink_kernel_send
 * ????????  : netlink????????????(????: ???? -> host app)
 * ????????  : puc_data   : ????????
 *             ul_data_len: ????????
 *             en_type    : netlink msg????
 * ?? ?? ??  : ????: ????????????(netlink?? + payload + padding)
 */
oal_int32 oam_netlink_kernel_send(oal_uint8 *puc_data, oal_uint32 ul_data_len, oam_nl_cmd_enum_uint8 en_type)
{
#if (_PRE_OS_VERSION_RAW == _PRE_OS_VERSION)

    return 0;
#else

#if (_PRE_TARGET_PRODUCT_TYPE_1102COMMON == _PRE_CONFIG_TARGET_PRODUCT)
    return 0;
#else
    oal_netbuf_stru *pst_netbuf;
    oal_nlmsghdr_stru *pst_nlmsghdr;
    oal_uint32 ul_size;
    oal_int32 l_ret;

    if (oal_unlikely(puc_data == NULL)) {
        oal_warn_on(1);
        return -1;
    }

    // ??APP??????????????0??????????????
    if (!g_netlink.ul_pid) {
        return -1;
    }

    ul_size = oal_nlmsg_space(ul_data_len);
    pst_netbuf = oal_netbuf_alloc(ul_size, 0, WLAN_MEM_NETBUF_ALIGN);
    if (pst_netbuf == OAL_PTR_NULL) {
        return -1;
    }

    /* ??????netlink???????? */
    pst_nlmsghdr = oal_nlmsg_put(pst_netbuf, 0, 0, (oal_int32)en_type, (oal_int32)ul_data_len, 0);

    /* ???????????? */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 44))
    oal_netlink_cb(pst_netbuf).portid = 0;
#else
    oal_netlink_cb(pst_netbuf).pid = 0;
#endif
    oal_netlink_cb(pst_netbuf).dst_group = 0;

    /* ?????????? */
    l_ret = memcpy_s(oal_nlmsg_data(pst_nlmsghdr), ul_data_len, puc_data, ul_data_len);
    if (l_ret != EOK) {
        oal_netbuf_free(pst_netbuf);
        OAL_IO_PRINT("oam_netlink_kernel_send: memcpy_s failed, ret = %d", l_ret);
        return -1;
    }

    /* ???????? */
    l_ret = oal_netlink_unicast(g_netlink.pst_nlsk, pst_netbuf, g_netlink.ul_pid, OAL_MSG_DONTWAIT);

    return l_ret;

#endif /* _PRE_TARGET_PRODUCT_TYPE_1102COMMON == _PRE_CONFIG_TARGET_PRODUCT */
#endif /* _PRE_OS_VERSION_RAW == _PRE_OS_VERSION  */
}

/*
 * ?? ?? ??  : oam_netlink_kernel_send_ex
 * ????????  : netlink????????????(????: ???? -> host app)
 * ????????  : puc_data_1st: ????????1
 *             puc_data_2nd: ????????2
 *             ul_len_1st  : ????????1
 *             ul_len_2nd  : ????????2
 *             en_type     : netlink msg????
 * ?? ?? ??  : ????: ????????????(netlink?? + payload + padding)
 */
oal_int32 oam_netlink_kernel_send_ex(oal_uint8 *puc_data_1st, oal_uint8 *puc_data_2nd,
                                     oal_uint32 ul_len_1st, oal_uint32 ul_len_2nd,
                                     oam_nl_cmd_enum_uint8 en_type)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 44))
    return 0;
#else

    oal_netbuf_stru *pst_netbuf = NULL;
    oal_nlmsghdr_stru *pst_nlmsghdr = NULL;
    oal_uint32 ul_size;
    oal_int32 l_ret;

    if (oal_unlikely((puc_data_1st == NULL) || (puc_data_2nd == NULL))) {
        oal_warn_on(1);
        return -1;
    }

    ul_size = oal_nlmsg_space(ul_len_1st + ul_len_2nd);
    pst_netbuf = oal_netbuf_alloc(ul_size, 0, WLAN_MEM_NETBUF_ALIGN);
    if (pst_netbuf == OAL_PTR_NULL) {
        return -1;
    }

    /* ??????netlink???????? */
    pst_nlmsghdr = oal_nlmsg_put(pst_netbuf, 0, 0, (oal_int32)en_type, (oal_int32)(ul_len_1st + ul_len_2nd), 0);

    /* ???????????? */
    oal_netlink_cb(pst_netbuf).pid = 0;
    oal_netlink_cb(pst_netbuf).dst_group = 0;

    /* ?????????? */
    if (memcpy_s(oal_nlmsg_data(pst_nlmsghdr), (oal_uint32)(ul_len_1st + ul_len_2nd),
                 puc_data_1st, ul_len_1st) != EOK) {
        oal_netbuf_free(pst_netbuf);
        OAL_IO_PRINT ("memcpy_s error, destlen=%u, srclen=%u\n ", (oal_uint32)(ul_len_1st + ul_len_2nd), ul_len_1st);
        return -OAL_EFAIL;
    }

    memcpy_s((oal_uint8 *)oal_nlmsg_data(pst_nlmsghdr) + ul_len_1st, ul_len_2nd, puc_data_2nd, ul_len_2nd);

    /* ???????? */
    l_ret = oal_netlink_unicast(g_netlink.pst_nlsk, pst_netbuf, g_netlink.ul_pid, OAL_MSG_DONTWAIT);

    return l_ret;
#endif
}

oal_uint32 oam_netlink_kernel_create(oal_void)
{
    g_netlink.pst_nlsk = oal_netlink_kernel_create(&OAL_INIT_NET, OAM_NETLINK_ID, 0,
                                                   oam_netlink_kernel_recv, OAL_PTR_NULL,
                                                   OAL_THIS_MODULE);
    if (g_netlink.pst_nlsk == OAL_PTR_NULL) {
        OAL_IO_PRINT("oam_netlink_kernel_create, can not create netlink.");

        return OAL_ERR_CODE_PTR_NULL;
    }

    OAL_IO_PRINT("netlink create succ.");

    return OAL_SUCC;
}

oal_void oam_netlink_kernel_release(oal_void)
{
    oal_netlink_kernel_release(g_netlink.pst_nlsk);

    g_netlink.ul_pid = 0;

    OAL_IO_PRINT("netlink release succ.");
}

/*lint -e578*/ /*lint -e19*/
oal_module_symbol(g_netlink_ops);
oal_module_symbol(oam_netlink_ops_register);
oal_module_symbol(oam_netlink_ops_unregister);
oal_module_symbol(oam_netlink_kernel_send);
oal_module_symbol(oam_netlink_kernel_send_ex);
