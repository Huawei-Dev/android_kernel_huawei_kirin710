

#ifndef __OAL_UTIL_H__
#define __OAL_UTIL_H__

/* ?????????????? */
#include "oal_types.h"
#include "oal_mm.h"
#include "arch/oal_util.h"
#include "platform_oneimage_define.h"
#include "securec.h"

/* ?????? */
#define OAL_VA_START va_start
#define OAL_VA_END   va_end

#define OAL_VA_LIST va_list

#define OAL_MAC_ADDRESS_LAN 6

#define OAL_SEC_PER_MIN 60
/* ??????16 bit???? 32bit */
#define oal_make_word16(lsb, msb)           ((((oal_uint16)(msb) << 8) & 0xFF00) | (lsb))
#define oal_make_word32(lsw, msw)           ((((oal_uint32)(msw) << 16) & 0xFFFF0000) | (lsw))
#define oal_join_word32(lsb, ssb, asb, msb) (((oal_uint32)(msb) << 24) | ((oal_uint32)(asb) << 16) | \
                                             ((oal_uint32)(ssb) << 8) | (lsb))
#define oal_join_word20(lsw, msw)           ((((oal_uint32)(msw) << 10) & 0xFFC00) | ((lsw) & 0x3FF))

/* ???????????????????????????? */
#define padding(x, size)           (((x) + (size) - 1) & (~ ((size) - 1)))

/* increment with wrap-around */
#define oal_incr(_l, _sz)  \
    do {                   \
        (_l)++;            \
        (_l) &= ((_sz) - 1); \
    } while (0)

#define oal_decr(_l, _sz)  \
    do {                   \
        (_l)--;            \
        (_l) &= ((_sz) - 1); \
    } while (0)

/* ???????? */
#define OAL_SIZEOF sizeof

/* ???????????? */
#define oal_array_size(_ast_array) (sizeof(_ast_array) / sizeof((_ast_array)[0]))

/* ?????????? */
#define oal_get_4byte_align_value(_ul_size) (((_ul_size) + 0x03) & (~0x03))

/* ???????????????? */
#define OAL_CURRENT_TASK (current_thread_info()->task)

#define oal_swap_byteorder_16(_val) ((((_val)&0x00FF) << 8) + (((_val)&0xFF00) >> 8))

#if (_PRE_BIG_CPU_ENDIAN == _PRE_CPU_ENDIAN) /* BIG_ENDIAN */
#define oal_byteorder_to_le32(_val)     OAL_SWAP_BYTEORDER_32(_val)
#define oal_byteorder_to_le16(_val)     oal_swap_byteorder_16(_val)
#define oal_mask_inverse(_len, _offset) ((oal_uint32)(OAL_SWAP_BYTEORDER_32(~(((1 << (_len)) - 1) << (_offset)))))
#define oal_mask(_len, _offset)         ((oal_uint32)(OAL_SWAP_BYTEORDER_32(((1 << (_len)) - 1) << (_offset))))
#define oal_ntoh_16(_val)               (_val)
#define oal_ntoh_32(_val)               (_val)
#define oal_hton_16(_val)               (_val)
#define oal_hton_32(_val)               (_val)

#elif (_PRE_LITTLE_CPU_ENDIAN == _PRE_CPU_ENDIAN) /* LITTLE_ENDIAN */
#define oal_byteorder_to_le32(_val)     (_val)
#define oal_byteorder_to_le16(_val)     (_val)
#define oal_mask_inverse(_len, _offset) ((oal_uint32)(~(((1UL << (_len)) - 1) << (_offset))))
#define oal_mask(_len, _offset)         ((oal_uint32)(((1UL << (_len)) - 1) << (_offset)))
#define oal_ntoh_16(_val)               oal_swap_byteorder_16(_val)
#define oal_ntoh_32(_val)               OAL_SWAP_BYTEORDER_32(_val)
#define oal_hton_16(_val)               oal_swap_byteorder_16(_val)
#define oal_hton_32(_val)               OAL_SWAP_BYTEORDER_32(_val)
#endif

#define oal_any_null_ptr1(_ptr1)                             (((_ptr1) == NULL))
#define oal_any_null_ptr2(_ptr1, _ptr2)                      (((_ptr1) == NULL) || ((_ptr2) == NULL))
#define oal_any_null_ptr3(_ptr1, _ptr2, _ptr3)               (((_ptr1) == NULL) || ((_ptr2) == NULL) || \
                                                              ((_ptr3) == NULL))
#define oal_any_null_ptr4(_ptr1, _ptr2, _ptr3, _ptr4)        (((_ptr1) == NULL) || ((_ptr2) == NULL) || \
                                                              ((_ptr3) == NULL) || ((_ptr4) == NULL))
#define oal_any_null_ptr5(_ptr1, _ptr2, _ptr3, _ptr4, _ptr5) (((_ptr1) == NULL) || ((_ptr2) == NULL) || \
                                                              ((_ptr3) == NULL) || ((_ptr4) == NULL) || \
                                                              ((_ptr5) == NULL))
#define oal_value_eq_any2(_value, _val0, _val1)              (((_val0) == (_value)) || ((_val1) == (_value)))
#define oal_value_not_in_valid_range(_value, _start, _end)   (((_value) < (_start)) || ((_value) > (_end)))
#define oal_all_true_value2(_val0, _val1)                    (((_val0) == OAL_TRUE) && ((_val1) == OAL_TRUE))

#if (!defined(_PRE_PC_LINT) && !defined(WIN32))
#ifdef __GNUC__
#define oal_build_bug_on(_con) ((oal_void)sizeof(char[1 - 2 * !!(_con)]))
#else
#define oal_build_bug_on(_con)
#endif
#else
#define oal_bug_on(_con)
#define oal_build_bug_on(_con)
#endif

#ifndef atomic_inc_return
#define oal_atomic_inc_return(a) 0
#else
#define oal_atomic_inc_return atomic_inc_return
#endif

/* ?????? */
#define oal_min(_A, _B) (((_A) < (_B)) ? (_A) : (_B))

/* ?????? */
#define oal_max(_A, _B) (((_A) > (_B)) ? (_A) : (_B))

#define oal_sub(_A, _B) (((_A) > (_B)) ? ((_A) - (_B)) : (0))

#define oal_absolute_sub(_A, _B) (((_A) > (_B)) ? ((_A) - (_B)) : ((_B) - (_A)))

/* ??????????????????????????????32-bit???????????? */
#define oal_reg_read32(_addr) \
    *((OAL_VOLATILE oal_uint32 *)(_addr))

#define oal_reg_read16(_addr) \
    *((OAL_VOLATILE oal_uint16 *)(_addr))

/* ??????????????32-bit???????????????????? */
#define oal_reg_write32(_addr, _val) \
    (*((OAL_VOLATILE oal_uint32 *)(_addr)) = (_val))
#define oal_reg_write16(_addr, _val) \
    (*((OAL_VOLATILE oal_uint16 *)(_addr)) = (_val))

/* Is val aligned to "align" ("align" must be power of 2) */
#ifndef IS_ALIGNED
#define oal_is_aligned(val, align) \
    (((oal_uint32)(val) & ((align) - 1)) == 0)
#else
#define oal_is_aligned IS_ALIGNED
#endif

/* Bit Values */
#define BIT31 ((oal_uint32)(1UL << 31))
#define BIT30 ((oal_uint32)(1 << 30))
#define BIT29 ((oal_uint32)(1 << 29))
#define BIT28 ((oal_uint32)(1 << 28))
#define BIT27 ((oal_uint32)(1 << 27))
#define BIT26 ((oal_uint32)(1 << 26))
#define BIT25 ((oal_uint32)(1 << 25))
#define BIT24 ((oal_uint32)(1 << 24))
#define BIT23 ((oal_uint32)(1 << 23))
#define BIT22 ((oal_uint32)(1 << 22))
#define BIT21 ((oal_uint32)(1 << 21))
#define BIT20 ((oal_uint32)(1 << 20))
#define BIT19 ((oal_uint32)(1 << 19))
#define BIT18 ((oal_uint32)(1 << 18))
#define BIT17 ((oal_uint32)(1 << 17))
#define BIT16 ((oal_uint32)(1 << 16))
#define BIT15 ((oal_uint32)(1 << 15))
#define BIT14 ((oal_uint32)(1 << 14))
#define BIT13 ((oal_uint32)(1 << 13))
#define BIT12 ((oal_uint32)(1 << 12))
#define BIT11 ((oal_uint32)(1 << 11))
#define BIT10 ((oal_uint32)(1 << 10))
#define BIT9  ((oal_uint32)(1 << 9))
#define BIT8  ((oal_uint32)(1 << 8))
#define BIT7  ((oal_uint32)(1 << 7))
#define BIT6  ((oal_uint32)(1 << 6))
#define BIT5  ((oal_uint32)(1 << 5))
#define BIT4  ((oal_uint32)(1 << 4))
#define BIT3  ((oal_uint32)(1 << 3))
#define BIT2  ((oal_uint32)(1 << 2))
#define BIT1  ((oal_uint32)(1 << 1))
#define BIT0  ((oal_uint32)(1 << 0))
#define ALL   0xFFFF

#define BIT(nr) (1UL << (nr))

#define OAL_BITS_PER_BYTE 8 /* ????????????????bit???? */

/* ?????? */
#define oal_set_bit(_val)                        (1 << (_val))
#define oal_left_shift(_data, _num)              ((_data) << (_num))
#define oal_rght_shift(_data, _num)              ((_data) >> (_num))
#define oal_write_bits(_data, _val, _bits, _pos) \
    do {                                                                    \
        (_data) &= ~((((oal_uint32)1 << (_bits)) - 1) << (_pos));           \
        (_data) |= (((_val) & (((oal_uint32)1 << (_bits)) - 1)) << (_pos)); \
    } while (0)
#define oal_get_bits(_data, _bits, _pos) (((_data) >> (_pos)) & (((oal_uint32)1 << (_bits)) - 1))

/* ???????? */
#define NUM_1_BITS  1
#define NUM_2_BITS  2
#define NUM_3_BITS  3
#define NUM_4_BITS  4
#define NUM_5_BITS  5
#define NUM_6_BITS  6
#define NUM_7_BITS  7
#define NUM_8_BITS  8
#define NUM_9_BITS  9
#define NUM_10_BITS 10
#define NUM_11_BITS 11
#define NUM_12_BITS 12
#define NUM_13_BITS 13
#define NUM_14_BITS 14
#define NUM_15_BITS 15
#define NUM_16_BITS 16
#define NUM_17_BITS 17
#define NUM_18_BITS 18
#define NUM_19_BITS 19
#define NUM_20_BITS 20
#define NUM_21_BITS 21
#define NUM_22_BITS 22
#define NUM_23_BITS 23
#define NUM_24_BITS 24
#define NUM_25_BITS 25
#define NUM_26_BITS 26
#define NUM_27_BITS 27
#define NUM_28_BITS 28
#define NUM_29_BITS 29
#define NUM_30_BITS 30
#define NUM_31_BITS 31
#define NUM_32_BITS 32

/* ?????????? */
#define BIT_OFFSET_0  0
#define BIT_OFFSET_1  1
#define BIT_OFFSET_2  2
#define BIT_OFFSET_3  3
#define BIT_OFFSET_4  4
#define BIT_OFFSET_5  5
#define BIT_OFFSET_6  6
#define BIT_OFFSET_7  7
#define BIT_OFFSET_8  8
#define BIT_OFFSET_9  9
#define BIT_OFFSET_10 10
#define BIT_OFFSET_11 11
#define BIT_OFFSET_12 12
#define BIT_OFFSET_13 13
#define BIT_OFFSET_14 14
#define BIT_OFFSET_15 15
#define BIT_OFFSET_16 16
#define BIT_OFFSET_17 17
#define BIT_OFFSET_18 18
#define BIT_OFFSET_19 19
#define BIT_OFFSET_20 20
#define BIT_OFFSET_21 21
#define BIT_OFFSET_22 22
#define BIT_OFFSET_23 23
#define BIT_OFFSET_24 24
#define BIT_OFFSET_25 25
#define BIT_OFFSET_26 26
#define BIT_OFFSET_27 27
#define BIT_OFFSET_28 28
#define BIT_OFFSET_29 29
#define BIT_OFFSET_30 30
#define BIT_OFFSET_31 31

/* ????????????????????????????, fract_bits?????????? */
#define _round_pos(fix_num, fract_bits) (((fix_num) + (1 << ((fract_bits)-1))) >> (fract_bits))
#define _round_neg(fix_num, fract_bits) (-_round_pos(-(fix_num), (fract_bits)))
#define oal_round(fix_num, fract_bits)\
        ((fix_num) > 0 ? _round_pos(fix_num, fract_bits) : _round_neg(fix_num, fract_bits))
/* ???????????????????????????? */
#define oal_roundup(_old_len, _align) ((((_old_len) + ((_align)-1)) / (_align)) * (_align))

#define OAL_RSSI_INIT_MARKER   0x320 /* RSSI???????????? */
#define OAL_RSSI_MAX_DELTA     24    /* ???????? 24/8 = 3 */
#define OAL_RSSI_FRACTION_BITS 3
#define OAL_RSSI_SIGNAL_MIN    (-103)   /* ????RSSI?????? */
#define OAL_RSSI_SIGNAL_MAX    5      /* ????RSSI?????? */
#define OAL_SNR_INIT_VALUE     0x7F   /* SNR???????????? */
#define OAL_RSSI_INIT_VALUE    (-128) /* RSSI???????? */

#define OAL_IPV6_ADDR_LEN 16

/* STRUCT???? */
#define HI11XX_LOG_ERR     0
#define HI11XX_LOG_WARN    1
#define HI11XX_LOG_INFO    2
#define HI11XX_LOG_DBG     3
#define HI11XX_LOG_VERBOSE 4

#ifdef CONFIG_PRINTK
#include <linux/module.h>

#include "platform_oneimage_define.h"
#ifndef HI11XX_LOG_MODULE_NAME
#define HI11XX_LOG_MODULE_NAME "[HI11XX]"
extern oal_int32 g_hi11xx_loglevel;
#else
static oal_int32 HI11XX_LOG_MODULE_NAME_VAR = HI11XX_LOG_INFO;
#if defined(PLATFORM_DEBUG_ENABLE) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
module_param(HI11XX_LOG_MODULE_NAME_VAR, int, S_IRUGO | S_IWUSR);
#endif
#endif

#ifndef HI11XX_LOG_MODULE_NAME_VAR
#define HI11XX_LOG_MODULE_NAME_VAR g_hi11xx_loglevel
extern oal_int32 g_hi11xx_loglevel;
#endif

#define hi11xx_log_module_name_nums_str(num) #num

extern char *g_hi11xx_loglevel_format[];

#define oal_print_hi11xx_log(loglevel, fmt, arg...)                           \
    do {                                                                      \
        if (oal_unlikely(HI11XX_LOG_MODULE_NAME_VAR >= loglevel)) {           \
            printk("%s%s" fmt "[%s:%d]\n", g_hi11xx_loglevel_format[loglevel], \
            HI11XX_LOG_MODULE_NAME, ##arg, __FUNCTION__, __LINE__);            \
        }                                                                      \
    } while (0)
#else
#define oal_print_hi11xx_log
#endif

#ifdef _PRE_CONFIG_HISI_PANIC_DUMP_SUPPORT
typedef struct _hwifi_panic_log_ hwifi_panic_log;
typedef oal_int32 (*hwifi_panic_log_cb)(oal_void *data, char *pst_buf, oal_int32 buf_len);
struct _hwifi_panic_log_ {
    struct list_head list;
    /* the log module name */
    char *name;
    hwifi_panic_log_cb cb;
    oal_void *data;
};
#define declare_wifi_panic_stru(module_name, func) \
    hwifi_panic_log module_name = {                \
        .name = #module_name,                      \
        .cb = (hwifi_panic_log_cb)func,            \
    }
#endif

/* ???????? */
extern oal_uint16 cal_crc_16(const oal_uint8 *data, const oal_uint16 data_bit_num);

#ifdef _PRE_CONFIG_HISI_PANIC_DUMP_SUPPORT
/*
 * ?? ?? ??  : hwifi_panic_log_register
 * ????????  : Kernl Panic ??????????????
 */
extern oal_void hwifi_panic_log_register(hwifi_panic_log *log, void *data);
extern oal_void hwifi_panic_log_unregister(hwifi_panic_log *log);
extern oal_void hwifi_panic_log_dump(char *print_level);
#else
OAL_STATIC OAL_INLINE oal_void hwifi_panic_log_dump(char *print_level)
{
}
#endif

OAL_STATIC OAL_INLINE oal_void oal_print_inject_check_stack(oal_void)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    const oal_uint32 trinity_name_len = 50;
    char trinity_name[trinity_name_len];
    memset_s(trinity_name, sizeof(trinity_name), 0, sizeof(trinity_name));
    if (memcpy_s(trinity_name, sizeof(trinity_name), current->comm, OAL_STRLEN("trinity")) != EOK) {
        OAL_IO_PRINT("memcpy_s error, destlen=%u, srclen=%u\n ",
                     (oal_uint32)sizeof(trinity_name), (oal_uint32)OAL_STRLEN("trinity"));
        return;
    }

    if (unlikely(!memcmp((void *)"trinity", (void *)trinity_name, OAL_STRLEN("trinity")))) {
        /* Debug */
        WARN_ON(1);
    }
#endif
}

/*
 * ?? ?? ??  : oal_strtohex
 * ????????  : ????????????????16??????
 */
OAL_STATIC OAL_INLINE oal_uint8 oal_strtohex(const oal_int8 *c_string)
{
    oal_uint8 uc_ret = 0;
    if (oal_unlikely(c_string == NULL)) {
        oal_warn_on(1);
        return 0;
    }

    if (*c_string >= '0' && *c_string <= '9') {
        uc_ret = (oal_uint8)(*c_string - '0');
    } else if (*c_string >= 'A' && *c_string <= 'F') {
        uc_ret = (oal_uint8)(*c_string - 'A' + 10); /* ??10??????????????'A'~'F'????10~15 */
    } else if (*c_string >= 'a' && *c_string <= 'f') {
        uc_ret = (oal_uint8)(*c_string - 'a' + 10); /* ??10??????????????'a'~'f'????10~15 */
    }

    return uc_ret;
}

/*
 * ?? ?? ??  : oal_strtoaddr
 * ????????  : ????????MAC????
 * ????????  : pc_param: MAC??????????, ???? xx:xx:xx:xx:xx:xx  ??????????':'??'-'
 * ????????  : puc_mac_addr: ??????16????????MAC????
 */
OAL_STATIC OAL_INLINE oal_void oal_strtoaddr(const oal_int8 *pc_param, oal_uint8 *puc_mac_addr)
{
    oal_uint8 uc_char_index;
    const oal_uint32 uc_mac_max_num = 12;

    if (oal_unlikely((pc_param == NULL) || (puc_mac_addr == NULL))) {
        oal_warn_on(1);
        return;
    }

    /* ????mac????,16???????? */
    for (uc_char_index = 0; uc_char_index < uc_mac_max_num; uc_char_index++) {
        if ((*pc_param == ':') || (*pc_param == '-')) {
            pc_param++;
            if (uc_char_index != 0) {
                uc_char_index--;
            }

            continue;
        }

        /* ??????????????????????????mac????????buff????xx:xx ??????????mac???? */
        puc_mac_addr[uc_char_index / 2] =
            (oal_uint8)(puc_mac_addr[uc_char_index / 2] * 16 * (uc_char_index % 2) +
                        oal_strtohex(pc_param));
        pc_param++;
    }
}

/*
 * ?? ?? ??  : oal_strtoipv6
 * ????????  : ????????ipv6????
 * ????????  : pc_param: ipv6??????????, ???? xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
 * ????????  : puc_mac_addr: ??????16????????ipv6????
 */
OAL_STATIC OAL_INLINE oal_void oal_strtoipv6(const oal_int8 *pc_param, oal_uint8 *puc_ipv6_addr)
{
    oal_uint8 uc_char_index;
    const oal_uint32 uc_ipv6_max_num = OAL_IPV6_ADDR_LEN * 2; /* ipv6??????????xx:xx ????????ipv6???? */

    if (oal_unlikely((pc_param == NULL) || (puc_ipv6_addr == NULL))) {
        oal_warn_on(1);
        return;
    }

    /* ????ipv6????,16???????? */
    for (uc_char_index = 0; uc_char_index < uc_ipv6_max_num; uc_char_index++) {
        if ((*pc_param == ':')) {
            pc_param++;
            if (uc_char_index != 0) {
                uc_char_index--;
            }

            continue;
        }
        /* ??ipv6????????????16???????? */
        puc_ipv6_addr[uc_char_index >> 1] =
            (oal_uint8)(((puc_ipv6_addr[uc_char_index >> 1]) << 4) * (uc_char_index % 2) +
                        oal_strtohex(pc_param));
        pc_param++;
    }
}

/*
 * ?? ?? ??  : oal_memcmp
 * ????????  : compare memory areas
 */
OAL_STATIC OAL_INLINE oal_int oal_memcmp(OAL_CONST oal_void *p_buf1, OAL_CONST oal_void *p_buf2, oal_uint32 ul_count)
{
    return OAL_MEMCMP(p_buf1, p_buf2, ul_count);
}

OAL_STATIC OAL_INLINE oal_int oal_strncmp(const char *p_buf1, const char *p_buf2, oal_uint32 ul_count)
{
    return OAL_STRNCMP(p_buf1, p_buf2, ul_count);
}

OAL_STATIC OAL_INLINE oal_int oal_strncasecmp(OAL_CONST oal_int8 *p_buf1, OAL_CONST oal_int8 *p_buf2,
                                              oal_uint32 ul_count)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return OAL_STRNCASECMP(p_buf1, p_buf2, ul_count);
#else
    return OAL_STRNCMP(p_buf1, p_buf2, ul_count); /* windows still use strncmp */
#endif
}

/*
 * ?? ?? ??  : oal_get_random_bytes
 * ????????  : ??urandom??????????????
 * ????????  : pc_random_buf :??????????????????????buf
 *             ul_random_len :????????????(??????)
 */
OAL_STATIC OAL_INLINE void oal_get_random_bytes(oal_int8 *pc_random_buf, oal_uint32 ul_random_len)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    if (oal_unlikely(pc_random_buf == NULL)) {
        oal_warn_on(1);
        return;
    }
    get_random_bytes(pc_random_buf, ul_random_len);
#endif
}

OAL_STATIC OAL_INLINE oal_uint8 oal_get_random(oal_void)
{
    return 1;
}

/*
 * ?? ?? ??  : oal_gen_random
 * ????????  : ??????????
 * ????????  : ul_val:????????   us_rst_flag:0:??????????????????0:????????????
 */
OAL_STATIC OAL_INLINE oal_uint8 oal_gen_random(oal_uint32 ul_val, oal_uint8 us_rst_flag)
{
    OAL_STATIC oal_uint32 ul_rand = 0;
    if (us_rst_flag != 0) {
        ul_rand = ul_val;
    }
    ul_rand = ul_rand * 1664525L + 1013904223L;
    return (oal_uint8)(ul_rand >> 24); /* ????24??????32??????????8???????????? */
}

/*
 * ?? ?? ??  : oal_bit_get_num_one_byte
 * ????????  : ??????????????????????????bit1??????
 * ????????  : byte:??????????????
 * ?? ?? ??  : bit??????
 */
OAL_STATIC OAL_INLINE oal_uint8 oal_bit_get_num_one_byte(oal_uint8 byte)
{
    byte = (byte & 0x55) + ((byte >> 1) & 0x55);
    byte = (byte & 0x33) + ((byte >> 2) & 0x33);
    byte = (byte & 0x0F) + ((byte >> 4) & 0x0F);

    return byte;
}

/*
 * ?? ?? ??  : oal_bit_get_num_four_byte
 * ????????  : ????????????????4??????bit1??????
 * ????????  : four_bytes:??????????????
 * ?? ?? ??  : bit??????
 */
OAL_STATIC OAL_INLINE oal_uint32 oal_bit_get_num_four_byte(oal_uint32 four_bytes)
{
    four_bytes = (four_bytes & 0x55555555) + ((four_bytes >> 1) & 0x55555555);
    four_bytes = (four_bytes & 0x33333333) + ((four_bytes >> 2) & 0x33333333);
    four_bytes = (four_bytes & 0x0F0F0F0F) + ((four_bytes >> 4) & 0x0F0F0F0F);
    four_bytes = (four_bytes & 0x00FF00FF) + ((four_bytes >> 8) & 0x00FF00FF);
    four_bytes = (four_bytes & 0x0000FFFF) + ((four_bytes >> 16) & 0x0000FFFF);

    return four_bytes;
}

/*
 * ?? ?? ??  : oal_bit_set_bit_one_byte
 * ????????  : ??1????????????????
 * ????????  : puc_byte: ??????????????????????
 *             nr: ??????????
 */
OAL_STATIC OAL_INLINE oal_void oal_bit_set_bit_one_byte(oal_uint8 *puc_byte, oal_bitops nr)
{
    if (oal_unlikely(puc_byte == NULL)) {
        oal_warn_on(1);
        return;
    }
    *puc_byte |= ((oal_uint8)(1 << nr));
}

/*
 * ?? ?? ??  : oal_bit_clear_bit_one_byte
 * ????????  : ??1????????????????
 * ????????  : puc_byte: ??????????????????????
 *             nr: ??????????
 */
OAL_STATIC OAL_INLINE oal_void oal_bit_clear_bit_one_byte(oal_uint8 *puc_byte, oal_bitops nr)
{
    if (oal_unlikely(puc_byte == NULL)) {
        oal_warn_on(1);
        return;
    }
    *puc_byte &= (~((oal_uint8)(1 << nr)));
}

OAL_STATIC OAL_INLINE oal_uint8 oal_bit_get_bit_one_byte(oal_uint8 uc_byte, oal_bitops nr)
{
    return ((uc_byte >> nr) & 0x1);
}

/*
 * ?? ?? ??  : oal_bit_set_bit_four_byte
 * ????????  : ??4????????????????
 * ????????  : pul_byte: ??????????????????????
 *             nr: ??????????
 */
OAL_STATIC OAL_INLINE oal_void oal_bit_set_bit_four_byte(oal_uint32 *pul_byte, oal_bitops nr)
{
    if (oal_unlikely(pul_byte == NULL)) {
        oal_warn_on(1);
        return;
    }
    *pul_byte |= ((oal_uint32)(1 << nr));
}

/*
 * ?? ?? ??  : oal_bit_clear_bit_four_byte
 * ????????  : ??4????????????????
 * ????????  : pul_byte: ??????????????????????
 *             nr: ??????????
 */
OAL_STATIC OAL_INLINE oal_void oal_bit_clear_bit_four_byte(oal_uint32 *pul_byte, oal_bitops nr)
{
    if (oal_unlikely(pul_byte == NULL)) {
        oal_warn_on(1);
        return;
    }
    *pul_byte &= ~((oal_uint32)(1 << nr));
}

/*
 * ?? ?? ??  : oal_bit_set_bit_eight_byte
 * ????????  : ??8????????????????
 */
OAL_STATIC OAL_INLINE oal_void oal_bit_set_bit_eight_byte(oal_uint64 *pull_byte, oal_bitops nr)
{
    if (oal_unlikely(pull_byte == NULL)) {
        oal_warn_on(1);
        return;
    }
    *pull_byte |= ((oal_uint64)1 << nr);
}

/*
 * ?? ?? ??  : oal_bit_clear_bit_eight_byte
 * ????????  : ??8??????????????
 */
OAL_STATIC OAL_INLINE oal_void oal_bit_clear_bit_eight_byte(oal_uint64 *pull_byte, oal_bitops nr)
{
    if (oal_unlikely(pull_byte == NULL)) {
        oal_warn_on(1);
        return;
    }
    *pull_byte &= ~((oal_uint64)1 << nr);
}

/*
 * ?? ?? ??  : oal_bit_find_first_bit_one_byte
 * ????????  : ????1????????????????1??????
 * ????????  : puc_byte: ????????????
 * ?? ?? ??  : ????????????1??????
 */
OAL_STATIC OAL_INLINE oal_uint8 oal_bit_find_first_bit_one_byte(oal_uint8 uc_byte)
{
    oal_uint8 uc_ret = 0;

    uc_byte = uc_byte & (oal_uint8)(-uc_byte);

    while (uc_byte != 1) {
        uc_ret++;
        uc_byte = (uc_byte >> 1);

        if (uc_ret > 7) { /* ??????????????????????bit?? */
            return uc_ret;
        }
    }

    return uc_ret;
}

/*
 * ?? ?? ??  : oal_bit_find_first_zero_one_byte
 * ????????  : ????1????????????????0??????
 * ????????  : puc_byte: ????????????
 * ?? ?? ??  : ????????????0??????
 */
OAL_STATIC OAL_INLINE oal_uint8 oal_bit_find_first_zero_one_byte(oal_uint8 uc_byte)
{
    oal_uint8 uc_ret = 0;

    uc_byte = ~uc_byte;
    uc_byte = uc_byte & (oal_uint8)(-uc_byte);

    while (uc_byte != 1) {
        uc_ret++;
        uc_byte = (uc_byte >> 1);

        if (uc_ret > 7) { /* ??????????????????????bit?? */
            return uc_ret;
        }
    }

    return uc_ret;
}

/*
 * ?? ?? ??  : oal_bit_find_first_bit_four_byte
 * ????????  : ????1????????????????1??????
 * ????????  : puc_byte: ????????????
 * ?? ?? ??  : ????????????1??????
 */
OAL_STATIC OAL_INLINE oal_uint8 oal_bit_find_first_bit_four_byte(oal_uint32 ul_byte)
{
    oal_uint8 uc_ret = 0;

    if (ul_byte == 0) {
        return uc_ret;
    }

    if (!(ul_byte & 0xffff)) {
        ul_byte >>= 16; /* ????32bit????????16bit????0??????????????????16bit????????1?????? */
        uc_ret += 16;
    }

    if (!(ul_byte & 0xff)) {
        ul_byte >>= 8; /* ????16bit????????8bit????0??????????????????8bit????????1?????? */
        uc_ret += 8;
    }

    if (!(ul_byte & 0xf)) {
        ul_byte >>= 4; /* ????8bit????????4bit????0??????????????????4bit????????1?????? */
        uc_ret += 4;
    }

    if (!(ul_byte & 0x3)) {
        ul_byte >>= 2; /* ????4bit????????2bit????0??????????????????2bit????????1?????? */
        uc_ret += 2;
    }

    if (!(ul_byte & 1)) {
        uc_ret += 1;
    }

    return uc_ret;
}

/*
 * ?? ?? ??  : oal_bit_find_first_zero_four_byte
 * ????????  : ????1????????????????0??????
 * ????????  : puc_byte: ????????????
 * ?? ?? ??  : ????????????0??????
 */
OAL_STATIC OAL_INLINE oal_uint8 oal_bit_find_first_zero_four_byte(oal_uint32 ul_byte)
{
    oal_uint8 uc_ret = 0;

    ul_byte = ~ul_byte;

    if (!(ul_byte & 0xffff)) {
        ul_byte >>= 16; /* ????32bit????????16bit????1??????????????????16bit????????0?????? */
        uc_ret += 16;
    }

    if (!(ul_byte & 0xff)) {
        ul_byte >>= 8; /* ????16bit????????8bit????1??????????????????8bit????????0?????? */
        uc_ret += 8;
    }

    if (!(ul_byte & 0xf)) {
        ul_byte >>= 4; /* ????8bit????????4bit????1??????????????????4bit????????0?????? */
        uc_ret += 4;
    }

    if (!(ul_byte & 0x3)) {
        ul_byte >>= 2; /* ????4bit????????2bit????1??????????????????2bit????????0?????? */
        uc_ret += 2;
    }

    if (!(ul_byte & 1)) {
        uc_ret += 1;
    }

    return uc_ret;
}

/*
 * ?? ?? ??  : oal_set_mac_addr
 * ????????  : ????????mac???? ??????diyimac????
 * ????????  : puc_mac_addr1: ??????mac????
 *             puc_mac_addr2: ??????mac????
 * ?? ?? ??  : ????OAL_SUCC??????OAL_ERR_CODE_PTR_NULL
 */
OAL_STATIC OAL_INLINE oal_void oal_set_mac_addr(unsigned char *puc_mac_addr1, const unsigned char *puc_mac_addr2)
{
    if (memcpy_s(puc_mac_addr1, OAL_MAC_ADDRESS_LAN, puc_mac_addr2, OAL_MAC_ADDRESS_LAN) != EOK) {
        OAL_IO_PRINT("oal_set_mac_addr: memcpy_s failed.\n");
    }
}

/*
 * ?? ?? ??  : oal_set_mac_addr_zero
 * ????????  : mac????????
 * ????????  : puc_mac_addr: ????????mac??????????
 * ?? ?? ??  :
 */
OAL_STATIC OAL_INLINE oal_void oal_set_mac_addr_zero(oal_uint8 *puc_mac_addr)
{
    memset_s(puc_mac_addr, OAL_MAC_ADDRESS_LAN, 0, OAL_MAC_ADDRESS_LAN);
}

/*
 * ?? ?? ??  : oal_compare_mac_addr
 * ????????  : ????????mac????????????
 * ????????  : puc_mac_addr1: ??????mac????
 *             puc_mac_addr2: ??????mac????
 * ?? ?? ??  : ????????1 ?? ????????0
 */
OAL_STATIC OAL_INLINE oal_uint32 oal_compare_mac_addr(const unsigned char *puc_mac_addr1, const unsigned char *puc_mac_addr2)
{
    return (oal_uint32)oal_memcmp((void *)puc_mac_addr1, (void *)puc_mac_addr2, OAL_MAC_ADDRESS_LAN);
}

/*
 * ?? ?? ??  : oal_cmp_seq_num
 * ????????  : ??????????????????????????????????????seq_num1????seq_num2??????
 * ????????  : (1)????1
 *             (2)????2
 *             (3)????????????????????
 * ?? ?? ??  : OAL_TRUE????OAL_FALSE
 */
OAL_STATIC OAL_INLINE oal_bool_enum_uint8 oal_cmp_seq_num(oal_uint32 ul_seq_num1,
                                                          oal_uint32 ul_seq_num2,
                                                          oal_uint32 ul_diff_value)
{
    if (((ul_seq_num1 < ul_seq_num2) && ((ul_seq_num2 - ul_seq_num1) < ul_diff_value)) ||
        ((ul_seq_num1 > ul_seq_num2) && ((ul_seq_num1 - ul_seq_num2) > ul_diff_value))) {
        return OAL_TRUE;
    }

    return OAL_FALSE;
}

/*
 * ?? ?? ??  : oal_strcmp
 * ????????  : ??????????
 * ????????  : pc_src: ????????
 *             pc_dst: ??????????
 */
OAL_STATIC OAL_INLINE oal_int32 oal_strcmp(const char *pc_src, const char *pc_dst)
{
    oal_int8 c_c1;
    oal_int8 c_c2;
    oal_int32 l_ret = 0;

    if (oal_unlikely((pc_src == NULL) || (pc_dst == NULL))) {
        oal_warn_on(1);
        return 1;
    }

    do {
        c_c1 = *pc_src++;
        c_c2 = *pc_dst++;
        l_ret = c_c1 - c_c2;
        if (l_ret) {
            break;
        }
    } while (c_c1);

    return l_ret;
}

/*
 * ?? ?? ??  : oal_strim
 * ????????  : ??????????????????????????
 */
OAL_STATIC OAL_INLINE oal_int8 *oal_strim(oal_int8 *pc_s)
{
    oal_uint32 ul_size;
    oal_int8 *pc_end = NULL;

    if (oal_unlikely(pc_s == NULL)) {
        oal_warn_on(1);
        return NULL;
    }

    while (*pc_s == ' ') {
        ++pc_s;
    }

    ul_size = OAL_STRLEN(pc_s);
    if (!ul_size) {
        return pc_s;
    }

    pc_end = pc_s + ul_size - 1;
    while (pc_end >= pc_s && *pc_end == ' ') {
        pc_end--;
    }

    *(pc_end + 1) = '\0';

    return pc_s;
}

/*
 * ?? ?? ??  : oal_strstr
 * ????????  : ??pc_s1??????pc_s2????????????????
 */
OAL_STATIC OAL_INLINE oal_int8 *oal_strstr(oal_int8 *pc_s1, oal_int8 *pc_s2)
{
    return OAL_STRSTR(pc_s1, pc_s2);
}

/*
 * ?? ?? ??  : oal_init_lut
 * ????????  : ????????????LUT BITMAP??
 */
OAL_STATIC OAL_INLINE oal_uint32 oal_init_lut(oal_uint8 *puc_lut_index_table, oal_uint8 uc_bmap_len)
{
    oal_uint8 uc_lut_idx;

    if (oal_unlikely(puc_lut_index_table == NULL)) {
        oal_warn_on(1);
        return OAL_FAIL;
    }

    for (uc_lut_idx = 0; uc_lut_idx < uc_bmap_len; uc_lut_idx++) {
        puc_lut_index_table[uc_lut_idx] = 0;
    }

    return OAL_SUCC;
}

/*
 * ?? ?? ??  : oal_get_lut_index
 * ????????  : ??LUT index bitmap??????????????????????????????????????????????
 *             ????????????????????(??????????????????????????????????????)
 */
OAL_STATIC OAL_INLINE oal_uint8 oal_get_lut_index(oal_uint8 *puc_lut_index_table,
                                                  oal_uint8 uc_bmap_len,
                                                  oal_uint16 us_max_lut_size,
                                                  oal_uint16 us_start,
                                                  oal_uint16 us_stop)
{
    oal_uint8 uc_byte = 0;
    oal_uint8 uc_bit = 0;
    oal_uint8 uc_temp = 0;
    oal_uint16 us_index = 0;

    if (oal_unlikely(puc_lut_index_table == NULL)) {
        oal_warn_on(1);
        return 0;
    }

    for (uc_byte = 0; uc_byte < uc_bmap_len; uc_byte++) {
        uc_temp = puc_lut_index_table[uc_byte];

        for (uc_bit = 0; uc_bit < 8; uc_bit++) {   /* ??????bit??????????????????0 */
            if ((uc_temp & (1 << uc_bit)) == 0x0) {
                us_index = (uc_byte * 8 + uc_bit); /* ??????0??bit???????? */
                if ((us_index < us_start) || (us_index >= us_stop)) {
                    continue;
                }
                if (us_index < us_max_lut_size) {
                    puc_lut_index_table[uc_byte] |= (oal_uint8)(1 << uc_bit);

                    return (oal_uint8)us_index;
                } else {
                    return (oal_uint8)us_max_lut_size;
                }
            }
        }
    }

    return (oal_uint8)us_max_lut_size;
}

/*
 * ?? ?? ??  : oal_del_lut_index
 * ????????  : ??LUT index bitmap??????????????LUT index (??:%??????????????)
 */
OAL_STATIC OAL_INLINE oal_void oal_del_lut_index(oal_uint8 *puc_lut_index_table, oal_uint8 uc_idx)
{
    oal_uint8 uc_byte = uc_idx >> 3; /* ????3 bits????index????5?? */
    oal_uint8 uc_bit = uc_idx & 0x07;

    if (oal_unlikely(puc_lut_index_table == NULL)) {
        oal_warn_on(1);
        return;
    }

    puc_lut_index_table[uc_byte] &= ~(oal_uint8)(1 << uc_bit);
}

OAL_STATIC OAL_INLINE oal_bool_enum oal_is_active_lut_index(oal_uint8 *puc_lut_idx_status_table,
                                                            oal_uint16 us_max_lut_size,
                                                            oal_uint8 uc_idx)
{
    oal_uint8 uc_byte = uc_idx >> 3; /* ????3bit????index????5?? */
    oal_uint8 uc_bit = uc_idx & 0x07;

    if (oal_unlikely(puc_lut_idx_status_table == NULL)) {
        oal_warn_on(1);
        return OAL_FALSE;
    }

    if (uc_idx >= us_max_lut_size) {
        return OAL_FALSE;
    }

    return puc_lut_idx_status_table[uc_byte] & ((oal_uint8)(1 << uc_bit)) ? OAL_TRUE : OAL_FALSE;
}

OAL_STATIC OAL_INLINE oal_void oal_set_lut_index_status(oal_uint8 *puc_lut_idx_status_table,
                                                        oal_uint16 us_max_lut_size,
                                                        oal_uint8 uc_idx)
{
    oal_uint8 uc_byte = uc_idx >> 3; /* ????3bit????index????5?? */
    oal_uint8 uc_bit = uc_idx & 0x07;

    if (oal_unlikely(puc_lut_idx_status_table == NULL)) {
        oal_warn_on(1);
        return;
    }

    if (uc_idx >= us_max_lut_size) {
        return;
    }

    puc_lut_idx_status_table[uc_byte] |= (oal_uint8)(1 << uc_bit);
}

OAL_STATIC OAL_INLINE oal_void oal_reset_lut_index_status(oal_uint8 *puc_lut_idx_status_table,
                                                          oal_uint16 us_max_lut_size,
                                                          oal_uint8 uc_idx)
{
    oal_uint8 uc_byte = uc_idx >> 3; /* ????3bit????index????5?? */
    oal_uint8 uc_bit = uc_idx & 0x07;

    if (oal_unlikely(puc_lut_idx_status_table == NULL)) {
        oal_warn_on(1);
        return;
    }

    if (uc_idx >= us_max_lut_size) {
        return;
    }

    puc_lut_idx_status_table[uc_byte] &= ~(oal_uint8)(1 << uc_bit);
}

/*
 * ?? ?? ??  : oal_get_virt_addr
 * ????????  : ??????????????????????
 */
OAL_STATIC OAL_INLINE oal_uint32 *oal_get_virt_addr(oal_uint32 *pul_phy_addr)
{
    /* ?????????????? */
    if (pul_phy_addr == OAL_PTR_NULL) {
        return pul_phy_addr;
    }

    return (oal_uint32 *)oal_phy_to_virt_addr((uintptr_t)pul_phy_addr);
}

extern oal_int32 oal_dump_stack_str(oal_uint8 *puc_str, oal_uint32 ul_max_size);

OAL_STATIC OAL_INLINE oal_int8 oal_get_real_rssi(oal_int16 s_scaled_rssi)
{
    /* ???????? */
    return oal_round(s_scaled_rssi, OAL_RSSI_FRACTION_BITS);
}

OAL_STATIC OAL_INLINE oal_void oal_rssi_smooth(oal_int16 *ps_old_rssi, oal_int8 c_new_rssi)
{
    oal_int16 s_delta;

    if (oal_unlikely(ps_old_rssi == NULL)) {
        oal_warn_on(1);
        return;
    }

    /* ???????????????????????????????????????????????????????? */
    if (c_new_rssi < OAL_RSSI_SIGNAL_MIN || c_new_rssi > OAL_RSSI_SIGNAL_MAX) {
        return;
    }

    /* ????????????0????????????????rssi??,?????????? */
    if (c_new_rssi == 0) {
        return;
    }

    /* ????????????,??????????rssi???????????? */
    if (*ps_old_rssi == OAL_RSSI_INIT_MARKER) {
        *ps_old_rssi = (oal_int16)c_new_rssi << OAL_RSSI_FRACTION_BITS;
    }

    /* old_rssi??????????????delta */
    s_delta = (oal_int16)c_new_rssi - oal_get_real_rssi(*ps_old_rssi);
    if (s_delta > OAL_RSSI_MAX_DELTA) {
        s_delta = OAL_RSSI_MAX_DELTA;
    }
    if (s_delta < -OAL_RSSI_MAX_DELTA) {
        s_delta = -OAL_RSSI_MAX_DELTA;
    }
    *ps_old_rssi += s_delta;
}

#endif /* end of oal_util.h */
