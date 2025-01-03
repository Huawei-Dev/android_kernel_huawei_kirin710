/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2012-2015. All rights reserved.
 * foss@huawei.com
 *
 * If distributed as part of the Linux kernel, the following license terms
 * apply:
 *
 * * This program is free software; you can redistribute it and/or modify
 * * it under the terms of the GNU General Public License version 2 and
 * * only version 2 as published by the Free Software Foundation.
 * *
 * * This program is distributed in the hope that it will be useful,
 * * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * * GNU General Public License for more details.
 * *
 * * You should have received a copy of the GNU General Public License
 * * along with this program; if not, write to the Free Software
 * * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 * Otherwise, the following license terms apply:
 *
 * * Redistribution and use in source and binary forms, with or without
 * * modification, are permitted provided that the following conditions
 * * are met:
 * * 1) Redistributions of source code must retain the above copyright
 * *    notice, this list of conditions and the following disclaimer.
 * * 2) Redistributions in binary form must reproduce the above copyright
 * *    notice, this list of conditions and the following disclaimer in the
 * *    documentation and/or other materials provided with the distribution.
 * * 3) Neither the name of Huawei nor the names of its contributors may
 * *    be used to endorse or promote products derived from this software
 * *    without specific prior written permission.
 *
 * * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __NV_PARTITION_UPGRADE_H__
#define __NV_PARTITION_UPGRADE_H__


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct _nv_file_map_s
{
    u32 magic_num;                      /*file valid flag*//*????????   0x766e(nv): ??*/
    u32 off;                            /*file offset in flash*/
    u32 len;                            /*length of the data in this section */
}nv_file_map_s;

/*****************************NV??????????????**************************************************/
typedef struct _xnv_map_file_s
{
    nv_file_map_s stXnvFile;           /*xnv.xml????????*/
    nv_file_map_s stCustFile;          /*cust.xml????????*/
    nv_file_map_s stMapFile;           /*xnv.xml map????????*/
}xnv_map_file_s;


/*NV??????????????*/
typedef struct _nv_dload_packet_head_s
{
    nv_file_map_s nv_bin;               /*nv.bin????????*/
    nv_file_map_s xnv_xml[2];           /*????xnv.xml????????*/
    nv_file_map_s cust_xml[2];          /*????cust.xml????????*/
    nv_file_map_s xnv_map[2];           /*????xnv.xml map????????*/
    u32 ulSimNumEx;                     /*NV????????modem??????2*/
    xnv_map_file_s xnv_file[0];         /*??????????????????????????ulSimNumEx -2??*/
}nv_dload_packet_head_s;


/*****************************NV????????????**************************************************/

#define XNV_SEC_MAX                 (0x100000)
/*************************************************************************************/
/*                              XNV MAP????????                                      */
/*************************************************************************************/
/*   |-------------------|          |------------|
     |    magic num      |          | product_id |
     |-------------------|          |------------|
     |   product num     |   |----> | map_offset | ----|
     |-------------------|   |      |------------|     |
     |   reserved[16]    |   |      | map_length |     |
     |-------------------|   |      |------------|     |
     | product_info[0]   | --|  |----------------------|
     |-------------------|      |   |------------|
     | product_info[1]   |      |   | magic_num  |
     |-------------------|      |   |------------|
     | product_info[...] |      |   | class_cnt  |      |------------|
     |-------------------|      |   |------------|      |   offset   |
     | product_info[n]   |      |   |class_map[n]|----->|------------|
     |-------------------|      |   |------------|      |   length   |
     | product_map[0]    | <----|   | cate_cnt   |      |------------|
     |-------------------|          |------------|      | src_length |
     | product_map[1]    | -------->| cate_map[n]|      |------------|
     |-------------------|          |------------|      | reserved   |
     | product_map[...]  |          | prdt_cnt   |      |------------|
     |-------------------|          |------------|
     | product_map[n]    |          | prdt_map[n]|
     |-------------------|          |------------|
Description:
1. magic num?? ??
2. product num ????????????????????????
3. ??????n??product info(n??????????????), ??????????????????????????????????????????????product_map;
   info????????????????xnv.map????????????
4. ??????n??product map(n??????????????)????????????nv????????????????
5. product map????magic num??0x766e;
6. ??????????????map????????n??class????n??cate??, n??product??(n>=0)????????????????????????????
   map????????????????xnv.bin????????????
*************************************************************************************/

typedef struct _xnv_sec_info{
    u32             offset;
    u32             length;
    u32             src_length;
    u32             reserved;
}xnv_sec_info;

typedef struct _xnv_sec_data{
    u32             cnt;
    xnv_sec_info    map[0];
}xnv_sec_data;

/* CAUTION! section map is variable, can't get cate_cnt/prdt_cnt from member of this struct. */
typedef struct _xnv_prdt_map{
    xnv_sec_data    class_map;
    xnv_sec_data    cate_map;
    xnv_sec_data    prdt_map;
}xnv_prdt_map;

typedef struct _xnv_prdt_info{
    u32             prdt_id;                    /*product id */
    u32             map_data_offset;            /*????product id????xnv_prdt_info???????? */
    u32             map_data_len;               /*????product id????xnv_prdt_info???????? */
}xnv_prdt_info;

/* CAUTION! product info is variable, can't get product map from member of this struct. */
typedef struct _xnv_map_file{
    u32             magic_num;
    u32             prdt_num;
    u8              reserved[16];
    xnv_prdt_info   prdt_info[0];
    xnv_prdt_map    prdt_map[0];
}xnv_map_file;


/*************************************************************************************/
/*                              XNV BIN????????                                      */
/*************************************************************************************/
/*               |--------------------------------------------------------|
                 |magic_num| seclist offset| seclist num| prdt stru offset|
                 |--------------------------------------------------------|
                 |                      section list                      |
                 |--------------------------------------------------------|
                 |                      section data[0]                   |
                 |--------------------------------------------------------|
                 |                      section data[...]                 |
                 |--------------------------------------------------------|
                 |                      section data[n]                   |
                 |--------------------------------------------------------|
                 |                      product_struct                    |
                 |--------------------------------------------------------|
Description:
1. section list??????????????????????????section list... ??
2. cust.map, cust.bin??????????xnv??????????????
3. product structure??????????????????????;

                 |******************* section list???????? ***************|
                 
                 |--------------------------------------------------------|
                 |                      section list[0]                   |
                 |    id     |    offset    |    length     |  src_length | 
                 |--------------------------------------------------------|
                 |                      section list[1]                   |
                 |--------------------------------------------------------|
                 |                      section list[...]                 |
                 |--------------------------------------------------------|
                 |                      section list[n]                   |
                 |--------------------------------------------------------|

                 |******************* section data???????? ***************|

                 |--------------------------------------------------------|
                 |      file name[64]       |  nv_num   |   reserved[2]   |
                 |--------------------------------------------------------|
                 |                      xnv_item[0]                       |
                 |--------------------------------------------------------|
                 |                      xnv_item[1]                       |
                 |--------------------------------------------------------|
                 |                      xnv_item[...]                     |
                 |--------------------------------------------------------|
                 |                      xnv_item[n]                       |
                 |--------------------------------------------------------|

                 |*******************   xnv item ????????  ***************|

                 |--------------------------------------------------------|
                 |    magic_num   |   id     |   length    |  modem_num   |
                 |--------------------------------------------------------|
                 |                      reserved[5]                       |
                 |--------------------------------------------------------|
                 |                      modem_data[0]                     |
                 |    modem_id    | has_priority  |  priority  |  data    |
                 |--------------------------------------------------------|
                 |                      modem_data[1]                     |
                 |--------------------------------------------------------|
                 |                      modem_data[...]                   |
                 |--------------------------------------------------------|
                 |                      modem_data[n]                     |
                 |--------------------------------------------------------|

*/
/*************************************************************************************/
#define XNV_ITEM_MAGIC              (0x766e)

typedef struct _xnv_sec_list{
    u32             id;
    u32             offset;
    u32             length;
    u32             src_length;
}xnv_sec_list;

typedef struct _xnv_modem{
    u8              modem_id;
    u8              reserved[3];
    u8              data[0];
}xnv_modem;

#pragma pack(push)
#pragma pack(1)
typedef struct _xnv_item{
    u16             magic_num;
    u16             id;
    u16             length;
    u8              has_priority;
    u8              priority;
    u8              modem_num;
    u8              has_resume;
    u8              resume_value;
    u8              reserved[5];
    xnv_modem       modem_data[0];
}xnv_item;
#pragma pack(pop)

typedef struct _xnv_sec{
    u8              file_name[64];
    u32             nv_num;
    u32             reserved[2];
    xnv_item        item[0];
}xnv_sec;

typedef struct _xnv_bin_file{
    u32             magic_num;
    u32             seclist_offset;
    u32             seclist_num;
    u32             sec_offset;
    u32             reserved[12];
    xnv_sec_list    seclist[0];
    xnv_sec         sec[0];
    u32             prdt_stru[0];
}xnv_bin_file;

/*************************************************************************************/
/*                              NV ??????????                                        */
/*************************************************************************************/
/*                         |--------------|
                           |   header     |
                           |--------------|
                           |   ctrl.bin   |
                           |--------------|
                           |   xnv.map    |
                           |--------------|
                           |   xnv.bin    |
                           |--------------|
                           |   cust.map   |
                           |--------------|
                           |   cust.bin   |
                           |--------------|
Description:
1. cust.map, cust.bin????????????????????????
2. cust.map, cust.bin??????????xnv??????????????
3. 
*/
/*************************************************************************************/
typedef struct _nv_dload_head
{
    nv_file_map_s   nv_bin;          /*nv.bin????????*/
    nv_file_map_s   xnv_map;         /*????cust.xml????????*/
    nv_file_map_s   xnv;             /*????xnv.xml????????*/
    nv_file_map_s   cust_map;        /*????xnv.xml map????????*/
    nv_file_map_s   cust;            /*????xnv.xml map????????*/
    u32             reserved[16];    /*NV????????modem??????2*/
}nv_dload_head;

typedef struct _nv_dload_tail
{
    u32 crc;
    u32 upgrade_flag;
    u32 reserve[2];
}nv_dload_tail;

typedef struct _nv_dload_file{
    nv_dload_head   header;
    xnv_map_file    xnv_map;
    xnv_bin_file    xnv_bin;
    xnv_map_file    cust_map;
    xnv_bin_file    cust_bin;
    nv_dload_tail   tail;
}nv_dload_file;

bool nv_upgrade_xnv_compressed(void);
u32 bsp_nvm_upgrade(void);
u32 nv_upgrade_dec_xml(s8* path,s8* map_path,u32 card_type);
u32 nv_upgrade_dec_xml_all(void);
u32 nv_upgrade_file_updata(void);
bool nv_upgrade_get_flag(void);
u32 nv_upgrade_set_flag(bool flag);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /*__NV_PARTITION_UPGRADE_H__*/






