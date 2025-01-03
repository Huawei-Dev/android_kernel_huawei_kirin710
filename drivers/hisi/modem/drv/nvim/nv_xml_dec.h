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

#ifndef _NV_XML_DEC_H_
#define _NV_XML_DEC_H_

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif
#pragma pack(push)
#pragma pack(4)

/*****************************************************************************
1 ??????????????
*****************************************************************************/
#include "nv_comm.h"
#include "nv_ctrl.h"

/*****************************************************************************
2 ??????
*****************************************************************************/
#define  XML_FILE_READ_BUFF_SIZE              (0x1000)  /* ????????????????         */
#define  XML_NODE_LABEL_BUFF_LENGTH_ORIGINAL  (0X80)   /* ??????????????????       */
#define  XML_NODE_VALUE_BUFF_LENGTH_ORIGINAL  (0X8000) /* ????????????????         */
#define  XML_MAX_HARDWARE_LEN                 (0X20)    /* ????Product Id?????????? */

/*****************************************************************************
3 ????????
*****************************************************************************/

/*****************************************************************************
??????    : XML_RESULT_ENUM_UINT32
????????  :
ASN.1???? :
????????  : XML????????????????????
*****************************************************************************/
enum XML_RESULT_ENUM
{
    XML_RESULT_SUCCEED                        = 0 , /* ????                      */
    XML_RESULT_SUCCEED_IGNORE_CHAR                , /* ??????????????\r\n\t      */
    XML_RESULT_FALIED_PARA_POINTER                , /* ??????????????            */
    XML_RESULT_FALIED_MALLOC                      , /* ????????????              */
    XML_RESULT_FALIED_BAD_SYNTAX                  , /* ??????XML????             */
    XML_RESULT_FALIED_BAD_CHAR                    , /* ??????????                */
    XML_RESULT_FALIED_READ_FILE                   , /* ????????????              */
    XML_RESULT_FALIED_WRITE_NV                    , /* ??NV Value????            */
    XML_RESULT_FALIED_OUT_OF_BUFF_LEN             , /* ??????????????            */
    XML_RESULT_FALIED_OUT_OF_MAX_VALUE            , /* ????NV ID????????         */
    XML_RESULT_FALIED_OUT_OF_0_9                  , /* NV ID??????0-9            */
    XML_RESULT_FALIED_OUT_OF_0_F                  , /* NV Value??????0-F         */
    XML_RESULT_FALIED_OUT_OF_2_CHAR               , /* NV Value??????1Byte       */
    XML_RESULT_FALIED_NV_ID_IS_NULL               , /* NV ID??????               */
    XML_RESULT_FALIED_NV_VALUE_IS_NULL            , /* NV Value??????            */
    XML_RESULT_FALIED_PRODUCT_MATCH               , /* <product>???????????????? */
    XML_RESULT_BUTT
};
typedef u32 XML_RESULT_ENUM_UINT32;

/*****************************************************************************
??????    : XML_RESULT_ENUM_UINT32
????????  :
ASN.1???? :
????????  : XML??????????
*****************************************************************************/
enum XML_ANALYSE_STATUS_ENUM
{
    XML_ANASTT_ORIGINAL                       = 0 , /* ????                 */
    XML_ANASTT_ENTER_LABLE                        , /* ????????             */
    XML_ANASTT_IGNORE                             , /* ??????????           */
    XML_ANASTT_NODE_LABLE                         , /* ??????????           */
    XML_ANASTT_SINGLE_ENDS_LABLE                  , /* ????????????         */
    XML_ANASTT_LABLE_END_MUST_RIGHT               , /* ??????????????       */
    XML_ANASTT_PROPERTY_START                     , /* ????????????         */
    XML_ANASTT_PROPERTY_NAME_START                , /* ????????????????     */
    XML_ANASTT_PROPERTY_NAME_END                  , /* ??????????????????"  */
    XML_ANASTT_PROPERTY_VALUE_START               , /* "??????????="        */
    XML_ANASTT_PROPERTY_VALUE_END                 , /* ????????????????>    */
    XML_ANASTT_BUTT
};
typedef u32 XML_ANALYSE_STATUS_ENUM_UINT32;
typedef u32 (*XML_FUN)(s8 cnowchar);

/*****************************************************************************
??????    : XML_PRODUCT_NODE_STATUS_ENUM_UINT32
????????  :
ASN.1???? :
????????  : ????????xnv.xml????????????product??????????????????????????
*****************************************************************************/
enum XML_PRODUCT_STATUS_ENUM
{
    XML_PRODUCT_NODE_STATUS_INVALID           = 0 , /* Product??????????ID???????? */
    XML_PRODUCT_NODE_STATUS_VALID                 , /* Product??????????ID???????? */
    XML_PRODUCT_NODE_BUTT
};
typedef u32 XML_PRODUCT_STATUS_ENUM_UINT32;

/*****************************************************************************
??????    : XML_DECODE_STATE_ENUM_UINT32
????????  :
ASN.1???? :
????????  : ????????xnv.xml????????????????XML????????????????
*****************************************************************************/
enum XML_DECODE_STATUS_ENUM
{
    XML_DECODE_STATUS_DECODING                = 0 , /* ????XML??????????   */
    XML_DECODE_STATUS_FINISHED                    , /* ????XML???????????? */
    XML_DECODE_BUTT
};
typedef u32 XML_DECODE_STATE_ENUM_UINT32;

/*****************************************************************************
??????    : XML_DECODE_JUMP_FLAG_ENUM
????????  :
ASN.1???? :
????????  : ????????xnv.xml????????????????????????????
*****************************************************************************/
enum XML_DECODE_JUMP_FLAG_ENUM
{
    XML_DECODE_STATUS_NOJUMP    = 0,              /* product_NvInfo????????????   */
    XML_DECODE_STATUS_JUMP ,                      /* product_NvInfo????????????*/
    XML_DECODE_STATUS_2JUMP,                      /* product????????*/
    XML_DECODE_STATUS_JUMP_BUTT
};
typedef u32 XML_DECODE_JUMP_FLAG_ENUM;

/*****************************************************************************
4 UNION????
*****************************************************************************/

/*****************************************************************************
5 STRUCT????
*****************************************************************************/

/*****************************************************************************
??????    : XNV_MAP_PRODUCT_INFO
????????  :
ASN.1???? :
????????  : XNV XML????????product????????
*****************************************************************************/
typedef struct
{
    u32 product_id;              /*product id*/
    u32 productCatOff;           /*product cat offset in the file*/
    u32 productIdOff;            /*product id  offset in the file*/
}XNV_MAP_PRODUCT_INFO;


/*****************************************************************************
??????    : XNV_MAP_HEAD_STRU
????????  :
ASN.1???? :
????????  : XNV XML??????????????
*****************************************************************************/
typedef struct
{
    u32 magic_num;               /*0x13579bde*/
    u32 product_num;             /*product ????*/
    u8  md5[16];                 /*MD5??????*/
    XNV_MAP_PRODUCT_INFO product_info[0];
}XNV_MAP_HEAD_STRU;

/*****************************************************************************
??????    : XML_NODE_PROPERTY
????????  :
ASN.1???? :
????????  : ??????????????????
*****************************************************************************/
typedef struct
{
    u32 ulnamelength;                  /* pcPropertyName ??????????  */
    u32 ulvaluelength;                 /* pcPropertyValue ?????????? */
    s8* pcpropertyname;                 /* ????????                   */
    s8* pcpropertyvalue;                /* ??????                     */
}XML_NODE_PROPERTY_STRU;

/*NV??????????*/

#define XML_NODE_PROPERTY_NUM   (2)
/*****************************************************************************
??????    : XML_NODE_STRU
????????  :
ASN.1???? :
????????  : XML????????
*****************************************************************************/
typedef struct
{
    u32 ullabellength;                 /* pcNodeLabel ??????????    */
    u32 ullabelendlength;              /* pcNodeLabelEnd ?????????? */
    u32 ulvaluelength;                 /* pcNodeValue ??????????    */
    u32  ulPropertyIndex;               /*????????????,????stproperty????????*/
    s8*  pcnodelabel;                   /* ????????                  */
    s8*  pcnodelabelend;                /* ????????????              */
    s8*  pcnodevalue;                   /* ??????                    */
    XML_NODE_PROPERTY_STRU stproperty[XML_NODE_PROPERTY_NUM];        /* ????                      */
}XML_NODE_STRU;

/*****************************************************************************
??????    : XML_PRODUCT_STRU
????????  :
ASN.1???? :
????????  : ????????PRODUCT????????
*****************************************************************************/
typedef struct
{
    /* ????product??????????????????????????    */
    XML_PRODUCT_STATUS_ENUM_UINT32 envalidnode;
    /* ????XML????????????                      */
    XML_DECODE_STATE_ENUM_UINT32   enxmldecodestate;
    /* ??????Product??????????product?????????? */
    u32                     ulnodelevel;
    /* ??????????????product id                 */
    s8                       acproductid[XML_MAX_HARDWARE_LEN];
    /*????XML????????????????product_NvInfo????*/
    XML_DECODE_JUMP_FLAG_ENUM      enxmldecodejump;
}XML_PRODUCT_STRU;

/*****************************************************************************
??????    : XML_ERROR_INFO_STRU
????????  :
ASN.1???? :
????????  : ????????XML????????
*****************************************************************************/
typedef struct
{
    u32 ulxmlline;      /* XML??????????      */
    u32 ulstatus;       /* XML??????????????  */
    u32 ulcodeline;     /* ?????????????????? */
    u16 usnvid;         /* NV ID????          */
    u16 usreserve;      /* NV ID????          */
    u32 ulresult;       /* ??????????         */
} XML_ERROR_INFO_STRU;


typedef struct
{
    XML_NODE_STRU g_stlxmlcurrentnode;
    XML_PRODUCT_STRU g_stlxmlproductinfo;
    u8 *g_puclnvitem;
    s8  *g_pclfilereadbuff;
    u32 g_stlxml_lineno;
    u32 g_stlxmlproductid;
    XML_ERROR_INFO_STRU g_stlxmlerrorinfo;
    u32 card_type;
    /*????????????????????????*/
    XML_DECODE_JUMP_FLAG_ENUM g_stlxmljumpflag;
    /*????product id????????????????*/
    XNV_MAP_PRODUCT_INFO g_stlxmljumpinfo;
}XML_DOCODE_INFO;
/*****************************************************************************
6 ??????????
*****************************************************************************/


/*****************************************************************************
7 ????????
*****************************************************************************/


/*****************************************************************************
8 ????????????
*****************************************************************************/


/*****************************************************************************
9 OTHERS????
*****************************************************************************/


/*****************************************************************************
10 ????????
*****************************************************************************/

u32 xml_decode_main(FILE* fp,s8* map_path,u32 card_type);
void xml_help(void);
u32 xml_nv_search_byid(u32 itemid,u8* pdata,nv_item_info_s* ref_info,nv_file_info_s* file_info, u8** ref_offset);
void xml_nv_write_priority(u8* ref_offset , u16 priority);
u32 xml_nv_write_to_mem(u8* pdata,u32 size,u32 file_id,u32 offset);
XML_RESULT_ENUM_UINT32 xml_analyse(s8 cnowchar);
void xml_write_error_log(u32 ulerrorline, u16 ulnvid, u32 ret);
XML_RESULT_ENUM_UINT32 xml_procinit(s8* map_path);



#pragma pack(pop)
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* _NV_XML_DEC_H_ */



