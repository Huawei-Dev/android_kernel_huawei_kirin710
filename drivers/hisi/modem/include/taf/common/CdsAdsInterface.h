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

#ifndef __CDS_ADS_INTERFACE_H__
#define __CDS_ADS_INTERFACE_H__

/*****************************************************************************
  1 ??????????
*****************************************************************************/

#include "vos.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#if (VOS_OS_VER != VOS_WIN32)
#pragma pack(4)
#else
#pragma pack(push, 4)
#endif

#ifdef WIN32
#pragma warning(disable:4200) /* zero-sized array in struct/union */
#endif

/*****************************************************************************
  2 ??????
*****************************************************************************/

#define ADS_CDS_MSG_ID_HEADER           (0x0000)
#define CDS_ADS_MSG_ID_HEADER           (0x0010)

#define CDS_ADS_MSG_ID_HEADER_V2        (0x0100)
#define ADS_CDS_MSG_ID_HEADER_V2        (0x0120)


/*****************************************************************************
  3 ????????
*****************************************************************************/

/*****************************************************************************
 ????????: CDS_ADS_MSG_ID_ENUM
 ????????: CDS??ADS????????????
*****************************************************************************/
enum CDS_ADS_MSG_ID_ENUM
{
    /* 0x01~0x03 ???????? */

    /* CDS<--->ADS */
    ID_CDS_ADS_DATA_IND                 = CDS_ADS_MSG_ID_HEADER + 0x04,
    ID_ADS_CDS_ERR_IND                  = ADS_CDS_MSG_ID_HEADER + 0x04,

    /* CDS<--->ADS */
    ID_CDS_ADS_DATA_IND_V2              = CDS_ADS_MSG_ID_HEADER_V2 + 0x01,
    ID_ADS_CDS_DATA_IND_V2              = ADS_CDS_MSG_ID_HEADER_V2 + 0x01,

    /* ADS--->CDS */
    ID_ADS_CDS_ERR_IND_V2               = ADS_CDS_MSG_ID_HEADER_V2 + 0x11,

    ID_CDS_ADS_MSG_ID_BUTT
};
typedef VOS_UINT32 CDS_ADS_MSG_ID_ENUM_UINT32;

/*****************************************************************************
 ????????: CDS_ADS_IP_PACKET_TYPE_ENUM_UINT8
 ????????: CDS??ADS??IP??????????????
*****************************************************************************/
enum CDS_ADS_IP_PACKET_TYPE_ENUM
{
    CDS_ADS_IP_PACKET_TYPE_DHCP_SERVERV4   = 0x00,
    CDS_ADS_IP_PACKET_TYPE_ND_SERVERDHCPV6 = 0x01,
    CDS_ADS_IP_PACKET_TYPE_ICMPV6          = 0x02,
    CDS_ADS_IP_PACKET_TYPE_LINK_FE80       = 0x03,
    CDS_ADS_IP_PACKET_TYPE_LINK_FF         = 0x04,
    CDS_ADS_IP_PACKET_TYPE_BUTT
};
typedef VOS_UINT8 CDS_ADS_IP_PACKET_TYPE_ENUM_UINT8;

/*****************************************************************************
 ????????: CDS_ADS_DL_IPF_BEARER_ID_ENUM
 ????????: CDS??ADS??????IPF Bearer Id????
           IPF Bearer ID:
               0~4      ????
               5~15     EPS Bearer ID
               16       ????DHCP
               17       ????DHCPv6
               18       ????ICMP
               19       ????ICMPv6
               20       ????Link Local Address FE80
               21       ????Link Local Address FF
               22       ????MIP
               23       ????MIP
               24~62    ????????????????
               63       ??????????Filter
*****************************************************************************/
enum CDS_ADS_DL_IPF_BEARER_ID_ENUM
{
    CDS_ADS_DL_IPF_BEARER_ID_RSV0       = 0,
    CDS_ADS_DL_IPF_BEARER_ID_EPSBID5    = 5,
    CDS_ADS_DL_IPF_BEARER_ID_EPSBID15   = 15,
    CDS_ADS_DL_IPF_BEARER_ID_DHCPV4     = 16,
    CDS_ADS_DL_IPF_BEARER_ID_DHCPV6     = 17,
    CDS_ADS_DL_IPF_BEARER_ID_ICMPV4     = 18,
    CDS_ADS_DL_IPF_BEARER_ID_ICMPV6     = 19,
    CDS_ADS_DL_IPF_BEARER_ID_LL_FE80    = 20,
    CDS_ADS_DL_IPF_BEARER_ID_LL_FF      = 21,
    CDS_ADS_DL_IPF_BEARER_ID_MIP_ADV    = 22,
    CDS_ADS_DL_IPF_BEARER_ID_MIP_REG_REPLY = 23,
    CDS_ADS_DL_IPF_BEARER_ID_INVALID    = 63
};
typedef VOS_UINT8 CDS_ADS_DL_IPF_BEARER_ID_ENUM_UINT8;

/*****************************************************************************
 ????????: ADS_CDS_IPF_PKT_TYPE_ENUM_UINT8
 ????????: ADS??CDS????????????
*****************************************************************************/
enum ADS_CDS_PKT_TYPE_ENUM
{
    ADS_CDS_IPF_PKT_TYPE_IP   = 0x00,
    ADS_CDS_IPF_PKT_TYPE_PPP  = 0x01,

    ADS_CDS_IPF_PKT_TYPE_BUTT
};
typedef VOS_UINT8 ADS_CDS_IPF_PKT_TYPE_ENUM_UINT8;

/*****************************************************************************
 ????????: CDS_ADS_DL_IPF_BID_ENUM
 ????????: IPF??????????????BID????
           IPF Bearer ID:
               0~4      ????
               5~15     EPS Bearer ID
               16       ????DHCP
               17       ????DHCPv6
               18       ????ICMP
               19       ????ICMPv6
               20       ????Link Local Address FE80
               21       ????Link Local Address FF
               22       ????MIP
               23       ????MIP
               24~254   ????????????????
               255      ??????????Filter
*****************************************************************************/
enum CDS_ADS_DL_IPF_BID_ENUM
{
    CDS_ADS_DL_IPF_BID_RSV0             = 0,
    CDS_ADS_DL_IPF_BID_EPSBID5          = 5,
    CDS_ADS_DL_IPF_BID_EPSBID15         = 15,
    CDS_ADS_DL_IPF_BID_DHCPV4           = 16,
    CDS_ADS_DL_IPF_BID_DHCPV6           = 17,
    CDS_ADS_DL_IPF_BID_ICMPV4           = 18,
    CDS_ADS_DL_IPF_BID_ICMPV6           = 19,
    CDS_ADS_DL_IPF_BID_LL_FE80          = 20,
    CDS_ADS_DL_IPF_BID_LL_FF            = 21,
    CDS_ADS_DL_IPF_BID_MIP_ADV          = 22,
    CDS_ADS_DL_IPF_BID_MIP_REG_REPLY    = 23,
    CDS_ADS_DL_IPF_BID_INVALID          = 255
};
typedef VOS_UINT8 CDS_ADS_DL_IPF_BID_ENUM_UINT8;

/*****************************************************************************
 ????????: CDS_ADS_UL_IPF_BID_ENUM
 ????????: IPF??????????????BID????????
           IPF Bearer ID:
               0~4      ????
               5~15     EPS Bearer ID
               16       ????DHCP
               17       ????DHCPv6
               18       ????ICMP
               19       ????ICMPv6
               20       ????Link Local Address FE80
               21       ????Link Local Address FF
               22~254   ????????????????
               255      ??????????Filter
*****************************************************************************/
enum CDS_ADS_UL_IPF_BID_ENUM
{
    CDS_ADS_UL_IPF_BID_RSV0             = 0,
    CDS_ADS_UL_IPF_BID_EPSBID5          = 5,
    CDS_ADS_UL_IPF_BID_EPSBID15         = 15,
    CDS_ADS_UL_IPF_BID_DHCPV4           = 16,
    CDS_ADS_UL_IPF_BID_DHCPV6           = 17,
    CDS_ADS_UL_IPF_BID_ICMPV4           = 18,
    CDS_ADS_UL_IPF_BID_ICMPV6           = 19,
    CDS_ADS_UL_IPF_BID_LL_FE80          = 20,
    CDS_ADS_UL_IPF_BID_LL_FF            = 21,
    CDS_ADS_UL_IPF_BID_INVALID          = 255
};
typedef VOS_UINT8 CDS_ADS_UL_IPF_BID_ENUM_UINT8;


/*****************************************************************************
  4 STRUCT????
*****************************************************************************/

/*****************************************************************************
 ????????: CDS_ADS_DATA_IND_STRU
 ????????: ID_CDS_ADS_DATA_IND ????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    CDS_ADS_MSG_ID_ENUM_UINT32          enMsgId;

    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT8                           ucRabId;
    CDS_ADS_IP_PACKET_TYPE_ENUM_UINT8   enIpPacketType;
    VOS_UINT16                          usLen;
    VOS_UINT8                           aucRsv[2];
    VOS_UINT8                           aucData[4];
} CDS_ADS_DATA_IND_STRU;

/*****************************************************************************
 ????????: ADS_CDS_ERR_IND_STRU
 ????????: ID_ADS_CDS_ERR_IND ????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    CDS_ADS_MSG_ID_ENUM_UINT32          enMsgId;

    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT8                           ucRabId;
    VOS_UINT8                           ucErrRate;
    VOS_UINT8                           aucRsv[4];
} ADS_CDS_ERR_IND_STRU;

/*****************************************************************************
 ????????: CDS_ADS_DATA_IND_V2_STRU
 ????????: ID_CDS_ADS_DATA_IND_V2 ????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    CDS_ADS_MSG_ID_ENUM_UINT32          enMsgId;

    VOS_UINT8                           ucIfaceId;
    CDS_ADS_UL_IPF_BID_ENUM_UINT8       enBid;
    VOS_UINT16                          usLen;
    VOS_UINT8                           aucData[0];/*lint !e43*/
} CDS_ADS_DATA_IND_V2_STRU;

/*****************************************************************************
 ????????: ADS_CDS_SEPCIAL_PACKET_IND_STRU
 ????????: ID_ADS_CDS_DATA_IND_V2 ????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    CDS_ADS_MSG_ID_ENUM_UINT32          enMsgId;

    VOS_UINT8                           ucIfaceId;
    CDS_ADS_DL_IPF_BID_ENUM_UINT8       enBid;
    MODEM_ID_ENUM_UINT16                enModemId;
    VOS_UINT8                           ucPduSessionId;
    VOS_UINT8                           aucRsv[1];
    VOS_UINT16                          usLen;
    VOS_UINT8                           aucData[0];/*lint !e43*/
} ADS_CDS_DATA_IND_V2_STRU;

/*****************************************************************************
 ????????: ADS_CDS_ERR_IND_V2_STRU
 ????????: ID_ADS_CDS_ERR_IND_V2 ????????
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    CDS_ADS_MSG_ID_ENUM_UINT32          enMsgId;

    VOS_UINT8                           ucIfaceId;
    VOS_UINT8                           ucErrRate;                              /* ????????????????????????????*/
    VOS_UINT8                           aucRsv[2];                              /* ????*/
} ADS_CDS_ERR_IND_V2_STRU;



#if (VOS_OS_VER != VOS_WIN32)
#pragma pack()
#else
#pragma pack(pop)
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif /* __CDS_ADS_INTERFACE_H__ */

