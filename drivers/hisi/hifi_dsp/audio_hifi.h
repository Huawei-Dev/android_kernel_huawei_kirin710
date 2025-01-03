/*
 * hifi msg define.
 *
 * Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


#ifndef _AUDIO_HIFI_H
#define _AUDIO_HIFI_H

#include <linux/types.h>

/*Each Short Audio Descriptor is 3-bytes long. There can be up to 31 bytes following any tag, therefore
there may be up to 10 Short Audio Descriptors in the Audio Data Block (ADB).*/
#define EDID_AUDIO_DATA_BLOCK_MAX 		(10)

typedef enum
{
	HIFI_CHN_SYNC_CMD = 0,
	HIFI_CHN_READNOTICE_CMD,
	HIFI_CHN_INVAILD_CMD
} HIFI_CHN_CMD_TYPE;

typedef struct HIFI_CHN_CMD_STRUCT
{
	HIFI_CHN_CMD_TYPE cmd_type;
	unsigned int		   sn;
} HIFI_CHN_CMD;

/*
	????????????HIFI??????
	??????HIFI??????????????AP??????
*/
struct misc_io_async_param {
	unsigned int			para_in_l;		/*????buffer*/
	unsigned int			para_in_h;		/*????buffer*/
	unsigned int			para_size_in;	/*????buffer????*/
};


/* misc_io_sync_cmd */
struct misc_io_sync_param {
	unsigned int			para_in_l;			 /*????buffer*/
	unsigned int			para_in_h;			 /*????buffer*/
	unsigned int			para_size_in;		/*????buffer????*/

	unsigned int			para_out_l; 		  /*????buffer*/
	unsigned int			para_out_h; 		  /*????buffer*/
	unsigned int			para_size_out;		/*????buffer????*/
};

/* misc_io_senddata_cmd */
struct misc_io_senddata_async_param {
	unsigned int			para_in_l;			 /*????buffer*/
	unsigned int			para_in_h;			 /*????buffer*/
	unsigned int			para_size_in;		/*????buffer????*/

	unsigned int			data_src_l; 		  /*????????????*/
	unsigned int			data_src_h; 		  /*????????????*/
	unsigned int			data_src_size;		/*????????????*/
};

struct misc_io_senddata_sync_param {
	unsigned int			para_in_l;			/*????buffer*/
	unsigned int			para_in_h;			/*????buffer*/
	unsigned int			para_size_in;		/*????buffer????*/

	unsigned int			src_l;				/*??????????*/
	unsigned int			src_h;				/*??????????*/
	unsigned int			src_size;			/*??????????*/

	unsigned int			dst_l;				/*????*/
	unsigned int			dst_h;				/*????*/
	unsigned int			dst_size;			/*????*/

	unsigned int			para_out_l; 		/*????buffer*/
	unsigned int			para_out_h; 		/*????buffer*/
	unsigned int			para_size_out;		/*????buffer????*/
};

struct misc_io_get_phys_param {
	unsigned int		   flag;			   /**/
	unsigned int		   phys_addr_l; 		 /*??????????????*/
	unsigned int		   phys_addr_h; 		 /*??????????????*/
};

struct misc_io_dump_buf_param {
	unsigned int			user_buf_l; 		/*??????????????????????*/
	unsigned int			user_buf_h; 		/*??????????????????????*/
	unsigned int			clear;				/*clear current log buf*/
	unsigned int			buf_size;			/*??????????????????????*/
};

/*
  *voice proxy interface
  */
/*****************************************************************************
  2 macro define
*****************************************************************************/
#define PROXY_VOICE_CODEC_MAX_DATA_LEN (32)           /* 16 bit */
#define PROXY_VOICE_RTP_MAX_DATA_LEN (256)          /* 16 bit */
#define PROXY_HIFI_RTT_MAX_DATA_LEN   (256)
/*****************************************************************************
  5 msg define
*****************************************************************************/

/* the MsgID define between PROXY and Voice */
enum voice_proxy_voice_msg_id {
	ID_VOICE_PROXY_RTCP_OM_INFO_NTF = 0xDDEC,
	ID_PROXY_VOICE_RCTP_OM_INFO_CNF = 0xDDED,
	ID_VOICE_PROXY_AJB_OM_INFO_NTF = 0xDDEE,
	ID_PROXY_VOICE_AJB_OM_INFO_CNF = 0xDDEF,
	ID_PROXY_VOICE_LTE_RX_NTF  = 0xDDF0,
	ID_VOICE_PROXY_LTE_RX_CNF  = 0xDDF1,
	ID_VOICE_PROXY_LTE_RX_NTF  = 0xDDF2,
	ID_PROXY_VOICE_LTE_RX_CNF  = 0xDDF3,
	ID_VOICE_PROXY_LTE_TX_NTF  = 0xDDF4,
	ID_PROXY_VOICE_LTE_TX_CNF  = 0xDDF5,
	ID_PROXY_VOICE_LTE_TX_NTF  = 0xDDF6,
	ID_VOICE_PROXY_LTE_TX_CNF  = 0xDDF7,

	ID_PROXY_VOICE_WIFI_RX_NTF = 0xDDF8,
	ID_VOICE_PROXY_WIFI_RX_CNF = 0xDDF9,
	ID_VOICE_PROXY_WIFI_TX_NTF = 0xDDFA,
	ID_PROXY_VOICE_WIFI_TX_CNF = 0xDDFB,
	ID_PROXY_VOICE_STATUS_IND = 0xDDFC,
	ID_PROXY_VOICE_ENCRYPT_KEY_BEGIN = 0xDDFD,
	ID_PROXY_VOICE_ENCRYPT_KEY_END = 0xDDFE,

	ID_PROXY_RTT_HIFI_TX_NTF = 0xDFD1,      // Kernel??HAL????????????HIFI
	ID_HIFI_PROXY_RTT_TX_CNF = 0xDFD2,      // HIFI????????Kernel??????????????????????
	ID_HIFI_PROXY_RTT_RX_NTF = 0xDFD3,      // HiFi??RTT??????????Kernel
	ID_PROXY_RTT_HIFI_RX_CNF = 0xDFD4,      // Kernel????Hifi??RTT????????????????????
	ID_HIFI_PROXY_RTT_CHANNEL_STATUS_IND = 0xDFD5, // HIFI????RTT??channel????????open????close

	ID_HIFI_PROXY_WIFI_STATUS_NTF = 0xDFD6, // HIFI????VOWIFI????????

	ID_PROXY_VOICE_DATA_MSGID_BUT
};

/*
 * 6 STRUCT define
 */

struct evs_unpack_param {
	uint16_t evs_mode; /* EVS Primary or AMRWB_IO */
	uint16_t chan_aw_mode;
	uint16_t chan_aw_offset;
	uint16_t chan_aw_level;
	uint16_t cmr_invalid; /* cmr is not exist or equals to 0x7 */
	uint16_t payload_lenth;
	uint16_t bandwidth;
	uint16_t reserved;
};

/* ciq rx statistics */
struct rtp_ciq_info {
	uint8_t rtp_header_flag;
	uint8_t payload_type;
	uint16_t payload_length;
	uint32_t time_stamp;
};

/*
 * describe: the struct of the Rx request between PROXY and hifi_voice by lte
 * size of voice_proxy_lte_rx_notify should be equal to ps_unpacked_rx_data
 */
struct voice_proxy_lte_rx_notify {
	uint16_t msg_id;
	uint16_t sn;
	uint32_t ts;
	uint16_t codec_type;
	uint16_t dtx_enable;
	uint16_t rate_mode;
	uint16_t error_flag;
	uint16_t frame_type;
	uint16_t quality_idx;
	uint16_t data[PROXY_VOICE_CODEC_MAX_DATA_LEN];
	uint32_t ssrc;
	struct evs_unpack_param evs_para;
	struct rtp_ciq_info ciq_info;
	uint32_t recv_ts;
};

/*
 * describe: the struct of the Rx request between PROXY and hifi_voice by wifi
 * the struct is as the same to IMSA_VOICE_RTP_RX_DATA_IND_STRU
 */
struct voice_proxy_wifi_rx_notify {
	uint16_t msg_id;
	uint16_t reserved;
	uint32_t channel_id;
	uint32_t port_type;		/* Port Type: 0 RTP; 1 RTCP */
	uint16_t data_len;
	uint16_t data_seq;
	uint8_t frag_seq;
	uint8_t frag_max;
	uint16_t reserved2;
	uint8_t data[PROXY_VOICE_RTP_MAX_DATA_LEN];
	uint32_t recv_ts; /* rtp packet recv timestamp is set on hifi receiving this packet */
	uint32_t reserve;
};

/*
 * describe: the struct of the confirm between PROXY and hifi_voice
 */
struct voice_proxy_confirm {
	uint16_t msg_id;
	uint16_t modem_no;
	uint32_t channel_id;
	uint32_t result;
};

/*
 * describe: the struct of the Tx request between Voice-Proxy and hifi_voice by lte
 */
struct voice_proxy_lte_tx_notify {
	uint16_t msg_id;
	uint16_t modem_no;
	uint16_t amr_type;
	uint16_t frame_type;
	uint16_t data[PROXY_VOICE_CODEC_MAX_DATA_LEN];
};

/*
 * describe: the struct of the Tx request between Voice-Proxy and hifi_voice by wifi
 */
struct voice_proxy_wifi_tx_notify {
	uint16_t msg_id;
	uint16_t modem_no;
	uint32_t channel_id;
	uint32_t port_type;
	uint16_t data_len;
	uint16_t data_seq;
	uint8_t frag_seq;
	uint8_t frag_max;
	uint16_t reserved2;
	uint8_t data[PROXY_VOICE_RTP_MAX_DATA_LEN];
};

struct voice_proxy_status {
	uint16_t msg_id;
	uint16_t reserved;
	uint32_t status;
	uint32_t socket_cfg;
};

struct voice_proxy_voice_encrypt_key_end {
	uint16_t msg_id;
	uint16_t reserved;
	bool encrypt_negotiation_result;
	bool reserved2[3];
};

/*defined in hifi, kernel and hal use it*/
struct proxy_rtt_hifi_tx_notify {
	uint16_t msg_id;                                     // Kernel??HIFI??????????ID
	uint8_t frag_seq;                                    // ??????????
	uint8_t frag_seq_max;                               // ????????????????
	uint32_t resv;                                       // ????????
	uint16_t channel_id;                                // rtt??????channelId
	uint16_t data_len;                                  // ??????????????????
	uint8_t data[PROXY_HIFI_RTT_MAX_DATA_LEN];       // ??????????,??????256
};

/*defined in hifi, kernel and hal use it*/
struct hifi_proxy_rtt_rx_notify {
	uint16_t msg_id;                                    // Kernel??HIFI??????????ID
	uint8_t frag_seq;                                   // ??????????
	uint8_t frag_seq_max;                               // ????????????????
	uint32_t resv;                                       // ????????
	uint16_t channel_id;                                // rtt??????channelId
	uint16_t data_len;                                  // ??????????????????
	uint8_t data[PROXY_HIFI_RTT_MAX_DATA_LEN];       // ??????????,??????256
};

/*hifi to proxy:channel status indication*/
struct hifi_proxy_rtt_channel_status_ind {
	uint16_t msg_id;                                    // Kernel??HIFI??????????ID
	uint8_t  channel_status;                           // ????????: 1-open; 0-close;
	uint8_t  resv;                                      // ????????
	uint32_t channel_id;                               // rtt??????channelId
};

/*hifi to proxy:wifi status indication*/
struct hifi_proxy_wifi_status_ind {
	uint16_t msg_id;                                    // Kernel??HIFI??????????ID
	uint8_t  status;                                    // ????????: 1-open; 0-close;
	uint8_t  resv;                                      // ????????
};
/*
  *end
  */

struct dp_edid_spec {
	unsigned short format;
	unsigned short channels;
	unsigned short sampling;
	unsigned short bitrate;
};

struct dp_edid_aparam {
	unsigned int data_width;
	unsigned int channel_num;
	unsigned int sample_rate;
};

struct dp_edid_info {
	struct dp_edid_spec spec[EDID_AUDIO_DATA_BLOCK_MAX];
	unsigned int ext_acount;
	struct dp_edid_aparam aparam;
};

/* voice bsd param hsm struct */
struct voice_bsd_param_hsm {
	unsigned int data_len;
	unsigned char *pdata;
};

//??????AP????HiFi Misc??????ioctl??????????HiFi Misc????????????
#define HIFI_MISC_IOCTL_ASYNCMSG		_IOWR('A', 0x70, struct misc_io_async_param)		  //AP??HiFi????????????
#define HIFI_MISC_IOCTL_SYNCMSG 		_IOW('A', 0x71, struct misc_io_sync_param)			  //AP??HiFi????????????
#define HIFI_MISC_IOCTL_GET_PHYS		_IOWR('A', 0x73, struct misc_io_get_phys_param) 	   //AP????????????
#define HIFI_MISC_IOCTL_TEST			_IOWR('A', 0x74, struct misc_io_senddata_sync_param)   //AP????????
#define HIFI_MISC_IOCTL_WRITE_PARAMS	_IOWR('A', 0x75, struct misc_io_sync_param) 		   //????????????HIFI
#define HIFI_MISC_IOCTL_DUMP_HIFI		_IOWR('A', 0x76, unsigned int) 	   //????HIFI??DDR????????????????????????
#define HIFI_MISC_IOCTL_DUMP_CODEC		_IOWR('A', 0x77, struct misc_io_dump_buf_param) 	   //????CODEC??????????????????????
#define HIFI_MISC_IOCTL_WAKEUP_THREAD	_IOW('A',  0x78, unsigned int) 	   //????read????,????????
#define HIFI_MISC_IOCTL_DISPLAY_MSG		_IOWR('A', 0x79, struct misc_io_dump_buf_param) 	   //????HIFI??DDR????????????????????????
#define HIFI_MISC_IOCTL_WAKEUP_PCM_READ_THREAD _IOW('A',  0x7a, unsigned int)
#define HIFI_MISC_IOCTL_AUDIO_EFFECT_PARAMS        _IOWR('A', 0x7B, struct misc_io_sync_param)
#define HIFI_MISC_IOCTL_USBAUDIO        _IOW('A', 0x7C, struct misc_io_sync_param)      //for usbaudio
#define HIFI_MISC_IOCTL_SMARTPA_PARAMS  _IOWR('A', 0x7D, struct misc_io_async_param)   //for smartpakit algo params
#define HIFI_MISC_IOCTL_SOUNDTRIGGER        _IOW('A', 0x7E, struct misc_io_sync_param)
#define HIFI_MISC_IOCTL_GET_DPAUDIO        _IOW('A', 0x7F, struct dp_edid_info)
#define HIFI_MISC_IOCTL_SET_DPAUDIO        _IOW('A', 0x80, struct dp_edid_info)

#define HIFI_MISC_IOCTL_KCOV_FAKE_MSG   _IOWR('A', 0x81, struct misc_io_dump_buf_param)
#define HIFI_MISC_IOCTL_KCOV_FAKE_WTD   _IOW('A', 0x82, unsigned int)

#ifdef CLT_VOICE
#define CLT_HIFI_MISC_IOCTL_SEND_VOICE _IOWR('A', 0x90, struct misc_io_async_param)
#endif

#define HIFI_MISC_IOCTL_GET_VOICE_BSD_PARAM	_IOWR('A', 0x7c, struct voice_bsd_param_hsm)    //????Voice BSD????
#define INT_TO_ADDR(low,high) (void*) (unsigned long)((unsigned long long)(low) | ((unsigned long long)(high)<<32))
#define GET_LOW32(x) (unsigned int)(((unsigned long long)(unsigned long)(x))&0xffffffffULL)
#define GET_HIG32(x) (unsigned int)((((unsigned long long)(unsigned long)(x))>>32)&0xffffffffULL)

#endif // _AUDIO_HIFI_H

