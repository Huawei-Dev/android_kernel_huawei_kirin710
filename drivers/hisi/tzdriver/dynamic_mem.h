#ifndef _DYNAMIC_MMEM_H_
#define _DYNAMIC_MMEM_H_
#include <linux/version.h>
#include <linux/hisi/hisi_ion.h>

#include "teek_ns_client.h"

#include <linux/types.h>

#ifndef MAX_ION_NENTS
#define MAX_ION_NENTS 1024
#endif

#ifndef TZDRIVER_TZ_SG_LIST_COMPAT
#define TZDRIVER_TZ_SG_LIST_COMPAT

typedef struct ion_page_info {
	phys_addr_t phys_addr;
	uint32_t npages;
} tz_page_info;

typedef struct sglist {
	uint64_t sglist_size;
	uint64_t ion_size;
	uint64_t ion_id;
	uint64_t info_length;
	struct ion_page_info page_info[0];
} tz_sg_list;

#endif

#define CAFD_MAX         10 //concurrent opened session count
#define SET_BIT(map, bit) (map |= (0x1<<(bit)))
#define CLR_BIT(map, bit) (map &= (~(unsigned)(0x1<<(bit))))
struct sg_memory {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0))
	int dyn_shared_fd;
	struct dma_buf *dyn_dma_buf;
	phys_addr_t ion_phys_addr;
#else
	struct ion_handle *ion_handle;
	ion_phys_addr_t ion_phys_addr;
#endif
	size_t len;
	void *ion_virt_addr;
};
struct dynamic_mem_item{
	struct list_head head;
	uint32_t configid;
	uint32_t size;
	struct sg_memory memory;
	uint32_t cafd[CAFD_MAX];
	uint32_t cafd_count_bitmap;
	uint32_t cafd_count;
	TEEC_UUID uuid;
};
int init_dynamic_mem(void);
void exit_dynamic_mem(void);
int load_app_use_configid(uint32_t configid, uint32_t cafd,  TEEC_UUID* uuid, uint32_t size);
void kill_ion_by_cafd(unsigned int cafd);
void kill_ion_by_uuid(TEEC_UUID* uuid);
int add_cafd_count_by_uuid(TEEC_UUID* uuid, uint32_t cafd);
int is_used_dynamic_mem(TEEC_UUID *uuid);
#endif
