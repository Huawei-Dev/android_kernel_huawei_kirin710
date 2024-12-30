/*
 *
 * Copyright (c) 2013-2015, Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/err.h>
#include <linux/hisi/bootdevice.h>
#include <asm/uaccess.h>
#include <partition.h>
#include <linux/hisi/kirin_partition.h>

int get_cunrrent_total_ptn_num(void)
{
	int current_ptn_num = 0;
	enum bootdevice_type boot_device_type = BOOT_DEVICE_EMMC;

	boot_device_type = get_bootdevice_type();

	if (BOOT_DEVICE_EMMC == boot_device_type) {
		current_ptn_num = sizeof(partition_table_emmc) / sizeof(struct partition);
	}
#ifdef CONFIG_HISI_STORAGE_UFS_PARTITION
	else if (BOOT_DEVICE_UFS  == boot_device_type){
		current_ptn_num = sizeof(partition_table_ufs) / sizeof(struct partition);
	}
#endif
	return current_ptn_num;
}
EXPORT_SYMBOL(get_cunrrent_total_ptn_num);

void flash_find_hisee_ptn(const char* str, char* pblkname)
{
	char device_block_path[] = "/dev/block/";
	char device_path_emmc[]="mmcblk0p28";
	char device_path_ufs[]="sdd24";
	enum bootdevice_type boot_device_type;

	if ((NULL == pblkname) || (NULL == str)) {
		pr_err("Input partition name or device path buffer is NULL\n");
		return;
	}

	boot_device_type = get_bootdevice_type();
	if (BOOT_DEVICE_EMMC == boot_device_type) {
	        strncpy(pblkname, device_block_path, strlen(device_block_path));/* unsafe_function_ignore: strncpy */
	        strncpy(pblkname + strlen(device_block_path), device_path_emmc, strlen(device_path_emmc) + 1);/* unsafe_function_ignore: strncpy */
	}
	else
	{
	        strncpy(pblkname, device_block_path, strlen(device_block_path));/* unsafe_function_ignore: strncpy */
	        strncpy(pblkname + strlen(device_block_path), device_path_ufs, strlen(device_path_ufs) + 1);/* unsafe_function_ignore: strncpy */
	}

}
EXPORT_SYMBOL(flash_find_hisee_ptn);
/*
 *Function: Get the device path by partition name
 *Input : str, partition name
 *Output: pblkname, boot device path, such as:/dev/block/bootdevice/by-name/xxx
 */
int flash_find_ptn(const char* str, char* pblkname)
{
	int n;
	char device_path[] = "/dev/block/by-name/";
	int current_ptn_num = 0;
	struct partition *current_partition_table = NULL;
	enum bootdevice_type boot_device_type = BOOT_DEVICE_EMMC;
	char partition_name_tmp[MAX_PARTITION_NAME_LENGTH];

	if ((NULL == pblkname) || (NULL == str)) {
		pr_err("Input partition name or device path buffer is NULL\n");
		return -1;
	}

	boot_device_type = get_bootdevice_type();

	if (BOOT_DEVICE_EMMC == boot_device_type) {
		current_partition_table  = (struct partition *)partition_table_emmc;
	}
#ifdef CONFIG_HISI_STORAGE_UFS_PARTITION
	else if (BOOT_DEVICE_UFS  == boot_device_type){
		current_partition_table  = (struct partition *)partition_table_ufs;
	}
#endif
	else {
		pr_err("Invalid boot device type\n");
		return -1;
	}

	current_ptn_num = get_cunrrent_total_ptn_num();
	for(n = 0; n < current_ptn_num; n++) {
		if(!strcmp((current_partition_table + n)->name, str)) {/*[false alarm]:current_partition_table!=NULL*/
			strncpy(pblkname, device_path, strlen(device_path));/* unsafe_function_ignore: strncpy */
			strncpy(pblkname + strlen(device_path), str, strlen(str)+1);/* unsafe_function_ignore: strncpy */
			return 0;
		}
	}

	if(strlen(str) > (sizeof(partition_name_tmp) - 3))
	{
		pr_err("Invalid input str\n");
		return -1;
	}

	memset(partition_name_tmp,0,sizeof(partition_name_tmp));/* unsafe_function_ignore: memset */
	strncpy(partition_name_tmp, str, sizeof(partition_name_tmp) - 3);/* unsafe_function_ignore: strncpy */

	strncpy(partition_name_tmp + strlen(partition_name_tmp), "_a", (unsigned long)3);/* unsafe_function_ignore: strncpy */
	current_ptn_num = get_cunrrent_total_ptn_num();

	for(n = 0; n < current_ptn_num; n++) {
		if(!strcmp((current_partition_table + n)->name, partition_name_tmp)) {/*[false alarm]:current_partition_table!=NULL*/
			strncpy(pblkname, device_path, strlen(device_path));/* unsafe_function_ignore: strncpy */
			strncpy(pblkname + strlen(device_path), str, strlen(str)+1);/* unsafe_function_ignore: strncpy */
			return 0;
		}
	}
	pr_err("[%s]partition is not found, str = %s, pblkname = %s\n",__func__,str, pblkname);
	return -1;
}
EXPORT_SYMBOL(flash_find_ptn);

/*
 *Get partition offset in total partitions(all lu), not the current LU
 */
int flash_get_ptn_index(const char* pblkname)
{
	int n;
	int current_ptn_num;
	struct partition *current_partition_table = NULL;
	enum bootdevice_type boot_device_type;
	char partition_name_tmp[MAX_PARTITION_NAME_LENGTH];

	if (NULL == pblkname) {
		pr_err("Input partition name is NULL\n");
		return -1;
	}

	boot_device_type = get_bootdevice_type();
	if (BOOT_DEVICE_EMMC == boot_device_type) {
		current_partition_table  = (struct partition *)partition_table_emmc;
	}
#ifdef CONFIG_HISI_STORAGE_UFS_PARTITION
	else if (BOOT_DEVICE_UFS  == boot_device_type) {
		current_partition_table  = (struct partition *)partition_table_ufs;
	}
#endif
	else {
		pr_err("Invalid boot device type\n");
		return -1;
	}

	current_ptn_num = get_cunrrent_total_ptn_num();

	if(!strcmp(PART_XLOADER, pblkname)) {
		pr_err("[%s]This is boot partition\n",__func__);
		return -1;
	}

	/*normal partition*/
	for(n = 0; n < current_ptn_num; n++) {
		if (!strcmp((current_partition_table + n)->name, pblkname)) {
			return n;
		}
	}

	if(strlen(pblkname) > (sizeof(partition_name_tmp) - 3))
	{
		pr_err("Invalid input pblkname\n");
		return -1;
	}

	memset(partition_name_tmp,0,sizeof(partition_name_tmp));/* unsafe_function_ignore: memset */
	strncpy(partition_name_tmp, pblkname, sizeof(partition_name_tmp) - 3);/* unsafe_function_ignore: strncpy */

	strncpy(partition_name_tmp + strlen(partition_name_tmp), "_a", 3);/* unsafe_function_ignore: strncpy */

	for(n = 0; n < current_ptn_num; n++) {
		if (!strcmp((current_partition_table + n)->name, partition_name_tmp)) {
			return n;
		}
	}

	pr_err("[%s]Input partition(%s) is not found\n",__func__,pblkname);
	return -1;
}
EXPORT_SYMBOL(flash_get_ptn_index);

enum AB_PARTITION_TYPE emmc_boot_partition_type = XLOADER_A;
enum AB_PARTITION_TYPE ufs_boot_partition_type = XLOADER_A;

/*
 *Get storage boot partition type:XLOADER_A or XLOADER_B
 */
enum AB_PARTITION_TYPE get_device_boot_partition_type(void)
{
	pr_info("Not support AB partition\n");
	return NO_SUPPORT_AB;
}

/*
 *set storage boot partition type
 */
int set_device_boot_partition_type(char boot_partition_type)
{
	pr_err("Not support AB partition writing\n");

	return 0;
}
