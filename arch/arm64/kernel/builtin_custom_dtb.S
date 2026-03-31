/*
 * DT override for Huawei bootloader
 *
 * Copyright (C) Surdu Petru
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef CUSTOM_BUILTIN_DTB_PATH
#error "CUSTOM_BUILTIN_DTB_PATH is not defined"
#endif

#if defined(CONFIG_ARM64_BUILTIN_APPENDED_DTB_OVERRIDE)

	.section .builtin_custom_dtb, "a"
	.balign 8

	.global __builtin_custom_dtb_start
__builtin_custom_dtb_start:
	.incbin CUSTOM_BUILTIN_DTB_PATH

	.global __builtin_custom_dtb_end
__builtin_custom_dtb_end:

	.balign 8

#endif
