/*
 * pmalloc.h: Header for Protectable Memory Allocator
 *
 * (C) Copyright 2017 Huawei Technologies Co. Ltd.
 * Author: Igor Stoppa <igor.stoppa@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#ifndef _PMALLOC_H
#define _PMALLOC_H
#include <linux/slab.h>
#include <linux/err.h>

/**
 * These are an alternate version of the pmalloc API, meant mostly for
 * debugging.
 */

#define ERR_PMALLOC_OFF 1
static inline
struct gen_pool *pmalloc_create_pool(const char *name,
				     int min_alloc_order)
{
	return ERR_PTR(ERR_PMALLOC_OFF);
}

static inline
bool pmalloc_prealloc(struct gen_pool *pool, size_t size)
{
	return true;
}

static inline
void *pmalloc(struct gen_pool *pool, size_t size, gfp_t gfp)
{
	return kmalloc(size, gfp);
}

static inline
void *pzalloc(struct gen_pool *pool, size_t size, gfp_t gfp)
{
	return kzalloc(size, gfp);
}

static inline
void *pmalloc_array(struct gen_pool *pool, size_t n,
		    size_t size, gfp_t flags)
{
	return kmalloc_array(n, size, flags);
}

static inline
void *pcalloc(struct gen_pool *pool, size_t n,
		    size_t size, gfp_t flags)
{
	return kcalloc(n, size, flags);
}

static inline
char *pstrdup(struct gen_pool *pool, const char *s, gfp_t gfp)
{
	return kstrdup(s, gfp);
}

static inline
int pmalloc_protect_pool(struct gen_pool *pool)
{
	return 0;
}

static inline
void pfree(struct gen_pool *pool, const void *addr)
{
	kfree(addr);
}

static inline
int pmalloc_destroy_pool(struct gen_pool *pool)
{
	return 0;
}
#endif
