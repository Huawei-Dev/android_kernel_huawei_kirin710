/*
 * Huawei Hidden kernel symbols feature
 *
 * Copyright (c) 2017 Huawei.
 *
 * Authors:
 * Weilai Zhou <zhouweilai@huawei.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>

#define MAX_HIDESYMS_NUM	10
#define SYM_NAME_LEN		128

static DEFINE_MUTEX(hidesyms_lock);
LIST_HEAD(hidesyms_blacklist);

struct symbol_node {
	char *sym;
	struct list_head list;
};

static const char *hw_litehidesymbs_blacklist[MAX_HIDESYMS_NUM] = {
	"commit_creds",
	"prepare_kernel_cred"
};

static inline struct symbol_node *litehide_sym_node_alloc(void)
{
	struct symbol_node *node;

	node = (struct symbol_node *)kzalloc(sizeof(struct symbol_node), GFP_KERNEL);
	if (!node)
		return NULL;

	node->sym = kzalloc(SYM_NAME_LEN, GFP_KERNEL);
	if (!node->sym) {
		kfree(node);
		return NULL;
	}

	return node;
}

static inline void litehide_sym_node_free(struct symbol_node *node)
{
	if (node) {
		kfree(node->sym);
		kfree(node);
	}
}

/*Clear hidesyms_blacklist and free all buffer*/
static void clear_blacklist(void)
{
	struct symbol_node *node, *tmp;

	mutex_lock(&hidesyms_lock);
	list_for_each_entry_safe(node, tmp, &hidesyms_blacklist, list) {
		list_del(&node->list);

		kfree(node->sym);
		kfree(node);
	}
	mutex_unlock(&hidesyms_lock);
}

/*
 * search the symbol from the hidden symbols' blacklist.
 * if found, return the symbol_node; if not, return NULL.
 */
static inline struct symbol_node *find_sym_from_blacklist(const char *symbol)
{
	struct symbol_node *node = NULL;

	if (!symbol)
		return NULL;

	list_for_each_entry(node, &hidesyms_blacklist, list) {
		if (node->sym == NULL)
			continue;

		if (!strcmp(symbol, node->sym))
			return node;
	}

	return NULL;
}

/*
 * check if it's a hidden symbol in the blacklist
 */
bool is_hide_symbols(const char *symbol)
{
	struct symbol_node *hidesym_node;

	mutex_lock(&hidesyms_lock);

	hidesym_node = find_sym_from_blacklist(symbol);
	if (hidesym_node) {
		mutex_unlock(&hidesyms_lock);
		return true;
	}

	mutex_unlock(&hidesyms_lock);

	return false;
}
EXPORT_SYMBOL(is_hide_symbols);

static __init int initialize_blacklist(void)
{
	int i;
	struct symbol_node *node;

	for (i = 0; i < MAX_HIDESYMS_NUM; i++) {
		if (!hw_litehidesymbs_blacklist[i])
			continue;

		node = litehide_sym_node_alloc();
		if (!node)
			return -ENOMEM;

		if (strlen(hw_litehidesymbs_blacklist[i]) > SYM_NAME_LEN - 1) {
			litehide_sym_node_free(node);
			return -EINVAL;
		}
		(void)strncpy(node->sym, hw_litehidesymbs_blacklist[i], strlen(hw_litehidesymbs_blacklist[i]));

		list_add_tail(&node->list, &hidesyms_blacklist);
	}

	return 0;
}

static int __init hw_litehide_symbols_init(void)
{
	initialize_blacklist();

	return 0;
}

static void __exit hw_litehide_symbols_exit(void)
{
	clear_blacklist();
}

module_init(hw_litehide_symbols_init);
module_exit(hw_litehide_symbols_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Huawei hide symbols module");
