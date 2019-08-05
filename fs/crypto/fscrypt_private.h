/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fscrypt_private.h
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * This contains encryption key functions.
 *
 * Written by Michael Halcrow, Ildar Muslukhov, and Uday Savagaonkar, 2015.
 */

#ifndef _FSCRYPT_PRIVATE_H
#define _FSCRYPT_PRIVATE_H

#include <linux/fscrypt.h>
#include <crypto/hash.h>

#define FS_IV_SIZE                     16

/**
 * Encryption context for inode
 *
 * Protector format:
 *  1 byte: Protector format (2 = this version)
 *  1 byte: File contents encryption mode
 *  1 byte: File names encryption mode
 *  1 byte: Flags
 *  8 bytes: Master Key descriptor
 *  80 bytes: Encryption Key derivation nonce (encrypted)
 *  12 bytes: IV
 */
struct fscrypt_context {
        u8 format;
        u8 contents_encryption_mode;
        u8 filenames_encryption_mode;
        u8 flags;
        u8 master_key_descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
        u8 nonce[FS_KEY_DERIVATION_CIPHER_SIZE];
        u8 iv[FS_KEY_DERIVATION_IV_SIZE];
} __packed;

#define FS_ENCRYPTION_CONTEXT_FORMAT_V2		2

/**
 * For encrypted symlinks, the ciphertext length is stored at the beginning
 * of the string in little-endian format.
 */
struct fscrypt_symlink_data {
	__le16 len;
	char encrypted_path[1];
} __packed;

/*
 * A pointer to this structure is stored in the file system's in-core
 * representation of an inode.
 */
struct fscrypt_info {
	u8 ci_data_mode;
	u8 ci_filename_mode;
	u8 ci_flags;
	struct crypto_skcipher *ci_ctfm;
	struct crypto_aead *ci_gtfm;
	struct crypto_cipher *ci_essiv_tfm;
	struct fscrypt_mode *ci_mode;
	struct inode *ci_inode;
	struct fscrypt_direct_key *ci_direct_key;
	u8 ci_master_key_descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
	u8 ci_nonce[FS_KEY_DERIVATION_NONCE_SIZE];
	void *ci_key;
	int ci_key_len;
	int ci_key_index;
	u8  ci_hw_enc_flag;
};

typedef enum {
	FS_DECRYPT = 0,
	FS_ENCRYPT,
} fscrypt_direction_t;

#define FS_CTX_REQUIRES_FREE_ENCRYPT_FL		0x00000001
#define FS_AES_256_GCM_KEY_SIZE         32

static inline bool fscrypt_valid_enc_modes(u32 contents_mode,
					   u32 filenames_mode)
{
	if (contents_mode == FSCRYPT_MODE_AES_128_CBC &&
	    filenames_mode == FSCRYPT_MODE_AES_128_CTS)
		return true;

	if (contents_mode == FSCRYPT_MODE_AES_256_XTS &&
	    filenames_mode == FSCRYPT_MODE_AES_256_CTS)
		return true;

	return false;
}

/* crypto.c */
extern struct kmem_cache *fscrypt_info_cachep;
extern int fscrypt_initialize(unsigned int cop_flags);
extern int fscrypt_crypt_block(const struct inode *inode,
			       fscrypt_direction_t rw, u64 lblk_num,
			       struct page *src_page, struct page *dest_page,
			       unsigned int len, unsigned int offs,
			       gfp_t gfp_flags);
extern struct page *fscrypt_alloc_bounce_page(gfp_t gfp_flags);
extern const struct dentry_operations fscrypt_d_ops;

extern void __printf(3, 4) __cold
fscrypt_msg(const struct inode *inode, const char *level, const char *fmt, ...);

#define fscrypt_warn(inode, fmt, ...)		\
	fscrypt_msg((inode), KERN_WARNING, fmt, ##__VA_ARGS__)
#define fscrypt_err(inode, fmt, ...)		\
	fscrypt_msg((inode), KERN_ERR, fmt, ##__VA_ARGS__)

#define FSCRYPT_MAX_IV_SIZE	32

union fscrypt_iv {
	struct {
		/* logical block number within the file */
		__le64 lblk_num;

		/* per-file nonce; only set in DIRECT_KEY mode */
		u8 nonce[FS_KEY_DERIVATION_NONCE_SIZE];
	};
	u8 raw[FSCRYPT_MAX_IV_SIZE];
};

void fscrypt_generate_iv(union fscrypt_iv *iv, u64 lblk_num,
			 const struct fscrypt_info *ci);

/* fname.c */
extern int fname_encrypt(struct inode *inode, const struct qstr *iname,
			 u8 *out, unsigned int olen);
extern bool fscrypt_fname_encrypted_size(const struct inode *inode,
					 u32 orig_len, u32 max_len,
					 u32 *encrypted_len_ret);

/* keysetup.c */

struct fscrypt_mode {
	const char *friendly_name;
	const char *cipher_str;
	int keysize;
	int ivsize;
	bool logged_impl_name;
	bool needs_essiv;
};

static inline bool
fscrypt_mode_supports_direct_key(const struct fscrypt_mode *mode)
{
	return mode->ivsize >= offsetofend(union fscrypt_iv, nonce);
}

extern struct crypto_skcipher *
fscrypt_allocate_skcipher(struct fscrypt_mode *mode, const u8 *raw_key,
			  const struct inode *inode);

extern int fscrypt_set_derived_key(struct fscrypt_info *ci,
				   const u8 *derived_key);

/* keysetup_v1.c */

extern void fscrypt_put_direct_key(struct fscrypt_direct_key *dk);

extern int fscrypt_setup_v1_file_key(struct fscrypt_info *ci,
				     const u8 *raw_master_key);

extern int fscrypt_setup_v1_file_key_via_subscribed_keyrings(
					struct fscrypt_info *ci);

#endif /* _FSCRYPT_PRIVATE_H */
