/*
 * Copyright (c) 2013 Joris Vink <joris@coders.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <openssl/sha.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "cyon.h"

/*
 * This code uses cyon_malloc() and memcpy() quite heavily due to the nature
 * of how keys and data are stored.
 */

#define CYON_RESOLVE_NOTHING		0
#define CYON_RESOLVE_LINK		1

#define STORE_HAS_PASSPHRASE		0x01

struct node {
	u_int8_t	rbase;
	u_int8_t	rtop;
	u_int8_t	flags;
	u_int8_t	*region;
} __attribute__((__packed__));

struct store_header {
	u_int8_t	flags;
	u_int64_t	offset;
} __attribute__((__packed__));

static const u_int8_t	store_log_magic[] = { 0x43, 0x59, 0x4F, 0x4E };

struct store_log {
	u_int8_t	magic[4];
	u_int8_t	hash[SHA_DIGEST_LENGTH];

	u_int8_t	op;
	u_int32_t	klen;
	u_int32_t	dlen;
	u_int32_t	flags;
} __attribute__((__packed__));

struct disknode {
	u_int8_t	magic[4];
	u_int8_t	hash[SHA_DIGEST_LENGTH];
	u_int16_t	didx;
	u_int32_t	klen;
	u_int32_t	dlen;
	u_int64_t	offset;
} __attribute__((__packed__));

static void		cyon_store_map(void);
static void		cyon_diskstore_open(void);
static void		cyon_store_mapnode(int, struct node *);
static void		cyon_storelog_replay(struct store_header *);
static struct node	*cyon_node_lookup(u_int8_t *, u_int32_t, u_int8_t);
static void		cyon_traverse_node(struct getkeys_ctx *,
			    struct connection *, struct node *);
static void		cyon_store_writenode(int, struct node *, u_int8_t *,
			    u_int32_t, u_int32_t *);
static struct disknode	*cyon_diskstore_write(u_int8_t *, u_int32_t,
			    u_int8_t *, u_int32_t);
static void		cyon_diskstore_read(struct disknode *, u_int8_t **,
			    u_int32_t *);

SHA_CTX			shactx;
u_int64_t		key_count;
char			*storepath;
char			*storename;
u_int8_t		store_mode;
u_int8_t		store_nopersist;
u_char			*store_passphrase;
u_int8_t		store_retain_logs;
u_int8_t		store_state[SHA_DIGEST_LENGTH];

static int		lfd;
static int		dfd;
static struct node	*rnode;
static pthread_mutex_t	disk_lock;
static pthread_rwlock_t	store_lock;
static u_int64_t	store_ds_offset;
static u_int64_t	store_log_offset;
static u_int8_t		replaying_log = 0;
static u_int8_t		log_modified = 0;
static u_int8_t		disk_modified = 0;
static u_int8_t		store_modified = 0;

void
cyon_store_init(void)
{
	char	*hex;

	lfd = -1;
	dfd = -1;
	rnode = NULL;
	key_count = 0;
	store_log_offset = 0;
	store_passphrase = NULL;

	SHA_Init(&shactx);
	SHA_Final(store_state, &shactx);

	pthread_mutex_init(&disk_lock, NULL);
	pthread_rwlock_init(&store_lock, NULL);
	cyon_store_map();

	if (rnode == NULL) {
		cyon_log(LOG_NOTICE, "store is empty, starting new store");
		rnode = cyon_malloc(sizeof(struct node));
		memset(rnode, 0, sizeof(struct node));
	} else {
		cyon_log(LOG_NOTICE,
		    "store loaded from disk with %ld keys", key_count);

		if (store_retain_logs) {
			cyon_sha_hex(store_state, &hex);
			cyon_log(LOG_NOTICE, "loaded state is %s", hex);
			cyon_mem_free(hex);
		}
	}

	if (cyon_readonly_mode)
		cyon_log(LOG_NOTICE, "Cyon is in read-only mode");

	if (!store_nopersist)
		cyon_storelog_reopen(0);

	if (store_mode == CYON_DISK_STORE)
		cyon_diskstore_open();
}

void
cyon_store_lock(int write)
{
	int		r, err;
	int		(*lock)(pthread_rwlock_t *);

	if (write)
		lock = pthread_rwlock_wrlock;
	else
		lock = pthread_rwlock_rdlock;

	err = 0;
	for (;;) {
		if ((r = lock(&store_lock)) == 0)
			break;

		cyon_log(LOG_NOTICE,
		    "cyon_store_lock(%d) err nr#%d: %d", write, err++, r);

		if (err == 5)
			fatal("cyon_store_lock(%d) completely failed", write);
	}
}

void
cyon_store_unlock(void)
{
	int		r;

	if ((r = pthread_rwlock_unlock(&store_lock)))
		fatal("cyon_store_unlock(): failed with %d", r);
}

int
cyon_store_get(u_int8_t *key, u_int32_t len, u_int8_t **out, u_int32_t *olen)
{
	struct node		*p;
	struct disknode		*dn;
	u_int32_t		dlen;
	int			resolve;

	if (store_mode == CYON_DISK_STORE)
		resolve = CYON_RESOLVE_NOTHING;
	else
		resolve = CYON_RESOLVE_LINK;

	*out = NULL;
	if ((p = cyon_node_lookup(key, len, resolve)) == NULL)
		return (CYON_RESULT_ERROR);

	if (!(p->flags & NODE_FLAG_HASDATA))
		return (CYON_RESULT_ERROR);

	if (store_mode == CYON_DISK_STORE) {
		dlen = *(u_int32_t *)p->region;
		if (dlen != sizeof(struct disknode))
			fatal("dlen != sizeof(struct disknode)");
		dn = (struct disknode *)(p->region + sizeof(u_int32_t));
		cyon_diskstore_read(dn, out, olen);
	} else {
		*olen = *(u_int32_t *)p->region;
		*out = p->region + sizeof(u_int32_t);
	}

	return (CYON_RESULT_OK);
}

void
cyon_store_getkeys(struct getkeys_ctx *ctx, struct connection *c,
    u_int8_t *root, u_int32_t rlen)
{
	struct node	*p;

	ctx->off = 0;
	ctx->bytes = 0;
	ctx->len = CYON_KEY_MAX;
	ctx->key = cyon_malloc(ctx->len);

	if ((p = cyon_node_lookup(root, rlen, CYON_RESOLVE_NOTHING)) == NULL)
		return;

	if (p->region == NULL)
		return;

	memset(ctx->key, '\0', ctx->len);
	memcpy(ctx->key, root, rlen);
	ctx->off = rlen;

	cyon_traverse_node(ctx, c, p);
}

int
cyon_store_del(u_int8_t *key, u_int32_t len)
{
	struct node	*p;
	u_int8_t	*old;
	u_int32_t	offset, rlen;

	if (!replaying_log && cyon_readonly_mode)
		return (CYON_RESULT_ERROR);

	if ((p = cyon_node_lookup(key, len, CYON_RESOLVE_NOTHING)) == NULL)
		return (CYON_RESULT_ERROR);

	if (!(p->flags & NODE_FLAG_HASDATA))
		return (CYON_RESULT_ERROR);

	if (!replaying_log && !store_nopersist)
		cyon_storelog_write(CYON_OP_DEL, key, len, NULL, 0, 0);

	key_count--;
	p->flags = 0;

	if (p->rbase == 0 && p->rtop == 0) {
		cyon_mem_free(p->region);
		p->region = NULL;
	} else {
		offset = sizeof(u_int32_t) + *(u_int32_t *)p->region;
		rlen = ((p->rtop - p->rbase) + 1) * sizeof(struct node);
		old = p->region;

		p->region = cyon_malloc(rlen);
		memcpy(p->region, old + offset, rlen);

		cyon_mem_free(old);
	}

	return (CYON_RESULT_OK);
}

int
cyon_store_replace(u_int8_t *key, u_int32_t len, u_int8_t *data, u_int32_t dlen)
{
	struct node		*p;
	struct disknode		*dn;
	u_int8_t		*old;
	u_int32_t		nlen, rlen, offset;

	if (!replaying_log && cyon_readonly_mode)
		return (CYON_RESULT_ERROR);

	if ((p = cyon_node_lookup(key, len, CYON_RESOLVE_NOTHING)) == NULL)
		return (CYON_RESULT_ERROR);

	if (!(p->flags & NODE_FLAG_HASDATA))
		return (CYON_RESULT_ERROR);

	if (!replaying_log && store_mode == CYON_DISK_STORE) {
		dn = cyon_diskstore_write(key, len, data, dlen);
		data = (u_int8_t *)dn;
		dlen = sizeof(*dn);
	}

	if (!replaying_log && !store_nopersist)
		cyon_storelog_write(CYON_OP_REPLACE, key, len, data, dlen, 0);

	old = p->region;
	if (p->rbase == 0 && p->rtop == 0) {
		rlen = 0;
		offset = 0;
	} else {
		offset = sizeof(u_int32_t) + *(u_int32_t *)p->region;
		rlen = ((p->rtop - p->rbase) + 1) * sizeof(struct node);
	}

	nlen = sizeof(u_int32_t) + dlen + rlen;
	p->region = cyon_malloc(nlen);

	*(u_int32_t *)p->region = dlen;
	memcpy(p->region + sizeof(u_int32_t), data, dlen);
	if (rlen != 0) {
		memcpy(p->region + sizeof(u_int32_t) + dlen,
		    old + offset, rlen);
	}

	cyon_mem_free(old);
	return (CYON_RESULT_OK);
}

int
cyon_store_put(u_int8_t *key, u_int32_t len, u_int8_t *data,
    u_int32_t dlen, u_int32_t flags)
{
	struct disknode		*dn;
	struct node		*p, *lnode;
	size_t			olen, rlen;
	u_int32_t		base, offset;
	u_int8_t		i, idx, *old;

	if (len > CYON_KEY_MAX) {
		cyon_log(LOG_NOTICE, "Attempt to put key > CYON_KEY_MAX");
		return (CYON_RESULT_ERROR);
	}

	if (!replaying_log && cyon_readonly_mode)
		return (CYON_RESULT_ERROR);

	p = rnode;
	for (i = 0; i < len; i++) {
		idx = key[i];
		if (p->region == NULL) {
			p->flags = 0;
			p->rtop = idx;
			p->rbase = idx;
			p->region = cyon_malloc(sizeof(struct node));
			memset(p->region, 0, sizeof(struct node));
		}

		if (p->rtop == 0 && p->rbase == 0) {
			p->rtop = idx;
			p->rbase = idx;

			if (p->flags & NODE_FLAG_HASDATA) {
				old = p->region;
				offset = sizeof(u_int32_t) + *(u_int32_t *)old;
				rlen = offset + sizeof(struct node);
			} else {
				offset = 0;
				rlen = sizeof(struct node);
			}

			p->region = cyon_malloc(rlen);

			if (p->flags & NODE_FLAG_HASDATA)
				memcpy(p->region, old, offset);
			memset(p->region + offset, 0, sizeof(struct node));

			if (p->flags & NODE_FLAG_HASDATA)
				cyon_mem_free(old);
		}

		if (idx < p->rbase || idx > p->rtop) {
			old = p->region;
			olen = ((p->rtop - p->rbase) + 1) * sizeof(struct node);

			if (idx < p->rbase) {
				base = p->rbase - idx;
				p->rbase = idx;
			} else {
				p->rtop = idx;
				base = 0;
			}

			if (p->flags & NODE_FLAG_HASDATA) {
				offset = sizeof(u_int32_t) +
				    *(u_int32_t *)p->region;
			} else {
				offset = 0;
			}

			rlen = offset +
			    (((p->rtop - p->rbase) + 1) * sizeof(struct node));
			base = offset + (base * sizeof(struct node));

			p->region = cyon_malloc(rlen);
			memset(p->region + offset, 0, rlen - offset);

			if (offset > 0)
				memcpy(p->region, old, offset);
			memcpy(p->region + base, old + offset, olen);

			cyon_mem_free(old);
		}

		if (p->flags & NODE_FLAG_HASDATA)
			offset = sizeof(u_int32_t) + *(u_int32_t *)p->region;
		else
			offset = 0;

		p = (struct node *)((u_int8_t *)p->region + offset +
		    ((idx - p->rbase) * sizeof(struct node)));
	}

	if (p->flags & NODE_FLAG_HASDATA)
		return (CYON_RESULT_ERROR);

	if (!replaying_log && store_mode == CYON_DISK_STORE) {
		if (flags & NODE_FLAG_ISLINK) {
			lnode = cyon_node_lookup(data,
			    dlen, CYON_RESOLVE_NOTHING);
			if (lnode == NULL)
				return (CYON_RESULT_ERROR);

			data = lnode->region + sizeof(u_int32_t);
			dlen = sizeof(struct disknode);
		} else {
			dn = cyon_diskstore_write(key, len, data, dlen);
			data = (u_int8_t *)dn;
			dlen = sizeof(*dn);
		}
	}

	if (!replaying_log && !store_nopersist)
		cyon_storelog_write(CYON_OP_PUT, key, len, data, dlen, flags);

	old = p->region;

	if (old != NULL) {
		olen = ((p->rtop - p->rbase) + 1) * sizeof(struct node);
		rlen = dlen + olen;
	} else {
		olen = 0;
		rlen = dlen;
	}

	p->flags = NODE_FLAG_HASDATA | flags;
	rlen += sizeof(u_int32_t);

	p->region = cyon_malloc(rlen);
	*(u_int32_t *)(p->region) = dlen;

	offset = sizeof(u_int32_t) + dlen;
	memcpy(p->region + sizeof(u_int32_t), data, dlen);

	if (old != NULL) {
		memcpy(p->region + offset, old, olen);
		cyon_mem_free(old);
	}

	key_count++;
	return (CYON_RESULT_OK);
}

void
cyon_store_flush(int what)
{
	int		fd;
	int		ret;

	if (cyon_readonly_mode || store_nopersist)
		return;

	if (what == CYON_STOREFLUSH_LOG) {
		if (log_modified == 0)
			return;
		fd = lfd;
	} else if (what == CYON_STOREFLUSH_DISK) {
		if (disk_modified == 0)
			return;
		fd = dfd;
	}

	for (;;) {
		ret = fsync(fd);
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret == -1) {
			cyon_log(LOG_WARNING,
			    "store sync failed (%d): %s", what, errno_s);
		}
		break;
	}

	if (what == CYON_STOREFLUSH_LOG)
		log_modified = 0;
	else if (what == CYON_STOREFLUSH_DISK)
		disk_modified = 0;
}

void
cyon_storelog_reopen(int wrlog)
{
	struct stat	st;
	int		flags;
	char		fpath[MAXPATHLEN], *fmt;

	if (lfd != -1) {
		cyon_store_flush(CYON_STOREFLUSH_LOG);
		close(lfd);
	}

	if (wrlog)
		fmt = CYON_WRITELOG_FILE;
	else
		fmt = CYON_LOG_FILE;

	snprintf(fpath, sizeof(fpath), fmt, storepath, storename);
	if (wrlog) {
		if (stat(fpath, &st) != -1)
			fatal("log open cancelled, log '%s' exists", fpath);
	}

	flags = O_CREAT | O_APPEND | O_WRONLY;
	if (store_always_sync)
		flags |= O_SYNC;

	lfd = open(fpath, flags, 0700);
	if (lfd == -1)
		fatal("could not open logfile %s: %s", fpath, errno_s);
	if (fstat(lfd, &st) == -1)
		fatal("fstat(lfd): %s", errno_s);

	store_log_offset = st.st_size;
}

pid_t
cyon_store_write(void)
{
	struct stat		st;
	pid_t			pid;
	u_int8_t		*buf;
	struct store_header	header;
	int			fd, ret;
	u_int32_t		len, blen;
	u_char			hash[SHA_DIGEST_LENGTH];
	char			*hex, fpath[MAXPATHLEN], tpath[MAXPATHLEN];

	if (rnode == NULL || store_modified == 0)
		return (CYON_RESULT_OK);

	cyon_store_lock(1);
	cyon_storelog_reopen(1);

	pid = fork();
	if (pid == -1) {
		cyon_store_unlock();
		cyon_log(LOG_NOTICE,
		    "store write not started (fork: %s)", errno_s);
		return (CYON_RESULT_ERROR);
	}

	if (pid != 0) {
		store_modified = 0;
		cyon_store_unlock();
		cyon_log(LOG_NOTICE, "store write started (%d)", pid);
		return (pid);
	}

	snprintf(fpath, sizeof(fpath), CYON_STORE_FILE, storepath, storename);
	snprintf(tpath, sizeof(tpath), CYON_STORE_TMPFILE,
	    storepath, storename);

	fd = open(tpath, O_CREAT | O_TRUNC | O_WRONLY, 0700);
	if (fd == -1)
		fatal("open(%s): %s", tpath, errno_s);

	memset(&header, 0, sizeof(header));
	if (store_passphrase != NULL)
		header.flags |= STORE_HAS_PASSPHRASE;
	if (lfd != -1)
		header.offset = store_log_offset;

	SHA_Init(&shactx);
	cyon_atomic_write(fd, &header, sizeof(header), CYON_ADD_CHECKSUM);
	if (header.flags & STORE_HAS_PASSPHRASE) {
		cyon_atomic_write(fd, store_passphrase,
		    SHA256_DIGEST_LENGTH, CYON_ADD_CHECKSUM);
	}

	if (store_nopersist == 0) {
		len = 0;
		blen = 128 * 1024 * 1024;
		buf = cyon_malloc(blen);

		cyon_store_writenode(fd, rnode, buf, blen, &len);
		if (len > 0)
			cyon_atomic_write(fd, buf, len, CYON_ADD_CHECKSUM);

		cyon_mem_free(buf);
	}

	SHA_Final(hash, &shactx);
	cyon_atomic_write(fd, hash, SHA_DIGEST_LENGTH, CYON_NO_CHECKSUM);

	for (;;) {
		ret = fsync(fd);
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret == -1)
			fatal("store write failed %s", errno_s);
		break;
	}

	close(fd);

	if (rename(tpath, fpath) == -1)
		fatal("cannot move store into place: %s", errno_s);

	snprintf(fpath, sizeof(fpath), CYON_LOG_FILE, storepath, storename);
	if (store_retain_logs) {
		cyon_sha_hex(store_state, &hex);
		snprintf(tpath, sizeof(fpath), CYON_MLOG_FILE,
		    storepath, storename, hex);
		cyon_mem_free(hex);

		if (stat(tpath, &st) != -1) {
			cyon_log(LOG_NOTICE,
			    "CAUTION: %s exists, skipping rename", tpath);
		} else if (rename(fpath, tpath) == -1) {
			fatal("could not move old log to marker: %s", errno_s);
		}
	}

	snprintf(tpath, sizeof(tpath), CYON_WRITELOG_FILE,
	    storepath, storename);

	if (rename(tpath, fpath) == -1)
		fatal("cannot move tmp log into place: %s", errno_s);

	exit(0);
}

void
cyon_storelog_write(u_int8_t op, u_int8_t *key, u_int32_t klen,
    u_int8_t *data, u_int32_t dlen, u_int32_t flags)
{
	u_int32_t		len;
	struct store_log	*slog;
	u_int8_t		*buf, *p;

	if (store_nopersist)
		return;

	len = sizeof(struct store_log) + klen + dlen;
	buf = cyon_malloc(len);

	slog = (struct store_log *)buf;
	memset(slog, 0, sizeof(*slog));

	slog->op = op;
	slog->klen = klen;
	slog->dlen = dlen;
	slog->flags = flags;
	memcpy(slog->magic, store_log_magic, 4);

	p = buf + sizeof(*slog);
	memcpy(p, key, slog->klen);
	if (dlen > 0)
		memcpy(p + slog->klen, data, dlen);

	SHA_Init(&shactx);
	SHA_Update(&shactx, buf, len);
	SHA_Final(slog->hash, &shactx);

	cyon_atomic_write(lfd, buf, len, CYON_NO_CHECKSUM);
	cyon_mem_free(buf);

	log_modified = 1;
	store_modified = 1;
	store_log_offset += len;
}

static void
cyon_store_writenode(int fd, struct node *p, u_int8_t *buf, u_int32_t blen,
    u_int32_t *len)
{
	struct node		*np;
	u_int32_t		offset, i, rlen, tlen, slen;

	if (p->flags & NODE_FLAG_HASDATA)
		offset = sizeof(u_int32_t) + *(u_int32_t *)p->region;
	else
		offset = 0;

	if (p->rbase == 0 && p->rtop == 0) {
		tlen = offset;
	} else {
		tlen = offset +
		    (((p->rtop - p->rbase) + 1) * sizeof(struct node));
	}

	if (p == rnode)
		tlen += sizeof(struct node);

	if ((*len + tlen) >= blen) {
		cyon_atomic_write(fd, buf, *len, CYON_ADD_CHECKSUM);
		*len = 0;
	}

	if (p == rnode) {
		tlen -= sizeof(struct node);
		memcpy(buf + *len, p, sizeof(struct node));

		/* Same hack as lower down for checksum. */
		np = (struct node *)(buf + *len);
		np->region = NULL;

		*len += sizeof(struct node);
	}

	if (p->region == NULL)
		return;

	slen = *len;
	memcpy(buf + *len, p->region, tlen);
	*len += tlen;

	if (p->rtop == 0 && p->rbase == 0)
		return;

	rlen = (p->rtop - p->rbase) + 1;
	for (i = 0; i < rlen; i++) {
		/*
		 * Set the region to NULL for the data we are going to
		 * write otherwise the checksum will be weird per machine.
		 */
		np = (struct node *)((u_int8_t *)(buf + slen) + offset +
		    (i * sizeof(struct node)));
		np->region = NULL;

		np = (struct node *)((u_int8_t *)p->region + offset +
		    (i * sizeof(struct node)));

		cyon_store_writenode(fd, np, buf, blen, len);
	}
}

static void
cyon_store_map(void)
{
	struct stat		st;
	int			fd;
	struct store_header	header;
	char			fpath[MAXPATHLEN];
	u_char			hash[SHA_DIGEST_LENGTH];
	u_char			ohash[SHA_DIGEST_LENGTH];

	if (store_nopersist)
		return;

	snprintf(fpath, sizeof(fpath), CYON_STORE_FILE, storepath, storename);
	if ((fd = open(fpath, O_RDONLY)) == -1) {
		if (errno != ENOENT)
			fatal("open(%s): %s", fpath, errno_s);

		store_modified = 1;
		memset(&header, 0, sizeof(header));
		cyon_storelog_replay(&header);
		return;
	}

	if (fstat(fd, &st) == -1)
		fatal("cyon_store_map(): fstat(): %s", errno_s);

	cyon_log(LOG_NOTICE, "starting store map");

	SHA_Init(&shactx);
	memset(&header, 0, sizeof(header));
	cyon_atomic_read(fd, &header, sizeof(header), CYON_ADD_CHECKSUM);

	if (header.flags & STORE_HAS_PASSPHRASE) {
		store_passphrase = cyon_malloc(SHA256_DIGEST_LENGTH);
		cyon_atomic_read(fd, store_passphrase,
		    SHA256_DIGEST_LENGTH, CYON_ADD_CHECKSUM);
	}

	rnode = cyon_malloc(sizeof(struct node));
	cyon_atomic_read(fd, rnode, sizeof(struct node), CYON_ADD_CHECKSUM);
	cyon_store_mapnode(fd, rnode);

	SHA_Final(hash, &shactx);
	cyon_atomic_read(fd, ohash, sizeof(ohash), CYON_NO_CHECKSUM);

	close(fd);

	if (memcmp(hash, ohash, SHA_DIGEST_LENGTH))
		fatal("SHA1 checksum mismatch, store corrupted?");

	memcpy(store_state, hash, SHA_DIGEST_LENGTH);
	cyon_storelog_replay(&header);
}

static void
cyon_storelog_replay(struct store_header *header)
{
	u_int8_t		ch;
	struct stat		st;
	u_int8_t		*buf;
	u_int64_t		len, olen;
	u_int8_t		*key, *data;
	struct store_log	slog, *plog;
	u_int64_t		added, removed;
	char			fpath[MAXPATHLEN];
	u_char			hash[SHA_DIGEST_LENGTH];

	snprintf(fpath, sizeof(fpath), CYON_LOG_FILE, storepath, storename);
	if ((lfd = open(fpath, O_RDONLY)) == -1) {
		if (errno == ENOENT)
			return;

		fatal("open(%s): %s", fpath, errno_s);
	}

	if (fstat(lfd, &st) == -1)
		fatal("fstat(): %s", errno_s);

	if (header->offset > (u_int64_t)st.st_size) {
		fatal("logfile %s corrupted? off: %ld > size: %ld",
		    fpath, header->offset, st.st_size);
	}

	if (header->offset == (u_int64_t)st.st_size) {
		close(lfd);
		return;
	}

	cyon_log(LOG_NOTICE,
	    "applying logfile to store from offset %ld", header->offset);

	if (lseek(lfd, header->offset, SEEK_SET) == -1)
		fatal("lseek() on logfile failed: %s", errno_s);

	olen = 0;
	buf = NULL;
	replaying_log = 1;
	added = removed = 0;

	for (;;) {
		while (header->offset < (u_int64_t)st.st_size) {
			cyon_atomic_read(lfd, &ch, 1, CYON_NO_CHECKSUM);
			if (ch != store_log_magic[0]) {
				header->offset++;
				continue;
			}

			header->offset++;

			if ((header->offset + sizeof(slog) - 1) >=
			    (u_int64_t)st.st_size)
				break;

			cyon_atomic_read(lfd, &slog.magic[1],
			    sizeof(slog) - 1, CYON_NO_CHECKSUM);
			header->offset += sizeof(slog) - 1;

			slog.magic[0] = ch;
			if (!memcmp(slog.magic, store_log_magic, 4))
				break;

			cyon_log(LOG_NOTICE,
			    "corrupted log entry in log @ %ld", header->offset);
			cyon_readonly_mode = 1;
		}

		if (header->offset >= (u_int64_t)st.st_size)
			break;

		if ((header->offset + slog.dlen +
		    slog.klen) > (u_int64_t)st.st_size) {
			cyon_readonly_mode = 1;
			cyon_log(LOG_NOTICE,
			    "log corrupted, would read past at %ld",
			    header->offset);
			continue;
		}

		len = slog.klen + slog.dlen + sizeof(slog);
		if (len > olen) {
			if (buf != NULL)
				cyon_mem_free(buf);
			buf = cyon_malloc(len);
		}

		olen = len;
		memcpy(buf, &slog, sizeof(slog));
		cyon_atomic_read(lfd, buf + sizeof(slog),
		    len - sizeof(slog), CYON_NO_CHECKSUM);
		header->offset += slog.klen + slog.dlen;

		plog = (struct store_log *)buf;
		memcpy(hash, plog->hash, SHA_DIGEST_LENGTH);
		memset(plog->hash, '\0', SHA_DIGEST_LENGTH);

		SHA_Init(&shactx);
		SHA_Update(&shactx, buf, len);
		SHA_Final(plog->hash, &shactx);

		if (memcmp(hash, plog->hash, SHA_DIGEST_LENGTH)) {
			cyon_readonly_mode = 1;
			cyon_log(LOG_NOTICE,
			    "Incorrect checksum for log @ %ld, skipping",
			    header->offset);
			continue;
		}

		key = buf + sizeof(slog);
		if (slog.dlen > 0)
			data = buf + sizeof(slog) + slog.klen;
		else
			data = NULL;

		if (rnode == NULL) {
			rnode = cyon_malloc(sizeof(struct node));
			memset(rnode, 0, sizeof(struct node));
		}

		store_modified = 1;

		switch (slog.op) {
		case CYON_OP_SETAUTH:
			if (slog.klen != SHA256_DIGEST_LENGTH) {
				cyon_log(LOG_NOTICE,
				    "replay of setauth log entry failed");
				break;
			}

			if (store_passphrase != NULL)
				cyon_mem_free(store_passphrase);
			store_passphrase = cyon_malloc(slog.klen);
			memcpy(store_passphrase, key, slog.klen);
			break;
		case CYON_OP_PUT:
			if (!cyon_store_put(key, slog.klen,
			    data, slog.dlen, slog.flags))
				fatal("replay of log failed at this stage?");
			added++;
			break;
		case CYON_OP_DEL:
			if (!cyon_store_del(key, slog.klen))
				fatal("replay of log failed at this stage?");
			removed++;
			break;
		case CYON_OP_REPLACE:
			if (!cyon_store_replace(key,
			    slog.klen, data, slog.dlen))
				fatal("replay of log failed at this stage?");
			break;
		default:
			printf("unknown log operation %d", slog.op);
			break;
		}
	}

	cyon_log(LOG_NOTICE,
	    "store replay completed: %ld added, %ld removed",
	    added, removed);

	close(lfd);
	replaying_log = 0;
}

static void
cyon_store_mapnode(int fd, struct node *p)
{
	struct node		*np;
	u_int32_t		rlen, i, offset;

	if (p->rbase > p->rtop)
		fatal("corruption in store detected");

	p->region = NULL;
	if (!(p->flags & NODE_FLAG_HASDATA) && p->rbase == 0 && p->rtop == 0)
		return;

	if (p->flags & NODE_FLAG_HASDATA) {
		key_count++;

		cyon_atomic_read(fd, &offset,
		    sizeof(u_int32_t), CYON_ADD_CHECKSUM);
		if (p->rbase != 0 && p->rtop != 0) {
			rlen = sizeof(u_int32_t) + offset +
			    (p->rtop - p->rbase + 1) * sizeof(struct node);
		} else {
			rlen = sizeof(u_int32_t) + offset;
		}

		p->region = cyon_malloc(rlen);
		*(u_int32_t *)p->region = offset;
		cyon_atomic_read(fd, p->region + sizeof(u_int32_t),
		    rlen - sizeof(u_int32_t), CYON_ADD_CHECKSUM);

		offset = offset + sizeof(u_int32_t);
	} else {
		offset = 0;
		if (p->rbase != 0 || p->rtop != 0) {
			rlen = (p->rtop - p->rbase + 1) * sizeof(struct node);
			p->region = cyon_malloc(rlen);
			cyon_atomic_read(fd,
			    p->region, rlen, CYON_ADD_CHECKSUM);
		}
	}

	if (p->rbase == 0 && p->rtop == 0)
		return;

	rlen = (p->rtop - p->rbase) + 1;
	for (i = 0; i < rlen; i++) {
		np = (struct node *)((u_int8_t *)p->region + offset +
		    (i * sizeof(struct node)));

		cyon_store_mapnode(fd, np);
	}
}

static struct node *
cyon_node_lookup(u_int8_t *key, u_int32_t len, u_int8_t resolve)
{
	u_int32_t	i;
	u_int8_t	idx;
	u_int32_t	rlen;
	struct node	*p, *l;

	if (len > CYON_KEY_MAX) {
		cyon_log(LOG_NOTICE, "Attempt to lookup key > CYON_KEY_MAX");
		return (NULL);
	}

	p = rnode;
	for (i = 0; i < len; i++) {
		idx = key[i];
		if (p == NULL || p->region == NULL)
			return (NULL);

		if (idx < p->rbase || idx > p->rtop)
			return (NULL);

		if (p->flags & NODE_FLAG_HASDATA)
			rlen = sizeof(u_int32_t) + *(u_int32_t *)p->region;
		else
			rlen = 0;

		p = (struct node *)((u_int8_t *)p->region + rlen +
		    ((idx - p->rbase) * sizeof(struct node)));
	}

	if (resolve == CYON_RESOLVE_LINK && (p->flags & NODE_FLAG_ISLINK)) {
		rlen = *(u_int32_t *)p->region;
		l = cyon_node_lookup(p->region + sizeof(u_int32_t),
		    rlen, CYON_RESOLVE_LINK);

		if (l == NULL || !(l->flags & NODE_FLAG_HASDATA)) {
			/* XXX - Should we do anything? */
		}

		p = l;
	}

	return (p);
}

static void
cyon_traverse_node(struct getkeys_ctx *ctx, struct connection *c,
    struct node *rp)
{
	struct disknode		*dn;
	u_int16_t		klen;
	struct node		*p, *wp;
	u_int8_t		i, *data;
	u_int32_t		rlen, len, nlen;

	if (rp->region == NULL)
		return;

	if (rp->flags & NODE_FLAG_HASDATA) {
		wp = rp;
		len = *(u_int32_t *)rp->region;
		rlen = sizeof(u_int32_t) + len;
		data = rp->region + sizeof(u_int32_t);

		if (store_mode == CYON_DISK_STORE) {
			len = *(u_int32_t *)rp->region;
			if (len != sizeof(struct disknode))
				fatal("dlen != sizeof(struct disknode)");
			dn = (struct disknode *)(rp->region + sizeof(len));
			cyon_diskstore_read(dn, &data, &len);
		} else {
			if (rp->flags & NODE_FLAG_ISLINK) {
				len = *(u_int32_t *)rp->region;
				rlen = sizeof(u_int32_t) + len;

				wp = cyon_node_lookup(rp->region +
				    sizeof(u_int32_t), len, CYON_RESOLVE_LINK);
				if (wp == NULL ||
				    !(wp->flags & NODE_FLAG_HASDATA))
					wp = NULL;

				len = *(u_int32_t *)wp->region;
				data = wp->region + sizeof(u_int32_t);
			}
		}

		net_write32((u_int8_t *)&nlen, len);
		net_write16((u_int8_t *)&klen, ctx->off);

		net_send_queue(c, (u_int8_t *)&klen, sizeof(klen), 0);
		net_send_queue(c, ctx->key, ctx->off, 0);
		net_send_queue(c, (u_int8_t *)&nlen, sizeof(nlen), 0);
		net_send_queue(c, data, len, 0);

		ctx->bytes += sizeof(klen) + ctx->off + sizeof(nlen) + len;
	} else {
		rlen = 0;
	}

	if (rp->rbase == 0 && rp->rtop == 0)
		return;

	for (i = rp->rbase; i <= rp->rtop; i++) {
		p = (struct node *)((u_int8_t *)rp->region + rlen +
		    ((i - rp->rbase) * sizeof(struct node)));

		if (ctx->off >= ctx->len)
			break;

		ctx->key[ctx->off++] = i;
		cyon_traverse_node(ctx, c, p);
		ctx->key[ctx->off--] = '\0';
	}
}

static void
cyon_diskstore_open(void)
{
	struct stat	st;
	int		flags;
	char		fpath[MAXPATHLEN];

	snprintf(fpath, sizeof(fpath), CYON_STORE_DSFILE, storepath, storename);

	flags = O_CREAT | O_APPEND | O_RDWR;
	if (store_always_sync)
		flags |= O_SYNC;

	dfd = open(fpath, flags, 0700);
	if (dfd == -1)
		fatal("could not open dsfile: %s", fpath);
	if (fstat(dfd, &st) == -1)
		fatal("fstat(dfd): %s", errno_s);

	store_ds_offset = st.st_size;
	cyon_log(LOG_NOTICE, "disk store opened at %ld", store_ds_offset);
}

static struct disknode *
cyon_diskstore_write(u_int8_t *key, u_int32_t klen, u_int8_t *d, u_int32_t dlen)
{
	u_int32_t		len;
	struct disknode		*dn;
	u_int8_t		*buf, *p;

	len = sizeof(struct disknode) + klen + dlen;
	buf = cyon_malloc(len);

	pthread_mutex_lock(&disk_lock);

	dn = (struct disknode *)buf;
	dn->didx = 1;
	dn->klen = klen;
	dn->dlen = dlen;
	dn->offset = store_ds_offset;
	memcpy(dn->magic, store_log_magic, 4);

	p = buf + sizeof(*dn);
	memcpy(p, key, dn->klen);
	if (dlen > 0)
		memcpy(p + dn->klen, d, dlen);

	SHA_Init(&shactx);
	SHA_Update(&shactx, buf, len);
	SHA_Final(dn->hash, &shactx);

	cyon_atomic_write(dfd, buf, len, CYON_NO_CHECKSUM);
	store_ds_offset += len;
	pthread_mutex_unlock(&disk_lock);

	disk_modified = 1;
	dn = cyon_malloc(sizeof(struct disknode));
	memcpy(dn, buf, sizeof(struct disknode));
	cyon_mem_free(buf);

	return (dn);
}

static void
cyon_diskstore_read(struct disknode *dn, u_int8_t **out, u_int32_t *len)
{
	u_int32_t		blen;
	u_int8_t		*buf;
	struct disknode		*dnode;

	blen = sizeof(struct disknode) + dn->klen + dn->dlen;
	buf = cyon_malloc(blen);

	pthread_mutex_lock(&disk_lock);
	if (lseek(dfd, dn->offset, SEEK_SET) == -1)
		fatal("lseek() on disk store failed: %s", errno_s);

	cyon_atomic_read(dfd, buf, blen, CYON_NO_CHECKSUM);

	if (lseek(dfd, store_ds_offset, SEEK_SET) == -1)
		fatal("lseek() on disk store failed (2): %s", errno_s);
	pthread_mutex_unlock(&disk_lock);

	dnode = (struct disknode *)buf;
	if (memcmp(dnode, dn, sizeof(struct disknode)))
		fatal("dnode != dn corruption in disk store?");

	*len = dnode->dlen;
	*out = cyon_malloc(dnode->dlen);
	memcpy(*out, buf + sizeof(*dnode) + dnode->klen, dnode->dlen);

	cyon_mem_free(buf);
}
