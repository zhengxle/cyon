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
#include <unistd.h>

#include "cyon.h"

/*
 * This code uses cyon_malloc() and memcpy() quite heavily due to the nature
 * of how keys and data are stored.
 */

#define CYON_NO_CHECKSUM		0
#define CYON_ADD_CHECKSUM		1

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

static void		cyon_store_map(void);
static void		cyon_traverse_node(struct node *);
static void		cyon_store_mapnode(int, struct node *);
static void		cyon_storelog_replay(struct store_header *);
static void		cyon_atomic_read(int, void *, u_int32_t, int);
static void		cyon_atomic_write(int, void *, u_int32_t, int);
static struct node	*cyon_node_lookup(u_int8_t *, u_int32_t, u_int8_t);
static void		cyon_store_writenode(int, struct node *, u_int8_t *,
			    u_int32_t, u_int32_t *);

u_int64_t		key_count;
char			*storepath;
char			*storename;
u_int8_t		store_nowrite;
u_char			*store_passphrase;

static int		lfd;
static struct node	*rnode;
static SHA_CTX		shactx;
static u_int64_t	store_log_offset;
static u_int8_t		replaying_log = 0;
static u_int8_t		log_modified = 0;

static u_int32_t	*traverse_count;
static u_int8_t		*traverse_buf = NULL;
static u_int32_t	traverse_buf_len = 0;
static u_int32_t	traverse_buf_off = 0;

static u_int8_t		*traverse_key = NULL;
static u_int32_t	traverse_key_len = 0;
static u_int32_t	traverse_key_off = 0;

void
cyon_store_init(void)
{
	lfd = -1;
	rnode = NULL;
	key_count = 0;
	store_log_offset = 0;
	store_passphrase = NULL;

	traverse_buf_off = 0;
	traverse_buf_len = 16 * 1024 * 1024;
	traverse_buf = cyon_malloc(traverse_buf_len);

	traverse_key_off = 0;
	traverse_key_len = 1024;
	traverse_key = cyon_malloc(traverse_key_len);
	memset(traverse_key, '\0', traverse_key_len);

	cyon_store_map();

	if (rnode == NULL) {
		cyon_log(LOG_NOTICE, "store is empty, starting new store");
		rnode = cyon_malloc(sizeof(struct node));
		memset(rnode, 0, sizeof(struct node));
	} else {
		cyon_log(LOG_NOTICE,
		    "store loaded from disk with %ld keys", key_count);
	}

	if (!store_nowrite)
		cyon_storelog_reopen(0);
}

int
cyon_store_get(u_int8_t *key, u_int32_t len, u_int8_t **out, u_int32_t *olen)
{
	struct node	*p;

	*out = NULL;
	if ((p = cyon_node_lookup(key, len, CYON_RESOLVE_LINK)) == NULL)
		return (CYON_RESULT_ERROR);

	if (!(p->flags & NODE_FLAG_HASDATA))
		return (CYON_RESULT_ERROR);

	*olen = *(u_int32_t *)p->region;
	*out = p->region + sizeof(u_int32_t);

	return (CYON_RESULT_OK);
}

int
cyon_store_getkeys(u_int8_t *root, u_int32_t rlen,
    u_int8_t **out, u_int32_t *olen)
{
	struct node	*p;

	*olen = 0;
	*out = NULL;

	if ((p = cyon_node_lookup(root, rlen, CYON_RESOLVE_NOTHING)) == NULL)
		return (CYON_RESULT_OK);

	if (p->region == NULL)
		return (CYON_RESULT_OK);

	memset(traverse_key, '\0', traverse_key_len);
	memcpy(traverse_key, root, rlen);
	traverse_key_off = rlen;

	traverse_count = (u_int32_t *)traverse_buf;
	traverse_buf_off = sizeof(u_int32_t);
	*traverse_count = 0;

	cyon_traverse_node(p);

	*out = traverse_buf;
	*olen = traverse_buf_off;
	net_write32((u_int8_t *)traverse_count, *traverse_count);

	return (CYON_RESULT_OK);
}

int
cyon_store_del(u_int8_t *key, u_int32_t len)
{
	struct node	*p;
	u_int8_t	*old;
	u_int32_t	offset, rlen;

	if ((p = cyon_node_lookup(key, len, CYON_RESOLVE_NOTHING)) == NULL)
		return (CYON_RESULT_ERROR);

	if (!(p->flags & NODE_FLAG_HASDATA))
		return (CYON_RESULT_ERROR);

	if (!replaying_log && !store_nowrite)
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
	struct node	*p;
	u_int8_t	*old;
	u_int32_t	nlen, rlen, offset;

	if ((p = cyon_node_lookup(key, len, CYON_RESOLVE_NOTHING)) == NULL)
		return (CYON_RESULT_ERROR);

	if (!(p->flags & NODE_FLAG_HASDATA))
		return (CYON_RESULT_ERROR);

	if (!replaying_log && !store_nowrite)
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
	struct node		*p;
	size_t			olen, rlen;
	u_int32_t		base, offset;
	u_int8_t		i, idx, *old;

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

	if (!replaying_log && !store_nowrite)
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
cyon_storelog_flush(void)
{
	int		ret;

	if (log_modified == 0)
		return;

	for (;;) {
		ret = fsync(lfd);
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret == -1)
			cyon_log(LOG_WARNING, "log sync failed: %s", errno_s);
		break;
	}
}

void
cyon_storelog_reopen(int wrlog)
{
	struct stat	st;
	char		fpath[MAXPATHLEN], *fmt;

	if (lfd != -1) {
		cyon_storelog_flush();
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

	lfd = open(fpath, O_CREAT | O_APPEND | O_WRONLY, 0700);
	if (lfd == -1)
		fatal("could not open logfile %s: %s", fpath, errno_s);
	if (fstat(lfd, &st) == -1)
		fatal("fstat(lfd): %s", errno_s);

	store_log_offset = st.st_size;
}

pid_t
cyon_store_write(void)
{
	pid_t			pid;
	u_int8_t		*buf;
	struct store_header	header;
	int			fd, ret;
	u_int32_t		len, blen;
	u_char			hash[SHA_DIGEST_LENGTH];
	char			fpath[MAXPATHLEN], tpath[MAXPATHLEN];

	if (rnode == NULL)
		return (CYON_RESULT_OK);

	cyon_storelog_reopen(1);

	pid = fork();
	if (pid == -1) {
		cyon_log(LOG_NOTICE,
		    "store write not started (fork: %s)", errno_s);
		return (CYON_RESULT_ERROR);
	}

	if (pid != 0) {
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

	if (store_nowrite == 0) {
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
			fatal("store write failed #6");

		break;
	}

	close(fd);

	if (rename(tpath, fpath) == -1)
		fatal("cannot move store into place: %s", errno_s);

	snprintf(fpath, sizeof(fpath), CYON_LOG_FILE, storepath, storename);
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
	u_int8_t		*buf;
	struct store_log	slog;

	if (store_nowrite)
		return;

	memset(&slog, 0, sizeof(slog));

	slog.op = op;
	slog.klen = klen;
	slog.dlen = dlen;
	slog.flags = flags;
	memcpy(slog.magic, store_log_magic, 4);

	len = klen + dlen + (sizeof(u_int32_t) * 2);
	buf = cyon_malloc(len);

	memcpy(buf, &klen, sizeof(u_int32_t));
	memcpy(buf + sizeof(u_int32_t), &dlen, sizeof(u_int32_t));
	memcpy(buf + (sizeof(u_int32_t) * 2), key, klen);
	if (dlen > 0)
		memcpy(buf + (sizeof(u_int32_t) * 2) + klen, data, dlen);

	SHA_Init(&shactx);
	SHA_Update(&shactx, buf, len);
	SHA_Final(slog.hash, &shactx);

	cyon_atomic_write(lfd, &slog, sizeof(slog), CYON_NO_CHECKSUM);
	cyon_atomic_write(lfd, buf + (sizeof(u_int32_t) * 2),
	    len - (sizeof(u_int32_t) * 2), CYON_NO_CHECKSUM);

	log_modified = 1;
	cyon_mem_free(buf);
	store_log_offset += sizeof(slog) + (len - (sizeof(u_int32_t) * 2));
}

static void
cyon_store_writenode(int fd, struct node *p, u_int8_t *buf, u_int32_t blen,
    u_int32_t *len)
{
	struct node		*np;
	u_int32_t		offset, i, rlen;

	if (p->flags & NODE_FLAG_HASDATA)
		offset = sizeof(u_int32_t) + *(u_int32_t *)p->region;
	else
		offset = 0;

	if (p->rbase == 0 && p->rtop == 0) {
		rlen = offset;
	} else {
		rlen = offset +
		    (((p->rtop - p->rbase) + 1) * sizeof(struct node));
	}

	if (p == rnode)
		rlen += sizeof(struct node);

	if ((*len + rlen) >= blen) {
		cyon_atomic_write(fd, buf, *len, CYON_ADD_CHECKSUM);
		*len = 0;
	}

	if (p == rnode) {
		rlen -= sizeof(struct node);
		memcpy(buf + *len, p, sizeof(struct node));
		*len += sizeof(struct node);
	}

	if (p->region == NULL)
		return;

	memcpy(buf + *len, p->region, rlen);
	*len += rlen;

	if (p->rtop == 0 && p->rbase == 0)
		return;

	rlen = (p->rtop - p->rbase) + 1;
	for (i = 0; i < rlen; i++) {
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

	snprintf(fpath, sizeof(fpath), CYON_STORE_FILE, storepath, storename);
	if ((fd = open(fpath, O_RDONLY)) == -1) {
		if (errno != ENOENT)
			fatal("open(%s): %s", fpath, errno_s);

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

	if (store_nowrite == 0) {
		rnode = cyon_malloc(sizeof(struct node));
		cyon_atomic_read(fd, rnode,
		    sizeof(struct node), CYON_ADD_CHECKSUM);
		cyon_store_mapnode(fd, rnode);
	}

	SHA_Final(hash, &shactx);
	cyon_atomic_read(fd, ohash, sizeof(ohash), CYON_NO_CHECKSUM);

	close(fd);

	if (memcmp(hash, ohash, SHA_DIGEST_LENGTH))
		fatal("SHA1 checksum mismatch, store corrupted?");

	cyon_storelog_replay(&header);
}

static void
cyon_storelog_replay(struct store_header *header)
{
	struct stat		st;
	struct store_log	slog;
	u_int8_t		*buf;
	u_int64_t		len, olen;
	u_int8_t		*key, *data;
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

	while (header->offset < (u_int64_t)st.st_size) {
		cyon_atomic_read(lfd, &slog, sizeof(slog), CYON_NO_CHECKSUM);
		if (memcmp(slog.magic, store_log_magic, 4))
			fatal("logfile is corrupted, run repair tool");

		len = slog.klen + slog.dlen + (sizeof(u_int32_t) * 2);
		if (len > olen) {
			if (buf != NULL)
				cyon_mem_free(buf);
			buf = cyon_malloc(len);
		}

		olen = len;
		memcpy(buf, &(slog.klen), sizeof(u_int32_t));
		memcpy(buf + sizeof(u_int32_t),
		    &(slog.dlen), sizeof(u_int32_t));

		cyon_atomic_read(lfd, (buf + (sizeof(u_int32_t) * 2)),
		    slog.klen + slog.dlen, CYON_NO_CHECKSUM);

		SHA_Init(&shactx);
		SHA_Update(&shactx, buf, len);
		SHA_Final(hash, &shactx);

		if (memcmp(hash, slog.hash, SHA_DIGEST_LENGTH))
			fatal("hash is wrong for entry, run repair tool");

		header->offset += sizeof(slog) + slog.klen + slog.dlen;

		key = buf + (sizeof(u_int32_t) * 2);
		if (slog.dlen > 0)
			data = buf + (sizeof(u_int32_t) * 2) + slog.klen;
		else
			data = NULL;

		if (rnode == NULL) {
			rnode = cyon_malloc(sizeof(struct node));
			memset(rnode, 0, sizeof(struct node));
		}

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

static void
cyon_atomic_write(int fd, void *buf, u_int32_t len, int calc)
{
	ssize_t		r;
	u_int8_t	*d;
	u_int32_t	written;

	d = buf;
	written = 0;
	while (written != len) {
		r = write(fd, d + written, len - written);
		if (r == -1 && errno == EINTR)
			continue;
		if (r == -1)
			fatal("cyon_atomic_write(): %s", errno_s);

		written += r;
	}

	if (calc)
		SHA_Update(&shactx, buf, len);
}

static void
cyon_atomic_read(int fd, void *buf, u_int32_t len, int calc)
{
	ssize_t		r;
	u_int8_t	*d;
	u_int32_t	done;

	d = buf;
	done = 0;
	while (done != len) {
		r = read(fd, d + done, len - done);
		if (r == -1 && errno == EINTR)
			continue;

		/* Treat eof (r == 0) as an error. */
		if (r == -1 || r == 0)
			fatal("cyon_atomic_read(): %s", errno_s);

		done += r;
	}

	if (calc)
		SHA_Update(&shactx, buf, len);
}

static struct node *
cyon_node_lookup(u_int8_t *key, u_int32_t len, u_int8_t resolve)
{
	u_int32_t	i;
	u_int8_t	idx;
	u_int32_t	rlen;
	struct node	*p, *l;

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

		/* XXX - this can be dealth with better. */
		if (l == NULL || !(l->flags & NODE_FLAG_HASDATA)) {
			if (!cyon_store_del(key, len)) {
				cyon_log(LOG_NOTICE,
				    "failed to remove stale link");
			}
		}

		p = l;
	}

	return (p);
}

static void
cyon_traverse_node(struct node *rp)
{
	u_int8_t	i;
	struct node	*p;
	u_int32_t	rlen, len, klen;

	if (rp->region == NULL)
		return;

	if (rp->flags & NODE_FLAG_HASDATA) {
		len = *(u_int32_t *)rp->region;
		rlen = sizeof(u_int32_t) + len;

		klen = sizeof(u_int16_t) + traverse_key_off;
		if ((traverse_buf_off + klen) >= traverse_buf_len) {
			cyon_log(LOG_NOTICE,
			    "traverse output exhausted (%d keys)",
			    *traverse_count);
			return;
		}

		*traverse_count = *traverse_count + 1;

		net_write16(traverse_buf + traverse_buf_off, traverse_key_off);
		memcpy(traverse_buf + traverse_buf_off + sizeof(u_int16_t),
		    traverse_key, traverse_key_off);

		traverse_buf_off += klen;
	} else {
		rlen = 0;
	}

	if (rp->rbase == 0 && rp->rtop == 0)
		return;

	for (i = rp->rbase; i <= rp->rtop; i++) {
		p = (struct node *)((u_int8_t *)rp->region + rlen +
		    ((i - rp->rbase) * sizeof(struct node)));

		if (traverse_key_off >= traverse_key_len) {
			traverse_key_len = traverse_key_len * 2;
			traverse_key = cyon_realloc(traverse_key,
			    traverse_key_len);

			memset(traverse_key + traverse_key_off,
			    '\0', traverse_key_len - traverse_key_off);
		}

		traverse_key[traverse_key_off++] = i;
		cyon_traverse_node(p);
		traverse_key[traverse_key_off--] = '\0';
	}
}
