/*
 * Copyright (c) 2013-2014 Joris Vink <joris@coders.se>
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "cyon.h"
#include "shared.h"

/*
 * This code uses cyon_malloc() and memcpy() quite heavily due to the nature
 * of how keys and data are stored.
 */

#define STORE_HAS_PASSPHRASE		0x01

#define NODE_REGION_OFFSET(o, p)					\
	do {								\
		struct node_data *_nd = (struct node_data *)p;		\
		o = sizeof(struct node_data) + _nd->size;		\
	} while (0)

#define NODE_REGION_RANGE(r, p)						\
	do {								\
		r = ((p->rtop - p->rbase) + 1) * sizeof(struct node);	\
	} while (0)

struct node {
	u_int8_t	*region;
	u_int8_t	rbase;
	u_int8_t	rtop;
	u_int8_t	flags;
};

struct node_data {
	u_int32_t	size;
};

struct store_header {
	u_int8_t	flags;
};

static const u_int8_t	store_log_magic[] = { 0x43, 0x59, 0x4F, 0x4E };

struct store_log {
	u_int8_t	magic[4];
	u_int8_t	hash[SHA_DIGEST_LENGTH];

	u_int8_t	op;
	u_int32_t	klen;
	u_int32_t	dlen;
	u_int32_t	flags;
};

static void		cyon_store_map(void);
static void		cyon_storelog_replay_all(void);
static void		cyon_store_mapnode(int, struct node *);
static struct node	*cyon_node_lookup(u_int8_t *, u_int32_t);
static void		cyon_store_writenode(int, struct node *, u_int8_t *,
			    u_int32_t, u_int32_t *, SHA_CTX *);

SHA_CTX			shactx;
u_int64_t		key_count;
char			*storepath;
char			*storename;
u_int8_t		store_nopersist;
u_char			*store_passphrase;
u_int8_t		store_retain_logs;
u_int8_t		store_modified = 0;
u_int8_t		store_state[SHA_DIGEST_LENGTH];

static int		lfd;
static int		dfd;
static struct node	*rnode;
static pthread_rwlock_t	store_lock;
static u_int32_t	store_errors;
static u_int8_t		store_validation;
static u_int64_t	store_log_offset;
static u_int8_t		replaying_log = 0;
static u_int8_t		log_modified = 0;

void
cyon_store_init(void)
{
	char		*hex;

	lfd = -1;
	dfd = -1;
	rnode = NULL;
	key_count = 0;
	store_errors = 0;
	store_log_offset = 0;
	store_passphrase = NULL;

	SHA_Init(&shactx);
	SHA_Final(store_state, &shactx);

	pthread_rwlock_init(&store_lock, NULL);
	cyon_store_map();

	if (rnode == NULL) {
		cyon_log(LOG_NOTICE, "store is empty, starting a new one");

		if (store_retain_logs) {
			cyon_sha_hex(store_state, &hex);
			cyon_log(LOG_NOTICE, "new state is %s", hex);
			cyon_mem_free(hex);
		}

		rnode = cyon_malloc(sizeof(struct node));
		memset(rnode, 0, sizeof(struct node));
	} else {
		cyon_log(LOG_NOTICE,
		    "store loaded from disk with %ld keys", key_count);
	}

	if (store_errors) {
		cyon_log(LOG_ERR, "INCONSISTENCIES IN STORE LOG/DATA FILE");
		cyon_log(LOG_ERR, "THESE MUST BE REPAIRED. FORCING READONLY");
		cyon_readonly_mode = 1;
	}

	if (!store_nopersist && !cyon_readonly_mode)
		cyon_storelog_reopen(0);

	if (cyon_readonly_mode)
		cyon_log(LOG_NOTICE, "Cyon is in read-only mode");
}

void
cyon_store_lock(int wr)
{
	int		r, i;
	int		(*lock)(pthread_rwlock_t *);

	if (wr)
		lock = pthread_rwlock_wrlock;
	else
		lock = pthread_rwlock_rdlock;

	i = 0;
	for (;;) {
		if ((r = lock(&store_lock)) == 0)
			break;

		cyon_log(LOG_NOTICE,
		    "cyon_store_lock(%d) err nr#%d: %d", wr, i++, r);

		if (i == 5)
			fatal("cyon_store_lock(%d) completely failed", wr);
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
cyon_store_get(u_int8_t *key, u_int32_t len, u_int8_t **out,
    u_int32_t *olen, u_int8_t *err)
{
	struct node		*p;
	struct node_data	*nd;

	*out = NULL;
	*err = CYON_ERROR_UNKNOWN;

	if ((p = cyon_node_lookup(key, len)) == NULL) {
		*err = CYON_ERROR_ENOENT;
		return (CYON_RESULT_ERROR);
	}

	if (!(p->flags & NODE_FLAG_HASDATA)) {
		*err = CYON_ERROR_ENOENT;
		return (CYON_RESULT_ERROR);
	}

	nd = (struct node_data *)p->region;
	*olen = nd->size;
	*out = p->region + sizeof(struct node_data);

	return (CYON_RESULT_OK);
}

int
cyon_store_del(u_int8_t *key, u_int32_t len, u_int8_t *err)
{
	struct node	*p;
	u_int8_t	*old;
	u_int32_t	offset, rlen;

	*err = CYON_ERROR_UNKNOWN;

	if (!replaying_log && cyon_readonly_mode) {
		*err = CYON_ERROR_READONLY_MODE;
		return (CYON_RESULT_ERROR);
	}

	if ((p = cyon_node_lookup(key, len)) == NULL) {
		*err = CYON_ERROR_ENOENT;
		return (CYON_RESULT_ERROR);
	}

	if (!(p->flags & NODE_FLAG_HASDATA)) {
		*err = CYON_ERROR_ENOENT;
		return (CYON_RESULT_ERROR);
	}

	if (!replaying_log && !store_nopersist)
		cyon_storelog_write(CYON_OP_DEL, key, len, NULL, 0, 0);

	key_count--;
	p->flags = 0;

	if (p->rbase == 0 && p->rtop == 0) {
		cyon_mem_free(p->region);
		p->region = NULL;
	} else {
		NODE_REGION_OFFSET(offset, p->region);
		NODE_REGION_RANGE(rlen, p);
		old = p->region;

		p->region = cyon_malloc(rlen);
		memcpy(p->region, old + offset, rlen);

		cyon_mem_free(old);
	}

	return (CYON_RESULT_OK);
}

int
cyon_store_replace(u_int8_t *key, u_int32_t len, u_int8_t *data,
    u_int32_t dlen, u_int8_t *err)
{
	struct node		*p;
	struct node_data	*nd;
	u_int8_t		*old;
	u_int32_t		nlen, rlen, offset;

	*err = CYON_ERROR_UNKNOWN;

	if (!replaying_log && cyon_readonly_mode) {
		*err = CYON_ERROR_READONLY_MODE;
		return (CYON_RESULT_ERROR);
	}

	if ((p = cyon_node_lookup(key, len)) == NULL) {
		*err = CYON_ERROR_ENOENT;
		return (CYON_RESULT_ERROR);
	}

	if (!(p->flags & NODE_FLAG_HASDATA)) {
		*err = CYON_ERROR_ENOENT;
		return (CYON_RESULT_ERROR);
	}

	if (!replaying_log && !store_nopersist)
		cyon_storelog_write(CYON_OP_REPLACE, key, len, data, dlen, 0);

	old = p->region;
	if (p->rbase == 0 && p->rtop == 0) {
		rlen = 0;
		offset = 0;
	} else {
		NODE_REGION_OFFSET(offset, p->region);
		NODE_REGION_RANGE(rlen, p);
	}

	nlen = sizeof(struct node_data) + dlen + rlen;
	p->region = cyon_malloc(nlen);

	nd = (struct node_data *)p->region;
	nd->size = dlen;
	memcpy(p->region + sizeof(struct node_data), data, dlen);

	if (rlen != 0) {
		memcpy(p->region + sizeof(struct node_data) + dlen,
		    old + offset, rlen);
	}

	cyon_mem_free(old);
	return (CYON_RESULT_OK);
}

int
cyon_store_put(u_int8_t *key, u_int32_t len, u_int8_t *data,
    u_int32_t dlen, u_int32_t flags, u_int8_t *err)
{
	struct node		*p;
	struct node_data	*nd;
	size_t			olen, rlen;
	u_int32_t		base, offset;
	u_int8_t		i, idx, *old;

	*err = CYON_ERROR_UNKNOWN;

	if (len > CYON_KEY_MAX) {
		*err = CYON_ERROR_KEYLEN_INVALID;
		cyon_log(LOG_NOTICE, "Attempt to put key > CYON_KEY_MAX");
		return (CYON_RESULT_ERROR);
	}

	if (!replaying_log && cyon_readonly_mode) {
		*err = CYON_ERROR_READONLY_MODE;
		return (CYON_RESULT_ERROR);
	}

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
				NODE_REGION_OFFSET(offset, old);
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
			NODE_REGION_RANGE(olen, p);

			if (idx < p->rbase) {
				base = p->rbase - idx;
				p->rbase = idx;
			} else {
				p->rtop = idx;
				base = 0;
			}

			if (p->flags & NODE_FLAG_HASDATA) {
				NODE_REGION_OFFSET(offset, p->region);
			} else {
				offset = 0;
			}

			NODE_REGION_RANGE(rlen, p);
			rlen += offset;
			base = offset + (base * sizeof(struct node));

			p->region = cyon_malloc(rlen);
			memset(p->region + offset, 0, rlen - offset);

			if (offset > 0)
				memcpy(p->region, old, offset);
			memcpy(p->region + base, old + offset, olen);

			cyon_mem_free(old);
		}

		if (p->flags & NODE_FLAG_HASDATA)
			NODE_REGION_OFFSET(offset, p->region);
		else
			offset = 0;

		p = (struct node *)((u_int8_t *)p->region + offset +
		    ((idx - p->rbase) * sizeof(struct node)));
	}

	if (p->flags & NODE_FLAG_HASDATA) {
		*err = CYON_ERROR_EEXIST;
		return (CYON_RESULT_ERROR);
	}

	if (!replaying_log && !store_nopersist)
		cyon_storelog_write(CYON_OP_PUT, key, len, data, dlen, flags);

	old = p->region;
	if (old != NULL) {
		NODE_REGION_RANGE(olen, p);
		rlen = dlen + olen;
	} else {
		olen = 0;
		rlen = dlen;
	}

	p->flags = NODE_FLAG_HASDATA | flags;
	rlen += sizeof(struct node_data);

	p->region = cyon_malloc(rlen);
	nd = (struct node_data *)p->region;
	nd->size = dlen;

	offset = sizeof(struct node_data) + dlen;
	memcpy(p->region + sizeof(struct node_data), data, dlen);

	if (old != NULL) {
		memcpy(p->region + offset, old, olen);
		cyon_mem_free(old);
	}

	key_count++;
	return (CYON_RESULT_OK);
}

int
cyon_store_aput(u_int8_t *key, u_int32_t klen, u_int8_t *data,
    u_int32_t dlen, u_int8_t *err)
{
	struct node		*p;
	struct node_data	*nd;
	struct store_array	*ar;
	u_int8_t		*old, *rdata;
	u_int32_t		alen, rlen, off, elm, tmp;

	*err = CYON_ERROR_UNKNOWN;

	if (!replaying_log && cyon_readonly_mode) {
		*err = CYON_ERROR_READONLY_MODE;
		return (CYON_RESULT_ERROR);
	}

	if ((p = cyon_node_lookup(key, klen)) == NULL) {
		*err = CYON_ERROR_ENOENT;
		return (CYON_RESULT_ERROR);
	}

	if (!(p->flags & NODE_FLAG_HASDATA)) {
		*err = CYON_ERROR_ENOENT;
		return (CYON_RESULT_ERROR);
	}

	rdata = p->region + sizeof(struct node_data);
	ar = (struct store_array *)rdata;
	if (dlen != ar->elen) {
		*err = CYON_ERROR_INVALID_ARRAY_LEN;
		return (CYON_RESULT_ERROR);
	}

	if (!replaying_log && !store_nopersist)
		cyon_storelog_write(CYON_OP_APUT, key, klen, data, dlen, 0);

	if (ar->count >= ar->elm) {
		old = p->region;
		if (p->rbase == 0 && p->rtop == 0) {
			rlen = 0;
		} else {
			NODE_REGION_RANGE(rlen, p);
		}

		elm = (ar->elm / 10) + 1;
		tmp = ar->elm + elm;
		if (tmp > CYON_ARRAY_ELM_MAX) {
			*err = CYON_ERROR_ARRAY_ELM_TOO_BIG;
			return (CYON_RESULT_ERROR);
		}

		ar->elm = tmp;
		nd = (struct node_data *)p->region;
		alen = sizeof(struct node_data) + nd->size +
		    rlen + (elm * ar->elen);

		p->region = cyon_malloc(alen);
		memcpy(p->region, old, alen - (elm * ar->elen));
		cyon_mem_free(old);

		nd = (struct node_data *)p->region;
		nd->size = alen - sizeof(struct node_data) - rlen;
	}

	rdata = p->region + sizeof(struct node_data);
	ar = (struct store_array *)rdata;

	off = (ar->count++ * ar->elen) + sizeof(struct store_array);
	memcpy(rdata + off, data, dlen);

	return (CYON_RESULT_OK);
}

int
cyon_store_adel(u_int8_t *key, u_int32_t klen, u_int32_t offset,
    u_int8_t *err)
{
	struct node		*p;
	struct store_array	*ar;
	u_int8_t		*data, *next, *elm;
	u_int32_t		elms;

	*err = CYON_ERROR_UNKNOWN;

	if (!replaying_log && cyon_readonly_mode) {
		*err = CYON_ERROR_READONLY_MODE;
		return (CYON_RESULT_ERROR);
	}

	if ((p = cyon_node_lookup(key, klen)) == NULL) {
		*err = CYON_ERROR_ENOENT;
		return (CYON_RESULT_ERROR);
	}

	if (!(p->flags & NODE_FLAG_HASDATA)) {
		*err = CYON_ERROR_ENOENT;
		return (CYON_RESULT_ERROR);
	}

	ar = (struct store_array *)(p->region + sizeof(struct node_data));
	if ((int)offset < 0 || offset >= ar->count) {
		*err = CYON_ERROR_INVALID_ARRAY_LEN;
		return (CYON_RESULT_ERROR);
	}

	data = (u_int8_t *)ar + sizeof(struct store_array);

	elms = ar->count - 1;
	elm = data + (offset * ar->elen);
	if (offset < elms) {
		next = data + ((offset + 1) * ar->elen);
		memcpy(elm, next, ((elms - offset) * ar->elen));
	} else {
		memset(elm, 0, ar->elen);
	}

	ar->count--;

	return (CYON_RESULT_OK);
}

void
cyon_store_flush(void)
{
	int		ret;

	if (cyon_readonly_mode || store_nopersist)
		return;

	if (log_modified == 0)
		return;

	for (;;) {
		ret = fsync(lfd);
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret == -1)
			fatal("store sync failed: %s", errno_s);
		break;
	}

	log_modified = 0;
}

void
cyon_storelog_reopen(int wrlog)
{
	struct stat	st;
	int		flags;
	char		fpath[MAXPATHLEN], *hex;

	if (lfd != -1) {
		cyon_store_flush();
		close(lfd);
	}

	if (wrlog) {
		snprintf(fpath, sizeof(fpath),
		    CYON_WRITELOG_FILE, storepath, storename);
	} else {
		cyon_sha_hex(store_state, &hex);
		snprintf(fpath, sizeof(fpath),
		    CYON_LOG_FILE, storepath, storename, hex);
		cyon_mem_free(hex);
	}

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
	pid_t			pid;
	u_int8_t		*buf;
	struct store_header	header;
	int			fd, ret;
	u_int32_t		len, blen;
	u_char			hash[SHA_DIGEST_LENGTH];
	char			fpath[MAXPATHLEN], tpath[MAXPATHLEN];

	if (rnode == NULL || store_modified == 0 || store_nopersist) {
		cyon_log(LOG_NOTICE, "store is clean, not writing");
		return (CYON_RESULT_OK);
	}

	/*
	 * The write lock protects us from getting new entries in the log
	 * so it is safe to reopen the logs after the fork.
	 */
	cyon_store_lock(1);

	pid = fork();
	if (pid == -1) {
		cyon_store_unlock();
		cyon_log(LOG_NOTICE,
		    "store write not started (fork: %s)", errno_s);
		return (CYON_RESULT_ERROR);
	}

	if (pid != 0) {
		store_modified = 0;
		if (!cyon_readonly_mode)
			cyon_storelog_reopen(1);
		cyon_store_unlock();
		cyon_log(LOG_NOTICE, "store write started (%d)", pid);
		return (pid);
	}

	if (!cyon_readonly_mode)
		close(lfd);

	snprintf(fpath, sizeof(fpath), CYON_STORE_FILE, storepath, storename);
	snprintf(tpath, sizeof(tpath), CYON_STORE_TMPFILE,
	    storepath, storename);

	fd = open(tpath, O_CREAT | O_TRUNC | O_WRONLY, 0700);
	if (fd == -1)
		fatal("open(%s): %s", tpath, errno_s);

	memset(&header, 0, sizeof(header));
	if (store_passphrase != NULL)
		header.flags |= STORE_HAS_PASSPHRASE;

	len = 0;
	blen = 128 * 1024 * 1024;
	buf = cyon_malloc(blen);

	memcpy(buf, &header, sizeof(header));
	len += sizeof(header);

	if (header.flags & STORE_HAS_PASSPHRASE) {
		memcpy(buf + len, store_passphrase, SHA256_DIGEST_LENGTH);
		len += SHA256_DIGEST_LENGTH;
	}

	SHA_Init(&shactx);
	cyon_store_writenode(fd, rnode, buf, blen, &len, NULL);
	if (len > 0)
		cyon_atomic_write(fd, buf, len, &shactx);
	cyon_mem_free(buf);
	SHA_Final(hash, &shactx);
	cyon_atomic_write(fd, hash, SHA_DIGEST_LENGTH, NULL);

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

	cyon_atomic_write(lfd, buf, len, NULL);
	cyon_mem_free(buf);

	log_modified = 1;
	store_modified = 1;
	store_log_offset += len;
}

void
cyon_store_current_state(u_int8_t *hash)
{
	SHA_CTX			sctx;
	u_int8_t		*buf;
	struct store_header	header;
	u_int32_t		len, blen;

	memset(&header, 0, sizeof(header));
	if (store_passphrase != NULL)
		header.flags |= STORE_HAS_PASSPHRASE;

	len = 0;
	blen = 128 * 1024 * 1024;
	buf = cyon_malloc(blen);

	memcpy(buf, &header, sizeof(header));
	len += sizeof(header);

	if (header.flags & STORE_HAS_PASSPHRASE) {
		memcpy(buf + len, store_passphrase, SHA256_DIGEST_LENGTH);
		len += SHA256_DIGEST_LENGTH;
	}

	store_validation = 1;

	SHA_Init(&sctx);
	cyon_store_writenode(-1, rnode, buf, blen, &len, &sctx);
	if (len > 0)
		SHA_Update(&sctx, buf, len);
	cyon_mem_free(buf);
	SHA_Final(hash, &sctx);

	store_validation = 0;
}

int
cyon_storelog_replay(char *state, int when)
{
	struct stat		st;
	long			offset;
	u_int64_t		len, olen;
	struct store_log	slog, *plog;
	u_int64_t		added, removed;
	char			fpath[MAXPATHLEN], *hex;
	u_char			hash[SHA_DIGEST_LENGTH];
	u_int8_t		*buf, err, ch, *key, *data;

	snprintf(fpath, sizeof(fpath),
	    CYON_LOG_FILE, storepath, storename, state);
	if ((lfd = open(fpath, O_RDONLY)) == -1) {
		if (errno == ENOENT)
			return (CYON_RESULT_ERROR);

		fatal("open(%s): %s", fpath, errno_s);
	}

	if (fstat(lfd, &st) == -1)
		fatal("fstat(): %s", errno_s);

	if (st.st_size == 0) {
		close(lfd);

		if (when == CYON_REPLAY_STARTUP)
			return (CYON_RESULT_ERROR);
		return (CYON_RESULT_OK);
	}

	olen = 0;
	buf = NULL;
	offset = 0;
	replaying_log = 1;
	added = removed = 0;

	if (when == CYON_REPLAY_REQUEST)
		store_errors = 0;

	cyon_log(LOG_NOTICE, "applying log %s", fpath);
	for (;;) {
		while (offset < st.st_size) {
			cyon_atomic_read(lfd, &ch, 1, NULL, 0);
			offset++;

			if (ch != store_log_magic[0])
				continue;

			if ((long)(offset + sizeof(slog) - 1) >= st.st_size)
				break;

			cyon_atomic_read(lfd, &slog.magic[1],
			    sizeof(slog) - 1, NULL, 0);
			offset += sizeof(slog) - 1;

			slog.magic[0] = ch;
			if (!memcmp(slog.magic, store_log_magic, 4))
				break;
		}

		if (offset >= st.st_size)
			break;

		if ((offset + slog.dlen + slog.klen) > st.st_size) {
			store_errors++;
			cyon_log(LOG_NOTICE,
			    "LOG CORRUPTED, would read past at %ld", offset);
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
		    len - sizeof(slog), NULL, 0);
		offset += slog.klen + slog.dlen;

		plog = (struct store_log *)buf;
		memcpy(hash, plog->hash, SHA_DIGEST_LENGTH);
		memset(plog->hash, '\0', SHA_DIGEST_LENGTH);

		SHA_Init(&shactx);
		SHA_Update(&shactx, buf, len);
		SHA_Final(plog->hash, &shactx);

		if (memcmp(hash, plog->hash, SHA_DIGEST_LENGTH)) {
			store_errors++;
			cyon_log(LOG_NOTICE,
			    "INCORRECT CHECKSUM for log @ %ld, skipping",
			    offset);
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
			    data, slog.dlen, slog.flags, &err)) {
				if (when != CYON_REPLAY_REQUEST)
					fatal("replay failed at this stage?");
			}
			added++;
			break;
		case CYON_OP_DEL:
			if (!cyon_store_del(key, slog.klen, &err)) {
				if (when != CYON_REPLAY_REQUEST)
					fatal("replay failed at this stage?");
			}
			removed++;
			break;
		case CYON_OP_REPLACE:
			if (!cyon_store_replace(key,
			    slog.klen, data, slog.dlen, &err)) {
				if (when != CYON_REPLAY_REQUEST)
					fatal("replay failed at this stage?");
			}
			break;
		case CYON_OP_APUT:
			if (!cyon_store_aput(key,
			    slog.klen, data, slog.dlen, &err)) {
				if (when != CYON_REPLAY_REQUEST)
					fatal("replay failed at this stage?");
			}
			break;
		default:
			store_errors++;
			printf("unknown log operation %d\n", slog.op);
			break;
		}
	}

	if (buf != NULL)
		cyon_mem_free(buf);

	if (store_errors) {
		cyon_log(LOG_NOTICE, "LOG REPLAY *FAILED*, SEE ERRORS ABOVE");

		if (when == CYON_REPLAY_REQUEST) {
			cyon_readonly_mode = 1;
			cyon_log(LOG_NOTICE, "FORCING READONLY MODE");
		}
	} else {
		cyon_log(LOG_NOTICE,
		    "log replay completed: %ld added, %ld removed",
		    added, removed);
	}

	close(lfd);
	replaying_log = 0;

	if (!store_errors && store_retain_logs) {
		cyon_store_current_state(store_state);
		cyon_sha_hex(store_state, &hex);
		cyon_log(LOG_NOTICE, "store state is %s", hex);
	}

	return ((store_errors) ? CYON_RESULT_ERROR : CYON_RESULT_OK);
}

static void
cyon_store_writenode(int fd, struct node *p, u_int8_t *buf, u_int32_t blen,
    u_int32_t *len, SHA_CTX *sctx)
{
	struct node		*np;
	u_int32_t		offset, i, rlen, tlen, slen;

	if (p->flags & NODE_FLAG_HASDATA)
		NODE_REGION_OFFSET(offset, p->region);
	else
		offset = 0;

	if (p->rbase == 0 && p->rtop == 0) {
		tlen = offset;
	} else {
		NODE_REGION_RANGE(tlen, p);
		tlen += offset;
	}

	if (p == rnode)
		tlen += sizeof(struct node);

	if ((*len + tlen) >= blen) {
		if (store_validation)
			SHA_Update(sctx, buf, *len);
		else
			cyon_atomic_write(fd, buf, *len, &shactx);
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

		cyon_store_writenode(fd, np, buf, blen, len, sctx);
	}
}

static void
cyon_store_map(void)
{
	struct stat		st;
	int			fd;
	struct store_header	header;
	char			fpath[MAXPATHLEN], *hex;
	u_char			hash[SHA_DIGEST_LENGTH];
	u_char			ohash[SHA_DIGEST_LENGTH];

	if (store_nopersist)
		return;

	snprintf(fpath, sizeof(fpath), CYON_STORE_FILE, storepath, storename);
	if ((fd = open(fpath, O_RDONLY)) == -1) {
		if (errno != ENOENT)
			fatal("open(%s): %s", fpath, errno_s);

		cyon_storelog_replay_all();
		return;
	}

	if (fstat(fd, &st) == -1)
		fatal("cyon_store_map(): fstat(): %s", errno_s);

	SHA_Init(&shactx);
	memset(&header, 0, sizeof(header));
	cyon_atomic_read(fd, &header, sizeof(header), &shactx, 0);

	if (header.flags & STORE_HAS_PASSPHRASE) {
		store_passphrase = cyon_malloc(SHA256_DIGEST_LENGTH);
		cyon_atomic_read(fd, store_passphrase,
		    SHA256_DIGEST_LENGTH, &shactx, 0);
	}

	rnode = cyon_malloc(sizeof(struct node));
	cyon_atomic_read(fd, rnode, sizeof(struct node), &shactx, 0);
	cyon_store_mapnode(fd, rnode);

	SHA_Final(hash, &shactx);
	cyon_atomic_read(fd, ohash, sizeof(ohash), NULL, 0);

	close(fd);

	if (memcmp(hash, ohash, SHA_DIGEST_LENGTH))
		fatal("SHA1 checksum mismatch, store corrupted?");

	memcpy(store_state, hash, SHA_DIGEST_LENGTH);
	if (store_retain_logs) {
		cyon_sha_hex(store_state, &hex);
		cyon_log(LOG_NOTICE, "store state is %s", hex);
		cyon_mem_free(hex);
	}

	cyon_storelog_replay_all();
}

static void
cyon_storelog_replay_all(void)
{
	char		*hex;

	for (;;) {
		cyon_sha_hex(store_state, &hex);
		if (!cyon_storelog_replay(hex, CYON_REPLAY_STARTUP) ||
		    !store_retain_logs) {
			cyon_mem_free(hex);
			break;
		}

		cyon_mem_free(hex);
	}
}

static void
cyon_store_mapnode(int fd, struct node *p)
{
	struct node_data	nd;
	struct node		*np;
	u_int32_t		rlen, i, offset;

	if (p->rbase > p->rtop)
		fatal("corruption in store detected");

	p->region = NULL;
	if (!(p->flags & NODE_FLAG_HASDATA) && p->rbase == 0 && p->rtop == 0)
		return;

	if (p->flags & NODE_FLAG_HASDATA) {
		key_count++;

		cyon_atomic_read(fd, &nd, sizeof(nd), &shactx, 0);
		if (p->rbase != 0 && p->rtop != 0) {
			NODE_REGION_RANGE(rlen, p);
			rlen += sizeof(struct node_data) + nd.size;
		} else {
			rlen = sizeof(struct node_data) + nd.size;
		}

		p->region = cyon_malloc(rlen);
		memcpy(p->region, &nd, sizeof(nd));
		cyon_atomic_read(fd, p->region + sizeof(struct node_data),
		    rlen - sizeof(struct node_data), &shactx, 0);
		offset = nd.size + sizeof(struct node_data);
	} else {
		offset = 0;
		if (p->rbase != 0 || p->rtop != 0) {
			NODE_REGION_RANGE(rlen, p);
			p->region = cyon_malloc(rlen);
			cyon_atomic_read(fd, p->region, rlen, &shactx, 0);
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
cyon_node_lookup(u_int8_t *key, u_int32_t len)
{
	u_int32_t		i;
	struct node		*p;
	u_int8_t		idx;
	u_int32_t		rlen;

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
			NODE_REGION_OFFSET(rlen, p->region);
		else
			rlen = 0;

		p = (struct node *)((u_int8_t *)p->region + rlen +
		    ((idx - p->rbase) * sizeof(struct node)));
	}

	return (p);
}
