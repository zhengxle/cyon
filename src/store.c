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

#include <sys/types.h>
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

#define CYON_STORE_PATH			"cyon.store"
#define CYON_STORE_TMPPATH		"cyon.store.tmp"

#define NODE_FLAG_HASDATA		0x01

#define STORE_HAS_PASSPHRASE		0x01

struct node {
	u_int8_t	rbase;
	u_int8_t	rtop;
	u_int8_t	flags;
	u_int8_t	*region;
} __attribute__((__packed__));

static int		cyon_store_map(void);
static int		cyon_atomic_read(int, void *, u_int32_t, int);
static int		cyon_atomic_write(int, void *, u_int32_t, int);
static int		cyon_store_mapnode(int, struct node *);
static struct node	*cyon_node_lookup(u_int8_t *, u_int32_t);
static int		cyon_store_writenode(int, struct node *,
			    u_int8_t *, u_int32_t, u_int32_t, u_int32_t *);

u_int64_t		key_count;
u_char			*store_passphrase;

static struct node	*rnode;
static SHA256_CTX	sha256ctx;

void
cyon_store_init(void)
{
	key_count = 0;
	rnode = NULL;
	store_passphrase = NULL;

	if (!cyon_store_map())
		fatal("could not load store file");

	if (rnode == NULL) {
		cyon_log(LOG_NOTICE, "starting new store");
		rnode = cyon_malloc(sizeof(struct node));
		memset(rnode, 0, sizeof(struct node));
	} else {
		cyon_log(LOG_NOTICE,
		    "store loaded from disk: %ld keys", key_count);
	}
}

int
cyon_store_get(u_int8_t *key, u_int32_t len, u_int8_t **out, u_int32_t *olen)
{
	struct node	*p;

	*out = NULL;
	if ((p = cyon_node_lookup(key, len)) == NULL)
		return (CYON_RESULT_ERROR);

	if (!(p->flags & NODE_FLAG_HASDATA))
		return (CYON_RESULT_ERROR);

	*olen = *(u_int32_t *)p->region;
	*out = p->region + sizeof(u_int32_t);

	return (CYON_RESULT_OK);
}

int
cyon_store_del(u_int8_t *key, u_int32_t len)
{
	struct node	*p;
	u_int8_t	*old;
	u_int32_t	offset, rlen;

	if ((p = cyon_node_lookup(key, len)) == NULL)
		return (CYON_RESULT_ERROR);

	if (!(p->flags & NODE_FLAG_HASDATA))
		return (CYON_RESULT_ERROR);

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
cyon_store_put(u_int8_t *key, u_int32_t len, u_int8_t *data, u_int32_t dlen)
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

	old = p->region;

	if (old != NULL) {
		olen = ((p->rtop - p->rbase) + 1) * sizeof(struct node);
		rlen = dlen + olen;
	} else {
		olen = 0;
		rlen = dlen;
	}

	p->flags = NODE_FLAG_HASDATA;
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

int
cyon_store_write(void)
{
	int			fd, ret;
	u_int8_t		*buf, flags;
	u_int32_t		len, blen, mlen;
	u_char			hash[SHA256_DIGEST_LENGTH];

	fd = open(CYON_STORE_TMPPATH, O_CREAT | O_TRUNC | O_WRONLY, 0700);
	if (fd == -1) {
		cyon_debug("open(%s): %d", CYON_STORE_TMPPATH, errno);
		return (CYON_RESULT_ERROR);
	}

	SHA256_Init(&sha256ctx);

	flags = 0;
	if (store_passphrase != NULL)
		flags = STORE_HAS_PASSPHRASE;

	if (!cyon_atomic_write(fd, &flags, sizeof(flags), CYON_ADD_CHECKSUM)) {
		close(fd);
		unlink(CYON_STORE_TMPPATH);
		return (CYON_RESULT_ERROR);
	}

	if (flags & STORE_HAS_PASSPHRASE) {
		if (!cyon_atomic_write(fd, store_passphrase,
		    SHA256_DIGEST_LENGTH, CYON_ADD_CHECKSUM)) {
			close(fd);
			unlink(CYON_STORE_TMPPATH);
			return (CYON_RESULT_ERROR);
		}
	}

	len = 0;
	blen = 128 * 1024 * 1024;
	buf = cyon_malloc(blen);
	mlen = sizeof(struct node);

	if (!cyon_store_writenode(fd, rnode, buf, blen, mlen, &len)) {
		cyon_mem_free(buf);
		close(fd);
		unlink(CYON_STORE_TMPPATH);
		return (CYON_RESULT_ERROR);
	}

	if (len > 0) {
		if (!cyon_atomic_write(fd, buf, len, CYON_ADD_CHECKSUM)) {
			cyon_mem_free(buf);
			close(fd);
			unlink(CYON_STORE_TMPPATH);
			return (CYON_RESULT_ERROR);
		}
	}

	SHA256_Final(hash, &sha256ctx);

	if (!cyon_atomic_write(fd, hash,
	    SHA256_DIGEST_LENGTH, CYON_NO_CHECKSUM)) {
		cyon_mem_free(buf);
		close(fd);
		unlink(CYON_STORE_TMPPATH);
		return (CYON_RESULT_ERROR);
	}

	cyon_mem_free(buf);

	cyon_log(LOG_NOTICE, "flushing store...");
	for (;;) {
		ret = fsync(fd);
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret == -1) {
			close(fd);
			cyon_debug("fsync(): %d, aborting!", errno);
			unlink(CYON_STORE_TMPPATH);
			return (CYON_RESULT_ERROR);
		}

		break;
	}

	close(fd);

	if (rename(CYON_STORE_TMPPATH, CYON_STORE_PATH) == -1) {
		cyon_debug("cannot move store into place: %d", errno);
		unlink(CYON_STORE_TMPPATH);
		return (CYON_RESULT_ERROR);
	}

	return (CYON_RESULT_OK);
}

static int
cyon_store_writenode(int fd, struct node *p, u_int8_t *buf, u_int32_t blen,
    u_int32_t mlen, u_int32_t *len)
{
	int			r;
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

	if ((*len + mlen) > (blen + rlen)) {
		if (!cyon_atomic_write(fd,
		    buf, *len, CYON_ADD_CHECKSUM))
			return (CYON_RESULT_ERROR);

		*len = 0;
	}

	if (p == rnode) {
		memcpy(buf + *len, p, mlen);
		*len += mlen;
	}

	if (p->region == NULL)
		return (CYON_RESULT_OK);

	memcpy(buf + *len, p->region, rlen);
	*len += rlen;

	if (p->rtop == 0 && p->rbase == 0)
		return (CYON_RESULT_OK);

	r = CYON_RESULT_OK;
	rlen = (p->rtop - p->rbase) + 1;
	for (i = 0; i < rlen; i++) {
		np = (struct node *)((u_int8_t *)p->region + offset +
		    (i * sizeof(struct node)));

		r = cyon_store_writenode(fd, np, buf, blen, mlen, len);
		if (r == CYON_RESULT_ERROR)
			break;
	}

	return (r);
}

static int
cyon_store_map(void)
{
	struct stat	st;
	int		fd;
	u_int8_t	flags;
	u_char		hash[SHA256_DIGEST_LENGTH];
	u_char		ohash[SHA256_DIGEST_LENGTH];

	if ((fd = open(CYON_STORE_PATH, O_RDONLY)) == -1) {
		if (errno != ENOENT) {
			cyon_debug("open(%s): %s", CYON_STORE_PATH, errno);
			return (CYON_RESULT_ERROR);
		}

		return (CYON_RESULT_OK);
	}

	if (fstat(fd, &st) == -1) {
		cyon_debug("fstat(): %d", errno);
		close(fd);
		return (CYON_RESULT_ERROR);
	}

	SHA256_Init(&sha256ctx);

	if (!cyon_atomic_read(fd, &flags, sizeof(flags), CYON_ADD_CHECKSUM)) {
		close(fd);
		return (CYON_RESULT_ERROR);
	}

	if (flags & STORE_HAS_PASSPHRASE) {
		store_passphrase = cyon_malloc(SHA256_DIGEST_LENGTH);
		if (!cyon_atomic_read(fd, store_passphrase,
		    SHA256_DIGEST_LENGTH, CYON_ADD_CHECKSUM)) {
			close(fd);
			free(store_passphrase);
			store_passphrase = NULL;
			return (CYON_RESULT_ERROR);
		}
	}

	rnode = cyon_malloc(sizeof(struct node));
	if (!cyon_atomic_read(fd, rnode,
	    sizeof(struct node), CYON_ADD_CHECKSUM)) {
		close(fd);
		cyon_mem_free(rnode);
		return (CYON_RESULT_ERROR);
	}

	if (!cyon_store_mapnode(fd, rnode)) {
		close(fd);
		cyon_mem_free(rnode);
		return (CYON_RESULT_ERROR);
	}

	SHA256_Final(hash, &sha256ctx);

	if (!cyon_atomic_read(fd, ohash,
	    sizeof(ohash), CYON_NO_CHECKSUM)) {
		close(fd);
		cyon_mem_free(rnode);
		return (CYON_RESULT_ERROR);
	}

	close(fd);

	if (memcmp(hash, ohash, SHA256_DIGEST_LENGTH)) {
		cyon_debug("SHA256 checksum mismatch, store corrupted?");
		cyon_mem_free(rnode);
		return (CYON_RESULT_ERROR);
	}

	return (CYON_RESULT_OK);
}

static int
cyon_store_mapnode(int fd, struct node *p)
{
	int			r;
	struct node		*np;
	u_int32_t		rlen, i, offset;

	if (p->rbase > p->rtop) {
		cyon_debug("corruption in store detected");
		return (CYON_RESULT_ERROR);
	}

	p->region = NULL;
	if (!(p->flags & NODE_FLAG_HASDATA) && p->rbase == 0 && p->rtop == 0)
		return (CYON_RESULT_OK);

	if (p->flags & NODE_FLAG_HASDATA) {
		key_count++;

		if (!cyon_atomic_read(fd, &offset,
		    sizeof(u_int32_t), CYON_ADD_CHECKSUM))
			return (CYON_RESULT_ERROR);

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
		if (p->rbase != 0 && p->rtop != 0) {
			rlen = (p->rtop - p->rbase + 1) * sizeof(struct node);
			p->region = cyon_malloc(rlen);
			if (!cyon_atomic_read(fd,
			    p->region, rlen, CYON_ADD_CHECKSUM))
				return (CYON_RESULT_ERROR);
		}
	}

	if (p->rbase == 0 && p->rtop == 0)
		return (CYON_RESULT_OK);

	r = CYON_RESULT_OK;
	rlen = (p->rtop - p->rbase) + 1;
	for (i = 0; i < rlen; i++) {
		np = (struct node *)((u_int8_t *)p->region + offset +
		    (i * sizeof(struct node)));

		r = cyon_store_mapnode(fd, np);
		if (r == CYON_RESULT_ERROR)
			break;
	}

	return (r);
}

static int
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
		if (r == -1) {
			cyon_debug("write(%d): %d\n", len, errno);
			return (CYON_RESULT_ERROR);
		}

		written += r;
	}

	if (calc)
		SHA256_Update(&sha256ctx, buf, len);

	return (CYON_RESULT_OK);
}

static int
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
		if (r == -1 || r == 0) {
			cyon_debug("read(%d): %d\n", len, errno);
			return (CYON_RESULT_ERROR);
		}

		done += r;
	}

	if (calc)
		SHA256_Update(&sha256ctx, buf, len);

	return (CYON_RESULT_OK);
}

static struct node *
cyon_node_lookup(u_int8_t *key, u_int32_t len)
{
	u_int32_t	i;
	struct node	*p;
	u_int8_t	idx;
	u_int32_t	rlen;

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

	return (p);
}
