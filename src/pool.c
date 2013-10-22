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

#include <sys/queue.h>

#include "cyon.h"

#define POOL_ELEMENT_BUSY		0
#define POOL_ELEMENT_FREE		1

static void		pool_region_create(struct pool *, u_int32_t);

void
pool_init(struct pool *pool, char *name, u_int32_t len, u_int32_t elm)
{
	pool->elms = 0;
	pool->inuse = 0;
	pool->elen = len;
	pool->name = cyon_strdup(name);
	pool->slen = pool->elen + sizeof(struct pool_entry);

	LIST_INIT(&(pool->regions));
	LIST_INIT(&(pool->freelist));

	pool_region_create(pool, elm);
}

void *
pool_get(struct pool *pool)
{
	u_int8_t			*ptr;
	struct pool_entry		*entry;

	if (LIST_EMPTY(&(pool->freelist))) {
		cyon_log(LOG_NOTICE, "pool %s is exhausted (%d/%d)",
		    pool->name, pool->inuse, pool->elms);

		pool_region_create(pool, pool->elms);
	}

	entry = LIST_FIRST(&(pool->freelist));
	if (entry->state != POOL_ELEMENT_FREE)
		fatal("%s: element %p was not free", pool->name, entry);
	LIST_REMOVE(entry, list);

	entry->state = POOL_ELEMENT_BUSY;
	ptr = (u_int8_t *)entry + sizeof(struct pool_entry);

	pool->inuse++;

	return (ptr);
}

void
pool_put(struct pool *pool, void *ptr)
{
	struct pool_entry		*entry;

	entry = (struct pool_entry *)
	    ((u_int8_t *)ptr - sizeof(struct pool_entry));

	if (entry->state != POOL_ELEMENT_BUSY)
		fatal("%s: element %p was not busy", pool->name, ptr);

	entry->state = POOL_ELEMENT_FREE;
	LIST_INSERT_HEAD(&(pool->freelist), entry, list);

	pool->inuse--;
}

static void
pool_region_create(struct pool *pool, u_int32_t elms)
{
	u_int32_t			i;
	u_int8_t			*p;
	struct pool_region		*reg;
	struct pool_entry		*entry;

	reg = cyon_malloc(sizeof(struct pool_region));
	LIST_INSERT_HEAD(&(pool->regions), reg, list);

	reg->start = cyon_malloc(elms * pool->slen);
	p = (u_int8_t *)reg->start;

	for (i = 0; i < elms; i++) {
		entry = (struct pool_entry *)p;
		entry->region = reg;
		entry->state = POOL_ELEMENT_FREE;
		LIST_INSERT_HEAD(&(pool->freelist), entry, list);

		p = p + pool->slen;
	}

	pool->elms += elms;
}
