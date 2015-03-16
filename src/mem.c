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

#include <stdlib.h>

#include "cyon.h"
#include "shared.h"

#define CYON_MEM_MAGIC		0xd0d0
#define CYON_MEMSIZE(x)		\
	(*(u_int32_t *)((u_int8_t *)x - sizeof(u_int32_t)))
#define CYON_MEMINFO(x)		\
	(struct meminfo *)((u_int8_t *)x + CYON_MEMSIZE(x))

struct meminfo {
	u_int16_t		magic;
} __attribute__((__packed__));

void
cyon_mem_init(void)
{
}

void *
cyon_malloc(size_t len)
{
	size_t			mlen;
	void			*ptr;
	struct meminfo		*mem;
	u_int8_t		*addr;
	u_int32_t		*plen;

	mlen = sizeof(u_int32_t) + len + sizeof(struct meminfo);
	if ((ptr = malloc(mlen)) == NULL)
		fatal("cyon_malloc(%d): %d", len, errno);

	plen = (u_int32_t *)ptr;
	*plen = len;
	addr = (u_int8_t *)ptr + sizeof(u_int32_t);

	mem = CYON_MEMINFO(addr);
	mem->magic = CYON_MEM_MAGIC;

	return (addr);
}

void *
cyon_realloc(void *ptr, size_t len)
{
	struct meminfo		*mem;
	void			*nptr;

	if (ptr == NULL) {
		nptr = cyon_malloc(len);
	} else {
		mem = CYON_MEMINFO(ptr);
		if (mem->magic != CYON_MEM_MAGIC)
			fatal("cyon_realloc(): magic boundary not found");

		nptr = cyon_malloc(len);
		memcpy(nptr, ptr, MIN(len, CYON_MEMSIZE(ptr)));
		cyon_mem_free(ptr);
	}

	return (nptr);
}

void *
cyon_calloc(size_t memb, size_t len)
{
	return (cyon_malloc(memb * len));
}

void
cyon_mem_free(void *ptr)
{
	u_int8_t	*addr;
	struct meminfo	*mem;

	mem = CYON_MEMINFO(ptr);
	if (mem->magic != CYON_MEM_MAGIC)
		fatal("cyon_mem_free(): magic boundary not found");

	addr = (u_int8_t *)ptr - sizeof(u_int32_t);
	free(addr);
}

char *
cyon_strdup(const char *str)
{
	size_t		len;
	char		*nstr;

	len = strlen(str) + 1;
	nstr = cyon_malloc(len);
	cyon_strlcpy(nstr, str, len);

	return (nstr);
}
