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

#include <pthread.h>

#include "cyon.h"
#include "shared.h"

u_int16_t
net_read16(u_int8_t *b)
{
	u_int16_t	r;

	r = *(u_int16_t *)b;
	return (ntohs(r));
}

u_int32_t
net_read32(u_int8_t *b)
{
	u_int32_t	r;

	r = *(u_int32_t *)b;
	return (ntohl(r));
}

void
net_write16(u_int8_t *p, u_int16_t n)
{
	u_int16_t	r;

	r = htons(n);
	memcpy(p, &r, sizeof(r));
}

void
net_write32(u_int8_t *p, u_int32_t n)
{
	u_int32_t	r;

	r = htonl(n);
	memcpy(p, &r, sizeof(r));
}

void
fatal(const char *fmt, ...)
{
	va_list			args;
	char			buf[2048];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

#if defined(CYON_SERVER)
	/*
	 * Ifs we fatals we fatals, bring down entire server even
	 * if the fatal was caused by a thread.
	 */
	cyon_log(LOG_ALERT, "fatal: %s", buf);
	if (!server_started)
		printf("cyon-server: %s\n", buf);
#else
	printf("cyon: %s\n", buf);
#endif

	exit(1);
}

