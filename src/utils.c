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

#include <unistd.h>

#include "cyon.h"

void
cyon_debug_internal(char *file, int line, const char *fmt, ...)
{
	va_list		args;
	char		buf[2048];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	printf("%s:%d - %s\n", file, line, buf);
}

void
cyon_strlcpy(char *dst, const char *src, size_t len)
{
	char		*d = dst;
	const char	*s = src;

	while ((*d++ = *s++) != '\0') {
		if (d == (dst + len - 1)) {
			*d = '\0';
			break;
		}
	}
}

u_int64_t
cyon_time_ms(void)
{
	struct timeval		tv;

	if (gettimeofday(&tv, NULL) == -1)
		return (0);

	return (tv.tv_sec * 1000 + (tv.tv_usec / 1000));
}

void
fatal(const char *fmt, ...)
{
	va_list		args;
	char		buf[2048];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	printf("cyon: %s\n", buf);
	exit(1);
}

