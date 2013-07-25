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
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>

#define errno_s		strerror(errno)
#define ssl_errno_s	ERR_error_string(ERR_get_error(), NULL)

struct cyon_op {
	u_int8_t	op;
	u_int32_t	length;
};

int			cfd = -1;
SSL			*ssl = NULL;
SSL_CTX			*ssl_ctx = NULL;

u_int16_t		net_read16(u_int8_t *);
u_int32_t		net_read32(u_int8_t *);
void			net_write16(u_int8_t *, u_int16_t);
void			net_write32(u_int8_t *, u_int32_t);

void			cyon_connect(void);
void			cyon_ssl_init(void);
void			fatal(const char *, ...);
void			cyon_ssl_write(void *, u_int32_t);
void			cyon_ssl_read(void *, u_int32_t);
void			cyon_add(char *, char *);

int
main(int argc, char *argv[])
{
	cyon_connect();
	cyon_ssl_init();

	cyon_add("joris", "testing123");

	close(cfd);

	return (0);
}

void
cyon_add(char *key, char *d)
{
	struct cyon_op		op;
	u_int8_t		p[8];
	u_int32_t		klen, dlen, flen;

	klen = strlen(key);
	dlen = strlen(d);
	flen = sizeof(klen) + sizeof(dlen) + klen + dlen;

	op.op = 1;
	net_write32((u_int8_t *)&(op.length), flen);

	net_write32(&p[0], klen);
	net_write32(&p[4], dlen);

	cyon_ssl_write(&op, sizeof(op));
	cyon_ssl_write(p, sizeof(p));
	cyon_ssl_write(key, klen);
	cyon_ssl_write(d, dlen);
}

void
cyon_ssl_init(void)
{
	SSL_library_init();
	SSL_load_error_strings();

	ssl_ctx = SSL_CTX_new(SSLv3_method());
	if (ssl_ctx == NULL)
		fatal("cyon_ssl_init(): SSL_CTX_new(): %s", ssl_errno_s);

	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
	if ((ssl = SSL_new(ssl_ctx)) == NULL)
		fatal("SSL_new(): %s", ssl_errno_s);
	if (!SSL_set_fd(ssl, cfd))
		fatal("SSL_set_fd(): %s", ssl_errno_s);
	if (!SSL_connect(ssl))
		fatal("could not connect over SSL: %s", ssl_errno_s);
}

void
cyon_connect(void)
{
	struct sockaddr_in	sin;

	if ((cfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		fatal("socket(): %s", errno_s);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(3331);
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");

	if (connect(cfd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		fatal("connect(): %s", errno_s);

	printf("connected\n");
}

void
fatal(const char *fmt, ...)
{
	va_list		args;
	char		buf[512];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	printf("client: %s\n", buf);
	exit(1);
}

void
cyon_ssl_write(void *src, u_int32_t len)
{
	if (SSL_write(ssl, src, len) <= 0)
		fatal("SSL_write(): %s", ssl_errno_s);
}

void
cyon_ssl_read(void *dst, u_int32_t len)
{
	if (SSL_read(ssl, dst, len) <= 0)
		fatal("SSL_read(): %s", ssl_errno_s);
}

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
