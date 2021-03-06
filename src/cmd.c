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

#include <sys/socket.h>
#include <sys/stat.h>

#include <openssl/sha.h>

#include <endian.h>
#include <inttypes.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "cyon.h"
#include "shared.h"

void		usage(void);
void		cyon_connect(void);
void		cyon_ssl_init(void);

void		cyon_disconnect(void);
void		fatal(const char *, ...);

void		cyon_write(void *, u_int32_t);
void		cyon_read(void *, u_int32_t);

int		cyon_del(u_int8_t, u_int8_t *, u_int32_t, u_int32_t);
int		cyon_get(u_int8_t, u_int8_t *, u_int32_t, u_int8_t **,
		    u_int32_t *);
int		cyon_upload(u_int8_t, u_int8_t *,
		    u_int32_t, u_int8_t *, u_int32_t);

void		cyon_cli_upload(u_int8_t, char **);
void		cyon_cli_get(u_int8_t, char **);
void		cyon_cli_del(u_int8_t, char **);
void		cyon_cli_stats(u_int8_t, char **);
void		cyon_cli_write(u_int8_t, char **);
void		cyon_cli_setauth(u_int8_t, char **);
void		cyon_cli_replay(u_int8_t, char **);
void		cyon_cli_stress(u_int8_t, char **);

int		cfd = -1;
char		*host = NULL;
SSL		*ssl = NULL;
SSL_CTX		*ssl_ctx = NULL;
char		*unixpath = NULL;

struct {
	char		*cmd;
	void		(*cb)(u_int8_t, char **);
} cmds[] = {
	{ "put",		cyon_cli_upload },
	{ "get",		cyon_cli_get },
	{ "del",		cyon_cli_del },
	{ "write",		cyon_cli_write },
	{ "stats",		cyon_cli_stats },
	{ "set-auth",		cyon_cli_setauth },
	{ "replace",		cyon_cli_upload },
	{ "replay",		cyon_cli_replay },
	{ "stress",		cyon_cli_stress },
	{ NULL,		NULL },
};

void
usage(void)
{
	int			i;
	extern const char	*__progname;

	fprintf(stderr, "Usage: %s [-s host] [-u socket] [cmd]\n", __progname);
	fprintf(stderr, "Available commands:\n");
	for (i = 0; cmds[i].cmd != NULL; i++)
		printf("\t%s\n", cmds[i].cmd);

	exit(1);
}

int
main(int argc, char *argv[])
{
	int			r;
	char			*input;
	struct cyon_op		*op, ret;
	size_t			len, slen;
	u_int8_t		i, authpwd, *p;

	authpwd = 0;
	while ((r = getopt(argc, argv, "ps:u:")) != -1) {
		switch (r) {
		case 'p':
			authpwd = 1;
			break;
		case 's':
			host = optarg;
			break;
		case 'u':
			unixpath = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (host != NULL && unixpath != NULL)
		fatal("-s and -u are mutually exclusive");

	if ((host == NULL && unixpath == NULL) || argv[0] == NULL)
		usage();

	cyon_connect();

	if (authpwd) {
		if ((input = getpass("passphrase: ")) == NULL)
			fatal("could not read passphrase");

		slen = strlen(input);
		len = sizeof(struct cyon_op) + slen;
		if ((p = malloc(len)) == NULL)
			fatal("malloc(): %s", errno_s);

		op = (struct cyon_op *)p;
		op->op = CYON_OP_AUTH;
		net_write32((u_int8_t *)&(op->length), slen);
		memcpy(p + sizeof(struct cyon_op), input, slen);
		memset(input, '\0', slen);

		cyon_write(p, len);
		free(p);

		cyon_read(&ret, sizeof(struct cyon_op));
		if (ret.op != CYON_OP_RESULT_OK)
			fatal("access denied");
	}

	for (i = 0; cmds[i].cmd != NULL; i++) {
		if (strcmp(cmds[i].cmd, argv[0]))
			continue;
		cmds[i].cb(argc, argv);
	}

	cyon_disconnect();

	return (0);
}

void
cyon_ssl_init(void)
{
	u_int32_t	len;
	X509		*cert;
	u_char		fp[EVP_MAX_MD_SIZE];

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

	if ((cert = SSL_get_peer_certificate(ssl)) == NULL)
		fatal("no peer certificate received? %s", ssl_errno_s);
	if (X509_digest(cert, EVP_sha1(), fp, &len) < 0)
		fatal("could not read fingerprint: %s", ssl_errno_s);
}

void
cyon_connect(void)
{
	struct sockaddr_un	sun;
	struct sockaddr		*sin;
	char			*port;
	socklen_t		sinlen;
	int			r, type, l;
	struct addrinfo		*res, *results;

	if (host != NULL) {
		if ((port = strchr(host, ':')) != NULL)
			*(port)++ = '\0';
		else
			port = "3331";

		r = getaddrinfo(host, port, NULL, &results);
		if (r != 0)
			fatal("%s", gai_strerror(r));

		for (res = results; res != NULL; res = res->ai_next) {
			if (res->ai_family == AF_INET &&
			    res->ai_socktype == SOCK_STREAM)
				break;
		}

		if (res == NULL)
			fatal("No useable address found for %s", host);

		type = AF_INET;
		sin = res->ai_addr;
		sinlen = res->ai_addrlen;
	} else {
		type = AF_UNIX;
		sin = (struct sockaddr *)&sun;
		sinlen = sizeof(sun);

		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_UNIX;
		l = snprintf(sun.sun_path, sizeof(sun.sun_path),"%s", unixpath);
		if (l == -1 || (size_t)l >= sizeof(sun.sun_path))
			fatal("path too long");
	}

	if ((cfd = socket(type, SOCK_STREAM, 0)) == -1)
		fatal("socket(): %s", errno_s);

	if (connect(cfd, sin, sinlen) == -1)
		fatal("connect(): %s", errno_s);

	if (host != NULL) {
		freeaddrinfo(results);
		cyon_ssl_init();
	}
}

void
cyon_disconnect(void)
{
	if (host != NULL)
		SSL_shutdown(ssl);
	close(cfd);
}

void
cyon_write(void *src, u_int32_t len)
{
	if (host != NULL) {
		if (SSL_write(ssl, src, len) <= 0)
			fatal("SSL_write(): %s", ssl_errno_s);
	} else {
		if (write(cfd, src, len) <= 0)
			fatal("write(): %s", errno_s);
	}
}

void
cyon_read(void *dst, u_int32_t len)
{
	int		r;
	u_int32_t	off;
	u_int8_t	*b = (u_int8_t *)dst;

	r = 0;
	off = 0;

	while (off != len) {
		if (host != NULL) {
			r = SSL_read(ssl, b + off, len - off);
			if (r <= 0)
				fatal("SSL_read(): %s", ssl_errno_s);
		} else {
			r = read(cfd, b + off, len - off);
			if (r <= 0)
				fatal("read(): %s", errno_s);
		}

		off += r;
	}
}

int
cyon_upload(u_int8_t id, u_int8_t *key, u_int32_t klen,
    u_int8_t *d, u_int32_t dlen)
{
	u_int8_t		*p;
	struct cyon_op		*op, ret;
	u_int32_t		len, flen, off;

	flen = sizeof(klen) + sizeof(dlen) + klen + dlen;
	len = flen + sizeof(struct cyon_op);

	if ((p = malloc(len)) == NULL)
		fatal("malloc(): %s", errno_s);

	op = (struct cyon_op *)p;
	op->op = id;
	net_write32((u_int8_t *)&(op->length), flen);

	off = sizeof(struct cyon_op);
	net_write32(&p[off], klen);
	net_write32(&p[off + 4], dlen);
	memcpy(&p[off + 8], key, klen);
	memcpy(&p[off + 8 + klen], d, dlen);

	cyon_write(p, len);
	free(p);

	memset(&ret, 0, sizeof(ret));
	cyon_read(&ret, sizeof(ret));
	if (ret.op == CYON_OP_RESULT_OK)
		return (1);

	return (0);
}

int
cyon_get(u_int8_t type, u_int8_t *key, u_int32_t klen, u_int8_t **out,
    u_int32_t *dlen) 
{
	u_int8_t		*p;
	struct cyon_op		*op, ret;
	u_int32_t		plen, off;

	plen = klen;
	if ((p = malloc(plen + sizeof(struct cyon_op))) == NULL)
		fatal("malloc(): %s", errno_s);

	op = (struct cyon_op *)p;
	op->op = type;
	net_write32((u_int8_t *)&(op->length), plen);

	off = sizeof(struct cyon_op);
	memcpy(&p[off], key, klen);
	cyon_write(p, plen + sizeof(struct cyon_op));
	free(p);

	*dlen = 0;
	*out = NULL;

	memset(&ret, 0, sizeof(ret));
	cyon_read(&ret, sizeof(ret));
	if (ret.op == CYON_OP_RESULT_OK) {
		*dlen = net_read32((u_int8_t *)&(ret.length));
		if ((*out = malloc(*dlen)) == NULL)
			fatal("malloc(): %s", errno_s);
		cyon_read(*out, *dlen);
	} else if (ret.op != CYON_OP_RESULT_ERROR) {
		fatal("Unexpected result from server: %d", ret.op);
	}

	return (*out != NULL);
}

int
cyon_del(u_int8_t type, u_int8_t *key, u_int32_t klen, u_int32_t offset)
{
	u_int8_t		*p;
	struct cyon_op		*op, ret;
	u_int32_t		plen, off;

	plen = klen;
	if ((p = malloc(plen + sizeof(struct cyon_op))) == NULL)
		fatal("malloc(): %s", errno_s);

	op = (struct cyon_op *)p;
	op->op = type;
	net_write32((u_int8_t *)&(op->length), plen);

	off = sizeof(struct cyon_op);
	memcpy(&p[off], key, klen);

	cyon_write(p, plen + sizeof(struct cyon_op));
	free(p);

	memset(&ret, 0, sizeof(ret));
	cyon_read(&ret, sizeof(ret));

	if (ret.op != CYON_OP_RESULT_OK && ret.op != CYON_OP_RESULT_ERROR)
		fatal("Unexpected result from server: %d", ret.op);

	return (ret.op == CYON_OP_RESULT_OK);
}

void
cyon_cli_upload(u_int8_t argc, char **argv)
{
	ssize_t		r;
	int		fd;
	struct stat	st;
	off_t		size;
	u_int8_t	*d, id;

	if (!strcmp(argv[0], "put")) {
		id = CYON_OP_PUT;
	} else if (!strcmp(argv[0], "replace")) {
		id = CYON_OP_REPLACE;
	} else {
		fatal("invalid request: %s", argv[0]);
	}

	if (argc != 3)
		fatal("%s [key] [infile]", argv[0]);

	if ((fd = open(argv[2], O_RDONLY)) == -1)
		fatal("could not open '%s': %s", argv[2], errno_s);

	if (fstat(fd, &st) == -1)
		fatal("fstat() failed: %s", errno_s);

	size = st.st_size;
	if ((d = malloc(size)) == NULL)
		fatal("malloc(): failed: %s", errno_s);

	r = read(fd, d, size);
	if (r != size)
		fatal("could not read from '%s'", argv[2]);

	if (cyon_upload(id, (u_int8_t *)argv[1], strlen(argv[1]), d, size))
		printf("OK.\n");
	else
		fatal("The key was not added successfully");

	free(d);
	close(fd);
}

void
cyon_cli_get(u_int8_t argc, char **argv)
{
	ssize_t		r;
	int		fd;
	u_int32_t	dlen;
	u_int8_t	*data, type;

	type = CYON_OP_GET;

	if (cyon_get(type, (u_int8_t *)argv[1],
	    strlen(argv[1]), &data, &dlen)) {
		printf("Received %d bytes of data\n", dlen);

		fd = open(argv[2], O_CREAT | O_TRUNC | O_WRONLY, 0700);
		if (fd == -1)
			fatal("open(%s): %s", argv[2], errno_s);

		r = write(fd, data, dlen);
		close(fd);
		free(data);

		if (r != (ssize_t)dlen)
			fatal("Error while writing to '%s'", argv[2]);
		else
			printf("Data stored in '%s'\n", argv[2]);
	} else {
		fatal("The server did not return a result");
	}
}

void
cyon_cli_del(u_int8_t argc, char **argv)
{
	if (argc != 2)
		fatal("del [key]");

	if (cyon_del(CYON_OP_DEL, (u_int8_t *)argv[1], strlen(argv[1]), 0))
		printf("%s was successfully deleted\n", argv[1]);
	else
		fatal("Error occured while deleting %s", argv[1]);
}

void
cyon_cli_write(u_int8_t argc, char **argv)
{
	struct cyon_op		op;

	op.op = CYON_OP_WRITE;
	net_write32((u_int8_t *)&(op.length), 0);
	cyon_write(&op, sizeof(op));

	memset(&op, 0, sizeof(op));
	cyon_read(&op, sizeof(op));
	if (op.op == CYON_OP_RESULT_OK)
		printf("Ok starting a write, check logs for result\n");
	else
		fatal("Unexpected result from store write");
}

void
cyon_cli_stats(u_int8_t argc, char **argv)
{
	struct cyon_op		op;
	u_int32_t		len;
	struct cyon_stats	stats;

	op.op = CYON_OP_STATS;
	net_write32((u_int8_t *)&(op.length), 0);
	cyon_write(&op, sizeof(op));

	memset(&op, 0, sizeof(op));
	cyon_read(&op, sizeof(op));
	len = net_read32((u_int8_t *)&(op.length));
	if (op.op != CYON_OP_RESULT_OK || len != sizeof(struct cyon_stats))
		fatal("Received unexpected result from server");

	cyon_read(&stats, sizeof(stats));
	stats.keycount = be64toh(stats.keycount);

	printf("Keys in store:    %" PRIu64 " keys\n", stats.keycount);
	printf("Current state:    %s %s\n", stats.state,
	    (stats.modified) ? "[*]" : "");
}

void
cyon_cli_setauth(u_int8_t argc, char **argv)
{
	u_int8_t		*p;
	u_int32_t		len;
	struct cyon_op		*op, ret;
	SHA256_CTX		sha256ctx;

	if (argc != 2)
		fatal("Usage: set-auth [passphrase]");

	len = sizeof(struct cyon_op) + SHA256_DIGEST_LENGTH;
	if ((p = malloc(len)) == NULL)
		fatal("malloc(): %s", errno_s);

	op = (struct cyon_op *)p;
	op->op = CYON_OP_SETAUTH;
	net_write32((u_int8_t *)&(op->length), SHA256_DIGEST_LENGTH);

	SHA256_Init(&sha256ctx);
	SHA256_Update(&sha256ctx, argv[1], strlen(argv[1]));
	SHA256_Final((u_char *)p + sizeof(struct cyon_op), &sha256ctx);

	cyon_write(p, len);
	free(p);

	memset(&ret, 0, sizeof(ret));
	cyon_read(&ret, sizeof(struct cyon_op));
	if (ret.op == CYON_OP_RESULT_OK)
		printf("Passphrase was successfully set\n");
	else
		fatal("Error while setting the passphrase");
}

void
cyon_cli_replay(u_int8_t argc, char **argv)
{
	u_int8_t		*p;
	u_int32_t		len;
	struct cyon_op		*op, ret;

	if (argc != 2)
		fatal("Usage: replay [state]");

	len = sizeof(struct cyon_op) + SHA_DIGEST_STRING_LEN;
	if ((p = malloc(len)) == NULL)
		fatal("malloc(): %s", errno_s);

	op = (struct cyon_op *)p;
	op->op = CYON_OP_REPLAY;
	net_write32((u_int8_t *)&(op->length), SHA_DIGEST_STRING_LEN);
	memcpy(p + sizeof(struct cyon_op), argv[1], strlen(argv[1]));

	cyon_write(p, len);
	free(p);

	memset(&ret, 0, sizeof(ret));
	cyon_read(&ret, sizeof(struct cyon_op));
	if (ret.op == CYON_OP_RESULT_OK)
		printf("The log was applied successfully, see messages\n");
	else
		fatal("Error while applying the log, see messages");
}

void
cyon_cli_stress(u_int8_t argc, char **argv)
{
	int		i, kps;
	char		key[17];
	time_t		now, last;

	time(&now);
	last = now;

	for (i = 0; i < 1000000; i++) {
		time(&now);
		if (now - last > 1) {
			last = now;
			printf("%d kps\n", kps);
			kps = 0;
		}

		snprintf(key, sizeof(key), "%16d", i);
		if (!cyon_upload(CYON_OP_PUT, (u_int8_t *)key,
		    16, (u_int8_t *)"mydata", 6))
			fatal("borked");

		kps++;
	}
}
