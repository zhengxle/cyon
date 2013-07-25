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

#include <sys/epoll.h>
#include <sys/prctl.h>

#include <sched.h>

#include "cyon.h"

static int			efd = -1;
static u_int32_t		event_count = 0;
static struct epoll_event	*events = NULL;

void
cyon_platform_event_init(void)
{
	if ((efd = epoll_create(10000)) == -1)
		fatal("epoll_create(): %s", errno_s);

	event_count = 50;
	events = cyon_calloc(event_count, sizeof(struct epoll_event));
	cyon_platform_event_schedule(server.fd, EPOLLIN, 0, &server);
}

void
cyon_platform_event_wait(void)
{
	struct connection	*c;
	int			n, i, *fd;

	n = epoll_wait(efd, events, event_count, 100);
	if (n == -1) {
		if (errno == EINTR)
			return;
		fatal("epoll_wait(): %s", errno_s);
	}

	if (n > 0)
		cyon_debug("main(): %d sockets available", n);

	for (i = 0; i < n; i++) {
		fd = (int *)events[i].data.ptr;

		if (events[i].events & EPOLLERR ||
		    events[i].events & EPOLLHUP) {
			if (*fd == server.fd)
				fatal("error on server socket");

			c = (struct connection *)events[i].data.ptr;
			cyon_connection_disconnect(c);
			continue;
		}

		if (*fd == server.fd) {
			cyon_connection_accept(&server, &c);
			cyon_platform_event_schedule(c->fd,
			    EPOLLIN | EPOLLOUT | EPOLLET, 0, c);
		} else {
			c = (struct connection *)events[i].data.ptr;
			if (events[i].events & EPOLLIN)
				c->flags |= CONN_READ_POSSIBLE;
			if (events[i].events & EPOLLOUT)
				c->flags |= CONN_WRITE_POSSIBLE;

			if (!cyon_connection_handle(c))
				cyon_connection_disconnect(c);
		}
	}
}

void
cyon_platform_event_schedule(int fd, int type, int flags, void *udata)
{
	struct epoll_event	evt;

	evt.events = type;
	evt.data.ptr = udata;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &evt) == -1) {
		if (errno == EEXIST) {
			if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &evt) == -1)
				fatal("epoll_ctl() MOD: %s", errno_s);
		} else {
			fatal("epoll_ctl() ADD: %s", errno_s);
		}
	}
}
