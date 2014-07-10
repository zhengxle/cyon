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

#define EVENT_COUNT	50

void
cyon_platform_event_init(struct netcontext *nctx)
{
	if ((nctx->efd = epoll_create(10000)) == -1)
		fatal("epoll_create(): %s", errno_s);

	nctx->events = cyon_calloc(EVENT_COUNT, sizeof(struct epoll_event));
}

void
cyon_platform_event_wait(struct netcontext *nctx)
{
	struct connection	*c;
	struct listener		*l;
	int			n, i, type;

	n = epoll_wait(nctx->efd, nctx->events, EVENT_COUNT, 100);
	if (n == -1) {
		if (errno == EINTR)
			return;
		fatal("epoll_wait(): %s", errno_s);
	}

	if (n > 0)
		cyon_debug("%d sockets available", n);

	for (i = 0; i < n; i++) {
		type = *(int *)nctx->events[i].data.ptr;

		if (nctx->events[i].events & EPOLLERR ||
		    nctx->events[i].events & EPOLLHUP) {
			if (type != EVENT_TYPE_CONNECTION)
				fatal("error on server socket");

			c = (struct connection *)nctx->events[i].data.ptr;
			cyon_connection_disconnect(c);
			continue;
		}

		if (type != EVENT_TYPE_CONNECTION) {
			l = (struct listener *)nctx->events[i].data.ptr;
			cyon_connection_accept(l);
		} else {
			c = (struct connection *)nctx->events[i].data.ptr;
			if (nctx->events[i].events & EPOLLIN)
				c->flags |= CONN_READ_POSSIBLE;
			if (nctx->events[i].events & EPOLLOUT)
				c->flags |= CONN_WRITE_POSSIBLE;

			if (!cyon_connection_handle(c))
				cyon_connection_disconnect(c);
		}
	}
}

void
cyon_platform_event_schedule(struct netcontext *nctx, int fd, int type,
    int flags, void *udata)
{
	struct epoll_event	evt;

	evt.events = type;
	evt.data.ptr = udata;
	if (epoll_ctl(nctx->efd, EPOLL_CTL_ADD, fd, &evt) == -1) {
		if (errno == EEXIST) {
			if (epoll_ctl(nctx->efd, EPOLL_CTL_MOD, fd, &evt) == -1)
				fatal("epoll_ctl() MOD: %s", errno_s);
		} else {
			fatal("epoll_ctl() ADD: %s", errno_s);
		}
	}
}
