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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <pthread.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>

#include "cyon.h"

static unsigned long	thread_ssl_id(void);
static void		thread_ssl_lock(int, int, const char *, int);

pthread_key_t			thread;
static u_int16_t		t_offset;
static struct thread		*threads;
static pthread_mutex_t		*ssl_mutexes;

void
cyon_threads_init(void)
{
	int			r;
	u_int16_t		i;
	struct thread		*t;

	if ((r = pthread_key_create(&thread, NULL)))
		fatal("pthread_key_create() failed %d", r);

	ssl_mutexes = cyon_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&ssl_mutexes[i], NULL);

	CRYPTO_set_id_callback(thread_ssl_id);
	CRYPTO_set_locking_callback(thread_ssl_lock);

	t = threads = cyon_malloc(thread_count * sizeof(struct thread));
	for (i = 0; i < thread_count; i++) {
		t->id = i;
		t++->quit = 0;
	}

	t_offset = 0;
}

void
cyon_threads_start(void)
{
	u_int16_t		i;
	struct thread		*t;

	t = threads;
	for (i = 0; i < thread_count; i++) {
		pthread_create(&(t->tid), NULL, cyon_thread_entry, t);
		t++;
	}
}

struct thread *
cyon_thread_getnext(void)
{
	u_int8_t		*p;
	struct thread		*t;

	if (t_offset == thread_count)
		t_offset = 0;

	p = (u_int8_t *)threads + t_offset++ * sizeof(struct thread);
	t = (struct thread *)p;

	return (t);
}

void
cyon_threads_stop(void)
{
	int			r;
	u_int16_t		i;
	struct thread		*t;

	t = threads;
	for (i = 0; i < thread_count; i++) {
		/* XXX safe? */
		t->quit = 1;

		if ((r = pthread_join(t->tid, NULL))) {
			cyon_log(LOG_NOTICE,
			    "pthread_join() on %d returned %d",
			    t->id, r);
		}

		t++;
	}
}

void *
cyon_thread_entry(void *arg)
{
	int			r;
	u_int64_t		now, idle_check;
	struct thread		*t = (struct thread *)arg;

	if ((r = pthread_setspecific(thread, t)))
		fatal("pthread_setspecific(): %d", r);

	net_init(&(t->nctx));
	TAILQ_INIT(&(t->nctx.clients));

	cyon_store_thread_init();
	cyon_platform_event_init(&(t->nctx));

	idle_check = now = cyon_time_ms();
	while (t->quit == 0) {
		cyon_platform_event_wait(&(t->nctx));

		if (idle_timeout > 0 && (now - idle_check) >= 10000) {
			idle_check = now;
			cyon_connection_check_idletimer(now);
		}
	}

	cyon_connection_disconnect_all(t);
	pthread_exit(NULL);
}

static void
thread_ssl_lock(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&ssl_mutexes[n]);
	else
		pthread_mutex_unlock(&ssl_mutexes[n]);
}

static unsigned long
thread_ssl_id(void)
{
	return ((unsigned long)pthread_self());
}
