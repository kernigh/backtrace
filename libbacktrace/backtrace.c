/* $backtrace$ */
/*
 * Copyright (c) 2010 Marco Peereboom <marco@conformal.com>
 * Copyright (c) 2010 Conformal Systems LLC <info@conformal.com>
 * Copyright (c) 2020 George Koehler <gkoehler@openbsd.org>
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

#ifndef __GNUC__
#error "this library must be compiled with gcc"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>

#include <dlfcn.h>

#include "backtrace.h"

__attribute__((unused)) static const char *cvstag = "$backtrace$";

#define BT_ADD_CR		(1)

/*
 * Output a line of the backtrace to either fd or memory.
 * If an error occurs, returns < 0.
 */
typedef int (*bt_out)(void *arg, const char *fmt, ...);

struct bt_fd
{
	int	f_fd;
};

static int
backtrace_out_fd(void *arg, const char *fmt, ...)
{
	struct bt_fd *box = arg;
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = vdprintf(box->f_fd, fmt, ap);
	va_end(ap);
	return rv;
}

struct bt_mem {
	char	*m_line[BT_MAX_DEPTH];
	size_t	 m_totalsz;
	int	 m_count;
};

static int
backtrace_out_mem(void *arg, const char *fmt, ...)
{
	struct bt_mem *mem = arg;
	va_list ap;
	int rv;
	char *line;

	va_start(ap, fmt);
	rv = vasprintf(&line, fmt, ap);
	va_end(ap);
	if (rv == -1)
		return -1;
	mem->m_totalsz += rv + 1;
	mem->m_line[mem->m_count++] = line;
	return rv;
}

static int
_backtrace_symbols(void *const *buffer, int depth, int add_cr, bt_out out,
    void *out_arg)
{
	struct bt_frame bt[BT_MAX_DEPTH];
	int i;
	char *cr, *s;

	if (buffer == NULL || depth <= 0)
		return -1;

	if (add_cr == BT_ADD_CR)
		cr = "\n";
	else
		cr = "";

	for (i = 0; i < depth; i++) {
		if (dladdr(buffer[i], &bt[i].bt_dlinfo) == 0) {
			/* try something */
			if ((*out)(out_arg, "%p%s",
			    buffer[i],
			    cr) < 0)
				return -1;
		} else {
			s = (char *)bt[i].bt_dlinfo.dli_sname;
			if (s == NULL)
				s = "???";
			if ((*out)(out_arg, "%p <%s+%ld> at %s%s",
			    buffer[i],
			    s,
			    buffer[i] - bt[i].bt_dlinfo.dli_saddr,
			    bt[i].bt_dlinfo.dli_fname,
			    cr) < 0)
				return -1;
		}
	}
	return 0;
}

char **
backtrace_symbols(void *const *buffer, int depth)
{
	struct bt_mem mem;
	size_t csz, sz, szleft;
	int i, x;
	char **rv = NULL, *current;

	mem.m_totalsz = 0;
	mem.m_count = 0;
	if (_backtrace_symbols(buffer, depth, 0, backtrace_out_mem,
	    &mem) == -1)
		goto unwind;

	/* adjust for array */
	sz = mem.m_totalsz + depth * sizeof(char *);

	rv = malloc(sz);
	if (rv == NULL)
		goto unwind;

	current = (char *)&rv[depth];
	for (x = 0; x < depth; x++) {
		rv[x] = current;
		szleft = sz - (current - (char *)rv);
		csz = strlcpy(current, mem.m_line[x], szleft);
		if (csz >= szleft) {
			free(rv);
			rv = NULL;
			goto unwind;
		}
		current += csz + 1;
	}
unwind:
	i = mem.m_count;
	while (--i >= 0)
		free(mem.m_line[i]);

	return (rv);
}

void
backtrace_symbols_fd(void *const *buffer, int depth, int fd)
{
	struct bt_fd box;

	box.f_fd = fd;
	_backtrace_symbols(buffer, depth, BT_ADD_CR, backtrace_out_fd, &box);
}
