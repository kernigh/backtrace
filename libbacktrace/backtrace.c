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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>

#include <dlfcn.h>

#include "backtrace.h"

__attribute__((unused)) static const char *cvstag = "$backtrace$";

#define BT_ADD_CR		(1)

char **
_backtrace_symbols(void *const *buffer, int depth, int add_cr)
{
	struct bt_frame		bt[BT_MAX_DEPTH];
	char			*line[BT_MAX_DEPTH];
	int			i, x;
	char			**rv = NULL, *current;
	char			*cr, *s;
	size_t			sz, csz;

	if (buffer == NULL || depth <= 0)
		return (NULL);

	if (add_cr == BT_ADD_CR)
		cr = "\n";
	else
		cr = "";

	for (i = 0, sz = 0; i < depth; i++) {
		if (dladdr(buffer[i], &bt[i].bt_dlinfo) == 0) {
			/* try something */
			if (asprintf(&line[i], "%p%s",
			    buffer[i],
			    cr) == -1)
				goto unwind;
		} else {
			s = (char *)bt[i].bt_dlinfo.dli_sname;
			if (s == NULL)
				s = "???";
			if (asprintf(&line[i], "%p <%s+%ld> at %s%s",
			    buffer[i],
			    s,
			    buffer[i] - bt[i].bt_dlinfo.dli_saddr,
			    bt[i].bt_dlinfo.dli_fname,
			    cr) == -1)
				goto unwind;
		}
		sz += strlen(line[i]) + 1;
	}

	/* adjust for array */
	sz += depth * sizeof(char *);

	rv = malloc(sz);
	if (rv == NULL)
		goto unwind;

	current = (char *)&rv[depth];
	for (x = 0; x < depth; x++) {
		rv[x] = current;
		csz = strlcpy(current, line[x], sz - (current - (char *)rv));
		if (csz >= sz) {
			free(rv);
			rv = NULL;
			goto unwind;
		}
		current += csz + 1;
	}
unwind:
	while (--i >= 0)
		free(line[i]);

	return (rv);
}

char **
backtrace_symbols(void *const *buffer, int depth)
{
	return (_backtrace_symbols(buffer, depth, 0));
}

void
backtrace_symbols_fd(void *const *buffer, int depth, int fd)
{
	char			**strings;
	size_t			sz;
	int			i;

	strings = _backtrace_symbols(buffer, depth, BT_ADD_CR);
	if (strings == NULL)
		return;

	for (i = 0; i < depth; i++) {
		sz = strlen(strings[i]);
		if (write(fd, strings[i], sz) == -1)
			return;
	}

	free(strings);
}
