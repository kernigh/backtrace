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

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "backtrace.h"

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
	char	**m_line;	/* array of lines */
	size_t	  m_totalsz;	/* size of all lines with '\0's */
	int	  m_count;	/* number of lines in array */
	int	  m_cap;	/* capacity of array */
};

static int
backtrace_out_mem(void *arg, const char *fmt, ...)
{
	struct bt_mem *mem = arg;
	va_list ap;
	size_t newcap;
	int rv;
	char *line, **newbuf;

	if (mem->m_count == mem->m_cap) {
		newcap = 2 * mem->m_cap;
		newbuf = reallocarray(mem->m_line, newcap,
		    sizeof(mem->m_line[0]));
		if (newbuf == NULL)
			return -1;
		mem->m_line = newbuf;
		mem->m_cap = newcap;
	}

	va_start(ap, fmt);
	rv = vasprintf(&line, fmt, ap);
	va_end(ap);
	if (rv == -1)
		return -1;
	mem->m_totalsz += rv + 1;
	mem->m_line[mem->m_count++] = line;
	return rv;
}

/*
 * We map an elf(5) object into memory to read its symbol table.  If
 * o_fname isn't NULL but o_mapping is NULL, then we failed to map
 * this object and find its symbol table.
 */
struct bt_object {
	const char	*o_fname;
	char		*o_mapping;
	const Elf_Sym	*o_symtab;
	const char	*o_strtab;
	Elf_Off		 o_size;
	Elf_Word	 o_symcount;
	Elf_Word	 o_strtabsz;
};

static void
backtrace_unmapobj(struct bt_object *obj)
{
	if (obj->o_mapping != NULL) {
		munmap(obj->o_mapping, obj->o_size);
		obj->o_mapping = NULL;
	}
}

static void
backtrace_mapobj(struct bt_object *obj, const char *fname)
{
	const Elf_Ehdr *ehdr;
	const Elf_Shdr *shdr, *strtabhdr, *symtabhdr;
	struct stat st;
	size_t sz;
	int fd, i;
	char *mapping;

	/* Remember that we tried to map this file. */
	obj->o_fname = fname;

	/*
	 * Open and mmap this object.  Unfortunately, if we have a
	 * relative path, and the program did chdir(2), then we won't
	 * open the correct object.
	 */
	if ((fd = open(fname, O_RDONLY|O_NONBLOCK)) == -1)
		return;
	if (fstat(fd, &st) == -1 ||
	    (sz = st.st_size) != st.st_size ||
	    sz < sizeof(ehdr)) {
		close(fd);
		return;
	}
	mapping = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (mapping == MAP_FAILED)
		return;

	ehdr = (Elf_Ehdr *)&mapping[0];
	if (!IS_ELF(*ehdr) ||
	    ehdr->e_machine != ELF_TARG_MACH ||
	    ehdr->e_shoff > sz ||
	    ehdr->e_shoff + ehdr->e_shnum * sizeof(shdr[0]) > sz) {
		munmap(mapping, sz);
		return;
	}

	/*
	 * Look for the symbol table, which is often almost the last
	 * section.  Skip section 0; it's SHT_NULL.
	 *
	 * e_shnum can be 0 in an object with more than about 60k
	 * sections.  We don't understand such objects.
	 */
	shdr = (Elf_Shdr *)&mapping[ehdr->e_shoff];
	symtabhdr = NULL;
	for (i = ehdr->e_shnum - 1; i >= 1; i--) {
		if (shdr[i].sh_type == SHT_SYMTAB) {
			symtabhdr = &shdr[i];
			break;
		}
	}
	if (symtabhdr == NULL ||
	    symtabhdr->sh_offset > sz ||
	    symtabhdr->sh_offset + symtabhdr->sh_size > sz) {
		munmap(mapping, sz);
		return;
	}

	/*
	 * The symbol table links to a string table, which
	 * must end with a '\0'.
	 */
	strtabhdr = &shdr[symtabhdr->sh_link];
	if (symtabhdr->sh_link >= ehdr->e_shnum ||
	    strtabhdr->sh_offset > sz ||
	    strtabhdr->sh_offset + strtabhdr->sh_size > sz ||
	    strtabhdr->sh_size == 0 ||
	    mapping[strtabhdr->sh_offset + strtabhdr->sh_size - 1]
	    != '\0') {
		munmap(mapping, sz);
		return;
	}

	/* This mapping looks good! */
	obj->o_mapping = mapping;
	obj->o_symtab = (Elf_Sym *)&mapping[symtabhdr->sh_offset];
	obj->o_strtab = &mapping[strtabhdr->sh_offset];
	obj->o_size = sz;
	obj->o_symcount = symtabhdr->sh_size /
	    sizeof(obj->o_symtab[0]);
	obj->o_strtabsz = strtabhdr->sh_size;
}

/*
 * Check the symbol table of the mapped object for a better symbol.
 * The info from dlsym(3) refers to an exported symbol, but our addr
 * might point into a function that wasn't exported.  (For example,
 * main executables tend not to export their functions.)
 *
 * Change info->dli_saddr and info->dli_sname to refer to the better
 * symbol if we find one.  If so, info->dli_sname will point into the
 * mapped object.
 */
static void
backtrace_cksymtab(struct bt_object *obj, Elf_Addr addr, Dl_info *info)
{
	const Elf_Sym *s;
	Elf_Addr base, bestv, v;
	Elf_Word i;
	const char *bestn, *fname;

	/* Keep our old mapping unless the fname pointer changed. */
	if ((fname = info->dli_fname) != obj->o_fname) {
		backtrace_unmapobj(obj);
		backtrace_mapobj(obj, fname);
	}

	/* If we failed to map this object, do nothing. */
	if (obj->o_mapping == NULL)
		return;

	/* Find the best symbol <= addr. */
	base = (Elf_Addr)info->dli_fbase;
	bestv = (Elf_Addr)info->dli_saddr;
	bestn = info->dli_sname;
	for (i = 0; i < obj->o_symcount; i++) {
		s = &obj->o_symtab[i];
		v = base + s->st_value;
		if (bestv < v && v <= addr) {
			bestv = v;
			if (s->st_name < obj->o_strtabsz)
				bestn = &obj->o_strtab[s->st_name];
			else
				bestn = "???";
		}
	}
	info->dli_saddr = (void *)bestv;
	info->dli_sname = bestn;
}

static int
_backtrace_symbols(void *const *buffer, int depth, int add_cr, bt_out out,
    void *out_arg)
{
	struct bt_object obj;
	Dl_info info;
	int i;
	char *cr, *s;

	if (buffer == NULL || depth <= 0)
		return -1;

	if (add_cr == BT_ADD_CR)
		cr = "\n";
	else
		cr = "";

	obj.o_fname = NULL;
	obj.o_mapping = NULL;

	for (i = 0; i < depth; i++) {
		if (dladdr(buffer[i], &info) == 0) {
			/* try something */
			if ((*out)(out_arg, "%p%s",
			    buffer[i],
			    cr) < 0) {
				backtrace_unmapobj(&obj);
				return -1;
			}
		} else {
			backtrace_cksymtab(&obj, (Elf_Addr)buffer[i],
			    &info);
			s = (char *)info.dli_sname;
			if (s == NULL)
				s = "???";
			if ((*out)(out_arg, "%p <%s+%ld> at %s%s",
			    buffer[i],
			    s,
			    buffer[i] - info.dli_saddr,
			    info.dli_fname,
			    cr) < 0) {
				backtrace_unmapobj(&obj);
				return -1;
			}
		}
	}
	backtrace_unmapobj(&obj);
	return 0;
}

char **
backtrace_symbols(void *const *buffer, int depth)
{
	struct bt_mem mem;
	size_t csz, sz, szleft;
	int i, x;
	char **rv = NULL, *current;

	mem.m_cap = 32;
	mem.m_line = reallocarray(NULL, mem.m_cap, sizeof(mem.m_line[0]));
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
