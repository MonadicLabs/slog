#ifndef GETLINE_H__
#define GETLINE_H__

/* The original code is public domain -- Will Hartung 4/9/09 */
/* Modifications, public domain as well, by Antti Haapala, 11/10/17 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>

intptr_t geetline(char **lineptr, size_t *n, FILE *stream);

#endif
