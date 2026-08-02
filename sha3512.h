/*
 * sha3 - a small SHA3-256 / SHA3-512 implementation
 * Copyright (C) 2026 G. David Butler <gdb@dbSystems.com>
 *
 * This file is part of sha3
 *
 * sha3 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * sha3 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SHA3512_H
#define SHA3512_H

#define SHA3512_SZ 64 /* 512 bits */
typedef struct sha3512 sha3512_t;
unsigned int sha3512tsize(void);
void sha3512init(sha3512_t *);
void sha3512update(sha3512_t *, const unsigned char *, unsigned int);
void sha3512final(sha3512_t *, unsigned char *); /* SHA3512_SZ */
void sha3512hmac(const unsigned char *k, unsigned int kl, const unsigned char *d, unsigned int dl, unsigned char *h); /* SHA3512_SZ */
void sha3512hkdf(const unsigned char *k, unsigned int kl, const unsigned char *d, unsigned int dl, unsigned char *o, unsigned int ol); /* up to 255 * SHA3512_SZ */
void sha3512hex(const unsigned char *, char *); /* SHA3512_SZ, 2 * SHA3512_SZ (not null-terminated) */

#endif /* SHA3512_H */
