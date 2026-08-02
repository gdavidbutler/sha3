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

#ifndef SHA3256_H
#define SHA3256_H

#define SHA3256_SZ 32 /* 256 bits */
typedef struct sha3256 sha3256_t;
unsigned int sha3256tsize(void);
void sha3256init(sha3256_t *);
void sha3256update(sha3256_t *, const unsigned char *, unsigned int);
void sha3256final(sha3256_t *, unsigned char *); /* SHA3256_SZ */
void sha3256hmac(const unsigned char *k, unsigned int kl, const unsigned char *d, unsigned int dl, unsigned char *h); /* SHA3256_SZ */
void sha3256hkdf(const unsigned char *k, unsigned int kl, const unsigned char *d, unsigned int dl, unsigned char *o, unsigned int ol); /* up to 255 * SHA3256_SZ */
void sha3256hex(const unsigned char *, char *); /* SHA3256_SZ, 2 * SHA3256_SZ (not null-terminated) */

#endif /* SHA3256_H */
