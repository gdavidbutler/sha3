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

#include "sha3512.h"

#define SHA3512_RT 72 /* rate: (1600 - 2 * 512) / 8, also the HMAC block */

typedef unsigned int sha3512_bt; /* unsigned 32 bits */
typedef int sha3512_bt_size_check[sizeof (sha3512_bt) == 4 ? 1 : -1];
typedef struct {
  sha3512_bt h; /* lane bits 32..63 */
  sha3512_bt l; /* lane bits 0..31 */
} sha3512_lt;
struct sha3512 {
  sha3512_lt a[25];             /* sponge state, 5 by 5 lanes of 64 bits */
  unsigned int l;               /* current short data */
  unsigned char d[SHA3512_RT];  /* short data */
};

/* d = s, d = x ^ y, d = x ^ (~y & z) */
#define LCP(d,s)     ((d).h = (s).h, (d).l = (s).l)
#define LXR(d,x,y)   ((d).h = (x).h ^ (y).h, (d).l = (x).l ^ (y).l)
#define LCH(d,x,y,z) ((d).h = (x).h ^ (~(y).h & (z).h) \
                     ,(d).l = (x).l ^ (~(y).l & (z).l))
/*
 * d = s rotated left n, for 1 <= n <= 63 and n != 32; d must not alias s.
 * n is a literal at every call site, so the arm not taken folds away; the
 * shift counts are masked to keep that arm from carrying an invalid count.
 */
#define LRL(d,s,n) ((n) < 32 \
  ? ((d).h = ((s).h << (n)) | ((s).l >> ((32 - (n)) & 31)) \
    ,(d).l = ((s).l << (n)) | ((s).h >> ((32 - (n)) & 31))) \
  : ((d).h = ((s).l << ((n) - 32)) | ((s).h >> ((64 - (n)) & 31)) \
    ,(d).l = ((s).h << ((n) - 32)) | ((s).l >> ((64 - (n)) & 31))))

static void
sha3512mix(
  sha3512_lt a[]
 ,const unsigned char x[]
){
  static const sha3512_bt k[][2] = { /* round constants, high then low */
    {0x00000000U,0x00000001U}
   ,{0x00000000U,0x00008082U}
   ,{0x80000000U,0x0000808aU}
   ,{0x80000000U,0x80008000U}
   ,{0x00000000U,0x0000808bU}
   ,{0x00000000U,0x80000001U}
   ,{0x80000000U,0x80008081U}
   ,{0x80000000U,0x00008009U}
   ,{0x00000000U,0x0000008aU}
   ,{0x00000000U,0x00000088U}
   ,{0x00000000U,0x80008009U}
   ,{0x00000000U,0x8000000aU}
   ,{0x00000000U,0x8000808bU}
   ,{0x80000000U,0x0000008bU}
   ,{0x80000000U,0x00008089U}
   ,{0x80000000U,0x00008003U}
   ,{0x80000000U,0x00008002U}
   ,{0x80000000U,0x00000080U}
   ,{0x00000000U,0x0000800aU}
   ,{0x80000000U,0x8000000aU}
   ,{0x80000000U,0x80008081U}
   ,{0x80000000U,0x00008080U}
   ,{0x00000000U,0x80000001U}
   ,{0x80000000U,0x80008008U}
  };
  sha3512_lt b[25]; /* rho and pi land here, chi reads it back */
  sha3512_lt c[5];  /* column parities */
  sha3512_lt d;
  sha3512_lt t;
  unsigned int i;
  unsigned int j;
  unsigned int y;

  for (i = 0; i < SHA3512_RT / 8; ++i) {
    a[i].l ^= (sha3512_bt)x[i * 8 + 0] | (sha3512_bt)x[i * 8 + 1] << 8
            | (sha3512_bt)x[i * 8 + 2] << 16 | (sha3512_bt)x[i * 8 + 3] << 24;
    a[i].h ^= (sha3512_bt)x[i * 8 + 4] | (sha3512_bt)x[i * 8 + 5] << 8
            | (sha3512_bt)x[i * 8 + 6] << 16 | (sha3512_bt)x[i * 8 + 7] << 24;
  }
  for (i = 0; i < sizeof (k) / sizeof (k[0]); ++i) {
    for (j = 0; j < 5; ++j) { /* theta */
      LCP(c[j], a[j]);
      for (y = 1; y < 5; ++y)
        LXR(c[j], c[j], a[j + 5 * y]);
    }
    for (j = 0; j < 5; ++j) {
      LRL(t, c[(j + 1) % 5], 1);
      LXR(d, c[(j + 4) % 5], t);
      for (y = 0; y < 5; ++y)
        LXR(a[j + 5 * y], a[j + 5 * y], d);
    }
    /* rho (offsets are (n+1)(n+2)/2 mod 64) and pi (y, 2x+3y) */
    LCP(b[ 0], a[ 0]);
    LRL(b[10], a[ 1],  1);
    LRL(b[20], a[ 2], 62);
    LRL(b[ 5], a[ 3], 28);
    LRL(b[15], a[ 4], 27);
    LRL(b[16], a[ 5], 36);
    LRL(b[ 1], a[ 6], 44);
    LRL(b[11], a[ 7],  6);
    LRL(b[21], a[ 8], 55);
    LRL(b[ 6], a[ 9], 20);
    LRL(b[ 7], a[10],  3);
    LRL(b[17], a[11], 10);
    LRL(b[ 2], a[12], 43);
    LRL(b[12], a[13], 25);
    LRL(b[22], a[14], 39);
    LRL(b[23], a[15], 41);
    LRL(b[ 8], a[16], 45);
    LRL(b[18], a[17], 15);
    LRL(b[ 3], a[18], 21);
    LRL(b[13], a[19],  8);
    LRL(b[14], a[20], 18);
    LRL(b[24], a[21],  2);
    LRL(b[ 9], a[22], 61);
    LRL(b[19], a[23], 56);
    LRL(b[ 4], a[24], 14);
    for (y = 0; y < 5; ++y) /* chi */
      for (j = 0; j < 5; ++j)
        LCH(a[j + 5 * y], b[j + 5 * y]
           ,b[(j + 1) % 5 + 5 * y], b[(j + 2) % 5 + 5 * y]);
    a[0].h ^= k[i][0]; /* iota */
    a[0].l ^= k[i][1];
  }
}

unsigned int
sha3512tsize(
  void
){
  return (sizeof (sha3512_t));
}

void
sha3512init(
  sha3512_t *v
){
  unsigned int i;

  for (i = 0; i < sizeof (v->a) / sizeof (v->a[0]); ++i)
    v->a[i].h = v->a[i].l = 0;
  v->l = 0;
}

void
sha3512update(
  sha3512_t *v
 ,const unsigned char *d
 ,unsigned int l
){
  unsigned char *s;

  if (v->l) {
    unsigned int i;

    for (i = v->l, s = v->d + i; l && i < SHA3512_RT; --l, ++i, ++s, ++d)
      *s = *d;
    if (i == SHA3512_RT) {
      sha3512mix(v->a, v->d);
      v->l = 0;
    } else {
      v->l = i;
      return;
    }
  }
  for (; l >= SHA3512_RT; l -= SHA3512_RT, d += SHA3512_RT)
    sha3512mix(v->a, d);
  if (l) {
    v->l = l;
    for (s = v->d; l; --l, ++s, ++d)
      *s = *d;
  }
}

void
sha3512final(
  sha3512_t *v
 ,unsigned char *h
){
  unsigned char *s;
  unsigned int i;

  /*
   * no length is appended: the sponge absorbs a domain tag 01 followed by
   * the 10*1 pad, which is 0x06 then 0x80 in the last rate byte. A single
   * squeeze suffices because SHA3512_SZ is inside the rate.
   */
  i = v->l;
  s = v->d + i;
  for (*s++ = 0x06, ++i; i < SHA3512_RT; ++i, ++s)
    *s = 0x00;
  *(v->d + SHA3512_RT - 1) |= 0x80;
  sha3512mix(v->a, v->d);
  for (i = 0; i < SHA3512_SZ / 8; ++i) {
    *h++ = (unsigned char)(v->a[i].l >> (0 * 8));
    *h++ = (unsigned char)(v->a[i].l >> (1 * 8));
    *h++ = (unsigned char)(v->a[i].l >> (2 * 8));
    *h++ = (unsigned char)(v->a[i].l >> (3 * 8));
    *h++ = (unsigned char)(v->a[i].h >> (0 * 8));
    *h++ = (unsigned char)(v->a[i].h >> (1 * 8));
    *h++ = (unsigned char)(v->a[i].h >> (2 * 8));
    *h++ = (unsigned char)(v->a[i].h >> (3 * 8));
  }
}

void
sha3512hmac(
  const unsigned char *k
 ,unsigned int kl
 ,const unsigned char *d
 ,unsigned int dl
 ,unsigned char *h
){
  sha3512_t c;
  unsigned char i[SHA3512_RT];
  unsigned char o[SHA3512_RT];
  unsigned int l;

  if (kl > SHA3512_RT) {
    sha3512init(&c);
    sha3512update(&c, k, kl);
    sha3512final(&c, h);
    k = h;
    kl = SHA3512_SZ;
  }
  for (l = 0; l < kl; ++l) {
    i[l] = *(k + l) ^ 0x36;
    o[l] = *(k + l) ^ 0x5c;
  }
  for (; l < SHA3512_RT; ++l) {
    i[l] = 0x00 ^ 0x36;
    o[l] = 0x00 ^ 0x5c;
  }
  sha3512init(&c);
  sha3512update(&c, i, sizeof (i));
  sha3512update(&c, d, dl);
  sha3512final(&c, h);
  sha3512init(&c);
  sha3512update(&c, o, sizeof (o));
  sha3512update(&c, h, SHA3512_SZ);
  sha3512final(&c, h);
  /* wipe stack residue; volatile defeats dead-store elimination */
  {
    volatile unsigned char *p;
    unsigned int n;

    p = (volatile unsigned char *)&c;
    for (n = 0; n < sizeof (c); ++n)
      *p++ = 0;
    p = (volatile unsigned char *)i;
    for (n = 0; n < sizeof (i); ++n)
      *p++ = 0;
    p = (volatile unsigned char *)o;
    for (n = 0; n < sizeof (o); ++n)
      *p++ = 0;
  }
}

void
sha3512hkdf(
  const unsigned char *k
 ,unsigned int kl
 ,const unsigned char *d
 ,unsigned int dl
 ,unsigned char *s
 ,unsigned int sl
){
  sha3512_t c;
  unsigned char i[SHA3512_RT];
  unsigned char o[SHA3512_RT];
  unsigned char t[SHA3512_SZ];
  unsigned char t2[SHA3512_SZ];
  unsigned int l;
  unsigned int n;

  if (sl > 255 * SHA3512_SZ)
    sl = 255 * SHA3512_SZ;
  if (kl > SHA3512_RT) {
    sha3512init(&c);
    sha3512update(&c, k, kl);
    sha3512final(&c, t);
    k = t;
    kl = SHA3512_SZ;
  }
  for (l = 0; l < kl; ++l) {
    i[l] = *(k + l) ^ 0x36;
    o[l] = *(k + l) ^ 0x5c;
  }
  for (; l < SHA3512_RT; ++l) {
    i[l] = 0x00 ^ 0x36;
    o[l] = 0x00 ^ 0x5c;
  }
  for (n = 0, l = 0; l < sl;) {
    unsigned char b;
    unsigned int j;

    b = (unsigned char)++n;
    sha3512init(&c);
    sha3512update(&c, i, sizeof (i));
    if (n > 1)
      sha3512update(&c, t, SHA3512_SZ);
    sha3512update(&c, d, dl);
    sha3512update(&c, &b, 1);
    sha3512final(&c, t2);
    sha3512init(&c);
    sha3512update(&c, o, sizeof (o));
    sha3512update(&c, t2, SHA3512_SZ);
    sha3512final(&c, t);
    for (j = 0; j < SHA3512_SZ && l < sl; ++j, ++l)
      s[l] = t[j];
  }
  /* wipe stack residue once; volatile defeats dead-store elimination */
  {
    volatile unsigned char *p;
    unsigned int m;

    p = (volatile unsigned char *)&c;
    for (m = 0; m < sizeof (c); ++m)
      *p++ = 0;
    p = (volatile unsigned char *)i;
    for (m = 0; m < sizeof (i); ++m)
      *p++ = 0;
    p = (volatile unsigned char *)o;
    for (m = 0; m < sizeof (o); ++m)
      *p++ = 0;
    p = (volatile unsigned char *)t;
    for (m = 0; m < sizeof (t); ++m)
      *p++ = 0;
    p = (volatile unsigned char *)t2;
    for (m = 0; m < sizeof (t2); ++m)
      *p++ = 0;
  }
}

void
sha3512hex(
  const unsigned char *h
 ,char *o
){
  unsigned int i;

  for (i = 0; i < SHA3512_SZ; ++i, ++h) {
    static const char m[] = "0123456789abcdef";

    *o++ = m[(*h >> 4) & 0xf];
    *o++ = m[(*h >> 0) & 0xf];
  }
}
