#include <stdio.h>
#include <stdlib.h>
#include "sha3256.h"

int
main(
  void
){
  sha3256_t *c;
  size_t i;
  unsigned char h[SHA3256_SZ];
  unsigned char b[2 * SHA3256_SZ];

  if (!(c = malloc(sha3256tsize())))
    return (1);
  sha3256init(c);
  while ((i = fread(b, 1, sizeof (b), stdin)) == sizeof (b))
    sha3256update(c, b, i);
  if (ferror(stdin)) {
    free(c);
    return (1);
  }
  if (i > 0)
    sha3256update(c, b, i);
  sha3256final(c, h);
  free(c);
  sha3256hex(h, (char *)b);
  printf("%.*s\n", (int)sizeof (b), b);
  return (0);
}
