#include <stdio.h>
#include <stdlib.h>
#include "sha3512.h"

int
main(
  void
){
  sha3512_t *c;
  size_t i;
  unsigned char h[SHA3512_SZ];
  unsigned char b[2 * SHA3512_SZ];

  if (!(c = malloc(sha3512tsize())))
    return (1);
  sha3512init(c);
  while ((i = fread(b, 1, sizeof (b), stdin)) == sizeof (b))
    sha3512update(c, b, i);
  if (ferror(stdin)) {
    free(c);
    return (1);
  }
  if (i > 0)
    sha3512update(c, b, i);
  sha3512final(c, h);
  free(c);
  sha3512hex(h, (char *)b);
  printf("%.*s\n", (int)sizeof (b), b);
  return (0);
}
