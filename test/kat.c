#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha3256.h"
#include "sha3512.h"

/*
 * Expected values are FIPS 202 SHA3-256 / SHA3-512, generated with an
 * independent implementation (python3 hashlib and hmac), not with this one.
 * Bvec lengths straddle both rates, 72 and 136, where the pad10*1 boundary
 * cases live: rate-1 puts the 0x06 tag and the 0x80 pad in the same byte.
 */
struct svec {
  const char *in;
  const char *h256;
  const char *h512;
  unsigned int inlen;
};

struct bvec {
  const char *h256;
  const char *h512;
  unsigned int inlen;
};

static const struct svec Svec[] = {
 { ""
   ,"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
   ,"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
   ,0 }
 ,{ "abc"
   ,"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
   ,"b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
   ,3 }
 ,{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
   ,"41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
   ,"04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"
   ,56 }
 ,{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
   ,"916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"
   ,"afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"
   ,112 }
};

static const struct bvec Bvec[] = {
 { "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
   ,"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
   ,  0 }
 ,{ "2767f15c8af2f2c7225d5273fdd683edc714110a987d1054697c348aed4e6cc7"
   ,"c46af35fa4594a247543c33e52e17572f94c48d2bdc42e0a2e861b805a28820e762a493b9d2660247198bae31ac510903c282ee224f15003cfdfaf402a19cb91"
   ,  1 }
 ,{ "011bceddb2f6891d5d155f631ed9683708c9279af96ca3fff2919982c600fc77"
   ,"9e4dee6367de5a2369552f7bc5984aa66c4ddec980d907592834fc194af9cc9965bcb79292faeedcc93471ecc5b3d33983beb5549e29126074ffccc59af809b8"
   , 71 }
 ,{ "2339b942c2cc2d0692692225dab7d21d9e4ece5a8d494fbfa29284703b46ba8b"
   ,"574f819c848e9d6f492f03847055180317740ce2f8473374e9c59255d9e2f5fc456eef18ed169f36b74e82a03e4164694c102389c0781483838c8840890c429e"
   , 72 }
 ,{ "6948bd84d8af02e3344df5b36f037adf79c706f5de5c15fde9930b138e95e2e3"
   ,"96836c50a2d824ff0eb228e5060e0b88efd30e10b366347e95ace6909bda65b23fa8d268ecf88ad5e53cc3492280389200015556d8c2ee3e3fbaa5bce3db678b"
   , 73 }
 ,{ "64ccd300c1cf3d3846046bd588a1613e5ba619c09d45d4b7cc9afa093af29e19"
   ,"3c1ac541af927d906b5b722ecac3ad4fc8b398ac833e8e040c5a217f041b8ef72036dfed2eda0d7cc3f1b7b97083a18c2d8c9cdb9c6581b893dcc036a5e99235"
   ,135 }
 ,{ "f106d1024a855c6a20d300bb53ec5472a1bae126fa630fee78219b51add7d768"
   ,"9be60e628febae576dd2cddb3ea62ab4f1c74ae6c4e03eca014b2e0f5f47059fe665cbd2d3bb4e0a9fc2add5552b16129a4a8ff515dfe1f03ffc43fe7ab3601a"
   ,136 }
 ,{ "fa4d0b0141ec2c69a5dc314ed611a0819b920e95d13d586df89f370809e9465a"
   ,"844664dcf5f70b68e5ea229db10a24d2830350ddce2ea5b205771aeb91e0e998d122b433063124522ba4d0a3b4006f4996808621431645818281f308a232bbce"
   ,137 }
 ,{ "4e64495a6bd9c2ec70eabe1f944c37ca869a3d38c201a35a890766460458b66c"
   ,"0ed3f446670b5dcd674fcfa83450e70a8362bbf1cf16ec25e770a99c206df607d35f537b05d84fa677ab07a9b8f2d50c94d4f00afdc0ac7737383f0794f7473a"
   ,143 }
 ,{ "c0ff52f5dbd999227dc068ad2e222ff4733c35227c0f95bf1eddcffd8f9679a1"
   ,"ef8c5c8315608c36b8bea9ba9b62aa83066fa9643a8a15764cbb4c4056416f5f3bacfc7280c9ca8af12288bbe5988317e4ce707e9861c316036731630c58ca8a"
   ,144 }
 ,{ "e48f30fe920a5e88a570c3c0a90ab2c2b3aabb1bf8114fb3f28310641ada39e7"
   ,"2848e855553de18c62cbe86ea0349af43168e481b8e51f3ad2ecdec16446a8a1108e78d3ad1e4593287233fe27dd55daf043b55b46a8b5b0e3541b1ecfd5d2e2"
   ,145 }
 ,{ "1bea1a85c82f141d118988be6f7a7c0875a45c1a9820f2e1d7797061d2b3d86a"
   ,"45418dbae0f40fc96a00351bc4feaa22764a6c20c90034f1bef2164b36d8f2e3d5ae8a1bad8ed82c090c88f5609d4deb27420b574d7ea5e75f62ab887699e0b0"
   ,200 }
 ,{ "e8290112975a2234c8aea40944ba52255fce073c96846ab3904baf1a32977501"
   ,"b94ac1821844b3935d4f222345a8a44fb92fe71870eeab1af80cb8adec3a79f89557183b3c6ba9d5f737adcb8af0b1775fa4b8c9761bf97f005e9e3000347936"
   ,255 }
};

/* chunk sizes for streaming equivalence, straddling both rates */
static const unsigned int Chunks[] = { 1, 7, 63, 71, 72, 73, 135, 136, 137, 200 };

#define MEGA256 "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"
#define MEGA512 "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"
#define HM256T1 "874d1d4e6e8302439bf707052e5d787d92bffcf0715853784e30da740a81e198"
#define HM512T1 "d2d9588c7e7886b08e09b56a7ac9d7e30a4badf13b37a041f5dfde34d87c086b5db1a7ec679bcfce81fa2eee982573c01dfb8d988e302f78d7b20d7d7ac2dfd7"
#define HM256T2 "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5"
#define HM512T2 "5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024"
#define HM256T6 "49ad92b02124fdac9627ae45e008a696182ab6bfb8470457777c744aeb9df06f"
#define HM512T6 "fafc7b7fe3332ce153966b27f6586fa5b49ec5d8dff3d7fd26a011451ca4c9de437913879159d9c5181a9a6f377ef18b48399756decea695b04fe90a9d3b93d1"
#define HK256 "4d5e518c1b63898308f11ed0cee4a43dc54221cd04e0232c569ac56750aaeb17ffe90d59f878503afb891773118a626bbcfb10cd652955d1532491f6e6a234f95a6b4e78eb256ab010a689432c95becbb2b4161e88bf9541873e435caa2f44f3d5d8dd48"
#define HK512 "2d32e95189fac60a59a2832e9aa41d17b99b0a5ded05a1702e6496af47f1de122ce6722a99a51291a29be9f1ad7ae136ebc4c05377b7f97dcc806744b4e31a7c3bbac795a6637f45bece410057ab8c1963bd2f624070231302bc1163d6e459124a66451b"
#define HKL256 "a27eb63779e57eb36f377b7a3e293fe7f19d06fddd7580e0bf8444fb4ed297c88f8d3b7a515415ca8a0411ee20ce2d76878d2fd4fb7c79efc7ec1feba520464dc66ce9f6b232069bef7c1d6b2f96bbdebaea31200658b87a58f5bcb6b89e8a895300f334"
#define HKL512 "af49e013b0fbfcde3c012306a80a6f1b051da84d25990b6255fa8efecdf228d1eac9ba0c23d01c80b5f17602eec5ac11d54cc7d1e0ed3fdb0d725c724d1009a49af616480e55eb6d299b436d115104274d561658d4bd28656b2ba4721c96bf66ce0478ba"

static void
hexof(
  const unsigned char *b
 ,unsigned int n
 ,char *o
){
  static const char m[] = "0123456789abcdef";
  unsigned int q;

  for (q = 0; q < n; ++q) {
    *o++ = m[(b[q] >> 4) & 0xf];
    *o++ = m[b[q] & 0xf];
  }
  *o = 0;
}

static int
check(
  const char *label
 ,const char *got
 ,const char *want
){
  if (!strcmp(got, want))
    return (0);
  fprintf(stderr, "FAIL %s:\n got  %s\n want %s\n", label, got, want);
  return (1);
}

int
main(
  void
){
  static const char Hd1[] = "Hi There";
  static const char Hk2[] = "Jefe";
  static const char Hd2[] = "what do ya want for nothing?";
  static const char Hd6[] = "Test Using Larger Than Block-Size Key - Hash Key First";
  static const char Hinf[] = "sha3 hkdf test";
  static unsigned char Buf[256];
  static unsigned char Hk1[16];
  static unsigned char Hk6[200];
  sha3256_t *c256;
  sha3512_t *c512;
  unsigned char *mega;
  unsigned char h256[SHA3256_SZ];
  unsigned char h512[SHA3512_SZ];
  unsigned char k[32];
  unsigned char s[100];
  char b256[2 * SHA3256_SZ + 1];
  char b512[2 * SHA3512_SZ + 1];
  char ref256[2 * SHA3256_SZ + 1];
  char ref512[2 * SHA3512_SZ + 1];
  char bs[2 * sizeof (s) + 1];
  unsigned int q;
  unsigned int off;
  unsigned int n;
  int fail;

  for (q = 0; q < sizeof (Buf); ++q)
    Buf[q] = (unsigned char)(q * 7 + 1);
  for (q = 0; q < sizeof (Hk1); ++q)
    Hk1[q] = 0x0b;
  for (q = 0; q < sizeof (Hk6); ++q)
    Hk6[q] = 0xaa;
  for (q = 0; q < sizeof (k); ++q)
    k[q] = (unsigned char)q;
  if (!(c256 = malloc(sha3256tsize()))) {
    fprintf(stderr, "FAIL: malloc(sha3256tsize)\n");
    return (1);
  }
  if (!(c512 = malloc(sha3512tsize()))) {
    fprintf(stderr, "FAIL: malloc(sha3512tsize)\n");
    free(c256);
    return (1);
  }
  fail = 0;

  /* FIPS 202 spec messages */
  for (q = 0; q < sizeof (Svec) / sizeof (Svec[0]); ++q) {
    sha3256init(c256);
    sha3256update(c256, (const unsigned char *)Svec[q].in, Svec[q].inlen);
    sha3256final(c256, h256);
    hexof(h256, SHA3256_SZ, b256);
    fail += check("sha3256 spec", b256, Svec[q].h256);

    sha3512init(c512);
    sha3512update(c512, (const unsigned char *)Svec[q].in, Svec[q].inlen);
    sha3512final(c512, h512);
    hexof(h512, SHA3512_SZ, b512);
    fail += check("sha3512 spec", b512, Svec[q].h512);
  }

  /* rate boundaries */
  for (q = 0; q < sizeof (Bvec) / sizeof (Bvec[0]); ++q) {
    sha3256init(c256);
    sha3256update(c256, Buf, Bvec[q].inlen);
    sha3256final(c256, h256);
    hexof(h256, SHA3256_SZ, b256);
    fail += check("sha3256 rate", b256, Bvec[q].h256);

    sha3512init(c512);
    sha3512update(c512, Buf, Bvec[q].inlen);
    sha3512final(c512, h512);
    hexof(h512, SHA3512_SZ, b512);
    fail += check("sha3512 rate", b512, Bvec[q].h512);
  }

  /* million-a */
  if (!(mega = malloc(1000000))) {
    fprintf(stderr, "FAIL: malloc(1000000)\n");
    free(c256);
    free(c512);
    return (1);
  }
  memset(mega, 'a', 1000000);
  sha3256init(c256);
  sha3256update(c256, mega, 1000000);
  sha3256final(c256, h256);
  hexof(h256, SHA3256_SZ, b256);
  fail += check("sha3256 million-a", b256, MEGA256);

  sha3512init(c512);
  sha3512update(c512, mega, 1000000);
  sha3512final(c512, h512);
  hexof(h512, SHA3512_SZ, b512);
  fail += check("sha3512 million-a", b512, MEGA512);
  free(mega);

  /* one-shot versus chunk-by-chunk across the rate buffer */
  sha3256init(c256);
  sha3256update(c256, Buf, sizeof (Buf));
  sha3256final(c256, h256);
  hexof(h256, SHA3256_SZ, ref256);
  sha3512init(c512);
  sha3512update(c512, Buf, sizeof (Buf));
  sha3512final(c512, h512);
  hexof(h512, SHA3512_SZ, ref512);
  for (q = 0; q < sizeof (Chunks) / sizeof (Chunks[0]); ++q) {
    sha3256init(c256);
    sha3512init(c512);
    for (off = 0; off < sizeof (Buf); off += n) {
      n = Chunks[q];
      if (off + n > sizeof (Buf))
        n = sizeof (Buf) - off;
      sha3256update(c256, Buf + off, n);
      sha3512update(c512, Buf + off, n);
    }
    sha3256final(c256, h256);
    sha3512final(c512, h512);
    hexof(h256, SHA3256_SZ, b256);
    hexof(h512, SHA3512_SZ, b512);
    fail += check("sha3256 stream", b256, ref256);
    fail += check("sha3512 stream", b512, ref512);
  }

  /* HMAC: block is the rate, 136 and 72; T6 exercises the long-key path */
  sha3256hmac(Hk1, sizeof (Hk1), (const unsigned char *)Hd1, sizeof (Hd1) - 1, h256);
  hexof(h256, SHA3256_SZ, b256);
  fail += check("hmac-sha3256 t1", b256, HM256T1);
  sha3512hmac(Hk1, sizeof (Hk1), (const unsigned char *)Hd1, sizeof (Hd1) - 1, h512);
  hexof(h512, SHA3512_SZ, b512);
  fail += check("hmac-sha3512 t1", b512, HM512T1);

  sha3256hmac((const unsigned char *)Hk2, sizeof (Hk2) - 1
             ,(const unsigned char *)Hd2, sizeof (Hd2) - 1, h256);
  hexof(h256, SHA3256_SZ, b256);
  fail += check("hmac-sha3256 t2", b256, HM256T2);
  sha3512hmac((const unsigned char *)Hk2, sizeof (Hk2) - 1
             ,(const unsigned char *)Hd2, sizeof (Hd2) - 1, h512);
  hexof(h512, SHA3512_SZ, b512);
  fail += check("hmac-sha3512 t2", b512, HM512T2);

  sha3256hmac(Hk6, sizeof (Hk6)
             ,(const unsigned char *)Hd6, sizeof (Hd6) - 1, h256);
  hexof(h256, SHA3256_SZ, b256);
  fail += check("hmac-sha3256 t6", b256, HM256T6);
  sha3512hmac(Hk6, sizeof (Hk6)
             ,(const unsigned char *)Hd6, sizeof (Hd6) - 1, h512);
  hexof(h512, SHA3512_SZ, b512);
  fail += check("hmac-sha3512 t6", b512, HM512T6);

  /* HKDF: 100 bytes spans several T(n) blocks for both */
  sha3256hkdf(k, sizeof (k)
             ,(const unsigned char *)Hinf, sizeof (Hinf) - 1, s, sizeof (s));
  hexof(s, sizeof (s), bs);
  fail += check("hkdf-sha3256", bs, HK256);
  sha3512hkdf(k, sizeof (k)
             ,(const unsigned char *)Hinf, sizeof (Hinf) - 1, s, sizeof (s));
  hexof(s, sizeof (s), bs);
  fail += check("hkdf-sha3512", bs, HK512);

  /* HKDF with a key longer than the block, the same branch HMAC T6 covers */
  sha3256hkdf(Hk6, sizeof (Hk6)
             ,(const unsigned char *)Hinf, sizeof (Hinf) - 1, s, sizeof (s));
  hexof(s, sizeof (s), bs);
  fail += check("hkdf-sha3256 longkey", bs, HKL256);
  sha3512hkdf(Hk6, sizeof (Hk6)
             ,(const unsigned char *)Hinf, sizeof (Hinf) - 1, s, sizeof (s));
  hexof(s, sizeof (s), bs);
  fail += check("hkdf-sha3512 longkey", bs, HKL512);

  free(c256);
  free(c512);
  if (fail) {
    fprintf(stderr, "%d FAILURES\n", fail);
    return (1);
  }
  printf("all sha3 known answer tests pass\n");
  return (0);
}
