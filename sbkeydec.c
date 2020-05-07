#include <stdio.h>
#include <windows.h>

#include "sbhelper.h"

/*
registration information stored here:
[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{98E6BD24-2D93-41A5-BC6D-CB7C1507318B}]
*/

/* RSAPublic[], RSAPrime[], RSADecode() and DecodeActivationString() taken from the SbieDrv.sys driver */
static ULONG RSAPublic[65] = {64,
  0x070964E3, 0x92A8CA80, 0x2C63816B, 0xD3972EEF, 0x7D7907EB, 0x1C299CF1, 0x9FE553C3, 0xD7655105,
  0x57039A3C, 0x99904C9F, 0xE6AC9B30, 0xCC849489, 0x905960FB, 0xF56E8707, 0xA4B68CA9, 0x492785B8,
  0x86EFDDD1, 0x3AC53FE2, 0x46D14C43, 0x063FFAA7, 0xE6647329, 0x250F8165, 0x369CAEAA, 0x9094EBFB,
  0x0ABC3137, 0xFA8E04D7, 0xF743CA1B, 0x7433C71C, 0x2085DE22, 0xF9534BBF, 0x89971BE0, 0xB325204A,
  0xE41A68C7, 0x65C021D2, 0x72165A6E, 0x37CF06B3, 0x12A796C3, 0xC096A2CD, 0x560C2549, 0xA604313B,
  0x61819A91, 0x31D8C689, 0xBA0405D7, 0xAA309DD1, 0xBF048392, 0x414DC7C1, 0xCD7C994B, 0x199F96C2,
  0x384B74EF, 0x528F1D79, 0xF2748BBF, 0xE2CCB6BE, 0x3B58D1AF, 0x7F473051, 0x719A92D3, 0xD14BF512,
  0x50DEE0D8, 0x75476A89, 0xC03B7AF4, 0x2D926E9F, 0x57F99663, 0x42A0EF2D, 0xC0D8ED19, 0xC96F1862
};

static ULONG RSAPrime[2] = {1, 0x00010001};

/* https://www.di-mgt.com.au/rsa_alg.html#crt */
BIGNUM RSADecode(void *poll, BIGNUM kvalue, BIGNUM kprime, BIGNUM kpublic) {
BIGNUM p, b_sum, b_mul, rp, tmp, dvt, bprime;
  p = NULL;
  b_sum = BigNum_CreateFromBigNum(poll, kvalue);
  if (b_sum) {
    bprime = BigNum_CreateFromBigNum(poll, kprime);
    kvalue = bprime;
    if (bprime) {
      b_mul = BigNum_CreateFromInteger(poll, 1);
      p = b_mul;
      if (b_mul) {
        while ((bprime[0] != 1) || bprime[1]) {
          if (bprime[1] & 1) {
            tmp = BigNum_Multiply(poll, b_mul, b_sum);
            if (!tmp) {
              bprime = kvalue;
              break;
            }
            BigNum_Free(p);
            p = NULL;
            rp = BigNum_Divide(poll, tmp, kpublic, &p);
            BigNum_Free(tmp);
            if (!rp) {
              bprime = kvalue;
              break;
            }
            BigNum_Free(rp);
            bprime = kvalue;
          }
          kvalue = BigNum_ShiftRight(poll, bprime, 1);
          if (!kvalue) { break; }
          BigNum_Free(bprime);
          tmp = BigNum_Multiply(poll, b_sum, b_sum);
          if (!tmp) {
            bprime = kvalue;
            break;
          }
          BigNum_Free(b_sum);
          rp = NULL;
          dvt = BigNum_Divide(poll, tmp, kpublic, &rp);
          BigNum_Free(tmp);
          if (!dvt) {
            b_sum = rp;
            bprime = kvalue;
            break;
          }
          BigNum_Free(dvt);
          b_sum = rp;
          bprime = kvalue;
          b_mul = p;
        }
      }
      if (bprime) {
        BigNum_Free(bprime);
      }
    }
    if (b_sum) {
      BigNum_Free(b_sum);
    }
  }
  return(p);
}

size_t DecodeActivationString(WCHAR *p, BIGNUM *pp) {
BIGNUM bkey, data;
size_t result;
sbx_key *k;
  *pp = NULL;
  bkey = BigNum_CreateFromString(NULL, p, 36);
  if (bkey) {
    data = RSADecode(NULL, bkey, (BIGNUM) RSAPrime, (BIGNUM) RSAPublic);
    BigNum_Free(bkey);
    if (data) {
      *pp = data;
      if (data[0] > 4) {
        k = (sbx_key *) &data[1];
        if ((k->flags_1 & 0x0F) == 1) {
          if (CRC_AdlerTzuk64((UCHAR *) &k->flags_2, (data[0] - 3) * sizeof(data[0])) == k->crcat64) {
            if (k->flags_2 == 0x80000001) {
              result = (k->flags_3 != 1) ? 34 : 0;
            } else {
              result = 33;
            }
          } else {
            result = 20;
          }
        } else {
          result = 19;
        }
      } else {
        result = 18;
      }
    } else {
      result = 17;
    }
  } else {
    result = 17;
  }
  return(result);
}

static WCHAR wkey[401];

int main(int argc, char *argv[]) {
BIGNUM data;
sbx_key *k;
size_t i;
  printf(
    "Sandboxie Activation Key decoder v1.0\n"
    "(c) SysTools 2020\n"
    "http://systools.losthost.org/?misc\n\n"
    "Tested only with Sandboxie 5.22.\n\n"
  );
  if (argc != 2) {
    printf("Usage: sbkeydec <400-character Activation Key>\n\n");
    return(1);
  }
  /* lazy ANSI to Unicode */
  ZeroMemory(wkey, sizeof(wkey));
  for (i = 0; i < 400; i++) {
    if (!argv[1][i]) { break; }
    wkey[i] = argv[1][i];
  }
  data = NULL;
  i = DecodeActivationString(wkey, &data);
  printf("ErrCode %d (0 - OK)\n", i);
  if (data) {
    if ((!i) && (data[0] >= 61)) {
      k = (sbx_key *) &data[1];
      printf(
        "Version of: %c%c%c%c\n"
        "Actived to: %02X-%02X-%04X (00-00-0000 = 31/12/2999)\n"
        "Limited to: %02X-%02X-%04X (00-00-0000 for lifetime)\n"
        "ProdKey is: %s\n"
        "SysCode is: %08X%08X\n",
        k->version[0], k->version[1], k->version[2], k->version[3],
        k->actilld, k->actillm, k->actilly,
        k->lmtilld, k->lmtillm, k->lmtilly,
        k->prodkey,
        (ULONG) (k->syscode >> 32), (ULONG) k->syscode
      );
    }
    BigNum_Free(data);
  }
  return(0);
}
