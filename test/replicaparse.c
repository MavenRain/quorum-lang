/* Exercise the runner's parsers without running the crypto operations. */
#define main replicatool_main
#include "replicatool.c"
#undef main

int main(void) {
  static const char *const bad[] = {"", "-1", "+1", " 1", "1 ", "1,0",
      "18446744073709551616", "9999999999999999999999999999999999999999"};
  u64 words[LIST_WORDS];
  u64 n = 0;
  unsigned i;
  int ok = number("0", &n) && n == 0 && number("18446744073709551615", &n) && n == UINT64_MAX;
  for (i = 0; i < sizeof bad / sizeof bad[0]; i++) ok &= !number(bad[i], &n);
  ok &= parse_stack("1,18446744073709551615,0", words) == 1 && words[1] == UINT64_MAX;
  ok &= parse_stack("1,18446744073709551616,0", words) == -1;
  ok &= parse_stack("1,-1,0", words) == -1;
  ok &= parse_stack("1,1,0,", words) == -1;
  ok &= parse_stack("1,,0", words) == -1;
  ok &= parse_chain("0", words) == 0;
  ok &= parse_chain("1,0,18446744073709551616,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0", words) == -1;
  ok &= parse_list("0", 2u, words) == 0;
  ok &= parse_list("1,0,18446744073709551615,0,0,0,0,0,0,0,0", 2u, words) == 1;
  ok &= parse_list("1,0,18446744073709551616,0,0,0,0,0,0,0,0", 2u, words) == -1;
  if (!ok) fputs("FAIL replica parser regressions\n", stderr);
  else puts("replica parser regressions: passed");
  return ok ? 0 : 1;
}
