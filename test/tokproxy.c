/* The token proxy of docs/TOKEN-BASELINE.md (S9 O127). It reads one file
   and prints its token count on stdout. The count is a fixed offline
   proxy, not the tokenizer of a model:
   - a run of ASCII letters, digits and `_` costs ceil(length / 4);
   - each other ASCII byte that is not white space costs 1;
   - each byte of a non-ASCII UTF-8 character costs 1;
   - white space (space, tab, line feed, carriage return, vertical tab and
     form feed) costs 0.
   The exit status is 0, or 2 on a usage error or a read error. */

#include <stdio.h>

static int is_word(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

static int is_space(int c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

int main(int argc, char **argv)
{
    FILE *in;
    unsigned long tokens = 0;
    unsigned long run = 0;
    int c;
    int bad;

    if (argc != 2) {
        fprintf(stderr, "usage: tokproxy FILE\n");
        return 2;
    }
    in = fopen(argv[1], "rb");
    if (in == NULL) {
        fprintf(stderr, "tokproxy: %s: cannot open the file\n", argv[1]);
        return 2;
    }
    while ((c = getc(in)) != EOF) {
        if (is_word(c)) {
            run++;
            continue;
        }
        tokens += (run + 3) / 4;
        run = 0;
        if (!is_space(c))
            tokens++;
    }
    tokens += (run + 3) / 4;
    bad = ferror(in);
    fclose(in);
    if (bad) {
        fprintf(stderr, "tokproxy: %s: cannot read the file\n", argv[1]);
        return 2;
    }
    printf("%lu\n", tokens);
    return 0;
}
