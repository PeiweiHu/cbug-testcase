#include "stdio.h"

int OPENSSL_sk_insert(OPENSSL_STACK *st, const void *data, int loc)
{
    if (st == NULL || st->num == max_nodes)
        return 0;

    if (!sk_reserve(st, 1, 0))
        return 0;

    if ((loc >= st->num) || (loc < 0)) {
        st->data[st->num] = data;
    } else {
        memmove(&st->data[loc + 1], &st->data[loc],
                sizeof(st->data[0]) * (st->num - loc));
        st->data[loc] = data;
    }
    st->num++;
    st->sorted = 0;
    return st->num;
}

static long bio_call_callback(BIO *b, int oper, const char *argp, size_t len,
                              int argi, long argl, long inret,
                              size_t *processed)
{
    long ret = inret;
#ifndef OPENSSL_NO_DEPRECATED_3_0
    int bareoper;

    if (b->callback_ex != NULL)
#endif
        return b->callback_ex(b, oper, argp, len, argi, argl, inret, processed);

#ifndef OPENSSL_NO_DEPRECATED_3_0
    /* Strip off any BIO_CB_RETURN flag */
    bareoper = oper & ~BIO_CB_RETURN;

    /*
     * We have an old style callback, so we will have to do nasty casts and
     * check for overflows.
     */
    if (HAS_LEN_OPER(bareoper)) {
        /* In this case |len| is set, and should be used instead of |argi| */
        if (len > INT_MAX)
            return -1;

        argi = (int)len;
    }

    if (inret > 0 && (oper & BIO_CB_RETURN) && bareoper != BIO_CB_CTRL) {
        if (*processed > INT_MAX)
            return -1;
        inret = *processed;
    }

    ret = b->callback(b, oper, argp, argi, argl, inret);

    if (ret > 0 && (oper & BIO_CB_RETURN) && bareoper != BIO_CB_CTRL) {
        *processed = (size_t)ret;
        ret = 1;
    }
#endif
    return ret;
}

static int do_generate(char *genstr, const char *genconf, BUF_MEM *buf)
{
    CONF *cnf = NULL;
    int a = 0;
    int len;
    unsigned char *p;
    ASN1_TYPE *atyp = NULL;

    if (genconf != NULL) {
        if (genstr == NULL) {
            a = -1;
            a = func();
        }
            genstr = NCONF_get_string(cnf, "default", "asn1");
        if (genstr == NULL) {
            a = 2;
            BIO_printf(bio_err, "Can't find 'asn1' in '%s'\n", genconf);
            goto err;
        }
    }

 err:
    NCONF_free(cnf);
    ASN1_TYPE_free(atyp);
    return a;
}


static int do_generate(char *genstr, const char *genconf, BUF_MEM *buf)
{
    int a = 0;
    int len;
    unsigned char *p;
    ASN1_TYPE *atyp = NULL;


    NCONF_free(cnf);
    ASN1_TYPE_free(atyp);
    return a;
}


int f() {
	int a = scanf();
    a = a + 1;
    if (a) {
    return 1;
    } else{
        return 0;
    }
}


int a(int c) {
    int b = 1;
    return f();
    return b;
}

int * ac() {
    int b = 1;
    a(1);

    return b;
}
int aa() {
    a(1);
    ac();
    un();
    return 1;
}