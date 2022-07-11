
int BIO_free(BIO *a)
{
    int ret;

    if (a == NULL)
        return 0;

    if (CRYPTO_DOWN_REF(&a->references, &ret, a->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("BIO", a);
    if (ret > 0)
        return 1;
    REF_ASSERT_ISNT(ret < 0);

    if (HAS_CALLBACK(a)) {
        ret = (int)bio_call_callback(a, BIO_CB_FREE, NULL, 0, 0, 0L, 1L, NULL);
        if (ret <= 0)
            return ret;
    }

    if ((a->method != NULL) && (a->method->destroy != NULL))
        a->method->destroy(a);

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, a, &a->ex_data);

    CRYPTO_THREAD_lock_free(a->lock);

    OPENSSL_free(a);

    return 1;
}

X509_CRL *X509_CRL_diff(X509_CRL *base, X509_CRL *newer,
                        EVP_PKEY *skey, const EVP_MD *md, unsigned int flags)
{
    X509_CRL *crl = NULL;
    int i;

    STACK_OF(X509_REVOKED) *revs = NULL;
    /* CRLs can't be delta already */
    if (base->base_crl_number != NULL || newer->base_crl_number != NULL) {
        ERR_raise(ERR_LIB_X509, X509_R_CRL_ALREADY_DELTA);
        return NULL;
    }
    /* Base and new CRL must have a CRL number */
    if (base->crl_number == NULL || newer->crl_number == NULL) {
        ERR_raise(ERR_LIB_X509, X509_R_NO_CRL_NUMBER);
        return NULL;
    }
    /* Issuer names must match */
    if (X509_NAME_cmp(X509_CRL_get_issuer(base),
                      X509_CRL_get_issuer(newer)) != 0) {
        ERR_raise(ERR_LIB_X509, X509_R_ISSUER_MISMATCH);
        return NULL;
    }
    /* AKID and IDP must match */
    if (!crl_extension_match(base, newer, NID_authority_key_identifier)) {
        ERR_raise(ERR_LIB_X509, X509_R_AKID_MISMATCH);
        return NULL;
    }
    if (!crl_extension_match(base, newer, NID_issuing_distribution_point)) {
        ERR_raise(ERR_LIB_X509, X509_R_IDP_MISMATCH);
        return NULL;
    }
    /* Newer CRL number must exceed full CRL number */
    if (ASN1_INTEGER_cmp(newer->crl_number, base->crl_number) <= 0) {
        ERR_raise(ERR_LIB_X509, X509_R_NEWER_CRL_NOT_NEWER);
        return NULL;
    }
    /* CRLs must verify */
    if (skey != NULL && (X509_CRL_verify(base, skey) <= 0 ||
                         X509_CRL_verify(newer, skey) <= 0)) {
        ERR_raise(ERR_LIB_X509, X509_R_CRL_VERIFY_FAILURE);
        return NULL;
    }
    /* Create new CRL */
    crl = X509_CRL_new_ex(base->libctx, base->propq);
    if (crl == NULL || !X509_CRL_set_version(crl, X509_CRL_VERSION_2))
        goto memerr;
    /* Set issuer name */
    if (!X509_CRL_set_issuer_name(crl, X509_CRL_get_issuer(newer)))
        goto memerr;

    if (!X509_CRL_set1_lastUpdate(crl, X509_CRL_get0_lastUpdate(newer)))
        goto memerr;
    if (!X509_CRL_set1_nextUpdate(crl, X509_CRL_get0_nextUpdate(newer)))
        goto memerr;

    /* Set base CRL number: must be critical */
    if (!X509_CRL_add1_ext_i2d(crl, NID_delta_crl, base->crl_number, 1, 0))
        goto memerr;

    /*
     * Copy extensions across from newest CRL to delta: this will set CRL
     * number to correct value too.
     */
    for (i = 0; i < X509_CRL_get_ext_count(newer); i++) {
        X509_EXTENSION *ext = X509_CRL_get_ext(newer, i);

        if (!X509_CRL_add_ext(crl, ext, -1))
            goto memerr;
    }

    /* Go through revoked entries, copying as needed */
    revs = X509_CRL_get_REVOKED(newer);

    for (i = 0; i < sk_X509_REVOKED_num(revs); i++) {
        X509_REVOKED *rvn, *rvtmp;

        rvn = sk_X509_REVOKED_value(revs, i);
        /*
         * Add only if not also in base.
         * Need something cleverer here for some more complex CRLs covering
         * multiple CAs.
         */
        if (!X509_CRL_get0_by_serial(base, &rvtmp, &rvn->serialNumber)) {
            rvtmp = X509_REVOKED_dup(rvn);
            if (rvtmp == NULL)
                goto memerr;
            if (!X509_CRL_add0_revoked(crl, rvtmp)) {
                X509_REVOKED_free(rvtmp);
                goto memerr;
            }
        }
    }

    if (skey != NULL && md != NULL && !X509_CRL_sign(crl, skey, md))
        goto memerr;

    return crl;

 memerr:
    ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
    X509_CRL_free(crl);
    return NULL;
}
static int addr_validate_path_internal(X509_STORE_CTX *ctx,
                                       STACK_OF(X509) *chain,
                                       IPAddrBlocks *ext)
{
    IPAddrBlocks *child = NULL;
    int i, j, ret = 1;
    X509 *x;

    if (!ossl_assert(chain != NULL && sk_X509_num(chain) > 0)
            || !ossl_assert(ctx != NULL || ext != NULL)
            || !ossl_assert(ctx == NULL || ctx->verify_cb != NULL)) {
        if (ctx != NULL)
            ctx->error = X509_V_ERR_UNSPECIFIED;
        return 0;
    }

    /*
     * Figure out where to start.  If we don't have an extension to
     * check, we're done.  Otherwise, check canonical form and
     * set up for walking up the chain.
     */
    if (ext != NULL) {
        i = -1;
        x = NULL;
    } else {
        i = 0;
        x = sk_X509_value(chain, i);
        if ((ext = x->rfc3779_addr) == NULL)
            goto done;
    }
    if (!X509v3_addr_is_canonical(ext))
        validation_err(X509_V_ERR_INVALID_EXTENSION);
    (void)sk_IPAddressFamily_set_cmp_func(ext, IPAddressFamily_cmp);
    if ((child = sk_IPAddressFamily_dup(ext)) == NULL) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        if (ctx != NULL)
            ctx->error = X509_V_ERR_OUT_OF_MEM;
        ret = 0;
        goto done;
    }

    /*
     * Now walk up the chain.  No cert may list resources that its
     * parent doesn't list.
     */
    for (i++; i < sk_X509_num(chain); i++) {
        x = sk_X509_value(chain, i);
        if (!X509v3_addr_is_canonical(x->rfc3779_addr))
            validation_err(X509_V_ERR_INVALID_EXTENSION);
        if (x->rfc3779_addr == NULL) {
            for (j = 0; j < sk_IPAddressFamily_num(child); j++) {
                IPAddressFamily *fc = sk_IPAddressFamily_value(child, j);
                if (fc->ipAddressChoice->type != IPAddressChoice_inherit) {
                    validation_err(X509_V_ERR_UNNESTED_RESOURCE);
                    break;
                }
            }
            continue;
        }
        (void)sk_IPAddressFamily_set_cmp_func(x->rfc3779_addr,
                                              IPAddressFamily_cmp);
        for (j = 0; j < sk_IPAddressFamily_num(child); j++) {
            IPAddressFamily *fc = sk_IPAddressFamily_value(child, j);
            int k = sk_IPAddressFamily_find(x->rfc3779_addr, fc);
            IPAddressFamily *fp =
                sk_IPAddressFamily_value(x->rfc3779_addr, k);
            if (fp == NULL) {
                if (fc->ipAddressChoice->type ==
                    IPAddressChoice_addressesOrRanges) {
                    validation_err(X509_V_ERR_UNNESTED_RESOURCE);
                    break;
                }
                continue;
            }
            if (fp->ipAddressChoice->type ==
                IPAddressChoice_addressesOrRanges) {
                if (fc->ipAddressChoice->type == IPAddressChoice_inherit
                    || addr_contains(fp->ipAddressChoice->u.addressesOrRanges,
                                     fc->ipAddressChoice->u.addressesOrRanges,
                                     length_from_afi(X509v3_addr_get_afi(fc))))
                    (void)sk_IPAddressFamily_set(child, j, fp);
                else
                    validation_err(X509_V_ERR_UNNESTED_RESOURCE);
            }
        }
    }

    /*
     * Trust anchor can't inherit.
     */
    if (x->rfc3779_addr != NULL) {
        for (j = 0; j < sk_IPAddressFamily_num(x->rfc3779_addr); j++) {
            IPAddressFamily *fp =
                sk_IPAddressFamily_value(x->rfc3779_addr, j);
            if (fp->ipAddressChoice->type == IPAddressChoice_inherit
                && sk_IPAddressFamily_find(child, fp) >= 0)
                validation_err(X509_V_ERR_UNNESTED_RESOURCE);
        }
    }

 done:
    sk_IPAddressFamily_free(child);
    return ret;
}

# define X509_LOOKUP_load_file(x,name,type) \
                X509_LOOKUP_ctrl((x),X509_L_FILE_LOAD,(name),(long)(type),NULL)

int EVP_PKEY_get_octet_string_param(const EVP_PKEY *pkey, const char *key_name,
                                    unsigned char *buf, size_t max_buf_sz,
                                    size_t *out_len)
{
    OSSL_PARAM params[2];
    int ret1 = 0, ret2 = 0;

    if (key_name == NULL)
        return 0;

    params[0] = OSSL_PARAM_construct_octet_string(key_name, buf, max_buf_sz);
    params[1] = OSSL_PARAM_construct_end();
    if ((ret1 = EVP_PKEY_get_params(pkey, params)))
        ret2 = OSSL_PARAM_modified(params);
    if (ret2 && out_len != NULL)
        *out_len = params[0].return_size;
    return ret1 && ret2;
}



static int setup(void)
{
    OPTION_CHOICE o;
    char *arg;
    char *colon;
    char *endptr;
    size_t idx, indent;
    const char *progname = opt_getprog();

    bio_in = BIO_new_fp(stdin, BIO_NOCLOSE | BIO_FP_TEXT);
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
#ifdef __VMS
    bio_out = BIO_push(BIO_new(BIO_f_linebuffer()), bio_out);
    bio_err = BIO_push(BIO_new(BIO_f_linebuffer()), bio_err);
#endif

    OPENSSL_assert(bio_in != NULL);
    OPENSSL_assert(bio_out != NULL);
    OPENSSL_assert(bio_err != NULL);


    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_AMOUNT:
            arg = opt_arg();
            amount = strtoul(arg, &endptr, 10);
            if (endptr[0] != '\0') {
                BIO_printf(bio_err,
                           "%s: -n argument isn't a decimal number: %s",
                           progname, arg);
                return 0;
            }
            if (amount < 1) {
                BIO_printf(bio_err, "%s: must set up at least one filter",
                           progname);
                return 0;
            }
            if (!setup_bio_chain(progname)) {
                BIO_printf(bio_err, "%s: failed setting up filter chain",
                           progname);
                return 0;
            }
            break;
        case OPT_INDENT:
            if (chain == NULL) {
                BIO_printf(bio_err, "%s: -i given before -n", progname);
                return 0;
            }
            arg = opt_arg();
            colon = strchr(arg, ':');
            idx = 0;
            if (colon != NULL) {
                idx = strtoul(arg, &endptr, 10);
                if (endptr[0] != ':') {
                    BIO_printf(bio_err,
                               "%s: -i index isn't a decimal number: %s",
                               progname, arg);
                    return 0;
                }
                colon++;
            } else {
                colon = arg;
            }
            indent = strtoul(colon, &endptr, 10);
            if (endptr[0] != '\0') {
                BIO_printf(bio_err,
                           "%s: -i value isn't a decimal number: %s",
                           progname, arg);
                return 0;
            }
            if (idx >= amount) {
                BIO_printf(bio_err, "%s: index (%zu) not within range 0..%zu",
                           progname, idx, amount - 1);
                return 0;
            }
            if (!BIO_set_indent(chain[idx], (long)indent)) {
                BIO_printf(bio_err, "%s: failed setting indentation: %s",
                           progname, arg);
                return 0;
            }
            break;
        case OPT_PREFIX:
            if (chain == NULL) {
                BIO_printf(bio_err, "%s: -p given before -n", progname);
                return 0;
            }
            arg = opt_arg();
            colon = strchr(arg, ':');
            idx = 0;
            if (colon != NULL) {
                idx = strtoul(arg, &endptr, 10);
                if (endptr[0] != ':') {
                    BIO_printf(bio_err,
                               "%s: -p index isn't a decimal number: %s",
                               progname, arg);
                    return 0;
                }
                colon++;
            } else {
                colon = arg;
            }
            if (idx >= amount) {
                BIO_printf(bio_err, "%s: index (%zu) not within range 0..%zu",
                           progname, idx, amount - 1);
                return 0;
            }
            if (!BIO_set_prefix(chain[idx], colon)) {
                BIO_printf(bio_err, "%s: failed setting prefix: %s",
                           progname, arg);
                return 0;
            }
            break;
        default:
        case OPT_ERR:
            return 0;
        }
    }
    return 1;
}

static int asn1_template_noexp_d2i(ASN1_VALUE **val,
                                   const unsigned char **in, long len,
                                   const ASN1_TEMPLATE *tt, char opt,
                                   ASN1_TLC *ctx, int depth,
                                   OSSL_LIB_CTX *libctx, const char *propq)
{
    int flags, aclass;
    int ret;
    ASN1_VALUE *tval;
    const unsigned char *p, *q;
    if (!val)
        return 0;
    flags = tt->flags;
    aclass = flags & ASN1_TFLG_TAG_CLASS;

    p = *in;

    /*
     * If field is embedded then val needs fixing so it is a pointer to
     * a pointer to a field.
     */
    if (tt->flags & ASN1_TFLG_EMBED) {
        tval = (ASN1_VALUE *)val;
        val = &tval;
    }

    if (flags & ASN1_TFLG_SK_MASK) {
        /* SET OF, SEQUENCE OF */
        int sktag, skaclass;
        char sk_eoc;
        /* First work out expected inner tag value */
        if (flags & ASN1_TFLG_IMPTAG) {
            sktag = tt->tag;
            skaclass = aclass;
        } else {
            skaclass = V_ASN1_UNIVERSAL;
            if (flags & ASN1_TFLG_SET_OF)
                sktag = V_ASN1_SET;
            else
                sktag = V_ASN1_SEQUENCE;
        }
        /* Get the tag */
        ret = asn1_check_tlen(&len, NULL, NULL, &sk_eoc, NULL,
                              &p, len, sktag, skaclass, opt, ctx);
        if (!ret) {
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            return 0;
        } else if (ret == -1)
            return -1;
        if (*val == NULL)
            *val = (ASN1_VALUE *)sk_ASN1_VALUE_new_null();
        else {
            /*
             * We've got a valid STACK: free up any items present
             */
            STACK_OF(ASN1_VALUE) *sktmp = (STACK_OF(ASN1_VALUE) *)*val;
            ASN1_VALUE *vtmp;
            while (sk_ASN1_VALUE_num(sktmp) > 0) {
                vtmp = sk_ASN1_VALUE_pop(sktmp);
                ASN1_item_ex_free(&vtmp, ASN1_ITEM_ptr(tt->item));
            }
        }

        if (*val == NULL) {
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /* Read as many items as we can */
        while (len > 0) {
            ASN1_VALUE *skfield;
            q = p;
            /* See if EOC found */
            if (asn1_check_eoc(&p, len)) {
                if (!sk_eoc) {
                    ERR_raise(ERR_LIB_ASN1, ASN1_R_UNEXPECTED_EOC);
                    goto err;
                }
                len -= p - q;
                sk_eoc = 0;
                break;
            }
            skfield = NULL;
            if (!asn1_item_embed_d2i(&skfield, &p, len,
                                     ASN1_ITEM_ptr(tt->item), -1, 0, 0, ctx,
                                     depth, libctx, propq)) {
                ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
                /* |skfield| may be partially allocated despite failure. */
                ASN1_item_free(skfield, ASN1_ITEM_ptr(tt->item));
                goto err;
            }
            len -= p - q;
            if (!sk_ASN1_VALUE_push((STACK_OF(ASN1_VALUE) *)*val, skfield)) {
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                ASN1_item_free(skfield, ASN1_ITEM_ptr(tt->item));
                goto err;
            }
        }
        if (sk_eoc) {
            ERR_raise(ERR_LIB_ASN1, ASN1_R_MISSING_EOC);
            goto err;
        }
    } else if (flags & ASN1_TFLG_IMPTAG) {
        /* IMPLICIT tagging */
        ret = asn1_item_embed_d2i(val, &p, len,
                                  ASN1_ITEM_ptr(tt->item), tt->tag, aclass, opt,
                                  ctx, depth, libctx, propq);
        if (!ret) {
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            goto err;
        } else if (ret == -1)
            return -1;
    } else {
        /* Nothing special */
        ret = asn1_item_embed_d2i(val, &p, len, ASN1_ITEM_ptr(tt->item),
                                  -1, 0, opt, ctx, depth, libctx, propq);
        if (!ret) {
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            goto err;
        } else if (ret == -1)
            return -1;
    }

    *in = p;
    return 1;

 err:
    return 0;
}


static int RAND_bytes_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    int count, n;

    for (count = 0; COND(c[D_RAND][testnum]); count++)
        RAND_bytes(buf, lengths[testnum]);
    return count;
}

int func() {
    int ret = 0;

    ret = func();
    
    if (ret < 0 || !ret ) {}
    if ((ret = func1()) < 0){}
    if (ret = func2()){}
    if (!(ret = func3())){}
    return 1;
}

static int setup_verification_ctx(OSSL_CMP_CTX *ctx)
{
    if (!setup_certs(opt_untrusted, "untrusted certificates", ctx,
                     (add_X509_stack_fn_t)OSSL_CMP_CTX_set1_untrusted))
        return 0;

    if (opt_srvcert != NULL || opt_trusted != NULL) {
        X509 *srvcert;
        X509_STORE *ts;
        int ok;

        if (opt_srvcert != NULL) {
            if (opt_trusted != NULL) {
                CMP_warn("-trusted option is ignored since -srvcert option is present");
                opt_trusted = NULL;
            }
            if (opt_recipient != NULL) {
                CMP_warn("-recipient option is ignored since -srvcert option is present");
                opt_recipient = NULL;
            }
            srvcert = load_cert_pwd(opt_srvcert, opt_otherpass,
                                    "directly trusted CMP server certificate");
            ok = srvcert != NULL && OSSL_CMP_CTX_set1_srvCert(ctx, srvcert);
            X509_free(srvcert);
            if (!ok)
                return 0;
        }
        if (opt_trusted != NULL) {
            /*
             * the 0 arg below clears any expected host/ip/email address;
             * opt_expect_sender is used instead
             */
            ts = load_trusted(opt_trusted, 0, "certs trusted by client");

            if (ts == NULL || !OSSL_CMP_CTX_set0_trusted(ctx, ts)) {
                X509_STORE_free(ts);
                return 0;
            }
        }
    }

    if (opt_ignore_keyusage)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IGNORE_KEYUSAGE, 1);

    if (opt_unprotected_errors)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_UNPROTECTED_ERRORS, 1);

    if (opt_out_trusted != NULL) { /* for use in OSSL_CMP_certConf_cb() */
        X509_VERIFY_PARAM *out_vpm = NULL;
        X509_STORE *out_trusted =
            load_trusted(opt_out_trusted, 1,
                         "trusted certs for verifying newly enrolled cert");

        if (out_trusted == NULL)
            return 0;
        /* ignore any -attime here, new certs are current anyway */
        out_vpm = X509_STORE_get0_param(out_trusted);
        X509_VERIFY_PARAM_clear_flags(out_vpm, X509_V_FLAG_USE_CHECK_TIME);

        (void)OSSL_CMP_CTX_set_certConf_cb_arg(ctx, out_trusted);
    }

    if (opt_disable_confirm)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_DISABLE_CONFIRM, 1);

    if (opt_implicit_confirm)
        (void)OSSL_CMP_CTX_set_option(ctx, OSSL_CMP_OPT_IMPLICIT_CONFIRM, 1);

    return 1;
}


int nseq_main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL;
    X509 *x509 = NULL;
    NETSCAPE_CERT_SEQUENCE *seq = NULL;
    OPTION_CHOICE o;
    int toseq = 0, ret = 1, i;
    char *infile = NULL, *outfile = NULL, *prog;

    prog = opt_init(argc, argv, nseq_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(nseq_options);
            goto end;
        case OPT_TOSEQ:
            toseq = 1;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                goto end;
            break;
        }
    }

    /* No extra arguments. */
    if (!opt_check_rest_arg(NULL))
        goto opthelp;

    in = bio_open_default(infile, 'r', FORMAT_PEM);
    if (in == NULL)
        goto end;
    out = bio_open_default(outfile, 'w', FORMAT_PEM);
    if (out == NULL)
        goto end;

    if (toseq) {
        seq = NETSCAPE_CERT_SEQUENCE_new();
        if (seq == NULL)
            goto end;
        seq->certs = sk_X509_new_null();
        if (seq->certs == NULL)
            goto end;
        while ((x509 = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
            if (!sk_X509_push(seq->certs, x509))
                goto end;
        }

        if (!sk_X509_num(seq->certs)) {
            BIO_printf(bio_err, "%s: Error reading certs file %s\n",
                       prog, infile);
            ERR_print_errors(bio_err);
            goto end;
        }
        PEM_write_bio_NETSCAPE_CERT_SEQUENCE(out, seq);
        ret = 0;
        goto end;
    }

    seq = PEM_read_bio_NETSCAPE_CERT_SEQUENCE(in, NULL, NULL, NULL);
    if (seq == NULL) {
        BIO_printf(bio_err, "%s: Error reading sequence file %s\n",
                   prog, infile);
        ERR_print_errors(bio_err);
        goto end;
    }

    for (i = 0; i < sk_X509_num(seq->certs); i++) {
        x509 = sk_X509_value(seq->certs, i);
        dump_cert_text(out, x509);
        PEM_write_bio_X509(out, x509);
    }
    ret = 0;
 end:
    BIO_free(in);
    BIO_free_all(out);
    NETSCAPE_CERT_SEQUENCE_free(seq);

    return ret;
}