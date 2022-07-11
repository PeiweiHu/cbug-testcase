# define X509_LOOKUP_load_file(x,name,type) \
                X509_LOOKUP_ctrl((x),X509_L_FILE_LOAD,(name),(long)(type),NULL)

# define BIO_set_write_buf_size(b,size) (int)BIO_ctrl(b,BIO_C_SET_WRITE_BUF_SIZE,size,NULL)

#  define BIO_get_ktls_send(b)         \
     BIO_ctrl(b, BIO_CTRL_GET_KTLS_SEND, 0, NULL)

# ifndef OPENSSL_NO_KTLS
#  define BIO_get_ktls_send(b)         \
     BIO_ctrl(b, BIO_CTRL_GET_KTLS_SEND, 0, NULL)
#  define BIO_get_ktls_recv(b)         \
     BIO_ctrl(b, BIO_CTRL_GET_KTLS_RECV, 0, NULL)
# else
#  define BIO_get_ktls_send(b)  (0)
#  define BIO_get_ktls_recv(b)  (0)
# endif
