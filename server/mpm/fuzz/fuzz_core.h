#ifndef APACHE_MPM_FUZZ_TYPES_H
#define APACHE_MPM_FUZZ_TYPES_H

int fuzz_main_loop(apr_pool_t * pconf, apr_pool_t * plog, server_rec * s);

typedef struct fuzz_conn_t fuzz_conn_t;
struct fuzz_conn_t
{
    apr_pool_t *pool;
    apr_socket_t *sock;
    apr_bucket_alloc_t *ba;
    conn_rec *c;

    conn_state_t cs;

    apr_thread_t *input_thread;
    apr_pool_t *input_pool;
    apr_socket_t *client_sock;
    int input_fd;
};


#endif /* APACHE_MPM_FUZZ_CORE_H */
