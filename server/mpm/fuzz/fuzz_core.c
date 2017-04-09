/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ap_mpm.h"
#include "httpd.h"
#include "http_config.h"
#include "mpm_common.h"
#include "http_log.h"
#include "scoreboard.h"
#include "ap_listen.h"

#include "fuzz_core.h"

#include "http_core.h"
#include "http_connection.h"
#include "http_main.h"
#include "http_vhost.h"

#include <unistd.h>

static apr_status_t fuzz_run_conn(fuzz_conn_t *fcon) {
    int rv;
    ap_sb_handle_t *sbh;
    long conn_id = 0;

    ap_create_sb_handle(&sbh, fcon->pool, 0, 0);

    fcon->c = ap_run_create_connection(fcon->pool, ap_server_conf, fcon->sock,
                                       conn_id, sbh, fcon->ba);
    if (fcon->c == NULL) {
        abort();
    }

    fcon->c->cs = &fcon->cs;

    ap_update_vhost_given_ip(fcon->c);

    rv = ap_run_pre_connection(fcon->c, fcon->sock);
    if (rv != OK && rv != DONE) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(0)
                     "fuzz_run_conn: connection aborted");
        fcon->c->aborted = 1;
    }

    ap_run_process_connection(fcon->c);

    ap_lingering_close(fcon->c);

    return APR_SUCCESS;
}

static apr_status_t apr__socket_pair(apr_pool_t *p, apr_socket_t **a, apr_socket_t **b) {
    apr_socket_t *listener;
    apr_sockaddr_t *bind_addr;
    int rv;

    *a = NULL;
    *b = NULL;


    rv = apr_sockaddr_info_get(&bind_addr, "127.0.0.1", APR_UNSPEC, 0, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, rv, p, APLOGNO(0)
                        "apr__socket_pair: apr_sockaddr_info_get failed");
        return rv;
    }

    rv = apr_socket_create(&listener, AF_INET, SOCK_STREAM, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, rv, p, APLOGNO(0)
                        "apr__socket_pair: apr_socket_create/listener %pI",
                        bind_addr);
        return rv;
    }

    rv = apr_socket_bind(listener, bind_addr);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, rv, p, APLOGNO(0)
                        "apr__socket_pair: apr_socket_bind failed %pI",
                        bind_addr);
        return rv;
    }

    rv = apr_socket_listen(listener, 1);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, rv, p, APLOGNO(0)
                        "apr__socket_pair: unable to listen for connections on address %pI",
                        bind_addr);
        return rv;
    }

    rv = apr_socket_addr_get(&bind_addr, APR_LOCAL, listener);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, rv, p, APLOGNO(0)
                        "apr__socket_pair: apr_socket_addr_get %pI",
                        bind_addr);
        return rv;
    }

    rv = apr_socket_create(b, AF_INET, SOCK_STREAM, 0, p);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, rv, p, APLOGNO(0)
                        "apr__socket_pair: apr_socket_create/b %pI",
                        bind_addr);
        return rv;
    }

    rv = apr_socket_connect(*b, bind_addr);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, rv, p, APLOGNO(0)
                        "apr__socket_pair: apr_socket_connect failed %pI",
                        bind_addr);
        return rv;
    }

    rv = apr_socket_accept(a, listener, p);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, rv, p, APLOGNO(0)
                        "apr__socket_pair: apr_socket_accept failed %pI",
                        bind_addr);
        return rv;
    }

    apr_socket_close(listener);

    return APR_SUCCESS;
}

static apr_status_t fuzz_start_input_thread(fuzz_conn_t *fcon);
static apr_status_t fuzz_wait_input_thread(fuzz_conn_t *fcon);

int fuzz_main_loop(apr_pool_t * pconf, apr_pool_t * plog, server_rec * s) {
    apr_status_t rv;

    // while (__AFL_LOOP(1)) {
    do {
        apr_pool_t *ptrans = NULL;

        /*
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(0)
                        "fuzz_main_loop: main loop start");
        */

        rv = apr_pool_create(&ptrans, pconf);
        if (rv != APR_SUCCESS) {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, rv, plog,
                         "fuzz_main_loop: ptrans pool_create failed");
            abort();
        }

        fuzz_conn_t *fcon = apr_pcalloc(ptrans, sizeof(fuzz_conn_t));
        fcon->pool = ptrans;
        fcon->ba = apr_bucket_alloc_create(fcon->pool);
        fcon->cs.state = CONN_STATE_READ_REQUEST_LINE;
        fcon->cs.sense = CONN_SENSE_DEFAULT;

        fcon->input_fd = 0; // stdin

        apr_socket_t *input;
        rv = apr__socket_pair(fcon->pool, &fcon->sock, &fcon->client_sock);
        if (rv != APR_SUCCESS) {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, rv, plog,
                         "fuzz_main_loop: apr_socket_pair failed");
            abort();
        }

        rv = fuzz_start_input_thread(fcon);
        if (rv != APR_SUCCESS) {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, rv, plog,
                         "fuzz_main_loop: fuzz_start_input_thread failed");
            abort();
        }

        /*
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(0)
                        "fuzz_main_loop: running conn");
        */
        rv = fuzz_run_conn(fcon);
        if (rv != APR_SUCCESS ) {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, rv, plog,
                         "fuzz_main_loop: fuzz_run_conn failed");
            abort();
        }

        /*
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(0)
                        "fuzz_main_loop: waiting for input thread");
        */
        rv = fuzz_wait_input_thread(fcon);
        if (rv != APR_SUCCESS) {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, rv, plog,
                         "fuzz_main_loop: fuzz_wait_input_thread failed");
            abort();
        }

        /*
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(0)
                        "fuzz_main_loop: done, cleanup");
        */
        apr_bucket_alloc_destroy(fcon->ba);
        apr_pool_destroy(ptrans);
    }  while(false);

    return OK;
}

static void *client_read_thread_func(apr_thread_t *t, void *v) {
    fuzz_conn_t *fcon = (fuzz_conn_t*) v;
    apr_status_t rv;

    while(true) {
        char buf[8096];
        apr_size_t nbytes = sizeof(buf);

        /* TODO(pquerna): save output somehwere? */
        rv = apr_socket_recv(fcon->client_sock,
            buf, &nbytes);

        if (rv != APR_SUCCESS) {
            if (rv == APR_EOF) {
                apr_socket_shutdown(fcon->client_sock,
                    APR_SHUTDOWN_READ);
                rv = APR_SUCCESS;
                break;
            } else {
                break;
            }
        }

        fwrite(buf, nbytes, 1, stdout);
        fflush(stdout);
    }

    return NULL;
}

static void *input_thread_func(apr_thread_t *t, void *v) {
    fuzz_conn_t *fcon = (fuzz_conn_t*) v;
    apr_pool_t *pool = fcon->input_pool;
    apr_status_t rv = APR_SUCCESS;
    apr_file_t *input = NULL;
    rv = apr_os_file_put(&input, &fcon->input_fd, APR_FOPEN_READ, pool);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_ERR, rv, pool, APLOGNO(0)
                        "input_thread_func: apr_os_file_put");
        return NULL;
    }

    apr_thread_t *read_thread;

    apr_thread_create(&read_thread,
        NULL,
        client_read_thread_func,
        fcon,
        fcon->input_pool);

    while(true) {
        char buf[8096];
        apr_size_t nbytes = sizeof(buf);
        rv = apr_file_read(input, buf, &nbytes);

        if (rv != APR_SUCCESS) {
            if (rv == APR_EOF) {
                apr_socket_shutdown(fcon->client_sock, APR_SHUTDOWN_WRITE);
                rv = APR_SUCCESS;
                break;
            } else {
                break;
            }
        }

        /*
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, 0, fcon->input_pool,
                        "client send size: %" APR_SIZE_T_FMT, nbytes);
         */
        rv = apr_socket_send(fcon->client_sock,
            buf, &nbytes);

        if (rv != APR_SUCCESS) {
            break;
        }
    }

    apr_status_t st = APR_SUCCESS;
    apr_thread_join(&st, read_thread);

    return NULL;
}

static apr_status_t fuzz_start_input_thread(fuzz_conn_t *fcon) {
    apr_status_t rv;

    rv = apr_pool_create(&fcon->input_pool, fcon->pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    return apr_thread_create(&fcon->input_thread,
        NULL,
        input_thread_func,
        fcon,
        fcon->pool);
}

static apr_status_t fuzz_wait_input_thread(fuzz_conn_t *fcon) {
    apr_status_t rv;
    apr_status_t st = APR_SUCCESS;

    close(fcon->input_fd);

    rv = apr_thread_join(&st, fcon->input_thread);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    return st;
}
