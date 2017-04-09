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

/* This file contains the absolute minimal MPM API, to interface with httpd. */

static int fuzz_run(apr_pool_t * pconf, apr_pool_t * plog, server_rec * s)
{
    __AFL_INIT();

    int rv;

    if (ap_run_pre_mpm(s->process->pool, SB_SHARED) != OK) {
        return !OK;
    }

    rv = fuzz_main_loop(pconf, plog, s);
    if (rv != 0) {
        exit(rv);
    }
    exit(rv);
    return rv;
}

static int fuzz_query(int query_code, int *result, apr_status_t *rv)
{
    *rv = APR_SUCCESS;
    switch (query_code) {
    case AP_MPMQ_IS_THREADED:
        *result = AP_MPMQ_STATIC;
        break;
    case AP_MPMQ_IS_FORKED:
        *result = AP_MPMQ_DYNAMIC;
        break;
    case AP_MPMQ_IS_ASYNC:
        *result = 1;
        break;
    case AP_MPMQ_MAX_DAEMON_USED:
        *result = 1;
        break;
    case AP_MPMQ_HARD_LIMIT_DAEMONS:
        *result = 1;
        break;
    case AP_MPMQ_HARD_LIMIT_THREADS:
        *result = 1;
        break;
    case AP_MPMQ_MAX_THREADS:
        *result = 1;;
        break;
    case AP_MPMQ_MAX_SPARE_DAEMONS:
        *result = 1;
        break;
    case AP_MPMQ_MIN_SPARE_DAEMONS:
        *result = 1;
        break;
    case AP_MPMQ_MIN_SPARE_THREADS:
    case AP_MPMQ_MAX_SPARE_THREADS:
        *result = 1;
        break;
    case AP_MPMQ_MAX_REQUESTS_DAEMON:
        *result = 1;
        break;
    case AP_MPMQ_MAX_DAEMONS:
        *result = 1;
        break;
    case AP_MPMQ_MPM_STATE:
        *result = AP_MPMQ_RUNNING;
        break;
    case AP_MPMQ_GENERATION:
        *result = 0;
        break;
    default:
        *rv = APR_ENOTIMPL;
        break;
    }
    return OK;
}

static const char *
fuzz_get_name(void)
{
    return "fuzz";
}

static int
fuzz_open_logs(apr_pool_t * p,
                 apr_pool_t * plog, apr_pool_t * ptemp, server_rec * s)
{
    int nsock;
    ap_sys_privileges_handlers(1);
    /* TODO(pquerna): is ap_setup_listeners needed at all? */
    nsock = ap_setup_listeners(s);
    return OK;
}

static int
fuzz_pre_config(apr_pool_t * pconf, apr_pool_t * plog, apr_pool_t * ptemp)
{
    return OK;
}

static int
fuzz_check_config(apr_pool_t * p, apr_pool_t * plog,
                    apr_pool_t * ptemp, server_rec * s)
{
    return OK;
}

static void fuzz_hooks(apr_pool_t * p)
{
    static const char *const aszSucc[] = { "core.c", NULL };

    ap_hook_open_logs(fuzz_open_logs, NULL, aszSucc, APR_HOOK_REALLY_FIRST);

    ap_hook_check_config(fuzz_check_config, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_mpm(fuzz_run, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_mpm_query(fuzz_query, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_mpm_get_name(fuzz_get_name, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec fuzz_cmds[] = {
    {NULL}
};



AP_DECLARE_MODULE(mpm_fuzz) = {
    MPM20_MODULE_STUFF,
    NULL,                       /* hook to run before apache parses args */
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    fuzz_cmds,                  /* command apr_table_t */
    fuzz_hooks                /* register_hooks */
};
