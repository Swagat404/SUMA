/***************************************************************************
 *                                  _____ __  __ 
 *  Project                        / ____|  \/  |
 *                                | (___  | \  / |
 *                                 \___ \ | |\/| |
 *                                 ____) || |  | |
 *                                |_____/ |_|  |_|
 *
 * Project Suma
 * 
 * Copyright (C) <your.email@example.com>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * should be included as part of this distribution. The terms
 * are also available at [https://yourprojecturl.example.com/license].
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: [your-spdx-identifier]
 *
 ***************************************************************************/

#include "sql3.h"
#include <string.h>
#include <stdio.h>
#include <pthread.h>


static sql3_connection g_sql3_conn = {0, NULL};
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;


int sql3_init(const char *filename, int db_flags, const char *zVfs) {
    
    int rc;
    if (g_sql3_conn.hd != NULL){
        return SQLITE_OK;
    }

    pthread_mutex_lock(&g_mutex);   
    rc = sqlite3_config(SQLITE_CONFIG_MULTITHREAD);    /* Configure for serialized threading mode*/
    
    if (rc != SQLITE_OK) {               
        printf("Configuring sqlite3 in SQLITE_CONFIG_MULTITHREAD mode failed");   /*Check if configuration was successful*/
        pthread_mutex_unlock(&g_mutex);                 
        return rc;
    }

    rc = sqlite3_open_v2(                                /*Open database connection*/
        filename, 
        &g_sql3_conn.hd, 
        db_flags | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
        zVfs
        );


    if (rc != SQLITE_OK) {
        const char* err = sqlite3_errmsg(g_sql3_conn.hd);
        printf("Error:%s\n", err);
        pthread_mutex_unlock(&g_mutex);
        return rc;
    }
    
    pthread_mutex_unlock(&g_mutex);
    return SQLITE_OK;
}



int sql3_destroy() {
    int rc;
    pthread_mutex_lock(&g_mutex);
    
    // Check if there's an active connection
    if (g_sql3_conn.hd == NULL) {
        pthread_mutex_unlock(&g_mutex);
        return SQLITE_OK;  // Nothing to destroy
    }
    
    // Close database connection
    rc = sqlite3_close(g_sql3_conn.hd);
    if (rc == SQLITE_OK) {
        g_sql3_conn.hd = NULL;
    }
    
    pthread_mutex_unlock(&g_mutex);
    return rc;
}


int sql3_get_connection(sqlite3 **db) {

    if (!db) {
        return SQLITE_ERROR;
    }
    
    
    if (g_sql3_conn.hd == NULL || g_sql3_conn.active_connections >= MAX_CLIENT) {
        pthread_mutex_unlock(&g_mutex);
        return SQLITE_ERROR;
    }
    

    g_sql3_conn.active_connections++;
    *db = g_sql3_conn.hd;

    return SQLITE_OK;
}

int sql3_release_connection() {
    pthread_mutex_lock(&g_mutex);
    
    if (g_sql3_conn.active_connections > 0) {
        g_sql3_conn.active_connections--;
    }
    
    pthread_mutex_unlock(&g_mutex);
    return SQLITE_OK;
}


/*
need to optimize here by making prepared statements and re-using them
*/
int sql3_insert(sqlite3 *db, const char *table_name, const char *column_names, const char *values) {
    char *sql;
    char *err_msg = 0;
    int rc;
    
    if (!db || !table_name || !column_names || !values) {
        return SQLITE_ERROR;
    }
    
    // Construct INSERT query
    sql = sqlite3_mprintf("INSERT INTO %s (%s) VALUES (%s);", table_name, column_names, values);
    if (!sql) {
        return SQLITE_NOMEM;
    }
    
    // Execute query
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
    }
    
    sqlite3_free(sql);
    return rc;
}

int sql3_update(sqlite3 *db, const char *table_name, const char *column_names, const char *values, const char *condition) {
    char *sql;
    char *err_msg = 0;
    int rc;
    
    if (!db || !table_name || !column_names || !values) {
        return SQLITE_ERROR;
    }
    
    // Construct UPDATE query
    if (condition) {
        sql = sqlite3_mprintf("UPDATE %s SET %s = %s WHERE %s;", table_name, column_names, values, condition);
    } else {
        sql = sqlite3_mprintf("UPDATE %s SET %s = %s;", table_name, column_names, values);
    }
    
    if (!sql) {
        return SQLITE_NOMEM;
    }
    
    // Execute query
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
    }
    
    sqlite3_free(sql);
    return rc;
}

int sql3_delete(sqlite3 *db, const char *table_name, const char *condition) {
    char *sql;
    char *err_msg = 0;
    int rc;
    
    if (!db || !table_name) {
        return SQLITE_ERROR;
    }
    
    // Construct DELETE query
    if (condition) {
        sql = sqlite3_mprintf("DELETE FROM %s WHERE %s;", table_name, condition);
    } else {
        sql = sqlite3_mprintf("DELETE FROM %s;", table_name);
    }
    
    if (!sql) {
        return SQLITE_NOMEM;
    }
    
    // Execute query
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
    }
    
    sqlite3_free(sql);
    return rc;
}

int sql3_select(
    sqlite3 *db,
    const char *table_name,
    const char *column_names,
    const char *condition,
    int (*callback)(void*, int, char**, char**),
    void *arg) {
    
    char *sql = NULL;
    char *err_msg = NULL;
    int rc;
    
    if(condition){
        sql = sqlite3_mprintf("SELECT %s FROM %s WHERE %s;", column_names, table_name, condition);
    } else {
        sql = sqlite3_mprintf("SELECT %s FROM %s;", column_names, table_name);
    }
    
    if (!sql) {
        return SQLITE_NOMEM;
    }
    
    rc = sqlite3_exec(db, sql, callback, arg, &err_msg);
    
    sqlite3_free(sql);
    if (err_msg) {
        sqlite3_free(err_msg);
    }
    
    return rc;
}