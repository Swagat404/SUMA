#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "sql3.h"

#define MAX_CONNECTIONS 100
#define DEFAULT_IDLE_CONNECTIONS 10

// Global state
static sql3_info g_sql3_info = {0, 0, 0, NULL};
static sqlite3 *g_db = NULL;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

int sql3_init(
    int sql3_config,
    int db_flags,
    const char *filename,
    sqlite3 **ppDb,
    const char *zVfs) {
    
    int rc;
    
    // Initialize SQLite
    sqlite3_config(sql3_config);
    rc = sqlite3_initialize();
    if (rc != SQLITE_OK) {
        return rc;
    }
    
    // Open database connection
    rc = sqlite3_open_v2(filename, ppDb, db_flags, zVfs);
    if (rc != SQLITE_OK) {
        sqlite3_close(*ppDb);
        return rc;
    }
    
    g_db = *ppDb;
    
    // Initialize connection pool
    g_sql3_info.connections_count = 0;
    g_sql3_info.idle_connections = 0;
    g_sql3_info.mutex_blocking = 0;
    g_sql3_info.connections = NULL;
    
    // Create initial idle connections
    return sql3_init_idle_connection(&g_sql3_info.connections, DEFAULT_IDLE_CONNECTIONS);
}

int sql3_destroy() {
    sql3_open_connections *current = g_sql3_info.connections;
    sql3_open_connections *next;
    
    // Close all connections
    while (current != NULL) {
        next = current->next;
        if (current->db) {
            sqlite3_close(current->db);
        }
        free(current);
        current = next;
    }
    
    // Reset global state
    g_sql3_info.connections = NULL;
    g_sql3_info.connections_count = 0;
    g_sql3_info.idle_connections = 0;
    g_sql3_info.mutex_blocking = 0;
    
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }
    
    sqlite3_shutdown();
    return SQLITE_OK;
}

int sql3_get_connection(sqlite3 **db) {
    int rc = SQLITE_OK;
    sql3_open_connections *conn;
    
    pthread_mutex_lock(&g_mutex);
    
    if (g_sql3_info.mutex_blocking) {
        pthread_mutex_unlock(&g_mutex);
        return SQLITE_BUSY;
    }
    
    // Find an idle connection
    conn = g_sql3_info.connections;
    while (conn != NULL) {
        if (conn->db != NULL) {
            *db = conn->db;
            conn->db = NULL;
            g_sql3_info.idle_connections--;
            pthread_mutex_unlock(&g_mutex);
            return SQLITE_OK;
        }
        conn = conn->next;
    }
    
    // If no idle connections and under MAX_CONNECTIONS, create new one
    if (g_sql3_info.connections_count < MAX_CONNECTIONS) {
        rc = sqlite3_open(sqlite3_db_filename(g_db, "main"), db);
        if (rc == SQLITE_OK) {
            g_sql3_info.connections_count++;
        }
    } else {
        rc = SQLITE_ERROR;
    }
    
    pthread_mutex_unlock(&g_mutex);
    return rc;
}

int sql3_block_mutex() {
    pthread_mutex_lock(&g_mutex);
    g_sql3_info.mutex_blocking = 1;
    
    // Close all connections
    sql3_open_connections *current = g_sql3_info.connections;
    while (current != NULL) {
        if (current->db) {
            sqlite3_close(current->db);
            current->db = NULL;
        }
        current = current->next;
    }
    
    pthread_mutex_unlock(&g_mutex);
    return SQLITE_OK;
}

int sql3_unlock_mutex() {
    int rc = SQLITE_OK;
    pthread_mutex_lock(&g_mutex);
    
    if (!g_sql3_info.mutex_blocking) {
        pthread_mutex_unlock(&g_mutex);
        return SQLITE_ERROR;
    }
    
    // Reopen connections
    sql3_open_connections *current = g_sql3_info.connections;
    while (current != NULL && rc == SQLITE_OK) {
        if (current->db == NULL) {
            rc = sqlite3_open(sqlite3_db_filename(g_db, "main"), &current->db);
            if (rc == SQLITE_OK) {
                g_sql3_info.idle_connections++;
            }
        }
        current = current->next;
    }
    
    g_sql3_info.mutex_blocking = 0;
    pthread_mutex_unlock(&g_mutex);
    return rc;
}

int sql3_init_idle_connection(sql3_open_connections **connections, int idle_connections_batch_size) {
    int rc = SQLITE_OK;
    
    pthread_mutex_lock(&g_mutex);
    
    for (int i = 0; i < idle_connections_batch_size && rc == SQLITE_OK; i++) {
        sql3_open_connections *new_conn = malloc(sizeof(sql3_open_connections));
        if (!new_conn) {
            rc = SQLITE_NOMEM;
            break;
        }
        
        rc = sqlite3_open(sqlite3_db_filename(g_db, "main"), &new_conn->db);
        if (rc == SQLITE_OK) {
            new_conn->next = *connections;
            *connections = new_conn;
            g_sql3_info.connections_count++;
            g_sql3_info.idle_connections++;
        } else {
            free(new_conn);
        }
    }
    
    pthread_mutex_unlock(&g_mutex);
    return rc;
}

int sql3_close_idle_connection(sql3_open_connections **connections, int idle_connections_batch_size) {
    pthread_mutex_lock(&g_mutex);
    
    sql3_open_connections *current = *connections;
    sql3_open_connections *prev = NULL;
    int closed = 0;
    
    while (current != NULL && g_sql3_info.idle_connections > idle_connections_batch_size) {
        if (current->db != NULL) {
            sqlite3_close(current->db);
            
            if (prev == NULL) {
                *connections = current->next;
                free(current);
                current = *connections;
            } else {
                prev->next = current->next;
                free(current);
                current = prev->next;
            }
            
            g_sql3_info.connections_count--;
            g_sql3_info.idle_connections--;
            closed++;
        } else {
            prev = current;
            current = current->next;
        }
    }
    
    pthread_mutex_unlock(&g_mutex);
    return SQLITE_OK;
}

int sql3_insert_data(
    sqlite3 *db,
    const char *table_name,
    const char *column_names,
    const char *values) {
    
    char *sql = NULL;
    char *err_msg = NULL;
    int rc;
    
    sql = sqlite3_mprintf("INSERT INTO %s (%s) VALUES (%s);",
                         table_name, column_names, values);
    
    if (!sql) {
        return SQLITE_NOMEM;
    }
    
    rc = sqlite3_exec(db, sql, NULL, NULL, &err_msg);
    
    sqlite3_free(sql);
    if (err_msg) {
        sqlite3_free(err_msg);
    }
    
    return rc;
}

int sql3_update_data(
    sqlite3 *db,
    const char *table_name,
    const char *column_names,
    const char *values,
    const char *condition) {
    
    char *sql = NULL;
    char *err_msg = NULL;
    int rc;
    
    sql = sqlite3_mprintf("UPDATE %s SET %s = %s WHERE %s;",
                         table_name, column_names, values, condition);
    
    if (!sql) {
        return SQLITE_NOMEM;
    }
    
    rc = sqlite3_exec(db, sql, NULL, NULL, &err_msg);
    
    sqlite3_free(sql);
    if (err_msg) {
        sqlite3_free(err_msg);
    }
    
    return rc;
}

int sql3_delete_data(
    sqlite3 *db,
    const char *table_name,
    const char *condition) {
    
    char *sql = NULL;
    char *err_msg = NULL;
    int rc;
    
    sql = sqlite3_mprintf("DELETE FROM %s WHERE %s;",
                         table_name, condition);
    
    if (!sql) {
        return SQLITE_NOMEM;
    }
    
    rc = sqlite3_exec(db, sql, NULL, NULL, &err_msg);
    
    sqlite3_free(sql);
    if (err_msg) {
        sqlite3_free(err_msg);
    }
    
    return rc;
}

int sql3_select_data(
    sqlite3 *db,
    const char *table_name,
    const char *column_names,
    const char *condition,
    int (*callback)(void*, int, char**, char**),
    void *arg) {
    
    char *sql = NULL;
    char *err_msg = NULL;
    int rc;
    
    sql = sqlite3_mprintf("SELECT %s FROM %s WHERE %s;",
                         column_names, table_name, condition);
    
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