#ifndef SQL3_H
#define SQL3_H

#include <sqlite3.h>

// Forward declaration
struct sql3_open_connections;

struct sql3_open_connections {
    sqlite3 *db;
    struct sql3_open_connections *next;
};

struct sql3_info {
    int connections_count;
    int idle_connections;
    int mutex_blocking;
    struct sql3_open_connections *connections;
};

/*
Initialize sql3 library, database and a sql3_handler
@param sql3_config: configuration for the sql3 library
@param db_flags: flags for the database
@param filename: Database filename (UTF-8)
@param ppDb: OUT: SQLite db handle
@param zVfs: VFS name
@return SQLITE_OK on success, error code on failure
*/
int sql3_init(
    int sql3_config,
    int db_flags,
    const char *filename,
    sqlite3 **ppDb,
    const char *zVfs);

/*
Drains all open connections and deletes all resources allocated with sql3_init()
@return SQLITE_OK on success, error code on failure
*/
int sql3_destroy();

/*
This routine is thread safe. It assigns an idle connection from list of all open connections or
creates one a new connection if there aren't any idle connections and the number of open connections
is less than MAX_CONNECTIONS. If the number of open connections is equal to MAX_CONNECTIONS then it
returns the calling thread with an error.
@param db: OUT: SQLite db handle
@return SQLITE_OK on success, SQLITE_BUSY if blocked, SQLITE_ERROR if max connections reached
*/
int sql3_get_connection(sqlite3 **db);

/*
sql3_block_mutex closes all open connection to the database. This routine offers administrator to
manually linger with the database file stored on the disk. sql3_unlock_mutex() can be used to bring
the system back to normal. All connections that were open before sql3_block_mutex() was called will
be opened again and will be ready for use. [[Note: sql3_block_mutex() is not thread safe.]]
@return SQLITE_OK on success, error code on failure
*/
int sql3_block_mutex();

/*
Restores the system back to its original state once sql3_block_mutex() was called. This
routine is "effective" only if sql3_block_mutex() was called before. [[Note: sql3_unlock_mutex() is not thread safe.]]
@return SQLITE_OK on success, SQLITE_ERROR if mutex wasn't blocked
*/
int sql3_unlock_mutex();

/*
Creates new connections to the database and adds them to the list of open connections.
@param connections: OUT: list of open connections
@param idle_connections_batch_size: number of connections to be opened
@return SQLITE_OK on success, SQLITE_NOMEM on allocation failure, or other error codes
*/
int sql3_init_idle_connection(struct sql3_open_connections **connections, int idle_connections_batch_size);

/*
Closes the idle connections and removes them from the list of open connections. idle_connections_batch_size of
idle connections will be maintained.
@param connections: IN/OUT: list of open connections
@param idle_connections_batch_size: minimum number of idle connections to maintain
@return SQLITE_OK on success, error code on failure
*/
int sql3_close_idle_connection(struct sql3_open_connections **connections, int idle_connections_batch_size);

/*
sql3_insert_data, sql3_update_data, sql3_delete_data and sql3_select_data
are thread safe and require a valid connection to the database to work.
*/

/*
Insert data into specified table
@param db: valid database connection
@param table_name: name of the table
@param column_names: comma-separated list of column names
@param values: comma-separated list of values
@return SQLITE_OK on success, error code on failure
*/
int sql3_insert_data(
    sqlite3 *db,
    const char *table_name,
    const char *column_names,
    const char *values);

/*
Update data in specified table
@param db: valid database connection
@param table_name: name of the table
@param column_names: comma-separated list of column names
@param values: comma-separated list of new values
@param condition: WHERE clause condition
@return SQLITE_OK on success, error code on failure
*/
int sql3_update_data(
    sqlite3 *db,
    const char *table_name,
    const char *column_names,
    const char *values,
    const char *condition);

/*
Delete data from specified table
@param db: valid database connection
@param table_name: name of the table
@param condition: WHERE clause condition
@return SQLITE_OK on success, error code on failure
*/
int sql3_delete_data(
    sqlite3 *db,
    const char *table_name,
    const char *condition);

/*
Select data from specified table
@param db: valid database connection
@param table_name: name of the table
@param column_names: comma-separated list of column names
@param condition: WHERE clause condition
@param callback: callback function to handle result rows
@param arg: first argument passed to callback
@return SQLITE_OK on success, error code on failure
*/
int sql3_select_data(
    sqlite3 *db,
    const char *table_name,
    const char *column_names,
    const char *condition,
    int (*callback)(void*, int, char**, char**),
    void *arg);

#endif // SQL3_H