#ifndef SQL3_H
#define SQL3_H

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

#include <sqlite3.h>

#define MAX_CLIENT 100

/*
so, we can support two modes of operations:
1. a single connecition FULLMUTEX fro wrtiting and multiple connections NOMUTEX for reading
configuration options with 1:
    max connections for reading that is allowed. 
    a pool of connections for reading will be maintained
    to tweek the pool one can set the batch_size  
2. a single connection FULLMUTEX for reading and writing.
everything will be serialized internally. max clients can be configured

3. multiple NOMUTEX conenctions are used to write and  a single NOMUTEX connection for writing 
but we manually serilize the writes.  

if first option or the third is occupanied by database in wal mode then write operations won't block the readers.
further more begin commit transactions by writer threads will enhance the speed of writes. as the actual commit happens
much later.

for now just go with second option and implement the other much later. 

let's develop a proper linrary for testing, debugging sql code and making it easier to user for web servers.
let's give all the modes we talked about above. with proper benchmarks on different architecturs and embedded systems.
also need to pack information in a confif file where can set the configurations. 
*/

/*
All sql3 operations are thread safe. sql3_init() must be called before any other sql3 
operation. sql3 is configured to be in SQL_CONFIG_SERIALIZED mode and connecitons are 
opened in SQLITE_OPEN_FULLMUTEX mode. This means that all threads can access the database
using the same handle. sqlite3 internally serealisez all the operations. 
*/ 

/*
sql3_connection: This structure holds details about the database connection,
*/
typedef struct sql3_connection {
    int active_connections;    /*Total number of threads using the connection*/
    sqlite3 *hd;               /*Handle to the connection*/
}sql3_connection;


/*
Initialize sql3 library, database and a sql3_handler. This routine is "effective"
only if a connection is not already open.
*/
int sql3_init(
    //int sql3_flags,       /*sql3_flags: Flags for the sql3 library*/
    const char *filename,   /*filename: Database filename (UTF-8)*/
    int db_flags,           /*db_flags: flags for the database*/
    const char *zVfs        /*zVfs: Name of VFS module to use*/
    );

/*
Deletes all resources allocated with sql3_init() and closes the database. This routine is 
"effective" only if sql3_init() was called before. Subsequent calls to sql3_destroy() will
have no effect. All active clients must release their connection before calling this routine.
Otherwise, the behaviour is undefined.
*/
int sql3_destroy();

/*
This routine is thread safe. Returns a handle to the database. If the number of active client
using the handle is more than MAX_CLIENT then this returns the calling thread with an error.
*/
int sql3_get_connection(
    sqlite3 **db           /*db: OUT: SQLite db handle*/
);

/*
This routine is thread safe. Releases the connection handle.
*/
int sql3_release_connection();


/*
Insert data into specified table
*/
int sql3_insert(
    sqlite3 *db,                /*db: valid database hanlde*/
    const char *table_name,     /*table_name: name of the table*/
    const char *column_names,   /*column_names: comma-separated list of column names*/
    const char *values          /*values: comma-separated list of values*/
    );        

/*
Update data in specified table
*/
int sql3_update(
    sqlite3 *db,                /*db: valid database handle*/
    const char *table_name,     /*table_name: name of the table*/
    const char *column_names,   /*column_names: comma-separated list of column names*/
    const char *values,         /*values: comma-separated list of new values*/
    const char *condition       /*condition: WHERE clause condition*/
    );

/*
Delete data from specified table
*/
int sql3_delete(
    sqlite3 *db,                /*db: valid database handle*/
    const char *table_name,     /*table_name: name of the table*/
    const char *condition       /*condition: WHERE clause condition*/
    );

/*
Select data from specified table
*/
int sql3_select(
    sqlite3 *db,                                    /*db: valid database handle*/
    const char *table_name,                         /*table_name: name of the table*/
    const char *column_names,                       /*column_names: comma-separated list of column names*/
    const char *condition,                          /*condition: WHERE clause condition*/
    int (*callback)(void*, int, char**, char**),    /*callback: callback function*/
    void *arg                                       /*arg: first argument to the callback function*/
    );


#endif // SQL3_H