#include "sql3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* need to test basic data_base functioanlity
continue working on a suma_router on which we can configure various endpoints with authentication and privellege based access 
to which routines can subscribe*/


/*
callback for sql3_select(): prints output to cosole
*/
int callback(void *NotUsed, int argc, char **argv, char **azColName) {
    for (int i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

int main() {
    
    /*
    Test database connection
    */
    sqlite3 *db;
    int rc = sql3_init("user_data.db", SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to initialize database.\n");
        return 0;
    }

    rc = sql3_get_connection(&db);
    if (rc != SQLITE_OK) {
        printf("Failed to get database handle.\n");
        return 0;
    }

    rc = sql3_select(db,"USER_DATA", "*", NULL, 0, 0);
    if (rc != SQLITE_OK) {
        printf("Failed to select data.\n");
        return 0;
    }
 
    rc = sql3_insert(db, "USER_DATA", "ID,NAME,EMAIL,STATUS, NAMESPACE, JOB", "20, 'AYUSH_NEW_new', 'ayufhe',2,3,3");
     if (rc != SQLITE_OK) {
        printf("Failed to insert data.\n");
        return 0;
    }
    sql3_release_connection();
    printf("Database connection Tests passed.\n");



    return 0;
}
