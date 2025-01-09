#include <stdio.h>
#include <sqlite3.h>

int init_from_config(const char *config_filename, sqlite3 **ppDb);


int main(int argc, char **argv) {
    
    sqlite3 *db;
    int rc = init_from_config("/path/to/config.ini", &db);
    
    if (rc != SQLITE_OK) {
    fprintf(stderr, "Failed to initialize database: %s\n", sqlite3_errmsg(db));
    return rc;
    }
    
    return 0;
}
