#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Configuration structure
typedef struct {
    char db_filename[256];
    char vfs_name[64];
    int flags;
    int config;
} sql3_config_t;

// Helper function to trim leading and trailing whitespace
static void trim(char *str) {
    char *start = str;
    char *end = str + strlen(str) - 1;

    while(isspace(*start)) start++;
    while(end > start && isspace(*end)) end--;
    
    *(end + 1) = '\0';
    memmove(str, start, strlen(start) + 1);
}

// Helper function to parse boolean values
static int parse_bool(const char *value) {
    if (strcasecmp(value, "true") == 0 || 
        strcasecmp(value, "yes") == 0 || 
        strcasecmp(value, "1") == 0) {
        return 1;
    }
    return 0;
}


static int parse_db_flags(const char *flags_str) {
    int flags = 0;
    char *str = strdup(flags_str);
    char *token = strtok(str, "|");
    
    while (token) {
        trim(token);
        if (strcasecmp(token, "SQLITE_OPEN_READONLY") == 0)
            flags |= SQLITE_OPEN_READONLY;
        else if (strcasecmp(token, "SQLITE_OPEN_READWRITE") == 0)
            flags |= SQLITE_OPEN_READWRITE;
        else if (strcasecmp(token, "SQLITE_OPEN_CREATE") == 0)
            flags |= SQLITE_OPEN_CREATE;
        else if (strcasecmp(token, "SQLITE_OPEN_URI") == 0)
            flags |= SQLITE_OPEN_URI;
        else if (strcasecmp(token, "SQLITE_OPEN_MEMORY") == 0)
            flags |= SQLITE_OPEN_MEMORY;
        else if (strcasecmp(token, "SQLITE_OPEN_NOMUTEX") == 0)
            flags |= SQLITE_OPEN_NOMUTEX;
        else if (strcasecmp(token, "SQLITE_OPEN_FULLMUTEX") == 0)
            flags |= SQLITE_OPEN_FULLMUTEX;
        else if (strcasecmp(token, "SQLITE_OPEN_SHAREDCACHE") == 0)
            flags |= SQLITE_OPEN_SHAREDCACHE;
        else if (strcasecmp(token, "SQLITE_OPEN_PRIVATECACHE") == 0)
            flags |= SQLITE_OPEN_PRIVATECACHE;
        
        token = strtok(NULL, "|");
    }
    
    free(str);
    return flags;
}


static int parse_config_file(const char *filename, sql3_config_t *config) {
    FILE *fp;
    char line[512];
    char key[256];
    char value[256];
    
    // Set default values
    memset(config, 0, sizeof(sql3_config_t));
    strcpy(config->db_filename, ":memory:"); // Default to in-memory database
    config->flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    config->config = 0;
    
    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open config file: %s\n", filename);
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == ';' || line[0] == '\n')
            continue;
            
        if (sscanf(line, "%[^=]=%[^\n]", key, value) == 2) {
            trim(key);
            trim(value);
            
            if (strcasecmp(key, "database_file") == 0) {
                strncpy(config->db_filename, value, sizeof(config->db_filename) - 1);
            }
            else if (strcasecmp(key, "vfs_name") == 0) {
                strncpy(config->vfs_name, value, sizeof(config->vfs_name) - 1);
            }
            else if (strcasecmp(key, "flags") == 0) {
                config->flags = parse_db_flags(value);
            }
            else if (strcasecmp(key, "enable_wal") == 0) {
                if (parse_bool(value))
                    config->config |= 0x1;
            }
            else if (strcasecmp(key, "enable_foreign_keys") == 0) {
                if (parse_bool(value))
                    config->config |= 0x2;
            }
            else if (strcasecmp(key, "enable_triggers") == 0) {
                if (parse_bool(value))
                    config->config |= 0x4;
            }
            else if (strcasecmp(key, "enable_shared_cache") == 0) {
                if (parse_bool(value))
                    config->flags |= SQLITE_OPEN_SHAREDCACHE;
            }
        }
    }
    
    fclose(fp);
    return 0;
}

// Main initialization routine
int init_from_config(const char *config_filename, sqlite3 **ppDb) {
    sql3_config_t config;
    int rc;
    
    // Parse configuration file
    rc = parse_config_file(config_filename, &config);
    if (rc != 0) {
        return rc;
    }
    
    // Initialize SQLite
    rc = sql3_init(
        config.config,
        config.flags,
        config.db_filename,
        ppDb,
        config.vfs_name[0] ? config.vfs_name : NULL
    );
    
    return rc;
}