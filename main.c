#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>

#define DB_FILE "user.db"

void initializeDatabase() {
    sqlite3 *db;
    char *errMsg = 0;

    int rc = sqlite3_open(DB_FILE, &db);

    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

    char *sql = "CREATE TABLE IF NOT EXISTS users (" \
                "id INTEGER PRIMARY KEY AUTOINCREMENT," \
                "username TEXT NOT NULL UNIQUE," \
                "password TEXT NOT NULL);";

    rc = sqlite3_exec(db, sql, 0, 0, &errMsg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    }

    sqlite3_close(db);
}

int main() {
    initializeDatabase();

    int choice;

    do {
        printf("1. Register\n");
        printf("2. Login\n");
        printf("3. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                registerUser();
                break;
            case 2:
                loginUser();
                break;
            case 3:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
    } while (choice != 3);

    return 0;
}