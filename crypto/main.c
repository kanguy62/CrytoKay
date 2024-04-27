#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define BUFFER_SIZE 1024
#define DB_FILE "user.db"
#define KEY_LENGTH_BYTES 128
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
                "password TEXT NOT NULL,"\
                "email TEXT NOT NULL"\
                "key TEXT)";

    rc = sqlite3_exec(db, sql, 0, 0, &errMsg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    }

    sqlite3_close(db);
}

void registerUser() {
    sqlite3 *db;
    char *errMsg = 0;
    char username[50];
    char password[100];
    char email[100];

    printf("Enter username: ");
    scanf("%s", username);
    printf("Enter password: ");
    scanf("%s", password);
    printf("Enter email: ");
    scanf("%s", email);

    // Open database
    int rc = sqlite3_open(DB_FILE, &db);

    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

    // Prepare SQL statement
    char sql[100];
    sprintf(sql, "INSERT INTO users (username, password, email) VALUES ('%s', '%s', '%s')", username, password, email);

    // Execute SQL statement
    rc = sqlite3_exec(db, sql, 0, 0, &errMsg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    } else {
        printf("User registered successfully!\n");
    }

    sqlite3_close(db);
}

void currentUser(const char *username) {
    int choice;
    const char *currentname = username;
    do {
        printf("1. Remove Account\n");
        printf("2. Logout\n");
        printf("3. Modify Password\n");
        printf("4. Logout\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                removeAccount(username);
                currentname = "";
                printf("You are logged out!\n");
                break;
            case 2:
                printf("Logged out successfully!\n");
                currentname = "";
                break;
            case 3:
                modifyPassword(username);
                break;    
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
    } while (choice != 2);
}

void loginUser() {
    sqlite3 *db;
    char *errMsg = 0;
    char username[50];
    char password[50];

    printf("Enter username: ");
    scanf("%s", username);
    printf("Enter password: ");
    scanf("%s", password);

    // Open database
    int rc = sqlite3_open(DB_FILE, &db);

    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

    // Prepare SQL statement
    char sql[85];
    sprintf(sql, "SELECT * FROM users WHERE username='%s' AND password='%s'", username, password);

    // Execute SQL statement
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        // Check if a row is returned
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            printf("Login successful!\n");
            currentUser(username);
        } else {
            printf("Login failed. Incorrect username or password.\n");
        }
    } else {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void modifyPassword(const char *username) {
    sqlite3 *db;
    char *errMsg = 0;
    char currentPassword[100];
    char newPassword[100];

    printf("Enter your current password: ");
    scanf("%s", currentPassword);
    printf("Enter your new password: ");
    scanf("%s", newPassword);

    // Open database
    int rc = sqlite3_open(DB_FILE, &db);

    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

    // Prepare SQL statement to check current password
    char sql[150];
    sprintf(sql, "SELECT * FROM users WHERE username='%s' AND password='%s'", username, currentPassword);

    // Execute SQL statement
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        // Check if a row is returned (i.e., current password is correct)
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            // Prepare SQL statement to update password
            sprintf(sql, "UPDATE users SET password='%s' WHERE username='%s'", newPassword, username);

            // Execute SQL statement to update password
            rc = sqlite3_exec(db, sql, 0, 0, &errMsg);

            if (rc != SQLITE_OK) {
                fprintf(stderr, "SQL error: %s\n", errMsg);
                sqlite3_free(errMsg);
            } else {
                printf("Password updated successfully!\n");
            }
        } else {
            printf("Failed to update password. Incorrect current password.\n");
        }
    } else {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

char *generateKey() {
    unsigned char key[KEY_LENGTH_BYTES];
    char *hexKey = malloc(2 * KEY_LENGTH_BYTES + 1); // +1 for null terminator
    
    if (hexKey == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    
    // Generate key
    if (RAND_bytes(key, KEY_LENGTH_BYTES) != 1) {
        fprintf(stderr, "Error generating key\n");
        exit(EXIT_FAILURE);
    }
    
    // Convert key to hexadecimal string
    for (int i = 0; i < KEY_LENGTH_BYTES; ++i) {
        sprintf(&hexKey[i * 2], "%02x", key[i]);
    }
    
    return hexKey;
}

void removeAccount(const char *username) {
    sqlite3 *db;
    char *errMsg = 0;

    // Open database
    int rc = sqlite3_open(DB_FILE, &db);

    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

    // Prepare SQL statement
    char sql[100];
    sprintf(sql, "DELETE FROM users WHERE username='%s'", username);

    // Execute SQL statement
    rc = sqlite3_exec(db, sql, 0, 0, &errMsg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errMsg);
        sqlite3_free(errMsg);
    } else {
        printf("Account removed successfully!\n");
    }

    sqlite3_close(db);
}

void hashFileSHA256(const char *filePath) {
    FILE *file = fopen(filePath, "rb");
    if (file == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    // Initialize SHA-256 context
    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);

    // Buffer to read file contents
    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead;

    // Read file contents and update hash
    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        SHA256_Update(&sha256Context, buffer, bytesRead);
    }

    // Finalize hash computation
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256Context);

    // Close the file
    fclose(file);

    // Print the hash in hexadecimal format
    printf("SHA-256 hash of file '%s': ", filePath);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void encryptFile(const char *inputFilePath, const char *outputFilePath, const char *algorithm, const unsigned char *key) {
    FILE *inputFile = fopen(inputFilePath, "rb");
    if (inputFile == NULL) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }

    FILE *outputFile = fopen(outputFilePath, "wb");
    if (outputFile == NULL) {
        perror("Error opening output file");
        fclose(inputFile);
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        perror("Error creating cipher context");
        fclose(inputFile);
        fclose(outputFile);
        exit(EXIT_FAILURE);
    }

    const EVP_CIPHER *cipher;
    if (strcmp(algorithm, "AES-192") == 0) {
        cipher = EVP_aes_192_cbc();
    } else if (strcmp(algorithm, "DES") == 0) {
        cipher = EVP_des_cbc();
    } else if (strcmp(algorithm, "Blowfish") == 0) {
        cipher = EVP_bf_cbc();
    } else {
        fprintf(stderr, "Unsupported encryption algorithm: %s\n", algorithm);
        fclose(inputFile);
        fclose(outputFile);
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    unsigned char iv[EVP_MAX_IV_LENGTH];
    RAND_bytes(iv, EVP_CIPHER_iv_length(cipher));

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        perror("Error initializing encryption");
        fclose(inputFile);
        fclose(outputFile);
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    unsigned char buffer[BUFFER_SIZE];
    int bytesRead;
    int encryptedBytesWritten;

    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, inputFile)) > 0) {
        if (EVP_EncryptUpdate(ctx, buffer, &encryptedBytesWritten, buffer, bytesRead) != 1) {
            perror("Error encrypting data");
            fclose(inputFile);
            fclose(outputFile);
            EVP_CIPHER_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
        fwrite(buffer, 1, encryptedBytesWritten, outputFile);
    }

    int finalEncryptedBytesWritten;
    if (EVP_EncryptFinal_ex(ctx, buffer, &finalEncryptedBytesWritten) != 1) {
        perror("Error finalizing encryption");
        fclose(inputFile);
        fclose(outputFile);
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    fwrite(buffer, 1, finalEncryptedBytesWritten, outputFile);

    fclose(inputFile);
    fclose(outputFile);
    EVP_CIPHER_CTX_free(ctx);

    printf("File encrypted successfully using %s algorithm\n", algorithm);
}

int main() {
    initializeDatabase();

    int choice;
    char *key;
    char filePath[256];
    
    char *filename[256];
    char *output[256];
    char *type[256];
    char *key2[1000];
    
    char *filenamede[256];
    char *outputde[256];
    char *typede[256];
    char *key3[1000];
    
    do { 
        printf("1. Register\n");
        printf("2. Login\n");
        printf("3. Exit\n");
        printf("4. Generate Key\n");
        printf("5. Hash A File\n");
        printf("6. Encrypt a file\n");
        printf("7. Decrypt a file\n");
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
                return 0;
            case 4:
                key = generateKey();
                printf("Generated key: %s\n", key);
                break;  
            case 5:
            	printf("Enter the file path: ");
                if (scanf("%255s", filePath) != 1) {
        	    fprintf(stderr, "Error reading file path\n");
        	    return EXIT_FAILURE;
    		}
    		hashFileSHA256(filePath);
                break;
            case 6:
            	printf("Enter the filename: ");
                scanf("%s", filename);
    		printf("Enter the key: ");
    		scanf("%s", key2);
    		for (int i = 0; i < 32; i += 2) {
        		sscanf(&key2[i], "%2hhx", &key2[i / 2]);
   		}	
    		printf("Enter the output: ");
    		scanf("%s", output);
    		printf("Enter the type: ");
    		scanf("%s", type);
    		
    		encryptFile(filename,output,type,key2);
                break;
            case 7:
            	printf("Enter the filename: ");
                scanf("%s", filenamede);
    		printf("Enter the key: ");
    		scanf("%s", key3);
    		for (int i = 0; i < 32; i += 2) {
        		sscanf(&key3[i], "%2hhx", &key3[i / 2]);
   		}	
    		printf("Enter the output: ");
    		scanf("%s", outputde);
    		printf("Enter the type: ");
    		scanf("%s", typede);
    		
    		encryptFile(filenamede,outputde,typede,key3);
                break;            
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
    } while (choice != 7);

    return 0;
}
