#ifndef WALLET_H_
#define WALLET_H_

#define MAX_ITEMS 100
#define MAX_ITEMS_SIZE 100

// Item
struct Item {
    char title[MAX_ITEMS_SIZE];
    char username[MAX_ITEMS_SIZE];
    char password[MAX_ITEMS_SIZE];
};
typedef struct Item item_t;

// Wallet
struct Wallet {
    item_t items[MAX_ITEMS];
    size_t size;
    char master_password[MAX_ITEMS_SIZE];
};
typedef struct Wallet wallet_t;

#endif // WALLET_H_