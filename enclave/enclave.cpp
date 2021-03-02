#include "enclave_t.h"

#include "string.h"

#include "enclave.h"
#include "wallet.h"

#include "sgx_tseal.h"
#include "sealing/sealing.h"

int ecall_create_wallet(const char *master_password) {

    // OVERVIEW
    // 1. Check password policy
    // 2. Abort if wallet already exist
    // 3. Create wallet
    // 4. Seal wallet
    // 5. Save wallet
    // 6. Exit enclave

    sgx_status_t ocall_status, sealing_status;
    int ocall_ret;

    // 1. Check password policy
    if (strlen(master_password) < 8 || strlen(master_password) + 1 > MAX_ITEMS_SIZE) {
        return ERR_PASSWORD_OUT_OF_RANGE;
    }

    // 2. Abort if wallet already exist
    ocall_status = ocall_is_wallet(&ocall_ret);
    if (ocall_ret != 0) {
        return ERR_WALLET_ALREADY_EXISTS;
    }

    // 3. Create new wallet
    // The malloc() function allocates a block of uninitialized memory and returns a void pointer to the first byte
    // of the allocated memory block if the allocation succeeds.
    wallet_t *wallet = (wallet_t *) malloc(sizeof(wallet_t));
    wallet->size = 0;
    // Copies the first num characters of source to destination.
    strncpy(wallet->master_password, master_password, strlen(master_password) + 1);

    // 4. Seal wallet
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
    uint8_t *sealed_data = (uint8_t *) malloc(sealed_size);
    sealing_status = seal_wallet(wallet, (sgx_sealed_data_t *) sealed_data, sealed_size);
    // free() -> deallocates a block of memory previously allocated using calloc, malloc or realloc functions,
    // making it available for further allocations.
    free(wallet);
    if (sealing_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_FAIL_SEAL;
    }

    // 5. Save wallet
    ocall_status = ocall_save_wallet(&ocall_ret, sealed_data, sealed_size);
    free(sealed_data);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        return ERR_CANNOT_SAVE_WALLET;
    }

    // Exist enclave
    return RET_SUCCESS;
}

/**
 * @brief      Provides the wallet content. The sizes/length of
 *             pointers need to be specified, otherwise SGX will
 *             assume a count of 1 for all pointers.
 *
 */
int ecall_show_wallet(const char *master_password, wallet_t *wallet, size_t wallet_size) {

    // OVERVIEW
    // 1. Load wallet
    // 2. Unseal wallet
    // 3. Verify master_password
    // 4. Return wallet to the app
    // 5. Exit enclave

    sgx_status_t ocall_status, sealing_status;
    int ocall_ret;

    // 1.Load wallet
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
    uint8_t *sealed_data = (uint8_t *) malloc(sealed_size);
    ocall_status = ocall_load_wallet(&ocall_ret, sealed_data, sealed_size);
    if (ocall_status != 0 || ocall_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_CANNOT_LOAD_WALLET;
    }

    // 2. Unseal loaded wallet
    uint32_t plaintext_size = sizeof(wallet_t);
    wallet_t *unsealed_wallet = (wallet_t *) malloc(plaintext_size);
    sealing_status = unseal_wallet((sgx_sealed_data_t *) sealed_data, unsealed_wallet, plaintext_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
        free(unsealed_wallet);
        return ERR_FAIL_UNSEAL;
    }

    // 3. Verify master-password
    // The strcmp() function compares two strings and returns 0 if both strings are identical.
    if (strcmp(unsealed_wallet->master_password, master_password) != 0) {
        free(unsealed_wallet);
        return ERR_WRONG_MASTER_PASSWORD;
    }

    // 4. Return wallet to the app
    (*wallet) = *unsealed_wallet;
    free(unsealed_wallet);

    // 5. Exit enclave
    return RET_SUCCESS;
}

/**
 * @brief      Changes the wallet's master-password.
 */
int ecall_change_master_password(const char *old_password, const char *new_password) {

    // OVERVIEW
    // 1. Check password policy
    // 2. Load wallet
    // 3. Unseal wallet
    // 4. Verify old password
    // 5. Update password
    // 6. Seal wallet
    // 7. Save sealed wallet
    // 8. Exit enclave

    sgx_status_t ocall_status, sealing_status;
    int ocall_ret;

    // 1. Check password policy
    if (strlen(new_password) < 8 || strlen(new_password) + 1 > MAX_ITEMS_SIZE) {
        return ERR_PASSWORD_OUT_OF_RANGE;
    }

    // 2. Load wallet
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
    uint8_t *sealed_data = (uint8_t *) malloc(sealed_size);
    ocall_status = ocall_load_wallet(&ocall_ret, sealed_data, sealed_size);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_CANNOT_LOAD_WALLET;
    }

    // 3. Unseal wallet
    uint32_t plaintext_size = sizeof(wallet_t);
    wallet_t *wallet = (wallet_t *) malloc(plaintext_size);
    sealing_status = unseal_wallet((sgx_sealed_data_t *) sealed_data, wallet, plaintext_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
        free(wallet);
        return ERR_FAIL_UNSEAL;
    }

    // 4. Verify master-password
    if (strcmp(wallet->master_password, old_password) != 0) {
        free(wallet);
        return ERR_WRONG_MASTER_PASSWORD;
    }

    // 5. Update password
    strncpy(wallet->master_password, new_password, strlen(new_password) + 1);

    // 6. Seal wallet
    sealed_data = (uint8_t *) malloc(sealed_size);
    sealing_status = seal_wallet(wallet, (sgx_sealed_data_t *) sealed_data, sealed_size);
    free(wallet);
    if (sealing_status != SGX_SUCCESS) {
        free(wallet);
        free(sealed_data);
        return ERR_FAIL_SEAL;
    }

    // 7. Save wallet
    ocall_status = ocall_save_wallet(&ocall_ret, sealed_data, sealed_size);
    free(sealed_data);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        return ERR_CANNOT_SAVE_WALLET;
    }

    // 8. Exit enclave
    return RET_SUCCESS;
}


/**
 * @brief      Adds an item to the wallet. The sizes/length of
 *             pointers need to be specified, otherwise SGX will
 *             assume a count of 1 for all pointers.
 */
int ecall_add_item(const char *master_password, const item_t *item, const size_t item_size) {

    // OVERVIEW
    // 1. Load wallet
    // 2. Unseal wallet
    // 3. Verify master-password
    // 4. Check input length
    // 5. Add item to the wallet
    // 6. Seal wallet
    // 7. Save sealed wallet
    // 8. Exit enclave

    sgx_status_t ocall_status, sealing_status;
    int ocall_ret;

    // 1. Load wallet
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
    uint8_t *sealed_data = (uint8_t *) malloc(sealed_size);
    ocall_status = ocall_load_wallet(&ocall_ret, sealed_data, sealed_size);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_CANNOT_LOAD_WALLET;
    }

    // 2. Unseal wallet
    uint32_t plaintext_size = sizeof(wallet_t);
    wallet_t *wallet = (wallet_t *) malloc(plaintext_size);
    sealing_status = unseal_wallet((sgx_sealed_data_t *) sealed_data, wallet, plaintext_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
        free(wallet);
        return ERR_FAIL_UNSEAL;
    }

    // 3. Verify master-password
    if (strcmp(wallet->master_password, master_password) != 0) {
        free(wallet);
        return ERR_WRONG_MASTER_PASSWORD;
    }

    // 4. Check input length
    if (strlen(item->title) + 1 > MAX_ITEMS_SIZE ||
        strlen(item->username) + 1 > MAX_ITEMS_SIZE ||
        strlen(item->password) + 1 > MAX_ITEMS_SIZE
            ) {
        free(wallet);
        return ERR_ITEM_TOO_LONG;
    }

    // 5. Add item to the wallet
    size_t wallet_size = wallet->size;
    if (wallet_size >= MAX_ITEMS) {
        free(wallet);
        return ERR_WALLET_FULL;
    }
    wallet->items[wallet_size] = *item;
    ++wallet->size;

    // 6. Seal wallet
    sealed_data = (uint8_t *) malloc(sealed_size);
    sealing_status = seal_wallet(wallet, (sgx_sealed_data_t *) sealed_data, sealed_size);
    free(wallet);
    if (sealing_status != SGX_SUCCESS) {
        free(wallet);
        free(sealed_data);
        return ERR_FAIL_SEAL;
    }

    // 7. Save wallet
    ocall_status = ocall_save_wallet(&ocall_ret, sealed_data, sealed_size);
    free(sealed_data);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        return ERR_CANNOT_SAVE_WALLET;
    }

    // 8. Exit enclave
    return RET_SUCCESS;
}

/**
 * @brief      Removes an item from the wallet. The sizes/length of
 *             pointers need to be specified, otherwise SGX will
 *             assume a count of 1 for all pointers.
 */
int ecall_remove_item(const char *master_password, const int index) {

    // OVERVIEW
    // 1. Check index bounds
    // 2. Load wallet
    // 3. Unseal wallet
    // 4. Verify master-password
    // 5. Remove item from the wallet
    // 6. Seal wallet
    // 7. Save sealed wallet
    // 8. Exit enclave

    sgx_status_t ocall_status, sealing_status;
    int ocall_ret;

    // 1. Check index bounds
    if (index < 0 || index >= MAX_ITEMS) {
        return ERR_ITEM_DOES_NOT_EXIST;
    }

    // 2. Load wallet
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(wallet_t);
    uint8_t *sealed_data = (uint8_t *) malloc(sealed_size);
    ocall_status = ocall_load_wallet(&ocall_ret, sealed_data, sealed_size);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_CANNOT_LOAD_WALLET;
    }

    // 3. Unseal wallet
    uint32_t plaintext_size = sizeof(wallet_t);
    wallet_t *wallet = (wallet_t *) malloc(plaintext_size);
    sealing_status = unseal_wallet((sgx_sealed_data_t *) sealed_data, wallet, plaintext_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
        free(wallet);
        return ERR_FAIL_UNSEAL;
    }

    // 4. Verify master-password
    if (strcmp(wallet->master_password, master_password) != 0) {
        free(wallet);
        return ERR_WRONG_MASTER_PASSWORD;
    }

    // 5. Remove item from the wallet
    size_t wallet_size = wallet->size;
    if (index >= wallet_size) {
        free(wallet);
        return ERR_ITEM_DOES_NOT_EXIST;
    }
    for (int i = index; i < wallet_size - 1; ++i) {
        wallet->items[i] = wallet->items[i + 1];
    }
    --wallet->size;

    // 6. Seal wallet
    sealed_data = (uint8_t *) malloc(sealed_size);
    sealing_status = seal_wallet(wallet, (sgx_sealed_data_t *) sealed_data, sealed_size);
    free(wallet);
    if (sealing_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_FAIL_SEAL;
    }

    // 7. Save wallet
    ocall_status = ocall_save_wallet(&ocall_ret, sealed_data, sealed_size);
    free(sealed_data);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        return ERR_CANNOT_SAVE_WALLET;
    }

    // 8. Exit enclave
    return RET_SUCCESS;
}