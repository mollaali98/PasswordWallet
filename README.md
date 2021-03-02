# sgx-wallet

This is a simple password-wallet application based on Intel SGX for linux. Intel also provides a full
[tutorial](https://software.intel.com/en-us/articles/introducing-the-intel-software-guard-extensions-tutorial-series)

## Pre-requisites

Ensure to have the Intel SGX Linux [drivers](https://github.com/intel/linux-sgx-driver)
and [SDK](https://github.com/intel/linux-sgx) installed. There is a video how to install
[here](https://www.youtube.com/watch?v=X0YzzT4uAY4)

## Install

Install **sgx-wallet** as follows:

- Source the Intel SGX SDK as described [here](https://github.com/intel/linux-sgx#install-the-intelr-sgx-sdk-1); if your
  SDK installation path is `/opt/intel/sgxsdk/`, run:

```shell
$ source /opt/intel/sgxsdk/environment
```

## Usage

**sgx-wallet** comes with a simple cli that can be run with the following options:

- Show help:

```shell
sgx-wallet -h
```

- Show version:

```shell
sgx-wallet -v
```

- Run tests:

```shell
sgx-wallet -t
``` 

- Create a new wallet with master-password `<master-passowrd>`:

```shell
sgx-wallet -n master-password
``` 

- Change current master-password to `<new-master-password>`:

```shell
sgx-wallet -p master-password -c new-master-password
``` 

- Add a new item to the wallet with title `<item_title>`, username `<item_username>`, and password `<item_password>`:

```shell
sgx-wallet -p master-password -a -x item_title -y item_username -z item_password
``` 

- Remove item at index `<item_index>` from the wallet:

```shell
sgx-wallet -p master-password -r item_index
``` 

The wallet data are saved in a file called `wallet.seal` in the same directory as the main application. Note that you
can have only one `wallet.seal` file, and attempting to call twice `sgx-wallet -n master-password` will result in an
error.
