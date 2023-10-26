This is a small program to sign an Ethereum transaction.

```
Usage of sign_txn:
    -chainid string
        Chain ID
    -keystore string
        Path to Keystore
    -password string
        Password (Default: "")
    -signer string
        Signer
    -txn string
        Path to a JSON file of an unsigned transaction
```

Example:

```
sign_txn --chainid 12345 --keystore ~/geth_data/keystore/ --txn txn.json --signer 0x7ea155883a46dccf117972cb1e438fe5ec1c353c
```
