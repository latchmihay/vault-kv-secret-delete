# small fast tool to delete vault secrets recursivly (supports kv2)

```console
# export VAULT_ADDR=https://urlVaultURL:{port}
# export VAULT_TOKEN={vault access token}

# go run main.go -path secret -secret mysecret

DEBU[2020-02-20 12:43:39] VAULT_STORE: DeleteAll key mysecret             vaultPath=secret
DEBU[2020-02-20 12:43:40] DeleteAll: deleting 3 keys                   
DEBU[2020-02-20 12:43:40] VAULT_STORE: Delete key secret/mysecret/gophergames/deps/dep1  vaultPath=secret
DEBU[2020-02-20 12:43:40] VAULT_STORE: Delete key secret/mysecret/gophergames/deps/dep2 vaultPath=secret
DEBU[2020-02-20 12:43:40] VAULT_STORE: Delete key secret/mysecret/gophergames/config  vaultPath=secret
```