package main

import (
	"flag"
	"fmt"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/latchmihay/vault-kv-secret-delete/store"
)

var (
	vaultKeyPath    string
	vaultSecretName string
)

func init() {
	flag.StringVar(&vaultKeyPath, "path", "", "/secret/path")
	flag.StringVar(&vaultSecretName, "secret", "", "mySecretName")
	flag.Parse()
}

func main() {
	// create vault client
	vaultConfig := *vaultapi.DefaultConfig()
	vaultConfig.ReadEnvironment()
	client, err := vaultapi.NewClient(&vaultConfig)
	if err != nil {
		panic(fmt.Errorf("failed to create vault client: %v", err))
	}

	vs := store.NewVaultStore(client, vaultKeyPath)

	err = vs.DeleteAll(vaultSecretName)
	if err != nil {
		fmt.Println(err)
	}
}
