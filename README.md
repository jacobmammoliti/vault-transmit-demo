# Vault Transit Secrets Engine Demo

## Introduction
I use this repository to demo the Transit Secrets Engine that Vault provides. I demo it with a Python application that takes in a username and password, uses Vault to encrypt that data with Transit, and then writes the data to the database.

## Prerequisites
This demo requires a Vault server to be setup. A demo Vault server can be used but is not recommended since it stores configuration in-memory only.

## Vault Setup
These are the following steps I use to configure Vault for this demo application.

Set up Vault Database Secrets Engine for dynamic credential creation. The application does not use static credentials and leverages Vault to generate credentials on the fly.
More can be read about the Secrets Engine [here](https://www.vaultproject.io/docs/secrets/databases/index.html).
```shell
$ vault secrets enable database
Success! Enabled the database secrets engine at: database/

$ vault write database/config/gcloud-postgresql-database \
  plugin_name=postgresql-database-plugin \
  allowed_roles="*" \
  connection_url="postgresql://{{username}}:{{password}}@<redacted>:5432/" \
  username="<redacted>" \
  password="<redacted>"

$ vault write database/roles/user-role \
  db_name=gcloud-postgresql-database \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
      GRANT INSERT, SELECT, UPDATE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="30m" \
  max_ttl="24h"
Success! Data written to: database/roles/user-role

$ vault list database/roles
Keys
----
user-role

$ vault read database/creds/user-role
Key                Value
---                -----
lease_id           database/creds/user-role/7T5UIPh65GwV7AyCgRccPfUK
lease_duration     30m
lease_renewable    true
password           A1a-s9S1hskt3UN0yJhS
username           v-root-user-rol-nEpOZou34VIcKaGy1EUi-1580745166
```

Configure the Transit Secrets Engine. This will create an encryption key that will be used to encrypt the plaintext.
```shell
$ vault secrets enable transit 
Success! Enabled the transit secrets engine at: transit/

$ vault write -f transit/keys/demo-key
Success! Data written to: transit/keys/demo-key

$ vault list transit/keys         
Keys
----
demo-key

$ vault read transit/keys/demo-key 
Key                       Value
---                       -----
allow_plaintext_backup    false
deletion_allowed          false
derived                   false
exportable                false
keys                      map[1:1580766338]
latest_version            1
min_available_version     0
min_decryption_version    1
min_encryption_version    0
name                      demo-key
supports_decryption       true
supports_derivation       true
supports_encryption       true
supports_signing          false
type                      aes256-gcm96
```

## Application Usage
Below is an example on how to use this application in a demo.

```shell
$ export VAULT_ADDR=https://<redacted>
$ export PSQL_ADDR=<redacted>

$ vault login -method=userpass username=jacobm
Password (will be hidden): 
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                    Value
---                    -----
token                  s.NYJ3CwIo1Xe9ozj0cgLd4HhU
token_accessor         lf6I5T7ngggIS0lHxyVCdJkQ
token_duration         768h
token_renewable        true
token_policies         ["admin-policy" "default"]
identity_policies      []
policies               ["admin-policy" "default"]
token_meta_username    jacobm

$ python3 app.py
Username: jacobm
Password: password
Successfully created new account for jacobm

# verify account got created in database
postgres=> SELECT * FROM users;
 username |                         password                          
----------+-----------------------------------------------------------
 jacobm   | vault:v1:f0k1odEyI8WEH2x0rAQ6PQv9mo56UDmPZ+WWczOsV6aIgA==
(2 rows)
```
