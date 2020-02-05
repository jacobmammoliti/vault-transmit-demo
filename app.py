import hvac
import psycopg2
import base64
import os
import argparse

hvac_client = {
    "url": os.environ["VAULT_ADDR"]
}

client    = hvac.Client(**hvac_client)
psql_host = os.environ["PSQL_ADDR"]
db_name   = "postgres"

def transit_encrypt(plain_text, encrypt_key="demo-key"):
    """Encrypt plain text data with Transit.

    Keyword arguments:
    plain_text  -- the text to encrypt (string)
    encrypt_key -- encryption key to use (string)

    Return:
    ciphertext (string)
    """
    encoded_text = base64.b64encode(plain_text.encode("utf-8"))

    ciphertext = client.secrets.transit.encrypt_data(
        name = encrypt_key,
        plaintext = str(encoded_text, "utf-8")
    )

    return ciphertext["data"]["ciphertext"]

def transit_decrypt(ciphertext, decrypt_key="demo-key"):
    """Decrypt ciphertext into plain text.

    Keyword arguments:
    ciphertext -- the text to decrypt (string)
    decrypt_key -- decryption key to use (string)

    Return:
    Base64 decoded plaintext
    """
    decrypt_data_response = client.secrets.transit.decrypt_data(
        name = decrypt_key,
        ciphertext = ciphertext
    )

    return str(base64.b64decode(decrypt_data_response["data"]["plaintext"]), "utf-8")


def psql_connection(role):
    """Connect to a PostgreSQL database with Vault role.

    Keyword arguments:
    role  -- Vault role to use for credentials (string)

    Return:
    psql connection (function)
    """
    psql_creds = client.secrets.database.generate_credentials(name=role)

    connection = psycopg2.connect(host = psql_host,
                                  database = db_name,
                                  user = psql_creds["data"]["username"],
                                  password = psql_creds["data"]["password"])
    
    return connection

def psql_input(sql_statement, username, ciphertext, connection):
    """Insert data into PostgreSQL database table.

    Keyword arguments:
    sql_statement  -- SQL statement to run against database (string)
    username       -- username to add to new row (string)
    ciphertext     -- ciphertext to add to new row (string)
    connection     -- psycopg2 connection (function)

    Return:
    psql connection
    """
    cursor = connection.cursor()
    
    cursor.execute(sql_statement, (username, ciphertext))

    connection.commit()

def psql_retrival(sql_statement, username, connection):
    """Retrieve data into PostgreSQL database table.

    Keyword arguments:
    sql_statement  -- SQL statement to run against database (string)
    username       -- username to add to new row (string)
    connection     -- psycopg2 connection (function)

    Return:
    records - list of records returned from database
    """
    cursor = connection.cursor()
    
    cursor.execute(sql_statement, (username,))

    records = cursor.fetchall()

    return records

def main():
    # ensures were authenticated to Vault
    # looks up Vault token in ~/.vault-token by default
    assert client.is_authenticated()

    parser = argparse.ArgumentParser()
    parser.add_argument("--decrypt", "-d", 
                        help="decrypts the password of the user")
    parser.add_argument("--encrypt", "-e",
                        help="encrypts the password of the user")
    args = parser.parse_args()

    if args.encrypt:
        print ("Password: ", end="")
        password = input()

        # encrypt password
        ciphertext = transit_encrypt(password)

        # Generate creds for the 'user-role' in Vault
        connection = psql_connection("user-role")

        # Insert encrypted data into database
        psql_input("INSERT INTO users (username, password) VALUES (%s, %s);", 
                   args.encrypt, ciphertext, connection)

        print ("Successfully created new account for {}".format(args.encrypt))
    elif args.decrypt:
        # Generate creds for the 'user-role' in Vault
        connection = psql_connection("user-role")

        # Insert encrypted data into database
        ciphertext = psql_retrival("SELECT password FROM users WHERE username=%s;", 
                                   args.decrypt, connection)

        plaintext = transit_decrypt(ciphertext[0][0])

        print ("The password for {} is {}.".format(args.decrypt, plaintext))

if __name__ == "__main__":
    main()