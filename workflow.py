import rsa
import base64
import requests

VAULT_ADDR = "http://localhost:8200"
URL = "http://localhost:8080/auth/token"
KEY = "apacheds/private-key-{}.pkcs1.pem"


def jwt(user: str):
  response = requests.post(
    URL, json={"name": user}, 
    headers={"Content-Type": 
        "application/json"}
  )

  encoded_jwt = response.text
  encrypted_jwt = base64.b64decode(encoded_jwt)

  key = KEY.format(user)
  prv_key = rsa.PrivateKey.load_pkcs1(open(key)
            .read())
  jwt = rsa.decrypt(encrypted_jwt, prv_key)
  return jwt


def vault_token(jwt: str, role: str):
  payload = {"jwt": jwt.decode("utf-8"), 
            "role": role}
  headers = {
      "Content-Type": "application/json",
      "X-Vault-Request": "true",
  }
  url = f"{VAULT_ADDR}/v1/auth/jwt/login"
  response = requests.put(url, json=payload, 
                headers=headers)
  token = response.json()["auth"]["client_token"]
  return token


def infra_username_password(vault_token: str):
  url = f"{VAULT_ADDR}/v1/secret" +\
    "/data/kv/users/alice/mysql_infra_db"

  headers = {
      "X-Vault-Token": vault_token,
      "Content-Type": "application/json",
  }
  response = requests.get(url, headers=headers)
  return response.json()["data"]


def main():
  alice_jwt = jwt("alice")
  token = vault_token(alice_jwt, "jwt_alice")
  data = infra_username_password(token)
  username = data["data"]["username"]
  password = data["data"]["password"]
  print(f"username: {username}," + 
        f"password: {password}")


if __name__ == "__main__":
    main()
