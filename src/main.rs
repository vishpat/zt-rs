extern crate jsonwebkey as jwk;
extern crate jsonwebtoken as jwt;
use actix_web::{get, post, web, App, HttpRequest, HttpServer, Responder};
use jwk::JsonWebKey;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use ldap3::{LdapConnAsync, Scope, SearchEntry};
use openssl::base64;
use openssl::rsa::Padding;
use openssl::x509::X509 as X509Cert;
use std::fmt;

struct TokenError {
    message: String,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Serialize, Deserialize)]
struct LdapConfig {
    url: String,
    bind_dn: String,
    bind_pwd: String,
    base: String,
}

async fn encrypt_token(
    user: &str,
    jwt: &str,
    ldap_config: &LdapConfig,
) -> Result<String, Box<dyn std::error::Error>> {
    let (conn, mut ldap) = LdapConnAsync::new(ldap_config.url.as_str()).await?;
    ldap3::drive!(conn);
    ldap.simple_bind(ldap_config.bind_dn.as_str(), ldap_config.bind_pwd.as_str())
        .await?;

    let (rs, _res) = ldap
        .search(
            ldap_config.base.as_str(),
            Scope::Subtree,
            format!("(uid={})", user).as_str(),
            vec!["userCertificate"],
        )
        .await?
        .success()?;

    let entry = rs.into_iter().next().unwrap();
    let search_entry = SearchEntry::construct(entry);
    let bin_atts = search_entry.bin_attrs;
    let der_cert = bin_atts.get("userCertificate").unwrap()[0].clone();
    let cert = X509Cert::from_der(&der_cert)?;
    let rsa = cert.public_key()?.rsa()?;
    let data = jwt.as_bytes();
    let mut buf = vec![0; rsa.size() as usize];
    let encrypted_len = rsa.public_encrypt(data, &mut buf, Padding::PKCS1).unwrap();
    ldap.unbind().await?;
    Ok(base64::encode_block(&buf[..encrypted_len]))
}

struct AppData {
    jwk: JsonWebKey,
    ldap_config: LdapConfig,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TokenClaims {
    exp: u64,
    iat: u64,
    sub: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Jwks {
    keys: Vec<JsonWebKey>,
}

#[get("/jwks")]
async fn jwks(req: HttpRequest) -> web::Json<Jwks> {
    let local_data = req
        .app_data::<web::Data<AppData>>()
        .expect("Key Data not found");
    let jwk = local_data.jwk.clone();

    let pub_key = jwk.key.to_public().unwrap().into_owned();
    let pub_jwk = jwk::JsonWebKey::new(pub_key);

    let jwks = vec![pub_jwk];
    let keys = Jwks { keys: jwks };
    web::Json(keys)
}

#[derive(Serialize, Deserialize, Debug)]
struct UserInfo {
    name: String,
}

#[post("/token")]
async fn token(user_info: web::Json<UserInfo>, state: web::Data<AppData>) -> impl Responder {
    let jwk = state.jwk.clone();
    let alg: jwt::Algorithm = jwk.algorithm.unwrap().into();
    let ctime = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let jwt_str = jwt::encode(
        &jwt::Header::new(alg),
        &TokenClaims {
            exp: ctime + 3600,
            iat: ctime,
            sub: user_info.name.clone(),
        },
        &jwk.key.to_encoding_key(),
    )
    .unwrap();
    encrypt_token(&user_info.name, jwt_str.as_str(), &state.ldap_config)
        .await
        .unwrap()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let contents = std::fs::read_to_string("key.json")?;
    let ldap_config_str = std::fs::read_to_string("ldap.json")?;
    let ldap_config = serde_json::from_str(&ldap_config_str)?;

    let mut jwk: JsonWebKey = serde_json::from_str(&contents)?;
    jwk.set_algorithm(jwk::Algorithm::ES256)
        .expect("Failed to set algorithm");

    let data = web::Data::new(AppData { jwk, ldap_config });

    HttpServer::new(move || {
        App::new().service(
            web::scope("/auth")
                .app_data(data.clone())
                .service(jwks)
                .service(token),
        )
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
