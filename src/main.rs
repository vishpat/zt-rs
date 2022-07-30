use ldap3::{LdapConn, Scope, SearchEntry};
use openssl::x509::X509 as X509Cert;
use openssl::rsa::{Rsa, Padding};
use openssl::base64;

fn main() -> Result<(), Box<dyn std::error::Error>> { 
    let mut ldap = LdapConn::new("ldap://localhost:389")?;
    ldap.simple_bind("uid=jwt,ou=service,dc=openmicroscopy,dc=org", "secret")?;

    let (rs, _res) = ldap.search(
        "dc=openmicroscopy,dc=org",
        Scope::Subtree,
        "(uid=alice)",
        vec!["userCertificate"],
    )?.success()?;

    if rs.len() == 0 {
        println!("No user found");
        return Ok(());
    }
    
    let entry = rs.into_iter().next().unwrap();
    let search_entry = SearchEntry::construct(entry);
    let bin_atts = search_entry.bin_attrs;
    let der_cert = bin_atts.get("userCertificate").unwrap()[0].clone();
    let cert = X509Cert::from_der(&der_cert)?;
    let rsa = cert.public_key()?.rsa()?;
    let data = b"abc";
    let mut buf = vec![0; rsa.size() as usize];
    let encrypted_len = rsa.public_encrypt(data, &mut buf, Padding::PKCS1).unwrap();
    println!("{}", base64::encode_block(&buf[..encrypted_len]));
    Ok(ldap.unbind()?)
}