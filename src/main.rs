use ldap3::{LdapConn, Scope, SearchEntry};
use openssl::x509::X509 as X509Cert;

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
    println!("{:?}", cert.public_key());
    Ok(ldap.unbind()?)
}