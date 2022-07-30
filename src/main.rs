use ldap3::{LdapConn, Scope, SearchEntry};
use ldap3::result::Result;

fn main() -> Result<()> {
    let mut ldap = LdapConn::new("ldap://localhost:389")?;
    ldap.simple_bind("uid=jwt,ou=service,dc=openmicroscopy,dc=org", "secret")?;

    let (rs, _res) = ldap.search(
        "dc=openmicroscopy,dc=org",
        Scope::Subtree,
        "(uid=alice)",
        vec!["userCertificate"],
    )?.success()?;
    for entry in rs {
        println!("{:?}", SearchEntry::construct(entry));
    }
    Ok(ldap.unbind()?)
}