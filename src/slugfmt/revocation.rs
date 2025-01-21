pub struct Revocation {
    revocation_methods: Vec<RevocationMethods>
}

pub enum RevocationMethods {
    None,
    X59Revoke,
}