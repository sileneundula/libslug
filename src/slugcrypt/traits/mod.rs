//use crate::slugfmt::certificate::cert::X59Certificate;
use crate::slugfmt::x59cert::X59Cert;

pub trait Signature {

}

pub trait AsymmetricEncryption {

}

pub trait SymmetricEncryption {
    
}

pub trait Hashing {

}

pub trait Rand {

}

pub trait X59Certificate {
    /// # Into Certificate
    /// 
    /// This converts the keypair into an X59Certificate.
    /// 
    /// ```rust
    /// 
    /// ```
    fn into_certificate<T: X59Certificate>(&self) -> X59Cert<T>;
}

pub trait X59Signature {

}

pub trait X59Encryption {

}

pub trait X59SymmetricEncryption {
    
}