pub struct Registar {
    registar: Vec<RegistarTypes>
}

pub enum RegistarTypes {
    NoRegistar,
    X59Registar,

    
    Custom(u16),
}