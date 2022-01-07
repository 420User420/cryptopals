#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}

#[derive(PartialEq)]
enum Role {
    User,
    Admin,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Role::User => write!(f, "user"),
            Role::Admin => write!(f, "admin"),
        }
    }
}

impl Role {
    pub fn from_string(s: &str) -> Result<Role> {
        match s {
            "admin" => Ok(Role::Admin),
            "user" => Ok(Role::User),
            _ => panic!("Invalid role string: {}", s),
        }
    }
}

struct Profile {
    email: String,
    uid: u32,
    role: Role,
    key: Option<[u8; 16]>,
}

impl Profile {
    fn encode(&self) -> Result<String> {
        Ok(format!(
            "email={}&uid={}&role={}",
            self.email, self.uid, self.role
        ))
    }

    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }

    pub fn from_encoded(encoded: &str) -> Result<Profile> {
        let url_obj = Url::parse(&format!("https://example.com/?{}", encoded))?;
        let mut pairs = url_obj.query_pairs();
        let mut email = String::new();
        let mut uid = 0u32;
        let mut role = Role::User;

        for (k, v) in pairs {
            match k {
                Cow::Borrowed("email") => email = v.into_owned(),
                Cow::Borrowed("uid") => uid = v.into_owned().parse::<u32>()?,
                Cow::Borrowed("role") => role = Role::from_string(v.as_ref())?,
                _ => panic!("Invalid key found in encoded profile: {}", k),
            }
        }

        Ok(Profile {
            email,
            uid,
            role,
            key: None,
        })
    }

    fn encrypt(&self) -> Result<String> {
        if self.key.is_none() {
            panic!("Cannot encrypt profile because it has no key.")
        }

        Ok(hex::vec_u8_to_string(aes::encrypt_aes_128_ecb(
            &self.encode()?.as_bytes(),
            &self.key.unwrap(),
        )?))
    }
}

fn profile_for(email: &str) -> Result<Profile> {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = rng.gen();
    }
    let uid = rng.gen();
    Ok(Profile {
        email: email.to_string().replace("&", "").replace("=", ""),
        uid,
        role: Role::User,
        key: Some(key),
    })
}
