use oracle::Oracle;
use rand::Rng;
use std::borrow::Cow;
use std::fmt;
use url::Url;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_eats_special_chars() {
        let profile = profile_for("a&role=admin@a.com");

        assert_eq!(profile.email, "aroleadmin@a.com");
    }
}

#[derive(PartialEq)]
pub enum Role {
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

pub struct Profile {
    email: String,
    uid: u32,
    role: Role,
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Email: {}\nUID: {}\nRole: {}",
            self.email, self.uid, self.role
        )
    }
}

impl Profile {
    pub fn encode(&self) -> Result<String> {
        let s = format!("email={}&uid={}&role={}", self.email, self.uid, self.role);
        // println!("Encode: {}", s);
        Ok(s)
    }

    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }

    pub fn from_encoded(encoded: &str) -> Result<Self> {
        let url_obj = Url::parse(&format!("https://example.com/?{}", encoded))?;
        let pairs = url_obj.query_pairs();
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

        Ok(Profile { email, uid, role })
    }
}

pub struct ProfileOracle {
    key: [u8; 16],
    uid: u32,
}

impl Oracle for ProfileOracle {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        /* let clean_email = data
            .iter()
            .filter(|c| **c < 127)
            .cloned()
            .collect::<Vec<u8>>();
        */
        if data
            .iter()
            .any(|&c| !c.is_ascii() || c == b'&' || c == b'=')
        {
            panic!("Invalid input");
        }

        self.encrypt_profile(&Profile {
            email: String::from_utf8(data.to_vec())?,
            uid: self.uid,
            role: Role::User,
        })
    }
}

impl ProfileOracle {
    pub fn new() -> ProfileOracle {
        let mut rng = rand::thread_rng();
        let mut key = [0u8; 16];
        for i in 0..16 {
            key[i] = rng.gen::<u8>();
        }

        let uid = rng.gen::<u32>();

        ProfileOracle { key, uid }
    }

    pub fn encrypt_profile(&self, profile: &Profile) -> Result<Vec<u8>> {
        aes::encrypt_aes_128_ecb(profile.encode()?.as_bytes(), &self.key)
    }

    pub fn profile_from_encrypted(&self, enc: &Vec<u8>) -> Result<Profile> {
        let dec = aes::decrypt_aes_128_ecb(enc, &self.key)?;

        Profile::from_encoded(&String::from_utf8(dec)?)
    }

    pub fn profile_for(&self, email: &str) -> Result<Vec<u8>> {
        let uid = self.uid;

        self.encrypt_profile(&Profile {
            email: email.to_string().replace("&", "%26").replace("=", "%3D"),
            uid,
            role: Role::User,
        })
    }
}
