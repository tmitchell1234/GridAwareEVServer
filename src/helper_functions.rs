/*
============================================================================
                HELPER FUNCTIONS FOR SERVER ACTIVITIES
============================================================================
*/

// use jsonwebtoken::{ encode, decode, Header, Validation, EncodingKey, DecodingKey, TokenData };
use jsonwebtoken::{ encode, Header, EncodingKey };
use sha2::{ Sha256, Digest};
use std::env;

use crate::structs::User;



pub fn hash_password(password: &str) -> String
{
    let mut hasher = Sha256::new();
    hasher.update(password);
    let result = hasher.finalize();
    format!{"{:x}", result}
}


// JWT functions
pub fn create_jwt(user_info: &User) -> String
{
    let key = env::var("JWT_SECRET").expect("JWT_SECRET environment variable not found!");
    let key_bytestring: Vec<u8> = key.as_bytes().to_vec();

    let token = encode(&Header::default(), &user_info, &EncodingKey::from_secret(&key_bytestring))
        .expect("Failed to encode token in create_jwt()!");

    println!("Created JWT token! {}", token);
    token
}

// fn verify_jwt(token: &str) -> Result<TokenData<User>, jsonwebtoken::errors::Error>
// {
//     let key = env::var("JWT_SECRET").expect("JWT_SECRET environment variable not found!");
//     let key_bytestring: Vec<u8> = key.as_bytes().to_vec();

//     let validation = Validation::default();

//     decode::<User>(token, &DecodingKey::from_secret(&key_bytestring), &validation)
// }