/*
============================================================================
                HELPER FUNCTIONS FOR SERVER ACTIVITIES
============================================================================
*/

use jsonwebtoken::{ encode, decode, Algorithm, Header, Validation, EncodingKey, DecodingKey, TokenData };
use sha2::{ Sha256, Digest};
use std::env;
use std::collections::HashSet;

use crate::structs::{ User, UserDecodedJWT };



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

    let token = encode(&Header::new(Algorithm::HS256), &user_info, &EncodingKey::from_secret(&key_bytestring))
        .expect("Failed to encode token in create_jwt()!");

    println!("Created JWT token! {}", token);
    token
}



pub fn verify_jwt(token: &str) -> Result<TokenData<UserDecodedJWT>, jsonwebtoken::errors::Error>
{
    let key = env::var("JWT_SECRET").expect("JWT_SECRET environment variable not found!");
    let key_bytestring: Vec<u8> = key.as_bytes().to_vec();

    // let mut validation = Validation::default();
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false; // do not require validation of expiration field

    // clear the contents of required_spec_claims to prevent it from looking for expiration field
    validation.required_spec_claims = HashSet::new();

    decode::<UserDecodedJWT>(token, &DecodingKey::from_secret(&key_bytestring), &validation)
}