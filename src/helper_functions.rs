/*
============================================================================
                HELPER FUNCTIONS FOR SERVER ACTIVITIES
============================================================================
*/

// use actix_web::web;
// use dotenvy::dotenv;
use jsonwebtoken::{ encode, decode, Algorithm, Header, Validation, EncodingKey, DecodingKey, TokenData };
use sha2::{ Sha256, Digest};
use sqlx::postgres::{PgDatabaseError, PgPool};
use sqlx;
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
    return token;
}


pub fn decode_user_jwt(token: &str) -> Result<TokenData<UserDecodedJWT>, jsonwebtoken::errors::Error>
{
    let key = env::var("JWT_SECRET").expect("JWT_SECRET environment variable not found!");
    let key_bytestring: Vec<u8> = key.as_bytes().to_vec();

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false; // do not require validation of expiration field

    // clear the contents of required_spec_claims to prevent it from looking for expiration field
    validation.required_spec_claims = HashSet::new();

    decode::<UserDecodedJWT>(token, &DecodingKey::from_secret(&key_bytestring), &validation)
}



pub async fn check_api_key(pool: &PgPool, key: &String, user_id: i32) -> Result< (), String>
{
    // // first, hash the key
    let hashed_key = get_hashed_key(key);

    // query the database for the API key, associated with a given user
    let result = sqlx::query!(
        r#"
        SELECT user_id, key_data
        FROM apikeys
        WHERE user_id = $1 AND key_data = $2
        "#,
        user_id,
        hashed_key
    )
    .fetch_one(pool)
    .await;

    match result
    {
        Ok(_) =>
        {
            // println!("Result of row:");
            // println!("{:?}", row);

            // at this point, the user_id and api key have been validated.
            // return a success message.
            Ok(())
        },
        // 
        Err(e) =>
        {
            println!("\nError in getting database result in check_api_key():");
            println!("{:?}\n", e);
            return Err(format!("API key validation failure!"));
        }
    }
}

fn get_hashed_key(base_key: &str) -> String
{
    let mut hasher = Sha256::new();
    hasher.update(base_key.as_bytes());

    format!("{:x}", hasher.finalize())
}