/*
============================================================================
                HELPER FUNCTIONS FOR SERVER ACTIVITIES
============================================================================
*/

use jsonwebtoken::{ encode, decode, Algorithm, Header, Validation, EncodingKey, DecodingKey, TokenData };
use sha2::{ Sha256, Digest};
use sqlx::postgres::PgPool;
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

    println!("\nCreated JWT: {}\n", token);
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



pub async fn validate_api_key(pool: &PgPool, key: &str) -> Result< (), String>
{
    // // first, hash the key
    let hashed_key = get_hashed_key(key);

    // query the database for the API key
    let result = sqlx::query!(
        r#"
        SELECT key_data
        FROM apikeys
        WHERE key_data = $1
        "#,
        hashed_key
    )
    .fetch_one(pool)
    .await;

    match result
    {
        Ok(_) =>
        {
            // the api key has been validated.
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

// helper function for login, queries the database with appropriate tools to catch and report errors
pub async fn get_user_with_credentials(pool: &PgPool, user_email: &str, hashed_password: &str) -> Result<User, sqlx::Error>
{
    let result = sqlx::query_as!(
        User,
        "SELECT user_id, user_type, user_email, user_first_name, user_last_name, user_organization
        FROM users
        WHERE user_email = $1 AND user_password = $2",
        user_email,
        hashed_password
    )
    .fetch_one(pool)
    .await;

    result
}