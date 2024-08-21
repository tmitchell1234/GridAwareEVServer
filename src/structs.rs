/*
============================================================================
                        STRUCT DEFINITIONS
                Used to receive JSON packets in API endpoints
============================================================================
*/

use serde::{Deserialize, Serialize};

// struct to hold JSON Web Token information
#[derive(Debug, Serialize, Deserialize)]
pub struct User
{
    pub user_type: String,
    pub user_email: String,
    pub user_first_name: Option<String>,
    pub user_last_name: Option<String>,
    pub user_organization: Option<String>,


    // user_date_registered: Option<chrono::DateTime<Utc>> // removing temporarily beause it's causing issues with the SQLX query

    // TODO: We can add an expiration time to the JSON Web token if we decide to do so with this field
    // exp: String
}

// no longer needed, but keeping for future syntax reference
impl User
{
    // getter methods
    // pub fn get_key(&self) -> &str { &self.api_key }
    // pub fn user_email(&self) -> &str { &self.user_email }
    // pub fn user_first_name(&self) -> Option<&str> { self.user_first_name.as_deref() }
    // pub fn user_last_name(&self) -> Option<&str> { self.user_last_name.as_deref() }
    // pub fn user_organization(&self) -> Option<&str> { self.user_organization.as_deref() }
}



// structs to receive API packets
#[derive(Deserialize)]
pub struct MyParams
{
    pub name: String,
}

#[derive(Deserialize)]
pub struct JsonPackage // for a JSON object with a single string, used for testing
{
    pub request_body: String,
}

#[derive(Deserialize)]
pub struct NewUserParams // for user_add endpoint
{
    user_type: String,
    user_email: String,
    user_password: String,
    user_first_name: String,
    user_last_name: String,
    user_organization: Option<String>,
}

impl NewUserParams
{
    pub fn user_type(&self) -> &str { &self.user_type }
    pub fn user_email(&self) -> &str { &self.user_email }
    pub fn user_password(&self) -> &str { &self.user_password }
    pub fn user_first_name(&self) -> &str { &self.user_first_name }
    pub fn user_last_name(&self) -> &str { &self.user_last_name }
    pub fn user_organization(&self) -> Option<&str> { self.user_organization.as_deref() }
}

#[derive(Deserialize)]
pub struct UserLoginParams
{
    user_email: String,
    user_password: String
}

impl UserLoginParams
{
    pub fn get_password_str(&self) -> &str
    {
        &self.user_password
    }

    // pub fn api_key(&self) -> &str { &self.api_key }
    pub fn user_email(&self) -> &str { &self.user_email }
}