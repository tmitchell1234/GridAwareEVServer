/*
==================================================
                STRUCT DEFINITIONS
        Used to receive JSON packets in API endpoints
==================================================
*/

use serde::{Deserialize, Serialize};

/*
==================================================
                USER INFORMATION
==================================================
*/

// struct to hold user information
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub user_id: i32,
    pub user_type: String,
    pub user_email: String,
    pub user_first_name: Option<String>,
    pub user_last_name: Option<String>,
    pub user_organization: Option<String>, // user_date_registered: Option<chrono::DateTime<Utc>> // removing temporarily beause it's causing issues with the SQLX query

    // TODO: We can add an expiration time to the JSON Web token if we decide to do so with this field
    // exp: String
}

// struct to hold JSON Web Token information
#[derive(Debug, Serialize, Deserialize)]
pub struct UserDecodedJWT
{
    pub user_id: i32,
    pub user_type: String,
    pub user_email: String,
    pub user_first_name: Option<String>,
    pub user_last_name: Option<String>,
    pub user_organization: Option<String>,
}

/*
==================================================
            VARIOUS API PACKETS
==================================================
*/

#[derive(Deserialize)]
pub struct NewUserParams
// for user_add endpoint
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
    user_password: String,
}

impl UserLoginParams
{
    pub fn get_password_str(&self) -> &str { &self.user_password }

    // pub fn api_key(&self) -> &str { &self.api_key }
    pub fn user_email(&self) -> &str { &self.user_email }
}

/*
==================================================
            SMART CONTROLLER PACKETS
==================================================
*/

#[derive(Debug, Serialize, Deserialize)]
pub struct SmartControllerPacket
{
    timestamp: String,
    mac_address: String,
    frequency: f32,
    voltage: f32,
    current: f32,
}

impl SmartControllerPacket
{
    pub fn timestamp(&self) -> &str { &self.timestamp }
    pub fn mac_address(&self) -> &str { &self.mac_address }
    pub fn frequency(&self) -> &f32 { &self.frequency }
    pub fn voltage(&self) -> &f32 { &self.voltage }
    pub fn current(&self) -> &f32 { &self.current }
}


/*
==================================================
            REGISTER DEVICE PACKETS
==================================================
*/

#[derive(Serialize, Deserialize)]
pub struct RegisterDevicePacket
{
    user_jwt: String,
    device_mac_address: String
}

impl RegisterDevicePacket
{
    pub fn user_jwt(&self) -> &str { &self.user_jwt }
    pub fn device_mac_address(&self) -> &str { &self.device_mac_address }
}


/*
==================================================
            QUERY USER DEVICES PACKET
==================================================
*/

#[derive(Deserialize)]
pub struct DeviceQueryPacket
{
    user_jwt: String
}

impl DeviceQueryPacket
{
    pub fn user_jwt(&self) -> &str { &self.user_jwt }
}

#[derive(Debug, Serialize)]
pub struct Devices
{
    pub device_mac_address: Option<String>
}

#[derive(Debug, Deserialize)]
pub struct TestPacket
{
    pub api_key: String,
    pub user_id: i32
}