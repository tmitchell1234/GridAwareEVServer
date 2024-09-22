/*
    GRID AWARE EV CHARGING - Web server

    A Computer Science Senior Design project by:
    JV, BB, SP, TM
*/

/*
==================================================
                STRUCT DEFINITIONS
        Used to receive JSON packets in API endpoints
==================================================
*/

// use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use time::serde::rfc3339;
use time::OffsetDateTime;

/*
==================================================
                USER INFORMATION
==================================================
*/

// struct to hold user information when queried from the database
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub user_id: i32,
    pub user_type: String,
    pub user_email: String,
    pub user_first_name: Option<String>,
    pub user_last_name: Option<String>,
    pub user_organization: Option<String>
    
    // user_date_registered: Option<chrono::DateTime<Utc>> // removing temporarily beause it's causing issues with the SQLX query

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
#[serde(deny_unknown_fields)]
pub struct NewUserParams
// for user_add endpoint
{
    api_key: String,
    user_type: String,
    user_email: String,
    user_password: String,
    user_first_name: String,
    user_last_name: String,
    user_organization: Option<String>,
}

impl NewUserParams
{
    pub fn api_key(&self) -> &str { &self.api_key }
    pub fn user_type(&self) -> &str { &self.user_type }
    pub fn user_email(&self) -> &str { &self.user_email }
    pub fn user_password(&self) -> &str { &self.user_password }
    pub fn user_first_name(&self) -> &str { &self.user_first_name }
    pub fn user_last_name(&self) -> &str { &self.user_last_name }
    pub fn user_organization(&self) -> Option<&str> { self.user_organization.as_deref() }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserLoginParams
{
    api_key: String,
    user_email: String,
    user_password: String,
}

impl UserLoginParams
{
    pub fn api_key(&self) -> &str { &self.api_key }
    pub fn user_password(&self) -> &str { &self.user_password }
    pub fn user_email(&self) -> &str { &self.user_email }
}

/*
==================================================
            SMART CONTROLLER PACKETS
==================================================
*/

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmartControllerPacket
{
    api_key: String,
    timestamp: String,
    mac_address: String,
    frequency: f32,
    voltage: f32,
    current: f32,
}

impl SmartControllerPacket
{
    pub fn api_key(&self) -> &str { &self.api_key }
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
#[serde(deny_unknown_fields)]
pub struct RegisterDevicePacket
{
    api_key: String,
    user_jwt: String,
    device_mac_address: String
}

impl RegisterDevicePacket
{
    pub fn api_key(&self) -> &str { &self.api_key }
    pub fn user_jwt(&self) -> &str { &self.user_jwt }
    pub fn device_mac_address(&self) -> &str { &self.device_mac_address }
}


/*
==================================================
            QUERY USER DEVICES PACKETS
==================================================
*/

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQueryPacket
{
    api_key: String,
    user_jwt: String
}

impl DeviceQueryPacket
{
    pub fn api_key(&self) -> &str { &self.api_key }
    pub fn user_jwt(&self) -> &str { &self.user_jwt }
}

// used to create array of devices in /get_devices_for_user endpoint
#[derive(Debug, Serialize)]
pub struct Devices
{
    pub device_mac_address: Option<String>
}

/*
==================================================
            QUERY DATA PACKETS
==================================================
*/
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataQueryPacket
{
    api_key: String,
    user_jwt: String,
    device_mac_address: String,
    time_seconds: f64
}

impl DataQueryPacket
{
    pub fn api_key(&self) -> &str { &self.api_key }
    pub fn user_jwt(&self) -> &str { &self.user_jwt }
    pub fn device_mac_address(&self) -> &str { &self.device_mac_address }
    pub fn time_seconds(&self) -> &f64 { &self.time_seconds }
}

#[derive(Debug, Serialize)]
pub struct Measurements
{
    // force formatting of timestamp as YYYY-MM-DD HH:MM:SS.MS
    #[serde(with = "rfc3339")]
    pub time: OffsetDateTime,
    pub device_mac_address: String,
    pub frequency: f32,
    pub voltage: f32,
    pub current: f32
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataQueryByDatePacket
{
    api_key: String,
    user_jwt: String,
    device_mac_address: String,
    date_string: String
}

impl DataQueryByDatePacket
{
    pub fn api_key(&self) -> &str { &self.api_key }
    pub fn user_jwt(&self) -> &str { &self.user_jwt }
    pub fn device_mac_address(&self) -> &str { &self.device_mac_address }
    pub fn date_string(&self) -> &str { &self.date_string }
}


/*
==================================================
            PASSWORD RESET PACKETS
==================================================
*/

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordResetPacket
{
    api_key: String,
    user_email: String
}

impl PasswordResetPacket
{
    pub fn api_key(&self) -> &str { &self.api_key }
    pub fn user_email(&self) -> &str { &self.user_email }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordResetCodePacket
{
    api_key: String,
    user_email: String,
    reset_code: i32,
    new_password: String
}

impl PasswordResetCodePacket
{
    pub fn api_key(&self) -> &str { &self.api_key }
    pub fn user_email(&self) -> &str { &self.user_email }
    pub fn reset_code(&self) -> &i32 { &self.reset_code }
    pub fn new_password(&self) -> &str { &self.new_password }
}