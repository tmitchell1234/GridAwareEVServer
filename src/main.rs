/*
    GRID AWARE EV CHARGING - Web server

    A Computer Science Senior Design project by:
    JV, BB, SP, TM
*/

/*
============================================================================
                            LIBRARY (CRATE) IMPORTS
============================================================================
*/
use actix_cors::Cors;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use chrono::{ DateTime, Utc };
use dotenvy::dotenv;
// use jsonwebtoken::TokenData;
use serde_json::json;
use sqlx::postgres::{PgDatabaseError, PgPool};
use sqlx;
use std::env;
use std::time::SystemTime;
use time::{OffsetDateTime, PrimitiveDateTime};


// module imports
mod structs;
use crate::structs::{ DeviceQueryPacket, Devices, NewUserParams, RegisterDevicePacket, SmartControllerPacket, User, UserLoginParams };


// DELETE ME
use structs::TestPacket;

mod helper_functions;
use crate::helper_functions::{ check_api_key, create_jwt, decode_user_jwt, hash_password};


/*
============================================================================
                        MAIN FUNCTION ENTRYPOINT
============================================================================
*/
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok(); // load environment variables file

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    println!("database_url = ");
    println!("{}", database_url);

    let pool = PgPool::connect(&database_url).await.expect("Failed to create pool.");

    println!("Successfully connected pool!");
 
    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(web::Data::new(pool.clone()))
            .route("/get_devices_for_user", web::get().to(get_devices_for_user))
            .route("/register_device", web::post().to(register_device))
            .route("/unregister_device_by_user", web::post().to(unregister_device_by_user))
            .route("/store_controller_reading", web::post().to(store_controller_reading))
            .route("/user_create", web::post().to(user_create))
            .route("/user_login", web::post().to(user_login))
            .route("/test_api_key_fn", web::post().to(test_api_key_fn))
    })
    .bind("0.0.0.0:3000")? // for production environment
    .run()
    .await
}

/*
============================================================================
                        BEGIN API ENDPOINTS
============================================================================
*/


/*
============================================================================
                User create / login API endpoints
============================================================================
*/
async fn user_create(pool: web::Data<PgPool>, params: web::Json<NewUserParams>) -> impl Responder
{
    let hashed_password = hash_password(&params.user_password());

    let result = sqlx::query!(
        r#"
        INSERT INTO Users (user_type, user_email, user_password, user_first_name, user_last_name, user_organization)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        params.user_type(),
        params.user_email(),
        hashed_password,
        params.user_first_name(),
        params.user_last_name(),
        params.user_organization()
    )
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(_) => HttpResponse::Ok().json("User created successfully"),
        Err(e) => {
            eprintln!("Failed to create user: {}", e);
            HttpResponse::InternalServerError().json("Failed to create user")
        }
    }
}


async fn user_login(pool: web::Data<PgPool>, params: web::Json<UserLoginParams>) -> impl Responder
{
    let hashed_password = hash_password(&params.get_password_str());

    // query the database (using helper function below) to search for user credentials
    match get_user_with_credentials(pool.as_ref(), params.user_email(), &hashed_password).await
    {
        Ok(user) => {
            // create and return JWT
            let return_jwt = create_jwt(&user);
            // println!("Generated JWT = {}", return_jwt);
            HttpResponse::Ok().json(web::Json(json!({ "token": return_jwt })))

        },
        Err(sqlx::Error::RowNotFound) => {
            // println!("No user found with given credentials!");
            HttpResponse::BadRequest().json(web::Json(json!({ "error": "Invalid email or password!"})))
        },
        Err(e) => {
            println!("{:?}", e);
            HttpResponse::BadRequest().json(web::Json(json!({ "error": "Some other error occured, see server stack trace" })))
        }
    }
}

// helper function for login, queries the database with appropriate tools to catch and report errors
async fn get_user_with_credentials(pool: &PgPool, user_email: &str, hashed_password: &str) -> Result<User, sqlx::Error>
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

/*
============================================================================
            Endpoints related to Smart Controller devices
============================================================================
*/

// receive and store controller reading packet
async fn store_controller_reading(pool: web::Data<PgPool>, controllerpacket: web::Json<SmartControllerPacket>) -> impl Responder
{
    // parse datetime from string in packet
    let parsed_datetime: DateTime<Utc> = controllerpacket.timestamp().parse().expect("Error: unable to parse timestamp from SmartControllerPacket!");

    // convert to OffsetDateTime to make sqlx happy
    let system_time: SystemTime = parsed_datetime.into();
    let time_offset: OffsetDateTime = OffsetDateTime::from(system_time);


    let result = sqlx::query!(
        r#"
        INSERT INTO measurements (time, device_mac_address, frequency, voltage, current)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        time_offset,
        controllerpacket.mac_address(),
        controllerpacket.frequency(),
        controllerpacket.voltage(),
        controllerpacket.current()
    )
    .execute(pool.get_ref())
    .await;

    println!("\nInserted data into measurements time series table!\n");

    match result {
        Ok(_) => HttpResponse::Ok().json("Smart controller package entered successfully!"),
        Err(e) => {
            eprintln!("Failed to enter smart controller package {}", e);
            HttpResponse::InternalServerError().json("Failed to enter smart controller package!")
        }
    }
}

// register device by user
async fn register_device(pool: web::Data<PgPool>, register_params: web::Json<RegisterDevicePacket> ) -> impl Responder
{
    // first, get user jwt information to get their userid
    match decode_user_jwt(register_params.user_jwt())
    {
        Ok(user_data_packet) =>
        {
            let user_data = user_data_packet.claims;

            // now store it in the devices table
            let result = sqlx::query!(
                r#"
                INSERT INTO devices ( user_id, device_mac_address )
                VALUES ($1, $2)
                "#,
                user_data.user_id,
                register_params.device_mac_address()
            )
            .execute(pool.get_ref())
            .await;

            match result
            {
                Ok(message) =>
                {
                    println!("Entered device with mac address {} successfully! {:?}", register_params.device_mac_address(), message);
                    HttpResponse::Ok().json("Device with mac address registered successfully!")
                }
                
                Err(sqlx::Error::Database(database_error)) =>
                {
                    // attempt to parse if the devie was already registered.
                    // (violates unique mac address contraints)
                    if let Some(postgres_error) = database_error.try_downcast_ref::<PgDatabaseError>()
                    {
                        if postgres_error.code() == "23505" {
                            HttpResponse::BadRequest().json("Error, device with given mac address is already registered!")
                        }
                        else {
                            println!("{}", database_error);
                            HttpResponse::BadRequest().json("Error, database insertion failed. See server stack trace for more info.")
                        }
                    }
                    
                    else {
                        println!("{}", database_error);
                        HttpResponse::BadRequest().json("Error, database insertion failed. See server stack trace for more info.")
                    }
                }

                // some other weird error occurred
                Err(e) =>
                {
                    println!("Other error in register_device: {}", e);
                    HttpResponse::InternalServerError().json("Error, database insertion failed. See server stack trace for more info.")
                }
            }
        }
        Err(e) =>
        {
            println!("Failed to decode JWT: {}", e);
            HttpResponse::BadRequest().json(web::Json(json!({ "error": "Invalid or expired JWT given." })))
        }
    }
}


// remove device from devices table, called by individual user which provides their JSON web token.
// we can re-use the RegisterDevicePacket struct.
async fn unregister_device_by_user(pool: web::Data<PgPool>, register_params: web::Json<RegisterDevicePacket>) -> impl Responder
{
    // first, get user jwt information to get their userid
    match decode_user_jwt(register_params.user_jwt())
    {
        Ok(user_data_packet) =>
        {
            let user_data = user_data_packet.claims;

            // first, check if the device actually belongs to the given user
            let user_device_check = sqlx::query!(
                r#"
                SELECT user_id, device_mac_address
                FROM devices
                WHERE user_id = $1 AND device_mac_address = $2
                "#,
                user_data.user_id,
                register_params.device_mac_address()
            )
            .fetch_one(pool.get_ref())
            .await;


            // check the result of this query
            match user_device_check
            {
                Ok(message) =>
                {
                    // query succeeded, do nothing and proceed to delete query
                    println!("In unregister_device_user, result of user_device_check is:");
                    println!("{:?}", message);
                }
                Err(e) =>
                {
                    println!("Error in user_device_check: {}", e);
                    return HttpResponse::BadRequest().json("Bad request: user not associated with device!");
                }
            }

            // next, delete all references to device_mac_address in measurements table
            let remove_device_references = sqlx::query!(
                r#"
                DELETE FROM measurements
                WHERE device_mac_address = $1
                "#,
                register_params.device_mac_address()
            )
            .execute(pool.get_ref())
            .await;

            // check that measurements deletion worked
            match remove_device_references
            {
                Ok(message) =>
                {
                    // query succeeded, do nothing and progress to device table deletion
                    println!("In unregister_device_user, reslut of measurement deletion is:");
                    println!("{:?}", message);
                }
                Err (e) =>
                {
                    println!("Error in remove_device_references: {}", e);
                    return HttpResponse::InternalServerError().json("Server error, unable to remove device references in measurements table!");
                }
            }

            // now remove from the devices table
            let result = sqlx::query!(
                r#"
                DELETE FROM devices
                WHERE user_id = $1 AND device_mac_address = $2
                "#,
                user_data.user_id,
                register_params.device_mac_address()
            )
            .execute(pool.get_ref())
            .await;

            match result
            {
                Ok(message) =>
                {
                    println!("Removed device with mac address {} successfully! {:?}", register_params.device_mac_address(), message);
                    HttpResponse::Ok().json("Device with mac address removed successfully!")
                }

                // some other weird error occurred
                Err(e) =>
                {
                    println!("Other error in unregister_device_user: {}", e);
                    HttpResponse::InternalServerError().json("Error, database deletion failed. Device is not registered or not associated with given user.")
                }
            }
        }
        Err(e) =>
        {
            println!("Failed to decode JWT: {}", e);
            HttpResponse::BadRequest().json(web::Json(json!({ "error": "Invalid or expired JWT given." })))
        }
    }
}

async fn get_devices_for_user(pool: web::Data<PgPool>, device_query_params: web::Json<DeviceQueryPacket>) -> impl Responder
{
    // decode the user's JWT
    match decode_user_jwt(device_query_params.user_jwt())
    {
        Ok(user_data_packet) =>
        {
            let user_id = user_data_packet.claims.user_id;

            // get and return list of devices from the database
            let result = sqlx::query_as!(
                Devices,
                r#"
                SELECT device_mac_address
                FROM devices
                WHERE user_id = $1
                "#,
                user_id
            )
            .fetch_all(pool.get_ref())
            .await;
            
            println!("Got list of devices successfully!");
            println!("{:?}", result);

            match result
            {
                Ok(device_list) =>
                {
                    HttpResponse::Ok().json(device_list)
                }
                Err(e) =>
                {
                    println!("Error querying DB in get_devices...");
                    println!("{:?}\n", e);
                    HttpResponse::InternalServerError().json("Error querying database! Check server stack trace.")
                }
            }
        }
        Err (e) =>
        {
            println!("Failed to decode JWT: {}", e);
            HttpResponse::BadRequest().json(web::Json(json!({ "error": "Invalid or expired JWT given." })))
        }
    }
    // HttpResponse::Ok()
}

async fn test_api_key_fn(pool: web::Data<PgPool>, test_params: web::Json<TestPacket>) -> impl Responder
{
    let result = check_api_key(pool.as_ref(), &test_params.api_key, test_params.user_id).await;

    match result
    {
        Ok(()) =>
        {
            // do nothing. key check passed.
            HttpResponse::Ok().finish()
        }
        Err(e) =>
        {
            println!("Result is:");
            println!("{:?}", e);
            return HttpResponse::BadRequest().json(e);
        }
    }
}