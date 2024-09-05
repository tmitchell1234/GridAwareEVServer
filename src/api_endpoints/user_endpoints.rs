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
use actix_web::{web, HttpResponse, Responder};
use serde_json::json;
use sqlx::postgres::{PgDatabaseError, PgPool};


/*
============================================================================
                        CUSTOM MODULE IMPORTS
============================================================================
*/
use crate::structs::structs::{ DeviceQueryPacket, Devices, NewUserParams, RegisterDevicePacket, UserLoginParams };

use crate::helper_functions::helper_functions::{ create_jwt, decode_user_jwt, hash_password, get_user_with_credentials, validate_api_key };


/*
============================================================================
                User create / login API endpoints
============================================================================
*/
pub async fn user_create(pool: web::Data<PgPool>, params: web::Json<NewUserParams>) -> impl Responder
{
    // first, validate the given API key
    let result = validate_api_key(pool.as_ref(), params.api_key()).await;

    match result
    {
        Ok(()) =>
        { /*  do nothing - key check passed */ }
        Err(e) =>
        { return HttpResponse::BadRequest().json(e); }
    }

    
    // hash the password and insert the new user into the DB
    let hashed_password = hash_password(&params.user_password());

    let query = sqlx::query!(
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

    match query {
        Ok(_) => HttpResponse::Ok().json("User created successfully"),
        Err(e) => {
            eprintln!("Failed to create user: {}", e);
            HttpResponse::InternalServerError().json("Failed to create user")
        }
    }
}


pub async fn user_login(pool: web::Data<PgPool>, params: web::Json<UserLoginParams>) -> impl Responder
{
    // first, validate the given API key
    let result = validate_api_key(pool.as_ref(), params.api_key()).await;

    match result
    {
        Ok(()) =>
        { /*  do nothing - key check passed */ }
        Err(e) =>
        { return HttpResponse::BadRequest().json(e); }
    }
    
    
    let hashed_password = hash_password(&params.user_password());

    // query the database (using helper function) to search for user credentials
    match get_user_with_credentials(pool.as_ref(), params.user_email(), &hashed_password).await
    {
        Ok(user) => {
            // create and return JWT
            let return_jwt = create_jwt(&user);
            // println!("Generated JWT = {}", return_jwt);
            HttpResponse::Ok().json(web::Json(json!({ "token": return_jwt })))

        },
        Err(sqlx::Error::RowNotFound) => {
            HttpResponse::BadRequest().json(web::Json(json!({ "error": "Incorrect email or password!"})))
        },
        Err(e) => {
            println!("{:?}", e);
            HttpResponse::BadRequest().json(web::Json(json!({ "error": "Some other error occured, see server stack trace" })))
        }
    }
}



// register device by user
pub async fn register_device(pool: web::Data<PgPool>, register_params: web::Json<RegisterDevicePacket> ) -> impl Responder
{
    // first, validate the given API key
    let result = validate_api_key(pool.as_ref(), register_params.api_key()).await;

    match result
    {
        Ok(()) =>
        { /*  do nothing - key check passed */ }
        Err(e) =>
        { return HttpResponse::BadRequest().json(e); }
    }


    // decode user jwt to get their user_id
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
pub async fn unregister_device_by_user(pool: web::Data<PgPool>, register_params: web::Json<RegisterDevicePacket>) -> impl Responder
{
    // first, validate the given API key
    let result = validate_api_key(pool.as_ref(), register_params.api_key()).await;

    match result
    {
        Ok(()) =>
        { /*  do nothing - key check passed */ }
        Err(e) =>
        { return HttpResponse::BadRequest().json(e); }
    }


    // decode user jwt to get their user_id
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


// get a list of devices registered to a user
pub async fn get_devices_for_user(pool: web::Data<PgPool>, device_query_params: web::Json<DeviceQueryPacket>) -> impl Responder
{
    // first, validate the given API key
    let result = validate_api_key(pool.as_ref(), device_query_params.api_key()).await;

    match result
    {
        Ok(()) =>
        { /*  do nothing - key check passed */ }
        Err(e) =>
        { return HttpResponse::BadRequest().json(e); }
    }


    // decode user jwt to get their user_id
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
