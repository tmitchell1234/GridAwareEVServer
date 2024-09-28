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
use actix_web::{web, HttpResponse, Responder };
use sqlx::postgres::PgPool;


/*
============================================================================
                        CUSTOM MODULE IMPORTS
============================================================================
*/
use crate::structs::structs::{AdminGenericPacket, AdminUserDevicePacket, DeviceList, User};

// use crate::helper_functions::helper_functions::{ create_jwt, decode_user_jwt, hash_password, get_user_with_credentials, validate_api_key };
use crate::helper_functions::helper_functions::validate_api_key_admin;



pub async fn test_admin_key(pool: web::Data<PgPool>, params: web::Json<AdminGenericPacket>) -> impl Responder
{
    // validate the key belongs to an admin
    let result = validate_api_key_admin(pool.as_ref(), params.api_key()).await;

    match result
    {
        Ok(()) =>
        { /*  do nothing - key check passed */ }
        Err(e) =>
        {
            eprintln!("Key validation failure in test_admin_key():");
            eprintln!("{}\n", e);
            return HttpResponse::BadRequest().json("Invalid key!");
        }
    }
    HttpResponse::Ok().finish()
}

// get a list of all users registered with the system (everything in the users table of the database)
pub async fn admin_get_all_users(pool: web::Data<PgPool>, params: web::Json<AdminGenericPacket>) -> impl Responder
{
    // validate the key belongs to an admin
    let result = validate_api_key_admin(pool.as_ref(), params.api_key()).await;

    match result
    {
        Ok(()) =>
        { /*  do nothing - key check passed */ }
        Err(e) =>
        {
            eprintln!("Key validation failure in admin_get_all_users():");
            eprintln!("{}\n", e);
            return HttpResponse::BadRequest().json("Invalid key!");
        }
    }

    // get everything in the users table (with the exception of the password)
    let all_users_query = sqlx::query_as!(
        User,
        r#"
        SELECT user_id, user_type, user_email, user_first_name, user_last_name, user_organization
        FROM users
        "#
    )
    .fetch_all( pool.get_ref() )
    .await;

    match all_users_query
    {
        Ok(user_list) =>
        {
            println!("Successfully queried all users in admin_get_all_users().");
            return HttpResponse::Ok().json(user_list);
        },
        Err(e) =>
        {
            eprintln!("Error querying database in admin_get_all_users():");
            eprintln!("{:?}", e);
            return HttpResponse::InternalServerError().json("Database error, check server logs.");
        }
    }
}



pub async fn admin_get_all_devices(pool: web::Data<PgPool>, params: web::Json<AdminGenericPacket>) -> impl Responder
{
    // validate the key belongs to an admin
    let result = validate_api_key_admin(pool.as_ref(), params.api_key()).await;

    match result
    {
        Ok(()) =>
        { /*  do nothing - key check passed */ }
        Err(e) =>
        {
            eprintln!("Key validation failure in admin_get_all_devices():");
            eprintln!("{}\n", e);
            return HttpResponse::BadRequest().json("Invalid key!");
        }
    }

    // get everything in the users table (with the exception of the password)
    let all_devices_query = sqlx::query_as!(
        DeviceList,
        r#"
        SELECT device_id, user_id, device_mac_address
        FROM devices
        "#
    )
    .fetch_all( pool.get_ref() )
    .await;

    match all_devices_query
    {
        Ok(device_list) =>
        {
            println!("Successfully queried all devices in admin_get_all_devices().");
            return HttpResponse::Ok().json(device_list);
        },
        Err(e) =>
        {
            eprintln!("Error querying database in admin_get_all_devices():");
            eprintln!("{:?}", e);
            return HttpResponse::InternalServerError().json("Database error, check server logs.");
        }
    }
}


// get list of devices associated with particular user
pub async fn admin_get_devices_for_user(pool: web::Data<PgPool>, params: web::Json<AdminUserDevicePacket>) -> impl Responder
{
    // validate the key belongs to an admin
    let result = validate_api_key_admin(pool.as_ref(), params.api_key()).await;

    match result
    {
        Ok(()) =>
        { /*  do nothing - key check passed */ }
        Err(e) =>
        {
            eprintln!("Key validation failure in admin_get_devices_for_user():");
            eprintln!("{}\n", e);
            return HttpResponse::BadRequest().json("Invalid key!");
        }
    }

    // get everything in the users table (with the exception of the password)
    let user_devices_query = sqlx::query_as!(
        DeviceList,
        r#"
        SELECT device_id, user_id, device_mac_address
        FROM devices
        WHERE user_id = $1
        "#,
        params.user_id()
    )
    .fetch_all( pool.get_ref() )
    .await;

    match user_devices_query
    {
        Ok(device_list) =>
        {
            println!("Successfully queried all devices in admin_get_devices_for_user().");
            return HttpResponse::Ok().json(device_list);
        },
        Err(e) =>
        {
            eprintln!("Error querying database in admin_get_devices_for_user():");
            eprintln!("{:?}", e);
            return HttpResponse::InternalServerError().json("Database error, check server logs.");
        }
    }
}

