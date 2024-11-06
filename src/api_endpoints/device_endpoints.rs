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
use actix_web::{ web, HttpResponse, Responder };
use chrono::{ DateTime, Utc };
use serde_json::json;
use sqlx::postgres::PgPool;
use std::time::SystemTime;
use time::OffsetDateTime;

/*
============================================================================
                        CUSTOM MODULE IMPORTS
============================================================================
*/
use crate::helper_functions::helper_functions::validate_api_key;
use crate::structs::structs::{ DeviceCheckPacket, SmartControllerPacket };


/*
============================================================================
            Endpoints related to Smart Controller devices
============================================================================
*/

// receive and store controller reading packet
pub async fn store_controller_reading(pool: web::Data<PgPool>, controller_packet: web::Json<SmartControllerPacket>) -> impl Responder
{
    // first, validate the given API key
    let result = validate_api_key(pool.as_ref(), controller_packet.api_key()).await;

    match result
    {
        Ok(()) =>
        { /*  do nothing - key check passed */ }
        Err(e) =>
        { return HttpResponse::BadRequest().json(e); }
    }

    // parse datetime from string in packet
    let parsed_datetime: DateTime<Utc> = controller_packet.timestamp().parse().expect("Error: unable to parse timestamp from SmartControllerPacket!");

    // convert to OffsetDateTime to make sqlx happy
    let system_time: SystemTime = parsed_datetime.into();
    let time_offset: OffsetDateTime = OffsetDateTime::from(system_time);


    let result = sqlx::query!(
        r#"
        INSERT INTO measurements (time, device_mac_address, is_charging, frequency, voltage, current, battery_percentage)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
        time_offset,
        controller_packet.mac_address(),
        controller_packet.is_charging(),
        controller_packet.frequency(),
        controller_packet.voltage(),
        controller_packet.current(),
        controller_packet.battery_percentage()
    )
    .execute(pool.get_ref())
    .await;

    // println!("\nInserted data into measurements time series table!\n");

    match result {
        Ok(_) => HttpResponse::Ok().json("Smart controller package entered successfully!"),
        Err(e) => {
            eprintln!("Failed to enter smart controller package {}", e);
            HttpResponse::InternalServerError().json("Failed to enter smart controller package!")
        }
    }
}


// used by smart controller devices to periodically check if they are still registered.
// if not, the controller will stop it's routine of sending data packets to the server,
// erase it's wifi credentials, and await the next mobile app connection for setup.
pub async fn check_exists(pool: web::Data<PgPool>, controller_packet: web::Json<DeviceCheckPacket>) -> impl Responder
{
    // first, validate the given API key
    let result = validate_api_key(pool.as_ref(), controller_packet.api_key()).await;

    match result
    {
        Ok(()) =>
        { /*  do nothing - key check passed */ }
        Err(e) =>
        { return HttpResponse::BadRequest().json(e); }
    }

    // check that the device exists in the devices table
    let check_query = sqlx::query!(
        r#"
        SELECT *
        FROM devices
        WHERE device_mac_address = $1
        "#,
        controller_packet.device_mac_address()
    )
    .fetch_one( pool.get_ref() )
    .await;

    match check_query
    {
        Ok(_) =>
        {
            return HttpResponse::Ok().json( web::Json(json!({ "exists": true })) );
        },
        Err(_e) =>
        {
            return HttpResponse::BadRequest().json( web::Json(json!({ "exists": false})) );
        }
    }
}