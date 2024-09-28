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
use chrono::{ DateTime, Utc };
use sqlx::postgres::PgPool;
use std::time::SystemTime;
use time::OffsetDateTime;

/*
============================================================================
                        CUSTOM MODULE IMPORTS
============================================================================
*/
use crate::helper_functions::helper_functions::validate_api_key;
use crate::structs::structs::SmartControllerPacket;


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
        INSERT INTO measurements (time, device_mac_address, is_charging, frequency, voltage, current)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        time_offset,
        controller_packet.mac_address(),
        controller_packet.is_charging(),
        controller_packet.frequency(),
        controller_packet.voltage(),
        controller_packet.current()
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
