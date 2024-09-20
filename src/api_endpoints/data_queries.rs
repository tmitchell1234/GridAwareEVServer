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
use sqlx::postgres::PgPool;

/*
============================================================================
                        CUSTOM MODULE IMPORTS
============================================================================
*/
use crate::helper_functions::helper_functions::{ decode_user_jwt, validate_api_key };
use crate::structs::structs::{ DataQueryPacket, Measurements };



/*
============================================================================
        Endpoints related to Smart Controller measurement data queries
============================================================================
*/

pub async fn get_data_in_recent_time_interval(pool: web::Data<PgPool>, query_packet: web::Json<DataQueryPacket>) -> impl Responder
{
    // first, validate the given API key
    let result = validate_api_key(pool.as_ref(), query_packet.api_key()).await;

    match result
    {
        Ok(()) =>
        { /*  do nothing - key check passed */ }
        Err(e) =>
        { return HttpResponse::BadRequest().json(e); }
    }

    // algorithm:
    // 1. decode user JWT, get their user_id
    // 2. check the devices table against the provided mac address,
    //      ensure the device actually belongs to the user. reject packet if no
    // 3. query measurements table for device mac address,
    //      check all entries for previous x seconds,
    //      grab everything and return results as a vector

    // get user info from given JWT
    let result = decode_user_jwt( query_packet.user_jwt() );

    let user_id: i32;

    match result
    {
        Ok( decoded_user ) =>
        {
            user_id = decoded_user.claims.user_id;
        }
        Err(_e) =>
        { return HttpResponse::BadRequest().json( "Expired or invalid JWT!" ); }
    }

    // check that the device belongs to the user
    let device_query = sqlx::query!(
        r#"
        SELECT device_mac_address
        FROM devices
        WHERE user_id = $1 AND device_mac_address = $2
        "#,
        user_id,
        query_packet.device_mac_address()
    )
    .fetch_one( pool.get_ref() )
    .await;


    match device_query
    {
        Ok(_) =>
        { /* do nothing, device was found and is registered to user */ }
        Err(e) =>
        {
            println!("Query failure for device table in get_data_in_recent_time_interval: {:?}", e);
            return HttpResponse::BadRequest().json( "Device does not exist or is not registered to user!" );
        }
    }

    // query the measurements table
    let measurements_query = sqlx::query_as!(
        Measurements,
        r#"
        SELECT * FROM measurements
        WHERE 
        device_mac_address = $1
        AND
        time >= NOW() - INTERVAL '4 hours' - $2 * INTERVAL '1 second';
        "#,
        query_packet.device_mac_address(),
        query_packet.time_seconds()
    )
    .fetch_all( pool.get_ref() )
    .await;


    match measurements_query
    {
        Ok(measurements_list) =>
        {
            // if we successfully retrieve a list of measurements, return it
             HttpResponse::Ok().json(measurements_list)
        }
        Err(e) =>
        {
            // either no rows were found, or some other error happened connecting to the DB
            println!("Error in get_data_in_recent_time_interval at measurements_query:");
            println!("{:?}", e);
            HttpResponse::InternalServerError().json("Error retrieving rows, check server logs")
        }
    }
}

