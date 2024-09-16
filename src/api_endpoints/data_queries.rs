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
use crate::structs::structs::{DataQueryPacket, SmartControllerPacket};


/*
============================================================================
        Endpoints related to Smart Controller measurement data queries
============================================================================
*/

pub async fn get_data_in_recent_time_interval(pool: web::Data<PgPool>, controller_packet: web::Json<DataQueryPacket>) -> impl Responder
{
    HttpResponse::Ok()
}

