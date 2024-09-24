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
use actix_web::{web, App, HttpServer };
use dotenvy::dotenv;
use sqlx::postgres::PgPool;
use std::env;


/*
============================================================================
                        CUSTOM MODULE IMPORTS
============================================================================
*/

mod structs;
mod helper_functions;
mod api_endpoints;
use crate::api_endpoints::user_endpoints::{ delete_user_account, get_devices_for_user, register_device,
                                            unregister_device_by_user, reset_password_code, reset_password_email,
                                            update_password, update_user_first_name, update_user_last_name,
                                            update_user_organization, user_create, user_login };

use crate::api_endpoints::device_endpoints::store_controller_reading;
use crate::api_endpoints::data_queries::{ get_data_in_recent_time_interval, get_data_report_for_day };


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

    // attempt to establish connection to database
    let pool = PgPool::connect(&database_url).await.expect("Failed to create pool.");

    println!("Successfully connected pool!");
 
    // create HttpServer endpoint handler, point endpoints to functions defined in custom module files
    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(web::Data::new(pool.clone()))
            .route("/delete_user_account", web::post().to( delete_user_account ))
            .route("/get_data_in_recent_time_interval", web::post().to( get_data_in_recent_time_interval ))
            .route("/get_data_report_for_day", web::post().to( get_data_report_for_day ))
            .route("/get_devices_for_user", web::post().to( get_devices_for_user ))
            .route("/register_device", web::post().to( register_device ))
            .route("/unregister_device_by_user", web::post().to( unregister_device_by_user ))
            .route("/reset_password_code", web::post().to( reset_password_code ))
            .route("/reset_password_email", web::post().to( reset_password_email ))
            .route("/store_controller_reading", web::post().to( store_controller_reading ))
            .route("/update_password", web::post().to( update_password ))
            .route("/update_user_first_name", web::post().to( update_user_first_name ))
            .route("/update_user_last_name", web::post().to( update_user_last_name ))
            .route("/update_user_organization", web::post().to( update_user_organization ))
            .route("/user_create", web::post().to( user_create ))
            .route("/user_login", web::post().to( user_login ))
    })
    .bind("0.0.0.0:3000")? // for production environment
    .run()
    .await
}
