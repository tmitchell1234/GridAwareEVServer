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
// use chrono::{ Utc, Duration };
use dotenvy::dotenv;
//use jsonwebtoken::{ encode, decode, Header, Validation, EncodingKey, DecodingKey, TokenData };
// use jsonwebtoken::{ encode, Header, EncodingKey };
use serde_json::json;
// use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use sqlx;
use std::env;

// for passowrd hashing
// use sha2::{ Sha256, Digest};


// module imports
mod structs;
use crate::structs::{ JsonPackage, NewUserParams, MyParams, User, UserLoginParams };

mod helper_functions;
use crate::helper_functions::{ hash_password, create_jwt };


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
            .route("/", web::post().to(index))
            .route("/echo", web::post().to(echo))
            .route("/user_create", web::post().to(user_create))
            .route("/user_login", web::post().to(user_login))
    })
    //.bind("127.0.0.1:8080")?  // Change port to this for local testing
    .bind("0.0.0.0:3000")? // for production environment
    .run()
    .await
}

/*
============================================================================
                        BEGIN API ENDPOINTS
============================================================================
*/


async fn index(params: web::Json<MyParams>) -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, {}!\n", params.name))
}


// useless API for testing/experimation purposes
async fn echo(params: web::Json<JsonPackage>) -> impl Responder {
    let owned_string: String = "ECHOOO ".to_owned();
    let body: &String = &params.request_body;

    let together = format!("{owned_string}{body}");

    HttpResponse::Ok().body(together)
}


/*
============================================================================
                User create / login API endpoints
============================================================================
*/
async fn user_create(pool: web::Data<PgPool>, params: web::Json<NewUserParams>) -> impl Responder
{
    // let pass_str: &str = params.get_password_str();

    let hashed_password = hash_password(&params.user_password());

    let result = sqlx::query!(
        r#"
        INSERT INTO Users (user_email, user_password, user_first_name, user_last_name, user_organization)
        VALUES ($1, $2, $3, $4, $5)
        "#,
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
            // println!("Found user: {:?}", user);

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
        "SELECT user_email, user_first_name, user_last_name, user_organization FROM users WHERE user_email = $1 AND user_password = $2",
        user_email,
        hashed_password
    )
    .fetch_one(pool)
    .await;

    result
}