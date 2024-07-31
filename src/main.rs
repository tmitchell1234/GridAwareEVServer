/*
    GRID AWARE EV CHARGING - Web server

    A Computer Science Senior Design project by:
    JV, BB, SP, TM
*/
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use dotenvy::dotenv;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use std::env;

#[derive(Deserialize)]
struct MyParams {
    name: String,
}

#[derive(Deserialize)]
struct JsonPackage {
    request_body: String,
}

#[derive(Deserialize)]
struct NewUserInfo {
    user_email: String,
    user_password: String,
    user_first_name: String,
    user_last_name: String,
    user_organization: Option<String>
}

async fn index(params: web::Json<MyParams>) -> impl Responder {
    HttpResponse::Ok().body(format!("Hello, {}!\n", params.name))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    println!("database_url = ");
    println!("{}", database_url);

    

    let pool = PgPool::connect(&database_url).await.expect("Failed to create pool.");

    

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .route("/", web::post().to(index))
            .route("/echo", web::post().to(echo))
            .route("/user_add", web::post().to(user_add))
    })
    .bind("127.0.0.1:8080")?  // Change port if needed
    .run()
    .await
}

// useless API for testing/experimation purposes
async fn echo(params: web::Json<JsonPackage>) -> impl Responder {
    let owned_string: String = "ECHOOO ".to_owned();
    let body: &String = &params.request_body;

    let together = format!("{owned_string}{body}");

    HttpResponse::Ok().body(together)
}


async fn user_add(pool: web::Data<PgPool>, params: web::Json<NewUserInfo>) -> impl Responder {

    let result = sqlx::query!(
        r#"
        INSERT INTO Users (user_email, user_password, user_first_name, user_last_name, user_organization)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        params.user_email,
        params.user_password,
        params.user_first_name,
        params.user_last_name,
        params.user_organization
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