#![allow(unused_imports)]
#![allow(dead_code)]

mod models;
mod user;

use actix_cors::Cors;
use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    get,
    http::{header, StatusCode},
    middleware::{from_fn, Logger, Next},
    post, web, App, Error, HttpMessage, HttpRequest, HttpResponse, HttpResponseBuilder, HttpServer,
    Responder,
};
use bson::{doc, oid::ObjectId};
use chrono::Utc;
use env_logger::Env;
use futures::TryStreamExt;
use models::{
    Category, CreateUser, FetchTransactions, FetchUsers, LoginUser, Token, Transaction, User,
};
use mongodb::{Client, Collection};

const DB_NAME: &str = "db";
const CAT_COLL: &str = "Category";
const TRANS_COLL: &str = "Transaction";
const USER_COLL: &str = "User";

async fn auth_middle(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    if let Some(auth_header) = req.headers().get("Authorization") {
        let auth_token = auth_header.to_str().unwrap_or("");
        if let Some(token) = auth_token.strip_prefix("Bearer ") {
            let user_id = User::decode_jwt(String::from(token));
            if !user_id.is_empty() {
                if user_id == String::from("SIG_EXP") {
                    req.request().extensions_mut().insert(true);
                } else {
                    req.request().extensions_mut().insert(user_id);
                }
            }
        }
    }
    return next.call(req).await;
}

#[get("/get-users")]
async fn get_users(client: web::Data<Client>) -> impl Responder {
    let collection: Collection<FetchUsers> = client.database(DB_NAME).collection(USER_COLL);

    let mut cursor = match collection.find(doc! {}).await {
        Ok(cursor) => cursor,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to fetch users: {}", err));
        }
    };

    let mut users: Vec<FetchUsers> = Vec::new();
    while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
        users.push(doc);
    }

    if users.is_empty() {
        return HttpResponse::Ok().json(Vec::<User>::new());
    }

    HttpResponse::Ok().json(users)
}

#[post("/create-user")]
async fn create_user(client: web::Data<Client>, new_user: web::Json<CreateUser>) -> impl Responder {
    let collection = client.database(DB_NAME).collection::<User>(USER_COLL);

    let hashed_password = match User::hash_password(&new_user.password) {
        Ok(password) => password,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to hash password"),
    };

    let user = User {
        _id: ObjectId::new(),
        username: new_user.username.clone(),
        email: new_user.email.clone(),
        password: hashed_password,
    };

    match collection.insert_one(user).await {
        Ok(_) => HttpResponse::Created().json("User created successfully"),
        Err(err) => {
            HttpResponse::InternalServerError().body(format!("Failed to create user: {}", err))
        }
    }
}

#[post("/login")]
async fn login(client: web::Data<Client>, login_data: web::Json<LoginUser>) -> impl Responder {
    let collection: Collection<User> = client.database(DB_NAME).collection(USER_COLL);

    let user = match collection
        .find_one(doc! { "username": &login_data.username })
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return HttpResponse::Unauthorized().body("Invalid email or password"),
        Err(err) => {
            return HttpResponse::InternalServerError()
                .body(format!("Error fetching user: {}", err))
        }
    };
    match User::verify_password(&user.password, &login_data.password) {
        Ok(true) => {
            let token = User::generate_jwt(&user._id.to_string());
            let token_response = Token { token };
            HttpResponse::Ok().json(token_response)
        }
        Ok(false) => HttpResponse::Unauthorized().body("Invalid email or password"),
        Err(_) => HttpResponse::InternalServerError().body("Error verifying password"),
    }
}

#[get("/get-categories")]
async fn get_cate(client: web::Data<Client>) -> impl Responder {
    let collection: Collection<Category> = client.database(DB_NAME).collection(CAT_COLL);

    let mut cursor = match collection.find(doc! {}).await {
        Ok(cursor) => cursor,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to fetch categories: {}", err))
        }
    };

    let mut categories: Vec<Category> = Vec::new();

    while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
        categories.push(doc);
    }

    if categories.is_empty() {
        return HttpResponse::Ok().json(categories);
    }

    HttpResponse::Ok().json(categories)
}

#[post("/create-transaction")]
async fn create_transaction(
    client: web::Data<Client>,
    transaction: web::Json<Transaction>,
    req: HttpRequest,
) -> impl Responder {
    let user_id = req.extensions().get::<String>().cloned();
    match user_id {
        Some(user_id) => {
            let collection: Collection<Transaction> =
                client.database(DB_NAME).collection(TRANS_COLL);
            let trans_new = Transaction {
                _id: ObjectId::new(),
                category_id: transaction.category_id.clone(),
                amount: transaction.amount,
                transaction_date: transaction.transaction_date.clone(),
                created_at: Utc::now().to_string(),
                description: transaction.description.clone(),
                currency: transaction.currency.clone(),
                user_id,
            };

            match collection.insert_one(trans_new).await {
                Ok(_) => HttpResponse::Created().json("Expense created successfully"),
                Err(err) => HttpResponse::InternalServerError()
                    .body(format!("Failed to create expense: {}", err)),
            }
        }
        _ => return HttpResponse::Unauthorized().body("UnAuthorized"),
    }
}

#[get("/get-transactions")]
async fn get_transactions(client: web::Data<Client>, req: HttpRequest) -> impl Responder {
    let user_id = req.extensions().get::<String>().cloned();
    let is_token_exp = req.extensions().get::<bool>().cloned();
    match user_id {
        Some(user_id) => {
            let collection: Collection<FetchTransactions> =
                client.database(DB_NAME).collection(TRANS_COLL);

            let mut cursor = match collection
                .find(doc! {"user_id": user_id})
                .sort(doc! {"transaction_date": 1})
                .await
            {
                Ok(cursor) => cursor,
                Err(err) => {
                    return HttpResponse::InternalServerError()
                        .body(format!("Failed to fetch transactions: {}", err))
                }
            };

            let mut transactions: Vec<FetchTransactions> = Vec::new();

            while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
                transactions.push(doc);
            }
            HttpResponse::Ok().json(transactions)
        }
        _ => {
            if is_token_exp.unwrap_or(false) {
                return HttpResponse::Unauthorized().body("Token Expired");
            }
            return HttpResponse::Forbidden().body("UnAuthorized");
        }
    }
}

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let uri = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".into());
    println!("connecting to {}", uri);
    let client = Client::with_uri_str(uri).await.expect("failed to connect");

    println!("connected");
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let _cors = Cors::default()
        .allowed_origin("*")
        .allowed_methods(vec!["GET", "POST"])
        .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
        .allowed_header(header::CONTENT_TYPE)
        .max_age(3600);
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(client.clone()))
            .wrap(from_fn(auth_middle))
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
            .service(hello)
            .service(get_cate)
            //.service(get_users)
            .service(create_user)
            .service(login)
            .service(get_transactions)
            .service(create_transaction)
    })
    .bind(("0.0.0.0", 80))?
    .run()
    .await
}
