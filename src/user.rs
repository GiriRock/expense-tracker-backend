use actix_web::{web, HttpResponse, Responder};
use bcrypt::{hash, verify, DEFAULT_COST};
use bson::oid::ObjectId;
use chrono::{Duration, Utc};
use jsonwebtoken::errors::{Error, ErrorKind};
use jsonwebtoken::{decode, encode, EncodingKey, Header};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::env;

use crate::models::User;

impl User {
    pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
        hash(password, DEFAULT_COST)
    }

    pub fn verify_password(
        stored_password: &str,
        password: &str,
    ) -> Result<bool, bcrypt::BcryptError> {
        verify(password, stored_password)
    }

    pub fn generate_jwt(user_id: &str) -> String {
        let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string());
        let expiration = Utc::now() + Duration::days(1);
        let claims = Claims {
            sub: user_id.to_string(),
            exp: expiration.timestamp() as usize,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }
    pub fn decode_jwt(token: String) -> String {
        let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string());
        let tokenmessage = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(secret.as_ref()),
            &Validation::new(Algorithm::HS256),
        );
        match tokenmessage {
            Ok(tokenmsg) => return tokenmsg.claims.sub,
            Err(err) => {
                if err.into_kind() == ErrorKind::ExpiredSignature {
                    return "SIG_EXP".to_string();
                }
                return "".to_string();
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}
