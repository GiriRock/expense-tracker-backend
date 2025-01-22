#![allow(dead_code)]

use bson::{oid::ObjectId, Uuid};
use chrono::{NaiveDate, NaiveDateTime};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub _id: ObjectId,
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Category {
    pub _id: ObjectId,
    pub name: String,
    pub category_type: String,
    //pub created_at: NaiveDate,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CategoryType {
    Income,
    Expense,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub _id: ObjectId,
    pub user_id: String,
    pub category_id: String,
    pub amount: f64,
    pub transaction_date: String,
    pub description: Option<String>,
    pub created_at: String,
    pub currency: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Budget {
    pub budget_id: Uuid,
    pub user_id: Uuid,
    pub category_id: Uuid,
    pub budget_amount: f64,
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecurringExpense {
    pub recurring_id: Uuid,
    pub user_id: Uuid,
    pub category_id: Uuid,
    pub amount: f64,
    pub recurrence_interval: RecurrenceInterval,
    pub start_date: NaiveDate,
    pub end_date: Option<NaiveDate>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RecurrenceInterval {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Debug, Deserialize)]
pub struct LoginUser {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct FetchUsers {
    pub username: String,
    pub email: String,
}

#[derive(Serialize, Deserialize)]
pub struct Token {
    pub token: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct FetchTransactions {
    pub amount: f64,
    pub transaction_date: String,
    pub description: String,
    pub currency: String,
}
