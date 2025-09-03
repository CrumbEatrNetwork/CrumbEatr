use std::{cell::RefCell, collections::HashMap};

use candid::Principal;
use env::{config::CONFIG, user::User, State, *};
use ic_cdk::{api::call::reply_raw, caller};

mod assets;
#[cfg(feature = "dev")]
mod dev_helpers;
mod env;
mod http;
mod metadata;
mod queries;
mod updates;

// ICRC method wrappers - these need to be here for the macros to register them as canister endpoints
use env::token::{
    Account, Allowance, AllowanceArgs, ApproveArgs, ApproveError, 
    Icrc21ConsentMessageRequest, Icrc21ConsentMessageResponse, Standard, Value,
    TransferArgs, TransferError, TransferFromArgs, TransferFromError,
};

#[ic_cdk::query]
pub fn icrc1_balance_of(account: Account) -> u128 {
    env::token::icrc1_balance_of(account)
}

#[ic_cdk::query]
pub fn icrc1_decimals() -> u8 {
    env::token::icrc1_decimals()
}

#[ic_cdk::query]
pub fn icrc1_fee() -> u128 {
    env::token::icrc1_fee()
}

#[ic_cdk::query]
pub fn icrc1_metadata() -> Vec<(String, Value)> {
    env::token::icrc1_metadata()
}

#[ic_cdk::query]
pub fn icrc1_minting_account() -> Option<Account> {
    env::token::icrc1_minting_account()
}

#[ic_cdk::query]
pub fn icrc1_name() -> String {
    env::token::icrc1_name()
}

#[ic_cdk::query]
pub fn icrc1_supported_standards() -> Vec<Standard> {
    env::token::icrc1_supported_standards()
}

#[ic_cdk::query]
pub fn icrc1_symbol() -> String {
    env::token::icrc1_symbol()
}

#[ic_cdk::query]
pub fn icrc1_total_supply() -> u128 {
    env::token::icrc1_total_supply()
}

#[ic_cdk::update]
pub fn icrc1_transfer(args: TransferArgs) -> Result<u128, TransferError> {
    env::token::icrc1_transfer(args)
}

#[ic_cdk::query]
pub fn icrc2_allowance(args: AllowanceArgs) -> Allowance {
    env::token::icrc2_allowance(args)
}

#[ic_cdk::update]
pub fn icrc2_approve(args: ApproveArgs) -> Result<u128, ApproveError> {
    env::token::icrc2_approve(args)
}

#[ic_cdk::update]
pub fn icrc2_transfer_from(args: TransferFromArgs) -> Result<u128, TransferFromError> {
    env::token::icrc2_transfer_from(args)
}

#[ic_cdk::update]
pub fn icrc21_canister_call_consent_message(
    request: Icrc21ConsentMessageRequest
) -> Icrc21ConsentMessageResponse {
    env::token::icrc21_canister_call_consent_message(request)
}

const BACKUP_PAGE_SIZE: u32 = 1024 * 1024;

thread_local! {
    static STATE: RefCell<State> = Default::default();
}

pub fn read<F, R>(f: F) -> R
where
    F: FnOnce(&State) -> R,
{
    STATE.with(|cell| f(&cell.borrow()))
}

pub fn mutate<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with(|cell| f(&mut cell.borrow_mut()))
}

fn parse<'a, T: serde::Deserialize<'a>>(bytes: &'a [u8]) -> T {
    serde_json::from_slice(bytes).expect("couldn't parse the input")
}

fn reply<T: serde::Serialize>(data: T) {
    reply_raw(serde_json::json!(data).to_string().as_bytes());
}

fn stable_to_heap_core() {
    STATE.with(|cell| cell.replace(env::memory::stable_to_heap()));
    mutate(|state| state.load());
}

fn optional(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

pub fn performance_counter(_n: u32) -> u64 {
    #[cfg(test)]
    return 0;
    #[cfg(not(test))]
    ic_cdk::api::performance_counter(_n)
}
pub fn id() -> Principal {
    #[cfg(test)]
    return Principal::anonymous();
    #[cfg(not(test))]
    ic_cdk::id()
}

pub fn time() -> u64 {
    #[cfg(test)]
    return 0;
    #[cfg(not(test))]
    ic_cdk::api::time()
}
