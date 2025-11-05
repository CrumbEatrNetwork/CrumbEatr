use super::MINUTE;
use crate::*;
use base64::{engine::general_purpose, Engine as _};
use candid::{CandidType, Deserialize, Principal};
use serde::Serialize;

type Timestamp = u64;

pub type Subaccount = Vec<u8>;

type Memo = Vec<u8>;

pub type Token = u64;

#[derive(Clone, Debug, Serialize, Deserialize, CandidType, PartialEq)]
pub enum TransactionKind {
    Transfer,
    Approve,
    TransferFrom,
    Mint,
    Burn,
}

#[derive(CandidType, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<Subaccount>,
}

#[derive(CandidType, Clone, Serialize, Deserialize)]
pub struct AllowanceData {
    pub allowance: Token,
    pub expires_at: Option<Timestamp>,
}

#[derive(CandidType, Deserialize)]
pub struct ApproveArgs {
    pub from_subaccount: Option<Subaccount>,
    pub spender: Account,
    pub amount: u128,
    pub expected_allowance: Option<u128>,
    pub expires_at: Option<Timestamp>,
    pub fee: Option<u128>,
    pub memo: Option<Memo>,
    pub created_at_time: Option<Timestamp>,
}

#[derive(CandidType, Deserialize)]
pub struct TransferFromArgs {
    pub spender_subaccount: Option<Subaccount>,
    pub from: Account,
    pub to: Account,
    pub amount: u128,
    pub fee: Option<u128>,
    pub memo: Option<Memo>,
    pub created_at_time: Option<Timestamp>,
}

#[derive(CandidType, Deserialize)]
pub struct AllowanceArgs {
    pub account: Account,
    pub spender: Account,
}

#[derive(CandidType, Serialize, Deserialize)]
pub struct Allowance {
    pub allowance: u128,
    pub expires_at: Option<Timestamp>,
}

// ICRC-21 Consent Message Types
#[derive(CandidType, Serialize, Deserialize)]
pub struct Icrc21ConsentMessageMetadata {
    pub language: String,
    pub utc_offset_minutes: Option<i16>,
}

#[derive(CandidType, Deserialize)]
pub enum Icrc21DeviceSpec {
    GenericDisplay,
    LineDisplay {
        characters_per_line: u16,
        lines_per_page: u16,
    },
}

#[derive(CandidType, Deserialize)]
pub struct Icrc21ConsentMessageSpec {
    pub metadata: Icrc21ConsentMessageMetadata,
    pub device_spec: Option<Icrc21DeviceSpec>,
}

#[derive(CandidType, Deserialize)]
pub struct Icrc21ConsentMessageRequest {
    pub method: String,
    pub arg: Vec<u8>,
    pub user_preferences: Icrc21ConsentMessageSpec,
}

#[derive(CandidType, Serialize)]
pub enum Icrc21ConsentMessage {
    GenericDisplayMessage(String),
    LineDisplayMessage { pages: Vec<Icrc21Page> },
}

#[derive(CandidType, Serialize)]
pub struct Icrc21Page {
    pub lines: Vec<String>,
}

#[derive(CandidType, Serialize)]
pub struct Icrc21ConsentInfo {
    pub consent_message: Icrc21ConsentMessage,
    pub metadata: Icrc21ConsentMessageMetadata,
}

#[derive(CandidType, Serialize)]
pub struct Icrc21ErrorInfo {
    pub description: String,
}

#[derive(CandidType, Serialize)]
pub enum Icrc21Error {
    UnsupportedCanisterCall(Icrc21ErrorInfo),
    ConsentMessageUnavailable(Icrc21ErrorInfo),
    InsufficientPayment(Icrc21ErrorInfo),
    GenericError {
        error_code: u128,
        description: String,
    },
}

#[derive(CandidType, Serialize)]
pub enum Icrc21ConsentMessageResponse {
    Ok(Icrc21ConsentInfo),
    Err(Icrc21Error),
}

#[derive(CandidType, Deserialize)]
pub struct TransferArgs {
    pub from_subaccount: Option<Subaccount>,
    pub to: Account,
    pub amount: u128,
    pub fee: Option<u128>,
    pub memo: Option<Memo>,
    pub created_at_time: Option<Timestamp>,
}

#[derive(Serialize, Deserialize, CandidType, Clone)]
pub struct Transaction {
    pub timestamp: u64,
    pub from: Account,
    pub to: Account,
    pub amount: Token,
    pub fee: Token,
    pub memo: Option<Memo>,
    pub kind: Option<TransactionKind>, // Option for backward compatibility
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(CandidType, Debug, Serialize, Deserialize)]
pub struct BadFee {
    expected_fee: u128,
}

// pub struct BadBurn {
//     min_burn_amount: u64,
// }

#[cfg_attr(test, derive(PartialEq))]
#[derive(CandidType, Debug, Serialize, Deserialize)]
pub struct Duplicate {
    duplicate_of: u128,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(CandidType, Debug, Serialize, Deserialize)]
pub struct InsufficientFunds {
    balance: u128,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(CandidType, Debug, Serialize, Deserialize)]
pub struct CreatedInFuture {
    ledger_time: Timestamp,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(CandidType, Debug, Serialize, Deserialize)]
pub struct GenericError {
    error_code: u128,
    message: String,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(CandidType, Debug, Serialize, Deserialize)]
pub enum TransferError {
    BadFee(BadFee),
    // BadBurn(BadBurn),
    Duplicate(Duplicate),
    TemporarilyUnavailable,
    InsufficientFunds(InsufficientFunds),
    TooOld,
    CreatedInFuture(CreatedInFuture),
    GenericError(GenericError),
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(CandidType, Debug, Serialize, Deserialize)]
pub struct AllowanceChanged {
    pub current_allowance: u128,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(CandidType, Debug, Serialize, Deserialize)]
pub struct Expired {
    pub ledger_time: Timestamp,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(CandidType, Debug, Serialize, Deserialize)]
pub enum ApproveError {
    BadFee(BadFee),
    InsufficientFunds(InsufficientFunds),
    AllowanceChanged(AllowanceChanged),
    Expired(Expired),
    TooOld,
    CreatedInFuture(CreatedInFuture),
    Duplicate(Duplicate),
    TemporarilyUnavailable,
    GenericError(GenericError),
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(CandidType, Debug, Serialize, Deserialize)]
pub struct InsufficientAllowance {
    pub allowance: u128,
}

#[cfg_attr(test, derive(PartialEq))]
#[derive(CandidType, Debug, Serialize, Deserialize)]
pub enum TransferFromError {
    BadFee(BadFee),
    InsufficientFunds(InsufficientFunds),
    InsufficientAllowance(InsufficientAllowance),
    TooOld,
    CreatedInFuture(CreatedInFuture),
    Duplicate(Duplicate),
    TemporarilyUnavailable,
    GenericError(GenericError),
}

#[derive(CandidType, Deserialize)]
pub enum Value {
    Nat(u128),
    Text(String),
    Int(i128),
    Blob(Vec<u8>),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
}

#[derive(CandidType)]
pub struct Standard {
    name: String,
    url: String,
}

pub fn icrc1_metadata() -> Vec<(String, Value)> {
    vec![
        ("icrc1:symbol".into(), Value::Text(icrc1_symbol())),
        ("icrc1:name".into(), Value::Text(icrc1_name())),
        (
            "icrc1:decimals".into(),
            Value::Nat(icrc1_decimals() as u128),
        ),
        ("icrc1:fee".into(), Value::Nat(icrc1_fee())),
        (
            "icrc1:logo".into(),
            Value::Text(format!(
                "data:image/png;base64,{}",
                general_purpose::STANDARD
                    .encode(include_bytes!("../../frontend/assets/apple-touch-icon.png"))
            )),
        ),
    ]
}

pub fn icrc1_name() -> String {
    CONFIG.name.into()
}

pub fn icrc1_symbol() -> String {
    CONFIG.token_symbol.into()
}

pub fn icrc1_decimals() -> u8 {
    CONFIG.token_decimals
}

pub fn icrc1_fee() -> u128 {
    CONFIG.transaction_fee as u128
}

pub fn icrc1_total_supply() -> u128 {
    read(|state| state.balances.values().copied().sum::<u64>() as u128)
}

pub fn icrc1_minting_account() -> Option<Account> {
    Some(account(Principal::anonymous()))
}

pub fn icrc1_balance_of(mut account: Account) -> u128 {
    if account
        .subaccount
        .as_ref()
        .map(|val| val.iter().all(|b| b == &0))
        .unwrap_or(true)
    {
        account.subaccount = None
    };
    read(|state| state.balances.get(&account).copied().unwrap_or_default() as u128)
}

pub fn icrc1_supported_standards() -> Vec<Standard> {
    vec![
        Standard {
            name: "ICRC-1".into(),
            url: "https://github.com/dfinity/ICRC-1".into(),
        },
        Standard {
            name: "ICRC-2".into(),
            url: "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-2".into(),
        },
        Standard {
            name: "ICRC-3".into(),
            url: "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3".into(),
        },
    ]
}

pub fn icrc1_transfer(mut args: TransferArgs) -> Result<u128, TransferError> {
    let owner = caller();
    if owner == Principal::anonymous() {
        return Err(TransferError::GenericError(GenericError {
            error_code: 0,
            message: "No transfers from the minting account possible.".into(),
        }));
    }
    if args.fee.is_none() {
        args.fee = Some(icrc1_fee())
    } else if args.fee != Some(icrc1_fee()) {
        return Err(TransferError::BadFee(BadFee {
            expected_fee: icrc1_fee(),
        }));
    }
    mutate(|state| transfer(state, time(), owner, args))
}

pub fn icrc2_approve(mut args: ApproveArgs) -> Result<u128, ApproveError> {
    let owner = caller();
    if owner == Principal::anonymous() {
        return Err(ApproveError::GenericError(GenericError {
            error_code: 0,
            message: "Anonymous principal cannot approve tokens".into(),
        }));
    }

    // Set default fee if not provided
    if args.fee.is_none() {
        args.fee = Some(icrc1_fee());
    } else if args.fee != Some(icrc1_fee()) {
        return Err(ApproveError::BadFee(BadFee {
            expected_fee: icrc1_fee(),
        }));
    }

    mutate(|state| approve(state, time(), owner, args))
}

pub fn icrc2_allowance(args: AllowanceArgs) -> Allowance {
    read(|state| {
        let allowance_key = (args.account, args.spender);
        match state.allowances.get(&allowance_key) {
            Some(allowance_data) => {
                // Check if allowance is expired
                let now = time();
                if let Some(expires_at) = allowance_data.expires_at {
                    if now >= expires_at {
                        return Allowance {
                            allowance: 0,
                            expires_at: None,
                        };
                    }
                }
                Allowance {
                    allowance: allowance_data.allowance as u128,
                    expires_at: allowance_data.expires_at,
                }
            }
            None => Allowance {
                allowance: 0,
                expires_at: None,
            },
        }
    })
}

pub fn icrc2_transfer_from(mut args: TransferFromArgs) -> Result<u128, TransferFromError> {
    let spender = caller();
    if spender == Principal::anonymous() {
        return Err(TransferFromError::GenericError(GenericError {
            error_code: 0,
            message: "Anonymous principal cannot transfer tokens".into(),
        }));
    }

    // Set default fee if not provided
    if args.fee.is_none() {
        args.fee = Some(icrc1_fee());
    } else if args.fee != Some(icrc1_fee()) {
        return Err(TransferFromError::BadFee(BadFee {
            expected_fee: icrc1_fee(),
        }));
    }

    mutate(|state| transfer_from(state, time(), spender, args))
}

pub fn icrc21_canister_call_consent_message(
    request: Icrc21ConsentMessageRequest,
) -> Icrc21ConsentMessageResponse {
    let method = request.method.as_str();

    match method {
        "icrc1_transfer" => match candid::decode_one::<TransferArgs>(&request.arg) {
            Ok(args) => {
                let amount_display = format_token_amount(args.amount);
                let to_display = format_account(&args.to);
                let fee_display = format_token_amount(args.fee.unwrap_or(icrc1_fee()));

                let message = format!(
                    "Transfer {} {} to account {} (Fee: {} {})",
                    amount_display,
                    icrc1_symbol(),
                    to_display,
                    fee_display,
                    icrc1_symbol()
                );

                Icrc21ConsentMessageResponse::Ok(Icrc21ConsentInfo {
                    consent_message: Icrc21ConsentMessage::GenericDisplayMessage(message),
                    metadata: request.user_preferences.metadata,
                })
            }
            Err(_) => Icrc21ConsentMessageResponse::Err(Icrc21Error::GenericError {
                error_code: 400,
                description: "Invalid transfer arguments".to_string(),
            }),
        },
        "icrc2_approve" => match candid::decode_one::<ApproveArgs>(&request.arg) {
            Ok(args) => {
                let amount_display = format_token_amount(args.amount);
                let spender_display = format_account(&args.spender);
                let fee_display = format_token_amount(args.fee.unwrap_or(icrc1_fee()));

                let expires_msg = match args.expires_at {
                    Some(exp) => format!(" (Expires: {})", format_timestamp(exp)),
                    None => "".to_string(),
                };

                let message = format!(
                    "Approve {} {} spending allowance for account {}{} (Fee: {} {})",
                    amount_display,
                    icrc1_symbol(),
                    spender_display,
                    expires_msg,
                    fee_display,
                    icrc1_symbol()
                );

                Icrc21ConsentMessageResponse::Ok(Icrc21ConsentInfo {
                    consent_message: Icrc21ConsentMessage::GenericDisplayMessage(message),
                    metadata: request.user_preferences.metadata,
                })
            }
            Err(_) => Icrc21ConsentMessageResponse::Err(Icrc21Error::GenericError {
                error_code: 400,
                description: "Invalid approve arguments".to_string(),
            }),
        },
        "icrc2_transfer_from" => match candid::decode_one::<TransferFromArgs>(&request.arg) {
            Ok(args) => {
                let amount_display = format_token_amount(args.amount);
                let from_display = format_account(&args.from);
                let to_display = format_account(&args.to);
                let fee_display = format_token_amount(args.fee.unwrap_or(icrc1_fee()));

                let message = format!(
                        "Transfer {} {} from account {} to account {} using pre-approved allowance (Fee: {} {})",
                        amount_display,
                        icrc1_symbol(),
                        from_display,
                        to_display,
                        fee_display,
                        icrc1_symbol()
                    );

                Icrc21ConsentMessageResponse::Ok(Icrc21ConsentInfo {
                    consent_message: Icrc21ConsentMessage::GenericDisplayMessage(message),
                    metadata: request.user_preferences.metadata,
                })
            }
            Err(_) => Icrc21ConsentMessageResponse::Err(Icrc21Error::GenericError {
                error_code: 400,
                description: "Invalid transfer_from arguments".to_string(),
            }),
        },
        _ => Icrc21ConsentMessageResponse::Err(Icrc21Error::UnsupportedCanisterCall(
            Icrc21ErrorInfo {
                description: format!("Method '{}' is not supported for consent messages", method),
            },
        )),
    }
}

// Rate limiting helper - returns Err if rate limit exceeded
fn check_rate_limit(state: &mut State, caller: Principal, now: u64) -> Result<(), ()> {
    const MAX_REQUESTS_PER_MINUTE: u64 = 60;
    const WINDOW_DURATION_NANOS: u64 = 60_000_000_000; // 1 minute

    // Exempt minting account
    if let Some(minting_account) = icrc1_minting_account() {
        if caller == minting_account.owner {
            return Ok(());
        }
    }

    let (count, window_start) = state.rate_limiter.get(&caller).copied().unwrap_or((0, now));

    if now.saturating_sub(window_start) > WINDOW_DURATION_NANOS {
        // New window
        state.rate_limiter.insert(caller, (1, now));
        Ok(())
    } else if count >= MAX_REQUESTS_PER_MINUTE {
        Err(())
    } else {
        state.rate_limiter.insert(caller, (count + 1, window_start));
        Ok(())
    }
}

// Check if transaction is a duplicate - returns tx_index if found
fn check_duplicate(
    state: &State,
    from: &Account,
    to: &Account,
    amount: u128,
    created_at_time: u64,
) -> Option<u128> {
    state
        .transaction_dedup
        .get(&(from.clone(), to.clone(), amount, created_at_time))
        .map(|(tx_index, _)| *tx_index)
}

// Record transaction for deduplication
fn record_transaction(
    state: &mut State,
    from: Account,
    to: Account,
    amount: u128,
    created_at_time: u64,
    tx_index: u128,
    now: u64,
) {
    state
        .transaction_dedup
        .insert((from, to, amount, created_at_time), (tx_index, now));
}

pub fn transfer(
    state: &mut State,
    now: u64,
    owner: Principal,
    args: TransferArgs,
) -> Result<u128, TransferError> {
    let TransferArgs {
        from_subaccount,
        mut to,
        amount,
        created_at_time,
        fee,
        memo,
        ..
    } = args;

    // Handle zero amount transfers (Kong compatibility)
    if amount == 0 {
        return Ok(0); // Return success with block_id = 0
    }

    // Check rate limit (exempts minting account)
    if check_rate_limit(state, owner, now).is_err() {
        return Err(TransferError::TemporarilyUnavailable);
    }

    if owner == icrc1_minting_account().expect("no minting account").owner {
        if !state.minting_mode {
            return Err(TransferError::GenericError(GenericError {
                error_code: 5,
                message: "minting invariant violation".into(),
            }));
        }
    } else if fee.is_none() {
        return Err(TransferError::GenericError(GenericError {
            error_code: 3,
            message: "only minting transactions are allowed without a fee".into(),
        }));
    }

    if state.voted_on_pending_proposal(owner) {
        return Err(TransferError::GenericError(GenericError {
            error_code: 1,
            message: "transfers locked: a vote on a pending proposal detected".to_string(),
        }));
    }

    if memo.as_ref().map(|bytes| bytes.len()) > Some(32) {
        return Err(TransferError::GenericError(GenericError {
            error_code: 2,
            message: "memo longer than 32 bytes".to_string(),
        }));
    }

    // check the time
    let effective_time = created_at_time.unwrap_or(now);
    if effective_time + 5 * MINUTE < now {
        return Err(TransferError::TooOld);
    }
    if effective_time.saturating_sub(5 * MINUTE) > now {
        return Err(TransferError::CreatedInFuture(CreatedInFuture {
            ledger_time: now,
        }));
    }

    let subaccount = if from_subaccount
        .as_ref()
        .map(|val| val.iter().all(|b| b == &0))
        .unwrap_or(true)
    {
        None
    } else {
        from_subaccount
    };

    if to
        .subaccount
        .as_ref()
        .map(|val| val.len() == 32 && val.iter().all(|b| b == &0))
        .unwrap_or_default()
    {
        to.subaccount = None;
    }

    let from = Account { owner, subaccount };

    // Check for duplicate transaction
    if let Some(duplicate_tx) = check_duplicate(state, &from, &to, amount, effective_time) {
        return Err(TransferError::Duplicate(Duplicate {
            duplicate_of: duplicate_tx,
        }));
    }

    let balance = state.balances.get(&from).copied().unwrap_or_default();
    if from.owner != Principal::anonymous() && balance == 0 {
        return Err(TransferError::InsufficientFunds(InsufficientFunds {
            balance: 0,
        }));
    }
    let effective_fee = fee.unwrap_or(icrc1_fee()) as Token;
    if from.owner != Principal::anonymous() {
        let effective_amount = (amount as Token).saturating_add(effective_fee);
        if balance < effective_amount {
            return Err(TransferError::InsufficientFunds(InsufficientFunds {
                balance: balance as u128,
            }));
        }
        let resulting_balance = balance.saturating_sub(effective_amount);
        if resulting_balance == 0 {
            state.balances.remove(&from);
        } else {
            state.balances.insert(from.clone(), resulting_balance);
        }
        update_user_balance(state, from.owner, resulting_balance as Token);
    }
    if to.owner != Principal::anonymous() {
        let recipient_balance = state.balances.remove(&to).unwrap_or_default();
        let updated_balance = recipient_balance.saturating_add(amount as Token);
        state.balances.insert(to.clone(), updated_balance);
        update_user_balance(state, to.owner, updated_balance as Token);
    }

    let tx_kind = if from.owner == Principal::anonymous() {
        TransactionKind::Mint
    } else if to.owner == Principal::anonymous() {
        TransactionKind::Burn
    } else {
        TransactionKind::Transfer
    };

    state.ledger.push(Transaction {
        timestamp: now,
        from: from.clone(),
        to: to.clone(),
        amount: amount as Token,
        fee: effective_fee,
        memo,
        kind: Some(tx_kind),
    });

    let tx_index = state.ledger.len().saturating_sub(1) as u128;

    // Record transaction for deduplication
    record_transaction(state, from, to, amount, effective_time, tx_index, now);

    Ok(tx_index)
}

fn update_user_balance(state: &mut State, principal: Principal, balance: Token) {
    if let Some(user) = state.principal_to_user_mut(principal) {
        if user.principal == principal {
            user.balance = balance
        } else if user.cold_wallet == Some(principal) {
            user.cold_balance = balance
        }
    }
}

pub fn approve(
    state: &mut State,
    now: u64,
    owner: Principal,
    args: ApproveArgs,
) -> Result<u128, ApproveError> {
    let ApproveArgs {
        from_subaccount,
        spender,
        amount,
        expected_allowance,
        expires_at,
        fee,
        memo,
        created_at_time,
    } = args;

    // Check rate limit (exempts minting account)
    if check_rate_limit(state, owner, now).is_err() {
        return Err(ApproveError::TemporarilyUnavailable);
    }

    // Check time bounds
    let effective_time = created_at_time.unwrap_or(now);
    if effective_time + 5 * MINUTE < now {
        return Err(ApproveError::TooOld);
    }
    if effective_time.saturating_sub(5 * MINUTE) > now {
        return Err(ApproveError::CreatedInFuture(CreatedInFuture {
            ledger_time: now,
        }));
    }

    // Check if allowance has expired
    if let Some(exp_time) = expires_at {
        if exp_time <= now {
            return Err(ApproveError::Expired(Expired { ledger_time: now }));
        }
    }

    // Validate memo length
    if memo.as_ref().map(|bytes| bytes.len()) > Some(32) {
        return Err(ApproveError::GenericError(GenericError {
            error_code: 2,
            message: "memo longer than 32 bytes".to_string(),
        }));
    }

    // Normalize subaccounts
    let subaccount = if from_subaccount
        .as_ref()
        .map(|val| val.iter().all(|b| b == &0))
        .unwrap_or(true)
    {
        None
    } else {
        from_subaccount
    };

    let from_account = Account { owner, subaccount };
    let allowance_key = (from_account.clone(), spender.clone());

    // Check for duplicate approval
    if let Some(duplicate_tx) =
        check_duplicate(state, &from_account, &spender, amount, effective_time)
    {
        return Err(ApproveError::Duplicate(Duplicate {
            duplicate_of: duplicate_tx,
        }));
    }

    // Check expected allowance if provided
    if let Some(expected) = expected_allowance {
        let current_allowance = state
            .allowances
            .get(&allowance_key)
            .map(|data| {
                // Check if current allowance is expired
                if let Some(exp) = data.expires_at {
                    if now >= exp {
                        0
                    } else {
                        data.allowance as u128
                    }
                } else {
                    data.allowance as u128
                }
            })
            .unwrap_or(0);

        if current_allowance != expected {
            return Err(ApproveError::AllowanceChanged(AllowanceChanged {
                current_allowance,
            }));
        }
    }

    // Check if user has sufficient balance to pay the fee
    let balance = state
        .balances
        .get(&from_account)
        .copied()
        .unwrap_or_default();
    let effective_fee = fee.unwrap_or(icrc1_fee()) as Token;
    if balance < effective_fee {
        return Err(ApproveError::InsufficientFunds(InsufficientFunds {
            balance: balance as u128,
        }));
    }

    // Deduct fee from user's balance
    let new_balance = balance.saturating_sub(effective_fee);
    if new_balance == 0 {
        state.balances.remove(&from_account);
    } else {
        state.balances.insert(from_account.clone(), new_balance);
    }
    update_user_balance(state, from_account.owner, new_balance);

    // Set or update the allowance
    let allowance_data = AllowanceData {
        allowance: amount as Token,
        expires_at,
    };
    state.allowances.insert(allowance_key, allowance_data);

    // Record the transaction in the ledger
    state.ledger.push(Transaction {
        timestamp: now,
        from: from_account.clone(),
        to: spender.clone(),     // For approve, the "to" is the spender
        amount: amount as Token, // This is the allowance amount
        fee: effective_fee,
        memo,
        kind: Some(TransactionKind::Approve), // Mark as approve!
    });

    let tx_index = state.ledger.len().saturating_sub(1) as u128;

    // Record transaction for deduplication
    record_transaction(
        state,
        from_account,
        spender,
        amount,
        effective_time,
        tx_index,
        now,
    );

    Ok(tx_index)
}

pub fn transfer_from(
    state: &mut State,
    now: u64,
    spender: Principal,
    args: TransferFromArgs,
) -> Result<u128, TransferFromError> {
    let TransferFromArgs {
        spender_subaccount,
        from,
        to,
        amount,
        fee,
        memo,
        created_at_time,
    } = args;

    // Handle zero amount transfers (Kong compatibility - error for transfer_from)
    if amount == 0 {
        return Err(TransferFromError::GenericError(GenericError {
            error_code: 1,
            message: "Transfer_from amount is zero".to_string(),
        }));
    }

    // Check rate limit (exempts minting account)
    if check_rate_limit(state, spender, now).is_err() {
        return Err(TransferFromError::TemporarilyUnavailable);
    }

    // Check time bounds
    let effective_time = created_at_time.unwrap_or(now);
    if effective_time + 5 * MINUTE < now {
        return Err(TransferFromError::TooOld);
    }
    if effective_time.saturating_sub(5 * MINUTE) > now {
        return Err(TransferFromError::CreatedInFuture(CreatedInFuture {
            ledger_time: now,
        }));
    }

    // Check for duplicate transaction
    if let Some(duplicate_tx) = check_duplicate(state, &from, &to, amount, effective_time) {
        return Err(TransferFromError::Duplicate(Duplicate {
            duplicate_of: duplicate_tx,
        }));
    }

    // Validate memo length
    if memo.as_ref().map(|bytes| bytes.len()) > Some(32) {
        return Err(TransferFromError::GenericError(GenericError {
            error_code: 2,
            message: "memo longer than 32 bytes".to_string(),
        }));
    }

    // Normalize spender subaccount
    let spender_subaccount = if spender_subaccount
        .as_ref()
        .map(|val| val.iter().all(|b| b == &0))
        .unwrap_or(true)
    {
        None
    } else {
        spender_subaccount
    };

    let spender_account = Account {
        owner: spender,
        subaccount: spender_subaccount,
    };
    let allowance_key = (from.clone(), spender_account);

    // Check allowance and get its value without holding a mutable reference
    let current_allowance = match state.allowances.get(&allowance_key) {
        Some(data) => {
            // Check if allowance is expired
            if let Some(expires_at) = data.expires_at {
                if now >= expires_at {
                    return Err(TransferFromError::InsufficientAllowance(
                        InsufficientAllowance { allowance: 0 },
                    ));
                }
            }
            data.allowance
        }
        None => {
            return Err(TransferFromError::InsufficientAllowance(
                InsufficientAllowance { allowance: 0 },
            ));
        }
    };

    let effective_fee = fee.unwrap_or(icrc1_fee()) as Token;
    let total_needed = (amount as Token) + effective_fee;

    // Check if allowance is sufficient
    if current_allowance < total_needed {
        return Err(TransferFromError::InsufficientAllowance(
            InsufficientAllowance {
                allowance: current_allowance as u128,
            },
        ));
    }

    // Check if the "from" account has sufficient balance
    let from_balance = state.balances.get(&from).copied().unwrap_or_default();
    if from_balance < total_needed {
        return Err(TransferFromError::InsufficientFunds(InsufficientFunds {
            balance: from_balance as u128,
        }));
    }

    // Update balances
    let new_from_balance = from_balance.saturating_sub(total_needed);
    if new_from_balance == 0 {
        state.balances.remove(&from);
    } else {
        state.balances.insert(from.clone(), new_from_balance);
    }
    update_user_balance(state, from.owner, new_from_balance);

    let to_balance = state.balances.get(&to).copied().unwrap_or_default();
    let new_to_balance = to_balance.saturating_add(amount as Token);
    state.balances.insert(to.clone(), new_to_balance);
    update_user_balance(state, to.owner, new_to_balance);

    // Update allowance - now we can safely get mutable reference
    let new_allowance = current_allowance.saturating_sub(total_needed);
    if new_allowance == 0 {
        state.allowances.remove(&allowance_key);
    } else if let Some(allowance_data) = state.allowances.get_mut(&allowance_key) {
        allowance_data.allowance = new_allowance;
    }

    // Record the transaction in the ledger
    state.ledger.push(Transaction {
        timestamp: now,
        from: from.clone(),
        to: to.clone(),
        amount: amount as Token,
        fee: effective_fee,
        memo,
        kind: Some(TransactionKind::TransferFrom),
    });

    let tx_index = state.ledger.len().saturating_sub(1) as u128;

    // Record transaction for deduplication
    record_transaction(state, from, to, amount, effective_time, tx_index, now);

    Ok(tx_index)
}

pub fn account(owner: Principal) -> Account {
    Account {
        owner,
        subaccount: None,
    }
}

// Helper functions for ICRC-21 consent messages
fn format_token_amount(amount: u128) -> String {
    let decimals = icrc1_decimals() as u32;
    let divisor = 10_u128.pow(decimals);
    let whole = amount / divisor;
    let fractional = amount % divisor;

    if fractional == 0 {
        format!("{}", whole)
    } else {
        let frac_str = format!("{:0width$}", fractional, width = decimals as usize);
        let trimmed = frac_str.trim_end_matches('0');
        if trimmed.is_empty() {
            format!("{}", whole)
        } else {
            format!("{}.{}", whole, trimmed)
        }
    }
}

fn format_account(account: &Account) -> String {
    match &account.subaccount {
        Some(subaccount) if !subaccount.iter().all(|b| b == &0) => {
            format!("{}.{}", account.owner.to_text(), hex::encode(subaccount))
        }
        _ => account.owner.to_text(),
    }
}

fn format_timestamp(timestamp: u64) -> String {
    // Convert nanoseconds to seconds for a more readable format
    let seconds = timestamp / 1_000_000_000;
    format!("{} seconds from epoch", seconds)
}

/// Smallest amount of non-fractional tokens
pub fn base() -> Token {
    10_u64.pow(CONFIG.token_decimals as u32)
}

pub fn mint(state: &mut State, account: Account, tokens: Token) {
    let now = time();
    let _result = transfer(
        state,
        now,
        icrc1_minting_account().expect("no minting account").owner,
        TransferArgs {
            from_subaccount: None,
            to: account,
            amount: tokens as u128,
            fee: None,
            memo: None,
            created_at_time: Some(now),
        },
    );
}

pub fn balances_from_ledger(ledger: &[Transaction]) -> Result<HashMap<Account, Token>, String> {
    let mut balances = HashMap::new();
    let minting_account = icrc1_minting_account().ok_or("no minting account found")?;

    for (index, transaction) in ledger.iter().enumerate() {
        // Skip known invalid/phantom transactions
        if SKIP_TRANSACTIONS.contains(&index) {
            ic_cdk::println!("Skipping phantom transaction at index {}", index);
            continue;
        }
        // Determine transaction type
        let tx_kind = transaction.kind.clone().unwrap_or_else(|| {
            // For backward compatibility with old transactions without kind field
            // Use heuristics to guess the type
            if transaction.from.owner == Principal::anonymous() {
                TransactionKind::Mint
            } else if transaction.to.owner == Principal::anonymous() {
                TransactionKind::Burn
            } else if index == 21 {
                // Known approve transactions that caused phantom tokens
                // Staging: 21
                // Production: 156, 163
                TransactionKind::Approve
            } else {
                TransactionKind::Transfer
            }
        });

        match tx_kind {
            TransactionKind::Mint => {
                // Credit recipient
                let balance = balances.entry(transaction.to.clone()).or_insert(0 as Token);
                *balance = (*balance).saturating_add(transaction.amount);
            }
            TransactionKind::Burn => {
                // Debit sender (amount + fee)
                let from = balances
                    .get_mut(&transaction.from)
                    .ok_or(format!("burning account not found at tx {}", index))?;
                let needed = transaction.amount.saturating_add(transaction.fee);
                if needed > *from {
                    return Err(format!(
                        "insufficient funds for burn at tx {}: {} < {}",
                        index, *from, needed
                    ));
                }
                *from = (*from).saturating_sub(needed);
            }
            TransactionKind::Transfer | TransactionKind::TransferFrom => {
                // Credit recipient
                if transaction.to != minting_account {
                    let balance = balances.entry(transaction.to.clone()).or_insert(0 as Token);
                    *balance = (*balance).saturating_add(transaction.amount);
                }

                // Debit sender (amount + fee)
                if transaction.from != minting_account {
                    let from = balances
                        .get_mut(&transaction.from)
                        .ok_or(format!("paying account not found at tx {}", index))?;
                    let needed = transaction.amount.saturating_add(transaction.fee);
                    if needed > *from {
                        return Err(format!(
                            "insufficient funds at tx {}: {} < {}",
                            index, *from, needed
                        ));
                    }
                    *from = (*from).saturating_sub(needed);
                }
            }
            TransactionKind::Approve => {
                // APPROVE: Only debit the fee, don't credit anyone
                if transaction.from != minting_account {
                    let from = balances
                        .get_mut(&transaction.from)
                        .ok_or(format!("approving account not found at tx {}", index))?;
                    if transaction.fee > *from {
                        return Err(format!(
                            "insufficient funds for approve fee at tx {}: {} < {}",
                            index, *from, transaction.fee
                        ));
                    }
                    *from = (*from).saturating_sub(transaction.fee);
                }
                // DO NOT credit the spender - approve doesn't transfer tokens!
            }
        }
    }

    Ok(balances)
}

// ICRC-3 Types and Implementation
#[derive(CandidType, Deserialize, Clone)]
pub struct GetBlocksRequest {
    pub start: u128,
    pub length: u128,
}

#[derive(CandidType, Deserialize)]
pub struct GetBlocksResponse {
    pub first_index: u128,
    pub chain_length: u64,
    pub certificate: Option<Vec<u8>>,
    pub blocks: Vec<Value>,
    pub archived_blocks: Vec<ArchivedRange>,
}

#[derive(CandidType, Deserialize)]
pub struct ArchivedRange {
    pub start: u128,
    pub length: u128,
    pub callback: QueryBlockArchiveFn,
}

#[derive(CandidType, Deserialize)]
pub struct QueryBlockArchiveFn {
    pub canister_id: Principal,
    pub method: String,
}

#[derive(CandidType, Deserialize)]
pub struct DataCertificate {
    pub certificate: Vec<u8>,
    pub hash_tree: Vec<u8>,
}

// Convert our Transaction type to ICRC-3 block format
pub fn transaction_to_block(tx: &Transaction, index: u64) -> Value {
    // Determine the operation type based on transaction kind
    let op = match &tx.kind {
        Some(TransactionKind::Approve) => "icrc2_approve",
        Some(TransactionKind::TransferFrom) => "icrc2_transfer_from",
        Some(TransactionKind::Mint) => "mint",
        Some(TransactionKind::Burn) => "burn",
        Some(TransactionKind::Transfer) | None => "icrc1_transfer",
    };

    // Build transaction fields
    let mut tx_fields = vec![
        ("op".to_string(), Value::Text(op.to_string())),
        ("amt".to_string(), Value::Nat(tx.amount as u128)),
        ("fee".to_string(), Value::Nat(tx.fee as u128)),
    ];

    // Encode accounts as arrays [principal_blob, subaccount_blob]
    let from_array = vec![
        Value::Blob(tx.from.owner.as_slice().to_vec()),
        if let Some(subaccount) = &tx.from.subaccount {
            Value::Blob(subaccount.clone())
        } else {
            Value::Blob(vec![0u8; 32])
        },
    ];

    let to_array = vec![
        Value::Blob(tx.to.owner.as_slice().to_vec()),
        if let Some(subaccount) = &tx.to.subaccount {
            Value::Blob(subaccount.clone())
        } else {
            Value::Blob(vec![0u8; 32])
        },
    ];

    tx_fields.push(("from".to_string(), Value::Array(from_array)));
    tx_fields.push(("to".to_string(), Value::Array(to_array)));

    // Add memo if present
    if let Some(ref memo) = tx.memo {
        tx_fields.push(("memo".to_string(), Value::Blob(memo.clone())));
    }

    // Return properly nested structure: { id: Nat, block: { ts, btype, tx } }
    Value::Map(vec![
        ("id".to_string(), Value::Nat(index as u128)),
        (
            "block".to_string(),
            Value::Map(vec![
                ("ts".to_string(), Value::Nat(tx.timestamp as u128)),
                ("btype".to_string(), Value::Text("1xfer".to_string())),
                ("tx".to_string(), Value::Map(tx_fields)),
            ]),
        ),
    ])
}

pub fn icrc3_get_blocks(reqs: Vec<GetBlocksRequest>) -> GetBlocksResponse {
    // Kong sends a vector with one request, so we process the first one
    let req = reqs.first().cloned().unwrap_or(GetBlocksRequest {
        start: 0,
        length: 0,
    });

    read(|state| {
        let start = req.start as usize;
        let length = std::cmp::min(req.length as usize, 2000); // Max 2000 blocks per request

        let ledger_len = state.ledger.len();
        let end = std::cmp::min(start + length, ledger_len);

        let blocks: Vec<Value> = state.ledger[start..end]
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                // Filter out phantom transactions from external API
                let global_idx = start + i;
                !SKIP_TRANSACTIONS.contains(&global_idx)
            })
            .map(|(i, tx)| transaction_to_block(tx, (start + i) as u64))
            .collect();

        GetBlocksResponse {
            first_index: start as u128,
            chain_length: ledger_len as u64,
            certificate: None, // Simple implementation without certification
            blocks,
            archived_blocks: vec![], // No archiving in simple implementation
        }
    })
}

pub fn icrc3_get_archives(_req: GetArchivesRequest) -> Vec<GetArchivesResult> {
    vec![] // No archives in simple implementation
}

pub fn icrc3_get_tip_certificate() -> Option<DataCertificate> {
    None // Simple implementation without certification
}

pub fn icrc3_supported_block_types() -> Vec<BlockType> {
    vec![
        BlockType {
            block_type: "1xfer".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md"
                .to_string(),
        },
        BlockType {
            block_type: "2approve".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md"
                .to_string(),
        },
        BlockType {
            block_type: "2xfer".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md"
                .to_string(),
        },
        BlockType {
            block_type: "1mint".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md"
                .to_string(),
        },
        BlockType {
            block_type: "1burn".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md"
                .to_string(),
        },
    ]
}

// The crucial get_transactions method that KongSwap expects - ICRC-3 format
#[derive(CandidType, Deserialize)]
pub struct GetTransactionsRequest {
    pub start: u128,
    pub length: u128,
}

#[derive(CandidType)]
pub struct GetTransactionsResponse {
    pub first_index: u128,
    pub log_length: u128,
    pub transactions: Vec<Icrc3Transaction>,
    pub archived_transactions: Vec<ArchivedTransactionRange>,
}

// Official ICRC-3 Transaction structure
#[derive(CandidType)]
pub struct Icrc3Transaction {
    pub kind: String,
    pub mint: Option<Icrc3Mint>,
    pub burn: Option<Icrc3Burn>,
    pub transfer: Option<Icrc3Transfer>,
    pub approve: Option<Icrc3Approve>,
    pub timestamp: u64,
}

#[derive(CandidType)]
pub struct Icrc3Transfer {
    pub from: Account,
    pub to: Account,
    pub amount: u128,
    pub fee: Option<u128>,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType)]
pub struct Icrc3Mint {
    pub to: Account,
    pub amount: u128,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType)]
pub struct Icrc3Burn {
    pub from: Account,
    pub amount: u128,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType)]
pub struct Icrc3Approve {
    pub from: Account,
    pub spender: Account,
    pub amount: u128,
    pub expected_allowance: Option<u128>,
    pub expires_at: Option<u64>,
    pub fee: Option<u128>,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

#[derive(CandidType)]
pub struct ArchivedTransactionRange {
    pub start: u128,
    pub length: u128,
    pub callback: QueryArchiveFn,
}

#[derive(CandidType)]
pub struct QueryArchiveFn {
    pub canister_id: Principal,
    pub method: String,
}

// Convert our internal Transaction to ICRC-3 format
fn transaction_to_icrc3(tx: &Transaction) -> Icrc3Transaction {
    let minting_account = icrc1_minting_account().expect("no minting account");

    // Check tx.kind first if available, otherwise fall back to heuristics
    match tx.kind.as_ref() {
        Some(TransactionKind::Mint) => Icrc3Transaction {
            kind: "mint".to_string(),
            mint: Some(Icrc3Mint {
                to: tx.to.clone(),
                amount: tx.amount as u128,
                memo: tx.memo.clone(),
                created_at_time: Some(tx.timestamp),
            }),
            burn: None,
            transfer: None,
            approve: None,
            timestamp: tx.timestamp,
        },
        Some(TransactionKind::Burn) => Icrc3Transaction {
            kind: "burn".to_string(),
            mint: None,
            burn: Some(Icrc3Burn {
                from: tx.from.clone(),
                amount: tx.amount as u128,
                memo: tx.memo.clone(),
                created_at_time: Some(tx.timestamp),
            }),
            transfer: None,
            approve: None,
            timestamp: tx.timestamp,
        },
        Some(TransactionKind::Transfer) | Some(TransactionKind::TransferFrom) => Icrc3Transaction {
            kind: "transfer".to_string(),
            mint: None,
            burn: None,
            transfer: Some(Icrc3Transfer {
                from: tx.from.clone(),
                to: tx.to.clone(),
                amount: tx.amount as u128,
                fee: Some(tx.fee as u128),
                memo: tx.memo.clone(),
                created_at_time: Some(tx.timestamp),
            }),
            approve: None,
            timestamp: tx.timestamp,
        },
        Some(TransactionKind::Approve) => Icrc3Transaction {
            kind: "approve".to_string(),
            mint: None,
            burn: None,
            transfer: None,
            approve: Some(Icrc3Approve {
                from: tx.from.clone(),
                spender: tx.to.clone(),    // For approve, tx.to is the spender
                amount: tx.amount as u128, // This is the allowance amount, not a transfer
                expected_allowance: None,  // Not stored in our Transaction struct
                expires_at: None,          // Not stored in our Transaction struct
                fee: Some(tx.fee as u128),
                memo: tx.memo.clone(),
                created_at_time: Some(tx.timestamp),
            }),
            timestamp: tx.timestamp,
        },
        // Fall back to heuristics for old transactions without kind field
        None => {
            if tx.from == minting_account {
                Icrc3Transaction {
                    kind: "mint".to_string(),
                    mint: Some(Icrc3Mint {
                        to: tx.to.clone(),
                        amount: tx.amount as u128,
                        memo: tx.memo.clone(),
                        created_at_time: Some(tx.timestamp),
                    }),
                    burn: None,
                    transfer: None,
                    approve: None,
                    timestamp: tx.timestamp,
                }
            } else if tx.to == minting_account {
                Icrc3Transaction {
                    kind: "burn".to_string(),
                    mint: None,
                    burn: Some(Icrc3Burn {
                        from: tx.from.clone(),
                        amount: tx.amount as u128,
                        memo: tx.memo.clone(),
                        created_at_time: Some(tx.timestamp),
                    }),
                    transfer: None,
                    approve: None,
                    timestamp: tx.timestamp,
                }
            } else {
                Icrc3Transaction {
                    kind: "transfer".to_string(),
                    mint: None,
                    burn: None,
                    transfer: Some(Icrc3Transfer {
                        from: tx.from.clone(),
                        to: tx.to.clone(),
                        amount: tx.amount as u128,
                        fee: Some(tx.fee as u128),
                        memo: tx.memo.clone(),
                        created_at_time: Some(tx.timestamp),
                    }),
                    approve: None,
                    timestamp: tx.timestamp,
                }
            }
        }
    }
}

pub fn get_transactions(req: GetTransactionsRequest) -> GetTransactionsResponse {
    read(|state| {
        let start = req.start as usize;
        let length = std::cmp::min(req.length as usize, 2000); // Max 2000 transactions per request

        let ledger_len = state.ledger.len();
        let end = std::cmp::min(start + length, ledger_len);

        let transactions: Vec<Icrc3Transaction> = state.ledger[start..end]
            .iter()
            .enumerate()
            .filter(|(idx, _)| {
                // Filter out phantom transactions from external API
                let global_idx = start + idx;
                !SKIP_TRANSACTIONS.contains(&global_idx)
            })
            .map(|(_, tx)| transaction_to_icrc3(tx))
            .collect();

        GetTransactionsResponse {
            first_index: start as u128,
            log_length: ledger_len as u128,
            transactions,
            archived_transactions: vec![], // No archiving in simple implementation
        }
    })
}

#[derive(CandidType, Deserialize)]
pub struct GetArchivesRequest {
    pub from: Option<Principal>,
}

#[derive(CandidType, Deserialize)]
pub struct GetArchivesResult {
    pub canister_id: Principal,
    pub start: u128,
    pub end: u128,
}

#[derive(CandidType, Deserialize)]
pub struct BlockType {
    pub block_type: String,
    pub url: String,
}

/// Known phantom/invalid transactions that should be skipped
/// These are transactions that created phantom tokens and should not affect balances
/// Staging: [] - Fresh reset, no phantom transactions
/// Production: [] - Fresh relaunch, no phantom transactions
#[cfg(feature = "staging")]
const SKIP_TRANSACTIONS: &[usize] = &[];
#[cfg(not(feature = "staging"))]
const SKIP_TRANSACTIONS: &[usize] = &[];

// Cleanup old deduplication records (called by daily chores)
pub fn prune_old_dedup_records(state: &mut State, now: u64) {
    const DEDUP_WINDOW_NANOS: u64 = 12 * 3_600_000_000_000; // 12 hours
    let initial_count = state.transaction_dedup.len();

    state
        .transaction_dedup
        .retain(|_, (_, recorded_at)| now.saturating_sub(*recorded_at) < DEDUP_WINDOW_NANOS);

    let removed_count = initial_count - state.transaction_dedup.len();
    if removed_count > 0 {
        ic_cdk::println!("Pruned {} old deduplication records", removed_count);
    }
}

// Cleanup old rate limit records (called by daily chores)
pub fn prune_old_rate_limit_records(state: &mut State, now: u64) {
    const RATE_LIMIT_RETENTION: u64 = 5 * 60_000_000_000; // 5 minutes
    let initial_count = state.rate_limiter.len();

    state
        .rate_limiter
        .retain(|_, (_, window_start)| now.saturating_sub(*window_start) < RATE_LIMIT_RETENTION);

    let removed_count = initial_count - state.rate_limiter.len();
    if removed_count > 0 {
        ic_cdk::println!("Pruned {} old rate limit records", removed_count);
    }
}

#[cfg(test)]
mod tests {
    use crate::env::proposals::{Proposal, Status};

    use super::*;

    fn pr(n: u8) -> Principal {
        let v = vec![n];
        Principal::from_slice(&v)
    }

    #[test]
    fn test_transfers() {
        let mut state = State::default();
        env::tests::create_user(&mut state, pr(0));

        let memo = vec![0; 33];

        assert_eq!(
            transfer(
                &mut state,
                1000 * MINUTE,
                pr(0),
                TransferArgs {
                    from_subaccount: None,
                    to: account(pr(1)),
                    amount: 1,
                    fee: Some(1),
                    memo: Some(memo),
                    created_at_time: None
                }
            ),
            Err(TransferError::GenericError(GenericError {
                error_code: 2,
                message: "memo longer than 32 bytes".into()
            }))
        );

        assert_eq!(
            transfer(
                &mut state,
                1000 * MINUTE,
                pr(0),
                TransferArgs {
                    from_subaccount: None,
                    to: account(pr(1)),
                    amount: 1,
                    fee: Some(1),
                    memo: None,
                    created_at_time: None
                }
            ),
            Err(TransferError::InsufficientFunds(InsufficientFunds {
                balance: 0
            }))
        );

        assert_eq!(
            transfer(
                &mut state,
                100 * MINUTE,
                pr(0),
                TransferArgs {
                    from_subaccount: None,
                    to: account(pr(1)),
                    amount: 1,
                    fee: Some(1),
                    memo: None,
                    created_at_time: Some(94 * MINUTE)
                }
            ),
            Err(TransferError::TooOld)
        );

        assert_eq!(
            transfer(
                &mut state,
                100 * MINUTE,
                pr(0),
                TransferArgs {
                    from_subaccount: None,
                    to: account(pr(1)),
                    amount: 1,
                    fee: Some(1),
                    memo: None,
                    created_at_time: Some(106 * MINUTE)
                }
            ),
            Err(TransferError::CreatedInFuture(CreatedInFuture {
                ledger_time: 6000000000000
            }))
        );

        state.balances.insert(account(pr(0)), 1000);

        // Create an open proposal with a pending vote
        state.proposals.push(Proposal {
            proposer: 0,
            bulletins: vec![(0, true, 1)],
            status: Status::Open,
            ..Default::default()
        });

        assert_eq!(
            transfer(
                &mut state,
                time(),
                pr(0),
                TransferArgs {
                    from_subaccount: None,
                    to: account(pr(1)),
                    amount: 500,
                    fee: Some(1),
                    memo: None,
                    created_at_time: None
                }
            ),
            Err(TransferError::GenericError(GenericError {
                error_code: 1,
                message: "transfers locked: a vote on a pending proposal detected".to_string(),
            })),
        );

        state.proposals.clear();

        assert_eq!(
            transfer(
                &mut state,
                time(),
                pr(0),
                TransferArgs {
                    from_subaccount: None,
                    to: account(pr(1)),
                    amount: 500,
                    fee: Some(1),
                    memo: None,
                    created_at_time: None
                }
            ),
            Ok(0),
        );
        assert_eq!(state.balances.get(&account(pr(0))), Some(&(1000 - 500 - 1)));
        assert_eq!(state.balances.get(&account(pr(1))), Some(&500));

        assert_eq!(
            transfer(
                &mut state,
                time(),
                pr(0),
                TransferArgs {
                    from_subaccount: None,
                    to: icrc1_minting_account().unwrap(),
                    amount: 350,
                    fee: Some(25),
                    memo: None,
                    created_at_time: None
                }
            ),
            Ok(1),
        );
        assert_eq!(
            state.balances.get(&account(pr(0))),
            Some(&(1000 - 500 - 1 - 350 - 25))
        );
        assert_eq!(state.balances.get(&icrc1_minting_account().unwrap()), None);

        assert_eq!(
            transfer(
                &mut state,
                time(),
                pr(0),
                TransferArgs {
                    from_subaccount: None,
                    to: account(pr(0)),
                    amount: 490,
                    fee: Some(1),
                    memo: None,
                    created_at_time: None
                }
            ),
            Err(TransferError::InsufficientFunds(InsufficientFunds {
                balance: 124
            }))
        );
    }
}
