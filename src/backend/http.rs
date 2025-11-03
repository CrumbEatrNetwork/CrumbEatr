use super::assets;
use crate::assets::{index_html_headers, INDEX_HTML};
use crate::post::Post;
use crate::read;
use crate::{config::CONFIG, metadata::set_metadata};
use candid::CandidType;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

pub type Headers = Vec<(String, String)>;

#[derive(Clone, CandidType, Deserialize)]
pub struct HttpRequest {
    url: String,
    headers: Headers,
}

impl HttpRequest {
    pub fn path(&self) -> &str {
        match self.url.find('?') {
            None => &self.url[..],
            Some(index) => &self.url[..index],
        }
    }

    // TODO: Future enhancement for platform-specific social media crawler optimization
    // /// Checks if the request is from a social media crawler
    // pub fn is_social_media_crawler(&self) -> bool {
    //     self.headers.iter().any(|(name, value)| {
    //         name.to_lowercase() == "user-agent" && {
    //             let ua = value.to_lowercase();
    //             ua.contains("twitterbot")
    //                 || ua.contains("facebookexternalhit")
    //                 || ua.contains("redditbot")
    //                 || ua.contains("linkedinbot")
    //                 || ua.contains("whatsapp")
    //                 || ua.contains("discordbot")
    //         }
    //     })
    // }

    /// Searches for the first appearance of a parameter in the request URL.
    /// Returns `None` if the given parameter does not appear in the query.
    pub fn raw_query_param(&self, param: &str) -> Option<&str> {
        const QUERY_SEPARATOR: &str = "?";
        let query_string = self.url.split(QUERY_SEPARATOR).nth(1)?;
        if query_string.is_empty() {
            return None;
        }
        const PARAMETER_SEPARATOR: &str = "&";
        for chunk in query_string.split(PARAMETER_SEPARATOR) {
            const KEY_VALUE_SEPARATOR: &str = "=";
            let mut split = chunk.splitn(2, KEY_VALUE_SEPARATOR);
            let name = split.next()?;
            if name == param {
                return Some(split.next().unwrap_or_default());
            }
        }
        None
    }
}

#[derive(Debug, CandidType, Serialize)]
pub struct HttpResponse {
    status_code: u16,
    headers: Headers,
    body: ByteBuf,
    upgrade: Option<bool>,
}

#[ic_cdk_macros::update]
fn http_request_update(req: HttpRequest) -> HttpResponse {
    let path = &req.url;
    route(path)
        .map(|(headers, body)| HttpResponse {
            status_code: 200,
            headers: add_security_headers(headers),
            body,
            upgrade: None,
        })
        .unwrap_or_else(|| panic!("no assets for {}", path))
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct Metadata<'a> {
    decimals: u8,
    symbol: &'a str,
    token_name: &'a str,
    fee: u64,
    logo: &'a str,
    maximum_supply: u64,
    total_supply: u64,
    latest_proposal_id: Option<u32>,
    proposal_count: u64,
}

#[ic_cdk_macros::query]
fn http_request(req: HttpRequest) -> HttpResponse {
    let path = &req.url;

    use serde_json;
    use std::str::FromStr;

    if req.path() == "/api/v1/proposals" {
        read(|state| {
            let offset = usize::from_str(req.raw_query_param("offset").unwrap_or_default())
                .unwrap_or_default()
                .min(state.proposals.len());
            let limit = usize::from_str(req.raw_query_param("limit").unwrap_or_default())
                .unwrap_or(1_000_usize);
            // Security fix: Use saturating_add to prevent integer overflow
            let end = offset.saturating_add(limit).min(state.proposals.len());

            let proposal_slice = if let Some(slice) = state.proposals.get(offset..end) {
                slice
            } else {
                &[]
            };
            HttpResponse {
                status_code: 200,
                headers: add_security_headers(vec![(
                    "Content-Type".to_string(),
                    "application/json; charset=UTF-8".to_string(),
                )]),
                body: ByteBuf::from(serde_json::to_vec(&proposal_slice).unwrap_or_default()),
                upgrade: None,
            }
        })
    } else if req.path() == "/api/v1/metadata" {
        use base64::{engine::general_purpose, Engine as _};
        read(|s| HttpResponse {
            status_code: 200,
            headers: add_security_headers(vec![(
                "Content-Type".to_string(),
                "application/json; charset=UTF-8".to_string(),
            )]),
            body: ByteBuf::from(
                serde_json::to_vec(&Metadata {
                    decimals: CONFIG.token_decimals,
                    symbol: CONFIG.token_symbol,
                    token_name: CONFIG.token_name,
                    fee: CONFIG.transaction_fee,
                    logo: &format!(
                        "data:image/png;base64,{}",
                        general_purpose::STANDARD
                            .encode(include_bytes!("../frontend/assets/apple-touch-icon.png"))
                    ),
                    maximum_supply: CONFIG.maximum_supply,
                    total_supply: s.balances.values().copied().sum::<u64>(),
                    latest_proposal_id: s.proposals.last().map(|p| p.id),
                    proposal_count: s.proposals.len() as u64,
                })
                .unwrap_or_default(),
            ),
            upgrade: None,
        })
    }
    // If the asset is certified, return it, otherwise, upgrade to http_request_update
    else if let Some((headers, body)) = assets::asset_certified(path) {
        HttpResponse {
            status_code: 200,
            headers: add_security_headers(headers),
            body,
            upgrade: None,
        }
    } else {
        HttpResponse {
            status_code: 200,
            headers: Default::default(),
            body: Default::default(),
            upgrade: Some(true),
        }
    }
}

// Security fix: Add security headers (CSP temporarily disabled for debugging)
fn add_security_headers(mut headers: Headers) -> Headers {
    // TODO: Re-enable CSP with correct domains for IC boundary nodes
    // Current issue: IC API calls may go through different domains than content serving
    // Need to allow: ic0.app, icp0.io, raw.ic0.app, raw.icp0.io, localhost:8080 (dev)

    // X-Frame-Options: Prevent clickjacking
    headers.push(("X-Frame-Options".to_string(), "DENY".to_string()));

    // X-Content-Type-Options: Prevent MIME-sniffing
    headers.push(("X-Content-Type-Options".to_string(), "nosniff".to_string()));

    headers
}

fn route(path: &str) -> Option<(Headers, ByteBuf)> {
    read(|state| {
        let domain = CONFIG.domains.first().cloned().expect("no domains");
        let filter = |val: &str| {
            val.chars()
                .filter(|c| c.is_alphanumeric() || " .,?!-:/@\n#".chars().any(|v| &v == c))
                .collect::<String>()
        };
        let mut parts = path.split('/').skip(1);
        match (parts.next(), parts.next()) {
            (Some("post"), Some(id)) | (Some("thread"), Some(id)) => {
                if let Some(post) =
                    Post::get(state, &id.parse::<u64>().expect("couldn't parse post id"))
                {
                    return index(
                        domain,
                        &format!(
                            "{}/{}",
                            match post.parent {
                                None => "post",
                                _ => "thread",
                            },
                            post.id
                        ),
                        &format!(
                            "{} #{} by @{}",
                            match post.parent {
                                None => "Post",
                                _ => "Reply",
                            },
                            post.id,
                            state.users.get(&post.user)?.name
                        ),
                        &filter(&post.body),
                        "article",
                    );
                }
                None
            }
            (Some("journal"), Some(handle)) => {
                let user = state.user(handle)?;
                index(
                    domain,
                    &format!("journal/{}", user.name),
                    &format!("@{}'s journal", user.name),
                    &filter(&user.about),
                    "website",
                )
            }
            (Some("user"), Some(handle)) => {
                let user = state.user(handle)?;
                index(
                    domain,
                    &format!("user/{}", user.name),
                    &format!("User @{}", user.name),
                    &filter(&user.about),
                    "profile",
                )
            }
            (Some("realm"), Some(arg)) => {
                let id = arg.to_uppercase();
                let realm = state.realms.get(&id)?;
                index(
                    domain,
                    &format!("realm/{}", id),
                    &format!("Realm {}", id),
                    &filter(&realm.description),
                    "website",
                )
            }
            (Some("feed"), Some(filter)) => index(
                domain,
                &format!("feed/{}", filter),
                filter,
                &format!("Latest posts on {}", filter),
                "website",
            ),
            _ => assets::asset("/"),
        }
    })
}

fn index(
    host: &str,
    path: &str,
    title: &str,
    desc: &str,
    page_type: &str,
) -> Option<(Headers, ByteBuf)> {
    Some((
        index_html_headers(),
        ByteBuf::from(set_metadata(INDEX_HTML, host, path, title, desc, page_type)),
    ))
}

#[test]
fn should_return_proposals() {
    use crate::proposals::{Proposal, Status};
    use crate::State;

    let mut http_request_arg = HttpRequest {
        url: "/api/v1/proposals".to_string(),
        headers: vec![],
    };
    let mut state = State::default();

    for id in 0..10_u32 {
        state.proposals.push(Proposal {
            id,
            proposer: 0,
            bulletins: vec![(0, true, 1)],
            status: Status::Open,
            ..Default::default()
        });
    }
    crate::mutate(|s| *s = state);

    fn check_proposals(http_request_arg: HttpRequest, len: usize, start: u32, end: u32) {
        let http_resp = http_request(http_request_arg.clone());
        match serde_json::from_slice::<Vec<Proposal>>(&http_resp.body) {
            Ok(proposals) => {
                assert_eq!(proposals.len(), len);
                assert_eq!(proposals[0].id, start);
                assert_eq!(proposals.last().unwrap().id, end);
            }
            Err(_) => panic!("failed to deserialize json"),
        }
    }

    check_proposals(http_request_arg.clone(), 10_usize, 0_u32, 9_u32);

    http_request_arg.url = "/api/v1/proposals?limit=5".to_string();
    check_proposals(http_request_arg.clone(), 5_usize, 0_u32, 4_u32);

    http_request_arg.url = "/api/v1/proposals?limit=3&offset=6".to_string();
    check_proposals(http_request_arg.clone(), 3_usize, 6_u32, 8_u32);

    http_request_arg.url = "/api/v1/proposals?offset=6&limit=3".to_string();
    check_proposals(http_request_arg.clone(), 3_usize, 6_u32, 8_u32);
}

#[test]
fn should_return_metadata() {
    use crate::proposals::{Proposal, Status};
    use crate::State;

    let mut state = State::default();

    for id in 0..10_u32 {
        state.proposals.push(Proposal {
            id,
            proposer: 0,
            bulletins: vec![(0, true, 1)],
            status: Status::Open,
            ..Default::default()
        });
    }
    crate::mutate(|s| *s = state);

    let http_resp = http_request(HttpRequest {
        url: "/api/v1/metadata".to_string(),
        headers: vec![],
    });
    match serde_json::from_slice::<Metadata>(&http_resp.body) {
        Ok(metadata) => {
            assert_eq!(metadata, Metadata {
                decimals: 2,
                symbol: "CRUMB",
                token_name: "Crumb",
                fee: 25,
                logo: "data:image/png;base64,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",
                maximum_supply: 100000000,
                total_supply: 0,
                latest_proposal_id: Some(
                    9,
                ),
                proposal_count: 10,
            });
        }
        Err(_) => panic!("failed to deserialize json"),
    }
}
