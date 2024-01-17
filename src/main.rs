use core::fmt;
use std::{convert::Infallible, error::Error, net::IpAddr, str::FromStr, time::Duration};

use anyhow::Result;

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::join;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    dotenvy::dotenv().unwrap();
    let config = || -> Result<Config> {
        Ok(Config {
            auth: AuthToken(dotenvy::var("auth")?),
            domain: dotenvy::var("domain")?,
            record: dotenvy::var("record")?,
        })
    }()?;
    let auth = &config.auth;
    let domain = &config.domain;
    let record = &config.record;
    let client = Client::new();
    let zone = get_zone(&client, auth, domain).await?;
    println!("Got Zone ID for {} : {}", config.domain, &zone);
    let dns_record_id = get_record_id(&client, &config.auth, &zone).await?;
    println!("Got dns id for {} : {:?}", config.domain, &dns_record_id);

    loop {
        match update_ip(&client, auth, &zone, &dns_record_id, record).await {
            Ok(()) => println!("Update Successfull"),
            Err(e) => println!("Update Failed {:?}", e),
        }

        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

async fn update_ip(
    client: &Client,
    auth: &AuthToken,
    zone: &ZoneId,
    record_id: &DNSRecordID,
    record_name: &str,
) -> Result<()> {
    let result = join!(get_ipv4(client), get_ipv6(client));
    let result = vec![result.0, result.1];
    let ids = vec![record_id.0.as_deref(), record_id.1.as_deref()];
    let updates = result
        .into_iter()
        .map(|v| v.ok())
        .zip(ids.into_iter())
        .filter_map(|v| v.0.zip(v.1)) // Only handle the case where we got a new address and an id
        .map(|v| UpdateRecord::new(v.1, record_name, &v.0, zone))
        .collect::<Vec<_>>();

    update_record_bulk(auth, &updates.into()).await?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AuthToken(String);

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ZoneId(String);

impl From<ZoneId> for String {
    fn from(val: ZoneId) -> Self {
        val.0
    }
}

impl FromStr for ZoneId {
    type Err = Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        core::result::Result::Ok(ZoneId(s.to_owned()))
    }
}

impl std::fmt::Display for ZoneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Zone {
    pub id: ZoneId,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ZoneResponse {
    zones: Vec<Zone>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RecordResponses {
    records: Vec<UpdateRecord>,
}

impl From<Vec<UpdateRecord>> for RecordResponses {
    fn from(value: Vec<UpdateRecord>) -> Self {
        RecordResponses { records: value }
    }
}

impl RecordResponses {
    fn len(&self) -> usize {
        self.records.len()
    }
}

#[derive(Clone, Debug)]
struct Config {
    domain: String,
    auth: AuthToken,
    record: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateRecord {
    id: String,
    name: String,
    ttl: Option<u64>,
    value: String,
    zone_id: ZoneId,
    #[serde(rename = "type")]
    dnstype: DNSType,
}

impl UpdateRecord {
    /// id is the hetzner given id
    /// name is the subdomain to be updated
    /// value ist the new ip address, type is created based on the type passed here
    /// zone is the zone id from hetzner
    fn new(id: &str, name: &str, value: &IpAddr, zone: &ZoneId) -> Self {
        UpdateRecord {
            id: id.to_string(),
            name: name.to_string(),
            ttl: Some(60),
            value: value.to_string(),
            zone_id: zone.clone(),
            dnstype: match value {
                IpAddr::V4(_) => DNSType::A,
                IpAddr::V6(_) => DNSType::AAAA,
            },
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum DNSType {

    A,
    AAAA,
    NS,
    MX,
    CNAME,
    RP,
    TXT,
    SOA,
    HINFO,
    SRV,
    DANE,
    TLSA,
    DS,
    CAA,
}

/// Get your current public IPv4 address.
///
/// Panics if the returned IP is not a valid IPv4 address.
pub async fn get_ipv4(client: &Client) -> Result<IpAddr> {
    Ok(client
        .get("https://4.icanhazip.com/")
        .send()
        .await?
        .text()
        .await?
        .trim()
        .parse::<IpAddr>()?)
}

/// Get your current public IPv6 address.
///
/// Errors if there is no Ipv6 connectivity.
/// Panics if the returned IP is not a valid IPv6 address.
pub async fn get_ipv6(client: &Client) -> Result<IpAddr> {
    Ok(client
        .get("https://6.icanhazip.com/")
        .send()
        .await?
        .text()
        .await?
        .trim()
        .parse::<IpAddr>()?)
}

async fn get_zone(client: &Client, auth: &AuthToken, name: &String) -> Result<ZoneId> {
    let response = client
        .get("https://dns.hetzner.com/api/v1/zones")
        .header("Auth-API-Token", &auth.0)
        .query(&[("name", name)])
        .send()
        .await?;
    let response = response.json::<ZoneResponse>().await?;
    let zone = response
        .zones
        .iter()
        .filter(|&zone| zone.name.eq(name))
        .last()
        .ok_or(APIError {
            code: StatusCode::NOT_FOUND,
        })?;
    Ok(zone.id.clone())
}

async fn get_record_id(client: &Client, auth: &AuthToken, zone: &ZoneId) -> Result<DNSRecordID> {
    let response = client
        .get("https://dns.hetzner.com/api/v1/records")
        .header("Auth-API-Token", &auth.0)
        .query(&[("zone_id", zone)])
        .send()
        .await?;

    let response = response.json::<RecordResponses>().await?;
    let ipv4 = response
        .records
        .iter()
        .filter(|val| matches!(val.dnstype, DNSType::A))
        .last()
        .map(|v| v.id.clone());
    let ipv6 = response
        .records
        .iter()
        .filter(|val| matches!(val.dnstype, DNSType::AAAA))
        .last()
        .map(|v| v.id.clone());
    Ok((ipv4, ipv6))
}

/// Update a specific hetzner dns record
async fn _update_record(
    client: &Client,
    auth: &AuthToken,
    record: &UpdateRecord,
) -> anyhow::Result<()> {
    let record_id = &record.id;
    let result = client
        .post(format!(
            "https://dns.hetzner.com/api/v1/records/{record_id}"
        ))
        .header("Auth-API-Token", &auth.0)
        .json(record)
        .send()
        .await?;
    match result.status() {
        StatusCode::OK => Ok(()),
        other => Err(APIError::from(other).into()),
    }
}

/// Update a specific hetzner dns record
async fn update_record_bulk(auth: &AuthToken, records: &RecordResponses) -> anyhow::Result<()> {
    if records.len() == 0 {
        return Ok(());
    }
    let client = reqwest::Client::new();
    let result = client
        .put("https://dns.hetzner.com/api/v1/records/bulk")
        .header("Auth-API-Token", &auth.0)
        .json(records)
        .send()
        .await?;
    let status = result.status();
    match status {
        StatusCode::OK => Ok(()),
        other => Err(APIError::from(other).into()),
    }
}

#[derive(Debug, Clone, Copy)]
struct APIError {
    code: StatusCode,
}

impl fmt::Display for APIError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(f)
    }
}

impl From<StatusCode> for APIError {
    fn from(value: StatusCode) -> Self {
        APIError { code: value }
    }
}

impl Error for APIError {}

type DNSRecordID = (Option<String>, Option<String>);
