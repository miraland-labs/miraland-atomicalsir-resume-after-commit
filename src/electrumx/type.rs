// std
use std::collections::HashMap;
// crates.io
use serde::{Deserialize, Serialize};
// use serde_with::skip_serializing_none;

#[derive(Debug, Serialize)]
pub struct Params<P>
where
	P: Serialize,
{
	pub params: P,
}
impl<P> Params<P>
where
	P: Serialize,
{
	pub fn new(params: P) -> Self {
		Self { params }
	}
}

// TODO: Handle errors.
#[derive(Debug, Deserialize)]
pub struct Response<R> {
	pub success: bool,
	pub response: R,
}

#[derive(Debug, Deserialize)]
pub struct ResponseResult<R> {
	pub global: Option<Global>,
	pub result: R,
}
#[derive(Debug, Deserialize)]
pub struct Global {
	pub atomical_count: u64,
	pub atomicals_block_hashes: HashMap<String, String>,
	pub atomicals_block_tip: String,
	pub block_tip: String,
	pub coin: String,
	pub height: u64,
	pub network: String,
	pub server_time: String,
}

#[derive(Debug, Deserialize)]
pub struct Ticker {
	pub status: String,
	pub candidate_atomical_id: String,
	pub atomical_id: String,
	pub candidates: Vec<Candidate>,
	pub r#type: String,
}
#[derive(Debug, Deserialize)]
pub struct Candidate {
	pub tx_num: u64,
	pub atomical_id: String,
	pub commit_height: u64,
	pub reveal_location_height: u64,
}

// #[skip_serializing_none]
#[derive(Debug, Deserialize)]
pub struct Ft {
	#[serde(rename = "$bitwork")]
	pub bitwork: Bitwork,
	#[serde(rename = "$max_mints")]
	pub max_mints: u64,
	#[serde(rename = "$max_supply")]
	// pub max_supply: u64,
	pub max_supply: i64, // under perpetual/infinite mode, max_supply is -1
	#[serde(rename = "$mint_amount")]
	pub mint_amount: u64,
	#[serde(default, rename = "$mint_bitworkc")]
	pub mint_bitworkc: Option<String>,
	#[serde(default, rename = "$mint_bitworkr")]
	pub mint_bitworkr: Option<String>,
	#[serde(rename = "$mint_height")]
	pub mint_height: u64,
	#[serde(rename = "$request_ticker")]
	pub request_ticker: String,
	#[serde(rename = "$request_ticker_status")]
	pub request_ticker_status: TickerStatus,
	#[serde(rename = "$ticker")]
	pub ticker: String,
	#[serde(rename = "$ticker_candidates")]
	pub ticker_candidates: Vec<TickerCandidate>,
	// MI
	#[serde(rename = "$mint_mode")]
	pub mint_mode: String,
	#[serde(default, rename = "$mint_bitwork_vec")]
	pub mint_bitwork_vec: Option<String>,
	#[serde(default, rename = "$mint_bitworkc_inc")]
	pub mint_bitworkc_inc: Option<u32>,
	#[serde(default, rename = "$mint_bitworkc_start")]
	pub mint_bitworkc_start: Option<u32>,
	#[serde(default, rename = "$mint_bitworkr_inc")]
	pub mint_bitworkr_inc: Option<u32>,
	#[serde(default, rename = "$mint_bitworkr_start")]
	pub mint_bitworkr_start: Option<u32>,
	pub atomical_id: String,
	pub atomical_number: u64,
	pub atomical_ref: String,
	pub confirmed: bool,
	pub dft_info: DftInfo,
	pub location_summary: LocationSummary,
	pub mint_data: MintData,
	pub mint_info: MintInfo,
	pub subtype: String,
	pub r#type: String,
}
#[derive(Debug, Deserialize)]
pub struct Bitwork {
	pub bitworkc: String,
	pub bitworkr: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct TickerStatus {
	pub note: String,
	pub status: String,
	pub verified_atomical_id: String,
}
#[derive(Debug, Deserialize)]
pub struct TickerCandidate {
	pub atomical_id: String,
	pub commit_height: u64,
	pub reveal_location_height: u64,
	pub tx_num: u64,
	pub txid: String,
}
#[derive(Debug, Deserialize)]
pub struct DftInfo {
	pub mint_count: u64,
	pub mint_bitworkc_current: Option<String>,
	pub mint_bitworkc_next: Option<String>,
	pub mint_bitworkc_next_next: Option<String>,
	pub mint_bitworkr_current: Option<String>,
	pub mint_bitworkr_next: Option<String>,
	pub mint_bitworkr_next_next: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct LocationSummary {
	pub circulating_supply: u64,
	pub unique_holders: u64,
}
#[derive(Debug, Deserialize)]
pub struct MintData {
	pub fields: Fields,
}
#[derive(Debug, Deserialize)]
pub struct Fields {
	pub args: Args,
	pub meta: Option<Meta>,
}
#[derive(Debug, Deserialize)]
pub struct Args {
	pub bitworkc: String,
	pub bitworkr: Option<String>,
	pub max_mints: u64,
	pub mint_amount: u64,
	pub mint_bitworkc: Option<String>,
	pub mint_bitworkr: Option<String>,
	pub mint_height: u64,
	// TODO: It's a `String` in mainnet but a `u64` in testnet.
	// pub nonce: u64,
	pub request_ticker: String,
	pub time: u64,
}
#[derive(Debug, Deserialize)]
pub struct Meta {
	pub description: Option<String>,
	pub legal: Option<Legal>,
	pub name: Option<String>,
}
#[derive(Debug, Deserialize)]
pub struct Legal {
	pub terms: String,
}
#[derive(Debug, Deserialize)]
pub struct MintInfo {
	#[serde(rename = "$bitwork")]
	pub bitwork: Bitwork,
	#[serde(rename = "$mint_bitworkc")]
	pub mint_bitworkc: Option<String>,
	#[serde(rename = "$mint_bitworkr")]
	pub mint_bitworkr: Option<String>,
	#[serde(rename = "$request_ticker")]
	pub request_ticker: String,
	pub args: Args,
	pub commit_height: u64,
	pub commit_index: u64,
	pub commit_location: String,
	pub commit_tx_num: u64,
	pub commit_txid: String,
	pub ctx: Ctx,
	pub meta: Meta,
	pub reveal_location: String,
	pub reveal_location_blockhash: String,
	pub reveal_location_header: String,
	pub reveal_location_height: u64,
	pub reveal_location_index: u64,
	pub reveal_location_script: String,
	pub reveal_location_scripthash: String,
	pub reveal_location_tx_num: u64,
	pub reveal_location_txid: String,
	pub reveal_location_value: u64,
}
// TODO: Check the real type.
#[derive(Debug, Deserialize)]
pub struct Ctx {}

#[derive(Debug, Deserialize)]
pub struct Unspent {
	pub txid: String,
	pub tx_hash: String,
	pub index: u32,
	pub tx_pos: u32,
	pub vout: u32,
	pub height: u64,
	pub value: u64,
	// TODO: Check the real type.
	// pub atomicals: Vec<()>,
	pub atomicals: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Utxo {
	pub txid: String,
	// The same as `output_index` and `index`.
	pub vout: u32,
	pub value: u64,
	// pub atomicals: Vec<()>,
	pub atomicals: Vec<String>,
}
impl From<Unspent> for Utxo {
	fn from(v: Unspent) -> Self {
		Self { txid: v.tx_hash, vout: v.tx_pos, value: v.value, atomicals: v.atomicals }
	}
}
