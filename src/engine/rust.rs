// std
use std::{
	path::Path,
	str::FromStr,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc, Mutex,
	},
	thread::{self, sleep, JoinHandle},
	time::{Duration, SystemTime, UNIX_EPOCH},
};
// crates.io
use bitcoin::{
	absolute::LockTime,
	consensus::encode,
	hashes::Hash,
	psbt::Input,
	secp256k1::{All, Keypair, Message, Secp256k1, XOnlyPublicKey},
	sighash::{Prevouts, SighashCache},
	taproot::{LeafVersion, Signature, TaprootBuilder, TaprootSpendInfo},
	transaction::Version,
	Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, TapSighashType, Transaction,
	TxIn, TxOut, Witness, Txid,
};
use serde::Serialize;
// atomicalsir
use crate::{
	electrumx::{r#type::Utxo, Api, ElectrumX, ElectrumXBuilder},
	prelude::*,
	util,
	wallet::Wallet as RawWallet,
};

pub async fn run(
	network: Network,
	electrumx: &str,
	wallet_dir: &Path,
	ticker: &str,
	max_fee: u64,
	commit_time: u64,
	commit_nonce: u64,
	commit_txid: &str,
	commit_scriptpk: &str,
	commit_refund: u64,
) -> Result<()> {
	let m = MinerBuilder { network, electrumx, wallet_dir, ticker, max_fee, commit_time, commit_nonce, commit_txid, commit_scriptpk, commit_refund }.build()?;

	#[allow(clippy::never_loop)]
	loop {
		for w in &m.wallets {
			m.mine(w).await?;

			// Once resume-after-commit succeeds, return immediately.
			return Ok(());
		}
	}
}

#[derive(Debug)]
struct Miner {
	network: Network,
	api: ElectrumX,
	wallets: Vec<Wallet>,
	ticker: String,
	max_fee: u64,
	commit_time: u64,
	commit_nonce: u64,
	commit_txid: String,
	commit_scriptpk: String,
	commit_refund: u64,
}
impl Miner {
	const BASE_BYTES: f64 = 10.5;
	const BROADCAST_SLEEP_SECONDS: u32 = 15;
	const INPUT_BYTES_BASE: f64 = 57.5;
	const MAX_BROADCAST_NUM: u32 = 20;
	const MAX_SEQUENCE: u32 = u32::MAX;
	// OP_RETURN size
	// 8-bytes value(roughly estimate), a one-byte script’s size
	// actual value size depends precisely on final nonce
	const OP_RETURN_BYTES: f64 = 21. + 8. + 1.;
	const OUTPUT_BYTES_BASE: f64 = 43.;
	const REVEAL_INPUT_BYTES_BASE: f64 = 66.;
	const SEQ_RANGE_BUCKET: u32 = 100_000_000;

	async fn mine(&self, wallet: &Wallet) -> Result<()> {
		let concurrency: u32 = num_cpus::get() as u32;
		let seq_range_per_revealer: u32 = Self::SEQ_RANGE_BUCKET / concurrency;

		let d = self.prepare_data(wallet).await?;

		let Data {
			secp,
			satsbyte: _,
			bitworkc: _,
			bitworkr,
			additional_outputs,
			reveal_script,
			reveal_spend_info,
			fees,
			funding_utxo: _,
		} = d.clone();
		let reveal_spk = ScriptBuf::new_p2tr(
			&secp,
			reveal_spend_info.internal_key(),
			reveal_spend_info.merkle_root(),
		);
		let funding_spk = wallet.funding.address.script_pubkey();
		let commit_output = {
			let spend = TxOut {
				value: Amount::from_sat(fees.reveal_and_outputs),
				script_pubkey: reveal_spk.clone(),
			};
			let refund = {
				let r = self.commit_refund;

				if r > 0 {
					Some(TxOut { value: Amount::from_sat(r), script_pubkey: funding_spk.clone() })
				} else {
					None
				}
			};

			if let Some(r) = refund {
				vec![spend, r]
			} else {
				vec![spend]
			}
		};

		// TODO: Move common code to a single function.
		let reveal_hty = TapSighashType::SinglePlusAnyoneCanPay;
		let reveal_lh = reveal_script.tapscript_leaf_hash();
		let reveal_tx = if let Some(bitworkr) = bitworkr {
			// exists bitworkr
			tracing::info!("\nStarting reveal stage mining now...\n");
			tracing::info!("Concurrency set to: {concurrency}");
			let psbt = Psbt::from_unsigned_tx(Transaction {
				version: Version::ONE,
				lock_time: LockTime::ZERO,
				input: vec![TxIn {
					previous_output: OutPoint::new(self.commit_txid.clone().parse::<Txid>()?, 0),
					sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
					..Default::default()
				}],
				output: additional_outputs,
			})?;
			let mut ts = <Vec<JoinHandle<Result<()>>>>::new();
			let solution_found = Arc::new(AtomicBool::new(false));
			let must_tx = Arc::new(Mutex::new(None));
			let solution_time = Arc::new(Mutex::<u64>::new(0));
			let solution_nonce = Arc::new(Mutex::<u32>::new(0));

			for i in 0..concurrency {
				tracing::info!("spawning reveal worker thread {i} for bitworkr");
				let secp = secp.clone();
				let bitworkr = bitworkr.clone();
				let funding_kp = wallet.funding.pair;
				let reveal_script = reveal_script.clone();
				let reveal_spend_info = reveal_spend_info.clone();
				let commit_output = commit_output.clone();
				let psbt = psbt.clone();
				let solution_found = solution_found.clone();
				let must_tx = must_tx.clone();
				let solution_time = solution_time.clone();
				let solution_nonce = solution_nonce.clone();

				ts.push(thread::spawn(move || {
					let mut seq_start = i * seq_range_per_revealer;
					let mut seq = seq_start;
					let mut seq_end = seq_start + seq_range_per_revealer - 1;
					if i == (concurrency - 1) {
						seq_end = Self::SEQ_RANGE_BUCKET - 1;
					}

					let mut unixtime =
						SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
					let mut nonces_generated: u32 = 0;

					loop {
						if seq > seq_end {
							if seq_end <= Self::MAX_SEQUENCE - Self::SEQ_RANGE_BUCKET {
								seq_start += Self::SEQ_RANGE_BUCKET;
								seq_end += Self::SEQ_RANGE_BUCKET;
								seq = seq_start;
							} else {
								// reveal worker thread stop mining w/o soluton found
								tracing::info!("reveal worker thread {i} traversed its range w/o solution found.");
							}
						}
						if seq % 10000 == 0 {
							tracing::trace!(
								"started reveal mining for sequence: {seq} - {}",
								(seq + 10000).min(seq_end)
							);
						}

						if solution_found.load(Ordering::Relaxed) {
							return Ok(());
						}

						if nonces_generated % 10000 == 0 {
							unixtime =
								SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
						}

						let mut psbt = psbt.clone();

						psbt.unsigned_tx.output.push(TxOut {
							value: Amount::ZERO,
							script_pubkey: util::solution_tm_nonce_script(unixtime, seq),
						});
						psbt.outputs.push(Default::default());

						let tap_key_sig = {
							let h = SighashCache::new(&psbt.unsigned_tx)
								.taproot_script_spend_signature_hash(
									0,
									&Prevouts::One(0, commit_output[0].clone()),
									reveal_lh,
									reveal_hty,
								)?;
							let m = Message::from_digest(h.to_byte_array());

							Signature {
								sig: secp.sign_schnorr(&m, &funding_kp),
								hash_ty: reveal_hty,
							}
						};

						psbt.inputs[0] = Input {
							// TODO: Check.
							witness_utxo: Some(commit_output[0].clone()),
							tap_internal_key: Some(reveal_spend_info.internal_key()),
							tap_merkle_root: reveal_spend_info.merkle_root(),
							final_script_witness: {
								let mut w = Witness::new();

								w.push(tap_key_sig.to_vec());
								w.push(reveal_script.as_bytes());
								w.push(
									reveal_spend_info
										.control_block(&(
											reveal_script.clone(),
											LeafVersion::TapScript,
										))
										.unwrap()
										.serialize(),
								);

								Some(w)
							},
							..Default::default()
						};

						let tx = psbt.extract_tx_unchecked_fee_rate();
						let txid = tx.txid();

						if txid.to_string().trim_start_matches("0x").starts_with(&bitworkr) {
							tracing::info!("solution found for reveal step");
							tracing::info!("reveal sequence {seq}");
							tracing::info!("solution at time: {unixtime}, solution nonce: {seq}");
							solution_found.store(true, Ordering::Relaxed);
							*must_tx.lock().unwrap() = Some(tx);
							*solution_time.lock().unwrap() = unixtime;
							*solution_nonce.lock().unwrap() = seq;

							tracing::info!("\nReveal workers have completed their tasks for the reveal transaction.\n");

							return Ok(());
						}

						seq += 1;
						nonces_generated += 1;
					}
				}));
			}

			tracing::info!(
				"\nDon't despair, it still takes some time! Reveal workers have started mining...\n"
			);
			for t in ts {
				t.join().unwrap()?;
			}

			let tx = must_tx.lock().unwrap().take().unwrap();

			tx
		} else {
			// No bitworkr
			let mut psbt = Psbt::from_unsigned_tx(Transaction {
				version: Version::ONE,
				lock_time: LockTime::ZERO,
				input: vec![TxIn {
					previous_output: OutPoint::new(self.commit_txid.clone().parse()?, 0),
					sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
					..Default::default()
				}],
				output: additional_outputs,
			})?;
			let tap_key_sig = {
				let h = SighashCache::new(&psbt.unsigned_tx).taproot_script_spend_signature_hash(
					0,
					&Prevouts::One(0, commit_output[0].clone()),
					reveal_lh,
					reveal_hty,
				)?;
				let m = Message::from_digest(h.to_byte_array());

				Signature { sig: secp.sign_schnorr(&m, &wallet.funding.pair), hash_ty: reveal_hty }
			};

			psbt.inputs[0] = Input {
				// TODO: Check.
				witness_utxo: Some(commit_output[0].clone()),
				tap_internal_key: Some(reveal_spend_info.internal_key()),
				tap_merkle_root: reveal_spend_info.merkle_root(),
				final_script_witness: {
					let mut w = Witness::new();

					w.push(tap_key_sig.to_vec());
					w.push(reveal_script.as_bytes());
					w.push(
						reveal_spend_info
							.control_block(&(reveal_script, LeafVersion::TapScript))
							.unwrap()
							.serialize(),
					);

					Some(w)
				},
				..Default::default()
			};

			psbt.extract_tx_unchecked_fee_rate()
		};

		let reveal_txid = reveal_tx.txid();
		tracing::info!("reveal txid {}", reveal_txid);
		tracing::info!("reveal tx {reveal_tx:#?}");

		tracing::info!("Broadcasting reveal tx...");
		let raw_tx = encode::serialize_hex(&reveal_tx);
		tracing::info!("raw tx: {}", &raw_tx);
		let mut attempts = 0;
		while attempts < Self::MAX_BROADCAST_NUM {
			if let Err(_) = self.api.broadcast(raw_tx.clone()).await {
				tracing::info!(
					"Network error, will retry to broadcast reveal transaction in {} seconds...",
					Self::BROADCAST_SLEEP_SECONDS
				);
				sleep(Duration::from_secs(15));
				attempts += 1;
				continue;
			}
			break;
		}

		if attempts < Self::MAX_BROADCAST_NUM {
			tracing::info!("✅ Successfully sent reveal tx {reveal_txid}");
			tracing::info!("✨Congratulations! Mission completed.✨");
		} else {
			tracing::info!("❌ Failed to send reveal tx {reveal_txid}");
		}

		Ok(())
	}

	async fn prepare_data(&self, wallet: &Wallet) -> Result<Data> {
		let id = self.api.get_by_ticker(&self.ticker).await?.atomical_id;
		let response = self.api.get_ft_info(id).await?;
		let global = response.global.unwrap();
		let ft = response.result;

		if ft.ticker != self.ticker {
			Err(anyhow::anyhow!("ticker mismatch"))?;
		}
		if ft.subtype != "decentralized" {
			Err(anyhow::anyhow!("not decentralized"))?;
		}
		if ft.mint_height > global.height + 1 {
			Err(anyhow::anyhow!("mint height mismatch"))?;
		}
		if ft.mint_amount == 0 || ft.mint_amount >= 100_000_000 {
			Err(anyhow::anyhow!("mint amount mismatch"))?;
		}
		if ft.dft_info.mint_count >= ft.max_mints {
			Err(anyhow::anyhow!("max mints reached"))?;
		}

		let secp = Secp256k1::new();
		let satsbyte = if self.network == Network::Bitcoin {
			(util::query_fee().await? + 5).min(self.max_fee)
		} else {
			2
		};
		let additional_outputs = vec![TxOut {
			value: Amount::from_sat(ft.mint_amount),
			script_pubkey: wallet.stash.address.script_pubkey(),
		}];

		let reveal_script: ScriptBuf;
		let reveal_spend_info: TaprootSpendInfo;

		// loop is for future purpose only.
		// let mut nonce: u64 = 10_000_000;
		let nonce: u64;
		loop {
			let payload = PayloadWrapper {
				args: {
					let time: u64 = self.commit_time;
					// nonce -= 1;
					nonce = self.commit_nonce;

					tracing::info!("input commit payload time: {time}, input commit payload nonce: {nonce}");

					Payload {
						bitworkc: ft.mint_bitworkc.clone(),
						mint_ticker: ft.ticker.clone(),
						nonce,
						time,
					}
				},
			};
			let payload_encoded = util::cbor(&payload)?;
			let reveal_script_ =
				util::build_reval_script(&wallet.funding.x_only_public_key, "dmt", &payload_encoded);
			let reveal_spend_info_ = TaprootBuilder::new()
				.add_leaf(0, reveal_script_.clone())?
				.finalize(&secp, wallet.funding.x_only_public_key)
				.unwrap();
			let reveal_spk = ScriptBuf::new_p2tr(
				&secp,
				reveal_spend_info_.internal_key(),
				reveal_spend_info_.merkle_root(),
			);

			assert_eq!(reveal_spk.to_hex_string(), self.commit_scriptpk.clone(), "we are expecting both values are same.");

			tracing::info!("The previous commit verified successfully with time: {}, nonce: {}", payload.args.time, payload.args.nonce);
			reveal_script = reveal_script_;
			reveal_spend_info = reveal_spend_info_;

			break ();
		}

		let perform_bitworkr = if ft.mint_bitworkr.is_some() { true } else { false };
		let fees = Self::fees_of(
			satsbyte,
			reveal_script.as_bytes().len(),
			&additional_outputs,
			perform_bitworkr,
		);
		let funding_utxo = self
			.api
			.wait_until_utxo(wallet.funding.address.to_string(), fees.commit_and_reveal_and_outputs)
			.await?;

		Ok(Data {
			secp,
			satsbyte,
			bitworkc: ft.mint_bitworkc,
			bitworkr: ft.mint_bitworkr,
			additional_outputs,
			reveal_script,
			reveal_spend_info,
			fees,
			funding_utxo,
		})
	}

	fn fees_of(
		satsbyte: u64,
		reveal_script_len: usize,
		additional_outputs: &[TxOut],
		perform_bitworkr: bool,
	) -> Fees {
		let satsbyte = satsbyte as f64;
		let commit = {
			(satsbyte * (Self::BASE_BYTES + Self::INPUT_BYTES_BASE + Self::OUTPUT_BYTES_BASE))
				.ceil() as u64
		};
		let op_return_size_bytes = if perform_bitworkr { Self::OP_RETURN_BYTES } else { 0. };
		let reveal = {
			let compact_input_bytes = if reveal_script_len <= 252 {
				1.
			} else if reveal_script_len <= 0xFFFF {
				3.
			} else if reveal_script_len <= 0xFFFFFFFF {
				5.
			} else {
				9.
			};

			(satsbyte
				* (Self::BASE_BYTES
						+ Self::REVEAL_INPUT_BYTES_BASE
						+ (compact_input_bytes + reveal_script_len as f64) / 4.
						// + utxos.len() as f64 * Self::INPUT_BYTES_BASE
                        + op_return_size_bytes
						+ additional_outputs.len() as f64 * Self::OUTPUT_BYTES_BASE))
				.ceil() as u64
		};
		let outputs = additional_outputs.iter().map(|o| o.value.to_sat()).sum::<u64>();
		let commit_and_reveal = commit + reveal;
		let commit_and_reveal_and_outputs = commit_and_reveal + outputs;

		Fees {
			commit,
			// commit_and_reveal,
			commit_and_reveal_and_outputs,
			// reveal,
			reveal_and_outputs: reveal + outputs,
		}
	}
}
#[derive(Debug)]
struct MinerBuilder<'a> {
	network: Network,
	electrumx: &'a str,
	wallet_dir: &'a Path,
	ticker: &'a str,
	max_fee: u64,
	commit_time: u64,
	commit_nonce: u64,
	commit_txid: &'a str,
	commit_scriptpk: &'a str,
	commit_refund: u64,
}
impl<'a> MinerBuilder<'a> {
	fn build(self) -> Result<Miner> {
		let api =
			ElectrumXBuilder::default().network(self.network).base_uri(self.electrumx).build()?;
		let wallets = RawWallet::load_wallets(self.wallet_dir)
			.into_iter()
			.map(|rw| Wallet::from_raw_wallet(rw, self.network))
			.collect::<Result<_>>()?;

		Ok(Miner {
			network: self.network,
			api,
			wallets,
			ticker: self.ticker.into(),
			max_fee: self.max_fee,
			commit_time: self.commit_time,
			commit_nonce: self.commit_nonce,
			commit_txid: self.commit_txid.into(),
			commit_scriptpk: self.commit_scriptpk.into(),
			commit_refund: self.commit_refund,
		})
	}
}

#[derive(Clone, Debug)]
struct Wallet {
	stash: Key,
	funding: Key,
}
impl Wallet {
	fn from_raw_wallet(raw_wallet: RawWallet, network: Network) -> Result<Self> {
		let s_p = util::keypair_from_wif(&raw_wallet.stash.key.wif)?;
		let f_p = util::keypair_from_wif(&raw_wallet.funding.wif)?;

		Ok(Self {
			stash: Key {
				pair: s_p,
				x_only_public_key: s_p.x_only_public_key().0,
				address: Address::from_str(&raw_wallet.stash.key.address)?
					.require_network(network)?,
			},
			funding: Key {
				pair: f_p,
				x_only_public_key: f_p.x_only_public_key().0,
				address: Address::from_str(&raw_wallet.funding.address)?
					.require_network(network)?,
			},
		})
	}
}

#[derive(Clone, Debug)]
struct Key {
	pair: Keypair,
	x_only_public_key: XOnlyPublicKey,
	address: Address,
}

#[derive(Debug, Serialize)]
pub struct PayloadWrapper {
	pub args: Payload,
}
#[derive(Debug, Serialize)]
pub struct Payload {
	pub bitworkc: String,
	pub mint_ticker: String,
	pub nonce: u64,
	pub time: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct Data {
	secp: Secp256k1<All>,
	satsbyte: u64,
	bitworkc: String,
	bitworkr: Option<String>,
	additional_outputs: Vec<TxOut>,
	reveal_script: ScriptBuf,
	reveal_spend_info: TaprootSpendInfo,
	fees: Fees,
	funding_utxo: Utxo,
}
#[allow(dead_code)]
#[derive(Clone, Debug)]
struct Fees {
	commit: u64,
	// commit_and_reveal: u64,
	commit_and_reveal_and_outputs: u64,
	// reveal: u64,
	reveal_and_outputs: u64,
}
