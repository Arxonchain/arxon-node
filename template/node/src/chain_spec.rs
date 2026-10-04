use std::{collections::BTreeMap, str::FromStr};

use hex_literal::hex;
// Substrate
use sc_chain_spec::{ChainType, Properties};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
#[allow(unused_imports)]
use sp_core::ecdsa;
use sp_core::{ed25519, sr25519, Pair, Public, H160, U256};
use sp_runtime::traits::{IdentifyAccount, Verify};
// Frontier
use arxon_runtime::{
	AccountId, SS58Prefix, Signature, ARXON_EVM_CHAIN_ID, ARX_DECIMALS, ARX_UNIT, WASM_BINARY,
};

// The URL for the telemetry server.
// const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{seed}"), None)
		.expect("static values are valid; qed")
		.public()
}

#[allow(dead_code)]
type AccountPublic = <Signature as Verify>::Signer;

/// Generate an account ID from seed.
/// For use with `AccountId32`, `dead_code` if `AccountId20`.
#[allow(dead_code)]
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Generate an Aura authority key.
pub fn authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
	(get_from_seed::<AuraId>(s), get_from_seed::<GrandpaId>(s))
}

/// Public keys only. Secret seeds stay offline and are never in this file.
fn authority_keys_from_hex(aura: [u8; 32], grandpa: [u8; 32]) -> (AuraId, GrandpaId) {
	(sr25519::Public::from_raw(aura).into(), ed25519::Public::from_raw(grandpa).into())
}

fn properties() -> Properties {
	let mut properties = Properties::new();
	properties.insert("tokenDecimals".into(), (ARX_DECIMALS as u32).into());
	properties.insert("tokenSymbol".into(), "ARX".into());
	properties.insert("ss58Format".into(), SS58Prefix::get().into());
	properties.insert("isEthereum".into(), true.into());
	properties
}

pub fn development_config(enable_manual_seal: bool) -> ChainSpec {
	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("Arxon")
		.with_id("arxon_dev")
		.with_chain_type(ChainType::Development)
		.with_properties(properties())
		.with_genesis_config_patch(testnet_genesis(
			// DEV ONLY. Well-known Alith test account (public key). Anyone can sudo
			// a node that uses this genesis. Replace before any public testnet or mainnet.
			AccountId::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")),
			// Pre-funded accounts
			vec![
				(
					AccountId::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")),
					300_000_000u128 * ARX_UNIT,
				), // Treasury 30%
				(
					AccountId::from(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0")),
					250_000_000u128 * ARX_UNIT,
				), // Mining Pool 25%
				(
					AccountId::from(hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc")),
					200_000_000u128 * ARX_UNIT,
				), // Investors 20%
				(
					AccountId::from(hex!("773539d4Ac0e786233D90A233654ccEE26a613D9")),
					150_000_000u128 * ARX_UNIT,
				), // Team 15%
				(
					AccountId::from(hex!("Ff64d3F6efE2317EE2807d223a0Bdc4c0c49dfDB")),
					100_000_000u128 * ARX_UNIT,
				), // Staking 10%
			],
			// Initial PoA authorities from well-known //Alice seed. DEV ONLY.
			vec![authority_keys_from_seed("Alice")],
			// Ethereum chain ID
			ARXON_EVM_CHAIN_ID,
			enable_manual_seal,
			true,
		))
		.build()
}

/// Public testnet (rpc-test.arxon.io). `--dev` / Alice genesis is `development_config`.
/// Addresses and Aura/Grandpa hex below are **public** on-chain values, not seeds.
pub fn local_testnet_config() -> ChainSpec {
	ChainSpec::builder(WASM_BINARY.expect("WASM not available"), Default::default())
		.with_name("Arxon Testnet")
		.with_id("arxon_testnet")
		.with_chain_type(ChainType::Live)
		.with_properties(properties())
		.with_genesis_config_patch(testnet_genesis(
			// Sudo (public 0x). Secret stays offline.
			AccountId::from(hex!("1681a02ba0008469f4380f246622e62fc170437b")),
			vec![
				(
					// Treasury / operator pocket (public 0x).
					AccountId::from(hex!("2a022a04e3d0ea66b8157c9b3c0510db52b8a286")),
					998_999_999u128 * ARX_UNIT,
				),
				(
					AccountId::from(hex!("1681a02ba0008469f4380f246622e62fc170437b")),
					1u128 * ARX_UNIT,
				),
				(
					// Relayer fee payer (public 0x). Key is RELAYER_KEY on the box.
					AccountId::from(hex!("f55260f227cb6a1b5a4cafb4dd365a0531b41fa7")),
					1_000_000u128 * ARX_UNIT,
				),
			],
			vec![authority_keys_from_hex(
				hex!("68a86a2d5e3f3dc3557172fc5f89a2fa90b74d98b970be759958e61c95035170"),
				hex!("e6e36daf7c4cdf3aa3259c1ebf70fa59d17727eaff264282066a10562e7ad172"),
			)],
			ARXON_EVM_CHAIN_ID,
			false,
			false,
		))
		.build()
}

/// Configure initial storage state for FRAME modules.
fn testnet_genesis(
	sudo_key: AccountId,
	endowed_accounts: Vec<(AccountId, u128)>,
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	chain_id: u64,
	enable_manual_seal: bool,
	include_dev_evm: bool,
) -> serde_json::Value {
	let evm_accounts = if !include_dev_evm {
		BTreeMap::new()
	} else {
		let mut map = BTreeMap::new();
		map.insert(
			// H160 address of Alice dev account
			// Derived from SS58 (42 prefix) address
			// SS58: 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
			// hex: 0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d
			// Using the full hex key, truncating to the first 20 bytes (the first 40 hex chars)
			H160::from_str("d43593c715fdd31c61141abd04a99fd6822c8558")
				.expect("internal H160 is valid; qed"),
			fp_evm::GenesisAccount {
				balance: U256::from_str("0xffffffffffffffffffffffffffffffff")
					.expect("internal U256 is valid; qed"),
				code: Default::default(),
				nonce: Default::default(),
				storage: Default::default(),
			},
		);
		map.insert(
			// H160 address of CI test runner account
			H160::from_str("6be02d1d3665660d22ff9624b7be0551ee1ac91b")
				.expect("internal H160 is valid; qed"),
			fp_evm::GenesisAccount {
				balance: U256::from_str("0xffffffffffffffffffffffffffffffff")
					.expect("internal U256 is valid; qed"),
				code: Default::default(),
				nonce: Default::default(),
				storage: Default::default(),
			},
		);
		map.insert(
			// H160 address for benchmark usage
			H160::from_str("1000000000000000000000000000000000000001")
				.expect("internal H160 is valid; qed"),
			fp_evm::GenesisAccount {
				nonce: U256::from(1),
				balance: U256::from(1_000_000_000_000_000_000_000_000u128),
				storage: Default::default(),
				code: vec![0x00],
			},
		);
		map
	};

	serde_json::json!({
		"sudo": { "key": Some(sudo_key) },
		"balances": {
			"balances": endowed_accounts.to_vec()
		},
		"aura": { "authorities": initial_authorities.iter().map(|x| (x.0.clone())).collect::<Vec<_>>() },
		"grandpa": { "authorities": initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect::<Vec<_>>() },
		"evmChainId": { "chainId": chain_id },
		"evm": { "accounts": evm_accounts },
		"manualSeal": { "enable": enable_manual_seal }
	})
}
