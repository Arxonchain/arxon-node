use crate::{
	AccountId, BalancesConfig, EVMChainIdConfig, EVMConfig, EthereumConfig, ManualSealConfig,
	RuntimeGenesisConfig, SudoConfig, ARXON_EVM_CHAIN_ID, ARX_UNIT,
};
use hex_literal::hex;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
#[allow(unused_imports)]
use sp_core::ecdsa;
use sp_core::{H160, U256};
use sp_genesis_builder::PresetId;
use sp_std::prelude::*;

/// Generate a chain spec for use with the development service.
/// ARX: 1,000,000,000 total supply, 18 decimals (see `ARX_UNIT`).
pub fn development() -> serde_json::Value {
	testnet_genesis(
		// DEV ONLY. Well-known Alith test account. Public private key. Not for public networks.
		AccountId::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")),
		// Genesis accounts with real ARX allocations
		vec![
			// Treasury: 30% = 300M ARX
			(
				AccountId::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")),
				300_000_000 * ARX_UNIT,
			),
			// Mining Pool: 25% = 250M ARX
			(
				AccountId::from(hex!("3Cd0A705a2DC65e5b1E1205896BaA2be8A07c6e0")),
				250_000_000 * ARX_UNIT,
			),
			// Investors: 20% = 200M ARX
			(
				AccountId::from(hex!("798d4Ba9baf0064Ec19eB4F0a1a45785ae9D6DFc")),
				200_000_000 * ARX_UNIT,
			),
			// Team: 15% = 150M ARX
			(
				AccountId::from(hex!("773539d4Ac0e786233D90A233654ccEE26a613D9")),
				150_000_000 * ARX_UNIT,
			),
			// Staking: 10% = 100M ARX
			(
				AccountId::from(hex!("Ff64d3F6efE2317EE2807d223a0Bdc4c0c49dfDB")),
				100_000_000 * ARX_UNIT,
			),
		],
		vec![],
		ARXON_EVM_CHAIN_ID,
		false, // disable manual seal
	)
}

/// Configure initial storage state for FRAME modules.
fn testnet_genesis(
	sudo_key: AccountId,
	endowed_accounts: Vec<(AccountId, u128)>,
	_initial_authorities: Vec<(AuraId, GrandpaId)>,
	chain_id: u64,
	enable_manual_seal: bool,
) -> serde_json::Value {
	let evm_accounts = {
		let mut map = sp_std::collections::btree_map::BTreeMap::new();
		map.insert(
			// H160 address of Alice dev account
			// Derived from SS58 (42 prefix) address
			// SS58: 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
			// hex: 0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d
			// Using the full hex key, truncating to the first 20 bytes (the first 40 hex chars)
			H160::from(hex!("f24FF3a9CF04c71Dbc94D0b566f7A27B94566cac")),
			fp_evm::GenesisAccount {
				balance: U256::MAX,
				code: Default::default(),
				nonce: Default::default(),
				storage: Default::default(),
			},
		);
		map.insert(
			// H160 address of CI test runner account
			H160::from(hex!("6be02d1d3665660d22ff9624b7be0551ee1ac91b")),
			fp_evm::GenesisAccount {
				balance: U256::MAX,
				code: Default::default(),
				nonce: Default::default(),
				storage: Default::default(),
			},
		);
		map.insert(
			// H160 address for benchmark usage
			H160::from(hex!("1000000000000000000000000000000000000001")),
			fp_evm::GenesisAccount {
				nonce: U256::from(1),
				balance: U256::from(1_000_000_000_000_000_000_000_000u128),
				storage: Default::default(),
				code: vec![0x00],
			},
		);
		map
	};

	let config = RuntimeGenesisConfig {
		system: Default::default(),
		aura: Default::default(),
		base_fee: Default::default(),
		grandpa: Default::default(),
		balances: BalancesConfig {
			balances: endowed_accounts.iter().cloned().collect(),
			..Default::default()
		},
		ethereum: EthereumConfig {
			..Default::default()
		},
		evm: EVMConfig {
			accounts: evm_accounts.into_iter().collect(),
			..Default::default()
		},
		evm_chain_id: EVMChainIdConfig {
			chain_id,
			..Default::default()
		},
		manual_seal: ManualSealConfig {
			enable: enable_manual_seal,
			..Default::default()
		},
		sudo: SudoConfig {
			key: Some(sudo_key),
		},
		transaction_payment: Default::default(),
		// Every circuit registered with its frozen verifying key hash, enabled.
		zk_verifier: Default::default(),
	};

	serde_json::to_value(&config).expect("Could not build genesis config.")
}

/// Provides the JSON representation of predefined genesis config for given `id`.
pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
	let patch = match id.as_str() {
		sp_genesis_builder::DEV_RUNTIME_PRESET => development(),
		_ => return None,
	};
	Some(
		serde_json::to_string(&patch)
			.expect("serialization to json is expected to work. qed.")
			.into_bytes(),
	)
}
