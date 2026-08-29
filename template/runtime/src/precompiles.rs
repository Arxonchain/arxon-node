use core::marker::PhantomData;
use fp_evm::{ExitRevert, PrecompileFailure};
use pallet_evm::{
	IsPrecompileResult, Precompile, PrecompileHandle, PrecompileResult, PrecompileSet,
};
use sp_core::H160;

use pallet_evm_precompile_curve25519 as curve25519_precompile;
use pallet_evm_precompile_modexp::Modexp;
use pallet_evm_precompile_sha3fips::Sha3FIPS256;
use pallet_evm_precompile_simple::{ECRecover, ECRecoverPublicKey, Identity, Ripemd160, Sha256};

/// Halo2 privacy verifier (Circuit 1+). Stub until ZK lands so nothing can deploy here.
pub const ARXON_ZK_PRECOMPILE: u64 = 0x800;

pub struct FrontierPrecompiles<R>(PhantomData<R>);

impl<R> FrontierPrecompiles<R>
where
	R: pallet_evm::Config,
{
	pub fn new() -> Self {
		Self(Default::default())
	}
	pub fn used_addresses() -> [H160; 10] {
		[
			hash(1),
			hash(2),
			hash(3),
			hash(4),
			hash(5),
			hash(1024),
			hash(1025),
			hash(1026),
			hash(1027),
			hash(ARXON_ZK_PRECOMPILE),
		]
	}
}
impl<R> PrecompileSet for FrontierPrecompiles<R>
where
	R: pallet_evm::Config + frame_system::Config,
{
	fn execute(&self, handle: &mut impl PrecompileHandle) -> Option<PrecompileResult> {
		match handle.code_address() {
			// Ethereum precompiles :
			a if a == hash(1) => Some(ECRecover::execute(handle)),
			a if a == hash(2) => Some(Sha256::execute(handle)),
			a if a == hash(3) => Some(Ripemd160::execute(handle)),
			a if a == hash(4) => Some(Identity::execute(handle)),
			a if a == hash(5) => Some(Modexp::execute(handle)),
			// Non-Frontier specific nor Ethereum precompiles :
			a if a == hash(1024) => Some(Sha3FIPS256::<
				R,
				crate::weights::pallet_evm_precompile_sha3fips::WeightInfo<R>,
			>::execute(handle)),
			a if a == hash(1025) => Some(ECRecoverPublicKey::execute(handle)),
			// Curve25519 precompiles
			a if a == hash(1026) => Some(curve25519_precompile::Curve25519Add::<
				R,
				crate::weights::pallet_evm_precompile_curve25519::WeightInfo<R>,
			>::execute(handle)),
			a if a == hash(1027) => Some(curve25519_precompile::Curve25519ScalarMul::<
				R,
				crate::weights::pallet_evm_precompile_curve25519::WeightInfo<R>,
			>::execute(handle)),
			a if a == hash(ARXON_ZK_PRECOMPILE) => Some(reserved_zk_precompile(handle)),
			_ => None,
		}
	}

	fn is_precompile(&self, address: H160, _gas: u64) -> IsPrecompileResult {
		IsPrecompileResult::Answer {
			is_precompile: Self::used_addresses().contains(&address),
			extra_cost: 0,
		}
	}
}

fn hash(a: u64) -> H160 {
	H160::from_low_u64_be(a)
}

fn reserved_zk_precompile(handle: &mut impl PrecompileHandle) -> PrecompileResult {
	handle.record_cost(100)?;
	Err(PrecompileFailure::Revert {
		exit_status: ExitRevert::Reverted,
		output: b"ARXON_ZK_PRECOMPILE_RESERVED".to_vec(),
	})
}
