use core::marker::PhantomData;
use pallet_evm::{
	IsPrecompileResult, Precompile, PrecompileHandle, PrecompileResult, PrecompileSet,
};
use pallet_evm_precompile_arxon_zk::{
	ArxonArx20Precompile, ArxonZkPrecompile, ArxonZkSubmitPrecompile,
};
use sp_core::H160;

use pallet_evm_precompile_curve25519 as curve25519_precompile;
use pallet_evm_precompile_modexp::Modexp;
use pallet_evm_precompile_sha3fips::Sha3FIPS256;
use pallet_evm_precompile_simple::{ECRecover, ECRecoverPublicKey, Identity, Ripemd160, Sha256};

/// Arxon ZK precompile: view-only access to the Halo2 verifier, the nullifier set
/// and the shielded pool tree roots (`pallet-evm-precompile-arxon-zk`).
pub const ARXON_ZK_PRECOMPILE: u64 = pallet_evm_precompile_arxon_zk::ADDRESS;
/// Arxon ZK submission precompile: shield, unshield and private transfer.
pub const ARXON_ZK_SUBMIT_PRECOMPILE: u64 = pallet_evm_precompile_arxon_zk::SUBMIT_ADDRESS;
/// Arxon ARX-20 pool: per-token trees, never native ARX.
pub const ARXON_ARX20_PRECOMPILE: u64 = pallet_evm_precompile_arxon_zk::ARX20_ADDRESS;

/// Code stored at the Arxon precompile addresses: `PUSH1 0 PUSH1 0 REVERT`.
/// The EVM runs the precompile, never this code. It is there so `extcodesize`
/// is not zero: Solidity checks it before calling a method that returns
/// nothing, and would revert every such call (`0x801.setBalanceVisibility`,
/// `0x802.shield` from a token) at an address without code.
pub const PRECOMPILE_PLACEHOLDER_CODE: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xfd];

/// Addresses of the Arxon precompiles, which carry [`PRECOMPILE_PLACEHOLDER_CODE`].
pub fn arxon_precompile_addresses() -> [H160; 3] {
	[
		hash(ARXON_ZK_PRECOMPILE),
		hash(ARXON_ZK_SUBMIT_PRECOMPILE),
		hash(ARXON_ARX20_PRECOMPILE),
	]
}

pub struct FrontierPrecompiles<R>(PhantomData<R>);

impl<R> FrontierPrecompiles<R>
where
	R: pallet_evm::Config,
{
	pub fn new() -> Self {
		Self(Default::default())
	}
	pub fn used_addresses() -> [H160; 12] {
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
			hash(ARXON_ZK_SUBMIT_PRECOMPILE),
			hash(ARXON_ARX20_PRECOMPILE),
		]
	}
}
impl<R> PrecompileSet for FrontierPrecompiles<R>
where
	R: pallet_evm::Config
		+ frame_system::Config<AccountId = pallet_evm::AccountIdOf<R>>
		+ pallet_zk_verifier::Config
		+ pallet_nullifier_registry::Config
		+ pallet_note_tree::Config
		+ pallet_privacy::Config,
	R::RuntimeCall: sp_runtime::traits::Dispatchable<PostInfo = frame_support::dispatch::PostDispatchInfo>
		+ frame_support::dispatch::GetDispatchInfo
		+ From<pallet_privacy::Call<R>>,
	<R::RuntimeCall as sp_runtime::traits::Dispatchable>::RuntimeOrigin:
		From<frame_system::RawOrigin<pallet_evm::AccountIdOf<R>>>,
	pallet_privacy::BalanceOf<R>: TryFrom<u128>,
	frame_system::pallet_prelude::BlockNumberFor<R>: TryFrom<u128>,
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
			// Arxon ZK view (nullifiers, roots, verifier).
			a if a == hash(ARXON_ZK_PRECOMPILE) => Some(ArxonZkPrecompile::<R>::execute(handle)),
			// Arxon ZK submit (same pallet_privacy path as the native extrinsics).
			a if a == hash(ARXON_ZK_SUBMIT_PRECOMPILE) => {
				Some(ArxonZkSubmitPrecompile::<R>::execute(handle))
			}
			a if a == hash(ARXON_ARX20_PRECOMPILE) => {
				Some(ArxonArx20Precompile::<R>::execute(handle))
			}
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
