#![cfg_attr(not(feature = "std"), no_std)]
pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    /// Trust tier levels
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum TrustTier {
        /// Bronze — 3 month minimum liquidity lock
        Bronze,
        /// Silver — 6 month minimum liquidity lock
        Silver,
        /// Gold — 12 month minimum liquidity lock
        Gold,
    }

    /// Registration status
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub enum RegistrationStatus {
        /// Active and verified
        Active,
        /// Under community alert
        UnderAlert,
        /// Revoked by governance
        Revoked,
    }

    /// A registered project entry
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub struct ProjectRegistration<AccountId, BlockNumber> {
        /// Project owner
        pub owner: AccountId,
        /// Project name (max 64 bytes)
        pub name: BoundedVec<u8, ConstU32<64>>,
        /// Trust tier chosen
        pub tier: TrustTier,
        /// Block when registration was submitted
        pub registered_at: BlockNumber,
        /// Block when liquidity lock expires
        pub lock_expires_at: BlockNumber,
        /// Lock duration in blocks chosen by project
        pub lock_duration_blocks: u32,
        /// Declared total token supply
        pub declared_supply: u128,
        /// Current status
        pub status: RegistrationStatus,
        /// Number of community alerts submitted
        pub alert_count: u32,
        /// Whether mint alerts are enabled
        pub mint_alerts_enabled: bool,
    }

    /// A community alert submitted against a project
    #[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub struct CommunityAlert<AccountId, BlockNumber> {
        /// Who submitted the alert
        pub submitted_by: AccountId,
        /// Block when alert was submitted
        pub submitted_at: BlockNumber,
        /// Short reason code (max 128 bytes)
        pub reason: BoundedVec<u8, ConstU32<128>>,
    }

    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// Minimum lock duration in blocks for Bronze (approx 3 months at 6s blocks)
        #[pallet::constant]
        type BronzeMinLockBlocks: Get<u32>;
        /// Minimum lock duration in blocks for Silver (approx 6 months)
        #[pallet::constant]
        type SilverMinLockBlocks: Get<u32>;
        /// Minimum lock duration in blocks for Gold (approx 12 months)
        #[pallet::constant]
        type GoldMinLockBlocks: Get<u32>;
        /// Number of community alerts before project is flagged automatically
        #[pallet::constant]
        type AlertThreshold: Get<u32>;
    }

    /// All registered projects by their contract address hash
    #[pallet::storage]
    pub type Projects<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, ProjectRegistration<T::AccountId, BlockNumberFor<T>>>;

    /// Community alerts per project
    #[pallet::storage]
    pub type Alerts<T: Config> = StorageDoubleMap<_, Blake2_128Concat, T::AccountId, Blake2_128Concat, T::AccountId, CommunityAlert<T::AccountId, BlockNumberFor<T>>>;

    /// Track which accounts have already alerted a project (one alert per account per project)
    #[pallet::storage]
    pub type HasAlerted<T: Config> = StorageDoubleMap<_, Blake2_128Concat, T::AccountId, Blake2_128Concat, T::AccountId, bool, ValueQuery>;

    /// Total registered projects
    #[pallet::storage]
    pub type TotalProjects<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Total community alerts ever submitted
    #[pallet::storage]
    pub type TotalAlerts<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A project registered and received a trust badge
        ProjectRegistered {
            project: T::AccountId,
            owner: T::AccountId,
            tier: TrustTier,
            lock_expires_at: BlockNumberFor<T>,
        },
        /// A project extended their liquidity lock
        LockExtended {
            project: T::AccountId,
            new_expires_at: BlockNumberFor<T>,
        },
        /// A project upgraded their trust tier
        TierUpgraded {
            project: T::AccountId,
            old_tier: TrustTier,
            new_tier: TrustTier,
        },
        /// A community alert was submitted
        AlertSubmitted {
            project: T::AccountId,
            submitted_by: T::AccountId,
            alert_count: u32,
        },
        /// Project automatically flagged due to alert threshold reached
        ProjectFlagged {
            project: T::AccountId,
            alert_count: u32,
        },
        /// A mint alert was triggered
        MintAlertTriggered {
            project: T::AccountId,
            amount_minted: u128,
            new_total: u128,
        },
        /// Project registration revoked by governance
        ProjectRevoked {
            project: T::AccountId,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Project already registered
        AlreadyRegistered,
        /// Project not found
        ProjectNotFound,
        /// Only project owner can perform this action
        NotProjectOwner,
        /// Lock duration below minimum for chosen tier
        LockTooShort,
        /// New lock must be longer than current lock
        LockNotExtended,
        /// New tier must be higher than current tier
        TierNotUpgraded,
        /// Already submitted an alert for this project
        AlreadyAlerted,
        /// Cannot alert your own project
        CannotAlertOwnProject,
        /// Project has been revoked
        ProjectRevoked,
        /// Arithmetic overflow
        Overflow,
    }


    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register a project and receive an Arxon Trust Badge.
        /// Voluntary — no project is forced to register.
        /// Registered projects display their tier badge on all Arxon infrastructure.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(20_000, 0))]
        pub fn register_project(
            origin: OriginFor<T>,
            project_id: T::AccountId,
            name: BoundedVec<u8, ConstU32<64>>,
            tier: TrustTier,
            lock_duration_blocks: u32,
            declared_supply: u128,
        ) -> DispatchResult {
            let owner = ensure_signed(origin)?;
            ensure!(!Projects::<T>::contains_key(&project_id), Error::<T>::AlreadyRegistered);

            // Enforce minimum lock duration per tier
            let min_lock = match tier {
                TrustTier::Bronze => T::BronzeMinLockBlocks::get(),
                TrustTier::Silver => T::SilverMinLockBlocks::get(),
                TrustTier::Gold => T::GoldMinLockBlocks::get(),
            };
            ensure!(lock_duration_blocks >= min_lock, Error::<T>::LockTooShort);

            let current_block = frame_system::Pallet::<T>::block_number();
            let lock_expires_at = current_block + lock_duration_blocks.into();

            let mint_alerts_enabled = matches!(tier, TrustTier::Silver | TrustTier::Gold);

            let registration = ProjectRegistration {
                owner: owner.clone(),
                name,
                tier: tier.clone(),
                registered_at: current_block,
                lock_expires_at,
                lock_duration_blocks,
                declared_supply,
                status: RegistrationStatus::Active,
                alert_count: 0,
                mint_alerts_enabled,
            };

            Projects::<T>::insert(&project_id, registration);

            let total = TotalProjects::<T>::get()
                .checked_add(1)
                .ok_or(Error::<T>::Overflow)?;
            TotalProjects::<T>::put(total);

            Self::deposit_event(Event::ProjectRegistered {
                project: project_id,
                owner,
                tier,
                lock_expires_at,
            });

            Ok(())
        }

        /// Extend the liquidity lock duration.
        /// Can only increase — never decrease. Shows long-term commitment.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn extend_lock(
            origin: OriginFor<T>,
            project_id: T::AccountId,
            new_lock_duration_blocks: u32,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let mut project = Projects::<T>::get(&project_id)
                .ok_or(Error::<T>::ProjectNotFound)?;
            ensure!(who == project.owner, Error::<T>::NotProjectOwner);
            ensure!(
                new_lock_duration_blocks > project.lock_duration_blocks,
                Error::<T>::LockNotExtended
            );

            let current_block = frame_system::Pallet::<T>::block_number();
            let new_expires_at = current_block + new_lock_duration_blocks.into();

            project.lock_duration_blocks = new_lock_duration_blocks;
            project.lock_expires_at = new_expires_at;
            Projects::<T>::insert(&project_id, &project);

            Self::deposit_event(Event::LockExtended {
                project: project_id,
                new_expires_at,
            });

            Ok(())
        }

        /// Upgrade to a higher trust tier.
        /// Can only go up — Bronze to Silver, Silver to Gold.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn upgrade_tier(
            origin: OriginFor<T>,
            project_id: T::AccountId,
            new_tier: TrustTier,
            new_lock_duration_blocks: u32,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let mut project = Projects::<T>::get(&project_id)
                .ok_or(Error::<T>::ProjectNotFound)?;
            ensure!(who == project.owner, Error::<T>::NotProjectOwner);

            // Verify upgrade direction
            let valid_upgrade = matches!(
                (&project.tier, &new_tier),
                (TrustTier::Bronze, TrustTier::Silver) |
                (TrustTier::Bronze, TrustTier::Gold) |
                (TrustTier::Silver, TrustTier::Gold)
            );
            ensure!(valid_upgrade, Error::<T>::TierNotUpgraded);

            // Enforce new tier minimum lock
            let min_lock = match new_tier {
                TrustTier::Bronze => T::BronzeMinLockBlocks::get(),
                TrustTier::Silver => T::SilverMinLockBlocks::get(),
                TrustTier::Gold => T::GoldMinLockBlocks::get(),
            };
            ensure!(new_lock_duration_blocks >= min_lock, Error::<T>::LockTooShort);

            let current_block = frame_system::Pallet::<T>::block_number();
            let old_tier = project.tier.clone();

            project.tier = new_tier.clone();
            project.lock_duration_blocks = new_lock_duration_blocks;
            project.lock_expires_at = current_block + new_lock_duration_blocks.into();
            project.mint_alerts_enabled = matches!(new_tier, TrustTier::Silver | TrustTier::Gold);
            Projects::<T>::insert(&project_id, &project);

            Self::deposit_event(Event::TierUpgraded {
                project: project_id,
                old_tier,
                new_tier,
            });

            Ok(())
        }

        /// Submit a community alert against a registered project.
        /// Each account can submit one alert per project.
        /// When alert threshold is reached project is automatically flagged.
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(15_000, 0))]
        pub fn submit_alert(
            origin: OriginFor<T>,
            project_id: T::AccountId,
            reason: BoundedVec<u8, ConstU32<128>>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let mut project = Projects::<T>::get(&project_id)
                .ok_or(Error::<T>::ProjectNotFound)?;
            ensure!(who != project.owner, Error::<T>::CannotAlertOwnProject);
            ensure!(!HasAlerted::<T>::get(&project_id, &who), Error::<T>::AlreadyAlerted);

            let current_block = frame_system::Pallet::<T>::block_number();

            let alert = CommunityAlert {
                submitted_by: who.clone(),
                submitted_at: current_block,
                reason,
            };

            Alerts::<T>::insert(&project_id, &who, alert);
            HasAlerted::<T>::insert(&project_id, &who, true);

            project.alert_count = project.alert_count.saturating_add(1);

            // Auto-flag if threshold reached
            if project.alert_count >= T::AlertThreshold::get() {
                project.status = RegistrationStatus::UnderAlert;
                Self::deposit_event(Event::ProjectFlagged {
                    project: project_id.clone(),
                    alert_count: project.alert_count,
                });
            }

            let alert_count = project.alert_count;
            Projects::<T>::insert(&project_id, &project);

            let total = TotalAlerts::<T>::get()
                .checked_add(1)
                .ok_or(Error::<T>::Overflow)?;
            TotalAlerts::<T>::put(total);

            Self::deposit_event(Event::AlertSubmitted {
                project: project_id,
                submitted_by: who,
                alert_count,
            });

            Ok(())
        }

        /// Trigger a mint alert for a Silver/Gold registered project.
        /// Called when tokens are minted beyond declared supply.
        #[pallet::call_index(4)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn trigger_mint_alert(
            origin: OriginFor<T>,
            project_id: T::AccountId,
            amount_minted: u128,
            new_total: u128,
        ) -> DispatchResult {
            ensure_root(origin)?;
            let project = Projects::<T>::get(&project_id)
                .ok_or(Error::<T>::ProjectNotFound)?;

            if project.mint_alerts_enabled {
                Self::deposit_event(Event::MintAlertTriggered {
                    project: project_id,
                    amount_minted,
                    new_total,
                });
            }

            Ok(())
        }

        /// Sudo: Revoke a project registration (governance action).
        #[pallet::call_index(5)]
        #[pallet::weight(Weight::from_parts(10_000, 0))]
        pub fn revoke_project(
            origin: OriginFor<T>,
            project_id: T::AccountId,
        ) -> DispatchResult {
            ensure_root(origin)?;
            let mut project = Projects::<T>::get(&project_id)
                .ok_or(Error::<T>::ProjectNotFound)?;
            project.status = RegistrationStatus::Revoked;
            Projects::<T>::insert(&project_id, &project);
            Self::deposit_event(Event::ProjectRevoked { project: project_id });
            Ok(())
        }
    }
}
