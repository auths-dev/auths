//! Error code registry — **generated** by `cargo xtask gen-error-docs`.
//!
//! Do not edit manually. Re-run the generator after changing any `AuthsErrorInfo` impl:
//! ```sh
//! cargo xtask gen-error-docs
//! ```
//!
//! ## Range Allocation
//!
//! | Range   | Crate            | Layer |
//! |---------|------------------|-------|
//! | E0xxx   | Reserved/meta    | -     |
//! | E1xxx   | auths-crypto     | 0     |
//! | E2xxx   | auths-verifier   | 1     |
//! | E3xxx   | auths-core       | 2     |
//! | E4xxx   | auths-id         | 3     |
//! | E5xxx   | auths-sdk        | 3-4   |
//! | E6xxx   | auths-cli        | 6     |

/// Returns the explanation markdown for a given error code, or `None` if unknown.
///
/// Args:
/// * `code`: An error code string like `"AUTHS-E3001"`.
pub fn explain(code: &str) -> Option<&'static str> {
    match code {
        // --- auths-crypto (CryptoError) ---
        "AUTHS-E1001" => Some(include_str!("../../../../docs/errors/AUTHS-E1001.md")),
        "AUTHS-E1002" => Some(include_str!("../../../../docs/errors/AUTHS-E1002.md")),
        "AUTHS-E1003" => Some(include_str!("../../../../docs/errors/AUTHS-E1003.md")),
        "AUTHS-E1004" => Some(include_str!("../../../../docs/errors/AUTHS-E1004.md")),
        "AUTHS-E1005" => Some(include_str!("../../../../docs/errors/AUTHS-E1005.md")),

        // --- auths-crypto (DidKeyError) ---
        "AUTHS-E1101" => Some(include_str!("../../../../docs/errors/AUTHS-E1101.md")),
        "AUTHS-E1102" => Some(include_str!("../../../../docs/errors/AUTHS-E1102.md")),
        "AUTHS-E1103" => Some(include_str!("../../../../docs/errors/AUTHS-E1103.md")),
        "AUTHS-E1104" => Some(include_str!("../../../../docs/errors/AUTHS-E1104.md")),

        // --- auths-crypto (KeriDecodeError) ---
        "AUTHS-E1201" => Some(include_str!("../../../../docs/errors/AUTHS-E1201.md")),
        "AUTHS-E1202" => Some(include_str!("../../../../docs/errors/AUTHS-E1202.md")),
        "AUTHS-E1203" => Some(include_str!("../../../../docs/errors/AUTHS-E1203.md")),
        "AUTHS-E1204" => Some(include_str!("../../../../docs/errors/AUTHS-E1204.md")),

        // --- auths-crypto (SshKeyError) ---
        "AUTHS-E1301" => Some(include_str!("../../../../docs/errors/AUTHS-E1301.md")),
        "AUTHS-E1302" => Some(include_str!("../../../../docs/errors/AUTHS-E1302.md")),

        // --- auths-verifier (AttestationError) ---
        "AUTHS-E2001" => Some(include_str!("../../../../docs/errors/AUTHS-E2001.md")),
        "AUTHS-E2002" => Some(include_str!("../../../../docs/errors/AUTHS-E2002.md")),
        "AUTHS-E2003" => Some(include_str!("../../../../docs/errors/AUTHS-E2003.md")),
        "AUTHS-E2004" => Some(include_str!("../../../../docs/errors/AUTHS-E2004.md")),
        "AUTHS-E2005" => Some(include_str!("../../../../docs/errors/AUTHS-E2005.md")),
        "AUTHS-E2006" => Some(include_str!("../../../../docs/errors/AUTHS-E2006.md")),
        "AUTHS-E2007" => Some(include_str!("../../../../docs/errors/AUTHS-E2007.md")),
        "AUTHS-E2008" => Some(include_str!("../../../../docs/errors/AUTHS-E2008.md")),
        "AUTHS-E2009" => Some(include_str!("../../../../docs/errors/AUTHS-E2009.md")),
        "AUTHS-E2010" => Some(include_str!("../../../../docs/errors/AUTHS-E2010.md")),
        "AUTHS-E2011" => Some(include_str!("../../../../docs/errors/AUTHS-E2011.md")),
        "AUTHS-E2012" => Some(include_str!("../../../../docs/errors/AUTHS-E2012.md")),
        "AUTHS-E2013" => Some(include_str!("../../../../docs/errors/AUTHS-E2013.md")),
        "AUTHS-E2014" => Some(include_str!("../../../../docs/errors/AUTHS-E2014.md")),
        "AUTHS-E2015" => Some(include_str!("../../../../docs/errors/AUTHS-E2015.md")),
        "AUTHS-E2016" => Some(include_str!("../../../../docs/errors/AUTHS-E2016.md")),
        "AUTHS-E2017" => Some(include_str!("../../../../docs/errors/AUTHS-E2017.md")),
        "AUTHS-E2018" => Some(include_str!("../../../../docs/errors/AUTHS-E2018.md")),

        // --- auths-verifier (CommitVerificationError) ---
        "AUTHS-E2101" => Some(include_str!("../../../../docs/errors/AUTHS-E2101.md")),
        "AUTHS-E2102" => Some(include_str!("../../../../docs/errors/AUTHS-E2102.md")),
        "AUTHS-E2103" => Some(include_str!("../../../../docs/errors/AUTHS-E2103.md")),
        "AUTHS-E2104" => Some(include_str!("../../../../docs/errors/AUTHS-E2104.md")),
        "AUTHS-E2105" => Some(include_str!("../../../../docs/errors/AUTHS-E2105.md")),
        "AUTHS-E2106" => Some(include_str!("../../../../docs/errors/AUTHS-E2106.md")),
        "AUTHS-E2107" => Some(include_str!("../../../../docs/errors/AUTHS-E2107.md")),
        "AUTHS-E2108" => Some(include_str!("../../../../docs/errors/AUTHS-E2108.md")),
        "AUTHS-E2109" => Some(include_str!("../../../../docs/errors/AUTHS-E2109.md")),

        // --- auths-core (AgentError) ---
        "AUTHS-E3001" => Some(include_str!("../../../../docs/errors/AUTHS-E3001.md")),
        "AUTHS-E3002" => Some(include_str!("../../../../docs/errors/AUTHS-E3002.md")),
        "AUTHS-E3003" => Some(include_str!("../../../../docs/errors/AUTHS-E3003.md")),
        "AUTHS-E3004" => Some(include_str!("../../../../docs/errors/AUTHS-E3004.md")),
        "AUTHS-E3005" => Some(include_str!("../../../../docs/errors/AUTHS-E3005.md")),
        "AUTHS-E3006" => Some(include_str!("../../../../docs/errors/AUTHS-E3006.md")),
        "AUTHS-E3007" => Some(include_str!("../../../../docs/errors/AUTHS-E3007.md")),
        "AUTHS-E3008" => Some(include_str!("../../../../docs/errors/AUTHS-E3008.md")),
        "AUTHS-E3009" => Some(include_str!("../../../../docs/errors/AUTHS-E3009.md")),
        "AUTHS-E3010" => Some(include_str!("../../../../docs/errors/AUTHS-E3010.md")),
        "AUTHS-E3011" => Some(include_str!("../../../../docs/errors/AUTHS-E3011.md")),
        "AUTHS-E3012" => Some(include_str!("../../../../docs/errors/AUTHS-E3012.md")),
        "AUTHS-E3013" => Some(include_str!("../../../../docs/errors/AUTHS-E3013.md")),
        "AUTHS-E3014" => Some(include_str!("../../../../docs/errors/AUTHS-E3014.md")),
        "AUTHS-E3015" => Some(include_str!("../../../../docs/errors/AUTHS-E3015.md")),
        "AUTHS-E3016" => Some(include_str!("../../../../docs/errors/AUTHS-E3016.md")),
        "AUTHS-E3017" => Some(include_str!("../../../../docs/errors/AUTHS-E3017.md")),
        "AUTHS-E3018" => Some(include_str!("../../../../docs/errors/AUTHS-E3018.md")),
        "AUTHS-E3019" => Some(include_str!("../../../../docs/errors/AUTHS-E3019.md")),
        "AUTHS-E3020" => Some(include_str!("../../../../docs/errors/AUTHS-E3020.md")),
        "AUTHS-E3021" => Some(include_str!("../../../../docs/errors/AUTHS-E3021.md")),
        "AUTHS-E3022" => Some(include_str!("../../../../docs/errors/AUTHS-E3022.md")),
        "AUTHS-E3023" => Some(include_str!("../../../../docs/errors/AUTHS-E3023.md")),
        "AUTHS-E3024" => Some(include_str!("../../../../docs/errors/AUTHS-E3024.md")),

        // --- auths-core (TrustError) ---
        "AUTHS-E3101" => Some(include_str!("../../../../docs/errors/AUTHS-E3101.md")),
        "AUTHS-E3102" => Some(include_str!("../../../../docs/errors/AUTHS-E3102.md")),
        "AUTHS-E3103" => Some(include_str!("../../../../docs/errors/AUTHS-E3103.md")),
        "AUTHS-E3104" => Some(include_str!("../../../../docs/errors/AUTHS-E3104.md")),
        "AUTHS-E3105" => Some(include_str!("../../../../docs/errors/AUTHS-E3105.md")),
        "AUTHS-E3106" => Some(include_str!("../../../../docs/errors/AUTHS-E3106.md")),
        "AUTHS-E3107" => Some(include_str!("../../../../docs/errors/AUTHS-E3107.md")),

        // --- auths-core (PairingError) ---
        "AUTHS-E3201" => Some(include_str!("../../../../docs/errors/AUTHS-E3201.md")),
        "AUTHS-E3202" => Some(include_str!("../../../../docs/errors/AUTHS-E3202.md")),
        "AUTHS-E3203" => Some(include_str!("../../../../docs/errors/AUTHS-E3203.md")),
        "AUTHS-E3204" => Some(include_str!("../../../../docs/errors/AUTHS-E3204.md")),
        "AUTHS-E3205" => Some(include_str!("../../../../docs/errors/AUTHS-E3205.md")),
        "AUTHS-E3206" => Some(include_str!("../../../../docs/errors/AUTHS-E3206.md")),
        "AUTHS-E3207" => Some(include_str!("../../../../docs/errors/AUTHS-E3207.md")),

        // --- auths-core (CryptoError) ---
        "AUTHS-E3301" => Some(include_str!("../../../../docs/errors/AUTHS-E3301.md")),
        "AUTHS-E3302" => Some(include_str!("../../../../docs/errors/AUTHS-E3302.md")),
        "AUTHS-E3303" => Some(include_str!("../../../../docs/errors/AUTHS-E3303.md")),
        "AUTHS-E3304" => Some(include_str!("../../../../docs/errors/AUTHS-E3304.md")),
        "AUTHS-E3305" => Some(include_str!("../../../../docs/errors/AUTHS-E3305.md")),

        // --- auths-core (WitnessError) ---
        "AUTHS-E3401" => Some(include_str!("../../../../docs/errors/AUTHS-E3401.md")),
        "AUTHS-E3402" => Some(include_str!("../../../../docs/errors/AUTHS-E3402.md")),
        "AUTHS-E3403" => Some(include_str!("../../../../docs/errors/AUTHS-E3403.md")),
        "AUTHS-E3404" => Some(include_str!("../../../../docs/errors/AUTHS-E3404.md")),
        "AUTHS-E3405" => Some(include_str!("../../../../docs/errors/AUTHS-E3405.md")),
        "AUTHS-E3406" => Some(include_str!("../../../../docs/errors/AUTHS-E3406.md")),
        "AUTHS-E3407" => Some(include_str!("../../../../docs/errors/AUTHS-E3407.md")),
        "AUTHS-E3408" => Some(include_str!("../../../../docs/errors/AUTHS-E3408.md")),
        "AUTHS-E3409" => Some(include_str!("../../../../docs/errors/AUTHS-E3409.md")),

        // --- auths-core (StorageError) ---
        "AUTHS-E3501" => Some(include_str!("../../../../docs/errors/AUTHS-E3501.md")),
        "AUTHS-E3502" => Some(include_str!("../../../../docs/errors/AUTHS-E3502.md")),
        "AUTHS-E3503" => Some(include_str!("../../../../docs/errors/AUTHS-E3503.md")),
        "AUTHS-E3504" => Some(include_str!("../../../../docs/errors/AUTHS-E3504.md")),
        "AUTHS-E3505" => Some(include_str!("../../../../docs/errors/AUTHS-E3505.md")),

        // --- auths-core (NetworkError) ---
        "AUTHS-E3601" => Some(include_str!("../../../../docs/errors/AUTHS-E3601.md")),
        "AUTHS-E3602" => Some(include_str!("../../../../docs/errors/AUTHS-E3602.md")),
        "AUTHS-E3603" => Some(include_str!("../../../../docs/errors/AUTHS-E3603.md")),
        "AUTHS-E3604" => Some(include_str!("../../../../docs/errors/AUTHS-E3604.md")),
        "AUTHS-E3605" => Some(include_str!("../../../../docs/errors/AUTHS-E3605.md")),
        "AUTHS-E3606" => Some(include_str!("../../../../docs/errors/AUTHS-E3606.md")),

        // --- auths-core (ResolutionError) ---
        "AUTHS-E3701" => Some(include_str!("../../../../docs/errors/AUTHS-E3701.md")),
        "AUTHS-E3702" => Some(include_str!("../../../../docs/errors/AUTHS-E3702.md")),
        "AUTHS-E3703" => Some(include_str!("../../../../docs/errors/AUTHS-E3703.md")),
        "AUTHS-E3704" => Some(include_str!("../../../../docs/errors/AUTHS-E3704.md")),

        // --- auths-core (PlatformError) ---
        "AUTHS-E3801" => Some(include_str!("../../../../docs/errors/AUTHS-E3801.md")),
        "AUTHS-E3802" => Some(include_str!("../../../../docs/errors/AUTHS-E3802.md")),
        "AUTHS-E3803" => Some(include_str!("../../../../docs/errors/AUTHS-E3803.md")),
        "AUTHS-E3804" => Some(include_str!("../../../../docs/errors/AUTHS-E3804.md")),
        "AUTHS-E3805" => Some(include_str!("../../../../docs/errors/AUTHS-E3805.md")),
        "AUTHS-E3806" => Some(include_str!("../../../../docs/errors/AUTHS-E3806.md")),

        // --- auths-core (SshAgentError) ---
        "AUTHS-E3901" => Some(include_str!("../../../../docs/errors/AUTHS-E3901.md")),
        "AUTHS-E3902" => Some(include_str!("../../../../docs/errors/AUTHS-E3902.md")),
        "AUTHS-E3903" => Some(include_str!("../../../../docs/errors/AUTHS-E3903.md")),

        // --- auths-core (ConfigStoreError) ---
        "AUTHS-E3951" => Some(include_str!("../../../../docs/errors/AUTHS-E3951.md")),
        "AUTHS-E3952" => Some(include_str!("../../../../docs/errors/AUTHS-E3952.md")),

        // --- auths-id (FreezeError) ---
        "AUTHS-E4001" => Some(include_str!("../../../../docs/errors/AUTHS-E4001.md")),
        "AUTHS-E4002" => Some(include_str!("../../../../docs/errors/AUTHS-E4002.md")),
        "AUTHS-E4003" => Some(include_str!("../../../../docs/errors/AUTHS-E4003.md")),
        "AUTHS-E4004" => Some(include_str!("../../../../docs/errors/AUTHS-E4004.md")),

        // --- auths-id (StorageError) ---
        "AUTHS-E4101" => Some(include_str!("../../../../docs/errors/AUTHS-E4101.md")),
        "AUTHS-E4102" => Some(include_str!("../../../../docs/errors/AUTHS-E4102.md")),
        "AUTHS-E4103" => Some(include_str!("../../../../docs/errors/AUTHS-E4103.md")),
        "AUTHS-E4104" => Some(include_str!("../../../../docs/errors/AUTHS-E4104.md")),
        "AUTHS-E4105" => Some(include_str!("../../../../docs/errors/AUTHS-E4105.md")),
        "AUTHS-E4106" => Some(include_str!("../../../../docs/errors/AUTHS-E4106.md")),
        "AUTHS-E4107" => Some(include_str!("../../../../docs/errors/AUTHS-E4107.md")),

        // --- auths-id (InitError) ---
        "AUTHS-E4201" => Some(include_str!("../../../../docs/errors/AUTHS-E4201.md")),
        "AUTHS-E4202" => Some(include_str!("../../../../docs/errors/AUTHS-E4202.md")),
        "AUTHS-E4203" => Some(include_str!("../../../../docs/errors/AUTHS-E4203.md")),
        "AUTHS-E4204" => Some(include_str!("../../../../docs/errors/AUTHS-E4204.md")),
        "AUTHS-E4205" => Some(include_str!("../../../../docs/errors/AUTHS-E4205.md")),
        "AUTHS-E4206" => Some(include_str!("../../../../docs/errors/AUTHS-E4206.md")),
        "AUTHS-E4207" => Some(include_str!("../../../../docs/errors/AUTHS-E4207.md")),
        "AUTHS-E4208" => Some(include_str!("../../../../docs/errors/AUTHS-E4208.md")),

        // --- auths-id (AgentProvisioningError) ---
        "AUTHS-E4301" => Some(include_str!("../../../../docs/errors/AUTHS-E4301.md")),
        "AUTHS-E4302" => Some(include_str!("../../../../docs/errors/AUTHS-E4302.md")),
        "AUTHS-E4303" => Some(include_str!("../../../../docs/errors/AUTHS-E4303.md")),
        "AUTHS-E4304" => Some(include_str!("../../../../docs/errors/AUTHS-E4304.md")),
        "AUTHS-E4305" => Some(include_str!("../../../../docs/errors/AUTHS-E4305.md")),

        // --- auths-id (IdentityError) ---
        "AUTHS-E4401" => Some(include_str!("../../../../docs/errors/AUTHS-E4401.md")),
        "AUTHS-E4402" => Some(include_str!("../../../../docs/errors/AUTHS-E4402.md")),
        "AUTHS-E4403" => Some(include_str!("../../../../docs/errors/AUTHS-E4403.md")),
        "AUTHS-E4404" => Some(include_str!("../../../../docs/errors/AUTHS-E4404.md")),
        "AUTHS-E4405" => Some(include_str!("../../../../docs/errors/AUTHS-E4405.md")),
        "AUTHS-E4406" => Some(include_str!("../../../../docs/errors/AUTHS-E4406.md")),
        "AUTHS-E4407" => Some(include_str!("../../../../docs/errors/AUTHS-E4407.md")),
        "AUTHS-E4408" => Some(include_str!("../../../../docs/errors/AUTHS-E4408.md")),

        // --- auths-id (ValidationError) ---
        "AUTHS-E4501" => Some(include_str!("../../../../docs/errors/AUTHS-E4501.md")),
        "AUTHS-E4502" => Some(include_str!("../../../../docs/errors/AUTHS-E4502.md")),
        "AUTHS-E4503" => Some(include_str!("../../../../docs/errors/AUTHS-E4503.md")),
        "AUTHS-E4504" => Some(include_str!("../../../../docs/errors/AUTHS-E4504.md")),
        "AUTHS-E4505" => Some(include_str!("../../../../docs/errors/AUTHS-E4505.md")),
        "AUTHS-E4506" => Some(include_str!("../../../../docs/errors/AUTHS-E4506.md")),
        "AUTHS-E4507" => Some(include_str!("../../../../docs/errors/AUTHS-E4507.md")),
        "AUTHS-E4508" => Some(include_str!("../../../../docs/errors/AUTHS-E4508.md")),
        "AUTHS-E4509" => Some(include_str!("../../../../docs/errors/AUTHS-E4509.md")),
        "AUTHS-E4510" => Some(include_str!("../../../../docs/errors/AUTHS-E4510.md")),

        // --- auths-id (KelError) ---
        "AUTHS-E4601" => Some(include_str!("../../../../docs/errors/AUTHS-E4601.md")),
        "AUTHS-E4602" => Some(include_str!("../../../../docs/errors/AUTHS-E4602.md")),
        "AUTHS-E4603" => Some(include_str!("../../../../docs/errors/AUTHS-E4603.md")),
        "AUTHS-E4604" => Some(include_str!("../../../../docs/errors/AUTHS-E4604.md")),
        "AUTHS-E4605" => Some(include_str!("../../../../docs/errors/AUTHS-E4605.md")),
        "AUTHS-E4606" => Some(include_str!("../../../../docs/errors/AUTHS-E4606.md")),
        "AUTHS-E4607" => Some(include_str!("../../../../docs/errors/AUTHS-E4607.md")),

        // --- auths-id (RotationError) ---
        "AUTHS-E4701" => Some(include_str!("../../../../docs/errors/AUTHS-E4701.md")),
        "AUTHS-E4702" => Some(include_str!("../../../../docs/errors/AUTHS-E4702.md")),
        "AUTHS-E4703" => Some(include_str!("../../../../docs/errors/AUTHS-E4703.md")),
        "AUTHS-E4704" => Some(include_str!("../../../../docs/errors/AUTHS-E4704.md")),
        "AUTHS-E4705" => Some(include_str!("../../../../docs/errors/AUTHS-E4705.md")),
        "AUTHS-E4706" => Some(include_str!("../../../../docs/errors/AUTHS-E4706.md")),
        "AUTHS-E4707" => Some(include_str!("../../../../docs/errors/AUTHS-E4707.md")),
        "AUTHS-E4708" => Some(include_str!("../../../../docs/errors/AUTHS-E4708.md")),

        // --- auths-id (ResolveError) ---
        "AUTHS-E4801" => Some(include_str!("../../../../docs/errors/AUTHS-E4801.md")),
        "AUTHS-E4802" => Some(include_str!("../../../../docs/errors/AUTHS-E4802.md")),
        "AUTHS-E4803" => Some(include_str!("../../../../docs/errors/AUTHS-E4803.md")),
        "AUTHS-E4804" => Some(include_str!("../../../../docs/errors/AUTHS-E4804.md")),
        "AUTHS-E4805" => Some(include_str!("../../../../docs/errors/AUTHS-E4805.md")),
        "AUTHS-E4806" => Some(include_str!("../../../../docs/errors/AUTHS-E4806.md")),
        "AUTHS-E4807" => Some(include_str!("../../../../docs/errors/AUTHS-E4807.md")),

        // --- auths-id (TenantIdError) ---
        "AUTHS-E4851" => Some(include_str!("../../../../docs/errors/AUTHS-E4851.md")),
        "AUTHS-E4852" => Some(include_str!("../../../../docs/errors/AUTHS-E4852.md")),
        "AUTHS-E4853" => Some(include_str!("../../../../docs/errors/AUTHS-E4853.md")),

        // --- auths-id (RegistryError) ---
        "AUTHS-E4861" => Some(include_str!("../../../../docs/errors/AUTHS-E4861.md")),
        "AUTHS-E4862" => Some(include_str!("../../../../docs/errors/AUTHS-E4862.md")),
        "AUTHS-E4863" => Some(include_str!("../../../../docs/errors/AUTHS-E4863.md")),
        "AUTHS-E4864" => Some(include_str!("../../../../docs/errors/AUTHS-E4864.md")),
        "AUTHS-E4865" => Some(include_str!("../../../../docs/errors/AUTHS-E4865.md")),
        "AUTHS-E4866" => Some(include_str!("../../../../docs/errors/AUTHS-E4866.md")),
        "AUTHS-E4867" => Some(include_str!("../../../../docs/errors/AUTHS-E4867.md")),
        "AUTHS-E4868" => Some(include_str!("../../../../docs/errors/AUTHS-E4868.md")),
        "AUTHS-E4869" => Some(include_str!("../../../../docs/errors/AUTHS-E4869.md")),
        "AUTHS-E4870" => Some(include_str!("../../../../docs/errors/AUTHS-E4870.md")),
        "AUTHS-E4871" => Some(include_str!("../../../../docs/errors/AUTHS-E4871.md")),
        "AUTHS-E4872" => Some(include_str!("../../../../docs/errors/AUTHS-E4872.md")),
        "AUTHS-E4873" => Some(include_str!("../../../../docs/errors/AUTHS-E4873.md")),
        "AUTHS-E4874" => Some(include_str!("../../../../docs/errors/AUTHS-E4874.md")),
        "AUTHS-E4875" => Some(include_str!("../../../../docs/errors/AUTHS-E4875.md")),
        "AUTHS-E4876" => Some(include_str!("../../../../docs/errors/AUTHS-E4876.md")),
        "AUTHS-E4877" => Some(include_str!("../../../../docs/errors/AUTHS-E4877.md")),

        // --- auths-id (InceptionError) ---
        "AUTHS-E4901" => Some(include_str!("../../../../docs/errors/AUTHS-E4901.md")),
        "AUTHS-E4902" => Some(include_str!("../../../../docs/errors/AUTHS-E4902.md")),
        "AUTHS-E4903" => Some(include_str!("../../../../docs/errors/AUTHS-E4903.md")),
        "AUTHS-E4904" => Some(include_str!("../../../../docs/errors/AUTHS-E4904.md")),
        "AUTHS-E4905" => Some(include_str!("../../../../docs/errors/AUTHS-E4905.md")),

        // --- auths-id (IncrementalError) ---
        "AUTHS-E4951" => Some(include_str!("../../../../docs/errors/AUTHS-E4951.md")),
        "AUTHS-E4952" => Some(include_str!("../../../../docs/errors/AUTHS-E4952.md")),
        "AUTHS-E4953" => Some(include_str!("../../../../docs/errors/AUTHS-E4953.md")),
        "AUTHS-E4954" => Some(include_str!("../../../../docs/errors/AUTHS-E4954.md")),
        "AUTHS-E4955" => Some(include_str!("../../../../docs/errors/AUTHS-E4955.md")),
        "AUTHS-E4956" => Some(include_str!("../../../../docs/errors/AUTHS-E4956.md")),
        "AUTHS-E4957" => Some(include_str!("../../../../docs/errors/AUTHS-E4957.md")),

        // --- auths-id (AnchorError) ---
        "AUTHS-E4961" => Some(include_str!("../../../../docs/errors/AUTHS-E4961.md")),
        "AUTHS-E4962" => Some(include_str!("../../../../docs/errors/AUTHS-E4962.md")),
        "AUTHS-E4963" => Some(include_str!("../../../../docs/errors/AUTHS-E4963.md")),
        "AUTHS-E4964" => Some(include_str!("../../../../docs/errors/AUTHS-E4964.md")),
        "AUTHS-E4965" => Some(include_str!("../../../../docs/errors/AUTHS-E4965.md")),

        // --- auths-id (WitnessIntegrationError) ---
        "AUTHS-E4971" => Some(include_str!("../../../../docs/errors/AUTHS-E4971.md")),
        "AUTHS-E4972" => Some(include_str!("../../../../docs/errors/AUTHS-E4972.md")),
        "AUTHS-E4973" => Some(include_str!("../../../../docs/errors/AUTHS-E4973.md")),

        // --- auths-id (CacheError) ---
        "AUTHS-E4981" => Some(include_str!("../../../../docs/errors/AUTHS-E4981.md")),
        "AUTHS-E4982" => Some(include_str!("../../../../docs/errors/AUTHS-E4982.md")),

        // --- auths-id (HookError) ---
        "AUTHS-E4991" => Some(include_str!("../../../../docs/errors/AUTHS-E4991.md")),
        "AUTHS-E4992" => Some(include_str!("../../../../docs/errors/AUTHS-E4992.md")),

        // --- auths-sdk (SetupError) ---
        "AUTHS-E5001" => Some(include_str!("../../../../docs/errors/AUTHS-E5001.md")),
        "AUTHS-E5002" => Some(include_str!("../../../../docs/errors/AUTHS-E5002.md")),
        "AUTHS-E5003" => Some(include_str!("../../../../docs/errors/AUTHS-E5003.md")),
        "AUTHS-E5004" => Some(include_str!("../../../../docs/errors/AUTHS-E5004.md")),
        "AUTHS-E5005" => Some(include_str!("../../../../docs/errors/AUTHS-E5005.md")),
        "AUTHS-E5006" => Some(include_str!("../../../../docs/errors/AUTHS-E5006.md")),

        // --- auths-sdk (DeviceError) ---
        "AUTHS-E5101" => Some(include_str!("../../../../docs/errors/AUTHS-E5101.md")),
        "AUTHS-E5102" => Some(include_str!("../../../../docs/errors/AUTHS-E5102.md")),
        "AUTHS-E5103" => Some(include_str!("../../../../docs/errors/AUTHS-E5103.md")),
        "AUTHS-E5104" => Some(include_str!("../../../../docs/errors/AUTHS-E5104.md")),

        // --- auths-sdk (DeviceExtensionError) ---
        "AUTHS-E5201" => Some(include_str!("../../../../docs/errors/AUTHS-E5201.md")),
        "AUTHS-E5202" => Some(include_str!("../../../../docs/errors/AUTHS-E5202.md")),
        "AUTHS-E5203" => Some(include_str!("../../../../docs/errors/AUTHS-E5203.md")),
        "AUTHS-E5204" => Some(include_str!("../../../../docs/errors/AUTHS-E5204.md")),
        "AUTHS-E5205" => Some(include_str!("../../../../docs/errors/AUTHS-E5205.md")),

        // --- auths-sdk (RotationError) ---
        "AUTHS-E5301" => Some(include_str!("../../../../docs/errors/AUTHS-E5301.md")),
        "AUTHS-E5302" => Some(include_str!("../../../../docs/errors/AUTHS-E5302.md")),
        "AUTHS-E5303" => Some(include_str!("../../../../docs/errors/AUTHS-E5303.md")),
        "AUTHS-E5304" => Some(include_str!("../../../../docs/errors/AUTHS-E5304.md")),
        "AUTHS-E5305" => Some(include_str!("../../../../docs/errors/AUTHS-E5305.md")),
        "AUTHS-E5306" => Some(include_str!("../../../../docs/errors/AUTHS-E5306.md")),

        // --- auths-sdk (RegistrationError) ---
        "AUTHS-E5401" => Some(include_str!("../../../../docs/errors/AUTHS-E5401.md")),
        "AUTHS-E5402" => Some(include_str!("../../../../docs/errors/AUTHS-E5402.md")),
        "AUTHS-E5403" => Some(include_str!("../../../../docs/errors/AUTHS-E5403.md")),

        // --- auths-sdk (McpAuthError) ---
        "AUTHS-E5501" => Some(include_str!("../../../../docs/errors/AUTHS-E5501.md")),
        "AUTHS-E5502" => Some(include_str!("../../../../docs/errors/AUTHS-E5502.md")),
        "AUTHS-E5503" => Some(include_str!("../../../../docs/errors/AUTHS-E5503.md")),
        "AUTHS-E5504" => Some(include_str!("../../../../docs/errors/AUTHS-E5504.md")),

        // --- auths-sdk (OrgError) ---
        "AUTHS-E5601" => Some(include_str!("../../../../docs/errors/AUTHS-E5601.md")),
        "AUTHS-E5602" => Some(include_str!("../../../../docs/errors/AUTHS-E5602.md")),
        "AUTHS-E5603" => Some(include_str!("../../../../docs/errors/AUTHS-E5603.md")),
        "AUTHS-E5604" => Some(include_str!("../../../../docs/errors/AUTHS-E5604.md")),
        "AUTHS-E5605" => Some(include_str!("../../../../docs/errors/AUTHS-E5605.md")),
        "AUTHS-E5606" => Some(include_str!("../../../../docs/errors/AUTHS-E5606.md")),
        "AUTHS-E5607" => Some(include_str!("../../../../docs/errors/AUTHS-E5607.md")),
        "AUTHS-E5608" => Some(include_str!("../../../../docs/errors/AUTHS-E5608.md")),
        "AUTHS-E5609" => Some(include_str!("../../../../docs/errors/AUTHS-E5609.md")),
        "AUTHS-E5610" => Some(include_str!("../../../../docs/errors/AUTHS-E5610.md")),

        // --- auths-sdk (ApprovalError) ---
        "AUTHS-E5701" => Some(include_str!("../../../../docs/errors/AUTHS-E5701.md")),
        "AUTHS-E5702" => Some(include_str!("../../../../docs/errors/AUTHS-E5702.md")),
        "AUTHS-E5703" => Some(include_str!("../../../../docs/errors/AUTHS-E5703.md")),
        "AUTHS-E5704" => Some(include_str!("../../../../docs/errors/AUTHS-E5704.md")),
        "AUTHS-E5705" => Some(include_str!("../../../../docs/errors/AUTHS-E5705.md")),
        "AUTHS-E5706" => Some(include_str!("../../../../docs/errors/AUTHS-E5706.md")),

        // --- auths-sdk (AllowedSignersError) ---
        "AUTHS-E5801" => Some(include_str!("../../../../docs/errors/AUTHS-E5801.md")),
        "AUTHS-E5802" => Some(include_str!("../../../../docs/errors/AUTHS-E5802.md")),
        "AUTHS-E5803" => Some(include_str!("../../../../docs/errors/AUTHS-E5803.md")),
        "AUTHS-E5804" => Some(include_str!("../../../../docs/errors/AUTHS-E5804.md")),
        "AUTHS-E5805" => Some(include_str!("../../../../docs/errors/AUTHS-E5805.md")),
        "AUTHS-E5806" => Some(include_str!("../../../../docs/errors/AUTHS-E5806.md")),
        "AUTHS-E5807" => Some(include_str!("../../../../docs/errors/AUTHS-E5807.md")),
        "AUTHS-E5808" => Some(include_str!("../../../../docs/errors/AUTHS-E5808.md")),

        // --- auths-sdk (SigningError) ---
        "AUTHS-E5901" => Some(include_str!("../../../../docs/errors/AUTHS-E5901.md")),
        "AUTHS-E5902" => Some(include_str!("../../../../docs/errors/AUTHS-E5902.md")),
        "AUTHS-E5903" => Some(include_str!("../../../../docs/errors/AUTHS-E5903.md")),
        "AUTHS-E5904" => Some(include_str!("../../../../docs/errors/AUTHS-E5904.md")),
        "AUTHS-E5905" => Some(include_str!("../../../../docs/errors/AUTHS-E5905.md")),
        "AUTHS-E5906" => Some(include_str!("../../../../docs/errors/AUTHS-E5906.md")),
        "AUTHS-E5907" => Some(include_str!("../../../../docs/errors/AUTHS-E5907.md")),
        "AUTHS-E5908" => Some(include_str!("../../../../docs/errors/AUTHS-E5908.md")),
        "AUTHS-E5909" => Some(include_str!("../../../../docs/errors/AUTHS-E5909.md")),
        "AUTHS-E5910" => Some(include_str!("../../../../docs/errors/AUTHS-E5910.md")),

        _ => None,
    }
}

/// Returns a sorted slice of all registered error codes.
pub fn all_codes() -> &'static [&'static str] {
    static CODES: &[&str] = &[
        "AUTHS-E1001",
        "AUTHS-E1002",
        "AUTHS-E1003",
        "AUTHS-E1004",
        "AUTHS-E1005",
        "AUTHS-E1101",
        "AUTHS-E1102",
        "AUTHS-E1103",
        "AUTHS-E1104",
        "AUTHS-E1201",
        "AUTHS-E1202",
        "AUTHS-E1203",
        "AUTHS-E1204",
        "AUTHS-E1301",
        "AUTHS-E1302",
        "AUTHS-E2001",
        "AUTHS-E2002",
        "AUTHS-E2003",
        "AUTHS-E2004",
        "AUTHS-E2005",
        "AUTHS-E2006",
        "AUTHS-E2007",
        "AUTHS-E2008",
        "AUTHS-E2009",
        "AUTHS-E2010",
        "AUTHS-E2011",
        "AUTHS-E2012",
        "AUTHS-E2013",
        "AUTHS-E2014",
        "AUTHS-E2015",
        "AUTHS-E2016",
        "AUTHS-E2017",
        "AUTHS-E2018",
        "AUTHS-E2101",
        "AUTHS-E2102",
        "AUTHS-E2103",
        "AUTHS-E2104",
        "AUTHS-E2105",
        "AUTHS-E2106",
        "AUTHS-E2107",
        "AUTHS-E2108",
        "AUTHS-E2109",
        "AUTHS-E3001",
        "AUTHS-E3002",
        "AUTHS-E3003",
        "AUTHS-E3004",
        "AUTHS-E3005",
        "AUTHS-E3006",
        "AUTHS-E3007",
        "AUTHS-E3008",
        "AUTHS-E3009",
        "AUTHS-E3010",
        "AUTHS-E3011",
        "AUTHS-E3012",
        "AUTHS-E3013",
        "AUTHS-E3014",
        "AUTHS-E3015",
        "AUTHS-E3016",
        "AUTHS-E3017",
        "AUTHS-E3018",
        "AUTHS-E3019",
        "AUTHS-E3020",
        "AUTHS-E3021",
        "AUTHS-E3022",
        "AUTHS-E3023",
        "AUTHS-E3024",
        "AUTHS-E3101",
        "AUTHS-E3102",
        "AUTHS-E3103",
        "AUTHS-E3104",
        "AUTHS-E3105",
        "AUTHS-E3106",
        "AUTHS-E3107",
        "AUTHS-E3201",
        "AUTHS-E3202",
        "AUTHS-E3203",
        "AUTHS-E3204",
        "AUTHS-E3205",
        "AUTHS-E3206",
        "AUTHS-E3207",
        "AUTHS-E3301",
        "AUTHS-E3302",
        "AUTHS-E3303",
        "AUTHS-E3304",
        "AUTHS-E3305",
        "AUTHS-E3401",
        "AUTHS-E3402",
        "AUTHS-E3403",
        "AUTHS-E3404",
        "AUTHS-E3405",
        "AUTHS-E3406",
        "AUTHS-E3407",
        "AUTHS-E3408",
        "AUTHS-E3409",
        "AUTHS-E3501",
        "AUTHS-E3502",
        "AUTHS-E3503",
        "AUTHS-E3504",
        "AUTHS-E3505",
        "AUTHS-E3601",
        "AUTHS-E3602",
        "AUTHS-E3603",
        "AUTHS-E3604",
        "AUTHS-E3605",
        "AUTHS-E3606",
        "AUTHS-E3701",
        "AUTHS-E3702",
        "AUTHS-E3703",
        "AUTHS-E3704",
        "AUTHS-E3801",
        "AUTHS-E3802",
        "AUTHS-E3803",
        "AUTHS-E3804",
        "AUTHS-E3805",
        "AUTHS-E3806",
        "AUTHS-E3901",
        "AUTHS-E3902",
        "AUTHS-E3903",
        "AUTHS-E3951",
        "AUTHS-E3952",
        "AUTHS-E4001",
        "AUTHS-E4002",
        "AUTHS-E4003",
        "AUTHS-E4004",
        "AUTHS-E4101",
        "AUTHS-E4102",
        "AUTHS-E4103",
        "AUTHS-E4104",
        "AUTHS-E4105",
        "AUTHS-E4106",
        "AUTHS-E4107",
        "AUTHS-E4201",
        "AUTHS-E4202",
        "AUTHS-E4203",
        "AUTHS-E4204",
        "AUTHS-E4205",
        "AUTHS-E4206",
        "AUTHS-E4207",
        "AUTHS-E4208",
        "AUTHS-E4301",
        "AUTHS-E4302",
        "AUTHS-E4303",
        "AUTHS-E4304",
        "AUTHS-E4305",
        "AUTHS-E4401",
        "AUTHS-E4402",
        "AUTHS-E4403",
        "AUTHS-E4404",
        "AUTHS-E4405",
        "AUTHS-E4406",
        "AUTHS-E4407",
        "AUTHS-E4408",
        "AUTHS-E4501",
        "AUTHS-E4502",
        "AUTHS-E4503",
        "AUTHS-E4504",
        "AUTHS-E4505",
        "AUTHS-E4506",
        "AUTHS-E4507",
        "AUTHS-E4508",
        "AUTHS-E4509",
        "AUTHS-E4510",
        "AUTHS-E4601",
        "AUTHS-E4602",
        "AUTHS-E4603",
        "AUTHS-E4604",
        "AUTHS-E4605",
        "AUTHS-E4606",
        "AUTHS-E4607",
        "AUTHS-E4701",
        "AUTHS-E4702",
        "AUTHS-E4703",
        "AUTHS-E4704",
        "AUTHS-E4705",
        "AUTHS-E4706",
        "AUTHS-E4707",
        "AUTHS-E4708",
        "AUTHS-E4801",
        "AUTHS-E4802",
        "AUTHS-E4803",
        "AUTHS-E4804",
        "AUTHS-E4805",
        "AUTHS-E4806",
        "AUTHS-E4807",
        "AUTHS-E4851",
        "AUTHS-E4852",
        "AUTHS-E4853",
        "AUTHS-E4861",
        "AUTHS-E4862",
        "AUTHS-E4863",
        "AUTHS-E4864",
        "AUTHS-E4865",
        "AUTHS-E4866",
        "AUTHS-E4867",
        "AUTHS-E4868",
        "AUTHS-E4869",
        "AUTHS-E4870",
        "AUTHS-E4871",
        "AUTHS-E4872",
        "AUTHS-E4873",
        "AUTHS-E4874",
        "AUTHS-E4875",
        "AUTHS-E4876",
        "AUTHS-E4877",
        "AUTHS-E4901",
        "AUTHS-E4902",
        "AUTHS-E4903",
        "AUTHS-E4904",
        "AUTHS-E4905",
        "AUTHS-E4951",
        "AUTHS-E4952",
        "AUTHS-E4953",
        "AUTHS-E4954",
        "AUTHS-E4955",
        "AUTHS-E4956",
        "AUTHS-E4957",
        "AUTHS-E4961",
        "AUTHS-E4962",
        "AUTHS-E4963",
        "AUTHS-E4964",
        "AUTHS-E4965",
        "AUTHS-E4971",
        "AUTHS-E4972",
        "AUTHS-E4973",
        "AUTHS-E4981",
        "AUTHS-E4982",
        "AUTHS-E4991",
        "AUTHS-E4992",
        "AUTHS-E5001",
        "AUTHS-E5002",
        "AUTHS-E5003",
        "AUTHS-E5004",
        "AUTHS-E5005",
        "AUTHS-E5006",
        "AUTHS-E5101",
        "AUTHS-E5102",
        "AUTHS-E5103",
        "AUTHS-E5104",
        "AUTHS-E5201",
        "AUTHS-E5202",
        "AUTHS-E5203",
        "AUTHS-E5204",
        "AUTHS-E5205",
        "AUTHS-E5301",
        "AUTHS-E5302",
        "AUTHS-E5303",
        "AUTHS-E5304",
        "AUTHS-E5305",
        "AUTHS-E5306",
        "AUTHS-E5401",
        "AUTHS-E5402",
        "AUTHS-E5403",
        "AUTHS-E5501",
        "AUTHS-E5502",
        "AUTHS-E5503",
        "AUTHS-E5504",
        "AUTHS-E5601",
        "AUTHS-E5602",
        "AUTHS-E5603",
        "AUTHS-E5604",
        "AUTHS-E5605",
        "AUTHS-E5606",
        "AUTHS-E5607",
        "AUTHS-E5608",
        "AUTHS-E5609",
        "AUTHS-E5610",
        "AUTHS-E5701",
        "AUTHS-E5702",
        "AUTHS-E5703",
        "AUTHS-E5704",
        "AUTHS-E5705",
        "AUTHS-E5706",
        "AUTHS-E5801",
        "AUTHS-E5802",
        "AUTHS-E5803",
        "AUTHS-E5804",
        "AUTHS-E5805",
        "AUTHS-E5806",
        "AUTHS-E5807",
        "AUTHS-E5808",
        "AUTHS-E5901",
        "AUTHS-E5902",
        "AUTHS-E5903",
        "AUTHS-E5904",
        "AUTHS-E5905",
        "AUTHS-E5906",
        "AUTHS-E5907",
        "AUTHS-E5908",
        "AUTHS-E5909",
        "AUTHS-E5910",
    ];
    CODES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_returns_content_for_known_code() {
        assert!(explain("AUTHS-E1001").is_some());
    }

    #[test]
    fn explain_returns_none_for_unknown_code() {
        assert!(explain("AUTHS-E9999").is_none());
    }

    #[test]
    fn all_codes_is_sorted() {
        let codes = all_codes();
        assert!(!codes.is_empty());
        for window in codes.windows(2) {
            assert!(
                window[0] < window[1],
                "codes not sorted: {} >= {}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn all_codes_count_matches_registry() {
        assert_eq!(all_codes().len(), 290);
    }
}
