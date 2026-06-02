use crate::enumerable::query_all_address_map;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    attr, to_json_binary, Addr, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env,
    MessageInfo, Response, StdResult, Uint128,
};
use cw2::{get_contract_version, set_contract_version};
use cw_utils::{Expiration, Scheduled};
use sha2::Digest;
use sha3::Keccak256;

use crate::error::ContractError;
use crate::ethereum::{ethereum_address, get_recovery_param};
use crate::msg::{
    AccountMapResponse, ConfigResponse, ExecuteMsg, InstantiateMsg, IsClaimedResponse,
    IsPausedResponse, LatestStageResponse, MerkleRootResponse, MigrateMsg, QueryMsg, SignatureInfo,
    TotalClaimedResponse,
};
use crate::state::{
    Config, CLAIM, CONFIG, LATEST_STAGE, MERKLE_ROOT, STAGE_ACCOUNT_MAP, STAGE_AMOUNT,
    STAGE_AMOUNT_CLAIMED, STAGE_EXPIRATION, STAGE_NATIVE_TOKEN, STAGE_PAUSED, STAGE_START,
};

// Version info, for migration info
const CONTRACT_NAME: &str = "crates.io:cw20-merkle-airdrop";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_PROOF_LENGTH: usize = 64;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let owner = msg
        .owner
        .map_or(Ok(info.sender), |o| deps.api.addr_validate(&o))?;

    let stage = 0;
    LATEST_STAGE.save(deps.storage, &stage)?;

    make_config(deps, Some(owner))?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    let ver = get_contract_version(deps.storage)?;
    if ver.contract != CONTRACT_NAME {
        return Err(ContractError::CannotMigrate {
            previous_contract: ver.contract,
        });
    }
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::UpdateConfig { new_owner } => execute_update_config(deps, env, info, new_owner),
        ExecuteMsg::RegisterMerkleRoot {
            merkle_root,
            expiration,
            start,
            total_amount,
            native_token,
        } => execute_register_merkle_root(
            deps,
            env,
            info,
            merkle_root,
            expiration,
            start,
            total_amount,
            native_token,
        ),
        ExecuteMsg::Claim {
            stage,
            amount,
            proof,
            sig_info,
        } => execute_claim(deps, env, info, stage, amount, proof, sig_info),
        ExecuteMsg::Pause { stage } => execute_pause(deps, env, info, stage),
        ExecuteMsg::Resume {
            stage,
            new_expiration,
        } => execute_resume(deps, env, info, stage, new_expiration),
        ExecuteMsg::WithdrawAll { denom } => execute_withdraw_all(deps, env, info, denom),
    }
}

pub fn make_config(deps: DepsMut, owner: Option<Addr>) -> Result<Response, ContractError> {
    let config = Config { owner };
    CONFIG.save(deps.storage, &config)?;
    Ok(Response::default())
}

pub fn execute_update_config(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    new_owner: Option<String>,
) -> Result<Response, ContractError> {
    // authorize owner
    let cfg = CONFIG.load(deps.storage)?;
    let owner = cfg.owner.ok_or(ContractError::Unauthorized {})?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    // if owner some validated to addr, otherwise set to none
    let mut tmp_owner = None;
    if let Some(addr) = new_owner {
        tmp_owner = Some(deps.api.addr_validate(&addr)?)
    }

    make_config(deps, tmp_owner)?;

    Ok(Response::new().add_attribute("action", "update_config"))
}

#[allow(clippy::too_many_arguments)]
pub fn execute_register_merkle_root(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    merkle_root: String,
    expiration: Option<Expiration>,
    start: Option<Scheduled>,
    total_amount: Option<Uint128>,
    native_token: String,
) -> Result<Response, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;

    // if owner set validate, otherwise unauthorized
    let owner = cfg.owner.ok_or(ContractError::Unauthorized {})?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    // check merkle root length
    let mut root_buf: [u8; 32] = [0; 32];
    hex::decode_to_slice(&merkle_root, &mut root_buf)?;

    let stage = LATEST_STAGE.update(deps.storage, |stage| -> Result<_, ContractError> {
        stage
            .checked_add(1)
            .ok_or(ContractError::StageLimitReached {})
    })?;

    MERKLE_ROOT.save(deps.storage, stage, &root_buf)?;
    LATEST_STAGE.save(deps.storage, &stage)?;

    // save expiration
    let exp = expiration.unwrap_or(Expiration::Never {});
    STAGE_EXPIRATION.save(deps.storage, stage, &exp)?;

    // save start
    if let Some(start) = start {
        STAGE_START.save(deps.storage, stage, &start)?;
    }

    STAGE_PAUSED.save(deps.storage, stage, &false)?;

    // save total airdropped amount
    let amount = total_amount.unwrap_or_else(Uint128::zero);
    STAGE_AMOUNT.save(deps.storage, stage, &amount)?;
    STAGE_AMOUNT_CLAIMED.save(deps.storage, stage, &Uint128::zero())?;

    STAGE_NATIVE_TOKEN.save(deps.storage, stage, &native_token)?;

    Ok(Response::new().add_attributes(vec![
        attr("action", "register_merkle_root"),
        attr("stage", stage.to_string()),
        attr("merkle_root", merkle_root),
        attr("total_amount", amount),
        attr("native_token", native_token),
    ]))
}

pub fn execute_claim(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    stage: u8,
    amount: Uint128,
    proof: Vec<String>,
    sig_info: Option<SignatureInfo>,
) -> Result<Response, ContractError> {
    if proof.len() > MAX_PROOF_LENGTH {
        return Err(ContractError::ProofTooLong {
            max: MAX_PROOF_LENGTH,
        });
    }

    // airdrop begun
    let start = STAGE_START.may_load(deps.storage, stage)?;
    if let Some(start) = start {
        if !start.is_triggered(&env.block) {
            return Err(ContractError::StageNotBegun { stage, start });
        }
    }
    // not expired
    let expiration = STAGE_EXPIRATION.load(deps.storage, stage)?;
    if expiration.is_expired(&env.block) {
        return Err(ContractError::StageExpired { stage, expiration });
    }

    let is_paused = STAGE_PAUSED.load(deps.storage, stage)?;
    if is_paused {
        return Err(ContractError::StagePaused { stage });
    }

    // if present verify signature and extract external address or use info.sender as proof
    // if signature is not present in the message, verification will fail since info.sender is not present in the merkle root
    let (proof_addr, external_account_map) = match sig_info {
        None => (info.sender.to_string(), None),
        Some(sig) => {
            // verify signature
            if sig.signature.len() != 65 {
                return Err(ContractError::InvalidSignature {});
            }

            let msg_str = String::from_utf8(sig.claim_msg.to_vec())
                .map_err(|_| ContractError::InvalidInput {})?;
            // Hashing
            let mut hasher = Keccak256::new();
            hasher.update(format!("\x19Ethereum Signed Message:\n{}", msg_str.len()));
            hasher.update(msg_str);
            let hash = hasher.finalize();

            // Decompose signature
            let (v, rs) = sig
                .signature
                .as_slice()
                .split_last()
                .ok_or(ContractError::InvalidSignature {})?;
            let recovery = get_recovery_param(*v)?;

            // Verification
            let calculated_pubkey = deps.api.secp256k1_recover_pubkey(&hash, rs, recovery)?;
            let result = deps.api.secp256k1_verify(&hash, rs, &calculated_pubkey);
            let valid_signature = result.unwrap_or_default();

            if !valid_signature {
                return Err(ContractError::InvalidSignature {});
            }

            let proof_addr = ethereum_address(&calculated_pubkey)?;

            let signed_addr = deps.api.addr_validate(&sig.extract_addr()?)?;
            if signed_addr != info.sender {
                return Err(ContractError::InvalidSignature {});
            }

            (proof_addr, Some(info.sender.to_string()))
        }
    };

    // verify not claimed
    let claimed = CLAIM.may_load(deps.storage, (proof_addr.clone(), stage))?;
    if claimed.is_some() {
        return Err(ContractError::Claimed {});
    }

    // verify merkle root
    let merkle_root = MERKLE_ROOT.load(deps.storage, stage)?;

    let user_input = format!("{}{}", proof_addr, amount);
    let hash: [u8; 32] = sha2::Sha256::digest(user_input.as_bytes()).into();

    let hash = proof.into_iter().try_fold(hash, |hash, p| {
        let mut proof_buf = [0; 32];
        hex::decode_to_slice(p, &mut proof_buf)?;
        let mut hashes = [hash, proof_buf];
        hashes.sort_unstable();
        Ok::<[u8; 32], ContractError>(sha2::Sha256::digest(hashes.concat()).into())
    })?;

    if merkle_root != hash {
        return Err(ContractError::VerificationFailed {});
    }

    // Update total claimed to reflect
    let claimed_amount = STAGE_AMOUNT_CLAIMED
        .load(deps.storage, stage)?
        .checked_add(amount)
        .map_err(|_| ContractError::ClaimAmountOverflow {})?;

    let native_token = STAGE_NATIVE_TOKEN.load(deps.storage, stage)?;
    let balance = deps
        .querier
        .query_balance(env.contract.address, native_token.clone())?;
    if balance.amount < amount {
        return Err(ContractError::InsufficientFunds {
            balance: balance.amount,
            amount,
        });
    }

    // Update claim/account indexes only after all fallible validation has passed.
    STAGE_AMOUNT_CLAIMED.save(deps.storage, stage, &claimed_amount)?;
    CLAIM.save(deps.storage, (proof_addr.clone(), stage), &true)?;
    if let Some(host_address) = external_account_map {
        STAGE_ACCOUNT_MAP.save(deps.storage, (stage, proof_addr), &host_address)?;
    }

    let message: CosmosMsg = CosmosMsg::Bank(BankMsg::Send {
        to_address: info.sender.to_string(),
        amount: vec![Coin {
            denom: native_token,
            amount,
        }],
    });
    let res = Response::new().add_message(message).add_attributes(vec![
        attr("action", "claim"),
        attr("stage", stage.to_string()),
        attr("address", info.sender.to_string()),
        attr("amount", amount),
    ]);
    Ok(res)
}

pub fn execute_pause(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    stage: u8,
) -> Result<Response, ContractError> {
    // authorize owner
    let cfg = CONFIG.load(deps.storage)?;
    let owner = cfg.owner.ok_or(ContractError::Unauthorized {})?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    let start = STAGE_START.may_load(deps.storage, stage)?;
    if let Some(start) = start {
        if !start.is_triggered(&env.block) {
            return Err(ContractError::StageNotBegun { stage, start });
        }
    }

    let expiration = STAGE_EXPIRATION.load(deps.storage, stage)?;
    if expiration.is_expired(&env.block) {
        return Err(ContractError::StageExpired { stage, expiration });
    }

    STAGE_PAUSED.save(deps.storage, stage, &true)?;
    Ok(Response::new().add_attributes(vec![attr("action", "pause"), attr("stage_paused", "true")]))
}

pub fn execute_resume(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    stage: u8,
    new_expiration: Option<Expiration>,
) -> Result<Response, ContractError> {
    // authorize owner
    let cfg = CONFIG.load(deps.storage)?;
    let owner = cfg.owner.ok_or(ContractError::Unauthorized {})?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    let start = STAGE_START.may_load(deps.storage, stage)?;
    if let Some(start) = start {
        if !start.is_triggered(&env.block) {
            return Err(ContractError::StageNotBegun { stage, start });
        }
    }

    let expiration = STAGE_EXPIRATION.load(deps.storage, stage)?;
    if expiration.is_expired(&env.block) {
        return Err(ContractError::StageExpired { stage, expiration });
    }

    let is_paused = STAGE_PAUSED.load(deps.storage, stage)?;
    if !is_paused {
        return Err(ContractError::StageNotPaused { stage });
    }

    if let Some(new_expiration) = new_expiration {
        if new_expiration.is_expired(&env.block) {
            return Err(ContractError::StageExpired { stage, expiration });
        }
        STAGE_EXPIRATION.save(deps.storage, stage, &new_expiration)?;
    }

    STAGE_PAUSED.save(deps.storage, stage, &false)?;
    Ok(Response::new().add_attributes(vec![
        attr("action", "resume"),
        attr("stage_paused", "false"),
    ]))
}

pub fn execute_withdraw_all(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    denom: String,
) -> Result<Response, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;
    let owner = cfg.owner.ok_or(ContractError::Unauthorized {})?;
    if info.sender != owner {
        return Err(ContractError::Unauthorized {});
    }

    let balance = deps
        .querier
        .query_balance(env.contract.address, denom.clone())?;

    let message: CosmosMsg = CosmosMsg::Bank(BankMsg::Send {
        to_address: owner.to_string(),
        amount: vec![Coin {
            denom,
            amount: balance.amount,
        }],
    });

    Ok(Response::new()
        .add_message(message)
        .add_attributes(vec![
            attr("action", "withdraw_all"),
            attr("recipient", owner),
            attr("amount", balance.amount),
        ]))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_json_binary(&query_config(deps)?),
        QueryMsg::MerkleRoot { stage } => to_json_binary(&query_merkle_root(deps, stage)?),
        QueryMsg::LatestStage {} => to_json_binary(&query_latest_stage(deps)?),
        QueryMsg::IsClaimed { stage, address } => {
            to_json_binary(&query_is_claimed(deps, stage, address)?)
        }
        QueryMsg::IsPaused { stage } => to_json_binary(&query_is_paused(deps, stage)?),
        QueryMsg::TotalClaimed { stage } => to_json_binary(&query_total_claimed(deps, stage)?),
        QueryMsg::AccountMap {
            stage,
            external_address,
        } => to_json_binary(&query_address_map(deps, stage, external_address)?),
        QueryMsg::AllAccountMaps {
            stage,
            start_after,
            limit,
        } => to_json_binary(&query_all_address_map(deps, stage, start_after, limit)?),
    }
}

pub fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let cfg = CONFIG.load(deps.storage)?;
    Ok(ConfigResponse {
        owner: cfg.owner.map(|o| o.to_string()),
    })
}

pub fn query_merkle_root(deps: Deps, stage: u8) -> StdResult<MerkleRootResponse> {
    let merkle_root = MERKLE_ROOT.load(deps.storage, stage)?;
    let expiration = STAGE_EXPIRATION.load(deps.storage, stage)?;
    let start = STAGE_START.may_load(deps.storage, stage)?;
    let total_amount = STAGE_AMOUNT.load(deps.storage, stage)?;
    let native_token = STAGE_NATIVE_TOKEN.load(deps.storage, stage)?;

    let resp = MerkleRootResponse {
        stage,
        merkle_root: hex::encode(merkle_root),
        expiration,
        start,
        total_amount,
        native_token,
    };

    Ok(resp)
}

pub fn query_latest_stage(deps: Deps) -> StdResult<LatestStageResponse> {
    let latest_stage = LATEST_STAGE.load(deps.storage)?;
    let resp = LatestStageResponse { latest_stage };

    Ok(resp)
}

pub fn query_is_claimed(deps: Deps, stage: u8, address: String) -> StdResult<IsClaimedResponse> {
    let is_claimed = CLAIM
        .may_load(deps.storage, (address, stage))?
        .unwrap_or(false);
    let resp = IsClaimedResponse { is_claimed };

    Ok(resp)
}

pub fn query_is_paused(deps: Deps, stage: u8) -> StdResult<IsPausedResponse> {
    let is_paused = STAGE_PAUSED.may_load(deps.storage, stage)?.unwrap_or(false);
    let resp = IsPausedResponse { is_paused };

    Ok(resp)
}

pub fn query_total_claimed(deps: Deps, stage: u8) -> StdResult<TotalClaimedResponse> {
    let total_claimed = STAGE_AMOUNT_CLAIMED.load(deps.storage, stage)?;
    let resp = TotalClaimedResponse { total_claimed };

    Ok(resp)
}

pub fn query_address_map(
    deps: Deps,
    stage: u8,
    external_address: String,
) -> StdResult<AccountMapResponse> {
    let host_address = STAGE_ACCOUNT_MAP.load(deps.storage, (stage, external_address.clone()))?;
    let resp = AccountMapResponse {
        host_address,
        external_address,
    };

    Ok(resp)
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::marker::PhantomData;
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::testing::{
        MOCK_CONTRACT_ADDR, MockApi, MockQuerier, MockStorage, message_info, mock_dependencies, mock_env,
    };

    use cosmwasm_std::{from_json, CosmosMsg, Coin, OwnedDeps, SubMsg};
    use serde::{Deserialize, Serialize};

    use crate::contract::{execute, instantiate, query};
    use crate::msg::{ExecuteMsg, InstantiateMsg};

    fn mock_dependencies_with_balance(
        contract_balance: &[Coin],
    ) -> OwnedDeps<MockStorage, MockApi, MockQuerier> {

        let balances = [(MOCK_CONTRACT_ADDR, contract_balance)];
        OwnedDeps {
            storage: MockStorage::default(),
            api: MockApi::default().with_prefix("wasm"),
            querier: MockQuerier::new(&balances),
            custom_query_type: PhantomData,
        }
    }

    #[test]
    fn proper_instantiation_native() {
        let mut deps = mock_dependencies();

        let owner = deps.api.addr_make("owner0000");
        let msg = InstantiateMsg {
            owner: Some(owner.to_string()),
        };

        let env = mock_env();
        let sender = deps.api.addr_make("owner0000");
        let info = message_info(&sender, &[]);

        // we can just call .unwrap() to assert this was a success
        let _res = instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();

        // it worked, let's query the state
        let res = query(deps.as_ref(), env.clone(), QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_json(&res).unwrap();
        assert_eq!(owner.to_string(), config.owner.unwrap().as_str());

        let res = query(deps.as_ref(), env, QueryMsg::LatestStage {}).unwrap();
        let latest_stage: LatestStageResponse = from_json(&res).unwrap();
        assert_eq!(0u8, latest_stage.latest_stage);
    }

    #[test]
    fn update_config() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            owner: None,
        };

        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        // update owner
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let new_owner = deps.api.addr_make("owner0001");
        let msg = ExecuteMsg::UpdateConfig {
            new_owner: Some(new_owner.to_string()),
        };

        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.as_ref(), env, QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_json(&res).unwrap();
        assert_eq!(new_owner.to_string(), config.owner.unwrap().as_str());

        // Unauthorized err
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_owner: None,
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::Unauthorized {});

        // freeze contract (owner set to None)
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0001"), &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_owner: None,
        };

        let _res = execute(deps.as_mut(), env.clone(), info, msg).ok();

        let query_result = query(deps.as_ref(), env, QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_json(&query_result).unwrap();
        assert_eq!(None, config.owner);
    }

    #[test]
    fn register_merkle_root() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            owner: Some(deps.api.addr_make("owner0000").to_string()),
        };

        let env = mock_env();
        let info = message_info(&deps.api.addr_make("addr0000"), &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        // register new merkle root
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37"
                .to_string(),
            expiration: None,
            start: None,
            total_amount: None,
            native_token: "ujunox".to_string(),
        };

        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "register_merkle_root"),
                attr("stage", "1"),
                attr(
                    "merkle_root",
                    "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37",
                ),
                attr("total_amount", "0"),
                attr("native_token", "ujunox"),
            ]
        );

        let res = query(deps.as_ref(), env.clone(), QueryMsg::LatestStage {}).unwrap();
        let latest_stage: LatestStageResponse = from_json(&res).unwrap();
        assert_eq!(1u8, latest_stage.latest_stage);

        let res = query(
            deps.as_ref(),
            env,
            QueryMsg::MerkleRoot {
                stage: latest_stage.latest_stage,
            },
        )
        .unwrap();
        let merkle_root: MerkleRootResponse = from_json(&res).unwrap();
        assert_eq!(
            "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37".to_string(),
            merkle_root.merkle_root
        );
    }

    const TEST_DATA_1: &[u8] = include_bytes!("../testdata/airdrop_stage_1_test_data.json");
    const TEST_DATA_2: &[u8] = include_bytes!("../testdata/airdrop_stage_2_test_data.json");

    #[cw_serde]
    struct Encoded {
        account: String,
        amount: Uint128,
        root: String,
        proofs: Vec<String>,
        signed_msg: Option<SignatureInfo>,
    }

    #[test]
    fn claim_native() {
        // Run test 1
        let mut deps = mock_dependencies_with_balance(&[Coin {
            denom: "ujunox".to_string(),
            amount: Uint128::new(1234567),
        }]);
        let test_data: Encoded = from_json(TEST_DATA_1).unwrap();

        let msg = InstantiateMsg {
            owner: Some(deps.api.addr_make("owner0000").to_string()),
        };

        let env = mock_env();
        let info = message_info(&deps.api.addr_make("addr0000"), &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data.root,
            expiration: None,
            start: None,
            total_amount: None,
            native_token: "ujunox".to_string(),
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        let account = test_data.account;
        let msg = ExecuteMsg::Claim {
            amount: test_data.amount,
            stage: 1u8,
            proof: test_data.proofs,
            sig_info: None,
        };

        let env = mock_env();
        let info = message_info(&Addr::unchecked(account.clone()), &[]);
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
        let expected = SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
            to_address: account.clone(),
            amount: vec![Coin {
                denom: "ujunox".to_string(),
                amount: test_data.amount,
            }],
        }));
        assert_eq!(res.messages, vec![expected]);

        assert_eq!(
            res.attributes,
            vec![
                attr("action", "claim"),
                attr("stage", "1"),
                attr("address", account.clone()),
                attr("amount", test_data.amount),
            ]
        );

        // Check total claimed on stage 1
        assert_eq!(
            from_json::<TotalClaimedResponse>(
                &query(
                    deps.as_ref(),
                    env.clone(),
                    QueryMsg::TotalClaimed { stage: 1 },
                )
                .unwrap()
            )
            .unwrap()
            .total_claimed,
            test_data.amount
        );

        // Check address is claimed
        assert!(
            from_json::<IsClaimedResponse>(
                &query(
                    deps.as_ref(),
                    env.clone(),
                    QueryMsg::IsClaimed {
                        stage: 1,
                        address: account,
                    },
                )
                .unwrap()
            )
            .unwrap()
            .is_claimed
        );

        // check error on double claim
        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::Claimed {});

        // Second test
        let test_data: Encoded = from_json(TEST_DATA_2).unwrap();

        // register new drop
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data.root,
            expiration: None,
            start: None,
            total_amount: None,
            native_token: "ujunox".to_string(),
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        // Claim next airdrop
        let account = test_data.account;
        let msg = ExecuteMsg::Claim {
            amount: test_data.amount,
            stage: 2u8,
            proof: test_data.proofs,
            sig_info: None,
        };

        let env = mock_env();
        let info = message_info(&Addr::unchecked(account.clone()), &[]);
        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        let expected = SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
            to_address: account.clone(),
            amount: vec![Coin {
                denom: "ujunox".to_string(),
                amount: test_data.amount,
            }],
        }));
        assert_eq!(res.messages, vec![expected]);

        assert_eq!(
            res.attributes,
            vec![
                attr("action", "claim"),
                attr("stage", "2"),
                attr("address", account),
                attr("amount", test_data.amount),
            ]
        );

        // Check total claimed on stage 2
        assert_eq!(
            from_json::<TotalClaimedResponse>(
                &query(deps.as_ref(), env, QueryMsg::TotalClaimed { stage: 2 }).unwrap()
            )
            .unwrap()
            .total_claimed,
            test_data.amount
        );
    }

    #[test]
    fn claim_native_multiple_stages_different_denoms() {
        let mut deps = mock_dependencies_with_balance(&[
            Coin { denom: "ujunox".to_string(), amount: Uint128::new(1234567) },
            Coin { denom: "uatom".to_string(), amount: Uint128::new(1234567) },
        ]);
        let test_data_1: Encoded = from_json(TEST_DATA_1).unwrap();
        let test_data_2: Encoded = from_json(TEST_DATA_2).unwrap();

        let msg = InstantiateMsg {
            owner: Some(deps.api.addr_make("owner0000").to_string()),
        };
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("addr0000"), &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        // register stage 1 with ujunox
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data_1.root,
            expiration: None,
            start: None,
            total_amount: None,
            native_token: "ujunox".to_string(),
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        // register stage 2 with uatom
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data_2.root,
            expiration: None,
            start: None,
            total_amount: None,
            native_token: "uatom".to_string(),
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        // claim stage 1 — expects ujunox
        let account1 = test_data_1.account.clone();
        let env = mock_env();
        let info = message_info(&Addr::unchecked(account1.clone()), &[]);
        let msg = ExecuteMsg::Claim {
            amount: test_data_1.amount,
            stage: 1u8,
            proof: test_data_1.proofs,
            sig_info: None,
        };
        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        let expected = SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
            to_address: account1.clone(),
            amount: vec![Coin { denom: "ujunox".to_string(), amount: test_data_1.amount }],
        }));
        assert_eq!(res.messages, vec![expected]);

        // claim stage 2 — expects uatom
        let account2 = test_data_2.account.clone();
        let env = mock_env();
        let info = message_info(&Addr::unchecked(account2.clone()), &[]);
        let msg = ExecuteMsg::Claim {
            amount: test_data_2.amount,
            stage: 2u8,
            proof: test_data_2.proofs,
            sig_info: None,
        };
        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        let expected = SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
            to_address: account2.clone(),
            amount: vec![Coin { denom: "uatom".to_string(), amount: test_data_2.amount }],
        }));
        assert_eq!(res.messages, vec![expected]);

        // verify each stage tracks its own claimed amount
        assert_eq!(
            from_json::<TotalClaimedResponse>(
                &query(deps.as_ref(), env.clone(), QueryMsg::TotalClaimed { stage: 1 }).unwrap()
            )
            .unwrap()
            .total_claimed,
            test_data_1.amount
        );
        assert_eq!(
            from_json::<TotalClaimedResponse>(
                &query(deps.as_ref(), env, QueryMsg::TotalClaimed { stage: 2 }).unwrap()
            )
            .unwrap()
            .total_claimed,
            test_data_2.amount
        );
    }

    #[test]
    fn claim_native_insufficient_funds() {
        // Run test 1
        let mut deps = mock_dependencies_with_balance(&[Coin {
            denom: "ujunox".to_string(),
            amount: Uint128::zero(),
        }]);
        let test_data: Encoded = from_json(TEST_DATA_1).unwrap();

        let msg = InstantiateMsg {
            owner: Some(deps.api.addr_make("owner0000").to_string()),
        };

        let env = mock_env();
        let info = message_info(&deps.api.addr_make("addr0000"), &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data.root,
            expiration: None,
            start: None,
            total_amount: None,
            native_token: "ujunox".to_string(),
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        let account = test_data.account;
        let msg = ExecuteMsg::Claim {
            amount: test_data.amount,
            stage: 1u8,
            proof: test_data.proofs,
            sig_info: None,
        };

        let env = mock_env();
        let info = message_info(&Addr::unchecked(account), &[]);
        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(
            ContractError::InsufficientFunds {
                balance: Uint128::zero(),
                amount: test_data.amount
            },
            res
        );
    }

    const TEST_DATA_1_MULTI: &[u8] =
        include_bytes!("../testdata/airdrop_stage_1_test_multi_data.json");

    #[cw_serde]
    struct Proof {
        account: String,
        amount: Uint128,
        proofs: Vec<String>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    struct MultipleData {
        total_claimed_amount: Uint128,
        root: String,
        accounts: Vec<Proof>,
    }

    #[test]
    fn multiple_claim_native() {
        // Run test 1
        let mut deps = mock_dependencies_with_balance(&[Coin {
            denom: "ujunox".to_string(),
            amount: Uint128::new(1234567),
        }]);
        let test_data: MultipleData = from_json::<MultipleData>(TEST_DATA_1_MULTI).unwrap();

        let msg = InstantiateMsg {
            owner: Some(deps.api.addr_make("owner0000").to_string()),
        };

        let env = mock_env();
        let info = message_info(&deps.api.addr_make("addr0000"), &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: test_data.root,
            expiration: None,
            start: None,
            total_amount: None,
            native_token: "ujunox".to_string(),
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        // Loop accounts and claim
        for account in test_data.accounts.iter() {
            let msg = ExecuteMsg::Claim {
                amount: account.amount,
                stage: 1u8,
                proof: account.proofs.clone(),
                sig_info: None,
            };

            let env = mock_env();
            let info = message_info(&Addr::unchecked(account.account.as_str()), &[]);
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
            let expected = SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
                to_address: account.account.clone(),
                amount: vec![Coin {
                    denom: "ujunox".to_string(),
                    amount: account.amount,
                }],
            }));
            assert_eq!(res.messages, vec![expected]);

            assert_eq!(
                res.attributes,
                vec![
                    attr("action", "claim"),
                    attr("stage", "1"),
                    attr("address", account.account.clone()),
                    attr("amount", account.amount),
                ]
            );
        }

        // Check total claimed on stage 1
        let env = mock_env();
        assert_eq!(
            from_json::<TotalClaimedResponse>(
                &query(deps.as_ref(), env, QueryMsg::TotalClaimed { stage: 1 }).unwrap()
            )
            .unwrap()
            .total_claimed,
            test_data.total_claimed_amount
        );
    }

    // Check expiration. Chain height in tests is 12345
    #[test]
    fn stage_expires() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            owner: Some(deps.api.addr_make("owner0000").to_string()),
        };

        let env = mock_env();
        let info = message_info(&deps.api.addr_make("addr0000"), &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        // can register merkle root
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: "5d4f48f147cb6cb742b376dce5626b2a036f69faec10cd73631c791780e150fc"
                .to_string(),
            expiration: Some(Expiration::AtHeight(100)),
            start: None,
            total_amount: None,
            native_token: "ujunox".to_string(),
        };
        execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // can't claim expired
        let msg = ExecuteMsg::Claim {
            amount: Uint128::new(5),
            stage: 1u8,
            proof: vec![],
            sig_info: None,
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(
            res,
            ContractError::StageExpired {
                stage: 1,
                expiration: Expiration::AtHeight(100),
            }
        )
    }

    #[test]
    fn stage_starts() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            owner: Some(deps.api.addr_make("owner0000").to_string()),
        };

        let env = mock_env();
        let info = message_info(&deps.api.addr_make("addr0000"), &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        // can register merkle root
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: "5d4f48f147cb6cb742b376dce5626b2a036f69faec10cd73631c791780e150fc"
                .to_string(),
            expiration: None,
            start: Some(Scheduled::AtHeight(200_000)),
            total_amount: None,
            native_token: "ujunox".to_string(),
        };
        execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // can't claim stage has not started yet
        let msg = ExecuteMsg::Claim {
            amount: Uint128::new(5),
            stage: 1u8,
            proof: vec![],
            sig_info: None,
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(
            res,
            ContractError::StageNotBegun {
                stage: 1,
                start: Scheduled::AtHeight(200_000),
            }
        )
    }

    #[test]
    fn owner_freeze() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            owner: Some(deps.api.addr_make("owner0000").to_string()),
        };

        let env = mock_env();
        let info = message_info(&deps.api.addr_make("addr0000"), &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        // can register merkle root
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: "5d4f48f147cb6cb742b376dce5626b2a036f69faec10cd73631c791780e150fc"
                .to_string(),
            expiration: None,
            start: None,
            total_amount: None,
            native_token: "ujunox".to_string(),
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        // can update owner
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_owner: Some(deps.api.addr_make("owner0001").to_string()),
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // freeze contract
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0001"), &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_owner: None,
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // cannot register new drop
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0001"), &[]);
        let msg = ExecuteMsg::RegisterMerkleRoot {
            merkle_root: "ebaa83c7eaf7467c378d2f37b5e46752d904d2d17acd380b24b02e3b398b3e5a"
                .to_string(),
            expiration: None,
            start: None,
            total_amount: None,
            native_token: "ujunox".to_string(),
        };
        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::Unauthorized {});

        // cannot update config
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0001"), &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_owner: Some(deps.api.addr_make("owner0001").to_string()),
        };
        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::Unauthorized {});
    }

    #[test]
    fn withdraw_all() {
        let owner = "owner0000";
        let denom = "ujunox";

        let mut deps = mock_dependencies_with_balance(&[Coin {
            denom: denom.to_string(),
            amount: Uint128::new(5000),
        }]);

        let msg = InstantiateMsg {
            owner: Some(deps.api.addr_make(owner).to_string()),
        };
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("addr0000"), &[]);
        instantiate(deps.as_mut(), env, info, msg).unwrap();

        // non-owner is rejected
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("stranger"), &[]);
        let err = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::WithdrawAll { denom: denom.to_string() },
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        // owner withdraws successfully
        let owner_addr = deps.api.addr_make(owner);
        let env = mock_env();
        let info = message_info(&owner_addr, &[]);
        let res = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::WithdrawAll { denom: denom.to_string() },
        )
        .unwrap();

        let expected = SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
            to_address: owner_addr.to_string(),
            amount: vec![Coin {
                denom: denom.to_string(),
                amount: Uint128::new(5000),
            }],
        }));
        assert_eq!(res.messages, vec![expected]);
        assert_eq!(
            res.attributes,
            vec![
                attr("action", "withdraw_all"),
                attr("recipient", owner_addr.to_string()),
                attr("amount", "5000"),
            ]
        );

        // frozen contract (owner == None) is rejected
        let env = mock_env();
        let info = message_info(&owner_addr, &[]);
        execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::UpdateConfig { new_owner: None },
        )
        .unwrap();

        let env = mock_env();
        let info = message_info(&owner_addr, &[]);
        let err = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::WithdrawAll { denom: denom.to_string() },
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});
    }

    mod external_sig {
        use super::*;
        use cw_utils::Expiration::AtHeight;

        const TEST_DATA_EXTERNAL_SIG: &[u8] =
            include_bytes!("../testdata/airdrop_external_sig_test_data.json");

        #[test]
        fn claim_with_external_sigs() {
            let mut deps = mock_dependencies_with_balance(&[Coin {
                denom: "ujunox".to_string(),
                amount: Uint128::new(1234567),
            }]);
            let test_data: Encoded = from_json(TEST_DATA_EXTERNAL_SIG).unwrap();
            let claim_addr = test_data
                .signed_msg
                .clone()
                .unwrap()
                .extract_addr()
                .unwrap();

            let msg = InstantiateMsg {
                owner: Some(deps.api.addr_make("owner0000").to_string()),
            };

            let env = mock_env();
            let info = message_info(&deps.api.addr_make("addr0000"), &[]);
            let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

            let env = mock_env();
            let info = message_info(&deps.api.addr_make("owner0000"), &[]);
            let msg = ExecuteMsg::RegisterMerkleRoot {
                merkle_root: test_data.root,
                expiration: None,
                start: None,
                total_amount: None,
                native_token: "ujunox".to_string(),
            };
            let _res = execute(deps.as_mut(), env, info, msg).unwrap();

            // cant claim without sig, info.sender is not present in the root
            let msg = ExecuteMsg::Claim {
                amount: test_data.amount,
                stage: 1u8,
                proof: test_data.proofs.clone(),
                sig_info: None,
            };

            let env = mock_env();
            let info = message_info(&Addr::unchecked(claim_addr.clone()), &[]);
            let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
            assert_eq!(res, ContractError::VerificationFailed {});

            // stage account map is not saved

            // can claim with sig
            let msg = ExecuteMsg::Claim {
                amount: test_data.amount,
                stage: 1u8,
                proof: test_data.proofs,
                sig_info: test_data.signed_msg,
            };

            let env = mock_env();
            let info = message_info(&Addr::unchecked(claim_addr.clone()), &[]);
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
            let expected = SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
                to_address: claim_addr.clone(),
                amount: vec![Coin {
                    denom: "ujunox".to_string(),
                    amount: test_data.amount,
                }],
            }));

            assert_eq!(res.messages, vec![expected]);
            assert_eq!(
                res.attributes,
                vec![
                    attr("action", "claim"),
                    attr("stage", "1"),
                    attr("address", claim_addr.clone()),
                    attr("amount", test_data.amount),
                ]
            );

            // Check total claimed on stage 1
            assert_eq!(
                from_json::<TotalClaimedResponse>(
                    &query(
                        deps.as_ref(),
                        env.clone(),
                        QueryMsg::TotalClaimed { stage: 1 },
                    )
                    .unwrap()
                )
                .unwrap()
                .total_claimed,
                test_data.amount
            );

            // Check address is claimed
            assert!(
                from_json::<IsClaimedResponse>(
                    &query(
                        deps.as_ref(),
                        env.clone(),
                        QueryMsg::IsClaimed {
                            stage: 1,
                            address: test_data.account.clone(),
                        },
                    )
                    .unwrap()
                )
                .unwrap()
                .is_claimed
            );

            // check error on double claim
            let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap_err();
            assert_eq!(res, ContractError::Claimed {});

            // query map

            let map = from_json::<AccountMapResponse>(
                &query(
                    deps.as_ref(),
                    env,
                    QueryMsg::AccountMap {
                        stage: 1,
                        external_address: test_data.account.clone(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(map.external_address, test_data.account);
            assert_eq!(map.host_address, claim_addr);
        }

        #[test]
        fn claim_with_invalid_signature() {
            let mut deps = mock_dependencies_with_balance(&[Coin {
                denom: "ujunox".to_string(),
                amount: Uint128::new(1234567),
            }]);
            let test_data: Encoded = from_json(TEST_DATA_EXTERNAL_SIG).unwrap();
            // random address trying to claim with invalid sig
            let claim_addr = "wasm1uwcjkghqlz030r989clzqs8zlaujwyphx0yumy".to_string();

            let msg = InstantiateMsg {
                owner: Some(deps.api.addr_make("owner0000").to_string()),
            };

            let env = mock_env();
            let info = message_info(&deps.api.addr_make("addr0000"), &[]);
            let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

            let env = mock_env();
            let info = message_info(&deps.api.addr_make("owner0000"), &[]);
            let msg = ExecuteMsg::RegisterMerkleRoot {
                merkle_root: test_data.root,
                expiration: None,
                start: None,
                total_amount: None,
                native_token: "ujunox".to_string(),
            };
            let _res = execute(deps.as_mut(), env, info, msg).unwrap();

            let msg = ExecuteMsg::Claim {
                amount: test_data.amount,
                stage: 1u8,
                proof: test_data.proofs,
                sig_info: test_data.signed_msg,
            };

            let env = mock_env();
            let info = message_info(&Addr::unchecked(claim_addr), &[]);
            let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
            assert_eq!(res, ContractError::InvalidSignature {});
        }

        #[test]
        fn claim_paused_airdrop() {
            let mut deps = mock_dependencies_with_balance(&[Coin {
                denom: "ujunox".to_string(),
                amount: Uint128::new(1234567),
            }]);
            let test_data: Encoded = from_json(TEST_DATA_1).unwrap();

            let msg = InstantiateMsg {
                owner: Some(deps.api.addr_make("owner0000").to_string()),
            };

            let env = mock_env();
            let info = message_info(&deps.api.addr_make("addr0000"), &[]);
            let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

            let env = mock_env();
            let info = message_info(&deps.api.addr_make("owner0000"), &[]);
            let msg = ExecuteMsg::RegisterMerkleRoot {
                merkle_root: test_data.root,
                expiration: None,
                start: None,
                total_amount: None,
                native_token: "ujunox".to_string(),
            };
            let _res = execute(deps.as_mut(), env, info, msg).unwrap();

            let pause_msg = ExecuteMsg::Pause { stage: 1u8 };
            let env = mock_env();
            let info = message_info(&deps.api.addr_make("owner0000"), &[]);
            let result = execute(deps.as_mut(), env, info, pause_msg).unwrap();

            assert_eq!(
                result.attributes,
                vec![attr("action", "pause"), attr("stage_paused", "true"),]
            );

            let account = test_data.account;
            let msg = ExecuteMsg::Claim {
                amount: test_data.amount,
                stage: 1u8,
                proof: test_data.proofs.clone(),
                sig_info: None,
            };

            let env = mock_env();
            let info = message_info(&Addr::unchecked(account.clone()), &[]);
            let res = execute(deps.as_mut(), env, info, msg).unwrap_err();

            assert_eq!(res, ContractError::StagePaused { stage: 1u8 });

            let resume_msg = ExecuteMsg::Resume {
                stage: 1u8,
                new_expiration: Some(AtHeight(12346)),
            };
            let env = mock_env();
            let info = message_info(&deps.api.addr_make("owner0000"), &[]);
            let result = execute(deps.as_mut(), env, info, resume_msg).unwrap();

            assert_eq!(
                result.attributes,
                vec![attr("action", "resume"), attr("stage_paused", "false"),]
            );
            let msg = ExecuteMsg::Claim {
                amount: test_data.amount,
                stage: 1u8,
                proof: test_data.proofs.clone(),
                sig_info: None,
            };
            let env = mock_env();
            let info = message_info(&Addr::unchecked(account.clone()), &[]);
            let res = execute(deps.as_mut(), env, info, msg).unwrap();
            let expected = SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
                to_address: account.clone(),
                amount: vec![Coin {
                    denom: "ujunox".to_string(),
                    amount: test_data.amount,
                }],
            }));
            assert_eq!(res.messages, vec![expected]);

            assert_eq!(
                res.attributes,
                vec![
                    attr("action", "claim"),
                    attr("stage", "1"),
                    attr("address", account),
                    attr("amount", test_data.amount),
                ]
            );
        }

    }
}
