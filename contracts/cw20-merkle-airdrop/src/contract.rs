use crate::enumerable::query_all_address_map;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    Addr, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint128, attr, to_json_binary
};
use cw2::set_contract_version;
use cw_utils::{Expiration, Scheduled};
use sha2::Digest;
use sha3::Keccak256;

use crate::error::ContractError;
use crate::ethereum::{
    ethereum_address, get_recovery_param,
};
use crate::msg::{
    AccountMapResponse, ConfigResponse, ExecuteMsg, InstantiateMsg, IsClaimedResponse,
    IsPausedResponse, LatestStageResponse, MerkleRootResponse, QueryMsg, SignatureInfo,
    TotalClaimedResponse,
};
use crate::state::{
    Config, CLAIM, CONFIG, LATEST_STAGE, MERKLE_ROOT, STAGE_ACCOUNT_MAP, STAGE_AMOUNT,
    STAGE_AMOUNT_CLAIMED, STAGE_EXPIRATION, STAGE_PAUSED, STAGE_START,
};

// Version info, for migration info
const CONTRACT_NAME: &str = "crates.io:cw20-merkle-airdrop";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

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

    make_config(deps, Some(owner), msg.native_token)?;

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
        ExecuteMsg::UpdateConfig {
            new_owner,
            new_native_token,
        } => execute_update_config(
            deps,
            env,
            info,
            new_owner,
            new_native_token,
        ),
        ExecuteMsg::RegisterMerkleRoot {
            merkle_root,
            expiration,
            start,
            total_amount,
        } => execute_register_merkle_root(
            deps,
            env,
            info,
            merkle_root,
            expiration,
            start,
            total_amount,
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
    }
}

pub fn make_config(
    deps: DepsMut,
    owner: Option<Addr>,
    native_token: String,
) -> Result<Response, ContractError> {
    let config = Config { owner, native_token };
    CONFIG.save(deps.storage, &config)?;
    Ok(Response::default())
}

pub fn execute_update_config(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    new_owner: Option<String>,
    native_token: String,
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

    make_config(deps, tmp_owner, native_token)?;

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

    let stage = LATEST_STAGE.update(deps.storage, |stage| -> StdResult<_> { Ok(stage + 1) })?;

    MERKLE_ROOT.save(deps.storage, stage, &merkle_root)?;
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

    Ok(Response::new().add_attributes(vec![
        attr("action", "register_merkle_root"),
        attr("stage", stage.to_string()),
        attr("merkle_root", merkle_root),
        attr("total_amount", amount),
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
    let proof_addr = match sig_info {
        None => info.sender.to_string(),
        Some(sig) => {
            // verify signature

            let msg_str = String::from_utf8(sig.claim_msg.to_vec())
            .map_err(|_| ContractError::InvalidInput {})?;
            // Hashing
            let mut hasher = Keccak256::new();
            hasher.update(format!("\x19Ethereum Signed Message:\n{}", msg_str.len()));
            hasher.update(msg_str);
            let hash = hasher.finalize();

            // Decompose signature
            let (v, rs) = match sig.signature.as_slice().split_last() {
                Some(pair) => pair,
                None => return Err(StdError::generic_err("Signature must not be empty").into()),
            };
            let recovery = get_recovery_param(*v)?;

            // Verification
            let calculated_pubkey = deps.api.secp256k1_recover_pubkey(&hash, rs, recovery)?;
            let result = deps.api.secp256k1_verify(&hash, rs, &calculated_pubkey);
            let valid_signature = result.unwrap_or_default();

            if !valid_signature {
                return Err(ContractError::InvalidSignature {})
            }

            let proof_addr = ethereum_address(&calculated_pubkey)?;

            if sig.extract_addr()? != info.sender.as_str() {
                return Err(ContractError::InvalidSignature {});
            }
            
            // let proof_addr = String::from_utf8_lossy(&eth_addr).to_string();
            // Save external address index
            STAGE_ACCOUNT_MAP.save(
                deps.storage,
                (stage, proof_addr.clone()),
                &info.sender.to_string(),
            )?;

            proof_addr
        }
    };

    // verify not claimed
    let claimed = CLAIM.may_load(deps.storage, (proof_addr.clone(), stage))?;
    if claimed.is_some() {
        return Err(ContractError::Claimed {});
    }

    // verify merkle root
    let config = CONFIG.load(deps.storage)?;
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

    let mut root_buf: [u8; 32] = [0; 32];
    hex::decode_to_slice(merkle_root, &mut root_buf)?;
    if root_buf != hash {
        return Err(ContractError::VerificationFailed {});
    }

    // Update claim index to the current stage
    CLAIM.save(deps.storage, (proof_addr, stage), &true)?;

    // Update total claimed to reflect
    let mut claimed_amount = STAGE_AMOUNT_CLAIMED.load(deps.storage, stage)?;
    claimed_amount += amount;
    STAGE_AMOUNT_CLAIMED.save(deps.storage, stage, &claimed_amount)?;

    let balance = deps
        .querier
        .query_balance(env.contract.address, config.native_token.clone())?;
    if balance.amount < amount {
        return Err(ContractError::InsufficientFunds {
            balance: balance.amount,
            amount,
        });
    }
    let message: CosmosMsg = CosmosMsg::Bank(BankMsg::Send {
        to_address: info.sender.to_string(),
        amount: vec![Coin {
            denom: config.native_token,
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
        native_token: cfg.native_token,
    })
}

pub fn query_merkle_root(deps: Deps, stage: u8) -> StdResult<MerkleRootResponse> {
    let merkle_root = MERKLE_ROOT.load(deps.storage, stage)?;
    let expiration = STAGE_EXPIRATION.load(deps.storage, stage)?;
    let start = STAGE_START.may_load(deps.storage, stage)?;
    let total_amount = STAGE_AMOUNT.load(deps.storage, stage)?;

    let resp = MerkleRootResponse {
        stage,
        merkle_root,
        expiration,
        start,
        total_amount,
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
            native_token: String::from("ujunox"),
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
        assert_eq!("ujunox", config.native_token.as_str());

        let res = query(deps.as_ref(), env, QueryMsg::LatestStage {}).unwrap();
        let latest_stage: LatestStageResponse = from_json(&res).unwrap();
        assert_eq!(0u8, latest_stage.latest_stage);
    }

    #[test]
    fn update_config() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            owner: None,
            native_token: "ujunox".to_string(),
        };

        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        // update owner and native token
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let new_owner = deps.api.addr_make("owner0001");
        let msg = ExecuteMsg::UpdateConfig {
            new_owner: Some(new_owner.to_string()),
            new_native_token: "uatom".to_string(),
        };

        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.as_ref(), env, QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_json(&res).unwrap();
        assert_eq!(new_owner.to_string(), config.owner.unwrap().as_str());
        assert_eq!("uatom", config.native_token.as_str());

        // Unauthorized err
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_owner: None,
            new_native_token: "ujunox".to_string(),
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::Unauthorized {});

        // freeze contract (owner set to None)
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0001"), &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_owner: None,
            new_native_token: "ujunox".to_string(),
        };

        let _res = execute(deps.as_mut(), env.clone(), info, msg).ok();

        let query_result = query(deps.as_ref(), env, QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_json(&query_result).unwrap();
        assert_eq!(None, config.owner);
        assert_eq!("ujunox", config.native_token.as_str());
    }

    #[test]
    fn register_merkle_root() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            owner: Some(deps.api.addr_make("owner0000").to_string()),
            native_token: "ujunox".to_string(),
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
            native_token: "ujunox".to_string(),
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
    fn claim_native_insufficient_funds() {
        // Run test 1
        let mut deps = mock_dependencies_with_balance(&[Coin {
            denom: "ujunox".to_string(),
            amount: Uint128::zero(),
        }]);
        let test_data: Encoded = from_json(TEST_DATA_1).unwrap();

        let msg = InstantiateMsg {
            owner: Some(deps.api.addr_make("owner0000").to_string()),
            native_token: "ujunox".to_string(),
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
            native_token: "ujunox".to_string(),
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
            native_token: "ujunox".to_string(),
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
            native_token: "ujunox".to_string(),
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
            native_token: "ujunox".to_string(),
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
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        // can update owner
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0000"), &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_owner: Some(deps.api.addr_make("owner0001").to_string()),
            new_native_token: "ujunox".to_string(),
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // freeze contract
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0001"), &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_owner: None,
            new_native_token: "ujunox".to_string(),
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
        };
        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::Unauthorized {});

        // cannot update config
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("owner0001"), &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_owner: Some(deps.api.addr_make("owner0001").to_string()),
            new_native_token: "ujunox".to_string(),
        };
        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::Unauthorized {});
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
                native_token: "ujunox".to_string(),
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
                native_token: "ujunox".to_string(),
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
                native_token: "ujunox".to_string(),
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
