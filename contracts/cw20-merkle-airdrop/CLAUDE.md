# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build WASM optimized binary
cargo wasm

# Build WASM debug binary
cargo wasm-debug

# Run unit tests
cargo unit-test

# Run a single test by name
cargo unit-test -- test_name_here

# Run integration tests
cargo integration-test

# Generate JSON schema
cargo schema

# Lint
cargo clippy -- -D warnings
```

### Helpers CLI (in `helpers/`)

```bash
yarn install
yarn link

# Generate merkle root from airdrop list
merkle-airdrop-cli generateRoot --file ../testdata/airdrop_stage_2_list.json

# Generate merkle proof for a specific address
merkle-airdrop-cli generateProofs --file ../testdata/airdrop_stage_2_list.json \
  --address <address> --amount <amount>

# Verify merkle proof
merkle-airdrop-cli verifyProofs --file ../testdata/airdrop.json \
  --address <address> --amount <amount> --proofs $PROOFS
```

## Architecture

This is a **CosmWasm smart contract** for merkle-tree-based token airdrops. It supports multiple airdrop rounds (stages) on the same contract instance. Both CW20 tokens and native tokens are supported, but exactly one must be configured.

### Core Contract Flow

1. **Owner registers a merkle root** (`RegisterMerkleRoot`) → increments `stage` counter
2. **Recipients claim** (`Claim`) by providing their merkle proof → contract verifies and sends tokens
3. **Owner burns/withdraws** unclaimed tokens after expiry

### Module Structure

- `src/contract.rs` — All entry points (`instantiate`, `execute`, `query`, `migrate`) and their handler functions
- `src/msg.rs` — Message types: `InstantiateMsg`, `ExecuteMsg`, `QueryMsg`, and response types
- `src/state.rs` — Storage layout using `cw-storage-plus` Items and Maps
- `src/error.rs` — `ContractError` enum
- `src/ethereum.rs` — Ethereum signature verification helpers (Keccak256, recovery param)
- `src/enumerable.rs` — Paginated query for `AllAccountMaps`
- `src/migrations.rs` — Migration logic (currently v0.12.1: initialize `STAGE_PAUSED` for existing stages)

### State Layout (key storage maps)

| Storage Key | Type | Purpose |
|---|---|---|
| `CONFIG` | `Item<Config>` | Owner, cw20 address or native denom |
| `LATEST_STAGE` | `Item<u8>` | Current stage counter |
| `MERKLE_ROOT` | `Map<u8, String>` | Hex-encoded root per stage |
| `CLAIM` | `Map<(String, u8), bool>` | Claimed status keyed by (address, stage) |
| `STAGE_EXPIRATION` | `Map<u8, Expiration>` | Expiry per stage |
| `STAGE_START` | `Map<u8, Scheduled>` | Start schedule per stage |
| `STAGE_AMOUNT` | `Map<u8, Uint128>` | Total airdrop amount per stage |
| `STAGE_AMOUNT_CLAIMED` | `Map<u8, Uint128>` | Claimed amount per stage |
| `STAGE_PAUSED` | `Map<u8, bool>` | Pause status per stage |
| `HRP` | `Map<u8, String>` | Bech32 HRP for cross-chain stages |
| `STAGE_ACCOUNT_MAP` | `Map<(u8, String), String>` | External→host address mapping for cross-chain claims |

### Cross-Chain / Ethereum Claim Flow

When `RegisterMerkleRoot` is called with an `hrp` (e.g., `"cosmos"`, `"terra"`), that stage supports cross-chain claims. In `Claim`, the optional `sig_info` field (`SignatureInfo { claim_msg, signature }`) carries an Ethereum-signed message. The contract:

1. Recovers the Ethereum public key from the secp256k1 signature
2. Derives the 20-byte Ethereum address (Keccak256 of uncompressed pubkey)
3. Converts it to a bech32 address using the stage's `hrp`
4. Verifies the proof against that derived address

The `claim_msg` is a JSON-encoded `ClaimMsg { memo: "<host_address>" }` — this is how the claimer proves ownership of the host address.

### Token Transfer Logic

- **CW20**: issues a `Cw20ExecuteMsg::Transfer` to the token contract
- **Native**: issues a `BankMsg::Send` with the configured denom
- Exactly one of `cw20_token_address` or `native_token` must be set; `make_config` enforces this and returns `InvalidTokenType` otherwise

### Airdrop File Format (for helpers CLI)

```json
[
  { "address": "wasm1...", "amount": "100" },
  { "address": "wasm1...", "amount": "1010" }
]
```

Test data lives in `testdata/`.
