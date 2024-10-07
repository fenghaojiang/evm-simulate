use std::sync::Arc;

use alloy::{
    providers::{Provider, RootProvider},
    sol_types::SolValue,
    transports::Transport,
};
use revm::primitives::{keccak256, AccountInfo, Address, Bytecode, Bytes, U256};

use crate::AlloyCacheDB;

fn cache_dir() -> String {
    ".evm_cache".to_string()
}

pub async fn init_account<T: Transport + Clone>(
    address: Address,
    cache_db: &mut AlloyCacheDB<T>,
    provider: Arc<RootProvider<T>>,
) -> eyre::Result<()> {
    let cache_key = format!("bytecode-{:?}", address);
    let bytecode = match cacache::read(&cache_dir(), cache_key.clone()).await {
        Ok(bytecode) => {
            let bytecode = Bytes::from(bytecode);
            Bytecode::new_raw(bytecode)
        }
        Err(_e) => {
            let bytecode = provider.get_code_at(address).await?;
            let bytecode_result = Bytecode::new_raw(bytecode.clone());
            let bytecode = bytecode.to_vec();
            cacache::write(&cache_dir(), cache_key, bytecode.clone()).await?;
            bytecode_result
        }
    };

    let code_hash = bytecode.hash_slow();
    let acc_info = AccountInfo {
        balance: U256::ZERO,
        nonce: 0_u64,
        code: Some(bytecode),
        code_hash,
    };

    cache_db.insert_account_info(address, acc_info);
    eyre::Ok(())
}

pub async fn insert_mapping_storage_slot<T: Transport + Clone>(
    contract: Address,
    slot: U256,
    slot_address: Address,
    value: U256,
    cache_db: &mut AlloyCacheDB<T>,
) -> eyre::Result<()> {
    let hashed_balance_slot = keccak256((slot_address, slot).abi_encode());
    cache_db.insert_account_storage(contract, hashed_balance_slot.into(), value)?;
    eyre::Ok(())
}

pub async fn init_account_with_bytecode<T: Transport + Clone>(
    address: Address,
    bytecode: Bytecode,
    cache_db: &mut AlloyCacheDB<T>,
) -> eyre::Result<()> {
    let code_hash = bytecode.hash_slow();
    let acc_info = AccountInfo {
        balance: U256::ZERO,
        nonce: 0_u64,
        code: Some(bytecode),
        code_hash,
    };

    cache_db.insert_account_info(address, acc_info);
    eyre::Ok(())
}
