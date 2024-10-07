use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{self, Duration},
};

use eyre::ContextCompat;
use revm::{
    db::CacheDB,
    interpreter::interpreter,
    primitives::{keccak256, AccountInfo, Address, Bytecode, B256, U256},
    Database, DatabaseRef,
};

use crate::MiniRpcClient;

pub struct ForkDB {
    rpc_client: MiniRpcClient,
    block_number: u64,
    measure_rpc_time: bool,
    cumulative_rpc_time: AtomicU64,
}

impl ForkDB {
    fn new<T: Into<String>, B: Into<u64>>(rpc_url: T, block_number: B) -> Self {
        ForkDB {
            rpc_client: MiniRpcClient::new(rpc_url),
            block_number: block_number.into(),
            measure_rpc_time: false,
            cumulative_rpc_time: AtomicU64::new(0),
        }
    }

    pub fn new_as_cache_db<T: Into<String>, B: Into<u64>>(
        rpc_url: T,
        block_number: B,
    ) -> CacheDB<Self> {
        CacheDB::new(ForkDB::new(rpc_url, block_number))
    }

    pub fn set_measure_rpc_time(&mut self, enable: bool) {
        self.measure_rpc_time = enable;
    }

    pub fn get_rpc_time(&self) -> Duration {
        Duration::from_millis(self.cumulative_rpc_time.load(Ordering::Relaxed))
    }

    pub fn reset_rpc_time(&mut self) {
        self.cumulative_rpc_time.store(0, Ordering::Relaxed);
    }

    pub fn make_request<F, R>(&self, f: F) -> eyre::Result<R>
    where
        F: FnOnce(&MiniRpcClient) -> eyre::Result<R>,
    {
        if self.measure_rpc_time {
            let start = time::Instant::now();
            let result = f(&self.rpc_client)?;
            let elapsed = start.elapsed().as_millis() as u64;
            self.cumulative_rpc_time
                .fetch_add(elapsed, Ordering::Relaxed);

            return eyre::Ok(result);
        }

        f(&self.rpc_client)
    }
}

impl Database for ForkDB {
    type Error = eyre::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        DatabaseRef::basic_ref(self, address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        DatabaseRef::code_by_hash_ref(self, code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        DatabaseRef::storage_ref(self, address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        DatabaseRef::block_hash_ref(self, number)
    }
}

impl DatabaseRef for ForkDB {
    type Error = eyre::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let (balance, nonce, code) = self
            .make_request(|rpc_client| rpc_client.get_account_basic(&address, self.block_number))?;
        let code_hash = keccak256(&code);
        let bytecode = interpreter::analysis::to_analysed(Bytecode::new_raw(code));

        eyre::Ok(Some(AccountInfo::new(balance, nonce, code_hash, bytecode)))
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        unreachable!("code_by_hash should not be called")
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let result = self.make_request(|rpc_client| {
            rpc_client.get_storage_at(&address, &index.into(), self.block_number)
        })?;

        eyre::Ok(result.into())
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        let block = self
            .make_request(|rpc_client| rpc_client.get_blockhash(number))?
            .context("block not found")?;

        block.hash.context("block not finalized")
    }
}
