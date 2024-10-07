use alloy::rpc::types::Transaction;
use revm::{
    db::CacheDB,
    primitives::{
        Bytes, EVMResult, ExecutionResult, Log, Output, SuccessReason, TransactTo, TxEnv, U256,
    },
    Database, Evm,
};

use crate::ForkDB;
use tracing::{error, info, warn};

pub fn tx_env_to_simulate(tx: Transaction) -> TxEnv {
    let mut tx_env = TxEnv::default();
    tx_env.caller = tx.from;
    tx_env.gas_limit = tx.gas as u64;

    if let Some(gas_price) = tx.gas_price {
        tx_env.gas_price = U256::from(gas_price);
    }

    if let Some(gas_price) = tx.max_fee_per_gas {
        tx_env.gas_price = U256::from(gas_price);
    }

    if let Some(gas_priority_fee) = tx.max_priority_fee_per_gas {
        tx_env.gas_priority_fee = Some(U256::from(gas_priority_fee));
    }

    if let Some(to) = tx.to {
        tx_env.transact_to = TransactTo::Call(to);
    }

    tx_env.value = tx.value;
    tx_env.data = Bytes::from(tx.input);
    tx_env.chain_id = tx.chain_id;
    tx_env.nonce = Some(tx.nonce);

    tx_env
}

pub struct Simulation<'a, T, DB>
where
    DB: Database,
{
    evm: Evm<'a, T, DB>,
}

#[derive(Debug)]
pub struct SimulateOutput {
    pub reason: SuccessReason,
    pub gas_used: u64,
    pub gas_refunded: u64,
    pub output: Output,
    pub logs: Vec<Log>,
}

impl<'a> Simulation<'a, (), CacheDB<ForkDB>> {
    pub fn new(db: CacheDB<ForkDB>, tx: TxEnv) -> Self {
        let evm = Evm::builder().with_db(db).with_tx_env(tx).build();
        Self { evm }
    }

    pub fn process_tx_calls(&mut self) -> EVMResult<<ForkDB as Database>::Error> {
        self.evm.preverify_transaction().map_err(|err| {
            error!("failed to verify transaciton, err: {}", err);
            err
        })?;
        self.evm.transact()
    }

    pub fn handle_evm_result(&self, result: ExecutionResult) -> eyre::Result<SimulateOutput> {
        match result {
            ExecutionResult::Success {
                reason,
                gas_used,
                gas_refunded,
                logs,
                output,
            } => {
                info!("transaction execute success, detail: reasons {:?}, gas_used: {}, gas_refunded: {}, logs: {:?}, output: {:?}", reason, gas_used, gas_refunded, logs, output);
                Ok(SimulateOutput {
                    reason,
                    gas_used,
                    gas_refunded,
                    output,
                    logs,
                })
            }
            ExecutionResult::Halt { reason, gas_used } => {
                warn!(
                    "transaction execute halt, reason: {:?}, gas_used: {}",
                    reason, gas_used
                );
                Err(eyre::eyre!("transaction execute halt"))
            }
            ExecutionResult::Revert { gas_used, output } => {
                error!(
                    "transaction execute revert, gas_used: {}, output: {:?}",
                    gas_used, output
                );
                Err(eyre::eyre!("transaction execute revert"))
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_on_simulation() -> eyre::Result<()> {
    use alloy::primitives::utils::parse_units;
    use alloy::providers::ProviderBuilder;
    use alloy::sol;
    use revm::primitives::{Address, TransactTo, U256};
    use std::str::FromStr;
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(LevelFilter::INFO)
        .init();

    sol! {
        #[sol(rpc)] // <-- Important! Generates the necessary `MyContract` struct and function methods.
        contract Eigenlayer{
            #[derive(Debug)]
            struct QueuedWithdrawalParams {
                address[] strategies;
                uint256[] shares;
                address withdrawer;
            }
            #[derive(Debug)]
            function queueWithdrawals(QueuedWithdrawalParams[]) external returns (bytes32[]);
        }
    }

    let withdrawer = "0x643c94706d3b3f056e8289e1f2de26b8aff88f1e"
        .parse::<Address>()
        .unwrap();
    // mock tx:
    // https://etherscan.io/tx/0x8c5f98e4d113af16eda3e92e65350be3de8b5b865ac877bfc047921ddd82eeb7
    let params = vec![Eigenlayer::QueuedWithdrawalParams {
        strategies: vec!["0x1bee69b7dfffa4e2d53c2a2df135c388ad25dcd2"
            .parse::<Address>()
            .unwrap()],
        shares: vec![U256::from_str("34999721528615607").unwrap()],
        withdrawer: withdrawer,
    }];

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_builtin("https://rpc.ankr.com/eth")
        .await?;
    let eigenlayer_contract = Eigenlayer::new(
        "0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A"
            .parse::<Address>()
            .unwrap(),
        provider,
    );
    let call = eigenlayer_contract.queueWithdrawals(params);
    let call = call.gas(105818u128);

    // println!("{:}", call.calldata());
    let gas_price: U256 = parse_units("7", "gwei").unwrap().into();
    let call = call.gas_price(gas_price.try_into()?);

    let ethers_db = ForkDB::new_as_cache_db("https://rpc.ankr.com/eth".to_string(), 19737667u64);

    let mut tx = TxEnv::default();
    tx.caller = withdrawer;
    tx.transact_to = TransactTo::Call(
        "0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A"
            .parse::<Address>()
            .unwrap(),
    );
    tx.gas_price = gas_price;
    tx.gas_limit = 161738u64;
    tx.data = call.calldata().clone();

    let mut simulator = Simulation::new(ethers_db, tx);

    let result = simulator.process_tx_calls();
    let success_tx = simulator.handle_evm_result(result.unwrap().result)?;
    println!("{:?}", success_tx);

    Ok(())
}
