use std::sync::Arc;

use alloy::eips::BlockId;
use alloy::{network::Ethereum, providers::RootProvider, transports::Transport};
use eyre::eyre;
use revm::{
    db::{AlloyDB, CacheDB},
    primitives::{Address, Bytes, ExecutionResult, TransactTo, U256},
    Evm,
};

use crate::SimulateOutput;

pub type AlloyCacheDB<T> = CacheDB<AlloyDB<T, Ethereum, Arc<RootProvider<T, Ethereum>>>>;

pub fn new_alloy_db<T: Transport + Clone>(
    provider: Arc<RootProvider<T>>,
    block_number: BlockId,
) -> AlloyCacheDB<T> {
    CacheDB::new(AlloyDB::new(provider, block_number).unwrap())
}

pub fn revm_call<T: Transport + Clone>(
    from: Address,
    to: Address,
    calldata: Bytes,
    cache_db: &mut AlloyCacheDB<T>,
    commit: bool,
) -> eyre::Result<SimulateOutput> {
    let mut evm = Evm::builder()
        .with_db(cache_db)
        .modify_tx_env(|tx| {
            tx.caller = from;
            tx.transact_to = TransactTo::Call(to);
            tx.data = calldata;
            tx.value = U256::ZERO;
        })
        .build();

    let res = match commit {
        true => evm.transact_commit()?,
        false => evm.transact()?.result,
    };

    let value = match res {
        ExecutionResult::Success {
            reason,
            gas_used,
            gas_refunded,
            logs,
            output,
        } => SimulateOutput {
            reason,
            gas_used,
            gas_refunded,
            output,
            logs,
        },
        ExecutionResult::Halt { reason, gas_used } => {
            return Err(eyre!(
                "transaction execute halt, reason: {:?}, gas_used: {}",
                reason,
                gas_used
            ));
        }
        ExecutionResult::Revert { gas_used, output } => {
            return Err(eyre!(
                "transaction execute revert, gas_used: {}, output: {:?}",
                gas_used,
                output
            ));
        }
    };

    eyre::Ok(value)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_new_alloy_db_call() -> eyre::Result<()> {
    use alloy::eips::BlockNumberOrTag;
    use alloy::primitives::utils::parse_units;
    use alloy::providers::ProviderBuilder;
    use alloy::sol;
    use revm::primitives::{Address, U256};
    use std::str::FromStr;
    use tracing::info;
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

    let provider = ProviderBuilder::new().on_http("https://rpc.ankr.com/eth".parse().unwrap());
    let provider = Arc::new(provider);

    let eigenlayer_contract = Eigenlayer::new(
        "0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A"
            .parse::<Address>()
            .unwrap(),
        provider.clone(),
    );

    let call = eigenlayer_contract.queueWithdrawals(params);
    let call = call.gas(105818u128);

    // println!("{:}", call.calldata());
    let gas_price: U256 = parse_units("7", "gwei").unwrap().into();
    let call = call.gas_price(gas_price.try_into()?);

    let mut alloydb = new_alloy_db(
        provider.clone(),
        BlockId::Number(BlockNumberOrTag::Number(19737667u64)),
    );
    let call_res = revm_call(
        withdrawer,
        "0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A"
            .parse::<Address>()
            .unwrap(),
        call.calldata().clone(),
        &mut alloydb,
        false,
    )?;

    info!("call result of alloydb: {:?}", call_res);

    let call_res = revm_call(
        withdrawer,
        "0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A"
            .parse::<Address>()
            .unwrap(),
        call.calldata().clone(),
        &mut alloydb,
        true,
    )?;

    info!("call result of alloydb: {:?}", call_res);

    let call_res = revm_call(
        withdrawer,
        "0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A"
            .parse::<Address>()
            .unwrap(),
        call.calldata().clone(),
        &mut alloydb,
        true,
    )?;

    info!("call result of alloydb: {:?}", call_res);

    eyre::Ok(())
}
