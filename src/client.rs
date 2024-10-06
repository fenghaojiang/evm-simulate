use eyre::Context;
use revm::primitives::{alloy_primitives::U64, Address, Bytes, B256, U256};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use ureq::Agent;

use crate::utils;

pub struct MiniRpcClient {
    client: Agent,
    rpc_url: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct MiniBlock {
    pub hash: Option<B256>,
}

impl MiniRpcClient {
    pub fn new<T: Into<String>>(rpc_url: T) -> Self {
        Self {
            client: Agent::new(),
            rpc_url: rpc_url.into(),
        }
    }

    pub(crate) fn make_request(id: u64, method: &str, params: &Value) -> Value {
        json!({
            "id": id,
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        })
    }

    pub(crate) fn handle_response<T: DeserializeOwned>(mut response: Value) -> eyre::Result<T> {
        if let Some(error) = response.get("error") {
            eyre::bail!("rpc error: {error}");
        } else if response.get("result").is_some() {
            let value = response["result"].take();
            return serde_json::from_value(value).context("fail to deserialize result");
        } else {
            eyre::bail!("rpc response missing result")
        }
    }

    pub(crate) fn do_request<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> eyre::Result<T> {
        let req = Self::make_request(1, method, &params);
        let resp = self
            .client
            .post(&self.rpc_url)
            .send_json(req)
            .context("failed to send request")?
            .into_json::<Value>()
            .context("failed to read response")?;

        tracing::trace!(
            method,
            params = format_args!("{}", params),
            "response: {resp}"
        );

        Self::handle_response(resp)
    }

    pub(crate) fn get_storage_at(
        &self,
        address: &Address,
        index: &B256,
        block_number: u64,
    ) -> eyre::Result<B256> {
        let resp = self.do_request::<B256>(
            "eth_getStorageAt",
            json!([
                address.to_string(),
                index.to_string(),
                utils::format_block_tag(block_number),
            ]),
        )?;

        eyre::Ok(resp)
    }

    pub(crate) fn get_blockhash(&self, block_number: u64) -> eyre::Result<Option<MiniBlock>> {
        let response = self.do_request::<Option<MiniBlock>>(
            "eth_getBlockByNumber",
            json!([utils::format_block_tag(block_number), false]),
        )?;

        eyre::Ok(response)
    }

    pub(crate) fn get_account_basic(
        &self,
        address: &Address,
        block_number: u64,
    ) -> eyre::Result<(U256, u64, Bytes)> {
        let requests = json!([
            Self::make_request(
                1,
                "eth_getBalance",
                &json!([address.to_string(), utils::format_block_tag(block_number)]),
            ),
            Self::make_request(
                2,
                "eth_getTransactionCount",
                &json!([address.to_string(), utils::format_block_tag(block_number)]),
            ),
            Self::make_request(
                3,
                "eth_getCode",
                &json!([address.to_string(), utils::format_block_tag(block_number)]),
            ),
        ]);

        let mut response = self
            .client
            .post(&self.rpc_url)
            .send_json(requests)
            .context("fail to send request")?
            .into_json::<Value>()?;

        tracing::trace!(
            account = address.to_string(),
            "get account basic info. response: {response}"
        );

        let results = response
            .as_array_mut()
            .ok_or(eyre::eyre!("expect array response"))?;
        if results.len() != 3 {
            eyre::bail!("expect 3 responses, got {}", results.len());
        }

        let balance =
            Self::handle_response::<U256>(results[0].take()).context("fail to parse balance")?;
        let nonce =
            Self::handle_response::<U64>(results[1].take()).context("fail to parse nonce")?;
        let code =
            Self::handle_response::<Bytes>(results[2].take()).context("fail to parse code")?;

        eyre::Ok((balance, nonce.as_limbs()[0], code))
    }
}
