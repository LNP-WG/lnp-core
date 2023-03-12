// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020-2022 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::collections::BTreeMap;

use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{OutPoint, Transaction, TxIn, TxOut};
use bitcoin_scripts::hlc::{HashLock, HashPreimage};
use bitcoin_scripts::{LockScript, PubkeyScript, WitnessScript};
use lnp2p::bolt::{ChannelId, Messages};
use p2p::bolt::ChannelType;
use wallet::psbt::{self, Output, Psbt, PsbtVersion};

use crate::channel::bolt::util::UpdateReq;
use crate::channel::bolt::{BoltExt, ChannelState, Error, TxType};
use crate::channel::tx_graph::TxGraph;
use crate::{ChannelExtension, Extension};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct HtlcKnown {
    pub amount: u64,
    pub preimage: HashPreimage,
    pub id: u64,
    pub cltv_expiry: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct HtlcSecret {
    pub amount: u64,
    pub hashlock: HashLock,
    pub id: u64,
    pub cltv_expiry: u32,
}

#[derive(Getters, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
pub struct Htlc {
    /// Set if the feature `option_anchors_zero_fee_htlc_tx` was negotiated via
    /// `channel_type`. Indicates that HTLC transactions will use zero fees and
    /// will be pushed through an anchor transaction.
    anchors_zero_fee_htlc_tx: bool,

    // Sets of HTLC informations
    offered_htlcs: BTreeMap<u64, HtlcSecret>,
    received_htlcs: BTreeMap<u64, HtlcSecret>,
    resolved_htlcs: BTreeMap<u64, HtlcKnown>,

    // Commitment round specific information
    to_self_delay: u16,
    local_revocation_basepoint: PublicKey,
    remote_revocation_basepoint: PublicKey,
    local_basepoint: PublicKey,
    remote_basepoint: PublicKey,
    local_delayed_basepoint: PublicKey,

    // Channel specific information
    channel_id: ChannelId,

    /// indicates the smallest value HTLC this node will accept.
    htlc_minimum_msat: u64,
    max_htlc_value_in_flight_msat: u64,
    max_accepted_htlcs: u16,

    next_recieved_htlc_id: u64,
    next_offered_htlc_id: u64,
}

impl Default for Htlc {
    fn default() -> Self {
        Htlc {
            anchors_zero_fee_htlc_tx: false,
            offered_htlcs: empty!(),
            received_htlcs: empty!(),
            resolved_htlcs: empty!(),
            to_self_delay: 0,
            local_revocation_basepoint: dumb_pubkey!(),
            remote_revocation_basepoint: dumb_pubkey!(),
            local_basepoint: dumb_pubkey!(),
            remote_basepoint: dumb_pubkey!(),
            local_delayed_basepoint: dumb_pubkey!(),
            channel_id: Default::default(),
            htlc_minimum_msat: 0,
            max_htlc_value_in_flight_msat: 0,
            max_accepted_htlcs: 0,
            next_recieved_htlc_id: 0,
            next_offered_htlc_id: 0,
        }
    }
}

impl Htlc {
    pub fn offer_htlc(
        &mut self,
        amount_msat: u64,
        payment_hash: HashLock,
        cltv_expiry: u32,
    ) -> u64 {
        let htlc_id = self.next_offered_htlc_id;
        self.next_offered_htlc_id += 1;
        self.offered_htlcs.insert(htlc_id, HtlcSecret {
            amount: amount_msat,
            hashlock: payment_hash,
            id: htlc_id,
            cltv_expiry,
        });
        htlc_id
    }
}

impl Extension<BoltExt> for Htlc {
    fn identity(&self) -> BoltExt {
        BoltExt::Htlc
    }

    fn update_from_local(&mut self, _message: &()) -> Result<(), Error> {
        // Nothing to do here so far
        Ok(())
    }

    fn state_change(
        &mut self,
        request: &UpdateReq,
        message: &mut Messages,
    ) -> Result<(), Error> {
        match (request, message) {
            (
                UpdateReq::PayBolt(_),
                Messages::UpdateAddHtlc(update_add_htlc),
            ) => {
                let htlc_id = self.offer_htlc(
                    update_add_htlc.amount_msat,
                    update_add_htlc.payment_hash,
                    update_add_htlc.cltv_expiry,
                );
                update_add_htlc.htlc_id = htlc_id;
            }
            (UpdateReq::PayBolt(_), _) => unreachable!(
                "state change request must match provided LN P2P message"
            ),
        }
        Ok(())
    }

    fn update_from_peer(&mut self, message: &Messages) -> Result<(), Error> {
        match message {
            Messages::OpenChannel(open_channel) => {
                self.anchors_zero_fee_htlc_tx = open_channel
                    .channel_type
                    .map(ChannelType::has_anchors_zero_fee_htlc_tx)
                    .unwrap_or_default();
                self.htlc_minimum_msat = open_channel.htlc_minimum_msat;
                self.max_accepted_htlcs = open_channel.max_accepted_htlcs;
                self.max_htlc_value_in_flight_msat =
                    open_channel.max_htlc_value_in_flight_msat;
                self.remote_basepoint = open_channel.htlc_basepoint;
                self.remote_revocation_basepoint =
                    open_channel.revocation_basepoint;
                self.local_delayed_basepoint =
                    open_channel.delayed_payment_basepoint;
                self.to_self_delay = open_channel.to_self_delay;
            }
            Messages::AcceptChannel(accept_channel) => {
                self.anchors_zero_fee_htlc_tx = accept_channel
                    .channel_type
                    .map(ChannelType::has_anchors_zero_fee_htlc_tx)
                    .unwrap_or_default();
                self.htlc_minimum_msat = accept_channel.htlc_minimum_msat;
                self.max_accepted_htlcs = accept_channel.max_accepted_htlcs;
                self.max_htlc_value_in_flight_msat =
                    accept_channel.max_htlc_value_in_flight_msat;
                self.remote_basepoint = accept_channel.htlc_basepoint;
                self.remote_revocation_basepoint =
                    accept_channel.revocation_basepoint;
                self.local_delayed_basepoint =
                    accept_channel.delayed_payment_basepoint;
                self.to_self_delay = accept_channel.to_self_delay;
            }
            Messages::UpdateAddHtlc(message) => {
                // TODO: Filter messages by channel_id at channel level with
                //       special API
                if message.channel_id == self.channel_id {
                    // Checks
                    // 1. sending node should afford current fee rate after
                    // adding this htlc to its local
                    // commitment including anchor outputs
                    // if opt in.
                    if message.amount_msat == 0
                        || message.amount_msat < self.htlc_minimum_msat
                    {
                        return Err(Error::Htlc(
                            "amount_msat has to be greater than 0".to_string(),
                        ));
                    } else if self.received_htlcs.len()
                        >= self.max_accepted_htlcs as usize
                    {
                        return Err(Error::Htlc(
                            "max no. of HTLC limit exceeded".to_string(),
                        ));
                    } else if message.cltv_expiry > 500000000 {
                        return Err(Error::Htlc(
                            "cltv_expiry limit exceeded".to_string(),
                        ));
                    } else if message.amount_msat.leading_zeros() < 32 {
                        return Err(Error::Htlc(
                            "Leading zeros not satisfied for Bitcoin network"
                                .to_string(),
                        ));
                    } else if message.htlc_id < self.next_recieved_htlc_id {
                        return Err(Error::Htlc(
                            "HTLC id violation occurred".to_string(),
                        )); // TODO handle reconnection
                    } else {
                        let htlc = HtlcSecret {
                            amount: message.amount_msat,
                            hashlock: message.payment_hash,
                            id: message.htlc_id,
                            cltv_expiry: message.cltv_expiry,
                        };
                        self.received_htlcs.insert(htlc.id, htlc);

                        self.next_recieved_htlc_id += 1;
                    }
                } else {
                    return Err(Error::Htlc(
                        "Missmatched channel_id, bad remote node".to_string(),
                    ));
                }
            }
            Messages::UpdateFulfillHtlc(message) => {
                if message.channel_id == self.channel_id {
                    // Get the corresponding offered htlc
                    let offered_htlc =
                        self.received_htlcs.get(&message.htlc_id).ok_or_else(
                            || Error::Htlc("HTLC id didn't match".to_string()),
                        )?;

                    // Check for correct hash preimage in the message
                    if offered_htlc.hashlock
                        == HashLock::from(message.payment_preimage)
                    {
                        self.offered_htlcs.remove(&message.htlc_id);
                        let resolved_htlc = HtlcKnown {
                            amount: offered_htlc.amount,
                            preimage: message.payment_preimage,
                            id: message.htlc_id,
                            cltv_expiry: offered_htlc.cltv_expiry,
                        };
                        self.resolved_htlcs
                            .insert(message.htlc_id, resolved_htlc);
                    }
                } else {
                    return Err(Error::Htlc(
                        "Missmatched channel_id, bad remote node".to_string(),
                    ));
                }
            }
            Messages::UpdateFailHtlc(message) => {
                if message.channel_id == self.channel_id {
                    self.offered_htlcs.remove(&message.htlc_id);

                    // TODO the failure reason should be handled here
                }
            }
            Messages::UpdateFailMalformedHtlc(_) => {}
            Messages::CommitmentSigned(_) => {}
            Messages::RevokeAndAck(_) => {}
            Messages::ChannelReestablish(_) => {}
            _ => {}
        }
        Ok(())
    }

    fn load_state(&mut self, state: &ChannelState) {
        self.anchors_zero_fee_htlc_tx = state
            .common_params
            .channel_type
            .has_anchors_zero_fee_htlc_tx();

        self.offered_htlcs = state.offered_htlcs.clone();
        self.received_htlcs = state.received_htlcs.clone();
        self.resolved_htlcs = state.resolved_htlcs.clone();

        self.to_self_delay = state.remote_params.to_self_delay;
        self.local_revocation_basepoint =
            state.local_keys.revocation_basepoint.key;
        self.remote_revocation_basepoint =
            state.remote_keys.revocation_basepoint;
        self.local_basepoint = state.local_keys.payment_basepoint.key;
        self.remote_basepoint = state.remote_keys.payment_basepoint;
        self.local_delayed_basepoint =
            state.local_keys.delayed_payment_basepoint.key;

        self.channel_id = state.active_channel_id.as_slice32().into();

        self.htlc_minimum_msat = state.remote_params.htlc_minimum_msat;
        self.max_htlc_value_in_flight_msat =
            state.remote_params.max_htlc_value_in_flight_msat;
        self.max_accepted_htlcs = state.remote_params.max_accepted_htlcs;

        self.next_recieved_htlc_id = state.last_recieved_htlc_id;
        self.next_offered_htlc_id = state.last_offered_htlc_id;
    }

    fn store_state(&self, state: &mut ChannelState) {
        state.offered_htlcs = self.offered_htlcs.clone();
        state.received_htlcs = self.received_htlcs.clone();
        state.resolved_htlcs = self.resolved_htlcs.clone();
        state.last_recieved_htlc_id = self.next_recieved_htlc_id;
        state.last_offered_htlc_id = self.next_offered_htlc_id;
    }
}

impl ChannelExtension<BoltExt> for Htlc {
    #[inline]
    fn new() -> Box<dyn ChannelExtension<BoltExt>>
    where
        Self: Sized,
    {
        Box::new(Htlc::default())
    }

    fn build_graph(
        &self,
        tx_graph: &mut TxGraph,
        _as_remote_node: bool,
    ) -> Result<(), Error> {
        // Process offered HTLCs
        let mut accumulate = 0;
        for (index, offered) in self.offered_htlcs.iter() {
            let htlc_output: Output = ScriptGenerators::ln_offered_htlc(
                offered.amount / 1000,
                self.remote_revocation_basepoint,
                self.local_basepoint,
                self.remote_basepoint,
                offered.hashlock,
            );
            // Sum amounts to same OutPoints
            match tx_graph.cmt_outs.iter().position(|out| {
                out.script == htlc_output.script
                    && out.witness_script == htlc_output.witness_script
            }) {
                Some(index) => {
                    let mut htlc_output = tx_graph.cmt_outs.remove(index);
                    htlc_output.amount += offered.amount;
                    tx_graph.cmt_outs.insert(index, htlc_output);
                }
                _ => tx_graph.cmt_outs.push(htlc_output),
            };

            let htlc_tx = Psbt::ln_htlc(
                offered.amount,
                // TODO: do a two-staged graph generation process
                OutPoint::default(),
                offered.cltv_expiry,
                self.remote_revocation_basepoint,
                self.local_delayed_basepoint,
                self.to_self_delay,
            );
            // Last index of transaction in graph
            let last_index = tx_graph.last_index(TxType::HtlcTimeout) + 1;
            tx_graph.insert_tx(
                TxType::HtlcTimeout,
                last_index as u64 + index,
                htlc_tx,
            );

            accumulate += offered.amount / 1000;
        }

        // Process received HTLCs
        for (index, recieved) in self.received_htlcs.iter() {
            let htlc_output: Output = ScriptGenerators::ln_received_htlc(
                recieved.amount / 1000,
                self.remote_revocation_basepoint,
                self.local_basepoint,
                self.remote_basepoint,
                recieved.cltv_expiry,
                recieved.hashlock,
            );

            // Sum amounts to same OutPoints
            match tx_graph.cmt_outs.iter().position(|out| {
                out.script == htlc_output.script
                    && out.witness_script == htlc_output.witness_script
            }) {
                Some(index) => {
                    let mut htlc_output = tx_graph.cmt_outs.remove(index);
                    htlc_output.amount += recieved.amount;
                    tx_graph.cmt_outs.insert(index, htlc_output);
                }
                _ => tx_graph.cmt_outs.push(htlc_output),
            };

            let htlc_tx = Psbt::ln_htlc(
                recieved.amount,
                // TODO: do a two-staged graph generation process
                OutPoint::default(),
                recieved.cltv_expiry,
                self.remote_revocation_basepoint,
                self.local_delayed_basepoint,
                self.to_self_delay,
            );
            // Figure out the last index of transaction in graph
            let last_index = tx_graph.last_index(TxType::HtlcSuccess) + 1;
            tx_graph.insert_tx(
                TxType::HtlcSuccess,
                last_index as u64 + index,
                htlc_tx,
            );

            accumulate += recieved.amount / 1000;
        }

        // Subtracts from the total amount of the commitment transaction
        if accumulate > 0 {
            let mut refund_tx = tx_graph.cmt_outs.remove(0);
            refund_tx.amount -= accumulate;

            tx_graph.cmt_outs.insert(tx_graph.cmt_outs.len(), refund_tx);
        }

        Ok(())
    }
}

pub trait ScriptGenerators {
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        payment_hash: HashLock,
    ) -> Self;

    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self;

    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self;
}

impl ScriptGenerators for LockScript {
    fn ln_offered_htlc(
        _: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        payment_hash: HashLock,
    ) -> Self {
        script::Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(
                &bitcoin::PublicKey::new(revocationpubkey).pubkey_hash(),
            )
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_key(&bitcoin::PublicKey::new(remote_htlcpubkey))
            .push_opcode(OP_SWAP)
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_NOTIF)
            .push_opcode(OP_DROP)
            .push_int(2)
            .push_opcode(OP_SWAP)
            .push_key(&bitcoin::PublicKey::new(local_htlcpubkey))
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .push_opcode(OP_ELSE)
            .push_opcode(OP_HASH160)
            .push_slice(payment_hash.as_ref())
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_ENDIF)
            .into_script()
            .into()
    }

    fn ln_received_htlc(
        _: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self {
        script::Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(
                &bitcoin::PublicKey::new(revocationpubkey).pubkey_hash(),
            )
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_key(&bitcoin::PublicKey::new(remote_htlcpubkey))
            .push_opcode(OP_SWAP)
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_HASH160)
            .push_slice(payment_hash.as_ref())
            .push_opcode(OP_EQUALVERIFY)
            .push_int(2)
            .push_opcode(OP_SWAP)
            .push_key(&bitcoin::PublicKey::new(local_htlcpubkey))
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .push_opcode(OP_ELSE)
            .push_opcode(OP_DROP)
            .push_int(cltv_expiry as i64)
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_ENDIF)
            .into_script()
            .into()
    }

    fn ln_htlc_output(
        _: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        script::Builder::new()
            .push_opcode(OP_IF)
            .push_key(&bitcoin::PublicKey::new(revocationpubkey))
            .push_opcode(OP_ELSE)
            .push_int(to_self_delay as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_key(&bitcoin::PublicKey::new(local_delayedpubkey))
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_CHECKSIG)
            .into_script()
            .into()
    }
}

impl ScriptGenerators for WitnessScript {
    #[inline]
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        payment_hash: HashLock,
    ) -> Self {
        LockScript::ln_offered_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            payment_hash,
        )
        .into()
    }

    #[inline]
    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self {
        LockScript::ln_received_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            cltv_expiry,
            payment_hash,
        )
        .into()
    }

    #[inline]
    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        LockScript::ln_htlc_output(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .into()
    }
}

impl ScriptGenerators for PubkeyScript {
    #[inline]
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        payment_hash: HashLock,
    ) -> Self {
        WitnessScript::ln_offered_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            payment_hash,
        )
        .to_p2wsh()
    }

    #[inline]
    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self {
        WitnessScript::ln_received_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            cltv_expiry,
            payment_hash,
        )
        .to_p2wsh()
    }

    #[inline]
    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        WitnessScript::ln_htlc_output(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .to_p2wsh()
    }
}

impl ScriptGenerators for TxOut {
    #[inline]
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        payment_hash: HashLock,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_offered_htlc(
                amount,
                revocationpubkey,
                local_htlcpubkey,
                remote_htlcpubkey,
                payment_hash,
            )
            .into(),
        }
    }

    #[inline]
    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_received_htlc(
                amount,
                revocationpubkey,
                local_htlcpubkey,
                remote_htlcpubkey,
                cltv_expiry,
                payment_hash,
            )
            .into(),
        }
    }

    #[inline]
    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_htlc_output(
                amount,
                revocationpubkey,
                local_delayedpubkey,
                to_self_delay,
            )
            .into(),
        }
    }
}

impl ScriptGenerators for psbt::Output {
    #[inline]
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        payment_hash: HashLock,
    ) -> Self {
        let witness_script = WitnessScript::ln_offered_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            payment_hash,
        )
        .into();
        let txout = TxOut::ln_offered_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            payment_hash,
        );
        let output = bitcoin::psbt::Output {
            witness_script: Some(witness_script),
            ..Default::default()
        };
        psbt::Output::with(0, output, txout)
    }

    #[inline]
    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self {
        let witness_script = WitnessScript::ln_received_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            cltv_expiry,
            payment_hash,
        )
        .into();
        let txout = TxOut::ln_received_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            cltv_expiry,
            payment_hash,
        );
        let output = bitcoin::psbt::Output {
            witness_script: Some(witness_script),
            ..Default::default()
        };
        psbt::Output::with(0, output, txout)
    }

    #[inline]
    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        let witness_script = WitnessScript::ln_htlc_output(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .into();
        let txout = TxOut::ln_htlc_output(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        );
        let output = bitcoin::psbt::Output {
            witness_script: Some(witness_script),
            ..Default::default()
        };
        psbt::Output::with(0, output, txout)
    }
}

pub trait TxGenerators {
    fn ln_htlc(
        amount: u64,
        outpoint: OutPoint,
        cltv_expiry: u32,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self;
}

impl TxGenerators for Transaction {
    /// NB: For HTLC Success transaction always set `cltv_expiry` parameter
    ///     to zero!
    fn ln_htlc(
        amount: u64,
        outpoint: OutPoint,
        cltv_expiry: u32,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        let txout = TxOut::ln_htlc_output(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        );
        Transaction {
            version: 2,
            lock_time: bitcoin::PackedLockTime(cltv_expiry),
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: none!(),
                sequence: bitcoin::Sequence(0),
                witness: empty!(),
            }],
            output: vec![txout],
        }
    }
}

impl TxGenerators for Psbt {
    fn ln_htlc(
        amount: u64,
        outpoint: OutPoint,
        cltv_expiry: u32,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        let output = psbt::Output::ln_htlc_output(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        );

        let mut psbt = Psbt::with(
            Transaction::ln_htlc(
                amount,
                outpoint,
                cltv_expiry,
                revocationpubkey,
                local_delayedpubkey,
                to_self_delay,
            ),
            PsbtVersion::V0,
        )
        .expect("Tx has empty sigs so PSBT creation does not fail");
        psbt.outputs[0] = output;
        psbt
    }
}
