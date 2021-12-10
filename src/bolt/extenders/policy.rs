// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
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

use lnp2p::legacy::Messages;

use crate::bolt::ExtensionId;
use crate::{channel, ChannelExtension, Extension};

/// The role of policy extension is to make sure that aggregate properties
/// of the transaction (no of HTLCs, fees etc) does not violate channel
/// policies – and adjust to these policies if needed
///
/// NB: Policy must always be applied after other extenders, which is guaranteed
/// by the [`ExtensionId::Policy`] value.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct Policy {
    /// The maximum inbound HTLC value in flight towards sender, in
    /// milli-satoshi
    max_htlc_value_in_flight_msat: u64,

    /// Accumulated inbound HTLC value
    total_htlc_value_in_flight_msat: u64,

    /// The minimum value unencumbered by HTLCs for the counterparty to keep in
    /// the channel
    channel_reserve_satoshis: u64,

    /// The maximum number of inbound HTLCs towards sender
    max_accepted_htlcs: u16,
}

impl channel::State for Policy {}

impl Extension for Policy {
    type Identity = ExtensionId;

    #[inline]
    fn new() -> Box<dyn ChannelExtension<Identity = Self::Identity>>
    where
        Self: Sized,
    {
        Box::new(Policy::default())
    }

    #[inline]
    fn identity(&self) -> Self::Identity {
        ExtensionId::Policy
    }

    #[inline]
    fn update_from_peer(
        &mut self,
        message: &Messages,
    ) -> Result<(), channel::Error> {
        match message {
            Messages::OpenChannel(open_channel) => {
                self.max_htlc_value_in_flight_msat =
                    open_channel.max_htlc_value_in_flight_msat;
                self.channel_reserve_satoshis =
                    open_channel.channel_reserve_satoshis;
                self.max_accepted_htlcs = open_channel.max_accepted_htlcs;
            }
            Messages::AcceptChannel(accept_channel) => {
                self.max_htlc_value_in_flight_msat =
                    accept_channel.max_htlc_value_in_flight_msat;
                self.channel_reserve_satoshis =
                    accept_channel.channel_reserve_satoshis;
                self.max_accepted_htlcs = accept_channel.max_accepted_htlcs;
            }
            Messages::UpdateFee(_) => {}
            Messages::UpdateAddHtlc(_message) => {
                /* TODO:
                self.total_htlc_value_in_flight_msat += message.amount_msat;
                if total_htlc_value_in_flight_msat
                    > self.max_htlc_value_in_flight_msat
                {
                    return Err(channel::Error::Htlc(
                        "max HTLC inflight amount limit exceeded".to_string(),
                    ));
                }
                 */
            }
            Messages::UpdateFulfillHtlc(_message) => {}
            Messages::UpdateFailMalformedHtlc(_message) => {}
            Messages::UpdateFailHtlc(_message) => {}
            _ => {}
        }
        Ok(())
    }

    #[inline]
    fn extension_state(&self) -> Box<dyn channel::State> {
        Box::from(self.clone())
    }
}

// TODO: Implement necessary checks on the global channel state

impl ChannelExtension for Policy {
    #[inline]
    fn channel_state(&self) -> Box<dyn channel::State> {
        Box::from(self.clone())
    }

    #[inline]
    fn apply(
        &mut self,
        _tx_graph: &mut channel::TxGraph,
    ) -> Result<(), channel::Error> {
        // TODO: Implement HTLC finalizer checking channel policies
        Ok(())
    }
}
