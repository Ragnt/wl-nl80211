// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211ChannelWidth, Nl80211Command, Nl80211Error, Nl80211Handle, Nl80211HtWiphyChannelType, Nl80211Message
};

use super::Nl80211InterfaceType;

pub struct Nl80211InterfaceSetRequest {
    handle: Nl80211Handle,
    attrs: Vec<Nl80211Attr>
}

impl Nl80211InterfaceSetRequest {
    // Create a set for a specific interface via index
    pub fn new(handle: Nl80211Handle, index: u32) -> Self {
        Nl80211InterfaceSetRequest { handle, attrs: vec![Nl80211Attr::IfIndex(index)] }
    }

    /// Set iftype of the interface
    pub fn with_mode(mut self, mode: Nl80211InterfaceType) -> Self {
        let attr = Nl80211Attr::IfType(mode);
        self.attrs.push(attr);
        self
    }

    /// Set monitor mode
    pub fn with_mon(mut self) -> Self {
        let attr = Nl80211Attr::IfType(Nl80211InterfaceType::Monitor);
        self.attrs.push(attr);
        self
    }

    // Set station mode
    pub fn with_station(mut self) -> Self {
        let attr = Nl80211Attr::IfType(Nl80211InterfaceType::Station);
        self.attrs.push(attr);
        self
    }

    // Set ap mode
    pub fn with_ap(mut self) -> Self {
        let attr = Nl80211Attr::IfType(Nl80211InterfaceType::Ap);
        self.attrs.push(attr);
        self
    }

    // Set mac address
    pub fn with_mac(mut self, mac: &[u8; 6]) -> Self {
        let attr = Nl80211Attr::Mac(*mac);
        self.attrs.push(attr);
        self
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211InterfaceSetRequest { mut handle, attrs } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::SetInterface,
            attributes: attrs,
        };
        
        let flags = NLM_F_REQUEST | NLM_F_ACK;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
        
    }
}

pub struct Nl80211InterfaceSetChannelRequest {
    handle: Nl80211Handle,
    attrs: Vec<Nl80211Attr>
}

impl Nl80211InterfaceSetChannelRequest {
    // Create a set for a specific interface via index
    pub fn new(handle: Nl80211Handle, index: u32) -> Self {
        Nl80211InterfaceSetChannelRequest { handle, attrs: vec![Nl80211Attr::IfIndex(index)] }
    }

    /// Set frequency of the interface
    pub fn with_frequency(mut self, freq: u32) -> Self {
        let attr = Nl80211Attr::WiphyFreq(freq);
        self.attrs.push(attr);
        self
    }

    /// Set channel width of the interface
    pub fn with_channel_width(mut self, width: Nl80211ChannelWidth) -> Self {
        let attr = Nl80211Attr::ChannelWidth(width);
        self.attrs.push(attr);
        self
    }

    /// Set HT channel type of the interface
    pub fn with_channel_type(mut self, chan_type: Nl80211HtWiphyChannelType) -> Self {
        let attr = Nl80211Attr::WiphyChannelType(chan_type);
        self.attrs.push(attr);
        self
    }

    /// Set freq1 for VHT channel
    pub fn with_center_freq1(mut self, freq: u32) -> Self {
        let attr = Nl80211Attr::CenterFreq1(freq);
        self.attrs.push(attr);
        self
    }

    /// Set freq2 for VHT channel
    pub fn with_center_freq2(mut self, freq: u32) -> Self {
        let attr = Nl80211Attr::CenterFreq2(freq);
        self.attrs.push(attr);
        self
    }

    /// Set basic 20MHz channel (no HT)
    pub fn as_channel(self, freq: u32) -> Self {
        self.clear_except_ifindex()
            .with_frequency(freq)
            .with_channel_width(Nl80211ChannelWidth::NoHt20)
    }

    /// Set HT40+ channel
    pub fn as_ht40_plus_channel(self, freq: u32) -> Self {
        self.clear_except_ifindex()
            .with_frequency(freq)
            .with_channel_width(Nl80211ChannelWidth::Mhz(40))
            .with_channel_type(Nl80211HtWiphyChannelType::Ht40Plus)
    }

    /// Set HT40- channel
    pub fn as_ht40_minus_channel(self, freq: u32) -> Self {
        self.clear_except_ifindex()
            .with_frequency(freq)
            .with_channel_width(Nl80211ChannelWidth::Mhz(40))
            .with_channel_type(Nl80211HtWiphyChannelType::Ht40Minus)
    }

    /// Set VHT 80MHz channel
    pub fn as_vht80_channel(self, freq: u32, center_freq1: u32) -> Self {
        self.clear_except_ifindex()
            .with_frequency(freq)
            .with_channel_width(Nl80211ChannelWidth::Mhz(80))
            .with_center_freq1(center_freq1)
    }

    /// Set VHT 160MHz channel
    pub fn as_vht160_channel(self, freq: u32, center_freq1: u32) -> Self {
        self.clear_except_ifindex()
            .with_frequency(freq)
            .with_channel_width(Nl80211ChannelWidth::Mhz(160))
            .with_center_freq1(center_freq1)
    }

    /// Set VHT 80+80MHz channel
    pub fn as_vht80p80_channel(self, freq: u32, center_freq1: u32, center_freq2: u32) -> Self {
        self.clear_except_ifindex()
            .with_frequency(freq)
            .with_channel_width(Nl80211ChannelWidth::Mhz80Plus80)
            .with_center_freq1(center_freq1)
            .with_center_freq2(center_freq2)
    }

    /// Set EHT 320MHz channel
    pub fn as_eht320_channel(self, freq: u32, center_freq1: u32) -> Self {
        self.clear_except_ifindex()
            .with_frequency(freq)
            .with_channel_width(Nl80211ChannelWidth::Mhz(320))
            .with_center_freq1(center_freq1)
    }

    /// Clear all attributes except IfIndex
    pub fn clear_except_ifindex(mut self) -> Self {
        self.attrs.retain(|attr| matches!(attr, Nl80211Attr::IfIndex(_)));
        self
    }
    
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211InterfaceSetChannelRequest { mut handle, attrs } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::SetChannel,
            attributes: attrs,
        };
        
        let flags = NLM_F_REQUEST | NLM_F_ACK;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}

