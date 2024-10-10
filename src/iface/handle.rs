// SPDX-License-Identifier: MIT

use crate::{Nl80211Handle, Nl80211InterfaceGetRequest};

use super::set::{Nl80211InterfaceSetChannelRequest, Nl80211InterfaceSetRequest};

pub struct Nl80211InterfaceHandle(Nl80211Handle);

impl Nl80211InterfaceHandle {
    pub fn new(handle: Nl80211Handle) -> Self {
        Nl80211InterfaceHandle(handle)
    }

    /// Retrieve the wireless interfaces
    /// (equivalent to `iw dev`)
    pub fn get(&mut self) -> Nl80211InterfaceGetRequest {
        Nl80211InterfaceGetRequest::new(self.0.clone())
    }

    /// Set wireless interface info
    /// capable of setting monitor, station, other type, or mac:
    /// .with_mon()
    /// .with_station()
    /// .with_mode(Nl80211IfType)
    /// (equivalent to `iw dev set`)
    pub fn set(&mut self, index: u32) -> Nl80211InterfaceSetRequest {
        Nl80211InterfaceSetRequest::new(self.0.clone(), index)
    }

    /// Set wireless interface info
    /// (equivalent to `iw dev set channel`)
    /// as_channel(freq: u32) // 20Mhz Channel
    /// as_ht40_plus_channel(freq: u32) // HT40+ Channel
    /// as_ht40_minus_channel(freq: u32) // HT40- Channel
    /// as_vht80_channel(freq: u32, center_freq1: u32) // VHT 80MHz Channel
    /// as_vht160_channel(freq: u32, center_freq1: u32) // VHT 160 Channel
    /// as_vht80p80_channel(freq: u32, center_freq1: u32, center_freq2: u32) // VHT 80+80 Mhz
    /// as_eht320_channel(freq: u32, center_freq1: u32) // EHT 320MHz Channel
    pub fn channel_set(&mut self, index: u32) -> Nl80211InterfaceSetChannelRequest {
        Nl80211InterfaceSetChannelRequest::new(self.0.clone(), index)
    }
}
