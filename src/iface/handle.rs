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
    pub fn channel_set(&mut self, index: u32) -> Nl80211InterfaceSetChannelRequest {
        Nl80211InterfaceSetChannelRequest::new(self.0.clone(), index)
    }
}
