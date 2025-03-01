// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211Command, Nl80211Error, Nl80211Handle, Nl80211Message
};

use super::Nl80211InterfaceType;

pub struct Nl80211InterfaceNewRequest {
    handle: Nl80211Handle,
    attrs: Vec<Nl80211Attr>
}

impl Nl80211InterfaceNewRequest {
    // Create a new VIF for a specific interface via index
    pub fn new(handle: Nl80211Handle, index: u32, name: String, mode: Nl80211InterfaceType) -> Self {
        Nl80211InterfaceNewRequest { handle, attrs: vec![Nl80211Attr::IfIndex(index), Nl80211Attr::IfName(name), Nl80211Attr::IfType(mode)] }
    }

    /// Create new ViF as station
    pub fn as_station(mut self, index: u32, name: String) -> Self {
        self.attrs = vec![Nl80211Attr::IfIndex(index), Nl80211Attr::IfName(name), Nl80211Attr::IfType(Nl80211InterfaceType::Station)];
        self
    }

    /// Create new ViF as ap
    pub fn as_ap(mut self, index: u32, name: String) -> Self {
        self.attrs = vec![Nl80211Attr::IfIndex(index), Nl80211Attr::IfName(name), Nl80211Attr::IfType(Nl80211InterfaceType::Ap)];
        self
    }

    /// Create new ViF as Monitor
    pub fn as_monitor(mut self, index: u32, name: String) -> Self {
        self.attrs = vec![Nl80211Attr::IfIndex(index), Nl80211Attr::IfName(name), Nl80211Attr::IfType(Nl80211InterfaceType::Monitor)];
        self
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211InterfaceNewRequest { mut handle, attrs } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::SetInterface,
            attributes: attrs,
        };        
        
        let flags = NLM_F_REQUEST;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}

pub struct Nl80211InterfaceDelRequest {
    handle: Nl80211Handle,
    attrs: Vec<Nl80211Attr>
}

impl Nl80211InterfaceDelRequest {
    // Delete a VIF
    pub fn new(handle: Nl80211Handle, index: u32) -> Self {
        Nl80211InterfaceDelRequest { handle, attrs: vec![Nl80211Attr::IfIndex(index)] }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211InterfaceDelRequest { mut handle, attrs } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::DelInterface,
            attributes: attrs,
        };        
        
        let flags = NLM_F_REQUEST;

        nl80211_execute(&mut handle, nl80211_msg, flags).await
    }
}