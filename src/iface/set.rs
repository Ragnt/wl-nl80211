// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211Command, Nl80211Error, Nl80211Handle, Nl80211Message
};

pub struct Nl80211InterfaceSetRequest {
    handle: Nl80211Handle,
    attrs: Vec<Nl80211Attr>
}

impl Nl80211InterfaceSetRequest {
    pub(crate) fn new(handle: Nl80211Handle, attrs: Vec<Nl80211Attr>) -> Self {
        Nl80211InterfaceSetRequest { handle, attrs }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211InterfaceSetRequest { mut handle, mut attrs } = self;

        let nl80211_msg = Nl80211Message {
            cmd: Nl80211Command::SetInterface,
            attributes: attrs,
        };
        nl80211_execute(&mut handle, nl80211_msg, false).await
    }
}

