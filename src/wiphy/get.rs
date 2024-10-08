// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_generic::GenlMessage;

use crate::{
    nl80211_execute, Nl80211Attr, Nl80211Command, Nl80211Error, Nl80211Handle,
    Nl80211Message,
};

pub struct Nl80211WiphyGetRequest {
    handle: Nl80211Handle,
    message: Nl80211Message,
    dump: bool,
}

impl Nl80211WiphyGetRequest {
    pub(crate) fn new(handle: Nl80211Handle) -> Self {
        Nl80211WiphyGetRequest { 
            handle,
            message: Nl80211Message { 
                cmd: Nl80211Command::GetWiphy, 
                attributes: vec![Nl80211Attr::SplitWiphyDump]
            },
            dump: true
        }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211WiphyGetRequest { mut handle, message, dump } = self;

        nl80211_execute(&mut handle, message, dump).await
    }

    /// Lookup a wiphy by index
    pub fn match_index(mut self, index: u32) -> Self {
        self.dump = false;
        self.message.attributes.push(Nl80211Attr::Wiphy(index));
        self
    }

    /// Lookup a wiphy by name
    pub fn match_name(mut self, name: String) -> Self {
        self.dump = false;
        self.message.attributes.push(Nl80211Attr::WiphyName(name));
        self
    }
}
