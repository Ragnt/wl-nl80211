// SPDX-License-Identifier: MIT

use futures::TryStream;
use netlink_packet_generic::GenlMessage;

use crate::{nl80211_execute, reg::{Nl80211RegDomType, Nl80211RegdomInitiator}, Nl80211Attr, Nl80211Command, Nl80211Error, Nl80211FrameType, Nl80211Handle, Nl80211Message};

// The command types in this file are specific to AP-mode operation (there is probably other use-cases, but the goal here is eventually parity with hostapd)

/// Prepare and send a CMD_REGISTER_FRAME - used for AP operations to register for authentication Et al.;
pub struct Nl80211RegisterFrame {
    handle: Nl80211Handle,
    message: Nl80211Message,
    dump: bool,
}

/*
General Format
Match Length: The length of the match data determines how specific the match is.
Length 1: Matches on the Category field only.
Length 2: Matches on Category and Action Code.
Decoding the Match Values
04

Length: 1 byte
Category: 0x04
Meaning: Public Action Frames
Used for various public actions like spectrum management, radio measurement, etc.
0501

Length: 2 bytes
Category: 0x05 (Radio Measurement)
Action Code: 0x01 (Neighbor Report Request)
Meaning: Specific Radio Measurement action frame for Neighbor Report Request.
0503

Category: 0x05 (Radio Measurement)
Action Code: 0x03 (Link Measurement Request)
Meaning: Specific action frame for Link Measurement Request.
0504

Category: 0x05 (Radio Measurement)
Action Code: 0x04 (Link Measurement Report)
Meaning: Specific action frame for Link Measurement Report.
06

Category: 0x06 (Fast BSS Transition - FT)
Meaning: Frames related to Fast BSS Transition (802.11r), used for fast roaming.
08

Category: 0x08 (Spectrum Management)
Meaning: Frames for spectrum management, such as Channel Switch Announcements.
09

Category: 0x09 (High Throughput - HT)
Meaning: Frames related to HT features (802.11n), like notifying about SM Power Save mode.
0a

Category: 0x0A (SA Query)
Meaning: Security Association Query frames, used in security protocols like 802.11w.
11

Category: 0x11 (Protected Dual of Public Action)
Meaning: Protected versions of Public Action frames, used with management frame protection.
12

Category: 0x12 (Wireless Network Management - WNM)
Meaning: Frames for WNM features like BSS Transition Management Requests.
7f

Category: 0x7F (Vendor-Specific)
Meaning: Vendor-specific action frames.

*/

impl Nl80211RegisterFrame {
    pub(crate) fn new(handle: Nl80211Handle, index: u32, frame_type: Nl80211FrameType) -> Self {
        Nl80211RegisterFrame { 
            handle,
            message: Nl80211Message {
                cmd: Nl80211Command::RegisterFrame,
                attributes: vec![Nl80211Attr::IfIndex(index), Nl80211Attr::FrameType(frame_type), ],
            },
            dump: false,
        }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211RegisterFrame { mut handle, message, dump } = self;

        nl80211_execute(&mut handle, message, dump).await
    }

}

/// Prepare and send a CMD_GET_REG - used to request the regulatory domain
pub struct Nl80211GetRegulatory {
    handle: Nl80211Handle,
    message: Nl80211Message,
    dump: bool,
}

impl Nl80211GetRegulatory {
    pub(crate) fn new(handle: Nl80211Handle) -> Self {
        Nl80211GetRegulatory { 
            handle,
            message: Nl80211Message {
                cmd: Nl80211Command::GetReg,
                attributes: vec![],
            },
            dump: false,
        }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211GetRegulatory { mut handle, message, dump } = self;

        nl80211_execute(&mut handle, message, dump).await
    }

}

/// Prepare and send a CMD_REQ_SET_REG - used to request a change to regulatory domain
pub struct Nl80211ReqSetRegulatory {
    handle: Nl80211Handle,
    message: Nl80211Message,
    dump: bool,
}

impl Nl80211ReqSetRegulatory {
    pub(crate) fn new(handle: Nl80211Handle, alpha2: String) -> Self {
        Nl80211ReqSetRegulatory { 
            handle,
            message: Nl80211Message {
                cmd: Nl80211Command::ReqSetReg,
                attributes: vec![Nl80211Attr::RegAlpha2(alpha2)],
            },
            dump: false,
        }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211ReqSetRegulatory { mut handle, message, dump } = self;

        nl80211_execute(&mut handle, message, dump).await
    }

}

/// Prepare and send a CMD_REG_CHANGE - used to change to regulatory domain
pub struct Nl80211RegChange {
    handle: Nl80211Handle,
    message: Nl80211Message,
    dump: bool,
}

impl Nl80211RegChange {
    pub(crate) fn new(handle: Nl80211Handle, alpha2: String) -> Self {
        Nl80211RegChange { 
            handle,
            message: Nl80211Message {
                cmd: Nl80211Command::RegChange,
                attributes: vec![Nl80211Attr::RegAlpha2(alpha2), Nl80211Attr::RegType(Nl80211RegDomType::Country), Nl80211Attr::RegInitiator(Nl80211RegdomInitiator::User)],
            },
            dump: false,
        }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211RegChange { mut handle, message, dump } = self;

        nl80211_execute(&mut handle, message, dump).await
    }

}

