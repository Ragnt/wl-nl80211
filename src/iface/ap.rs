// SPDX-License-Identifier: MIT

use std::any::Any;

use futures::TryStream;
use log::debug;
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;
use netlink_packet_utils::Emitable;

use crate::{element::{Nl80211AkmSuite, Nl80211AuthType}, nl80211_execute, reg::{Nl80211RegDomType, Nl80211RegdomInitiator}, Nl80211Attr, Nl80211BssCapabilities, Nl80211ChannelWidth, Nl80211CipherSuite, Nl80211Command, Nl80211Element, Nl80211Elements, Nl80211Error, Nl80211FrameType, Nl80211Handle, Nl80211Message};

// The command types in this file are specific to AP-mode operation (there is probably other use-cases, but the goal here is eventually parity with hostapd)

/// Prepare and send a CMD_REGISTER_FRAME - used for AP operations to register for authentication Et al.;
pub struct Nl80211RegisterFrame {
    handle: Nl80211Handle,
    message: Nl80211Message,
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
    pub fn new(
        handle: Nl80211Handle,
        index: u32,
        frame_type: Nl80211FrameType,
        frame_match: Vec<u8>, // Accept frame match data
    ) -> Self {
        Nl80211RegisterFrame { 
            handle,
            message: Nl80211Message {
                cmd: Nl80211Command::RegisterFrame,
                attributes: vec![
                    Nl80211Attr::IfIndex(index),
                    Nl80211Attr::FrameType(frame_type),
                    Nl80211Attr::FrameMatch(frame_match), // Include the frame match data
                ],
            },
        }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211RegisterFrame { mut handle, message } = self;

        nl80211_execute(&mut handle, message, NLM_F_REQUEST | NLM_F_ACK).await
    }
}


/// Prepare and send a CMD_GET_REG - used to request the regulatory domain
pub struct Nl80211GetRegulatory {
    handle: Nl80211Handle,
    message: Nl80211Message,
}

impl Nl80211GetRegulatory {
    pub(crate) fn new(handle: Nl80211Handle) -> Self {
        Nl80211GetRegulatory { 
            handle,
            message: Nl80211Message {
                cmd: Nl80211Command::GetReg,
                attributes: vec![],
            },
        }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211GetRegulatory { mut handle, message } = self;
        
        nl80211_execute(&mut handle, message, NLM_F_REQUEST).await
    }

}

/// Prepare and send a CMD_REQ_SET_REG - used to request a change to regulatory domain
pub struct Nl80211ReqSetRegulatory {
    handle: Nl80211Handle,
    message: Nl80211Message,
}

impl Nl80211ReqSetRegulatory {
    pub(crate) fn new(handle: Nl80211Handle, alpha2: String) -> Self {
        Nl80211ReqSetRegulatory { 
            handle,
            message: Nl80211Message {
                cmd: Nl80211Command::ReqSetReg,
                attributes: vec![Nl80211Attr::RegAlpha2(alpha2)],
            },
        }
    }

    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211ReqSetRegulatory { mut handle, message } = self;

        nl80211_execute(&mut handle, message, NLM_F_REQUEST).await
    }

}

// To set as an AP:
// Set AP Mode
// Set Regulatory Domain
// Set Channel and Width
// Send NL80211_CMD_START_AP 
// - Include attributes:
//   - NL80211_ATTR_SSID: SSID of the network.
//   - NL80211_ATTR_BEACON_INTERVAL: Time interval between beacons.
//   - NL80211_ATTR_DTIM_PERIOD: Delivery Traffic Indication Message period.
//   - NL80211_ATTR_BEACON_HEAD: Beacon frame components 
//   - NL80211_ATTR_BEACON_TAIL: Beacon frame components.
//   - NL80211_ATTR_WPA_VERSIONS: WPA versions supported.
//   - NL80211_ATTR_CIPHER_SUITES_PAIRWISE: Supported pairwise ciphers.
//   - NL80211_ATTR_AKM_SUITES: Supported authentication and key management suites.
//   - NL80211_ATTR_RSN_ENABLED: Enable RSN (Robust Security Network).
// Handle Client Associations and Authentications
// Operation: Manage client connections.
// Details:
//   Listen for Netlink events:
//    - NL80211_CMD_AUTHENTICATE: Client attempts to authenticate.
//    - NL80211_CMD_ASSOCIATE: Client attempts to associate.
//    - NL80211_CMD_DEAUTHENTICATE: Client deauthenticates.
//    - NL80211_CMD_DISASSOCIATE: Client disassociates.
//    - Respond accordingly by sending management frames using NL80211_CMD_FRAME
// Send Management Frames
// Operation: Communicate with clients using management frames.
// Details:
//    - Use NL80211_CMD_FRAME to send frames like authentication and association responses.
//    - Include attributes:
//      - NL80211_ATTR_FRAME: Raw frame data.
//      - NL80211_ATTR_MAC: Destination MAC address.
//      - NL80211_ATTR_WIPHY_FREQ: Frequency to send the frame on.

/// Struct to handle building and sending NL80211_CMD_START_AP
pub struct Nl80211StartAp {
    handle: Nl80211Handle,
    message: Nl80211Message,
}

impl Nl80211StartAp {
    /// Create a new instance with required attributes
    pub fn new(
        handle: Nl80211Handle,
        ifindex: u32,
        ssid: &String,
        freq: u32,
        channel_width: Nl80211ChannelWidth,
    ) -> Self {
        // Hardcoded values for DTIM period and Beacon Interval
        let dtim_period = 2;       // DTIM period
        let beacon_interval = 100; // Beacon interval in TUs

        let attributes = vec![
            Nl80211Attr::IfIndex(ifindex),
            Nl80211Attr::Ssid(ssid.to_string()),
            Nl80211Attr::HiddenSsid(0),
            Nl80211Attr::BeaconInterval(beacon_interval),
            Nl80211Attr::DtimPeriod(dtim_period),
            Nl80211Attr::WiphyFreq(freq),
            Nl80211Attr::ChannelWidth(channel_width),
            //Nl80211Attr::Pmk(Vec::new()),
            Nl80211Attr::ApSettingsFlags(1),
            Nl80211Attr::ControlPortOverNl80211,
            Nl80211Attr::SocketOwner,
            Nl80211Attr::ControlPortEthertype(34958),
            Nl80211Attr::ControlPortNoPreauth,
        ];

        Nl80211StartAp {
            handle,
            message: Nl80211Message {
                cmd: Nl80211Command::StartAp,
                attributes,
            },
        }
    }

    /// Add optional security settings
    pub fn set_security(
        &mut self,
        wpa_versions: u32,
        cipher_suites_pairwise: Vec<Nl80211CipherSuite>,
        cipher_suite_group: Nl80211CipherSuite,
        akm_suites: Vec<Nl80211AkmSuite>,
    ) {
        self.message.attributes.push(Nl80211Attr::WpaVersions(wpa_versions));
        self.message
            .attributes
            .push(Nl80211Attr::CipherSuitesPairwise(cipher_suites_pairwise));
        self.message
            .attributes
            .push(Nl80211Attr::CipherSuiteGroup(cipher_suite_group));
        self.message
            .attributes
            .push(Nl80211Attr::AkmSuites(akm_suites));
        self.message.attributes.push(Nl80211Attr::Privacy);
    }

    /// Set authentication type
    pub fn set_auth_type(&mut self, auth_type: Nl80211AuthType) {
        self.message.attributes.retain(|attr| !matches!(attr, Nl80211Attr::AuthType(_)));
        self.message.attributes.push(Nl80211Attr::AuthType(auth_type));
    }

    /// Set hidden SSID
    pub fn set_hidden_ssid(&mut self, hidden: bool) {
        self.message.attributes.retain(|attr| !matches!(attr, Nl80211Attr::HiddenSsid(_)));
        self.message.attributes.push(Nl80211Attr::HiddenSsid(1));
    }

    /// Add additional IEs
    pub fn add_ies(&mut self, ies: Nl80211Elements) {
        self.message.attributes.push(Nl80211Attr::Ie(ies));
    }

    /// Add additional IEs
    pub fn add_probe_resp_ies(&mut self, ies: Nl80211Elements) {
        self.message.attributes.push(Nl80211Attr::IeProbeResp(ies));
    }

    /// Add additional IEs
    pub fn add_assoc_resp_ies(&mut self, ies: Nl80211Elements) {
        self.message.attributes.push(Nl80211Attr::IeAssocResp(ies));
    }

    pub fn with_beacon_head(
        mut self,
        src_mac: [u8; 6],
        capabilities: Nl80211BssCapabilities,
        ssid: &str,
        supported_rates: &[u8],
        channel: u8,
    ) -> Self {
        let mut beacon_head = Vec::new();
    
        // Frame Control
        beacon_head.extend_from_slice(&[0x80, 0x00]);
    
        // Duration
        beacon_head.extend_from_slice(&[0x00, 0x00]);
    
        // Destination Address (Broadcast)
        beacon_head.extend_from_slice(&[0xFF; 6]);
    
        // Source Address
        beacon_head.extend_from_slice(&src_mac);
    
        // BSSID
        beacon_head.extend_from_slice(&src_mac);
    
        // Sequence Control
        beacon_head.extend_from_slice(&[0x00, 0x00]);
    
        // Timestamp
        beacon_head.extend_from_slice(&[0x00; 8]);
    
        // Beacon Interval
        beacon_head.extend_from_slice(&100u16.to_le_bytes());
    
        // Capability Information
        beacon_head.extend_from_slice(&capabilities.bits().to_le_bytes());
    
        // **Include SSID IE**
        let ssid_bytes = ssid.as_bytes();
        beacon_head.push(0x00); // SSID Element ID
        beacon_head.push(ssid_bytes.len() as u8); // SSID Length
        beacon_head.extend_from_slice(ssid_bytes); // SSID
    
        // **Include Supported Rates IE**
        beacon_head.push(0x01); // Supported Rates Element ID
        beacon_head.push(supported_rates.len() as u8); // Supported Rates Length
        beacon_head.extend_from_slice(supported_rates); // Supported Rates
    
        // **Include DS Parameter Set IE**
        beacon_head.push(0x03); // DS Parameter Set Element ID
        beacon_head.push(0x01); // Length
        beacon_head.push(channel); // Current Channel
    
        // Remove any existing BeaconHead attribute
        self.message.attributes.retain(|attr| !matches!(attr, Nl80211Attr::BeaconHead(_)));
    
        // Add the new BeaconHead attribute
        self.message.attributes.push(Nl80211Attr::BeaconHead(beacon_head));
        self
    }
    
    

    /*
    Example of creating IE's
    // Create IEs
    let ssid_ie = Nl80211Element::Ssid(ssid.clone());
    let supported_rates_ie = Nl80211Element::SupportedRatesAndSelectors(vec![
        Nl80211RateAndSelector::Rate(6),
        Nl80211RateAndSelector::Rate(9),
        Nl80211RateAndSelector::Rate(12),
        Nl80211RateAndSelector::Rate(18),
        Nl80211RateAndSelector::Rate(24),
        Nl80211RateAndSelector::Rate(36),
        Nl80211RateAndSelector::Rate(48),
        Nl80211RateAndSelector::Rate(54),
    ]);
    let ds_parameter_ie = Nl80211Element::Channel(1);

    // Create RSN IE
    let rsn_ie = Nl80211Element::Rsn(Nl80211ElementRsn {
        version: 1,
        group_cipher: Some(Nl80211CipherSuite::Ccmp128),
        pairwise_ciphers: vec![Nl80211CipherSuite::Ccmp128],
        akm_suits: vec![Nl80211AkmSuite::Psk],
        rsn_capbilities: Some(Nl80211RsnCapbilities::default()),
        ..Default::default()
    });

    // Compile the IEs into a slice
    let beacon_ies = Vec::new(
        ssid_ie,
        supported_rates_ie,
        ds_parameter_ie,
        rsn_ie,
    );
    */
    /// Set the beacon tail using high-level Information Elements
    pub fn with_beacon_tail(mut self, elements: &Vec<Nl80211Element>) -> Self {
        // Convert elements to raw bytes
        let beacon_elements = Nl80211Elements::from(elements);
        let buffer_len = beacon_elements.buffer_len();
        let mut beacon_tail_buffer = vec![0u8; buffer_len];
        beacon_elements.emit(&mut beacon_tail_buffer);

        debug!("Custom: {:?}", beacon_tail_buffer);

        // Remove any existing BeaconTail attribute
        self.message
            .attributes
            .retain(|attr| !matches!(attr, Nl80211Attr::BeaconTail(_)));

        // Add the new BeaconTail attribute
        self.message
            .attributes
            .push(Nl80211Attr::BeaconTail(beacon_tail_buffer));
        self
    }

    /// Set the beacon tail using raw bytes
    pub fn with_beacon_tail_raw(mut self, elements: &[u8]) -> Self {
        // Remove any existing BeaconTail attribute
        self.message
            .attributes
            .retain(|attr| !matches!(attr, Nl80211Attr::BeaconTail(_)));

        // Add the new BeaconTail attribute
        self.message
            .attributes
            .push(Nl80211Attr::BeaconTail(elements.to_vec()));
        self
    }

    
    pub async fn execute(
        self,
    ) -> impl TryStream<Ok = GenlMessage<Nl80211Message>, Error = Nl80211Error>
    {
        let Nl80211StartAp { mut handle, message } = self;

        debug!("CMD_START_AP message: {:#?}", message);

        nl80211_execute(&mut handle, message, NLM_F_REQUEST | NLM_F_ACK).await
    }
}
