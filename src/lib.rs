// SPDX-License-Identifier: MIT

mod attr;
mod channel;
mod command;
mod connection;
mod element;
mod error;
mod ext_cap;
mod feature;
mod frame_type;
mod handle;
mod iface;
mod macros;
mod message;
mod mlo;
mod scan;
mod station;
mod stats;
mod wifi4;
mod wifi5;
mod wifi6;
mod wifi7;
mod wiphy;

pub(crate) mod bytes;

pub use self::attr::Nl80211Attr;
pub use self::attr::{
    NL80211_ATTR_WIPHY,
    NL80211_ATTR_WIPHY_NAME,
    NL80211_ATTR_IFINDEX,
    NL80211_ATTR_IFNAME,
    NL80211_ATTR_IFTYPE,
    NL80211_ATTR_MAC,
    NL80211_ATTR_STA_INFO,
    NL80211_ATTR_WIPHY_BANDS,
    NL80211_ATTR_SUPPORTED_IFTYPES,
    NL80211_ATTR_WIPHY_FREQ,
    NL80211_ATTR_WIPHY_CHANNEL_TYPE,
    NL80211_ATTR_MAX_NUM_SCAN_SSIDS,
    NL80211_ATTR_GENERATION,
    NL80211_ATTR_BSS,
    NL80211_ATTR_SUPPORTED_COMMANDS,
    NL80211_ATTR_SSID,
    NL80211_ATTR_MAX_SCAN_IE_LEN,
    NL80211_ATTR_CIPHER_SUITES,
    NL80211_ATTR_WIPHY_RETRY_SHORT,
    NL80211_ATTR_WIPHY_RETRY_LONG,
    NL80211_ATTR_WIPHY_FRAG_THRESHOLD,
    NL80211_ATTR_WIPHY_RTS_THRESHOLD,
    NL80211_ATTR_4ADDR,
    NL80211_ATTR_MAX_NUM_PMKIDS,
    NL80211_ATTR_WIPHY_COVERAGE_CLASS,
    NL80211_ATTR_PS_STATE,
    NL80211_ATTR_WIPHY_TX_POWER_LEVEL,
    NL80211_ATTR_TX_FRAME_TYPES,
    NL80211_ATTR_RX_FRAME_TYPES,
    NL80211_ATTR_CONTROL_PORT_ETHERTYPE,
    NL80211_ATTR_SUPPORT_IBSS_RSN,
    NL80211_ATTR_WIPHY_ANTENNA_TX,
    NL80211_ATTR_WIPHY_ANTENNA_RX,
    NL80211_ATTR_OFFCHANNEL_TX_OK,
    NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION,
    NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX,
    NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX,
    NL80211_ATTR_SUPPORT_MESH_AUTH,
    NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED,
    NL80211_ATTR_INTERFACE_COMBINATIONS,
    NL80211_ATTR_SOFTWARE_IFTYPES,
    NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS,
    NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN,
    NL80211_ATTR_SUPPORT_AP_UAPSD,
    NL80211_ATTR_ROAM_SUPPORT,
    NL80211_ATTR_MAX_MATCH_SETS,
    NL80211_ATTR_TDLS_SUPPORT,
    NL80211_ATTR_TDLS_EXTERNAL_SETUP,
    NL80211_ATTR_FEATURE_FLAGS,
    NL80211_ATTR_PROBE_RESP_OFFLOAD,
    NL80211_ATTR_HT_CAPABILITY_MASK,
    NL80211_ATTR_WDEV,
    NL80211_ATTR_VHT_CAPABILITY,
    NL80211_ATTR_CHANNEL_WIDTH,
    NL80211_ATTR_CENTER_FREQ1,
    NL80211_ATTR_CENTER_FREQ2,
    NL80211_ATTR_MAC_ADDRS,
    NL80211_ATTR_EXT_CAPA,
    NL80211_ATTR_EXT_CAPA_MASK,
    NL80211_ATTR_SPLIT_WIPHY_DUMP,
    NL80211_ATTR_VHT_CAPABILITY_MASK,
    NL80211_ATTR_WIPHY_SELF_MANAGED_REG,
    NL80211_ATTR_EXT_FEATURES,
    NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS,
    NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL,
    NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS,
    NL80211_ATTR_IFTYPE_EXT_CAPA,
    NL80211_ATTR_BANDS,
    NL80211_ATTR_MAX_NUM_AKM_SUITES,
    NL80211_ATTR_EML_CAPABILITY,
    NL80211_ATTR_MLD_CAPA_AND_OPS,
    NL80211_ATTR_MAX_HW_TIMESTAMP_PEERS,
    NL80211_ATTR_WIPHY_FREQ_OFFSET,
    NL80211_ATTR_MLO_LINKS,
};
pub use self::channel::Nl80211ChannelWidth;
pub use self::command::Nl80211Command;
#[cfg(feature = "tokio_socket")]
pub use self::connection::new_connection;
pub use self::connection::new_connection_with_socket;
pub use self::element::Nl80211Element;
pub use self::error::Nl80211Error;
pub use self::ext_cap::{
    Nl80211ExtendedCapability, Nl80211IfTypeExtCapa, Nl80211IfTypeExtCapas,
};
pub use self::feature::{Nl80211ExtFeature, Nl80211Features};
pub use self::frame_type::{Nl80211FrameType, Nl80211IfaceFrameType};
pub use self::handle::Nl80211Handle;
pub use self::iface::{
    Nl80211IfaceComb, Nl80211IfaceCombAttribute, Nl80211IfaceCombLimit,
    Nl80211IfaceCombLimitAttribute, Nl80211InterfaceGetRequest,
    Nl80211InterfaceHandle, Nl80211InterfaceType,
};
pub use self::message::Nl80211Message;
pub use self::mlo::Nl80211MloLink;
pub use self::scan::{
    Nl80211BssCapabilities, Nl80211BssInfo, Nl80211BssUseFor,
    Nl80211ScanGetRequest, Nl80211ScanHandle,
};
pub use self::station::{
    Nl80211RateInfo, Nl80211StationGetRequest, Nl80211StationHandle,
    Nl80211StationInfo,
};
pub use self::stats::{
    NestedNl80211TidStats, Nl80211TidStats, Nl80211TransmitQueueStat,
};
pub use self::wifi4::{
    Nl80211ElementHtCap, Nl80211HtAMpduPara, Nl80211HtAselCaps,
    Nl80211HtCapabilityMask, Nl80211HtCaps, Nl80211HtExtendedCap,
    Nl80211HtMcsInfo, Nl80211HtTransmitBeamformingCaps, Nl80211HtTxParameter,
    Nl80211HtWiphyChannelType,
};
pub use self::wifi5::{
    Nl80211VhtCapInfo, Nl80211VhtCapability, Nl80211VhtMcsInfo,
};
pub use self::wifi6::{
    Nl80211He6GhzCapa, Nl80211HeMacCapInfo, Nl80211HeMcsNssSupp,
    Nl80211HePhyCapInfo, Nl80211HePpeThreshold,
};
pub use self::wifi7::{
    Nl80211EhtMacCapInfo, Nl80211EhtMcsNssSupp,
    Nl80211EhtMcsNssSuppMoreThan20Mhz, Nl80211EhtMcsNssSuppOnly20Mhz,
    Nl80211EhtPhyCapInfo, Nl80211EhtPpeThres,
};
pub use self::wiphy::{
    Nl80211Band, Nl80211BandInfo, Nl80211BandType, Nl80211BandTypes,
    Nl80211CipherSuite, Nl80211Frequency, Nl80211FrequencyInfo, Nl80211IfMode,
    Nl80211WiphyGetRequest, Nl80211WiphyHandle, Nl80211WowlanTcpTrigerSupport,
    Nl80211WowlanTrigerPatternSupport, Nl80211WowlanTrigersSupport,
};

pub(crate) use self::element::Nl80211Elements;
pub(crate) use self::feature::Nl80211ExtFeatures;
pub(crate) use self::handle::nl80211_execute;
pub(crate) use self::iface::Nl80211InterfaceTypes;
