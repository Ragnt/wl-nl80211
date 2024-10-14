use netlink_packet_utils::{DecodeError, Emitable};

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211RegDomType {
    Country = 0,
    World = 1,
    CustomWorld = 2,
    Intersection = 3,
    Other(u8)
}

impl Nl80211RegDomType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Nl80211RegDomType::Country,
            1 => Nl80211RegDomType::World,
            2 => Nl80211RegDomType::CustomWorld,
            3 => Nl80211RegDomType::Intersection,
            _ => Nl80211RegDomType::Other(value),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Nl80211RegDomType::Country => 0,
            Nl80211RegDomType::World => 1,
            Nl80211RegDomType::CustomWorld => 2,
            Nl80211RegDomType::Intersection => 3,
            Nl80211RegDomType::Other(x) => x,
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::from_u8(buf[0]))
    }
}


impl Emitable for Nl80211RegDomType {
    fn buffer_len(&self) -> usize {
        1
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = self.to_u8();
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211RegdomInitiator {
    Core = 0,
    User = 1,
    Driver = 2,
    CountryIE = 3,
    Other(u8),
}

impl Nl80211RegdomInitiator {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Nl80211RegdomInitiator::Core,
            1 => Nl80211RegdomInitiator::User,
            2 => Nl80211RegdomInitiator::Driver,
            3 => Nl80211RegdomInitiator::CountryIE,
            _ => Nl80211RegdomInitiator::Other(value),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Nl80211RegdomInitiator::Core => 0,
            Nl80211RegdomInitiator::User => 1,
            Nl80211RegdomInitiator::Driver => 2,
            Nl80211RegdomInitiator::CountryIE => 3,
            Nl80211RegdomInitiator::Other(x) => x,
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::from_u8(buf[0]))
    }
}

impl Emitable for Nl80211RegdomInitiator {
    fn buffer_len(&self) -> usize {
        1
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = self.to_u8();
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211DfsRegion {
    Unset = 0,
    FCC = 1,
    ETSI = 2,
    JP = 3,
    CN = 4,
    Unknown(u8),
}

impl Nl80211DfsRegion {
    /// Converts a `u8` value to `Nl80211DfsRegion`.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Nl80211DfsRegion::Unset,
            1 => Nl80211DfsRegion::FCC,
            2 => Nl80211DfsRegion::ETSI,
            3 => Nl80211DfsRegion::JP,
            4 => Nl80211DfsRegion::CN,
            _ => Nl80211DfsRegion::Unknown(value),
        }
    }

    /// Converts `Nl80211DfsRegion` to a `u8` value.
    pub fn to_u8(self) -> u8 {
        match self {
            Nl80211DfsRegion::Unset => 0,
            Nl80211DfsRegion::FCC => 1,
            Nl80211DfsRegion::ETSI => 2,
            Nl80211DfsRegion::JP => 3,
            Nl80211DfsRegion::CN => 4,
            Nl80211DfsRegion::Unknown(value) => value,
        }
    }

    /// Parses the DFS region from a byte slice.
    pub fn parse(buf: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::from_u8(buf[0]))
    }
}

impl Emitable for Nl80211DfsRegion {
    fn buffer_len(&self) -> usize {
        1
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = self.to_u8();
    }
}
