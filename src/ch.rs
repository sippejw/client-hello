use crypto::digest::Digest;
use crypto::sha1::Sha1;
use byteorder::{ByteOrder, BigEndian};
use enum_primitive::FromPrimitive;
use hex_slice::AsHex;
use std::fmt;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TLSParseError {
    NotAHandshake,
    NotAClientHello,
    InnerOuterRecordLenContradict,
    UnknownChTLSVersion,
    SessionIDLenExceedBuf,
    CiphersuiteLenMisparse,
    CompressionLenExceedBuf,
    ExtensionsLenExceedBuf,
    ShortExtensionHeader,
    ExtensionLenExceedBuf,
    KeyShareExtShort,
    KeyShareExtLong,
    KeyShareExtLenMisparse,
    PskKeyExchangeModesExtShort,
    PskKeyExchangeModesExtLenMisparse,
    SupportedVersionsExtLenMisparse,
}

enum_from_primitive! {
 #[repr(u8)]
#[derive(PartialEq, Debug)]
pub enum TlsRecordType {
	ChangeCipherSpec = 20,
	Alert            = 21,
	Handshake        = 22,
	ApplicationData  = 23,
	Heartbeat        = 24,
}
}

enum_from_primitive! {
#[repr(u8)]
#[derive(PartialEq, Clone, Debug)]
pub enum TlsHandshakeType {
    HelloRequest       = 0,
	ClientHello        = 1,
	ServerHello        = 2,
	NewSessionTicket   = 4,
	Certificate        = 11,
	ServerKeyExchange  = 12,
	CertificateRequest = 13,
	ServerHelloDone    = 14,
	CertificateVerify  = 15,
	ClientKeyExchange  = 16,
	Finished           = 20,
	CertificateStatus  = 22,
	NextProtocol       = 67, // Not IANA assigned
}
}

enum_from_primitive! {
#[repr(i16)]
#[derive(Debug, Hash, PartialEq, Clone, Copy)]
pub enum TlsVersion {
    // TODO
    NONE  = 0x0000,
	SSL30 = 0x0300,
	TLS10 = 0x0301,
	TLS11 = 0x0302,
	TLS12 = 0x0303,
    TLS13 = 0x0304,
}
}

enum_from_primitive! {
#[repr(u16)]
#[derive(Debug, PartialEq)]
pub enum TlsExtension {
	ServerName                       = 0,
	StatusRequest                    = 5,
	SupportedCurves                  = 10,
	SupportedPoints                  = 11,
	SignatureAlgorithms              = 13,
	ALPN                             = 16,
	SCT                              = 18, // https://tools.ietf.org/html/rfc6962#section-6
	Padding                          = 21,
	ExtendedMasterSecret             = 23, // https://tools.ietf.org/html/rfc7627
	SessionTicket                    = 35,
	NextProtoNeg                     = 13172, // not IANA assigned
	RenegotiationInfo                = 0xff01,
	ChannelID                        = 30032, // not IANA assigned

    KeyShare                         = 0x0033,
    PskKeyExchangeModes              = 0x002D,
    SupportedVersions                = 0x002B,
    CertificateCompressionAlgorithms = 0x001B,
    TokenBinding                     = 0x0018,
    EarlyData                        = 0x002A,
    PreSharedKey                     = 0x0029,
    RecordSizeLimit                  = 0x001C,
}
}

pub struct ClientHello {
    pub record_tls_version: TlsVersion,
    pub ch_tls_version: TlsVersion,
    pub client_random: Vec<u8>,
    pub cipher_suites: Vec<u8>,
    pub compression_methods: Vec<u8>,

    pub extensions: Vec<u8>,
    pub named_groups: Vec<u8>,
    pub ec_point_fmt: Vec<u8>,
    pub sig_algs: Vec<u8>,
    pub alpn: Vec<u8>,

    // fields below are not part of final fingerprint
    pub sni: Vec<u8>,
    pub ticket_size: Option<i16>,

    pub key_share: Vec<u8>, // format [[u16, u16], [u16, u16], ...], where each element is [group, length]
    pub key_share_val: Vec<u8>,
    pub psk_key_exchange_modes: Vec<u8>,
    pub supported_versions: Vec<u8>,
    pub cert_compression_algs: Vec<u8>,
    pub record_size_limit : Vec<u8>,
    pub session_id: Option<Vec<u8>>,
}
pub type ClientHelloParseResult = Result<ClientHello, TLSParseError>;
impl ClientHello {
    pub fn from_try(a: &[u8], record_type: Option<TlsRecordType>, record_tls_version: TlsVersion) -> ClientHelloParseResult {
        if record_type != Some(TlsRecordType::Handshake) {
            return Err(TLSParseError::NotAHandshake);
        }

        let record_length = a.len();

	if record_length == 0 {
            return Err(TLSParseError::NotAClientHello);
        }

        if TlsHandshakeType::from_u8(a[0]) != Some(TlsHandshakeType::ClientHello) {
            return Err(TLSParseError::NotAClientHello);
        }

        let ch_length = u8_to_u32_be(0, a[1], a[2], a[3]);
        if ch_length != record_length as u32 - 4 {
            return Err(TLSParseError::InnerOuterRecordLenContradict);
        }

        let ch_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[4], a[5])) {
            Some(tls_version) => tls_version,
            None => return Err(TLSParseError::UnknownChTLSVersion),
        };

        // 32 bytes of client random

        let mut offset: usize = 6;
        let c_random = a[offset..offset+32].to_vec();
        offset += 32;

        let session_id_len = a[offset] as usize;
        let mut session_id = None;
        offset += 1;
        if session_id_len != 0 && (offset + session_id_len) < a.len() {
            session_id = Some(a[offset..offset+session_id_len].to_vec());
        }
        offset += session_id_len;
        if offset + 2 > a.len() {
            return Err(TLSParseError::SessionIDLenExceedBuf);
        }

        let cipher_suites_len = u8_to_u16_be(a[offset], a[offset + 1]) as usize;
        offset += 2;
        if offset + cipher_suites_len + 1 > a.len() || cipher_suites_len % 2 == 1 {
            return Err(TLSParseError::CiphersuiteLenMisparse);
        }

        let cipher_suites = ungrease_u8(&a[offset..offset + cipher_suites_len]);
        offset += cipher_suites_len;

        let compression_len = a[offset] as usize;
        offset += 1;
        if offset + compression_len + 2 > a.len() {
            return Err(TLSParseError::CompressionLenExceedBuf);
        }

        let compression_methods = a[offset..offset + compression_len].to_vec();
        offset += compression_len;

        let extensions_len = u8_to_u16_be(a[offset], a[offset + 1]) as usize;
        offset += 2;
        if offset + extensions_len > a.len() {
            return Err(TLSParseError::ExtensionsLenExceedBuf);
        }

        let mut ch = ClientHello {
            record_tls_version: record_tls_version,
            ch_tls_version: ch_tls_version,
            client_random: c_random,
            cipher_suites: cipher_suites,
            compression_methods: compression_methods,
            extensions: Vec::new(),
            named_groups: Vec::new(),
            ec_point_fmt: Vec::new(),
            sig_algs: Vec::new(),
            alpn: Vec::new(),
            sni: Vec::new(),
            ticket_size: None,
            key_share: Vec::new(),
            key_share_val: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            supported_versions: Vec::new(),
            cert_compression_algs: Vec::new(),
            record_size_limit: Vec::new(),
            session_id: session_id,
        };

        let ch_end = offset + extensions_len;
        while offset < ch_end {
            if offset > ch_end - 4 {
                return Err(TLSParseError::ShortExtensionHeader);
            }
            let ext_len = u8_to_u16_be(a[offset + 2], a[offset + 3]) as usize;
            if offset + ext_len > ch_end || offset + ext_len + 4 > a.len() {
                return Err(TLSParseError::ExtensionLenExceedBuf);
            }
            ch.process_extension(&a[offset..offset + 2], &a[offset + 4..offset + 4 + ext_len])?;
            offset = match (offset + 4).checked_add(ext_len) {
                Some(i) => i,
                None => return Err(TLSParseError::ExtensionLenExceedBuf),
            };
        }
        Ok(ch)
    }

    fn process_extension(&mut self, ext_id_u8: &[u8], ext_data: &[u8]) -> Result<(), TLSParseError> {
        let ext_id = u8_to_u16_be(ext_id_u8[0], ext_id_u8[1]);
        match TlsExtension::from_u16(ext_id) {
            // we copy whole ext_data, including all the redundant lengths
            Some(TlsExtension::SupportedCurves) => {
                self.named_groups = ungrease_u8(ext_data);
            }
            Some(TlsExtension::SupportedPoints) => {
                self.ec_point_fmt = ext_data.to_vec();
            }
            Some(TlsExtension::SignatureAlgorithms) => {
                self.sig_algs = ext_data.to_vec();
            }
            Some(TlsExtension::ServerName) => {
                self.sni = ext_data.to_vec();
            }
            Some(TlsExtension::SessionTicket) => {
                if ext_data.len() <= i16::max_value() as usize {
                    self.ticket_size = Some(ext_data.len() as i16)
                }
            }
            Some(TlsExtension::ALPN) => {
                /* TODO Could be greasy
   ALPN identifiers beginning with
   the prefix "ignore/".  This corresponds to the seven-octet prefix:
   0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65, 0x2f.
                */
                self.alpn = ext_data.to_vec();
            }
            Some(TlsExtension::KeyShare) => {
                // key share goes [[group, size, key_itself], [group, size, key_itself], ...]
                // we want [[group, size], [group, size], ...]
                let key_share_data = ext_data.to_vec();
                if key_share_data.len() < 2 {
                    return Err(TLSParseError::KeyShareExtShort);
                }
                let key_share_inner_len = u8_to_u16_be(key_share_data[0], key_share_data[1]) as usize;
                let key_share_inner_data = match key_share_data.get(2 .. key_share_data.len()) {
                    Some(data) => data,
                    None => return Err(TLSParseError::KeyShareExtShort),
                };
                if key_share_inner_len != key_share_inner_data.len() {
                    return Err(TLSParseError::KeyShareExtLenMisparse);
                }
                self.key_share = parse_key_share(key_share_inner_data)?;
                if key_share_inner_data.len() > 4 {
                    self.key_share_val = key_share_inner_data[4 .. ].to_vec();
                }
            }
            Some(TlsExtension::PskKeyExchangeModes) => {
                if ext_data.len() < 1 {
                    return Err(TLSParseError::PskKeyExchangeModesExtShort);
                }
                let psk_modes_inner_len = ext_data[0] as usize;
                if psk_modes_inner_len != ext_data.len() - 1 {
                    return Err(TLSParseError::PskKeyExchangeModesExtLenMisparse);
                }

                self.psk_key_exchange_modes = ungrease_u8(&ext_data[1 .. ]);
            }
            Some(TlsExtension::SupportedVersions) => {
                if ext_data.len() < 1 {
                    return Err(TLSParseError::SupportedVersionsExtLenMisparse);
                }
                let versions_inner_len = ext_data[0] as usize;
                if versions_inner_len != ext_data.len() - 1 {
                    return Err(TLSParseError::PskKeyExchangeModesExtLenMisparse);
                }

                self.supported_versions = ungrease_u8(&ext_data[1 .. ]);
            }
            Some(TlsExtension::CertificateCompressionAlgorithms) => {
                self.cert_compression_algs = ext_data.to_vec();
            }
            Some(TlsExtension::RecordSizeLimit) => {
                self.record_size_limit = ext_data.to_vec();
            }
            _ => {}
        };

        self.extensions.append(&mut ungrease_u8(ext_id_u8));
        Ok(())
    }

    pub fn get_fingerprint(&self) -> u64 {
        //let mut s = DefaultHasher::new(); // This is SipHasher13, nobody uses this...
        //let mut s = SipHasher24::new_with_keys(0, 0);
        // Fuck Rust's deprecated "holier than thou" bullshit attitude
        // We'll use Sha1 instead...

        let mut hasher = Sha1::new();
        let versions = (self.record_tls_version as u32) << 16 | (self.ch_tls_version as u32);
        hash_u32(&mut hasher, versions);


        hash_u32(&mut hasher, self.cipher_suites.len() as u32);
        hasher.input(&self.cipher_suites);

        hash_u32(&mut hasher, self.compression_methods.len() as u32);
        hasher.input(&self.compression_methods);

        hash_u32(&mut hasher, self.extensions.len() as u32);
        hasher.input(&self.extensions);

        hash_u32(&mut hasher, self.named_groups.len() as u32);
        hasher.input(&self.named_groups);

        hash_u32(&mut hasher, self.ec_point_fmt.len() as u32);
        hasher.input(&self.ec_point_fmt);

        hash_u32(&mut hasher, self.sig_algs.len() as u32);
        hasher.input(&self.sig_algs);

        hash_u32(&mut hasher, self.alpn.len() as u32);
        hasher.input(&self.alpn);

        hash_u32(&mut hasher, self.key_share.len() as u32);
        hasher.input(&self.key_share);

        hash_u32(&mut hasher, self.psk_key_exchange_modes.len() as u32);
        hasher.input(&self.psk_key_exchange_modes);

        hash_u32(&mut hasher, self.supported_versions.len() as u32);
        hasher.input(&self.supported_versions);

        hash_u32(&mut hasher, self.cert_compression_algs.len() as u32);
        hasher.input(&self.cert_compression_algs);

        hash_u32(&mut hasher, self.record_size_limit.len() as u32);
        hasher.input(&self.record_size_limit);

        let mut result = [0; 20];
        hasher.result(&mut result);
        BigEndian::read_u64(&result[0..8])
    }
}
impl fmt::Display for ClientHello {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "record: {:?} ch: {:?} random: {:02x?} ciphers: {:X} compression: {:X} \
        extensions: {:X} curves: {:X} ec_fmt: {:X} sig_algs: {:X} alpn: {:X} sni: {}",
               self.record_tls_version, self.ch_tls_version, self.client_random.as_slice(),
               vec_u8_to_vec_u16_be(&self.cipher_suites).as_slice().as_hex(),
               &self.compression_methods.as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.extensions).as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.named_groups).as_slice().as_hex(),
               self.ec_point_fmt.as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.sig_algs).as_slice().as_hex(),
               self.alpn.as_slice().as_hex(),
               String::from_utf8_lossy(self.sni.clone().as_slice()),
        )
    }
}

// Coverts array of [u8] into Vec<u8>, and performs ungrease.
// Ungrease stores all greasy extensions/ciphers/etc under single id to produce single fingerprint
// https://tools.ietf.org/html/draft-davidben-tls-grease-01
pub fn ungrease_u8(arr: &[u8]) -> Vec<u8> {
    let mut res: Vec<u8> = arr.iter().cloned().collect();
    for i in 0..(arr.len() / 2) {
        if res[2 * i] == res[2 * i + 1] && (res[2 * i] & 0x0f == 0x0a) {
            res[2 * i] = 0x0a;
            res[2 * i + 1] = 0x0a;
        }
    }
    res
}

// parses groups and lengths of key_share (but not keys themselves) and ungreases the groups
// passed vector must already be stripped from overall size
pub fn parse_key_share(arr: &[u8]) -> Result<Vec<u8>, TLSParseError> {
    if arr.len() > std::u16::MAX as usize {
        return Err(TLSParseError::KeyShareExtLong);
    }
    let mut i: usize = 0;
    let mut res = Vec::new();
    while i < arr.len() {
        if i  > arr.len() - 4 {
            return Err(TLSParseError::KeyShareExtShort);
        }
        let mut group_size = ungrease_u8(&arr[i .. i+2]);
        let size = u8_to_u16_be(arr[i+2], arr[i+3]) as usize;
        group_size.push(arr[i+2]);
        group_size.push(arr[i+3]);
        res.append(&mut group_size);

        i = match i.checked_add(4 + size) {
            Some(i) => i,
            None => return Err(TLSParseError::KeyShareExtShort),
        };
    }
    Ok(res)
}

pub fn hash_u32<D: Digest>(h: &mut D, n: u32) {
    h.input(&[((n >> 24) & 0xff) as u8,
        ((n >> 16) & 0xff) as u8,
        ((n >> 8) & 0xff) as u8,
        (n & 0xff) as u8]);
}

pub fn u8_to_u16_be(first_byte: u8, second_byte: u8) -> u16 {
    (first_byte as u16) << 8 | (second_byte as u16)
}

pub fn u8_to_u32_be(first_byte: u8, second_byte: u8, third_byte: u8, forth_byte: u8) -> u32 {
    (first_byte as u32) << 24 | (second_byte as u32) << 16 | (third_byte as u32) << 8 |
        (forth_byte as u32)
}

// Doesn't check that a.len() % 2 == 1.
pub fn vec_u8_to_vec_u16_be(a: &Vec<u8>) -> Vec<u16> {
    let mut result = Vec::with_capacity(a.len() / 2);
    for i in 0..result.capacity() {
        result.push(u8_to_u16_be(a[2 * i], a[2 * i + 1]));
    }
    result
}