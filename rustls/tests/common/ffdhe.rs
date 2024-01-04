use num_bigint::BigUint;
use rustls::{
    crypto::{
        ActiveKeyExchange, CipherSuiteCommon, CryptoProvider, KeyExchangeAlgorithm, SharedSecret,
        SupportedKxGroup,
    },
    ffdhe_groups::FfdheGroup,
    CipherSuite, NamedGroup, SupportedCipherSuite, Tls12CipherSuite,
};

use super::*;

static TLS12_DHE_RSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite =
    match &provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
        SupportedCipherSuite::Tls12(provider) => Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                ..provider.common
            },
            kx: KeyExchangeAlgorithm::DHE,
            ..**provider
        },
        _ => unreachable!(),
    };

/// The (test-only) TLS1.2 ciphersuite TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
pub static TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&TLS12_DHE_RSA_WITH_AES_128_GCM_SHA256);

static FFDHE_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
];

#[derive(Debug)]
pub struct FfdheKxGroup(pub NamedGroup);

impl SupportedKxGroup for FfdheKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let mut x = vec![0; 64];
        ffdhe_provider()
            .secure_random
            .fill(&mut x)?;
        let x = BigUint::from_bytes_be(&x);

        let group = FfdheGroup::from_named_group(self.0).unwrap();
        let p = BigUint::from_bytes_be(group.p);
        let g = BigUint::from_bytes_be(group.g);

        let x_pub = g.modpow(&x, &p);
        let x_pub = to_bytes_be_with_len(x_pub, group.p.len());

        Ok(Box::new(ActiveFfdheKx {
            x_pub,
            x,
            p,
            group,
            named_group: self.0,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.0
    }
}

struct ActiveFfdheKx {
    x_pub: Vec<u8>,
    x: BigUint,
    p: BigUint,
    group: FfdheGroup<'static>,
    named_group: NamedGroup,
}

impl ActiveKeyExchange for ActiveFfdheKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer_pub = BigUint::from_bytes_be(peer_pub_key);
        let secret = peer_pub.modpow(&self.x, &self.p);
        let secret = to_bytes_be_with_len(secret, self.group.p.len());

        Ok(SharedSecret::from(&secret[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.x_pub
    }

    fn group(&self) -> NamedGroup {
        self.named_group
    }
}

fn to_bytes_be_with_len(n: BigUint, len_bytes: usize) -> Vec<u8> {
    let mut bytes = n.to_bytes_le();
    bytes.resize(len_bytes, 0);
    bytes.reverse();
    bytes
}

pub const FFDHE2048_KX_GROUP: FfdheKxGroup = FfdheKxGroup(NamedGroup::FFDHE2048);
pub const FFDHE3072_KX_GROUP: FfdheKxGroup = FfdheKxGroup(NamedGroup::FFDHE3072);
static FFDHE_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&FFDHE2048_KX_GROUP, &FFDHE3072_KX_GROUP];

/// A test-only `CryptoProvider`, only supporting FFDHE key exchange
pub fn ffdhe_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: FFDHE_CIPHER_SUITES.to_vec(),
        kx_groups: FFDHE_KX_GROUPS.to_vec(),
        ..provider::default_provider()
    }
}
