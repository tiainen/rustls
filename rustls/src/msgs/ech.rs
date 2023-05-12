
use crate::hash_hs::HandshakeHash;
use crate::msgs::base::{PayloadU16, PayloadU24, PayloadU8};
use crate::msgs::codec;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{EchClientHelloType, ExtensionType, HandshakeType};
use crate::msgs::handshake::ClientExtension::EchOuterExtensions;
use crate::msgs::handshake::{
    ClientExtension, ClientHelloOuterAAD, ClientHelloPayload, EchClientHello, EchConfig,
    EchConfigContents, EchConfigList, HandshakeMessagePayload, HandshakePayload,
    HpkeSymmetricCipherSuite, Random, ServerHelloPayload, SessionID,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::tls13::key_schedule::{PayloadU8Len, hkdf_expand};
use crate::{rand, SupportedCipherSuite};
use crate::{Error, ProtocolVersion};
use hpke_rs::prelude::*;
use hpke_rs::{Hpke, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use ring::digest::{Algorithm, Context};
use ring::hkdf::KeyType;
use webpki;

const HPKE_INFO: &[u8; 8] = b"tls ech\0";
const ACCEPT_CONFIRMATION: &[u8; 23]  = b"ech accept confirmation";

fn hpke_info(config: &EchConfig) -> Vec<u8> {
    let mut info = Vec::with_capacity(128);
    info.extend_from_slice(HPKE_INFO);
    config.encode(&mut info);
    info
}

#[derive(Debug)]
pub struct EncryptedClientHello {
    pub hostname: webpki::DnsName,
    pub hpke_params: HpkeParams,
    pub hpke_info: Vec<u8>,
    pub suite: HpkeSymmetricCipherSuite,
    pub config_contents: EchConfigContents,
    pub inner_message: Option<Message>,
    pub inner_random: [u8; 32],
    /// Extensions that will be referenced in the ClientHelloOuter by the EncryptedClientHelloInner.
    pub compressed_extensions: Vec<ExtensionType>,
    // outer_only_exts?
}

impl Clone for EncryptedClientHello {
    fn clone(&self) -> Self {
        Self { hostname: self.hostname.clone(), hpke_params: self.hpke_params.clone(), hpke_info: self.hpke_info.clone(), suite: self.suite.clone(), config_contents: self.config_contents.clone(), inner_message: None, inner_random: self.inner_random.clone(), compressed_extensions: self.compressed_extensions.clone() }
    }
}

#[derive(Clone, Debug)]
pub struct HpkeParams {
    kem: KemAlgorithm,
    kdf: KdfAlgorithm,
    aead: AeadAlgorithm,
}

#[allow(unused_parens)]
impl EncryptedClientHello {
    pub fn with_host_and_config_list(
        name: webpki::DnsNameRef,
        config_bytes: &Vec<u8>,
    ) -> Result<EncryptedClientHello, Error> {
        let configs: EchConfigList = EchConfigList::read(&mut Reader::init(config_bytes))
            .ok_or_else(|| Error::General("Couldn't parse ECH record.".to_string()))?;
        eprintln!("configs {:?}", configs);
        let (config_contents, hpke_info, (suite, hpke_params)) = configs
            .iter()
            .find_map(|config| {
                let c = &config.contents;
                Some((
                    c.clone(),
                    hpke_info(&config),
                    c.hpke_key_config
                        .hpke_symmetric_cipher_suites
                        .iter()
                        .find_map(|suite| {
                            Some((
                                suite,
                                HpkeParams {
                                    kem: KemAlgorithm::try_from(
                                        c.hpke_key_config.hpke_kem_id.get_u16(),
                                    )
                                    .ok()?,
                                    kdf: KdfAlgorithm::try_from(suite.hpke_kdf_id.get_u16())
                                        .ok()?,
                                    aead: AeadAlgorithm::try_from(suite.hpke_aead_id.get_u16())
                                        .ok()?,
                                },
                            ))
                        })?,
                ))
            })
            .ok_or(Error::NoHpkeConfig)?;

        // TODO: check for unknown mandatory extensions in config_contents (Section 4.1)
        // Clients MUST parse the extension list and check for unsupported mandatory extensions.
        // If an unsupported mandatory extension is present, clients MUST ignore the ECHConfig.

        let mut inner_random = [0u8; 32];
        rand::fill_random(&mut inner_random).unwrap();

        eprintln!("name: {:?}", name);
        Ok(EncryptedClientHello {
            hostname: name.to_owned(),
            hpke_params,
            hpke_info,
            suite: suite.clone(),
            config_contents,
            inner_message: None,
            inner_random,
            compressed_extensions: vec![],
        })
    }

    pub fn public_key(&self) -> HpkePublicKey {
        HpkePublicKey::from(
            self.config_contents
                .hpke_key_config
                .hpke_public_key
                .clone()
                .into_inner(),
        )
    }

    pub fn encode(&mut self, mut hello: ClientHelloPayload) -> HandshakeMessagePayload {
        // Remove the SNI
        if let Some(index) = hello
            .extensions
            .iter()
            .position(|ext| ext.get_type() == ExtensionType::ServerName)
        {
            hello.extensions.remove(index);
        };

        let mut inner_hello = hello.clone();

        // Remove the ClientExtensions that match outer_exts.
        // Nightly's drain_filter would be nice here.
        let mut indices = Vec::with_capacity(self.compressed_extensions.len());
        for (i, ext) in inner_hello
            .extensions
            .iter()
            .enumerate()
        {
            if self
                .compressed_extensions
                .contains(&ext.get_type())
            {
                indices.push(i);
            }
        }
        let mut outers = Vec::with_capacity(indices.len());
        for index in indices.iter().rev() {
            outers.push(
                inner_hello
                    .extensions
                    .swap_remove(*index),
            );
        }

        // Add the inner SNI
        eprintln!("Add host name: {:?}", self.hostname);
        inner_hello
            .extensions
            .insert(0, ClientExtension::make_sni(self.hostname.as_ref()));

        // Preserve these for reuse
        let original_session_id = inner_hello.session_id;
        inner_hello.random = Random::from(self.inner_random);

        // SessionID is required to be empty in the EncodedClientHelloInner.
        inner_hello.session_id = SessionID::empty();

        // Add these two extensions which can only appear in ClientHelloInner.
        let outer_extensions = EchOuterExtensions(
            outers
                .iter()
                .map(|ext| ext.get_type())
                .collect(),
        );

        let mut encoded_hello1 = Vec::new();
        inner_hello.encode(&mut encoded_hello1);
        println!("Before extensions, innerHello encoded = {:02x?}", encoded_hello1);
        // inner_hello.extensions.push(outer_extensions);

        inner_hello.extensions.push(
            ClientExtension::EncryptedClientHello(EchClientHello::inner()),
        );
        // Create the buffer to be encrypted.
        let mut encoded_hello = Vec::new();
        inner_hello.encode(&mut encoded_hello);
        println!("After extensions: encoded_hello has length {}, {:02x?}", encoded_hello.len(),encoded_hello);
        while (encoded_hello.len() < 256) {
            encoded_hello.push(0);
        }
        inner_hello.session_id = original_session_id;
        println!("step 1, inner_hello = {:?}", inner_hello);

        // Remove outer_extensions.
        // inner_hello.extensions.pop();
        println!("step 2, inner_hello = {:?}", inner_hello);
        inner_hello.extensions.extend(outers);
        println!("step 3, inner_hello = {:?}", inner_hello);

        let chp = HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(inner_hello),
        };
        self.inner_message = Some(Message {
            // "This value MUST be set to 0x0303 for all records generated
            //  by a TLS 1.3 implementation other than an initial ClientHello
            //  (i.e., one not generated after a HelloRetryRequest)"
            version: ProtocolVersion::TLSv1_0,
            payload: MessagePayload::handshake(chp),
        });
        println!("Created inner msg, msg = {:?}", self.inner_message);

        // Add the outer SNI
        hello.extensions.insert(
            0,
            ClientExtension::make_sni(
                self.config_contents
                    .public_name
                    .0
                    .as_ref(),
            ),
        );

        // PSK extensions are prohibited in the ClientHelloOuter.
        let index = hello
            .extensions
            .iter()
            .position(|ext| ext.get_type() == ExtensionType::PreSharedKey);
        if let Some(i) = index {
            hello.extensions.remove(i);
        }

        let pk_r = self.public_key();
        let hpke = Hpke::<HpkeRustCrypto>::new(
            Mode::Base,
            self.hpke_params.kem,
            self.hpke_params.kdf,
            self.hpke_params.aead,
        );
        let (enc, mut context) = hpke
            .setup_sender(&pk_r, self.hpke_info.as_slice(), None, None, None)
            .unwrap();
        let mut encoded_outer_pre = Vec::new();
        hello.encode(&mut encoded_outer_pre);

        let mut total_size = encoded_outer_pre.len();
        println!("TOTALSIZE = {}", total_size);
        // create a dummy ech outer extension with the correct size
        let dummy_payload = vec![0u8; encoded_hello.len() + 16];

        let client_ech_pre = EchClientHello {
            hello_type: EchClientHelloType::OUTER,
            cipher_suite: Some(self.suite.clone()),
            config_id: Some(
                self.config_contents
                    .hpke_key_config
                    .config_id,
            ),
            enc: Some(PayloadU16::new(enc.clone())),
            payload: Some(PayloadU16::new(dummy_payload)),
        };

        let my_extension_pre = ClientExtension::EncryptedClientHello(client_ech_pre);
        let index_pre = hello.extensions.len();
        hello
            .extensions
            .push(my_extension_pre);

        let mut encoded_outer = Vec::new();
        hello.encode(&mut encoded_outer);

        total_size = encoded_outer.len();
        println!("TOTALSIZE after ech extension added = {}", total_size);
        let outer_aad = ClientHelloOuterAAD {
            cipher_suite: self.suite.clone(),
            config_id: self
                .config_contents
                .hpke_key_config
                .config_id,
            enc: PayloadU16::new(enc.clone()),
            outer_hello: PayloadU24::new(encoded_outer),
        };



        let mut aad_orig = Vec::new();
        outer_aad.encode(&mut aad_orig);

        let aad = aad_orig;
        eprintln!("Sealing, encodedsize = {} and aadsize = {} and aad[0] = {}", encoded_hello.len(), aad.len(), aad[0]);
        let payload = context
            .seal(aad.as_slice(), &*encoded_hello)
            .unwrap();
        let client_ech = EchClientHello {
            hello_type: EchClientHelloType::OUTER,
            cipher_suite: Some(self.suite.clone()),
            config_id: Some(
                self.config_contents
                    .hpke_key_config
                    .config_id,
            ),
            enc: Some(PayloadU16::new(enc)),
            payload: Some(PayloadU16::new(payload)),
        };

        eprintln!("client_ech ext: {:#?}", client_ech);
        hello.extensions.remove(index_pre);
        let my_extension = ClientExtension::EncryptedClientHello(client_ech);
        hello
            .extensions
            .push(my_extension);
        HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(hello),
        }
    }

    pub(crate) fn confirm_ech(
        &self,
        server_hello: &ServerHelloPayload,
        suite: &SupportedCipherSuite,
    ) -> () {
        // The ClientHelloInner prior to encoding.
        let m = self
            .inner_message
            .as_ref()
            .ok_or_else(|| Error::General("No ClientHelloInner".to_string())).unwrap();
        eprintln!("CONFIRM");
        eprintln!("Inner hello: {:#?}", m);

        // A confirmation transcript calculated from the ClientHelloInner and the ServerHello,
        // with the last 8 bytes of the server random modified to be zeros.
        let conf = confirmation_transcript(m, server_hello, suite.hash_algorithm());
        
        let hkdf_algorithm = match self.hpke_params.kdf {
            KdfAlgorithm::HkdfSha256 => ring::hkdf::HKDF_SHA256,
            KdfAlgorithm::HkdfSha384 => ring::hkdf::HKDF_SHA384,
            KdfAlgorithm::HkdfSha512 => ring::hkdf::HKDF_SHA512,
        };

        eprintln!("hkdf algorithm from ECH: {:?}", hkdf_algorithm);

        let zero_vec = vec![0; hkdf_algorithm.len()];
        let prk = ring::hkdf::Salt::new(hkdf_algorithm, &zero_vec).extract(&self.inner_random);
        let payload: PayloadU8 = hkdf_expand(&prk, PayloadU8Len(8), ACCEPT_CONFIRMATION, conf.get_current_hash().as_ref());
        eprintln!("payload:    {:x?}", payload.into_inner());
        eprintln!("random: {:?}", server_hello.random);
        // todo: check if 8 last bytes of sh random match with payload and return true or false
    }
}

fn confirmation_transcript(
    m: &Message,
    server_hello: &ServerHelloPayload,
    alg: &'static Algorithm,
) -> HandshakeHash {
    let ctx = Context::new(alg);
    let mut confirmation_transcript = HandshakeHash {
        ctx,
        client_auth: None
    };
    confirmation_transcript.add_message(m);
    let shc = server_hello_conf(server_hello);
    confirmation_transcript.update_raw(&shc);
    confirmation_transcript
}

fn server_hello_conf(server_hello: &ServerHelloPayload) -> Vec<u8> {
    let mut encoded_sh = Vec::new();
    server_hello.encode_for_ech_confirmation(&mut encoded_sh);
    let mut hmp_encoded = Vec::new();
    HandshakeType::ServerHello.encode(&mut hmp_encoded);
    codec::u24(encoded_sh.len() as u32).encode(&mut hmp_encoded);
    hmp_encoded.append(&mut encoded_sh);
    hmp_encoded
}

#[cfg(test)]
mod test {
    use crate::msgs::enums::{EchVersion, KEM, KDF, AEAD};

    use super::*;
    
    const BASE64_ECHCONFIG_LIST: &str = "AED+DQA8AAAgACAxoIJyV36iDlfFRmqE+ho2PxXE0EISPfUUJYKCy6T8VwAIAAEAAQABAAOACWxvY2FsaG9zdAAA";
    fn get_ech_config(s: &str) -> (EchConfigList, Vec<u8>) {
        let bytes = base64::decode(s).unwrap();
        let configs = EchConfigList::read(&mut Reader::init(&bytes)).unwrap();
        assert_eq!(configs.len(), 1);
        (configs, bytes.to_vec())
    }

    #[test]
    fn test_decode_config_list() {
        let bytes = base64::decode(BASE64_ECHCONFIG_LIST).unwrap();
        let config_list = EchConfigList::read(&mut Reader::init(&bytes)).unwrap();
        assert_eq!(config_list.len(), 1);
        assert_eq!(config_list[0].contents.maximum_name_length, 128);
    }

    #[test]
    fn test_echconfig_serialization() {
        let (configs, _bytes) = get_ech_config(BASE64_ECHCONFIG_LIST);
        let config = &configs[0];
        assert_eq!(config.version, EchVersion::V14);
        assert_eq!(
            "localhost",
            config
                .contents
                .public_name
                .as_ref()
        );
        assert_eq!(
            config
                .contents
                .hpke_key_config
                .hpke_kem_id,
            KEM::DHKEM_X25519_HKDF_SHA256
        );
        assert_eq!(
            config
                .contents
                .hpke_key_config
                .hpke_symmetric_cipher_suites
                .len(),
            2
        );
        assert_eq!(
            config
                .contents
                .hpke_key_config
                .hpke_symmetric_cipher_suites[0]
                .hpke_kdf_id,
            KDF::HKDF_SHA256
        );
        assert_eq!(
            config
                .contents
                .hpke_key_config
                .hpke_symmetric_cipher_suites[0]
                .hpke_aead_id,
            AEAD::AES_128_GCM
        );
        assert_eq!(
            config
                .contents
                .hpke_key_config
                .hpke_symmetric_cipher_suites[1]
                .hpke_kdf_id,
            KDF::HKDF_SHA256
        );
        assert_eq!(
            config
                .contents
                .hpke_key_config
                .hpke_symmetric_cipher_suites[1]
                .hpke_aead_id,
            AEAD::CHACHA20_POLY_1305
        );
        let mut output = Vec::new();
        configs.encode(&mut output);
        assert_eq!(BASE64_ECHCONFIG_LIST, base64::encode(&output));
    }
}
