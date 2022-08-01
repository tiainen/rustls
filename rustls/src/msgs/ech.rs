use crate::hash_hs::HandshakeHash;
use crate::msgs::base::{PayloadU16, PayloadU24};
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
use crate::tls13::key_schedule::KeyScheduleHandshake;
use crate::{rand, SupportedCipherSuite};
use crate::{Error, ProtocolVersion};
use hpke_rs::prelude::*;
use hpke_rs::{Hpke, Mode};
use hpke_rs_crypto::{
    types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use ring::digest::{Algorithm, Context};
use webpki;

const HPKE_INFO: &[u8; 8] = b"tls ech\0";

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

#[derive(Debug)]
pub struct HpkeParams {
    kem: KemAlgorithm,
    kdf: KdfAlgorithm,
    aead: AeadAlgorithm,
}

impl EncryptedClientHello {
    pub fn with_host_and_config_list(
        name: webpki::DnsNameRef,
        config_bytes: &Vec<u8>,
    ) -> Result<EncryptedClientHello, Error> {
        let configs: EchConfigList = EchConfigList::read(&mut Reader::init(config_bytes))
            .ok_or_else(|| Error::General("Couldn't parse ECH record.".to_string()))?;
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
        inner_hello
            .extensions
            .insert(0, ClientExtension::make_sni(self.hostname.as_ref()));
        inner_hello
            .extensions
            .insert(0, ClientExtension::EncryptedClientHello(EchClientHello::inner()));

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
        inner_hello
            .extensions
            .push(outer_extensions);

        // Create the buffer to be encrypted.
        let mut encoded_hello = Vec::new();
        inner_hello.encode(&mut encoded_hello);
        inner_hello.session_id = original_session_id;

        // Remove outer_extensions.
        inner_hello.extensions.pop();
        inner_hello.extensions.extend(outers);

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

        // Add the outer SNI
        hello.extensions.insert(
            0,
            ClientExtension::make_sni(
                self.config_contents
                    .public_name.0
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
        let mut encoded_outer = Vec::new();
        hello.encode(&mut encoded_outer);
        let outer_aad = ClientHelloOuterAAD {
            cipher_suite: self.suite.clone(),
            config_id: self
                .config_contents
                .hpke_key_config
                .config_id,
            enc: PayloadU16::new(enc.clone()),
            outer_hello: PayloadU24::new(encoded_outer),
        };

        let mut aad = Vec::new();
        outer_aad.encode(&mut aad);

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

        hello
            .extensions
            .insert(0, ClientExtension::EncryptedClientHello(client_ech));
        //.push();
        //hello_details
        //    .sent_extensions
        //   .push(ExtensionType::EncryptedClientHello);
        HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(hello),
        }
    }

    pub(crate) fn confirm_ech(
        &self,
        ks: &mut KeyScheduleHandshake,
        server_hello: &ServerHelloPayload,
        suite: &SupportedCipherSuite,
    ) -> Result<([u8; 32], HandshakeHash), Error> {
        // The ClientHelloInner prior to encoding.
        let m = self
            .inner_message
            .as_ref()
            .ok_or_else(|| Error::General("No ClientHelloInner".to_string()))?;

        // A confirmation transcript calculated from the ClientHelloInner and the ServerHello,
        // with the last 8 bytes of the server random modified to be zeros.
        let conf = confirmation_transcript(m, server_hello, suite.hash_algorithm());

        // Derive a secret from the current handshake and the confirmation transcript.
        let derived = ks.server_ech_confirmation_secret(&conf.get_current_hash());

        // Check that first 8 digits of the derived secret match the last 8 digits of the original
        // server random. This match signals that the server accepted the ECH offer.
        if derived.into_inner()[..8] != server_hello.random.get_encoding()[24..] {
            return Err(Error::General("ECH didn't match".to_string()));
        }

        // Since the ECH offer was accepted, the handshake will move forward with a fresh transcript
        // calculated from the ClientHelloInner, and the handshake should also use the client random
        // from the ClientHelloInner. The ServerHello is added to the transcript next, whether or
        // not the ECH offer was accepted.
        let ctx = Context::new(suite.hash_algorithm());
        let mut inner_transcript = HandshakeHash {
            ctx,
            client_auth: None
        };
        inner_transcript.add_message(m);
        Ok((self.inner_random, inner_transcript))
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
