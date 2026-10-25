use crate::{
    Capabilities, Error, Frame, Result, SessionOptions, TAG_BYTES,
    codec::{Reader, Writer},
    max_message_bytes,
};
use blendr_identity::{Identity, IdentityDocument};
use blendr_transport::{LinkRole, PeerLink, TransportError};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const PROLOGUE: &[u8] = b"blendr:direct-session:v1:bis:1:Noise_XX_25519_ChaChaPoly_SHA256";
const AUTH_DOMAIN: &str = "blendr:session-auth:v1";
// Canonical [version=1, type=5], reserved for the authentication confirmation.
const CONFIRM: &[u8] = &[0x82, 0x01, 0x05];

// Own the link and cipher together. Taking this out of SecureSession BEFORE an
// await makes cancellation by dropping the future fail closed as well: the link
// and cipher drop, and a later call cannot reuse a half-consumed Noise nonce.
struct Active {
    link: Box<dyn PeerLink>,
    noise: snow::TransportState,
}
pub struct SecureSession {
    active: Option<Active>,
    peer: IdentityDocument,
    peer_capabilities: Capabilities,
    local_capabilities: Capabilities,
    role: LinkRole,
    frame_limit: usize,
    sent_messages: u32,
    received_messages: u32,
    sent_bytes: u64,
    received_bytes: u64,
}
impl SecureSession {
    pub fn peer(&self) -> &IdentityDocument {
        &self.peer
    }
    pub fn peer_capabilities(&self) -> &Capabilities {
        &self.peer_capabilities
    }
    pub fn role(&self) -> LinkRole {
        self.role
    }
    pub fn max_message_bytes(&self) -> usize {
        max_message_bytes(self.frame_limit)
    }
    pub async fn send(&mut self, frame: &Frame, cancel: &CancellationToken) -> Result<()> {
        let mut active = self.active.take().ok_or(Error::Closed)?;
        check_frame(
            frame,
            &self.peer_capabilities,
            &self.local_capabilities,
            &mut self.sent_messages,
            &mut self.sent_bytes,
        )?;
        let bytes = frame.encode(self.frame_limit - TAG_BYTES)?;
        encrypted_send(&mut active, &bytes, self.frame_limit, cancel).await?;
        self.active = Some(active);
        Ok(())
    }
    pub async fn recv(&mut self, cancel: &CancellationToken) -> Result<Frame> {
        let mut active = self.active.take().ok_or(Error::Closed)?;
        let bytes = encrypted_recv(&mut active, self.frame_limit, cancel).await?;
        let frame = Frame::decode(&bytes, self.frame_limit - TAG_BYTES)?;
        check_frame(
            &frame,
            &self.local_capabilities,
            &self.peer_capabilities,
            &mut self.received_messages,
            &mut self.received_bytes,
        )?;
        self.active = Some(active);
        Ok(frame)
    }
    /// Responder-side drain after the final Goodbye: only a physical disconnect
    /// is success, never cancellation, malformed data, timeout or crypto failure.
    pub async fn wait_for_disconnect(&mut self, cancel: &CancellationToken) -> Result<()> {
        let mut active = self.active.take().ok_or(Error::Closed)?;
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(Error::Cancelled),
            result = active.link.recv_frame(cancel) => result,
        };
        match result {
            Err(TransportError::Disconnected) => Ok(()),
            Err(e) => Err(e.into()),
            Ok(_) => Err(Error::Malformed),
        }
    }
    pub async fn close(&mut self) -> Result<()> {
        if let Some(mut active) = self.active.take() {
            active.link.close().await?;
        }
        Ok(())
    }
}
fn check_frame(
    frame: &Frame,
    receiver: &Capabilities,
    sender: &Capabilities,
    count: &mut u32,
    bytes: &mut u64,
) -> Result<()> {
    match frame {
        Frame::Message(payload) => {
            *count = count.checked_add(1).ok_or(Error::Limit)?;
            *bytes = bytes
                .checked_add(payload.len() as u64)
                .ok_or(Error::Limit)?;
            if *count > receiver.max_messages.min(sender.max_messages)
                || *bytes > u64::from(receiver.max_bytes.min(sender.max_bytes))
            {
                return Err(Error::Limit);
            }
        }
        Frame::LinkAck(_) if !receiver.link_receipt || !sender.link_receipt => {
            return Err(Error::Unsupported);
        }
        Frame::DestinationReceipt(_)
            if !receiver.destination_receipt || !sender.destination_receipt =>
        {
            return Err(Error::Unsupported);
        }
        _ => {}
    }
    Ok(())
}
async fn send_raw(
    link: &mut dyn PeerLink,
    bytes: &[u8],
    limit: usize,
    cancel: &CancellationToken,
) -> Result<()> {
    if bytes.len() > limit {
        return Err(Error::Limit);
    }
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(Error::Cancelled),
        result = link.send_frame(bytes, cancel) => result.map_err(Into::into),
    }
}
async fn recv_raw(
    link: &mut dyn PeerLink,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Vec<u8>> {
    let bytes = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(Error::Cancelled),
        result = link.recv_frame(cancel) => result?,
    };
    if bytes.len() > limit {
        return Err(Error::Limit);
    }
    Ok(bytes)
}
async fn encrypted_send(
    active: &mut Active,
    bytes: &[u8],
    limit: usize,
    cancel: &CancellationToken,
) -> Result<()> {
    if bytes.len() > limit.saturating_sub(TAG_BYTES) {
        return Err(Error::Limit);
    }
    let mut wire = vec![0; bytes.len() + TAG_BYTES];
    let size = active.noise.write_message(bytes, &mut wire)?;
    send_raw(active.link.as_mut(), &wire[..size], limit, cancel).await
}
async fn encrypted_recv(
    active: &mut Active,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<Vec<u8>> {
    let wire = recv_raw(active.link.as_mut(), limit, cancel).await?;
    if wire.len() < TAG_BYTES {
        return Err(Error::Malformed);
    }
    let mut plaintext = vec![0; wire.len() - TAG_BYTES];
    let n = active.noise.read_message(&wire, &mut plaintext)?;
    plaintext.truncate(n);
    Ok(plaintext)
}
fn role_name(role: LinkRole) -> &'static str {
    match role {
        LinkRole::Initiator => "initiator",
        LinkRole::Responder => "responder",
    }
}
fn opposite(role: LinkRole) -> LinkRole {
    match role {
        LinkRole::Initiator => LinkRole::Responder,
        LinkRole::Responder => LinkRole::Initiator,
    }
}
fn auth_payload(
    identity: &Identity,
    caps: &Capabilities,
    role: LinkRole,
    transcript: &[u8],
    ni: &[u8; 32],
    nr: &[u8; 32],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.array(5);
    w.text(AUTH_DOMAIN);
    w.uint(1);
    w.document(&identity.document());
    w.bytes(&identity.prove(role_name(role), transcript, ni, nr));
    caps.write(&mut w);
    w.finish()
}
struct Binding<'a> {
    role: LinkRole,
    transcript: &'a [u8],
    ni: &'a [u8; 32],
    nr: &'a [u8; 32],
    remote_static: &'a [u8],
}
fn verify_auth(
    bytes: &[u8],
    local: &Identity,
    options: &SessionOptions,
    binding: &Binding<'_>,
    limit: usize,
) -> Result<(IdentityDocument, Capabilities)> {
    let mut r = Reader::new(bytes, limit)?;
    r.array(5)?;
    r.literal(AUTH_DOMAIN)?;
    if r.uint()? != 1 {
        return Err(Error::Unsupported);
    }
    let doc = r.document()?;
    let proof = r.fixed::<64>()?;
    let caps = Capabilities::read(&mut r)?;
    r.finish()?;
    doc.verify()?;
    if binding.remote_static != doc.encryption_public_key {
        return Err(Error::Authentication);
    }
    Identity::verify_proof(
        &doc,
        role_name(binding.role),
        binding.transcript,
        binding.ni,
        binding.nr,
        &proof,
    )?;
    if doc.bid == local.bid()
        || options.blocked_bids.iter().any(|bid| bid == &doc.bid)
        || options
            .expected_peer
            .as_ref()
            .is_some_and(|bid| bid != &doc.bid)
    {
        return Err(Error::PeerRejected);
    }
    Ok((doc, caps))
}
async fn handshake_send(
    link: &mut dyn PeerLink,
    noise: &mut snow::HandshakeState,
    payload: &[u8],
    limit: usize,
    cancel: &CancellationToken,
) -> Result<()> {
    // XX's largest message is 96 bytes of tokens/tags plus the nonce payload.
    let mut wire = [0u8; 128];
    let n = noise.write_message(payload, &mut wire)?;
    send_raw(link, &wire[..n], limit, cancel).await
}
async fn handshake_recv(
    link: &mut dyn PeerLink,
    noise: &mut snow::HandshakeState,
    expected: usize,
    limit: usize,
    cancel: &CancellationToken,
) -> Result<[u8; 32]> {
    let wire = recv_raw(link, limit.min(128), cancel).await?;
    let mut payload = [0u8; 128];
    let n = noise.read_message(&wire, &mut payload)?;
    if n != expected {
        return Err(Error::Malformed);
    }
    let mut nonce = [0u8; 32];
    if expected == 32 {
        nonce.copy_from_slice(&payload[..32]);
    }
    Ok(nonce)
}

/// Mutual Noise XX + signed BIS/static/transcript/role/nonce binding, followed
/// by authenticated capability exchange and initiator confirmation. Dropping
/// this future or returning any error drops the owned link and Noise state.
pub async fn authenticate(
    mut link: Box<dyn PeerLink>,
    identity: &Identity,
    options: SessionOptions,
    cancel: &CancellationToken,
) -> Result<SecureSession> {
    options.capabilities.validate()?;
    let limit = options.capabilities.max_frame_bytes as usize;
    if limit > link.mtu() {
        return Err(Error::Limit);
    }
    let role = link.role();
    let doc = identity.document();
    let raw = Zeroizing::new(
        identity
            .encryption_secret_for(doc.encryption_epoch)
            .ok_or(Error::Recipient)?
            .to_bytes(),
    );
    let builder = snow::Builder::new("Noise_XX_25519_ChaChaPoly_SHA256".parse()?)
        .local_private_key(raw.as_ref())?
        .prologue(PROLOGUE)?;
    let mut noise = match role {
        LinkRole::Initiator => builder.build_initiator()?,
        LinkRole::Responder => builder.build_responder()?,
    };
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
    let (ni, nr) = match role {
        LinkRole::Initiator => {
            handshake_send(link.as_mut(), &mut noise, &nonce, limit, cancel).await?;
            let nr = handshake_recv(link.as_mut(), &mut noise, 32, limit, cancel).await?;
            handshake_send(link.as_mut(), &mut noise, &[], limit, cancel).await?;
            (nonce, nr)
        }
        LinkRole::Responder => {
            let ni = handshake_recv(link.as_mut(), &mut noise, 32, limit, cancel).await?;
            handshake_send(link.as_mut(), &mut noise, &nonce, limit, cancel).await?;
            handshake_recv(link.as_mut(), &mut noise, 0, limit, cancel).await?;
            (ni, nonce)
        }
    };
    let transcript = noise.get_handshake_hash().to_vec();
    let remote_static = noise
        .get_remote_static()
        .ok_or(Error::Authentication)?
        .to_vec();
    let binding = Binding {
        role: opposite(role),
        transcript: &transcript,
        ni: &ni,
        nr: &nr,
        remote_static: &remote_static,
    };
    let mut active = Active {
        link,
        noise: noise.into_transport_mode()?,
    };
    let auth = auth_payload(identity, &options.capabilities, role, &transcript, &ni, &nr);
    let (peer, peer_capabilities) = match role {
        LinkRole::Initiator => {
            encrypted_send(&mut active, &auth, limit, cancel).await?;
            let bytes = encrypted_recv(&mut active, limit, cancel).await?;
            let peer = verify_auth(&bytes, identity, &options, &binding, limit)?;
            encrypted_send(
                &mut active,
                CONFIRM,
                limit.min(peer.1.max_frame_bytes as usize),
                cancel,
            )
            .await?;
            peer
        }
        LinkRole::Responder => {
            let bytes = encrypted_recv(&mut active, limit, cancel).await?;
            let peer = verify_auth(&bytes, identity, &options, &binding, limit)?;
            let negotiated = limit.min(peer.1.max_frame_bytes as usize);
            encrypted_send(&mut active, &auth, negotiated, cancel).await?;
            let confirmation = encrypted_recv(&mut active, negotiated, cancel).await?;
            if confirmation != CONFIRM {
                return Err(Error::Authentication);
            }
            peer
        }
    };
    let frame_limit = limit.min(peer_capabilities.max_frame_bytes as usize);
    Ok(SecureSession {
        active: Some(active),
        peer,
        peer_capabilities,
        local_capabilities: options.capabilities,
        role,
        frame_limit,
        sent_messages: 0,
        received_messages: 0,
        sent_bytes: 0,
        received_bytes: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_bid_must_match_noise_static_and_full_proof_context() {
        let local = Identity::generate("local").unwrap();
        let remote = Identity::generate("remote").unwrap();
        let attacker = Identity::generate("attacker").unwrap();
        let options = crate::tests::options();
        let ni = [1; 32];
        let nr = [2; 32];
        let transcript = [3; 32];
        let mut binding = Binding {
            role: LinkRole::Responder,
            transcript: &transcript,
            ni: &ni,
            nr: &nr,
            remote_static: remote.encryption_public_key(),
        };
        let payload = auth_payload(
            &remote,
            &options.capabilities,
            LinkRole::Responder,
            &transcript,
            &ni,
            &nr,
        );
        assert!(verify_auth(&payload, &local, &options, &binding, 8192).is_ok());
        binding.remote_static = attacker.encryption_public_key();
        assert!(verify_auth(&payload, &local, &options, &binding, 8192).is_err());
        binding.remote_static = remote.encryption_public_key();
        binding.role = LinkRole::Initiator;
        assert!(verify_auth(&payload, &local, &options, &binding, 8192).is_err());
        binding.role = LinkRole::Responder;
        binding.ni = &nr;
        assert!(verify_auth(&payload, &local, &options, &binding, 8192).is_err());
        binding.ni = &ni;
        binding.nr = &ni;
        assert!(verify_auth(&payload, &local, &options, &binding, 8192).is_err());
        binding.nr = &nr;
        binding.transcript = &ni;
        assert!(verify_auth(&payload, &local, &options, &binding, 8192).is_err());
        binding.transcript = &transcript;
        let mut proof = remote.prove("responder", &transcript, &ni, &nr);
        proof[0] ^= 1;
        let mut altered = Writer::new();
        altered.array(5);
        altered.text(AUTH_DOMAIN);
        altered.uint(1);
        altered.document(&remote.document());
        altered.bytes(&proof);
        options.capabilities.write(&mut altered);
        assert!(verify_auth(&altered.finish(), &local, &options, &binding, 8192).is_err());
        // Copying a victim BID into an attacker's signed document does not help.
        let mut stolen = attacker.document();
        stolen.bid = remote.bid().to_owned();
        let mut w = Writer::new();
        w.array(5);
        w.text(AUTH_DOMAIN);
        w.uint(1);
        w.document(&stolen);
        w.bytes(&attacker.prove("responder", &transcript, &ni, &nr));
        options.capabilities.write(&mut w);
        binding.transcript = &transcript;
        binding.remote_static = attacker.encryption_public_key();
        assert!(verify_auth(&w.finish(), &local, &options, &binding, 8192).is_err());
    }
}
