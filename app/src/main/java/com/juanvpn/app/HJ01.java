package com.juanvpn.app;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * HJ01: JUAN VPN protected configuration container (binary format, envelope encryption).
 *
 * Layout (big endian):
 *   core header (55 bytes): magic "HJ01", version, aead id, kdf id, flags, created, expires, maxImports,
 *                           fileId(16), payloadNonce(12), wrapCount
 *   wrap entries:           type(1) len(2) body(len)          (1..4 entries)
 *   ciphertextLen(4), ciphertext (AES-256-GCM, 16 byte tag at the end)
 *
 * Every file gets its own random 256-bit data key (DEK) and fresh random nonces. The DEK is wrapped separately
 * for each authorized party:
 *   PASSWORD  : Argon2id(password, salt) -> HKDF-SHA256 -> KEK -> AES-256-GCM wrap
 *   RECIPIENT : ephemeral ECDH P-256 against the recipient/device public key -> HKDF-SHA256 -> KEK -> wrap
 * The payload is encrypted with the DEK and the WHOLE header (core + every wrap entry) as AAD, so any change to
 * a security-sensitive field makes authentication fail. Each wrap is also bound to the core header.
 *
 * There is no universal key, no hidden bypass, no unauthenticated mode and no downgrade path in this class.
 * Pure Java on purpose (no android.* imports) so the whole format can be tested on a normal JVM.
 */
public final class HJ01 {
    private HJ01() {}

    public static final String PREFIX = "HJ01.";
    public static final int VERSION = 1;

    private static final byte[] MAGIC = {'H', 'J', '0', '1'};
    private static final int AEAD_AES256GCM = 1;
    private static final int KDF_ARGON2ID = 1;
    private static final int WRAP_PASSWORD = 1;
    private static final int WRAP_RECIPIENT = 2;

    private static final int CORE_LEN = 55;
    private static final int PW_BODY_LEN = 4 + 4 + 1 + 16 + 12 + 48;        // 85
    private static final int RCPT_PUB_LEN = 91;                              // X.509 SubjectPublicKeyInfo of a P-256 key
    private static final int RCPT_BODY_LEN = 8 + 1 + RCPT_PUB_LEN + 12 + 48; // 160
    private static final int MAX_WRAPS = 4;
    private static final int MAX_PLAINTEXT = 2 * 1024 * 1024;
    private static final int MAX_FILE = MAX_PLAINTEXT + 4096;
    private static final int TAG_LEN = 16;

    // Argon2id limits. Encrypt refuses anything below the OWASP minimum; decrypt refuses values that could
    // exhaust a phone's memory when they come from an untrusted file.
    private static final int ENC_MIN_MEM_KIB = 19_456, ENC_MIN_ITERS = 2;
    private static final int DEC_MIN_MEM_KIB = 8_192, DEC_MAX_MEM_KIB = 131_072;
    private static final int DEC_MAX_ITERS = 12, DEC_MAX_LANES = 4;

    private static final SecureRandom RNG = new SecureRandom();

    /* ------------------------------------------------------------------ exceptions */

    public static class HJException extends Exception {
        public HJException(String m) { super(m); }
    }
    /** Malformed, truncated, unsupported version/algorithm, trailing data. */
    public static final class FormatException extends HJException {
        public FormatException(String m) { super(m); }
    }
    /** Wrong password, wrong key, or the file was modified. Deliberately one message: no oracle. */
    public static final class AuthException extends HJException {
        public AuthException() { super("Wrong password, or the file was changed or damaged"); }
    }
    public static final class ExpiredException extends HJException {
        public ExpiredException() { super("This configuration has expired"); }
    }
    /** The credentials given have no matching key slot in this file (e.g. a file for another device). */
    public static final class NotAuthorizedException extends HJException {
        public NotAuthorizedException(String m) { super(m); }
    }

    /* ------------------------------------------------------------------ public types */

    /** A device or recipient key whose private half never leaves its secure store (Android Keystore on the phone). */
    public interface DeviceKey {
        /** First 8 bytes of SHA-256 of the public key's X.509 encoding (see {@link #recipientId}). */
        byte[] id();
        /** ECDH with the sender's ephemeral public key (X.509 encoding). Returns the raw shared secret. */
        byte[] agree(byte[] peerPublicX509) throws GeneralSecurityException;
    }

    public static final class Options {
        public char[] password;                                   // optional password slot
        public final List<byte[]> recipients = new ArrayList<>(); // optional recipient/device public keys (X.509)
        public long createdSec = System.currentTimeMillis() / 1000;
        public long expiresSec = 0;                               // 0 = no expiry
        public int maxImports = 0;                                // 0 = unlimited (enforced by the app, see HJGuard)
        public int memKiB = 65_536, iters = 3, lanes = 1;         // Argon2id parameters; see calibrate()
    }

    public static final class Credentials {
        public char[] password;
        public DeviceKey deviceKey;
        public Credentials password(char[] p) { this.password = p; return this; }
        public Credentials device(DeviceKey k) { this.deviceKey = k; return this; }
    }

    public static final class Result {
        public final byte[] plaintext;
        public final byte[] fileId;
        public final int maxImports;
        public final long expiresSec;
        Result(byte[] p, byte[] id, int m, long e) { plaintext = p; fileId = id; maxImports = m; expiresSec = e; }
    }

    /** What can be read from the header WITHOUT authenticating it. For UI hints only; never trust it for decisions. */
    public static final class Info {
        public boolean hasPassword, hasRecipient;
        public long createdSec, expiresSec;
        public int maxImports;
        public byte[] fileId;
        public List<byte[]> recipientIds = new ArrayList<>();
    }

    public static final class Argon2Choice {
        public final int memKiB, iters, lanes;
        Argon2Choice(int m, int t, int p) { memKiB = m; iters = t; lanes = p; }
    }

    /* ------------------------------------------------------------------ helpers */

    public static Argon2Choice choice(int memKiB, int iters, int lanes) { return new Argon2Choice(memKiB, iters, lanes); }

    public static byte[] recipientId(byte[] pubX509) {
        try { return Arrays.copyOf(MessageDigest.getInstance("SHA-256").digest(pubX509), 8); }
        catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }

    /**
     * Benchmarks Argon2id on this device and returns parameters that take roughly targetMs (memory is capped so a
     * low-end phone never runs out). Call once, cache the result, and pass it into {@link Options}.
     */
    public static Argon2Choice calibrate(long targetMs, int maxMemKiB) {
        int mem = Math.max(ENC_MIN_MEM_KIB, Math.min(maxMemKiB, DEC_MAX_MEM_KIB));
        int t = ENC_MIN_ITERS;
        byte[] salt = new byte[16], pw = "calibration".getBytes(StandardCharsets.UTF_8);
        while (t < 8) {
            long t0 = System.nanoTime();
            argon2(pw, salt, mem, t, 1);
            long ms = (System.nanoTime() - t0) / 1_000_000;
            if (ms * (t + 1) / t > targetMs) break;
            t++;
        }
        return new Argon2Choice(mem, t, 1);
    }

    /* ------------------------------------------------------------------ encrypt */

    /**
     * Builds an HJ01 file and verifies it before returning it: the finished bytes are re-parsed strictly, the
     * payload is decrypted again with the data key, and (when a password slot exists) the password slot is
     * re-opened with the password. Throws instead of returning a file that does not verify.
     */
    public static byte[] encrypt(byte[] plaintext, Options o) throws HJException {
        if (plaintext == null || plaintext.length == 0 || plaintext.length > MAX_PLAINTEXT)
            throw new FormatException("Configuration is empty or too large");
        boolean hasPw = o.password != null && o.password.length > 0;
        if (!hasPw && o.recipients.isEmpty()) throw new FormatException("A password or a recipient key is required");
        if (o.recipients.size() + (hasPw ? 1 : 0) > MAX_WRAPS) throw new FormatException("Too many key slots");
        if (o.maxImports < 0 || o.maxImports > 65_535) throw new FormatException("Invalid import limit");
        if (o.expiresSec < 0 || o.createdSec < 0) throw new FormatException("Invalid dates");
        if (hasPw && (o.memKiB < ENC_MIN_MEM_KIB || o.iters < ENC_MIN_ITERS || o.memKiB > DEC_MAX_MEM_KIB
                || o.iters > DEC_MAX_ITERS || o.lanes < 1 || o.lanes > DEC_MAX_LANES))
            throw new FormatException("Weak or invalid password hashing settings");

        byte[] dek = new byte[32], fileId = new byte[16], payloadNonce = new byte[12];
        RNG.nextBytes(dek); RNG.nextBytes(fileId); RNG.nextBytes(payloadNonce);
        try {
            ByteBuffer core = ByteBuffer.allocate(CORE_LEN);
            core.put(MAGIC).put((byte) VERSION).put((byte) AEAD_AES256GCM).put((byte) (hasPw ? KDF_ARGON2ID : 0)).put((byte) 0)
                .putLong(o.createdSec).putLong(o.expiresSec).putShort((short) o.maxImports)
                .put(fileId).put(payloadNonce).put((byte) (o.recipients.size() + (hasPw ? 1 : 0)));
            byte[] coreBytes = core.array();

            List<byte[]> entries = new ArrayList<>();
            if (hasPw) entries.add(buildPasswordWrap(coreBytes, fileId, dek, o));
            for (byte[] pub : o.recipients) entries.add(buildRecipientWrap(coreBytes, fileId, dek, pub));

            int hdrLen = CORE_LEN;
            for (byte[] e : entries) hdrLen += e.length;
            ByteBuffer hdr = ByteBuffer.allocate(hdrLen).put(coreBytes);
            for (byte[] e : entries) hdr.put(e);
            byte[] header = hdr.array();

            byte[] ct = gcm(true, dek, payloadNonce, header, plaintext);
            byte[] out = ByteBuffer.allocate(header.length + 4 + ct.length).put(header).putInt(ct.length).put(ct).array();

            // ---- verification before the file is handed out
            Parsed p = parse(out);
            byte[] back = gcm(false, dek, p.payloadNonce, p.header, p.ciphertext);
            if (!MessageDigest.isEqual(back, plaintext)) throw new FormatException("Self-check failed");
            Arrays.fill(back, (byte) 0);
            if (hasPw) {
                Result r = decrypt(out, new Credentials().password(o.password), 0L, true);
                if (!MessageDigest.isEqual(r.plaintext, plaintext)) throw new FormatException("Self-check failed");
                Arrays.fill(r.plaintext, (byte) 0);
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new FormatException("Encryption failed");
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    private static byte[] buildPasswordWrap(byte[] core, byte[] fileId, byte[] dek, Options o) throws GeneralSecurityException {
        byte[] salt = new byte[16], nonce = new byte[12];
        RNG.nextBytes(salt); RNG.nextBytes(nonce);
        ByteBuffer prefix = ByteBuffer.allocate(25).putInt(o.memKiB).putInt(o.iters).put((byte) o.lanes).put(salt);
        byte[] ikm = argon2(passwordBytes(o.password), salt, o.memKiB, o.iters, o.lanes);
        byte[] kek = hkdf(ikm, fileId, "HJ01/kek/password".getBytes(StandardCharsets.US_ASCII));
        Arrays.fill(ikm, (byte) 0);
        try {
            byte[] wrapped = gcm(true, kek, nonce, wrapAad(core, WRAP_PASSWORD, prefix.array()), dek);
            return entry(WRAP_PASSWORD, concat(prefix.array(), nonce, wrapped));
        } finally { Arrays.fill(kek, (byte) 0); }
    }

    private static byte[] buildRecipientWrap(byte[] core, byte[] fileId, byte[] dek, byte[] recipientPubX509) throws GeneralSecurityException, HJException {
        PublicKey rpub = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(recipientPubX509));
        if (!(rpub instanceof ECPublicKey) || ((ECPublicKey) rpub).getParams().getCurve().getField().getFieldSize() != 256
                || recipientPubX509.length != RCPT_PUB_LEN)
            throw new FormatException("Recipient key must be a P-256 public key");
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"), RNG);
        KeyPair eph = g.generateKeyPair();
        byte[] ephPub = eph.getPublic().getEncoded();
        if (ephPub.length != RCPT_PUB_LEN) throw new FormatException("Unexpected key size");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(eph.getPrivate());
        ka.doPhase(rpub, true);
        byte[] z = ka.generateSecret();
        byte[] rid = recipientId(recipientPubX509), nonce = new byte[12];
        RNG.nextBytes(nonce);
        byte[] kek = hkdf(z, fileId, concat("HJ01/kek/recipient".getBytes(StandardCharsets.US_ASCII), rid, ephPub));
        Arrays.fill(z, (byte) 0);
        try {
            byte[] prefix = concat(rid, new byte[]{(byte) RCPT_PUB_LEN}, ephPub);
            byte[] wrapped = gcm(true, kek, nonce, wrapAad(core, WRAP_RECIPIENT, prefix), dek);
            return entry(WRAP_RECIPIENT, concat(prefix, nonce, wrapped));
        } finally { Arrays.fill(kek, (byte) 0); }
    }

    /* ------------------------------------------------------------------ decrypt */

    /** Opens a file. Nothing is returned unless the GCM tag over the whole header and payload verifies. */
    public static Result decrypt(byte[] file, Credentials cred, long nowSec) throws HJException {
        return decrypt(file, cred, nowSec, false);
    }

    private static Result decrypt(byte[] file, Credentials cred, long nowSec, boolean skipExpiry) throws HJException {
        Parsed p = parse(file);
        if (!skipExpiry && p.expires != 0 && nowSec > p.expires) throw new ExpiredException();

        boolean havePw = cred != null && cred.password != null && cred.password.length > 0;
        boolean haveDev = cred != null && cred.deviceKey != null;
        byte[] dek = null;
        boolean triedSlot = false;
        try {
            for (Wrap w : p.wraps) {
                if (dek != null) break;
                if (w.type == WRAP_PASSWORD && havePw) {
                    triedSlot = true;
                    byte[] ikm = argon2(passwordBytes(cred.password), w.salt, w.mem, w.iters, w.lanes);
                    byte[] kek = hkdf(ikm, p.fileId, "HJ01/kek/password".getBytes(StandardCharsets.US_ASCII));
                    Arrays.fill(ikm, (byte) 0);
                    dek = tryUnwrap(kek, w, p.core);
                } else if (w.type == WRAP_RECIPIENT && haveDev && MessageDigest.isEqual(w.recipientId, cred.deviceKey.id())) {
                    triedSlot = true;
                    byte[] z = cred.deviceKey.agree(w.ephPub);
                    byte[] kek = hkdf(z, p.fileId, concat("HJ01/kek/recipient".getBytes(StandardCharsets.US_ASCII), w.recipientId, w.ephPub));
                    Arrays.fill(z, (byte) 0);
                    dek = tryUnwrap(kek, w, p.core);
                }
            }
            if (dek == null) {
                if (triedSlot) throw new AuthException();
                throw new NotAuthorizedException(haveDev || havePw
                        ? "This file is not authorized for this password or this device"
                        : "A password or an authorized device is required");
            }
            byte[] plain = gcm(false, dek, p.payloadNonce, p.header, p.ciphertext);   // verifies every header byte
            return new Result(plain, p.fileId, p.maxImports, p.expires);
        } catch (HJException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new AuthException();
        } finally {
            if (dek != null) Arrays.fill(dek, (byte) 0);
        }
    }

    private static byte[] tryUnwrap(byte[] kek, Wrap w, byte[] core) throws AuthException {
        try {
            return gcm(false, kek, w.nonce, wrapAad(core, w.type, w.prefix), w.wrapped);
        } catch (GeneralSecurityException e) {
            throw new AuthException();
        } finally { Arrays.fill(kek, (byte) 0); }
    }

    /* ------------------------------------------------------------------ inspect */

    /** Structural parse only. Throws FormatException for malformed files. Values are NOT authenticated. */
    public static Info inspect(byte[] file) throws FormatException {
        Parsed p = parse(file);
        Info i = new Info();
        i.createdSec = p.created; i.expiresSec = p.expires; i.maxImports = p.maxImports; i.fileId = p.fileId;
        for (Wrap w : p.wraps) {
            if (w.type == WRAP_PASSWORD) i.hasPassword = true;
            else { i.hasRecipient = true; i.recipientIds.add(w.recipientId); }
        }
        return i;
    }

    /* ------------------------------------------------------------------ parsing */

    private static final class Wrap {
        int type, mem, iters, lanes;
        byte[] prefix, nonce, wrapped, salt, recipientId, ephPub;
    }

    private static final class Parsed {
        byte[] header, core, fileId, payloadNonce, ciphertext;
        long created, expires;
        int maxImports;
        List<Wrap> wraps = new ArrayList<>();
    }

    private static Parsed parse(byte[] f) throws FormatException {
        if (f == null || f.length < CORE_LEN + 3 + 4 + TAG_LEN || f.length > MAX_FILE) throw new FormatException("Not a valid HJ file");
        try {
            ByteBuffer b = ByteBuffer.wrap(f);
            byte[] magic = new byte[4]; b.get(magic);
            if (!Arrays.equals(magic, MAGIC)) throw new FormatException("Not an HJ01 file");
            int version = b.get() & 0xff, aead = b.get() & 0xff, kdf = b.get() & 0xff, flags = b.get() & 0xff;
            if (version != VERSION) throw new FormatException("Unsupported HJ file version");
            if (aead != AEAD_AES256GCM) throw new FormatException("Unsupported encryption algorithm");
            if (kdf != 0 && kdf != KDF_ARGON2ID) throw new FormatException("Unsupported key derivation");
            if (flags != 0) throw new FormatException("Unsupported HJ file flags");
            Parsed p = new Parsed();
            p.created = b.getLong(); p.expires = b.getLong();
            if (p.created < 0 || p.expires < 0) throw new FormatException("Invalid dates");
            p.maxImports = b.getShort() & 0xffff;
            p.fileId = new byte[16]; b.get(p.fileId);
            p.payloadNonce = new byte[12]; b.get(p.payloadNonce);
            int count = b.get() & 0xff;
            if (count < 1 || count > MAX_WRAPS) throw new FormatException("Invalid key slot count");
            p.core = Arrays.copyOfRange(f, 0, CORE_LEN);

            boolean pw = false;
            for (int i = 0; i < count; i++) {
                if (b.remaining() < 3) throw new FormatException("Truncated file");
                int type = b.get() & 0xff, len = b.getShort() & 0xffff;
                if (b.remaining() < len) throw new FormatException("Truncated file");
                byte[] body = new byte[len]; b.get(body);
                Wrap w = new Wrap(); w.type = type;
                ByteBuffer wb = ByteBuffer.wrap(body);
                if (type == WRAP_PASSWORD) {
                    if (len != PW_BODY_LEN || pw) throw new FormatException("Invalid password slot");
                    pw = true;
                    w.mem = wb.getInt(); w.iters = wb.getInt(); w.lanes = wb.get() & 0xff;
                    if (w.mem < DEC_MIN_MEM_KIB || w.mem > DEC_MAX_MEM_KIB || w.iters < 1 || w.iters > DEC_MAX_ITERS
                            || w.lanes < 1 || w.lanes > DEC_MAX_LANES) throw new FormatException("Invalid password hashing settings");
                    w.salt = new byte[16]; wb.get(w.salt);
                    w.prefix = Arrays.copyOfRange(body, 0, 25);
                    w.nonce = new byte[12]; wb.get(w.nonce);
                    w.wrapped = new byte[48]; wb.get(w.wrapped);
                } else if (type == WRAP_RECIPIENT) {
                    if (len != RCPT_BODY_LEN) throw new FormatException("Invalid recipient slot");
                    w.recipientId = new byte[8]; wb.get(w.recipientId);
                    if ((wb.get() & 0xff) != RCPT_PUB_LEN) throw new FormatException("Invalid recipient slot");
                    w.ephPub = new byte[RCPT_PUB_LEN]; wb.get(w.ephPub);
                    w.prefix = Arrays.copyOfRange(body, 0, 8 + 1 + RCPT_PUB_LEN);
                    w.nonce = new byte[12]; wb.get(w.nonce);
                    w.wrapped = new byte[48]; wb.get(w.wrapped);
                    for (Wrap o : p.wraps) if (o.type == WRAP_RECIPIENT && Arrays.equals(o.recipientId, w.recipientId))
                        throw new FormatException("Duplicate recipient slot");
                } else {
                    throw new FormatException("Unsupported key slot type");
                }
                p.wraps.add(w);
            }
            if ((kdf == KDF_ARGON2ID) != pw) throw new FormatException("Key derivation does not match key slots");
            p.header = Arrays.copyOfRange(f, 0, b.position());
            if (b.remaining() < 4) throw new FormatException("Truncated file");
            long ctLen = b.getInt() & 0xffffffffL;
            if (ctLen < TAG_LEN || ctLen > MAX_PLAINTEXT + TAG_LEN) throw new FormatException("Invalid payload size");
            if (b.remaining() != ctLen) throw new FormatException(b.remaining() < ctLen ? "Truncated file" : "Unexpected data after the file");
            p.ciphertext = new byte[(int) ctLen]; b.get(p.ciphertext);
            return p;
        } catch (java.nio.BufferUnderflowException e) {
            throw new FormatException("Truncated file");
        }
    }

    /* ------------------------------------------------------------------ primitives */

    private static byte[] entry(int type, byte[] body) {
        return ByteBuffer.allocate(3 + body.length).put((byte) type).putShort((short) body.length).put(body).array();
    }

    private static byte[] wrapAad(byte[] core, int type, byte[] prefix) {
        return concat("HJ01-WRAP".getBytes(StandardCharsets.US_ASCII), core, new byte[]{(byte) type}, prefix);
    }

    private static byte[] gcm(boolean enc, byte[] key, byte[] nonce, byte[] aad, byte[] data) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(enc ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD(aad);
        return c.doFinal(data);
    }

    private static byte[] passwordBytes(char[] pw) {
        String n = Normalizer.normalize(new String(pw), Normalizer.Form.NFKC);
        return n.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] argon2(byte[] pw, byte[] salt, int memKiB, int iters, int lanes) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13).withIterations(iters).withMemoryAsKB(memKiB)
                .withParallelism(lanes).withSalt(salt).build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[32];
        gen.generateBytes(pw, out);
        Arrays.fill(pw, (byte) 0);
        return out;
    }

    /** HKDF-SHA-256 (RFC 5869), one 32-byte output block. */
    private static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(info);
            mac.update((byte) 1);
            byte[] okm = mac.doFinal();
            Arrays.fill(prk, (byte) 0);
            return okm;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, o, p.length); o += p.length; }
        return out;
    }
}
