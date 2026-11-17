package com.juanvpn.app;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import javax.crypto.KeyAgreement;

/** Plain-JVM security regression tests for HJ01 (run with security-tests/run.sh). Exit code 1 on any failure. */
public class HJ01SelfTest {
    static int pass = 0, fail = 0;
    static final byte[] CFG = "{\"name\":\"test\",\"host\":\"example.com\",\"user\":\"u\",\"pass\":\"p\"}".getBytes();
    static final long NOW = 1_800_000_000L;

    static void ok(String name, boolean cond) { if (cond) { pass++; System.out.println("PASS  " + name); } else { fail++; System.out.println("FAIL  " + name); } }

    interface Thrower { void run() throws Exception; }
    static boolean rejects(Class<? extends HJ01.HJException> t, Thrower r) {
        try { r.run(); return false; } catch (Exception e) { return t.isInstance(e); }
    }

    static HJ01.Options pw(String p) {
        HJ01.Options o = new HJ01.Options();
        o.password = p.toCharArray(); o.memKiB = 19_456; o.iters = 2; o.lanes = 1; o.createdSec = NOW - 10;
        return o;
    }
    static HJ01.Credentials cpw(String p) { return new HJ01.Credentials().password(p.toCharArray()); }

    static class SoftKey implements HJ01.DeviceKey {
        final KeyPair kp; final byte[] id;
        SoftKey() throws Exception {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC"); g.initialize(new ECGenParameterSpec("secp256r1"));
            kp = g.generateKeyPair(); id = HJ01.recipientId(kp.getPublic().getEncoded());
        }
        public byte[] id() { return id; }
        public byte[] agree(byte[] peer) throws GeneralSecurityException {
            PublicKey pk = KeyFactory.getInstance("EC").generatePublic(new java.security.spec.X509EncodedKeySpec(peer));
            KeyAgreement ka = KeyAgreement.getInstance("ECDH"); ka.init(kp.getPrivate()); ka.doPhase(pk, true); return ka.generateSecret();
        }
        byte[] pub() { return kp.getPublic().getEncoded(); }
    }

    static byte[] flip(byte[] f, int i) { byte[] c = f.clone(); c[i] ^= 1; return c; }

    public static void main(String[] a) throws Exception {
        final String PW = "correct horse battery";
        byte[] file = HJ01.encrypt(CFG, pw(PW));

        // ---- basic round trip and password handling
        ok("correct password imports", Arrays.equals(HJ01.decrypt(file, cpw(PW), NOW).plaintext, CFG));
        ok("incorrect password rejected", rejects(HJ01.AuthException.class, () -> HJ01.decrypt(file, cpw("wrong password!!"), NOW)));
        ok("empty password rejected", rejects(HJ01.NotAuthorizedException.class, () -> HJ01.decrypt(file, cpw(""), NOW)));
        ok("no credentials rejected", rejects(HJ01.NotAuthorizedException.class, () -> HJ01.decrypt(file, new HJ01.Credentials(), NOW)));
        ok("password is not stored in the file", indexOf(file, PW.getBytes()) < 0);
        ok("plaintext is not in the file", indexOf(file, "example.com".getBytes()) < 0);
        ok("file starts with magic HJ01", file[0]=='H' && file[1]=='J' && file[2]=='0' && file[3]=='1');

        // ---- tamper tests: every single byte position must be rejected
        int bad = 0, accepted = 0;
        for (int i = 0; i < file.length; i++) {
            try { HJ01.decrypt(flip(file, i), cpw(PW), NOW); accepted++; }
            catch (HJ01.HJException e) { bad++; }
        }
        ok("flipping ANY single byte is rejected (" + file.length + " positions, accepted=" + accepted + ")", accepted == 0);
        int ctStart = file.length - 16 - CFG.length;
        ok("modified ciphertext rejected", rejects(HJ01.AuthException.class, () -> HJ01.decrypt(flip(file, ctStart + 3), cpw(PW), NOW)));
        ok("modified authentication tag rejected", rejects(HJ01.AuthException.class, () -> HJ01.decrypt(flip(file, file.length - 1), cpw(PW), NOW)));
        ok("modified header (created field) rejected", rejects(HJ01.AuthException.class, () -> HJ01.decrypt(flip(file, 15), cpw(PW), NOW)));
        ok("modified header (maxImports field) rejected", rejects(HJ01.AuthException.class, () -> HJ01.decrypt(flip(file, 24), cpw(PW), NOW)));

        // ---- malformed input
        ok("truncated file rejected", rejects(HJ01.FormatException.class, () -> HJ01.decrypt(Arrays.copyOf(file, file.length - 5), cpw(PW), NOW)));
        ok("every truncation length rejected safely", allTruncationsRejected(file, PW));
        ok("trailing data rejected", rejects(HJ01.FormatException.class, () -> HJ01.decrypt(concat(file, new byte[]{1}), cpw(PW), NOW)));
        ok("garbage rejected", rejects(HJ01.FormatException.class, () -> HJ01.decrypt(new byte[200], cpw(PW), NOW)));
        ok("empty rejected", rejects(HJ01.FormatException.class, () -> HJ01.decrypt(new byte[0], cpw(PW), NOW)));
        ok("bad magic rejected", rejects(HJ01.FormatException.class, () -> HJ01.decrypt(flip(file, 0), cpw(PW), NOW)));
        ok("unsupported version rejected", rejects(HJ01.FormatException.class, () -> HJ01.decrypt(setByte(file, 4, 2), cpw(PW), NOW)));
        ok("invalid AEAD id rejected", rejects(HJ01.FormatException.class, () -> HJ01.decrypt(setByte(file, 5, 9), cpw(PW), NOW)));
        ok("invalid KDF id rejected", rejects(HJ01.FormatException.class, () -> HJ01.decrypt(setByte(file, 6, 7), cpw(PW), NOW)));
        ok("KDF id downgrade (0) rejected", rejects(HJ01.FormatException.class, () -> HJ01.decrypt(setByte(file, 6, 0), cpw(PW), NOW)));
        ok("non-zero flags rejected", rejects(HJ01.FormatException.class, () -> HJ01.decrypt(setByte(file, 7, 1), cpw(PW), NOW)));
        ok("unknown slot type rejected", rejects(HJ01.FormatException.class, () -> HJ01.decrypt(setByte(file, 55, 9), cpw(PW), NOW)));
        // hostile Argon2 memory value in a file must be refused before any hashing
        byte[] hostile = file.clone(); ByteBuffer.wrap(hostile).putInt(55 + 3, 1_000_000);
        ok("hostile Argon2 memory parameter rejected", rejects(HJ01.FormatException.class, () -> HJ01.decrypt(hostile, cpw(PW), NOW)));

        // ---- nonce / key uniqueness
        byte[] f2 = HJ01.encrypt(CFG, pw(PW));
        ok("two exports of the same config differ completely", !Arrays.equals(Arrays.copyOfRange(file, 26, 54), Arrays.copyOfRange(f2, 26, 54)));
        Set<String> nonces = new HashSet<>(), ids = new HashSet<>(), salts = new HashSet<>();
        for (int i = 0; i < 40; i++) {
            byte[] f = HJ01.encrypt(CFG, pw(PW));
            nonces.add(hex(f, 42, 12)); ids.add(hex(f, 26, 16)); salts.add(hex(f, 55 + 3 + 9, 16));
        }
        ok("40 files: 40 unique payload nonces, file ids and salts", nonces.size() == 40 && ids.size() == 40 && salts.size() == 40);
        ok("same password, different files: ciphertext differs", !Arrays.equals(tail(file, 40), tail(f2, 40)));

        // ---- expiry
        HJ01.Options ex = pw(PW); ex.expiresSec = NOW + 100;
        byte[] exf = HJ01.encrypt(CFG, ex);
        ok("not-yet-expired file imports", Arrays.equals(HJ01.decrypt(exf, cpw(PW), NOW).plaintext, CFG));
        ok("expired file rejected", rejects(HJ01.ExpiredException.class, () -> HJ01.decrypt(exf, cpw(PW), NOW + 101)));
        ok("expiry value is authenticated (extending it breaks the file)", rejects(HJ01.HJException.class,
                () -> HJ01.decrypt(setLong(exf, 16, NOW + 999_999), cpw(PW), NOW + 101)));
        ok("import limit and file id are returned after authentication", maxImp(CFG) == 3);

        // ---- device / recipient binding
        SoftKey devA = new SoftKey(), devB = new SoftKey();
        HJ01.Options d = new HJ01.Options(); d.recipients.add(devA.pub()); d.createdSec = NOW - 5;
        byte[] devFile = HJ01.encrypt(CFG, d);
        ok("device-bound file opens on the authorized device", Arrays.equals(HJ01.decrypt(devFile, new HJ01.Credentials().device(devA), NOW).plaintext, CFG));
        ok("device-bound file rejected on another device", rejects(HJ01.NotAuthorizedException.class, () -> HJ01.decrypt(devFile, new HJ01.Credentials().device(devB), NOW)));
        ok("device-bound file rejected without a device key", rejects(HJ01.NotAuthorizedException.class, () -> HJ01.decrypt(devFile, cpw(PW), NOW)));
        ok("device-bound file: any flipped byte rejected", allFlipsRejectedDev(devFile, devA));
        // a device that forges its id still cannot unwrap
        HJ01.DeviceKey liar = new HJ01.DeviceKey() { public byte[] id() { return devA.id(); } public byte[] agree(byte[] p) throws GeneralSecurityException { return devB.agree(p); } };
        ok("device spoofing another device's id fails cryptographically", rejects(HJ01.AuthException.class, () -> HJ01.decrypt(devFile, new HJ01.Credentials().device(liar), NOW)));
        // multi slot: password + two devices (authorized migration = add the new device's key)
        HJ01.Options m = pw(PW); m.recipients.add(devA.pub()); m.recipients.add(devB.pub());
        byte[] multi = HJ01.encrypt(CFG, m);
        ok("multi-slot: password works", Arrays.equals(HJ01.decrypt(multi, cpw(PW), NOW).plaintext, CFG));
        ok("multi-slot: device A works", Arrays.equals(HJ01.decrypt(multi, new HJ01.Credentials().device(devA), NOW).plaintext, CFG));
        ok("multi-slot: device B works", Arrays.equals(HJ01.decrypt(multi, new HJ01.Credentials().device(devB), NOW).plaintext, CFG));
        ok("multi-slot: unknown device C rejected", rejects(HJ01.NotAuthorizedException.class, () -> HJ01.decrypt(multi, new HJ01.Credentials().device(sk()), NOW)));
        ok("password-only file never opens with a device key", rejects(HJ01.NotAuthorizedException.class, () -> HJ01.decrypt(file, new HJ01.Credentials().device(devA), NOW)));

        // ---- encrypt-side validation
        ok("encrypt refuses no password and no recipient", rejects(HJ01.FormatException.class, () -> HJ01.encrypt(CFG, new HJ01.Options())));
        HJ01.Options weak = pw(PW); weak.memKiB = 1024; weak.iters = 1;
        ok("encrypt refuses weak Argon2 settings", rejects(HJ01.FormatException.class, () -> HJ01.encrypt(CFG, weak)));
        ok("encrypt refuses a non-P-256 recipient key", rejects(HJ01.FormatException.class, () -> { HJ01.Options o = new HJ01.Options(); o.recipients.add(new byte[91]); HJ01.encrypt(CFG, o); }));
        ok("encrypt refuses empty config", rejects(HJ01.FormatException.class, () -> HJ01.encrypt(new byte[0], pw(PW))));

        // ---- defaults are strong
        HJ01.Options def = new HJ01.Options();
        ok("default Argon2id parameters: 64 MiB, t=3", def.memKiB == 65_536 && def.iters == 3);
        HJ01.Argon2Choice c = HJ01.calibrate(150, 32_768);
        ok("calibrate() returns usable parameters (m=" + c.memKiB + " t=" + c.iters + ")", c.memKiB >= 19_456 && c.iters >= 2);

        System.out.println("\n" + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }

    static int maxImp(byte[] cfg) throws Exception { HJ01.Options o = pw("correct horse battery"); o.maxImports = 3; byte[] f = HJ01.encrypt(cfg, o); HJ01.Result r = HJ01.decrypt(f, cpw("correct horse battery"), NOW); return r.maxImports; }
    static SoftKey sk() { try { return new SoftKey(); } catch (Exception e) { throw new RuntimeException(e); } }
    static boolean allTruncationsRejected(byte[] f, String pw) { for (int n = 0; n < f.length; n++) { try { HJ01.decrypt(Arrays.copyOf(f, n), cpw(pw), NOW); return false; } catch (HJ01.HJException e) { } catch (Throwable t) { return false; } } return true; }
    static boolean allFlipsRejectedDev(byte[] f, HJ01.DeviceKey k) { for (int i = 0; i < f.length; i++) { try { HJ01.decrypt(flip(f, i), new HJ01.Credentials().device(k), NOW); return false; } catch (HJ01.HJException e) { } catch (Throwable t) { return false; } } return true; }
    static byte[] setByte(byte[] f, int i, int v) { byte[] c = f.clone(); c[i] = (byte) v; return c; }
    static byte[] setLong(byte[] f, int i, long v) { byte[] c = f.clone(); ByteBuffer.wrap(c).putLong(i, v); return c; }
    static byte[] concat(byte[] a, byte[] b) { byte[] o = Arrays.copyOf(a, a.length + b.length); System.arraycopy(b, 0, o, a.length, b.length); return o; }
    static byte[] tail(byte[] f, int n) { return Arrays.copyOfRange(f, f.length - n, f.length); }
    static String hex(byte[] f, int off, int n) { StringBuilder s = new StringBuilder(); for (int i = off; i < off + n; i++) s.append(String.format("%02x", f[i])); return s.toString(); }
    static int indexOf(byte[] h, byte[] n) { outer: for (int i = 0; i <= h.length - n.length; i++) { for (int j = 0; j < n.length; j++) if (h[i + j] != n[j]) continue outer; return i; } return -1; }
}
