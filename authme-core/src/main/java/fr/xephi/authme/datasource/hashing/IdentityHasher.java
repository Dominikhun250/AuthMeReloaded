package fr.xephi.authme.datasource.hashing;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.UUID;

public final class IdentityHasher {
    public static final int KEY_LENGTH = 64;

    private static final int IP_SALT_LENGTH = 8;
    private static final int IP_HASH_LENGTH = 32;
    private static final int IP_RECORD_LENGTH = IP_SALT_LENGTH + IP_HASH_LENGTH;
    private static final String VERSION = "v1";
    private static final String SEPARATOR = "$";
    private static final int RANDOM_SALT_BYTES = 16;
    private static final int MIN_UUID_SALT_LENGTH = 32;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private final byte[] uuidSalt;

    public IdentityHasher(String uuidSalt) {
        if (!isValidUuidSalt(uuidSalt)) {
            throw new IllegalArgumentException("The UUID salt must be at least " + MIN_UUID_SALT_LENGTH
                + " characters long");
        }
        this.uuidSalt = uuidSalt.getBytes(StandardCharsets.UTF_8);
    }

    public static String generateSalt() {
        return randomHex(32);
    }

    public static boolean isValidUuidSalt(String salt) {
        return salt != null && salt.trim().length() >= MIN_UUID_SALT_LENGTH;
    }

    public static boolean isKey(String value) {
        if (value == null || value.length() != KEY_LENGTH) {
            return false;
        }
        for (int i = 0; i < value.length(); ++i) {
            char c = value.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    public String uuidKey(UUID uuid) {
        return hex(digest(uuidSalt, uuid.toString().getBytes(StandardCharsets.UTF_8)));
    }

    public String createNameRecord(String lowercaseName, String realName) {
        String nameSalt = randomHex(RANDOM_SALT_BYTES);
        String realSalt = randomHex(RANDOM_SALT_BYTES);
        return VERSION + SEPARATOR + nameSalt + SEPARATOR + saltedHash(nameSalt, normalize(lowercaseName))
            + SEPARATOR + realSalt + SEPARATOR + saltedHash(realSalt, realName);
    }

    public NameRecord parse(String record) {
        if (record == null) {
            return null;
        }
        String[] parts = record.split("\\$", -1);
        if (parts.length != 5 || !VERSION.equals(parts[0])) {
            return null;
        }
        return new NameRecord(parts[1], parts[2], parts[3], parts[4]);
    }

    public boolean matchesName(NameRecord record, String name) {
        return name != null && constantTimeEquals(record.nameHash, saltedHash(record.nameSalt, normalize(name)));
    }

    public boolean matchesRealName(NameRecord record, String realName) {
        return realName != null && constantTimeEquals(record.realHash, saltedHash(record.realSalt, realName));
    }

    public String createIpRecord(String ip) {
        String salt = randomHex(4);
        return salt + saltedHash(salt, ip).substring(0, IP_HASH_LENGTH);
    }

    public static boolean isIpRecord(String value) {
        if (value == null || value.length() != IP_RECORD_LENGTH) {
            return false;
        }
        for (int i = 0; i < value.length(); ++i) {
            char c = value.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    public boolean matchesIp(String record, String ip) {
        if (ip == null || !isIpRecord(record)) {
            return false;
        }
        String salt = record.substring(0, IP_SALT_LENGTH);
        return constantTimeEquals(record.substring(IP_SALT_LENGTH),
            saltedHash(salt, ip).substring(0, IP_HASH_LENGTH));
    }

    private static String normalize(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    private static String saltedHash(String saltHex, String value) {
        return hex(digest(saltHex.getBytes(StandardCharsets.UTF_8), value.getBytes(StandardCharsets.UTF_8)));
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] digest(byte[] salt, byte[] value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            md.update((byte) 0);
            md.update(value);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static String randomHex(int byteCount) {
        byte[] bytes = new byte[byteCount];
        RANDOM.nextBytes(bytes);
        return hex(bytes);
    }

    private static String hex(byte[] bytes) {
        char[] chars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; ++i) {
            chars[i * 2] = HEX[(bytes[i] >> 4) & 0xF];
            chars[i * 2 + 1] = HEX[bytes[i] & 0xF];
        }
        return new String(chars);
    }

    public static final class NameRecord {
        private final String nameSalt;
        private final String nameHash;
        private final String realSalt;
        private final String realHash;

        NameRecord(String nameSalt, String nameHash, String realSalt, String realHash) {
            this.nameSalt = nameSalt;
            this.nameHash = nameHash;
            this.realSalt = realSalt;
            this.realHash = realHash;
        }
    }
}
