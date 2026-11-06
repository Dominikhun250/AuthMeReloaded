package fr.xephi.authme.datasource.hashing;

import ch.jalu.datasourcecolumns.data.DataSourceValue;
import fr.xephi.authme.ConsoleLogger;
import fr.xephi.authme.data.auth.PlayerAuth;
import fr.xephi.authme.datasource.DataSource;
import fr.xephi.authme.datasource.DataSourceType;
import fr.xephi.authme.output.ConsoleLoggerFactory;
import fr.xephi.authme.security.crypts.HashedPassword;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public class HashedIdentityDataSource implements DataSource {
    private static final int MAX_KNOWN_NAMES = 10_000;

    public static final String HIDDEN_IP = "hidden";

    private final ConsoleLogger logger = ConsoleLoggerFactory.get(HashedIdentityDataSource.class);
    private final DataSource delegate;
    private final IdentityHasher hasher;
    private final PlayerIdentityRegistry registry;

    private final Map<String, String> ipRecords = new java.util.concurrent.ConcurrentHashMap<>();
    private volatile boolean ipRecordsLoaded;
    private final Map<String, String> namesByKey = Collections.synchronizedMap(
        new LinkedHashMap<String, String>(256, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
                return size() > MAX_KNOWN_NAMES;
            }
        });

    public HashedIdentityDataSource(DataSource delegate, IdentityHasher hasher, PlayerIdentityRegistry registry) {
        this.delegate = delegate;
        this.hasher = hasher;
        this.registry = registry;
    }

    public void migratePlainAccounts() {
        int converted = 0;
        int failed = 0;
        for (PlayerAuth plain : delegate.getAllAuths()) {
            if (IdentityHasher.isKey(plain.getNickname())) {
                continue;
            }
            UUID uuid = plain.getUuid() != null
                ? plain.getUuid() : PlayerIdentityRegistry.offlineUuid(plain.getRealName());
            String key = hasher.uuidKey(uuid);
            PlayerAuth storage = copy(plain, key,
                hasher.createNameRecord(plain.getNickname(), plain.getRealName()), null,
                hashPlainIp(plain.getLastIp()), hashPlainIp(plain.getRegistrationIp()));
            if (!delegate.isAuthAvailable(key) && !delegate.saveAuth(storage)) {
                logger.warning("Could not convert the account '" + plain.getNickname() + "' (kept unchanged)");
                ++failed;
                continue;
            }
            delegate.updateSession(storage);
            delegate.updateQuitLoc(storage);
            if (plain.getTotpKey() != null) {
                delegate.setTotpKey(key, plain.getTotpKey());
            }
            if (plain.getPremiumUuid() != null) {
                delegate.updatePremiumUuid(storage);
            }
            delegate.removeAuth(plain.getNickname());
            namesByKey.put(key, plain.getRealName());
            ipRecords.remove(key);
            ipRecordsLoaded = false;
            ++converted;
        }
        if (converted > 0 || failed > 0) {
            logger.info("Hashed identities: converted " + converted + " account(s), " + failed + " failed");
        }
    }

    private String keyOf(String user) {
        return IdentityHasher.isKey(user) ? user : hasher.uuidKey(registry.resolve(user));
    }

    private String keyOf(PlayerAuth auth) {
        String nick = auth.getNickname();
        if (IdentityHasher.isKey(nick)) {
            return nick;
        }
        UUID uuid = auth.getUuid() != null ? auth.getUuid() : registry.resolve(nick);
        return hasher.uuidKey(uuid);
    }

    private PlayerAuth copy(PlayerAuth src, String name, String realName, UUID uuid) {
        return copy(src, name, realName, uuid, src.getLastIp(), src.getRegistrationIp());
    }

    private PlayerAuth copy(PlayerAuth src, String name, String realName, UUID uuid,
                            String lastIp, String registrationIp) {
        return PlayerAuth.builder()
            .name(name)
            .realName(realName)
            .password(src.getPassword())
            .totpKey(src.getTotpKey())
            .lastIp(lastIp)
            .email(src.getEmail())
            .groupId(src.getGroupId())
            .lastLogin(src.getLastLogin())
            .registrationIp(registrationIp)
            .registrationDate(src.getRegistrationDate())
            .locX(src.getQuitLocX())
            .locY(src.getQuitLocY())
            .locZ(src.getQuitLocZ())
            .locWorld(src.getWorld())
            .locYaw(src.getYaw())
            .locPitch(src.getPitch())
            .uuid(uuid)
            .premiumUuid(src.getPremiumUuid())
            .build();
    }

    private String hashPlainIp(String ip) {
        return ip == null || IdentityHasher.isIpRecord(ip) ? ip : hasher.createIpRecord(ip);
    }

    private PlayerAuth toStorage(PlayerAuth auth, boolean includeRegistrationIp) {
        String key = keyOf(auth);
        boolean keyOnly = IdentityHasher.isKey(auth.getNickname());
        boolean hiddenIp = HIDDEN_IP.equals(auth.getLastIp())
            || (includeRegistrationIp && HIDDEN_IP.equals(auth.getRegistrationIp()));
        PlayerAuth stored = keyOnly || hiddenIp ? delegate.getAuth(key) : null;

        String record;
        if (keyOnly) {
            record = stored == null ? auth.getRealName() : stored.getRealName();
        } else {
            record = hasher.createNameRecord(auth.getNickname(), auth.getRealName());
            namesByKey.put(key, auth.getRealName());
        }

        String lastIp = auth.getLastIp();
        if (HIDDEN_IP.equals(lastIp)) {
            lastIp = stored == null ? null : stored.getLastIp();
        } else if (lastIp != null && !IdentityHasher.isIpRecord(lastIp)) {
            if (!keyOnly) {
                registry.rememberIp(auth.getNickname(), lastIp);
            }
            lastIp = hasher.createIpRecord(lastIp);
        }
        String regIp = auth.getRegistrationIp();
        if (!includeRegistrationIp) {
            regIp = null;
        } else if (HIDDEN_IP.equals(regIp)) {
            regIp = stored == null ? null : stored.getRegistrationIp();
        } else {
            regIp = hashPlainIp(regIp);
        }
        return copy(auth, key, record, null, lastIp, regIp);
    }

    private void putIpRecord(String key, String record) {
        if (record == null) {
            ipRecords.remove(key);
        } else {
            ipRecords.put(key, record);
        }
    }

    private void ensureIpRecordsLoaded() {
        if (ipRecordsLoaded) {
            return;
        }
        synchronized (ipRecords) {
            if (!ipRecordsLoaded) {
                ipRecords.clear();
                for (PlayerAuth raw : delegate.getAllAuths()) {
                    if (IdentityHasher.isKey(raw.getNickname()) && raw.getLastIp() != null) {
                        ipRecords.put(raw.getNickname(), raw.getLastIp());
                    }
                }
                ipRecordsLoaded = true;
            }
        }
    }

    private String resolveIp(String stored, List<String> candidates) {
        if (stored == null || !IdentityHasher.isIpRecord(stored)) {
            return stored;
        }
        for (String candidate : candidates) {
            if (hasher.matchesIp(stored, candidate)) {
                return candidate;
            }
        }
        return HIDDEN_IP;
    }

    private PlayerAuth restore(PlayerAuth raw, String name, UUID uuid) {
        IdentityHasher.NameRecord record = hasher.parse(raw.getRealName());
        if (record == null || !hasher.matchesName(record, name)) {
            return null;
        }
        String realName = name.toLowerCase(Locale.ROOT);
        String known = namesByKey.get(raw.getNickname());
        if (hasher.matchesRealName(record, name)) {
            realName = name;
        } else if (known != null && hasher.matchesRealName(record, known)) {
            realName = known;
        }
        namesByKey.put(raw.getNickname(), realName);
        List<String> ips = registry.getIps(name);
        return copy(raw, name.toLowerCase(Locale.ROOT), realName, uuid,
            resolveIp(raw.getLastIp(), ips), resolveIp(raw.getRegistrationIp(), ips));
    }

    private String displayName(String key) {
        String known = namesByKey.get(key);
        return known != null ? known : "#" + key.substring(0, 8);
    }

    private String resolveRecord(String stored) {
        IdentityHasher.NameRecord record = hasher.parse(stored);
        if (record == null) {
            return null;
        }
        List<String> candidates;
        synchronized (namesByKey) {
            candidates = new ArrayList<>(namesByKey.values());
        }
        for (String candidate : candidates) {
            if (hasher.matchesRealName(record, candidate)) {
                return candidate;
            }
        }
        return null;
    }

    @Override
    public boolean isAuthAvailable(String user) {
        return getAuth(user) != null;
    }

    @Override
    public PlayerAuth getAuth(String user) {
        if (IdentityHasher.isKey(user)) {
            PlayerAuth raw = delegate.getAuth(user);
            return raw == null ? null : copy(raw, user, displayName(user), null,
                resolveIp(raw.getLastIp(), Collections.<String>emptyList()),
                resolveIp(raw.getRegistrationIp(), Collections.<String>emptyList()));
        }
        UUID uuid = registry.resolve(user);
        PlayerAuth raw = delegate.getAuth(hasher.uuidKey(uuid));
        return raw == null ? null : restore(raw, user, uuid);
    }

    @Override
    public HashedPassword getPassword(String user) {
        if (!IdentityHasher.isKey(user) && getAuth(user) == null) {
            return null;
        }
        return delegate.getPassword(keyOf(user));
    }

    @Override
    public boolean removeAuth(String user) {
        if (!IdentityHasher.isKey(user) && getAuth(user) == null) {
            return false;
        }
        String key = keyOf(user);
        ipRecords.remove(key);
        return delegate.removeAuth(key);
    }

    @Override
    public boolean saveAuth(PlayerAuth auth) {
        PlayerAuth storage = toStorage(auth, true);
        boolean saved = delegate.saveAuth(storage);
        if (saved) {
            putIpRecord(storage.getNickname(), storage.getLastIp());
        }
        return saved;
    }

    @Override
    public boolean updateSession(PlayerAuth auth) {
        PlayerAuth storage = toStorage(auth, false);
        boolean updated = delegate.updateSession(storage);
        if (updated) {
            putIpRecord(storage.getNickname(), storage.getLastIp());
        }
        return updated;
    }

    @Override
    public boolean updatePassword(PlayerAuth auth) {
        return delegate.updatePassword(toStorage(auth, false));
    }

    @Override
    public boolean updatePassword(String user, HashedPassword password) {
        return delegate.updatePassword(keyOf(user), password);
    }

    @Override
    public boolean updateQuitLoc(PlayerAuth auth) {
        return delegate.updateQuitLoc(copy(auth, keyOf(auth), auth.getRealName(), null));
    }

    @Override
    public boolean updateEmail(PlayerAuth auth) {
        return delegate.updateEmail(copy(auth, keyOf(auth), auth.getRealName(), null));
    }

    @Override
    public boolean updatePremiumUuid(PlayerAuth auth) {
        return delegate.updatePremiumUuid(copy(auth, keyOf(auth), auth.getRealName(), null));
    }

    @Override
    public boolean updateRealName(String user, String realName) {
        String key = keyOf(user);
        namesByKey.put(key, realName);
        return delegate.updateRealName(key, hasher.createNameRecord(user, realName));
    }

    @Override
    public boolean setTotpKey(String user, String totpKey) {
        return delegate.setTotpKey(keyOf(user), totpKey);
    }

    @Override
    public boolean isLogged(String user) {
        return delegate.isLogged(keyOf(user));
    }

    @Override
    public void setLogged(String user) {
        delegate.setLogged(keyOf(user));
    }

    @Override
    public void setUnlogged(String user) {
        delegate.setUnlogged(keyOf(user));
    }

    @Override
    public boolean hasSession(String user) {
        return delegate.hasSession(keyOf(user));
    }

    @Override
    public void grantSession(String user) {
        delegate.grantSession(keyOf(user));
    }

    @Override
    public void revokeSession(String user) {
        delegate.revokeSession(keyOf(user));
    }

    @Override
    public DataSourceValue<String> getEmail(String user) {
        return delegate.getEmail(keyOf(user));
    }

    @Override
    public Set<String> getRecordsToPurge(long until) {
        return delegate.getRecordsToPurge(until);
    }

    @Override
    public void purgeRecords(Collection<String> toPurge) {
        List<String> keys = new ArrayList<>(toPurge.size());
        for (String entry : toPurge) {
            String key = keyOf(entry);
            keys.add(key);
            ipRecords.remove(key);
        }
        delegate.purgeRecords(keys);
    }

    @Override
    public List<String> getAllAuthsByIp(String ip) {
        ensureIpRecordsLoaded();
        List<String> result = new ArrayList<>();
        for (Map.Entry<String, String> entry : ipRecords.entrySet()) {
            if (hasher.matchesIp(entry.getValue(), ip)) {
                result.add(displayName(entry.getKey()));
            }
        }
        return result;
    }

    @Override
    public List<String> getLoggedPlayersWithEmptyMail() {
        List<String> result = new ArrayList<>();
        for (String stored : delegate.getLoggedPlayersWithEmptyMail()) {
            String name = resolveRecord(stored);
            if (name != null) {
                result.add(name);
            }
        }
        return result;
    }

    @Override
    public List<PlayerAuth> getAllAuths() {
        List<PlayerAuth> result = new ArrayList<>();
        for (PlayerAuth raw : delegate.getAllAuths()) {
            String key = raw.getNickname();
            if (IdentityHasher.isKey(key)) {
                result.add(copy(raw, key, displayName(key), null,
                    resolveIp(raw.getLastIp(), Collections.<String>emptyList()),
                    resolveIp(raw.getRegistrationIp(), Collections.<String>emptyList())));
            } else {
                result.add(raw);
            }
        }
        return result;
    }

    @Override
    public List<PlayerAuth> getRecentlyLoggedInPlayers() {
        List<PlayerAuth> result = new ArrayList<>();
        for (PlayerAuth raw : delegate.getRecentlyLoggedInPlayers()) {
            String key = raw.getNickname();
            String name = resolveRecord(raw.getRealName());
            result.add(copy(raw, key, name != null ? name : displayName(key), null,
                resolveIp(raw.getLastIp(), Collections.<String>emptyList()),
                resolveIp(raw.getRegistrationIp(), Collections.<String>emptyList())));
        }
        return result;
    }

    @Override
    public List<String> getPremiumUsernames() {
        List<String> result = new ArrayList<>();
        for (String key : delegate.getPremiumUsernames()) {
            String known = namesByKey.get(key);
            if (known != null) {
                result.add(known.toLowerCase(Locale.ROOT));
            }
        }
        return result;
    }

    @Override
    public int countAuthsByEmail(String email) {
        return delegate.countAuthsByEmail(email);
    }

    @Override
    public void purgeLogged() {
        delegate.purgeLogged();
    }

    @Override
    public int getAccountsRegistered() {
        return delegate.getAccountsRegistered();
    }

    @Override
    public void closeConnection() {
        delegate.closeConnection();
    }

    @Override
    public DataSourceType getType() {
        return delegate.getType();
    }

    @Override
    public boolean isCached() {
        return delegate.isCached();
    }

    @Override
    public void reload() {
        delegate.reload();
    }
}
