package fr.xephi.authme.datasource.hashing;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;

import javax.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

public class PlayerIdentityRegistry {
    private static final int MAX_ENTRIES = 10_000;

    private final Map<String, UUID> uuidsByName = Collections.synchronizedMap(
        new LinkedHashMap<String, UUID>(256, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, UUID> eldest) {
                return size() > MAX_ENTRIES;
            }
        });

    private final Map<String, java.util.List<String>> ipsByName = Collections.synchronizedMap(
        new LinkedHashMap<String, java.util.List<String>>(256, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, java.util.List<String>> eldest) {
                return size() > MAX_ENTRIES;
            }
        });

    @Inject
    public PlayerIdentityRegistry() {
    }

    public void remember(String name, UUID uuid) {
        if (name != null && uuid != null) {
            uuidsByName.put(name.toLowerCase(Locale.ROOT), uuid);
        }
    }

    public void rememberIp(String name, String ip) {
        if (name == null || ip == null) {
            return;
        }
        synchronized (ipsByName) {
            java.util.List<String> ips = ipsByName.computeIfAbsent(
                name.toLowerCase(Locale.ROOT), k -> new java.util.ArrayList<>());
            ips.remove(ip);
            ips.add(0, ip);
            while (ips.size() > 3) {
                ips.remove(ips.size() - 1);
            }
        }
    }

    public java.util.List<String> getIps(String name) {
        synchronized (ipsByName) {
            java.util.List<String> ips = ipsByName.get(name.toLowerCase(Locale.ROOT));
            return ips == null ? Collections.<String>emptyList() : new java.util.ArrayList<>(ips);
        }
    }

    public UUID resolve(String name) {
        UUID known = uuidsByName.get(name.toLowerCase(Locale.ROOT));
        if (known != null) {
            return known;
        }
        try {
            Player online = Bukkit.getPlayerExact(name);
            if (online != null) {
                return online.getUniqueId();
            }
            @SuppressWarnings("deprecation")
            UUID offline = Bukkit.getOfflinePlayer(name).getUniqueId();
            if (offline != null) {
                return offline;
            }
        } catch (RuntimeException | LinkageError e) {
        }
        return offlineUuid(name);
    }

    public static UUID offlineUuid(String name) {
        return UUID.nameUUIDFromBytes(("OfflinePlayer:" + name).getBytes(StandardCharsets.UTF_8));
    }
}
