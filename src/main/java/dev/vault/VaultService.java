package dev.vault;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.*;

@Service
public class VaultService {
    static final SecureRandom RANDOM = new SecureRandom();
    private final JdbcTemplate db;
    private final BCryptPasswordEncoder encoder;
    private final String dummyVerifier;
    private final Map<String, Bucket> limits = new HashMap<>();
    private record Bucket(long until, int count) {}
    record User(UUID id, String salt, String verifier) {}
    public record Session(String token, Instant expiresAt) {}
    public record Entry(UUID id, String iv, String ciphertext, long revision) {}

    public VaultService(JdbcTemplate db, BCryptPasswordEncoder encoder) {
        this.db = db; this.encoder = encoder; this.dummyVerifier = encoder.encode(randomBase64(32));
    }
    static String randomBase64(int size) {
        byte[] bytes = new byte[size]; RANDOM.nextBytes(bytes); return Base64.getEncoder().encodeToString(bytes);
    }
    static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    static String email(String value) { return value.strip().toLowerCase(Locale.ROOT); }
    synchronized void rateLimit(String key, int max, int seconds) {
        long now = System.currentTimeMillis();
        limits.entrySet().removeIf(e -> e.getValue().until < now);
        Bucket b = limits.getOrDefault(key, new Bucket(now + seconds * 1000L, 0));
        if (b.count >= max || (!limits.containsKey(key) && limits.size() >= 20000))
            throw new ResponseStatusException(TOO_MANY_REQUESTS, "Слишком много попыток. Повторите позже.");
        limits.put(key, new Bucket(b.until, b.count + 1));
    }
    Optional<User> findUser(String email) {
        return db.query("SELECT id, salt, verifier FROM vault_user WHERE email = ?",
            (rs, n) -> new User(rs.getObject("id", UUID.class), rs.getString("salt"), rs.getString("verifier")), email(email)).stream().findFirst();
    }
    String salt(String email) { return findUser(email).map(User::salt).orElseGet(() -> randomBase64(32)); }

    @Transactional
    public Session register(String email, String salt, String authKey) {
        UUID id = UUID.randomUUID();
        db.update("INSERT INTO vault_user(id, email, salt, verifier) VALUES (?, ?, ?, ?)", id, email(email), salt, encoder.encode(authKey));
        return newSession(id);
    }
    public Session login(String email, String authKey) {
        rateLimit("email:" + hash(email(email)), 10, 900);
        Optional<User> user = findUser(email);
        boolean match = encoder.matches(authKey, user.map(User::verifier).orElse(dummyVerifier));
        if (user.isEmpty() || !match) throw new ResponseStatusException(UNAUTHORIZED, "Неверный email, мастер-пароль или секретный ключ.");
        return newSession(user.get().id);
    }
    private Session newSession(UUID user) {
        String token = randomBase64(32);
        Instant expiry = Instant.now().plus(30, ChronoUnit.MINUTES);
        db.update("INSERT INTO vault_session(token_hash, user_id, expires_at) VALUES (?, ?, ?)", hash(token), user, java.sql.Timestamp.from(expiry));
        return new Session(token, expiry);
    }
    public Optional<UUID> authenticate(String token) {
        return db.query("SELECT user_id FROM vault_session WHERE token_hash = ? AND expires_at > ?",
            (rs, n) -> rs.getObject(1, UUID.class), hash(token), java.sql.Timestamp.from(Instant.now())).stream().findFirst();
    }
    public void logout(String token) { db.update("DELETE FROM vault_session WHERE token_hash = ?", hash(token)); }
    @Scheduled(fixedDelay = 300000)
    public void cleanup() { db.update("DELETE FROM vault_session WHERE expires_at <= ?", java.sql.Timestamp.from(Instant.now())); }
    public List<Entry> list(UUID owner) {
        return db.query("SELECT id, iv, ciphertext, revision FROM vault_entry WHERE user_id = ? ORDER BY updated_at DESC",
            (rs, n) -> new Entry(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getLong(4)), owner);
    }
    @Transactional
    public Entry save(UUID owner, UUID id, String iv, String ciphertext, long revision) {
        if (revision == 0) {
            db.update("INSERT INTO vault_entry(id, user_id, iv, ciphertext) VALUES (?, ?, ?, ?)", id, owner, iv, ciphertext);
            return new Entry(id, iv, ciphertext, 1);
        }
        int count = db.update("UPDATE vault_entry SET iv = ?, ciphertext = ?, revision = revision + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND revision = ?",
            iv, ciphertext, id, owner, revision);
        if (count == 0) throw new ResponseStatusException(CONFLICT, "Запись изменена или недоступна. Обновите список.");
        return new Entry(id, iv, ciphertext, revision + 1);
    }
    public void delete(UUID owner, UUID id) {
        if (db.update("DELETE FROM vault_entry WHERE id = ? AND user_id = ?", id, owner) == 0)
            throw new ResponseStatusException(NOT_FOUND, "Запись не найдена.");
    }
}
