package dev.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import org.springframework.http.MediaType;

@SpringBootTest
@AutoConfigureMockMvc
class VaultIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired JdbcTemplate db;

    String register(String email, String key) throws Exception {
        return json.readTree(mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
            .content(json.writeValueAsString(Map.of("email",email,"salt",VaultService.randomBase64(32),"authKey",key))))
            .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString()).get("token").asText();
    }
    String body(long revision) throws Exception {
        return json.writeValueAsString(Map.of("iv",VaultService.randomBase64(12),"ciphertext",VaultService.randomBase64(80),"revision",revision));
    }
    @Test void registrationLoginRevocationAndNoPlaintextCredentialStorage() throws Exception {
        String email = "alice-"+UUID.randomUUID()+"@example.com", key = VaultService.randomBase64(32);
        String token = register(email,key);
        String stored = db.queryForObject("SELECT verifier FROM vault_user WHERE email = ?",String.class,email);
        assertThat(stored).startsWith("$2a$12$").isNotEqualTo(key);
        assertThat(db.queryForObject("SELECT count(*) FROM vault_session WHERE token_hash = ?",Integer.class,token)).isZero();
        mvc.perform(post("/api/auth/params").contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("email",email))))
            .andExpect(status().isOk()).andExpect(jsonPath("$.iterations").value(600000));
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
            .content(json.writeValueAsString(Map.of("email",email,"authKey",VaultService.randomBase64(32)))))
            .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
            .content(json.writeValueAsString(Map.of("email",email,"authKey",key)))).andExpect(status().isOk());
        mvc.perform(post("/api/auth/logout").header("Authorization","Bearer "+token)).andExpect(status().isNoContent());
        mvc.perform(get("/api/entries").header("Authorization","Bearer "+token)).andExpect(status().isUnauthorized());
    }
    @Test void entriesAreIsolatedAndStaleUpdatesAreRejected() throws Exception {
        String alice = register("a-"+UUID.randomUUID()+"@example.com", VaultService.randomBase64(32));
        String bob = register("b-"+UUID.randomUUID()+"@example.com", VaultService.randomBase64(32));
        String id = UUID.randomUUID().toString();
        mvc.perform(put("/api/entries/"+id).header("Authorization","Bearer "+alice).contentType(MediaType.APPLICATION_JSON).content(body(0)))
            .andExpect(status().isOk()).andExpect(jsonPath("$.revision").value(1));
        mvc.perform(get("/api/entries").header("Authorization","Bearer "+bob)).andExpect(status().isOk()).andExpect(content().json("[]"));
        mvc.perform(put("/api/entries/"+id).header("Authorization","Bearer "+bob).contentType(MediaType.APPLICATION_JSON).content(body(1)))
            .andExpect(status().isConflict());
        mvc.perform(delete("/api/entries/"+id).header("Authorization","Bearer "+bob)).andExpect(status().isNotFound());
        mvc.perform(put("/api/entries/"+id).header("Authorization","Bearer "+alice).contentType(MediaType.APPLICATION_JSON).content(body(1)))
            .andExpect(status().isOk()).andExpect(jsonPath("$.revision").value(2));
        mvc.perform(put("/api/entries/"+id).header("Authorization","Bearer "+alice).contentType(MediaType.APPLICATION_JSON).content(body(1)))
            .andExpect(status().isConflict());
        mvc.perform(delete("/api/entries/"+id).header("Authorization","Bearer "+alice)).andExpect(status().isNoContent());
    }
    @Test void expiredSessionsAndMalformedPayloadsAreRejected() throws Exception {
        String token = register("expiry-"+UUID.randomUUID()+"@example.com",VaultService.randomBase64(32));
        mvc.perform(put("/api/entries/"+UUID.randomUUID()).header("Authorization","Bearer "+token).contentType(MediaType.APPLICATION_JSON)
            .content("{\"iv\":\"bad\",\"ciphertext\":\"plaintext\",\"revision\":0}")).andExpect(status().isBadRequest());
        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isBadRequest());
        db.update("UPDATE vault_session SET expires_at = ? WHERE token_hash = ?", Timestamp.from(Instant.now().minusSeconds(1)),VaultService.hash(token));
        mvc.perform(get("/api/entries").header("Authorization","Bearer "+token)).andExpect(status().isUnauthorized());
        mvc.perform(get("/")).andExpect(status().isOk())
            .andExpect(header().string("Cache-Control","no-store"))
            .andExpect(header().exists("Content-Security-Policy"))
            .andExpect(header().string("X-Frame-Options","DENY"));
    }
    @Test void loginHasAccountRateLimit() throws Exception {
        String email = "rate-"+UUID.randomUUID()+"@example.com";
        for (int i=0;i<10;i++) mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
            .content(json.writeValueAsString(Map.of("email",email,"authKey",VaultService.randomBase64(32)))))
            .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
            .content(json.writeValueAsString(Map.of("email",email,"authKey",VaultService.randomBase64(32)))))
            .andExpect(status().isTooManyRequests());
    }
}
