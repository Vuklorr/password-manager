package dev.vault;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api")
public class VaultController {
    private final VaultService service;
    public VaultController(VaultService service) { this.service = service; }
    record EmailRequest(@NotBlank @Email @Size(max=254) String email) {}
    record RegisterRequest(@NotBlank @Email @Size(max=254) String email,
        @NotNull @Pattern(regexp="[A-Za-z0-9+/]{43}=") String salt,
        @NotNull @Pattern(regexp="[A-Za-z0-9+/]{43}=") String authKey) {}
    record LoginRequest(@NotBlank @Email @Size(max=254) String email,
        @NotNull @Pattern(regexp="[A-Za-z0-9+/]{43}=") String authKey) {}
    record EntryRequest(@NotNull @Pattern(regexp="[A-Za-z0-9+/]{16}") String iv,
        @NotNull @Size(min=24,max=45000) @Pattern(regexp="[A-Za-z0-9+/]+={0,2}") String ciphertext,
        @Min(0) long revision) {}

    void limit(HttpServletRequest request) { service.rateLimit("ip:" + request.getRemoteAddr(), 60, 60); }
    @GetMapping("/health") Map<String, String> health() { return Map.of("status", "ok"); }
    @PostMapping("/auth/params") Map<String, Object> params(@Valid @RequestBody EmailRequest body, HttpServletRequest req) {
        limit(req); return Map.of("salt", service.salt(body.email), "iterations", 600000, "version", 1);
    }
    @PostMapping("/auth/register") @ResponseStatus(HttpStatus.CREATED)
    VaultService.Session register(@Valid @RequestBody RegisterRequest body, HttpServletRequest req) {
        limit(req); return service.register(body.email, body.salt, body.authKey);
    }
    @PostMapping("/auth/login") VaultService.Session login(@Valid @RequestBody LoginRequest body, HttpServletRequest req) {
        limit(req); return service.login(body.email, body.authKey);
    }
    @PostMapping("/auth/logout") @ResponseStatus(HttpStatus.NO_CONTENT)
    void logout(@RequestHeader("Authorization") String bearer) { service.logout(bearer.substring(7)); }
    @GetMapping("/entries") List<VaultService.Entry> entries(Authentication auth) { return service.list((UUID)auth.getPrincipal()); }
    @PutMapping("/entries/{id}") VaultService.Entry save(Authentication auth, @PathVariable UUID id, @Valid @RequestBody EntryRequest body) {
        return service.save((UUID)auth.getPrincipal(), id, body.iv, body.ciphertext, body.revision);
    }
    @DeleteMapping("/entries/{id}") @ResponseStatus(HttpStatus.NO_CONTENT)
    void delete(Authentication auth, @PathVariable UUID id) { service.delete((UUID)auth.getPrincipal(), id); }
}

@RestControllerAdvice
class ApiErrors {
    @ExceptionHandler(ResponseStatusException.class)
    org.springframework.http.ResponseEntity<Map<String,String>> status(ResponseStatusException e) {
        return org.springframework.http.ResponseEntity.status(e.getStatusCode()).body(Map.of("error", e.getReason() == null ? "Ошибка запроса" : e.getReason()));
    }
    @ExceptionHandler(DataIntegrityViolationException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    Map<String,String> conflict() { return Map.of("error", "Невозможно сохранить: аккаунт или запись уже существует."); }
    @ExceptionHandler({MethodArgumentNotValidException.class, org.springframework.http.converter.HttpMessageNotReadableException.class,
        org.springframework.web.method.annotation.MethodArgumentTypeMismatchException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    Map<String,String> invalid() { return Map.of("error", "Неверный формат данных."); }
}
