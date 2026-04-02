package ch.furchert.homelab.auth.dto;

public record LoginResponse(
        String accessToken,
        String refreshToken
) {}
