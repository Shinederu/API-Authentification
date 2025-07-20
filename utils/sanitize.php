<?php

function sanitizeRegisterInput(array $data): array
{
    return [
        'username' => trim(htmlspecialchars($data['username'] ?? '', ENT_QUOTES, 'UTF-8')),
        'email' => trim(htmlspecialchars($data['email'] ?? '', ENT_QUOTES, 'UTF-8')),
        'password' => $data['password'] ?? '',
    ];
}

function sanitizeLoginInput(array $data): array
{
    // login = username ou email + password
    return [
        'username' => trim(htmlspecialchars($data['username'] ?? '', ENT_QUOTES, 'UTF-8')),
        'password' => $data['password'] ?? '',
    ];
}

function sanitizeVerifyEmailInput(array $data): array
{
    return [
        'token' => trim($data['token'] ?? ''),
    ];
}

?>