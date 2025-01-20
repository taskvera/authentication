<?php
return [
    'app' => [
        'env'   => $_ENV['APP_ENV'] ?? 'production',
        'debug' => filter_var($_ENV['APP_DEBUG'] ?? false, FILTER_VALIDATE_BOOLEAN),
    ],
    'database' => [
        'host' => $_ENV['DB_HOST'] ?? 'localhost',
        'name' => $_ENV['DB_NAME'] ?? 'taskvera_auth',
        'user' => $_ENV['DB_USER'] ?? 'root',
        'pass' => $_ENV['DB_PASS'] ?? '',
    ],
    'jwt' => [
        'secret'   => $_ENV['JWT_SECRET'] ?? 'your-jwt-secret-key',
        'issuer'   => 'your-domain.com',
        'audience' => 'your-domain.com',
        'expiry'   => 3600, // in seconds
    ],
];
