<?php
/**
 * /public/index.php
 *
 * A single entry point (front controller) for your application.
 */

declare(strict_types=1);

// ---------------------------------------------------------------------
// 1. Error handling & environment setup
// ---------------------------------------------------------------------
error_reporting(E_ALL);
ini_set('display_errors', '1');

// ---------------------------------------------------------------------
// 2. Define constants (adjust as needed)
// ---------------------------------------------------------------------
define('BASE_PATH', dirname(__DIR__));
define('APP_ENV', 'development'); // e.g., 'production' or 'development'

// ---------------------------------------------------------------------
// 3. Bootstrap tasks (config, DB connections, sessions, etc.)
// ---------------------------------------------------------------------
require BASE_PATH . '/vendor/autoload.php';

// Load .env variables
$dotenv = Dotenv\Dotenv::createImmutable(BASE_PATH);
$dotenv->load();

// Load configuration settings
$config = require BASE_PATH . '/src/Config/config.php';

// Establish database connection
try {
    $dsn = 'mysql:host=' . $config['database']['host'] . ';dbname=' . $config['database']['name'];
    $pdo = new PDO($dsn, $config['database']['user'], $config['database']['pass']);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    if ($config['app']['env'] === 'development') {
        die('Database connection failed: ' . $e->getMessage());
    } else {
        error_log($e->getMessage());
        die('Database connection failed.');
    }
}

// Start session if not already
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ---------------------------------------------------------------------
// 4. Simple routing logic
// ---------------------------------------------------------------------
$requestUri    = $_SERVER['REQUEST_URI'] ?? '/';
$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Strip query params
if (false !== $pos = strpos($requestUri, '?')) {
    $requestUri = substr($requestUri, 0, $pos);
}

// Define routes
$routes = [
    'GET' => [
        '/'      => 'AuthController@showLogin',
        '/login' => 'AuthController@showLogin',
    ],
    'POST' => [
        '/login'  => 'AuthController@handleLogin',
        '/logout' => 'AuthController@handleLogout',
    ],
];

/**
 * Dispatches the route.
 */
function dispatch(string $method, string $uri, array $routes)
{
    // 1) First, check if there's a direct match in $routes.
    if (isset($routes[$method]) && array_key_exists($uri, $routes[$method])) {
        $target = $routes[$method][$uri];
        return runController($target);
    }

    // 2) Fallback check: Is it something like /login/something?
    //    We'll capture "something" as the tenant.
    if ($method === 'GET' && preg_match('#^/login/([^/]+)$#', $uri, $matches)) {
        $tenant = $matches[1];
        $controller = new \App\Controllers\AuthController();
        return $controller->showLogin($tenant);
    }
    elseif ($method === 'POST' && preg_match('#^/login/([^/]+)$#', $uri, $matches)) {
        $tenant = $matches[1];
        $controller = new \App\Controllers\AuthController();
        return $controller->handleLogin($tenant);
    }

    // 3) If nothing matches, send 404
    return sendNotFound();
}

/**
 * Helper function to call the appropriate controller action.
 */
function runController(string $target)
{
    list($controller, $action) = explode('@', $target);
    $controllerClass = '\\App\\Controllers\\' . $controller;

    if (!class_exists($controllerClass)) {
        throw new \RuntimeException("Controller class {$controllerClass} not found.");
    }

    $controllerInstance = new $controllerClass();
    if (!method_exists($controllerInstance, $action)) {
        throw new \RuntimeException("Method {$action} not found in controller {$controllerClass}.");
    }

    return call_user_func([$controllerInstance, $action]);
}

/**
 * Handles 404 Not Found.
 */
function sendNotFound()
{
    header('HTTP/1.1 404 Not Found');
    include BASE_PATH . '/src/Views/404.php'; // Serve the dedicated 404 page
    exit;
}

// ---------------------------------------------------------------------
// 5. Execute the route
// ---------------------------------------------------------------------
dispatch($requestMethod, $requestUri, $routes);
