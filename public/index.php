<?php
/**
 * /public/index.php
 * 
 * A single entry point (front controller) for your application.
 */

// ---------------------------------------------------------------------
// 1. Error handling & environment setup
// ---------------------------------------------------------------------
declare(strict_types=1);

// Display all errors in development (be sure to hide in production)
error_reporting(E_ALL);
ini_set('display_errors', '1');

// ---------------------------------------------------------------------
// 2. Define constants (adjust as needed)
// ---------------------------------------------------------------------
define('BASE_PATH', dirname(__DIR__));
define('APP_ENV', 'development'); // e.g., 'production' or 'development'

// ---------------------------------------------------------------------
// 3. Composer or custom autoloader
// ---------------------------------------------------------------------
// If using Composer, just require the vendor/autoload.php file:
// require BASE_PATH . '/vendor/autoload.php';

// Otherwise, a quick custom autoloader (for classes in /src):
spl_autoload_register(function ($class) {
    $file = BASE_PATH . '/src/' . str_replace('\\', '/', $class) . '.php';
    if (is_file($file)) {
        require_once $file;
    }
});

// ---------------------------------------------------------------------
// 4. Bootstrap tasks (config, DB connections, sessions, etc.)
// ---------------------------------------------------------------------
// Example: parse an .env, initialize DB, load config, etc.
//
// If you have a config file:
// $config = require BASE_PATH . '/config.php'; 
//
// For example, start a session if needed:
// session_start();

// ---------------------------------------------------------------------
// 5. Simple routing logic
// ---------------------------------------------------------------------
$requestUri  = $_SERVER['REQUEST_URI'] ?? '/';
$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Strip query string if present
if (false !== $pos = strpos($requestUri, '?')) {
    $requestUri = substr($requestUri, 0, $pos);
}

// Define a simple route map
$routes = [
    'GET' => [
        '/'       => 'HomeController@index',
        '/about'  => 'PageController@about',
    ],
    'POST' => [
        '/submit' => 'FormController@submit',
    ],
];

/**
 * Dispatch route
 *
 * This example uses a "controller@method" string format.
 * For an actual project, you might create a dedicated router class
 * or a third-party package. Below is a simple demonstration.
 */
function dispatch($method, $uri, $routes)
{
    // If no route found for HTTP method, fail early
    if (!isset($routes[$method])) {
        return sendNotFound();
    }
    
    // Check if route exists under this method
    if (!array_key_exists($uri, $routes[$method])) {
        return sendNotFound();
    }
    
    // Get the "controller@method" spec
    $target = $routes[$method][$uri]; 
    if (is_callable($target)) {
        // If the route directly has a Closure or function, call it
        return $target();
    }
    
    // If it's the "Controller@method" pattern, split and call
    list($controller, $action) = explode('@', $target);
    
    // Build the fully qualified class name (adjust namespace as needed)
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

// ---------------------------------------------------------------------
// 6. Helper: 404 response
// ---------------------------------------------------------------------
function sendNotFound()
{
    header('HTTP/1.1 404 Not Found');
    echo "404 - Page Not Found";
    exit;
}

// ---------------------------------------------------------------------
// 7. Execute the route
// ---------------------------------------------------------------------
dispatch($requestMethod, $requestUri, $routes);