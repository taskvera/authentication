<?php
namespace App\Controllers;

class AuthController
{
    /**
     * Displays the login view.
     */
    public function showLogin()
    {
        include BASE_PATH . '/src/Views/login.php';
    }

    /**
     * Handles login form submission.
     */
    public function handleLogin()
    {
        global $pdo, $config;

        // Retrieve and sanitize POST data
        $username = trim($_POST['username'] ?? '');
        $password = trim($_POST['password'] ?? '');

        // Basic validation
        if (empty($username) || empty($password)) {
            header('Location: /login?error=' . urlencode('Please enter both username and password.'));
            exit;
        }

        // Prepare and execute the SQL statement
        $stmt = $pdo->prepare('SELECT id, password_hash FROM users WHERE username = :username');
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(\PDO::FETCH_ASSOC);

        // Verify user existence and password
        if ($user && password_verify($password, $user['password_hash'])) {
            // Authentication successful
            $_SESSION['user_id'] = $user['id'];
            session_regenerate_id(true);

            // Redirect to a protected dashboard page
            header('Location: /dashboard');
            exit;
        } else {
            // Authentication failed
            header('Location: /login?error=' . urlencode('Invalid username or password.'));
            exit;
        }
    }

    /**
     * Handles user logout.
     */
    public function handleLogout()
    {
        // Unset all session variables
        $_SESSION = [];

        // Destroy the session
        session_destroy();

        // Redirect to the login page
        header('Location: /login');
        exit;
    }
}
