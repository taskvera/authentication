<?php
namespace App\Controllers;

class AuthController
{
    /**
     * Displays the login view.
     */
    public function showLogin(?string $tenant = null)
    {
        if (empty($tenant)) {
            $tenant = 'default';
        }

        // (Optional) store $tenant in $_GET for your existing view code
        // or pass $tenant directly to your view.
        $_GET['tenant'] = $tenant;

        // Then include the normal login view
        include BASE_PATH . '/src/Views/LoginView.php';
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
        $tenant   = $_POST['tenant']   ?? 'default';  // get from hidden input, or fallback
    
        // Basic validation
        if (empty($username) || empty($password)) {
            $errorMsg = urlencode('Please enter both username and password.');
            header("Location: /login?tenant={$tenant}&error={$errorMsg}");
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
            $errorMsg = urlencode('Invalid username or password.');
            header("Location: /login?tenant={$tenant}&error={$errorMsg}");
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
