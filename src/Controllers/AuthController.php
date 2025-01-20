<?php
namespace App\Controllers;

class AuthController
{
    /**
     * Sends a string to the browser console via a <script> tag.
     * This only appears if the page does not redirect and actually renders.
     */
    public function console_debug($label, $value = null)
    {
        // Convert arrays/objects to JSON for easier reading
        if (is_array($value) || is_object($value)) {
            $value = json_encode($value);
        } elseif ($value === null) {
            $value = '';
        }
    
        // Escape quotes
        $label = addslashes($label);
        $value = addslashes((string)$value);
    
        // Output a <script> block that is opened and closed here.
        echo "<script>console.log('[DEBUG] {$label}: {$value}');</script>";
    }
    

    /**
     * Displays the login view.
     */
    public function showLogin(?string $tenant = null)
    {
        $this->console_debug('showLogin() called with tenant param', $tenant);

        // Default tenant to 'default' if none provided
        if (empty($tenant)) {
            $this->console_debug('Tenant was empty, defaulting to "default"');
            $tenant = 'default';
        }

        // Put tenant in $_GET for your existing view code
        $_GET['tenant'] = $tenant;
        $this->console_debug('$_GET["tenant"] set to', $_GET['tenant']);

        // Include the normal login view
        $this->console_debug('Including LoginView.php now...');
        include BASE_PATH . '/src/Views/LoginView.php';
    }
    public function handleLogin()
    {
        global $pdo, $config;
    
        $this->console_debug('handleLogin() started');
    
        // Retrieve and sanitize POST data
        $username = trim($_POST['username'] ?? '');
        $password = trim($_POST['password'] ?? '');
        $tenant   = $_POST['tenant'] ?? 'default';
    
        $this->console_debug('POST data (raw)', $_POST);
        $this->console_debug('Extracted username', $username);
        $this->console_debug('Extracted password length', strlen($password));
        $this->console_debug('Extracted tenant', $tenant);
    
        // Basic validation
        if (empty($username) || empty($password)) {
            $this->console_debug('Validation fail: missing username or password');
            $errorMsg = urlencode('Please enter both username and password.');
            $this->console_debug('Redirecting to /login with error', $errorMsg);
    
            header("Location: /login?tenant={$tenant}&error={$errorMsg}");
            exit;
        }
    
        // Prepare and execute the SQL statement in core_users
        // We now select 'user_type' as well
        $this->console_debug('Preparing SQL: SELECT id, password_hash, user_type FROM core_users WHERE email = :email');
        $stmt = $pdo->prepare('
            SELECT 
                id,
                password_hash,
                user_type
            FROM core_users
            WHERE email = :email
            LIMIT 1
        ');
    
        $this->console_debug('Executing statement with username (which is actually an email)', $username);
        $stmt->execute(['email' => $username]);
        $user = $stmt->fetch(\PDO::FETCH_ASSOC);
        $this->console_debug('Result from DB', $user);
    
        // Verify user existence and password
        if ($user && password_verify($password, $user['password_hash'])) {
            $this->console_debug('Password verify success. Setting session user_id to', $user['id']);
            $_SESSION['user_id'] = $user['id'];
            session_regenerate_id(true);
    
            // Decide redirect based on user_type
            if ($user['user_type'] === 'admin') {
                $this->console_debug('User is admin; redirecting to /admin/dashboard');
                header('Location: /admin/dashboard');
                exit;
            } else {
                // Default or 'tenant'
                $this->console_debug('User is tenant; redirecting to /dashboard');
                header('Location: /dashboard');
                exit;
            }
        } else {
            $this->console_debug('Authentication failed. Invalid username or password');
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
        $this->console_debug('handleLogout() called. Clearing session...');
        $_SESSION = [];

        $this->console_debug('Destroying session');
        session_destroy();

        $this->console_debug('Redirecting to /login...');
        header('Location: /login');
        exit;
    }

    /**
     * Show the register form.
     */
    public function showRegister(?string $tenant = null)
    {
        $this->console_debug('showRegister() called with tenant param', $tenant);

        if (empty($tenant)) {
            $this->console_debug('Tenant was empty, defaulting to "default"');
            $tenant = 'default';
        }

        // Provide tenant in $_GET or pass to a separate RegisterView
        $_GET['tenant'] = $tenant;
        $this->console_debug('$_GET["tenant"] set to', $_GET['tenant']);

        // Include a RegisterView that renders a form
        $this->console_debug('Including RegisterView.php now...');
        include BASE_PATH . '/src/Views/RegisterView.php';
    }

    /**
     * Handles registration form submission.
     */
    public function handleRegister()
    {
        global $pdo;
    
        // Hardcode tenant_id to 2431243
        $tenantId = 2431243;
    
        // Retrieve form data
        $email    = trim($_POST['email'] ?? '');
        $password = trim($_POST['password'] ?? '');
    
        // Basic validation
        if (empty($email) || empty($password)) {
            $errorMsg = urlencode('Email and password are required.');
            header("Location: /register?tenant=default&error={$errorMsg}");
            exit;
        }
    
        // Check if a user with this email + tenant already exists
        $checkSql = "SELECT id FROM core_users WHERE email = :email AND tenant_id = :tenantId LIMIT 1";
        $checkStmt = $pdo->prepare($checkSql);
        $checkStmt->execute(['email' => $email, 'tenantId' => $tenantId]);
        if ($checkStmt->fetch()) {
            // User already exists
            $errorMsg = urlencode('User with that email already exists for this tenant.');
            header("Location: /register?tenant=default&error={$errorMsg}");
            exit;
        }
    
        // Generate a random ID (no AUTO_INCREMENT)
        $newId = random_int(100000, 999999);
    
        // Hash the password using Argon2ID
        $hash = password_hash($password, PASSWORD_ARGON2ID);
    
        // Insert the new user
        $insertSql = "
            INSERT INTO core_users (id, tenant_id, email, password_hash)
            VALUES (:id, :tenantId, :email, :hash)
        ";
        $insertStmt = $pdo->prepare($insertSql);
        $insertStmt->execute([
            'id'       => $newId,
            'tenantId' => $tenantId,  // Hardcoded 2431243
            'email'    => $email,
            'hash'     => $hash,
        ]);
    
        // Redirect to login or show success
        header("Location: /login?tenant=default&success=Account%20created.%20Please%20log%20in.");
        exit;
    }
    
}
