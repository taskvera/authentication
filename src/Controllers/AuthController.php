<?php
namespace App\Controllers;

class AuthController
{
    /**
     * Writes debug info to a custom log file in the same directory (e.g., "auth_debug.log").
     * This will work even on localhost.
     */
    public function console_debug($label, $value = null)
    {
        // Convert arrays/objects to JSON for easier reading
        if (is_array($value) || is_object($value)) {
            $value = json_encode($value);
        } elseif ($value === null) {
            $value = '';
        }

        // Prepare a timestamped log entry
        $date = date('Y-m-d H:i:s');
        $logEntry = "[{$date}] [DEBUG] {$label}: {$value}\n";

        // Construct the log file path in this same directory
        $logFile = __DIR__ . '/auth_debug.log';

        // Append the log entry
        file_put_contents($logFile, $logEntry, FILE_APPEND);
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
        global $pdo;
    
        $this->console_debug('handleLogin() started');
    
        // 1) Retrieve and sanitize POST data
        $username  = trim($_POST['username'] ?? '');
        $password  = trim($_POST['password'] ?? '');
        $tenant    = $_POST['tenant']        ?? 'default';
    
        // 2) Grab IP and country from hidden fields
        $ipAddress = $_POST['client_ip']      ?? 'unknown';
        $country   = $_POST['client_country'] ?? '';
    
        $this->console_debug('Client IP from form', $ipAddress);
        $this->console_debug('POST data (raw)', $_POST);
        $this->console_debug('Extracted username', $username);
        $this->console_debug('Extracted password length', strlen($password));
        $this->console_debug('Extracted tenant', $tenant);
    
        // --------------------------------------------------------
        // STEP A) Insert a row in core_login_attempts right away
        // --------------------------------------------------------
        $attemptId = null;
        try {
            $insertSql = "
  INSERT INTO core_login_attempts 
    (ip_address, username, tenant, country, user_agent, attempted_at, attempt_status)
  VALUES 
    (:ip, :user, :tenant, :country, :ua, NOW(), 'pending')
";
            $Stmt = $pdo->prepare($insertSql);
            $Stmt->execute([
                'ip'     => $ipAddress,
                'user'   => $username,
                'tenant' => $tenant,
                'country'=> $country,
                'ua'     => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255),
            ]);
            // If the table is AUTO_INCREMENT, we can get the new attempt_id:
            $attemptId = $pdo->lastInsertId();
            $this->console_debug('Logged new attempt in DB, attempt_id', $attemptId);
        } catch (\Exception $e) {
            // If logging fails, we just proceed — but you might want to handle or re-throw.
            $this->console_debug('Failed to insert core_login_attempts row', $e->getMessage());
        }
    
        // 3) Basic validation
        if (empty($username) || empty($password)) {
            $this->console_debug('Validation fail: missing username or password');
    
            // Mark attempt as "fail" in the DB (missing credentials)
            $this->updateLoginAttempt($attemptId, 'fail', 'missing_credentials');
    
            $errorMsg = urlencode('Please enter both username and password.');
            $this->console_debug('Redirecting to /login with error', $errorMsg);
    
            header("Location: /login?tenant={$tenant}&error={$errorMsg}");
            exit;
        }
    
        // 4) Load and call the RiskAssessmentService
        $riskService = new \App\Services\RiskAssessmentService();
        $userAgent   = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    
        $this->console_debug('Calling assessLoginRisk...');
        $riskPassed  = $riskService->assessLoginRisk($username, $tenant, $ipAddress, $userAgent, $country);
        $this->console_debug('RiskAssessment outcome', $riskPassed);
    
        if (!$riskPassed) {
            // If the service decides this is too risky
            $this->console_debug('RiskAssessmentService blocked the login attempt.');
    
            // Mark attempt as "blocked"
            $this->updateLoginAttempt($attemptId, 'blocked', 'risk_threshold_exceeded');
    
            $errorMsg = urlencode('Login blocked due to suspicious activity.');
            header("Location: /login?tenant={$tenant}&error={$errorMsg}");
            exit;
        }
    
        // 5) Proceed with normal login if risk check passes
        $this->console_debug('Preparing SQL for user lookup...');
        $stmt = $pdo->prepare('
            SELECT 
                id,
                password_hash,
                user_type
            FROM core_users
            WHERE email = :email
            LIMIT 1
        ');
        $stmt->execute(['email' => $username]);
        $user = $stmt->fetch(\PDO::FETCH_ASSOC);
        $this->console_debug('Result from DB', $user);
    
        // 6) Verify user existence and password
        if ($user && password_verify($password, $user['password_hash'])) {
            $this->console_debug('Password verify success. Setting session user_id to', $user['id']);
    
            // Mark attempt as "success"
            $this->updateLoginAttempt($attemptId, 'success', 'ok');
    
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
    
            // Mark attempt as "fail"
            $this->updateLoginAttempt($attemptId, 'fail', 'invalid_credentials');
    
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

    private function updateLoginAttempt(?int $attemptId, string $status, string $reason = ''): void
{
    if (!$attemptId) {
        // If we never got an attempt ID (maybe insert failed?), skip
        return;
    }

    global $pdo;
    try {
        $sql = "
            UPDATE core_login_attempts
            SET 
                attempt_status = :status,
                reason = :reason,
                updated_at = NOW()
            WHERE attempt_id = :attemptId
        ";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            'status'    => $status,
            'reason'    => $reason,
            'attemptId' => $attemptId,
        ]);
    } catch (\Exception $e) {
        $this->console_debug('Failed to update core_login_attempts row', $e->getMessage());
        // Not much else we can do, just log it
    }
}

}
