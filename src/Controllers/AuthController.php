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
        if (is_array($value) || is_object($value)) {
            $value = json_encode($value);
        } elseif ($value === null) {
            $value = '';
        }

        $date = date('Y-m-d H:i:s');
        $logEntry = "[{$date}] [DEBUG] {$label}: {$value}\n";
        $logFile = __DIR__ . '/../auth_debug.log';
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

        $_GET['tenant'] = $tenant;
        $this->console_debug('$_GET["tenant"] set to', $_GET['tenant']);

        $this->console_debug('Including LoginView.php now...');
        include BASE_PATH . '/src/Views/LoginView.php';
    }

    /**
     * Handles the login form submission.
     */
    public function handleLogin()
    {
        
        global $pdo;
    
        $this->console_debug('handleLogin() started');
    
        // 1) Retrieve and sanitize POST data
        $username    = trim($_POST['username']    ?? '');
        $password    = trim($_POST['password']    ?? '');
        $tenant      = $_POST['tenant_id']        ?? 'default';
    
        // 2) Grab IP/country/ISP plus everything else
        $ipAddress   = $_POST['client_ip']        ?? 'unknown';
        $country     = $_POST['client_country']   ?? '';
        $client_isp  = $_POST['client_isp']       ?? '';

        // Log some core fields
        $this->console_debug('Client Username from form', $username);
        $this->console_debug('Extracted password length', strlen($password));
        $this->console_debug('Client IP from form', $ipAddress);
        $this->console_debug('Client ISP from form', $client_isp);
        $this->console_debug('Client Country from form', $country);

        // Log the entire $_POST raw array
        $this->console_debug('POST data (raw)', $_POST);

        // Additionally, log each relevant device info field individually
        // so we can confirm every piece is accepted and logged (for testing).
        $allDeviceFields = [
            'deviceType', 'deviceModel', 'manufacturer', 'osName', 'osVersion', 'osBuildNumber',
            'osArchitecture', 'browserName', 'browserVersion', 'renderingEngine', 'browserMode',
            'screenResolution', 'pixelDensity', 'viewportSize', 'colorDepth', 'orientation',
            'availableScreenSpace', 'cpuModel', 'cpuCores', 'cpuClockSpeed', 'cpuArchitecture',
            'gpuModel', 'gpuVendor', 'gpuMemory', 'totalMemory', 'availableMemory',
            'totalDiskSpace', 'availableDiskSpace', 'storageType', 'batteryLevel',
            'batteryCharging', 'batteryHealth', 'touchSupport', 'touchPoints', 'pointerType',
            'cameraAvailability', 'cameraResolutions', 'microphoneAvailability', 'microphoneQuality',
            'biometricCapabilities', 'installedPlugins', 'browserExtensions', 'installedApplications',
            'installedApplicationsVersions', 'languageSettings', 'localeInformation',
            'numberFormats', 'dateTimeFormats', 'timeZone', 'cpuUsage', 'memoryUsage',
            'batteryUsage', 'networkSpeed', 'renderingFPS', 'timeToInteractive',
            'ttfb', 'resourceLoadTimes', 'secureBootStatus', 'antivirusPresence',
            'firewallStatus', 'encryptionStatus', 'osPatchLevel', 'ipAddress',
            'location', 'isp', 'latitude', 'longitude'
        ];

        foreach ($allDeviceFields as $field) {
            if (isset($_POST[$field])) {
                $this->console_debug("Field '{$field}'", $_POST[$field]);
            } else {
                $this->console_debug("Field '{$field}'", '[NOT PROVIDED]');
            }
        }

        $this->console_debug('Extracted tenant', $tenant);
    
        // Insert row in auth_login_attempts
        $loginAttemptId = null;
        try {
            $insertSql = "
                INSERT INTO auth_login_attempts
                  (ip_address, email_entered, tenant_id, country, user_agent, attempt_status)
                VALUES
                  (:ip, :emailEntered, :tenantId, :country, :ua, 'pending')
            ";
            $tenantIdInt = (is_numeric($tenant)) ? (int)$tenant : null;
    
            $stmt = $pdo->prepare($insertSql);
            $stmt->execute([
                'ip'          => $ipAddress,
                'emailEntered'=> $username,
                'tenantId'    => $tenantIdInt,
                'country'     => $country,
                'ua'          => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 1024),
            ]);
            $loginAttemptId = $pdo->lastInsertId();
            $this->console_debug('Logged new attempt in DB, login_attempt_id', $loginAttemptId);
        } catch (\Exception $e) {
            $this->console_debug('Failed to insert auth_login_attempts row', $e->getMessage());
        }
    
        // 3) Basic validation
        if (empty($username) || empty($password)) {
            $this->console_debug('Validation fail: missing username or password');
            $this->updateLoginAttempt($loginAttemptId, [
                'attempt_status' => 'FAILURE',
                'error_code'     => 'MISSING_CREDENTIALS',
                'completed_at'   => 'NOW()',
            ]);
    
            $errorMsg = urlencode('Please enter both username and password.');
            $this->console_debug('Redirecting to /login with error', $errorMsg);
            header("Location: /login?tenant={$tenant}&error={$errorMsg}");
            exit;
        }
    
        // 4) Risk check
        $riskService = new \App\Services\RiskAssessmentService();
        $userAgent   = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    
        $this->console_debug('Calling assessLoginRisk...');
        $riskPassed  = $riskService->assessLoginRisk($username, $tenant, $ipAddress, $userAgent, $country);
        $this->console_debug('RiskAssessment outcome', $riskPassed);
    
        if (!$riskPassed) {
            $this->console_debug('RiskAssessmentService blocked the login attempt.');
            $this->updateLoginAttempt($loginAttemptId, [
                'attempt_status' => 'BLOCKED',
                'error_code'     => 'RISK_THRESHOLD_EXCEEDED',
                'completed_at'   => 'NOW()',
            ]);
            $errorMsg = urlencode('Login blocked due to suspicious activity.');
            header("Location: /login?tenant={$tenant}&error={$errorMsg}");
            exit;
        }
    
        // 5) Proceed with normal login if risk check passes
        $this->console_debug('Preparing SQL for user lookup...');
        $stmt = $pdo->prepare('
            SELECT 
                user_id,
                tenant_id,
                password_hash,
                user_type
            FROM auth_users
            WHERE email = :email
            LIMIT 1
        ');
        $stmt->execute(['email' => $username]);
        $user = $stmt->fetch(\PDO::FETCH_ASSOC);
        $this->console_debug('Result from DB', $user);
    
        // 6) Verify user existence and password
        if (!$user) {
            // No user with that email => NO_USER_FOUND
            $this->console_debug(label: 'Authentication failed: user does not exist');
            
            // Log final action:
            $this->console_debug(label: sprintf(
                "Authentication failed -> updating login attempt #%d -> redirecting to /login?tenant=%s&error=NO_USER_FOUND",
                $loginAttemptId,
                $tenant ?: 'default'
            ));
    
            // Update login attempt record
            $this->updateLoginAttempt($loginAttemptId, [
                'attempt_status' => 'FAILURE',
                'error_code'     => 'NO_USER_FOUND',
                'completed_at'   => 'NOW()',
            ]);

            // Log confirmation:
            $this->console_debug(label: sprintf(
                'Attempt #%d updated → status=FAILURE, error_code=NO_USER_FOUND, completed_at=%s',
                $loginAttemptId,
                date('Y-m-d H:i:s')
            ));
        
            $errorMsg = urlencode('Invalid username or password.');
            header("Location: /login?tenant={$tenant}&error={$errorMsg}");
            exit;
        }
    
        // If user record exists, check password
        if (!password_verify($password, $user['password_hash'])) {
            // Invalid password
            $this->console_debug('Authentication failed: incorrect password');
    
            $this->updateLoginAttempt($loginAttemptId, [
                'attempt_status' => 'FAILURE',
                'error_code'     => 'INVALID_PASSWORD',
                'user_id'        => $user['user_id'],  // we do have a user row
                'tenant_id'      => $user['tenant_id'] ?? null,
                'completed_at'   => 'NOW()',
            ]);
    
            $errorMsg = urlencode('Invalid username or password.');
            header("Location: /login?tenant={$tenant}&error={$errorMsg}");
            exit;
        }
    
        // If we got here => user + password are valid
        $this->console_debug('Password verify success. Setting session user_id', $user['user_id']);
    
        $this->updateLoginAttempt($loginAttemptId, [
            'user_id'        => $user['user_id'],
            'tenant_id'      => $user['tenant_id'] ?? null,
            'attempt_status' => 'SUCCESS',
            'completed_at'   => 'NOW()',
            'success_at'     => 'NOW()',
        ]);
    
        $_SESSION['user_id'] = $user['user_id'];
        session_regenerate_id(true);
    
        if ($user['user_type'] === 'admin') {
            $this->console_debug('User is admin; redirecting to /admin/dashboard');
            header('Location: /admin/dashboard');
        } else {
            $this->console_debug('User is tenant; redirecting to /dashboard');
            header('Location: /dashboard');
        }
        exit;
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

        $_GET['tenant'] = $tenant;
        $this->console_debug('$_GET["tenant"] set to', $_GET['tenant']);

        $this->console_debug('Including RegisterView.php now...');
        include BASE_PATH . '/src/Views/RegisterView.php';
    }

    /**
     * Handles registration form submission.
     */
    public function handleRegister()
    {
        global $pdo;

        // Hardcode some tenant_id or parse from form
        $tenantId = 1; // example: assigning them to tenant_id=1 (Globex). Adjust as needed.

        // Retrieve form data
        $email = trim($_POST['email'] ?? '');
        $password = trim($_POST['password'] ?? '');

        // Basic validation
        if (empty($email) || empty($password)) {
            $errorMsg = urlencode('Email and password are required.');
            header("Location: /register?tenant=default&error={$errorMsg}");
            exit;
        }

        // Check if a user with this email + tenant already exists
        $checkSql = "SELECT user_id FROM auth_users WHERE email = :email AND tenant_id = :tenantId LIMIT 1";
        $checkStmt = $pdo->prepare($checkSql);
        $checkStmt->execute(['email' => $email, 'tenantId' => $tenantId]);
        if ($checkStmt->fetch()) {
            $errorMsg = urlencode('User with that email already exists for this tenant.');
            header("Location: /register?tenant=default&error={$errorMsg}");
            exit;
        }

        // Hash the password using Argon2ID
        $hash = password_hash($password, PASSWORD_ARGON2ID);

        // Insert the new user (auto-increment user_id)
        $insertSql = "
            INSERT INTO auth_users (tenant_id, email, password_hash)
            VALUES (:tenantId, :email, :hash)
        ";
        $insertStmt = $pdo->prepare($insertSql);
        $insertStmt->execute([
            'tenantId' => $tenantId,
            'email' => $email,
            'hash' => $hash,
        ]);

        header("Location: /login?tenant=default&success=Account%20created.%20Please%20log%20in.");
        exit;
    }

    /**
     * Update a login attempt record in auth_login_attempts.
     *
     * @param int|null $loginAttemptId The primary key of the record to update.
     * @param array    $updates        Key-value pairs of columns to update. 
     *                                 For example: ['attempt_status' => 'fail', 'risk_score' => 50].
     *                                 If you want a column set to NOW(), pass `'column_name' => 'NOW()'`.
     */
    private function updateLoginAttempt(?int $loginAttemptId, array $updates = []): void
    {
        if (!$loginAttemptId) {
            // If we never got a login_attempt_id, skip
            return;
        }

        global $pdo;

        try {
            // Always keep an updated_at = NOW() for auditing. 
            $updates['updated_at'] = 'NOW()';

            $setClauses = [];
            $params = [':loginAttemptId' => $loginAttemptId];

            foreach ($updates as $column => $value) {
                if ($column === 'login_attempt_id') {
                    continue;
                }
                if ($value === 'NOW()') {
                    $setClauses[] = "`{$column}` = NOW()";
                } else {
                    $paramName = ':col_' . $column;
                    $setClauses[] = "`{$column}` = {$paramName}";
                    $params[$paramName] = $value;
                }
            }

            if (empty($setClauses)) {
                return;
            }

            $setClause = implode(', ', $setClauses);
            $sql = "UPDATE `auth_login_attempts`
                SET {$setClause}
                WHERE `login_attempt_id` = :loginAttemptId";

            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);

        } catch (\Exception $e) {
            $this->console_debug('Failed to update auth_login_attempts row', $e->getMessage());
        }
    }

}
