<?php

namespace App\Services;


class RiskAssessmentService
{
    /**
     * Writes debug info to a custom log file in the same directory (e.g., "RiskAssessmentService.log").
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
        $logFile = __DIR__ . '/RiskAssessmentService.log';

        // Append the log entry
        file_put_contents($logFile, $logEntry, FILE_APPEND);
    }

    /**
     * The threshold above which we block the login.
     * e.g., if total risk >= 50, block the attempt.
     */
    private const RISK_THRESHOLD = 50;

    /**
     * The main method for assessing risk. 
     * Returns true if the login attempt is ALLOWED (risk is below threshold),
     * or false if it's BLOCKED (risk is >= threshold).
     */
    public function assessLoginRisk(
        string $username,
        string $tenant,
        string $ipAddress,
        string $userAgent,
        string $country, // new param
        ?string $deviceFingerprintBase64 = null
    ): bool
    {
        $this->console_debug('assessLoginRisk START', [
            'username' => $username,
            'tenant'   => $tenant,
            'ip'       => $ipAddress,
            'userAgent'=> $userAgent,
            'country'  => $country,
            'fingerprint' => substr($deviceFingerprintBase64 ?? '', 0, 30) // for debug
        ]);
    
        // Array to hold individual risk scores
        $riskScores = [];
    
        // 1) Check global IP blacklist (already in your code)
        $scoreIP = $this->checkGlobalIPBlacklist($ipAddress);
        $riskScores[] = $scoreIP;
        $this->console_debug('checkGlobalIPBlacklist returned', $scoreIP);
    
        // 2) Check AbuseIPDB (already in your code)
        $scoreAbuse = $this->checkAbuseIPDB($ipAddress);
        $riskScores[] = $scoreAbuse;
        $this->console_debug('checkAbuseIPDB returned', $scoreAbuse);
    
        // 3) Check global region blacklist (NEW)
        $scoreRegion = $this->checkGlobalRegionBlacklist($country);
        $riskScores[] = $scoreRegion;
        $this->console_debug('checkGlobalRegionBlacklist returned', $scoreRegion);
    
        // 4) (Optional) Check if user is logging in from an unusual continent
        //    e.g., historically US, now CN => suspicious
        $suddenChangeScore = $this->checkSuddenContinentChange($username, $country);
        $riskScores[] = $suddenChangeScore;
        $this->console_debug('checkSuddenContinentChange returned', $suddenChangeScore);

         // 4) Tor/Proxy/VPN detection
    $scoreTorProxy = $this->checkTorProxyVPN($ipAddress);
    $riskScores[] = $scoreTorProxy;
    $this->console_debug('checkTorProxyVPN returned', $scoreTorProxy);

     // 6) Velocity check
     $scoreVelocity = $this->checkVelocityLimit($ipAddress, $username);
     $riskScores[] = $scoreVelocity;
     $this->console_debug('checkVelocityLimit returned', $scoreVelocity);
    


    // 1) Device fingerprint generation
    $dfService = new \App\Services\DeviceFingerprintService();
    $fingerprintHash = $dfService->createFingerprintHash($deviceFingerprintBase64 ?? '');

    // 2) If you can find a user_id before the login check, you'd do something like:
    //    - Look up user in DB to get their ID
    //    For the sake of example, let's pretend we found $userId=123
    //    Or if you do this after you find the user, you can do a second pass in risk logic.
    $fakeUserId = 123; // in reality, you'd fetch or pass in the user’s ID from some context

    // 3) Compare device fingerprint => return some risk
    $scoreFingerprint = $dfService->compareFingerprintHashToKnown($fakeUserId, $fingerprintHash);
    $riskScores[] = $scoreFingerprint;
    $this->console_debug('DeviceFingerprintService risk', $scoreFingerprint);

    
        // Sum the scores
        $totalRisk = array_sum($riskScores);
        $this->console_debug('Total risk so far', $totalRisk);
    
        // Compare total risk to threshold
        $isAllowed = $totalRisk < self::RISK_THRESHOLD;
        $this->console_debug('Comparing totalRisk to RISK_THRESHOLD', [
            'totalRisk' => $totalRisk,
            'threshold' => self::RISK_THRESHOLD
        ]);
    
        $this->console_debug(
            'assessLoginRisk Decision',
            $isAllowed ? 'ALLOWED (below threshold)' : 'BLOCKED (above threshold)'
        );
    
        $this->console_debug('assessLoginRisk END', [
            'result'    => $isAllowed ? 'true' : 'false',
            'finalRisk' => $totalRisk
        ]);

        
    
        return $isAllowed;
    }
    
    
/**
 * Check #1: Global IP blacklist (database-driven).
 *
 * If $ipAddress is 'unknown', we exit immediately.
 * Otherwise, we query `core_global_ip_blacklist`.
 * - If a row has ip_end = NULL, it is a SINGLE IP block.
 * - If a row has ip_end != NULL, it is an IP RANGE block.
 * ANY match triggers an immediate EXIT (blocking the login).
 */
private function checkGlobalIPBlacklist(string $ipAddress): int
{
    $this->console_debug('checkGlobalIPBlacklist START', $ipAddress);

    // 1) If IP is unknown, exit
    if ($ipAddress === 'unknown') {
        $this->console_debug('checkGlobalIPBlacklist ERROR', 'IP was unknown, cannot perform blacklist check');
        exit("RiskAssessmentService: IP was 'unknown', so we cannot perform a blacklist check. "
            . "This likely means the controller didn't pass it from the form hidden input.");
    }

    // 2) Convert the current IP to a numeric form for easy comparison
    $currentIpLong = ip2long($ipAddress);
    if ($currentIpLong === false) {
        // If ip2long fails, the IP might be invalid or IPv6 unsupported by ip2long
        // We'll log and exit or treat it as suspicious
        $this->console_debug('checkGlobalIPBlacklist ERROR', "ip2long() failed for IP: {$ipAddress}");
        exit("RiskAssessmentService: Failed to parse IP address '{$ipAddress}' via ip2long().");
    }

    // 3) Query the core_global_ip_blacklist table
    //    We'll fetch all rows and check each individually.
    //    In production, you might want a more optimized query, but this is a straightforward approach.
    $sql = "
        SELECT
            blacklist_id,
            ip_start,
            ip_end,
            notes,
            created_at,
            updated_at
        FROM core_global_ip_blacklist
    ";
    // If you want to filter in SQL (for large tables), you might do range logic in SQL,
    // but here we'll just fetch and compare in PHP.
    $this->console_debug('checkGlobalIPBlacklist Query', $sql);

    // We'll assume we have a PDO instance accessible, or pass it in somehow.
    // Example: global $pdo;
    global $pdo;

    $stmt = $pdo->prepare($sql);
    $stmt->execute();
    $rows = $stmt->fetchAll(\PDO::FETCH_ASSOC);

    // 4) Iterate over each row and check
    foreach ($rows as $row) {
        $this->console_debug('checkGlobalIPBlacklist Checking Row', $row);

        $dbIpStart = $row['ip_start'] ?? '';
        $dbIpEnd   = $row['ip_end'] ?? null; // might be null for single IP
        $dbIpStartLong = ip2long($dbIpStart);

        if ($dbIpStartLong === false) {
            // Log an error if the data in the table isn't valid
            $this->console_debug('checkGlobalIPBlacklist ERROR', "ip2long() failed for ip_start: {$dbIpStart}");
            continue; // skip this row
        }

        if ($dbIpEnd === null) {
            // Single IP check
            // If $currentIpLong equals $dbIpStartLong, block
            if ($currentIpLong === $dbIpStartLong) {
                $this->console_debug('checkGlobalIPBlacklist MATCH', [
                    'type' => 'single IP',
                    'ip_start' => $dbIpStart,
                    'notes' => $row['notes']
                ]);
return 100;
            }
        } else {
            // Range check
            $dbIpEndLong = ip2long($dbIpEnd);
            if ($dbIpEndLong === false) {
                $this->console_debug('checkGlobalIPBlacklist ERROR', "ip2long() failed for ip_end: {$dbIpEnd}");
                continue;
            }

            // Ensure start <= end
            $rangeStart = min($dbIpStartLong, $dbIpEndLong);
            $rangeEnd   = max($dbIpStartLong, $dbIpEndLong);

            // If current IP is within [rangeStart, rangeEnd], block
            if ($currentIpLong >= $rangeStart && $currentIpLong <= $rangeEnd) {
                $this->console_debug('checkGlobalIPBlacklist MATCH', [
                    'type' => 'IP range',
                    'ip_start' => $dbIpStart,
                    'ip_end'   => $dbIpEnd,
                    'notes'    => $row['notes']
                ]);
return 100;
            }
        }
    }

    // 5) If no match found
    $this->console_debug('checkGlobalIPBlacklist NO MATCH', "IP {$ipAddress} not found in DB. OK to proceed.");
    $this->console_debug('checkGlobalIPBlacklist END');

    // For your risk aggregator approach, you might return 0 risk if no match,
    // but since you said "this is global it will ALWAYS 100% block",
    // the code above "exit()" if found. So we can just return 0 here.
    return 0;
}
 /**
     * NEW METHOD:
     * Query AbuseIPDB for an IP's 'abuseConfidenceScore'
     * and return it as an integer "risk" value.
     *
     * The higher the 'abuseConfidenceScore' (0-100),
     * the more likely the IP is malicious.
     * 
     * Docs: https://www.abuseipdb.com/api.html
     */
    private function checkAbuseIPDB(string $ipAddress): int
    {
        $this->console_debug('checkAbuseIPDB START', $ipAddress);

        // If IP is invalid or placeholder, return 0 or handle appropriately.
        if ($ipAddress === 'unknown') {
            $this->console_debug('checkAbuseIPDB ERROR', 'IP was unknown');
            return 0;
        }

        // 1) Get the AbuseIPDB API key from environment
        $apiKey = '5970bf069dbae545cdef01d4fa684ce867f6031664c1e1ed937b0fa0976c01f9c87e4158facacddc';
        if (!$apiKey) {
            $this->console_debug('checkAbuseIPDB ERROR', 'No API key set in environment');
            return 0;  // or handle differently if key is missing
        }

        // 2) Build the API endpoint URL
        //    ?maxAgeInDays=90 checks 3 months of data
        $endpoint = 'https://api.abuseipdb.com/api/v2/check';
        $queryParams = http_build_query([
            'ipAddress'    => $ipAddress,
            'maxAgeInDays' => 90,
        ]);
        $url = $endpoint . '?' . $queryParams;

        // 3) Make the HTTP request (using cURL here)
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'X-Api-Key: ' . $apiKey,  // Important: use the correct header
            ],
            // You could set a timeout, SSL options, etc. if desired
        ]);
        $response = curl_exec($ch);

        // Check for cURL errors
        if (curl_errno($ch)) {
            $error = curl_error($ch);
            $this->console_debug('checkAbuseIPDB CURL ERROR', $error);
            curl_close($ch);
            return 0;  // or handle error logic
        }
        curl_close($ch);

        // 4) Decode JSON
        $decoded = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->console_debug('checkAbuseIPDB JSON ERROR', json_last_error_msg());
            return 0;
        }

        // 5) Extract the abuseConfidenceScore
        //    The docs say it's in $decoded['data']['abuseConfidenceScore'] (0-100).
        $confidenceScore = $decoded['data']['abuseConfidenceScore'] ?? 0;
        $this->console_debug('checkAbuseIPDB confidenceScore', $confidenceScore);

        $this->console_debug('checkAbuseIPDB END');
        // Return that directly as the "risk" points from this source
        return (int)$confidenceScore;
    }

    private function checkGlobalRegionBlacklist(string $countryCode): int
{
    $this->console_debug('checkGlobalRegionBlacklist START', $countryCode);

    // If for some reason it’s empty, skip
    if (empty($countryCode)) {
        $this->console_debug('checkGlobalRegionBlacklist NO COUNTRY', 'No country code provided');
        return 0;
    }

    // Query the region blacklist table
    global $pdo;
    $sql = "
        SELECT region_id, country_code, notes
        FROM core_global_region_blacklist
        WHERE UPPER(country_code) = UPPER(:code)
        LIMIT 1
    ";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['code' => $countryCode]);
    $row = $stmt->fetch(\PDO::FETCH_ASSOC);

    if ($row) {
        // If found, return high risk (100)
        $this->console_debug('checkGlobalRegionBlacklist MATCH', $row);
        return 100;
    }

    $this->console_debug('checkGlobalRegionBlacklist NO MATCH', $countryCode . ' not found in region blacklist');
    $this->console_debug('checkGlobalRegionBlacklist END');

    return 0; // not blacklisted => no additional risk
}

private function checkSuddenContinentChange(string $username, string $currentCountry): int
{
    $this->console_debug('checkSuddenContinentChange START', [
        'username' => $username,
        'current'  => $currentCountry
    ]);

    if (empty($username) || empty($currentCountry)) {
        return 0;
    }

    global $pdo;
    // 1) Fetch user’s last_country from DB
    $sql = "SELECT last_country FROM core_users WHERE email = :email LIMIT 1";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['email' => $username]);
    $row = $stmt->fetch(\PDO::FETCH_ASSOC);

    if (!$row || empty($row['last_country'])) {
        // No history => no penalty
        $this->console_debug('checkSuddenContinentChange NO HISTORY', 'User has no last_country on file');
        return 0;
    }

    $lastCountry = strtoupper($row['last_country']);
    $currentCountry = strtoupper($currentCountry);

    // 2) Compare continents
    // A quick hack: Map each country code to a continent. For a real solution,
    // you might store a "continent_code" (e.g., 'NA', 'EU', 'AS', etc.) in the DB.
    $continentOfLast    = $this->getContinentCode($lastCountry);
    $continentOfCurrent = $this->getContinentCode($currentCountry);

    if ($continentOfLast && $continentOfCurrent && $continentOfLast !== $continentOfCurrent) {
        // if the user historically logs in from the US (NA) but is now e.g. in Germany (EU), suspicious +20
        $this->console_debug('checkSuddenContinentChange DIFFERENT', [
            'last_country' => $lastCountry,
            'last_continent' => $continentOfLast,
            'current_country' => $currentCountry,
            'current_continent' => $continentOfCurrent,
            'added_risk' => 20
        ]);
        return 20;
    }

    return 0;
}

/**
 * (Very) rough method to map a country code to a continent code.
 * In production, you could keep a DB or library with full mapping. 
 */
private function getContinentCode(string $countryCode): ?string
{
    // Very incomplete map for demonstration
    $map = [
        'US' => 'NA', // North America
        'CA' => 'NA',
        'MX' => 'NA',

        'GB' => 'EU', // Europe
        'FR' => 'EU',
        'DE' => 'EU',
        'ES' => 'EU',

        'JP' => 'AS', // Asia
        'CN' => 'AS',
        'IN' => 'AS',

        'AU' => 'OC', // Oceania
        // etc...
    ];

    return $map[$countryCode] ?? null;
}

private function checkTorProxyVPN(string $ipAddress): int
{
    $this->console_debug('checkTorProxyVPN START', $ipAddress);

    if ($ipAddress === 'unknown') {
        return 0; // can't do much
    }

    // Example: Using a fictional API endpoint that returns JSON
    // that indicates "is this IP a known proxy/VPN/Tor exit?"
    // Replace with your real endpoint / approach.
    $apiKey = getenv('PROXY_DETECT_API_KEY'); 
    if (!$apiKey) {
        // No key configured, skip
        $this->console_debug('checkTorProxyVPN ERROR', 'No API key set for proxy detection');
        return 0;
    }

    $url = 'https://api.proxy-detect-example.com/v1/check?ip=' . urlencode($ipAddress);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'Accept: application/json',
            'X-API-KEY: ' . $apiKey,
        ],
    ]);
    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        $error = curl_error($ch);
        curl_close($ch);
        $this->console_debug('checkTorProxyVPN CURL ERROR', $error);
        return 0;
    }
    curl_close($ch);

    $decoded = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        $this->console_debug('checkTorProxyVPN JSON ERROR', json_last_error_msg());
        return 0;
    }

    // Suppose the API returns something like:
    // {
    //   "ip": "8.8.8.8",
    //   "proxy": true,
    //   "vpn": false,
    //   "tor": false,
    //   "risk_score": 85
    // }
    // For demonstration, let's say if "proxy" or "vpn" or "tor" is true, we add 30 risk
    // or we might just use "risk_score" directly.
    $isProxy = $decoded['proxy'] ?? false;
    $isVPN   = $decoded['vpn']   ?? false;
    $isTor   = $decoded['tor']   ?? false;

    if ($isProxy || $isVPN || $isTor) {
        $this->console_debug('checkTorProxyVPN MATCH', 'IP is flagged as proxy/VPN/Tor');
        return 30; 
    }

    // Or if your API gives a direct risk score:
    // $risk = $decoded['risk_score'] ?? 0;
    // return min($risk, 100);

    $this->console_debug('checkTorProxyVPN NO MATCH', 'Not flagged as proxy/VPN/Tor');
    return 0;
}

private function checkVelocityLimit(string $ipAddress, string $username): int
{
    $this->console_debug('checkVelocityLimit START', [
        'ip' => $ipAddress,
        'user' => $username
    ]);

    if ($ipAddress === 'unknown') {
        // Can't do velocity check if IP is unknown
        return 0;
    }

    // 1) Query how many attempts from this IP in last 15 minutes
    global $pdo;
    $sql = "
        SELECT COUNT(*) AS attempt_count
        FROM core_login_attempts
        WHERE ip_address = :ip
          AND attempted_at >= (NOW() - INTERVAL 15 MINUTE)
    ";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['ip' => $ipAddress]);
    $row = $stmt->fetch(\PDO::FETCH_ASSOC);

    $attemptCount = (int) ($row['attempt_count'] ?? 0);
    $this->console_debug('checkVelocityLimit attemptCount', $attemptCount);

    // 2) Define your threshold
    // e.g., if more than 5 attempts in 15 min, either block or add heavy risk
    $threshold = 5;
    if ($attemptCount > $threshold) {
        // Maybe return 50 or 100 to effectively block
        $this->console_debug('checkVelocityLimit ABOVE THRESHOLD', $attemptCount);
        return 50;  // or 100
    }

    $this->console_debug('checkVelocityLimit END', 'below threshold');
    return 0;
}


}

/**
 * TODO: Future Security & Risk Assessment Enhancements
 *
 * 1) Device & Environment Checks
 *    - Device Fingerprinting
 *      * Generate a fingerprint from user-agent, screen size, OS, installed fonts, etc.
 *      * If a known account fingerprint changes drastically, consider it suspicious.
 *
 *    - User-Agent Anomalies
 *      * If the User-Agent string is obviously fake or known for malicious bots (e.g., "PostmanRuntime"), add high risk.
 *
 *    - Location/Time Anomalies
 *      * If a user last logged in from Germany, but 2 minutes later from Australia, it's physically impossible travel time.
 *      * Treat as high risk or block.
 *
 *    - Referrer / Origin Checks
 *      * If you expect the login request to come from a certain domain, but see a suspicious or empty Referer, treat with caution.
 *
 *    - Browser Integrity Checks
 *      * Use JavaScript challenges (like reCAPTCHA or custom puzzles) to verify a real browser.
 *      * If it fails, treat as suspicious.
 *
 * 2) Credential & User Validation
 *    - Known Compromised Credentials Check
 *      * Compare user's email or password (securely hashed) against known data breach APIs (e.g., HaveIBeenPwned).
 *      * If compromised, block or force reset.
 *
 *    - Account Lock or Suspicious Flag
 *      * If the user account is flagged for suspicious activity (too many failed attempts), block or require 2FA.
 *      * A separate "UserAccountLocks" or "UserSecurityStatus" table might track this.
 *
 *    - Password Strength / Expiration
 *      * Enforce password rotation or complexity requirements.
 *      * If password is expired or too weak, force a reset or add risk.
 *
 *    - Multi-Factor Requirements
 *      * If the user's tenant/org requires 2FA, ensure the user has a valid factor configured.
 *      * Block or prompt setup if missing.
 *
 * 3) Behavioral & Historical Checks
 *    - Login Velocity for This Account
 *      * If the user logs in many times in a short window, might be brute force.
 *
 *    - Account Age
 *      * If the account was just created and is already logging in, could be spam/bot behavior.
 *      * Add risk or block if obviously malicious.
 *
 *    - Tenant-Specific IP Policies
 *      * Some tenants only allow logins from certain IP ranges (corporate networks).
 *      * If outside that range, block.
 *
 *    - Email Domain Policy
 *      * If a tenant requires a specific domain (e.g., @mycompany.com), block or add risk if it doesn't match.
 *
 *    - User’s Typical Patterns
 *      * If the user normally logs in from a certain device/time window, but now it's drastically different, treat as suspicious.
 *
 * 4) Suspicious Activity & Bot Detection
 *    - Bot / Script Detection
 *      * Use JS challenges, CAPTCHAs, or puzzle tests to confirm a human user.
 *      * Block or add risk on failure.
 *
 *    - Credential Stuffing Detection
 *      * If the same user or IP tries many passwords, or tries many usernames from one IP, that's suspicious.
 *
 *    - Account Sharing or Unexpected Tenant
 *      * If the email belongs to Tenant A but the request is for Tenant B, mismatch => add risk/block.
 *
 * 5) Additional Checks & Signals
 *    - Time-of-Day / Day-of-Week
 *      * If the system expects logins only during business hours, a 3 AM login might be riskier.
 *
 *    - Honeytoken Accounts
 *      * Logins to a “canary” account can be an immediate security alert.
 *
 *    - Known Attack Patterns
 *      * Scan for SQL injection or exploit patterns in the username/email. Block if found.
 *
 *    - Browser Plug-in / JavaScript
 *      * Advanced checks to ensure the browser is standard (no dev tool tampering, etc.).
 *
 *    - Third-Party Risk Feeds
 *      * Integrate with external data sources (Spamhaus, abuse.ch, etc.) for additional threat intel.
 *
 *    - Check Payment/Account Status
 *      * If the tenant subscription is suspended, block or reduce access.
 *
 *    - One-Click Threat Hunting
 *      * Real-time cross-check of the username/IP in historical logs to see if it’s new or suspicious.
 *
 *    - Check for Cloned or Spoofed Tenant
 *      * In multi-tenant SaaS, confirm domain/subdomain actually belongs to that tenant (avoid phishing).
 */
