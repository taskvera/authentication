<?php

namespace App\Services;

use DateTime;
use DateTimeZone;
use PDO;

use App\Services\GlobalAuthLogger;

class RiskAssessmentService
{
    /**
     * Writes debug info to a custom log file in the same directory (e.g., "auth_debug.log").
     */
    public function console_debug($label, $value = null)
    {
        // Convert arrays/objects to JSON for easier reading in logs
        if (is_array($value) || is_object($value)) {
            $value = json_encode($value);
        } elseif ($value === null) {
            $value = '';
        }

        // Prepare a timestamped log entry
        $date = date('Y-m-d H:i:s');
        $logEntry = "[{$date}] [DEBUG] {$label}: {$value}\n";

        // Construct the log file path in this same directory (adjust as needed)
        $logFile = __DIR__ . '/../auth_debug.log';

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
        ?string $deviceFingerprintBase64 = null,
        ?DateTime $attemptedAt = null // new param
    ): bool {
        $attemptedAt = $attemptedAt ?? new DateTime('now', new DateTimeZone('UTC'));

        $this->console_debug('assessLoginRisk START', [
            'username' => $username,
            'tenant' => $tenant,
            'ipAddress' => $ipAddress,
            'userAgent' => $userAgent,
            'country' => $country,
            'fingerprintB64' => substr($deviceFingerprintBase64 ?? '', 0, 30), // partial for brevity
            'attemptedAt' => $attemptedAt->format('Y-m-d H:i:s')
        ]);

        // --- Parameter Validations ---
        if (empty($username)) {
            $this->console_debug('assessLoginRisk WARNING', 'Username is empty. This may cause subsequent lookups to fail.');
        }
        if (empty($tenant)) {
            $this->console_debug('assessLoginRisk WARNING', 'Tenant is empty. Ensure you handle multi-tenant logic accordingly.');
        }
        if (empty($ipAddress)) {
            $this->console_debug('assessLoginRisk WARNING', 'IP address is empty. Risk checks may be inaccurate.');
        }
        if (empty($userAgent)) {
            $this->console_debug('assessLoginRisk WARNING', 'User-Agent is empty. This could be suspicious or simply missing data.');
        }
        if (empty($country)) {
            $this->console_debug('assessLoginRisk INFO', 'Country is empty or unknown. Region checks will be minimal.');
        }

        // Array to hold individual risk scores
        $riskScores = [];

        // --------------------------
        // 1) Global IP Blacklist
        // --------------------------
        $this->console_debug('assessLoginRisk STEP', 'Calling checkGlobalIPBlacklist()');
        $scoreIP = $this->checkGlobalIPBlacklist($ipAddress);
        $riskScores[] = $scoreIP;
        $this->console_debug('checkGlobalIPBlacklist returned', $scoreIP);

        // --------------------------
        // 2) AbuseIPDB Check
        // --------------------------
        $this->console_debug('assessLoginRisk STEP', 'Calling checkAbuseIPDB()');
        $scoreAbuse = $this->checkAbuseIPDB($ipAddress);
        $riskScores[] = $scoreAbuse;
        $this->console_debug('checkAbuseIPDB returned', $scoreAbuse);

        // --------------------------
        // 3) Global Region Blacklist
        // --------------------------
        $this->console_debug('assessLoginRisk STEP', 'Calling checkGlobalRegionBlacklist()');
        $scoreRegion = $this->checkGlobalRegionBlacklist($country);
        $riskScores[] = $scoreRegion;
        $this->console_debug('checkGlobalRegionBlacklist returned', $scoreRegion);

        // --------------------------
        // 4a) Sudden Continent Change
        // --------------------------
        $this->console_debug('assessLoginRisk STEP', 'Calling checkSuddenContinentChange()');
        $suddenChangeScore = $this->checkSuddenContinentChange($username, $country);
        $riskScores[] = $suddenChangeScore;
        $this->console_debug('checkSuddenContinentChange returned', $suddenChangeScore);

        // --------------------------
        // 4b) Tor/Proxy/VPN Detection
        // --------------------------
        $this->console_debug('assessLoginRisk STEP', 'Calling checkTorProxyVPN()');
        $scoreTorProxy = $this->checkTorProxyVPN($ipAddress);
        $riskScores[] = $scoreTorProxy;
        $this->console_debug('checkTorProxyVPN returned', $scoreTorProxy);

        // --------------------------
        // 5) Velocity Check
        // --------------------------
        $this->console_debug('assessLoginRisk STEP', 'Calling checkVelocityLimit()');
        $scoreVelocity = $this->checkVelocityLimit($ipAddress, $username);
        $riskScores[] = $scoreVelocity;
        $this->console_debug('checkVelocityLimit returned', $scoreVelocity);

        // --------------------------
        // 6) Device Fingerprint Checking
        // --------------------------
        $this->console_debug('assessLoginRisk STEP', 'Generating device fingerprint hash');
        $dfService = new DeviceFingerprintService();
        $fingerprintHash = $dfService->createFingerprintHash($deviceFingerprintBase64 ?? '');
        $this->console_debug('DeviceFingerprintService hash generated', substr($fingerprintHash, 0, 16) . '...');

        // Here, we might or might not know the user_id. This example uses a placeholder ID.
        // If you do know the user ID by this point, pass it in to compare fingerprints properly.
        $fakeUserId = 123;
        $this->console_debug('assessLoginRisk INFO', 'Using fakeUserId=123 for device fingerprint check');

        // Compare device fingerprint => return some risk
        $this->console_debug('assessLoginRisk STEP', 'Calling compareFingerprintHashToKnown()');
        $scoreFingerprint = $dfService->compareFingerprintHashToKnown($fakeUserId, $fingerprintHash);
        $riskScores[] = $scoreFingerprint;
        $this->console_debug('DeviceFingerprintService risk', $scoreFingerprint);

        // --------------------------
        // 7) Login Time Anomaly Check
        // --------------------------
        $this->console_debug('assessLoginRisk STEP', 'Checking login time anomaly');

        // Fetch user ID and timezone
        $userData = $this->getUserData($username);

        if (!$userData) {
            $this->console_debug('assessLoginRisk ERROR', "User {$username} not found. Assigning high risk.");
            $riskScores[] = 50; // Assign high risk if user not found
        } else {
            $userId = (int) $userData['user_id'];
            $timezone = $userData['timezone'] ?? 'UTC';

            // Use provided attemptedAt or current time
            $loginTime = clone $attemptedAt; // Clone to avoid modifying original

            // Check for login time anomaly
            $scoreTimeAnomaly = $this->checkLoginTimeAnomaly($userId, $timezone, $loginTime);
            $riskScores[] = $scoreTimeAnomaly;
            $this->console_debug('checkLoginTimeAnomaly returned', $scoreTimeAnomaly);
        }

        // --------------------------
        // Calculate Total Risk
        // --------------------------
        $totalRisk = array_sum($riskScores);
        $this->console_debug('Total risk so far', $totalRisk);

        // Compare total risk to threshold
        $this->console_debug('Comparing totalRisk to RISK_THRESHOLD', [
            'totalRisk' => $totalRisk,
            'threshold' => self::RISK_THRESHOLD
        ]);

        // Decide ALLOW or BLOCK
        $isAllowed = $totalRisk < self::RISK_THRESHOLD;
        $decisionLog = $isAllowed
            ? 'ALLOWED (below threshold)'
            : 'BLOCKED (above threshold)';

        $this->console_debug('assessLoginRisk Decision', $decisionLog);

        $this->console_debug('assessLoginRisk END', [
            'result' => $isAllowed ? 'true' : 'false',
            'finalRisk' => $totalRisk
        ]);

        return $isAllowed;
    }

    // -----------------------------------------------------------------------
    //                          HELPER METHODS
    // -----------------------------------------------------------------------

    /**
     * Fetches user data (user_id and timezone) based on the username/email.
     */
    private function getUserData(string $username): ?array
    {
        $this->console_debug('getUserData START', $username);

        global $pdo;
        $sql = "SELECT user_id, timezone FROM auth_users WHERE email = :email LIMIT 1";
        $stmt = $pdo->prepare($sql);
        $stmt->execute(['email' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $this->console_debug('getUserData FOUND', $user);
            return $user;
        }

        $this->console_debug('getUserData NOT FOUND', $username);
        return null;
    }

    /**
     * Retrieves the typical login hours for a user based on historical data.
     * Returns an array of typical hours (0-23).
     */
    private function getTypicalLoginHours(int $userId, string $timezone): array
    {
        $this->console_debug('getTypicalLoginHours START', ['userId' => $userId, 'timezone' => $timezone]);

        global $pdo;
        $sql = "
            SELECT attempted_at
            FROM auth_login_attempts
            WHERE user_id = :user_id
              AND success_at IS NOT NULL
            ORDER BY attempted_at DESC
            LIMIT 1000
        ";
        $stmt = $pdo->prepare($sql);
        $stmt->execute(['user_id' => $userId]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (empty($rows)) {
            $this->console_debug('getTypicalLoginHours NO HISTORY', 'No historical login data found.');
            // Default typical hours if no history exists (e.g., 8 AM–6 PM)
            return range(8, 17);
        }

        // Initialize an array to count logins per hour
        $hourCounts = array_fill(0, 24, 0);

        foreach ($rows as $row) {
            $utcTime = new DateTime($row['attempted_at'], new DateTimeZone('UTC'));
            $userTime = clone $utcTime;
            $userTime->setTimezone(new DateTimeZone($timezone));
            $hour = (int) $userTime->format('G'); // 0-23
            $hourCounts[$hour]++;
        }

        // Calculate cumulative distribution
        arsort($hourCounts);
        $cumulative = 0;
        $typicalHours = [];
        $totalLogins = array_sum($hourCounts);
        foreach ($hourCounts as $hour => $count) {
            $cumulative += $count;
            $typicalHours[] = (int) $hour;
            if ($cumulative / $totalLogins >= 0.8) { // Top 80%
                break;
            }
        }

        $this->console_debug('getTypicalLoginHours RESULT', $typicalHours);
        return $typicalHours;
    }

    /**
     * Checks if the login attempt is at an unusual time for the user.
     * Returns the risk score for time anomaly (e.g., +10).
     */
    private function checkLoginTimeAnomaly(int $userId, string $timezone, DateTime $loginTime): int
    {
        $this->console_debug('checkLoginTimeAnomaly START', [
            'userId' => $userId,
            'loginTime' => $loginTime->format('Y-m-d H:i:s')
        ]);

        $typicalHours = $this->getTypicalLoginHours($userId, $timezone);

        $loginHour = (int) $loginTime->format('G'); // 0-23

        $this->console_debug('checkLoginTimeAnomaly Typical Hours', $typicalHours);
        $this->console_debug('checkLoginTimeAnomaly Login Hour', $loginHour);

        if (!in_array($loginHour, $typicalHours)) {
            $this->console_debug('checkLoginTimeAnomaly ANOMALY', "Login hour {$loginHour} is unusual.");
            return 10; // Assign a risk score, adjust as needed
        }

        $this->console_debug('checkLoginTimeAnomaly NORMAL', 'Login hour is within typical hours.');
        return 0;
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
    /**
     * Checks if an IP is globally blacklisted in `core_global_ip_blacklist`.
     * Returns 100 if blacklisted, 0 if not.
     * 
     * @throws \InvalidArgumentException if IP is invalid or unknown
     * @throws \RuntimeException for any critical DB or logic error
     */
    private function checkGlobalIPBlacklist(string $ipAddress): int
    {
        $this->console_debug('Starting Global IP Blacklist Check with given IP: ', $ipAddress);

        // 1) If IP is unknown
        if ($ipAddress === 'unknown') {
            $this->console_debug('checkGlobalIPBlacklist ERROR', 'IP was "unknown". Throwing exception.');
            throw new \InvalidArgumentException("RiskAssessmentService: IP was 'unknown'.");
        }

        // 2) Convert to numeric
        $currentIpLong = ip2long($ipAddress);
        if ($currentIpLong === false) {
            $this->console_debug('checkGlobalIPBlacklist ERROR', "ip2long() failed for IP: {$ipAddress}.");
            throw new \InvalidArgumentException("RiskAssessmentService: Failed to parse IP address '{$ipAddress}' via ip2long().");
        }

        // 3) Single, more efficient query:
        //    - We treat single IP block if ip_end is NULL
        //    - We treat range block if ip_end is not null AND currentIp is between ip_start, ip_end (regardless of which is smaller)

        global $pdo;

        $sql = <<<SQL
SELECT COUNT(*) AS match_count
FROM core_global_ip_blacklist
WHERE 
    (
      ip_end IS NULL 
      AND ip_start = :singleIp
    )
    OR (
      ip_end IS NOT NULL
      AND INET_ATON(:ipString) BETWEEN LEAST(INET_ATON(ip_start), INET_ATON(ip_end))
                                 AND GREATEST(INET_ATON(ip_start), INET_ATON(ip_end))
    )
SQL;

        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':singleIp', $ipAddress, \PDO::PARAM_STR);
        $stmt->bindValue(':ipString', $ipAddress, \PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);

        if (!$row) {
            $this->console_debug('checkGlobalIPBlacklist ERROR', 'No DB result found (unexpected).');
            throw new \RuntimeException("RiskAssessmentService: Unexpected DB error; no row returned.");
        }

        $matchCount = (int) $row['match_count'];
        $this->console_debug('checkGlobalIPBlacklist match_count', $matchCount);

        if ($matchCount > 0) {
            $this->console_debug('checkGlobalIPBlacklist MATCH - ', "IP {$ipAddress} is globally blacklisted. Returning 100% risk assessment and blocking login.");
            return 100; // block
        }

        // 4) If no match
        $this->console_debug('checkGlobalIPBlacklist NO MATCH - ', "IP {$ipAddress} is NOT globally blacklisted. We are okay to proceed with next check.");
        $this->console_debug('checkGlobalIPBlacklist nding and moving to next check.');
        return 0;
    }


    /**
     * Query AbuseIPDB for an IP's 'abuseConfidenceScore'
     * and return it as an integer "risk" value.
     */
    private function checkAbuseIPDB(string $ipAddress): int
    {
        $this->console_debug('checkAbuseIPDB START', $ipAddress);

        // Basic checks
        if ($ipAddress === 'unknown') {
            $this->console_debug('checkAbuseIPDB ERROR', 'IP was "unknown". Returning 0 risk.');
            return 0;
        }

        // Retrieve API key
        $apiKey = '5970bf069dbae545cdef01d4fa684ce867f6031664c1e1ed937b0fa0976c01f9c87e4158facacddc';
        if (!$apiKey) {
            $this->console_debug('checkAbuseIPDB ERROR', 'No API key set. Returning 0 risk.');
            return 0;
        }

        // Build the URL
        $endpoint = 'https://api.abuseipdb.com/api/v2/check';
        $queryParams = http_build_query([
            'ipAddress' => $ipAddress,
            'maxAgeInDays' => 90,
        ]);
        $url = $endpoint . '?' . $queryParams;

        // Make cURL request
        $this->console_debug('checkAbuseIPDB cURL REQUEST', $url);
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                    'Accept: application/json',
                    'X-Api-Key: ' . $apiKey,
                ],
        ]);
        $response = curl_exec($ch);

        if (curl_errno($ch)) {
            $error = curl_error($ch);
            $this->console_debug('checkAbuseIPDB CURL ERROR', $error);
            curl_close($ch);
            return 0;
        }
        curl_close($ch);

        // Decode JSON
        $decoded = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->console_debug('checkAbuseIPDB JSON ERROR', json_last_error_msg());
            return 0;
        }

        // Extract the abuseConfidenceScore
        $confidenceScore = $decoded['data']['abuseConfidenceScore'] ?? 0;
        $this->console_debug('checkAbuseIPDB confidenceScore', $confidenceScore);

        $this->console_debug('checkAbuseIPDB END');
        return (int) $confidenceScore;
    }

    private function checkGlobalRegionBlacklist(string $countryCode): int
    {
        $this->console_debug('checkGlobalRegionBlacklist START', $countryCode);

        if (empty($countryCode)) {
            $this->console_debug('checkGlobalRegionBlacklist NO COUNTRY', 'No country code provided. Returning 0.');
            return 0;
        }

        global $pdo;
        $sql = "
            SELECT region_id, country_code, notes
            FROM core_global_region_blacklist
            WHERE UPPER(country_code) = UPPER(:code)
            LIMIT 1
        ";
        $this->console_debug('checkGlobalRegionBlacklist Query', [
            'sql' => $sql,
            'param' => $countryCode
        ]);

        $stmt = $pdo->prepare($sql);
        $stmt->execute(['code' => $countryCode]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row) {
            $this->console_debug('checkGlobalRegionBlacklist MATCH', [
                'region_id' => $row['region_id'],
                'country_code' => $row['country_code'],
                'notes' => $row['notes']
            ]);
            return 100;
        }

        $this->console_debug('checkGlobalRegionBlacklist NO MATCH', "{$countryCode} not found in region blacklist");
        $this->console_debug('checkGlobalRegionBlacklist END');
        return 0;
    }

    private function checkSuddenContinentChange(string $username, string $currentCountry): int
    {
        $this->console_debug('checkSuddenContinentChange START', [
            'username' => $username,
            'currentCountry' => $currentCountry
        ]);

        if (empty($username) || empty($currentCountry)) {
            $this->console_debug('checkSuddenContinentChange SKIP', 'Missing username or currentCountry. Returning 0.');
            return 0;
        }

        global $pdo;
        $sql = "
            SELECT country
            FROM auth_login_attempts
            WHERE email_entered = :email
              AND success_at IS NOT NULL
            ORDER BY success_at DESC
            LIMIT 1
        ";
        $this->console_debug('checkSuddenContinentChange Query', $sql);

        $stmt = $pdo->prepare($sql);
        $stmt->execute(['email' => $username]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row || empty($row['country'])) {
            $this->console_debug('checkSuddenContinentChange NO HISTORY', 'No prior successful login found. Returning 0.');
            return 0;
        }

        $lastCountry = strtoupper($row['country']);
        $currentCountry = strtoupper($currentCountry);

        $continentOfLast = $this->getContinentCode($lastCountry);
        $continentOfCurrent = $this->getContinentCode($currentCountry);

        $this->console_debug('checkSuddenContinentChange CONTINENTS', [
            'last' => $continentOfLast,
            'current' => $continentOfCurrent
        ]);

        if ($continentOfLast && $continentOfCurrent && $continentOfLast !== $continentOfCurrent) {
            $this->console_debug('checkSuddenContinentChange DIFFERENT', [
                'last_country' => $lastCountry,
                'last_continent' => $continentOfLast,
                'current_country' => $currentCountry,
                'current_continent' => $continentOfCurrent,
                'added_risk' => 20
            ]);
            return 20;
        }

        $this->console_debug('checkSuddenContinentChange SAME OR EMPTY', [
            'continentOfLast' => $continentOfLast,
            'continentOfCurrent' => $continentOfCurrent
        ]);
        return 0;
    }

    /**
     * (Very) rough method to map a country code to a continent code.
     * In production, you could keep a DB or library with full mapping.
     */
    private function getContinentCode(string $countryCode): ?string
    {
        $this->console_debug('getContinentCode START', $countryCode);

        $map = [
            'US' => 'NA', // North America
            'CA' => 'NA',
            'MX' => 'NA',

            'GB' => 'EU',
            'FR' => 'EU',
            'DE' => 'EU',
            'ES' => 'EU',

            'JP' => 'AS',
            'CN' => 'AS',
            'IN' => 'AS',

            'AU' => 'OC',
            // etc...
        ];

        $continentCode = $map[$countryCode] ?? null;
        if ($continentCode) {
            $this->console_debug('getContinentCode FOUND', [
                'country' => $countryCode,
                'continent' => $continentCode
            ]);
        } else {
            $this->console_debug('getContinentCode NOT FOUND', $countryCode);
        }

        return $continentCode;
    }

    private function checkTorProxyVPN(string $ipAddress): int
    {
        $this->console_debug('checkTorProxyVPN START', $ipAddress);

        if ($ipAddress === 'unknown') {
            $this->console_debug('checkTorProxyVPN SKIP', 'IP is "unknown". Returning 0 risk.');
            return 0;
        }

        $apiKey = getenv('PROXY_DETECT_API_KEY');
        if (!$apiKey) {
            $this->console_debug('checkTorProxyVPN ERROR', 'No API key set for proxy detection. Returning 0.');
            return 0;
        }

        $url = 'https://api.proxy-detect-example.com/v1/check?ip=' . urlencode($ipAddress);
        $this->console_debug('checkTorProxyVPN cURL REQUEST', $url);

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
        $isProxy = $decoded['proxy'] ?? false;
        $isVPN = $decoded['vpn'] ?? false;
        $isTor = $decoded['tor'] ?? false;

        $this->console_debug('checkTorProxyVPN API RESPONSE', [
            'isProxy' => $isProxy,
            'isVPN' => $isVPN,
            'isTor' => $isTor
        ]);

        if ($isProxy || $isVPN || $isTor) {
            $this->console_debug('checkTorProxyVPN MATCH', 'IP flagged as proxy/VPN/Tor => +30 risk');
            return 30;
        }

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
            $this->console_debug('checkVelocityLimit SKIP', 'IP is "unknown". Returning 0.');
            return 0;
        }

        global $pdo;
        $sql = "
            SELECT COUNT(*) AS attempt_count
            FROM auth_login_attempts
            WHERE ip_address = :ip
              AND attempted_at >= (NOW() - INTERVAL 15 MINUTE)
        ";
        $this->console_debug('checkVelocityLimit Query', $sql);

        $stmt = $pdo->prepare($sql);
        $stmt->execute(['ip' => $ipAddress]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        $attemptCount = (int) ($row['attempt_count'] ?? 0);
        $this->console_debug('checkVelocityLimit attemptCount', $attemptCount);

        // e.g. threshold = 5 attempts per 15 minutes
        $threshold = 5;
        if ($attemptCount > $threshold) {
            $this->console_debug('checkVelocityLimit ABOVE THRESHOLD', [
                'attemptCount' => $attemptCount,
                'threshold' => $threshold,
                'addedRisk' => 50
            ]);
            return 50; // could do 100 if you want an immediate block
        }

        $this->console_debug('checkVelocityLimit END', 'attemptCount is below threshold => 0 risk');
        return 0;
    }
}

?>