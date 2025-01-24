<?php

namespace App\Services;

use DateTime;
use DateTimeZone;
use PDO;

class IPRiskAssessment
{
    /**
     * Writes debug info to a custom log file in the same directory (e.g., "auth_debug.log").
     */
    public function console_debug($label, $value = null)
    {
        // Convert arrays/objects to JSON for easier reading in logs
        if (is_array($value) || is_object($value)) {
            $value = json_encode($value, JSON_PRETTY_PRINT);
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
     * Assesses the IP-related risks for a given IP address.
     * Returns an array with individual risk scores and the total risk.
     */
    public function assessIPRisk(string $ipAddress, string $username, PDO $pdo): array
    {
        $this->console_debug('assessIPRisk START', [
            'ipAddress' => $ipAddress,
            'username'  => $username
        ]);

        // Array to hold individual risk scores
        $riskScores = [];

        try {
            // 1. Global IP Blacklist Check
            $this->console_debug('assessIPRisk STEP', 'Executing Global IP Blacklist Check');
            $score = $this->checkGlobalIPBlacklist($ipAddress, $pdo);
            $riskScores['GlobalIPBlacklist'] = $score;

            // 2. AbuseIPDB Check
            $this->console_debug('assessIPRisk STEP', 'Executing AbuseIPDB Check');
            $score = $this->checkAbuseIPDB($ipAddress);
            $riskScores['AbuseIPDB'] = $score;

            // 3. Global Region Blacklist Check
            $this->console_debug('assessIPRisk STEP', 'Executing Global Region Blacklist Check');
            $score = $this->checkGlobalRegionBlacklist($ipAddress, $pdo);
            $riskScores['GlobalRegionBlacklist'] = $score;

            // 4. Sudden Continent Change Detection
            $this->console_debug('assessIPRisk STEP', 'Executing Sudden Continent Change Detection');
            $score = $this->checkSuddenContinentChange($username, $ipAddress, $pdo);
            $riskScores['SuddenContinentChange'] = $score;

            // 5. Tor/Proxy/VPN Detection
            $this->console_debug('assessIPRisk STEP', 'Executing Tor/Proxy/VPN Detection');
            $score = $this->checkTorProxyVPN($ipAddress);
            $riskScores['TorProxyVPN'] = $score;

            // 6. Velocity Limit Check
            $this->console_debug('assessIPRisk STEP', 'Executing Velocity Limit Check');
            $score = $this->checkVelocityLimit($ipAddress, $username, $pdo);
            $riskScores['VelocityLimit'] = $score;

            // 7. ASN Reputation Check
            $this->console_debug('assessIPRisk STEP', 'Executing ASN Reputation Check');
            $score = $this->checkASNReputation($ipAddress, $pdo);
            $riskScores['ASNReputation'] = $score;

            // 8. Cloud Provider IP Detection
            $this->console_debug('assessIPRisk STEP', 'Executing Cloud Provider IP Detection');
            $score = $this->checkCloudProviderIP($ipAddress, $pdo);
            $riskScores['CloudProviderIP'] = $score;

            // 9. Reverse DNS Lookup
            $this->console_debug('assessIPRisk STEP', 'Executing Reverse DNS Lookup');
            $score = $this->checkReverseDNS($ipAddress);
            $riskScores['ReverseDNS'] = $score;

            // 10. Multiple Reputation Services Aggregation
            $this->console_debug('assessIPRisk STEP', 'Executing Multiple Reputation Services Aggregation');
            $score = $this->checkMultipleReputationServices($ipAddress);
            $riskScores['MultipleReputationServices'] = $score;

            // 11. Shared IP Detection
            $this->console_debug('assessIPRisk STEP', 'Executing Shared IP Detection');
            $score = $this->checkSharedIP($ipAddress, $pdo);
            $riskScores['SharedIP'] = $score;

            // 12. Spam Network Identification
            $this->console_debug('assessIPRisk STEP', 'Executing Spam Network Identification');
            $score = $this->checkSpamNetwork($ipAddress, $pdo);
            $riskScores['SpamNetwork'] = $score;

            // 13. DDoS Source Detection
            $this->console_debug('assessIPRisk STEP', 'Executing DDoS Source Detection');
            $score = $this->checkDDoSSource($ipAddress, $pdo);
            $riskScores['DDoSSource'] = $score;

            // 14. IP Geolocation Consistency Check
            $this->console_debug('assessIPRisk STEP', 'Executing IP Geolocation Consistency Check');
            $score = $this->checkIPGeolocationConsistency($ipAddress, $username, $pdo);
            $riskScores['IPGeolocationConsistency'] = $score;

            // 15. IP Entropy Analysis
            $this->console_debug('assessIPRisk STEP', 'Executing IP Entropy Analysis');
            $score = $this->checkIPEntropy($ipAddress);
            $riskScores['IPEntropy'] = $score;

            // 16. Number of Associated Domains Check
            $this->console_debug('assessIPRisk STEP', 'Executing Number of Associated Domains Check');
            $score = $this->checkAssociatedDomains($ipAddress, $pdo);
            $riskScores['AssociatedDomains'] = $score;

            // 17. IP Rotation Detection
            $this->console_debug('assessIPRisk STEP', 'Executing IP Rotation Detection');
            $score = $this->checkIPRotation($ipAddress, $username, $pdo);
            $riskScores['IPRotation'] = $score;

            // 18. Proxy Score Assessment
            $this->console_debug('assessIPRisk STEP', 'Executing Proxy Score Assessment');
            $score = $this->checkProxyScore($ipAddress, $pdo);
            $riskScores['ProxyScore'] = $score;

            // 19. Malicious IP Range Identification
            $this->console_debug('assessIPRisk STEP', 'Executing Malicious IP Range Identification');
            $score = $this->checkMaliciousIPRange($ipAddress, $pdo);
            $riskScores['MaliciousIPRange'] = $score;

            // 20. IP Change Frequency Monitoring
            $this->console_debug('assessIPRisk STEP', 'Executing IP Change Frequency Monitoring');
            $score = $this->checkIPChangeFrequency($username, $ipAddress, $pdo);
            $riskScores['IPChangeFrequency'] = $score;

            // Calculate Total Risk
            $totalRisk = array_sum($riskScores);
            $this->console_debug('assessIPRisk TOTAL', $totalRisk);

            // Final Output
            $result = [
                'individualScores' => $riskScores,
                'totalRisk'        => $totalRisk
            ];

            $this->console_debug('assessIPRisk END', $result);

            return $result;
        }
    }
        // -----------------------------------------------------------------------
        //                          IP-RELATED CHECK METHODS
        // -----------------------------------------------------------------------

        /**
         * 1. Global IP Blacklist Check
         * Checks if the IP is present in the global IP blacklist.
         * Returns 100 if blacklisted, 0 otherwise.
         */
        private function checkGlobalIPBlacklist(string $ipAddress, PDO $pdo): int
        {
            $this->console_debug('checkGlobalIPBlacklist START', $ipAddress);

            // Validate IP
            if ($ipAddress === 'unknown') {
                $this->console_debug('checkGlobalIPBlacklist ERROR', 'IP is "unknown".');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkGlobalIPBlacklist ERROR', 'Invalid IP format.');
                return 0;
            }

            // Query the blacklist table for exact IP or range
            $sql = <<<SQL
SELECT COUNT(*) AS match_count
FROM core_global_ip_blacklist
WHERE 
    (ip_end IS NULL AND ip_start = :ip)
    OR (
        ip_end IS NOT NULL 
        AND INET_ATON(:ip) BETWEEN LEAST(INET_ATON(ip_start), INET_ATON(ip_end)) 
                           AND GREATEST(INET_ATON(ip_start), INET_ATON(ip_end))
    )
SQL;

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['ip' => $ipAddress]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $matchCount = (int)$row['match_count'];
            $this->console_debug('checkGlobalIPBlacklist MATCH_COUNT', $matchCount);

            if ($matchCount > 0) {
                $this->console_debug('checkGlobalIPBlacklist MATCH', "IP {$ipAddress} is blacklisted.");
                return 100;
            }

            $this->console_debug('checkGlobalIPBlacklist NO MATCH', "IP {$ipAddress} is not blacklisted.");
            return 0;
        }

        /**
         * 2. AbuseIPDB Check
         * Queries AbuseIPDB for the abuse confidence score of the IP.
         * Returns the score (0-100).
         */
        private function checkAbuseIPDB(string $ipAddress): int
        {
            $this->console_debug('checkAbuseIPDB START', $ipAddress);

            if ($ipAddress === 'unknown') {
                $this->console_debug('checkAbuseIPDB SKIP', 'IP is "unknown".');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkAbuseIPDB ERROR', 'Invalid IP format.');
                return 0;
            }

            // Retrieve API key securely, e.g., from environment variables
            $apiKey = getenv('ABUSEIPDB_API_KEY');
            if (!$apiKey) {
                $this->console_debug('checkAbuseIPDB ERROR', 'AbuseIPDB API key not set.');
                return 0;
            }

            // Build the URL
            $endpoint    = 'https://api.abuseipdb.com/api/v2/check';
            $queryParams = http_build_query([
                'ipAddress'    => $ipAddress,
                'maxAgeInDays' => 90,
            ]);
            $url = "{$endpoint}?{$queryParams}";

            // Initialize cURL
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER     => [
                    'Accept: application/json',
                    "Key: {$apiKey}",
                ],
                CURLOPT_TIMEOUT        => 10,
            ]);

            // Execute cURL request
            $response = curl_exec($ch);
            $curlError = curl_error($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($response === false) {
                $this->console_debug('checkAbuseIPDB CURL ERROR', $curlError);
                return 0;
            }

            if ($httpCode !== 200) {
                $this->console_debug('checkAbuseIPDB HTTP ERROR', "Status Code: {$httpCode}");
                return 0;
            }

            // Decode JSON response
            $decoded = json_decode($response, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                $this->console_debug('checkAbuseIPDB JSON ERROR', json_last_error_msg());
                return 0;
            }

            $confidenceScore = $decoded['data']['abuseConfidenceScore'] ?? 0;
            $confidenceScore = is_numeric($confidenceScore) ? (int)$confidenceScore : 0;
            $this->console_debug('checkAbuseIPDB RESULT', $confidenceScore);

            return $confidenceScore;
        }

        /**
         * 3. Global Region Blacklist Check
         * Checks if the IP's country is in the global region blacklist.
         * Returns 100 if blacklisted, 0 otherwise.
         */
        private function checkGlobalRegionBlacklist(string $ipAddress, PDO $pdo): int
        {
            $this->console_debug('checkGlobalRegionBlacklist START', $ipAddress);

            if ($ipAddress === 'unknown') {
                $this->console_debug('checkGlobalRegionBlacklist SKIP', 'IP is "unknown".');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkGlobalRegionBlacklist ERROR', 'Invalid IP format.');
                return 0;
            }

            // Determine the country from IP
            $countryCode = $this->getCountryFromIP($ipAddress, $pdo);
            if (!$countryCode) {
                $this->console_debug('checkGlobalRegionBlacklist ERROR', 'Unable to determine country from IP.');
                return 0;
            }

            $this->console_debug('checkGlobalRegionBlacklist COUNTRY', $countryCode);

            // Query the region blacklist
            $sql = "
                SELECT COUNT(*) AS match_count
                FROM core_global_region_blacklist
                WHERE UPPER(country_code) = UPPER(:country)
                LIMIT 1
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['country' => $countryCode]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $matchCount = (int)$row['match_count'];
            $this->console_debug('checkGlobalRegionBlacklist MATCH_COUNT', $matchCount);

            if ($matchCount > 0) {
                $this->console_debug('checkGlobalRegionBlacklist MATCH', "Country {$countryCode} is blacklisted.");
                return 100;
            }

            $this->console_debug('checkGlobalRegionBlacklist NO MATCH', "Country {$countryCode} is not blacklisted.");
            return 0;
        }

        /**
         * Helper method to determine the country code from an IP address.
         * Uses MaxMind GeoIP2 or similar service.
         * Replace with actual implementation.
         */
        private function getCountryFromIP(string $ipAddress, PDO $pdo): ?string
        {
            $this->console_debug('getCountryFromIP START', $ipAddress);

            // Example implementation using a hypothetical geoip_table
            $sql = "
                SELECT country_code 
                FROM geoip_table 
                WHERE INET_ATON(ip_start) <= INET_ATON(:ip)
                  AND (INET_ATON(ip_end) >= INET_ATON(:ip) OR ip_end IS NULL)
                LIMIT 1
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['ip' => $ipAddress]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($row && !empty($row['country_code'])) {
                $this->console_debug('getCountryFromIP FOUND', $row['country_code']);
                return strtoupper($row['country_code']);
            }

            $this->console_debug('getCountryFromIP NOT FOUND', 'Country code could not be determined.');
            return null;
        }

        /**
         * 4. Sudden Continent Change Detection
         * Detects if the IP's continent has changed abruptly compared to the user's last login.
         * Returns 20 if detected, 0 otherwise.
         */
        private function checkSuddenContinentChange(string $username, string $ipAddress, PDO $pdo): int
        {
            $this->console_debug('checkSuddenContinentChange START', [
                'username'  => $username,
                'ipAddress' => $ipAddress
            ]);

            if (empty($username) || empty($ipAddress)) {
                $this->console_debug('checkSuddenContinentChange SKIP', 'Missing username or IP address.');
                return 0;
            }

            // Get user's last successful login IP
            $sql = "
                SELECT la.ip_address
                FROM auth_login_attempts la
                WHERE la.email_entered = :email
                  AND la.success_at IS NOT NULL
                ORDER BY la.success_at DESC
                LIMIT 1
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['email' => $username]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$row || empty($row['ip_address'])) {
                $this->console_debug('checkSuddenContinentChange NO HISTORY', 'No prior successful login found.');
                return 0;
            }

            $lastIP = $row['ip_address'];
            $this->console_debug('checkSuddenContinentChange LAST_IP', $lastIP);

            // Get continents
            $lastCountry = $this->getCountryFromIP($lastIP, $pdo);
            $currentCountry = $this->getCountryFromIP($ipAddress, $pdo);

            if (!$lastCountry || !$currentCountry) {
                $this->console_debug('checkSuddenContinentChange ERROR', 'Unable to determine countries for comparison.');
                return 0;
            }

            $lastContinent = $this->getContinentCode($lastCountry);
            $currentContinent = $this->getContinentCode($currentCountry);

            $this->console_debug('checkSuddenContinentChange CONTINENTS', [
                'lastContinent'    => $lastContinent,
                'currentContinent' => $currentContinent
            ]);

            if ($lastContinent && $currentContinent && $lastContinent !== $currentContinent) {
                $this->console_debug('checkSuddenContinentChange MATCH', 'Sudden continent change detected.');
                return 20;
            }

            $this->console_debug('checkSuddenContinentChange NO MATCH', 'No sudden continent change detected.');
            return 0;
        }

        /**
         * Helper method to map country code to continent code.
         * Extend this mapping as needed.
         */
        private function getContinentCode(string $countryCode): ?string
        {
            $this->console_debug('getContinentCode START', $countryCode);

            $map = [
                'AF' => 'AS', // Asia
                'AX' => 'EU', // Europe
                'AL' => 'EU',
                'DZ' => 'AF',
                'AS' => 'OC',
                'AD' => 'EU',
                'AO' => 'AF',
                'AI' => 'NA',
                'AQ' => 'AN',
                'AG' => 'NA',
                'AR' => 'SA',
                'AM' => 'AS',
                'AW' => 'NA',
                'AU' => 'OC',
                'AT' => 'EU',
                'AZ' => 'AS',
                // ... (complete the mapping for all country codes)
                'US' => 'NA',
                'CA' => 'NA',
                'GB' => 'EU',
                'FR' => 'EU',
                'DE' => 'EU',
                'CN' => 'AS',
                'IN' => 'AS',
                'BR' => 'SA',
                'RU' => 'EU', // Russia spans Europe and Asia; assign based on actual location
                // Add all required mappings
            ];

            $continentCode = $map[$countryCode] ?? null;

            if ($continentCode) {
                $this->console_debug('getContinentCode FOUND', $continentCode);
            } else {
                $this->console_debug('getContinentCode NOT FOUND', 'Continent code not found for country.');
            }

            return $continentCode;
        }

        /**
         * 5. Tor/Proxy/VPN Detection
         * Determines if the IP is a known Tor exit node, proxy, or VPN.
         * Returns 30 if any are true, 0 otherwise.
         */
        private function checkTorProxyVPN(string $ipAddress): int
        {
            $this->console_debug('checkTorProxyVPN START', $ipAddress);

            if ($ipAddress === 'unknown') {
                $this->console_debug('checkTorProxyVPN SKIP', 'IP is "unknown".');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkTorProxyVPN ERROR', 'Invalid IP format.');
                return 0;
            }

            // Retrieve API key securely
            $apiKey = getenv('PROXY_DETECT_API_KEY');
            if (!$apiKey) {
                $this->console_debug('checkTorProxyVPN ERROR', 'Proxy detection API key not set.');
                return 0;
            }

            // Build the URL (replace with actual proxy detection API endpoint)
            $endpoint = 'https://api.proxy-detect-example.com/v1/check';
            $url = "{$endpoint}?ip=" . urlencode($ipAddress);

            // Initialize cURL
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER     => [
                    'Accept: application/json',
                    "X-API-KEY: {$apiKey}",
                ],
                CURLOPT_TIMEOUT        => 10,
            ]);

            // Execute cURL request
            $response = curl_exec($ch);
            $curlError = curl_error($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($response === false) {
                $this->console_debug('checkTorProxyVPN CURL ERROR', $curlError);
                return 0;
            }

            if ($httpCode !== 200) {
                $this->console_debug('checkTorProxyVPN HTTP ERROR', "Status Code: {$httpCode}");
                return 0;
            }

            // Decode JSON response
            $decoded = json_decode($response, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                $this->console_debug('checkTorProxyVPN JSON ERROR', json_last_error_msg());
                return 0;
            }

            // Assume the API returns boolean flags
            $isProxy = $decoded['proxy'] ?? false;
            $isVPN   = $decoded['vpn'] ?? false;
            $isTor   = $decoded['tor'] ?? false;

            $this->console_debug('checkTorProxyVPN API RESPONSE', [
                'proxy' => $isProxy,
                'vpn'   => $isVPN,
                'tor'   => $isTor
            ]);

            if ($isProxy || $isVPN || $isTor) {
                $this->console_debug('checkTorProxyVPN MATCH', 'IP is a Proxy/VPN/Tor node.');
                return 30;
            }

            $this->console_debug('checkTorProxyVPN NO MATCH', 'IP is not a Proxy/VPN/Tor node.');
            return 0;
        }

        /**
         * 6. Velocity Limit Check
         * Monitors the number of login attempts from the same IP within a timeframe.
         * Returns 50 if attempts exceed the threshold, 0 otherwise.
         */
        private function checkVelocityLimit(string $ipAddress, string $username, PDO $pdo): int
        {
            $this->console_debug('checkVelocityLimit START', [
                'ipAddress' => $ipAddress,
                'username'  => $username
            ]);

            if ($ipAddress === 'unknown') {
                $this->console_debug('checkVelocityLimit SKIP', 'IP is "unknown".');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkVelocityLimit ERROR', 'Invalid IP format.');
                return 0;
            }

            // Define threshold and timeframe
            $threshold = 5; // e.g., 5 attempts
            $timeframe = '15 MINUTE'; // e.g., within the last 15 minutes

            // Query the number of attempts from this IP within the timeframe
            $sql = "
                SELECT COUNT(*) AS attempt_count
                FROM auth_login_attempts
                WHERE ip_address = :ip
                  AND attempted_at >= (NOW() - INTERVAL {$timeframe})
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['ip' => $ipAddress]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $attemptCount = (int)($row['attempt_count'] ?? 0);
            $this->console_debug('checkVelocityLimit ATTEMPT_COUNT', $attemptCount);

            if ($attemptCount > $threshold) {
                $this->console_debug('checkVelocityLimit MATCH', 'Velocity limit exceeded.');
                return 50;
            }

            $this->console_debug('checkVelocityLimit NO MATCH', 'Velocity limit not exceeded.');
            return 0;
        }

        /**
         * 7. ASN Reputation Check
         * Evaluates the reputation of the ASN associated with the IP.
         * Returns a score based on ASN reputation (e.g., 0-30).
         */
        private function checkASNReputation(string $ipAddress, PDO $pdo): int
        {
            $this->console_debug('checkASNReputation START', $ipAddress);

            if ($ipAddress === 'unknown') {
                $this->console_debug('checkASNReputation SKIP', 'IP is "unknown".');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkASNReputation ERROR', 'Invalid IP format.');
                return 0;
            }

            // Retrieve ASN information using MaxMind GeoIP2 ASN database or similar
            // Placeholder: Replace with actual ASN retrieval logic
            $asn = $this->getASNFromIP($ipAddress, $pdo);
            if (!$asn) {
                $this->console_debug('checkASNReputation ERROR', 'Unable to retrieve ASN.');
                return 0;
            }

            $this->console_debug('checkASNReputation ASN', $asn);

            // Check ASN reputation (e.g., from internal DB or external API)
            $reputationScore = $this->getASNReputationScore($asn, $pdo);
            $this->console_debug('checkASNReputation REPUTATION_SCORE', $reputationScore);

            return $reputationScore;
        }

        /**
         * Helper method to retrieve ASN from IP.
         * Implement using MaxMind GeoIP2 ASN or similar service.
         */
        private function getASNFromIP(string $ipAddress, PDO $pdo): ?string
        {
            $this->console_debug('getASNFromIP START', $ipAddress);

            // Example implementation using a hypothetical asn_table
            $sql = "
                SELECT asn 
                FROM geoip_asn_table 
                WHERE INET_ATON(ip_start) <= INET_ATON(:ip)
                  AND (INET_ATON(ip_end) >= INET_ATON(:ip) OR ip_end IS NULL)
                LIMIT 1
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['ip' => $ipAddress]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($row && !empty($row['asn'])) {
                $this->console_debug('getASNFromIP FOUND', $row['asn']);
                return $row['asn'];
            }

            $this->console_debug('getASNFromIP NOT FOUND', 'ASN could not be determined.');
            return null;
        }

        /**
         * Helper method to get ASN reputation score.
         * Implement based on your own criteria or external service.
         * Returns an integer score (0-30).
         */
        private function getASNReputationScore(string $asn, PDO $pdo): int
        {
            $this->console_debug('getASNReputationScore START', $asn);

            // Example: Retrieve reputation score from internal DB
            $sql = "
                SELECT reputation_score 
                FROM asn_reputation 
                WHERE asn = :asn
                LIMIT 1
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['asn' => $asn]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($row && isset($row['reputation_score'])) {
                $score = (int)$row['reputation_score'];
                $this->console_debug('getASNReputationScore FOUND', $score);
                return $score;
            }

            // Default score if not found
            $this->console_debug('getASNReputationScore NOT FOUND', 'Defaulting to 0.');
            return 0;
        }

        /**
         * 8. Cloud Provider IP Detection
         * Identifies if the IP belongs to a known cloud service provider.
         * Returns 10 if detected, 0 otherwise.
         */
        private function checkCloudProviderIP(string $ipAddress, PDO $pdo): int
        {
            $this->console_debug('checkCloudProviderIP START', $ipAddress);

            if ($ipAddress === 'unknown') {
                $this->console_debug('checkCloudProviderIP SKIP', 'IP is "unknown".');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkCloudProviderIP ERROR', 'Invalid IP format.');
                return 0;
            }

            // Query cloud provider IP ranges from a dedicated table
            $sql = "
                SELECT provider_name
                FROM cloud_provider_ip_ranges
                WHERE INET_ATON(:ip) BETWEEN INET_ATON(ip_start) AND INET_ATON(ip_end)
                LIMIT 1
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['ip' => $ipAddress]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($row && !empty($row['provider_name'])) {
                $this->console_debug('checkCloudProviderIP MATCH', $row['provider_name']);
                return 10;
            }

            $this->console_debug('checkCloudProviderIP NO MATCH', 'IP does not belong to a known cloud provider.');
            return 0;
        }

        /**
         * 9. Reverse DNS Lookup
         * Performs a reverse DNS lookup and checks for consistency.
         * Returns 15 if reverse DNS is suspicious, 0 otherwise.
         */
        private function checkReverseDNS(string $ipAddress): int
        {
            $this->console_debug('checkReverseDNS START', $ipAddress);

            if ($ipAddress === 'unknown') {
                $this->console_debug('checkReverseDNS SKIP', 'IP is "unknown".');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkReverseDNS ERROR', 'Invalid IP format.');
                return 0;
            }

            $hostname = gethostbyaddr($ipAddress);
            $this->console_debug('checkReverseDNS HOSTNAME', $hostname);

            if ($hostname === $ipAddress) {
                // No PTR record found
                $this->console_debug('checkReverseDNS NO PTR RECORD', 'No PTR record found.');
                return 15;
            }

            // Optional: Additional checks on hostname format
            if (!filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                $this->console_debug('checkReverseDNS SUSPICIOUS HOSTNAME', 'Hostname format is invalid.');
                return 15;
            }

            $this->console_debug('checkReverseDNS NORMAL', 'PTR record and hostname format are valid.');
            return 0;
        }

        /**
         * 10. Multiple Reputation Services Aggregation
         * Aggregates risk scores from multiple reputation services.
         * Returns the cumulative score.
         */
        private function checkMultipleReputationServices(string $ipAddress): int
        {
            $this->console_debug('checkMultipleReputationServices START', $ipAddress);

            // Example: Integrate with multiple services like Project Honeypot, Spamhaus, etc.
            // For demonstration, we'll mock two services.

            $score = 0;

            // Service 1: Project Honeypot
            $score += $this->checkProjectHoneypot($ipAddress);

            // Service 2: Spamhaus
            $score += $this->checkSpamhaus($ipAddress);

            $this->console_debug('checkMultipleReputationServices TOTAL_SCORE', $score);
            return $score;
        }

        /**
         * Helper method to check Project Honeypot data.
         * Returns a score based on data (e.g., 0-15).
         */
        private function checkProjectHoneypot(string $ipAddress): int
        {
            $this->console_debug('checkProjectHoneypot START', $ipAddress);

            // Implement actual Project Honeypot API integration
            // Placeholder implementation
            // Assume it returns a score between 0-15

            // Example response
            $isSuspicious = false; // Replace with actual API response

            if ($isSuspicious) {
                $this->console_debug('checkProjectHoneypot MATCH', 'IP is listed in Project Honeypot.');
                return 15;
            }

            $this->console_debug('checkProjectHoneypot NO MATCH', 'IP is not listed in Project Honeypot.');
            return 0;
        }

        /**
         * Helper method to check Spamhaus data.
         * Returns a score based on data (e.g., 0-15).
         */
        private function checkSpamhaus(string $ipAddress): int
        {
            $this->console_debug('checkSpamhaus START', $ipAddress);

            // Implement actual Spamhaus API integration
            // Placeholder implementation
            // Assume it returns a score between 0-15

            // Example response
            $isListed = false; // Replace with actual API response

            if ($isListed) {
                $this->console_debug('checkSpamhaus MATCH', 'IP is listed in Spamhaus.');
                return 15;
            }

            $this->console_debug('checkSpamhaus NO MATCH', 'IP is not listed in Spamhaus.');
            return 0;
        }

        /**
         * 11. Shared IP Detection
         * Determines if the IP is shared among multiple users.
         * Returns 10 if shared, 0 otherwise.
         */
        private function checkSharedIP(string $ipAddress, PDO $pdo): int
        {
            $this->console_debug('checkSharedIP START', $ipAddress);

            if ($ipAddress === 'unknown') {
                $this->console_debug('checkSharedIP SKIP', 'IP is "unknown".');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkSharedIP ERROR', 'Invalid IP format.');
                return 0;
            }

            // Define a threshold for number of unique users sharing the IP
            $threshold = 10; // Example threshold

            $sql = "
                SELECT COUNT(DISTINCT user_id) AS user_count
                FROM auth_login_attempts
                WHERE ip_address = :ip
                LIMIT 1
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['ip' => $ipAddress]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $userCount = (int)($row['user_count'] ?? 0);
            $this->console_debug('checkSharedIP USER_COUNT', $userCount);

            if ($userCount > $threshold) {
                $this->console_debug('checkSharedIP MATCH', 'IP is shared among multiple users.');
                return 10;
            }

            $this->console_debug('checkSharedIP NO MATCH', 'IP is not shared among multiple users.');
            return 0;
        }

        /**
         * 12. Spam Network Identification
         * Checks if the IP is part of a known spam network.
         * Returns 20 if identified, 0 otherwise.
         */
        private function checkSpamNetwork(string $ipAddress, PDO $pdo): int
        {
            $this->console_debug('checkSpamNetwork START', $ipAddress);

            if ($ipAddress === 'unknown') {
                $this->console_debug('checkSpamNetwork SKIP', 'IP is "unknown".');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkSpamNetwork ERROR', 'Invalid IP format.');
                return 0;
            }

            // Query the spam_networks table
            $sql = "
                SELECT COUNT(*) AS match_count
                FROM spam_networks
                WHERE ip_address = :ip
                LIMIT 1
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['ip' => $ipAddress]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $matchCount = (int)($row['match_count'] ?? 0);
            $this->console_debug('checkSpamNetwork MATCH_COUNT', $matchCount);

            if ($matchCount > 0) {
                $this->console_debug('checkSpamNetwork MATCH', 'IP is part of a known spam network.');
                return 20;
            }

            $this->console_debug('checkSpamNetwork NO MATCH', 'IP is not part of a known spam network.');
            return 0;
        }

        /**
         * 13. DDoS Source Detection
         * Identifies if the IP is a known source of DDoS attacks.
         * Returns 25 if identified, 0 otherwise.
         */
        private function checkDDoSSource(string $ipAddress, PDO $pdo): int
        {
            $this->console_debug('checkDDoSSource START', $ipAddress);

            if ($ipAddress === 'unknown') {
                $this->console_debug('checkDDoSSource SKIP', 'IP is "unknown".');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkDDoSSource ERROR', 'Invalid IP format.');
                return 0;
            }

            // Query the ddos_sources table
            $sql = "
                SELECT COUNT(*) AS match_count
                FROM ddos_sources
                WHERE ip_address = :ip
                LIMIT 1
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['ip' => $ipAddress]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $matchCount = (int)($row['match_count'] ?? 0);
            $this->console_debug('checkDDoSSource MATCH_COUNT', $matchCount);

            if ($matchCount > 0) {
                $this->console_debug('checkDDoSSource MATCH', 'IP is a known DDoS source.');
                return 25;
            }

            $this->console_debug('checkDDoSSource NO MATCH', 'IP is not a known DDoS source.');
            return 0;
        }

        /**
         * 14. IP Geolocation Consistency Check
         * Ensures the IP's geolocation aligns with user data or other contextual information.
         * Returns 15 if inconsistent, 0 otherwise.
         */
        private function checkIPGeolocationConsistency(string $ipAddress, string $username, PDO $pdo): int
        {
            $this->console_debug('checkIPGeolocationConsistency START', [
                'ipAddress' => $ipAddress,
                'username'  => $username
            ]);

            if ($ipAddress === 'unknown' || empty($username)) {
                $this->console_debug('checkIPGeolocationConsistency SKIP', 'Missing IP or username.');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkIPGeolocationConsistency ERROR', 'Invalid IP format.');
                return 0;
            }

            // Example: Compare IP's country with user's profile country
            $userCountry = $this->getUserCountry($username, $pdo);
            $ipCountry = $this->getCountryFromIP($ipAddress, $pdo);

            $this->console_debug('checkIPGeolocationConsistency DATA', [
                'userCountry' => $userCountry,
                'ipCountry'   => $ipCountry
            ]);

            if ($userCountry && $ipCountry && $userCountry !== $ipCountry) {
                $this->console_debug('checkIPGeolocationConsistency MATCH', 'IP geolocation does not match user profile.');
                return 15;
            }

            $this->console_debug('checkIPGeolocationConsistency NO MATCH', 'IP geolocation matches user profile.');
            return 0;
        }

        /**
         * Helper method to retrieve user's country from profile.
         * Implement based on your user data structure.
         */
        private function getUserCountry(string $username, PDO $pdo): ?string
        {
            $this->console_debug('getUserCountry START', $username);

            $sql = "
                SELECT country_code
                FROM auth_users
                WHERE email = :email
                LIMIT 1
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['email' => $username]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($row && !empty($row['country_code'])) {
                $this->console_debug('getUserCountry FOUND', $row['country_code']);
                return strtoupper($row['country_code']);
            }

            $this->console_debug('getUserCountry NOT FOUND', 'User country not available.');
            return null;
        }

        /**
         * 15. IP Entropy Analysis
         * Analyzes the randomness of the IP address to detect algorithmically generated IPs.
         * Returns 10 if high entropy detected, 0 otherwise.
         */
        private function checkIPEntropy(string $ipAddress): int
        {
            $this->console_debug('checkIPEntropy START', $ipAddress);

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkIPEntropy ERROR', 'Invalid IP format.');
                return 0;
            }

            // Simple entropy calculation for demonstration
            $octets = explode('.', $ipAddress);
            if (count($octets) !== 4) {
                $this->console_debug('checkIPEntropy ERROR', 'Unexpected IP format.');
                return 0;
            }

            $uniqueOctets = count(array_unique($octets));
            $entropy = ($uniqueOctets / 4) * 10; // Scale to 0-10

            $this->console_debug('checkIPEntropy RESULT', $entropy);

            return (int)$entropy;
        }

        /**
         * 16. Number of Associated Domains Check
         * Checks how many domains are associated with the IP.
         * Returns 10 if above threshold, 0 otherwise.
         */
        private function checkAssociatedDomains(string $ipAddress, PDO $pdo): int
        {
            $this->console_debug('checkAssociatedDomains START', $ipAddress);

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkAssociatedDomains ERROR', 'Invalid IP format.');
                return 0;
            }

            // Define a threshold for number of domains
            $threshold = 50; // Example threshold

            $sql = "
                SELECT COUNT(*) AS domain_count
                FROM domain_ip_mapping
                WHERE ip_address = :ip
                LIMIT 1
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['ip' => $ipAddress]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $domainCount = (int)($row['domain_count'] ?? 0);
            $this->console_debug('checkAssociatedDomains DOMAIN_COUNT', $domainCount);

            if ($domainCount > $threshold) {
                $this->console_debug('checkAssociatedDomains MATCH', 'IP has a high number of associated domains.');
                return 10;
            }

            $this->console_debug('checkAssociatedDomains NO MATCH', 'IP does not have a high number of associated domains.');
            return 0;
        }

        /**
         * 17. IP Rotation Detection
         * Detects if the user is rapidly changing IP addresses across login attempts.
         * Returns 20 if rotation detected, 0 otherwise.
         */
        private function checkIPRotation(string $ipAddress, string $username, PDO $pdo): int
        {
            $this->console_debug('checkIPRotation START', [
                'ipAddress' => $ipAddress,
                'username'  => $username
            ]);

            if ($ipAddress === 'unknown' || empty($username)) {
                $this->console_debug('checkIPRotation SKIP', 'Missing IP or username.');
                return 0;
            }

            // Define a timeframe and threshold
            $timeframe = '1 HOUR';
            $threshold = 3; // e.g., more than 3 different IPs in the last hour

            // Retrieve distinct IPs from the user's recent login attempts
            $sql = "
                SELECT COUNT(DISTINCT ip_address) AS unique_ip_count
                FROM auth_login_attempts
                WHERE email_entered = :email
                  AND attempted_at >= (NOW() - INTERVAL {$timeframe})
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['email' => $username]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $uniqueIPCount = (int)($row['unique_ip_count'] ?? 0);
            $this->console_debug('checkIPRotation UNIQUE_IP_COUNT', $uniqueIPCount);

            if ($uniqueIPCount > $threshold) {
                $this->console_debug('checkIPRotation MATCH', 'User is rapidly changing IP addresses.');
                return 20;
            }

            $this->console_debug('checkIPRotation NO MATCH', 'No rapid IP changes detected.');
            return 0;
        }

        /**
         * 18. Proxy Score Assessment
         * Assigns a score based on the likelihood of the IP being a proxy.
         * Returns a score (e.g., 0-10).
         */
        private function checkProxyScore(string $ipAddress, PDO $pdo): int
        {
            $this->console_debug('checkProxyScore START', $ipAddress);

            if ($ipAddress === 'unknown') {
                $this->console_debug('checkProxyScore SKIP', 'IP is "unknown".');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkProxyScore ERROR', 'Invalid IP format.');
                return 0;
            }

            // Query a proxy_score table or integrate with an external API
            $sql = "
                SELECT proxy_score 
                FROM ip_proxy_scores 
                WHERE ip_address = :ip
                LIMIT 1
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['ip' => $ipAddress]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $proxyScore = (int)($row['proxy_score'] ?? 0);
            $this->console_debug('checkProxyScore PROXY_SCORE', $proxyScore);

            // Define a threshold for assigning risk
            $threshold = 5; // Example threshold

            if ($proxyScore > $threshold) {
                $this->console_debug('checkProxyScore MATCH', 'IP is likely a proxy.');
                return $proxyScore; // Assign based on the score
            }

            $this->console_debug('checkProxyScore NO MATCH', 'IP is unlikely a proxy.');
            return 0;
        }

        /**
         * 19. Malicious IP Range Identification
         * Checks if the IP falls within a range known for malicious activities.
         * Returns 25 if identified, 0 otherwise.
         */
        private function checkMaliciousIPRange(string $ipAddress, PDO $pdo): int
        {
            $this->console_debug('checkMaliciousIPRange START', $ipAddress);

            if ($ipAddress === 'unknown') {
                $this->console_debug('checkMaliciousIPRange SKIP', 'IP is "unknown".');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkMaliciousIPRange ERROR', 'Invalid IP format.');
                return 0;
            }

            // Query the malicious_ip_ranges table
            $sql = "
                SELECT COUNT(*) AS match_count
                FROM malicious_ip_ranges
                WHERE INET_ATON(:ip) BETWEEN INET_ATON(ip_start) AND INET_ATON(ip_end)
                LIMIT 1
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['ip' => $ipAddress]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $matchCount = (int)($row['match_count'] ?? 0);
            $this->console_debug('checkMaliciousIPRange MATCH_COUNT', $matchCount);

            if ($matchCount > 0) {
                $this->console_debug('checkMaliciousIPRange MATCH', 'IP falls within a malicious IP range.');
                return 25;
            }

            $this->console_debug('checkMaliciousIPRange NO MATCH', 'IP does not fall within any malicious IP range.');
            return 0;
        }

        /**
         * 20. IP Change Frequency Monitoring
         * Monitors how frequently a user changes IP addresses across login attempts.
         * Returns 15 if frequency is high, 0 otherwise.
         */
        private function checkIPChangeFrequency(string $username, string $ipAddress, PDO $pdo): int
        {
            $this->console_debug('checkIPChangeFrequency START', [
                'username'  => $username,
                'ipAddress' => $ipAddress
            ]);

            if (empty($username) || $ipAddress === 'unknown') {
                $this->console_debug('checkIPChangeFrequency SKIP', 'Missing username or IP address.');
                return 0;
            }

            if (filter_var($ipAddress, FILTER_VALIDATE_IP) === false) {
                $this->console_debug('checkIPChangeFrequency ERROR', 'Invalid IP format.');
                return 0;
            }

            // Define timeframe and threshold
            $timeframe = '24 HOUR';
            $threshold = 3; // e.g., more than 3 different IPs in the last 24 hours

            // Retrieve distinct IPs from the user's recent login attempts
            $sql = "
                SELECT COUNT(DISTINCT ip_address) AS unique_ip_count
                FROM auth_login_attempts
                WHERE email_entered = :email
                  AND attempted_at >= (NOW() - INTERVAL {$timeframe})
            ";

            $stmt = $pdo->prepare($sql);
            $stmt->execute(['email' => $username]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            $uniqueIPCount = (int)($row['unique_ip_count'] ?? 0);
            $this->console_debug('checkIPChangeFrequency UNIQUE_IP_COUNT', $uniqueIPCount);

            if ($uniqueIPCount > $threshold) {
                $this->console_debug('checkIPChangeFrequency MATCH', 'User is frequently changing IP addresses.');
                return 15;
            }

            $this->console_debug('checkIPChangeFrequency NO MATCH', 'User is not frequently changing IP addresses.');
            return 0;
        }

        // -----------------------------------------------------------------------
        //                          END OF CHECK METHODS
        // -----------------------------------------------------------------------
    }

