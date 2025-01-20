<?php
namespace App\Services;

class DeviceFingerprintService
{
    /**
     * Logs debug info (similar to your console_debug).
     */
    private function debugLog($label, $value = null): void
    {
        // Example debug logger
        if (is_array($value) || is_object($value)) {
            $value = json_encode($value);
        }
        $date = date('Y-m-d H:i:s');
        $logFile = __DIR__ . '/DeviceFingerprintService.log';
        file_put_contents(
            $logFile,
            "[{$date}] [DEBUG] {$label}: {$value}\n",
            FILE_APPEND
        );
    }

    /**
     * Parse and hash the fingerprint data (from POST).
     * 
     * @param string $base64Fingerprint Base64-encoded JSON from the client
     * @return string A stable "fingerprint hash" (e.g. SHA-256)
     */
    public function createFingerprintHash(string $base64Fingerprint): string
    {
        $this->debugLog('createFingerprintHash() called', $base64Fingerprint);

        if (empty($base64Fingerprint)) {
            // Return some fallback
            return 'no_fingerprint';
        }

        // 1) Decode the base64
        $json = base64_decode($base64Fingerprint, true);
        if ($json === false) {
            $this->debugLog('base64_decode failed', $base64Fingerprint);
            return 'invalid_fingerprint';
        }

        // 2) Decode JSON to array
        $data = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->debugLog('json_decode failed', json_last_error_msg());
            return 'invalid_fingerprint';
        }

        // 3) Sort or otherwise normalize the data to ensure stable hashing
        //    (Ensures same keys in the same order => same hash for same device)
        ksort($data);

        // 4) Convert back to JSON for hashing
        $normalized = json_encode($data);

        // 5) Hash it (SHA-256, for example)
        $hash = hash('sha256', $normalized);

        $this->debugLog('Fingerprint hash generated', $hash);
        return $hash;
    }
    
    /**
     * Evaluate how "different" this new fingerprint is from the user's known device(s).
     * 
     * For example, if user typically logs in with userAgent X, screen Y,
     * but now it's drastically different, we might return a risk score or boolean.
     * 
     * In real usage, you'd compare partial matches or handle false positives.
     */
    public function compareFingerprintHashToKnown(
        int $userId,
        string $newFingerprintHash
    ): int {
        // For demonstration: fetch known fingerprints from your DB or a separate table
        // e.g. core_user_devices (user_id, device_fingerprint_hash, last_used_at, etc.)
        
        // Pseudocode:
        /*
        global $pdo;
        $sql = "SELECT device_fingerprint_hash FROM core_user_devices WHERE user_id = :uid";
        $stmt = $pdo->prepare($sql);
        $stmt->execute(['uid' => $userId]);
        $rows = $stmt->fetchAll(\PDO::FETCH_COLUMN);

        // If the newFingerprintHash is in $rows => recognized device => 0 risk
        // If not => new device => let's return +20 risk
        */
        
        // For this example, assume we have no matches => new device
        $isNewDevice = true;

        return $isNewDevice ? 20 : 0;  // add 20 risk if new device
    }

    /**
     * (Optional) If the login succeeds, we can store/update the new device fingerprint.
     * So next time, it's recognized.
     */
    public function storeFingerprintForUser(int $userId, string $fingerprintHash): void
    {
        // Check if fingerprintHash is already in DB for this user
        // If not, insert a new row in e.g. core_user_devices
        /*
        global $pdo;
        $sql = "SELECT count(*) FROM core_user_devices
                WHERE user_id = :uid AND device_fingerprint_hash = :hash";
        $stmt = $pdo->prepare($sql);
        $stmt->execute(['uid' => $userId, 'hash' => $fingerprintHash]);
        $count = $stmt->fetchColumn();

        if ($count == 0) {
            $insertSql = "INSERT INTO core_user_devices (user_id, device_fingerprint_hash, last_used_at)
                          VALUES (:uid, :hash, NOW())";
            $ins = $pdo->prepare($insertSql);
            $ins->execute(['uid'=>$userId, 'hash'=>$fingerprintHash]);
        } else {
            // Update last_used_at
            $updSql = "UPDATE core_user_devices SET last_used_at = NOW()
                       WHERE user_id=:uid AND device_fingerprint_hash=:hash";
            $upd = $pdo->prepare($updSql);
            $upd->execute(['uid'=>$userId, 'hash'=>$fingerprintHash]);
        }
        */
    }
}
