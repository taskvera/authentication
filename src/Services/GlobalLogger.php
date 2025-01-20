<?php

if (!function_exists('console_debug')) {
    /**
     * Writes debug info to a log file named after the *calling* .php file
     * (e.g. "DeviceFingerprintService.php" -> "DeviceFingerprintService.log")
     * in the same directory as the caller. Logs only if APP_ENV=development.
     *
     * @param string $label A label for the log entry.
     * @param mixed  $value The data to log (string, array, object, etc.).
     * @param string|null $customLogName Optional override for the log filename.
     */
    function console_debug($label, $value = null, $customLogName = null)
    {
        // 1. Check environment
        if (getenv('APP_ENV') !== 'development') {
            return;
        }

        // 2. Figure out the file that called this function (the 'caller')
        $backtrace  = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 1);
        $callerFile = $backtrace[0]['file'] ?? __FILE__;  // fallback if missing
        $callerDir  = dirname($callerFile);

        // 3. If a custom log name isn't provided, base it on the caller's file name
        if (!$customLogName) {
            // e.g. "/var/www/html/DeviceFingerprintService.php" -> "DeviceFingerprintService"
            $callerBaseName = basename($callerFile, '.php');
            $customLogName  = $callerBaseName . '.log';
        }

        // 4. Construct the log file path in that same directory
        $logFilePath = $callerDir . DIRECTORY_SEPARATOR . $customLogName;

        // 5. Convert arrays/objects to JSON, handle null
        if (is_array($value) || is_object($value)) {
            $value = json_encode($value);
        } elseif ($value === null) {
            $value = '';
        }

        // 6. Prepare a timestamped log entry
        $date = date('Y-m-d H:i:s');
        $logEntry = "[{$date}] [DEBUG] {$label}: {$value}\n";

        // 7. Append the log entry
        file_put_contents($logFilePath, $logEntry, FILE_APPEND);
    }
}
