<?php

namespace App\Services;

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\BrowserConsoleHandler;

/**
 * Class GlobalAuthLogger
 * 
 * Responsible for providing a centralized logger that
 * is configured differently for development vs. production.
 */
class GlobalAuthLogger
{
    /**
     * @var Logger
     */
    private Logger $logger;
    
    /**
     * GlobalAuthLogger constructor.
     * 
     * @param string $environment  The current application environment (e.g. 'development' or 'production').
     * @param string|null $devLogPath  Path to development log file (optional if not needed).
     * @param string|null $prodLogPath Path to production log file (optional if not needed).
     * 
     * @return void
     */
    public function __construct(
        string $environment,
        ?string $devLogPath = null,
        ?string $prodLogPath = null
    ) {
        /**
         * START: constructor initialization
         */
        
        // Create a new Monolog logger instance
        $this->logger = new Logger('global_auth_logger');
        
        // Decide how to configure the logger based on environment
        if ($environment === 'development') {
            /**
             * DEVELOPMENT ENVIRONMENT CONFIG
             *
             * - StreamHandler => typically writes to a local file
             * - BrowserConsoleHandler => convenient for debugging in browser dev tools console
             * - More verbose logging, e.g. DEBUG or INFO level
             */

            // Use dev log path, or fallback to a default
            $devLogPath = $devLogPath ?? __DIR__ . '/../../logs/development.log';

            // 1) StreamHandler => log to file with DEBUG level
            $streamHandler = new StreamHandler($devLogPath, Logger::DEBUG);

            // Optionally, add a more detailed formatter
            $lineFormatter = new LineFormatter(
                "[%datetime%] %channel%.%level_name%: %message% %context% %extra%\n",
                "Y-m-d H:i:s",
                true, // allow inline line breaks
                true  // ignore empty context and extra
            );
            $streamHandler->setFormatter($lineFormatter);

            $this->logger->pushHandler($streamHandler);

            // 2) BrowserConsoleHandler => log messages to browser dev console
            $browserConsoleHandler = new BrowserConsoleHandler(Logger::DEBUG);
            $this->logger->pushHandler($browserConsoleHandler);

        } else {
            /**
             * PRODUCTION ENVIRONMENT CONFIG
             *
             * - Typically write logs to a secure location not publicly accessible
             * - Possibly rotate logs to prevent huge log files (RotatingFileHandler)
             * - Higher minimum logging level, e.g. WARNING or ERROR
             */

            // Use prod log path, or fallback to a default
            $prodLogPath = $prodLogPath ?? __DIR__ . '/../../logs/production.log';

            // RotatingFileHandler => keep logs separate by date, limit number of files
            $rotatingHandler = new RotatingFileHandler(
                $prodLogPath,    // filename
                30,              // max number of log files to keep
                Logger::WARNING  // minimum logging level
            );

            // Optionally, a different log format for production
            $prodFormatter = new LineFormatter(
                "[%datetime%] %level_name%: %message% %context%\n",
                "Y-m-d H:i:s",
                true,
                true
            );
            $rotatingHandler->setFormatter($prodFormatter);

            $this->logger->pushHandler($rotatingHandler);
        }

        /**
         * END: constructor initialization
         */
    }

    /**
     * logInfo
     * 
     * Logs an informational message.
     * 
     * @param string $message The log message
     * @param array $context Additional context array
     * 
     * @return void
     */
    public function logInfo(string $message, array $context = []): void
    {
        $this->logger->info($message, $context);
    }

    /**
     * logWarning
     * 
     * Logs a warning message.
     * 
     * @param string $message The log message
     * @param array $context Additional context
     * 
     * @return void
     */
    public function logWarning(string $message, array $context = []): void
    {
        $this->logger->warning($message, $context);
    }

    /**
     * logError
     * 
     * Logs an error message.
     * 
     * @param string $message The log message
     * @param array $context Additional context
     * 
     * @return void
     */
    public function logError(string $message, array $context = []): void
    {
        $this->logger->error($message, $context);
    }

    /**
     * getLogger
     * 
     * Returns the underlying Monolog logger instance,
     * allowing you to add additional handlers, processors, etc.
     * 
     * @return Logger
     */
    public function getLogger(): Logger
    {
        return $this->logger;
    }
}
