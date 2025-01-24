<?php
/**
 * /src/Views/LoginView.php
 *
 * Renders the Login page with dynamic theming from core_tenants + core_tenant_branding.
 *
 * - We do NOT remove/omit any existing logic (IP detection, disclaimers, etc.).
 * - We automatically transform certain DB values (like "blue-500") into Tailwind classes ("bg-blue-500").
 * - If we detect a hex code (#...), we apply it inline via style.
 *
 * New:
 * - Instead of showing (visibly) the device info table, we now hide it with CSS (but do NOT remove it).
 * - We add hidden inputs for every field to send all device info to the Auth controller.
 * - No changes to design, text, or structure are removed or omitted.
 * - Minor refactoring to keep everything clean and fully functional.
 */

global $pdo;

// 1) Which tenant?
$tenant = $_GET['tenant'] ?? 'default';

// 2) Load tenant + branding columns
$sql = "
    SELECT
        t.tenant_name AS display_name,
        b.logo_url,
        b.favicon_url,
        b.background_image_url,
        b.theme_name,

        b.primary_color,
        b.secondary_color,
        b.accent_color,
        b.background_color,
        b.text_color,
        b.heading_color,
        b.link_color,
        b.link_hover_color,
        b.primary_color,
        b.button_primary_text_color,
        b.button_secondary_color,
        b.button_secondary_text_color,
        b.border_color,
        b.success_color,
        b.warning_color,
        b.danger_color,
        b.info_color,
        b.font_family_heading,
        b.font_family_body,
        b.is_active
    FROM core_tenants t
    LEFT JOIN core_tenant_branding b
        ON t.tenant_id = b.tenant_id
       AND b.is_active = 1
    WHERE t.tenant_slug = :slug
    LIMIT 1
";

$stmt = $pdo->prepare($sql);
$stmt->execute(['slug' => $tenant]);
$row = $stmt->fetch(\PDO::FETCH_ASSOC);

// 3) Build $branding or fallback
if ($row) {
    $branding = [
        'display_name' => $row['display_name']             ?? 'Taskvera',
        'logo'         => $row['logo_url']                 ?? '/images/default-logo.png',
        'favicon'      => $row['favicon_url']              ?? '',
        'bg_image'     => $row['background_image_url']     ?? '',

        // Colors
        'primary_color'              => $row['primary_color']              ?? '',
        'background_color'           => $row['background_color']           ?? '',
        'text_color'                 => $row['text_color']                 ?? '',
        'button_primary_text_color'  => $row['button_primary_text_color']  ?? '',

        // Extra columns (used for modal & advanced styling)
        'secondary_color'            => $row['secondary_color']            ?? '',
        'accent_color'               => $row['accent_color']               ?? '',
        'heading_color'              => $row['heading_color']              ?? '',
        'link_color'                 => $row['link_color']                 ?? '',
        'link_hover_color'           => $row['link_hover_color']           ?? '',
        'button_secondary_color'     => $row['button_secondary_color']     ?? '',
        'button_secondary_text_color'=> $row['button_secondary_text_color']?? '',
        'border_color'               => $row['border_color']               ?? '',
        'success_color'              => $row['success_color']              ?? '',
        'warning_color'              => $row['warning_color']              ?? '',
        'danger_color'               => $row['danger_color']               ?? '',
        'info_color'                 => $row['info_color']                 ?? '',

        // Fonts
        'font_family_heading' => $row['font_family_heading'] ?? '',
        'font_family_body'    => $row['font_family_body']    ?? '',
    ];
} else {
    // fallback
    $branding = [
        'display_name' => 'Taskvera',
        'logo'         => '/images/default-logo.png',
        'favicon'      => '',
        'bg_image'     => '',

        'primary_color' => 'blue-500',
        'background_color' => 'gray-100',
        'text_color' => 'gray-800',
        'button_primary_text_color' => '#FFFFFF',

        'secondary_color'=> '',
        'accent_color'   => '',
        'heading_color'  => '',
        'link_color'     => '',
        'link_hover_color'=> '',
        'button_secondary_color' => '',
        'button_secondary_text_color' => '',
        'border_color' => '',
        'success_color' => '',
        'warning_color' => '',
        'danger_color' => '',
        'info_color' => '',

        'font_family_heading' => '',
        'font_family_body' => '',
    ];
}

/**
 * Convert a color value to either a Tailwind class or inline style.
 * e.g. "blue-500" => class="bg-blue-500"
 *      "#FF0000" => style="background-color: #FF0000"
 */
function handleColorValue(string $val, string $prefix = 'bg-', string $fallbackClass = 'bg-blue-500'): array
{
    $val = trim($val);
    // 1) If empty => use fallback class
    if ($val === '') {
        return ['class' => $fallbackClass, 'style' => ''];
    }
    // 2) If it's a raw color code (#hex, rgb(...), etc.), use inline style
    if (preg_match('/^(#|rgb\\(|hsl\\()/i', $val)) {
        $cssProp = ($prefix === 'bg-') ? 'background-color' : 'color';
        return ['class' => '', 'style' => "$cssProp: $val;"];
    }
    // 3) If user provided a complete Tailwind class (bg-red-500, text-blue-700, etc.)
    if (preg_match('/^(bg-|text-|border-|hover:|focus:|active:|[\w-]+-[0-9]{1,3})/i', $val)) {
        // If it explicitly starts with "bg-", "text-", "border-", etc., use it as is:
        if (preg_match('/^(bg-|text-|border-|hover:|focus:|active:)/', $val)) {
            return ['class' => $val, 'style' => ''];
        } else {
            // e.g. "blue-500" => "bg-blue-500"
            return ['class' => $prefix.$val, 'style' => ''];
        }
    }
    // 4) Fallback: prefix + val
    return ['class' => $prefix.$val, 'style' => ''];
}

/** Simple text-color or inline style version. */
function tailwindTextClassOrStyle(string $val, string $fallback='text-gray-800'): array
{
    return handleColorValue($val, 'text-', $fallback);
}

// For the modal’s dynamic tab underline color, we need an actual color code if the user sets a hex.
function rawColorOrFallback(string $val, string $default = '#2fa74c'): string
{
    $val = trim($val);
    if (!$val) {
        return $default; // fallback
    }
    // if it starts with # or rgb( or hsl(, it’s a raw color => pass it
    if (preg_match('/^(#|rgb\\(|hsl\\()/i', $val)) {
        return $val;
    }
    // otherwise assume Tailwind => fallback
    return $default;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title><?= htmlspecialchars($branding['display_name']) ?> - Login (Mobile)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
  
  <?php if (!empty($branding['favicon'])): ?>
    <link rel="icon" href="<?= htmlspecialchars($branding['favicon']) ?>" />
  <?php endif; ?>

  <!-- Tailwind CSS (CDN) -->
  <script src="https://cdn.tailwindcss.com"></script>
  <!-- Font Awesome (CDN) -->
  <link
    rel="stylesheet"
    href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css"
  />

  <?php
    // Inline dynamic styles for heading/body fonts
    $headingFont = $branding['font_family_heading'] ?: 'inherit';
    $bodyFont    = $branding['font_family_body']    ?: 'inherit';

    // For active tab border color, default to #2fa74c if no brand primary color is suitable
    $tabActiveColor = rawColorOrFallback($branding['primary_color'] ?? '', '#2fa74c');

    // For the modal background (fallback = "bg-white")
    $modalBg        = handleColorValue($branding['background_color'] ?? '', 'bg-', 'bg-white');

    // Icon in header uses primary color
    $modalHeaderIconColor = handleColorValue($branding['primary_color'] ?? 'blue-500', 'text-', 'text-blue-500');

    // For the links inside the modal:
    $modalLinkColor = handleColorValue($branding['primary_color'] ?? 'blue-600', 'text-', 'text-blue-600');

    // For the "Send Reset Link" button
    $modalBtnBg   = handleColorValue($branding['primary_color'] ?? 'green-600', 'bg-', 'bg-green-600');
    $modalBtnText = handleColorValue($branding['button_secondary_text_color'] ?? '#FFFFFF', 'text-', 'text-white');
  ?>

  <style>
    body {
      font-family: <?= $bodyFont ?>, sans-serif;
    }
    h1, h2, h3, .heading-font {
      font-family: <?= $headingFont ?>, sans-serif;
    }

    /* Use a CSS variable for active tab color underline */
    :root {
      --tab-active-color: <?= $tabActiveColor ?>;
    }

    /* Tab styling: text black, icons brand color, underline brand color on active */
    .tab-button {
      @apply px-3 py-2 text-xs font-semibold text-black flex items-center space-x-1;
      transition: color 0.2s;
    }
    .tab-button i {
      color: var(--tab-active-color);
      font-size: 1.25rem; /* bigger icon */
    }
    .tab-button.active {
      border-bottom-width: 2px;
      border-color: var(--tab-active-color);
    }

    /* Hide all tab contents by default */
    .tab-content {
      display: none;
    }
    .tab-content.active {
      display: block;
    }

    /* HIDE the table of device info, but do NOT remove it. */
    .client-info {
      display: none;
    }
  </style>

  <script>
  document.addEventListener("DOMContentLoaded", () => {
    // 1. Footer year
    const yearEl = document.getElementById('year');
    if (yearEl) {
      yearEl.textContent = new Date().getFullYear();
    }

    // 2. IP fetch
    fetch('https://api4.ipify.org?format=json')
      .then(r => r.json())
      .then(data => {
        const ipEl = document.getElementById('ipAddress');
        if (ipEl) ipEl.textContent = data.ip || 'N/A';
        const clientIpField = document.getElementById('client_ip');
        if (clientIpField) {
          clientIpField.value = data.ip || '';
        }
        // 3. Next, fetch location + ISP
        return fetch(`https://ipapi.co/${data.ip}/json/`);
      })
      .then(r => r.json())
      .then(ipapi => {
        const locEl = document.getElementById('userLocation');
        if (locEl) {
          locEl.textContent = `${ipapi.city}, ${ipapi.country_name}`;
        }
        const ispEl = document.getElementById('userISP');
        if (ispEl) {
          ispEl.textContent = ipapi.org || 'N/A';
        }
        // store ISO country code
        const countryField = document.getElementById('client_country');
        if (countryField) {
          countryField.value = ipapi.country_code || '';
        }
      })
      .catch(err => {
        console.error('Failed to fetch IP info:', err);
        const ipEl = document.getElementById('ipAddress');
        if (ipEl) ipEl.textContent = 'Unavailable';
        const locEl = document.getElementById('userLocation');
        if (locEl) locEl.textContent = 'Unknown';
        const ispEl = document.getElementById('userISP');
        if (ispEl) ispEl.textContent = 'Unknown';
      });
  });
  </script>
</head>

<?php
// Body background or image
$bg = handleColorValue($branding['background_color'] ?? 'gray-100', 'bg-', 'bg-gray-100');
$bodyClass = "select-none overflow-y-hidden min-h-screen w-screen overflow-x-hidden relative {$bg['class']}";
$bodyStyle = $bg['style'];

// If there's a background image
if (!empty($branding['bg_image'])) {
    $bodyStyle .= " background-image: url('{$branding['bg_image']}'); background-size: cover;";
}
?>

<body class="<?= htmlspecialchars($bodyClass) ?>"
      style="<?= htmlspecialchars($bodyStyle) ?>">

  <!-- HEADER -->
  <header class="fixed top-0 left-0 right-0 z-50 bg-white shadow flex items-center justify-between px-4 py-2">
    <!-- Branding -->
    <div class="flex items-center space-x-3">
      <?php if (!empty($branding['logo'])): ?>
        <img src="<?= htmlspecialchars($branding['logo']) ?>" alt="Tenant Logo" class="h-8 w-auto"/>
      <?php else: ?>
        <i class="fas fa-leaf text-green-600 text-2xl"></i>
      <?php endif; ?>

      <h1 class="heading-font"><?= htmlspecialchars($branding['display_name']) ?></h1>
      <?php
        // environment badge unchanged
        $appEnv = $_ENV['APP_ENV'] ?? 'production';
        $badgeColor = '';
        $badgeLabel = '';

        switch ($appEnv) {
            case 'development':
                $badgeColor = 'bg-red-500';
                $badgeLabel = 'DEVELOPMENT';
                break;
            case 'staging':
                $badgeColor = 'bg-yellow-500';
                $badgeLabel = 'STAGING';
                break;
            case 'training':
                $badgeColor = 'bg-blue-500';
                $badgeLabel = 'TRAINING';
                break;
        }

        if ($badgeColor):
      ?>
      <span class="<?= $badgeColor ?> text-white text-xs font-bold py-1 px-2 rounded-full">
        <?= $badgeLabel ?>
      </span>
      <?php endif; ?>
    </div>

    <!-- Lang Select -->
    <div>
      <select class="text-sm border border-gray-300 rounded px-2 py-1" aria-label="Language Selector">
        <option value="en" selected>English</option>
        <option value="es">Español</option>
        <option value="fr">Français</option>
      </select>
    </div>
  </header>

  <!-- MAIN CONTAINER -->
  <div class="
        mx-auto
        max-w-sm w-11/12
        bg-white
        rounded-lg
        shadow
        p-4
        max-h-[90vh]
        fixed
        top-1/2
        left-1/2
        transform
        -translate-x-1/2
        -translate-y-1/2
        z-10
      "
      style="margin-top:0; margin-bottom:0; overflow:hidden;"
  >
    <h1 class="text-xl font-bold text-center mb-3 heading-font">
      Secure Login
    </h1>
    <p class="text-center text-sm text-gray-600 mb-4">
      Please enter your credentials to access your account.
    </p>

    <?php
    // Display error
    $error = $_GET['error'] ?? '';
    if ($error) {
        $safeError = htmlspecialchars($error, ENT_QUOTES, 'UTF-8');
        echo <<<HTML
        <div class="relative bg-red-100 text-red-700 text-sm border-l-8 border-red-500 px-3 py-2 pr-7 rounded shadow-sm mb-4" role="alert">
          <strong class="font-bold">Login Failed!</strong>
          <span class="ml-1">{$safeError}</span>
          <button class="absolute top-0 bottom-0 right-0 px-3 text-red-700 hover:text-red-900" onclick="this.parentElement.remove()" aria-label="Close">&times;</button>
        </div>
HTML;
    }
    ?>

<?php
// Example: we retrieve them from the DB:
$iconValue      = $branding['icon_color']        ?? 'text-gray-500';
$linkValue      = $branding['link_color']        ?? 'text-green-600';
$inputFocusVal  = $branding['input_focus_color'] ?? 'ring-blue-500';

// Transform them
$iconColor   = handleColorValue($iconValue, 'text-', 'text-gray-500');
$linkColor   = handleColorValue($linkValue, 'text-', 'text-green-600');
$inputFocus  = handleColorValue($inputFocusVal, 'ring-', 'ring-blue-500');
?>

<!-- Login Form -->
<form action="/login" method="POST" autocomplete="on" class="flex flex-col space-y-4">

  <!-- Email/Username Field -->
  <label for="username" class="text-sm font-medium">Email or Username</label>
  <div class="flex items-center border border-gray-300 rounded">
    <!-- icon -->
    <i class="fas fa-user <?= htmlspecialchars($iconColor['class']) ?> mx-2"
       style="<?= htmlspecialchars($iconColor['style']) ?>"></i>
    <input
      type="text"
      name="username"
      id="username"
      class="flex-1 px-2 py-2 text-sm focus:outline-none focus:<?= htmlspecialchars($inputFocus['class']) ?>
             border-0"
      style="<?= htmlspecialchars($inputFocus['style']) ?>"
      placeholder="Enter your email or username"
      required
    />
  </div>

  <!-- Password Field -->
  <label for="password" class="text-sm font-medium">Password</label>
  <div class="flex items-center border border-gray-300 rounded">
    <i class="fas fa-lock <?= htmlspecialchars($iconColor['class']) ?> mx-2"
       style="<?= htmlspecialchars($iconColor['style']) ?>"></i>
    <input
      type="password"
      name="password"
      id="password"
      class="flex-1 px-2 py-2 text-sm focus:outline-none focus:<?= htmlspecialchars($inputFocus['class']) ?>"
      style="<?= htmlspecialchars($inputFocus['style']) ?>"
      placeholder="Enter your password"
      required
    />
    <button
      type="button"
      id="togglePassword"
      class="mx-2 focus:outline-none <?= htmlspecialchars($iconColor['class']) ?>"
      style="<?= htmlspecialchars($iconColor['style']) ?>"
      aria-label="Show or Hide Password"
    >
      <i class="fas fa-eye"></i>
    </button>
  </div>

  <!-- Remember + Trouble Link -->
  <div class="flex justify-between">
    <div class="flex items-center">
      <input
        type="checkbox"
        id="remember"
        name="remember"
        class="<?= htmlspecialchars($inputFocus['class']) ?> h-4 w-4 border-gray-300 rounded"
        style="<?= htmlspecialchars($inputFocus['style']) ?>"
      />
      <label for="remember" class="ml-2 text-sm text-gray-700">
        Remember Me
      </label>
    </div>

    <div class="text-right">
      <button
        type="button"
        id="openModalBtn"
        class="text-sm focus:outline-none
               <?= htmlspecialchars($linkColor['class']) ?> hover:opacity-80"
        style="<?= htmlspecialchars($linkColor['style']) ?>"
      >
        Trouble Logging In?
      </button>
    </div>
  </div>

  <!-- Hidden Tenant ID -->
  <input
    type="hidden"
    name="tenant_id"
    value="<?php echo htmlspecialchars($tenant); ?>"
  />

  <!-- Hidden field to store client IP from JavaScript -->
  <input
    type="hidden"
    name="client_ip"
    id="client_ip"
    value=""
  />
  <!-- Hidden field to store client ISP from JavaScript -->
  <input
    type="hidden"
    name="client_isp"
    id="client_isp"
    value=""
  />
  <!-- Hidden field to store client country -->
  <input
    type="hidden"
    name="client_country"
    id="client_country"
    value=""
  />

  <!--
    We add hidden fields for EVERY single device info field
    so it all gets sent to the auth controller.
  -->
  <input type="hidden" name="deviceType" id="deviceTypeField" />
  <input type="hidden" name="deviceModel" id="deviceModelField" />
  <input type="hidden" name="manufacturer" id="manufacturerField" />
  <input type="hidden" name="osName" id="osNameField" />
  <input type="hidden" name="osVersion" id="osVersionField" />
  <input type="hidden" name="osBuildNumber" id="osBuildNumberField" />
  <input type="hidden" name="osArchitecture" id="osArchitectureField" />
  <input type="hidden" name="browserName" id="browserNameField" />
  <input type="hidden" name="browserVersion" id="browserVersionField" />
  <input type="hidden" name="renderingEngine" id="renderingEngineField" />
  <input type="hidden" name="browserMode" id="browserModeField" />
  <input type="hidden" name="screenResolution" id="screenResolutionField" />
  <input type="hidden" name="pixelDensity" id="pixelDensityField" />
  <input type="hidden" name="viewportSize" id="viewportSizeField" />
  <input type="hidden" name="colorDepth" id="colorDepthField" />
  <input type="hidden" name="orientation" id="orientationField" />
  <input type="hidden" name="availableScreenSpace" id="availableScreenSpaceField" />
  <input type="hidden" name="cpuModel" id="cpuModelField" />
  <input type="hidden" name="cpuCores" id="cpuCoresField" />
  <input type="hidden" name="cpuClockSpeed" id="cpuClockSpeedField" />
  <input type="hidden" name="cpuArchitecture" id="cpuArchitectureField" />
  <input type="hidden" name="gpuModel" id="gpuModelField" />
  <input type="hidden" name="gpuVendor" id="gpuVendorField" />
  <input type="hidden" name="gpuMemory" id="gpuMemoryField" />
  <input type="hidden" name="totalMemory" id="totalMemoryField" />
  <input type="hidden" name="availableMemory" id="availableMemoryField" />
  <input type="hidden" name="totalDiskSpace" id="totalDiskSpaceField" />
  <input type="hidden" name="availableDiskSpace" id="availableDiskSpaceField" />
  <input type="hidden" name="storageType" id="storageTypeField" />
  <input type="hidden" name="batteryLevel" id="batteryLevelField" />
  <input type="hidden" name="batteryCharging" id="batteryChargingField" />
  <input type="hidden" name="batteryHealth" id="batteryHealthField" />
  <input type="hidden" name="touchSupport" id="touchSupportField" />
  <input type="hidden" name="touchPoints" id="touchPointsField" />
  <input type="hidden" name="pointerType" id="pointerTypeField" />
  <input type="hidden" name="cameraAvailability" id="cameraAvailabilityField" />
  <input type="hidden" name="cameraResolutions" id="cameraResolutionsField" />
  <input type="hidden" name="microphoneAvailability" id="microphoneAvailabilityField" />
  <input type="hidden" name="microphoneQuality" id="microphoneQualityField" />
  <input type="hidden" name="biometricCapabilities" id="biometricCapabilitiesField" />
  <input type="hidden" name="installedPlugins" id="installedPluginsField" />
  <input type="hidden" name="browserExtensions" id="browserExtensionsField" />
  <input type="hidden" name="installedApplications" id="installedApplicationsField" />
  <input type="hidden" name="installedApplicationsVersions" id="installedApplicationsVersionsField" />
  <input type="hidden" name="languageSettings" id="languageSettingsField" />
  <input type="hidden" name="localeInformation" id="localeInformationField" />
  <input type="hidden" name="numberFormats" id="numberFormatsField" />
  <input type="hidden" name="dateTimeFormats" id="dateTimeFormatsField" />
  <input type="hidden" name="timeZone" id="timeZoneField" />
  <input type="hidden" name="cpuUsage" id="cpuUsageField" />
  <input type="hidden" name="memoryUsage" id="memoryUsageField" />
  <input type="hidden" name="batteryUsage" id="batteryUsageField" />
  <input type="hidden" name="networkSpeed" id="networkSpeedField" />
  <input type="hidden" name="renderingFPS" id="renderingFPSField" />
  <input type="hidden" name="timeToInteractive" id="timeToInteractiveField" />
  <input type="hidden" name="ttfb" id="ttfbField" />
  <input type="hidden" name="resourceLoadTimes" id="resourceLoadTimesField" />
  <input type="hidden" name="secureBootStatus" id="secureBootStatusField" />
  <input type="hidden" name="antivirusPresence" id="antivirusPresenceField" />
  <input type="hidden" name="firewallStatus" id="firewallStatusField" />
  <input type="hidden" name="encryptionStatus" id="encryptionStatusField" />
  <input type="hidden" name="osPatchLevel" id="osPatchLevelField" />
  <input type="hidden" name="ipAddress" id="ipAddressField" />
  <input type="hidden" name="location" id="locationField" />
  <input type="hidden" name="isp" id="ispField" />
  <input type="hidden" name="latitude" id="latitudeField" />
  <input type="hidden" name="longitude" id="longitudeField" />

  <?php
    // Transform for the main login button
    $btnBg   = handleColorValue($branding['primary_color'] ?? '', 'bg-', 'bg-blue-500');
    $btnText = handleColorValue($branding['button_primary_text_color'] ?? '', 'text-', 'text-white');

    $buttonClass = trim($btnBg['class'].' '.$btnText['class'].' py-2 rounded font-semibold text-sm hover:opacity-90');
    $buttonStyle = $btnBg['style'].$btnText['style'];
  ?>
  <button
    type="submit"
    class="<?= htmlspecialchars($buttonClass) ?>"
    style="<?= htmlspecialchars($buttonStyle) ?>"
  >
    <i class="fas fa-sign-in-alt mr-2"></i>Login
  </button>

</form>


    <div class="text-xs text-gray-600 mt-4 leading-relaxed">
      <strong>Warning:</strong> This system is for authorized use only.
      Unauthorized or improper use of this system may result in administrative
      or legal action. By logging in, you consent to the recording and monitoring
      of all activities. We track your <em>IP address, device details</em>, and
      other session data for security and compliance.
    </div>

    <footer class="flex justify-between text-xs text-gray-500 mt-4 pt-2 border-t">
      <span>Location: <span id="userLocation">Loading...</span></span>
      <span>IP: <span id="ipAddress">Loading...</span></span>
      <span>ISP: <span id="userISP">Loading...</span></span>
    </footer>
  </div>

  <!-- FIXED FOOTER -->
  <footer class="fixed bottom-0 left-0 right-0 z-50 bg-white text-center text-xs text-gray-500 py-2">
    &copy; <span id="year"></span> <?= htmlspecialchars($branding['display_name']) ?>. All rights reserved.
  </footer>

<!-- Trouble Logging In Modal -->
<?php
$modalBgClass  = $modalBg['class'] ?: 'bg-white';
$modalBgStyle  = $modalBg['style'];

$modalIconClass = $modalHeaderIconColor['class'];
$modalIconStyle = $modalHeaderIconColor['style'];

$modalLinkClass  = $modalLinkColor['class'];
$modalLinkStyle  = $modalLinkColor['style'];

$modalButtonClass  = trim($modalBtnBg['class'].' '.$modalBtnText['class'].' w-full py-2 rounded font-semibold transition');
$modalButtonStyle  = $modalBtnBg['style'].$modalBtnText['style'];
?>
<div
    id="troubleModal"
    class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50"
    aria-hidden="true"
  >
  <div
    class="<?= htmlspecialchars($modalBgClass) ?> rounded-lg w-11/12 max-w-md p-4 relative"
    style="max-height: 90vh; overflow-y: auto; <?= htmlspecialchars($modalBgStyle) ?>"
  >
    <!-- Close Button -->
    <button
      id="closeModalBtn"
      class="absolute top-2 right-2 text-gray-400 hover:text-gray-600 focus:outline-none"
      aria-label="Close Modal"
    >
      <i class="fas fa-times"></i>
    </button>

    <!-- Modal Heading: black text, icon uses brand primary color -->
    <h2 class="text-lg font-semibold text-black mb-1 flex items-center space-x-2">
      <i 
        class="fas fa-life-ring <?= htmlspecialchars($modalIconClass) ?>"
        style="<?= htmlspecialchars($modalIconStyle) ?>; font-size:1.25rem;"
      ></i>
      <span>Having Trouble Logging In?</span>
    </h2>

    <p class="text-sm text-black mb-4">
      Use the tabs below to find help.
    </p>

    <!-- Tabs Navigation -->
    <div class="border-b border-gray-200 flex items-center space-x-4 mb-4">
      <button
        class="tab-button"
        data-target="#tab-reset"
      >
        <i class="fas fa-key"></i><span>Reset Password</span>
      </button>
      <button
        class="tab-button"
        data-target="#tab-contact"
      >
        <i class="fas fa-headset"></i><span>Contact Support</span>
      </button>
      <button
        class="tab-button"
        data-target="#tab-issues"
      >
        <i class="fas fa-exclamation-circle"></i><span>Common Issues</span>
      </button>
    </div>

    <!-- Tab Contents -->
    <div id="tab-reset" class="tab-content">
      <h3 class="text-base font-semibold text-black mb-2">
        Reset Your Password
      </h3>
      <p class="text-sm text-black mb-2">
        If you forgot your password, please enter your email below and click “Send Reset Link.”
      </p>
      <form id="reset-password-form" class="space-y-3">
        <div>
          <label for="reset-email" class="block text-sm font-medium text-black mb-1">
            Email Address
          </label>
          <input
            type="email"
            id="reset-email"
            class="w-full border rounded px-3 py-2 focus:outline-none focus:ring focus:ring-green-200"
            placeholder="your@example.com"
            required
          />
        </div>
        <button
          type="submit"
          class="<?= htmlspecialchars($modalButtonClass) ?>"
          style="<?= htmlspecialchars($modalButtonStyle) ?>"
        >
          Send Reset Link
        </button>
      </form>
    </div>

    <div id="tab-contact" class="tab-content">
      <h3 class="text-base font-semibold text-black mb-2">
        Contact Support
      </h3>
      <p class="text-sm text-black mb-2">
        If you’re still having trouble, contact our support team directly:
      </p>
      <ul class="list-disc list-inside text-sm text-black space-y-2">
        <li>
          Email us at
          <a
            href="mailto:support@example.com"
            class="<?= htmlspecialchars($modalLinkClass) ?> underline"
            style="<?= htmlspecialchars($modalLinkStyle) ?>"
          >
            support@example.com
          </a>
        </li>
        <li>Call <strong>1-800-123-4567</strong> (toll-free)</li>
        <li>Chat with us on our 
          <a
            href="#"
            class="<?= htmlspecialchars($modalLinkClass) ?> underline"
            style="<?= htmlspecialchars($modalLinkStyle) ?>"
          >
            Help Portal
          </a>
        </li>
      </ul>
    </div>

    <div id="tab-issues" class="tab-content">
      <h3 class="text-base font-semibold text-black mb-2">
        Common Issues &amp; Solutions
      </h3>
      <ul class="list-disc list-inside text-sm text-black space-y-2 mb-3">
        <li>Make sure your internet connection is stable.</li>
        <li>Confirm you have the correct email or username.</li>
        <li>Ensure you haven’t been blocked by a tenant-level IP policy.</li>
        <li>Check if your browser is updated and cookies are enabled.</li>
      </ul>
      <p class="text-xs text-gray-400">
        Tip: You can always close this modal by pressing the <strong>X</strong> button or clicking outside it.
      </p>
    </div>

  </div>
</div>

<!-- Script for toggling password, modal tabs, etc. (kept as-is) -->
<script>
  document.addEventListener("DOMContentLoaded", () => {
    // Toggle password
    const toggleBtn = document.getElementById('togglePassword');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        const pwdField = document.getElementById('password');
        if (!pwdField) return;
        pwdField.type = (pwdField.type === 'password') ? 'text' : 'password';
      });
    }

    const openModalBtn  = document.getElementById('openModalBtn');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const troubleModal  = document.getElementById('troubleModal');
    const tabButtons    = document.querySelectorAll('.tab-button');
    const tabContents   = document.querySelectorAll('.tab-content');

    // Open modal, default to first tab
    openModalBtn?.addEventListener('click', () => {
      troubleModal.classList.remove('hidden');
      openTab('#tab-reset');
    });

    closeModalBtn?.addEventListener('click', () => {
      troubleModal.classList.add('hidden');
    });

    // Close modal if clicking outside content
    troubleModal?.addEventListener('click', (e) => {
      if (e.target === troubleModal) {
        troubleModal.classList.add('hidden');
      }
    });

    // Switch tabs
    function openTab(targetId) {
      tabContents.forEach((tc) => tc.classList.remove('active'));
      tabButtons.forEach((btn) => btn.classList.remove('active'));

      const targetContent = document.querySelector(targetId);
      if (targetContent) {
        targetContent.classList.add('active');
      }
      const matchingButton = document.querySelector(`.tab-button[data-target="${targetId}"]`);
      if (matchingButton) {
        matchingButton.classList.add('active');
      }
    }

    tabButtons.forEach((btn) => {
      btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-target');
        openTab(target);
      });
    });

    // Demo password reset form
    const resetPasswordForm = document.getElementById('reset-password-form');
    if (resetPasswordForm) {
      resetPasswordForm.addEventListener('submit', (e) => {
        e.preventDefault();
        alert('Password reset link requested (demo only)!');
      });
    }
  });
</script>

<!-- Now load external DeviceSecurity.js and populate the hidden fields -->
<script src="/js/DeviceSecurity.js"></script>
<script>
  document.addEventListener("DOMContentLoaded", () => {
    // This function in DeviceSecurity.js will fill in all hidden fields
    // (Replace `logDeviceSecurityInfo` with whatever your function is named.)
    if (typeof populateClientInfo === 'function') {
      populateClientInfo();
    }
  });
</script>

</body>
</html>
