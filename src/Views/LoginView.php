<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Amazing Blades Landscaping - Login (Mobile)</title>

  <!-- Mobile-first meta tag -->
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"
  />

  <!-- Tailwind CSS (CDN) -->
  <script src="https://cdn.tailwindcss.com"></script>
  <!-- Font Awesome (CDN) -->
  <link
    rel="stylesheet"
    href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css"
  />
  <script>
    document.addEventListener("DOMContentLoaded", () => {
      // 1. Update current year in the footer
      const yearEl = document.getElementById('year');
      if (yearEl) {
        yearEl.textContent = new Date().getFullYear();
      }

      // 2. First, fetch IPv4 address from ipify (IPv4-only endpoint)
      fetch('https://api4.ipify.org?format=json')
        .then(response => response.json())
        .then(ipifyData => {
          // Display the IPv4
          const ipEl = document.getElementById('ipAddress');
          if (ipEl) ipEl.textContent = ipifyData.ip || 'N/A';

          // 3. Next, use that IPv4 to fetch location & ISP from ipapi
          return fetch(`https://ipapi.co/${ipifyData.ip}/json/`);
        })
        .then(response => response.json())
        .then(ipapiData => {
          // Display Location
          const locEl = document.getElementById('userLocation');
          if (locEl) {
            locEl.textContent = `${ipapiData.city}, ${ipapiData.country_name}`;
          }

          // Display ISP
          const ispEl = document.getElementById('userISP');
          if (ispEl) {
            // ipapi.co returns ISP-like info in the 'org' field
            ispEl.textContent = ipapiData.org || 'N/A';
          }
        })
        .catch(error => {
          console.error('Failed to fetch IP/location/ISP data:', error);

          // Fallback text if any API call fails
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

<body class="select-none overflow-y-hidden bg-gray-100 text-gray-800 h-screen w-screen overflow-x-hidden relative">

  <!-- Fixed Header with Staging Pill and Language Selector -->
  <header class="fixed top-0 left-0 right-0 z-50 bg-white shadow flex items-center justify-between px-4 py-2">
    <!-- Branding / Logo -->
    <div class="flex items-center space-x-3">
      <!-- Updated to a green leaf icon -->
      <i class="fas fa-leaf text-green-600 text-2xl"></i>
      <h1>Amazing Blades</h1>
      <?php
        // Get the current app environment; default to 'production' if not set
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
            default:
                $badgeColor = '';
                break;
        }

        if ($badgeColor !== ''):
      ?>
      <span class="<?= $badgeColor ?> text-white text-xs font-bold py-1 px-2 rounded-full">
        <?= $badgeLabel ?>
      </span>
      <?php endif; ?>
    </div>

    <!-- Language Select -->
    <div>
      <select
        class="text-sm border border-gray-300 rounded px-2 py-1"
        aria-label="Language Selector"
      >
        <option value="en" selected>English</option>
        <option value="es">Español</option>
        <option value="fr">Français</option>
      </select>
    </div>
  </header>

  <!-- Main Container (Center-aligned, NO scrolling, DO NOT remove or omit any existing classes) -->
  <div
    class="
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
    <h1 class="text-xl font-bold text-center mb-3">
      Secure Login
    </h1>

    <p class="text-center text-sm text-gray-600 mb-4">
      Please enter your credentials to access your account.
    </p>

    <?php
      function get_isp_from_ip($ip) {
          // ip-api free endpoint
          $url = "http://ip-api.com/json/" . urlencode($ip);
          
          // Perform the request
          $json = @file_get_contents($url);
          if ($json === false) {
              return null;
          }

          // Decode the JSON response
          $data = json_decode($json, true);

          // Check if the query was successful
          if (isset($data['status']) && $data['status'] === 'success') {
              return $data['isp'];
          }
          return null;
      }

      // Example usage
      $ip = '8.8.8.8';
      $isp = get_isp_from_ip($ip);
      if ($isp) {
          echo "IP $ip belongs to ISP/Organization: $isp\n";
      } else {
          echo "Could not get ISP info for $ip\n";
      }
    ?>

    <!-- Alert (Optional) -->
    <div
      class="relative bg-red-100 text-red-700 text-sm border-l-8 border-red-500 px-3 py-2 pr-7 rounded shadow-sm mb-4"
      role="alert"
    >
      <strong class="font-bold">Login failed!</strong>
      <span class="ml-1">Please check your credentials and try again.</span>
      <button
        class="absolute top-0 bottom-0 right-0 px-3 text-red-700 hover:text-red-900"
        onclick="this.parentElement.remove()" 
        aria-label="Close"
      >
        &times;
      </button>
    </div>

    <!-- Login Form -->
    <form
      action="/login"
      method="POST"
      autocomplete="on"
      class="flex flex-col space-y-4"
    >
      <!-- Email/Username Field -->
      <label for="username" class="text-sm font-medium">Email or Username</label>
      <div class="flex items-center border border-gray-300 rounded">
        <i class="fas fa-user text-gray-500 mx-2"></i>
        <input
          type="text"
          name="username"
          id="username"
          class="flex-1 px-2 py-2 text-sm focus:outline-none"
          placeholder="Enter your email or username"
          required
        />
      </div>

      <!-- Password Field with Toggle -->
      <label for="password" class="text-sm font-medium">Password</label>
      <div class="flex items-center border border-gray-300 rounded">
        <i class="fas fa-lock text-gray-500 mx-2"></i>
        <input
          type="password"
          name="password"
          id="password"
          class="flex-1 px-2 py-2 text-sm focus:outline-none"
          placeholder="Enter your password"
          required
        />
        <button
          type="button"
          id="togglePassword"
          class="text-gray-500 mx-2 focus:outline-none"
          aria-label="Show or Hide Password"
        >
          <i class="fas fa-eye"></i>
        </button>
      </div>

      <div class="flex justify-between">
        <!-- Remember Me (brand green) -->
        <div class="flex items-center">
          <input
            type="checkbox"
            id="remember"
            name="remember"
            class="text-green-600 focus:ring-green-500 h-4 w-4 border-gray-300 rounded"
          />
          <label for="remember" class="ml-2 text-sm text-gray-700">
            Remember Me
          </label>
        </div>
        <!-- Trouble Logging In Link -->
        <div class="text-right">
          <button
            type="button"
            id="openModalBtn"
            class="text-sm text-green-600 hover:text-green-800 focus:outline-none"
          >
            Trouble Logging In?
          </button>
        </div>
      </div>

      <!-- Hidden Tenant ID -->
      <input
        type="hidden"
        name="tenant_id"
        value=""
      />

      <!-- Submit Button (Brand green) -->
      <button
        type="submit"
        class="bg-green-600 hover:bg-green-700 text-white py-2 rounded font-semibold text-sm"
      >
        <i class="fas fa-sign-in-alt mr-2"></i>Login
      </button>
    </form>

    <!-- Disclaimers / Warnings -->
    <div class="text-xs text-gray-600 mt-4 leading-relaxed">
      <strong>Warning:</strong> This system is for authorized use only.
      Unauthorized or improper use of this system may result in administrative
      or legal action. By logging in, you consent to the recording and monitoring
      of all activities. We track your <em>IP address, device details</em>, and
      other session data for security and compliance.
    </div>

    <!-- Footer Section (Location, IP, and now ISP) -->
    <footer class="flex justify-between text-xs text-gray-500 mt-4 pt-2 border-t">
      <span>
        Location: <span id="userLocation">Loading...</span>
      </span>
      <span>
        IP: <span id="ipAddress">Loading...</span>
      </span>
      <span>
        ISP: <span id="userISP">Loading...</span>
      </span>
    </footer>
  </div>

  <!-- Fixed Footer -->
  <footer
    class="fixed bottom-0 left-0 right-0 z-50 bg-white text-center text-xs text-gray-500 py-2"
  >
    &copy; <span id="year"></span> Amazing Blades Landscaping. All rights reserved.
  </footer>

  <!-- Trouble Logging In Modal -->
  <div
    id="troubleModal"
    class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50"
    aria-hidden="true"
  >
    <div
      class="bg-white rounded-lg w-11/12 max-w-sm p-4 relative"
      style="max-height: 90vh; overflow-y: auto;"
    >
      <!-- Close Button -->
      <button
        id="closeModalBtn"
        class="absolute top-2 right-2 text-gray-400 hover:text-gray-600 focus:outline-none"
        aria-label="Close Modal"
      >
        <i class="fas fa-times"></i>
      </button>

      <h2 class="text-lg font-semibold mb-2">Having Trouble Logging In?</h2>
      <p class="text-sm text-gray-600 mb-3">
        If you're unable to access your account, you can:
      </p>
      <ul class="list-disc list-inside text-sm text-gray-600 mb-3">
        <li>
          Reset your password via the
          <a href="#" class="text-green-600 underline">password reset form</a>.
        </li>
        <li>
          Contact our support team at
          <a href="mailto:support@example.com" class="text-green-600 underline">
            support@example.com
          </a>.
        </li>
        <li>Check your browser or device's internet connection settings.</li>
        <li>Ensure you haven't been blocked by a tenant-level IP policy.</li>
      </ul>
      <p class="text-xs text-gray-400">
        Dismiss this modal by clicking outside or pressing the
        <strong>X</strong>.
      </p>
    </div>
  </div>

  <!-- JS for Show Password Toggle & Modal Logic -->
  <script>
    // Show/hide password toggle
    const togglePwdBtn = document.getElementById('togglePassword');
    const passwordInput = document.getElementById('password');

    if (togglePwdBtn && passwordInput) {
      togglePwdBtn.addEventListener('click', function() {
        const pwdType = passwordInput.getAttribute('type');
        if (pwdType === 'password') {
          passwordInput.setAttribute('type', 'text');
          this.innerHTML = '<i class="fas fa-eye-slash"></i>';
        } else {
          passwordInput.setAttribute('type', 'password');
          this.innerHTML = '<i class="fas fa-eye"></i>';
        }
      });
    }

    // Trouble Logging In Modal
    const openModalBtn = document.getElementById('openModalBtn');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const troubleModal = document.getElementById('troubleModal');

    if (openModalBtn && troubleModal) {
      openModalBtn.addEventListener('click', () => {
        troubleModal.classList.remove('hidden');
      });
    }

    if (closeModalBtn && troubleModal) {
      closeModalBtn.addEventListener('click', () => {
        troubleModal.classList.add('hidden');
      });
    }

    // Close modal when clicking outside the modal content
    if (troubleModal) {
      troubleModal.addEventListener('click', (e) => {
        // If the user clicks the backdrop (troubleModal itself), close it
        if (e.target === troubleModal) {
          troubleModal.classList.add('hidden');
        }
      });
    }
  </script>
</body>
</html>
