<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Advanced Device Info</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 20px;
      line-height: 1.6;
    }
    h1 {
      margin-bottom: 0.5em;
    }
    #infoContainer {
      margin-top: 1em;
    }
    .section {
      margin: 1em 0;
      padding: 1em;
      border: 1px solid #ccc;
      border-radius: 5px;
    }
    .section h2 {
      margin-top: 0;
    }
    table {
      border-collapse: collapse;
      margin-top: 0.5em;
    }
    table td, table th {
      border: 1px solid #ccc;
      padding: 8px;
      vertical-align: top;
    }
    table th {
      background: #f0f0f0;
    }
  </style>
</head>
<body>
  <h1>Advanced Device Information</h1>
  <p>
    Below is a comprehensive collection of device, browser, and system details
    gathered from the front-end. Please note that certain information requires
    explicit user permission or may not be available depending on your browser and OS.
  </p>

  <div id="infoContainer"></div>

  <!-- Include our script -->
  <script>(function () {
    const infoContainer = document.getElementById('infoContainer');
  
    // Utility function to create a section with a table
    function createSection(title, dataPairs) {
      const section = document.createElement('div');
      section.className = 'section';
  
      const heading = document.createElement('h2');
      heading.textContent = title;
      section.appendChild(heading);
  
      if (Array.isArray(dataPairs) && dataPairs.length > 0) {
        const table = document.createElement('table');
        const tbody = document.createElement('tbody');
  
        dataPairs.forEach(([key, value]) => {
          const row = document.createElement('tr');
          const keyCell = document.createElement('th');
          keyCell.textContent = key;
          const valueCell = document.createElement('td');
          valueCell.textContent = value;
          row.appendChild(keyCell);
          row.appendChild(valueCell);
          tbody.appendChild(row);
        });
  
        table.appendChild(tbody);
        section.appendChild(table);
      } else {
        const p = document.createElement('p');
        p.textContent = 'No data available or not supported.';
        section.appendChild(p);
      }
  
      infoContainer.appendChild(section);
    }
  
    // 1. Browser and Window Info
    function gatherBrowserInfo() {
      const data = [];
      data.push(['User Agent', navigator.userAgent || 'N/A']);
      data.push(['Language', navigator.language || 'N/A']);
      data.push(['Languages', navigator.languages ? navigator.languages.join(', ') : 'N/A']);
      data.push(['Platform', navigator.platform || 'N/A']);
      data.push(['Cookie Enabled', navigator.cookieEnabled]);
      data.push(['Online (Navigator)', navigator.onLine]);
      data.push(['Product', navigator.product || 'N/A']);
      data.push(['Vendor', navigator.vendor || 'N/A']);
      data.push(['App Code Name', navigator.appCodeName || 'N/A']);
      data.push(['App Name', navigator.appName || 'N/A']);
      data.push(['App Version', navigator.appVersion || 'N/A']);
      data.push(['Do Not Track', navigator.doNotTrack || 'N/A']);
  
      // Browser window / screen
      data.push(['Window Inner Size', window.innerWidth + ' x ' + window.innerHeight]);
      data.push(['Window Outer Size', window.outerWidth + ' x ' + window.outerHeight]);
  
      return data;
    }
  
    // 2. Screen Info
    function gatherScreenInfo() {
      const data = [];
      if (window.screen) {
        data.push(['Screen Width', screen.width]);
        data.push(['Screen Height', screen.height]);
        data.push(['Available Width', screen.availWidth]);
        data.push(['Available Height', screen.availHeight]);
        data.push(['Color Depth', screen.colorDepth]);
        data.push(['Pixel Depth', screen.pixelDepth]);
      }
      data.push(['Device Pixel Ratio', window.devicePixelRatio || 'N/A']);
  
      return data;
    }
  
    // 3. Hardware Info (Concurrency, Memory, etc.)
    function gatherHardwareInfo() {
      const data = [];
      // Hardware concurrency
      if (navigator.hardwareConcurrency) {
        data.push(['CPU Threads (hardwareConcurrency)', navigator.hardwareConcurrency]);
      } else {
        data.push(['CPU Threads (hardwareConcurrency)', 'N/A']);
      }
  
      // Device memory
      // NOTE: This is in GB for some browsers; many browsers do not support this.
      if (navigator.deviceMemory) {
        data.push(['Estimated Device Memory (GB)', navigator.deviceMemory]);
      } else {
        data.push(['Estimated Device Memory (navigator.deviceMemory)', 'N/A']);
      }
  
      return data;
    }
  
    // 4. Battery Info (Requires Promise-based API)
    function gatherBatteryInfo() {
      if (!navigator.getBattery) {
        createSection('Battery Info', [['Battery API', 'Not supported']]);
        return;
      }
  
      navigator.getBattery().then(function (battery) {
        const data = [];
        data.push(['Battery Charging', battery.charging]);
        data.push(['Battery Charging Time (s)', battery.chargingTime]);
        data.push(['Battery Discharging Time (s)', battery.dischargingTime]);
        data.push(['Battery Level (0-1)', battery.level]);
  
        createSection('Battery Info', data);
      }).catch(function (err) {
        createSection('Battery Info', [['Error', err.toString()]]);
      });
    }
  
    // 5. Network Info
    function gatherNetworkInfo() {
      const data = [];
      // Some browsers implement navigator.connection under different names
      const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
      if (connection) {
        data.push(['Effective Type', connection.effectiveType]);
        data.push(['Downlink (Mbps)', connection.downlink]);
        data.push(['RTT (ms)', connection.rtt]);
        data.push(['Save Data Mode?', connection.saveData]);
        data.push(['Type', connection.type || 'N/A']);
      } else {
        data.push(['Network Information', 'Not supported']);
      }
      return data;
    }
  
    // 6. Geolocation (Requires permission)
    function gatherGeolocationInfo() {
      if (!navigator.geolocation) {
        createSection('Geolocation', [['Geolocation API', 'Not supported']]);
        return;
      }
  
      navigator.geolocation.getCurrentPosition(
        function (position) {
          const data = [];
          data.push(['Latitude', position.coords.latitude]);
          data.push(['Longitude', position.coords.longitude]);
          data.push(['Accuracy (m)', position.coords.accuracy]);
          if (position.coords.altitude) {
            data.push(['Altitude (m)', position.coords.altitude]);
          }
          if (position.coords.altitudeAccuracy) {
            data.push(['Altitude Accuracy (m)', position.coords.altitudeAccuracy]);
          }
          if (position.coords.heading) {
            data.push(['Heading (degrees)', position.coords.heading]);
          }
          if (position.coords.speed) {
            data.push(['Speed (m/s)', position.coords.speed]);
          }
          data.push(['Timestamp', new Date(position.timestamp).toString()]);
  
          createSection('Geolocation', data);
        },
        function (error) {
          createSection('Geolocation', [['Error', error.message]]);
        }
      );
    }
  
    // 7. Device Orientation (requires sensors, often only over HTTPS + user gesture)
    //    We'll attempt to capture one event if available.
    function gatherOrientationInfo() {
      const orientationData = [
        ['Absolute', 'N/A'],
        ['Alpha', 'N/A'],
        ['Beta', 'N/A'],
        ['Gamma', 'N/A']
      ];
  
      function handleOrientation(event) {
        orientationData[0][1] = event.absolute || 'N/A';
        orientationData[1][1] = event.alpha || 'N/A';
        orientationData[2][1] = event.beta || 'N/A';
        orientationData[3][1] = event.gamma || 'N/A';
  
        createSection('Device Orientation', orientationData);
        window.removeEventListener('deviceorientation', handleOrientation);
      }
  
      // If the browser never fires 'deviceorientation', we'll display "No data"
      let orientationTimeout = setTimeout(() => {
        createSection('Device Orientation', [['Device Orientation', 'No data or not supported']]);
      }, 3000);
  
      window.addEventListener('deviceorientation', function wrapper(event) {
        clearTimeout(orientationTimeout);
        handleOrientation(event);
        window.removeEventListener('deviceorientation', wrapper);
      });
    }
  
    // 8. Time/Date/Locale Info
    function gatherTimeLocaleInfo() {
      const data = [];
      const now = new Date();
      data.push(['Current Time', now.toString()]);
      data.push(['Time Zone Offset (minutes)', now.getTimezoneOffset()]);
      data.push(['Intl.DateTimeFormat().resolvedOptions().timeZone', 
        Intl && Intl.DateTimeFormat ? Intl.DateTimeFormat().resolvedOptions().timeZone : 'N/A'
      ]);
      data.push(['Locale (from Intl)', Intl && Intl.DateTimeFormat ? Intl.DateTimeFormat().resolvedOptions().locale : 'N/A']);
  
      return data;
    }
  
    // 9. WebGL / GPU Info
    //    Attempt to create a WebGL context and pull the unmasked renderer/vendor.
    function gatherWebGLInfo() {
      const data = [];
      let gl, debugInfo, vendor, renderer;
  
      let canvas = document.createElement('canvas');
      gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl) {
        debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
          vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
          renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
          data.push(['WebGL Vendor (UNMASKED)', vendor]);
          data.push(['WebGL Renderer (UNMASKED)', renderer]);
        } else {
          data.push(['WebGL Info', 'WEBGL_debug_renderer_info not supported']);
        }
      } else {
        data.push(['WebGL Context', 'Not available']);
      }
  
      return data;
    }
  
    // 10. Storage Availability (localStorage, sessionStorage, indexedDB)
    function gatherStorageInfo() {
      const data = [];
      // localStorage
      try {
        const testKey = '__testLocalStorage__';
        localStorage.setItem(testKey, 'test');
        localStorage.removeItem(testKey);
        data.push(['localStorage', 'Available']);
      } catch (e) {
        data.push(['localStorage', 'Not available']);
      }
  
      // sessionStorage
      try {
        const testKey = '__testSessionStorage__';
        sessionStorage.setItem(testKey, 'test');
        sessionStorage.removeItem(testKey);
        data.push(['sessionStorage', 'Available']);
      } catch (e) {
        data.push(['sessionStorage', 'Not available']);
      }
  
      // indexedDB
      if (window.indexedDB) {
        data.push(['indexedDB', 'Available']);
      } else {
        data.push(['indexedDB', 'Not available']);
      }
  
      return data;
    }
  
    // 11. Other Media Capabilities (Optional demonstration)
    //     This section checks for getUserMedia (camera, mic), but won't request them here.
    function gatherMediaCapabilities() {
      const data = [];
      if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        data.push(['MediaDevices', 'Supported']);
      } else {
        data.push(['MediaDevices', 'Not Supported']);
      }
      return data;
    }
  
    // Gather data synchronously
    createSection('Browser & Window Info', gatherBrowserInfo());
    createSection('Screen Info', gatherScreenInfo());
    createSection('Hardware Info', gatherHardwareInfo());
    createSection('Network Info', gatherNetworkInfo());
    createSection('Time & Locale Info', gatherTimeLocaleInfo());
    createSection('WebGL / GPU Info', gatherWebGLInfo());
    createSection('Storage Info', gatherStorageInfo());
    createSection('Media Capabilities', gatherMediaCapabilities());
  
    // Asynchronous or event-based
    gatherBatteryInfo();       // Battery Info
    gatherGeolocationInfo();   // Geolocation
    gatherOrientationInfo();   // Device Orientation
  })();
  </script>
</body>
</html>
