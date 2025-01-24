// File: /public/js/DeviceSecurity.js

(function () {
    /**
     * Parse browser name and version from the User-Agent string.
     */
    function getBrowserInfo() {
      const agent = navigator.userAgent;
      let browserName = 'Unknown';
      let browserVersion = 'Unknown';
  
      if (agent.indexOf('Chrome') > -1 && agent.indexOf('Edg') === -1 && agent.indexOf('OPR') === -1) {
        browserName = 'Chrome';
        const match = agent.match(/Chrome\/([\d.]+)/);
        if (match && match[1]) {
          browserVersion = match[1];
        }
      } else if (agent.indexOf('Safari') > -1 && agent.indexOf('Chrome') === -1 && agent.indexOf('OPR') === -1) {
        browserName = 'Safari';
        const match = agent.match(/Version\/([\d.]+)/);
        if (match && match[1]) {
          browserVersion = match[1];
        }
      } else if (agent.indexOf('Firefox') > -1) {
        browserName = 'Firefox';
        const match = agent.match(/Firefox\/([\d.]+)/);
        if (match && match[1]) {
          browserVersion = match[1];
        }
      } else if (agent.indexOf('Edg') > -1) {
        browserName = 'Edge';
        const match = agent.match(/Edg\/([\d.]+)/);
        if (match && match[1]) {
          browserVersion = match[1];
        }
      } else if (agent.indexOf('OPR') > -1) {
        browserName = 'Opera';
        const match = agent.match(/OPR\/([\d.]+)/);
        if (match && match[1]) {
          browserVersion = match[1];
        }
      }
  
      return { browserName, browserVersion };
    }
  
    /**
     * Parse OS name and version from the User-Agent string.
     */
    function getOSInfo() {
      const agent = navigator.userAgent;
      let osName = 'Unknown';
      let osVersion = 'Unknown';
  
      if (agent.indexOf('Win') !== -1) {
        osName = 'Windows';
        const versionMatch = agent.match(/Windows NT ([\d.]+)/);
        if (versionMatch && versionMatch[1]) {
          switch (versionMatch[1]) {
            case '10.0':
              osVersion = '10';
              break;
            case '6.3':
              osVersion = '8.1';
              break;
            case '6.2':
              osVersion = '8';
              break;
            case '6.1':
              osVersion = '7';
              break;
            default:
              osVersion = versionMatch[1]; // fallback for other versions
          }
        }
      } else if (agent.indexOf('Mac') !== -1) {
        osName = 'macOS';
        const versionMatch = agent.match(/Mac OS X ([\d_]+)/);
        if (versionMatch && versionMatch[1]) {
          osVersion = versionMatch[1].replace(/_/g, '.');
        }
      } else if (agent.indexOf('X11') !== -1) {
        osName = 'UNIX';
      } else if (agent.indexOf('Linux') !== -1 && agent.indexOf('Android') === -1) {
        osName = 'Linux';
      } else if (/Android/i.test(agent)) {
        osName = 'Android';
        const match = agent.match(/Android\s+([\d.]+)/i);
        if (match && match[1]) {
          osVersion = match[1];
        }
      } else if (/iPhone|iPad|iPod/i.test(agent)) {
        osName = 'iOS';
        const match = agent.match(/OS\s([\d_]+)/i);
        if (match && match[1]) {
          // iOS versions in UA often look like "OS 14_4"
          osVersion = match[1].replace(/_/g, '.');
        }
      }
  
      return { osName, osVersion };
    }
  
    /**
     * Collect screen resolution, color depth, and pixel density.
     */
    function getScreenInfo() {
      const screenResolution = window.screen.width + ' x ' + window.screen.height;
      const colorDepth = window.screen.colorDepth;
      const pixelDensity = window.devicePixelRatio || 1;
  
      return { screenResolution, colorDepth, pixelDensity };
    }
  
    /**
     * Collect basic hardware info.
     */
    function getHardwareInfo() {
      // Not all browsers support deviceMemory; Safari on iOS returns undefined.
      const cpuCores = navigator.hardwareConcurrency || 'Unknown';
      const deviceMemory = navigator.deviceMemory || 'Unknown';
  
      return { cpuCores, deviceMemory };
    }
  
    /**
     * Gather locale and time zone info.
     */
    function getLocaleInfo() {
      const languageSettings = navigator.language || 'Unknown';
      const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown';
  
      // Optional placeholders (for demonstration), you can expand with Intl APIs if you like:
      const numberFormats = 'N/A'; 
      const dateTimeFormats = 'N/A';
  
      return { languageSettings, timeZone, numberFormats, dateTimeFormats };
    }
  
    /**
     * Infer device type & input features from UA + screen size.
     */
    function getBasicDeviceInfo() {
      const width = window.screen.width;
      let deviceType = 'desktop';
  
      if (/Mobi|Android/i.test(navigator.userAgent)) {
        deviceType = 'mobile';
      } else if (/Tablet|iPad/i.test(navigator.userAgent) || (width >= 600 && width < 900)) {
        deviceType = 'tablet';
      }
  
      const touchPoints = navigator.maxTouchPoints || 0;
      const touchSupport = touchPoints > 0;
  
      // Basic detection of "coarse" vs. "fine" pointer
      let pointerType = 'mouse';
      if (window.matchMedia && window.matchMedia('(pointer: coarse)').matches) {
        pointerType = 'touch';
      }
  
      return { deviceType, touchSupport, touchPoints, pointerType };
    }
  
    /**
     * Installed plugins are increasingly locked down in modern browsers,
     * so this may not return useful info on all platforms.
     */
    function getInstalledPlugins() {
      const pluginNames = [];
      if (navigator.plugins) {
        for (let i = 0; i < navigator.plugins.length; i++) {
          pluginNames.push(navigator.plugins[i].name);
        }
      }
      return pluginNames;
    }
  
    /**
     * Gather all of the relevant device/broswer security info into one object.
     */
    function gatherDeviceSecurityInfo() {
      const { osName, osVersion } = getOSInfo();
      const { browserName, browserVersion } = getBrowserInfo();
      const { screenResolution, colorDepth, pixelDensity } = getScreenInfo();
      const { cpuCores, deviceMemory } = getHardwareInfo();
      const {
        languageSettings,
        timeZone,
        numberFormats,
        dateTimeFormats
      } = getLocaleInfo();
      const {
        deviceType,
        touchSupport,
        touchPoints,
        pointerType
      } = getBasicDeviceInfo();
      const installedPlugins = getInstalledPlugins();
  
      return {
        osName,
        osVersion,
        browserName,
        browserVersion,
        screenResolution,
        colorDepth,
        pixelDensity,
        cpuCores,
        deviceMemory,
        languageSettings,
        timeZone,
        numberFormats,
        dateTimeFormats,
        deviceType,
        touchSupport,
        touchPoints,
        pointerType,
        installedPlugins
      };
    }
  
    /**
     * Public function to gather and log the info in the console.
     */
    function logDeviceSecurityInfo() {
      const info = gatherDeviceSecurityInfo();
      console.log('Device Security Info:', info);
    }
  
    // Expose the logging function to the global scope so you can call it from anywhere.
    window.logDeviceSecurityInfo = logDeviceSecurityInfo;
  })();
  