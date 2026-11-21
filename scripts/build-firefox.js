'use strict';

/**
 * Generates the ready-to-load `extension-firefox/` package from `extension/`
 * with a native Firefox manifest (`browser.proxy.onRequest` + `webRequestBlocking` AdBlock/Phishing/Custom Block).
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'extension');
const DST = path.join(ROOT, 'extension-firefox');

function copyDir(srcDir, dstDir) {
  fs.mkdirSync(dstDir, { recursive: true });
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    if (entry.name === 'manifest.json' || entry.name === '_metadata') continue;
    const srcPath = path.join(srcDir, entry.name);
    const dstPath = path.join(dstDir, entry.name);
    if (entry.isDirectory()) {
      copyDir(srcPath, dstPath);
    } else {
      fs.copyFileSync(srcPath, dstPath);
    }
  }
}

const chromeManifest = JSON.parse(fs.readFileSync(path.join(SRC, 'manifest.json'), 'utf8'));

const firefoxManifest = {
  manifest_version: 2,
  name: chromeManifest.name,
  version: chromeManifest.version,
  description: chromeManifest.description,
  icons: chromeManifest.icons,
  browser_action: {
    default_title: chromeManifest.action.default_title,
    default_popup: chromeManifest.action.default_popup,
    default_icon: chromeManifest.action.default_icon,
  },
  background: {
    scripts: ['background.js'],
  },
  web_accessible_resources: [
    'blocked.html',
    'blocked.css',
    'blocked.js',
    'icons/foxy-avatar.png',
  ],
  permissions: [
    'proxy',
    'storage',
    'privacy',
    'alarms',
    'tabs',
    'webRequest',
    'webRequestBlocking',
    '<all_urls>',
  ],
  browser_specific_settings: {
    gecko: {
      id: 'splitwire-browser@splitwire.local',
      strict_min_version: '109.0',
    },
  },
};

copyDir(SRC, DST);
fs.writeFileSync(
  path.join(DST, 'manifest.json'),
  JSON.stringify(firefoxManifest, null, 2) + '\n',
  'utf8'
);

console.log('[OK] Firefox extension synced to:', DST);
