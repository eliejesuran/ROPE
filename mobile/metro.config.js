const { getDefaultConfig } = require('expo/metro-config');

const config = getDefaultConfig(__dirname);

// Required for @noble/curves and @noble/hashes which use package.json `exports` field
config.resolver.unstable_enablePackageExports = true;

module.exports = config;
