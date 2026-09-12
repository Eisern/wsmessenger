const { AppState, Linking } = require('./rnStubs');
module.exports = { AppState, Linking, Platform: { OS: 'android', select: (o) => o.android } };
