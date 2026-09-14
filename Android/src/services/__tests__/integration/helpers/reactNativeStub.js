const { AppState, Linking, Alert } = require('./rnStubs');
module.exports = { AppState, Linking, Alert, Platform: { OS: 'android', select: (o) => o.android } };
