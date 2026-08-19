const mongoose = require('mongoose');

// singleton-style key/value store for bootstrap flags that must be claimed
// atomically (e.g. "has the first admin account been created yet")
const SystemConfigSchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  value: mongoose.Schema.Types.Mixed,
});

module.exports = mongoose.model('SystemConfig', SystemConfigSchema);
