const SystemConfig = require('../models/SystemConfig');

const FIRST_ADMIN_KEY = 'firstAdminClaimed';

// atomically claims the "first account becomes admin" slot so concurrent
// registrations can't all see themselves as the first user. findOneAndUpdate
// with upsert returns the pre-update document (null if none existed), so a
// null result means this call is the one that just created it.
const claimFirstAdminSlot = async () => {
  const existing = await SystemConfig.findOneAndUpdate(
    { key: FIRST_ADMIN_KEY },
    { $setOnInsert: { key: FIRST_ADMIN_KEY, value: true } },
    { upsert: true, new: false }
  );
  return existing === null;
};

// releases the slot if claimed but the account that claimed it was never
// actually created, so a later registration can still become admin
const releaseFirstAdminSlot = async () => {
  await SystemConfig.deleteOne({ key: FIRST_ADMIN_KEY });
};

module.exports = { claimFirstAdminSlot, releaseFirstAdminSlot };
