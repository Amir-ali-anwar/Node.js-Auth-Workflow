const User = require('../models/User');
const Token= require('../models/Token')
const { StatusCodes } = require('http-status-codes');
const crypto= require('crypto')
const CustomError = require('../errors');
const {
  attachCookiesToResponse,
  createTokenUser,
  sendVerificationEmail,
  sendResetPasswordEmail,
  sendNewDeviceAlertEmail,
  createHash,
  validatePasswordStrength,
  safeCompare,
  claimFirstAdminSlot,
  releaseFirstAdminSlot,
} = require('../utils');

const VERIFICATION_TOKEN_LIFETIME_MS = 24 * 60 * 60 * 1000;

const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_BASE_MINUTES = 1;
const MAX_KNOWN_DEVICES = 10;

const register = async (req, res) => {
  const { email, name, password } = req.body;

  const existingUser = await User.findOne({ email });

  // never reveal whether the email is already registered/verified - every
  // path below responds identically to a brand-new registration
  if (existingUser && existingUser.isVerified) {
    return res
      .status(StatusCodes.CREATED)
      .json({ msg: 'Success! Please check your email to verify account' });
  }

  await validatePasswordStrength(password, [name, email]);

  const verificationToken = crypto.randomBytes(40).toString('hex');
  const verificationTokenExpirationDate = new Date(
    Date.now() + VERIFICATION_TOKEN_LIFETIME_MS
  );
  const origin = process.env.CLIENT_URL || 'http://localhost:3000';

  if (existingUser) {
    // unverified account re-registering - refresh credentials/token in place
    // instead of creating a duplicate (email is unique)
    existingUser.name = name;
    existingUser.password = password;
    existingUser.verificationToken = createHash(verificationToken);
    existingUser.verificationTokenExpirationDate = verificationTokenExpirationDate;
    await existingUser.save();
  } else {
    // first registered user is an admin - claimed atomically so concurrent
    // registrations can't all see themselves as the first user
    const isFirstAccount = await claimFirstAdminSlot();
    const role = isFirstAccount ? 'admin' : 'user';
    try {
      await User.create({
        name,
        email,
        password,
        role,
        verificationToken: createHash(verificationToken),
        verificationTokenExpirationDate,
      });
    } catch (error) {
      if (isFirstAccount) {
        await releaseFirstAdminSlot();
      }
      throw error;
    }
  }

  await sendVerificationEmail({ name, email, verificationToken, origin });
  res
    .status(StatusCodes.CREATED)
    .json({ msg: 'Success! Please check your email to verify account' });
};
const verifyEmail = async (req, res) => {
  const { verificationToken, email } = req.body;
  const user = await User.findOne({ email });
  if (
    !user ||
    !user.verificationToken ||
    !safeCompare(createHash(verificationToken || ''), user.verificationToken) ||
    !user.verificationTokenExpirationDate ||
    user.verificationTokenExpirationDate < new Date()
  ) {
    throw new CustomError.UnauthenticatedError('Verification Failed');
  }
  user.isVerified = true;
  user.verified = Date.now();
  user.verificationToken = '';
  user.verificationTokenExpirationDate = undefined;
  await user.save();
  res.status(StatusCodes.OK).json({ msg: 'Email Verified' });
};
const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new CustomError.BadRequestError('Please provide email and password');
  }
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }

  if (user.lockUntil && user.lockUntil > Date.now()) {
    const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
    throw new CustomError.TooManyRequestsError(
      `Account temporarily locked due to repeated failed login attempts. Try again in ${minutesLeft} minute(s).`
    );
  }

  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    user.loginAttempts = (user.loginAttempts || 0) + 1;
    if (user.loginAttempts >= MAX_LOGIN_ATTEMPTS) {
      const lockCount = Math.floor(user.loginAttempts / MAX_LOGIN_ATTEMPTS);
      const lockMinutes = LOCK_BASE_MINUTES * 2 ** (lockCount - 1);
      user.lockUntil = new Date(Date.now() + lockMinutes * 60 * 1000);
    }
    await user.save();
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }
  if(!user.isVerified){
    throw new CustomError.UnauthenticatedError('Please verify your email');
  }

  user.loginAttempts = 0;
  user.lockUntil = undefined;

  const tokenUser = createTokenUser(user);
  // each login is its own session/device - do not reuse another session's refresh token
  const refreshToken = crypto.randomBytes(40).toString('hex');
  const userAgent = req.headers['user-agent'];
  const ip = req.ip;

  const knownDevice = user.knownDevices.find(
    (device) => device.ip === ip && device.userAgent === userAgent
  );
  if (knownDevice) {
    knownDevice.lastSeen = new Date();
  } else {
    try {
      await sendNewDeviceAlertEmail({ name: user.name, email: user.email, ip, userAgent });
    } catch (error) {
      // do not block login if the alert email fails to send
    }
    user.knownDevices.push({ ip, userAgent, lastSeen: new Date() });
    if (user.knownDevices.length > MAX_KNOWN_DEVICES) {
      user.knownDevices = user.knownDevices.slice(-MAX_KNOWN_DEVICES);
    }
  }
  await user.save();

  const userToken= {refreshToken,ip,userAgent,user:user._id};
  await Token.create(userToken)
  attachCookiesToResponse({ res, user: tokenUser,refreshToken });

  res.status(StatusCodes.OK).json({tokenUser });
};
const clearAuthCookies = (res) => {
  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
  res.cookie('refreshToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
};

const logout = async (req, res) => {
  // req.currentRefreshToken is set by authenticateUser and reflects the
  // rotated value if this request itself triggered a refresh
  if (req.currentRefreshToken) {
    await Token.findOneAndDelete({
      user: req.user.userId,
      refreshToken: req.currentRefreshToken,
    });
  }
  clearAuthCookies(res);
  res.status(StatusCodes.OK).json({ msg: 'user logged out!' });
};

const logoutAllSessions = async (req, res) => {
  await Token.deleteMany({ user: req.user.userId });
  clearAuthCookies(res);
  res.status(StatusCodes.OK).json({ msg: 'Logged out of all devices' });
};

const getSessions = async (req, res) => {
  const tokens = await Token.find({ user: req.user.userId }).sort(
    '-updatedAt'
  );
  const sessions = tokens.map((token) => ({
    id: token._id,
    ip: token.ip,
    userAgent: token.userAgent,
    createdAt: token.createdAt,
    updatedAt: token.updatedAt,
    isCurrent: Boolean(
      req.currentRefreshToken && token.refreshToken === req.currentRefreshToken
    ),
  }));
  res.status(StatusCodes.OK).json({ sessions, count: sessions.length });
};

const revokeSession = async (req, res) => {
  const { id } = req.params;
  const token = await Token.findOne({ _id: id, user: req.user.userId });
  if (!token) {
    throw new CustomError.NotFoundError('No session found with that id');
  }
  await token.deleteOne();
  res.status(StatusCodes.OK).json({ msg: 'Session revoked' });
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    throw new CustomError.BadRequestError('Please provide a valid email');
  }
  const user = await User.findOne({ email });

  if (user) {
    const passwordToken = crypto.randomBytes(70).toString('hex');
    const origin = process.env.CLIENT_URL || 'http://localhost:3000';
    await sendResetPasswordEmail({
      name: user.name,
      email: user.email,
      token: passwordToken,
      origin,
    });

    const tenMinutes = 1000 * 60 * 10;
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes);

    user.passwordToken = createHash(passwordToken);
    user.passwordTokenExpirationDate = passwordTokenExpirationDate;
    await user.save();
  }

  res
    .status(StatusCodes.OK)
    .json({ msg: 'Please check your email for a reset password link' });
};

const resetPassword = async (req, res) => {
  const { token, email, password } = req.body;
  if (!token || !email || !password) {
    throw new CustomError.BadRequestError('Please provide all values');
  }
  const user = await User.findOne({ email });
  if (
    !user ||
    user.passwordToken !== createHash(token) ||
    !user.passwordTokenExpirationDate ||
    user.passwordTokenExpirationDate < new Date()
  ) {
    throw new CustomError.UnauthenticatedError('Invalid or expired token');
  }

  await validatePasswordStrength(password, [user.name, user.email]);

  user.password = password;
  user.passwordToken = null;
  user.passwordTokenExpirationDate = null;
  await user.save();
  // password changed - revoke all existing sessions across every device
  await Token.deleteMany({ user: user._id });

  res.status(StatusCodes.OK).json({ msg: 'Password reset successful' });
};

module.exports = {
  register,
  login,
  logout,
  logoutAllSessions,
  getSessions,
  revokeSession,
  verifyEmail,
  forgotPassword,
  resetPassword,
};
