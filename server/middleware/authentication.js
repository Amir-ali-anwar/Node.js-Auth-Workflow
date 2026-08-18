const crypto = require('crypto');
const CustomError = require('../errors');
const { isTokenValid, attachCookiesToResponse } = require('../utils');
const Token = require('../models/Token');

const authenticateUser = async (req, res, next) => {
  const { refreshToken, accessToken } = req.signedCookies;
  try {
    if (accessToken) {
      const payload = isTokenValid(accessToken);
      req.user = payload.user;
      // let downstream handlers (e.g. logout) identify this session
      // without re-deriving it from a cookie that rotation may have changed
      if (refreshToken) {
        try {
          req.currentRefreshToken = isTokenValid(refreshToken).refreshToken;
        } catch (error) {
          req.currentRefreshToken = undefined;
        }
      }
      return next();
    }
    if (refreshToken) {
      const payload = isTokenValid(refreshToken);
      const existingToken = await Token.findOne({
        user: payload.user.userId,
        refreshToken: payload.refreshToken,
      });
      if (!existingToken || !existingToken.isValid) {
        throw new CustomError.UnauthenticatedError('Authentication Invalid');
      }

      // rotate: issue a new refresh token for this session and invalidate the old value -
      // a replay of the old cookie will no longer match any stored token
      const newRefreshToken = crypto.randomBytes(40).toString('hex');
      existingToken.refreshToken = newRefreshToken;
      existingToken.ip = req.ip;
      existingToken.userAgent = req.headers['user-agent'];
      await existingToken.save();

      attachCookiesToResponse({
        res,
        user: payload.user,
        refreshToken: newRefreshToken,
      });
      req.user = payload.user;
      req.currentRefreshToken = newRefreshToken;
      return next();
    }
    throw new CustomError.UnauthenticatedError('Authentication Invalid');
  } catch (error) {
    throw new CustomError.UnauthenticatedError('Authentication Invalid');
  }
};

const authorizePermissions = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      throw new CustomError.UnauthorizedError(
        'Unauthorized to access this route'
      );
    }
    next();
  };
};

module.exports = {
  authenticateUser,
  authorizePermissions,
};
