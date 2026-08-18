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
  createHash,
} = require('../utils');

const register = async (req, res) => {
  const { email, name, password } = req.body;

  const emailAlreadyExists = await User.findOne({ email });
  
  if (emailAlreadyExists && !emailAlreadyExists.isVerified ) {
    throw new CustomError.BadRequestError('Email already exists, please verify your email');
  }  
  if (emailAlreadyExists) {
    throw new CustomError.BadRequestError('Email already exists');
  }


  // first registered user is an admin
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? 'admin' : 'user';

  const verificationToken= crypto.randomBytes(40).toString('hex')
  const user = await User.create({ name, email, password, role,verificationToken });
  const origin = process.env.CLIENT_URL || 'http://localhost:3000';

  await sendVerificationEmail({  name: user.name,
    email: user.email,
    verificationToken: user.verificationToken,
    origin});
  res.status(StatusCodes.CREATED).json({  msg: 'Success! Please check your email to verify account'});
};
const verifyEmail= async (req,res)=>{
  const {verificationToken,email}= req.body;
  const user= await User.findOne({email})
  if(!user){
    throw new CustomError.BadRequestError('Please provide valid email address');
  }
  if(verificationToken !==user.verificationToken){
    throw new CustomError.UnauthenticatedError('Verification Failed');
  }
  user.isVerified=true,
  user.verified= Date.now(),
  user.verificationToken=''
  await user.save()
  res.status(StatusCodes.OK).json({ msg: 'Email Verified' });
}
const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new CustomError.BadRequestError('Please provide email and password');
  }
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }
 
  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }
  if(!user.isVerified){
    throw new CustomError.UnauthenticatedError('Please verify your email');
  }
  const tokenUser = createTokenUser(user);
  //refresh token
  const existingToken = await Token.findOne({ user: user._id });
  if (existingToken) {
    const { isValid } = existingToken;
    if (!isValid) {
      throw new CustomError.UnauthenticatedError('Invalid Credentials');
    }
    attachCookiesToResponse({
      res,
      user: tokenUser,
      refreshToken: existingToken.refreshToken,
    });
    return res.status(StatusCodes.OK).json({ tokenUser });
  }

  const refreshToken = crypto.randomBytes(40).toString('hex');
  const userAgent = req.headers['user-agent'];
  const ip = req.ip;
  const userToken= {refreshToken,ip,userAgent,user:user._id};
  await Token.create(userToken)
  attachCookiesToResponse({ res, user: tokenUser,refreshToken });

  res.status(StatusCodes.OK).json({tokenUser });
};
const logout = async (req, res) => {
  await Token.findOneAndDelete({ user: req.user.userId });
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
  res.status(StatusCodes.OK).json({ msg: 'user logged out!' });
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

  user.password = password;
  user.passwordToken = null;
  user.passwordTokenExpirationDate = null;
  await user.save();
  // password changed - revoke any existing sessions
  await Token.findOneAndDelete({ user: user._id });

  res.status(StatusCodes.OK).json({ msg: 'Password reset successful' });
};

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
};
