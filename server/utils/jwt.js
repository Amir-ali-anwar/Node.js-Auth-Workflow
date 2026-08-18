const jwt = require('jsonwebtoken');

const createJWT = ({ payload, expiresIn }) => {
  const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn });
  return token;
};

const isTokenValid = ( token ) => jwt.verify(token, process.env.JWT_SECRET);

const attachCookiesToResponse = ({ res, user,refreshToken }) => {
  const accessTokenJWT = createJWT({
    payload: {user},
    expiresIn: process.env.JWT_LIFETIME || '15m',
  });
  const refreshTokenJWT = createJWT({
    payload: {user,refreshToken},
    expiresIn: process.env.JWT_REFRESH_LIFETIME || '30d',
  });

  const fifteenMinutes = 1000 * 60 * 15;
  const thirtyDays = 1000 * 60 * 60 * 24 * 30;

  res.cookie('accessToken', accessTokenJWT, {
    httpOnly: true,
    expires: new Date(Date.now() + fifteenMinutes),
    secure: process.env.NODE_ENV === 'production',
    signed: true,
  });
  res.cookie('refreshToken', refreshTokenJWT, {
    httpOnly: true,
    expires: new Date(Date.now() + thirtyDays),
    secure: process.env.NODE_ENV === 'production',
    signed: true,
  });
};


// const attachCookiesToResponse = ({ res, user }) => {
//   const token = createJWT({ payload: user });

//   const oneDay = 1000 * 60 * 60 * 24;

//   res.cookie('token', token, {
//     httpOnly: true,
//     expires: new Date(Date.now() + oneDay),
//     secure: process.env.NODE_ENV === 'production',
//     signed: true,
//   });
// };

module.exports = {
  createJWT,
  isTokenValid,
  attachCookiesToResponse,
};
