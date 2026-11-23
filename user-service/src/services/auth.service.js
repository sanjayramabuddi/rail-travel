const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const prisma = require("../config/prisma");
const logger = require("../config/logger");
const { config } = require("../config");
const { redis } = require("../config/redis");
const { generateAndStoreOtp, verifyOtp } = require("../utils/otp");
const { sendOtpEmail, verifyOtpEmail } = require("../utils/email");
const { generateAccessToken, generateRefreshToken, verifyRefreshToken } = require("../utils/auth");
const { BadRequestError, UnauthorizedError, ConflictError, ForbiddenError } = require("../utils/error");

const sendOTP = async (firstName, lastName, email, password) => {
  const existingUser = await prisma.user.findUnique({
    where: { email },
  });

  if (existingUser) {
    throw new ConflictError("User already exists");
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const meta = { firstName, lastName, email, hashedPassword };
  const { otp, otpSessionId } = await generateAndStoreOtp(meta);
  await sendOtpEmail(email, otp);
  logger.info(`OTP email queued for : ${email}`);
  return { otpSessionId };
};

const verifyOTP = async (otp, otpSessionId) => {
  const meta = await verifyOtp(otp, otpSessionId);
  if (meta === null) {
    throw new BadRequestError("Invalid or expired OTP", "OTP_INVALID");
  }

  const user = await prisma.user.create({
    data: {
      firstName: meta.firstName,
      lastName: meta.lastName,
      email: meta.email,
      password: meta.hashedPassword,
      emailVerified: true,
    },
  });

  await verifyOtpEmail(meta);
  logger.info(`Welcome email queued for ${meta.email}`);
  return user;
};

const login = async (email, password, deviceId) => {
  const existingUser = await prisma.user.findUnique({
    where: { email },
  });
  if (!existingUser) {
    throw new UnauthorizedError("Invalid email or password", "INVALID_CREDENTIALS");
  }

  const doesPasswordMatch = await bcrypt.compare( password, existingUser.password );
  if (!doesPasswordMatch) {
    throw new UnauthorizedError("Invalid email or password", "INVALID_CREDENTIALS");
  }

  const accessToken = generateAccessToken(existingUser.id);
  const refreshToken = generateRefreshToken(existingUser.id);
  const { jti } = jwt.decode(refreshToken);

  await redis.set(`refresh:${existingUser.id}:${deviceId}`, jti, "EX", config.REFRESH_TOKEN_EXP_SEC);
  const { password: _password, ...safeUser } = existingUser;
  await redis.set(`user:${existingUser.id}`, JSON.stringify(safeUser), "EX", config.REDIS_USER_TTL);

  return { accessToken, refreshToken, loggedInUser: safeUser };
};

const rotateRefreshToken = async (refreshToken, deviceId) => {
  const payload = verifyRefreshToken(refreshToken);
  const { id: userId, jti } = payload;

  const storedJti = await redis.get(`refresh:${userId}:${deviceId}`);
  if (!storedJti) {
    throw new ForbiddenError("Session Expired", "Login AGAIN");
  }
  if (storedJti !== jti) {
    await redis.del(`refresh:${userId}:${deviceId}`);
    throw new ForbiddenError("Refresh token reused", "LOGIN AGAIN");
  }

  const newAccessToken = generateAccessToken(payload.id);
  const newRefreshToken = generateRefreshToken(payload.id);
  const { jti: newJti } = jwt.decode(newRefreshToken);
  await redis.set(`refresh:${payload.id}:${deviceId}`, newJti, "EX", config.REFRESH_TOKEN_EXP_SEC);
  
  return { newAccessToken, newRefreshToken };
};

module.exports = {
  sendOTP,
  verifyOTP,
  login,
  rotateRefreshToken,
};
