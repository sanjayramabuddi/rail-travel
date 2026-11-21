const bcrypt = require("bcrypt");
const prisma = require("../config/prisma");
const logger = require("../config/logger");
const { generateAndStoreOtp, verifyOtp } = require("../utils/otp");
const { sendOtpEmail, verifyOtpEmail } = require("../utils/email");
const { BadRequestError, ConflictError } = require("../utils/error");

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

module.exports = {
  sendOTP,
  verifyOTP,
};
