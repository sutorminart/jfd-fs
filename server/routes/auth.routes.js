const express = require("express");
const bcrypt = require("bcryptjs");
const { check, validationResult } = require("express-validator");
const User = require("../models/User");
const router = express.Router({ mergeParams: true });
const { generateUserData } = require("../utils/helpers");
const tokenServices = require("../services/token.services");
const Token = require("../models/Token");

// npm install bcryptjs jsonwebtoken express-validator

// 1. get data from req (email, password)
// 2. check if user alresdy exist
// 3. hash password
// 4. create user
// 5. generate tokens

router.post("/signUp", [
  check("email", "Некорректный email").isEmail(),
  check("password", "Минимальная длина пароля 8 символов").isLength({ min: 8 }),

  async (req, res) => {
    try {
      console.log("test");
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: {
            message: "INVALID_DATA",
            code: 400,
            // errors: errors.array(),
          },
        });
      }
      const { email, password } = req.body;
      const existingUser = await User.findOne({ email: email });
      if (existingUser) {
        return res.status(400).json({
          error: {
            message: "EMAIL_EXISTS",
            code: 400,
          },
        });
      }
      const hashedPassword = await bcrypt.hash(password, 12);
      console.log("hashedPassword", hashedPassword);

      const newUser = await User.create({
        ...generateUserData(),
        ...req.body,
        password: hashedPassword,
      });

      const tokens = tokenServices.generate({ _id: newUser._id });
      await tokenServices.save(newUser._id, tokens.refreshToken);
      console.log("tokens", tokens);

      res.status(201).send({
        ...tokens,
        userId: newUser._id,
      });
    } catch (error) {
      res.status(500).json({
        message: "На сервере произошла ошибка. Попробуйте позже.",
      });
    }
  },
]);

// 1. validate
// 2. find user
// 3. compare hashed passwords
// 4. generate token
// 5 . return data

router.post("/signInWhithPassword", [
  check("email", "Email некорректный").normalizeEmail().isEmail(),
  check("password", "Пароль не может быть пустым").exists(),

  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: {
            message: "INVALID_DATA",
            code: 400,
          },
        });
      }

      const { email, password } = req.body;
      const existingUser = await User.findOne({ email });
      if (!existingUser) {
        return res.status(400).send({
          error: {
            message: "EMAIL_NOT_FOUND",
            code: 400,
          },
        });
      }

      const isPasswordEqual = await bcrypt.compare(
        password,
        existingUser.password
      );
      if (!isPasswordEqual) {
        return res.status(400).send({
          error: {
            message: "INVALID_PASSWORD",
            code: 400,
          },
        });
      }

      const tokens = tokenServices.generate({ _id: existingUser._id });
      await tokenServices.save(existingUser._id, tokens.refreshToken);

      res.status(200).send({
        ...tokens,
        userId: existingUser._id,
      });
    } catch (error) {
      res.status(500).json({
        message: "На сервере произошла ошибка. Попробуйте позже.",
      });
    }
  },
]);

function isTokenInvalid(data, dbToken) {
  return !data || !dbToken || data._id !== dbToken?.user?.toString();
}

router.post("/token", async (req, res) => {
  try {
    const { refresh_token: refreshToken } = req.body;
    const data = tokenServices.validateRefresh(refreshToken);
    const dbToken = await tokenServices.findToken(refreshToken);

    if (isTokenInvalid(data, dbToken)) {
      return res.status(400).json({ message: "Unauthorized" });
    }

    const tokens = await tokenServices.generate({
      _id: data._id,
    });

    await tokenServices.save(data._id, tokens.refreshToken);

    res.status(200).send({ ...tokens, userId: data._id });
  } catch (error) {
    res.status(500).json({
      message: "На сервере произошла ошибка. Попробуйте позже.",
    });
  }
});

module.exports = router;
