const express = require("express");
const { Client } = require("@googlemaps/google-maps-services-js");
const cors = require("cors");
const dotenv = require("dotenv");
const { createHash, randomBytes } = require("crypto");
const { Email } = require("./email/email");

dotenv.config();

const app = express();
const client = new Client({});

app.use(cors());

app.get("/near-by-places", async (req, res) => {
  console.log("req.query");
  console.log(req.query);
  // { latitude: '0.3244032', longitude: '32.587776' }
  const latitude = req.query.latitude;
  const longitude = req.query.longitude;

  if (!latitude || !longitude) {
    return res.status(400).json({
      success: false,
      message: "Please provide location co-ordinates",
    });
  }

  const healthFacilities = await client.placesNearby({
    params: {
      // location: "0.3244032, 32.587776",
      location: `${latitude}, ${longitude}`,
      key: process.env.GOOGLE_MAPS_API_KEY,
      radius: 1000,
      types: ["hospital", "health"],
    },
  });

  if (healthFacilities.statusText !== "OK") {
    return res
      .status(400)
      .json({ success: false, message: "could not find places" });
  }

  res.status(200).json({
    success: true,
    message: "get health successfully",
    data: healthFacilities.data,
  });
});

app.post("/users/forgot-password/:email", async (req, res) => {
  try {
    console.log("req.body");
    console.log(req.body);
    console.log("req.params");
    console.log(req.params);
    console.log("req.query");
    console.log(req.query);

    // const email = req.body.email;
    // const { email } = req.body;
    const { email } = req.params;

    if (!email) {
      return res
        .status(200)
        .json({ success: false, message: "Please provide email" });
    }
    // const user = await db.collection("doceaseclients").get(email);

    // if (!user) {
    //   return res.status(200).json({
    //     success: false,
    //     message: "There is no user with supplied email",
    //   });
    // }
    const resetToken = randomBytes(32).toString("hex");

    const passwordResetToken = createHash("sha256")
      .update(resetToken)
      .digest("hex");
    const passwordResetExpires = new Date(
      Date.now() + 20 * 60 * 1000
    ).toISOString();

    // const params = {
    //   passwordResetToken: passwordResetToken,
    //   passwordResetExpires: passwordResetExpires,
    // };
    // // save passwordResetToken and passwordResetExpires in dynamodb
    // const result = await db.collection("doceaseclients").set(email, params); //To confirm

    const resetURL = `${req.protocol}://localhost:5173/reset-password/${resetToken}`;
    // const resetURL = `${req.protocol}://docease.netlify.app/reset-password/${resetToken}`;
    const subject = "Reset Password";

    console.log("resetURL");
    console.log(resetURL);

    // const fullName = user.props.userName;

    await new Email(email, subject).sendPasswordReset(resetURL, "Tibs");

    res.status(200).json({
      status: "success",
      message: "Password reset token sent to mail",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});

app.post("users/reset-password/:token", async (req, res, next) => {
  const token = req.params.token;
  if (!token) return next(new AppError("Please a reset token", 400));
  const hashedToken = createHash("sha256").update(token).digest("hex");
  // compare reset token
  // check for token expiry

  const user = await User.findOne({
    where: {
      passwordResetToken: hashedToken,
      passwordResetExpires: { [Op.gt]: Date.now() },
    },
  });

  if (!user) {
    return next(new AppError("Token is invalid or has expired", 400));
  }
  const newPassword = req.body.password;
  if (!newPassword) return next(new AppError("Please supply  password", 400));

  user.password = req.body.password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();
  // delete token and its expiry dates from dynamodb

  // login user

  await new Auth(user, 200, res).send();
  // send response here
});

const PORT = 5000 || process.env.PORT;

app.listen(PORT, () => {
  console.log("server started on port " + PORT);
});
