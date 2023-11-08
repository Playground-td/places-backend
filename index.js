const express = require("express");
const { Client } = require("@googlemaps/google-maps-services-js");
const cors = require("cors");
const dotenv = require("dotenv");
const { createHash, randomBytes } = require("crypto");
const { Email } = require("./email/email");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mime = require("mime-types");
const { Upload, uploadFile } = require("./uploadFile");

const CyclicDb = require("@cyclic.sh/dynamodb");
const db = CyclicDb("successful-ant-zipperCyclicDB");

dotenv.config();

const app = express();
const client = new Client({});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const signAccessToken = (key) => {
  const jwtSecret = "wzPe7g19Yan27T2ATud1Kw==";
  return jwt.sign({ key: key }, jwtSecret, {
    expiresIn: "3h",
  });
};

app.post("/clients/new", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the user exists
    const client = await db.collection("doceaseclients").get(email);

    // If the user exists, return a message
    if (client) {
      res.status(400).json({ success: false, message: "User already exists." });
      return;
    }

    const saltRounds = 12;
    // Hash the password before storing
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Replace the plain password with the hashed version
    req.body.password = hashedPassword;

    // Store the user in the database
    const result = await db.collection("doceaseclients").set(email, req.body);
    console.log(JSON.stringify(result, null, 2));

    await new Email(email, "Welcome").sendWelcome(req.body.fullName);

    res.json({
      success: true,
      message: "User added successfully.",
      data: { added: true },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});

app.post("/users/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Fetching the client with the provided email
    const client = await db.collection("doceaseclients").get(email);
    if (client) {
      const passwordMatch = await bcrypt.compare(
        password,
        client.props.password
      );
      if (!passwordMatch) {
        return res
          .status(401)
          .json({ success: false, message: "Invalid password entered." });
      } else {
        // return res.status(401).json({ success: false, message: 'Invalid email or password.' });
        const accessToken = signAccessToken(client.key);
        return res.status(200).json({
          success: true,
          message: "Login successful.",
          data: { client },
          accessToken: accessToken,
        });
      }
    } else {
      return res.status(401).json({
        success: false,
        message: `Email adress not found, if you don't have an account please sign up.`,
      });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});

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
app.post("/users/forgot-password", async (req, res) => {
  try {
    const email = req.body.email;

    if (!email) {
      return res
        .status(200)
        .json({ success: false, message: "Please provide email" });
    }
    const user = await db.collection("doceaseclients").get(email);

    if (!user) {
      return res.status(200).json({
        success: false,
        message: "There is no user with supplied email",
      });
    }
    const resetToken = randomBytes(32).toString("hex");

    const passwordResetToken = createHash("sha256")
      .update(resetToken)
      .digest("hex");
    const passwordResetExpires = new Date(
      Date.now() + 20 * 60 * 1000
    ).toISOString();

    const params = {
      passwordResetToken: passwordResetToken,
      passwordResetExpires: passwordResetExpires,
    };
    // save passwordResetToken and passwordResetExpires in database
    const result = await db.collection("doceaseclients").set(email, params); //To confirm

    // const resetURL = `${req.protocol}://localhost:5173/reset-password/${resetToken}`;
    const resetURL = `${req.protocol}://docease.netlify.app/reset-password/${email}/${resetToken}`;
    const subject = "Reset Password";

    console.log("resetURL");
    console.log(resetURL);

    const fullName = user.props.fullName;

    await new Email(email, subject).sendPasswordReset(resetURL, fullName);

    res.status(200).json({
      status: "success",
      message: "Password reset token sent to mail",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});

app.post("/users/reset-password/:key/:token", async (req, res) => {
  try {
    const key = req.params.key;
    const token = req.params.token;

    if (!key)
      return res.status(400).json({
        success: false,
        message: "Please provide the password reset key",
      });

    if (!token)
      return res.status(400).json({
        success: false,
        message: "Please provide the reset token",
      });
    const hashedToken = createHash("sha256").update(token).digest("hex");

    console.log("hashedToken resetToken ", hashedToken);

    const user = await db.collection("doceaseclients").get(key);

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "We could'nt that matches provided key",
      });
    }
    const savedToken = user.props?.passwordResetToken;

    if (hashedToken !== savedToken) {
      return res.status(400).json({
        success: false,
        message: "Token provided is invalid",
      });
    }

    const passwordResetExpiry = new Date(user.props.passwordResetExpires);
    const currentDate = new Date();

    if (passwordResetExpiry < currentDate) {
      return res.status(400).json({
        success: false,
        message: "Token  has expired",
      });
    }
    const newPassword = req.body.password;
    if (!newPassword) {
      return res.status(400).json({
        success: false,
        message: "Please provide password",
      });
    }

    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    const params = {
      passwordResetToken: null,
      passwordResetExpires: null,
      password: hashedPassword,
    };

    const email = user.props.email;
    await db.collection("doceaseclients").set(email, params); //To confirm

    res
      .status(200)
      .json({ success: true, message: "password reset successful" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Internal server error." });
  }
});

// TODO: To include protection check
// update profile
app.patch("/users/update-profile", authorize, async (req, res) => {
  const key = res.locals.key;

  const fullName = req.body.fullName;
  const email = req.body.email;
  if (!fullName || !email) {
    return res
      .status(400)
      .json({ success: false, message: "Please fill out all fields" });
  }
  let user = await db.collection("doceaseclients").get(key);

  if (user.props.email !== email) {
    user = await db.collection("doceaseclients").get(email);
    if (user) {
      return res.status(400).json({
        success: false,
        message: "Can't update to already registered email",
      });
    }
  }

  const params = {
    email: email,
    fullName: fullName,
  };

  await db.collection("doceaseclients").set(key, params);

  res.status(200).json({
    status: "success",
    user,
  });
});

// change password
app.patch("/users/update-password", authorize, async (req, res) => {
  const key = res.locals.key;
  const currentPassword = req.body.currentPassword;
  const newPassword = req.body.newPassword;

  const user = await db.collection("doceaseclients").get(key);

  if (!(await bcrypt.compare(currentPassword, user.props.password))) {
    return res.status(403).json({
      success: false,
      message: "Wrong current password",
    });
  }
  if (await bcrypt.compare(newPassword, user.props.password)) {
    return res.status(403).json({
      success: false,
      message: "New password same as current password",
    });
  }

  const saltRounds = 12;
  const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
  const params = {
    password: hashedPassword,
  };

  await db.collection("doceaseclients").set(key, params);

  res
    .status(200)
    .json({ success: true, message: "Password changed successfully" });
});

async function authorize(req, res, next) {
  const authHeader = req.headers["authorization"];
  let token;
  if (authHeader && authHeader.startsWith("Bearer")) {
    token = authHeader.split(" ")[1];
  }
  if (!token) {
    return res.status(401).json({
      success: false,
      message: "You are not logged! Please to get access",
    });
  }
  const jwtSecret = "wzPe7g19Yan27T2ATud1Kw==";

  const decoded = jwt.verify(token, jwtSecret);

  const user = await db.collection("doceaseclients").get(decoded.key);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "The user belonging to this token no exists!",
    });
  }

  res.locals.key = decoded.key;
  next();
}

app.post("/users/profile-picture", authorize, uploadFile, async (req, res) => {
  try {
    const file = req.file;
    const key = res.locals.key;

    if (file == undefined) {
      return res.status(400).json({
        success: false,
        message: "Please provide your profile picture !",
      });
    }

    const mimeType = mime.lookup(file.originalname);
    const isImage = mimeType && mimeType.startsWith("image");
    if (!isImage) {
      return res.status(400).json({
        success: false,
        message: "Please provide file of image type !",
      });
    }

    const imagePath = `users/${Date.now()}_${file.originalname}`;
    const upload = await new Upload(imagePath).add(file);
    const url = upload?.url;

    const params = {
      imageUrl: url,
      imagePath: imagePath,
    };

    await db.collection("doceaseclients").set(key, params);

    const user = await db.collection("doceaseclients").get(key);

    user.props.password = undefined;
    user.props.passwordResetToken = undefined;
    user.props.passwordResetExpires = undefined;
    user.props.imagePath = undefined;
    user.props.imageUrl = url;

    res.status(200).json({
      status: "success",
      message: `Photo uploaded successfully`,
      data: {
        user: user.props,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: error.message });
  }
});

app.patch("/users/profile-picture", authorize, uploadFile, async (req, res) => {
  try {
    const file = req.file;
    const key = res.locals.key;
    if (file == undefined) {
      return res.status(400).json({
        success: false,
        message: "Please provide your profile picture !",
      });
    }

    const mimeType = mime.lookup(file.originalname);
    const isImage = mimeType && mimeType.startsWith("image");
    if (!isImage) {
      return res.status(400).json({
        success: false,
        message: "Please provide file of image type !",
      });
    }

    const user = await db.collection("doceaseclients").get(key);

    const savedImagePath = user.props.imagePath;

    const imagePath = `users/${Date.now()}_${file.originalname}`;
    const upload = await new Upload(imagePath).update(file, savedImagePath);
    const url = upload?.url;

    const params = {
      imageUrl: url,
      imagePath: imagePath,
    };

    await db.collection("doceaseclients").set(key, params);

    user.props.password = undefined;
    user.props.passwordResetToken = undefined;
    user.props.passwordResetExpires = undefined;
    user.props.imagePath = undefined;
    user.props.imageUrl = url;

    res.status(200).json({
      status: "success",
      message: `Photo uploaded successfully`,
      data: {
        user: user.props,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get("/user/feedback", async (req, res) => {
  const feedback = req.body.feedback;
  console.log("feedback", feedback);
});

app.get("/:col/:key", async (req, res) => {
  // getting a key from a collection
  const col = req.params.col;
  const key = req.params.key;
  console.log(
    `from collection: ${col} get key: ${key} with params ${JSON.stringify(
      req.params
    )}`
  );
  const item = await db.collection(col).get(key);
  console.log(JSON.stringify(item, null, 2));
  res.json(item).end();
});

app.get("/:col", async (req, res) => {
  // listing a collection
  const col = req.params.col;
  console.log(
    `list collection: ${col} with params: ${JSON.stringify(req.params)}`
  );
  const items = await db.collection(col).list();
  console.log(JSON.stringify(items, null, 2));
  res.json(items).end();
});

const PORT = 5000 || process.env.PORT;

app.listen(PORT, () => {
  console.log("server started on port " + PORT);
});
