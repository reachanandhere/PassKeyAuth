const express = require("express");
const PORT = process.env.PORT || 3000;
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require("@simplewebauthn/server")
const app = express();

const userStore = {};
const challengeStore = {};

app.use(express.static("./public"));
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Hello World");
});

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  const userId = `user_${Date.now()}`;

  if (!username || !password) {
    return res.status(400).json({
      status: "error",
      error: "Username and password are required",
    });
  }

  if (userStore[username]) {
    return res.status(400).json({
      status: "error",
      error: "Username already in use",
    });
  }

  const user = {
    userId,
    username,
    password,
  };
  userStore[userId] = user;
  
  console.log(user)
  return res.status(201).json({
    status: "success",
    message: "User registered successfully",
    userId
  });
});

app.post("/register-challenge",async(req, res)=>{
        const { userId  } = req.body;
       
        if(!userStore[userId]){
            return res.status(400).json({
                status: "error",
                error: "User not found",
            });
        };

        const challengePayload = await generateRegistrationOptions({
            rpID: "localhost",
            rpName: "My Localhost",
          
            userName: userStore[userId].username,
            timeout: 60000,
        })

        challengeStore[userId] = challengePayload.challenge;
        return res.status(200).json({
            options: challengePayload,
        });

})

app.post("/register-verify",async(req,res)=>{
    const { userId, cred } = req.body;
    if(!userStore[userId]){
        return res.status(400).json({
            status: "error",
            error: "User not found",
        });
    };
    if(!challengeStore[userId]){
        return res.status(400).json({
            status: "error",
            error: "Challenge not found",
        });
    };

   

    const verification = await verifyRegistrationResponse({
        expectedChallenge: challengeStore[userId],
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        response: cred,
    });

    if(!verification.verified){
        return res.status(400).json({
            status: "error",
            error: "Verification failed",
        });
    }

    userStore[userId].passkey = verification.registrationInfo;
    res.json({
        status: "success",
        message: "User verified successfully",
    });

})


app.post("/login-challenge", async(req, res) => {
    const { userId } = req.body;
    console.log("this",userStore)
    console.log("this",userStore[userId])
    if (!userStore[userId]) {
      return res.status(400).json({
        status: "error",
        error: "User not found",
      });
    }

    const options = await generateAuthenticationOptions({
        rpID: "localhost",
    })

   

    challengeStore[userId] = options.challenge;
    return res.status(200).json({
        options,
    });


})

app.post("/login-verify", async(req, res) => {
    const { userId, cred } = req.body;
    if (!userStore[userId]) {
      return res.status(400).json({
        status: "error",
        error: "User not found",
      });
    }
    if (!challengeStore[userId]) {
      return res.status(400).json({
        status: "error",
        error: "Challenge not found",
      });
    }

    const verification = await verifyAuthenticationResponse({
        expectedChallenge: challengeStore[userId],
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        response: cred,
        authenticator: userStore[userId].passkey,
    });

    if (!verification.verified) {
      return res.status(400).json({
        status: "error",
        error: "Verification failed",
      });
    }
    //Login User here
    res.json({
      status: "success",
      message: "User verified successfully",
    });
  }
);


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
