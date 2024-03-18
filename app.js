import express from "express";
import bcrypt from "bcrypt";
import cors from "cors";
import jwt from "jsonwebtoken";
import { LowSync } from "lowdb";
import { JSONFileSync } from "lowdb/node";

const db = new LowSync(new JSONFileSync("database.json"), {
	users: [],
});

// Initialize Express app
const app = express();

// Define a JWT secret key. This should be isolated by using env variables for security
const jwtSecretKey = "dsfdsfsdfdsvcsvdfgefg";

// Set up CORS and JSON middlewares
const corsOptions = {
	origin: "http://localhost:3000",
	credentials: true, //access-control-allow-credentials:true
	optionSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Basic home route for the API
app.get("/users", (_req, res) => {
	res.send(db.data.user);
});

// The auth endpoint that creates a new user record or logs a user based on an existing record
app.post("/auth", (req, res) => {
	const { userName, password } = req.body;
	// Look up the user entry in the database
	const user = db.data.users.filter((user) => userName === user.userName);
	console.log(user);
	// If found, compare the hashed passwords and generate the JWT token for the user
	if (user.length === 1) {
		bcrypt.compare(password, user[0].password, function (_err, result) {
			if (!result) {
				return res.status(401).json({ message: "Invalid password" });
			} else {
				let loginData = {
					userName,
					signInTime: Date.now(),
				};

				const token = jwt.sign(loginData, jwtSecretKey);
				res.status(200).json({ message: "success", token });
			}
		});
		// If no user is found, hash the given password and create a new entry in the auth db with the userName and hashed password
	} else {
		return res.status(401).json({ message: "Invalid UserName" });
	}
});

app.post("/register", (req, res) => {
	const { userName, password } = req.body;

	const indexUser = db.data.users.findIndex(
		(user) => userName === user.userName
	);

	if (indexUser === -1) {
		bcrypt.hash(password, 10, function (_err, hash) {
			console.log({ userName, password: hash });
			db.data.users.push({ userName, password: hash });

			let loginData = {
				userName,
				signInTime: Date.now(),
			};

			const token = jwt.sign(loginData, jwtSecretKey);
			res.status(200).json({ message: "success", token });
		});
	} else {
		const user = db.data.users;
		bcrypt.hash(password, 10, function (_err, hash) {
			user[indexUser].password = hash;

			let loginData = {
				userName,
				signInTime: Date.now(),
			};

			const token = jwt.sign(loginData, jwtSecretKey);
			res.status(200).json({ message: "success", token });
		});
	}
});

// The verify endpoint that checks if a given JWT token is valid
app.post("/verify", (req, res) => {
	const tokenHeaderKey = "jwt-token";
	const authToken = req.headers[tokenHeaderKey];
	try {
		const verified = jwt.verify(authToken, jwtSecretKey);
		if (verified) {
			return res.status(200).json({ status: "logged in", message: "success" });
		} else {
			// Access Denied
			return res.status(401).json({ status: "invalid auth", message: "error" });
		}
	} catch (error) {
		// Access Denied
		return res.status(401).json({ status: "invalid auth", message: "error" });
	}
});

// An endpoint to see if there's an existing account for a given userName address
app.post("/check-account", (req, res) => {
	const { userName } = req.body;

	console.log(req.body);

	const user = db.data.users.filter((user) => userName === user.userName);

	console.log(user);
	if (user.length === 0) {
		res.status(200).json({
			status: "User does not exist",
		});
	} else if (user.length === 1) {
		res.status(200).json({
			status: "User exists",
		});
	} else {
		return res.status(401).json({ message: "UserName Exist" });
	}
});



app.listen(3080);
