const { SignupFunction, LoginFunction, PasswordResetFunction, UpdatePasswordFunction } = require("../controllers/userAuth.controller");
const { userVerification } = require("../middleware/userAuth.middleware");
const router = require("express").Router();

router.post('/', userVerification)

router.post("/signup", SignupFunction);

router.post('/login', LoginFunction)

router.post("/reset-request", PasswordResetFunction)

router.post("/reset-password/:token", UpdatePasswordFunction)

module.exports = router;