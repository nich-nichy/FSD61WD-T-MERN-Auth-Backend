const { SignupFunction, LoginFunction, PasswordResetFunction, UpdatePasswordFunction, checkUserFunction } = require("../controllers/userAuth.controller");
const { userVerification } = require("../middleware/userAuth.middleware");
const router = require("express").Router();

router.post('/', userVerification)

router.post("/check-user", checkUserFunction)

router.post("/signup", SignupFunction);

router.post('/login', LoginFunction)

router.post("/reset-request", PasswordResetFunction)

router.post("/reset-password/:token", UpdatePasswordFunction)

module.exports = router;