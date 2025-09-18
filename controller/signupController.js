const User = require("../model/signupModel"); // avoid naming conflict
const bcrypt = require("bcryptjs");

const { setUser} = require("../services/auth");


async function handleUserSignup(req, res) {
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(req.body.password, salt);
  // console.log(req.file);
    const { username, email, password } = req.body;
    const profileImage = req.file.filename;
     if (!username || !password || !email) {
            return res.status(400).json({ error: "All fields are required" });
        }

    await User.create({
        username,
        email,
        hashedPassword,
        profileImage
    });
    return res.redirect('/');

}


async function handleUserLogin(req, res) {
  const { username, password } = req.body;
  // console.log(username, password);
  const user = await User.findOne({ username});
  
  if (!user || !bcrypt.compareSync(password, user.hashedPassword))
    return res.render("login", {
      error: "Invalid Username or Password",
    });

  
  const token=setUser(user);
  res.cookie("uid", token);

  return res.redirect("/");
  // return res.json({token});
}

module.exports = { handleUserSignup, handleUserLogin }