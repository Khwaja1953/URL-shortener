const { getUser } = require("../services/auth");



async function checkAuthentication(req, res, next) {
  const token = req.cookies?.uid;
  if (!token) return next();

  try {
    const user = getUser(token);
    // console.log(user);
    req.user = user;
  } catch (err) {
    console.error("JWT error:", err.message);
    return res.redirect("/login");
  }
  return next();
}

function restrictTo(roles) {
  return (req, res, next) => {
    if(!req.user)  {
      return res.redirect('/login')
    }
    if(!roles.includes(req.user.role)) return res.end('Unauthorized') ;
    return next();
}
}
module.exports = { checkAuthentication,restrictTo };