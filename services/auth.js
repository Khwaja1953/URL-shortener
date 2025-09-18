const jwt = require('jsonwebtoken');
const secret = "Ilssrinagar1234";
function setUser(user){
  return jwt.sign({
    _id:user._id,
    username:user.username,
    role:user.role,
  },secret);
}

function getUser(token){
  // console.log(token);
  if(!token) return null;
  return jwt.verify(token,secret);
}
module.exports = {
  setUser,
  getUser
};