const tokenServices = require("../services/token.services");

module.exports = (req, res, next) => {
  if (req.method === "OPTIONS") {
    return next();
  }

  try {
    // Bearer wqewqeqwedasdasdwqdwqdqw
    const token = req.headers.authorization.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const data = tokenServices.validateAccess(token);

    console.log("data", data);

    req.user = data;

    next();
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" });
  }
};
