const jwt = require("jsonwebtoken");
const Model= require("../models/index.model");
const universalFunction = require("../utils/helpers/universal-function.js");
const jwtHelper = require("../utils/helpers/jwt.helper.js");


const auth = async (req, res, next) => {
  try {
    const custom_header = req.header('X-custom-header');
    const token = req.header("Authorization");
    if(custom_header !== process.env.CUSTOM_HEADER) {
      throw new Error('Error - Header');
    }

    const decode = await jwtHelper.jwtVerify(token);
   
    const user = await Model.Admin.findOne({ _id: decode._id });  
    if (!user) {
      universalFunction.sendUnauthorizedErrorResponse(req,res);
    }

    req.user = user;
    req.user.token = token;
    next();
  } catch (error) {
    res.status(403).send({
        status: false,
        status_code: 403,
        error: error,
        message: error.message
    });
  }
};

module.exports = auth;
