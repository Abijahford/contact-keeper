const jwt = require('jsonwebtoken');
const config = require('config');


// middleware function to check to see if token in header, if not then tell user. 
// If there is a token then verify it and pull out payload to set user so we can have access.
module.exports = function(req, res, next) {
    // Get tokn from header
    const token = req.header('x-auth-token');

    //Check if no token
    if(!token) {
        return res.status(401).json({msg: 'No token, authorization denied.'});
    }

    try {
        const decoded = jwt.verify(token, config.get('jwtSecret'));

        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({msg: 'Token not Valid.'});
    }
}