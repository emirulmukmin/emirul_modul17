const jwt = require('jsonwebtoken');


SECRET = process.env.SECRET
const Auth = {
    verifyToken(req, res, next){ 
        const token = req.cookies["jwt"];
        //const {token} = req.body; localstorage sesi mingdep
        if (token) {
            // 12. Lalukan jwt verify
            const verified = jwt.verify(token, SECRET)
            if(verified){
              console.log("You're authenticated");
              //req.verified = verified utk modul storage
              return next();
        } else {
          res.status(403).send({message: 'Youre not authenticated, please login first'})
            console.log('Youre not authenticated');
        }
      }
  }
}

module.exports = Auth;
