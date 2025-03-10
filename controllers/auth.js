const User = require('../models/user');
const bcrypt = require("bcryptjs");
const nodemailer = require('nodemailer');
const crypto = require("crypto");



exports.getLogin = (req, res, next) => {
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    isAuthenticated: false,
      error:req.flash('error')
  });
};

exports.getSignup = (req, res, next) => {
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    isAuthenticated: false
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  User.findOne({email: email})
    .then(user => {
      if(!user){
          req.flash('error', 'Invalid email or password');
          return res.redirect('/login');
      }
      bcrypt.compare(password, user.password)
          .then(result=>{
            if(result){
              req.session.isLoggedIn = true;
              req.session.user = user;
              console.log("req.session.user",user)
              return req.session.save(err => {
                console.log(err);
                res.redirect('/');
              });
            }
            res.redirect('/login');

          }).catch(err =>{
            console.log(err);
            res.redirect('/login');
      });

    })
    .catch(err => console.log(err));
};



// Create a Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail', // You can use other services like Mailgun, SendGrid, etc.
    auth: {
        user: 'atulya220@gmail.com', // Replace with your email
        pass: 'syll tsig pxgw eouo'  // Replace with your email password or app-specific password
    }
});

exports.postSignup = (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;

    User.findOne({ email: email })
        .then(userDoc => {
            if (userDoc) {
                return res.redirect('/signup');
            }
            return bcrypt.hash(password, 12)
                .then(hashPassw => {
                    const user = new User({
                        email: email,
                        password: hashPassw,
                        cart: { items: [] }
                    });
                    return user.save();
                })
                .then(result => {
                    // After user is saved, send the confirmation email
                    let mailOptions = {
                        from: "nodeEcoon@gmail.com", // Sender address
                        to: email, // Receiver address
                        subject: 'Signup Successful', // Subject line
                        text: 'Congratulations! Your account has been successfully created.' // Plain text body
                    };

                    // Send the email
                    transporter.sendMail(mailOptions, (err, info) => {
                        if (err) {
                            console.log('Error sending email:', err);
                        } else {
                            console.log('Email sent: ' + info.response);
                        }
                    });

                    // Redirect user to the login page after successful signup
                    res.redirect('/login');
                });
        })
        .catch(err => console.log(err));
};


exports.postLogout = (req, res, next) => {
    req.session.destroy(err => {
        if (err) {
            console.log("ERR", err);
            return res.status(500).send('Logout failed');
        }
        // Clear cookie
        res.clearCookie('connect.sid'); // Default session cookie name for express-session
        console.log("LoggedOut");
        res.redirect('/login');
    });
};


exports.getReset = (req,res,next)=>{
    let message = req.flash('error');
    if(message.length>0){
        message = message[0]
    }else{
        message = null;
    }
    res.render('auth/reset', {
        path: '/reset',
        pageTitle: 'Password Reset',
        error: message,
        isAuthenticated: false
    });

}

const baseUrl = process.env.BASE_URL;

exports.postRest = (req, res, next) => {
    crypto.randomBytes(32,(err,buffer)=>{
        if(err){
            console.log(err);
            return res.redirect('/login');
        }
        const token = buffer.toString('hex');
        User.findOne({email:req.body.email})
            .then(user=>{
                if(!user){
                    req.flash("error","Invalid email");
                    return res.redirect('/login');
                }
                user.resetToken = token;
                user.resetTokenExpires = Date.now() + 3600000; //1hr in miliSec
                return user.save();

            })
            .then(result => {

                let mailOptions = {
                    from: "nodeEcoon@gmail.com", // Sender address
                    to: req.body.email, // Receiver address
                    subject: 'Password Reset', // Subject line
                    html:`
                    <p>You Requested a password Reset</p>
                    <p>Click this <a href="${baseUrl}/new-password/${token}" > Link</a> to set new Password</p>
                    `
                };

                transporter.sendMail(mailOptions, (err, info) => {
                    if (err) {
                        console.log('Error sending email:', err);
                    } else {
                        console.log('Email sent: ' + info.response);
                        res.redirect("/");
                    }
                });

            })
            .catch(err=>console.log(err))

    })

}


exports.getNewPassword = (req, res, next) => {
    const token = req.params.token;
    User.findOne({resetToken:token, resetTokenExpires: {$gt: Date.now()}})
        .then((user)=>{
            console.log("getNewPassword",user)
            let message = req.flash('error');
            if(message.length>0){
                message = message[0]
            }else{
                message = null;
            }
            res.render('auth/new-password', {
                path: '/new-password',
                pageTitle: 'Update Password',
                error: message,
                isAuthenticated: false,
                userId:user._id.toString(),
                passwordToken : token
            });

        })
        .catch(err => console.log(err));


}


exports.postNewPassword = (req,res,next)=> {
    const newPassword = req.body.password;
    const userId = req.body.userId;
    const passwordToken = req.body.passwordToken;
    let resetUser;

    User.findOne({resetToken:passwordToken, resetTokenExpires:{$gt: Date.now()},_id:userId})
        .then(user => {
            resetUser = user;
            return bcrypt.hash(newPassword, 12);
        })
        .then(hashedPassword=>{
            resetUser.password = hashedPassword;
            resetUser.resetToken = undefined;
            resetUser.resetTokenExpires = undefined;
            return resetUser.save();
        })
        .then(result =>{
          res.redirect('/login');
        }).catch(err => console.log(err));

}