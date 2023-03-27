const bcrypt = require('bcrypt');
const jwt = require ('jsonwebtoken');

const User = require('../models/User');


exports.signup = (req, res, next) => {
    //d'abord, on cherche un potentiel utilisateur déjà inscrit avec le même email
    const oldUser = User.findOne({ email: req.body.email })
      .then((oldUser) => {
        if (oldUser) {
          //un utilisateur inscrit avec le même email existe
          //-> on retourne une réponse sans aller plus loin
          return res.status(409).json({ message: 'There was an error' });
        } else {
          //pas d'utilisateur déjà inscrit avec le même email
          //-> on peut inscrire le nouvel utilisateur
          bcrypt
            .hash(req.body.password, 10)
            .then((hash) => {
              const newUser = new User({
                email: req.body.email,
                password: hash,
              });
              newUser
                .save()
                .then(() => {
                  res.status(201).json({ message: 'utilisateur créé' });
                })
                .catch((error) => res.status(400).json({ error }));
            })
            .catch((error) => res.status(500).json({ error }));
        }
      })
      .catch((error) => res.status(500).json({ error }));
  };

exports.login = (req, res, next) => {
   User.findOne({ email: req.body.email })
    .then(user => {
        if (!user) {
            return res.status(401).json({ message: 'Paire login/mot de passe incorrecte'})
        }
        bcrypt.compare(req.body.password, user.password)
        .then(valid => {
            if (!valid) {
                return res.status(401).json({ message: 'Paire login/mot de passe incorrect'})
            }
            res.status(200).json({
                userId: user._id,
                       token: jwt.sign(
                        { userId: user._id },
                           'RANDOM_TOKEN_SECRET',
                           { expiresIn: '24h' }
                       )
                   });
               })
               .catch(error => res.status(500).json({ error }));
       })
       .catch(error => res.status(500).json({ error }));
  };