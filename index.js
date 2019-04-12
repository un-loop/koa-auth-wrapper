const passport = require('koa-passport');
const route = require('koa-route');
const compose = require('koa-compose');

module.exports = function({login, logout, encrypt, decrypt, localStrategy}) {

    if (!login || !logout || !encrypt || !decrypt || !localStrategy) {
        throw new Error('Invalid arguments');
    }

    passport.serializeUser(function(user, done) {
        try {
            const data = encrypt(JSON.stringify(user));
            const buffer = new Buffer(JSON.stringify(data));

            done(null, buffer.toString('base64'));
        } catch(err) {
            done(err);
        }
    });

    passport.deserializeUser(async function(data, done) {
        try {
            const buffer = new Buffer(data, 'base64');
            const dataObj = JSON.parse(buffer.toString('utf8'));
            const decryptedData = decrypt(dataObj);
            const user = JSON.parse(decryptedData);
            done(null, user);
        } catch(err) {
          done(err);
        }
    });

    //todo: implement a jwt strategy. See https://medium.com/@rob.s.ellis/koa-api-secured-with-passport-jwt-2fd2d32771bd,
    // https://www.npmjs.com/package/jsonwebtoken
    const LocalStrategy = require('passport-local').Strategy;
    passport.use(new LocalStrategy(function(username, password, done) {
            localStrategy(username, password)
            .then((result) =>
                {
                    return done(null, result);
                })
            .catch(done)
    }));

    const authenticateMiddleware = (login) => (ctx, next) => {
        const successRedirect = ctx.request.body.redirect || '/';
        const failureRedirect = `${login}?message=${encodeURI("invalid username or password")}`;

        return passport.authenticate('local', { successRedirect, failureRedirect })(ctx, next);
    }

    this.middleware = () => {
          return compose([
              passport.initialize(),
              passport.session(),
              route.post(login, authenticateMiddleware(login)),
              route.get(logout, function(ctx) {
                if (ctx.isAuthenticated()) {
                    ctx.logout();
                    ctx.redirect(login);
                  } else {
                    ctx.body = "Not Authorized";
                    ctx.throw(401);
                  }
              })
          ]);
    }
}
