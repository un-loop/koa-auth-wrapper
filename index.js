const passport = require('koa-passport');
const route = require('koa-route');
const compose = require('koa-compose');

module.exports = function({routes, encrypt, decrypt, localStrategy, changePassword}) {

    if (!encrypt || !decrypt || !localStrategy) {
        throw new Error('Invalid arguments');
    }

    if (!routes)  routes = {};
    if (!routes.login) routes.login = '/login'
    if (!routes.logout) routes.logout = '/logout'
    if (!routes.changePassword) routes.changePassword = '/account/changePassword/'
    if (!routes.signUp) routes.signUp = '/signup';

    passport.serializeUser(function(user, done) {
        try {
            const data = encrypt(JSON.stringify(user));
            const buffer = new Buffer(JSON.stringify(data));

            done(null, buffer.toString('base64'));
        } catch(err) {
            done(err);
        }
    });

    passport.deserializeUser(function(data, done) {
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

    const authenticateMiddleware = (ctx, next) => {
        const successRedirect = ctx.request.body.redirect || '/';
        const failureRedirect = `${routes.login}?message=${encodeURI("invalid username or password")}`;

        return passport.authenticate('local', { successRedirect, failureRedirect })(ctx, next);
    }

    const logoutMiddleware = (ctx) => {
        if (!ctx.isAuthenticated()) {
            ctx.body = "Not Authorized";
            ctx.throw(401);
        }

        ctx.logout();
        ctx.redirect(routes.login);
    }

    const changePasswordMiddleware = async (ctx) => {
        if (!ctx.isAuthenticated() || !ctx.request.body || !ctx.request.body.password) {
            ctx.body = "Not Authorized";
            ctx.throw(401);
        }

        let password = ctx.request.body.password;
        let newPassword = ctx.request.body.newPassword;
        await changePassword(ctx.req.user, password, newPassword)
            .then((result) => 
            {
                if (!result) {
                    ctx.body = "Not Authorized";
                    ctx.throw(401);
                }

                ctx.body = "Success";
                ctx.status = 200;
            }).catch( () => {
                ctx.body = "Internal Error";
                ctx.status = 500;
            });
    }

    this.middleware = () => {
        return compose([
            passport.initialize(),
            passport.session(),
            route.post(routes.login, authenticateMiddleware),
            route.get(routes.logout, logoutMiddleware),
            changePassword && route.post(routes.changePassword, changePasswordMiddleware)
        ]);
    }
}
