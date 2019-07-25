const passport = require('koa-passport');
const route = require('koa-route');
const compose = require('koa-compose');

// using 403 responses per this thread: https://stackoverflow.com/a/14713094/4488100

module.exports = function({routes, encrypt, decrypt, localStrategy, updateUser, changePassword, changeAccountDetails}) {

    if (!encrypt || !decrypt || !localStrategy) {
        throw new Error('Invalid arguments');
    }

    if (!routes) routes = {};
    if (!routes.login) routes.login = '/login'
    if (!routes.logout) routes.logout = '/logout'
    if (!routes.changePassword) routes.changePassword = '/account/changePassword/'
    if (!routes.changeAccountDetails) routes.changeAccountDetails = '/account/changeAccountDetails/';
    if (!routes.refreshUserContext) routes.refreshUserContext = '/account/refreshUserContext';
    if (!routes.signUp) routes.signUp = '/signup';

    const serializeData = (data) => {
        const encdata = encrypt(JSON.stringify(data));
        const buffer = new Buffer(JSON.stringify(encdata));
        return buffer.toString('base64');
    }

    const deserializeData = (data) => {
        const buffer = new Buffer(data, 'base64');
        const dataObj = JSON.parse(buffer.toString('utf8'));
        const decryptedData = decrypt(dataObj);
        return JSON.parse(decryptedData);
    }

    const renewUser = async function(req, user) {
        Object.assign(user, await updateUser(user));
        req.session.user = serializeData(user); //HACK alert -- update the user for the session
        req._passport.session.user = req.session.user; //HACK alert -- update the passport user, will be sent to cookie
    };

    passport.serializeUser(function(user, done) {
        try {
            const result = serializeData(user);

            done(null, result);
        } catch(err) {
            done(err);
        }
    });

    passport.deserializeUser(async function(req, data, done) {
        try {
            let user = deserializeData(data);

            if (req.ctx.refreshUser) {
                try {
                    await renewUser(req, user);
                    done(null, user);
                } catch(ex) {
                    done(ex);
                }

            } else {
                done(null, user);
            }
        } catch(err) {
          req.logout();
          req.redirect(routes.login);
        }
    });

    //todo: implement a jwt strategy. See https://medium.com/@rob.s.ellis/koa-api-secured-with-passport-jwt-2fd2d32771bd,
    // https://www.npmjs.com/package/jsonwebtoken
    const LocalStrategy = require('passport-local').Strategy;
    passport.use(new LocalStrategy(function(username, password, done) {
            localStrategy(username, password)
            .then((result) => {
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
            ctx.throw(403);
        }

        ctx.logout();
        ctx.redirect(routes.login);
    }

    const changePasswordMiddleware = async (ctx) => {
        if (!ctx.isAuthenticated() || !ctx.request.body || !ctx.request.body.password) {
            ctx.body = "Not Authorized";
            ctx.throw(403);
        }

        let password = ctx.request.body.password;
        let newPassword = ctx.request.body.newPassword;

        if (password === newPassword) {
            ctx.body = "Must select a new password";
            ctx.throw(400);
        }

        await changePassword(ctx.req.user, password, newPassword)
            .then((result) =>
            {
                if (!result) {
                    ctx.body = "Not Authorized";
                    ctx.throw(403);
                }

                ctx.body = "Success";
                ctx.status = 200;
            });
    }

    const changeAccountDetailsMiddleware = async (ctx) => {
        if (!ctx.isAuthenticated() || !ctx.request.body || !ctx.request.body.password) {
            ctx.body = "Not Authorized";
            ctx.throw(403);
        }

        const {password, confirm, ...details} = ctx.request.body;

        await changeAccountDetails(ctx.req.user, details, password)
            .then((result) =>
            {
                if (!result) {
                    ctx.body = "Not Authorized";
                    ctx.throw(403);
                }

                ctx.body = "Success";
                ctx.status = 200;
            });

        }

    const refreshUserContextMiddleware = async (ctx, next) => {
        ctx.refreshUser = true;
        await next();

        ctx.status = 204; //no-content, just server action+cookie
        ctx.body = "";
    }

    this.middleware = () => {

        const middleware = [
            passport.initialize(),
            route.post(routes.refreshUserContext, refreshUserContextMiddleware), //needs to be before passport.session middleware
            passport.session(),
            route.post(routes.login, authenticateMiddleware),
            route.get(routes.logout, logoutMiddleware),
            changePassword && route.post(routes.changePassword, changePasswordMiddleware),
            changeAccountDetails && route.post(routes.changeAccountDetails, changeAccountDetailsMiddleware)
        ].filter(m => m);

        return compose(middleware);
    }
}
