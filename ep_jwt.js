var jwt = require("jsonwebtoken");

var authorManager = require("ep_etherpad-lite/node/db/AuthorManager");
var settings = require("ep_etherpad-lite/node/utils/Settings");

function setUsername(token, username) {
  console.log("ep_jwt.setUsername: getting author_id for token %s", token);
  authorManager.getAuthor4Token(token).then(function (author_id) {
    console.log('ep_jwt.setUsername: have authorid %s, setting username to "%s"', author_id, username);
    authorManager.setAuthorName(author_id, username);
  });
  return;
}

exports.authenticate = function (hook_name, context, cb) {
  console.log("ep_jwt.authenticate");
  if (context.req.cookies.token) {
    jwt.verify(context.req.cookies.token, settings.users.jwt.secret, (e, decoded) => {
      // console.log("ep_jwt.authenticate", e, decoded);
      if (!e) {
        console.log("ep_jwt.authenticate: successful authentication");
        settings.globalUserName = decoded.username;
        context.req.session.user = decoded;
        if (context.resource.match(/^\/admin/)) {
          console.log("ep_jwt.authenticate: attempting to authenticate along administrative path %s", context.resource);
          if (decoded.username && -1 < settings.users.jwt.admins.indexOf(decoded.username)) {
            console.log("ep_jwt.authenticate: username %s, is_admin", decoded.username);
            context.req.session.user.is_admin = true;
          }
        }
        return cb([true]);
      } else {
        console.log("ep_jwt.authenticate: failed authentication no token cookies");
        context.res.redirect(settings.users.jwt.redirect_url);
        return cb([false]);
      }
    });
  } else {
    console.log("ep_jwt.authenticate: failed authentication no token cookies");
    context.res.redirect(settings.users.jwt.redirect_url);
    return cb([false]);
  }
};

exports.authorize = function (hook_name, context, cb) {
  console.log("ep_jwt.authorize");
  if (/^\/(static|javascripts|pluginfw|favicon.ico|api)/.test(context.resource)) {
    console.log("ep_jwt.authorize: authorizing static path %s", context.resource);
    return cb([true]);
  } else {
    jwt.verify(context.req.cookies.token, settings.users.jwt.secret, (e, decoded) => {
      // console.log("ep_jwt.authorize", e, decoded);
      if (!e) {
        console.log("ep_jwt.authorize: successful authorization");
        // if (context.resource.match(/^\/admin/)) {
        //   console.log("ep_jwt.authorize: attempting to authorize along administrative path %s", context.resource);
        //   if (decoded.username && -1 < settings.users.jwt.admins.indexOf(decoded.username)) {
        //     console.log("ep_jwt.authorize: username %s, is_admin", decoded.username);
        //     context.req.session.user.is_admin = true;
        //   }
        // }
        return cb([true]);
      } else {
        console.log("ep_jwt.authorize: failed authorization no token cookies");
        context.res.redirect(settings.users.jwt.redirect_url);
        return cb([false]);
      }
    });
  }
};

exports.handleMessage = function (hook_name, context, cb) {
  console.log("ep_jwt.handleMessage");
  if (context.message.type == "CLIENT_READY") {
    if (!context.message.token) {
      console.log("ep_jwt.handleMessage: intercepted CLIENT_READY message has no token!");
    } else {
      console.log("ep_jwt.handleMessage: intercepted CLIENT_READY message for client_id %s, setting username for token %s", context.client.id, context.message.token);
      jwt.verify(context.message.token, settings.users.jwt.secret, (e, decoded) => {
        // console.log("ep_jwt.handleMessage", e, decoded);
        if (!e && decoded.username) setUsername(context.message.token, decoded.username);
      });
    }
  } else if (
    context.message.type == "COLLABROOM" &&
    context.message.data.type == "USERINFO_UPDATE"
  ) {
    console.log("ep_jwt.handleMessage: intercepted USERINFO_UPDATE and dropping it!");
    return cb([null]);
  }
  return cb([context.message]);
};
