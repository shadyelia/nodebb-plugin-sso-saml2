"use strict";

const user = require.main.require("./src/user");
const groups = require.main.require("./src/groups");
const db = require.main.require("./src/database");
const meta = require.main.require("./src/meta");
const winston = require.main.require("winston");
const bodyParser = require("body-parser");
const ssoProvider = require("./ssoProvider");

const plugin = {};

plugin.init = async function ({ router, middleware }) {
  winston.info("[sso-saml] Start init SAML 2");

  router.get(
    "/admin/plugins/sso-saml",
    middleware.admin.buildHeader,
    renderAdmin
  );
  router.get("/api/admin/plugins/sso-saml", renderAdmin);

  router.get("/auth/saml", async (_, res) => {
    try {
      winston.info("[sso-saml] Start generating login URL");

      const loginUrl = await ssoProvider.generateLoginUrl();
      return res.redirect(loginUrl);
    } catch (err) {
      winston.error("[sso-saml] Error generating login URL:", err);
      return res.status(500).send("Login Error");
    }
  });

  router.post(
    "/auth/saml/callback",
    bodyParser.urlencoded({ extended: false }),
    async (req, res) => {
      winston.info("[sso-saml] Start call back from login");

      try {
        const samlResponse = await ssoProvider.assertLogin(req);
        const userData = samlResponse.user;

        const uid = await getOrCreateUser(userData);
        req.login({ uid }, async (err) => {
          if (err) {
            winston.error("[sso-saml] Login session error:", err);
            return res.redirect("/login");
          }

          const settings = await meta.settings.get("sso-saml");
          res.redirect(settings.loginsuccessredirecturl || "/");
        });
      } catch (err) {
        winston.error("[sso-saml] SAML assertion error:", err);
        return res.redirect("/login");
      }
    }
  );

  router.get("/auth/saml/logout", async (req, res) => {
    try {
      winston.info("[sso-saml] Start logout the user");

      const userInfo = await getUserInfo(req.user);
      const logoutUrl = await ssoProvider.generateLogoutUrl(userInfo);

      if (req.logout) req.logout();
      res.redirect(logoutUrl);
    } catch (err) {
      winston.error("[sso-saml] Logout error:", err);
      res.redirect("/");
    }
  });
};

plugin.getStrategy = async function (strategies) {
  strategies.push({
    name: "saml 2",
    url: "/auth/saml",
    callbackURL: "/auth/saml/callback",
    icon: "fa-sign-in-alt",
    scope: "",
  });

  return strategies;
};

plugin.overrideLogin = async function (data) {
  data.templateData.register_button = {
    url: "/auth/saml",
    text: "Login with CMMI SSO",
    icon: "fa-sign-in-alt",
  };
  return data;
};

plugin.addAdminNavigation = function (header) {
  header.authentication.push({
    route: "/plugins/sso-saml",
    icon: "fa-tint",
    name: "SAML 2",
  });

  return header;
};

function renderAdmin(_, res) {
  console.log("[sso-saml] start rendering admin page");

  res.render("admin/plugins/sso-saml", {});
}

async function getOrCreateUser(samlUser) {
  const samlId = samlUser.name_id || samlUser.email;
  if (!samlId) throw new Error("Missing name_id or email in SAML response");

  let uid = await db.getObjectField("samlid:uid", samlId);

  if (!uid) {
    uid = await user.getUidByEmail(samlUser.email);
    if (!uid) {
      uid = await user.create({
        username: samlUser.display_name || samlUser.name_id || samlUser.email,
        email: samlUser.email,
      });
    }

    await user.setUserField(uid, "samlid", samlId);
    await db.setObjectField("samlid:uid", samlId, uid);
  }

  // Optional: Assign groups based on roles
  const roles = Array.isArray(samlUser.roles) ? samlUser.roles : [];
  for (const role of roles) {
    const group = roleToGroupName(role);
    try {
      await groups.join(group, uid);
    } catch (err) {
      winston.warn(
        `[sso-saml] Could not join group "${group}": ${err.message}`
      );
    }
  }

  return uid;
}

function roleToGroupName(role) {
  const roleMap = {
    admin: "administrators",
    mod: "moderators",
    member: "registered-users",
  };

  return roleMap[role.toLowerCase()] || role.toLowerCase();
}

async function getUserInfo(sessionUser) {
  if (!sessionUser || !sessionUser.uid) return {};
  const samlId = await user.getUserField(sessionUser.uid, "samlid");
  return {
    name_id: samlId,
    session_index: sessionUser.sessionIndex || null, // if your IDP uses session_index
  };
}

module.exports = plugin;
