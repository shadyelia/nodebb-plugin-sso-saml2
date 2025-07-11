"use strict";

const user = require.main.require("./src/user");
const groups = require.main.require("./src/groups");
const db = require.main.require("./src/database");
const meta = require.main.require("./src/meta");
const winston = require.main.require("winston");
const bodyParser = require("body-parser");
const ssoProvider = require("./ssoProvider");

const ROLE_MAP = {
  "MDDAP-Portal-Admin": "administrators",
  //Add more roles as needed
};

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
    "/sso/assert",
    bodyParser.urlencoded({ extended: false }),
    async (req, res) => {
      winston.info("[sso-saml] Start call back from login");

      try {
        const samlResponse = await ssoProvider.assertLogin(req);
        const userData = normalizeSamlAttributes(samlResponse.user.attributes);

        winston.info("[sso-saml] User logged in with info", userData);

        const uid = await getOrCreateUser(userData);
        winston.info(`[sso-saml] Created new user: ${userData.Email}`);

        req.login({ uid }, async (err) => {
          if (err) {
            winston.error("[sso-saml] Login session error:", err);
            return res.redirect("/login");
          }

          req.session.save(async (err) => {
            if (err) {
              winston.error("[sso-saml] Session save error:", err);
              return res.redirect("/login");
            }

            const settings = await meta.settings.get("sso-saml");
            res.redirect(settings.loginsuccessredirecturl || "/");
          });
        });
      } catch (err) {
        winston.error("[sso-saml] SAML assertion error:", err);
        return res.redirect("/login");
      }
    }
  );
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

plugin.onLogout = async function ({ caller, uid } = {}) {
  const req = caller?.req;
  const res = caller?.res;

  if (!req || !res) {
    winston.warn(
      `[sso-saml] Logout for uid ${uid} skipped: req or res is missing`
    );
    return;
  }

  try {
    winston.info(
      `[sso-saml] Intercepting logout request for uid ${uid}, redirecting...`
    );

    const userInfo = await getUserInfo(uid); // getUserInfo expects sessionUser or { uid }
    const logoutUrl = await ssoProvider.generateLogoutUrl(userInfo);

    if (req.logout) req.logout();
    req.session?.destroy?.();

    res.redirect(logoutUrl);
  } catch (err) {
    winston.error(`[sso-saml] onLogout error for uid ${uid}:`, err);

    if (req.logout) req.logout();
    req.session?.destroy?.();

    res.redirect("/");
  }
};

function renderAdmin(_, res) {
  console.log("[sso-saml] start rendering admin page");

  res.render("admin/plugins/sso-saml", {});
}

function normalizeSamlAttributes(rawData) {
  const normalized = {};

  for (const key in rawData) {
    if (Array.isArray(rawData[key])) {
      normalized[key] = rawData[key][0];
    } else {
      normalized[key] = rawData[key];
    }
  }

  return normalized;
}

async function getOrCreateUser(samlUser) {
  const samlId = samlUser.ID || samlUser.Email;
  if (!samlId) throw new Error("Missing name_id or email in SAML response");

  let uid = await db.getObjectField("samlid:uid", samlId);

  if (!uid) {
    uid = await user.getUidByEmail(samlUser.Email);
    if (!uid) {
      uid = await user.create({
        username: samlUser.FirstName,
        email: samlUser.Email,
      });
    }

    await user.setUserField(uid, "samlid", samlId);
    await db.setObjectField("samlid:uid", samlId, uid);
  }

  // Map SAML roles to NodeBB group names
  const roles = samlUser.Roles?.split(",") || [];
  const groupsToJoin = roles
    .map((role) => role.trim())
    .map((role) => ROLE_MAP[role])
    .filter(Boolean);

  winston.info("[sso-saml] Mapped user groups", groupsToJoin);

  for (const group of groupsToJoin) {
    try {
      await groups.join(group, uid);

      winston.info(`[sso-saml] User ${uid} mapped to group "${group}"`);
    } catch (err) {
      winston.warn(
        `[sso-saml] Could not join group "${group}": ${err.message}`
      );
    }
  }

  return uid;
}

async function getUserInfo(sessionUserUID) {
  if (!sessionUserUID) return {};
  const samlId = await user.getUserField(sessionUserUID, "samlid");
  return {
    name_id: samlId,
    session_index: null,
  };
}

module.exports = plugin;
