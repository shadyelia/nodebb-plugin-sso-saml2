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

router.get("/auth/saml/logout", async (req, res) => {
  winston.info("[sso-saml] auth/saml/logout triggered");

  const uid = req.user?.uid;
  if (!uid) return res.redirect("/");

  const userInfo = await getUserInfo({ uid });
  const logoutUrl = await ssoProvider.generateLogoutUrl(userInfo);

  req.logout((err) => {
    if (err) {
      winston.error("[sso-saml] Logout error:", err);
    }

    req.session?.destroy((sessionErr) => {
      if (sessionErr) {
        winston.error("[sso-saml] Session destroy error:", sessionErr);
      }

      // Always redirect after cleanup
      winston.info(`[sso-saml] Redirecting to SAML logout URL: ${logoutUrl}`);
      res.redirect(logoutUrl);
    });
  });
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

// plugin.logout = async function (data) {
//   try {
//     winston.info("[sso-saml] action:user.logout hook triggered");
//     const { uid, req, res } = data;
//     winston.info("[sso-saml] data", uid, req, res);

//     if (!uid) {
//       winston.warn("[sso-saml] No user ID provided in logout hook");
//       return res.redirect("/");
//     }

//     const userInfo = await getUserInfo({ uid });
//     const logoutUrl = await ssoProvider.generateLogoutUrl(userInfo);
//     winston.info(`[sso-saml] Generated logout URL (hook): ${logoutUrl}`);

//     // Destroy session
//     if (req.session && req.session.destroy) {
//       await new Promise((resolve, reject) => {
//         req.session.destroy((err) => {
//           if (err) {
//             winston.error("[sso-saml] Error destroying session (hook):", err);
//             return reject(err);
//           }
//           winston.info("[sso-saml] Session destroyed (hook)");
//           res.clearCookie("connect.sid"); // Adjust cookie name if different
//           resolve();
//         });
//       });
//     } else {
//       res.clearCookie("connect.sid");
//     }

//     winston.info(`[sso-saml] Redirecting to (hook): ${logoutUrl}`);
//     return res.redirect(logoutUrl);
//   } catch (err) {
//     winston.error("[sso-saml] Logout hook error:", err);
//     return res.redirect("/");
//   }
// };

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

async function getUserInfo(sessionUser) {
  if (!sessionUser || !sessionUser.uid) return {};
  const samlId = await user.getUserField(sessionUser.uid, "samlid");
  return {
    name_id: samlId,
    session_index: null,
  };
}

module.exports = plugin;
