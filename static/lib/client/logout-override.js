"use strict";

define("sso-saml/logout-override", ["components"], function (components) {
  const overrideLogout = () => {
    const logoutComp = components.get("user/logout");
    if (!logoutComp) return;

    logoutComp.off("click").on("click", function (e) {
      e.preventDefault();
      window.location.href = "/auth/saml/logout";
    });
  };

  // Bind to ajaxify events (SPA-style navigation)
  require(["hooks"], function (hooks) {
    hooks.on("action:ajaxify.end", overrideLogout);
    overrideLogout();
  });
});
