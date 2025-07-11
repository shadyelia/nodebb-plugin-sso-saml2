$(document).ready(function () {
  $('[component="logout"]').on("click", function (e) {
    e.preventDefault();
    // Redirect to the new logout route
    window.location.href = "/auth/saml/logout";
  });
});
