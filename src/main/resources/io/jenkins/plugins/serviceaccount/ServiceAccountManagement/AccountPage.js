document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".service-account-delete-form").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      var confirmationMessage =
        "Permanently delete this account and all of its credentials?";
      if (!window.confirm(confirmationMessage)) {
        event.preventDefault();
      }
    });
  });
});
