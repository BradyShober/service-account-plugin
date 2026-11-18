document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".service-account-delete-form").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });
});
