
window.onload = function () {
  const params = new URLSearchParams(window.location.search);
  const name = decodeURIComponent(params.get("name"));
  if (name) {
    // Intentionally vulnerable
    document.getElementById("output").innerHTML = "Hello, " + name;
  }
};

