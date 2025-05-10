

window.onload = function() {
  const params = new URLSearchParams(window.location.search);
  const name = params.get('name');
  
  if (name) {
      // Vulnerable DOM injection (demonstration purpose)
      document.getElementById("output").innerHTML = "Hello, " + name;
  }
};
