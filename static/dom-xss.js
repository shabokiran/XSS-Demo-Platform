/*function inject() {
    const val = document.getElementById('input').value;
    const clean = DOMPurify.sanitize(val); // Sanitize input using DOMPurify
    document.getElementById('output').innerHTML = clean;
  }
  function inject() {
  const val = document.getElementById('input').value;
  // Vulnerable (no sanitization)
  document.getElementById('output').innerHTML = val;
  // Optional fix (uncomment to protect)
  // document.getElementById('output').innerHTML = DOMPurify.sanitize(val);
}
*/


window.onload = function() {
  const params = new URLSearchParams(window.location.search);
  const name = params.get('name');
  
  if (name) {
      // Vulnerable DOM injection (demonstration purpose)
      document.getElementById("output").innerHTML = "Hello, " + name;
  }
};
