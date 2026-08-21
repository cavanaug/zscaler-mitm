// Classic script (not module): runs even if popup.js fails to load.
setTimeout(function () {
  var d = document.getElementById('debug');
  if (d && d.textContent === 'starting…') {
    d.hidden = false;
    d.textContent = 'popup.js did not start — reload the extension on chrome://extensions';
  }
}, 2000);
