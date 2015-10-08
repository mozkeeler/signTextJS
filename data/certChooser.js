// data is an object with the following properties:
//   domain: a string representing the domain that called signText
//   textToSign: the text being signed
//   certs: a map of nicknames to objects with the following properties:
//     nickname: the nickname of a certificate
//     subject: the subject of a certificate
//     issuer: the issuer of a certificate
//     token: the token the certificate lives on
//   cancelled: to be set to true if the user cancels the dialog
//   selectedCert: the nickname of the selected certificate
var data = window.arguments[0];
var headline = document.getElementById("headline");
headline.textContent = headline.textContent.replace("<site here>", data.domain);
var textArea = document.getElementById("text");
textArea.textContent = data.textToSign;
var certNicknames = document.getElementById("certNicknames");
for (var nickname in data.certs) {
  var option = document.createElement("option");
  option.setAttribute("value", nickname);
  option.textContent = nickname;
  certNicknames.appendChild(option);
}

// If the user closes the window without clicking "OK" or "Cancel",
// assume they wanted to cancel.
data.cancelled = true;

function selectPassword() {
  setTimeout(function(){ document.getElementById("certPassword").focus(); }, 100);
}

function displayCertDetails() {
  var selection = document.getElementById("certNicknames");
  data.selectedCert = selection.value;
  var certDetails = data.certs[selection.value];
  var detailsElement = document.getElementById("certDetails");
  detailsElement.textContent = "Issued to: " + certDetails.subject + "\n" +
                               "  Serial Number: " + certDetails.serialNumber + "\n" +
                               "  Valid from " + certDetails.notBefore + " to " +
                                                 certDetails.notAfter + "\n" +
                               "  Certificate Key Usage: " + certDetails.usagesString + "\n" +
                               "  Email: " + certDetails.email + "\n" +
                               "Issued by: " + certDetails.issuer + "\n" +
                               "Stored in: " + certDetails.token;
  selectPassword();
}

displayCertDetails();

function doOK() {
  data.cancelled = false;
  data.certPassword = document.getElementById("certPassword").value;
  window.close();
}

function doCancel() {
  window.close();
}

function keyboardListener(e) {
  // KeyCode 13 is Enter, and keyCode 27 is Escape key.
  if (e.keyCode === 13) {
    doOK();
  } else if (e.keyCode === 27) {
    doCancel();
  }
}

document.addEventListener("keydown", keyboardListener);
selectPassword();
