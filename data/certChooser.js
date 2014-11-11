var args = window.arguments.slice();
var domain = args.shift();
var headline = document.getElementById("headline");
headline.textContent = headline.textContent.replace("<site here>", domain);
var textToSign = args.shift();
var textArea = document.getElementById("text");
textArea.textContent = textToSign;
var certNicknames = document.getElementById("certNicknames");
var certs = {};
while (args.length > 0) {
  var option = document.createElement("option");
  var nickname = args.shift();
  option.setAttribute("value", nickname);
  option.textContent = nickname;
  certNicknames.appendChild(option);
  var subject = args.shift();
  var issuer = args.shift();
  var token = args.shift();
  certs[nickname] = {
    subject: subject,
    issuer: issuer,
    token: token
  };
}

function displayCertDetails() {
  var selection = document.getElementById("certNicknames");
  var certDetails = certs[selection.value];
  var detailsElement = document.getElementById("certDetails");
  detailsElement.textContent = "Issued to: " + certDetails.subject + "\n" +
                               "Issued by: " + certDetails.issuer + "\n" +
                               "Stored in: " + certDetails.token;
}

displayCertDetails();
