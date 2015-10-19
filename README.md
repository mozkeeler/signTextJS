signTextJS
==========

re-implements window.crypto.signText and exposes it to content

How-To
------
Install and activate the Firefox Add-On SDK following the directions
[here](https://developer.mozilla.org/en-US/Add-ons/SDK/Tutorials/Installation).
Then, after checking out this repo, use `cfx run` to run Firefox with the
add-on installed or `cfx xpi` to package the addon. After the add-on has been
installed, content scripts that call `window.crypto.signText` should "just
work".
Alternatively, download and install the prepackaged xpi [here](signtextjs.xpi).

TODO
----
See [issues](https://github.com/mozkeeler/signTextJS/issues).
