twostep
=======

Google Two-Step Authenticator for Pebble


This is very much a WIP.  Why?

-There's no way to enter your secret phrase without recompiling the application
-...and the Pebble only reports local time, not GMT, so you have to enter an offset in the source
-...which means you have to download the source, make changes to src/twostep.c, and recompile for a .pbw specific to your account
-...and if you cross time zones or there's a DST change you'll need to rebuild the app again
-I don't have a base32-to-base64 conversion function yet, so if you have your secret in base32 (i.e. from the URL) you'll need to convert it by hand

More to come later...
