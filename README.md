# What
Generates self-signed certificate to be used with websites with ease.
This generates a private CA. Using that it issues certificate to DNS & IP Addresses. 
So using the same CA one can issue many certificate for different websites/ web services.

# Why
To avoid complex process of generating self-signed certificate that works on modern devices.
For many people this is a bit confusing and sometimes hard to do. 
This will help generate the certificate & CA in very easy way.

# Use-case
This can be useful in some cases where SSL is necessary but is not (easily) possible to use a real SSL certificate or 
just don't want purchase a real certificate. In our case - <br />
We've some applications which want to print from web to users local printer.
Their printer is available in their local network & open for everybody in the network.
As our site is using SSL but users local network printers aren't. This is a problem,
By default browsers intercept connecting to insecure endpoints from secure sites.
Our goal -<br />
Issue a certificate from our Local CA to some of our customers.
Then they can install that certificate in the printer & also install the root certificate (not the CA cert)
in their device (in which they use our web application). So our application can securely connect with their printer &
do the printing. <br />
Obviously for the printing to happen there's lot more needed but those are out of this project's context.

# How to
WIll be available once this reaches MVP