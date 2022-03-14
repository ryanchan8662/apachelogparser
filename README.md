# apachelogparser

This program was built to process the hundreds of requests sent to my personally hosted server.
Since many of these requests were vulnerability probes, it would be best to filter them out using an .htaccess file or Apache root permissions. 
An additional benefit is to get an overview of the requests and demographics of the visitors visiting the site. This program includes an API call for every IP visited, recording their city and country on the printout. 

For now, this works locally on the computer and produces a printout of the new updated .htaccess file. Copy+paste the new IP denys and blocks into your .htaccess file. This can easily be modified to work by inverting the regex keys to allow only the permitted files/directories.

Key notes:
- Colour formatting works on Linux or Powershell: if you see strange characters, don't use Command Prompt.
- API call(s) combines all request IPs into groups of up to 100 IPs, and sends them to a free access point. Program will likely freeze for a while here.
- Slashes (for directory navigation) ONLY work with Windows. To ensure compatibility with Linux, change the "systemSlash" string to "\\" before compile of Display.java.
