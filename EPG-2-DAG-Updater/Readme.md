# ACI EGP TO PANW DAG UPDATER

This example code may be used capture select ACI EPG learned Endpoints and populate PANW Dynamic Address Groups.  The script assumes the following information is defined:

* Tenant that the EPG's reside in.
* EPG Name.
* Firewall VSYS that the DAG should be placed in.

What the script does:
Creates a DAG if one does not exist in the format "tenant--EPG" in the defined PANW vsys.  Extracts the Learned Enpoint information from the APIC controller and checks to see if the firewall has correct entries.  If additions for deletions are needed the script creates an API call to make the appropriate changes.  A firewall commit is not required unless Address Objects need to be added or removed.

Support Policy

This template is released under an as-is, best effort, support policy. It should be seen as community supported and Palo Alto Networks will contribute our expertise as and when possible. We do not provide technical support or help in using or troubleshooting the components of the project through our normal support options such as Palo Alto Networks support teams, or ASC (Authorized Support Centers) partners and backline support options. The underlying product used by the scripts or templates are still supported, but the support is only for the product functionality and not for help in deploying or using the template or script itself. Unless explicitly tagged, all projects or work posted in our GitHub repository (at https://github.com/PaloAltoNetworks) or sites other than our official Downloads page on https://support.paloaltonetworks.com are provided under the best effort policy.
