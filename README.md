Windows Firewall - Create Dynamic Block Lists based on Country

Used to deploy and update the Windows host based firewall solution which will block Russia (IPv4/IPv6), China(IPv4/IPv6), North Korea(IPv4), South Korea (IPv4/IPv6) and content from exteranl intel sources such as TOR Exit IP Addresses, Bulletproof IP Addresses, High-Risk IP Addresses and Known Malicious IP Addresses.

Use

 Deploy-Solution.ps1 - Deploys this solution

Deploy-Update.ps1 - Deploys solution and runs daily to get dynamic content

Firewall-Block.ps1 - Creates and deletes the rules

