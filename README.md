C# implementation of Lyndir's open source project 'Master Password App' 
(https://github.com/Lyndir/MasterPassword)
 
Key derivation was achieved using Chris McKee's CryptSharp Library
(https://www.nuget.org/packages/CryptSharp/)
 
Written By: James Booth
(mailto:jimbojetset35@gmail.com)

Example C# usage:
  MasterPasswordClass mpc = new MasterPasswordClass();
  SecureString secureUserName = mpc.GenerateSecureString("User Name");
  SecureString securePassword = mpc.GenerateSecureString("P@ssw0rd");   SecureString secureWebsite = mpc.GenerateSecureString("https://www.reddit.com");   int siteCounter = 1;
  String password = mpc.GetPasswordPattern(secureUserName, securePassword, secureWebsite, siteCounter, MasterPasswordClass.templateTypes.Long);
