using System;

namespace SharpDomainInfo
{
    class Program
    {


        static void Useage() {
            Console.WriteLine(@"Usage:
    SharpDomainInfo.exe -help
    SharpDomainInfo.exe -dump
    execute-assembly /path/to/SharpDomainInfo.exe -dump");
        
        
        }

        static void Banner()
        {
            Console.WriteLine("\n[*]SharpDomainInfo.exe");
            Console.WriteLine("    https://github.com/0neAtSec/SharpDomainInfo \n");
        }
        static void Main(string[] args)
        {
            Banner();
            
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-dump")
                {

                    string ldapPath = Localquery.GetLdapAddress();

                    Localquery.QueryLdap_getDC(ldapPath);
                    Localquery.QueryLdap_maq(ldapPath);
                    Localquery.QueryLdap_GetDomainAdmins(ldapPath);
                    Localquery.QueryLdap_admincountuser(ldapPath);
                    Localquery.QueryLdap_usernotd(ldapPath);
                    Localquery.QueryLdap_oulists(ldapPath);

                    Localquery.QueryLdap_userdescription(ldapPath);
                    Localquery.QueryLdap_computerdescription(ldapPath);

                    Localquery.QueryLdap_arpuser(ldapPath);
                    Localquery.QueryLdap_spnuser(ldapPath);




                    Localquery.QueryLdap_getservers(ldapPath);
                    Localquery.QueryLdap_UDelegationpc(ldapPath);
                    Localquery.QueryLdap_CDelegation(ldapPath);
                    Localquery.QueryLdap_RBCD(ldapPath);
                    Localquery.QueryLdap_createsid(ldapPath);

                    Localquery.QueryLdap_getADCS(ldapPath);
                    Localquery.QueryLdap_getESC1(ldapPath);

                    return;
                }
                else
                {
                    Useage();
                    return;
                }
                
            }
            
        }
    }
}
