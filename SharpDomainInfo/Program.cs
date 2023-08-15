using System;
using System.Collections.Generic;

namespace SharpDomainInfo
{
    class Program
    {


        static void Useage()
        {
            Console.WriteLine(@"Usage:
    SharpDomainInfo.exe -help
    SharpDomainInfo.exe -localdump
    SharpDomainInfo.exe -h dc-ip -u user -p password -d domain.com
    execute-assembly /path/to/SharpDomainInfo.exe -localdump");


        }

        static void Remotedump(string ip, string domain, string username, string password)
        {
            string dcString = "DC=" + domain.Replace(".", ",DC=");
            string ldapPath = "LDAP://" + ip + "/" + dcString;
            string ldapPath2 = "LDAP://" + ip + "/CN=Services,CN=Configuration," + dcString;
            string ldapPathdns = "LDAP://" + ip + $"/DC={domain},CN=MicrosoftDNS,DC=DomainDnsZones," + dcString;

            Remotequery.QueryLdap_getDC(ldapPath, ldapPathdns, username, password);
            Remotequery.QueryLdap_maq(ldapPath, username, password);
            Remotequery.QueryLdap_GetDomainAdmins(ldapPath, username, password);
            Remotequery.QueryLdap_admincountuser(ldapPath, username, password);
            Remotequery.QueryLdap_usernotd(ldapPath, username, password);
            Remotequery.QueryLdap_oulists(ldapPath, username, password);

            Remotequery.QueryLdap_userdescription(ldapPath, username, password);
            Remotequery.QueryLdap_computerdescription(ldapPath, username, password);

            Remotequery.QueryLdap_arpuser(ldapPath, username, password);
            Remotequery.QueryLdap_spnuser(ldapPath, username, password);

            //QueryDnsRecords(ldapPathdns, username, password, dNSHostName)
            Remotequery.QueryLdap_getservers(ldapPath, ldapPathdns, username, password);
            Remotequery.QueryLdap_UDelegationpc(ldapPath, ldapPathdns, username, password);
            Remotequery.QueryLdap_CDelegation(ldapPath, username, password);
            Remotequery.QueryLdap_RBCD(ldapPath, username, password);
            Remotequery.QueryLdap_createsid(ldapPath, username, password);

            Remotequery.QueryLdap_getADCS(ldapPath2, ldapPathdns,username, password);
            Remotequery.QueryLdap_getESC1(ldapPath2, username, password);

        }
        static void Localdump()
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


        }
        static void Banner()
        {
            Console.WriteLine("\n[*]SharpDomainInfo.exe");
            Console.WriteLine("    https://github.com/0neAtSec/SharpDomainInfo \n");
        }
        static void Main(string[] args)
        {
            Banner();
            if (args.Length == 0 || args[0] == "-help")
            {
                Useage();
                return;
            }

            if (args[0] == "-localdump")
            {
                // 执行localdump操作
                Localdump();
                return;
            }
            else
            {
                Dictionary<string, string> arguments = new Dictionary<string, string>();
                for (int i = 0; i < args.Length; i += 2)
                {
                    if (i + 1 < args.Length)
                    {
                        arguments[args[i]] = args[i + 1];
                    }
                }

                if (arguments.ContainsKey("-h") && arguments.ContainsKey("-u") && arguments.ContainsKey("-p") && arguments.ContainsKey("-d"))
                {
                    string ip = arguments["-h"];
                    string username = arguments["-u"];
                    string password = arguments["-p"];
                    string domain = arguments["-d"];

                    Remotedump(ip, domain, username, password);
                    return;
                }
                else
                {
                    Console.WriteLine("Invalid arguments. Use -help for usage information.");
                    return;
                }
            }


        }
    }
}
