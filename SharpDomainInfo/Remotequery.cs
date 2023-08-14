using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace SharpDomainInfo
{
    class Remotequery
    {
        public static string geturl(string url)
        {

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.UserAgent = @"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36";
            request.Timeout = 5000;
            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    return ((int)response.StatusCode).ToString();
                }
            }
            catch (WebException ex)
            {
                if (ex.Response is HttpWebResponse errorResponse)
                {
                    return ((int)errorResponse.StatusCode).ToString();
                }
                else
                {
                    return "error";
                }
            }
        }
        public static string QueryDnsRecords(string ldapPath, string username, string password, string dNSHostName)
        {

            try
            {

                DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);

                DirectorySearcher searcher = new DirectorySearcher(entry);

                string dc = dNSHostName.Substring(0, dNSHostName.IndexOf("."));

                searcher.Filter = $"(&(objectClass=dnsNode)(dc={dc})(dnsRecord=*))";

                foreach (SearchResult result in searcher.FindAll())
                {
                    // 处理结果
                    
                    if (result.Properties.Contains("dnsRecord"))
                    {
                        foreach (byte[] dnsRecord in result.Properties["dnsRecord"])
                        {
                            // 处理dnsRecord
                            BitConverter.ToString(dnsRecord);
                            string[] hexValues = BitConverter.ToString(dnsRecord).Split('-');
                            int[] decimalValues = new int[hexValues.Length];
                            for (int i = 0; i < hexValues.Length; i++)
                            {
                                decimalValues[i] = Convert.ToInt32(hexValues[i], 16);
                            }
                            string ipAddress = string.Join(".", decimalValues.Skip(decimalValues.Length - 4).Take(4));
                            return ipAddress;
                        }
                    }
                }
            }
            catch { return null; }
            return null;


        }
        public static void QueryLdap_getESC1(string ldapPath, string username, string password)
        {
            //ESC1
            
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = @"(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspki-certificate-name-flag:1.2.840.113556.1.4.804:=1)(!(cn=OfflineRouter))(!(cn=CA))(!(cn=SubCA)))";
            Console.WriteLine("[*]ESC1-vulnerability-template: ");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果
                //Console.WriteLine(result.Path);
                if (result.Properties.Contains("cn"))
                    Console.WriteLine(result.Properties["cn"][0]);
                Console.WriteLine("");
            }
        }
        public static void QueryLdap_getADCS(string ldapPath, string ldapPathdns, string username, string password)
        {
            //ADCS - ip
            
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = "(&(objectCategory=pKIEnrollmentService))";

            Console.WriteLine("[*]ADCS - ips:");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                //处理结果
                if (result.Properties.Contains("cn"))
                    Console.WriteLine($"Root CA: " + (string)result.Properties["cn"][0]);

                if (result.Properties.Contains("dNSHostName"))
                {
                    string dNSHostName = (string)result.Properties["dNSHostName"][0];
                    string ADCS_ip = QueryDnsRecords(ldapPathdns, username, password, dNSHostName);
                    string url = "http://" + ADCS_ip + "/certsrv/certfnsh.asp";
                    Console.WriteLine(dNSHostName + " - " + ADCS_ip);
                    Console.WriteLine($"[{geturl(url)}]" + url);
                }
                Console.WriteLine("");
            }
        }
        public static void QueryLdap_createsid(string ldapPath, string username, string password)
        {
            //mS-DS-CreatorSID
            string query = @"(&(objectClass=computer)(mS-DS-CreatorSID=*))";
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = query;
            Console.WriteLine("[*]mS-DS-CreatorSID: ");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果
                //Console.WriteLine(result.Path);
                if (result.Properties.Contains("sAMAccountName"))
                {
                    SecurityIdentifier sid = new SecurityIdentifier((byte[])result.Properties["mS-DS-CreatorSID"][0], 0);
                    Console.WriteLine($"{GetSamAccountNameFromSid(ldapPath, username, password, sid.Value)} -add-> {result.Properties["sAMAccountName"][0]}");
                }

                Console.WriteLine("");
            }
        }

        public static void QueryLdap_RBCD(string ldapPath, string username, string password)
        {
            //find RBCD
            string query = @"(&((sAMAccountName=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*)))";
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = query;
            Console.WriteLine("[*]Resource Based Constrained Delegation (RBCD):");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果


                Console.WriteLine(result.Properties["sAMAccountName"][0] + " <==");

                var act = (byte[])result.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"][0];
                var sd = new RawSecurityDescriptor(act, 0);
                foreach (var ace in sd.DiscretionaryAcl)
                {
                    if (ace is CommonAce commonAce)
                    {
                        string sid = commonAce.SecurityIdentifier.Value;
                        string samAccountName = GetSamAccountNameFromSid(ldapPath, username, password, sid);
                        Console.WriteLine(samAccountName);
                    }
                    else if (ace is QualifiedAce qualifiedAce)
                    {
                        string sid = qualifiedAce.SecurityIdentifier.Value;
                        string samAccountName = GetSamAccountNameFromSid(ldapPath, username, password, sid);
                        Console.WriteLine(samAccountName);
                    }
                }

                Console.WriteLine("");

            }
        }

        public static string GetSamAccountNameFromSid(string ldapPath, string username, string password, string sid)
        {
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = $"(objectSid={sid})";
            searcher.PropertiesToLoad.Add("sAMAccountName");
            SearchResult result = searcher.FindOne();
            if (result != null)
            {
                return result.Properties["sAMAccountName"][0].ToString();
            }
            else
            {
                return null;
            }
        }
        public static void QueryLdap_CDelegation(string ldapPath, string username, string password)
        {
            //约束委派
            string query = @"(&(sAMAccountName=*)(msDS-AllowedToDelegateTo=*))";
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = query;
            Console.WriteLine("[*]Constrained Delegation:");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果
                Console.WriteLine(result.Properties["sAMAccountName"][0] + " ==>");
                foreach (object value in result.Properties["msDS-AllowedToDelegateTo"])
                {
                    Console.WriteLine(value);
                }
                Console.WriteLine("");
            }
        }

        public static void QueryLdap_UDelegationpc(string ldapPath, string ldapPathdns, string username, string password)
        {
            //非约束委派主机
            string query = @"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))";
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = query;
            Console.WriteLine("[*]Unconstrained Delegation Computer:");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果

                if (result.Properties.Contains("dNSHostName"))
                {
                    string dNSHostName = (string)result.Properties["dNSHostName"][0];
                    Console.WriteLine(dNSHostName + " - " + QueryDnsRecords(ldapPathdns, username, password, dNSHostName));
                }

                if (result.Properties.Contains("operatingSystem"))
                    Console.WriteLine(result.Properties["operatingSystem"][0]);
                Console.WriteLine("");
            }
        }

        public static void QueryLdap_getservers(string ldapPath, string ldapPathdns, string username, string password)
        {
            //servers - ip
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))";

            Console.WriteLine("[*]Look for places (servers) to move laterally - ips:");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果

                if (result.Properties.Contains("dNSHostName"))
                {
                    string dNSHostName = (string)result.Properties["dNSHostName"][0];
                    Console.WriteLine(dNSHostName + " - " + QueryDnsRecords(ldapPathdns, username, password, dNSHostName));
                    
                }
                //operatingSystem
                if (result.Properties.Contains("operatingSystem"))
                    Console.WriteLine(result.Properties["operatingSystem"][0]);

            }
            Console.WriteLine("");
        }
        public static void QueryLdap_spnuser(string ldapPath, string username, string password)
        {
            //Kerberoastable Users
            string query = @"(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(samaccounttype=805306369)))";
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = query;
            Console.WriteLine("[*]Kerberoastable Users:");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果

                if (result.Properties.Contains("sAMAccountName"))
                    Console.WriteLine("sAMAccountName: " + result.Properties["sAMAccountName"][0]);

                Console.WriteLine("");
            }
        }



        public static void QueryLdap_arpuser(string ldapPath, string username, string password)
        {

            //不做kerberos预认证
            string query = @"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = query;
            Console.WriteLine("[*]Kerberos Pre-Authentication Disabled:");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果

                if (result.Properties.Contains("sAMAccountName"))
                    Console.WriteLine("sAMAccountName: " + result.Properties["sAMAccountName"][0]);

                Console.WriteLine("");
            }
        }
        public static void QueryLdap_computerdescription(string ldapPath, string username, string password)
        {
            //存在描述的机器
            string query = @"(&(objectCategory=computer)(description=*))";
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = query;
            Console.WriteLine("[*]Computer Objects With Description:");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果

                if (result.Properties.Contains("sAMAccountName"))
                    Console.WriteLine("sAMAccountName: " + result.Properties["sAMAccountName"][0]);
                if (result.Properties.Contains("description"))
                    Console.WriteLine("description: " + result.Properties["description"][0]);
                Console.WriteLine("");
            }
        }
        public static void QueryLdap_userdescription(string ldapPath, string username, string password)
        {
            //存在描述的用户
            string query = @"(&(objectCategory=user)(description=*)(!(samaccountname=krbtgt))(!(samaccountname=Guest))(!(samaccountname=DefaultAccount)))";
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = query;
            Console.WriteLine("[*]User Objects With Description:");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果

                if (result.Properties.Contains("sAMAccountName"))
                    Console.WriteLine("sAMAccountName: " + result.Properties["sAMAccountName"][0]);
                if (result.Properties.Contains("description"))
                    Console.WriteLine("description: " + result.Properties["description"][0]);

                Console.WriteLine("");
            }
        }
        public static void QueryLdap_oulists(string ldapPath, string username, string password)
        {
            //Find all organizational units (OU) :
            string query = @"(&(objectClass=organizationalUnit)(!(ou=Domain Controllers)))";
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = query;
            Console.WriteLine("[*]All organizational units (OU):");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果

                if (result.Properties.Contains("ou"))
                    Console.WriteLine("ou: " + result.Properties["ou"][0]);
                if (result.Properties.Contains("description"))
                    Console.WriteLine("description: " + result.Properties["description"][0]);

                Console.WriteLine("");
            }
        }

        public static void QueryLdap_usernotd(string ldapPath, string username, string password)
        {
            //Accounts Not Trusted for Delegation:
            string query = @"(&(samaccountname=*)(userAccountControl:1.2.840.113556.1.4.803:=1048576))";
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = query;
            Console.WriteLine("[*]Accounts Not Trusted for Delegation:");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果

                if (result.Properties.Contains("sAMAccountName"))
                    Console.WriteLine("sAMAccountName: " + result.Properties["sAMAccountName"][0]);
                if (result.Properties.Contains("telephoneNumber"))
                    Console.WriteLine("tel: " + result.Properties["telephoneNumber"][0]);
                if (result.Properties.Contains("mail"))
                    Console.WriteLine("mail: " + result.Properties["mail"][0]);
                Console.WriteLine("");
            }
        }
        public static void QueryLdap_admincountuser(string ldapPath, string username, string password)
        {
            //User Objects with Elevated Domain Rights:
            string query = @"(&(objectClass=user)(admincount=1)(!(samaccountname=krbtgt))(!(samaccountname=administrator)))";
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = query;
            Console.WriteLine("[*]User Objects with Elevated Domain Rights-admincount=1:");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果

                if (result.Properties.Contains("sAMAccountName"))
                    Console.WriteLine("sAMAccountName: " + result.Properties["sAMAccountName"][0]);
                if (result.Properties.Contains("telephoneNumber"))
                    Console.WriteLine("tel: " + result.Properties["telephoneNumber"][0]);
                if (result.Properties.Contains("mail"))
                    Console.WriteLine("mail: " + result.Properties["mail"][0]);
                Console.WriteLine("");
            }
        }
        public static void QueryLdap_GetDomainAdmins(string ldapPath, string username, string password)
        {
            //Doamin Admins
            DirectoryEntry entry = new DirectoryEntry(ldapPath,username,password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = "(&(objectclass=group)(samaccountname=Domain Admins))";
            SearchResult result = searcher.FindOne();
            Console.WriteLine("[*]Domain Admins's sAMAccountName:");
            Console.WriteLine("");
            if (result != null)
            {
                DirectoryEntry group = result.GetDirectoryEntry();
                foreach (object member in (System.Collections.IEnumerable)group.Invoke("Members"))
                {
                    using (DirectoryEntry memberEntry = new DirectoryEntry(member))
                    {
                        if (memberEntry.Properties.Contains("sAMAccountName"))
                            Console.WriteLine("sAMAccountName: " + memberEntry.Properties["sAMAccountName"][0]);
                        if (memberEntry.Properties.Contains("telephoneNumber"))
                            Console.WriteLine("tel: " + memberEntry.Properties["telephoneNumber"][0]);
                        if (memberEntry.Properties.Contains("mail"))
                            Console.WriteLine("mail: " + memberEntry.Properties["mail"][0]);
                        Console.WriteLine("");
                    }
                }
            }

        }
        public static void QueryLdap_maq(string ldapPath, string username, string password)
        {
            //ms-DS-MachineAccountQuota:
            string query = @"(ms-DS-MachineAccountQuota=*)";
            DirectoryEntry entry = new DirectoryEntry(ldapPath,username,password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = query;
            Console.WriteLine("[*]ms-DS-MachineAccountQuota:");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果

                if (result.Properties.Contains("ms-DS-MachineAccountQuota"))
                    Console.WriteLine("MAQ=" + result.Properties["ms-DS-MachineAccountQuota"][0]);

                Console.WriteLine("");
            }
        }

        public static void QueryLdap_getDC(string ldapPath, string ldapPathdns,string username,string password)
        {
            //DCs - ip
            DirectoryEntry entry = new DirectoryEntry(ldapPath,username,password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))";

            Console.WriteLine("[*]Domain Controllers - ips:");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果

                if (result.Properties.Contains("dNSHostName"))
                {
                    string dNSHostName = (string)result.Properties["dNSHostName"][0];
                    //Console.WriteLine(dNSHostName);
                    Console.WriteLine(dNSHostName + " - " + QueryDnsRecords(ldapPathdns, username, password, dNSHostName));
                }
                if (result.Properties.Contains("operatingSystem"))
                    Console.WriteLine(result.Properties["operatingSystem"][0]);

                Console.WriteLine("");


            }

        }
        public static void QueryLdap_demo(string ldapPath, string username, string password)
        {
            //Kerberoastable Users
            string query = @"(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(samaccounttype=805306369)))";
            DirectoryEntry entry = new DirectoryEntry(ldapPath, username, password);
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.Filter = query;
            Console.WriteLine("[*]Kerberoastable Users");
            Console.WriteLine("");
            foreach (SearchResult result in searcher.FindAll())
            {
                // 处理结果
                Console.WriteLine(result.Path);
                if (result.Properties.Contains("sAMAccountName"))
                    Console.WriteLine("sAMAccountName: " + result.Properties["sAMAccountName"][0]);
                if (result.Properties.Contains("telephoneNumber"))
                    Console.WriteLine("tel: " + result.Properties["telephoneNumber"][0]);
                if (result.Properties.Contains("mail"))
                    Console.WriteLine("mail: " + result.Properties["mail"][0]);
                Console.WriteLine("");
            }
        }
















    }
}
