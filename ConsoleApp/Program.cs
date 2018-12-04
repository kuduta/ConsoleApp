using System;
using System.IO;
using System.Text;
using Microsoft.Win32;
using System.ServiceProcess;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Management;

namespace ConsoleApp
{
    class Program
    {
        public static string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            throw new Exception("No network adapters with an IPv4 address in the system!");
        } ///

        static string ReadSubKeyValue(string subKey, string key)
        {
            string str = string.Empty;
            using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(subKey))
            {
                if (registryKey != null)

                {
                    try
                    {
                        str = registryKey.GetValue(key).ToString();
                        registryKey.Close();
                    }
                    catch (Exception ex3)
                    {
                        // Console.WriteLine("Exception error with get regkey :" + ex1.ToString());
                    }

                }
            }
            return str;
        }///

        public static String GetServerAV(String ip_)
        {
            string[] ipvalues = ip_.Split('.');
            string instserver = "";
            if (ipvalues[0] == "10")
            {
                if (Int32.Parse(ipvalues[1]) <= 33)
                {
                    instserver = "10.20.2.7";
                }
                else if ((Int32.Parse(ipvalues[1]) >= 34 && Int32.Parse(ipvalues[1]) <= 69) && (Int32.Parse(ipvalues[2]) < 16))
                {
                    instserver = ipvalues[0] + "." + ipvalues[1] + ".1.5";  //PAK1-3
                }
                else if ((Int32.Parse(ipvalues[1]) >= 34 && Int32.Parse(ipvalues[1]) <= 69) && (Int32.Parse(ipvalues[2]) >= 16))
                {
                    instserver = "10.20.2.9";  //PAK1-3 SS
                }
                else if ((Int32.Parse(ipvalues[1]) >= 80 && Int32.Parse(ipvalues[1]) <= 95) && (Int32.Parse(ipvalues[2]) < 16))
                {
                    instserver = ipvalues[0] + "." + ipvalues[1] + ".1.5";    //PAK4
                }
                else if ((Int32.Parse(ipvalues[1]) >= 80 && Int32.Parse(ipvalues[1]) <= 95) && (Int32.Parse(ipvalues[2]) >= 16))
                {
                    instserver = "10.80.7.7";   //PAK4 SS
                }
                else if ((Int32.Parse(ipvalues[1]) >= 96 && Int32.Parse(ipvalues[1]) <= 111) && (Int32.Parse(ipvalues[2]) < 16))
                {
                    instserver = ipvalues[0] + "." + ipvalues[1] + ".1.5";    //PAK5
                }
                else if ((Int32.Parse(ipvalues[1]) >= 96 && Int32.Parse(ipvalues[1]) <= 111) && (Int32.Parse(ipvalues[2]) >= 16))
                {
                    instserver = "10.96.7.7";   //PAK5 SS
                }
                else if ((Int32.Parse(ipvalues[1]) >= 112 && Int32.Parse(ipvalues[1]) <= 127) && (Int32.Parse(ipvalues[2]) < 16))
                {
                    instserver = ipvalues[0] + "." + ipvalues[1] + ".1.5";    //PAK6
                }
                else if ((Int32.Parse(ipvalues[1]) >= 112 && Int32.Parse(ipvalues[1]) <= 127) && (Int32.Parse(ipvalues[2]) >= 16))
                {
                    instserver = "10.122.7.7";   //PAK6 SS
                }
                else if ((Int32.Parse(ipvalues[1]) >= 128 && Int32.Parse(ipvalues[1]) <= 143) && (Int32.Parse(ipvalues[2]) < 16))
                {
                    instserver = ipvalues[0] + "." + ipvalues[1] + ".1.5";    //PAK7
                }
                else if ((Int32.Parse(ipvalues[1]) >= 128 && Int32.Parse(ipvalues[1]) <= 143) && (Int32.Parse(ipvalues[2]) >= 16))
                {
                    instserver = "10.128.7.7";   //PAK7 SS
                }
                else if ((Int32.Parse(ipvalues[1]) >= 144 && Int32.Parse(ipvalues[1]) <= 159) && (Int32.Parse(ipvalues[2]) < 16))
                {
                    instserver = ipvalues[0] + "." + ipvalues[1] + ".1.5";    //PAK8
                }
                else if ((Int32.Parse(ipvalues[1]) >= 144 && Int32.Parse(ipvalues[1]) <= 159) && (Int32.Parse(ipvalues[2]) >= 16))
                {
                    instserver = "10.144.7.7";   //PAK8 SS
                }
                else if ((Int32.Parse(ipvalues[1]) >= 160 && Int32.Parse(ipvalues[1]) <= 175) && (Int32.Parse(ipvalues[2]) < 16))
                {
                    instserver = ipvalues[0] + "." + ipvalues[1] + ".1.5";    //PAK9
                }
                else if ((Int32.Parse(ipvalues[1]) >= 160 && Int32.Parse(ipvalues[1]) <= 175) && (Int32.Parse(ipvalues[2]) >= 16))
                {
                    instserver = "10.160.7.7";   //PAK9 SS
                }
                else if ((Int32.Parse(ipvalues[1]) >= 176 && Int32.Parse(ipvalues[1]) <= 191) && (Int32.Parse(ipvalues[2]) < 16))
                {
                    instserver = ipvalues[0] + "." + ipvalues[1] + ".1.5";    //PAK10
                }
                else if ((Int32.Parse(ipvalues[1]) >= 176 && Int32.Parse(ipvalues[1]) <= 191) && (Int32.Parse(ipvalues[2]) >= 16))
                {
                    instserver = "10.176.7.7";   //PAK10 SS
                }
                else if ((Int32.Parse(ipvalues[1]) >= 192 && Int32.Parse(ipvalues[1]) <= 207) && (Int32.Parse(ipvalues[2]) < 16))
                {
                    instserver = ipvalues[0] + "." + ipvalues[1] + ".1.5";    //PAK11
                }
                else if ((Int32.Parse(ipvalues[1]) >= 192 && Int32.Parse(ipvalues[1]) <= 207) && (Int32.Parse(ipvalues[2]) > 16))
                {
                    instserver = "10.192.7.7";   //PAK11 SS

                }
                else if ((Int32.Parse(ipvalues[1]) >= 208 && Int32.Parse(ipvalues[1]) <= 216) && (Int32.Parse(ipvalues[2]) < 16))
                {
                    instserver = ipvalues[0] + "." + ipvalues[1] + ".1.5";    //PAK12
                }
                else if ((Int32.Parse(ipvalues[1]) >= 208 && Int32.Parse(ipvalues[1]) <= 216) && (Int32.Parse(ipvalues[2]) > 16))
                {
                    instserver = "10.208.7.7";   //PAK12 SS

                }
                else
                {
                    instserver = "10.20.2.9";
                }
            }
            else
            {
                instserver = "10.20.2.7";
            }

            return instserver;

        }//end function Get IP Server AV       

        public static string CHKEMss()
        {
            ServiceController ctl = ServiceController.GetServices()
                .FirstOrDefault(s => s.ServiceName == "EMSS Agent");
            if (ctl == null)
                return "Not installed";

            else
                return ctl.Status.ToString();
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Service EMSS Agent is : " + CHKEMss());
            //Console.WriteLine("Pass 1");

            string regtry_text = "";
            string SID = "";
            string ComName = "";
            string Manufacturer = "";
            string OperSys = "";
            string SerialNumber = "";

            string version = "";
            string productname = "";
            string ipaddress = "";
            string MAC = "";
            string GUID = "";
            string InstallDate = "";
            string domain = "";
            string NtVer = "";
            string server = "";
            string NetID = "";
            //string regtry_patch = "SOFTWARE\\Lumension\\LMAgent";
            string EMSSagentstatus = CHKEMss();
            //Not installed
            string AVstatus = "";
            string sysos = "";
            string dlAV = "";
            string dlpatch = "";

            //Console.WriteLine("Pass 2");
            ComName = Environment.MachineName.ToString();

            if (Environment.Is64BitOperatingSystem)
            {
                regtry_text = @"SOFTWARE\WOW6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion";
                sysos = "64";
            }
            else
            {
                regtry_text = @"SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion";
                sysos = "32";
            }
            //Console.WriteLine("Pass 3");
            try
            {
                ipaddress = GetLocalIPAddress();
                NetID = ipaddress.Substring(0, ipaddress.LastIndexOf("."));
                MAC = ReadSubKeyValue(regtry_text, "MAC");
                GUID = ReadSubKeyValue(regtry_text, "GUID");
                InstallDate = ReadSubKeyValue(regtry_text, "InstDate");
                domain = ReadSubKeyValue(regtry_text, "Domain");
                NtVer = ReadSubKeyValue(regtry_text, "NtVer");
                server = ReadSubKeyValue(regtry_text, "Server");

            }catch (Exception ex10)
            {

            }
            //Console.WriteLine("Pass 4");

            try
            {
                RegistryKey masterKey = Registry.LocalMachine.OpenSubKey(regtry_text + "\\Misc.");
                if (masterKey != null)
                {
                    version = masterKey.GetValue("ProgramVer").ToString();
                    productname = masterKey.GetValue("ProductName").ToString();
                }
                masterKey.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Can not get value inregistry!");
            }

            //Console.WriteLine("Pass 5");
            ConnectionOptions options = new ConnectionOptions();
            options.Impersonation = System.Management.ImpersonationLevel.Impersonate;

            ManagementScope scope = new ManagementScope("\\\\.\\root\\cimv2", options);
            scope.Connect();

            // get information of machine
            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_OperatingSystem");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection queryCollection = searcher.Get();

            //Console.WriteLine("Pass 6");
            foreach (ManagementObject m in queryCollection)
            {

                OperSys = m["Caption"].ToString().Trim();
            }

            ObjectQuery queryBIOS = new ObjectQuery("SELECT * FROM Win32_BIOS");
            ManagementObjectSearcher searcherBIOS = new ManagementObjectSearcher(scope, queryBIOS);
            ManagementObjectCollection queryCollectionBIOS = searcherBIOS.Get();
            foreach (ManagementObject m in queryCollectionBIOS)
            {
                Manufacturer = m["Manufacturer"].ToString().Trim();
                SerialNumber = m["SerialNumber"].ToString().Trim();
            }

            //Console.WriteLine("Pass 7");
            //Get SID in machine 
            //ObjectQuery queryAcc = new ObjectQuery("SELECT * FROM Win32_UserAccount");
            //ManagementObjectSearcher searcherAcc = new ManagementObjectSearcher(scope, queryAcc);
            //ManagementObjectCollection queryCollectionAcc = searcherAcc.Get();
            //foreach (ManagementObject m in queryCollectionAcc)
            //{
            //    SID = m["SID"].ToString().Trim().Substring(0, 40);
            //}


            //Console.WriteLine("Pass 8");


            Console.WriteLine("Computer name  : {0}", ComName);
            Console.WriteLine("Operating System   : {0}", OperSys);
            Console.WriteLine("Manufacturer  : {0}", Manufacturer);
            Console.WriteLine("SerialNumber : {0}", SerialNumber);
            //Console.WriteLine("SID  : {0}", SID);

            Console.WriteLine("IP Address is  :  " + ipaddress);
            //Console.WriteLine("IP Cut is  :  " + NetID);
            Console.WriteLine("MAC Address is  :  " + MAC);
            Console.WriteLine("GUID is  :  " + GUID);
            Console.WriteLine("Domain is  :  " + domain);
            Console.WriteLine("Windows NT version is  :  " + NtVer);
            //Console.WriteLine("Server is  :  " + server);

            Console.WriteLine("Product Name is  :  " + productname);
            Console.WriteLine("Version is :  " + version);
            Console.WriteLine("Install Date :  " + InstallDate);

            Console.WriteLine("EMSS Agent status:  " + EMSSagentstatus);
            //Console.WriteLine("AV status   :  " + AVstatus);
            Console.WriteLine("Server AV  : " + GetServerAV(ipaddress));

            Console.WriteLine("Version client : " + sysos);

         

            if(Equals(EMSSagentstatus.ToString().Trim(), "Not installed"))
            {
                if (sysos == "32")
                {
                    //Console.WriteLine("http://" + GetServerAV(ipaddress) + "/agents/Agents/Patch/patch_agent_86.exe");
                    dlpatch = "http://" + server + "/agents/Agents/Patch/patch_agent_86.exe";
                }
                else
                {
                    //Console.WriteLine("http://" + GetServerAV(ipaddress) + "/agents/Agents/Patch/patch_agent_64.exe");
                    dlpatch = "http://" + GetServerAV(ipaddress) + "/agents/Agents/Patch/patch_agent_64.exe";
                }

            }
            if (!Equals(version.ToString().Trim(), "12.0"))
            {
                if (sysos == "32")
                {                  
                    //Console.WriteLine("http://" + GetServerAV(ipaddress) + "/agents/Agents/OSCE/agent_cloud_x86.exe");
                    dlAV = "http://" + GetServerAV(ipaddress) + "/agents/Agents/OSCE/agent_cloud_x86.exe";
                }
                else
                {
                    //Console.WriteLine("agent_cloud_x86");
                    dlAV = "http://"+ GetServerAV(ipaddress) + "/agents/Agents/Patch/agent_cloud_x64.exe";
                }
            }


        
            //Console.WriteLine("Test Print html");

            //Console.WriteLine(dlAV);
            //Console.WriteLine(dlpatch);
            Console.WriteLine();
            //Console.WriteLine("Get information finish");





            /*********************Post method for send data to restful PAI ************************/

            string URI = "http://10.20.2.59/input";
            //string myParameters = "param1=value1&param2=value2&param3=value3";
            string myParameters = "ComName=" + ComName + "&SerialNumber=" + SerialNumber + "&Manufacturer=" + Manufacturer +
                "&NtVer=" + NtVer + "&OperSys=" + OperSys + "&domain=" + domain + "&ipaddress=" + ipaddress +
                "&NetID=" + NetID + "&MAC==" + MAC + "&productname=" + productname + "&version=" + version +
                "&GUID=" + GUID + "&server=" + server + "&EMSSagentstatus=" + EMSSagentstatus;


            using (WebClient wc = new WebClient())
            {
                wc.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                try
                {
                    string HtmlResult = wc.UploadString(URI, myParameters);
                }
                catch (Exception ex5)
                {
                    //Console.WriteLine("Exception error with create htm :" + ex.ToString());
                    Console.WriteLine("######## Can not connect server!#############");
                }

            }

            //write html 
            if (!Equals(dlAV, "") || !Equals(dlpatch, ""))
            {
                using (FileStream fs = new FileStream("ComInfo.html", FileMode.Create))
                {
                    using (StreamWriter w = new StreamWriter(fs, Encoding.UTF8))
                    {
                        if(!Equals(dlAV, ""))
                        {
                            w.WriteLine("<br>กรุณาติดตั้งโปรแกรมป้องกันไวรัส :  <a href = "+dlAV+" >Download Antivirus </a>");
                            Console.WriteLine("This computer is not installed software TreandMicro or TrendMicro new version.");


                        }

                        if (!Equals(dlpatch, ""))
                        {
                            w.WriteLine("<br>กรุณาติดตั้งโปรแกรมอุดช่องโหว่ :  <a href = " + dlpatch + " >Download Patch</a>");
                            Console.WriteLine("This computer is not installed software Patch management.");
                        }

                        //ipaddress, MAC, GUID, InstallDate, domain, NtVer, server
                        //w.WriteLine("<H1>System Information</H1>");

                        //w.WriteLine("<br>Computer Name is  :  " + ComName);
                        //w.WriteLine("<br>Serial Number is  :  " + SerialNumber);
                        //w.WriteLine("<br>SID is  : " + SID);
                        //w.WriteLine("<br>Manufacturer  :  " + Manufacturer);
                        //w.WriteLine("<br>Windows NT version is  :  " + NtVer);
                        //w.WriteLine("<br>OS is  :  " + OperSys);
                        //w.WriteLine("<br>Group is  :  " + domain);
                        //w.WriteLine("<br>IP Address is  :  " + ipaddress);
                        //w.WriteLine("<br>Net ID  :  " + NetID);
                        //w.WriteLine("<br>MAC Address is  :  " + MAC);              
                        //w.WriteLine("<br>Product Name is  :  " + productname);
                        //w.WriteLine("<br>Version is :  " + version);
                        //w.WriteLine("<br>GUID is  :  " + GUID);
                        //w.WriteLine("<br>Server AV is  :  " + server);

                        //w.WriteLine("<table style=\"width:60%\" border=\"0\">");
                        //w.WriteLine("<tr><td><H5>Computer Name  : </td><td> " + ComName + "</td></tr>");
                        //w.WriteLine("<tr><td><H4>Serial Number :  </td><td>" + SerialNumber + " </td ></tr> ");
                        //w.WriteLine("<tr><td><H4>SID :  </td><td> " + SID + "</td></tr>");
                        //w.WriteLine("<tr><td><H4>Manufacturer  :  </td><td> " + Manufacturer + "</td></tr>");
                        //w.WriteLine("<tr><td><H4>Windows version  :  </td><td> " + NtVer + "</td></tr>");
                        //w.WriteLine("<tr><td><H4>OS  :  </td><td> " + OperSys + "</td></tr>");

                        //w.WriteLine("<tr><td><H4>Group  :  </td><td> " + domain + "</td></tr>");
                        //w.WriteLine("<tr><td><H4>IP Address  :  </td><td> " + ipaddress + "</td></tr>");
                        ////w.WriteLine("<tr><td>Net ID </td><td> " + NetID + "</td></tr>");
                        //w.WriteLine("<tr><td><H4>MAC Address  :  </td><td> " + MAC + "</td></tr>");
                        //w.WriteLine("<tr><td><H4>Antivirus Product  :  </td><td> " + productname + "</td></tr>");
                        //w.WriteLine("<tr><td><H4>Antivirus Version  :  </td><td> " + version + "</td></tr>");
                        //w.WriteLine("<tr><td><H4>Antivirus GUID  :  </td><td> " + GUID + "</td></tr>");
                        //w.WriteLine("<tr><td><H4>Antivirus Server  :  </td><td> " + server + "</td></tr>");
                        //w.WriteLine("<tr><td><H4>Antivirus status  :  </td><td> " + AVstatus + "</td></tr>");
                        //w.WriteLine("<tr><td><H4>EMSS Agent status  :  </td><td> " + EMSSagentstatus + "</td></tr>");



                        //w.WriteLine(" <form action = \"http://127.0.0.1:5000/input\" medthod =\"POST\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"ComName\" value=\"" + ComName + "\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"SerialNumber\" value = \"" + SerialNumber + "\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"SID\" value = \"" + SID + "\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"Manufacturer\" value = \"" + Manufacturer + "\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"NtVer\" value = \"" + NtVer + "\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"OperSys\" value = \"" + OperSys + "\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"domain\" value = \"" + domain + "\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"ipaddress\" value = \"" + ipaddress + "\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"NetID\" value = \"" + NetID + "\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"MAC\" value = \"" + MAC + "\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"productname\" value = \"" + productname + "\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"version\" value = \"" + version + "\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"GUID\" value = \"" + GUID + "\">");
                        //w.WriteLine("<input type=\"hidden\" name=\"server\" value = \"" + server + "\">");
                        //w.WriteLine("</table>");
                        //w.WriteLine("<br>&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp<button align=\"center\" type = \"submit\" formmethod = \"post\" > Send Data </ button >");


                        //w.WriteLine("</form >");
                        w.WriteLine("<br>");
                        w.WriteLine("<br>");
                        w.WriteLine("<br>");
                        w.WriteLine("<br>");
                        w.WriteLine("<form class=\"contact100 -form validate-form\"><span class=\"contact100-form-title\" action = \"http://10.20.2.59/helpme\" medthod =\"POST\"> ถ้าท่านไม่สามารถติดตั้งโปรแกรมได้ <br>กรุณากรอกข้อมูลเพื่อช่วยเหลือ การติดตั้ง Antivirus และ Patch Agent</span>");
                        w.WriteLine("<br> <label class=\"label-input100\" for=\"first-name\">ชื่อผู้ขอความช่วยเหลือ</label>");
                        w.WriteLine("<div class=\"wrap-input100 rs1-wrap-input100 validate-input\" data-validate=\"Type first name\">");
                        w.WriteLine("<input id = \"first-name\" class=\"input100\" type=\"text\" name=\"first-name\" placeholder=\"ชื่อ\">");
                        w.WriteLine("<input type=\"hidden\" name=\"ipaddress\" value = \"" + ipaddress + "\">");
                        w.WriteLine("<input type=\"hidden\" name=\"EMSSagentstatus\" value = \"" + EMSSagentstatus + "\">");
                   
                        w.WriteLine("<input type=\"hidden\" name=\"version\" value = \"" + version + "\">");
                        w.WriteLine("<span class=\"focus-input100\"></span</div>");
                        w.WriteLine("<div class=\"wrap-input100 rs2-wrap-input100 validate-input\" data-validate=\"Type last name\">");
                        w.WriteLine("<input class=\"input100\" type=\"text\" name=\"last-name\" placeholder=\"นามสกุล\">");
                        w.WriteLine("<span class=\"focus-input100\"></span>");
                        w.WriteLine("</div>");



                        w.WriteLine("<label class=\"label-input100\" for=\"phone\">เบอร์โทรศัพท์ที่สามารถติดต่อได้</label>");
                        w.WriteLine("<div class=\"wrap-input100\">");
                        w.WriteLine("<input id = \"phone\" class=\"input100\" type=\"text\" name=\"phone\" placeholder=\"เช่น 098-8888888\">");
                        w.WriteLine("<span class=\"focus-input100\"></span>");
                        w.WriteLine("</div>");

                        w.WriteLine("<div class=\"container-contact100-form-btn\">");
                        w.WriteLine("<button class=\"contact100-form-btn\">");

                        w.WriteLine("ขอความช่วยเหลือ");
                        w.WriteLine("</button>");
                        w.WriteLine("</div>");
            w.WriteLine("</form>");

                    }
                }
                System.Diagnostics.Process.Start("ComInfo.html");
            }
            else
            {
                Console.WriteLine("Your computer is successfully installed.");
            }


            Console.WriteLine("Step Out Press any key to exit.");

            Console.ReadKey();

        }//End Main 
    }
}
