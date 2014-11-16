using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Xml;
using System.Reflection;
using System.Text;
using System.Xml.Linq;
using System.Threading.Tasks;

namespace SharpOCSP
{
    class Configuration
    {
        public string getConfigValue(string key)
        {
			try{
				return ConfigurationManager.AppSettings[key];
			}catch (KeyNotFoundException){
				return null;
			}
        }
		//TODO
        public Configuration(string configFile)
        {
			XmlDocument doc = new XmlDocument();
			try{
				doc.Load ("file://" + configFile);
			}catch (XmlException e){
				throw new ConfigurationException ("XML Sytax error in: " + configFile, e);
			}
			//build tokens
			XmlNode	tokensNode = doc.SelectSingleNode ("//tokens");
			XmlNodeList tokenNodeList = tokensNode.SelectNodes(".//token");
			if (tokenNodeList.Count <= 0) {
				throw new ConfigurationException ("No tokens supplied!");
			}
			foreach (XmlElement token_config in tokenNodeList){
				try{
					var name = token_config ["name"].InnerText;
					var type = token_config ["type"].InnerText ?? "software";
					var ocspCertificate = token_config ["certificate"].InnerText;
					var ocspKey = token_config ["certificateKey"].InnerText;
					if(type == "software"){
						SharpOCSP.token_list.Add(new SoftToken(name, ocspCertificate, ocspKey));
					}else{
						throw new ConfigurationException("Only software tokens for now...");
					}
				}catch (NullReferenceException e){
					throw new ConfigurationException ("Unable to parse token: " + token_config ["name"].InnerText ?? "unknown", e);
				}
			}
			//build CAs
			XmlNode calistNode = doc.SelectSingleNode ("//calist");
			XmlNodeList caNodeList = calistNode.SelectNodes(".//ca");
			if (caNodeList.Count <= 0) {
				throw new ConfigurationException ("No CAs supplied!");
			}
			foreach (XmlElement ca_config in caNodeList){
				try{
					var name = ca_config ["name"].InnerText;
					var caCertPath = ca_config ["certificate"].InnerText;
					var token = ca_config ["token"].InnerText;
					var crl = ca_config ["crl"].InnerText;
					var index = (ca_config["serials"] != null) ? ca_config["serials"].InnerText : null;
					bool compromised;
					if (!Boolean.TryParse ( 
							(ca_config ["compromised"] != null) ? ca_config ["compromised"].InnerText : "false"
							, out compromised)){
						compromised = false;
					}
					SharpOCSP.ca_list.Add(CA.CreateCA(name, caCertPath, token, crl, index, compromised));
				}/*catch (NullReferenceException e){
					throw new ConfigurationException ("Unable to parse CA: " + ca_config ["name"].InnerText ?? "unknown", e);
				}*/finally{}
			}
			//get interfaces
			//read rest settings
        }

        private Dictionary<string, string> config;
    }
}
