using System;
using System.Collections.Generic;
using System.Xml;

namespace SharpOCSP
{
    public class Configuration
    {
		private Dictionary<string, string> _config = new Dictionary<string, string>();
        public string getConfigValue(string key)
        {
			try{
				return _config[key];
			}catch (KeyNotFoundException){
				return null;
			}
        }
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
			if (tokensNode == null) {
				throw new ConfigurationException ("No tokens supplied!");
			}
			XmlNodeList tokenNodeList = tokensNode.SelectNodes("./token");
			if (tokenNodeList.Count <= 0) {
				throw new ConfigurationException ("No tokens supplied!");
			}
			foreach (XmlElement token_config in tokenNodeList){
				string name, type, ocspCertificate, ocspKey;
				if (token_config ["name"] != null) {
					name = token_config ["name"].InnerText;
				} else {
					throw new ConfigurationException("Unable to parse token name.");
				}
				//default to software
				type = ( token_config ["type"] != null) ? token_config["type"].InnerText : "software";
				if (token_config ["certificate"] != null) {
					ocspCertificate = token_config ["certificate"].InnerText;
				}else{
					throw new ConfigurationException ("Unable to parse certificate path.");
				}
				if (token_config ["certificateKey"] != null) {
					ocspKey = token_config ["certificateKey"].InnerText;
				} else {
					throw new ConfigurationException ("Unable to parse key path.");
				}
				if(type == "software"){
					SharpOCSP.token_list.Add(new SoftToken(name, ocspCertificate, ocspKey));
				}else{
					throw new ConfigurationException("Only software tokens for now...");
				}
			}
			//build CAs
			XmlNode calistNode = doc.SelectSingleNode ("//calist");
			if (calistNode == null) {
				throw new ConfigurationException ("No CAs supplied!");
			}
			XmlNodeList caNodeList = calistNode.SelectNodes("./ca");
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
				}catch (NullReferenceException e){
					throw new ConfigurationException ("Unable to parse CA: " + ca_config ["name"].InnerText ?? "unknown", e);
				}
			}
			//get interfaces
			XmlNode uriprefixesNode = doc.SelectSingleNode ("//uriprefixes");
			if (uriprefixesNode == null) {
				throw new ConfigurationException ("No URI list supplied!");
			}
			XmlNodeList uriprefixNodeList = uriprefixesNode.SelectNodes("./uriprefix");
			if (uriprefixNodeList.Count <= 0) {
				throw new ConfigurationException ("URI list is empty!");
			}
			foreach (XmlElement url in uriprefixNodeList) {
				SharpOCSP.url_list.Add (url.InnerText);
			}
			//read rest settings
			var extended_revoke = doc.SelectSingleNode ("//extendedrevoke");
			//check if extendedrevoke is yes or no
			_config.Add("extendedrevoke", 
				( extended_revoke != null &&  (extended_revoke.InnerText == "yes" || extended_revoke.InnerText == "no")) ? extended_revoke.InnerText : null);
			var user = doc.SelectSingleNode ("//user");
			if (user != null && user.InnerText != null && user.InnerText != "") {
				_config.Add ("user", user.InnerText);
			}
			var group = doc.SelectSingleNode ("//group");
			if (group != null && group.InnerText != null && group.InnerText != "") {
				_config.Add ("group", group.InnerText);
			}
			var nextupdate = doc.SelectSingleNode ("//nextupdate");
			if (nextupdate != null && nextupdate.InnerText != null && nextupdate.InnerText != "") {
				double dummy_double;
				if (Double.TryParse(nextupdate.InnerText, out dummy_double)) {
					_config.Add ("nextupdate", nextupdate.InnerText);
				}
			}
        }
    }
}
