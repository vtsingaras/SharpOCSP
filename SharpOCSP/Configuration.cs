using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SharpOCSP
{
    class Configuration
    {
        public string getConfigValue(string key)
        {
			try{
				return ConfigurationManager.AppSettings[key];
			}catch (KeyNotFoundException e){
				throw new ConfigurationKeyValueReadException ("Could not read requested key.", e);
			}catch (Exception){
				return "true";
			}
        }
		//TODO
        public Configuration(string configFile)
        {
			//build tokens
			//build CAs
			//get interfaces
			//read rest settings
        }

        private Dictionary<string, string> config;
    }
}
