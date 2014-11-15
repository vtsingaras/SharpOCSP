using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BouncyOCSP
{
    class Configuration
    {
        public string getConfigValue(string key)
        {
			try{
				return config[key];
			}catch (KeyNotFoundException e){
				throw new ConfigurationKeyValueReadException ("Could not read requested key.", e);
			}
        }
        public Configuration(string configFile)
        {

        }

        private Dictionary<string, string> config;
    }
}
