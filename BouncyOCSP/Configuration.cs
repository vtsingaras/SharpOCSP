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
            throw new ConfigurationKeyValueReadException("Could not read requested key.");
        }
        public Configuration(string configFile)
        {

        }

        private Dictionary<string, string> config;
    }
}
