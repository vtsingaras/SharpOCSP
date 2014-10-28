using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BouncyOCSP
{
    class BouncyOCSP
    {
        static void Main(string[] args)
        {
            Configuration config = new Configuration("config.xml");
            String ca_name = config.getConfigValue("ca_name");
        }
    }
}
