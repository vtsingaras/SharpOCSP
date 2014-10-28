using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BouncyOCSP
{
    class Exceptions
    {
    }
    public class ConfigurationKeyValueReadException : Exception
    {
        public ConfigurationKeyValueReadException(){}
        public ConfigurationKeyValueReadException(string message) : base(message){}
        public ConfigurationKeyValueReadException(string message, Exception inner) : base(message, inner){}
    }
}
