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

    public class ITokenSignDataException : Exception
    {
        public ITokenSignDataException() { }
        public ITokenSignDataException(string message) : base(message) { }
        public ITokenSignDataException(string message, Exception inner) : base(message, inner) { }
    }
	public class OcspUnrecognizedIssuerException : Exception
	{
		public OcspUnrecognizedIssuerException() { }
		public OcspUnrecognizedIssuerException(string message) : base(message) { }
		public OcspUnrecognizedIssuerException(string message, Exception inner) : base(message, inner) { }
	}
	public class OcspMalformedRequestException : Exception
	{
		public OcspMalformedRequestException() { }
		public OcspMalformedRequestException(string message) : base(message) { }
		public OcspMalformedRequestException(string message, Exception inner) : base(message, inner) { }
	}
}
