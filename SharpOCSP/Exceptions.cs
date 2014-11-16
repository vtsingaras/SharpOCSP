using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpOCSP
{
    class Exceptions
    {
    }
    public class ConfigurationException : Exception
    {
        public ConfigurationException(){}
        public ConfigurationException(string message) : base(message){}
        public ConfigurationException(string message, Exception inner) : base(message, inner){}
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
	public class OcspFilesystemException : Exception
	{
		public OcspFilesystemException() { }
		public OcspFilesystemException(string message) : base(message) { }
		public OcspFilesystemException(string message, Exception inner) : base(message, inner) { }
	}
	//Never catch this gracefully
	public class OcspInternalMalfunctionException : Exception
	{
		public OcspInternalMalfunctionException() { }
		public OcspInternalMalfunctionException(string message) : base(message) { }
		public OcspInternalMalfunctionException(string message, Exception inner) : base(message, inner) { }
	}
}
