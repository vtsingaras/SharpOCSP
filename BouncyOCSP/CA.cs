using Org.BouncyCastle;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Asn1 = Org.BouncyCastle.Asn1;
using Math = Org.BouncyCastle.Math;
using X509 = Org.BouncyCastle.X509;
using Crypto = Org.BouncyCastle.Crypto;
using Ocsp	=	Org.BouncyCastle.Ocsp;
using OpenSsl = Org.BouncyCastle.OpenSsl;

namespace BouncyOCSP
{
    class CA
    {
        //Public
        public IToken caToken;
		public string caCrlPath{ get; private set; }
		public string caSerialsPath{ get; private set; }
		public X509.X509Certificate caCertificate { get; private set; }
		public bool caCompromised { get; private set; }
        //Private
		private Crypto.AsymmetricKeyParameter caKey;
        private Asn1.X509.X509Name caName;
        private DateTime caSerialsLastUpdate;
		//TODO
		public Org.BouncyCastle.X509.X509CrlEntry GetCrlEntry(Math.BigInteger serial)
		{

			return null;
		}
        //TODO
        public bool SerialExists(Math.BigInteger serial)
        {
			if (serial.IntValue == 666)
				return false;
			return true;
        }
        //TODO
        public void ReloadSerials()
        {
            return;
        }
		//TODO
		public void ReloadCrl()
		{
			return;
		}
		public override string ToString()
		{
			return caName.ToString ();
		}
		public CA(string name, string caCertPath, IToken token, string crlPath, string serialsPath, bool compromised = false)
        {
            //Read CA certificate 
            var certReader = new OpenSsl.PemReader(new StreamReader(caCertPath));
            caCertificate = (X509.X509Certificate)certReader.ReadObject();
            caName = caCertificate.SubjectDN;
            caKey = caCertificate.GetPublicKey();

            caToken = token;
            caCompromised = compromised;
            //TODO: Check if exists and access
            caSerialsPath = serialsPath;
        }
    }
}
