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
using OpenSsl = Org.BouncyCastle.OpenSsl;

namespace BouncyOCSP
{
    class CA
    {
        //Public
        public IToken caToken;
        //Private
        private bool caCompromised;
        private Crypto.AsymmetricKeyParameter caKey;
        private Asn1.X509.X509Name caName;
        private X509.X509Certificate caCertificate;
        //Serials handling
        private string caSerialsPath;
        private DateTime caSerialsLastUpdate;
        private int caSerialsTimeout;
        //TODO
        public bool SerialExists(Math.BigInteger serial)
        {
            return true;
        }
        //TODO
        public void ReloadSerials()
        {
            return;
        }
        //TODO: Overload ToString to output name
        public CA(string name, string caCertPath, IToken token, string serialsPath, int serialsTimeout, bool compromised = false)
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
            caSerialsTimeout = serialsTimeout;
        }
    }
}
