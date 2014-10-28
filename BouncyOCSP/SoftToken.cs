using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;

using Org.BouncyCastle;
using Crypto = Org.BouncyCastle.Crypto;
using Engines = Org.BouncyCastle.Crypto.Engines;
using Signers = Org.BouncyCastle.Crypto.Signers;
using X509 = Org.BouncyCastle.X509;
using OpenSsl = Org.BouncyCastle.OpenSsl;

namespace BouncyOCSP
{
    class SoftToken : IToken
    {
        public String Name
        {
            get;
            private set;
        }
        public byte[] SignData(byte[] data, Crypto.IDigest digestAlgorithm)
        {
            byte[] signature;
            Signers.RsaDigestSigner rsaSigner = new Crypto.Signers.RsaDigestSigner(digestAlgorithm);

            rsaSigner.Init(true, privateKey);
            rsaSigner.BlockUpdate(data, 0, data.Length);
            signature = rsaSigner.GenerateSignature();
            rsaSigner.Reset();

            return signature;
        }
        private X509.X509Certificate ocspCertificate;
        private Crypto.Parameters.RsaPrivateCrtKeyParameters privateKey;
        /// <summary>
        /// Creates an instance of a 'SoftToken'.
        /// </summary>
        /// <param name="name">The token's name.</param>
        /// <param name="certPath">Path to OCSP signer certificate.</param>
        /// <param name="keyPath">Path to OCSP signer certificate key.</param>
        public SoftToken(string name,string certPath, string keyPath)
        {
            Name = name;
            //Read OCSP signer certificate
            var ocspCertReader = new OpenSsl.PemReader(new StreamReader(certPath));
            ocspCertificate = (X509.X509Certificate)ocspCertReader.ReadObject();
            //Read private key
            var keyReader = new OpenSsl.PemReader(new StreamReader(keyPath));
            privateKey = (Crypto.Parameters.RsaPrivateCrtKeyParameters)keyReader.ReadObject();
        }
    }
}
