using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;

using Org.BouncyCastle;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.OpenSsl;

namespace SharpOCSP
{
    class SoftToken : IToken
    {
		public  override String Name{ get ; protected set; }
		private X509Certificate _ocspCertificate;
		private RsaPrivateCrtKeyParameters _privateKey;
        /// <summary>
        /// Creates an instance of a 'SoftToken'.
        /// </summary>
        /// <param name="name">The token's name.</param>
        /// <param name="certPath">Path to OCSP signer certificate.</param>
        /// <param name="keyPath">Path to OCSP signer certificate key.</param>
		public override byte[] SignData(byte[] data, IDigest digestAlgorithm)
		{
			byte[] signature;
			RsaDigestSigner rsaSigner = new RsaDigestSigner(digestAlgorithm);

			rsaSigner.Init(true, _privateKey);
			rsaSigner.BlockUpdate(data, 0, data.Length);
			signature = rsaSigner.GenerateSignature();
			rsaSigner.Reset();

			return signature;
		}
		public override AsymmetricKeyParameter GetPublicKey ()
		{
			return _ocspCertificate.GetPublicKey ();
		}
		public override AsymmetricKeyParameter GetPrivateKey ()
		{
			return  (AsymmetricKeyParameter)_privateKey;
		}
		public override X509Certificate GetOcspSigningCert()
		{
			return _ocspCertificate;
		}
        public SoftToken(string name,string certPath, string keyPath)
        {
            Name = name;
            //Read OCSP signer certificate
			try{
	            var ocspCertReader = new PemReader(new StreamReader(certPath));
				_ocspCertificate = (X509Certificate) ocspCertReader.ReadObject();
			}catch (System.UnauthorizedAccessException e){
				throw new OcspFilesystemException ("Error reading ocsp certificate: " + keyPath, e);
			}catch (FileNotFoundException e){
				throw new OcspFilesystemException ("Error reading ocsp certificate: " + keyPath, e);
			}
            //Read private key
			try{
            	var keyReader = new PemReader(new StreamReader(keyPath));
				var key_pem = (AsymmetricCipherKeyPair) keyReader.ReadObject ();
				_privateKey = (RsaPrivateCrtKeyParameters) key_pem.Private;
			}catch (System.UnauthorizedAccessException e){
				throw new OcspFilesystemException ("Error reading private key: " + keyPath, e);
			}
			catch (FileNotFoundException e){
				throw new OcspFilesystemException ("Error reading private key: " + keyPath, e);
			}
        }
    }
}
