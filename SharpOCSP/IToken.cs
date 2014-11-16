using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle;
using Crypto = Org.BouncyCastle.Crypto;
using X509	=	Org.BouncyCastle.X509;

namespace SharpOCSP
{
    interface IToken
    {
        /// <summary>
        /// Gets the token name.
        /// </summary>
        string Name { get; }
        /// <summary>
        /// This functions signs a block of data using the supplied hashing implementation.
        /// </summary>
        /// <param name="data">The data to be signed.</param>
        /// <param name="hashAlgorithm">The hashing algorithm, example Crypto.Digests.Sha1Digest</param>
        /// <returns>The digital signature.</returns>
        byte[] SignData(byte[] data, Crypto.IDigest hashAlgorithm);
		Crypto.AsymmetricKeyParameter GetPublicKey ();
		Crypto.AsymmetricKeyParameter GetPrivateKey ();
		X509.X509Certificate	GetOcspSigningCert();
    }
}
