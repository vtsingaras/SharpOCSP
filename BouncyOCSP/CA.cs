using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using CrlException = Org.BouncyCastle.Security.Certificates.CrlException;

namespace BouncyOCSP
{
    class CA
    {
        //Public
        public IToken caToken;
		private string _caCrlPath;
		private string _caSerialsPath;
		public X509Certificate caCertificate { get; private set; }
		public bool caCompromised { get; private set; }
        //Private
		private Object _crlLock = new Object();
		private Object _serialsLock = new Object();
		private X509Crl	_crl;
		private IList<BigInteger> _serials;
		private X509CrlParser _crlReader;
		private AsymmetricKeyParameter caKey;
		private X509Name caName;
		private DateTime _crlLastUpdate = DateTime.MinValue;
		private DateTime _serialsLastUpdate = DateTime.MinValue;
		//TODO
		public Org.BouncyCastle.X509.X509CrlEntry GetCrlEntry(BigInteger serial)
		{
			//first time only
			if (_crl == null) {
				ReloadCrl ();
			}
			try{
				if (_crl == null)
					throw new OcspInternalMalfunctionException("CRLReloading error.");
			}finally{}
			return _crl.GetRevokedCertificate (serial);
		}
        //TODO
        public bool SerialExists(BigInteger serial)
        {
			return _serials.Contains (serial);
        }
        public void ReloadSerials()
        {
			if (Monitor.TryEnter(_serialsLock))
			{
				try
				{
					//TODO
				}
				finally
				{
					Monitor.Exit(_serialsLock);
				}
			}
            return;
        }
		//TODO
		public void ReloadCrl()
		{
			if (Monitor.TryEnter(_crlLock))
			{
				try{
					using (var crl_stream = new FileStream (_caCrlPath, FileMode.Open)) {
						_crl = _crlReader.ReadCrl (crl_stream);
					}
				}
				catch (CrlException e){
					Console.WriteLine ("Error reloading CRL:" + e.Message);
					_crl = null;
				}
				finally{
					Monitor.Exit(_crlLock);
				}
			}
			return;
		}
		public override string ToString()
		{
			return caName.ToString ();
		}
		public CA(string name, string caCertPath, IToken token, string crlPath, string serialsPath, bool compromised = false)
        {
            //Read CA certificate 
            var certReader = new PemReader(new StreamReader(caCertPath));
            caCertificate = (X509Certificate)certReader.ReadObject();
            caName = caCertificate.SubjectDN;
            caKey = caCertificate.GetPublicKey();
			//Init CRL
			_crlReader = new X509CrlParser ();
			//init token
            caToken = token;
            caCompromised = compromised;
            //TODO: Check if exists and access
            _caSerialsPath = serialsPath;
        }
    }
}
