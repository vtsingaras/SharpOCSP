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
		private string _crlPath;
		private string _serialsPath;
		public X509Certificate caCertificate { get; private set; }
		public bool caCompromised { get; private set; }
        //Private
		private Object _crlReloadLock = new Object();
		private Object _serialsReloadLock = new Object();
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
			//no need for lock
			return _crl.GetRevokedCertificate (serial);
		}
        public bool SerialExists(BigInteger serial)
        {
			lock (_serialsLock) {
				return _serials.Contains (serial);
			}
        }
        public void ReloadSerials()
        {
			if (Monitor.TryEnter(_serialsReloadLock))
			{
				try
				{
					_serials.Clear();
					using (var serials_reader = new StreamReader(File.OpenRead(_serialsPath)) ) {
						while(!serials_reader.EndOfStream){
							string db_line = serials_reader.ReadLine();
							//serial is entry number 4, tab separated
							var serial_read = new BigInteger(db_line.Split(new char[1]{'\t'},6)[3]);
							_serials.Add(serial_read);
						}
					}
				}
				finally
				{
					Monitor.Exit(_serialsReloadLock);
				}
			}
            return;
        }
		public void ReloadCrl()
		{
			if (Monitor.TryEnter(_crlReloadLock))
			{
				try{
					using (var crl_stream = new FileStream (_crlPath, FileMode.Open)) {
						_crl = _crlReader.ReadCrl (crl_stream);
					}
				}
				finally{
					Monitor.Exit(_crlReloadLock);
				}
			}
			return;
		}
		public override string ToString()
		{
			return caName.ToString ();
		}
		private CA(string name, string caCertPath, IToken token, string crlPath, string serialsPath, bool compromised = false)
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
            _serialsPath = serialsPath;
        }
		public static CA CAGenerator(string name, string caCertPath, IToken token, string crlPath, string serialsPath, bool compromised = false)
		{
			var new_ca = new CA(name, caCertPath, token, crlPath, serialsPath, compromised);
			new_ca.ReloadCrl ();
			new_ca.ReloadSerials ();
			return new_ca;
		}
    }
}
