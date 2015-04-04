using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace SharpOCSP
{
	public class CA
    {
        public IToken caToken;
		public X509Certificate caCertificate { get; private set; }
		public bool caCompromised { get; private set; }
		private string _crlPath;
		private X509Crl	_crl;
		private ReaderWriterLockSlim _crlLock;
		private string _serialsPath;
		private ReaderWriterLockSlim _serialsLock; 
		private IList<BigInteger> _serials;
		private X509CrlParser _crlReader;
		private string _name;

		public X509CrlEntry GetCrlEntry(BigInteger serial)
		{
			X509CrlEntry result = null;
			_crlLock.EnterReadLock ();
			try{
				result = _crl.GetRevokedCertificate(serial);
			}catch(Exception e) {
			}finally{
				_crlLock.ExitReadLock ();
			}
			return result;
		}
		public void ReloadCrl()
		{
			_crlLock.EnterWriteLock ();
			try{
				using (var crl_stream = new FileStream (_crlPath, FileMode.Open)) {
					_crl = _crlReader.ReadCrl (crl_stream);
				}
			}catch (System.UnauthorizedAccessException e){
				throw new OcspFilesystemException ("Error reading CRL: " + _crlPath, e);
			}catch (FileNotFoundException e){
				throw new OcspFilesystemException ("Error reading CRL: " + _crlPath, e);
			}
			finally{
				_crlLock.ExitWriteLock ();
			}
			SharpOCSP.log.Info ("CRL reloaded for CA: " + this);
			return;
		}
        public bool SerialExists(BigInteger serial)
        {
			if (_serialsPath == null) {
				return true;
			}
			bool result = false;
			_serialsLock.EnterReadLock ();
			try{
				result = _serials.Contains (serial);
			}finally{
				_serialsLock.ExitReadLock ();
			}
			return result;
        }
        public void ReloadSerials()
        {
			if (_serialsPath == null) {
				return;
			}
			_serialsLock.EnterWriteLock ();
			try
			{
				_serials.Clear();
				using (var serials_reader = new StreamReader(File.OpenRead(_serialsPath)) ) {
					while(!serials_reader.EndOfStream){
						string db_line = serials_reader.ReadLine();
						//serial is entry number 4, tab separated, in hexstring
						var serial_read = new BigInteger(db_line.Split(new char[1]{'\t'},6)[3], 16);
						_serials.Add(serial_read);
					}
				}
			}catch (System.UnauthorizedAccessException e){
				throw new OcspFilesystemException ("Error reading index.txt: " + _serialsPath, e);
			}catch (FileNotFoundException e){
				throw new OcspFilesystemException ("Error reading index.txt: " + _serialsPath, e);
			}
			finally
			{
				_serialsLock.ExitWriteLock ();
			}
			SharpOCSP.log.Info ("Serials reloaded for CA: " + this);
            return;
        }
		public override string ToString()
		{
			return _name;
		}
		private CA(string name, string caCertPath, IToken token, string crlPath, string serialsPath, bool compromised = false)
        {
            //Read CA certificate 
			try{
	            var certReader = new PemReader(new StreamReader(caCertPath));
	            caCertificate = (X509Certificate)certReader.ReadObject();
			}catch (System.UnauthorizedAccessException e){
				throw new OcspFilesystemException ("Error reading ca certificate: " + caCertPath, e);
			}catch (FileNotFoundException e){
				throw new OcspFilesystemException ("Error reading ca certificate: " + caCertPath, e);
			}
			//Set name to SubjectDN if null
			if (name == null) {
				_name = caCertificate.SubjectDN.ToString ();
			} else {
				_name = name;
			}
			//Init CRLReader and serials
			_crlReader = new X509CrlParser ();
			_crlPath = crlPath;
			_serials = new List<BigInteger> ();
			_serialsPath = serialsPath;
			//Init token
            caToken = token;
            caCompromised = compromised;
			//Initialize locks
			_crlLock = new ReaderWriterLockSlim (LockRecursionPolicy.NoRecursion);
			_serialsLock = new ReaderWriterLockSlim (LockRecursionPolicy.NoRecursion);
        }
		public static CA CreateCA(string name, string caCertPath, string token, string crlPath, string serialsPath, bool compromised = false)
		{
			IToken _itoken = SharpOCSP.FindTokenByName (token);
			var new_ca = new CA(name, caCertPath, _itoken, crlPath, serialsPath, compromised);
			new_ca.ReloadCrl ();
			new_ca.ReloadSerials ();
			return new_ca;
		}
    }
}