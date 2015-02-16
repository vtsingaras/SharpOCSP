using System;
using System.Net;
using System.Collections.Generic;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using log4net;
using log4netExtensions;
using System.Threading;
using Mono.Unix;
using Mono.Unix.Native;
using System.Diagnostics;

namespace SharpOCSP
{
	static class SharpOCSP
    {
		public static ILog log = LogManager.GetLogger ("SharpOCSP");
		public static List<string> url_list = new List<string> ();
		public static List<CA> ca_list = new List<CA>();
		public static List<IToken> token_list = new List<IToken>();
		private static Configuration config =null;
		private static HttpHandler http_handler =null;
		private static SignalHandler signaler = null;

		public static void OnSerialsReload()
		{
			foreach (CA ca in ca_list) {
				ca.ReloadSerials ();
			}
		}
		public static void OnCrlReload()
		{
			foreach (CA ca in ca_list) {
				ca.ReloadCrl ();
			}
		}
		public static CA GetIssuerForSingleRequest(Req single_req)
		{
			//select issuer
			CertificateID cert_id = single_req.GetCertID ();
			foreach (CA issuer in ca_list)
			{
				if ( cert_id.MatchesIssuer(issuer.caCertificate))
					return issuer;
			}
			//Issuer not recognized
			throw new OcspUnrecognizedIssuerException("Unrecognized CA in request.");
		}
		public static IToken FindTokenByName(string name)
		{
			foreach (var token in token_list) {
				if (token.Name == name) {
					return token;
				}
			}
			return null;
		}
		public static IToken GetTokenForRequest(OcspReq ocsp_req)
		{
			//get first singleRequest
			Req first_single_req = ocsp_req.GetRequestList () [0];
			IToken _token_a = GetIssuerForSingleRequest (first_single_req).caToken;
			//check if request contains requests for different responders
			foreach ( Req single_req in ocsp_req.GetRequestList() )
			{
				IToken _token_b = GetIssuerForSingleRequest(single_req).caToken;
				if ( _token_a != _token_b)
					throw new OcspMalformedRequestException ("Multiple responderIDs in request!");
			}
			return _token_a;
		}
		public static OcspResp CreateResponseForRequest (OcspReq ocsp_req)
		{
			try{
				//validate ocsp_req
				if (ocsp_req == null){
					throw new OcspMalformedRequestException();
				}
				IToken token = GetTokenForRequest(ocsp_req);
				BasicResponseGenerator resp_generator = new BasicResponseGenerator (token);
				//append nonce
				var nonce = RequestUtilities.ExtractNonce(ocsp_req);
				if(nonce != null)
				{
					resp_generator.SetNonce (nonce);
				}
				foreach (Req single_req in ocsp_req.GetRequestList())
				{
					CertificateID cert_id;
					CA issuer;
					issuer = GetIssuerForSingleRequest(single_req);
					cert_id = single_req.GetCertID ();
					log.Debug ("Got request for serial: " + cert_id.SerialNumber.ToString() + " for CA: " + issuer.ToString());
					//check for ca compromise flag
					if (issuer.caCompromised == true) {
						//return revoked with reason cacompromised
						resp_generator.AddCaCompromisedResponse (cert_id);
					} else {
						if (issuer.SerialExists (cert_id.SerialNumber) == false) {
							//return unknown, if config.rfc6960 is true the return extended revoke instead
							if (config.getConfigValue ("extendedrevoke") == "yes") {
								//extended revoke, 1 Jan 1970 and certificateHold
								resp_generator.AddExtendedRevocationResponse (cert_id);
								continue;
							} else {
								//unknown
								resp_generator.AddUnknownResponse (cert_id);
								continue;
							}
						}
						//serial exists, check for revocation
						var crl_entry = issuer.GetCrlEntry (cert_id.SerialNumber);
						if ( crl_entry != null) {
							//serial is revoked
							resp_generator.AddRevokedResponse (cert_id, crl_entry);
							continue;
						} else {
							//serial is good
							resp_generator.AddGoodResponse (cert_id);
							continue;
						}
					}
				}
				//Build basic resp
				BasicOcspResp basic_ocsp_resp = resp_generator.Generate ();
				OCSPRespGenerator ocsp_resp_builder = new OCSPRespGenerator ();
				return ocsp_resp_builder.Generate (OcspRespStatus.Successful, basic_ocsp_resp);
			}catch (OcspMalformedRequestException e){
				log.Warn (e.Message);
				return new OCSPRespGenerator ().Generate (OcspRespStatus.MalformedRequest, null);
			}catch (OcspUnrecognizedIssuerException e){
				log.Warn (e.Message);
				return new OCSPRespGenerator ().Generate (OcspRespStatus.Unauthorized, null);
			}
		}
		public static byte[] SendOcspResponse(HttpListenerRequest http_request)
		{
			OcspReq ocsp_req = RequestUtilities.GetRequestFromHttp(http_request);
			OcspResp ocsp_resp = CreateResponseForRequest(ocsp_req);
			return ocsp_resp.GetEncoded ();
		}
        static void Main(string[] args)
        {
			Console.WriteLine ("PID for daemon: " + Process.GetCurrentProcess ().Id);
			if (Environment.OSVersion.Platform == PlatformID.Unix || Environment.OSVersion.Platform == PlatformID.MacOSX) {
				signaler = new SignalHandler (OnCrlReload, OnSerialsReload);
			}
			try{
				log.Always ("SharpOCSP v0.1 OCSP responder by Vyronas Tsingaras (c) 2015 firing up!");
				//check if user supplied xml configuration path, else use current directory
				//This will also initialize all CAs and tokens
				if (args.Length != 0){
					config = new Configuration(args[0]);
				}else{
					config  = new Configuration(Environment.CurrentDirectory + "\\sharpocsp.xml");
				}
				try{
					http_handler = new HttpHandler (SendOcspResponse, url_list.ToArray());
				}catch (ArgumentException e){
					throw new ConfigurationException("Verify URI prefixes", e);
				}
				//Listen for HTTP requests
				http_handler.Run ();
				//pause
				Console.ReadKey ();
			}catch (ConfigurationException e){
				log.Error ("Configuration: " + e.Message);
			}catch (OcspFilesystemException e){
				log.Error (e.Message);
			}catch (OcspInternalMalfunctionException e){
				log.Error ("The application encountered a serious error: " + e.Message);
				throw e.InnerException;
			}finally{
				if (Environment.OSVersion.Platform == PlatformID.Unix || Environment.OSVersion.Platform == PlatformID.MacOSX) {
					signaler.Dispose();
				}
			}
        }
    }
}
