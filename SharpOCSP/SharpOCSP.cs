﻿using log4net;
using log4netExtensions;
using Org.BouncyCastle.Ocsp;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Security.Principal;
using System.Threading;

namespace SharpOCSP
{
	static class SharpOCSP
    {
		public static ILog log = LogManager.GetLogger ("SharpOCSP");
		public static List<string> url_list = new List<string> ();
		public static List<CA> ca_list = new List<CA>();
		public static List<IToken> token_list = new List<IToken>();
		public static Configuration config = null;
		private static HttpHandler http_handler =null;
		private static SignalHandler signaler = null;
		private static ManualResetEvent app_exit_event = new ManualResetEvent (false);

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
			//TODO: Leverage RequestUtilities.RespondersMatch method to perform the token comparison
			Req[] request_list = null;
			try{
				request_list = ocsp_req.GetRequestList ();
			}catch (System.NullReferenceException){
				throw new OcspMalformedRequestException ("Unknown error parsing the request :(");
			}
			if (request_list.Length <= 0){
				throw new OcspMalformedRequestException ("Empty request list.");
			}
			//get first singleRequest
			Req first_single_req = request_list[0];
			IToken _token_a = GetIssuerForSingleRequest (first_single_req).caToken;
			//if we got only one single_req just return this issuer
			if (request_list.Length == 1) {
				return _token_a;
			}
			//check if request contains requests for different responders
			foreach ( Req single_req in request_list )
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
			Console.WriteLine ("PID of daemon: " + Process.GetCurrentProcess ().Id);
			if (Environment.OSVersion.Platform == PlatformID.Unix) {
				signaler = new SignalHandler (OnCrlReload, OnSerialsReload);
				if (Environment.OSVersion.Platform != PlatformID.MacOSX) {
					PlatformHacks.SetProcessName ("sharpocsp");
				}
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
				//Drop privileges
				if (config.getConfigValue("user") != null){
					if (Environment.OSVersion.Platform == PlatformID.Unix){
						//Bail-out on Unix if no group was specified but user was.
						if (config.getConfigValue("group") == null){
							throw new OcspInternalMalfunctionException("Group is required on UNIX-like platforms.");
						}
						//drop group privileges
						String group_name = config.getConfigValue("group");
						var group = Mono.Unix.Native.Syscall.getgrnam(group_name);
						if (group == null){
							throw new OcspInternalMalfunctionException("No such group: " + group_name);
						}
						if (Mono.Unix.Native.Syscall.setresgid(group.gr_gid, group.gr_gid, group.gr_gid) == -1) {
							throw new OcspInternalMalfunctionException("Can't drop group privileges!");
						}
						//drop user privileges
						String user_name = config.getConfigValue("user");
						var passwd = Mono.Unix.Native.Syscall.getpwnam(user_name);
						if (passwd == null){
							throw new OcspInternalMalfunctionException("No such user: " + user_name);
						}
						if (Mono.Unix.Native.Syscall.setresuid(passwd.pw_uid, passwd.pw_uid, passwd.pw_uid) == -1) {
							throw new OcspInternalMalfunctionException("Can't drop user privileges.");
						}
					}else{
						WindowsIdentity new_id = new WindowsIdentity(config.getConfigValue("user"));
						try{
							WindowsImpersonationContext new_id_context = new_id.Impersonate();
						}catch{
							throw new OcspInternalMalfunctionException("Unable to drop privileges!");
						}
					}
				}
				//Listen for HTTP requests
				http_handler.Run ();
				//pause
				app_exit_event.WaitOne();
				Environment.Exit(1);
			}catch (ConfigurationException e) {
				log.Error ("Configuration: " + e.Message);
			}catch (OcspFilesystemException e) {
				log.Error ("Filesystem: " + e.Message);
			}catch (OcspInternalMalfunctionException e) {
				log.Error ("The application encountered a serious error: " + e.Message);
				throw e.InnerException;
			}finally{
				if (Environment.OSVersion.Platform == PlatformID.Unix || Environment.OSVersion.Platform == PlatformID.MacOSX) {
					signaler.Dispose();
				}
				Environment.Exit(1);
			}
        }
    }
}
