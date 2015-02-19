using NUnit.Framework;
using System;
using NUnitUtils;
using Org.BouncyCastle.Ocsp;
using SharpOCSP;

namespace Tests
{
	//TODO
	[TestFixture ()]
	public class ResponseGenerationTests
	{
		CA testCA = null;
		IToken testSoftToken = null;

		[DeploymentItem("TestData/cacert.pem")]
		[DeploymentItem("TestData/crlv1.pem")]
		[DeploymentItem("TestData/index.txt")]
		[DeploymentItem("TestData/ocspcert.pem")]
		[DeploymentItem("TestData/ocspcert.key")]
		[SetUp]
		public void Init()
		{
			testSoftToken = new SoftToken ("TestSoftToken", "TestData/ocspcert.pem", "TestData/ocspcert.key");
			testCA = CA.CreateCA ("TestCA", "TestData/cacert.pem", "TestSoftToken", "TestData/crlv1.pem", "TestData/index.txt", false);
		}
		[DeploymentItem("TestData/validcert.pem")]
		[Test ()]
		public void RequestValidWithNonce()
		{
			OcspReqGenerator request_generator = new OcspReqGenerator();

			//request_generator.AddRequest
			OcspReq request_valid;
		}
	}
}

