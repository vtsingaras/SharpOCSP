using NUnit.Framework;
using System;
using NUnitUtils;
using SharpOCSP;

namespace Tests
{
	[TestFixture ()]
	public class TokenCACreationTests
	{
		[DeploymentItem("TestData/cacert.pem")]
		[DeploymentItem("TestData/crlv1.pem")]
		[DeploymentItem("TestData/index.txt")]
		[Test()]
		public void InitCA()
		{
			CA testCA = CA.CreateCA ("TestCA", "TestData/cacert.pem", "TestSoftToken", "TestData/crlv1.pem", "TestData/index.txt", false);
		}

		[DeploymentItem("TestData/ocspcert.pem")]
		[DeploymentItem("TestData/ocspcert.key")]
		[Test ()]
		public void InitToken()
		{
			IToken testSoftToken = new SoftToken ("TestSoftToken", "TestData/ocspcert.pem", "TestData/ocspcert.key");
		}
	}
}

