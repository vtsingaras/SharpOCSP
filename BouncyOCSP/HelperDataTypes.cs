using System;

namespace BouncyOCSP
{
	public enum CrlReason
	{
		unspecified = 0,
		keyCompromise,
		caCompromise,
		affiliationChanged,
		superseded,
		cessationOfOperation,
		certificateHold,
		removeFromCrl = 8
	}
}